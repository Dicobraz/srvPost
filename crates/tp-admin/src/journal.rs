//! Журнал переписки в Admin API (SRS 4.9, 5.2; ADM-52): доступ — только роль «аудитор журнала»
//! ([`AdminRole::JournalAuditor`](crate::server::AdminRole::JournalAuditor), вход только OIDC, как у прочих
//! администраторов).
//!
//! - `GET /api/v1/orgs/{org}/journal` — поиск ([`JournalStore::search`], [`JournalQuery`]): отправитель,
//!   получатель (в том числе скрытый), Message-ID, правило, интервал; страницы — по непрозрачной позиции
//!   `after` (`next` предыдущей страницы).
//! - `GET /api/v1/orgs/{org}/journal/{id}` — запись журнала: конверт и хеш цепочки.
//! - `GET /api/v1/orgs/{org}/journal/{id}/export` — выгрузка `.eml` с конвертом
//!   ([`journal_eml`](tp_contracts::journal::journal_eml), модель journal report Exchange).
//! - `GET /api/v1/orgs/{org}/journal/verify` — отчёт целостности хеш-цепочки индекса
//!   ([`JournalStore::verify_chain`]; для аудита и thepost doctor).
//!
//! Содержимое журнала недоступно администраторам организации и инсталляции, оператору и аудитору
//! (журнал аудита), пользовательскому токену — 403; через IMAP и JMAP журнал не виден. Каждое обращение
//! (поиск, просмотр, выгрузка, проверка) — запись журнала аудита ([`AdminAuditRecord`]): кто, какой
//! маршрут, когда и с каким критерием (строка запроса — в `path`), `content_messages` — сколько писем
//! выдано; запись не сохранена — содержимое не отдаётся (как доступ к темам писем, `crate::content`).
//! Журнал не подключён ([`Admin::with_journal`]) — 503 (записи пишет этап ядра конвейера, волна узла;
//! ADM-52 читает готовое хранилище — BLOB-18 и META-88).
//!
//! Правила журналирования (ADM-53, решение #171) — не содержимое журнала: ими управляет только
//! администратор организации ([`AdminRole::permits`]: маршруты `/journal/rules` исключены из области
//! «аудитора журнала», который читает записи, но правил не видит — 403):
//! - `GET /api/v1/orgs/{org}/journal/rules` — список в порядке наследования ящик > группа >
//!   организация ([`JournalScope::priority`]);
//! - `PUT /api/v1/orgs/{org}/journal/rules/{id}` — создать или заменить правило (область, направление,
//!   включено); область проверена (группа и ящик существуют), повторная цель с тем же направлением —
//!   409 с подсказкой;
//! - `DELETE /api/v1/orgs/{org}/journal/rules/{id}` — удалить.
//!
//! Изменения подхватывает конвейер без перезапуска: порт [`JournalRuleStore`] читает правила на каждом
//! письме (SMTP-53). Каждое изменение — запись журнала аудита с деталями «было → стало»
//! ([`AuditDetails::JournalRule`]).
//!
//! Выгрузка во внешний архив заказчика (SRS 4.9): по секции `admin.journal_archive` — каталог или
//! HTTPS-эндпоинт; каждая не выгруженная ещё запись ([`archive_pass`]) выгружается `.eml` с конвертом,
//! сбой выгрузки не влияет на доставку почты (проход ведёт роль maintenance узла, как SIEM —
//! [`crate::export`]), повтор — по журналу выгрузки ([`ArchiveLedger`]).

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::extract::{MatchedPath, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, put};
use axum::{Extension, Router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tp_contracts::admin_audit::{AdminAuditRecord, AuditDetails};
use tp_contracts::config::duration;
use tp_contracts::ids::{JournalId, TenantId};
use tp_contracts::journal::{
    ChainReport, JournalAudit, JournalCursor, JournalDirection, JournalEntry, JournalQuery,
    JournalRecord, JournalRule, JournalRuleStore, JournalScope, JournalStore, MAX_RULE_ID_LEN,
    valid_rule_id,
};
use tp_contracts::tls::Profile;
use tp_contracts::{Error, Result};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::extract::{Json, Path, Query};
use crate::server::{Admin, ApiResult, Caller, Problem, Refused};

/// Шаблон маршрута поиска журнала.
pub const JOURNAL_ROUTE: &str = "/api/v1/orgs/{org}/journal";

/// Шаблон маршрута записи журнала.
pub const JOURNAL_ENTRY_ROUTE: &str = "/api/v1/orgs/{org}/journal/{id}";

/// Шаблон маршрута выгрузки записи: `.eml` с конвертом.
pub const JOURNAL_EXPORT_ROUTE: &str = "/api/v1/orgs/{org}/journal/{id}/export";

/// Шаблон маршрута проверки хеш-цепочки индекса.
pub const JOURNAL_VERIFY_ROUTE: &str = "/api/v1/orgs/{org}/journal/verify";

/// Начало шаблонов маршрутов журнала: им ограничена роль «аудитор журнала»
/// ([`AdminRole::permits`](crate::server::AdminRole::permits)).
pub const JOURNAL_PREFIX: &str = "/api/v1/orgs/{org}/journal";

/// Шаблон маршрута списка правил журналирования (ADM-53).
pub const JOURNAL_RULES_ROUTE: &str = "/api/v1/orgs/{org}/journal/rules";

/// Шаблон маршрута правила журналирования: создание/замена и удаление (ADM-53).
pub const JOURNAL_RULES_ITEM_ROUTE: &str = "/api/v1/orgs/{org}/journal/rules/{id}";

/// Начало шаблонов маршрутов правил журналирования: правила — не содержимое журнала (ADM-53), ими
/// управляет администратор организации; [`AdminRole::permits`] исключает их из области «аудитора
/// журнала» (содержимое — [`JOURNAL_PREFIX`]).
pub const JOURNAL_RULES_PREFIX: &str = "/api/v1/orgs/{org}/journal/rules";

/// Тип содержимого выгрузки и записи архива: `.eml` с конвертом.
const EML_TYPE: &str = "message/rfc822";

/// Конверт записи журнала в ответе API ([`JournalRecord`] контракта; обе стороны serde — ADM-13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JournalRecordView {
    /// Организация.
    pub tenant: String,
    /// Отправитель конверта; пустой — уведомление о доставке.
    pub sender: String,
    /// Все получатели конверта, включая скрытых и раскрытых из групп.
    pub recipients: Vec<String>,
    /// Message-ID без угловых скобок; `null` — нет.
    pub message_id: Option<String>,
    /// Момент письма (UTC).
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub at: OffsetDateTime,
    /// Правило журналирования.
    pub rule: String,
}

impl From<&JournalRecord> for JournalRecordView {
    fn from(r: &JournalRecord) -> Self {
        Self {
            tenant: r.tenant.to_string(),
            sender: r.sender.clone(),
            recipients: r.recipients.clone(),
            message_id: r.message_id.clone(),
            at: r.at,
            rule: r.rule.clone(),
        }
    }
}

/// Запись журнала: идентификатор, конверт и хеш цепочки.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JournalEntryView {
    /// Идентификатор записи (UUID).
    pub id: String,
    /// Конверт.
    pub record: JournalRecordView,
    /// Хеш цепочки записи (SHA-256, hex); проверяется маршрутом `verify`.
    pub hash: String,
}

impl From<&JournalEntry> for JournalEntryView {
    fn from(e: &JournalEntry) -> Self {
        Self {
            id: e.id.to_string(),
            record: JournalRecordView::from(&e.record),
            hash: e.hash.to_string(),
        }
    }
}

/// Страница журнала: записи в порядке (`at`, `id`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JournalPageView {
    /// Записи страницы.
    pub entries: Vec<JournalEntryView>,
    /// `after` следующей страницы; `null` — записей больше нет.
    pub next: Option<String>,
}

/// Отчёт проверки хеш-цепочки индекса организации.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ChainReportView {
    /// Число проверенных записей.
    pub records: u64,
    /// Цепочка целостна.
    pub ok: bool,
    /// Первая запись с нарушением; `null` — нарушений нет.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broken_at: Option<String>,
}

impl From<ChainReport> for ChainReportView {
    fn from(r: ChainReport) -> Self {
        Self {
            records: r.records,
            ok: r.ok,
            broken_at: r.broken_at.map(|id| id.to_string()),
        }
    }
}

/// Параметры поиска журнала (условия — по «и»; без условия — вся организация).
#[derive(Debug, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct JournalParams {
    /// Отправитель конверта (точно, без учёта регистра ASCII).
    pub sender: Option<String>,
    /// Один из получателей записи, включая скрытых (точно, без учёта регистра ASCII).
    pub recipient: Option<String>,
    /// Message-ID без угловых скобок (точно).
    pub message_id: Option<String>,
    /// Правило журналирования (точно).
    pub rule: Option<String>,
    /// Начало интервала (RFC 3339), включительно.
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(value_type = Option<String>, format = DateTime)]
    pub since: Option<OffsetDateTime>,
    /// Конец интервала (RFC 3339), не включительно.
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(value_type = Option<String>, format = DateTime)]
    pub until: Option<OffsetDateTime>,
    /// Размер страницы (по умолчанию и наибольший — из конфигурации).
    pub limit: Option<usize>,
    /// Продолжение: `next` предыдущей страницы с теми же условиями.
    pub after: Option<String>,
}

impl JournalParams {
    /// Запрос [`JournalQuery`] из параметров (проверка — [`JournalQuery::validate`]).
    fn query(&self, a: &Admin, org: TenantId) -> Result<JournalQuery> {
        Ok(JournalQuery {
            tenant: org,
            sender: self.sender.clone(),
            recipient: self.recipient.clone(),
            message_id: self.message_id.clone(),
            rule: self.rule.clone(),
            since: self.since,
            until: self.until,
            limit: a.cfg.page(self.limit),
            after: self.after.clone().map(JournalCursor),
        })
    }
}

/// Хранилище журнала; не подключено — 503.
fn store(a: &Admin) -> ApiResult<&dyn JournalStore> {
    Ok(a.journal.as_deref().ok_or(Error::UNAVAILABLE)?)
}

/// Правила журналирования; не подключены — 503 (как хранилище записей — [`store`], но ошибка —
/// `Error`, годится и обработчикам с [`Refused`]).
fn rule_store(a: &Admin) -> std::result::Result<&dyn JournalRuleStore, Error> {
    a.journal_rules.as_deref().ok_or(Error::UNAVAILABLE)
}

/// Маршруты журнала.
pub(crate) fn routes(r: Router<Arc<Admin>>) -> Router<Arc<Admin>> {
    r.route(JOURNAL_ROUTE, get(search_journal))
        .route(JOURNAL_VERIFY_ROUTE, get(verify_journal))
        .route(JOURNAL_ENTRY_ROUTE, get(get_journal))
        .route(JOURNAL_EXPORT_ROUTE, get(export_journal))
        .route(JOURNAL_RULES_ROUTE, get(list_rules))
        .route(JOURNAL_RULES_ITEM_ROUTE, put(put_rule).delete(delete_rule))
}

/// Спецификация OpenAPI маршрутов модуля.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        search_journal,
        verify_journal,
        get_journal,
        export_journal,
        list_rules,
        put_rule,
        delete_rule
    ),
    components(schemas(
        JournalRecordView,
        JournalEntryView,
        JournalPageView,
        ChainReportView,
        JournalRulesView,
        JournalRuleView,
        JournalRuleBody,
        JournalScopeSchema,
        JournalDirectionSchema,
        JournalRuleSchema
    ))
)]
pub(crate) struct Doc;

/// Поиск по журналу организации: записи в порядке (`at`, `id`), продолжение — `after`.
#[utoipa::path(get, path = "/api/v1/orgs/{org}/journal", tag = "journal",
    params(("org" = String, Path, description = "Организация (UUID)"), JournalParams),
    responses((status = 200, body = JournalPageView), (status = 400, body = Problem),
        (status = 403, body = Problem), (status = 503, body = Problem)))]
async fn search_journal(
    State(a): State<Arc<Admin>>,
    Extension(caller): Extension<Caller>,
    route: MatchedPath,
    uri: Uri,
    Path(org): Path<TenantId>,
    Query(q): Query<JournalParams>,
) -> ApiResult<Json<JournalPageView>> {
    let query = q.query(&a, org)?;
    query.validate()?;
    let page = store(&a)?.search(&JournalAudit::grant(), &query).await?;
    access(&a, &caller, org, route.as_str(), &uri, page.entries.len()).await?;
    Ok(Json(JournalPageView {
        entries: page.entries.iter().map(Into::into).collect(),
        next: page.next.map(|c| c.0),
    }))
}

/// Запись журнала по идентификатору: конверт и хеш цепочки; нет записи — 404.
#[utoipa::path(get, path = "/api/v1/orgs/{org}/journal/{id}", tag = "journal",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("id" = String, Path, description = "Запись журнала (UUID)")),
    responses((status = 200, body = JournalEntryView), (status = 400, body = Problem),
        (status = 403, body = Problem), (status = 404, body = Problem), (status = 503, body = Problem)))]
async fn get_journal(
    State(a): State<Arc<Admin>>,
    Extension(caller): Extension<Caller>,
    route: MatchedPath,
    uri: Uri,
    Path((org, id)): Path<(TenantId, JournalId)>,
) -> ApiResult<Json<JournalEntryView>> {
    let entry = entry(store(&a)?, org, id, a.cfg.max_page_size).await?;
    access(&a, &caller, org, route.as_str(), &uri, 1).await?;
    Ok(Json(JournalEntryView::from(&entry)))
}

/// Запись организации по идентификатору: страницы поиска до записи (контракт отбирает записи условиями
/// [`JournalQuery`], по идентификатору выборки нет); записи чужих организаций не видны, нет записи —
/// `NotFound`. Просмотр после поиска — одна страница; выгрузка по прямой ссылке — сколько потребуется.
async fn entry(
    store: &dyn JournalStore,
    org: TenantId,
    id: JournalId,
    limit: usize,
) -> Result<JournalEntry> {
    let cap = JournalAudit::grant();
    let mut after = None;
    loop {
        let query = JournalQuery {
            tenant: org,
            limit,
            after,
            ..JournalQuery::all(org, limit)
        };
        let page = store.search(&cap, &query).await?;
        if let Some(e) = page.entries.iter().find(|e| e.id == id) {
            return Ok(e.clone());
        }
        match page.next {
            Some(next) => after = Some(next),
            None => return Err(Error::NotFound),
        }
    }
}

/// Выгрузка записи: `.eml` с конвертом (заголовки `X-ThePost-Journal-*` и письмо целиком).
#[utoipa::path(get, path = "/api/v1/orgs/{org}/journal/{id}/export", tag = "journal",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("id" = String, Path, description = "Запись журнала (UUID)")),
    responses((status = 200, description = "файл .eml", content_type = "message/rfc822"),
        (status = 400, body = Problem), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn export_journal(
    State(a): State<Arc<Admin>>,
    Extension(caller): Extension<Caller>,
    route: MatchedPath,
    uri: Uri,
    Path((org, id)): Path<(TenantId, JournalId)>,
) -> ApiResult<(HeaderMap, Vec<u8>)> {
    let eml = store(&a)?.export(&JournalAudit::grant(), org, id).await?;
    access(&a, &caller, org, route.as_str(), &uri, 1).await?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(EML_TYPE));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename={id}.eml"))
            .map_err(|e| Error::internal(format!("заголовок Content-Disposition: {e}")))?,
    );
    Ok((headers, eml.to_vec()))
}

/// Отчёт целостности хеш-цепочки индекса организации (`hash = SHA-256(prev_hash ‖ canonical)`).
#[utoipa::path(get, path = "/api/v1/orgs/{org}/journal/verify", tag = "journal",
    params(("org" = String, Path, description = "Организация (UUID)")),
    responses((status = 200, body = ChainReportView), (status = 400, body = Problem),
        (status = 403, body = Problem), (status = 503, body = Problem)))]
async fn verify_journal(
    State(a): State<Arc<Admin>>,
    Extension(caller): Extension<Caller>,
    route: MatchedPath,
    uri: Uri,
    Path(org): Path<TenantId>,
) -> ApiResult<Json<ChainReportView>> {
    let report = store(&a)?.verify_chain(&JournalAudit::grant(), org).await?;
    access(&a, &caller, org, route.as_str(), &uri, 0).await?;
    Ok(Json(report.into()))
}

/// Запись аудита об обращении к журналу: кто, маршрут, момент и критерий (строка запроса — в `path`);
/// `messages` — сколько записей выдано с содержимым писем (0 — проверка цепочки, писем не отдаёт).
/// Запись не сохранена — содержимое не отдаётся (как доступ к темам, [`crate::content`]).
async fn access(
    a: &Admin,
    caller: &Caller,
    org: TenantId,
    route: &str,
    uri: &Uri,
    messages: usize,
) -> Result<()> {
    let p = &caller.principal;
    let path = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_owned(), ToString::to_string);
    let record = AdminAuditRecord {
        at: OffsetDateTime::now_utc(),
        tenant: Some(org),
        actor_tenant: p.tenant,
        actor: p.account,
        actor_login: p.login.clone(),
        roles: caller.audit_roles(),
        method: Method::GET.to_string(),
        route: route.to_owned(),
        path,
        status: 200,
        content_messages: Some(u64::try_from(messages).unwrap_or(u64::MAX)),
        details: None,
    };
    crate::audit::record(&a.d, &record).await
}

// ---------- Правила журналирования (ADM-53, решение #171) ----------

// Схемы OpenAPI контрактов `tp_contracts::journal` (в `serde` — тот же вид); значений этих типов нет.

/// Область правила журналирования: `"org"` — организация, `{"group": "<uuid>"}` — группа рассылки,
/// `{"mailbox": "<uuid>"}` — ящик.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = JournalScope)]
pub enum JournalScopeSchema {
    /// Организация целиком.
    Org,
    /// Группа рассылки (UUID): отправитель или получатель — член группы.
    Group(String),
    /// Ящик (учётная запись, UUID).
    Mailbox(String),
}

/// Направление правила: `"in"` — доставляемое, `"out"` — отправляемое, `"both"` — оба.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "lowercase")]
#[schema(as = JournalDirection)]
pub enum JournalDirectionSchema {
    /// Доставляемое в ящики организации (включая внутреннюю почту).
    In,
    /// Отправляемое клиентом.
    Out,
    /// Оба направления.
    Both,
}

/// Правило журналирования контракта ([`tp_contracts::journal::JournalRule`]) — для деталей записи
/// аудита ([`crate::audit::AuditDetailsSchema`]).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = JournalRule)]
pub struct JournalRuleSchema {
    /// Идентификатор.
    pub id: String,
    /// Организация (UUID).
    pub tenant: String,
    /// Область.
    pub scope: JournalScopeSchema,
    /// Направление.
    pub direction: JournalDirectionSchema,
    /// Включено.
    pub enabled: bool,
}

/// Правило журналирования в ответе API ([`tp_contracts::journal::JournalRule`]; обе стороны serde — ADM-13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JournalRuleView {
    /// Идентификатор (1–64 байта без пробелов и управляющих).
    pub id: String,
    /// Организация (UUID).
    pub tenant: String,
    /// Область: организация, группа или ящик.
    #[schema(value_type = JournalScopeSchema)]
    pub scope: JournalScope,
    /// Направление: `in`, `out`, `both`.
    #[schema(value_type = JournalDirectionSchema)]
    pub direction: JournalDirection,
    /// Включено (выключенное правило писем не касается).
    pub enabled: bool,
}

impl From<JournalRule> for JournalRuleView {
    fn from(r: JournalRule) -> Self {
        Self {
            id: r.id,
            tenant: r.tenant.to_string(),
            scope: r.scope,
            direction: r.direction,
            enabled: r.enabled,
        }
    }
}

/// Правила журналирования организации в порядке наследования: ящик > группа > организация
/// ([`JournalScope::priority`]), внутри области — по идентификаторам.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct JournalRulesView {
    /// Правила; пусто — журналирование выключено.
    pub rules: Vec<JournalRuleView>,
}

/// Правило журналирования: создание или замена целиком (идентификатор — в пути).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct JournalRuleBody {
    /// Область: `"org"`, `{"group": "<uuid>"}` или `{"mailbox": "<uuid>"}`.
    #[schema(value_type = JournalScopeSchema)]
    pub scope: JournalScope,
    /// Направление: `in`, `out`, `both`.
    #[schema(value_type = JournalDirectionSchema)]
    pub direction: JournalDirection,
    /// Включено (по умолчанию — включено).
    #[serde(default = "rule_enabled_by_default")]
    pub enabled: bool,
}

/// Правило создаётся включённым, пока не сказано иное ([`JournalRuleBody::enabled`]).
fn rule_enabled_by_default() -> bool {
    true
}

/// Правила журналирования организации (ADM-53): порядок наследования ящик > группа > организация,
/// внутри области — по идентификаторам. Право — администратор организации; аудитор журнала содержимое
/// читает, правила не видит (403). Хранилище правил не подключено — 503.
#[utoipa::path(get, path = "/api/v1/orgs/{org}/journal/rules", tag = "journal",
    params(("org" = String, Path, description = "Организация (UUID)")),
    responses((status = 200, body = JournalRulesView), (status = 403, body = Problem),
        (status = 503, body = Problem)))]
async fn list_rules(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
) -> ApiResult<Json<JournalRulesView>> {
    let mut rules = rule_store(&a)?.rules(org).await?;
    rules.sort_by_key(|r| (r.scope.priority(), r.id.clone()));
    Ok(Json(JournalRulesView {
        rules: rules.into_iter().map(Into::into).collect(),
    }))
}

/// Создаёт или заменяет правило журналирования (замена целиком по идентификатору). Группа и ящик
/// области должны существовать (422), та же цель с тем же направлением у другого правила — 409 с
/// подсказкой; конвейер подхватывает изменение без перезапуска (SMTP-53). Изменение — в журнал аудита
/// с парой «было → стало».
#[utoipa::path(put, path = "/api/v1/orgs/{org}/journal/rules/{id}", tag = "journal",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("id" = String, Path, description = "Идентификатор правила (1–64 байта без пробелов)")),
    request_body = JournalRuleBody,
    responses((status = 200, body = JournalRuleView), (status = 400, body = Problem),
        (status = 403, body = Problem),
        (status = 409, description = "та же цель с тем же направлением уже журналируется", body = Problem),
        (status = 422, description = "группа или ящик области не существуют", body = Problem),
        (status = 503, body = Problem)))]
async fn put_rule(
    State(a): State<Arc<Admin>>,
    Path((org, id)): Path<(TenantId, String)>,
    Json(body): Json<JournalRuleBody>,
) -> std::result::Result<Response, Refused> {
    let rule = JournalRule {
        id,
        tenant: org,
        scope: body.scope,
        direction: body.direction,
        enabled: body.enabled,
    };
    if !valid_rule_id(&rule.id) {
        return Err(Refused::Problem(
            StatusCode::BAD_REQUEST,
            format!(
                "идентификатор правила {:?}: 1–{MAX_RULE_ID_LEN} байт без пробелов и управляющих",
                rule.id
            ),
        ));
    }
    check_scope(&a, org, rule.scope).await?;
    let store = rule_store(&a)?;
    let existing = store.rules(org).await?;
    if let Some(dup) = existing
        .iter()
        .find(|r| r.id != rule.id && r.scope == rule.scope && r.direction == rule.direction)
    {
        return Err(Refused::Problem(
            StatusCode::CONFLICT,
            format!(
                "{} уже журналируется правилом {} ({}) — измените или удалите его",
                scope_ru(rule.scope),
                dup.id,
                direction_ru(rule.direction)
            ),
        ));
    }
    let old = existing.iter().find(|r| r.id == rule.id).cloned();
    store.set_rule(&rule).await?;
    Ok(rule_response(
        JournalRuleView::from(rule.clone()),
        AuditDetails::JournalRule {
            from: old,
            to: Some(rule),
        },
    ))
}

/// Удаляет правило журналирования; нет правила — 404. Записи журнала правило не трогает: изменение
/// действует на будущие письма, конвейер подхватывает его без перезапуска (SMTP-53). Удаление — в
/// журнал аудита с парой «было → стало».
#[utoipa::path(delete, path = "/api/v1/orgs/{org}/journal/rules/{id}", tag = "journal",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("id" = String, Path, description = "Идентификатор правила")),
    responses((status = 200, body = JournalRuleView), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn delete_rule(
    State(a): State<Arc<Admin>>,
    Path((org, id)): Path<(TenantId, String)>,
) -> std::result::Result<Response, Refused> {
    let store = rule_store(&a)?;
    let old = store
        .rules(org)
        .await?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or(Error::NotFound)?;
    store.delete_rule(org, &id).await?;
    Ok(rule_response(
        JournalRuleView::from(old.clone()),
        AuditDetails::JournalRule {
            from: Some(old),
            to: None,
        },
    ))
}

/// Ответ с деталями изменения в расширениях: слой доступа ([`crate::server`]) переносит их в запись
/// журнала аудита (кто/что/было-стало).
fn rule_response(v: JournalRuleView, details: AuditDetails) -> Response {
    let mut resp = Json(v).into_response();
    resp.extensions_mut().insert(details);
    resp
}

/// Область правила существует: группа и ящик — в этой организации; нет — 422 с подсказкой
/// (организация — вся организация пути).
async fn check_scope(
    a: &Admin,
    org: TenantId,
    scope: JournalScope,
) -> std::result::Result<(), Refused> {
    let gone = |what: &str, id: String| {
        Refused::Problem(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("{what} {id} не найдена — правило можно задать только на существующую"),
        )
    };
    match scope {
        JournalScope::Org => Ok(()),
        JournalScope::Group(g) => match a.d.groups.get(org, g).await? {
            Some(_) => Ok(()),
            None => Err(gone("группа", g.to_string())),
        },
        JournalScope::Mailbox(acc) => match a.d.accounts.get(org, acc).await? {
            Some(_) => Ok(()),
            None => Err(gone("учётная запись", acc.to_string())),
        },
    }
}

/// Область правила по-русски (подсказка повторной цели).
fn scope_ru(scope: JournalScope) -> String {
    match scope {
        JournalScope::Org => "организация".to_owned(),
        JournalScope::Group(g) => format!("группа {g}"),
        JournalScope::Mailbox(a) => format!("ящик {a}"),
    }
}

/// Направление правила — имя из API (подсказка повторной цели).
fn direction_ru(direction: JournalDirection) -> &'static str {
    match direction {
        JournalDirection::In => "in",
        JournalDirection::Out => "out",
        JournalDirection::Both => "both",
    }
}

// ---------- Внешний архив (SRS 4.9) ----------

/// Подсекция `admin.journal_archive.https`: выгрузка записей журнала POST-запросами.
///
/// ```yaml
/// endpoint: "https://archive.example.org/journal"
/// ca_file: /etc/thepost/archive-ca.pem
/// timeout: 30s
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HttpsArchiveConfig {
    /// Базовый адрес приёмника; запись выгружается `POST {адрес}/{организация}/{идентификатор}`.
    pub endpoint: String,
    /// Корневые сертификаты приёмника (PEM); не задано — системные корни.
    pub ca_file: Option<PathBuf>,
    /// Не проверять сертификат приёмника — только профиль dev.
    pub insecure: bool,
    /// Предельное время запроса.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub timeout: Duration,
}

impl Default for HttpsArchiveConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            ca_file: None,
            insecure: false,
            timeout: Duration::from_secs(30),
        }
    }
}

impl HttpsArchiveConfig {
    /// Проверяет подсекцию: адрес — `http`/`https`, таймаут положительный.
    pub fn check(&self) -> Result<()> {
        let ok = self.endpoint.starts_with("https://") || self.endpoint.starts_with("http://");
        if !ok || self.endpoint.len() <= "https://".len() {
            return Err(Error::invalid(
                "admin.journal_archive.https: endpoint — адрес https:// (http:// — только профиль dev)",
            ));
        }
        if self.timeout.is_zero() {
            return Err(Error::invalid(
                "admin.journal_archive.https: timeout must be positive",
            ));
        }
        Ok(())
    }
}

/// Секция `admin.journal_archive`: выгрузка новых записей журнала во внешний архив заказчика (SRS 4.9,
/// ADM-52). Без `directory` и `https` — выключена; заданы обе — ошибка: приёмник один. Проход —
/// [`archive_pass`], его ведёт роль maintenance узла.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct JournalArchiveConfig {
    /// Каталог выгрузки: файл `{каталог}/{организация}/{идентификатор}.eml`.
    pub directory: Option<PathBuf>,
    /// Приёмник HTTPS ([`HttpsArchiveConfig`]).
    pub https: Option<HttpsArchiveConfig>,
    /// Пауза между проходами, когда новых записей нет.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub interval: Duration,
    /// Пауза перед повтором после сбоя выгрузки.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub retry: Duration,
    /// Записей в одном проходе.
    pub batch: usize,
}

impl Default for JournalArchiveConfig {
    fn default() -> Self {
        Self {
            directory: None,
            https: None,
            interval: Duration::from_secs(10),
            retry: Duration::from_secs(30),
            batch: 100,
        }
    }
}

impl JournalArchiveConfig {
    /// Приёмник задан.
    pub fn enabled(&self) -> bool {
        self.directory.is_some() || self.https.is_some()
    }

    /// Проверяет секцию (без профиля; открытый канал и `insecure` проверяет [`JournalArchiveConfig::start`]).
    pub fn check(&self) -> Result<()> {
        if self.batch == 0 {
            return Err(Error::invalid(
                "admin.journal_archive: batch must be positive",
            ));
        }
        if self.interval.is_zero() || self.retry.is_zero() {
            return Err(Error::invalid(
                "admin.journal_archive: interval and retry must be positive",
            ));
        }
        if self.directory.is_some() && self.https.is_some() {
            return Err(Error::invalid(
                "admin.journal_archive: задайте один приёмник — directory или https",
            ));
        }
        if let Some(h) = &self.https {
            h.check()?;
        }
        Ok(())
    }

    /// Приёмник по секции; выключена — `None`. Канал без TLS и `insecure` — только профиль dev.
    pub fn start(&self, profile: Profile) -> Result<Option<Arc<dyn ArchiveSink>>> {
        self.check()?;
        if let Some(d) = &self.directory {
            return Ok(Some(Arc::new(DirectoryArchive { root: d.clone() })));
        }
        let Some(h) = &self.https else {
            return Ok(None);
        };
        let dev_only = |what: &str| {
            if profile == Profile::Dev {
                Ok(())
            } else {
                Err(Error::invalid(format!(
                    "admin.journal_archive.https: {what} — только профиль dev"
                )))
            }
        };
        let insecure = if h.insecure {
            dev_only("insecure")?;
            true
        } else {
            false
        };
        if h.endpoint.starts_with("http://") {
            dev_only("адрес http://")?;
        }
        let mut client = reqwest::Client::builder().timeout(h.timeout);
        if let Some(ca) = &h.ca_file {
            let pem = std::fs::read(ca).map_err(|e| {
                Error::invalid(format!(
                    "admin.journal_archive.https: {}: {e}",
                    ca.display()
                ))
            })?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
                Error::invalid(format!(
                    "admin.journal_archive.https: {}: не PEM: {e}",
                    ca.display()
                ))
            })? {
                client = client.add_root_certificate(cert);
            }
        }
        if insecure {
            client = client.danger_accept_invalid_certs(true);
        }
        let http = client
            .build()
            .map_err(|e| Error::invalid(format!("admin.journal_archive.https: {e}")))?;
        Ok(Some(Arc::new(HttpsArchive {
            endpoint: h.endpoint.trim_end_matches('/').to_owned(),
            http,
        })))
    }
}

/// Приёмник внешнего архива: выгрузка записи `.eml` с конвертом (ADM-52, SRS 4.9). Повтор записи —
/// не ошибка: приёмник получает то же содержимое (файл каталога перезаписывается).
#[async_trait]
pub trait ArchiveSink: Send + Sync + 'static {
    /// Имя приёмника (`directory`, `https`) — для журнала узла.
    fn name(&self) -> &'static str;

    /// Выгружает запись `id` организации `tenant`; сбой — позиция ([`ArchiveLedger`]) не сдвигается,
    /// следующий проход повторит (доставку почты приёмник не затрагивает).
    async fn deliver(&self, tenant: TenantId, id: JournalId, eml: &[u8]) -> Result<()>;
}

/// Архив в каталоге заказчика: файл `{корень}/{организация}/{идентификатор}.eml` (`.eml` с конвертом).
#[derive(Debug, Clone)]
pub struct DirectoryArchive {
    /// Корень архива (секция `admin.journal_archive.directory`).
    root: PathBuf,
}

impl DirectoryArchive {
    /// Файл записи в архиве.
    fn path(&self, tenant: TenantId, id: JournalId) -> PathBuf {
        self.root.join(tenant.to_string()).join(format!("{id}.eml"))
    }
}

#[async_trait]
impl ArchiveSink for DirectoryArchive {
    fn name(&self) -> &'static str {
        "directory"
    }

    async fn deliver(&self, tenant: TenantId, id: JournalId, eml: &[u8]) -> Result<()> {
        let path = self.path(tenant, id);
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await.map_err(|e| {
                tracing::warn!(error = %e, dir = %dir.display(), "журнал: каталог архива не создан");
                Error::UNAVAILABLE
            })?;
        }
        // Перезапись той же записи — тем же содержимым (`journal_eml` детерминирован).
        tokio::fs::write(&path, eml).await.map_err(|e| {
            tracing::warn!(error = %e, path = %path.display(), "журнал: запись архива не сохранена");
            Error::UNAVAILABLE
        })?;
        Ok(())
    }
}

/// Архив на HTTPS-эндпоинте заказчика: `POST {endpoint}/{организация}/{идентификатор}`, тело — `.eml`.
#[derive(Debug, Clone)]
pub struct HttpsArchive {
    /// Базовый адрес приёмника без `/` на конце.
    endpoint: String,
    /// Клиент HTTP (корни CA приёмника, таймаут; `insecure` — только dev).
    http: reqwest::Client,
}

#[async_trait]
impl ArchiveSink for HttpsArchive {
    fn name(&self) -> &'static str {
        "https"
    }

    async fn deliver(&self, tenant: TenantId, id: JournalId, eml: &[u8]) -> Result<()> {
        let url = format!("{}/{tenant}/{id}", self.endpoint);
        let resp = self
            .http
            .post(&url)
            .header(header::CONTENT_TYPE, EML_TYPE)
            .body(eml.to_vec())
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, url = %url, "журнал: выгрузка в архив не удалась");
                Error::UNAVAILABLE
            })?;
        let status = resp.status();
        if !status.is_success() {
            tracing::warn!(status = %status, url = %url, "журнал: архив не принял запись");
            return Err(Error::UNAVAILABLE);
        }
        Ok(())
    }
}

/// Позиция журнала выгрузки организации: граница выгруженных страниц поиска и записи последней
/// неполной страницы (у неё курсора нет — [`JournalPage`](tp_contracts::journal::JournalPage)::`next`
/// есть только у полной).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ArchivePosition {
    /// Курсор поиска, после которого записи ещё не выгружены ([`JournalQuery::after`]); `None` — с начала.
    pub after: Option<JournalCursor>,
    /// Идентификаторы уже выгруженных записей страницы, на которую курсор не сдвинут.
    pub done: BTreeSet<JournalId>,
}

/// Журнал выгрузки внешнего архива (SRS 4.9: повтор по журналу выгрузки): позиция выгруженных записей
/// каждой организации. Постоянный журнал (PostgreSQL, схема `journal`) — волна узла; здесь — контракт и
/// реализация в памяти.
#[async_trait]
pub trait ArchiveLedger: Send + Sync + 'static {
    /// Позиция организации; пустая — выгружать с начала журнала.
    async fn position(&self, tenant: TenantId) -> Result<ArchivePosition>;

    /// Записывает позицию после выгрузки записи или страницы (сбой — позиция на месте, повтор).
    async fn advance(&self, tenant: TenantId, position: ArchivePosition) -> Result<()>;
}

/// Журнал выгрузки в памяти (небольшие установки и тесты); клоны разделяют данные.
#[derive(Debug, Clone, Default)]
pub struct MemArchiveLedger {
    state: Arc<Mutex<BTreeMap<TenantId, ArchivePosition>>>,
}

impl MemArchiveLedger {
    /// Пустой журнал выгрузки.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ArchiveLedger for MemArchiveLedger {
    async fn position(&self, tenant: TenantId) -> Result<ArchivePosition> {
        Ok(self
            .state
            .lock()
            .expect("ledger")
            .get(&tenant)
            .cloned()
            .unwrap_or_default())
    }

    async fn advance(&self, tenant: TenantId, position: ArchivePosition) -> Result<()> {
        self.state.lock().expect("ledger").insert(tenant, position);
        Ok(())
    }
}

/// Один проход выгрузки организации `tenant` в приёмник `sink`: новые записи ([`JournalStore::search`]
/// после позиции журнала выгрузки `ledger`) выгружаются `.eml` с конвертом ([`JournalStore::export`]),
/// каждая — отмечается в `ledger`. Сбой выгрузки — позиции записи нет, следующий проход повторит её
/// (доставку почты проход не затрагивает: его ведёт роль maintenance, как SIEM — [`crate::export`]);
/// повтор выгруженной записи приёмнику не страшен — то же содержимое. Возвращает число выгруженных
/// записей (0 — новых нет).
pub async fn archive_pass(
    store: &dyn JournalStore,
    ledger: &dyn ArchiveLedger,
    sink: &dyn ArchiveSink,
    tenant: TenantId,
    batch: usize,
) -> Result<usize> {
    let cap = JournalAudit::grant();
    let mut position = ledger.position(tenant).await?;
    let mut delivered = 0usize;
    loop {
        let query = JournalQuery {
            tenant,
            limit: batch.max(1),
            after: position.after.clone(),
            ..JournalQuery::all(tenant, batch.max(1))
        };
        let page = store.search(&cap, &query).await?;
        for entry in &page.entries {
            if position.done.contains(&entry.id) {
                continue;
            }
            let eml = store.export(&cap, tenant, entry.id).await?;
            sink.deliver(tenant, entry.id, &eml).await?;
            position.done.insert(entry.id);
            ledger.advance(tenant, position.clone()).await?;
            delivered += 1;
        }
        // Курсор сдвигается только у полной страницы; записи неполной — в `done` журнала выгрузки.
        match page.next {
            Some(next) => {
                position = ArchivePosition {
                    after: Some(next),
                    done: BTreeSet::new(),
                };
                ledger.advance(tenant, position.clone()).await?;
            }
            None => return Ok(delivered),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc as StdArc;

    use axum::http::StatusCode;
    use serde_json::json;
    use time::format_description::well_known::Rfc3339;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tp_contracts::TenantId;
    use tp_contracts::journal::{JournalDirection, JournalRule, JournalRuleStore, JournalScope};

    use crate::testenv::Env;

    use super::*;

    fn at(s: &str) -> OffsetDateTime {
        OffsetDateTime::parse(s, &Rfc3339).expect("time")
    }

    fn url(q: &str) -> String {
        format!("/api/v1/orgs/{}/journal?{q}", TenantId::DEFAULT)
    }

    /// Записи в журнал тестов: две записи организации по умолчанию (конверт с скрытым получателем) и
    /// одна чужой организации.
    async fn seed(env: &Env) -> Vec<JournalId> {
        let d = TenantId::DEFAULT;
        let mut ids = Vec::new();
        for (tenant, sender, rcpt, mid, moment, subject) in [
            (
                d,
                "a@external.example",
                vec!["anna@example.org", "hidden@example.org"],
                "m1@external.example",
                "2026-11-01T10:00:00Z",
                "one",
            ),
            (
                d,
                "b@external.example",
                vec!["bob@example.org"],
                "m2@external.example",
                "2026-11-01T11:00:00Z",
                "two",
            ),
            (
                env.other_tenant,
                "c@external.example",
                vec!["x@other.example"],
                "m3@external.example",
                "2026-11-01T10:30:00Z",
                "other",
            ),
        ] {
            let rule = JournalRule {
                id: "org-all".to_owned(),
                tenant,
                scope: JournalScope::Org,
                direction: JournalDirection::Both,
                enabled: true,
            };
            let record = tp_contracts::journal::JournalRecord {
                tenant,
                sender: sender.to_owned(),
                recipients: rcpt.iter().map(|r| (*r).to_owned()).collect(),
                message_id: Some(mid.to_owned()),
                at: at(moment),
                rule: rule.id.clone(),
            };
            let id = env
                .journal
                .append(
                    &rule,
                    &record,
                    bytes::Bytes::from(
                        format!("Message-ID: <{mid}>\r\nSubject: {subject}\r\n\r\nbody")
                            .into_bytes(),
                    ),
                )
                .await
                .expect("append");
            ids.push(id);
        }
        ids
    }

    /// Приёмка ADM-52: `journal-auditor` ищет по всем условиям запроса, смотрит запись, выгружает `.eml`
    /// с конвертом, проверяет цепочку; `administrator` (организации и инсталляции), оператор, аудитор и
    /// пользовательский токен — 403; чужая организация не видна.
    #[tokio::test]
    async fn journal_auditor_search_get_export_verify() {
        let env = Env::new();
        let ids = seed(&env).await;
        let d = TenantId::DEFAULT;

        // Поиск: записи своей организации в порядке времени, чужая не видна.
        let (s, _, b) = env.call("GET", &url(""), Some("journal"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let entries = b["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 2, "{b}");
        assert_eq!(entries[0]["record"]["sender"], "a@external.example");
        assert_eq!(entries[0]["record"]["recipients"][1], "hidden@example.org");
        assert_eq!(entries[0]["record"]["rule"], "org-all");
        assert_eq!(entries[0]["record"]["at"], "2026-11-01T10:00:00Z");
        assert_eq!(entries[0]["record"]["tenant"], d.to_string());
        assert_eq!(entries[0]["id"], ids[0].to_string());
        assert!(
            entries[0]["hash"].as_str().is_some_and(|h| h.len() == 64),
            "{b}"
        );

        // Условия поиска — по «и»: отправитель, скрытый получатель, Message-ID, правило; регистр не важен.
        for (q, want) in [
            ("sender=A@EXTERNAL.example", 1),
            ("recipient=HIDDEN@example.org", 1),
            ("message_id=m2@external.example", 1),
            ("rule=org-all", 2),
            ("rule=other-rule", 0),
        ] {
            let (s, _, b) = env.call("GET", &url(q), Some("journal"), None).await;
            assert_eq!(s, StatusCode::OK, "{q}: {b}");
            assert_eq!(b["entries"].as_array().expect("entries").len(), want, "{q}");
        }
        let interval = "since=2026-11-01T10:00:00Z&until=2026-11-01T11:00:00Z";
        let (s, _, b) = env.call("GET", &url(interval), Some("journal"), None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["entries"].as_array().expect("entries").len(), 1);

        // Страницы по `after`.
        let (s, _, b) = env
            .call("GET", &url("limit=1"), Some("journal"), None)
            .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b["entries"].as_array().expect("entries").len(), 1);
        // Курсор непрозрачен и может содержать недопустимые в URI символы (вертикальную черту): в запросе —
        // в процентной записи, как его передаёт клиент (reqwest кодирует автоматически).
        let next = b["next"]
            .as_str()
            .expect("next")
            .to_owned()
            .replace('|', "%7C");
        let (_, _, b) = env
            .call(
                "GET",
                &url(&format!("limit=1&after={next}")),
                Some("journal"),
                None,
            )
            .await;
        assert_eq!(b["entries"].as_array().expect("entries").len(), 1);
        assert!(b["next"].is_null());

        // Просмотр записи и выгрузка: `.eml` с конвертом.
        let entry = format!("/api/v1/orgs/{d}/journal/{}", ids[0]);
        let (s, _, b) = env.call("GET", &entry, Some("journal"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["record"]["message_id"], "m1@external.example");
        let (s, _, b) = env
            .call(
                "GET",
                &format!("/api/v1/orgs/{d}/journal/{}", JournalId::new()),
                Some("journal"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{b}");
        let export = format!("{entry}/export");
        let (s, h, b) = env.call("GET", &export, Some("journal"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let eml = b.as_str().expect("тело ответа — текст .eml");
        assert!(
            eml.starts_with("X-ThePost-Journal-Sender: a@external.example\r\n"),
            "{eml}"
        );
        assert!(eml.contains("X-ThePost-Journal-Recipient: hidden@example.org\r\n"));
        assert!(eml.ends_with("Subject: one\r\n\r\nbody"));
        assert_eq!(h[header::CONTENT_TYPE], "message/rfc822");

        // Проверка цепочки: обе записи своей организации, чужая не считается.
        let verify = format!("/api/v1/orgs/{d}/journal/verify");
        let (s, _, b) = env.call("GET", &verify, Some("journal"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["records"], 2);
        assert_eq!(b["ok"], true);
        assert!(b["broken_at"].is_null());

        // Содержимое журнала — только «аудитору журнала».
        for token in ["org", "root", "operator", "auditor", "user"] {
            for path in [
                url("").as_str(),
                entry.as_str(),
                export.as_str(),
                verify.as_str(),
            ] {
                let (s, _, _) = env.call("GET", path, Some(token), None).await;
                assert_eq!(s, StatusCode::FORBIDDEN, "{token} GET {path}");
            }
        }
        // Изменений в журнале нет: POST — 403 (и он записан в аудит слоем доступа).
        let (s, _, _) = env.call("POST", &url(""), Some("journal"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);

        // Другая организация — не его область роли.
        let other = format!("/api/v1/orgs/{}/journal", env.other_tenant);
        let (s, _, _) = env.call("GET", &other, Some("journal"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }

    /// Ошибки запроса: пустой интервал, неизвестный параметр, не UUID записи — 400; журнал не подключён — 503.
    #[tokio::test]
    async fn bad_requests_and_unconnected() {
        let env = Env::new();
        for q in [
            "since=2026-11-02T00:00:00Z&until=2026-11-01T00:00:00Z",
            "color=red",
        ] {
            let (s, _, _) = env.call("GET", &url(q), Some("journal"), None).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{q}");
        }
        let (s, _, _) = env
            .call(
                "GET",
                &format!("/api/v1/orgs/{}/journal/не-uuid", TenantId::DEFAULT),
                Some("journal"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        // Без хранилища журнала маршруты отвечают 503.
        let env = Env::without_journal();
        let (s, _, b) = env.call("GET", &url(""), Some("journal"), None).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
        let verify = format!("/api/v1/orgs/{}/journal/verify", TenantId::DEFAULT);
        let (s, _, _) = env.call("GET", &verify, Some("journal"), None).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Каждое обращение к журналу — запись аудита: кто, маршрут, критерий (строка запроса), сколько
    /// записей с содержимым; отказ администратору (`GET`) — 403 слоя доступа, в аудит не пишется.
    #[tokio::test]
    async fn every_access_is_audited() {
        let env = Env::new();
        let ids = seed(&env).await;
        let d = TenantId::DEFAULT;
        let filtered = url("sender=a@external.example");
        let paths = [
            filtered.clone(),
            format!("/api/v1/orgs/{d}/journal/{}", ids[0]),
            format!("/api/v1/orgs/{d}/journal/{}/export", ids[0]),
            format!("/api/v1/orgs/{d}/journal/verify"),
        ];
        for path in &paths {
            let (s, _, _) = env.call("GET", path, Some("journal"), None).await;
            assert_eq!(s, StatusCode::OK, "{path}");
        }
        let (s, _, _) = env.call("GET", &url(""), Some("org"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);

        let log = env.audit.records();
        assert_eq!(log.len(), 4, "поиск, просмотр, выгрузка, проверка: {log:?}");
        let want = [
            ("/api/v1/orgs/{org}/journal", 1),
            ("/api/v1/orgs/{org}/journal/{id}", 1),
            ("/api/v1/orgs/{org}/journal/{id}/export", 1),
            ("/api/v1/orgs/{org}/journal/verify", 0),
        ];
        for (record, (route, messages)) in log.iter().zip(want) {
            assert_eq!(record.method, "GET", "{}", record.route);
            assert_eq!(record.route, route);
            assert_eq!(record.tenant, Some(d));
            assert_eq!(record.actor_login, "ja@example.org");
            assert_eq!(record.roles, vec!["journal_auditor"]);
            assert_eq!(record.status, 200);
            assert_eq!(record.content_messages, Some(messages));
            assert!(
                record.path.contains(&format!("/orgs/{d}/journal")),
                "{}",
                record.path
            );
        }
        assert!(
            log[0].path.ends_with("?sender=a@external.example"),
            "критерий запроса — в пути: {}",
            log[0].path
        );
    }

    /// Приёмка ADM-52: выгрузка во внешний архив по настройке воспроизводима после сбоя — позиции
    /// выгруженных записей на месте, повтор доставляет ровно недостающее, файлы каталога — `.eml` с
    /// конвертом, HTTPS-приёмник получает POST с телом записи.
    #[tokio::test]
    async fn archive_pass_retries_after_failure() {
        let env = Env::new();
        let d = TenantId::DEFAULT;
        let ids = seed(&env).await;
        let ledger = MemArchiveLedger::new();

        // Приёмник недоступен: проход не удался, журнал выгрузки пуст, записи ждут.
        let sink = FailingSink::down();
        assert!(
            archive_pass(&env.journal, &ledger, &sink, d, 2)
                .await
                .is_err(),
            "приёмник не принимает"
        );
        assert!(sink.delivered().await.is_empty());
        assert_eq!(ledger.position(d).await, Ok(ArchivePosition::default()));

        // После возврата приёмника все записи выгружены по одному разу.
        let ok = OkSink::default();
        let mut total = 0;
        loop {
            let n = archive_pass(&env.journal, &ledger, &ok, d, 2)
                .await
                .expect("pass");
            if n == 0 {
                break;
            }
            total += n;
        }
        assert_eq!(
            total, 2,
            "своя организация — 2 записи, чужая не выгружается"
        );
        assert_eq!(ok.delivered().await, ids[..2].to_vec(), "по одной выгрузке");

        // Новая запись выгружается, старые — нет; после неё выгрузок больше нет.
        let tail = env
            .journal
            .append(
                &JournalRule {
                    id: "org-all".to_owned(),
                    tenant: d,
                    scope: JournalScope::Org,
                    direction: JournalDirection::Both,
                    enabled: true,
                },
                &tp_contracts::journal::JournalRecord {
                    tenant: d,
                    sender: "d@external.example".to_owned(),
                    recipients: vec!["eve@example.org".to_owned()],
                    message_id: None,
                    at: at("2026-11-01T12:00:00Z"),
                    rule: "org-all".to_owned(),
                },
                bytes::Bytes::from_static(b"Subject: four\r\n\r\nbody"),
            )
            .await
            .expect("append");
        assert_eq!(
            archive_pass(&env.journal, &ledger, &ok, d, 2).await,
            Ok(1),
            "только новая запись"
        );
        assert_eq!(ok.delivered().await.last(), Some(&tail));
        assert_eq!(archive_pass(&env.journal, &ledger, &ok, d, 2).await, Ok(0));

        // Выгрузка чужой организации не смешивается.
        let mut other_total = 0;
        loop {
            let n = archive_pass(&env.journal, &ledger, &ok, env.other_tenant, 2)
                .await
                .expect("pass");
            if n == 0 {
                break;
            }
            other_total += n;
        }
        assert_eq!(other_total, 1);

        // Каталог: файлы `{организация}/{идентификатор}.eml` — `.eml` с конвертом.
        let dir = tempfile::tempdir().expect("tempdir");
        let sink = DirectoryArchive {
            root: dir.path().to_owned(),
        };
        let fresh = MemArchiveLedger::new();
        loop {
            let n = archive_pass(&env.journal, &fresh, &sink, d, 2)
                .await
                .expect("pass");
            if n == 0 {
                break;
            }
        }
        for id in &ids[..2] {
            let path = dir.path().join(d.to_string()).join(format!("{id}.eml"));
            let eml = std::fs::read_to_string(&path).expect("файл записи");
            assert!(
                eml.starts_with("X-ThePost-Journal-Sender: "),
                "{}",
                path.display()
            );
        }

        // Приёмник HTTPS отвечает не успехом: проход не удался, позиция на месте (повтор по журналу).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).await.expect("read");
            sock.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("write");
        });
        let sink = HttpsArchive {
            endpoint: format!("http://{address}"),
            http: reqwest::Client::new(),
        };
        let fresh = MemArchiveLedger::new();
        assert!(
            archive_pass(&env.journal, &fresh, &sink, d, 100)
                .await
                .is_err()
        );
        assert_eq!(
            fresh.position(d).await,
            Ok(ArchivePosition::default()),
            "позиция не сдвинута — повтор по журналу выгрузки"
        );
        server.await.expect("join");

        // Успешный приёмник: POST `{endpoint}/{организация}/{идентификатор}` с телом `.eml`; соединение
        // одно — клиент переиспользует его для всех записей прохода.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("addr");
        let server: tokio::task::JoinHandle<Vec<(String, String)>> = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            let mut requests = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                // Заголовки и тело очередного запроса.
                let done = loop {
                    if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..at]).into_owned();
                        let len = head
                            .lines()
                            .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                            .and_then(|l| l.split_once(':'))
                            .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if buf.len() >= at + 4 + len {
                            break (at, len, head);
                        }
                    }
                    let n = sock.read(&mut chunk).await.expect("read");
                    if n == 0 {
                        return requests; // клиент закончил выгрузку и закрыл соединение
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    assert!(buf.len() < 1 << 20, "запрос не разбирается");
                };
                let (at, len, head) = done;
                let body = String::from_utf8_lossy(&buf[at + 4..at + 4 + len]).into_owned();
                sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .expect("write");
                requests.push((head, body));
                buf.drain(..at + 4 + len);
            }
        });
        let sink = HttpsArchive {
            endpoint: format!("http://{address}"),
            http: reqwest::Client::new(),
        };
        let fresh = MemArchiveLedger::new();
        assert_eq!(
            archive_pass(&env.journal, &fresh, &sink, d, 100).await,
            Ok(3),
            "все записи организации выгружены"
        );
        drop(sink); // закрываем пул клиента — соединение закрывается и сервер завершается
        let requests = server.await.expect("join");
        assert_eq!(requests.len(), 3, "по запросу на запись: {requests:?}");
        assert!(
            requests[0].0.starts_with(&format!("POST /{d}/")),
            "{requests:?}"
        );
        assert!(
            requests
                .iter()
                .all(|(_, b)| b.contains("X-ThePost-Journal-Sender: ")),
            "тело запроса — .eml с конвертом: {requests:?}"
        );
    }

    /// Секция `admin.journal_archive`: разбор, проверка (один приёмник, положительные паузы) и запуск
    /// приёмников (открытый канал и `insecure` — только dev).
    #[test]
    fn archive_config() {
        assert!(!JournalArchiveConfig::default().enabled());
        JournalArchiveConfig::default().check().expect("выключена");

        let dir: JournalArchiveConfig = serde_json::from_value(json!({
            "directory": "/var/archives/journal"
        }))
        .expect("directory");
        assert!(dir.enabled());
        dir.check().expect("ok");
        assert_eq!(
            dir.start(Profile::Prod)
                .expect("start")
                .expect("sink")
                .name(),
            "directory"
        );
        assert_eq!(dir.interval, Duration::from_secs(10));
        assert_eq!(dir.batch, 100);

        let https: JournalArchiveConfig = serde_json::from_value(json!({
            "https": {
                "endpoint": "https://archive.example.org/journal/",
                "timeout": "5s"
            }
        }))
        .expect("https");
        https.check().expect("ok");
        assert_eq!(
            https
                .start(Profile::Prod)
                .expect("start")
                .expect("sink")
                .name(),
            "https"
        );
        let sink = https.https.as_ref().expect("https");
        assert_eq!(
            sink.endpoint, "https://archive.example.org/journal/",
            "адрес из секции (слэш срезает [`HttpsArchive`])"
        );
        assert_eq!(https.retry, Duration::from_secs(30));

        let dev: JournalArchiveConfig = serde_json::from_value(json!({
            "https": {"endpoint": "http://127.0.0.1:8080/journal", "insecure": true}
        }))
        .expect("dev");
        assert!(
            dev.start(Profile::Dev).is_ok(),
            "открытый канал — только dev"
        );
        assert!(dev.start(Profile::Prod).is_err());
        let prod: JournalArchiveConfig = serde_json::from_value(json!({
            "https": {"endpoint": "https://archive.example.org", "insecure": true}
        }))
        .expect("insecure");
        assert!(prod.start(Profile::Prod).is_err());
        assert!(prod.start(Profile::Dev).is_ok());

        for bad in [
            json!({"directory": "/a", "https": {"endpoint": "https://a.example"}}),
            json!({"batch": 0}),
            json!({"interval": 0}),
            json!({"https": {"endpoint": "archive.example.org"}}),
            json!({"https": {"endpoint": "https://"}}),
            json!({"https": {"endpoint": "https://a.example", "timeout": 0}}),
            json!({"queue": 10}),
        ] {
            let rejected = match serde_json::from_value::<JournalArchiveConfig>(bad.clone()) {
                Err(_) => true,
                Ok(cfg) => cfg.check().is_err(),
            };
            assert!(rejected, "допустимо: {bad}");
        }
    }

    /// Приёмник, который всегда отказывает; выгруженные записи — для проверок.
    #[derive(Debug, Clone, Default)]
    struct FailingSink {
        delivered: StdArc<Mutex<Vec<JournalId>>>,
        down: StdArc<Mutex<bool>>,
    }

    impl FailingSink {
        fn down() -> Self {
            Self {
                down: StdArc::new(Mutex::new(true)),
                ..Self::default()
            }
        }

        async fn delivered(&self) -> Vec<JournalId> {
            self.delivered.lock().expect("lock").clone()
        }
    }

    #[async_trait]
    impl ArchiveSink for FailingSink {
        fn name(&self) -> &'static str {
            "failing"
        }

        async fn deliver(&self, _tenant: TenantId, id: JournalId, _eml: &[u8]) -> Result<()> {
            if *self.down.lock().expect("lock") {
                return Err(Error::UNAVAILABLE);
            }
            self.delivered.lock().expect("lock").push(id);
            Ok(())
        }
    }

    /// Успешный приёмник: порядок выгруженных записей.
    #[derive(Debug, Clone, Default)]
    struct OkSink(StdArc<Mutex<Vec<JournalId>>>);

    impl OkSink {
        async fn delivered(&self) -> Vec<JournalId> {
            self.0.lock().expect("lock").clone()
        }
    }

    #[async_trait]
    impl ArchiveSink for OkSink {
        fn name(&self) -> &'static str {
            "ok"
        }

        async fn deliver(&self, _tenant: TenantId, id: JournalId, _eml: &[u8]) -> Result<()> {
            self.0.lock().expect("lock").push(id);
            Ok(())
        }
    }

    /// Правила журналирования организации по умолчанию (идентификаторы по порядку списка).
    async fn rule_ids(env: &Env) -> Vec<String> {
        let (s, _, b) = env
            .call(
                "GET",
                &format!("/api/v1/orgs/{}/journal/rules", TenantId::DEFAULT),
                Some("org"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        b["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .map(|r| r["id"].as_str().expect("id").to_owned())
            .collect()
    }

    /// Приёмка ADM-53: администратор организации ведёт правила журналирования — список в порядке
    /// наследования ящик > группа > организация, создание/замена/удаление; область проверена (группа и
    /// ящик существуют), дубликат цели — 409 с подсказкой; изменение видно конвейеру без перезапуска
    /// (порт читает на каждом письме, SMTP-53); аудитор журнала правил не видит (403), оператор —
    /// только чтение, администратор инсталляции — все организации, чужой организации — 403.
    #[tokio::test]
    async fn journal_rules_crud_and_roles() {
        let env = Env::new();
        let d = TenantId::DEFAULT;
        let base = format!("/api/v1/orgs/{d}/journal/rules");
        let acc = env.account("director@example.org").await;
        let group = tp_contracts::GroupId::new();
        env.group(d, "board", group, acc.account).await;

        // Создание: включено по умолчанию, ответ — правило.
        let (s, _, b) = env
            .call(
                "PUT",
                &format!("{base}/all-mail"),
                Some("org"),
                Some(json!({"scope": "org", "direction": "both"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(
            b,
            json!({
                "id": "all-mail", "tenant": d.to_string(), "scope": "org",
                "direction": "both", "enabled": true,
            })
        );
        let (s, _, _) = env
            .call(
                "PUT",
                &format!("{base}/team-in"),
                Some("org"),
                Some(json!({"scope": {"group": group.to_string()}, "direction": "in"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = env
            .call(
                "PUT",
                &format!("{base}/director"),
                Some("org"),
                Some(json!({
                    "scope": {"mailbox": acc.account.to_string()},
                    "direction": "out", "enabled": false
                })),
            )
            .await;
        assert_eq!(s, StatusCode::OK);

        // Список — порядок наследования: ящик > группа > организация.
        assert_eq!(
            rule_ids(&env).await,
            vec!["director", "team-in", "all-mail"]
        );

        // Замена целиком: выключенное правило организации с другим направлением.
        let (s, _, b) = env
            .call(
                "PUT",
                &format!("{base}/all-mail"),
                Some("org"),
                Some(json!({"scope": "org", "direction": "in", "enabled": false})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["enabled"], false);
        assert_eq!(b["direction"], "in");
        assert_eq!(rule_ids(&env).await.len(), 3, "замена, не добавление");

        // Дубликат цели: та же группа с тем же направлением у другого правила — 409 с подсказкой.
        let (s, _, b) = env
            .call(
                "PUT",
                &format!("{base}/team-copy"),
                Some("org"),
                Some(json!({"scope": {"group": group.to_string()}, "direction": "in"})),
            )
            .await;
        assert_eq!(s, StatusCode::CONFLICT, "{b}");
        assert!(
            b["detail"].as_str().expect("detail").contains("team-in"),
            "подсказка: {b}"
        );
        // Та же цель другим направлением — не дубликат.
        let (s, _, _) = env
            .call(
                "PUT",
                &format!("{base}/team-out"),
                Some("org"),
                Some(json!({"scope": {"group": group.to_string()}, "direction": "out"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK);

        // Область существует: чужая группа и ящик — 422 с подсказкой; направление — enum, идентификатор
        // и тело — 400.
        let (s, _, b) = env
            .call(
                "PUT",
                &format!("{base}/ghost-group"),
                Some("org"),
                Some(
                    json!({"scope": {"group": tp_contracts::GroupId::new().to_string()},
                            "direction": "both"}),
                ),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert!(b["detail"].as_str().expect("detail").contains("группа"));
        let (s, _, b) = env
            .call(
                "PUT",
                &format!("{base}/ghost-box"),
                Some("org"),
                Some(
                    json!({"scope": {"mailbox": tp_contracts::AccountId::new().to_string()},
                            "direction": "both"}),
                ),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert!(
            b["detail"]
                .as_str()
                .expect("detail")
                .contains("учётная запись"),
            "{b}"
        );
        for (id, body) in [
            ("sideways", json!({"scope": "org", "direction": "sideways"})),
            ("has%20space", json!({"scope": "org", "direction": "both"})),
        ] {
            let (s, _, b) = env
                .call("PUT", &format!("{base}/{id}"), Some("org"), Some(body))
                .await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{id}: {b}");
        }

        // Удаление: ответ — удалённое правило; повтор — 404.
        let (s, _, b) = env
            .call("DELETE", &format!("{base}/team-in"), Some("org"), None)
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["id"], "team-in");
        assert_eq!(b["scope"], json!({"group": group.to_string()}));
        let (s, _, _) = env
            .call("DELETE", &format!("{base}/team-in"), Some("org"), None)
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        assert_eq!(
            rule_ids(&env).await,
            vec!["director", "team-out", "all-mail"],
            "ящик > группа > организация"
        );

        // Изменение видно конвейеру без перезапуска: порт читает правила на каждом письме (SMTP-53) —
        // то же хранилище, что подключено к Admin API.
        let pipeline = env.journal.rules(d).await.expect("правила");
        assert_eq!(
            pipeline.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
            vec!["all-mail", "director", "team-out"],
            "конвейер прочитает новые правила"
        );
        assert!(
            !pipeline
                .iter()
                .find(|r| r.id == "all-mail")
                .expect("есть")
                .enabled,
            "выключенное правило писем не касается"
        );

        // Право — только администратор организации (и инсталляции): аудитор журнала правил не видит —
        // 403 на чтение и запись, оператор — только чтение, пользователь — 403, чужая организация — 403.
        for method in ["GET", "PUT", "DELETE"] {
            let (s, _, _) = env.call(method, &base, Some("journal"), None).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "аудитор журнала {method}");
        }
        let (s, _, _) = env.call("GET", &base, Some("operator"), None).await;
        assert_eq!(s, StatusCode::OK, "оператор читает");
        let (s, _, _) = env
            .call(
                "PUT",
                &format!("{base}/ops"),
                Some("operator"),
                Some(json!({"scope": "org", "direction": "both"})),
            )
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "оператор не пишет");
        let (s, _, _) = env.call("GET", &base, Some("user"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, _) = env.call("GET", &base, Some("root"), None).await;
        assert_eq!(
            s,
            StatusCode::OK,
            "администратор инсталляции — все организации"
        );
        let other = format!("/api/v1/orgs/{}/journal/rules", env.other_tenant);
        let (s, _, _) = env.call("GET", &other, Some("org"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "чужая организация");
        let (s, _, _) = env
            .call(
                "PUT",
                &format!("{other}/mine"),
                Some("other"),
                Some(json!({"scope": "org", "direction": "both"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "своя организация — администратор другой");

        // Хранилище правил не подключено — 503 (записи журнала при этом не нужны правилам).
        let env = Env::without_journal();
        let (s, _, b) = env
            .call(
                "GET",
                &format!("/api/v1/orgs/{d}/journal/rules"),
                Some("org"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    }

    /// Приёмка ADM-53: каждое изменение правил — запись журнала аудита с деталями «было → стало»
    /// (кто/что менял), отказ аудитору журнала — 403 слоя доступа (тоже с записью).
    #[tokio::test]
    async fn journal_rules_changes_are_audited() {
        let env = Env::new();
        let d = TenantId::DEFAULT;
        let base = format!("/api/v1/orgs/{d}/journal/rules");
        let put = |id: &str, direction: &str, enabled: bool| {
            (
                format!("{base}/{id}"),
                json!({"scope": "org", "direction": direction, "enabled": enabled}),
            )
        };

        // Создание: from — null, to — новое правило.
        let (path, body) = put("all-mail", "both", true);
        let (s, _, _) = env.call("PUT", &path, Some("org"), Some(body)).await;
        assert_eq!(s, StatusCode::OK);
        // Замена: from — прежнее, to — новое.
        let (path, body) = put("all-mail", "in", false);
        let (s, _, _) = env.call("PUT", &path, Some("org"), Some(body)).await;
        assert_eq!(s, StatusCode::OK);
        // Отказ аудитору журнала — тоже запись (слой доступа).
        let (s, _, _) = env.call("DELETE", &path, Some("journal"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        // Удаление: from — прежнее, to — null.
        let (s, _, _) = env.call("DELETE", &path, Some("org"), None).await;
        assert_eq!(s, StatusCode::OK);

        let log = env.audit.records();
        assert_eq!(log.len(), 4, "GET списка в аудит не пишется: {log:?}");
        let statuses: Vec<u16> = log.iter().map(|r| r.status).collect();
        let details: Vec<Option<AuditDetails>> = log.iter().map(|r| r.details.clone()).collect();
        assert_eq!(statuses, vec![200, 200, 403, 200]);
        for record in &log {
            assert_eq!(record.route, JOURNAL_RULES_ITEM_ROUTE, "{record:?}");
            assert_eq!(record.tenant, Some(d));
        }
        assert_eq!(log[0].method, "PUT");
        assert_eq!(log[1].method, "PUT");
        assert_eq!(log[2].method, "DELETE");
        assert_eq!(log[3].method, "DELETE");
        assert_eq!(log[0].actor_login, "admin@example.org");
        assert_eq!(log[0].roles, vec!["organization_admin"]);
        assert_eq!(log[2].roles, vec!["journal_auditor"]);
        let what = |d: &Option<AuditDetails>| -> String {
            serde_json::to_value(d).expect("json")["what"]
                .as_str()
                .expect("what")
                .to_owned()
        };
        assert_eq!(what(&details[0]), "journal_rule");
        assert_eq!(what(&details[1]), "journal_rule");
        assert_eq!(details[2], None, "отказ — без деталей");
        assert_eq!(what(&details[3]), "journal_rule");
        let field = |i: usize, name: &str| -> serde_json::Value {
            serde_json::to_value(&details[i]).expect("json")[name].clone()
        };
        // Создание: не было → новое; замена: прежнее → новое; удаление: прежнее → нет.
        assert!(field(0, "from").is_null());
        assert_eq!(field(0, "to")["direction"], "both");
        assert_eq!(field(1, "from")["direction"], "both");
        assert_eq!(field(1, "to")["direction"], "in");
        assert_eq!(field(1, "to")["enabled"], false);
        assert_eq!(field(3, "from")["direction"], "in");
        assert!(field(3, "to").is_null());
    }
}
