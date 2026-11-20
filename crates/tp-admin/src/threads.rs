//! Беседы учётных записей в Admin API (SRS 5.2; ADM-50, решение 125 е): беседа письма, удержание беседы
//! целиком и выгрузка (как Google Vault). Беседа — объект JMAP Thread с неизменяемым `threadId` (RFC 8621 §3);
//! хранилище — контракт [`ThreadStore`] (CTR-94, `tp-testkit::MemThreads` / `tp-meta`, META-86), привязку писем
//! ведёт приём (`MS-21`) — Admin API читает готовое и меняет только удержание.
//!
//! - `GET /api/v1/orgs/{org}/accounts/{account}/threads?message_id=…` — беседа письма ([`ThreadStore::thread_of`]):
//!   удержание и письма в порядке привязки; письма у учётной записи нет — 404.
//! - `PUT|DELETE /api/v1/orgs/{org}/accounts/{account}/threads/{thread}/hold` — удержать (тело — основание,
//!   [`ThreadHoldBody`]) и снять ([`ThreadStore::set_hold`]). Удержание действует на все письма беседы, включая
//!   будущие: окончательное удаление запретит хук базовой поставки [`ThreadHoldHook`] (CTR-94) — после снятия
//!   письма снова удаляются по сроку корзины.
//! - `GET /api/v1/orgs/{org}/holds` — удержанные беседы организации: кто, когда и основание.
//! - `GET /api/v1/orgs/{org}/accounts/{account}/threads/{thread}/export` — выгрузка беседы: письма `.eml` в архиве
//!   ZIP (до `admin.max_page_size`), в том числе удалённые в корзину и скрытые «очисткой корзины»
//!   (`trash.purge: hide`); окончательно стёртых писем объекта уже нет. Обращение — запись журнала аудита с числом
//!   писем ([`AdminAuditRecord::content_messages`], как доступ к содержимому, [`crate::content`]); запись не
//!   сохранена — архив не отдаётся.
//!
//! Права: администраторы организации и установки, `GET` (кроме выгрузки) — и оператор. Выгрузка отдаёт письма
//! целиком — только администраторам (как `include=subject`, ADM-19), отказ оператору пишется в аудит. Беседы не
//! пересекаются между учётными записями и организациями (CTR-94): письмо чужой учётной записи — 404, чужая
//! организация — 403 слоя доступа. Основание удержания хранит само удержание ([`ThreadHold`], видно в `GET`
//! маршрутах); в записи аудита изменения — кто и какая беседа (шаблон маршрута и путь), без содержимого писем:
//! детали записи — закрытый список контракта (решение владельца 19.11), расширение — вопрос полосы contracts.
//! Список `GET …/holds` строит по журналу аудита своих операций (удержания меняет только Admin API; модуль
//! «Соответствие требованиям» ведёт свой учёт) и сверяет с хранилищем. Хранилище бесед не подключено
//! ([`Admin::with_threads`]) — 503.

use std::collections::BTreeMap;
use std::io::Write as _;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{MatchedPath, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::routing::{get, put};
use axum::{Extension, Router};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tp_contracts::admin_audit::AdminAuditQuery;
use tp_contracts::blob::ByteStream;
use tp_contracts::meta::{AccountScope, Message};
use tp_contracts::thread::{ThreadHold, ThreadStore};
use tp_contracts::{AccountId, Error, MessageId, Result, TenantId, ThreadId};
use utoipa::{IntoParams, OpenApi, ToSchema};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::accounts::account;
use crate::content::Access;
use crate::extract::{Json, Path, Query};
use crate::server::{Admin, ApiResult, Caller, Problem};

/// Шаблон маршрута беседы письма.
pub const THREADS_ROUTE: &str = "/api/v1/orgs/{org}/accounts/{account}/threads";

/// Шаблон маршрута удержания беседы.
pub const THREAD_HOLD_ROUTE: &str = "/api/v1/orgs/{org}/accounts/{account}/threads/{thread}/hold";

/// Шаблон маршрута выгрузки беседы.
pub const THREAD_EXPORT_ROUTE: &str =
    "/api/v1/orgs/{org}/accounts/{account}/threads/{thread}/export";

/// Шаблон маршрута удержанных бесед организации.
pub const HOLDS_ROUTE: &str = "/api/v1/orgs/{org}/holds";

/// Тип содержимого выгрузки беседы.
const ZIP_TYPE: &str = "application/zip";

/// Удержание беседы в ответе API ([`ThreadHold`] контракта CTR-94; обе стороны serde).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ThreadHoldView {
    /// Кто удержал (имя входа администратора).
    pub by: String,
    /// Когда установлено (UTC).
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub at: OffsetDateTime,
    /// Основание (дело, требование, регламент).
    pub reason: String,
}

impl From<&ThreadHold> for ThreadHoldView {
    fn from(h: &ThreadHold) -> Self {
        Self {
            by: h.by.clone(),
            at: h.at,
            reason: h.reason.clone(),
        }
    }
}

/// Беседа письма: удержание и письма в порядке привязки.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ThreadView {
    /// Беседа (UUID); `threadId` письма неизменяем (RFC 8621 §3).
    pub thread: String,
    /// Удержание беседы (решение 125 е); `null` — не удержана.
    pub hold: Option<ThreadHoldView>,
    /// Письма беседы в порядке привязки (до `admin.max_page_size`).
    pub messages: Vec<String>,
}

/// Тело удержания беседы: основание.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ThreadHoldBody {
    /// Основание (дело, требование, регламент): 1–1000 символов без управляющих ([`ThreadHold::validate`]).
    pub reason: String,
}

/// Удержанная беседа организации.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ThreadHoldEntryView {
    /// Учётная запись (UUID).
    pub account: String,
    /// Беседа (UUID).
    pub thread: String,
    /// Удержание.
    pub hold: ThreadHoldView,
}

/// Удержанные беседы организации.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ThreadHoldsView {
    /// Удержанные беседы в порядке удержания (`at`).
    pub holds: Vec<ThreadHoldEntryView>,
}

/// Параметры поиска беседы письма.
#[derive(Debug, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct ThreadFindParams {
    /// Письмо учётной записи (UUID, из списков корзины и очереди модерации), чья беседа; без параметра — 400.
    #[param(value_type = Option<String>)]
    pub message_id: Option<MessageId>,
}

/// Хранилище бесед; не подключено — 503.
fn store(a: &Admin) -> ApiResult<&dyn ThreadStore> {
    Ok(a.threads.as_deref().ok_or(Error::UNAVAILABLE)?)
}

/// Маршруты бесед.
pub(crate) fn routes(r: Router<Arc<Admin>>) -> Router<Arc<Admin>> {
    r.route(THREADS_ROUTE, get(find_thread))
        .route(THREAD_HOLD_ROUTE, put(hold_thread).delete(unhold_thread))
        .route(THREAD_EXPORT_ROUTE, get(export_thread))
        .route(HOLDS_ROUTE, get(list_thread_holds))
}

/// Спецификация OpenAPI маршрутов модуля.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        find_thread,
        hold_thread,
        unhold_thread,
        export_thread,
        list_thread_holds
    ),
    components(schemas(
        ThreadView,
        ThreadHoldView,
        ThreadHoldEntryView,
        ThreadHoldsView,
        ThreadHoldBody
    ))
)]
pub(crate) struct Doc;

/// Беседа письма: удержание и письма в порядке привязки; письма у учётной записи нет — 404.
#[utoipa::path(get, path = "/api/v1/orgs/{org}/accounts/{account}/threads", tag = "threads",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("account" = String, Path, description = "Учётная запись (UUID)"), ThreadFindParams),
    responses((status = 200, body = ThreadView), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 503, body = Problem)))]
async fn find_thread(
    State(a): State<Arc<Admin>>,
    Path((org, id)): Path<(TenantId, AccountId)>,
    Query(q): Query<ThreadFindParams>,
) -> ApiResult<Json<ThreadView>> {
    let message = q.message_id.ok_or_else(|| {
        Error::invalid("message_id: укажите письмо учётной записи (UUID), чью беседу найти")
    })?;
    account(&a, org, id).await?;
    let scope = AccountScope {
        tenant: org,
        account: id,
    };
    let threads = store(&a)?;
    let thread = threads
        .thread_of(scope, message)
        .await?
        .ok_or(Error::NotFound)?;
    Ok(Json(
        view(threads, a.cfg.max_page_size, scope, thread).await?,
    ))
}

/// Беседа с удержанием и письмами (до `limit`).
async fn view(
    threads: &dyn ThreadStore,
    limit: usize,
    scope: AccountScope,
    thread: ThreadId,
) -> Result<ThreadView> {
    let hold = threads.hold(scope, thread).await?;
    let messages = threads.messages(scope, thread, limit).await?;
    Ok(ThreadView {
        thread: thread.to_string(),
        hold: hold.as_ref().map(Into::into),
        messages: messages.iter().map(ToString::to_string).collect(),
    })
}

/// Удерживает беседу (решение 125 е): все письма, включая будущие, не удаляются окончательно ([`ThreadHoldHook`]); повторное удержание заменяет основание. Беседы нет — 404.
#[utoipa::path(put, path = "/api/v1/orgs/{org}/accounts/{account}/threads/{thread}/hold", tag = "threads",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("account" = String, Path, description = "Учётная запись (UUID)"),
        ("thread" = String, Path, description = "Беседа (UUID)")),
    request_body = ThreadHoldBody,
    responses((status = 200, body = ThreadHoldView), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 503, body = Problem)))]
async fn hold_thread(
    State(a): State<Arc<Admin>>,
    Extension(caller): Extension<Caller>,
    Path((org, id, thread)): Path<(TenantId, AccountId, ThreadId)>,
    Json(body): Json<ThreadHoldBody>,
) -> ApiResult<Json<ThreadHoldView>> {
    account(&a, org, id).await?;
    let hold = ThreadHold {
        by: caller.principal.login.clone(),
        at: OffsetDateTime::now_utc(),
        reason: body.reason,
    };
    hold.validate()?;
    let scope = AccountScope {
        tenant: org,
        account: id,
    };
    store(&a)?
        .set_hold(scope, thread, Some(hold.clone()))
        .await?;
    Ok(Json((&hold).into()))
}

/// Снимает удержание: письма беседы снова удаляются окончательно по сроку корзины. Беседы нет — 404.
#[utoipa::path(delete, path = "/api/v1/orgs/{org}/accounts/{account}/threads/{thread}/hold", tag = "threads",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("account" = String, Path, description = "Учётная запись (UUID)"),
        ("thread" = String, Path, description = "Беседа (UUID)")),
    responses((status = 204), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 503, body = Problem)))]
async fn unhold_thread(
    State(a): State<Arc<Admin>>,
    Path((org, id, thread)): Path<(TenantId, AccountId, ThreadId)>,
) -> ApiResult<StatusCode> {
    account(&a, org, id).await?;
    let scope = AccountScope {
        tenant: org,
        account: id,
    };
    store(&a)?.set_hold(scope, thread, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Удержанные беседы организации: кто, когда и основание, в порядке удержания. Удержания меняет только Admin API — список строится по журналу аудита операций удержания и сверяется с хранилищем бесед.
#[utoipa::path(get, path = "/api/v1/orgs/{org}/holds", tag = "threads",
    params(("org" = String, Path, description = "Организация (UUID)")),
    responses((status = 200, body = ThreadHoldsView), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 503, body = Problem)))]
async fn list_thread_holds(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
) -> ApiResult<Json<ThreadHoldsView>> {
    let threads = store(&a)?;
    let mut holds = Vec::new();
    for (id, thread) in held(&a, org).await? {
        let scope = AccountScope {
            tenant: org,
            account: id,
        };
        if let Some(hold) = threads.hold(scope, thread).await? {
            holds.push(ThreadHoldEntryView {
                account: id.to_string(),
                thread: thread.to_string(),
                hold: (&hold).into(),
            });
        }
    }
    holds.sort_by(|x, y| {
        (x.hold.at, &x.account, &x.thread).cmp(&(y.hold.at, &y.account, &y.thread))
    });
    Ok(Json(ThreadHoldsView { holds }))
}

/// Удержанные беседы организации по журналу аудита ([`THREAD_HOLD_ROUTE`]): последняя успешная операция каждой
/// беседы решает — удержана (`PUT`) или снята (`DELETE`); порядок журнала — возрастание номера записи.
async fn held(a: &Admin, org: TenantId) -> Result<Vec<(AccountId, ThreadId)>> {
    let mut after = None;
    let mut state = BTreeMap::new();
    loop {
        let query = AdminAuditQuery {
            route_prefix: Some(THREAD_HOLD_ROUTE.to_owned()),
            after,
            ..AdminAuditQuery::first(a.cfg.max_page_size)
        };
        let page = a.d.audit_log.search(org, &query).await?;
        for e in &page.entries {
            if (200..300).contains(&e.record.status)
                && let Some(target) = hold_target(org, &e.record.path)
            {
                state.insert(target, e.record.method == "PUT");
            }
        }
        match page.next {
            Some(next) => after = Some(next),
            None => {
                return Ok(state
                    .into_iter()
                    .filter(|(_, held)| *held)
                    .map(|(t, _)| t)
                    .collect());
            }
        }
    }
}

/// Учётная запись и беседа из пути запроса удержания (шаблон [`THREAD_HOLD_ROUTE`]).
fn hold_target(org: TenantId, path: &str) -> Option<(AccountId, ThreadId)> {
    let rest = path.strip_prefix("/api/v1/orgs/")?;
    let mut parts = rest.split('/');
    if parts.next()? != org.to_string() || parts.next()? != "accounts" {
        return None;
    }
    let account = parts.next()?.parse().ok()?;
    if parts.next()? != "threads" {
        return None;
    }
    let thread = parts.next()?.parse().ok()?;
    (parts.next()? == "hold").then_some((account, thread))
}

/// Выгрузка беседы: письма `.eml` в архиве ZIP, в порядке привязки, включая удалённые в корзину и скрытые «очисткой корзины»; окончательно стёртых писем объекта нет. Обращение — в журнал аудита, запись не сохранена — архив не отдаётся. Содержимое — только администраторам (отказ — в аудит).
#[utoipa::path(get, path = "/api/v1/orgs/{org}/accounts/{account}/threads/{thread}/export", tag = "threads",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("account" = String, Path, description = "Учётная запись (UUID)"),
        ("thread" = String, Path, description = "Беседа (UUID)")),
    responses((status = 200, description = "архив ZIP с письмами беседы (.eml)", content_type = "application/zip"),
        (status = 400, body = Problem), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn export_thread(
    State(a): State<Arc<Admin>>,
    Extension(caller): Extension<Caller>,
    route: MatchedPath,
    uri: Uri,
    Path((org, id, thread)): Path<(TenantId, AccountId, ThreadId)>,
) -> ApiResult<(HeaderMap, Vec<u8>)> {
    account(&a, org, id).await?;
    let access = Access {
        caller: &caller,
        org,
        route: route.as_str(),
        path: uri.path(),
    };
    access.check(&a).await?;
    let scope = AccountScope {
        tenant: org,
        account: id,
    };
    let messages = store(&a)?
        .messages(scope, thread, a.cfg.max_page_size)
        .await?;
    // Беседа без писем — чужая или несуществующая (беседа создаётся письмом, CTR-94).
    if messages.is_empty() {
        return Err(Error::NotFound.into());
    }
    let mut zip = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    let mut exported = 0usize;
    for (i, message) in messages.iter().enumerate() {
        let Some(eml) = export_message(&a, scope, *message).await? else {
            continue; // окончательно стёрто — объекта нет
        };
        zip.start_file(format!("{}-{message}.eml", i + 1), options)
            .map_err(zip_error)?;
        zip.write_all(&eml).map_err(zip_error)?;
        exported += 1;
    }
    let bytes = zip.finish().map_err(zip_error)?.into_inner();
    access.record(&a, 200, exported).await?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(ZIP_TYPE));
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename={thread}.zip"))
            .map_err(|e| Error::internal(format!("заголовок Content-Disposition: {e}")))?,
    );
    Ok((headers, bytes))
}

/// Письмо беседы для выгрузки: исходные байты ([`MailStore::fetch_raw`](tp_contracts::mailstore::MailStore::fetch_raw),
/// видно и удалённое в корзину); скрытое «очисткой корзины» письмо собирается из объектов ([`hidden_eml`]);
/// окончательно стёртое — `None`.
async fn export_message(
    a: &Admin,
    scope: AccountScope,
    message: MessageId,
) -> Result<Option<Vec<u8>>> {
    let eml = match a.d.store.fetch_raw(scope, message, None).await {
        Ok(stream) => read_all(stream).await?,
        // Скрытое письмо хранилище писем не отдаёт (CTR-38) — метаданные и объекты у корзины.
        Err(Error::NotFound) => match a.d.trash.hidden_message(scope, message).await? {
            Some(m) => hidden_eml(a, &m).await?,
            None => return Ok(None),
        },
        Err(e) => return Err(e),
    };
    Ok(Some(eml))
}

/// Скрытое письмо собирается из объекта-скелета и объектов частей — как `fetch_raw`, который скрытые письма не
/// видит. Читатель объектов узла ([`Admin`] `held_blobs`, у узла — с распаковкой) не подключён — конверт из
/// метаданных письма ([`stub_eml`]): снимать скрытие выгрузка не должна.
async fn hidden_eml(a: &Admin, m: &Message) -> Result<Vec<u8>> {
    let Some(blobs) = a.held_blobs.as_deref() else {
        return Ok(stub_eml(m));
    };
    let skeleton = read_all(blobs.get(&m.skeleton, None).await?).await?;
    let skeleton = tp_mailstore::split::Skeleton::decode(skeleton.into())?;
    let mut out = Vec::with_capacity(skeleton.size() as usize);
    for seg in skeleton.segments() {
        match seg {
            tp_mailstore::split::Segment::Inline { data, .. } => out.extend_from_slice(data),
            tp_mailstore::split::Segment::Part { path, len, .. } => {
                let part = m.parts.iter().find(|p| p.part == *path).ok_or_else(|| {
                    Error::internal("экспорт беседы: части письма нет в метаданных")
                })?;
                let bytes = read_all(blobs.get(&part.blob, Some(0..*len)).await?).await?;
                out.extend_from_slice(&bytes);
            }
        }
    }
    Ok(out)
}

/// Конверт скрытого письма из метаданных (читатель объектов не подключён): заголовки без тела — тело скрытого
/// письма контракт `MailStore` не отдаёт, а снимать скрытие выгрузка не должна.
fn stub_eml(m: &Message) -> Vec<u8> {
    let e = &m.meta.envelope;
    let address = |list: &[tp_contracts::meta::Address]| {
        list.iter()
            .map(|a| match a.name.as_deref().map(str::trim) {
                Some(n) if !n.is_empty() => format!("{n} <{}>", a.email),
                _ => a.email.clone(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut out = String::new();
    for (name, value) in [
        // `Envelope::message_id` хранит идентификатор уже в угловых скобках (tp-mailstore).
        ("Message-ID", e.message_id.clone()),
        ("From", (!e.from.is_empty()).then(|| address(&e.from))),
        ("To", (!e.to.is_empty()).then(|| address(&e.to))),
        ("Subject", e.subject.clone()),
        (
            "Date",
            m.received_at
                .format(&time::format_description::well_known::Rfc2822)
                .ok(),
        ),
    ] {
        if let Some(value) = value {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    out.push_str("X-ThePost-Thread-Export: hidden (headers only)\r\n\r\n");
    out.into_bytes()
}

/// Поток байтов целиком.
async fn read_all(stream: ByteStream) -> Result<Vec<u8>> {
    axum::body::to_bytes(Body::from_stream(stream), usize::MAX)
        .await
        .map(|b| b.to_vec())
        .map_err(|e| Error::internal(format!("экспорт беседы: чтение письма: {e}")))
}

/// Ошибка архива.
fn zip_error(e: impl std::fmt::Display) -> Error {
    Error::internal(format!("экспорт беседы: архив ZIP: {e}"))
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use axum::http::StatusCode;
    use serde_json::{Value, json};
    use tp_contracts::ext::{Decision, DecisionHook, DecisionHooks, FinalDelete};
    use tp_contracts::mailstore::MailStore as _;
    use tp_contracts::meta::SpecialUse;
    use tp_contracts::retention::TrashStore as _;
    use tp_contracts::thread::ThreadHoldHook;

    use super::*;
    use crate::testenv::Env;

    fn threads(account: AccountId) -> String {
        format!(
            "/api/v1/orgs/{}/accounts/{account}/threads",
            TenantId::DEFAULT
        )
    }

    /// Беседа письма из `GET …/threads?message_id=…`.
    async fn thread_of(
        env: &Env,
        scope: tp_contracts::meta::AccountScope,
        message: MessageId,
    ) -> String {
        let (s, _, b) = env
            .call(
                "GET",
                &format!("{}?message_id={message}", threads(scope.account)),
                Some("org"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        b["thread"].as_str().expect("thread").to_owned()
    }

    /// Приёмка ADM-50: беседа письма — удержание и письма; удержание накрывает письмо, пришедшее после
    /// (`before_final_delete` — `Deny`), снятие — снова `Allow`; операции — в журнале аудита.
    #[tokio::test]
    async fn hold_covers_later_messages_until_released() {
        let env = Env::new();
        let scope = env.account("user@example.org").await;

        // Первое письмо — новая беседа; удержание: основание — в теле, пустое — 400, повторное — заменяет.
        let first = env
            .deliver_threaded(scope, "a@external.example", None, "первое")
            .await;
        let (s, _, b) = env
            .call(
                "GET",
                &format!("{}?message_id={first}", threads(scope.account)),
                Some("org"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let thread = b["thread"].as_str().expect("thread").to_owned();
        assert_eq!(b["hold"], Value::Null, "{b}");
        assert_eq!(b["messages"], json!([first.to_string()]), "{b}");

        let hold = format!("{}/{thread}/hold", threads(scope.account));
        let (s, _, b) = env
            .call("PUT", &hold, Some("org"), Some(json!({"reason": ""})))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        let (s, _, b) = env
            .call(
                "PUT",
                &hold,
                Some("org"),
                Some(json!({"reason": "дело №42"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["reason"], "дело №42");
        assert_eq!(b["by"], "admin@example.org");
        assert!(b["at"].as_str().is_some_and(|t| t.ends_with('Z')), "{b}");

        // Письмо, пришедшее после удержания, — в той же беседе и тоже удержано: хук запрещает окончательное
        // удаление, пока удержание стоит (без беседы в записи находит по письму, CTR-94).
        let reply = env
            .deliver_threaded(
                scope,
                "b@external.example",
                Some("a@external.example"),
                "ответ",
            )
            .await;
        let (s, _, b) = env
            .call(
                "GET",
                &format!("{}?message_id={reply}", threads(scope.account)),
                Some("org"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["thread"], thread, "{b}");
        assert_eq!(b["hold"]["reason"], "дело №42", "{b}");
        assert_eq!(
            b["messages"],
            json!([first.to_string(), reply.to_string()]),
            "{b}"
        );
        let hook = ThreadHoldHook::new(Arc::new(env.threads.clone()));
        let op = |message: MessageId| FinalDelete {
            scope,
            mailbox: env
                .meta
                .mailbox_by_role(scope, SpecialUse::Trash)
                .expect("корзина"),
            message,
            received_at: OffsetDateTime::now_utc(),
            thread: None,
        };
        for message in [first, reply] {
            assert_eq!(
                hook.before_final_delete(&op(message)).await,
                Ok(Decision::Deny("thread hold: дело №42".into())),
                "удержана вся беседа, включая письмо после удержания"
            );
        }

        // Снятие: снова `Allow` — письма удаляются окончательно по сроку корзины; повторное снятие — 204.
        let (s, _, _) = env.call("DELETE", &hold, Some("org"), None).await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (_, _, b) = env
            .call(
                "GET",
                &format!("{}?message_id={first}", threads(scope.account)),
                Some("org"),
                None,
            )
            .await;
        assert_eq!(b["hold"], Value::Null, "{b}");
        assert_eq!(
            hook.before_final_delete(&op(reply)).await,
            Ok(Decision::Allow)
        );
        let (s, _, _) = env.call("DELETE", &hold, Some("org"), None).await;
        assert_eq!(
            s,
            StatusCode::NO_CONTENT,
            "повторное снятие — без изменений"
        );

        // Операции — в журнале аудита: кто, какая беседа (путь), без содержимого писем.
        let log: Vec<_> = env
            .audit
            .records()
            .into_iter()
            .filter(|r| r.path == hold)
            .collect();
        assert_eq!(
            log.len(),
            4,
            "два удержания, снятие, повтор снятия: {log:?}"
        );
        // Неудачная попытка (пустое основание) тоже в журнале — первой записью.
        assert_eq!((log[0].method.as_str(), log[0].status), ("PUT", 400));
        assert_eq!((log[1].method.as_str(), log[1].status), ("PUT", 200));
        assert_eq!(log[1].actor_login, "admin@example.org");
        assert_eq!(log[1].tenant, Some(TenantId::DEFAULT));
        assert!(log.iter().all(|r| r.content_messages.is_none()));
        assert!(
            log.iter()
                .all(|r| !serde_json::to_string(r).expect("json").contains("первое"))
        );

        // Несуществующая беседа — 404.
        let (s, _, _) = env
            .call(
                "PUT",
                &format!("{}/{}/hold", threads(scope.account), ThreadId::new()),
                Some("org"),
                Some(json!({"reason": "нет беседы"})),
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    /// Приёмка ADM-50: выгрузка беседы — письма `.eml` в архиве ZIP, включая удалённые в корзину и скрытые
    /// «очисткой корзины» (собраны из объектов, как `fetch_raw`); обращение — в журнале аудита с числом писем;
    /// оператору содержимое — 403 с записью в аудит.
    #[tokio::test]
    async fn export_includes_trashed_and_hidden() {
        let env = Env::new();
        let scope = env.account("user@example.org").await;
        let first = env
            .deliver_threaded(scope, "a@external.example", None, "первое")
            .await;
        let reply = env
            .deliver_threaded(
                scope,
                "b@external.example",
                Some("a@external.example"),
                "ответ",
            )
            .await;
        let thread = thread_of(&env, scope, first).await;
        env.call(
            "PUT",
            &format!("{}/{thread}/hold", threads(scope.account)),
            Some("org"),
            Some(json!({"reason": "дело №7"})),
        )
        .await;

        // Одно письмо — в корзине (видимое), другое скрыто «очисткой корзины» (`trash.purge: hide`).
        env.store
            .delete_to_trash(scope, &[first, reply])
            .await
            .expect("trash");
        env.trash
            .purge(scope, &[reply], &DecisionHooks::default())
            .await
            .expect("purge");
        assert!(
            env.store.fetch_raw(scope, reply, None).await.is_err(),
            "скрытое письмо хранилище не отдаёт"
        );

        let export = format!("{}/{thread}/export", threads(scope.account));
        let (s, h, zip) = env.call_raw("GET", &export, Some("org"), None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], ZIP_TYPE);
        assert_eq!(
            h[header::CONTENT_DISPOSITION],
            format!("attachment; filename={thread}.zip")
        );
        let names = entries(&zip);
        assert_eq!(
            names,
            vec![format!("1-{first}.eml"), format!("2-{reply}.eml")],
            "{names:?}"
        );
        // Письмо из корзины — исходные байты; скрытое — собрано из объекта-скелета и частей.
        let visible = String::from_utf8(read_entry(&zip, &names[0])).expect("eml");
        assert!(visible.contains("Subject: первое"), "{visible}");
        assert!(visible.ends_with("body\r\n"), "{visible}");
        let hidden = String::from_utf8(read_entry(&zip, &names[1])).expect("eml");
        assert!(hidden.contains("Subject: ответ"), "{hidden}");
        assert!(
            hidden.contains("Message-ID: <b@external.example>"),
            "{hidden}"
        );
        assert!(hidden.ends_with("body\r\n"), "{hidden}");

        // Обращение — в журнале аудита: два письма выданы, тем в записи нет.
        let log: Vec<_> = env
            .audit
            .records()
            .into_iter()
            .filter(|r| r.path == export)
            .collect();
        assert_eq!(log.len(), 1, "{log:?}");
        assert_eq!(log[0].method, "GET");
        assert_eq!(log[0].content_messages, Some(2));
        assert!(
            !serde_json::to_string(&log[0])
                .expect("json")
                .contains("первое"),
            "тем в аудите нет"
        );

        // Оператору выгрузка — 403 (содержимое писем — только администраторам, как `include=subject`),
        // отказ — запись аудита без писем; несуществующая беседа — 404.
        let (s, _, _) = env.call("GET", &export, Some("operator"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert_eq!(
            env.audit.records().last().expect("audit").content_messages,
            Some(0),
            "отказ оператору — запись с нулём писем"
        );
        let ghost = format!("{}/{}/export", threads(scope.account), ThreadId::new());
        let (s, _, _) = env.call("GET", &ghost, Some("org"), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    /// Имена записей архива в порядке добавления.
    fn entries(zip: &[u8]) -> Vec<String> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip)).expect("архив");
        (0..archive.len())
            .map(|i| {
                archive
                    .by_index(i)
                    .expect("запись")
                    .name()
                    .expect("имя")
                    .into_owned()
            })
            .collect()
    }

    /// Содержимое записи архива.
    fn read_entry(zip: &[u8], name: &str) -> Vec<u8> {
        let mut archive = zip::ZipArchive::new(std::io::Cursor::new(zip)).expect("архив");
        let mut out = Vec::new();
        archive
            .by_name(name)
            .expect("запись")
            .read_to_end(&mut out)
            .expect("чтение");
        out
    }

    /// Приёмка ADM-50: список удержанных бесед организации — кто, когда и основание; снятое исчезает;
    /// права — администраторы и оператор (чтение), аудитор журнала и пользовательский токен — нет.
    #[tokio::test]
    async fn holds_list_and_rights() {
        let env = Env::new();
        let one = env.account("one@example.org").await;
        let two = env.account("two@example.org").await;
        let holds = format!("/api/v1/orgs/{}/holds", TenantId::DEFAULT);

        // Две беседы двух учётных записей с разными основаниями.
        let mut held = Vec::new();
        for (scope, reason) in [(one, "дело №1"), (two, "дело №2")] {
            let message = env
                .deliver_threaded(scope, "x@external.example", None, "письмо")
                .await;
            let thread = thread_of(&env, scope, message).await;
            let (s, _, b) = env
                .call(
                    "PUT",
                    &format!("{}/{thread}/hold", threads(scope.account)),
                    Some("org"),
                    Some(json!({"reason": reason})),
                )
                .await;
            assert_eq!(s, StatusCode::OK, "{b}");
            held.push((scope.account, thread));
        }

        // Администратор установки, организации и оператор читают список.
        for token in ["root", "org", "operator"] {
            let (s, _, b) = env.call("GET", &holds, Some(token), None).await;
            assert_eq!(s, StatusCode::OK, "{token}: {b}");
            let list = b["holds"].as_array().expect("holds");
            assert_eq!(list.len(), 2, "{token}: {b}");
            assert_eq!(list[0]["account"], one.account.to_string(), "{b}");
            assert_eq!(list[0]["thread"], held[0].1, "{b}");
            assert_eq!(list[0]["hold"]["reason"], "дело №1");
            assert_eq!(list[0]["hold"]["by"], "admin@example.org");
            assert_eq!(list[1]["hold"]["reason"], "дело №2");
            let at = |v: &Value| v["hold"]["at"].as_str().expect("at").to_owned();
            assert!(at(&list[0]) <= at(&list[1]), "в порядке удержания");
        }
        for token in ["journal", "user", "auditor"] {
            let (s, _, _) = env.call("GET", &holds, Some(token), None).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{token}");
        }

        // Снятое удержание исчезает из списка.
        let (s, _, _) = env
            .call(
                "DELETE",
                &format!("{}/{}/hold", threads(two.account), held[1].1),
                Some("org"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::NO_CONTENT);
        let (_, _, b) = env.call("GET", &holds, Some("org"), None).await;
        let list = b["holds"].as_array().expect("holds");
        assert_eq!(list.len(), 1, "{b}");
        assert_eq!(list[0]["thread"], held[0].1, "{b}");

        // Оператор не удерживает и не снимает; чужая организация — 403 слоя доступа.
        let (s, _, _) = env
            .call(
                "PUT",
                &format!("{}/{}/hold", threads(one.account), held[0].1),
                Some("operator"),
                Some(json!({"reason": "нет прав"})),
            )
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, _) = env.call("GET", &holds, Some("other"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let other = format!("/api/v1/orgs/{}/holds", env.other_tenant);
        let (s, _, _) = env.call("GET", &other, Some("org"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }

    /// Приёмка ADM-50: письмо чужой учётной записи и чужой организации — 404; ошибки запроса — 400;
    /// хранилище бесед не подключено — 503.
    #[tokio::test]
    async fn find_errors_and_unconnected() {
        let env = Env::new();
        let scope = env.account("user@example.org").await;
        let foreign = env.account_in(env.other_tenant, "x@other.example").await;
        let base = threads(scope.account);
        let message = env
            .deliver_threaded(scope, "a@external.example", None, "письмо")
            .await;

        for query in ["", "message_id=не-uuid", "message_id=&color=red"] {
            let (s, _, _) = env
                .call("GET", &format!("{base}?{query}"), Some("org"), None)
                .await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{query:?}");
        }
        // Письма нет у учётной записи (чужое или случайное) — 404; учётной записи нет — 404.
        let (s, _, _) = env
            .call(
                "GET",
                &format!("{base}?message_id={}", MessageId::new()),
                Some("org"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _, _) = env
            .call(
                "GET",
                &format!(
                    "/api/v1/orgs/{}/accounts/{}/threads?message_id={message}",
                    TenantId::DEFAULT,
                    AccountId::new()
                ),
                Some("org"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        // Письмо чужой учётной записи (другой организации) этой не видно — 404; чужая организация — тоже.
        let (s, _, _) = env
            .call(
                "GET",
                &format!(
                    "/api/v1/orgs/{}/accounts/{}/threads?message_id={message}",
                    TenantId::DEFAULT,
                    foreign.account
                ),
                Some("root"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "чужая учётная запись");
        let (s, _, _) = env
            .call(
                "GET",
                &format!(
                    "/api/v1/orgs/{}/accounts/{}/threads?message_id={message}",
                    env.other_tenant, scope.account
                ),
                Some("root"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "чужая организация");

        // Без хранилища бесед маршруты отвечают 503.
        let env = Env::without_threads();
        let scope = env.account("user@example.org").await;
        let (s, _, _) = env
            .call(
                "GET",
                &format!(
                    "/api/v1/orgs/{}/accounts/{}/threads?message_id={}",
                    TenantId::DEFAULT,
                    scope.account,
                    MessageId::new()
                ),
                Some("org"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        let (s, _, _) = env
            .call(
                "GET",
                &format!("/api/v1/orgs/{}/holds", TenantId::DEFAULT),
                Some("org"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Конверт скрытого письма из метаданных — заголовки и пометка, без тела.
    #[tokio::test]
    async fn hidden_stub_is_headers_only() {
        let env = Env::new();
        let scope = env.account("user@example.org").await;
        let message = env
            .deliver_threaded(scope, "a@external.example", None, "первое")
            .await;
        env.store
            .delete_to_trash(scope, &[message])
            .await
            .expect("trash");
        env.trash
            .purge(scope, &[message], &DecisionHooks::default())
            .await
            .expect("purge");
        let m = env
            .trash
            .hidden_message(scope, message)
            .await
            .expect("hidden")
            .expect("письмо");
        let stub = String::from_utf8(stub_eml(&m)).expect("eml");
        assert!(
            stub.contains("Message-ID: <a@external.example>\r\n"),
            "{stub}"
        );
        assert!(stub.contains("Subject: первое\r\n"), "{stub}");
        assert!(stub.contains("Date: "), "{stub}");
        assert!(stub.ends_with("X-ThePost-Thread-Export: hidden (headers only)\r\n\r\n"));
    }
}
