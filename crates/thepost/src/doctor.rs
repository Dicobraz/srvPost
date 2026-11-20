//! `thepost doctor [--json]` (SRS 5.5, 3.1; APP-02): проверки окружения узла — конфигурация, хранилище секретов,
//! СУБД (проверки `tp-meta`: версия, синхронная реплика, часовой пояс, RLS, TLS, роль узла; кодировка и LC_CTYPE —
//! `database.locale`, APP-24; сторонние расширения — `database.extensions`, APP-08), BLOB (запись, чтение и удаление
//! пробного объекта), синхронизация часов узла и СУБД,
//! минимальные привилегии процесса (PLT-16): учётная запись, capabilities, no_new_privs, seccomp, Landlock;
//! DNS почтового домена (MX, SPF, DKIM, DMARC, MTA-STS, PTR), сертификаты и PROXY v2 — `doctor_dns` (APP-06);
//! сроки внутренних сертификатов (CA СУБД и OpenBao, сертификат узла от них) — `pki.*` (APP-25); короткий
//! сертификат узла (срок меньше двух окон продления) — предупреждение о смене режима (APP-81); приёмники экспорта
//! журнала аудита — `admin.audit.syslog`, `admin.audit.otlp` (APP-59);
//! журнал переписки (APP-82, SRS 4.9) — хеш-цепочка индекса и сверка с хранилищем записей (`journal.chain`,
//! `journal.index`), прогноз объёма на срок блокировки (`journal.retention`), предупреждение SMB о локальном
//! хранилище записей (`journal.backend`); прицельно — `thepost doctor journal [chain|retention]`.
//!
//! Вывод — таблица или JSON; код возврата ≠ 0, если хотя бы одна проверка не пройдена (`fail`).

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use futures::TryStreamExt;
use serde::Serialize;
use tp_admin_client::style::{self, Role, State, Theme};
use tp_cluster::NodeTls;
use tp_contracts::blob::BlobStore;
use tp_contracts::ids::{JournalId, TenantId};
use tp_contracts::journal::{JournalAudit, JournalRecord, JournalRecords, JournalStore};
use tp_contracts::secrets::{Secret, SecretStore};
use tp_contracts::{Error, Result};
use tp_meta::journal::PgJournal;
use tp_meta::pool::DbPool;
use tp_meta::{MetaConfig, PgMeta};
use tp_platform::{AcmeConfig, Config};

use crate::doctor_dns::{self, Dns};
use crate::infra;
use crate::secrets;
use crate::sections::{self, DOCTOR, DoctorSection, JOURNAL, JournalLocation, JournalSection};

/// Итог проверки; порядок — по тяжести.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Не применяется.
    Skipped,
    /// Требование выполнено.
    Ok,
    /// Работать можно, но стоит исправить.
    Warn,
    /// Требование не выполнено: код возврата ≠ 0.
    Fail,
}

impl Status {
    /// Обозначение в таблице.
    pub fn label(self) -> &'static str {
        match self {
            Status::Skipped => "SKIP",
            Status::Ok => "OK",
            Status::Warn => "WARN",
            Status::Fail => "FAIL",
        }
    }

    /// Знак и метка в цвете итога: ✓ `OK`, ▲ `WARN`, × `FAIL`; у пропущенной проверки знака нет — `SKIP` (`muted`)
    /// с отступом под знак.
    fn render(self, theme: Theme) -> String {
        let state = match self {
            Status::Skipped => return format!("  {}", theme.paint(Role::Muted, self.label())),
            Status::Ok => State::Done,
            Status::Warn => State::Warn,
            Status::Fail => State::Err,
        };
        theme.state(state, self.label())
    }
}

impl From<tp_platform::secrets::DoctorStatus> for Status {
    fn from(s: tp_platform::secrets::DoctorStatus) -> Self {
        use tp_platform::secrets::DoctorStatus as S;
        match s {
            S::Skipped => Status::Skipped,
            S::Ok => Status::Ok,
            S::Warn => Status::Warn,
            S::Fail => Status::Fail,
        }
    }
}

impl From<tp_meta::doctor::Status> for Status {
    fn from(s: tp_meta::doctor::Status) -> Self {
        match s {
            tp_meta::doctor::Status::Skipped => Status::Skipped,
            tp_meta::doctor::Status::Ok => Status::Ok,
            tp_meta::doctor::Status::Warn => Status::Warn,
            tp_meta::doctor::Status::Fail => Status::Fail,
        }
    }
}

/// Одна проверка.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    /// Идентификатор `<группа>.<проверка>`: `config.load`, `secrets.store`, `database.rls`, `blob.write`,
    /// `time.clock_skew` …
    pub id: String,
    /// Итог.
    pub status: Status,
    /// Фактическое значение.
    pub value: String,
    /// Пояснение для администратора.
    pub message: String,
}

/// Отчёт `thepost doctor`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Худший итог.
    pub status: Option<Status>,
    /// Проверки в порядке выполнения.
    pub checks: Vec<Check>,
}

impl Report {
    pub(crate) fn push(
        &mut self,
        id: &str,
        status: Status,
        value: impl Into<String>,
        message: impl Into<String>,
    ) {
        self.checks.push(Check {
            id: id.to_owned(),
            status,
            value: value.into(),
            message: message.into(),
        });
        self.status = Some(self.worst());
    }

    /// Худший итог; пропущенные проверки его не ухудшают.
    pub fn worst(&self) -> Status {
        self.checks
            .iter()
            .map(|c| c.status)
            .max()
            .map_or(Status::Ok, |s| s.max(Status::Ok))
    }

    /// Код возврата: 1 — есть непройденная проверка.
    pub fn exit_code(&self) -> i32 {
        i32::from(self.worst() == Status::Fail)
    }

    /// Проверка по идентификатору.
    pub fn get(&self, id: &str) -> Option<&Check> {
        self.checks.iter().find(|c| c.id == id)
    }

    /// JSON (`--json`) в оформлении `theme` (решение 120): без цвета — `serde_json::to_string_pretty` байт в байт.
    pub fn to_json(&self, theme: Theme) -> Result<String> {
        style::json(theme, self).map_err(|e| Error::internal(e.to_string()))
    }

    /// Таблица для терминала в оформлении `theme` (решение 120, APP-70): шапка — `head`; итог проверки — знак и
    /// метка (✓ `OK`, ▲ `WARN`, × `FAIL`); пути файлов — `muted`; последняя строка — счёт ошибок и предупреждений
    /// в цвете худшего итога. Без цвета знаки те же.
    pub fn render(&self, theme: Theme) -> String {
        let rows: Vec<Vec<String>> = self
            .checks
            .iter()
            .map(|c| {
                let value = if c.value.starts_with('/') {
                    theme.paint(Role::Muted, &c.value)
                } else {
                    c.value.clone()
                };
                vec![
                    c.status.render(theme),
                    c.id.clone(),
                    value,
                    c.message.clone(),
                ]
            })
            .collect();
        let mut out = style::table(theme, &["ИТОГ", "ПРОВЕРКА", "ЗНАЧЕНИЕ", "ПОЯСНЕНИЕ"], &rows);
        out.push_str(&self.summary(theme));
        out.push('\n');
        out
    }

    /// «итог: 1 ошибка, 1 предупреждение» в цвете худшего итога со знаком.
    fn summary(&self, theme: Theme) -> String {
        let count = |s: Status| self.checks.iter().filter(|c| c.status == s).count();
        let (fails, warns) = (count(Status::Fail), count(Status::Warn));
        let fails_text = plural(fails, "ошибка", "ошибки", "ошибок");
        let warns_text = plural(warns, "предупреждение", "предупреждения", "предупреждений");
        match (fails, warns) {
            (0, 0) => theme.state(State::Done, "итог: ошибок и предупреждений нет"),
            (0, _) => theme.state(State::Warn, &format!("итог: {warns_text}")),
            (_, 0) => theme.state(State::Err, &format!("итог: {fails_text}")),
            _ => theme.state(State::Err, &format!("итог: {fails_text}, {warns_text}")),
        }
    }
}

/// Число и слово в нужной форме: 1 ошибка, 2 ошибки, 5 ошибок.
fn plural(n: usize, one: &str, few: &str, many: &str) -> String {
    let word = match (n % 10, n % 100) {
        (_, 11..=14) => many,
        (1, _) => one,
        (2..=4, _) => few,
        _ => many,
    };
    format!("{n} {word}")
}

/// Сообщение ошибки без префикса варианта.
pub(crate) fn message(e: &Error) -> String {
    match e {
        Error::Invalid(m) | Error::Internal(m) => m.clone(),
        other => other.to_string(),
    }
}

/// Проверки окружения по config.yaml `path`; `store` — хранилище секретов (`None` — не настроено).
pub async fn run(path: &Path, store: Option<Arc<dyn SecretStore>>) -> Report {
    run_with(path, store, None).await
}

/// То же с резолвером DNS `dns` (`None` — системный).
pub async fn run_with(
    path: &Path,
    store: Option<Arc<dyn SecretStore>>,
    dns: Option<&dyn Dns>,
) -> Report {
    run_scoped_with(path, store, dns, Scope::All).await
}

/// Прицельные проверки журнала переписки (`thepost doctor journal [chain|retention]`, APP-82):
/// только проверки `journal.*` — остальные общим прогоном; `topic` — подмножество или все.
pub async fn run_journal(path: &Path, topic: Option<JournalTopic>) -> Report {
    run_scoped_with(path, None, None, Scope::Journal(topic)).await
}

/// Прогон doctor: общий или прицельный.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    /// Все проверки окружения (включая журнал).
    All,
    /// Только проверки журнала; `None` — все проверки журнала.
    Journal(Option<JournalTopic>),
}

/// Прогоны doctor: общий или прицельный (`journal`).
async fn run_scoped_with(
    path: &Path,
    store: Option<Arc<dyn SecretStore>>,
    dns: Option<&dyn Dns>,
    scope: Scope,
) -> Report {
    let mut report = Report::default();
    let loaded = sections::registry().and_then(|r| r.load(path));
    let cfg = match loaded {
        Ok(cfg) => cfg,
        Err(e) => {
            report.push(
                "config.load",
                Status::Fail,
                path.display().to_string(),
                message(&e),
            );
            return report;
        }
    };
    report.push(
        "config.load",
        Status::Ok,
        path.display().to_string(),
        "конфигурация разобрана",
    );
    for w in cfg.warnings() {
        report.push("config.unknown", Status::Warn, "", w.clone());
    }
    match scope {
        Scope::All => {
            let text = tokio::fs::read_to_string(path).await.unwrap_or_default();
            let confine = crate::startup::has_section(&text, tp_platform::privileges::CONFINE);
            check(&cfg, confine, store, dns, &mut report).await;
        }
        Scope::Journal(topic) => check_journal_only(&cfg, topic, &mut report).await,
    }
    report
}

/// Прицельный прогон журнала: хранилище секретов и СУБД — насколько нужны самому журналу (ключи S3,
/// индекс, правила); их причины — в сообщениях проверок `journal.*` (FIX-10), остальные проверки
/// общего прогона не выполняются.
async fn check_journal_only(cfg: &Config, topic: Option<JournalTopic>, report: &mut Report) {
    let secrets_report = secrets::doctor(cfg).await;
    let cause = secrets::unavailable_cause(&secrets_report);
    let store = secrets::doctor_store(cfg, None).await.ok();
    let meta = cfg
        .section::<MetaConfig>(MetaConfig::SECTION)
        .map(|m| m.doctor.clone())
        .unwrap_or_default();
    let pool = match &store {
        Some(store) => tokio::time::timeout(meta.timeout, infra::connect_db(cfg, store.as_ref()))
            .await
            .ok()
            .and_then(|r| r.ok()),
        None => None,
    };
    journal(
        cfg,
        store.as_ref(),
        pool.as_ref(),
        cause.as_deref(),
        topic,
        true,
        report,
    )
    .await;
    if let Some(pool) = pool {
        pool.close().await;
    }
}

/// Проверки по разобранной конфигурации; `confine` — в файле есть секция `confine` (нет — seccomp в режиме `log`,
/// как при запуске `serve`); `dns` — резолвер (`None` — системный).
pub async fn check(
    cfg: &Config,
    confine: bool,
    store: Option<Arc<dyn SecretStore>>,
    dns: Option<&dyn Dns>,
    report: &mut Report,
) {
    let doctor = cfg
        .section::<DoctorSection>(DOCTOR)
        .map(|d| (*d).clone())
        .unwrap_or_default();
    // Хранилище секретов (PLT-12): `secrets_store` → `secrets.store` и т. д. Медленному, но живому хранилищу
    // даётся бюджет `doctor.secrets_login_budget`: таймаут попытки — повтор, а не `fail` (FIX-10, issue #5).
    let secrets_report = secrets::doctor(cfg).await;
    let secret_cause = secrets::unavailable_cause(&secrets_report);
    let slow_store = secrets::slow_store(&secrets_report);
    let cause = secret_cause.as_deref();
    for c in secrets_report.checks {
        let id = c.id.replacen('_', ".", 1);
        report.push(&id, c.status.into(), c.value, c.message);
    }
    // Привилегии процесса (PLT-16): `privileges_user` → `privileges.user` и т. д.
    for mut c in tp_platform::privileges::doctor(cfg).await.checks {
        if !confine {
            seccomp_as_serve(&mut c);
        }
        let id = c.id.replacen('_', ".", 1);
        report.push(&id, c.status.into(), c.value, c.message);
    }
    let refs = secrets::references(cfg);
    let store = match secrets::doctor_store(cfg, store).await {
        Ok(store) => {
            let (status, msg) = if refs.is_empty() {
                (Status::Skipped, "ссылок на секреты нет".to_owned())
            } else {
                (Status::Ok, format!("ссылок на секреты: {}", refs.len()))
            };
            report.push("secrets.refs", status, "", msg);
            Some(store)
        }
        Err(e) => {
            report.push("secrets.refs", Status::Fail, "", message(&e));
            None
        }
    };

    let db = match &store {
        Some(store) => database(cfg, store.as_ref(), &doctor, cause, slow_store, report).await,
        None => {
            report.push(
                "database.connect",
                Status::Skipped,
                "",
                "хранилище секретов не настроено",
            );
            None
        }
    };
    match &store {
        Some(store) => match infra::open_blob(cfg, store.as_ref()).await {
            Ok(blob) => {
                report.push("blob.open", Status::Ok, blob_kind(cfg), "хранилище открыто");
                probe_blob(blob.as_ref(), &doctor, report).await;
            }
            Err(e) => {
                let (status, msg) = dependent(cause, &e, "открытие BLOB");
                report.push("blob.open", status, blob_kind(cfg), msg);
            }
        },
        None => report.push(
            "blob.open",
            Status::Skipped,
            "",
            "хранилище секретов не настроено",
        ),
    }
    doctor_dns::check_with(cfg, dns, store.as_ref(), &doctor, cause, report).await;
    internal_keys(cfg, store.as_ref(), cause, report).await;
    internal_pki(cfg, SystemTime::now(), report).await;
    dav_well_known(cfg, report);
    admin_audit(cfg, store.as_ref(), cause, report).await;
    journal(cfg, store.as_ref(), db.as_ref(), cause, None, false, report).await;
    if let Some(pool) = db {
        pool.close().await;
    }
}

/// Отказ зависимой проверки, которой нужен секрет из хранилища (FIX-10, issue #5): если хранилище не
/// обслуживает запросы (`cause` — непройденная проверка `secrets.store`/`secrets.login`), реальная причина
/// отказа — оно, а не сама проверка: итог `warn` с исходной причиной в сообщении вместо голого
/// «unavailable»/«нет ответа» и отдельного `fail` — узел может работать на прочитанных секретах, мониторинг
/// по `doctor` не даёт ложных аварий на нагруженных узлах. Ошибка не из хранилища (нет секрета, нет прав,
/// собственный сбой проверки) — как было: `fail` с сообщением ошибки.
pub(crate) fn dependent(cause: Option<&str>, e: &Error, what: &str) -> (Status, String) {
    match cause {
        Some(cause) if e.is_retryable() => (
            Status::Warn,
            format!(
                "{what} не выполнено: причина — хранилище секретов ({cause}); \
                 узел может работать на прочитанных секретах"
            ),
        ),
        _ => (Status::Fail, message(e)),
    }
}

/// Таймаут подключения к приёмнику OTLP (у syslog — свой, `admin.audit.syslog.connect_timeout`).
const OTLP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// TCP-подключение к `address` за `timeout`: `None` — подключились, иначе — причина.
async fn tcp_reachable(address: &str, timeout: Duration) -> Option<String> {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await {
        Ok(Ok(_)) => None,
        Ok(Err(e)) => Some(format!(
            "нет подключения к {address}: {e}; записи ждут в журнале до возврата приёмника"
        )),
        Err(_) => Some(format!(
            "нет подключения к {address} за {}",
            tp_contracts::config::duration::format(timeout)
        )),
    }
}

/// Выгрузка журнала аудита в SIEM (`admin.audit`, APP-59) узла с ролью maintenance (выгружает она).
/// `admin.audit.syslog` — приёмник собирается, как при выгрузке (проверка, ключ клиента `tls.key` из хранилища
/// секретов, TLS), затем подключение к `address` с рукопожатием TLS и проверкой сертификата приёмника за
/// `connect_timeout`; `admin.audit.otlp` — TCP-подключение к узлу и порту `endpoint`. Нет подсекции — нет проверки.
/// Пока приёмник недоступен, записи ждут в журнале и уходят после его возврата. `cause` — причина отказавшего
/// хранилища секретов (FIX-10): ключ клиента не получен из хранилища — `warn` с ней, не отдельный `fail`.
pub async fn admin_audit(
    cfg: &Config,
    store: Option<&Arc<dyn SecretStore>>,
    cause: Option<&str>,
    report: &mut Report,
) {
    if !cfg.roles().contains(tp_contracts::role::Role::Maintenance) {
        return;
    }
    let Ok(admin) = cfg.section::<sections::AdminSection>(sections::ADMIN) else {
        return;
    };
    let audit = &admin.0.audit;
    if let Some(syslog) = &audit.syslog {
        let id = "admin.audit.syslog";
        let value = syslog.address.clone();
        match store {
            None => report.push(
                id,
                Status::Skipped,
                value,
                "хранилище секретов не настроено",
            ),
            Some(store) => {
                match tp_admin::SyslogAudit::start(syslog.clone(), cfg.profile(), store.as_ref())
                    .await
                {
                    Err(e) => {
                        let (status, msg) = dependent(cause, &e, "подключение приёмника syslog");
                        report.push(id, status, value, msg);
                    }
                    Ok(sink) => match sink.probe().await {
                        Err(e) => report.push(
                            id,
                            Status::Fail,
                            value,
                            format!(
                                "нет подключения к {}: {e}; записи ждут в журнале до возврата приёмника",
                                syslog.address
                            ),
                        ),
                        Ok(()) => report.push(
                            id,
                            Status::Ok,
                            value,
                            "приёмник syslog принимает соединения",
                        ),
                    },
                }
            }
        }
    }
    if let Some(otlp) = &audit.otlp {
        let id = "admin.audit.otlp";
        let value = otlp.endpoint.clone();
        let target = reqwest::Url::parse(&otlp.endpoint)
            .map_err(|e| format!("endpoint: {e}"))
            .and_then(|u| match (u.host_str(), u.port_or_known_default()) {
                (Some(host), Some(port)) => Ok(format!("{host}:{port}")),
                _ => Err("endpoint: нет узла или порта".to_owned()),
            });
        let why = match target {
            Ok(target) => tcp_reachable(&target, OTLP_CONNECT_TIMEOUT).await,
            Err(e) => Some(e),
        };
        match why {
            Some(why) => report.push(id, Status::Fail, value, why),
            None => report.push(id, Status::Ok, value, "приёмник OTLP принимает соединения"),
        }
    }
}

// ---------- журнал переписки (APP-82, SRS 4.9) ----------

/// Порог предупреждения о сроке блокировки журнала (APP-82, риск 21): записи не удаляются весь срок,
/// ошибка в сроке compliance не освобождает бакет — дольше порога предупреждение.
pub const JOURNAL_RETENTION_WARN: Duration = Duration::from_secs(10 * 365 * 86_400);

/// Прицельная проверка журнала (`thepost doctor journal <проверка>`); общий прогон выполняет все.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalTopic {
    /// Целостность хеш-цепочки индекса и сверка с хранилищем записей (`journal.chain`, `journal.index`).
    Chain,
    /// Прогноз объёма на срок блокировки и предупреждения о сроке (`journal.retention`).
    Retention,
}

/// Проверки журнала переписки (SRS 4.9, APP-82): `journal.backend` — хранилище записей (предупреждение
/// SMB о локальном диске, риск 23), `journal.chain` — хеш-цепочка индекса (`verify_chain`, разрыв с
/// записью), `journal.index` — число записей индекса против объектов хранилища записей (хвост после
/// обрыва между фазами записи чинит восстановление индекса из хранилища), `journal.retention` — прогноз
/// объёма на срок блокировки (риск 21). `topic` — подмножество прицельного прогона; `targeted` — прогон
/// только журнала: выключенный журнал объясняется, общий прогон молчит (как роль dav без роли).
/// `cause` — причина отказавшего хранилища секретов (FIX-10): открытие S3 — `warn` с ней, не `fail`.
pub async fn journal(
    cfg: &Config,
    store: Option<&Arc<dyn SecretStore>>,
    pool: Option<&DbPool>,
    cause: Option<&str>,
    topic: Option<JournalTopic>,
    targeted: bool,
    report: &mut Report,
) {
    let section = cfg.section::<JournalSection>(JOURNAL).map(|s| (*s).clone());
    let Ok(section) = section else {
        if targeted {
            report.push(
                "journal.backend",
                Status::Skipped,
                "",
                "секция journal не настроена (журналирование переписки, SRS 4.9)",
            );
        }
        return;
    };
    if !section.enabled() {
        if targeted {
            report.push(
                "journal.backend",
                Status::Skipped,
                "",
                "журналирование выключено (journal.enabled: false) — включается явно",
            );
        }
        return;
    }
    let chain = topic.is_none_or(|t| t == JournalTopic::Chain);
    let retention = topic.is_none_or(|t| t == JournalTopic::Retention);
    // Хранилище записей — отдельное от BLOB ящиков (SRS 4.9).
    let records = match infra::open_journal_records(cfg, &section, store).await {
        Ok(records) => {
            let (status, value, msg) = journal_backend_status(&section);
            report.push("journal.backend", status, value, msg);
            Some(records)
        }
        Err(e) => {
            let value = match section.location() {
                Ok(JournalLocation::Local(dir)) => dir.display().to_string(),
                Ok(JournalLocation::S3 { bucket }) => format!("s3 {bucket}"),
                Err(_) => String::new(),
            };
            let (status, msg) = dependent(cause, &e, "открытие хранилища журнала");
            report.push("journal.backend", status, value, msg);
            None
        }
    };
    // Организации каталога и счётчики записей индекса (системная транзакция, RLS) — нужны цепочке и
    // прогнозу; ошибка чтения — отказ цепочки, прогноз считает по записям хранилища без правил.
    let indexed: Option<JournalTenants> = match pool {
        Some(pool) if chain || retention => match journal_tenants_and_counts(pool).await {
            Ok(x) => Some(x),
            Err(e) => {
                if chain {
                    report.push(
                        "journal.chain",
                        Status::Fail,
                        "",
                        format!("индекс журнала не прочитан: {}", message(&e)),
                    );
                    report.push(
                        "journal.index",
                        Status::Skipped,
                        "",
                        "индекс журнала не прочитан",
                    );
                }
                None
            }
        },
        _ => None,
    };
    if chain {
        if pool.is_none() {
            for id in ["journal.chain", "journal.index"] {
                report.push(
                    id,
                    Status::Skipped,
                    "",
                    "индекс журнала — в СУБД, подключение не установлено (см. database.connect)",
                );
            }
        } else if records.is_none() {
            for id in ["journal.chain", "journal.index"] {
                report.push(
                    id,
                    Status::Skipped,
                    "",
                    "хранилище записей не открыто (см. journal.backend)",
                );
            }
        } else if let (Some(pool), Some(records), Some((tenants, counts))) =
            (pool, &records, &indexed)
        {
            // Индекс журнала — PgJournal (META-88) над пулом и хранилищем записей.
            match cfg
                .section::<MetaConfig>(MetaConfig::SECTION)
                .map(|m| (*m).clone())
            {
                Ok(meta) => {
                    let port = Arc::new(StorageRecords(records.clone()));
                    let index = PgJournal::new(PgMeta::new(pool.clone(), meta), port.clone());
                    journal_chain(
                        &index,
                        Some(port.as_ref()),
                        Some(records.as_ref()),
                        tenants,
                        counts,
                        report,
                    )
                    .await;
                }
                Err(e) => {
                    report.push("journal.chain", Status::Fail, "", message(&e));
                    report.push(
                        "journal.index",
                        Status::Skipped,
                        "",
                        "секция meta не прочитана",
                    );
                }
            }
        }
    }
    if retention {
        let (_, retention) = section.lock();
        match &records {
            Some(records) => {
                let tenants: &[TenantId] = indexed.as_ref().map_or(&[], |(t, _)| t);
                let volume = journal_volume(records.as_ref(), tenants, pool).await;
                let (status, value, msg) = journal_retention_status(retention, &volume);
                report.push("journal.retention", status, value, msg);
            }
            None => report.push(
                "journal.retention",
                Status::Skipped,
                "",
                "хранилище записей не открыто (см. journal.backend)",
            ),
        }
    }
}

/// Итог проверки `journal.backend` (APP-82): S3 с Object Lock — OK (режим и срок конфигурации пишутся
/// в каждый объект при записи, BLOB-18); локальный диск (профиль SMB) — предупреждение (риск 23):
/// блокировка только сервером, от администратора ОС защиты нет.
pub fn journal_backend_status(section: &JournalSection) -> (Status, String, String) {
    let (mode, retention) = section.lock();
    match section.location() {
        Ok(JournalLocation::Local(dir)) => (
            Status::Warn,
            dir.display().to_string(),
            "хранилище записей журнала на локальном диске: блокировка только сервером (записи лишь \
             добавляются), от администратора ОС защиты нет (риск 23); для требований неизменяемости — \
             S3 с Object Lock (journal.s3); перезапись записи ловит journal.chain"
                .to_owned(),
        ),
        Ok(JournalLocation::S3 { bucket }) => (
            Status::Ok,
            format!("s3 {bucket}"),
            format!(
                "хранилище записей журнала — S3 с Object Lock: режим {}, срок при записи {}",
                mode.as_str(),
                tp_contracts::config::duration::format(retention)
            ),
        ),
        Err(e) => (Status::Fail, String::new(), message(&e)),
    }
}

/// Проверки `journal.chain` и `journal.index` (APP-82): хеш-цепочка индекса организаций
/// (`JournalStore::verify_chain`; разрыв — с номером записи) и хранилища записей (`storage`,
/// `tp_blob::JournalRecords::verify`, BLOB-18: подмена конверта или письма, развилка, потеря записи),
/// сверка числа записей индекса с объектами хранилища (`records` — порт со `scan`; `None` без сверки).
/// `index_counts` — записи индекса по организациям (СУБД), `tenants` — организации каталога (у
/// организации без записей индекса цепочка проверяется как пустая).
pub async fn journal_chain(
    index: &dyn JournalStore,
    records: Option<&dyn JournalRecords>,
    storage: Option<&tp_blob::JournalRecords>,
    tenants: &[TenantId],
    index_counts: &[(TenantId, u64)],
    report: &mut Report,
) {
    let cap = JournalAudit::grant();
    let mut total = 0u64;
    let mut broken: Option<String> = None;
    let mut ok = true;
    let mut error = None;
    for tenant in tenants {
        match index.verify_chain(&cap, *tenant).await {
            Ok(chain) => {
                total += chain.records;
                if !chain.ok {
                    ok = false;
                    if broken.is_none() {
                        broken = Some(match chain.broken_at {
                            Some(id) => format!("запись {id} организации {tenant}"),
                            None => format!("организация {tenant}"),
                        });
                    }
                }
            }
            Err(e) => {
                error = Some(message(&e));
                break;
            }
        }
        // Цепочка хранилища записей (BLOB-18): пересчёт хешей объектов от генезиса — подмена конверта
        // или письма, развилка, потерянная запись; источник нарушения отличается от индекса.
        if let Some(storage) = storage {
            match storage.verify(*tenant).await {
                Ok(chain) => {
                    if !chain.ok {
                        ok = false;
                        if broken.is_none() {
                            broken = Some(match chain.broken_at {
                                Some(id) => {
                                    format!("запись {id} организации {tenant} (хранилище записей)")
                                }
                                None => format!("организация {tenant} (хранилище записей)"),
                            });
                        }
                    }
                }
                Err(e) => {
                    error = Some(format!("хранилище записей: {}", message(&e)));
                    break;
                }
            }
        }
    }
    let value = format!("{total} записей, {} организаций", tenants.len());
    if let Some(e) = error {
        report.push("journal.chain", Status::Fail, value, e);
        report.push("journal.index", Status::Skipped, "", "цепочка не проверена");
        return;
    }
    let (status, msg) = if ok {
        (
            Status::Ok,
            if storage.is_some() {
                "хеш-цепочка индекса и хранилища записей целостна".to_owned()
            } else {
                "хеш-цепочка индекса целостна".to_owned()
            },
        )
    } else {
        (
            Status::Fail,
            format!(
                "разрыв хеш-цепочки индекса: {} — запись изменена или потеряна; индекс восстанавливается \
                 из хранилища записей (restore_index)",
                broken.unwrap_or_else(|| "запись не найдена".to_owned())
            ),
        )
    };
    report.push("journal.chain", status, value, msg);

    let Some(records) = records else {
        return;
    };
    let mut stored_total = 0u64;
    let mut mismatch: Option<String> = None;
    for (tenant, indexed) in index_counts {
        match records.scan(*tenant).await {
            Ok(stored) => {
                stored_total += stored.len() as u64;
                if (stored.len() as u64) != *indexed && mismatch.is_none() {
                    mismatch = Some(format!(
                        "организация {tenant}: в индексе {indexed}, в хранилище записей {} — обрыв \
                         между фазами записи",
                        stored.len()
                    ));
                }
            }
            Err(e) => {
                if mismatch.is_none() {
                    mismatch = Some(format!("хранилище записей не прочитано: {}", message(&e)));
                }
            }
        }
    }
    match mismatch {
        None => report.push(
            "journal.index",
            Status::Ok,
            format!("{stored_total} записей"),
            "число записей индекса и объектов хранилища совпадает",
        ),
        Some(m) => report.push(
            "journal.index",
            Status::Fail,
            format!("{stored_total} записей"),
            format!("{m}; восстановите индекс из хранилища записей (restore_index)"),
        ),
    }
}

/// Замеры журнала для прогноза объёма (APP-82): записи, средний размер записи (по выборке),
/// записей в сутки (по размаху дат записей), включённые правила (охват журналирования).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct JournalVolume {
    /// Записей в хранилище (все организации).
    pub records: u64,
    /// Включённых правил журналирования (данные организации, Admin API); `None` — СУБД недоступна.
    pub enabled_rules: Option<u64>,
    /// Средний размер записи по выборке, байт; `None` — записей нет.
    pub avg_record_bytes: Option<u64>,
    /// Записей в сутки по размаху дат записей; `None` — записей нет.
    pub records_per_day: Option<f64>,
}

/// Замеры по хранилищу записей и СУБД (APP-82): записи всех организаций из `tenants` (цепочка каждой),
/// средний размер письма записи — по выборке до 32 записей (равномерно по порядку), записей в сутки —
/// по размаху дат записей (не меньше суток), включённые правила — из `journal.rules` (без СУБД не
/// подсчитаны).
pub async fn journal_volume(
    records: &tp_blob::JournalRecords,
    tenants: &[TenantId],
    pool: Option<&DbPool>,
) -> JournalVolume {
    /// Записей выборки для среднего размера письма.
    const SAMPLE: usize = 32;
    let mut entries: Vec<(TenantId, JournalId, i64)> = Vec::new();
    for tenant in tenants {
        if let Ok(chain) = records.chain(*tenant).await {
            entries.extend(
                chain
                    .into_iter()
                    .map(|s| (*tenant, s.id, s.record.at.unix_timestamp())),
            );
        }
    }
    let total = entries.len() as u64;
    let per_day = (!entries.is_empty()).then(|| {
        let mut min = entries[0].2;
        let mut max = min;
        for (_, _, at) in &entries {
            min = min.min(*at);
            max = max.max(*at);
        }
        let span_days = ((max - min).max(0) as f64 / 86_400.0).max(1.0);
        entries.len() as f64 / span_days
    });
    let avg_record_bytes = if entries.is_empty() {
        None
    } else {
        let n = entries.len().clamp(1, SAMPLE);
        let mut sizes: Vec<u64> = Vec::with_capacity(n);
        for i in 0..n {
            let (tenant, id, _) = entries[i * entries.len() / n];
            if let Ok(message) = records.message(tenant, id).await {
                sizes.push(message.len() as u64);
            }
        }
        (!sizes.is_empty()).then(|| sizes.iter().sum::<u64>() / sizes.len() as u64)
    };
    let enabled_rules = match pool {
        Some(pool) => journal_enabled_rules(pool).await.ok(),
        None => None,
    };
    JournalVolume {
        records: total,
        enabled_rules,
        avg_record_bytes,
        records_per_day: per_day,
    }
}

/// Порт хранилища записей журнала (CTR-97) над реализацией tp-blob (BLOB-18) для проверок doctor
/// (APP-82): `scan` — конверты по цепочке хранилища (сверка числа записей с индексом), ссылка — путь
/// объекта записи. Запись и чтение по порту doctor не нужны (записывает этап конвейера журналирования —
/// полная проводка порта у узла, [`crate::journal::NodeRecords`], APP-84; письма doctor читает напрямую,
/// с известной организацией) и не реализуются; здесь порт нужен конструкции `PgJournal` (проверка
/// `verify_chain` индекса в хранилище не заглядывает).
struct StorageRecords(Arc<tp_blob::JournalRecords>);

#[async_trait::async_trait]
impl JournalRecords for StorageRecords {
    async fn put(
        &self,
        _id: JournalId,
        _record: &JournalRecord,
        _message: Bytes,
    ) -> Result<String> {
        Err(Error::internal(
            "journal: запись журнала — этап конвейера, в doctor недоступна",
        ))
    }

    async fn read(&self, _id: JournalId) -> Result<(JournalRecord, Bytes)> {
        Err(Error::internal(
            "journal: doctor читает записи напрямую из хранилища (организация известна)",
        ))
    }

    async fn scan(&self, tenant: TenantId) -> Result<Vec<(JournalId, JournalRecord, String)>> {
        let records = self.0.clone();
        Ok(records
            .chain(tenant)
            .await?
            .into_iter()
            .map(|s| {
                let storage = records.record_path(tenant, s.record.at, s.id);
                (s.id, s.record, storage)
            })
            .collect())
    }
}

/// Включённые правила журналирования всех организаций (`journal.rules`, системная транзакция; APP-82):
/// охват журналирования — без правил новых записей нет, прогноз объёма беспредметен.
async fn journal_enabled_rules(pool: &DbPool) -> Result<u64> {
    let count: i64 = tp_meta::pool::with_system(pool, |tx| {
        Box::pin(async move {
            sqlx::query_scalar("SELECT count(*) FROM journal.rules WHERE enabled")
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| Error::internal(format!("journal.rules: {e}")))
        })
    })
    .await?;
    Ok(count.max(0) as u64)
}

/// Организации каталога и их счётчики записей индекса (сверка цепочки и прогноза объёма, APP-82).
type JournalTenants = (Vec<TenantId>, Vec<(TenantId, u64)>);

/// Организации каталога и число записей индекса каждой (APP-82): системная транзакция
/// (`app.all_tenants`, RLS), счётчики — `journal.entries` (схема journal, META-88). У организации без
/// записей цепочка проверяется как пустая.
async fn journal_tenants_and_counts(pool: &DbPool) -> Result<JournalTenants> {
    let rows: Vec<(String, i64)> = tp_meta::pool::with_system(pool, |tx| {
        Box::pin(async move {
            sqlx::query_as(
                "SELECT t.tenant_id::text, \
                 (SELECT count(*) FROM journal.entries e WHERE e.tenant_id = t.tenant_id)::int8 \
                 FROM tenants t ORDER BY 1",
            )
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| Error::internal(format!("journal.entries: {e}")))
        })
    })
    .await?;
    let mut tenants = Vec::with_capacity(rows.len());
    let mut counts = Vec::with_capacity(rows.len());
    for (id, count) in rows {
        let tenant: TenantId = id
            .parse()
            .map_err(|e| Error::internal(format!("tenants: {e}")))?;
        tenants.push(tenant);
        counts.push((tenant, count.max(0) as u64));
    }
    Ok((tenants, counts))
}

/// Итог проверки `journal.retention` (APP-82, риск 21): прогноз объёма хранилища записей на срок
/// блокировки (записей в сутки × средний размер письма × срок — объём к концу срока, записи не
/// удаляются весь срок). Предупреждения: срок дольше [`JOURNAL_RETENTION_WARN`] (ошибка в сроке
/// compliance не освобождает бакет) и нет включённых правил (новых записей не будет).
pub fn journal_retention_status(
    retention: Duration,
    volume: &JournalVolume,
) -> (Status, String, String) {
    let days = retention.as_secs() / 86_400;
    let mut warnings: Vec<String> = Vec::new();
    if retention > JOURNAL_RETENTION_WARN {
        warnings.push(format!(
            "срок блокировки {days} сут. — дольше {} сут.: записи не удаляются весь срок, ошибка \
             compliance не освобождает хранилище (риск 21)",
            JOURNAL_RETENTION_WARN.as_secs() / 86_400
        ));
    }
    if volume.enabled_rules == Some(0) {
        warnings.push(
            "нет включённых правил журналирования — новые записи не появляются; правила — данные \
             организации (Admin API)"
                .to_owned(),
        );
    }
    let (value, msg) = match (volume.records_per_day, volume.avg_record_bytes) {
        (Some(per_day), Some(avg)) => {
            let forecast = per_day * avg as f64 * days as f64;
            (
                format!("≈ {} на {days} сут.", human_bytes(forecast)),
                format!(
                    "{per_day:.1} записей/сутки × {} × {days} сут. — ожидаемый объём хранилища \
                     срока блокировки (сейчас {} записей)",
                    human_bytes(avg as f64),
                    volume.records
                ),
            )
        }
        _ => (
            format!("на {days} сут."),
            format!(
                "прогноз появится с первыми записями (сейчас {}); срок блокировки продлевается только",
                volume.records
            ),
        ),
    };
    let status = if warnings.is_empty() {
        Status::Ok
    } else {
        Status::Warn
    };
    let msg = if warnings.is_empty() {
        msg
    } else if volume.records_per_day.is_some() {
        format!("{msg}; {}", warnings.join("; "))
    } else {
        warnings.join("; ")
    };
    (status, value, msg)
}

/// Размер в человекочитаемом виде (`1.5 GiB`) — прогноз и средний размер записи в doctor.
fn human_bytes(bytes: f64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes.max(0.0);
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Путь адреса автонастройки `target` (`jmap.autoconfig.caldav`, `carddav`): путь на этом сервере или полный URL.
/// Второе значение — `true` для полного URL.
fn context_path(target: &str) -> (&str, bool) {
    match target.split_once("://") {
        Some((_, rest)) => (rest.find('/').map_or("/", |i| &rest[i..]), true),
        None => (target, false),
    }
}

/// Роль dav (APP-29): клиенты находят календари и контакты по `/.well-known/caldav` и `/.well-known/carddav`
/// (RFC 6764 §5) — перенаправление должно вести на `/dav/`, где их отдаёт узел. Перенаправление отдаёт JMAP по
/// `jmap.autoconfig.caldav` и `carddav`; на слушателе без JMAP — сама роль dav, всегда на `/dav/`.
/// `FAIL` — путь не `/dav/`; `WARN` — слушателя нет либо DAV на отдельном порту `http.dav`, а адрес задан путём
/// (перенаправление останется на порту JMAP, где DAV нет).
pub fn dav_well_known(cfg: &Config, report: &mut Report) {
    use tp_contracts::role::Role;
    let roles = cfg.roles();
    if !roles.contains(Role::Dav) {
        return;
    }
    let http = cfg
        .section::<sections::HttpSection>(sections::HTTP)
        .map(|h| (*h).clone())
        .unwrap_or_default();
    let (listener, shared) = http.dav_listener(roles);
    let Some(listener) = listener else {
        report.push(
            "dav.listener",
            Status::Warn,
            "",
            "роль dav включена, но слушатель не задан (http.dav или http.jmap): календари и контакты недоступны",
        );
        return;
    };
    let value = listener.listen.to_string();
    let msg = if shared {
        "календари и контакты — на слушателе http.jmap"
    } else {
        "календари и контакты — на отдельном слушателе"
    };
    report.push("dav.listener", Status::Ok, value, msg);
    if !roles.contains(Role::Jmap) {
        report.push(
            "dav.well_known",
            Status::Ok,
            tp_dav::PREFIX,
            "перенаправление /.well-known/caldav и /.well-known/carddav отдаёт слушатель dav",
        );
        return;
    }
    let auto = cfg
        .section::<tp_jmap::JmapConfig>(sections::JMAP)
        .map(|j| j.autoconfig.clone())
        .unwrap_or_default();
    for (name, target) in [("caldav", &auto.caldav), ("carddav", &auto.carddav)] {
        let id = format!("dav.well_known.{name}");
        let (path, absolute) = context_path(target);
        let (status, msg) = if path.trim_end_matches('/') != tp_dav::PREFIX.trim_end_matches('/') {
            (
                Status::Fail,
                format!(
                    "/.well-known/{name} ведёт на {path}, а узел отдаёт календари и контакты по {}: исправьте jmap.autoconfig.{name}",
                    tp_dav::PREFIX
                ),
            )
        } else if !shared && !absolute {
            (
                Status::Warn,
                format!(
                    "DAV слушает отдельный адрес http.dav ({}), а /.well-known/{name} ведёт на порт JMAP: задайте jmap.autoconfig.{name} полным адресом (https://<имя>:{}{})",
                    listener.listen,
                    listener.listen.port(),
                    tp_dav::PREFIX
                ),
            )
        } else {
            (
                Status::Ok,
                format!("/.well-known/{name} ведёт на {}", tp_dav::PREFIX),
            )
        };
        report.push(&id, status, target.clone(), msg);
    }
}

/// Режим seccomp без секции `confine` — `log`, как при запуске `serve` (`startup::confine`): проверка
/// `privileges_seccomp` по умолчанию секции (`enforce`) так не показывала бы итог запуска.
fn seccomp_as_serve(c: &mut tp_platform::secrets::DoctorCheck) {
    use tp_platform::secrets::DoctorStatus;
    if c.id != "privileges_seccomp" || c.value != "enforce" {
        return;
    }
    c.value = "log".to_owned();
    if c.status == DoctorStatus::Ok {
        c.status = DoctorStatus::Warn;
        c.message = "секции confine нет: режим журнала, как при запуске — вызовы вне профиля не блокируются \
                     (confine.seccomp: enforce — блокировать)"
            .to_owned();
    }
}

fn blob_kind(cfg: &Config) -> String {
    match cfg
        .section::<sections::BlobSection>(sections::BLOB)
        .and_then(|b| b.location())
    {
        Ok(sections::BlobLocation::Local(root)) => format!("local {}", root.display()),
        Ok(sections::BlobLocation::S3 { bucket, .. }) => format!("s3 {bucket}"),
        Err(_) => String::new(),
    }
}

/// СУБД: подключение, проверки `tp-meta` (версия, репликация, часовой пояс, RLS, TLS), часы. `cause` —
/// причина отказавшего хранилища секретов, `slow_store` — хранилище отвечает медленнее транспортного
/// таймаута (FIX-10): подключение не получает пароль и не успевает в `meta.doctor.timeout` — это не
/// самостоятельный отказ проверки БД, а `warn` с исходной причиной.
/// Возвращает пул (индекс журнала — `journal.*`, APP-82); закрывает вызывающий.
async fn database(
    cfg: &Config,
    store: &dyn SecretStore,
    doctor: &DoctorSection,
    cause: Option<&str>,
    slow_store: bool,
    report: &mut Report,
) -> Option<DbPool> {
    let meta = cfg
        .section::<MetaConfig>(MetaConfig::SECTION)
        .map(|m| m.doctor.clone())
        .unwrap_or_default();
    let pool = match tokio::time::timeout(meta.timeout, infra::connect_db(cfg, store)).await {
        Ok(Ok(pool)) => pool,
        Ok(Err(e)) => {
            let (status, msg) = dependent(cause, &e, "подключение к СУБД");
            report.push("database.connect", status, "", msg);
            return None;
        }
        Err(_) => {
            let no_answer = format!(
                "нет ответа за {}",
                tp_contracts::config::duration::format(meta.timeout)
            );
            let (status, msg) = match (cause, slow_store) {
                (Some(cause), _) => (
                    Status::Warn,
                    format!("{no_answer}: причина — хранилище секретов ({cause})"),
                ),
                (None, true) => (
                    Status::Warn,
                    format!(
                        "{no_answer}: проверка не успела — хранилище секретов отвечает медленнее \
                         транспортного таймаута (secrets.login удался с повторной попытки), узел под нагрузкой"
                    ),
                ),
                _ => (Status::Fail, no_answer),
            };
            report.push("database.connect", status, "", msg);
            return None;
        }
    };
    report.push("database.connect", Status::Ok, "", "соединение установлено");
    match tp_meta::doctor::check(&pool, &meta).await {
        Ok(db) => {
            for c in db.checks {
                report.push(
                    &format!("database.{}", c.id),
                    c.status.into(),
                    c.value,
                    c.message,
                );
            }
        }
        Err(e) => report.push("database.checks", Status::Fail, "", message(&e)),
    }
    locale(&pool, meta.timeout, report).await;
    extensions(&pool, meta.timeout, report).await;
    clock_skew(&pool, meta.timeout, doctor, report).await;
    Some(pool)
}

/// Кодировка и `LC_CTYPE` базы узла (решение 2026-11-11 №23): `lower(login)` переводит кириллицу только в UTF8 с
/// `LC_CTYPE` UTF-8.
async fn locale(pool: &DbPool, timeout: Duration, report: &mut Report) {
    let id = "database.locale";
    let query = async {
        sqlx::query_as::<_, (String, String)>(
            "SELECT pg_encoding_to_char(encoding)::text, datctype::text FROM pg_database \
             WHERE datname = current_database()",
        )
        .fetch_one(&mut *pool.acquire_sqlx().await?)
        .await
    };
    let (encoding, ctype) = match tokio::time::timeout(timeout, query).await {
        Ok(Ok(row)) => row,
        Ok(Err(e)) => {
            report.push(
                id,
                Status::Fail,
                "",
                format!("кодировка базы не получена: {e}"),
            );
            return;
        }
        Err(_) => {
            report.push(
                id,
                Status::Fail,
                "",
                "кодировка базы не получена: нет ответа",
            );
            return;
        }
    };
    let (status, msg) = locale_status(&encoding, &ctype);
    report.push(id, status, format!("{encoding}, {ctype}"), msg);
}

/// Итог по кодировке (`pg_database.encoding`) и `LC_CTYPE` (`datctype`) базы: нужны UTF8 и `*.UTF-8`/`*.utf8`.
pub fn locale_status(encoding: &str, ctype: &str) -> (Status, &'static str) {
    let ctype = ctype.to_ascii_lowercase();
    if encoding.eq_ignore_ascii_case("UTF8")
        && (ctype.ends_with(".utf-8") || ctype.ends_with(".utf8"))
    {
        (Status::Ok, "кодировка UTF8, LC_CTYPE UTF-8")
    } else {
        (
            Status::Fail,
            "база не в UTF8 с LC_CTYPE UTF-8 (C.UTF-8 или <язык>.UTF-8): lower() не переводит кириллицу в именах входа \
             в нижний регистр — ломаются регистронезависимая уникальность и поиск по префиксу; создайте базу \
             с ENCODING 'UTF8' LC_CTYPE 'C.UTF-8' TEMPLATE template0 — docs/PREREQUISITES.md",
        )
    }
}

/// Расширения PostgreSQL базы узла, кроме встроенного `plpgsql` (по имени, по возрастанию).
async fn extensions(pool: &DbPool, timeout: Duration, report: &mut Report) {
    let id = "database.extensions";
    let query = async {
        sqlx::query_scalar::<_, String>(
            "SELECT extname::text FROM pg_extension WHERE extname <> 'plpgsql' ORDER BY 1",
        )
        .fetch_all(&mut *pool.acquire_sqlx().await?)
        .await
    };
    let names = match tokio::time::timeout(timeout, query).await {
        Ok(Ok(names)) => names,
        Ok(Err(e)) => {
            report.push(
                id,
                Status::Fail,
                "",
                format!("список расширений не получен: {e}"),
            );
            return;
        }
        Err(_) => {
            report.push(
                id,
                Status::Fail,
                "",
                "список расширений не получен: нет ответа",
            );
            return;
        }
    };
    let (status, msg) = extensions_status(&names);
    report.push(id, status, names.join(", "), msg);
}

/// Итог по списку сторонних расширений: продукт работает без расширений (SRS 3.1, решение
/// 2026-11-01-interaction-db-ha) — установленные не нужны и не должны требоваться механизмом HA.
pub fn extensions_status(names: &[String]) -> (Status, &'static str) {
    if names.is_empty() {
        (Status::Ok, "сторонних расширений нет")
    } else {
        (
            Status::Warn,
            "установлены сторонние расширения: продукт их не использует; механизм HA и перенос базы не должны от них зависеть",
        )
    }
}

/// Расхождение часов узла и СУБД: момент СУБД сравнивается с серединой интервала запроса.
async fn clock_skew(pool: &DbPool, timeout: Duration, doctor: &DoctorSection, report: &mut Report) {
    let id = "time.clock_skew";
    let before = unix_seconds(SystemTime::now());
    let query = async {
        sqlx::query_scalar::<_, f64>("SELECT extract(epoch FROM clock_timestamp())::float8")
            .fetch_one(&mut *pool.acquire_sqlx().await?)
            .await
    };
    let db = match tokio::time::timeout(timeout, query).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            report.push(id, Status::Fail, "", format!("время СУБД не получено: {e}"));
            return;
        }
        Err(_) => {
            report.push(id, Status::Fail, "", "время СУБД не получено: нет ответа");
            return;
        }
    };
    let after = unix_seconds(SystemTime::now());
    let skew = (db - (before + after) / 2.0).abs();
    let (status, msg) = skew_status(Duration::from_secs_f64(skew.min(1e9)), doctor);
    report.push(id, status, format!("{:.3}s", skew), msg);
}

/// Итог по расхождению часов и порогам секции `doctor`.
pub fn skew_status(skew: Duration, doctor: &DoctorSection) -> (Status, String) {
    if skew >= doctor.max_clock_skew {
        (
            Status::Fail,
            "часы узла и СУБД расходятся: настройте синхронизацию времени (NTP/chrony) на узлах и сервере СУБД".to_owned(),
        )
    } else if skew >= doctor.warn_clock_skew {
        (
            Status::Warn,
            "часы узла и СУБД заметно расходятся: проверьте синхронизацию времени".to_owned(),
        )
    } else {
        (Status::Ok, "часы синхронизированы".to_owned())
    }
}

fn unix_seconds(t: SystemTime) -> f64 {
    t.duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

/// Пробный объект: запись, чтение со сверкой содержимого, удаление.
///
/// Путь плоский, без подкаталога (FIX-19, issue #195): `LocalStore` удаляет только сам объект, каталог
/// `doctor/` остался бы с владельцем запустившего (root:root при прогоне от root) — следующий прогон от
/// `thepost` падал бы на `blob.write` с `Permission denied`.
pub async fn probe_blob(store: &dyn BlobStore, doctor: &DoctorSection, report: &mut Report) {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let path = format!("probe-doctor-{}-{nanos}", std::process::id());
    let data = Bytes::from(format!("thepost doctor {nanos}"));
    let limit = doctor.blob_timeout;
    let timed = |what: &'static str| {
        move |r: std::result::Result<Result<()>, tokio::time::error::Elapsed>| match r {
            Ok(r) => r,
            // FIX-10 (issue #5): «нет ответа» без числа не говорило, что это таймаут зонда, а не сбой
            // BLOB — в сообщении срок и имя настройки.
            Err(_) => Err(Error::Invalid(format!(
                "{what}: нет ответа за {} (doctor.blob_timeout)",
                tp_contracts::config::duration::format(limit)
            ))),
        }
    };

    let write = tokio::time::timeout(limit, store.put_raw(&path, data.clone())).await;
    if let Err(e) = timed("запись")(write) {
        report.push("blob.write", Status::Fail, &path, message(&e));
        return;
    }
    report.push("blob.write", Status::Ok, &path, "пробный объект записан");

    let read = tokio::time::timeout(limit, async {
        let stream = store.get_raw(&path, None).await?;
        let chunks: Vec<Bytes> = stream.try_collect().await?;
        if chunks.concat() == data.as_ref() {
            Ok(())
        } else {
            Err(Error::Invalid("прочитано не то, что записано".to_owned()))
        }
    })
    .await;
    match timed("чтение")(read) {
        Ok(()) => report.push("blob.read", Status::Ok, &path, "содержимое совпадает"),
        Err(e) => report.push("blob.read", Status::Fail, &path, message(&e)),
    }

    let delete = tokio::time::timeout(limit, store.delete_raw(&path)).await;
    match timed("удаление")(delete) {
        Ok(()) => report.push("blob.delete", Status::Ok, &path, "пробный объект удалён"),
        Err(e) => report.push("blob.delete", Status::Fail, &path, message(&e)),
    }
}

/// Порог предупреждения о сроке внутренних сертификатов (решение 2026-11-11 №27): плейбук перевыпускает
/// сертификат за 90 сут. (DEP-18), предупреждение за 60 — прогона не было.
pub const PKI_WARN_BEFORE: Duration = Duration::from_secs(60 * 86_400);

/// Как обновить сертификат узла от внутреннего CA.
const PKI_RENEW_CERT: &str = "перевыпуск — повторный прогон плейбука (DEP-18)";
/// Как обновить сам CA.
const PKI_RENEW_CA: &str = "новый CA — удалить каталог роли thepost_pki (/etc/thepost/pki) и повторно прогнать \
                            плейбук; клиентам — новый ca.pem";

/// Сертификаты PEM-файла: срок первого сертификата (листа цепочки), ближайшее окончание срока,
/// субъекты (DER) и издатель первого сертификата (DER).
struct PemCerts {
    not_before: SystemTime,
    not_after: SystemTime,
    subjects: Vec<Vec<u8>>,
    issuer: Vec<u8>,
}

fn pem_certs(pem: &[u8]) -> std::result::Result<PemCerts, String> {
    let mut out: Option<PemCerts> = None;
    for block in x509_parser::pem::Pem::iter_from_buffer(pem) {
        let block = block.map_err(|e| e.to_string())?;
        if block.label != "CERTIFICATE" {
            continue;
        }
        let cert = block.parse_x509().map_err(|e| e.to_string())?;
        let not_before = UNIX_EPOCH
            + Duration::from_secs(
                u64::try_from(cert.validity().not_before.timestamp()).unwrap_or(0),
            );
        let not_after = UNIX_EPOCH
            + Duration::from_secs(
                u64::try_from(cert.validity().not_after.timestamp()).unwrap_or(0),
            );
        let subject = cert.subject().as_raw().to_vec();
        match &mut out {
            Some(c) => {
                c.not_after = c.not_after.min(not_after);
                c.subjects.push(subject);
            }
            None => {
                out = Some(PemCerts {
                    not_before,
                    not_after,
                    subjects: vec![subject],
                    issuer: cert.issuer().as_raw().to_vec(),
                });
            }
        }
    }
    out.ok_or_else(|| "сертификатов PEM нет".to_owned())
}

/// Системный набор CA: сроки публичных корней — забота ОС, не плейбука.
fn not_system_bundle(
    path: std::path::PathBuf,
) -> std::result::Result<std::path::PathBuf, &'static str> {
    if path == tp_platform::secrets::SecretsTlsConfig::default().ca_file {
        Err("системный набор CA")
    } else {
        Ok(path)
    }
}

/// CA для проверки СУБД: `database.tls.ca_file`, иначе `sslrootcert` адреса `database.url` / `database.urls`.
fn database_ca(cfg: &Config) -> std::result::Result<std::path::PathBuf, &'static str> {
    const NONE: &str = "CA не задан: системные корни";
    let db = cfg
        .section::<tp_meta::pool::PoolConfig>(tp_meta::pool::PoolConfig::SECTION)
        .map_err(|_| NONE)?;
    let from_url = || {
        std::iter::once(&db.url).chain(&db.urls).find_map(|url| {
            let (_, query) = url.split_once('?')?;
            let parsed = reqwest::Url::parse(&format!("http://h/?{query}")).ok()?;
            parsed
                .query_pairs()
                .find(|(k, v)| k == "sslrootcert" && !v.is_empty())
                .map(|(_, v)| std::path::PathBuf::from(v.into_owned()))
        })
    };
    not_system_bundle(db.tls.ca_file.clone().or_else(from_url).ok_or(NONE)?)
}

/// CA для проверки OpenBao: `secrets.tls.ca_file`, если хранилище настроено.
fn secrets_ca(cfg: &Config) -> std::result::Result<std::path::PathBuf, &'static str> {
    const NONE: &str = "OpenBao не настроен";
    let s = cfg
        .section::<tp_platform::secrets::SecretsConfig>(secrets::SECRETS)
        .map_err(|_| NONE)?;
    if s.url.is_none() {
        return Err(NONE);
    }
    not_system_bundle(s.tls.ca_file.clone())
}

/// Итог по сроку `not_after` с порогом [`PKI_WARN_BEFORE`]; `renew` — как обновить.
fn pki_expiry(not_after: SystemTime, now: SystemTime, renew: &str) -> (Status, String) {
    let days = not_after.duration_since(now).unwrap_or_default().as_secs() / 86_400;
    match doctor_dns::expiry_status(not_after, now, PKI_WARN_BEFORE) {
        Status::Fail => (Status::Fail, format!("срок действия истёк: {renew}")),
        Status::Warn => (Status::Warn, format!("истекает через {days} сут.: {renew}")),
        s => (s, format!("действителен ещё {days} сут.")),
    }
}

/// Сутки.
const DAY: Duration = Duration::from_secs(86_400);

/// Предупреждение о коротком сертификате узла (APP-81): срок жизни меньше `2 ×` максимального окна
/// продления (`acme.renew_before`, 30 сут.) — окно режется до трети срока (правило PLT-37:
/// `min(renew_before, треть срока)`), продление начинается через `срок − окно` после выпуска, обращения
/// к серверу частые. Короткий сертификат — норма нового графика CA/B Forum (ballot SC-081v3: 47 сут. с
/// 03.2029, профиль Let's Encrypt — 6 сут.), поэтому тон — предупреждение о смене режима обслуживания,
/// а не ошибка: при `acme.enabled` продлением занимается узел, иначе перевыпуск — вручную или внешним
/// средством. `None` — срок не короткий, `notBefore`/`notAfter` нестандартны или окно не уместилось.
fn short_cert_note(cfg: &Config, c: &PemCerts) -> Option<String> {
    let acme = cfg.section::<AcmeConfig>("acme").unwrap_or_default();
    let lifetime = c.not_after.duration_since(c.not_before).ok()?;
    if lifetime >= acme.renew_before.checked_mul(2)? {
        return None;
    }
    // Эффективное окно — как у узла (PLT-37): продление начинается, когда до конца остаётся меньше окна.
    let window = acme.renew_before.min(lifetime / 3);
    let days = |d: Duration| usize::try_from(d.as_secs() / DAY.as_secs()).unwrap_or(0);
    let who = if acme.enabled {
        "продлением занимается узел (встроенный ACME)"
    } else {
        "автоматическое продление не настроено: перевыпуск — вручную или внешним средством"
    };
    Some(format!(
        "сертификат живёт {}, продление начнётся через {} после выпуска — частые обращения к серверу; \
         ожидаемо при переходе CA на короткие сертификаты; {who}",
        plural(days(lifetime), "день", "дня", "дней"),
        plural(days(lifetime - window), "день", "дня", "дней"),
    ))
}

/// Срок CA из файла `path` (проверка `id`); субъекты CA — для сопоставления с издателем сертификата узла.
async fn pki_ca(id: &str, path: &Path, now: SystemTime, report: &mut Report) -> Vec<Vec<u8>> {
    let shown = path.display().to_string();
    let certs = match tokio::fs::read(path).await {
        Ok(pem) => pem_certs(&pem),
        Err(e) => Err(format!("файл не прочитан: {e}")),
    };
    match certs {
        Ok(c) => {
            let (status, msg) = pki_expiry(c.not_after, now, PKI_RENEW_CA);
            report.push(id, status, shown, msg);
            c.subjects
        }
        Err(e) => {
            report.push(id, Status::Warn, shown, e);
            Vec::new()
        }
    }
}

/// Итог проверки закрытого ключа внутреннего канала `id`: `key` — ссылка на секрет (читается из хранилища
/// `store`), иначе файл `key_file`; `load` — та же загрузка пары, что при запуске узла. В отчёте — путь или ссылка
/// на секрет, значение ключа не выводится (правило APP-35).
async fn internal_key<F, Fut>(
    id: &str,
    tls: &tp_contracts::tls::InternalTls,
    store: Option<&Arc<dyn SecretStore>>,
    cause: Option<&str>,
    load: F,
    report: &mut Report,
) where
    F: FnOnce(Option<Arc<dyn SecretStore>>) -> Fut,
    Fut: Future<Output = Result<()>>,
{
    let (value, loaded) = match (&tls.key, store) {
        (Some(secret), None) => {
            report.push(
                id,
                Status::Skipped,
                format!("секрет {secret}"),
                "хранилище секретов не настроено",
            );
            return;
        }
        (Some(secret), Some(store)) => {
            (format!("секрет {secret}"), load(Some(store.clone())).await)
        }
        (None, _) => (
            tls.key_file
                .as_ref()
                .map(|f| f.display().to_string())
                .unwrap_or_default(),
            load(None).await,
        ),
    };
    match loaded {
        Ok(()) => report.push(id, Status::Ok, value, "ключ подходит к сертификату"),
        Err(e) => {
            let (status, msg) = dependent(cause, &e, "загрузка ключа");
            report.push(id, status, value, msg);
        }
    }
}

/// Закрытые ключи внутренних каналов (APP-36) — по правилу `tls.key` (APP-35): ключ межузлового канала
/// (`cluster.rpc.tls.key`; загрузка `NodeTls`, как при запуске) и ключ клиентского сертификата СУБД
/// (`database.tls.key`) подходят к своим сертификатам. При ссылке на секрет файл `key_file` не читается; без
/// хранилища секретов проверка пропускается. Канал без mTLS — проверка пропускается. `cause` — причина
/// отказавшего хранилища секретов (FIX-10): отказ загрузки ключа из хранилища — `warn` с ней, не `fail`.
pub async fn internal_keys(
    cfg: &Config,
    store: Option<&Arc<dyn SecretStore>>,
    cause: Option<&str>,
    report: &mut Report,
) {
    let id = "cluster.rpc.tls.key";
    match cfg.section::<sections::ClusterSection>(sections::CLUSTER) {
        Ok(cluster) if cluster.rpc_enabled() => {
            let tls = &cluster.rpc.tls;
            let load = |store: Option<Arc<dyn SecretStore>>| async move {
                match store {
                    Some(store) => NodeTls::load(tls, store.as_ref()).await,
                    None => NodeTls::load(tls, &crate::secrets::NoSecretStore).await,
                }
                .map(drop)
            };
            internal_key(id, tls, store, cause, load, report).await;
        }
        _ => report.push(id, Status::Skipped, "", "запросы узел → узел не включены"),
    }
    let id = "database.tls.key";
    let db = cfg.section::<tp_meta::pool::PoolConfig>(tp_meta::pool::PoolConfig::SECTION);
    match db.as_ref().map(|db| (&db.tls, db.tls.cert_file.clone())) {
        Ok((tls, Some(cert_file))) => {
            // Пара «сертификат и ключ» — та же проверка, что у ключа слушателей (`tp_platform::tls::check_pair`).
            let load = |store: Option<Arc<dyn SecretStore>>| async move {
                let key = match (&tls.key, &tls.key_file, store) {
                    (Some(secret), _, Some(store)) => store.get(secret).await?,
                    (None, Some(file), _) => tokio::fs::read_to_string(file)
                        .await
                        .map(Secret::new)
                        .map_err(|e| Error::Invalid(format!("{}: {e}", file.display())))?,
                    _ => {
                        return Err(Error::Invalid(
                            "ключ клиентского сертификата не задан".into(),
                        ));
                    }
                };
                tp_platform::tls::check_pair(&cert_file, &key).await
            };
            internal_key(id, tls, store, cause, load, report).await;
        }
        _ => report.push(
            id,
            Status::Skipped,
            "",
            "клиентский сертификат СУБД не задан",
        ),
    }
}

/// Сроки внутренних сертификатов (решение 2026-11-11 №27, APP-25): CA СУБД (`pki.database_ca`), CA OpenBao
/// (`pki.secrets_ca`) и сертификат узла `tls.cert_file`, если его выпустил один из этих CA (`pki.node`;
/// сертификат другого издателя — проверка `tls.certificate`). `WARN` — за [`PKI_WARN_BEFORE`], `FAIL` — после
/// срока. Короткий сертификат узла — предупреждение о частых продлениях (APP-81, [`short_cert_note`]) —
/// читается и у другого издателя: срок меньше двух окон продления означает смену режима обслуживания.
pub async fn internal_pki(cfg: &Config, now: SystemTime, report: &mut Report) {
    let mut issuers = Vec::new();
    match database_ca(cfg) {
        Ok(path) => issuers.extend(pki_ca("pki.database_ca", &path, now, report).await),
        Err(why) => report.push("pki.database_ca", Status::Skipped, "", why),
    }
    match secrets_ca(cfg) {
        Ok(path) => issuers.extend(pki_ca("pki.secrets_ca", &path, now, report).await),
        Err(why) => report.push("pki.secrets_ca", Status::Skipped, "", why),
    }
    let id = "pki.node";
    let file = cfg
        .section::<tp_platform::TlsConfig>("tls")
        .map(|t| t.cert_file.clone())
        .unwrap_or_default();
    let shown = file.display().to_string();
    let node = match tokio::fs::read(&file).await {
        Ok(pem) => pem_certs(&pem),
        Err(e) => Err(format!("файл не прочитан: {e}")),
    };
    let no_issuer = if issuers.is_empty() {
        "внутреннего CA нет"
    } else {
        "выпущен не внутренним CA: срок — проверка tls.certificate"
    };
    match node {
        Ok(c) if !issuers.is_empty() && issuers.contains(&c.issuer) => {
            let (status, msg) = pki_expiry(c.not_after, now, PKI_RENEW_CERT);
            let msg = match short_cert_note(cfg, &c) {
                Some(note) => format!("{msg}; {note}"),
                None => msg,
            };
            report.push(id, status, shown, msg);
        }
        Ok(c) => match short_cert_note(cfg, &c) {
            Some(note) => report.push(id, Status::Warn, shown, note),
            None => report.push(id, Status::Skipped, shown, no_issuer),
        },
        // Нечитаемый файл — прежнее поведение: срок и читаемость — проверка tls.certificate.
        Err(e) => report.push(
            id,
            Status::Skipped,
            shown,
            if issuers.is_empty() {
                no_issuer.to_owned()
            } else {
                format!("{e}: см. tls.certificate")
            },
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tp_testkit::{BlobOp, MemBlobStore};

    #[tokio::test]
    async fn blob_probe_ok_and_failures() {
        let store = MemBlobStore::default();
        let mut report = Report::default();
        probe_blob(&store, &DoctorSection::default(), &mut report).await;
        for id in ["blob.write", "blob.read", "blob.delete"] {
            assert_eq!(report.get(id).map(|c| c.status), Some(Status::Ok), "{id}");
        }
        assert!(store.paths().is_empty(), "пробный объект удалён");
        // FIX-19 (issue #195): путь без подкаталога — root-прогон не оставляет каталог `doctor/` root:root
        assert!(
            !report
                .get("blob.write")
                .expect("blob.write")
                .value
                .contains('/'),
            "плоский путь зонда"
        );
        assert_eq!(report.exit_code(), 0);

        store.fail_next(BlobOp::PutRaw, Error::UNAVAILABLE);
        let mut report = Report::default();
        probe_blob(&store, &DoctorSection::default(), &mut report).await;
        assert_eq!(
            report.get("blob.write").map(|c| c.status),
            Some(Status::Fail)
        );
        assert!(report.get("blob.read").is_none());
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn clock_skew_thresholds() {
        let d = DoctorSection::default();
        assert_eq!(skew_status(Duration::from_millis(10), &d).0, Status::Ok);
        assert_eq!(skew_status(Duration::from_secs(1), &d).0, Status::Warn);
        assert_eq!(skew_status(Duration::from_secs(60), &d).0, Status::Fail);
    }

    /// Без секции `confine` проверка seccomp показывает режим запуска `serve` — `log`.
    #[test]
    fn seccomp_without_confine_section_is_log() {
        use tp_platform::secrets::{DoctorCheck, DoctorStatus};
        let check = |id: &'static str, status, value: &str| DoctorCheck {
            id,
            status,
            value: value.to_owned(),
            message: "m".to_owned(),
        };
        let mut ok = check("privileges_seccomp", DoctorStatus::Ok, "enforce");
        seccomp_as_serve(&mut ok);
        assert_eq!((ok.status, ok.value.as_str()), (DoctorStatus::Warn, "log"));
        assert!(ok.message.contains("confine"), "{}", ok.message);
        let mut no_kernel = check("privileges_seccomp", DoctorStatus::Fail, "enforce");
        seccomp_as_serve(&mut no_kernel);
        assert_eq!(
            (
                no_kernel.status,
                no_kernel.value.as_str(),
                no_kernel.message.as_str()
            ),
            (DoctorStatus::Fail, "log", "m")
        );
        for mut same in [
            check("privileges_seccomp", DoctorStatus::Warn, "off"),
            check("privileges_landlock", DoctorStatus::Ok, "enforce"),
        ] {
            let before = same.clone();
            seccomp_as_serve(&mut same);
            assert_eq!(same, before);
        }
    }

    /// `thepost doctor` без секции `confine` и с ней: режим seccomp — как у `serve` (Linux).
    #[tokio::test]
    async fn doctor_seccomp_mode_follows_serve() {
        if !Path::new("/proc/self/status").exists() {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let base = "domain: example.org\nprofile: dev\ndatabase:\n  url: postgres://thepost@127.0.0.1:1/thepost?sslmode=disable\n  acquire_timeout: 1s\n  tls: { allow_plaintext: true }\nblob:\n  url: file:///nonexistent/blob\n";
        let dns = crate::doctor_dns::MockDns::default();
        for (extra, mode) in [("", "log"), ("confine:\n  seccomp: enforce\n", "enforce")] {
            let path = write_config(dir.path(), &format!("{base}{extra}"));
            let report = run_with(&path, None, Some(&dns)).await;
            assert_eq!(
                report.get("privileges.seccomp").map(|c| c.value.as_str()),
                Some(mode),
                "{report:?}"
            );
        }
    }

    fn write_config(dir: &Path, yaml: &str) -> std::path::PathBuf {
        let path = dir.join("config.yaml");
        std::fs::write(&path, yaml).expect("write");
        path
    }

    #[tokio::test]
    async fn bad_config_fails_with_exit_code() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(dir.path(), "domain: example.org\n");
        let report = run_with(&path, None, Some(&crate::doctor_dns::MockDns::default())).await;
        assert_eq!(
            report.get("config.load").map(|c| c.status),
            Some(Status::Fail)
        );
        assert_eq!(report.exit_code(), 1);
        let json = report.to_json(Theme::PLAIN).expect("json");
        assert!(json.contains("\"status\": \"fail\""), "{json}");
        assert!(report.render(Theme::PLAIN).contains("× FAIL"));
    }

    #[tokio::test]
    async fn secrets_without_store_fail() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blob = dir.path().join("blob");
        let path = write_config(
            dir.path(),
            &format!(
                "domain: example.org\nprofile: dev\ndatabase:\n  url: postgres://thepost@127.0.0.1:1/thepost?sslmode=disable\n  password: {{ secret: \"thepost/db#password\" }}\n  tls: {{ allow_plaintext: true }}\nblob:\n  url: file://{}\n",
                blob.display().to_string().replace('\\', "/")
            ),
        );
        let report = run_with(&path, None, Some(&crate::doctor_dns::MockDns::default())).await;
        assert_eq!(
            report.get("secrets.refs").map(|c| c.status),
            Some(Status::Fail)
        );
        assert_eq!(
            report.get("secrets.config").map(|c| c.status),
            Some(Status::Skipped),
            "{report:?}"
        );
        assert_eq!(
            report.get("database.connect").map(|c| c.status),
            Some(Status::Skipped)
        );
        assert_eq!(report.exit_code(), 1);
    }

    #[tokio::test]
    async fn local_blob_and_unreachable_database() {
        let dir = tempfile::tempdir().expect("tempdir");
        let blob = dir.path().join("blob");
        let path = write_config(
            dir.path(),
            &format!(
                "domain: example.org\nprofile: dev\ndatabase:\n  url: postgres://thepost@127.0.0.1:1/thepost?sslmode=disable\n  acquire_timeout: 1s\n  tls: {{ allow_plaintext: true }}\nmeta:\n  doctor:\n    timeout: 2s\nblob:\n  url: file://{}\n",
                blob.display().to_string().replace('\\', "/")
            ),
        );
        let report = run_with(&path, None, Some(&crate::doctor_dns::MockDns::default())).await;
        assert_eq!(
            report.get("database.connect").map(|c| c.status),
            Some(Status::Fail)
        );
        for id in ["blob.open", "blob.write", "blob.read", "blob.delete"] {
            assert_eq!(
                report.get(id).map(|c| c.status),
                Some(Status::Ok),
                "{id}: {report:?}"
            );
        }
        assert_eq!(report.exit_code(), 1);
    }

    /// HTTP-имитация OpenBao (profile dev) для FIX-10, как стенд school-99 (issue #5): `/v1/sys/health` и
    /// `/v1/sys/seal-status` отвечают сразу, а `/v1/auth/approle/login` — с задержкой `login_delay`
    /// (свежий TLS-хендшейк и approle-вход не укладываются в транспортный таймаут под CPU-нагрузкой). KV
    /// отдаёт пароль СУБД `thepost/db#password` и ключ сертификата `thepost/tls#key`.
    struct SlowVault {
        addr: std::net::SocketAddr,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for SlowVault {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl SlowVault {
        async fn start(login_delay: Duration, key: &'static str) -> Self {
            use axum::Json;
            use axum::routing::{get, post};
            use serde_json::json;

            let login = move || async move {
                tokio::time::sleep(login_delay).await;
                Json(json!({
                    "auth": { "client_token": "s.mock", "lease_duration": 60, "renewable": true }
                }))
            };
            let db = || async {
                Json(
                    json!({ "data": { "data": { "password": "pw" }, "metadata": { "version": 1 } } }),
                )
            };
            let tls = move || async move {
                Json(json!({ "data": { "data": { "key": key }, "metadata": { "version": 1 } } }))
            };
            let router = axum::Router::new()
                .route(
                    "/v1/sys/health",
                    get(|| async {
                        Json(json!({ "initialized": true, "sealed": false, "version": "2.7.2" }))
                    }),
                )
                .route(
                    "/v1/sys/seal-status",
                    get(|| async { Json(json!({ "type": "auto", "sealed": false })) }),
                )
                .route("/v1/auth/approle/login", post(login))
                .route(
                    "/v1/auth/token/lookup-self",
                    get(|| async { Json(json!({ "data": { "ttl": 60, "renewable": true } })) }),
                )
                .route("/v1/thepost/data/db", get(db))
                .route("/v1/thepost/data/tls", get(tls));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let task = tokio::spawn(async move {
                axum::serve(listener, router).await.expect("serve");
            });
            Self { addr, task }
        }
    }

    /// Конфигурация узла с хранилищем `vault` на `addr`: пароль СУБД и ключ сертификата — секреты, СУБД
    /// недоступна (отказ не связан с хранилищем), BLOB локальный.
    fn slow_vault_config(
        dir: &Path,
        addr: &std::net::SocketAddr,
        transport: &str,
        budget: &str,
    ) -> String {
        let slash = |p: &Path| p.display().to_string().replace('\\', "/");
        let cert = dir.join("cert.pem");
        std::fs::write(&cert, include_bytes!("testdata/cert.pem")).expect("cert");
        std::fs::write(dir.join("secret_id"), "secret-1\n").expect("secret_id");
        format!(
            "domain: example.org\nprofile: dev\n\
             database:\n  url: postgres://thepost@127.0.0.1:1/thepost?sslmode=disable\n  \
             password: {{ secret: \"thepost/db#password\" }}\n  acquire_timeout: 100ms\n  \
             tls: {{ allow_plaintext: true }}\n\
             meta:\n  doctor:\n    timeout: 2s\n\
             blob:\n  url: file://{blob}\n\
             tls:\n  cert_file: \"{cert}\"\n\
             secrets:\n  url: http://{addr}\n  tls: {{ allow_plaintext: true }}\n  \
             request_timeout: {transport}\n  auth:\n    approle:\n      role_id: role-1\n      \
             secret_id_file: {secret}\n\
             doctor:\n  secrets_login_budget: {budget}\n",
            blob = slash(&dir.join("blob")),
            cert = slash(&cert),
            secret = slash(&dir.join("secret_id")),
        )
    }

    /// Приёмка FIX-10: вход в хранилище дольше транспортного таймаута (`secrets.request_timeout`), но в
    /// бюджете `doctor.secrets_login_budget` — `secrets.login` не `fail`, а повтор с попытки в сообщении;
    /// зависимые проверки сами healthy: ключ `tls.key` читается, зонд BLOB пишется; `database.connect` —
    /// отказ по своей причине (СУБД недоступна), не «unavailable» из-за секрета.
    #[tokio::test]
    async fn slow_secret_store_retries_login_within_budget() {
        let vault =
            SlowVault::start(Duration::from_millis(400), include_str!("testdata/key.pem")).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(
            dir.path(),
            &slow_vault_config(dir.path(), &vault.addr, "100ms", "2s"),
        );
        let report = run_with(&path, None, Some(&crate::doctor_dns::MockDns::default())).await;
        let login = report.get("secrets.login").expect("secrets.login");
        assert_eq!(login.status, Status::Ok, "{report:?}");
        assert!(
            login.message.contains("удалось с попытки 2"),
            "{}",
            login.message
        );
        assert_eq!(
            report.get("tls.key").map(|c| c.status),
            Some(Status::Ok),
            "{report:?}"
        );
        for id in ["blob.open", "blob.write", "blob.read", "blob.delete"] {
            assert_eq!(report.get(id).map(|c| c.status), Some(Status::Ok), "{id}");
        }
        let connect = report.get("database.connect").expect("database.connect");
        assert_eq!(connect.status, Status::Fail, "{report:?}");
        assert!(
            !connect.message.contains("хранилище секретов"),
            "отказ СУБД выдан за секрет: {}",
            connect.message
        );
    }

    /// Приёмка FIX-10: хранилище не отвечает и за бюджет — `secrets.login` не `fail`, а `warn` «проверка не
    /// успела»; зависимые проверки (`database.connect`, `tls.key`) — `warn` с исходной причиной хранилища в
    /// сообщении, а не голый `unavailable`/`fail`; BLOB от секрета не зависит и работает.
    #[tokio::test]
    async fn slow_secret_store_beyond_budget_warns_dependents() {
        let vault =
            SlowVault::start(Duration::from_secs(10), include_str!("testdata/key.pem")).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(
            dir.path(),
            &slow_vault_config(dir.path(), &vault.addr, "100ms", "400ms"),
        );
        let report = run_with(&path, None, Some(&crate::doctor_dns::MockDns::default())).await;
        let login = report.get("secrets.login").expect("secrets.login");
        assert_eq!(login.status, Status::Warn, "{report:?}");
        assert!(
            login.message.contains("проверка не успела"),
            "{}",
            login.message
        );
        assert!(
            login.message.contains("doctor.secrets_login_budget"),
            "{}",
            login.message
        );
        for (id, what) in [("database.connect", "СУБД"), ("tls.key", "ключа")] {
            let check = report.get(id).unwrap_or_else(|| panic!("{id}: {report:?}"));
            assert_eq!(check.status, Status::Warn, "{id}: {report:?}");
            assert!(
                check.message.contains("хранилище секретов"),
                "{id}: {}",
                check.message
            );
            assert!(
                check.message.contains("secrets.login"),
                "{id} без исходной причины ({what}): {}",
                check.message
            );
        }
        for id in ["blob.open", "blob.write", "blob.read", "blob.delete"] {
            assert_eq!(report.get(id).map(|c| c.status), Some(Status::Ok), "{id}");
        }
        // Ложного каскада `fail` нет: хранилище и зависимые от него проверки — не `fail` (на school-99
        // оставался единственный ожидаемый FAIL `dns.mx`).
        for id in [
            "secrets.store",
            "secrets.login",
            "database.connect",
            "tls.key",
            "blob.open",
            "blob.write",
        ] {
            assert_ne!(
                report.get(id).map(|c| c.status),
                Some(Status::Fail),
                "{id}: {report:?}"
            );
        }
    }

    #[tokio::test]
    async fn database_checks_with_test_database() {
        let Some(url) = tp_testkit::pg_url() else {
            eprintln!("TEST_DATABASE_URL не задан — тест пропущен");
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let blob = dir.path().join("blob");
        let path = write_config(
            dir.path(),
            &format!(
                "domain: example.org\nprofile: dev\ndatabase:\n  url: \"{}\"\n  tls: {{ allow_plaintext: true }}\nblob:\n  url: file://{}\n",
                crate::testutil::dev_url(&url),
                blob.display().to_string().replace('\\', "/")
            ),
        );
        let report = run_with(&path, None, Some(&crate::doctor_dns::MockDns::default())).await;
        assert_eq!(
            report.get("database.connect").map(|c| c.status),
            Some(Status::Ok),
            "{report:?}"
        );
        assert!(
            report.get("database.server_version").is_some(),
            "{report:?}"
        );
        assert!(report.get("time.clock_skew").is_some(), "{report:?}");
        assert!(report.get("database.extensions").is_some(), "{report:?}");
        assert_eq!(
            report.get("database.locale").map(|c| c.status),
            Some(Status::Ok),
            "{report:?}"
        );
        assert!(
            report.get("database.sync_replication").is_some(),
            "{report:?}"
        );
    }

    #[test]
    fn database_locale_needs_utf8() {
        for (enc, ctype) in [
            ("UTF8", "C.UTF-8"),
            ("UTF8", "en_US.utf8"),
            ("UTF8", "ru_RU.UTF-8"),
        ] {
            assert_eq!(locale_status(enc, ctype).0, Status::Ok, "{enc} {ctype}");
        }
        for (enc, ctype) in [
            ("UTF8", "C"),
            ("UTF8", "POSIX"),
            ("SQL_ASCII", "C"),
            ("LATIN1", "en_US.utf8"),
        ] {
            assert_eq!(locale_status(enc, ctype).0, Status::Fail, "{enc} {ctype}");
        }
    }

    /// APP-29: `/.well-known/caldav` и `carddav` ведут на `/dav/` — по `jmap.autoconfig` и слушателям `http`.
    #[test]
    fn dav_well_known_points_to_dav() {
        const BASE: &str = "domain: example.org\nprofile: dev\ndatabase:\n  url: postgres://x@y/z?sslmode=disable\n  tls: { allow_plaintext: true }\nblob:\n  url: file:///tmp/b\n";
        let report = |extra: &str| {
            let cfg = sections::registry()
                .expect("registry")
                .parse(&format!("{BASE}{extra}"), Vec::new())
                .expect("config");
            let mut r = Report::default();
            dav_well_known(&cfg, &mut r);
            r
        };
        let status = |r: &Report, id: &str| r.get(id).map(|c| c.status);

        // Роль dav выключена — проверок нет.
        let r = report("roles: [jmap]\nhttp:\n  jmap: { listen: 127.0.0.1:443 }\n");
        assert!(r.checks.is_empty(), "{r:?}");
        // Общий порт с JMAP, адреса по умолчанию.
        let r = report("roles: [jmap, dav]\nhttp:\n  jmap: { listen: 127.0.0.1:443 }\n");
        assert_eq!(status(&r, "dav.listener"), Some(Status::Ok), "{r:?}");
        assert_eq!(status(&r, "dav.well_known.caldav"), Some(Status::Ok));
        assert_eq!(status(&r, "dav.well_known.carddav"), Some(Status::Ok));
        // Слушателя нет.
        let r = report("roles: [jmap, dav]\n");
        assert_eq!(status(&r, "dav.listener"), Some(Status::Warn), "{r:?}");
        // Перенаправление мимо /dav/.
        let r = report(
            "roles: [jmap, dav]\nhttp:\n  jmap: { listen: 127.0.0.1:443 }\njmap:\n  autoconfig:\n    caldav: /caldav/\n    carddav: https://mail.example.org/dav\n",
        );
        assert_eq!(
            status(&r, "dav.well_known.caldav"),
            Some(Status::Fail),
            "{r:?}"
        );
        assert_eq!(status(&r, "dav.well_known.carddav"), Some(Status::Ok));
        // Отдельный порт: путь без адреса оставит клиента на порту JMAP.
        let split = "roles: [jmap, dav]\nhttp:\n  jmap: { listen: 127.0.0.1:443 }\n  dav: { listen: 127.0.0.1:8443 }\n";
        let r = report(split);
        assert_eq!(
            status(&r, "dav.well_known.caldav"),
            Some(Status::Warn),
            "{r:?}"
        );
        let r = report(&format!(
            "{split}jmap:\n  autoconfig:\n    caldav: https://mail.example.org:8443/dav/\n    carddav: https://mail.example.org:8443/dav/\n"
        ));
        assert_eq!(
            status(&r, "dav.well_known.caldav"),
            Some(Status::Ok),
            "{r:?}"
        );
        // Узел без роли jmap: перенаправление отдаёт сама роль dav.
        let r = report("roles: [dav]\nhttp:\n  dav: { listen: 127.0.0.1:8443 }\n");
        assert_eq!(status(&r, "dav.well_known"), Some(Status::Ok), "{r:?}");
    }

    #[test]
    fn third_party_extensions_warn() {
        assert_eq!(extensions_status(&[]).0, Status::Ok);
        assert_eq!(
            extensions_status(&["pg_stat_statements".to_owned()]).0,
            Status::Warn
        );
    }

    // ---------- журнал переписки (APP-82) ----------

    /// Секция `journal` из config.yaml (проверки backend и прогноза).
    fn journal_section(yaml: &str) -> JournalSection {
        sections::registry()
            .expect("registry")
            .parse(
                &format!(
                    "domain: example.org\nprofile: dev\ndatabase:\n  url: postgres://x@y/z?sslmode=disable\n  \
                     tls: {{ allow_plaintext: true }}\nblob:\n  url: file:///tmp/b\n{yaml}"
                ),
                Vec::new(),
            )
            .expect("config")
            .section::<JournalSection>(sections::JOURNAL)
            .expect("journal")
            .as_ref()
            .clone()
    }

    /// APP-82: профиль SMB — предупреждение о локальном диске (риск 23) только для `journal.local`;
    /// S3 с Object Lock — OK с режимом и сроком.
    #[test]
    fn journal_backend_warns_local_only() {
        let local = journal_section(
            "journal:\n  enabled: true\n  local:\n    dir: /var/lib/thepost/journal\n",
        );
        let (status, value, msg) = journal_backend_status(&local);
        assert_eq!(status, Status::Warn);
        assert_eq!(value, "/var/lib/thepost/journal");
        assert!(msg.contains("риск 23"), "{msg}");
        assert!(msg.contains("Object Lock"), "{msg}");

        let s3 = journal_section(
            "journal:\n  enabled: true\n  s3:\n    bucket: thepost-journal\n    retention: 2555d\n",
        );
        let (status, value, msg) = journal_backend_status(&s3);
        assert_eq!(status, Status::Ok);
        assert_eq!(value, "s3 thepost-journal");
        assert!(msg.contains("governance"), "{msg}");
        assert!(msg.contains("2555d"), "{msg}");
    }

    /// APP-82: цепочка цела — `journal.chain` и `journal.index` OK (JSON стабилен); разрыв цепочки
    /// индекса — FAIL с записью; расхождение числа записей индекса и хранилища — FAIL `journal.index`.
    #[tokio::test]
    async fn journal_chain_ok_broken_and_index_mismatch() {
        use tp_contracts::journal::{JournalDirection, JournalRule, JournalScope};
        use tp_testkit::journal::{MemJournal, MemJournalRecords};

        let tenant = TenantId::DEFAULT;
        let rule = JournalRule {
            id: "r-0042".to_owned(),
            tenant,
            scope: JournalScope::Org,
            direction: JournalDirection::Both,
            enabled: true,
        };
        // Запись — из JSON (крейт thepost не зависит от time; `at` — строкой RFC 3339, сутки между
        // записями — для размаха дат прогноза).
        let record = |i: i64| {
            serde_json::from_value::<JournalRecord>(serde_json::json!({
                "tenant": tenant.to_string(),
                "sender": format!("s{i}@external.example"),
                "recipients": ["anna@internal.example"],
                "message_id": format!("m{i}@external.example"),
                "at": (["2026-12-14T00:00:00Z", "2026-12-15T00:00:00Z", "2026-12-16T00:00:00Z"]
                    [i as usize]),
                "rule": "r-0042",
            }))
            .expect("record")
        };

        let journal = MemJournal::new();
        let records = MemJournalRecords::new();
        let mut ids = Vec::new();
        for i in 0..3i64 {
            let id = journal
                .append(&rule, &record(i), Bytes::from_static(b"message"))
                .await
                .expect("append");
            records
                .put(id, &record(i), Bytes::from_static(b"message"))
                .await
                .expect("put");
            ids.push(id);
        }
        let tenants = [tenant];
        let counts = [(tenant, 3)];
        let mut report = Report::default();
        journal_chain(
            &journal,
            Some(&records),
            None,
            &tenants,
            &counts,
            &mut report,
        )
        .await;
        assert_eq!(
            report.get("journal.chain").map(|c| c.status),
            Some(Status::Ok),
            "{report:?}"
        );
        assert_eq!(
            report.get("journal.index").map(|c| c.status),
            Some(Status::Ok),
            "{report:?}"
        );
        let json = report.to_json(Theme::PLAIN).expect("json");
        assert!(json.contains("\"id\": \"journal.chain\""), "{json}");
        assert!(json.contains("\"status\": \"ok\""), "{json}");

        // Разрыв цепочки индекса: подмена записи без пересчёта хеша — FAIL с номером записи.
        journal.tamper(ids[1]);
        let mut report = Report::default();
        journal_chain(
            &journal,
            Some(&records),
            None,
            &tenants,
            &counts,
            &mut report,
        )
        .await;
        let chain = report.get("journal.chain").expect("chain");
        assert_eq!(chain.status, Status::Fail, "{report:?}");
        assert!(chain.message.contains("разрыв"), "{}", chain.message);
        assert!(
            chain.message.contains(&ids[1].to_string()),
            "{}",
            chain.message
        );
        assert_eq!(
            report.get("journal.index").map(|c| c.status),
            Some(Status::Ok),
            "число записей сходится и при разрыве цепочки"
        );

        // Обрыв между фазами записи: в индексе больше записей, чем в хранилище — FAIL journal.index.
        let counts = [(tenant, 4)];
        let mut report = Report::default();
        journal_chain(
            &journal,
            Some(&records),
            None,
            &tenants,
            &counts,
            &mut report,
        )
        .await;
        let index = report.get("journal.index").expect("index");
        assert_eq!(index.status, Status::Fail, "{report:?}");
        assert!(index.message.contains("в индексе 4"), "{}", index.message);
        assert!(index.message.contains("restore_index"), "{}", index.message);
    }

    /// APP-82: замеры объёма по хранилищу записей — записи, средний размер письма (выборка) и записей
    /// в сутки по размаху дат.
    #[tokio::test]
    async fn journal_volume_measures() {
        use tp_blob::system_now;
        use tp_contracts::journal::GENESIS_HASH;

        let dir = tempfile::tempdir().expect("tempdir");
        let local = tp_blob::LocalStore::open(tp_blob::LocalConfig {
            root: dir.path().join("journal"),
            ..tp_blob::LocalConfig::default()
        })
        .await
        .expect("local");
        let records = tp_blob::JournalRecords::new(
            Arc::new(local),
            tp_blob::JournalConfig::default(),
            system_now(),
        )
        .expect("records");
        let tenant = TenantId::DEFAULT;
        let mut prev = GENESIS_HASH;
        for i in 0..3i64 {
            let record = serde_json::from_value::<JournalRecord>(serde_json::json!({
                "tenant": tenant.to_string(),
                "sender": format!("s{i}@external.example"),
                "recipients": ["anna@internal.example"],
                "message_id": format!("m{i}@external.example"),
                "at": (["2026-12-14T00:00:00Z", "2026-12-15T00:00:00Z", "2026-12-16T00:00:00Z"]
                    [i as usize]),
                "rule": "r-0042",
            }))
            .expect("record");
            prev = records
                .put(
                    JournalId::new(),
                    prev,
                    &record,
                    Bytes::from(vec![0u8; 4096]),
                )
                .await
                .expect("put");
        }
        let volume = journal_volume(&records, &[tenant], None).await;
        assert_eq!(volume.records, 3);
        assert_eq!(volume.avg_record_bytes, Some(4096));
        assert_eq!(volume.enabled_rules, None, "без СУБД правила не считаны");
        // Размах дат — двое суток: 3 записи / 2 суток.
        let rate = volume.records_per_day.expect("rate");
        assert!((rate - 1.5).abs() < 1e-9);
    }

    /// APP-82: прогноз объёма на срок блокировки — от правил и средних размеров; предупреждения —
    /// срок дольше 10 лет (риск 21) и нет включённых правил.
    #[test]
    fn journal_retention_forecast_and_warnings() {
        let day = Duration::from_secs(86_400);
        let volume = JournalVolume {
            records: 500,
            enabled_rules: Some(3),
            avg_record_bytes: Some(10_240),
            records_per_day: Some(100.0),
        };
        let (status, value, msg) = journal_retention_status(730 * day, &volume);
        assert_eq!(status, Status::Ok);
        assert!(value.contains("730 сут."), "{value}");
        assert!(value.contains("MiB"), "{value}");
        assert!(msg.contains("100.0 записей/сутки"), "{msg}");
        assert!(msg.contains("10.0 KiB"), "{msg}");

        // Срок дольше 10 лет — предупреждение (риск 21): compliance не освобождает бакет.
        let (status, _, msg) = journal_retention_status(11 * 365 * day, &volume);
        assert_eq!(status, Status::Warn);
        assert!(msg.contains("compliance"), "{msg}");

        // Нет включённых правил — новых записей не будет (правила — Admin API).
        let empty = JournalVolume {
            records: 0,
            enabled_rules: Some(0),
            avg_record_bytes: None,
            records_per_day: None,
        };
        let (status, _, msg) = journal_retention_status(730 * day, &empty);
        assert_eq!(status, Status::Warn);
        assert!(msg.contains("Admin API"), "{msg}");

        // Без СУБД (правила не считаны) и без записей — не предупреждение.
        let unknown = JournalVolume {
            enabled_rules: None,
            ..empty
        };
        let (status, _, _) = journal_retention_status(730 * day, &unknown);
        assert_eq!(status, Status::Ok);
    }

    /// APP-82: прицельный прогон `thepost doctor journal` — только проверки журнала: без секции
    /// `journal` объяснение, общие проверки окружения не выполняются.
    #[tokio::test]
    async fn doctor_journal_targeted_without_section() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = write_config(
            dir.path(),
            "domain: example.org\nprofile: dev\ndatabase:\n  url: postgres://thepost@127.0.0.1:1/thepost?sslmode=disable\n  acquire_timeout: 1s\n  tls: { allow_plaintext: true }\nblob:\n  url: file:///nonexistent/blob\n",
        );
        let report = run_journal(&path, None).await;
        let backend = report.get("journal.backend").expect("journal.backend");
        assert_eq!(backend.status, Status::Skipped, "{report:?}");
        // Секции нет — она разбирается как выключенная: оба объяснения говорят о журналировании.
        assert!(
            backend.message.contains("журналирован"),
            "{}",
            backend.message
        );
        assert!(
            report.get("database.connect").is_none(),
            "прицельный прогон не выполняет общие проверки: {report:?}"
        );
    }

    /// Внутренний CA (10 лет) и сертификат узла от него (825 сут.), как у роли thepost_pki.
    const PKI_CA: &[u8] = include_bytes!("testdata/pki-ca.pem");
    const PKI_NODE: &[u8] = include_bytes!("testdata/pki-node.pem");
    /// Самоподписанный сертификат другого издателя.
    const OTHER: &[u8] = include_bytes!("testdata/cert.pem");

    fn pki_config(dir: &Path, db_ca: &str, secrets: &str, node: &Path) -> Config {
        let slash = |p: &Path| p.display().to_string().replace('\\', "/");
        sections::registry()
            .expect("registry")
            .parse(
                &format!(
                    "domain: example.org\nprofile: dev\ndatabase:\n  url: \"postgres://thepost@db:5432/thepost?sslmode=verify-full{db_ca}\"\n\
                     blob:\n  url: file:///tmp/b\ntls:\n  cert_file: \"{node}\"\n{secrets}",
                    node = slash(node),
                ),
                Vec::new(),
            )
            .unwrap_or_else(|e| panic!("config {}: {e}", dir.display()))
    }

    async fn pki_report(cfg: &Config, now: SystemTime) -> Report {
        let mut report = Report::default();
        internal_pki(cfg, now, &mut report).await;
        report
    }

    fn pki_status(r: &Report, id: &str) -> Option<Status> {
        r.get(id).map(|c| c.status)
    }

    /// APP-36: ключи внутренних каналов по правилу APP-35 — ключ из хранилища секретов (файл не читается) и из
    /// файла проверяются на пару с сертификатом; без хранилища секретов проверка пропускается; значение ключа в
    /// отчёт не попадает.
    #[tokio::test]
    async fn internal_channel_keys() {
        let certs = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tp-cluster/src/testdata");
        let c = certs.display();
        let config = |rpc_key: &str, db_key: &str| {
            sections::registry()
                .expect("registry")
                .parse(
                    &format!(
                        "domain: example.org\nprofile: dev\n\
                         database:\n  url: postgres://x@y/z\n  tls:\n    ca_file: {c}/ca.pem\n    \
                         cert_file: {c}/node-b.pem\n    {db_key}\n\
                         blob:\n  url: file:///tmp/b\n\
                         cluster:\n  rpc:\n    tls:\n      ca_file: {c}/ca.pem\n      \
                         cert_file: {c}/node-b.pem\n      {rpc_key}\n"
                    ),
                    Vec::new(),
                )
                .expect("config")
        };
        let ids = ["cluster.rpc.tls.key", "database.tls.key"];
        let statuses = |r: &Report| ids.map(|id| r.get(id).map(|c| c.status));

        // Ключ в файле: хранилище не нужно.
        let key_file = format!("key_file: {c}/node-b-key.pem");
        let mut report = Report::default();
        internal_keys(&config(&key_file, &key_file), None, None, &mut report).await;
        assert_eq!(statuses(&report), [Some(Status::Ok); 2], "{report:?}");
        // Чужой ключ в файле.
        let other = format!("key_file: {c}/node-a-key.pem");
        let mut report = Report::default();
        internal_keys(&config(&other, &other), None, None, &mut report).await;
        assert_eq!(statuses(&report), [Some(Status::Fail); 2], "{report:?}");

        // Ключ по ссылке на секрет.
        let by_secret = "key: { secret: \"thepost/node-b#key\" }";
        let cfg = config(by_secret, by_secret);
        let mut report = Report::default();
        internal_keys(&cfg, None, None, &mut report).await;
        assert_eq!(statuses(&report), [Some(Status::Skipped); 2], "{report:?}");
        let mem = Arc::new(tp_testkit::MemSecretStore::default());
        let key = "thepost/node-b#key".parse().expect("ref");
        let pem = std::fs::read_to_string(certs.join("node-b-key.pem")).expect("key");
        mem.set(&key, pem.clone());
        let store: Arc<dyn SecretStore> = mem.clone();
        let mut report = Report::default();
        internal_keys(&cfg, Some(&store), None, &mut report).await;
        assert_eq!(statuses(&report), [Some(Status::Ok); 2], "{report:?}");
        for id in ids {
            let check = report.get(id).expect("check");
            assert_eq!(check.value, "секрет thepost/node-b#key", "{check:?}");
        }
        // Секрет с чужим ключом: FAIL, значение ключа в отчёт не попадает.
        let wrong = std::fs::read_to_string(certs.join("node-a-key.pem")).expect("key");
        mem.set(&key, wrong.clone());
        let mut report = Report::default();
        internal_keys(&cfg, Some(&store), None, &mut report).await;
        assert_eq!(statuses(&report), [Some(Status::Fail); 2], "{report:?}");
        let body = wrong.lines().nth(1).expect("key body");
        assert!(!format!("{report:?}").contains(body), "ключ в отчёте");

        // Каналы без mTLS: проверки пропущены.
        let plain = sections::registry()
            .expect("registry")
            .parse(
                "domain: example.org\nprofile: dev\ndatabase:\n  url: postgres://x@y/z\n\
                 blob:\n  url: file:///tmp/b\n",
                Vec::new(),
            )
            .expect("config");
        let mut report = Report::default();
        internal_keys(&plain, None, None, &mut report).await;
        assert_eq!(statuses(&report), [Some(Status::Skipped); 2], "{report:?}");
    }

    /// Сроки внутренних сертификатов (APP-25): OK, WARN за 60 сут., FAIL после срока; издатель узла — другой CA.
    #[tokio::test]
    async fn internal_certificates_expiry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = dir.path().join("ca.pem");
        let node = dir.path().join("fullchain.pem");
        let other = dir.path().join("other.pem");
        std::fs::write(&ca, PKI_CA).expect("ca");
        std::fs::write(&node, PKI_NODE).expect("node");
        std::fs::write(&other, OTHER).expect("other");
        let slash = |p: &Path| p.display().to_string().replace('\\', "/");
        let day = Duration::from_secs(86_400);
        let node_end = pem_certs(PKI_NODE).expect("node").not_after;
        let ca_end = pem_certs(PKI_CA).expect("ca").not_after;
        assert!(ca_end > node_end + 365 * day, "CA дольше сертификата узла");

        // SMB: CA СУБД — sslrootcert адреса, OpenBao — secrets.tls.ca_file.
        let secrets = format!(
            "secrets:\n  url: https://bao.internal:8200\n  tls:\n    ca_file: \"{}\"\n  auth:\n    token: {{ token_file: /run/thepost/openbao-token }}\n",
            slash(&ca)
        );
        let cfg = pki_config(
            dir.path(),
            &format!("&sslrootcert={}", slash(&ca)),
            &secrets,
            &node,
        );
        for (now, node_status) in [
            (node_end - 200 * day, Status::Ok),
            (node_end - 59 * day, Status::Warn),
            (node_end + day, Status::Fail),
        ] {
            let r = pki_report(&cfg, now).await;
            assert_eq!(pki_status(&r, "pki.node"), Some(node_status), "{r:?}");
            assert_eq!(pki_status(&r, "pki.database_ca"), Some(Status::Ok), "{r:?}");
            assert_eq!(pki_status(&r, "pki.secrets_ca"), Some(Status::Ok), "{r:?}");
            if node_status != Status::Ok {
                let msg = &r.get("pki.node").expect("node").message;
                assert!(msg.contains("плейбук"), "{msg}");
            }
        }
        let r = pki_report(&cfg, node_end - 30 * day).await;
        assert!(
            r.get("pki.node")
                .expect("node")
                .message
                .contains("через 30 сут."),
            "{r:?}"
        );
        let r = pki_report(&cfg, ca_end - 10 * day).await;
        assert_eq!(
            pki_status(&r, "pki.database_ca"),
            Some(Status::Warn),
            "{r:?}"
        );
        let r = pki_report(&cfg, ca_end + day).await;
        assert_eq!(
            pki_status(&r, "pki.secrets_ca"),
            Some(Status::Fail),
            "{r:?}"
        );
        assert!(
            r.get("pki.secrets_ca")
                .expect("ca")
                .message
                .contains("thepost_pki"),
            "{r:?}"
        );
        assert_eq!(r.exit_code(), 1);

        // Сертификат узла другого издателя (ACME, коммерческий) — проверка tls.certificate.
        let cfg = pki_config(
            dir.path(),
            &format!("&sslrootcert={}", slash(&ca)),
            "",
            &other,
        );
        let r = pki_report(&cfg, node_end - 59 * day).await;
        assert_eq!(pki_status(&r, "pki.node"), Some(Status::Skipped), "{r:?}");
        assert_eq!(
            pki_status(&r, "pki.secrets_ca"),
            Some(Status::Skipped),
            "{r:?}"
        );

        // Без внутреннего CA и с системным набором — пропуск; нет файла CA — WARN.
        let cfg = pki_config(dir.path(), "", "", &node);
        let r = pki_report(&cfg, SystemTime::now()).await;
        for id in ["pki.database_ca", "pki.secrets_ca", "pki.node"] {
            assert_eq!(pki_status(&r, id), Some(Status::Skipped), "{id}: {r:?}");
        }
        let cfg = pki_config(
            dir.path(),
            "&sslrootcert=/etc/ssl/certs/ca-certificates.crt",
            "",
            &node,
        );
        let r = pki_report(&cfg, SystemTime::now()).await;
        assert_eq!(
            pki_status(&r, "pki.database_ca"),
            Some(Status::Skipped),
            "{r:?}"
        );
        let cfg = pki_config(dir.path(), "&sslrootcert=/nonexistent/ca.pem", "", &node);
        let r = pki_report(&cfg, SystemTime::now()).await;
        assert_eq!(
            pki_status(&r, "pki.database_ca"),
            Some(Status::Warn),
            "{r:?}"
        );
    }

    /// Самоподписанные сертификаты mx.example.org со сроком 47 сут. (график CA/B Forum с 03.2029,
    /// ballot SC-081v3) и 398 сут. (нынешний предел публичных CA); выпущены 2026-01-01.
    const SHORT: &[u8] = include_bytes!("testdata/cert-47d.pem");
    const NOT_SHORT: &[u8] = include_bytes!("testdata/cert-398d.pem");

    /// APP-81: сертификат узла на 47 сут. — предупреждение с числами (срок и начало продления по
    /// правилу PLT-37: окно — треть срока, продление — через 47 − 15⅔ = 31 сут. после выпуска); при
    /// `acme.enabled` — приписка про встроенный ACME, без секции и при выключенном — про ручной
    /// перевыпуск. На 398 сут. предупреждения нет — прежний пропуск.
    #[tokio::test]
    async fn short_node_certificate_warns() {
        let dir = tempfile::tempdir().expect("tempdir");
        let short = dir.path().join("short.pem");
        let long = dir.path().join("long.pem");
        std::fs::write(&short, SHORT).expect("short");
        std::fs::write(&long, NOT_SHORT).expect("long");
        let slash = |p: &Path| p.display().to_string().replace('\\', "/");
        // «Сейчас» — внутри срока сертификатов: проверка короткого срока не зависит от него,
        // но так сообщение не спорит с проверкой tls.certificate.
        let now = pem_certs(SHORT).expect("short").not_before + DAY;
        let config = |cert: &Path, extra: &str| {
            sections::registry()
                .expect("registry")
                .parse(
                    &format!(
                        "domain: example.org\nprofile: dev\ndatabase:\n  url: postgres://x@y/z?sslmode=disable\n  tls: {{ allow_plaintext: true }}\n\
                         blob:\n  url: file:///tmp/b\ntls:\n  cert_file: \"{}\"\n{extra}",
                        slash(cert)
                    ),
                    Vec::new(),
                )
                .expect("config")
        };

        // Продлением занимается узел (встроенный ACME).
        let cfg = config(
            &short,
            "acme:\n  enabled: true\n  domains: [mx.example.org]\n",
        );
        let r = pki_report(&cfg, now).await;
        let node = r.get("pki.node").expect("pki.node");
        assert_eq!(node.status, Status::Warn, "{r:?}");
        for part in [
            "сертификат живёт 47 дней",
            "продление начнётся через 31 день",
            "короткие сертификаты",
            "продлением занимается узел (встроенный ACME)",
        ] {
            assert!(node.message.contains(part), "{}: {part}", node.message);
        }

        // Секции acme нет и включена с false — автоматического продления нет, перевыпуск вручную.
        for extra in ["", "acme:\n  enabled: false\n"] {
            let r = pki_report(&config(&short, extra), now).await;
            let node = r.get("pki.node").expect("pki.node");
            assert_eq!(node.status, Status::Warn, "{extra}: {r:?}");
            for part in [
                "сертификат живёт 47 дней",
                "автоматическое продление не настроено: перевыпуск — вручную или внешним средством",
            ] {
                assert!(node.message.contains(part), "{extra}: {part}");
            }
            assert!(!node.message.contains("ACME"), "{extra}: {}", node.message);
        }

        // 398 сут. — не короткий: прежний пропуск («внутреннего CA нет» и у другого издателя).
        let cfg = config(
            &long,
            "acme:\n  enabled: true\n  domains: [mx.example.org]\n",
        );
        let r = pki_report(&cfg, now).await;
        assert_eq!(pki_status(&r, "pki.node"), Some(Status::Skipped), "{r:?}");
        assert_eq!(
            r.get("pki.node").expect("node").message,
            "внутреннего CA нет"
        );

        // Внутренний CA настроен, сертификат короткий, но другого издателя (ACME, коммерческий CA) —
        // предупреждение вместо прежнего пропуска «срок — проверка tls.certificate»; длинный — пропуск.
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, PKI_CA).expect("ca");
        let cfg = pki_config(
            dir.path(),
            &format!("&sslrootcert={}", slash(&ca)),
            "",
            &short,
        );
        let r = pki_report(&cfg, now).await;
        let node = r.get("pki.node").expect("pki.node");
        assert_eq!(node.status, Status::Warn, "{r:?}");
        assert!(node.message.contains("47 дней"), "{}", node.message);
        let cfg = pki_config(
            dir.path(),
            &format!("&sslrootcert={}", slash(&ca)),
            "",
            &long,
        );
        let r = pki_report(&cfg, now).await;
        assert_eq!(pki_status(&r, "pki.node"), Some(Status::Skipped), "{r:?}");
        assert_eq!(
            r.get("pki.node").expect("node").message,
            "выпущен не внутренним CA: срок — проверка tls.certificate"
        );
    }

    /// APP-81: файл сертификата узла не читается — прежнее поведение doctor, без паники: с внутренним
    /// CA — пропуск с причиной («файл не прочитан … см. tls.certificate»), без него — «внутреннего CA нет».
    #[tokio::test]
    async fn unreadable_node_certificate_keeps_prior_result() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, PKI_CA).expect("ca");
        let missing = dir.path().join("missing.pem");
        let slash = |p: &Path| p.display().to_string().replace('\\', "/");

        let cfg = pki_config(
            dir.path(),
            &format!("&sslrootcert={}", slash(&ca)),
            "",
            &missing,
        );
        let r = pki_report(&cfg, SystemTime::now()).await;
        assert_eq!(pki_status(&r, "pki.node"), Some(Status::Skipped), "{r:?}");
        let msg = &r.get("pki.node").expect("node").message;
        assert!(msg.contains("файл не прочитан"), "{msg}");
        assert!(msg.contains("см. tls.certificate"), "{msg}");

        let cfg = pki_config(dir.path(), "", "", &missing);
        let r = pki_report(&cfg, SystemTime::now()).await;
        assert_eq!(pki_status(&r, "pki.node"), Some(Status::Skipped), "{r:?}");
        assert_eq!(
            r.get("pki.node").expect("node").message,
            "внутреннего CA нет"
        );
    }
}
