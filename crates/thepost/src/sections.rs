//! Секции config.yaml приложения и реестр секций всех крейтов (SRS 5.5; APP-01, PLT-09).
//!
//! Приложение регистрирует секции полос (`database`, `meta`) и свои: `blob` — хранилище BLOB (локальный каталог
//! или S3), `bus` — шина уведомлений (в процессе), `cluster` — имя узла и опросы, `doctor` — пороги
//! проверок окружения, `startup` — ожидание хранилища секретов при запуске. Проверки открытых каналов подключаются через [`SectionRegistry::add_check`]: `thepost config
//! check` (строгий режим) и запуск (мягкий режим) отвергают адрес без TLS вне профиля dev.
//!
//! Подсекции `blob.local` и `blob.s3` — секции крейта `tp-blob` как есть (BLOB-11): приложение подставляет только каталог, бакет и префикс из `blob.url`.
//!
//! Секция `journal` (APP-83, SRS 4.9) — журналирование переписки: хранилище записей — отдельное от BLOB
//! ящиков (`s3` бакет с Object Lock или `local` каталог профиля SMB), режим и срок блокировки, выгрузка во
//! внешний архив; правила журналирования — данные организации (Admin API), не файл узла.
//!
//! Секции ролей (APP-04) — секции крейтов как есть: `smtp`, `sieve`, `imap`, `jmap`, `dav`, `search`, `mailstore`; `admin` — секция
//! `tp-admin` без `listen` (адрес Admin API — один ключ `http.admin.listen`, APP-16); приложение добавляет `auth`
//! (каталог, OIDC, пароли приложений, Kerberos) и `http` (слушатели jmap, dav и admin).

use std::borrow::Cow;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer};
use tp_blob::{GcConfig, JournalConfig, LocalConfig, LockMode, OrphanConfig, S3Config};
use tp_cluster::{LocalBusConfig, RpcConfig};
use tp_contracts::config::duration;
use tp_contracts::role::{Role, RoleSet};
use tp_contracts::tls::{InternalChannel, Profile};
use tp_contracts::{Error, Result};
use tp_meta::MetaConfig;
use tp_meta::pool::PoolConfig;
use tp_platform::{Config, SectionRegistry, ServiceHttpConfig};

use crate::modules;

/// Имя секции хранилища BLOB.
pub const BLOB: &str = "blob";
/// Имя секции журнала переписки.
pub const JOURNAL: &str = "journal";
/// Имя секции шины уведомлений.
pub const BUS: &str = "bus";
/// Имя секции кластера.
pub const CLUSTER: &str = "cluster";
/// Имя секции порогов `thepost doctor`.
pub const DOCTOR: &str = "doctor";
/// Имя секции запуска узла.
pub const STARTUP: &str = "startup";
/// Имя секции `thepost verify`.
pub const VERIFY: &str = "verify";
/// Имя секции SMTP (`tp-smtp`).
pub const SMTP: &str = "smtp";
/// Имя секции IMAP (`tp-imap`).
pub const IMAP: &str = "imap";
/// Имя секции JMAP (`tp-jmap`).
pub const JMAP: &str = "jmap";
/// Имя секции календарей и контактов CalDAV/CardDAV (`tp-dav`).
pub const DAV: &str = "dav";
/// Имя секции правил Sieve и автоответа (`tp-sieve`).
pub const SIEVE: &str = "sieve";
/// Имя секции поиска (`tp-search`).
pub const SEARCH: &str = "search";
/// Имя секции Admin API (`tp-admin`).
pub const ADMIN: &str = "admin";
/// Имя секции почтового хранилища (`tp-mailstore`).
pub const MAILSTORE: &str = "mailstore";
/// Имя секции роли maintenance.
pub const MAINTENANCE: &str = "maintenance";
/// Имя секции командной строки `thepost admin`.
pub const CLI: &str = "cli";
/// Имя секции входа: каталог, OIDC, пароли приложений, Kerberos.
pub const AUTH: &str = "auth";
/// Имя секции слушателей HTTP ролей jmap, dav и admin.
pub const HTTP: &str = "http";
/// Имя секции кэша политики доверия.
pub const TRUST: &str = "trust";
/// Имя секции справочника аномалий (APP-78).
pub const RISK: &str = "risk";

/// Реестр секций: платформа, `tp-meta`, приложение и встроенные модули; проверки каналов.
pub fn registry() -> Result<SectionRegistry> {
    registry_of(modules::BUILTIN)
}

/// Как [`registry`] с секциями модулей `builtin` (тесты — свои модули).
pub fn registry_of(builtin: &[modules::Builtin]) -> Result<SectionRegistry> {
    let mut r = SectionRegistry::new();
    r.add_section::<PoolConfig>(PoolConfig::SECTION)?;
    r.add_section::<MetaConfig>(MetaConfig::SECTION)?;
    r.add_section::<BlobSection>(BLOB)?;
    r.add_section::<JournalSection>(JOURNAL)?;
    r.add_section::<BusSection>(BUS)?;
    r.add_section::<ClusterSection>(CLUSTER)?;
    r.add_section::<DoctorSection>(DOCTOR)?;
    r.add_section::<VerifySection>(VERIFY)?;
    r.add_section::<StartupSection>(STARTUP)?;
    r.add_section::<MaintenanceSection>(MAINTENANCE)?;
    r.add_section::<CliSection>(CLI)?;
    r.add_section::<tp_smtp::SmtpConfig>(SMTP)?;
    r.add_section::<tp_sieve::SieveConfig>(SIEVE)?;
    r.add_section::<tp_imap::ImapConfig>(IMAP)?;
    r.add_section::<tp_jmap::JmapConfig>(JMAP)?;
    r.add_section::<tp_dav::DavConfig>(DAV)?;
    r.add_section::<tp_search::SearchConfig>(SEARCH)?;
    r.add_section::<AdminSection>(ADMIN)?;
    r.add_section::<tp_mailstore::Config>(MAILSTORE)?;
    r.add_section::<AuthSection>(AUTH)?;
    r.add_section::<HttpSection>(HTTP)?;
    r.add_section::<TrustSection>(TRUST)?;
    r.add_section::<RiskSection>(RISK)?;
    r.add_check::<RiskSection>(RISK, |c, profile| c.check(profile))?;
    r.add_check::<PoolConfig>(PoolConfig::SECTION, |c, profile| {
        pool_config(c, profile).check().map(drop)
    })?;
    r.add_check::<BlobSection>(BLOB, BlobSection::check)?;
    r.add_check::<JournalSection>(JOURNAL, |c, profile| c.check(profile))?;
    r.add_check::<StartupSection>(STARTUP, |c, _| c.check())?;
    r.add_check::<MaintenanceSection>(MAINTENANCE, |c, _| c.check())?;
    r.add_check::<CliSection>(CLI, |c, _| c.oidc.check())?;
    r.add_check::<ClusterSection>(CLUSTER, |c, _| c.check())?;
    r.add_check::<AdminSection>(ADMIN, |c, _| c.0.check())?;
    r.add_check::<AuthSection>(AUTH, AuthSection::check)?;
    r.add_check::<HttpSection>(HTTP, HttpSection::check)?;
    modules::register_sections_of(&mut r, builtin)?;
    // Секция веб-клиента (WEB-01, полоса mod-webmail): модуль `modules.webmail`, фича `webmail`.
    #[cfg(feature = "webmail")]
    crate::webmail::register(&mut r)?;
    Ok(r)
}

/// Секция `database` с профилем узла (поле профиля задаёт приложение, в config.yaml его нет).
pub fn pool_config(c: &PoolConfig, profile: Profile) -> PoolConfig {
    PoolConfig {
        profile,
        ..c.clone()
    }
}

// ---------- blob ----------

/// Секция `blob`: хранилище объектов писем и индексов.
///
/// ```yaml
/// blob:
///   url: file:///var/lib/thepost/blob      # или s3://thepost-blob/prefix
///   s3:
///     endpoint: https://seaweedfs:8333
///     credentials:
///       access_key_id: { secret: "thepost/s3#access_key_id" }
///       secret_access_key: { secret: "thepost/s3#secret_access_key" }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct BlobSection {
    /// Адрес хранилища: `file:///<каталог>` — локальный каталог (в том числе общий для узлов),
    /// `s3://<бакет>[/<префикс>]` — S3 (адрес API — `s3.endpoint`). Требует перезапуска.
    pub url: String,
    /// Параметры локального каталога — секция `tp-blob`; каталог (`root`) задаётся в `url`.
    pub local: LocalConfig,
    /// Параметры S3 — секция `tp-blob`; бакет и префикс (`bucket`, `prefix`) задаются в `url`.
    pub s3: S3Config,
    /// Сборка мусора объектов (роль maintenance) — секция `tp-blob`.
    pub gc: GcConfig,
    /// Поиск «сирот» (роль maintenance) — секция `tp-blob`.
    pub orphans: OrphanConfig,
    /// Сжатие объектов писем zstd при записи (BLOB-13, MS-15) — секция `tp-blob`.
    pub compression: tp_blob::CompressionConfig,
}

/// Где лежат объекты: разобранный `blob.url`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobLocation {
    /// Локальный каталог.
    Local(PathBuf),
    /// Бакет S3 и префикс ключей.
    S3 {
        /// Бакет.
        bucket: String,
        /// Префикс ключей; пустой — без префикса.
        prefix: String,
    },
}

impl BlobSection {
    /// Разбор `url`.
    pub fn location(&self) -> Result<BlobLocation> {
        let url = self.url.trim();
        if let Some(path) = url.strip_prefix("file://") {
            if !path.starts_with('/') {
                return Err(Error::invalid(
                    "blob.url: путь file:// должен быть абсолютным (file:///var/lib/thepost/blob)",
                ));
            }
            return Ok(BlobLocation::Local(PathBuf::from(path)));
        }
        if let Some(rest) = url.strip_prefix("s3://") {
            let (bucket, prefix) = rest.split_once('/').unwrap_or((rest, ""));
            if bucket.is_empty() {
                return Err(Error::invalid("blob.url: не задан бакет s3://<бакет>"));
            }
            return Ok(BlobLocation::S3 {
                bucket: bucket.to_owned(),
                prefix: prefix.trim_matches('/').to_owned(),
            });
        }
        Err(Error::invalid(
            "blob.url: ожидается file:///<каталог> или s3://<бакет>[/<префикс>]",
        ))
    }

    /// Конфигурация локального хранилища для каталога `root` из `url`.
    pub fn local_config(&self, root: PathBuf) -> LocalConfig {
        LocalConfig {
            root,
            ..self.local.clone()
        }
    }

    /// Конфигурация S3 для бакета и префикса из `url`.
    pub fn s3_config(&self, bucket: String, prefix: String) -> S3Config {
        S3Config {
            bucket,
            prefix,
            ..self.s3.clone()
        }
    }

    /// Проверка секции: адрес, TLS канала S3 (`https://`; `http://` — только dev с `s3.tls.allow_plaintext`);
    /// каталог, бакет и префикс — только в `url`.
    pub fn check(&self, profile: Profile) -> Result<()> {
        self.s3.tls.validate(InternalChannel::S3, profile)?;
        if self.local.root != LocalConfig::default().root {
            return Err(Error::invalid(
                "local.root: каталог задаётся в blob.url (file:///<каталог>)",
            ));
        }
        if self.s3.bucket != S3Config::default().bucket || !self.s3.prefix.is_empty() {
            return Err(Error::invalid(
                "s3.bucket, s3.prefix: бакет и префикс задаются в blob.url (s3://<бакет>/<префикс>)",
            ));
        }
        match self.location()? {
            BlobLocation::Local(_) => Ok(()),
            BlobLocation::S3 { bucket, prefix } => {
                self.s3_config(bucket, prefix).check(profile).map(drop)
            }
        }
    }
}

// ---------- journal ----------

/// Подсказка для `journal.rules`: правила журналирования — данные организации (Admin API), не файл
/// узла (SRS 4.9, APP-83): как `JournalRule` Exchange — командлетами, а не конфигом сервера.
const JOURNAL_RULES_HINT: &str = "journal.rules не используется: правила журналирования — данные \
     организации, задаются через Admin API; в config.yaml — только параметры узла (хранилище записей, \
     режим и срок блокировки, выгрузка)";

/// Срок блокировки записей журнала по умолчанию (SRS 4.9: 730 суток, как у tp-blob BLOB-18);
/// для режима `compliance` срок задаётся явно.
pub const JOURNAL_RETENTION_DEFAULT: Duration = Duration::from_secs(730 * 24 * 3600);

/// Секция `journal`: журналирование переписки (SRS 4.9, 5.5; APP-83). Выключено по умолчанию —
/// включается явно. Хранилище записей — отдельное от BLOB ящиков (SRS 4.9): `s3` — бакет с Object Lock
/// или `local` — каталог на локальном диске (профиль SMB: блокировка только сервером, предупреждение
/// `thepost doctor`). Правила журналирования — данные организации (Admin API), не здесь.
///
/// ```yaml
/// journal:
///   enabled: true
///   s3:
///     bucket: thepost-journal     # отдельный от бакета BLOB ящиков
///     lock_mode: governance       # compliance — явно и только с явным сроком (риск 21)
///     retention: 2555d            # срок блокировки при записи; не задан — 730d
///     # …прочие параметры S3 — подсекция tp-blob (endpoint, credentials), как у blob.s3
///   # local:                      # профиль SMB: локальный каталог
///   #   dir: /var/lib/thepost/journal
///   export:                       # выгрузка во внешний архив (.eml с конвертом)
///     address: archive.example.ru:25
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JournalSection(JournalFields);

/// Поля секции (разбор и схема; `rules` — известный, но отвергаемый ключ, см. [`JOURNAL_RULES_HINT`]).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
struct JournalFields {
    /// Журналирование включено; по умолчанию выключено — включается явно (SRS 4.9). Требует перезапуска.
    pub enabled: bool,
    /// Хранилище записей — S3: отдельный бакет с Object Lock (Enterprise); одновременно с `local` — ошибка.
    pub s3: Option<JournalS3>,
    /// Хранилище записей — локальный каталог (профиль SMB); одновременно с `s3` — ошибка.
    pub local: Option<JournalLocal>,
    /// Префикс объектов журнала внутри корня/бакета (`journal`); сегменты через `/`, без пустых.
    pub prefix: String,
    /// Минимальный размер части записи, байт: ближе точки сливаются (дедупликация, BLOB-18).
    pub chunk_min_bytes: usize,
    /// Средний размер части записи, байт: задаёт порог разреза.
    pub chunk_avg_bytes: usize,
    /// Максимальный размер части записи, байт: режется принудительно.
    pub chunk_max_bytes: usize,
    /// Выгрузка записей во внешний архив заказчика (.eml с конвертом; SRS 4.9).
    pub export: JournalExport,
}

impl Default for JournalFields {
    fn default() -> Self {
        let records = JournalConfig::default();
        Self {
            enabled: false,
            s3: None,
            local: None,
            prefix: records.prefix,
            chunk_min_bytes: records.chunk_min_bytes,
            chunk_avg_bytes: records.chunk_avg_bytes,
            chunk_max_bytes: records.chunk_max_bytes,
            export: JournalExport::default(),
        }
    }
}

impl<'de> Deserialize<'de> for JournalSection {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let value = serde_json::Value::deserialize(d)?;
        if value.is_null() {
            return Ok(Self::default());
        }
        if value.get("rules").is_some() {
            return Err(D::Error::custom(JOURNAL_RULES_HINT));
        }
        JournalFields::deserialize(value)
            .map(Self)
            .map_err(D::Error::custom)
    }
}

impl JsonSchema for JournalSection {
    fn schema_name() -> Cow<'static, str> {
        "JournalSection".into()
    }

    /// Схема полей; `rules` — известный, но отвергаемый ключ с подсказкой (как `admin.listen`):
    /// иначе мягкий режим отбросил бы его с предупреждением, не сказав, куда идти.
    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let mut schema = JournalFields::json_schema(generator);
        if let Some(props) = schema.get_mut("properties").and_then(|p| p.as_object_mut()) {
            props.insert(
                "rules".to_owned(),
                serde_json::json!({ "description": JOURNAL_RULES_HINT, "not": {} }),
            );
        }
        schema
    }
}

/// `journal.s3`: хранилище записей журнала — отдельный бакет S3 с Object Lock (SRS 4.9). Режим и срок
/// блокировки tp-blob пишет в каждый объект при записи (`x-amz-meta-thepost-lock-*`, решение #113,
/// BLOB-18); бакетный дефолт в срок не входит. Прочие параметры S3 — подсекция `tp-blob` как у
/// `blob.s3` (endpoint, ключи, таймауты).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
pub struct JournalS3 {
    /// Бакет записей журнала — отдельный от бакета BLOB ящиков (`blob.url`); проверяет
    /// `thepost config check`.
    pub bucket: String,
    /// Режим блокировки объектов (S3 Object Lock): `governance` по умолчанию; `compliance` — явно и
    /// только с явным сроком (риск 21: объект compliance не удаляет никто до конца срока).
    #[serde(default)]
    pub lock_mode: LockMode,
    /// Срок блокировки при записи (`retention: 2555d`); не задан — [`JOURNAL_RETENTION_DEFAULT`].
    /// Для `compliance` обязателен явно. Продлевается только.
    #[serde(default, with = "duration::option")]
    #[schemars(with = "Option<duration::HumanDuration>")]
    pub retention: Option<Duration>,
    /// Параметры S3 — подсекция `tp-blob` (`endpoint`, `credentials`, таймауты); бакет задаётся
    /// полем `bucket` этой подсекции.
    #[serde(flatten)]
    pub params: S3Config,
}

/// `journal.local`: хранилище записей журнала на локальном диске (профиль SMB, SRS 4.9). Неизменяемость
/// обеспечивает только сервер (записи лишь добавляются); от администратора ОС защиты нет — предупреждение
/// `thepost doctor` (APP-82); для требований неизменяемости — S3 с Object Lock (`journal.s3`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
pub struct JournalLocal {
    /// Каталог записей журнала (абсолютный путь), отдельный от каталога BLOB ящиков.
    pub dir: PathBuf,
    /// Параметры локального хранилища — подсекция `tp-blob` как у `blob.local` (`fsync`, `stale_tmp`);
    /// каталог задаётся полем `dir` этой подсекции.
    #[serde(flatten)]
    pub params: LocalConfig,
}

/// Формат выгрузки записи во внешний архив (SRS 4.9): .eml с конвертом `X-ThePost-Journal-*`
/// (модель journal report Exchange).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum JournalExportFormat {
    /// Письмо целиком с добавленными заголовками конверта.
    #[default]
    Eml,
}

/// `journal.export`: выгрузка записей во внешний архив заказчика (SRS 4.9) — .eml с конвертом; при сбое
/// приёмника запись ждёт и уходит повторами (пока не истёк `retry_for`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct JournalExport {
    /// Приёмник архива (`host:port`, SMTP); не задан — выгрузка выключена.
    pub address: Option<String>,
    /// Формат выгрузки: `eml` — письмо с конвертом.
    pub format: JournalExportFormat,
    /// Пауза перед первым повтором выгрузки (`1m`); дальше удваивается до `retry_max`.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub retry_initial: Duration,
    /// Наибольшая пауза между повторами (`30m`).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub retry_max: Duration,
    /// Срок повторов выгрузки от первой попытки (`72h`); после — запись остаётся в журнале,
    /// ошибка в журнал узла.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub retry_for: Duration,
}

impl Default for JournalExport {
    fn default() -> Self {
        Self {
            address: None,
            format: JournalExportFormat::default(),
            retry_initial: Duration::from_secs(60),
            retry_max: Duration::from_secs(30 * 60),
            retry_for: Duration::from_secs(72 * 3600),
        }
    }
}

/// Где лежат записи журнала: разобранные `journal.s3`/`journal.local` (одно из двух).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalLocation {
    /// Локальный каталог (профиль SMB).
    Local(PathBuf),
    /// Бакет S3 (Enterprise, Object Lock).
    S3 {
        /// Бакет.
        bucket: String,
    },
}

impl JournalSection {
    /// Журналирование включено.
    pub fn enabled(&self) -> bool {
        self.0.enabled
    }

    /// Хранилище записей — ровно одно: каталог (SMB) или бакет S3.
    pub fn location(&self) -> Result<JournalLocation> {
        match (&self.0.local, &self.0.s3) {
            (Some(_), Some(_)) => Err(Error::invalid(
                "хранилище записей: заданы и local, и s3 — одно (каталог SMB или бакет S3)",
            )),
            (None, None) => Err(Error::invalid(
                "хранилище записей: не задано — journal.s3 (бакет) или journal.local (каталог)",
            )),
            (Some(local), None) => Ok(JournalLocation::Local(local.dir.clone())),
            (None, Some(s3)) => Ok(JournalLocation::S3 {
                bucket: s3.bucket.clone(),
            }),
        }
    }

    /// Конфигурация локального хранилища для каталога `dir` из `local.dir`.
    pub fn local_config(&self, dir: PathBuf) -> LocalConfig {
        LocalConfig {
            root: dir,
            ..self
                .0
                .local
                .as_ref()
                .map(|l| l.params.clone())
                .unwrap_or_default()
        }
    }

    /// Конфигурация S3 для бакета из `s3.bucket`.
    pub fn s3_config(&self, bucket: String) -> S3Config {
        S3Config {
            bucket,
            prefix: String::new(),
            ..self
                .0
                .s3
                .as_ref()
                .map(|s| s.params.clone())
                .unwrap_or_default()
        }
    }

    /// Конфигурация записей `tp-blob` (BLOB-18): префикс и размеры частей секции, режим и срок
    /// блокировки — из `s3` (срок по умолчанию [`JOURNAL_RETENTION_DEFAULT`]; локальное хранилище —
    /// умолчания: блокирует только сервер). Проверяется `JournalConfig::validate`.
    pub fn records_config(&self) -> Result<JournalConfig> {
        let (lock_mode, retention) = match &self.0.s3 {
            Some(s3) => (
                s3.lock_mode,
                s3.retention.unwrap_or(JOURNAL_RETENTION_DEFAULT),
            ),
            None => (LockMode::default(), JOURNAL_RETENTION_DEFAULT),
        };
        let cfg = JournalConfig {
            prefix: self.0.prefix.clone(),
            lock_mode,
            retention,
            chunk_min_bytes: self.0.chunk_min_bytes,
            chunk_avg_bytes: self.0.chunk_avg_bytes,
            chunk_max_bytes: self.0.chunk_max_bytes,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Режим и срок блокировки для сообщений doctor (APP-82).
    pub fn lock(&self) -> (LockMode, Duration) {
        match &self.0.s3 {
            Some(s3) => (
                s3.lock_mode,
                s3.retention.unwrap_or(JOURNAL_RETENTION_DEFAULT),
            ),
            None => (LockMode::default(), JOURNAL_RETENTION_DEFAULT),
        }
    }

    /// Проверка секции (запуск и `thepost config check`): одно хранилище записей (при включённом
    /// журналировании — обязательно), бакет непустой, `compliance` — только с явным сроком, префикс и
    /// размеры частей (`records_config`), подсекции `tp-blob` без полей места (каталог и префикс —
    /// `dir`/`bucket` этой секции), TLS и параметры S3, адрес и паузы выгрузки. Бакет отдельен от
    /// BLOB ящиков — [`journal_bucket_separate`] (видно только по всей конфигурации).
    pub fn check(&self, profile: Profile) -> Result<()> {
        if self.0.local.is_some() && self.0.s3.is_some() {
            return self.location().map(drop);
        }
        if let Some(s3) = &self.0.s3 {
            if s3.bucket.trim().is_empty() {
                return Err(Error::invalid("s3.bucket: пуст"));
            }
            if s3.lock_mode == LockMode::Compliance && s3.retention.is_none() {
                return Err(Error::invalid(
                    "s3.lock_mode: compliance — только с явным сроком (s3.retention): объект не \
                     удаляет никто до конца срока, ошибка в сроке не освобождает бакет (риск 21)",
                ));
            }
            if !s3.params.prefix.is_empty() {
                return Err(Error::invalid(
                    "s3.prefix: не используется — объекты журнала лежат префиксом journal.prefix \
                     внутри бакета s3.bucket",
                ));
            }
            s3.params.tls.validate(InternalChannel::S3, profile)?;
            self.s3_config(s3.bucket.clone()).check(profile)?;
        }
        if let Some(local) = &self.0.local {
            if local.dir.as_os_str().is_empty() {
                return Err(Error::invalid("local.dir: пуст"));
            }
            if !local.dir.is_absolute() {
                return Err(Error::invalid(
                    "local.dir: путь абсолютный (/var/lib/thepost/journal)",
                ));
            }
            if local.params.root != LocalConfig::default().root {
                return Err(Error::invalid(
                    "local.root: не используется — каталог задаётся в journal.local.dir",
                ));
            }
        }
        if self.0.enabled {
            self.location()?;
        }
        if let Some(address) = &self.0.export.address
            && host_port(address).is_none()
        {
            return Err(Error::invalid(format!(
                "export.address: ожидается host:port (приёмник SMTP), получено {address:?}"
            )));
        }
        let export = &self.0.export;
        if export.retry_initial.is_zero()
            || export.retry_max < export.retry_initial
            || export.retry_for < export.retry_initial
        {
            return Err(Error::invalid(
                "export: retry_initial положительна и не больше retry_max и retry_for",
            ));
        }
        // Префикс и части записей — JournalConfig tp-blob (сообщения без префикса секции журнала).
        self.records_config().map_err(|e| match e {
            Error::Invalid(m) => Error::Invalid(m.trim_start_matches("journal: ").to_owned()),
            other => other,
        })?;
        Ok(())
    }
}

/// Бакет журнала отдельен от бакета BLOB ящиков (SRS 4.9): блокировка общих объектов сделала бы
/// неудаляемыми письма ящиков и связала бы уборщик мусора со сроками журнала. Проверка всей
/// конфигурации (`thepost config check`, APP-83): проверки секций по отдельности этого не видят.
pub fn journal_bucket_separate(cfg: &Config) -> Result<()> {
    let Some(journal) = cfg
        .section::<JournalSection>(JOURNAL)
        .ok()
        .and_then(|j| j.0.s3.clone())
    else {
        return Ok(());
    };
    let blob_bucket = cfg
        .section::<BlobSection>(BLOB)
        .ok()
        .and_then(|b| match b.location() {
            Ok(BlobLocation::S3 { bucket, .. }) => Some(bucket),
            _ => None,
        });
    if blob_bucket.as_deref() == Some(journal.bucket.as_str()) {
        return Err(Error::invalid(format!(
            "journal: s3.bucket {:?} совпадает с бакетом BLOB ящиков (blob.url): записи журнала — \
             отдельный бакет с собственной блокировкой (SRS 4.9)",
            journal.bucket
        )));
    }
    Ok(())
}

// ---------- bus ----------

/// Реализация шины уведомлений.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum BusKind {
    /// В процессе: один узел (SMB).
    #[default]
    Local,
    /// PostgreSQL LISTEN/NOTIFY (`tp_meta::signals::PgSignalBus`): кластер из нескольких узлов. Канал, буферы и
    /// очередь публикатора — секция `meta.signals`; слушатель — прямое соединение с primary (с PgBouncer —
    /// `database.direct_url`).
    Postgres,
}

/// Секция `bus`: шина сигналов (SRS 2.8). Требует перезапуска. Шина Valkey удалена (CLU-09).
///
/// ```yaml
/// bus:
///   kind: local      # postgres — кластер (LISTEN/NOTIFY, параметры — meta.signals)
///   capacity: 256
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct BusSection {
    /// Реализация: `local` — в процессе, `postgres` — LISTEN/NOTIFY.
    pub kind: BusKind,
    /// Буфер подписчика шины в процессе: столько непрочитанных уведомлений до отключения отставшего (`local`).
    pub capacity: usize,
}

impl Default for BusSection {
    fn default() -> Self {
        Self {
            kind: BusKind::Local,
            capacity: LocalBusConfig::default().capacity,
        }
    }
}

impl BusSection {
    /// Конфигурация шины в процессе.
    pub fn local(&self) -> LocalBusConfig {
        LocalBusConfig {
            capacity: self.capacity,
        }
    }
}

// ---------- cluster ----------

/// Секция `cluster`: узел в составе кластера (членство, разделы журнала событий, запросы узел → узел).
///
/// ```yaml
/// cluster:
///   node_id: mail-1
///   site: dc-1
///   addr: https://mail-1.corp.example:7443   # адрес узла для других узлов; пусто — запросов не принимает
///   listen: 0.0.0.0:7443                     # где узел слушает; не задан — как в addr
///   rpc:                                     # секция tp-cluster (CLU-12): mTLS внутреннего канала
///     tls:
///       ca_file: /etc/thepost/cluster-ca.pem
///       cert_file: /etc/thepost/node.pem     # CN — node_id
///       key_file: /etc/thepost/node-key.pem  # либо key: { secret: "thepost/node#key" } — ключ из хранилища секретов
///     permissions:
///       jmap: [search/query]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ClusterSection {
    /// Имя узла в членстве кластера, постоянное для узла; не задано — имя хоста. Требует перезапуска.
    pub node_id: Option<String>,
    /// Площадка (ЦОД) узла в членстве кластера; по умолчанию `default` (одна площадка).
    pub site: String,
    /// Внутренний адрес служебного канала узла для запросов узел → узел (`https://host:port`): объявляется в
    /// записи узла, по нему другие узлы вызывают этот; пусто — узел запросов не принимает. Требует `rpc.tls` и
    /// перезапуска.
    pub addr: String,
    /// Адрес приёма запросов узел → узел (`host:port`, `0.0.0.0:port`, `[::]:port`): на нём узел слушает
    /// (`NodeRpc::listen`), другим узлам объявляется `addr` — за NAT, пробросом порта или балансировщиком они
    /// различаются. Не задан — как в `addr` (решение 36). Требует `addr` и перезапуска.
    pub listen: String,
    /// Запросы узел → узел (секция `tp-cluster`, CLU-12): пределы, сроки, матрица разрешений и mTLS внутреннего
    /// канала (`rpc.tls`: УЦ узлов, сертификат с CN — имя узла, ключ — файл `key_file` либо ссылка на секрет
    /// `key`). Транспорт включается адресом `addr` или сертификатом узла `rpc.tls.cert_file` (только исходящие
    /// запросы).
    pub rpc: RpcConfig,
    /// Период опроса отпечатка файлов сертификатов внутреннего канала `rpc.tls` (УЦ, сертификат, `key_file`;
    /// секрет `key` опрашивается с периодом `rpc.key_poll_interval`) — только без событий ОС; замена файлов
    /// и перечитывание конфигурации (SIGHUP, запрос) применяются по событиям без перезапуска (APP-45),
    /// ошибка новой пары оставляет прежнюю. `0s` — без опроса, только события.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub rpc_tls_reload_interval: Duration,
    /// Запросов перестройки индексов, просматриваемых ролью indexer за проход (перестраиваются ящики своих
    /// разделов журнала).
    pub rebuild_scan: usize,
}

impl Default for ClusterSection {
    fn default() -> Self {
        Self {
            node_id: None,
            site: tp_contracts::membership::SiteId::DEFAULT.to_owned(),
            addr: String::new(),
            listen: String::new(),
            rpc: RpcConfig::default(),
            rpc_tls_reload_interval: Duration::from_secs(60),
            rebuild_scan: 64,
        }
    }
}

impl ClusterSection {
    /// Площадка узла.
    pub fn site_id(&self) -> Result<tp_contracts::membership::SiteId> {
        tp_contracts::membership::SiteId::new(self.site.clone())
            .map_err(|e| Error::invalid(format!("site: {e}")))
    }

    /// Проверка: имя узла (если задано), площадка, адрес (пусто или `https://host:port`), адрес приёма (пусто или
    /// `host:port` с портом 1–65535, только вместе с `addr`), секция `rpc`; с
    /// включённым транспортом ([`ClusterSection::rpc_enabled`]) — `rpc.tls`: файлы УЦ и сертификата, ключ — файл
    /// `key_file` либо ссылка на секрет `key` (вместе не задаются).
    pub fn check(&self) -> Result<()> {
        if let Some(node) = &self.node_id {
            tp_contracts::membership::NodeId::new(node.clone())?;
        }
        self.site_id()?;
        if !self.addr.is_empty()
            && self
                .addr
                .strip_prefix("https://")
                .and_then(host_port)
                .is_none()
        {
            return Err(Error::invalid(format!(
                "addr: ожидается https://host:port, получено {:?}",
                self.addr
            )));
        }
        if !self.listen.is_empty() {
            if host_port(&self.listen).is_none() {
                return Err(Error::invalid(format!(
                    "listen: ожидается host:port с портом 1–65535 (0.0.0.0:7443), получено {:?}",
                    self.listen
                )));
            }
            if self.addr.is_empty() {
                return Err(Error::invalid(
                    "listen: задан без addr — другим узлам адрес этого узла не объявлен",
                ));
            }
        }
        if self.rpc_enabled() {
            let tls = &self.rpc.tls;
            // Ключ — файл либо секрет (CTR-52): источник определяет контракт, оба сразу — ошибка.
            let key = tls.key_source().map_err(|e| match e {
                Error::Invalid(m) => Error::invalid(format!("rpc.{m}")),
                other => other,
            })?;
            for (field, set) in [
                ("ca_file", tls.ca_file.is_some()),
                ("cert_file", tls.cert_file.is_some()),
                ("key_file либо rpc.tls.key", key.is_some()),
            ] {
                if !set {
                    return Err(Error::invalid(format!(
                        "rpc.tls.{field}: обязателен для запросов узел → узел (mTLS; задан addr или rpc.tls.cert_file)"
                    )));
                }
            }
        }
        self.rpc.check()
    }

    /// Транспорт запросов узел → узел включён: задан адрес узла или его сертификат.
    pub fn rpc_enabled(&self) -> bool {
        !self.addr.is_empty() || self.rpc.tls.cert_file.is_some()
    }

    /// Адрес слушателя запросов узел → узел: `listen`, не задан — `host:port` из `addr`; `None` — адреса нет или он
    /// неверен.
    pub fn listen_addr(&self) -> Option<&str> {
        if self.listen.is_empty() {
            self.addr.strip_prefix("https://").and_then(host_port)
        } else {
            host_port(&self.listen)
        }
    }

    /// Ключ, из которого взят адрес слушателя (`cluster.listen` или `cluster.addr`), — для сообщений об ошибках.
    pub fn listen_key(&self) -> &'static str {
        if self.listen.is_empty() {
            "cluster.addr"
        } else {
            "cluster.listen"
        }
    }
}

/// `host:port` без схемы и пути, имя непустое, порт 1–65535; иначе `None`.
fn host_port(s: &str) -> Option<&str> {
    let (name, port) = s.rsplit_once(':')?;
    let valid = !name.is_empty()
        && !s.contains(['/', '?', '#'])
        && !s.chars().any(char::is_whitespace)
        && port.parse::<u16>().is_ok_and(|p| p != 0);
    valid.then_some(s)
}

// ---------- auth ----------

/// Секция `auth`: вход в протоколы (SRS 6.1) — каталог LDAP, OIDC (Bearer), пароли приложений, Kerberos, защита от
/// перебора.
///
/// ```yaml
/// auth:
///   ldap:
///     url: ldaps://dc.example.ru
///     bind_dn: cn=thepost,ou=services,dc=example,dc=ru
///     bind_password: { secret: "thepost/ldap#password" }
///     base_dn: dc=example,dc=ru
///   oidc:
///     issuer: https://sso.example.ru/realms/mail
///     audience: [thepost]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AuthSection {
    /// Каталог LDAP / Active Directory (`tp-auth`): адреса, группы, проверка пароля привязкой; не задан —
    /// учётные записи только из PostgreSQL, вход — паролями приложений. Требует перезапуска.
    pub ldap: Option<tp_auth::LdapConfig>,
    /// Поставщик OpenID Connect: токены Bearer (JMAP, Admin API, SASL OAUTHBEARER). Требует перезапуска.
    pub oidc: Option<tp_auth::OidcConfig>,
    /// Пароли приложений (argon2id).
    pub passwords: tp_auth::PasswordConfig,
    /// Kerberos (SASL GSSAPI). Keytab задаёт переменная `KRB5_KTNAME` (systemd `Environment=`): поле `keytab`
    /// только сверяется с ней. Требует перезапуска.
    pub gssapi: Option<tp_auth::GssapiConfig>,
    /// Защита от перебора (`tp-auth`, AUTH-08): пороги неудачных входов, срок блокировки. Требует перезапуска.
    pub abuse: tp_auth::AbuseConfig,
}

impl AuthSection {
    /// Проверка: каналы LDAP и OIDC (TLS вне dev), keytab Kerberos.
    pub fn check(&self, profile: Profile) -> Result<()> {
        if let Some(ldap) = &self.ldap {
            ldap.check(profile).map_err(|e| sub("ldap", e))?;
        }
        if let Some(oidc) = &self.oidc {
            oidc.check(profile).map_err(|e| sub("oidc", e))?;
        }
        if let Some(gssapi) = &self.gssapi {
            gssapi.check().map_err(|e| sub("gssapi", e))?;
        }
        self.abuse.check()?;
        Ok(())
    }
}

// ---------- trust ----------

/// Секция `trust`: кэш действующей матрицы политики доверия на узле (APP-76, решение 124; SRS 5.5). Сама политика
/// — уровни в хранилище (`PgMeta`, META-85) и Admin API (ADM-49); узел читает её через [`crate::trust::TrustCache`]:
/// срок и размер кэша — здесь, сброс — по событию `trust_changed` шины (CTR-93). Значения применяются без
/// перезапуска.
///
/// ```yaml
/// trust:
///   cache_ttl: 1m         # срок записи кэша; 0s — без кэша
///   cache_entries: 10000  # наибольшее число записей кэша; 0 — без кэша
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TrustSection {
    /// Срок действующей матрицы учётной записи и политик уровней в кэше узла (`1m`); запись перечитывается и
    /// раньше срока — по событию `trust_changed` шины (изменение политики через Admin API) и по `Resync`
    /// (потеря сигналов). `0s` — без кэша: каждое чтение — в хранилище. Применяется без перезапуска.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub cache_ttl: Duration,
    /// Наибольшее число записей кэша (учётные записи, домены-партнёры, уровни) — `10000`; сверх — вытесняется
    /// давнее. `0` — без кэша. Применяется без перезапуска.
    pub cache_entries: usize,
}

impl Default for TrustSection {
    fn default() -> Self {
        Self {
            cache_ttl: Duration::from_secs(60),
            cache_entries: 10_000,
        }
    }
}

// ---------- risk ----------

/// Секция `risk` (APP-78, решение 126): справочник аномалий на узле — доверенные ключи подписи пакетов
/// поставщика, первый пакет из поставки, обновление (роль maintenance) и срок «только отчёт».
///
/// ```yaml
/// risk:
///   trusted_keys:
///     vendor: /usr/share/thepost/risk/vendor.pub
///   update:
///     url: https://risk.thepost.example/packages/
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RiskSection {
    /// Доверенные открытые ключи подписи пакетов (Ed25519): `key_id` → ключ — base64 или hex (32 байта)
    /// либо путь к файлу с ним (пакеты ОС кладут ключи в `/usr/share/thepost/risk/`, DEP-57).
    /// Пусто — проверенные пакеты не устанавливаются (подпись не проверить), предупреждение — `doctor`.
    pub trusted_keys: std::collections::BTreeMap<String, String>,
    /// Первый пакет из поставки.
    pub package: RiskPackageSection,
    /// Обновление пакета поставщика — роль maintenance раз в `interval`.
    pub update: RiskUpdateSection,
    /// Сколько суток новый признак поставщика работает «только отчёт» без решения администратора
    /// (`14`): дольше — признак переходит в `Enforce` (журнал узла и строка в `doctor`).
    pub report_only_days: u32,
    /// Каталог импорта источников TI (закрытый контур: файлы кладут руками или зеркалом, APP-79).
    pub import: RiskImportSection,
}

impl Default for RiskSection {
    fn default() -> Self {
        Self {
            trusted_keys: Default::default(),
            package: Default::default(),
            update: Default::default(),
            report_only_days: 14,
            import: Default::default(),
        }
    }
}

impl RiskSection {
    /// Период обновления положителен; источник — URL только по HTTPS (HTTP — профиль dev, конфиденциальные
    /// списки TI и подписанные пакеты идут по TLS); `url` и `dir` вместе — ошибка (один источник обновления).
    pub fn check(&self, profile: Profile) -> Result<()> {
        if self.update.interval.is_zero() {
            return Err(Error::invalid("risk: update.interval must be positive"));
        }
        if let Some(url) = &self.update.url
            && !url.starts_with("https://")
            && !(url.starts_with("http://") && profile == Profile::Dev)
        {
            return Err(Error::invalid(
                "risk: update.url — только HTTPS (http — профиль dev)",
            ));
        }
        if self.update.url.is_some() && self.update.dir.is_some() {
            return Err(Error::invalid(
                "risk: заданы update.url и update.dir — источник обновления один (url или каталог)",
            ));
        }
        Ok(())
    }
}

/// `risk.package`: первый пакет из поставки (DEP-57). При пустом хранилище узел ставит пакет из каталога
/// поставки.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RiskPackageSection {
    /// Каталог поставки с пакетом (`*-v*.zip`) и открытыми ключами (`*.pub`); пусто — первый пакет не ставится.
    pub dir: Option<PathBuf>,
}

impl Default for RiskPackageSection {
    fn default() -> Self {
        Self {
            dir: Some(PathBuf::from("/usr/share/thepost/risk")),
        }
    }
}

/// `risk.update`: обновление пакета поставщика в роли maintenance (решение 126 б). Источник — `url`
/// (HTTPS, `If-None-Match`) или `dir` (закрытый контур: файл пакета кладут руками или зеркалом).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RiskUpdateSection {
    /// Период опроса источника (`24h`). Требует перезапуска.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub interval: Duration,
    /// Адрес обновлений (HTTPS): каталог с файлами пакетов, запрос с `If-None-Match` по последней
    /// установленной версии.
    pub url: Option<String>,
    /// Каталог обновлений закрытого контура: свежий пакет в нём ставится при проходе.
    pub dir: Option<PathBuf>,
    /// Ставить проверенный пакет сразу (`true`): новые признаки всё равно приходят «только отчёт»
    /// (`report_only_days`); `false` — пакет ждёт администратора (`POST …/activate`).
    pub auto_activate: bool,
}

impl Default for RiskUpdateSection {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(24 * 3600),
            url: None,
            dir: None,
            auto_activate: true,
        }
    }
}

/// `risk.import`: каталог импорта списков TI закрытого контура (решение 126 к; APP-79).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RiskImportSection {
    /// Каталог: источник [`tp_contracts::risk::SourceKind::File`] читает файл `<каталог>/<id источника>`
    /// (ГосСОПКА и ФинЦЕРТ — только импорт, всегда с организациями).
    pub dir: PathBuf,
}

impl Default for RiskImportSection {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("/var/lib/thepost/risk-import"),
        }
    }
}

// ---------- http ----------

/// Секция `http`: слушатели HTTP ролей jmap, dav и admin (TLS — секция `tls`; открытый HTTP — только `profile: dev`
/// с `allow_plaintext`). Слушатель не задан — роль готова, но соединений не принимает. Требует перезапуска.
/// Календари и контакты (роль dav, `/dav/*`) без `dav` отдаёт слушатель `jmap` — один порт 443 с JMAP.
/// `acme` — открытый HTTP для проверок ACME HTTP-01 (только при `acme.enabled`, APP-14).
///
/// ```yaml
/// http:
///   jmap: { listen: 0.0.0.0:443 }
///   admin: { listen: 127.0.0.1:8443 }
///   acme: { listen: 0.0.0.0:80 }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HttpSection {
    /// JMAP (`/.well-known/jmap`, `/jmap/*`).
    pub jmap: Option<HttpListener>,
    /// CalDAV и CardDAV (`/dav/*`, `/.well-known/caldav`, `/.well-known/carddav`) на отдельном адресе; не задан —
    /// на слушателе `jmap`.
    pub dav: Option<HttpListener>,
    /// Admin API (`/api/*`); адрес — только внутренний (loopback, частные сети).
    pub admin: Option<HttpListener>,
    /// Проверки ACME HTTP-01 (`/.well-known/acme-challenge/*`, остальное — 404) при `acme.enabled`.
    pub acme: AcmeListener,
}

/// Слушатель проверок ACME HTTP-01: открытый HTTP (сервер ACME обращается на порт 80, RFC 8555 §8.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AcmeListener {
    /// Адрес и порт.
    pub listen: SocketAddr,
}

impl Default for AcmeListener {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 80)),
        }
    }
}

/// Слушатель HTTP роли.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct HttpListener {
    /// Адрес и порт.
    pub listen: SocketAddr,
    /// Открытый HTTP без TLS: только `profile: dev`.
    pub allow_plaintext: bool,
    /// Время на TLS-рукопожатие.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub handshake_timeout: Duration,
    /// Одновременных незавершённых TLS-рукопожатий.
    pub max_handshakes: usize,
}

impl Default for HttpListener {
    fn default() -> Self {
        let base = ServiceHttpConfig::default();
        Self {
            listen: SocketAddr::from(([0, 0, 0, 0], 443)),
            allow_plaintext: false,
            handshake_timeout: base.handshake_timeout,
            max_handshakes: base.max_handshakes,
        }
    }
}

impl HttpListener {
    /// Параметры сервера HTTP платформы (`tp_platform::service_http::serve`). `public` — роль для клиентов
    /// (jmap): адрес слушателя разрешён явно; иначе (admin) — только внутренние адреса, как у служебного HTTP.
    pub fn server(&self, public: bool) -> ServiceHttpConfig {
        let ip = self.listen.ip();
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        ServiceHttpConfig {
            listen: self.listen,
            internal_networks: if public {
                vec![tp_platform::Cidr::new(ip, prefix)]
            } else {
                Vec::new()
            },
            allow_plaintext: self.allow_plaintext,
            handshake_timeout: self.handshake_timeout,
            max_handshakes: self.max_handshakes,
        }
    }
}

impl HttpSection {
    /// Проверка: открытый HTTP — только в dev, ненулевые таймауты, Admin API — только на внутреннем адресе,
    /// `dav` — не тот же адрес, что `jmap` (общий порт — без `http.dav`).
    pub fn check(&self, profile: Profile) -> Result<()> {
        for (name, l, public) in [
            ("jmap", &self.jmap, true),
            ("dav", &self.dav, true),
            ("admin", &self.admin, false),
        ] {
            if let Some(l) = l {
                l.server(public).check(profile).map_err(|e| sub(name, e))?;
            }
        }
        if let (Some(jmap), Some(dav)) = (&self.jmap, &self.dav)
            && jmap.listen == dav.listen
            && jmap.listen.port() != 0
        {
            return Err(Error::Invalid(format!(
                "dav: listen {} совпадает с http.jmap.listen: для общего порта уберите http.dav — календари и \
                 контакты отдаёт слушатель jmap",
                dav.listen
            )));
        }
        Ok(())
    }

    /// Слушатель календарей и контактов узла с ролями `roles`: `http.dav`; не задан — `http.jmap`. Второе
    /// значение — `true`, если это слушатель роли jmap того же узла (маршруты DAV добавляются к JMAP, своего
    /// сокета у роли dav нет).
    pub fn dav_listener(&self, roles: &RoleSet) -> (Option<&HttpListener>, bool) {
        match &self.dav {
            Some(dav) => (Some(dav), false),
            None => (self.jmap.as_ref(), roles.contains(Role::Jmap)),
        }
    }
}

/// Ошибка подсекции с префиксом её имени.
fn sub(name: &str, e: Error) -> Error {
    match e {
        Error::Invalid(m) => Error::Invalid(format!("{name}: {m}")),
        other => other,
    }
}

// ---------- admin ----------

/// Подсказка для `admin.listen`: адрес Admin API задаёт только `http.admin.listen` (SRS, APP-16).
const ADMIN_LISTEN_HINT: &str = "admin.listen не используется: адрес Admin API задаётся в http.admin.listen \
     (например, http: { admin: { listen: 127.0.0.1:8443 } })";

/// Подсказка для `admin.allow_external`: ключ без действия — Admin API слушает только внутренний адрес
/// `http.admin.listen` (SRS 6.8), внешний адрес не разрешается ничем.
const ADMIN_ALLOW_EXTERNAL_HINT: &str = "admin.allow_external не используется: Admin API принимает соединения \
     только на внутреннем адресе http.admin.listen (loopback или частная сеть, SRS 6.8); внешний доступ — через \
     обратный прокси или VPN";

/// Ключи `tp-admin`, которые приложение не применяет, и подсказки к ним.
const ADMIN_REJECTED: [(&str, &str); 2] = [
    ("listen", ADMIN_LISTEN_HINT),
    ("allow_external", ADMIN_ALLOW_EXTERNAL_HINT),
];

/// Секция `admin`: секция `tp-admin` как есть, кроме `listen` — адрес слушателя задаёт `http.admin.listen`, ключ
/// `admin.listen` — ошибка разбора с подсказкой (два ключа одного адреса расходились: проверялся один, слушал другой);
/// `admin.allow_external` — тоже ошибка с подсказкой: ключ без действия (адрес проверяет `http.admin`, только внутренний).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AdminSection(pub tp_admin::AdminConfig);

impl<'de> Deserialize<'de> for AdminSection {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        use serde::de::Error as _;
        let value = serde_json::Value::deserialize(d)?;
        if value.is_null() {
            return Ok(Self::default());
        }
        if let Some((_, hint)) = ADMIN_REJECTED
            .iter()
            .find(|(key, _)| value.get(key).is_some())
        {
            return Err(D::Error::custom(hint));
        }
        tp_admin::AdminConfig::deserialize(value)
            .map(Self)
            .map_err(D::Error::custom)
    }
}

impl JsonSchema for AdminSection {
    fn schema_name() -> Cow<'static, str> {
        "AdminSection".into()
    }

    /// Схема `tp-admin`; `listen` и `allow_external` остаются известными ключами (иначе мягкий режим отбросил бы
    /// их с предупреждением), но не допускают значений.
    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        let mut schema = tp_admin::AdminConfig::json_schema(generator);
        for (key, hint) in ADMIN_REJECTED {
            if let Some(prop) = schema.get_mut("properties").and_then(|p| p.get_mut(key)) {
                *prop = serde_json::json!({ "description": hint, "not": {} });
            }
        }
        schema
    }
}

// ---------- verify ----------

/// Секция `verify`: сверка хранилища BLOB и учёта объектов (`thepost verify`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct VerifySection {
    /// Записей учёта на страницу перечисления (каждая страница — своя короткая транзакция).
    pub page_size: usize,
}

impl Default for VerifySection {
    fn default() -> Self {
        Self { page_size: 1000 }
    }
}

// ---------- startup ----------

/// Секция `startup`: ожидание внешних служб при запуске узла (APP-31, решение 2026-11-11 п. 58).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct StartupSection {
    /// Сколько узел ждёт хранилище секретов (OpenBao) при запуске, повторяя вход и чтение секретов (`120s`);
    /// `0s` — без повторов: первая неудача завершает запуск.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub secrets_timeout: Duration,
    /// Пауза перед первым повтором (`1s`); дальше удваивается.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub secrets_retry_initial: Duration,
    /// Наибольшая пауза между повторами (`15s`).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub secrets_retry_max: Duration,
}

impl Default for StartupSection {
    fn default() -> Self {
        Self {
            secrets_timeout: Duration::from_secs(120),
            secrets_retry_initial: Duration::from_secs(1),
            secrets_retry_max: Duration::from_secs(15),
        }
    }
}

impl StartupSection {
    /// Паузы положительны, наибольшая — не меньше первой.
    pub fn check(&self) -> Result<()> {
        if self.secrets_retry_initial.is_zero()
            || self.secrets_retry_max < self.secrets_retry_initial
        {
            return Err(Error::invalid(
                "startup: secrets_retry_initial must be positive and not exceed secrets_retry_max",
            ));
        }
        Ok(())
    }
}

// ---------- maintenance ----------

/// Секция `maintenance`: задания роли maintenance, у которых нет своей секции крейта (APP-32, решение 2026-11-11
/// п. 65). Сроки хранения — в `meta` (`meta.dav.tombstone_ttl`, `meta.sieve.vacation_log_ttl`,
/// `meta.delivery.retention`); срок токенов `admin init` — здесь (APP-39).
///
/// ```yaml
/// maintenance:
///   purge_interval: 1h
///   admin_token_retention: 30d
///   gal_interval: 1m
///   verify:
///     at: "03:00"
///     interval: 24h
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct MaintenanceSection {
    /// Период очистки по сроку надгробий DAV, журнала автоответов, журнала доставки и токенов `admin init`
    /// (`1h`); первый проход — при запуске роли.
    /// Требует перезапуска.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub purge_interval: Duration,
    /// Сколько хранить одноразовые токены `thepost admin init` после истечения их срока (`30d`): погашенные,
    /// отозванные и истёкшие токены остаются для аудита, затем удаляются очисткой по сроку; `0s` — сразу по
    /// истечении.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub admin_token_retention: Duration,
    /// Период заполнения книги GAL «Организация» из каталога (`1m`, APP-49): `auth.ldap`, без него — учётные записи и
    /// группы PostgreSQL (APP-51). Первый проход — при запуске роли; изменение каталога видно в книге CardDAV и JMAP
    /// не позже чем через период.
    /// Требует перезапуска.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub gal_interval: Duration,
    /// Проверка целостности BLOB по расписанию (`thepost verify` без `--fix`, APP-44).
    pub verify: VerifySchedule,
}

impl Default for MaintenanceSection {
    fn default() -> Self {
        Self {
            purge_interval: Duration::from_secs(3600),
            admin_token_retention: Duration::from_secs(30 * 24 * 3600),
            gal_interval: Duration::from_secs(60),
            verify: VerifySchedule::default(),
        }
    }
}

impl MaintenanceSection {
    /// Периоды положительны, расписание проверки целостности согласовано.
    pub fn check(&self) -> Result<()> {
        if self.purge_interval.is_zero() {
            return Err(Error::invalid(
                "maintenance: purge_interval must be positive",
            ));
        }
        if self.gal_interval.is_zero() {
            return Err(Error::invalid("maintenance: gal_interval must be positive"));
        }
        self.verify.check()
    }
}

/// `maintenance.verify`: расписание проверки целостности BLOB в роли maintenance (APP-44). Проход — сверка
/// `thepost verify` без `--fix`: ничего не удаляет и не помечает, итог — в журнал узла и `/metrics`
/// (`tp_blob_verify_*`); исправление — только вручную (`thepost verify --fix`). В кластере проход выполняет один
/// узел — держатель лизы `lease_name`. Требует перезапуска.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct VerifySchedule {
    /// Выполнять проверку по расписанию (`true`).
    pub enabled: bool,
    /// Время прохода, UTC, `ЧЧ:ММ` (`03:00`); при `interval` не в целых сутках — сдвиг сетки проходов от
    /// полуночи UTC 1970-01-01.
    #[serde(deserialize_with = "time_of_day::deserialize")]
    #[schemars(with = "String")]
    pub at: Duration,
    /// Период проходов (`24h` — раз в сутки в `at`).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub interval: Duration,
    /// Имя лизы лидера (`blob-verify`).
    pub lease_name: String,
    /// Срок лизы (`2m`): продлевается, пока идёт проход; после прохода держится до истечения, чтобы узел с
    /// отстающими часами не повторил проход, — срок должен покрывать расхождение часов узлов.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub lease_ttl: Duration,
}

impl Default for VerifySchedule {
    fn default() -> Self {
        Self {
            enabled: true,
            at: Duration::from_secs(3 * 3600),
            interval: Duration::from_secs(24 * 3600),
            lease_name: "blob-verify".to_owned(),
            lease_ttl: Duration::from_secs(120),
        }
    }
}

impl VerifySchedule {
    /// Период и срок лизы положительны, имя лизы задано.
    pub fn check(&self) -> Result<()> {
        if self.interval.is_zero() {
            return Err(Error::invalid(
                "maintenance: verify.interval must be positive",
            ));
        }
        if self.lease_ttl.is_zero() {
            return Err(Error::invalid(
                "maintenance: verify.lease_ttl must be positive",
            ));
        }
        if self.lease_name.is_empty() {
            return Err(Error::invalid("maintenance: verify.lease_name is empty"));
        }
        Ok(())
    }

    /// Сколько ждать от момента `now` (от начала эпохи Unix, UTC) до следующего прохода: ближайший момент
    /// сетки `at + k·interval` строго после `now`.
    pub fn until_next(&self, now: Duration) -> Duration {
        let interval = self.interval.as_nanos().max(1);
        let phase = self.at.as_nanos() % interval;
        let since = (now.as_nanos() + interval - phase) % interval;
        let wait = interval - since;
        Duration::new(
            u64::try_from(wait / 1_000_000_000).unwrap_or(u64::MAX),
            u32::try_from(wait % 1_000_000_000).unwrap_or(0),
        )
    }
}

/// Время суток `ЧЧ:ММ` (UTC) как смещение от полуночи.
mod time_of_day {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Duration, D::Error> {
        use serde::de::Error as _;
        let raw = String::deserialize(d)?;
        let parsed = raw.split_once(':').and_then(|(h, m)| {
            let two_digits = |s: &str| s.len() == 2 && s.bytes().all(|b| b.is_ascii_digit());
            if !two_digits(h) || !two_digits(m) {
                return None;
            }
            let (h, m) = (h.parse::<u64>().ok()?, m.parse::<u64>().ok()?);
            (h < 24 && m < 60).then(|| Duration::from_secs(h * 3600 + m * 60))
        });
        parsed
            .ok_or_else(|| D::Error::custom(format!("время суток {raw:?}: ожидается ЧЧ:ММ (UTC)")))
    }
}

// ---------- cli ----------

/// Секция `cli`: командная строка `thepost admin` (APP-42).
///
/// ```yaml
/// cli:
///   oidc:
///     client_id: thepost-cli
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CliSection {
    /// Вход администратора через поставщика `auth.oidc` с устройства без браузера (RFC 8628).
    pub oidc: CliOidc,
}

/// `cli.oidc`: клиент OAuth командной строки у поставщика `auth.oidc` и опрос токена при входе с устройства.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct CliOidc {
    /// Идентификатор открытого клиента (public client) с разрешённым Device Authorization Grant; не задан —
    /// вход с устройства недоступен. Токен клиента должен содержать получателя из `auth.oidc.audience`.
    pub client_id: Option<String>,
    /// Запрашиваемые области доступа через пробел (`openid`).
    pub scope: String,
    /// Пауза между опросами токена, если поставщик не задал `interval` (`5s`, RFC 8628).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub poll_interval: Duration,
    /// Прибавка к паузе на ответ `slow_down` (`5s`, RFC 8628).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub slow_down_step: Duration,
    /// Наибольшее время ожидания подтверждения (`15m`), даже если код поставщика действует дольше.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub max_wait: Duration,
}

impl Default for CliOidc {
    fn default() -> Self {
        Self {
            client_id: None,
            scope: "openid".to_owned(),
            poll_interval: Duration::from_secs(5),
            slow_down_step: Duration::from_secs(5),
            max_wait: Duration::from_secs(15 * 60),
        }
    }
}

impl CliOidc {
    /// Клиент и области доступа не пусты, паузы и время ожидания положительны.
    pub fn check(&self) -> Result<()> {
        if self.client_id.as_deref().is_some_and(str::is_empty) {
            return Err(Error::invalid("cli: oidc.client_id is empty"));
        }
        if self.scope.trim().is_empty() {
            return Err(Error::invalid("cli: oidc.scope is empty"));
        }
        if self.poll_interval.is_zero() || self.slow_down_step.is_zero() || self.max_wait.is_zero()
        {
            return Err(Error::invalid(
                "cli: oidc.poll_interval, slow_down_step and max_wait must be positive",
            ));
        }
        Ok(())
    }
}

// ---------- doctor ----------

/// Секция `doctor`: пороги проверок окружения `thepost doctor` (проверки СУБД — `meta.doctor`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct DoctorSection {
    /// Расхождение часов узла и СУБД, с которого выдаётся предупреждение.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub warn_clock_skew: Duration,
    /// Расхождение часов узла и СУБД, с которого проверка не пройдена (лизы, сроки записей, DKIM, TOTP).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub max_clock_skew: Duration,
    /// Предел ожидания каждой проверки хранилища BLOB.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub blob_timeout: Duration,
    /// Предел ожидания каждого запроса DNS (MX, SPF, DKIM, DMARC, MTA-STS, PTR).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub dns_timeout: Duration,
    /// Сертификату `tls` осталось действовать меньше — предупреждение.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub cert_warn_before: Duration,
    /// Бюджет проверок хранилища секретов `secrets.store`/`secrets.login` (FIX-10): при транспортном таймауте
    /// (`secrets.request_timeout`) проверка повторяется с таймаутом запроса не меньше остатка бюджета, пока он
    /// не исчерпан. Больше транспортного таймаута: под CPU-нагрузкой узла ответ OpenBao требует больше времени
    /// (`/v1/auth/approle/login`), хотя `/v1/sys/health` отвечает за миллисекунды; таймаут при живом хранилище —
    /// `warn` «проверка не успела», не `fail` (мониторинг по `doctor` без ложных аварий).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub secrets_login_budget: Duration,
}

impl Default for DoctorSection {
    fn default() -> Self {
        Self {
            warn_clock_skew: Duration::from_millis(500),
            max_clock_skew: Duration::from_secs(5),
            blob_timeout: Duration::from_secs(10),
            dns_timeout: Duration::from_secs(5),
            cert_warn_before: Duration::from_secs(21 * 86_400),
            secrets_login_budget: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<tp_platform::Config> {
        registry().expect("registry").parse(yaml, Vec::new())
    }

    fn strict(yaml: &str) -> Result<tp_platform::Config> {
        registry().expect("registry").parse_strict(yaml, Vec::new())
    }

    fn err(r: Result<tp_platform::Config>) -> String {
        match r {
            Ok(c) => panic!("ожидалась ошибка: {c:?}"),
            Err(Error::Invalid(m)) => m,
            Err(e) => e.to_string(),
        }
    }

    /// Минимальная конфигурация dev; секция `blob` — последней (тесты дописывают её подсекции).
    const MINIMAL_DEV: &str = "
domain: example.org
profile: dev
service_http:
  allow_plaintext: true
database:
  url: postgres://thepost@localhost/thepost?sslmode=disable
  tls: { allow_plaintext: true }
blob:
  url: file:///var/lib/thepost/blob
";

    #[test]
    fn minimal_config_parses() {
        let c = parse(MINIMAL_DEV).expect("config");
        assert_eq!(c.domain(), "example.org");
        assert_eq!(c.profile(), Profile::Dev);
        let blob = c.section::<BlobSection>(BLOB).expect("blob");
        assert_eq!(
            blob.location().expect("location"),
            BlobLocation::Local(PathBuf::from("/var/lib/thepost/blob"))
        );
        assert_eq!(
            *c.section::<BusSection>(BUS).expect("bus"),
            BusSection::default()
        );
        assert!(c.roles().contains(tp_contracts::role::Role::Maintenance));
        strict(MINIMAL_DEV).expect("strict");
    }

    #[test]
    fn strict_rejects_unknown_fields_lenient_warns() {
        let yaml = format!("{MINIMAL_DEV}bus:\n  capasity: 3\nblob_typo: 1\n");
        let e = err(strict(&yaml));
        assert!(e.contains("bus.capasity"), "{e}");
        assert!(e.contains("blob_typo"), "{e}");
        let c = parse(&yaml).expect("lenient");
        assert_eq!(c.warnings().len(), 2, "{:?}", c.warnings());
    }

    #[test]
    fn plaintext_channels_only_in_dev() {
        let prod = |extra: &str| {
            format!(
                "domain: example.org\ndatabase:\n  url: postgres://thepost@db/thepost\n\
                 blob:\n  url: s3://bucket\n  s3:\n    endpoint: https://s3.internal\n{extra}"
            )
        };
        parse(&prod("")).expect("tls everywhere");
        // PostgreSQL без TLS.
        let e = err(parse(
            &prod("").replace("/thepost\n", "/thepost?sslmode=disable\n"),
        ));
        assert!(e.contains("database"), "{e}");
        // S3 по http.
        let e = err(parse(&prod("").replace("https://s3", "http://s3")));
        assert!(e.contains("blob"), "{e}");
        // Секции Valkey нет (CLU-09).
        let e = err(parse(&prod(
            "bus:\n  kind: valkey\n  valkey:\n    url: rediss://v:6379\n",
        )));
        assert!(e.contains("valkey"), "{e}");
    }

    #[test]
    fn secrets_only_by_reference() {
        let keys = |key: &str| {
            format!(
                "{MINIMAL_DEV}  s3:\n    credentials:\n      access_key_id: {{ secret: \"thepost/s3#id\" }}\n      secret_access_key: {key}\n"
            )
        };
        let e = err(parse(&keys("hunter2")));
        assert!(!e.contains("hunter2"), "{e}");
        assert!(e.contains("secret"), "{e}");
        let c = parse(&keys("{ secret: \"thepost/s3#key\" }")).expect("reference");
        let blob = c.section::<BlobSection>(BLOB).expect("blob");
        assert_eq!(
            blob.s3
                .credentials
                .as_ref()
                .map(|k| k.secret_access_key.to_string()),
            Some("thepost/s3#key".to_owned())
        );
        let refs: Vec<String> = c.secret_refs().map(ToString::to_string).collect();
        assert_eq!(refs.len(), 2, "{refs:?}");
    }

    #[test]
    fn blob_locations() {
        let loc = |url: &str| {
            BlobSection {
                url: url.to_owned(),
                ..BlobSection::default()
            }
            .location()
        };
        assert_eq!(
            loc("s3://bucket/a/b/").expect("s3"),
            BlobLocation::S3 {
                bucket: "bucket".into(),
                prefix: "a/b".into()
            }
        );
        assert_eq!(
            loc("s3://bucket").expect("s3"),
            BlobLocation::S3 {
                bucket: "bucket".into(),
                prefix: String::new()
            }
        );
        for bad in ["", "file://relative", "s3://", "/var/lib", "http://x"] {
            assert!(loc(bad).is_err(), "{bad}");
        }
    }

    /// mTLS внутреннего канала узла: файлы читаются при запуске транспорта, здесь — только наличие.
    const RPC_TLS: &str = "  rpc:\n    tls:\n      ca_file: /etc/thepost/ca.pem\n      \
                           cert_file: /etc/thepost/node.pem\n      key_file: /etc/thepost/node-key.pem\n";

    #[test]
    fn cluster_site_and_addr_are_checked() {
        let c = parse(&format!(
            "{MINIMAL_DEV}cluster:\n  site: dc-1\n  addr: https://10.0.0.1:7443\n{RPC_TLS}"
        ))
        .expect("config");
        let cluster = c.section::<ClusterSection>(CLUSTER).expect("cluster");
        assert_eq!(cluster.site_id().expect("site").as_str(), "dc-1");
        assert_eq!(cluster.addr, "https://10.0.0.1:7443");
        assert_eq!(cluster.listen_addr(), Some("10.0.0.1:7443"));
        assert_eq!(cluster.listen_key(), "cluster.addr");
        assert!(cluster.rpc_enabled());
        let d = ClusterSection::default();
        assert_eq!(d.site_id().expect("site").as_str(), "default");
        assert!(d.addr.is_empty());
        assert_eq!(d.listen_addr(), None);
        assert!(!d.rpc_enabled());
        for bad in [
            "  site: \"dc 1\"\n",
            "  site: \"\"\n",
            "  addr: http://x:1\n",
            "  addr: https://\n",
            "  addr: https://x/p\n",
            "  addr: https://x\n",
            "  addr: https://x:0\n",
            "  addr: https://:7443\n",
        ] {
            let e = err(parse(&format!("{MINIMAL_DEV}cluster:\n{bad}{RPC_TLS}")));
            assert!(e.contains("site") || e.contains("addr"), "{bad}: {e}");
        }
    }

    /// APP-30: `cluster.listen` — где узел слушает, `cluster.addr` — что объявляет; без `listen` слушает `addr`
    /// (решение 36); порт обязателен, `listen` без `addr` — ошибка.
    #[test]
    fn cluster_listen_is_separate_from_addr() {
        let addr = "  addr: https://mail-1.corp.example:7443\n";
        let c = parse(&format!(
            "{MINIMAL_DEV}cluster:\n{addr}  listen: 0.0.0.0:7443\n{RPC_TLS}"
        ))
        .expect("config");
        let cluster = c.section::<ClusterSection>(CLUSTER).expect("cluster");
        assert_eq!(cluster.addr, "https://mail-1.corp.example:7443");
        assert_eq!(cluster.listen_addr(), Some("0.0.0.0:7443"));
        assert_eq!(cluster.listen_key(), "cluster.listen");
        let c = parse(&format!(
            "{MINIMAL_DEV}cluster:\n{addr}  listen: \"[::]:17443\"\n{RPC_TLS}"
        ))
        .expect("config");
        let cluster = c.section::<ClusterSection>(CLUSTER).expect("cluster");
        assert_eq!(cluster.listen_addr(), Some("[::]:17443"));
        for bad in [
            "0.0.0.0",
            "0.0.0.0:0",
            "0.0.0.0:70000",
            ":7443",
            "https://0.0.0.0:7443",
            "0.0.0.0 :7443",
        ] {
            let e = err(parse(&format!(
                "{MINIMAL_DEV}cluster:\n{addr}  listen: \"{bad}\"\n{RPC_TLS}"
            )));
            assert!(
                e.contains("listen") && e.contains("host:port"),
                "{bad}: {e}"
            );
        }
        let e = err(parse(&format!(
            "{MINIMAL_DEV}cluster:\n  listen: 0.0.0.0:7443\n{RPC_TLS}"
        )));
        assert!(e.contains("listen") && e.contains("addr"), "{e}");
    }

    /// APP-18: адрес узла (или сертификат для исходящих запросов) требует mTLS внутреннего канала
    /// `cluster.rpc.tls`; открытого канала нет ни в одном профиле; матрица разрешений — при разборе.
    #[test]
    fn cluster_rpc_requires_internal_mtls() {
        let addr = "  addr: https://[::1]:7443\n";
        let c = parse(&format!("{MINIMAL_DEV}cluster:\n{addr}{RPC_TLS}")).expect("config");
        let cluster = c.section::<ClusterSection>(CLUSTER).expect("cluster");
        assert_eq!(cluster.listen_addr(), Some("[::1]:7443"));
        for missing in ["ca_file", "cert_file", "key_file"] {
            let tls: String = RPC_TLS
                .lines()
                .filter(|l| !l.contains(missing))
                .map(|l| format!("{l}\n"))
                .collect();
            let e = err(parse(&format!("{MINIMAL_DEV}cluster:\n{addr}{tls}")));
            assert!(
                e.contains("rpc.tls") && e.contains(missing),
                "{missing}: {e}"
            );
        }
        // APP-36: ключ по ссылке на секрет вместо файла; оба сразу — ошибка.
        let by_secret = RPC_TLS.replace(
            "key_file: /etc/thepost/node-key.pem",
            "key: { secret: \"thepost/node#key\" }",
        );
        assert_ne!(by_secret, RPC_TLS);
        let c = parse(&format!("{MINIMAL_DEV}cluster:\n{addr}{by_secret}")).expect("key");
        let cluster = c.section::<ClusterSection>(CLUSTER).expect("cluster");
        assert!(cluster.rpc.tls.key.is_some() && cluster.rpc.tls.key_file.is_none());
        let e = err(parse(&format!(
            "{MINIMAL_DEV}cluster:\n{addr}{RPC_TLS}      key: {{ secret: \"thepost/node#key\" }}\n"
        )));
        assert!(e.contains("mutually exclusive"), "{e}");
        // Только сертификат (исходящие запросы без слушателя) — тоже с УЦ.
        let e = err(parse(&format!(
            "{MINIMAL_DEV}cluster:\n  rpc:\n    tls:\n      cert_file: /n.pem\n      key_file: /k.pem\n"
        )));
        assert!(e.contains("ca_file"), "{e}");
        let e = err(parse(&format!(
            "{MINIMAL_DEV}cluster:\n{addr}{RPC_TLS}      allow_plaintext: true\n"
        )));
        assert!(e.contains("allow_plaintext"), "{e}");
        let e = err(parse(&format!(
            "{MINIMAL_DEV}cluster:\n{addr}{RPC_TLS}    permissions:\n      search: [nonsense]\n"
        )));
        assert!(e.contains("nonsense"), "{e}");
        let e = err(parse(&format!(
            "{MINIMAL_DEV}cluster:\n{addr}{RPC_TLS}    max_in_flight: 0\n"
        )));
        assert!(e.contains("max_in_flight"), "{e}");
    }

    #[test]
    fn durations_are_humantime() {
        let c = parse(&format!("{MINIMAL_DEV}doctor:\n  max_clock_skew: 2s\n")).expect("config");
        let doctor = c.section::<DoctorSection>(DOCTOR).expect("doctor");
        assert_eq!(doctor.max_clock_skew, Duration::from_secs(2));
        let e = err(parse(&format!(
            "{MINIMAL_DEV}doctor:\n  max_clock_skew: 5\n"
        )));
        assert!(
            e.contains("duration") || e.contains("max_clock_skew"),
            "{e}"
        );
    }

    /// APP-08: опроса журнала событий нет — ключ `cluster.events_poll_interval` неизвестен (строгая проверка).
    #[test]
    fn events_poll_interval_is_gone() {
        let e = err(strict(&format!(
            "{MINIMAL_DEV}cluster:\n  events_poll_interval: 1s\n"
        )));
        assert!(e.contains("events_poll_interval"), "{e}");
    }

    /// APP-32: период очистки роли maintenance — `1h` по умолчанию, из config.yaml, нулевой — ошибка.
    #[test]
    fn maintenance_purge_interval() {
        let c = parse(MINIMAL_DEV).expect("config");
        let m = c
            .section::<MaintenanceSection>(MAINTENANCE)
            .expect("section");
        assert_eq!(m.purge_interval, Duration::from_secs(3600));
        let c = parse(&format!(
            "{MINIMAL_DEV}maintenance:\n  purge_interval: 10m\n"
        ))
        .expect("config");
        let m = c
            .section::<MaintenanceSection>(MAINTENANCE)
            .expect("section");
        assert_eq!(m.purge_interval, Duration::from_secs(600));
        // APP-39: срок хранения токенов admin init — 30 суток по умолчанию, из config.yaml.
        assert_eq!(m.admin_token_retention, Duration::from_secs(30 * 24 * 3600));
        let c = parse(&format!(
            "{MINIMAL_DEV}maintenance:\n  admin_token_retention: 7d\n"
        ))
        .expect("config");
        let m = c
            .section::<MaintenanceSection>(MAINTENANCE)
            .expect("section");
        assert_eq!(m.admin_token_retention, Duration::from_secs(7 * 24 * 3600));
        let e = err(parse(&format!(
            "{MINIMAL_DEV}maintenance:\n  purge_interval: 0s\n"
        )));
        assert!(e.contains("purge_interval"), "{e}");
    }

    /// APP-49: период заполнения книги GAL — `1m` по умолчанию, из config.yaml, нулевой — ошибка.
    #[test]
    fn maintenance_gal_interval() {
        let c = parse(MINIMAL_DEV).expect("config");
        let m = c
            .section::<MaintenanceSection>(MAINTENANCE)
            .expect("section");
        assert_eq!(m.gal_interval, Duration::from_secs(60));
        let c = parse(&format!(
            "{MINIMAL_DEV}maintenance:
  gal_interval: 5m
"
        ))
        .expect("config");
        let m = c
            .section::<MaintenanceSection>(MAINTENANCE)
            .expect("section");
        assert_eq!(m.gal_interval, Duration::from_secs(300));
        let e = err(parse(&format!(
            "{MINIMAL_DEV}maintenance:
  gal_interval: 0s
"
        )));
        assert!(e.contains("gal_interval"), "{e}");
    }

    /// APP-44: расписание проверки целостности — раз в сутки в 03:00 UTC по умолчанию; время и период из
    /// config.yaml; неверное время и нулевой период — ошибки.
    #[test]
    fn maintenance_verify_schedule() {
        let config = |yaml: &str| parse(&format!("{MINIMAL_DEV}maintenance:\n  verify:\n{yaml}"));
        let section = |yaml: &str| {
            config(yaml)
                .expect("config")
                .section::<MaintenanceSection>(MAINTENANCE)
                .expect("section")
                .verify
                .clone()
        };
        let hours = |h: u64| Duration::from_secs(h * 3600);
        let v = parse(MINIMAL_DEV)
            .expect("config")
            .section::<MaintenanceSection>(MAINTENANCE)
            .expect("section")
            .verify
            .clone();
        assert_eq!(v, VerifySchedule::default());
        assert!(v.enabled);
        assert_eq!((v.at, v.interval), (hours(3), hours(24)));
        // Сутки: до 03:00 — в тот же день, в 03:00 и позже — на следующий.
        let day = 20_000 * hours(24);
        assert_eq!(v.until_next(day + hours(1)), hours(2));
        assert_eq!(v.until_next(day + hours(3)), hours(24));
        assert_eq!(v.until_next(day + hours(23)), hours(4));

        let v = section("    at: \"23:30\"\n    interval: 12h\n    enabled: false\n");
        assert!(!v.enabled);
        assert_eq!(v.at, Duration::from_secs(23 * 3600 + 30 * 60));
        assert_eq!(
            v.until_next(day + hours(11)),
            Duration::from_secs(30 * 60),
            "период 12h: проходы в 11:30 и 23:30"
        );

        for bad in ["24:00", "3:00", "03:60", "ночью"] {
            let e = err(config(&format!("    at: \"{bad}\"\n")));
            assert!(e.contains("ЧЧ:ММ"), "{bad}: {e}");
        }
        let e = err(config("    interval: 0s\n"));
        assert!(e.contains("verify.interval"), "{e}");
        let e = err(config("    lease_ttl: 0s\n"));
        assert!(e.contains("verify.lease_ttl"), "{e}");
    }

    /// APP-42: секция `cli` — клиент входа с устройства не задан по умолчанию; паузы из config.yaml; пустой
    /// клиент и нулевая пауза — ошибки.
    #[test]
    fn cli_oidc_section() {
        let config = |yaml: &str| parse(&format!("{MINIMAL_DEV}cli:\n  oidc:\n{yaml}"));
        let c = parse(MINIMAL_DEV).expect("config");
        let cli = c.section::<CliSection>(CLI).expect("section");
        assert_eq!(cli.oidc, CliOidc::default());
        assert_eq!(cli.oidc.client_id, None);
        let c = config("    client_id: thepost-cli\n    scope: openid email\n    max_wait: 5m\n")
            .expect("config");
        let cli = c.section::<CliSection>(CLI).expect("section");
        assert_eq!(cli.oidc.client_id.as_deref(), Some("thepost-cli"));
        assert_eq!(cli.oidc.scope, "openid email");
        assert_eq!(cli.oidc.max_wait, Duration::from_secs(300));
        let e = err(config("    client_id: \"\"\n"));
        assert!(e.contains("client_id"), "{e}");
        let e = err(config("    poll_interval: 0s\n"));
        assert!(e.contains("poll_interval"), "{e}");
    }

    /// APP-08: шина — в процессе (по умолчанию) или PostgreSQL LISTEN/NOTIFY; Valkey — ошибка строгой проверки.
    #[test]
    fn bus_kinds() {
        let c = parse(MINIMAL_DEV).expect("config");
        assert_eq!(
            c.section::<BusSection>(BUS).expect("bus").kind,
            BusKind::Local
        );
        let c = strict(&format!("{MINIMAL_DEV}bus:\n  kind: postgres\n")).expect("postgres");
        assert_eq!(
            c.section::<BusSection>(BUS).expect("bus").kind,
            BusKind::Postgres
        );
        let e = err(strict(&format!(
            "{MINIMAL_DEV}bus:\n  kind: valkey\n  valkey:\n    url: rediss://v:6379\n"
        )));
        assert!(e.contains("valkey"), "{e}");
    }

    #[test]
    fn crate_sections_parse_and_url_owns_location() {
        let c = parse(&format!(
            "{MINIMAL_DEV}  local:\n    stale_tmp: 1h\n  s3:\n    request_timeout: 5s\n\
             bus:\n  capacity: 64\n"
        ))
        .expect("config");
        let blob = c.section::<BlobSection>(BLOB).expect("blob");
        let local = blob.local_config(PathBuf::from("/data"));
        assert_eq!(
            (local.root, local.stale_tmp),
            (PathBuf::from("/data"), Duration::from_secs(3600))
        );
        let s3 = blob.s3_config("b".into(), "p".into());
        assert_eq!((s3.bucket.as_str(), s3.prefix.as_str()), ("b", "p"));
        assert_eq!(s3.request_timeout, Duration::from_secs(5));
        let bus = c.section::<BusSection>(BUS).expect("bus");
        assert_eq!(bus.local().capacity, 64);
        // Каталог и бакет — только в blob.url.
        let e = err(parse(&format!("{MINIMAL_DEV}  local:\n    root: /other\n")));
        assert!(e.contains("local.root"), "{e}");
        let e = err(parse(&format!("{MINIMAL_DEV}  s3:\n    bucket: other\n")));
        assert!(e.contains("s3.bucket"), "{e}");
    }

    #[test]
    fn schema_lists_app_sections() {
        let schema = registry().expect("registry").schema_json();
        for key in [
            "\"blob\"",
            "\"journal\"",
            "\"bus\"",
            "\"cluster\"",
            "\"database\"",
            "\"meta\"",
            "\"doctor\"",
            "\"verify\"",
            "\"startup\"",
            "\"secrets\"",
            "\"smtp\"",
            "\"sieve\"",
            "\"imap\"",
            "\"jmap\"",
            "\"dav\"",
            "\"search\"",
            "\"admin\"",
            "\"auth\"",
            "\"http\"",
            "\"trust\"",
        ] {
            assert!(schema.contains(key), "{key}");
        }
    }

    #[test]
    fn admin_listen_is_rejected_with_hint() {
        for r in [
            parse(&format!("{MINIMAL_DEV}admin:\n  listen: 127.0.0.1:9443\n")),
            strict(&format!("{MINIMAL_DEV}admin:\n  listen: 127.0.0.1:9443\n")),
        ] {
            let m = err(r);
            assert!(m.contains("http.admin.listen"), "{m}");
        }
        let c = parse(&format!(
            "{MINIMAL_DEV}admin:\n  page_size: 50\nhttp:\n  admin: {{ listen: 127.0.0.1:9443, allow_plaintext: true }}\n"
        ))
        .expect("config");
        assert_eq!(
            c.section::<AdminSection>(ADMIN).expect("admin").0.page_size,
            50
        );
        let http = c.section::<HttpSection>(HTTP).expect("http");
        assert_eq!(http.admin.as_ref().map(|l| l.listen.port()), Some(9443));
        assert_eq!(
            *parse(MINIMAL_DEV)
                .expect("config")
                .section::<AdminSection>(ADMIN)
                .expect("admin"),
            AdminSection::default()
        );
        let schema = registry().expect("registry").schema_json();
        assert!(schema.contains("admin.listen не используется"));
    }

    /// `admin.allow_external` — ключ без действия (APP-17): ошибка разбора с подсказкой в обоих режимах.
    #[test]
    fn admin_allow_external_is_rejected_with_hint() {
        for value in ["true", "false"] {
            let yaml = format!("{MINIMAL_DEV}admin:\n  allow_external: {value}\n");
            for r in [parse(&yaml), strict(&yaml)] {
                let m = err(r);
                assert!(m.contains("admin.allow_external"), "{m}");
                assert!(m.contains("http.admin.listen"), "{m}");
            }
        }
        let schema = registry().expect("registry").schema_json();
        assert!(schema.contains("admin.allow_external не используется"));
    }

    /// Пресеты секции `journal` (APP-83): Enterprise — S3 с Object Lock (governance по умолчанию,
    /// compliance — явно), SMB — локальный каталог.
    const JOURNAL_S3: &str = "journal:\n  enabled: true\n  s3:\n    bucket: thepost-journal\n    \
                              lock_mode: governance\n    retention: 2555d\n    endpoint: https://seaweedfs:8333\n";
    const JOURNAL_LOCAL: &str =
        "journal:\n  enabled: true\n  local:\n    dir: /var/lib/thepost/journal\n";

    fn journal(yaml: &str) -> JournalSection {
        let cfg = parse(&format!("{MINIMAL_DEV}{yaml}")).expect("config");
        (*cfg.section::<JournalSection>(JOURNAL).expect("journal")).clone()
    }

    /// APP-83: секция по умолчанию выключена (журналирование включается явно), пустая секция
    /// проходит проверку; пресеты разбираются с параметрами бакета и каталога.
    #[test]
    fn journal_section_defaults_and_presets() {
        let d = journal("");
        assert!(!d.enabled());
        assert_eq!(d, JournalSection::default());
        assert!(
            d.check(Profile::Dev).is_ok(),
            "выключено — хранилище не обязательно"
        );

        let s3 = journal(JOURNAL_S3);
        assert!(s3.enabled());
        assert_eq!(
            s3.location().expect("location"),
            JournalLocation::S3 {
                bucket: "thepost-journal".into()
            }
        );
        let records = s3.records_config().expect("records");
        assert_eq!(
            (
                records.lock_mode,
                records.retention,
                records.prefix.as_str()
            ),
            (
                tp_blob::LockMode::Governance,
                Duration::from_secs(2555 * 24 * 3600),
                "journal"
            )
        );
        let s3cfg = s3.s3_config("thepost-journal".into());
        assert_eq!(
            (s3cfg.bucket.as_str(), s3cfg.prefix.as_str()),
            ("thepost-journal", "")
        );
        assert_eq!(s3cfg.endpoint.as_deref(), Some("https://seaweedfs:8333"));
        assert!(s3.check(Profile::Dev).is_ok());

        let local = journal(JOURNAL_LOCAL);
        assert_eq!(
            local.location().expect("location"),
            JournalLocation::Local(PathBuf::from("/var/lib/thepost/journal"))
        );
        let local_cfg = local.local_config(PathBuf::from("/var/lib/thepost/journal"));
        assert_eq!(local_cfg.root, PathBuf::from("/var/lib/thepost/journal"));
        assert_eq!(local_cfg.fsync, LocalConfig::default().fsync);
        // Локальное хранилище: режим и срок — умолчания (блокирует только сервер, APP-82 предупреждает).
        assert_eq!(
            local.records_config().expect("records").retention,
            JOURNAL_RETENTION_DEFAULT
        );
        assert!(local.check(Profile::Dev).is_ok());
    }

    /// APP-83: выгрузка во внешний архив — адрес приёмника, формат .eml, повтор при сбое.
    #[test]
    fn journal_export_section() {
        let e = journal("").0.export;
        assert_eq!((e.address, e.format), (None, JournalExportFormat::Eml));
        assert_eq!(
            (e.retry_initial, e.retry_max, e.retry_for),
            (
                Duration::from_secs(60),
                Duration::from_secs(30 * 60),
                Duration::from_secs(72 * 3600)
            )
        );
        let j = journal(
            "journal:\n  enabled: true\n  local:\n    dir: /var/lib/thepost/journal\n  export:\n    \
             address: archive.example.ru:25\n    format: eml\n    retry_initial: 30s\n    retry_max: 10m\n    retry_for: 24h\n",
        );
        assert_eq!(j.0.export.address.as_deref(), Some("archive.example.ru:25"));
        assert_eq!(j.0.export.retry_initial, Duration::from_secs(30));
        // Неизвестный формат и плохой адрес — ошибки разбора и проверки.
        for (bad, what) in [
            ("journal:\n  export:\n    format: mbox\n", "eml"),
            (
                "journal:\n  export:\n    address: archive.example.ru\n",
                "export.address",
            ),
            (
                "journal:\n  export:\n    address: archive.example.ru:0\n",
                "export.address",
            ),
            ("journal:\n  export:\n    retry_initial: 0s\n", "export"),
        ] {
            let e = err(parse(&format!("{MINIMAL_DEV}{bad}")));
            assert!(e.contains(what), "{bad}: {e}");
        }
    }

    /// APP-83: проверка секции (разбор и `thepost config check`) отвергает: compliance без срока,
    /// неизвестный режим, оба хранилища, включённое журналирование без хранилища, пустой бакет,
    /// относительный каталог, поля места в подсекциях tp-blob.
    #[test]
    fn journal_section_check_rejects() {
        let reject = |yaml: &str, what: &str| {
            let e = err(parse(&format!("{MINIMAL_DEV}journal:\n{yaml}")));
            assert!(e.contains(what), "{yaml}: {e}");
        };
        // compliance — только с явным сроком (риск 21); с явным сроком — проходит.
        reject(
            "  enabled: true\n  s3:\n    bucket: j\n    lock_mode: compliance\n",
            "compliance",
        );
        parse(&format!(
            "{MINIMAL_DEV}journal:\n  enabled: true\n  s3:\n    bucket: j\n    lock_mode: compliance\n    retention: 3650d\n"
        ))
        .expect("compliance со сроком");
        // Неизвестный режим — ошибка разбора (перечисление governance/compliance).
        reject(
            "  s3:\n    bucket: j\n    lock_mode: hardened\n",
            "governance",
        );
        // Оба хранилища и ни одного (при включённом журналировании).
        reject(
            "  enabled: true\n  s3:\n    bucket: j\n  local:\n    dir: /var/lib/thepost/journal\n",
            "хранилище записей",
        );
        reject("  enabled: true\n", "хранилище записей");
        // Пустой бакет, не-абсолютный каталог.
        reject("  enabled: true\n  s3:\n    bucket: \"  \"\n", "s3.bucket");
        reject(
            "  enabled: true\n  local:\n    dir: relative/journal\n",
            "local.dir",
        );
        // Поля места в подсекциях tp-blob — каталог и префикс задаёт секция журнала.
        reject(
            "  enabled: true\n  local:\n    dir: /var/lib/thepost/journal\n    root: /other\n",
            "local.root",
        );
        reject(
            "  enabled: true\n  s3:\n    bucket: j\n    prefix: mail\n",
            "s3.prefix",
        );
        // Префикс и части записей — JournalConfig tp-blob.
        reject(
            "  enabled: true\n  local:\n    dir: /var/lib/thepost/journal\n  prefix: \"\"\n",
            "prefix",
        );
        reject(
            "  enabled: true\n  local:\n    dir: /var/lib/thepost/journal\n  chunk_min_bytes: 0\n",
            "chunk",
        );
        // Выключенное журналирование без хранилища — не ошибка (включается явно).
        parse(&format!("{MINIMAL_DEV}journal:\n  enabled: false\n")).expect("выключено");
    }

    /// APP-83: правила журналирования — данные организации (Admin API): ключ `journal.rules` — ошибка
    /// с подсказкой в обоих режимах, схема помечает ключ.
    #[test]
    fn journal_rules_rejected_with_hint() {
        let yaml = format!(
            "{MINIMAL_DEV}journal:\n  rules:\n    - id: r-1\n      scope: org\n      direction: both\n"
        );
        for r in [parse(&yaml), strict(&yaml)] {
            let m = err(r);
            assert!(m.contains("journal.rules"), "{m}");
            assert!(m.contains("Admin API"), "{m}");
        }
        let schema = registry().expect("registry").schema_json();
        assert!(schema.contains("journal.rules не используется"), "{schema}");
    }

    /// APP-83: бакет журнала — отдельный от бакета BLOB ящиков (`thepost config check` по всей
    /// конфигурации; проверки секций по отдельности этого не видят).
    #[test]
    fn journal_bucket_must_differ_from_blob() {
        let cfg = |blob_url: &str, journal_yaml: &str| {
            parse(&format!(
                "domain: example.org\nprofile: dev\ndatabase:\n  url: postgres://thepost@localhost/thepost?sslmode=disable\n  tls: {{ allow_plaintext: true }}\nblob:\n  url: {blob_url}\n{journal_yaml}"
            ))
            .expect("config")
        };
        let journal_s3 =
            |bucket: &str| format!("journal:\n  enabled: true\n  s3:\n    bucket: {bucket}\n");
        // Тот же бакет — ошибка; другой бакет и локальный BLOB — проходят.
        assert!(
            journal_bucket_separate(&cfg("s3://thepost-blob", &journal_s3("thepost-journal")))
                .is_ok()
        );
        let e =
            match journal_bucket_separate(&cfg("s3://thepost-blob", &journal_s3("thepost-blob"))) {
                Err(Error::Invalid(m)) => m,
                other => panic!("ожидалась ошибка: {other:?}"),
            };
        assert!(
            e.contains("journal") && e.contains("blob.url") && e.contains("отдельный бакет"),
            "{e}"
        );
        assert!(
            journal_bucket_separate(&cfg(
                "file:///var/lib/thepost/blob",
                &journal_s3("thepost-blob")
            ))
            .is_ok()
        );
        assert!(journal_bucket_separate(&cfg("s3://thepost-blob", JOURNAL_LOCAL)).is_ok());
        assert!(journal_bucket_separate(&cfg("s3://thepost-blob", "")).is_ok());
    }
}
