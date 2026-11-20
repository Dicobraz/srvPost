//! Справочник аномалий и TI в Admin API (ADM-51, решение 126; CONTRACTS.md#Risk, CTR-95): действующий
//! каталог признаков уровней установка → организация, пороги действий, пакеты поставщика, источники TI
//! и журнал срабатываний. Хранилище — контракт [`RiskStore`] (`tp-testkit::MemRisk` / `tp-meta`,
//! META-87); проверку пакета (подпись, lint, пробный прогон) и коннекторы источников делает узел
//! (APP-78) через интерфейс [`RiskNode`] — в тестах его заменяет память ([`MemRiskNode`]).
//!
//! - Признаки: `GET /api/v1/risk/signals` — каталог уровня установки (активный пакет с изменениями
//!   установки, без политик организаций); `GET /api/v1/orgs/{org}/risk/signals` — действующий каталог
//!   организации. По признаку — `{id, origin, detector, weight, threshold, action, mode, since, source,
//!   orphaned}`: `source` — уровень, давший отличие от пакета; `orphaned` — изменение администратора
//!   признака, которого в пакете больше нет (не удаляется молча, решение 126 в). `PUT|DELETE
//!   …/risk/signals/{id}` — изменение и сброс: у признака поставщика (`tp.*`) — вес, действие и режим,
//!   свои признаки (`org.*`) создаются тем же `PUT` целиком. Установка меняет значения как угодно,
//!   организация — только в сторону строгости: мягче — 422 problem+json с `errors:
//!   [{signal, field, value, base}]`. Уровень установки — только администратор установки; уровень
//!   организации — администратор организации (и установки), `GET` — и оператор.
//! - Пороги: `GET|PUT /api/v1/risk/thresholds` и `/api/v1/orgs/{org}/risk/thresholds` — четыре балла
//!   действий. Контракт CTR-95 в вердикте конвейера держит константы (подключение значений уровней —
//!   APP-78); сами значения уровней читаются и пишутся здесь и держатся в [`ThresholdLevels`], узел
//!   подключает своё хранилище. Организация не мягче установки: порог выше — 422.
//! - Пакеты (администратор установки): `GET /api/v1/risk/packages` — активный и N прошлых
//!   (`risk.package.keep`); `POST` — загрузка файла пакета (`application/octet-stream`, офлайн-импорт,
//!   до `admin.risk.max_package_bytes`) → 202 и отчёт проверки (подпись, пробный прогон, что
//!   изменится); `POST …/{version}/activate`, `POST …/{version}/rollback`. Проверяет пакет узел
//!   ([`RiskNode`], APP-78), ставит и активирует — хранилище контракта.
//! - Источники TI: `GET|POST /api/v1/risk/sources`, `GET|PUT|DELETE …/{id}` — вид, формат, TTL,
//!   действие при устаревании, лицензия, организации MSSP; ключ — только ссылка на хранилище секретов
//!   (`{"secret": "путь#поле"}`), значение ключа API не принимает и не отдаёт. `Bundled` через API не
//!   создаётся — только пакетом поставщика (400). `POST …/{id}/import` — файл списка;
//!   `POST …/{id}/refresh` — обновить сейчас (коннектор, APP-79); `GET …/{id}/usage?since=` — учёт
//!   обращений и совпадений, суммы по организациям (MSSP). Источники и пакеты — уровень установки.
//! - Срабатывания: `GET /api/v1/orgs/{org}/risk/hits?signal=&mode=&since=` — журнал срабатываний
//!   организации постранично (свежие первыми, продолжение — `next` как `until`); оператор — только
//!   `GET`.
//!
//! Каждое изменение (не `GET`/`HEAD`) — запись журнала аудита общим слоем доступа ([`crate::server`]):
//! кто, уровень (шаблон маршрута и `{org}`), какой признак (путь) и код; срабатывания справочник не
//! читает, содержимое писем не отдаёт. Хранилище не подключено ([`Admin::with_risk`]) — 503.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tp_contracts::config::duration;
use tp_contracts::ids::BlobHash;
use tp_contracts::risk::{
    ADMIN_PREFIX, Catalog, Detector, EffectiveCatalog, FeedFormat, HitRecord, HttpAuth, License,
    ListId, ListVersion, MAX_WEIGHT, Mode, Origin, PackageEntry, PackageManifest, PackageState,
    PolicyViolation, RiskAction, RiskLevel, RiskPolicy, RiskStore, Signal, SignalId,
    SignalOverride, SourceId, SourceKind, StaleAction, Tenants, Thresholds, TiOrigin, TiSource,
    Tier, UpdateReport, UsageEntry, VENDOR_PREFIX,
};
use tp_contracts::secrets::SecretRef;
use tp_contracts::{Error, Result, TenantId};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::branding::RefusedResponse;
use crate::extract::{Json, Path, Query};
use crate::server::{Admin, ApiError, Problem, Refused};

/// Префикс маршрутов уровня установки: признаки, пороги, пакеты и источники TI — только администратор
/// установки ([`crate::AdminRole::permits`]); организация и оператор работают с `/api/v1/orgs/{org}/risk/…`.
pub const RISK_PREFIX: &str = "/api/v1/risk";
/// Каталог признаков установки.
pub const RISK_SIGNALS_ROUTE: &str = "/api/v1/risk/signals";
/// Признак каталога установки.
pub const RISK_SIGNAL_ROUTE: &str = "/api/v1/risk/signals/{id}";
/// Каталог признаков организации.
pub const ORG_RISK_SIGNALS_ROUTE: &str = "/api/v1/orgs/{org}/risk/signals";
/// Признак каталога организации.
pub const ORG_RISK_SIGNAL_ROUTE: &str = "/api/v1/orgs/{org}/risk/signals/{id}";
/// Пороги действий установки.
pub const RISK_THRESHOLDS_ROUTE: &str = "/api/v1/risk/thresholds";
/// Пороги действий организации.
pub const ORG_RISK_THRESHOLDS_ROUTE: &str = "/api/v1/orgs/{org}/risk/thresholds";
/// Пакеты поставщика.
pub const RISK_PACKAGES_ROUTE: &str = "/api/v1/risk/packages";
/// Активация пакета.
pub const RISK_PACKAGE_ACTIVATE_ROUTE: &str = "/api/v1/risk/packages/{version}/activate";
/// Откат пакета.
pub const RISK_PACKAGE_ROLLBACK_ROUTE: &str = "/api/v1/risk/packages/{version}/rollback";
/// Источники TI.
pub const RISK_SOURCES_ROUTE: &str = "/api/v1/risk/sources";
/// Источник TI.
pub const RISK_SOURCE_ROUTE: &str = "/api/v1/risk/sources/{id}";
/// Импорт файла списка источника.
pub const RISK_SOURCE_IMPORT_ROUTE: &str = "/api/v1/risk/sources/{id}/import";
/// Обновление источника сейчас.
pub const RISK_SOURCE_REFRESH_ROUTE: &str = "/api/v1/risk/sources/{id}/refresh";
/// Учёт обращений к источнику.
pub const RISK_SOURCE_USAGE_ROUTE: &str = "/api/v1/risk/sources/{id}/usage";
/// Журнал срабатываний организации.
pub const ORG_RISK_HITS_ROUTE: &str = "/api/v1/orgs/{org}/risk/hits";

/// Тип содержимого загружаемых файлов (пакет, список TI).
const OCTET_STREAM: &str = "application/octet-stream";

// ---------- Схемы OpenAPI контрактов `tp_contracts::risk` (в `serde` — тот же вид); значений типов нет ----------

/// Происхождение признака: поставщик или администратор.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = Origin)]
pub enum OriginSchema {
    /// Признак поставщика (пакет, префикс `tp.`).
    Vendor,
    /// Признак администратора (префикс `org.`).
    Admin,
}

/// Поле письма детектора совпадения со списком TI.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = Field)]
pub enum FieldSchema {
    /// IP отправителя (соединение).
    SenderIp,
    /// Домен ссылки.
    LinkDomain,
    /// URL ссылки.
    LinkUrl,
    /// Домен `From`.
    FromDomain,
    /// SHA-256 вложения.
    AttachmentSha256,
}

/// Детектор признака — типизированный Rust-код с параметрами (решение 126 г).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = Detector)]
pub enum DetectorSchema {
    /// Новый для беседы тип вложения.
    ThreadNewAttachmentType,
    /// Архив с паролем.
    EncryptedArchive,
    /// Образ диска или ярлык: ISO, IMG, VHD, LNK.
    DiskImageOrShortcut,
    /// Ссылка на новый для беседы домен.
    ThreadNewLinkDomain,
    /// Смена `Reply-To` относительно беседы.
    ReplyToChanged,
    /// Совпадение поля письма со списком TI.
    ListMatch {
        /// Список.
        list: String,
        /// Поле письма.
        field: FieldSchema,
    },
}

/// Собственное действие признака (от мягкого к строгому).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = RiskAction)]
pub enum RiskActionSchema {
    /// Ничего (только балл).
    None,
    /// Пометить письмо (флаг/заголовок).
    Tag,
    /// В папку «Спам».
    Junk,
    /// В карантин.
    Quarantine,
    /// Отказ.
    Reject,
}

/// Режим признака: «только отчёт» или «применять».
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = Mode)]
pub enum ModeSchema {
    /// Срабатывания в журнале, балл и действие не применяются.
    Report,
    /// Балл и действие применяются.
    Enforce,
}

/// Уровень политики справочника: установка → организация.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = RiskLevel)]
pub enum RiskLevelSchema {
    /// Установка — меняет значения как угодно.
    Installation,
    /// Организация (UUID) — только в сторону строгости.
    Org(String),
}

/// Пороги действий: балл, с которого действует действие (константы контракта — 1, 6, 10, 15).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = Thresholds)]
pub struct ThresholdsSchema {
    /// Пометка письма.
    pub tag: u32,
    /// В папку «Спам».
    pub junk: u32,
    /// В карантин.
    pub quarantine: u32,
    /// Отказ.
    pub reject: u32,
}

/// Несоответствие политики организации базовым значениям: организация смягчила признак.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PolicyViolation)]
pub struct PolicyViolationSchema {
    /// Признак.
    pub signal: String,
    /// Поле: `weight`, `action`, `mode`.
    pub field: String,
    /// Заданное значение.
    pub value: String,
    /// Базовое значение (уровней ниже).
    pub base: String,
}

/// Итог обновления пакета: что изменится при активации.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = UpdateReport)]
pub struct UpdateReportSchema {
    /// Добавленные признаки (приходят в режиме «только отчёт»).
    pub added: Vec<String>,
    /// Удалённые из пакета без изменений администратора.
    pub removed: Vec<String>,
    /// Изменённые пакетом.
    pub changed: Vec<String>,
    /// Изменения администратора признаков, которых больше нет в пакете.
    pub orphaned_overrides: Vec<String>,
}

/// Состояние хранимого пакета.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = PackageState)]
pub enum PackageStateSchema {
    /// Действующий каталог пакета.
    Active,
    /// Хранимый для отката.
    Previous,
    /// Отклонён при проверке — отчёт в `report`.
    Rejected {
        /// Отчёт проверки (что не так).
        report: String,
    },
}

/// Уровень источника TI (решение 126 е–з).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = Tier)]
pub enum TierSchema {
    /// В поставке — раздаёт вендор подписанным пакетом; через API не создаётся.
    Bundled,
    /// Ключ заказчика — заказчик включает фид своим ключом или подпиской.
    CustomerKey,
    /// Импорт по стандартам (txt, CSV, RPZ, MISP, TAXII/STIX).
    Import,
}

/// Происхождение данных источника — для журнала и отчётов (решение 126 к).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = TiOrigin)]
pub enum TiOriginSchema {
    /// Вендор фида.
    Vendor,
    /// ГосСОПКА (НКЦКИ).
    GosSopka,
    /// ФинЦЕРТ Банка России.
    FinCert,
    /// Собственные индикаторы заказчика.
    Own,
}

/// Доставка и параметры источника TI.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = SourceKind)]
pub enum SourceKindSchema {
    /// Фид по HTTP(S).
    Http {
        /// Адрес.
        url: String,
    },
    /// Коллекция TAXII 2.1.
    Taxii {
        /// API root.
        api_root: String,
        /// Коллекция.
        collection: String,
    },
    /// Файл в каталоге импорта (закрытый контур).
    File,
}

/// Формат фида источника TI.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = FeedFormat)]
pub enum FeedFormatSchema {
    /// Простой текст: индикатор в строке.
    Txt,
    /// CSV; `column` — колонка с индикатором.
    Csv {
        /// Имя колонки.
        column: String,
    },
    /// RPZ (Response Policy Zone).
    Rpz,
    /// Фид MISP (manifest.json + CSV).
    MispFeed,
    /// STIX 2.1 (в том числе по TAXII).
    Stix21,
}

/// Действие при устаревании источника («отключить» нет).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = StaleAction)]
pub enum StaleActionSchema {
    /// Снизить вес признаков источника на `percent` процентов.
    Reduce {
        /// Процент снижения, 0–100.
        percent: u8,
    },
    /// Перевести признаки в «только отчёт».
    Report,
}

/// Лицензия источника TI: условия и атрибуция.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = License)]
pub struct LicenseSchema {
    /// Адрес условий использования.
    pub terms_url: String,
    /// Атрибуция (ссылка, дата, ©); `null` — не требуется.
    pub attribution: Option<String>,
    /// Коммерческое использование разрешено условиями.
    pub commercial: bool,
}

/// Организации, которым доступен источник.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = Tenants)]
pub enum TenantsSchema {
    /// Все организации установки.
    All,
    /// Только перечисленные (UUID).
    Only(Vec<String>),
}

/// Ссылка на поле секрета в хранилище (`<путь>#<поле>`); значение ключа API не принимает и не отдаёт.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = SecretRef)]
pub struct SecretRefSchema {
    /// Ссылка `<путь>#<поле>`, например `thepost/db#api_key`.
    pub secret: String,
}

/// Авторизация источника TI: секрет — из ссылки `key`.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = HttpAuth)]
pub enum HttpAuthSchema {
    /// Без авторизации.
    None,
    /// Свой заголовок; имя здесь, значение — секрет.
    Header {
        /// Имя заголовка (`X-Api-Key` у RST Cloud, `Auth-Key` у abuse.ch).
        name: String,
    },
    /// Basic; пользователь здесь, пароль — секрет.
    Basic {
        /// Имя пользователя (Kaspersky TAXII: `taxii`).
        user: String,
    },
    /// Bearer-токен из секрета.
    Bearer,
    /// Сертификат клиента из секрета.
    ClientCert,
}

/// Маркировка TLP версии списка из источника.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = Tlp)]
pub enum TlpSchema {
    /// TLP:CLEAR.
    Clear,
    /// TLP:GREEN.
    Green,
    /// TLP:AMBER.
    Amber,
    /// TLP:AMBER+STRICT.
    AmberStrict,
    /// TLP:RED.
    Red,
}

// ---------- Признаки ----------

/// Признак действующего каталога: значение и уровень-источник. У «осиротевшего» изменения (признака
/// больше нет в пакете поставщика, решение 126 в) детектор, порог и дата — `null`: известно только
/// само изменение.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SignalView {
    /// Идентификатор: `tp.*` — поставщик, `org.*` — администратор.
    pub id: String,
    /// Происхождение значения: поставщик или администратор.
    #[schema(value_type = OriginSchema)]
    pub origin: Origin,
    /// Детектор; `null` — осиротевшее изменение.
    #[schema(value_type = Option<DetectorSchema>)]
    pub detector: Option<Detector>,
    /// Вес в балле письма, 0–100.
    pub weight: Option<u16>,
    /// Порог силы срабатывания детектора, 0–100; `null` — осиротевшее изменение.
    pub threshold: Option<u8>,
    /// Собственное действие.
    #[schema(value_type = Option<RiskActionSchema>)]
    pub action: Option<RiskAction>,
    /// Режим: «только отчёт» или «применять».
    #[schema(value_type = Option<ModeSchema>)]
    pub mode: Option<Mode>,
    /// Дата появления признака (UTC).
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[schema(value_type = Option<String>, format = DateTime)]
    pub since: Option<OffsetDateTime>,
    /// Уровень, давший отличие от пакета; `null` — признак пакета без изменений.
    #[schema(value_type = Option<RiskLevelSchema>)]
    pub source: Option<RiskLevel>,
    /// Осиротевшее изменение: признака нет в действующем пакете (решение 126 в).
    pub orphaned: bool,
}

impl From<&tp_contracts::risk::EffectiveSignal> for SignalView {
    fn from(e: &tp_contracts::risk::EffectiveSignal) -> Self {
        Self {
            id: e.signal.id.to_string(),
            origin: e.signal.origin,
            detector: Some(e.signal.detector.clone()),
            weight: Some(e.signal.weight),
            threshold: Some(e.signal.threshold),
            action: Some(e.signal.action),
            mode: Some(e.signal.mode),
            since: Some(e.signal.since),
            source: e.source,
            orphaned: false,
        }
    }
}

impl From<&Signal> for SignalView {
    fn from(s: &Signal) -> Self {
        Self {
            id: s.id.to_string(),
            origin: s.origin,
            detector: Some(s.detector.clone()),
            weight: Some(s.weight),
            threshold: Some(s.threshold),
            action: Some(s.action),
            mode: Some(s.mode),
            since: Some(s.since),
            source: None,
            orphaned: false,
        }
    }
}

/// Изменение признака каталога: у признака поставщика (`tp.*`) — вес, действие и режим (незаданные
/// наследуются пакетом); свой признак (`org.*`) задаётся целиком — детектор, вес, порог, действие и
/// режим обязательны.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct SignalBody {
    /// Детектор (только свой признак `org.*`).
    #[schema(value_type = Option<DetectorSchema>)]
    pub detector: Option<Detector>,
    /// Вес, 0–100.
    pub weight: Option<u16>,
    /// Порог силы срабатывания, 0–100 (только свой признак).
    pub threshold: Option<u8>,
    /// Собственное действие.
    #[schema(value_type = Option<RiskActionSchema>)]
    pub action: Option<RiskAction>,
    /// Режим.
    #[schema(value_type = Option<ModeSchema>)]
    pub mode: Option<Mode>,
}

impl From<SignalOverride> for SignalBody {
    fn from(o: SignalOverride) -> Self {
        Self {
            detector: None,
            weight: o.weight,
            threshold: None,
            action: o.action,
            mode: o.mode,
        }
    }
}

/// Действующий каталог: признаки по возрастанию идентификатора; «осиротевшие» изменения — в общем
/// списке с признаком `orphaned`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SignalsView {
    /// Признаки каталога.
    pub signals: Vec<SignalView>,
}

// ---------- Пороги ----------

/// Пороги действий уровня целиком: баллы, с которых действуют действия.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ThresholdsBody {
    /// Балл пометки письма.
    pub tag: u32,
    /// Балл перемещения в «Спам».
    pub junk: u32,
    /// Балл карантина.
    pub quarantine: u32,
    /// Балл отказа.
    pub reject: u32,
}

impl From<ThresholdsBody> for Thresholds {
    fn from(b: ThresholdsBody) -> Self {
        Thresholds {
            tag: b.tag,
            junk: b.junk,
            quarantine: b.quarantine,
            reject: b.reject,
        }
    }
}

impl From<&Thresholds> for ThresholdsBody {
    fn from(t: &Thresholds) -> Self {
        ThresholdsBody {
            tag: t.tag,
            junk: t.junk,
            quarantine: t.quarantine,
            reject: t.reject,
        }
    }
}

/// Пороги уровня: свои (уровень не задан — `null`), действующие и уровень-источник.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ThresholdsView {
    /// Пороги уровня; `null` — уровень не задан (действует уровень выше и константы контракта).
    #[schema(value_type = Option<ThresholdsSchema>)]
    pub own: Option<Thresholds>,
    /// Действующие пороги.
    #[schema(value_type = ThresholdsSchema)]
    pub effective: Thresholds,
    /// Уровень, давший действующие пороги; `null` — константы контракта.
    #[schema(value_type = Option<RiskLevelSchema>)]
    pub source: Option<RiskLevel>,
}

// ---------- Пакеты ----------

/// Хранимый пакет: номер и состояние.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PackageEntryView {
    /// Номер версии (только растёт).
    pub version: u64,
    /// Состояние: активный, прошлый, отклонённый с отчётом.
    #[schema(value_type = PackageStateSchema)]
    pub state: PackageState,
}

impl From<PackageEntry> for PackageEntryView {
    fn from(p: PackageEntry) -> Self {
        Self {
            version: p.version,
            state: p.state,
        }
    }
}

/// Хранимые пакеты: действующий и N прошлых, по убыванию номера (`risk.package.keep`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PackagesView {
    /// Пакеты.
    pub packages: Vec<PackageEntryView>,
}

/// Отчёт проверки загруженного пакета (решение 126 б): подпись, пробный прогон и что изменится — до
/// активации. Пакет поставлен (202), но не активен.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PackageReportView {
    /// Номер версии проверенного пакета.
    pub version: u64,
    /// Ключ подписи (подпись Ed25519 проверил узел, APP-78).
    pub key_id: String,
    /// Прогнано образцов пакета (пробный прогон).
    pub samples: u64,
    /// Признаков в пакете.
    pub signals: u64,
    /// Что изменится при активации (новые признаки приходят в режиме «только отчёт»).
    #[schema(value_type = UpdateReportSchema)]
    pub update: UpdateReport,
}

// ---------- Источники TI ----------

/// Источник TI без идентификатора (тело `PUT`): вид, доставка, формат, TTL, действие при устаревании,
/// лицензия, организации, ключ-ссылка и авторизация.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TiSourceBody {
    /// Уровень: ключ заказчика или импорт (`bundled` — только пакетом поставщика, 400).
    #[schema(value_type = TierSchema)]
    pub tier: Tier,
    /// Доставка.
    #[schema(value_type = SourceKindSchema)]
    pub kind: SourceKind,
    /// Формат.
    #[schema(value_type = FeedFormatSchema)]
    pub format: FeedFormat,
    /// Срок жизни данных (TTL): старше — устаревший (`1h`, `30m`).
    #[serde(with = "duration")]
    #[schema(value_type = String, example = "1h")]
    pub ttl: Duration,
    /// Действие при устаревании («отключить» нет).
    #[schema(value_type = StaleActionSchema)]
    pub stale: StaleAction,
    /// Лицензия.
    #[schema(value_type = LicenseSchema)]
    pub license: License,
    /// Организации, которым доступен.
    #[schema(value_type = TenantsSchema)]
    pub tenants: Tenants,
    /// Ключ (токен, сертификат) — ссылка на хранилище секретов; значение ключа не принимает и не отдаёт.
    #[schema(value_type = Option<SecretRefSchema>)]
    pub key: Option<SecretRef>,
    /// Авторизация (секрет — из `key`).
    #[schema(value_type = HttpAuthSchema)]
    pub auth: HttpAuth,
    /// Происхождение — для журнала и отчётов.
    #[schema(value_type = TiOriginSchema)]
    pub origin: TiOrigin,
}

/// Новый источник TI (тело `POST`): идентификатор и параметры.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct NewTiSourceBody {
    /// Идентификатор: `[a-z0-9._-]`, до 64 символов.
    pub id: String,
    /// Уровень: ключ заказчика или импорт (`bundled` — только пакетом поставщика, 400).
    #[schema(value_type = TierSchema)]
    pub tier: Tier,
    /// Доставка.
    #[schema(value_type = SourceKindSchema)]
    pub kind: SourceKind,
    /// Формат.
    #[schema(value_type = FeedFormatSchema)]
    pub format: FeedFormat,
    /// Срок жизни данных (TTL): старше — устаревший (`1h`, `30m`).
    #[serde(with = "duration")]
    #[schema(value_type = String, example = "1h")]
    pub ttl: Duration,
    /// Действие при устаревании («отключить» нет).
    #[schema(value_type = StaleActionSchema)]
    pub stale: StaleAction,
    /// Лицензия.
    #[schema(value_type = LicenseSchema)]
    pub license: License,
    /// Организации, которым доступен.
    #[schema(value_type = TenantsSchema)]
    pub tenants: Tenants,
    /// Ключ (токен, сертификат) — ссылка на хранилище секретов; значение ключа не принимает и не отдаёт.
    #[schema(value_type = Option<SecretRefSchema>)]
    pub key: Option<SecretRef>,
    /// Авторизация (секрет — из `key`).
    #[schema(value_type = HttpAuthSchema)]
    pub auth: HttpAuth,
    /// Происхождение — для журнала и отчётов.
    #[schema(value_type = TiOriginSchema)]
    pub origin: TiOrigin,
}

impl NewTiSourceBody {
    /// Источник контракта; недопустимый идентификатор — `Invalid`.
    fn source(&self) -> Result<TiSource> {
        Ok(TiSource {
            id: SourceId::new(&self.id)?,
            tier: self.tier,
            kind: self.kind.clone(),
            format: self.format.clone(),
            ttl: self.ttl,
            stale: self.stale,
            license: self.license.clone(),
            tenants: self.tenants.clone(),
            key: self.key.clone(),
            auth: self.auth.clone(),
            origin: self.origin,
        })
    }
}

/// Источник TI в ответе API (ключ — только ссылка, значения не отдаёт).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct TiSourceView {
    /// Идентификатор.
    pub id: String,
    /// Уровень: в поставке, ключ заказчика, импорт.
    #[schema(value_type = TierSchema)]
    pub tier: Tier,
    /// Доставка.
    #[schema(value_type = SourceKindSchema)]
    pub kind: SourceKind,
    /// Формат.
    #[schema(value_type = FeedFormatSchema)]
    pub format: FeedFormat,
    /// Срок жизни данных (TTL).
    #[serde(with = "duration")]
    #[schema(value_type = String, example = "1h")]
    pub ttl: Duration,
    /// Действие при устаревании.
    #[schema(value_type = StaleActionSchema)]
    pub stale: StaleAction,
    /// Лицензия.
    #[schema(value_type = LicenseSchema)]
    pub license: License,
    /// Организации, которым доступен.
    #[schema(value_type = TenantsSchema)]
    pub tenants: Tenants,
    /// Ключ — ссылка на хранилище секретов; значение не отдаётся.
    #[schema(value_type = Option<SecretRefSchema>)]
    pub key: Option<SecretRef>,
    /// Авторизация.
    #[schema(value_type = HttpAuthSchema)]
    pub auth: HttpAuth,
    /// Происхождение.
    #[schema(value_type = TiOriginSchema)]
    pub origin: TiOrigin,
}

impl From<&TiSource> for TiSourceBody {
    fn from(s: &TiSource) -> Self {
        Self {
            tier: s.tier,
            kind: s.kind.clone(),
            format: s.format.clone(),
            ttl: s.ttl,
            stale: s.stale,
            license: s.license.clone(),
            tenants: s.tenants.clone(),
            key: s.key.clone(),
            auth: s.auth.clone(),
            origin: s.origin,
        }
    }
}

impl From<&TiSource> for TiSourceView {
    fn from(s: &TiSource) -> Self {
        Self {
            id: s.id.to_string(),
            tier: s.tier,
            kind: s.kind.clone(),
            format: s.format.clone(),
            ttl: s.ttl,
            stale: s.stale,
            license: s.license.clone(),
            tenants: s.tenants.clone(),
            key: s.key.clone(),
            auth: s.auth.clone(),
            origin: s.origin,
        }
    }
}

/// Источники TI по идентификатору.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SourcesView {
    /// Источники.
    pub sources: Vec<TiSourceView>,
}

/// Версия списка TI, ставшая текущей (импорт или обновление).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ListVersionView {
    /// Список.
    pub list: String,
    /// Источник.
    pub source: String,
    /// SHA-256 содержимого (hex).
    pub sha256: String,
    /// Ссылка на объект содержимого в BLOB.
    pub blob: String,
    /// Число записей.
    pub entries: u64,
    /// Момент загрузки (UTC).
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub fetched_at: OffsetDateTime,
    /// Маркировка TLP из источника; `null` — маркировки нет.
    #[schema(value_type = Option<TlpSchema>)]
    pub tlp: Option<tp_contracts::risk::Tlp>,
}

impl From<ListVersion> for ListVersionView {
    fn from(v: ListVersion) -> Self {
        Self {
            list: v.list.to_string(),
            source: v.source.to_string(),
            sha256: v.sha256.to_string(),
            blob: v.blob,
            entries: v.entries,
            fetched_at: v.fetched_at,
            tlp: v.tlp,
        }
    }
}

/// Параметры учёта источника.
#[derive(Debug, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct UsageParams {
    /// Учёт с этого момента (RFC 3339), включительно; по умолчанию — весь учёт.
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(value_type = Option<String>, format = DateTime)]
    pub since: Option<OffsetDateTime>,
}

/// Учёт источника по организации: суммы обращений и совпадений (MSSP, решение 126 е).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct UsageTotalView {
    /// Организация (UUID).
    pub tenant: String,
    /// Обращения (проверки полей письма по спискам источника).
    pub lookups: u64,
    /// Совпадения.
    pub hits: u64,
}

/// Учёт источника: суммы по организациям с `since`, по возрастанию организации.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct UsageView {
    /// Источник.
    pub source: String,
    /// Начало периода (UTC).
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub since: OffsetDateTime,
    /// Суммы по организациям.
    pub usage: Vec<UsageTotalView>,
}

// ---------- Срабатывания ----------

/// Параметры журнала срабатываний (условия — по «и»; без условия — вся организация).
#[derive(Debug, Default, Serialize, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(deny_unknown_fields)]
pub struct HitsParams {
    /// Только этот признак (`tp.*`, `org.*`).
    #[param(value_type = Option<String>)]
    pub signal: Option<String>,
    /// Режим: `report` — только отчёт, `enforce` — применённые.
    #[param(value_type = Option<String>)]
    pub mode: Option<String>,
    /// Начало интервала (RFC 3339), включительно.
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(value_type = Option<String>, format = DateTime)]
    pub since: Option<OffsetDateTime>,
    /// Конец интервала (RFC 3339), не включительно; продолжение страницы — её `next`.
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(value_type = Option<String>, format = DateTime)]
    pub until: Option<OffsetDateTime>,
    /// Размер страницы (по умолчанию и наибольший — из конфигурации).
    pub limit: Option<usize>,
}

/// Срабатывание признака в журнале организации.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HitView {
    /// Письмо (SHA-256, hex).
    pub message: String,
    /// Признак.
    pub signal: String,
    /// Сила срабатывания, 0–100.
    pub strength: u8,
    /// Вес признака при срабатывании.
    pub weight: u16,
    /// Режим признака при срабатывании: `report` — только журнал.
    #[schema(value_type = ModeSchema)]
    pub mode: Mode,
    /// Момент (UTC).
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, format = DateTime)]
    pub at: OffsetDateTime,
}

impl From<HitRecord> for HitView {
    fn from(r: HitRecord) -> Self {
        Self {
            message: r.message.to_string(),
            signal: r.signal.to_string(),
            strength: r.strength,
            weight: r.weight,
            mode: r.mode,
            at: r.at,
        }
    }
}

/// Страница журнала срабатываний: свежие первыми; срабатывания одного момента (одно письмо —
/// несколько признаков) не разрезаются страницей.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct HitsView {
    /// Срабатывания страницы.
    pub hits: Vec<HitView>,
    /// Конец интервала следующей страницы (`until`, RFC 3339); `null` — записей больше нет.
    pub next: Option<String>,
}

/// Отказ записи признака: организация мягче установки (RFC 9457 с расширением `errors`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct RiskProblem {
    /// Код HTTP (422).
    pub status: u16,
    /// Краткое описание кода.
    pub title: String,
    /// Несоответствия по-русски, через «; ».
    pub detail: String,
    /// Несоответствия: организация смягчила признак.
    #[schema(value_type = Vec<PolicyViolationSchema>)]
    pub errors: Vec<PolicyViolation>,
}

// ---------- Узел: проверка пакета и коннекторы (APP-78) ----------

/// Проверенный пакет: манифест (подпись и lint пройдены) и итог пробного прогона.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageVerified {
    /// Манифест пакета.
    pub manifest: PackageManifest,
    /// Прогнано образцов.
    pub samples: u64,
}

/// Операции узла над справочником риска (APP-78), которые приложение передаёт с [`Admin::with_risk`]:
/// проверка загруженного пакета (подпись Ed25519 доверенным ключом, lint, пробный прогон на образцах)
/// и работа с содержимым источников TI (разбор форматов, коннекторы). Admin API только вызывает их;
/// в тестах и на узле без коннекторов — память ([`MemRiskNode`]).
#[async_trait]
pub trait RiskNode: Send + Sync + 'static {
    /// Проверяет байты загруженного файла пакета: подпись, lint (схема, известные детекторы,
    /// запрещённые к поставке источники) и пробный прогон на образцах. Отказ — `Error::Invalid` с
    /// причиной (чужая подпись, образец не совпал).
    async fn verify_package(&self, bytes: &[u8]) -> Result<PackageVerified>;

    /// Разбирает файл списка источника (импорт): число записей и маркировка TLP; содержимое — в BLOB
    /// узла ([`ListVersion::blob`]). Список импорта — один на источник.
    async fn import_list(&self, source: &TiSource, bytes: &[u8]) -> Result<ListVersion>;

    /// Обновляет источник сейчас (коннектор, APP-79): выгрузка фида и новая версия списка; `File` —
    /// файл из каталога импорта `risk.import.dir`. Ошибка выгрузки — как есть.
    async fn refresh_source(&self, source: &TiSource) -> Result<ListVersion>;
}

/// Проверка пакета и импорт списков в памяти (для тестов и узлов без коннекторов): файл пакета — JSON
/// манифеста, подпись — доверенный `key_id` (по умолчанию `vendor`, добавляет
/// [`MemRiskNode::with_trusted_key`]); записи списка — непустые строки файла; обновление — сводка
/// вместо выгрузки.
#[derive(Debug, Clone)]
pub struct MemRiskNode {
    trusted: BTreeSet<String>,
}

impl Default for MemRiskNode {
    fn default() -> Self {
        Self {
            trusted: BTreeSet::from(["vendor".to_owned()]),
        }
    }
}

impl MemRiskNode {
    /// Узел с дополнительным доверенным ключом подписи.
    pub fn with_trusted_key(mut self, key: impl Into<String>) -> Self {
        self.trusted.insert(key.into());
        self
    }

    /// Версия списка из байтов: записи — непустые строки, SHA-256 содержимого.
    fn version(source: &TiSource, bytes: &[u8], fetched_at: OffsetDateTime) -> ListVersion {
        ListVersion {
            list: ListId::new(source.id.as_str())
                .unwrap_or_else(|_| ListId::new("list").expect("id")),
            source: source.id.clone(),
            sha256: BlobHash(Sha256::digest(bytes).into()),
            blob: format!("mem/risk/{}", source.id),
            entries: u64::try_from(
                String::from_utf8_lossy(bytes)
                    .lines()
                    .filter(|l| !l.trim().is_empty())
                    .count(),
            )
            .unwrap_or(u64::MAX),
            fetched_at,
            tlp: None,
        }
    }
}

#[async_trait]
impl RiskNode for MemRiskNode {
    async fn verify_package(&self, bytes: &[u8]) -> Result<PackageVerified> {
        let manifest: PackageManifest = serde_json::from_slice(bytes)
            .map_err(|e| Error::invalid(format!("risk: файл пакета — не манифест JSON: {e}")))?;
        manifest.validate()?;
        if !self.trusted.contains(&manifest.key_id) {
            return Err(Error::invalid(format!(
                "risk: пакет {}: подпись ключом {:?} не принята (доверенные: {})",
                manifest.version,
                manifest.key_id,
                self.trusted.iter().cloned().collect::<Vec<_>>().join(", ")
            )));
        }
        let samples = u64::try_from(manifest.samples.len()).unwrap_or(u64::MAX);
        Ok(PackageVerified { manifest, samples })
    }

    async fn import_list(&self, source: &TiSource, bytes: &[u8]) -> Result<ListVersion> {
        Ok(Self::version(source, bytes, OffsetDateTime::now_utc()))
    }

    async fn refresh_source(&self, source: &TiSource) -> Result<ListVersion> {
        let at = OffsetDateTime::now_utc();
        let bytes = format!("{} refresh {}", source.id, at.unix_timestamp()).into_bytes();
        Ok(Self::version(source, &bytes, at))
    }
}

// ---------- Пороги уровней ----------

/// Пороги действий по уровням (ADM-51): контракт CTR-95 в действующем каталоге отдаёт константы
/// ([`Thresholds::default`]); значения уровней читаются и пишутся маршрутами, а держит эта память,
/// пока узел не подключит своё хранилище (APP-78). Организация не мягче установки — проверяет маршрут.
#[derive(Debug, Clone, Default)]
pub struct ThresholdLevels(Arc<Mutex<BTreeMap<RiskLevel, Thresholds>>>);

impl ThresholdLevels {
    /// Пороги уровня; не заданы — `None`.
    pub fn get(&self, level: RiskLevel) -> Option<Thresholds> {
        self.0.lock().expect("пороги").get(&level).copied()
    }

    /// Заменяет пороги уровня целиком.
    pub fn set(&self, level: RiskLevel, thresholds: Thresholds) {
        self.0.lock().expect("пороги").insert(level, thresholds);
    }
}

/// Подсекция `admin.risk` config.yaml: пределы загрузки файлов справочника аномалий.
///
/// ```yaml
/// max_package_bytes: 67108864
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RiskApiConfig {
    /// Наибольший размер файла пакета поставщика и файла списка TI (`application/octet-stream`), байт.
    pub max_package_bytes: usize,
}

impl Default for RiskApiConfig {
    /// Пакет с образцами и списком TI — до 64 МиБ.
    fn default() -> Self {
        Self {
            max_package_bytes: 64 * 1024 * 1024,
        }
    }
}

impl RiskApiConfig {
    /// Проверка: предел не меньше 1 КиБ.
    pub fn check(&self) -> Result<()> {
        if self.max_package_bytes < 1024 {
            return Err(Error::invalid(
                "admin.risk: max_package_bytes — не меньше 1024 байт",
            ));
        }
        Ok(())
    }
}

/// Подключённый справочник: хранилище контракта, операции узла и пороги уровней.
#[derive(Clone)]
pub(crate) struct RiskStores {
    /// Хранилище справочника (CTR-95).
    pub store: Arc<dyn RiskStore>,
    /// Операции узла (APP-78): проверка пакета, коннекторы источников.
    pub node: Arc<dyn RiskNode>,
    /// Пороги уровней.
    pub thresholds: ThresholdLevels,
}

impl fmt::Debug for RiskStores {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RiskStores").finish_non_exhaustive()
    }
}

/// Маршруты справочника аномалий; `max_bytes` — предел файлов пакета и списка (больше общего предела
/// тела запроса, [`crate::AdminConfig::max_body_size`]).
pub(crate) fn routes(r: Router<Arc<Admin>>, max_bytes: usize) -> Router<Arc<Admin>> {
    r.route(RISK_SIGNALS_ROUTE, get(list_installation_signals))
        .route(
            RISK_SIGNAL_ROUTE,
            put(put_installation_signal).delete(reset_installation_signal),
        )
        .route(ORG_RISK_SIGNALS_ROUTE, get(list_org_signals))
        .route(
            ORG_RISK_SIGNAL_ROUTE,
            put(put_org_signal).delete(reset_org_signal),
        )
        .route(
            RISK_THRESHOLDS_ROUTE,
            get(get_installation_thresholds).put(put_installation_thresholds),
        )
        .route(
            ORG_RISK_THRESHOLDS_ROUTE,
            get(get_org_thresholds).put(put_org_thresholds),
        )
        .route(
            RISK_PACKAGES_ROUTE,
            get(list_packages)
                .post(upload_package)
                .layer(DefaultBodyLimit::max(max_bytes)),
        )
        .route(RISK_PACKAGE_ACTIVATE_ROUTE, post(activate_package))
        .route(RISK_PACKAGE_ROLLBACK_ROUTE, post(rollback_package))
        .route(
            RISK_SOURCES_ROUTE,
            get(list_ti_sources)
                .post(create_source)
                .layer(DefaultBodyLimit::max(max_bytes)),
        )
        .route(
            RISK_SOURCE_ROUTE,
            get(get_source).put(put_source).delete(delete_source),
        )
        .route(
            RISK_SOURCE_IMPORT_ROUTE,
            post(import_source).layer(DefaultBodyLimit::max(max_bytes)),
        )
        .route(RISK_SOURCE_REFRESH_ROUTE, post(refresh_source))
        .route(RISK_SOURCE_USAGE_ROUTE, get(source_usage))
        .route(ORG_RISK_HITS_ROUTE, get(list_risk_hits))
}

/// Спецификация OpenAPI маршрутов модуля.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        list_installation_signals,
        put_installation_signal,
        reset_installation_signal,
        list_org_signals,
        put_org_signal,
        reset_org_signal,
        get_installation_thresholds,
        put_installation_thresholds,
        get_org_thresholds,
        put_org_thresholds,
        list_packages,
        upload_package,
        activate_package,
        rollback_package,
        list_ti_sources,
        create_source,
        get_source,
        put_source,
        delete_source,
        import_source,
        refresh_source,
        source_usage,
        list_risk_hits
    ),
    components(schemas(
        OriginSchema,
        FieldSchema,
        DetectorSchema,
        RiskActionSchema,
        ModeSchema,
        RiskLevelSchema,
        ThresholdsSchema,
        PolicyViolationSchema,
        UpdateReportSchema,
        PackageStateSchema,
        TierSchema,
        TiOriginSchema,
        SourceKindSchema,
        FeedFormatSchema,
        StaleActionSchema,
        LicenseSchema,
        TenantsSchema,
        SecretRefSchema,
        HttpAuthSchema,
        TlpSchema,
        SignalView,
        SignalBody,
        SignalsView,
        ThresholdsBody,
        ThresholdsView,
        PackageEntryView,
        PackagesView,
        PackageReportView,
        TiSourceBody,
        NewTiSourceBody,
        TiSourceView,
        SourcesView,
        ListVersionView,
        UsageTotalView,
        UsageView,
        HitView,
        HitsView,
        RiskProblem
    ))
)]
pub(crate) struct Doc;

// ---------- Внутренние помощники ----------

impl Admin {
    /// Подключает справочник аномалий и TI (ADM-51): хранилище контракта (CTR-95) и операции узла
    /// (проверка пакета, коннекторы источников, APP-78). Без него маршруты справочника — 503.
    pub fn with_risk(mut self, store: Arc<dyn RiskStore>, node: Arc<dyn RiskNode>) -> Self {
        self.risk = Some(RiskStores {
            store,
            node,
            thresholds: ThresholdLevels::default(),
        });
        self
    }
}

/// Справочник; не подключён — 503.
fn risk(a: &Admin) -> std::result::Result<&RiskStores, Error> {
    a.risk.as_ref().ok_or(Error::UNAVAILABLE)
}

/// Ошибка контракта — готовый отказ (обёртка [`RefusedResponse`], как [`Refused`] для сложных ответов).
fn api(e: Error) -> RefusedResponse {
    RefusedResponse::from(ApiError(e).into_response())
}

/// 422 problem+json с пояснением (без перечня).
fn refused_422(detail: String) -> RefusedResponse {
    problem(StatusCode::UNPROCESSABLE_ENTITY, &detail)
}

/// Ответ problem+json (RFC 9457).
fn problem(status: StatusCode, detail: &str) -> RefusedResponse {
    let body = Problem {
        status: status.as_u16(),
        title: status.canonical_reason().unwrap_or_default().to_owned(),
        detail: Some(detail.to_owned()),
    };
    let mut resp = (status, axum::Json(body)).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/problem+json"),
    );
    RefusedResponse::from(resp)
}

/// 422 problem+json с перечнем несоответствий (`errors`).
fn softening(errors: Vec<PolicyViolation>) -> RefusedResponse {
    let status = StatusCode::UNPROCESSABLE_ENTITY;
    let list = errors
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("; ");
    let body = RiskProblem {
        status: status.as_u16(),
        title: status.canonical_reason().unwrap_or_default().to_owned(),
        detail: format!("организация может только ужесточить: {list}"),
        errors,
    };
    let mut resp = (status, axum::Json(body)).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("application/problem+json"),
    );
    RefusedResponse::from(resp)
}

/// Действующий каталог уровня установки — активный пакет с изменениями установки, без политик
/// организаций ([`RiskStore::effective`] организации без политики: политики пишет только
/// администратор своей организации, случайной — никто).
async fn base_catalog(store: &dyn RiskStore) -> Result<EffectiveCatalog> {
    store.effective(TenantId::new()).await
}

/// Каталог уровня и политика уровня (свои изменения и признаки; пустая — уровень не задан).
async fn level_state(
    a: &Admin,
    level: RiskLevel,
) -> std::result::Result<(EffectiveCatalog, RiskPolicy), Error> {
    let stores = risk(a)?;
    let policy = stores.store.policy(level).await?;
    let catalog = match level {
        RiskLevel::Installation => base_catalog(&*stores.store).await?,
        RiskLevel::Org(org) => stores.store.effective(org).await?,
    };
    Ok((catalog, policy.unwrap_or_default()))
}

/// «Осиротевшее» изменение — запись каталога: признак поставщика исчез из пакета, изменение
/// администратора осталось (известны только заданные поля, решение 126 в).
fn orphaned_view(level: RiskLevel, id: &SignalId, o: &SignalOverride) -> SignalView {
    SignalView {
        id: id.to_string(),
        origin: Origin::Vendor,
        detector: None,
        weight: o.weight,
        threshold: None,
        action: o.action,
        mode: o.mode,
        since: None,
        source: Some(level),
        orphaned: true,
    }
}

/// Действующий каталог уровня: признаки по возрастанию идентификатора, «осиротевшие» изменения — в
/// общем списке.
async fn signals_view(a: &Admin, level: RiskLevel) -> std::result::Result<SignalsView, Error> {
    let (catalog, policy) = level_state(a, level).await?;
    let mut signals: Vec<SignalView> = catalog.signals.iter().map(SignalView::from).collect();
    for (id, o) in &policy.overrides {
        if catalog.get(id).is_none() {
            signals.push(orphaned_view(level, id, o));
        }
    }
    signals.sort_by(|x, y| x.id.cmp(&y.id));
    Ok(SignalsView { signals })
}

/// Признак после изменения: запись каталога или «осиротевшее» изменение политики уровня.
async fn signal_view(
    a: &Admin,
    level: RiskLevel,
    id: &SignalId,
) -> std::result::Result<SignalView, Error> {
    let (catalog, policy) = level_state(a, level).await?;
    if let Some(entry) = catalog.get(id) {
        return Ok(SignalView::from(entry));
    }
    let o = policy.overrides.get(id).ok_or(Error::NotFound)?;
    Ok(orphaned_view(level, id, o))
}

/// Несоответствия политики организации базовым значениям (как [`RiskPolicy::validate`], но
/// структурно — для 422 с `errors`): вес ниже, действие мягче, «только отчёт» вместо «применять».
fn violations(policy: &RiskPolicy, base: &EffectiveCatalog) -> Vec<PolicyViolation> {
    let mut out = Vec::new();
    for (id, o) in &policy.overrides {
        let Some(b) = base.get(id) else {
            continue;
        };
        if let Some(weight) = o.weight
            && weight < b.signal.weight
        {
            out.push(PolicyViolation {
                signal: id.clone(),
                field: "weight".to_owned(),
                value: weight.to_string(),
                base: b.signal.weight.to_string(),
            });
        }
        if let Some(action) = o.action
            && action < b.signal.action
        {
            out.push(PolicyViolation {
                signal: id.clone(),
                field: "action".to_owned(),
                value: action.to_string(),
                base: b.signal.action.to_string(),
            });
        }
        if o.mode == Some(Mode::Report) && b.signal.mode == Mode::Enforce {
            out.push(PolicyViolation {
                signal: id.clone(),
                field: "mode".to_owned(),
                value: Mode::Report.to_string(),
                base: Mode::Enforce.to_string(),
            });
        }
    }
    out
}

/// Идентификатор признака из пути: `[a-z0-9._-]`, до 64 символов; недопустимый — пояснение для 400.
fn signal_id(raw: &str) -> std::result::Result<SignalId, String> {
    SignalId::new(raw).map_err(|_| {
        format!(
            "признак {raw:?}: идентификатор — [a-z0-9._-], до 64 символов, с префиксом tp. или org."
        )
    })
}

/// Идентификатор источника из пути; недопустимый — пояснение для 400.
fn source_id(raw: &str) -> std::result::Result<SourceId, String> {
    SourceId::new(raw)
        .map_err(|_| format!("источник {raw:?}: идентификатор — [a-z0-9._-], до 64 символов"))
}

/// Изменение или создание признака уровня: проверка тела по префиксу, запись политики, ответ —
/// признак после изменения. Смягчение организации — 422 с `errors`; вес выше предела — 422.
async fn put_signal(
    a: &Admin,
    level: RiskLevel,
    id: SignalId,
    body: SignalBody,
) -> std::result::Result<Response, RefusedResponse> {
    let stores = risk(a).map_err(api)?;
    let mut policy = stores
        .store
        .policy(level)
        .await
        .map_err(api)?
        .unwrap_or_default();
    let text = id.as_str();
    if text.starts_with(VENDOR_PREFIX) {
        if body.detector.is_some() || body.threshold.is_some() {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                &format!(
                    "признак {text}: детектор и порог срабатывания меняет только пакет поставщика"
                ),
            ));
        }
        if body.weight.is_none() && body.action.is_none() && body.mode.is_none() {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                &format!("признак {text}: пустое изменение — задайте weight, action или mode"),
            ));
        }
        if body.weight.is_some_and(|w| w > MAX_WEIGHT) {
            return Err(refused_422(format!(
                "признак {text}: вес выше предела {MAX_WEIGHT}"
            )));
        }
        policy.overrides.insert(
            id.clone(),
            SignalOverride {
                weight: body.weight,
                action: body.action,
                mode: body.mode,
            },
        );
    } else if text.starts_with(ADMIN_PREFIX) {
        let SignalBody {
            detector: Some(detector),
            weight: Some(weight),
            threshold: Some(threshold),
            action: Some(action),
            mode: Some(mode),
        } = body
        else {
            return Err(problem(
                StatusCode::BAD_REQUEST,
                &format!(
                    "свой признак {text} задаётся целиком: detector, weight, threshold, action и mode"
                ),
            ));
        };
        if weight > MAX_WEIGHT {
            return Err(refused_422(format!(
                "признак {text}: вес выше предела {MAX_WEIGHT}"
            )));
        }
        let signal = Signal {
            id: id.clone(),
            detector,
            weight,
            threshold,
            action,
            mode,
            origin: Origin::Admin,
            since: OffsetDateTime::now_utc(),
        };
        signal.validate().map_err(api)?;
        match policy.signals.iter_mut().find(|s| s.id == signal.id) {
            Some(old) => *old = signal,
            None => policy.signals.push(signal),
        }
    } else {
        return Err(problem(
            StatusCode::BAD_REQUEST,
            &format!(
                "идентификатор признака {text:?}: префикс {VENDOR_PREFIX} — признаки поставщика, \
                 {ADMIN_PREFIX} — свои"
            ),
        ));
    }
    // Организация — только в сторону строгости: мягче уровней ниже — 422 с `errors`.
    if let RiskLevel::Org(_) = level {
        let base = base_catalog(&*stores.store).await.map_err(api)?;
        let errors = violations(&policy, &base);
        if !errors.is_empty() {
            return Err(softening(errors));
        }
    }
    stores.store.set_policy(level, &policy).await.map_err(|e| {
        matches!(e, Error::Invalid(_))
            .then(|| refused_422(e.to_string()))
            .unwrap_or_else(|| api(e))
    })?;
    let view = signal_view(a, level, &id).await.map_err(api)?;
    Ok(Json(view).into_response())
}

/// Сброс изменения или своего признака уровня: политика без него; изменения на уровне нет — 404.
/// Ответ — признак после сброса (у пакета — значение пакета) или удалённый свой признак.
async fn reset_signal(
    a: &Admin,
    level: RiskLevel,
    id: SignalId,
) -> std::result::Result<Response, RefusedResponse> {
    let stores = risk(a).map_err(api)?;
    let mut policy = stores
        .store
        .policy(level)
        .await
        .map_err(api)?
        .unwrap_or_default();
    if id.as_str().starts_with(ADMIN_PREFIX) {
        let Some(at) = policy
            .signals
            .iter()
            .position(|s| s.id == id)
            .map(|at| policy.signals.swap_remove(at))
        else {
            return Err(api(Error::NotFound));
        };
        stores.store.set_policy(level, &policy).await.map_err(api)?;
        let mut view = SignalView::from(&at);
        view.source = Some(level);
        return Ok(Json(view).into_response());
    }
    let Some(over) = policy.overrides.remove(&id) else {
        return Err(api(Error::NotFound));
    };
    stores.store.set_policy(level, &policy).await.map_err(api)?;
    let view = match signal_view(a, level, &id).await {
        Ok(v) => v,
        // Признака в пакете нет — сброшенное изменение и было «осиротевшим».
        Err(_) => orphaned_view(level, &id, &over),
    };
    Ok(Json(view).into_response())
}

/// Пороги уровня: свои, действующие и уровень-источник (организация поверх установки, без своей —
/// установка, без неё — константы контракта).
fn thresholds_view(a: &Admin, level: RiskLevel) -> std::result::Result<ThresholdsView, Error> {
    let stores = risk(a)?;
    let own = stores.thresholds.get(level);
    let inst = stores.thresholds.get(RiskLevel::Installation);
    let (effective, source) = match (own, inst) {
        (Some(t), _) => (t, Some(level)),
        (None, Some(t)) => (t, Some(RiskLevel::Installation)),
        (None, None) => (Thresholds::default(), None),
    };
    Ok(ThresholdsView {
        own,
        effective,
        source,
    })
}

/// Замена порогов уровня: веса растут с действием мягче к строже; организация не мягче установки
/// (порог выше — действие позже — 422).
async fn put_thresholds(
    a: &Admin,
    level: RiskLevel,
    body: ThresholdsBody,
) -> std::result::Result<ThresholdsView, RefusedResponse> {
    let stores = risk(a).map_err(api)?;
    let t: Thresholds = body.into();
    if !(t.tag <= t.junk && t.junk <= t.quarantine && t.quarantine <= t.reject) {
        return Err(refused_422(
            "пороги растут с действием: tag ≤ junk ≤ quarantine ≤ reject".to_owned(),
        ));
    }
    if let RiskLevel::Org(_) = level {
        let base = stores
            .thresholds
            .get(RiskLevel::Installation)
            .unwrap_or_default();
        for (name, value, base_value) in [
            ("tag", t.tag, base.tag),
            ("junk", t.junk, base.junk),
            ("quarantine", t.quarantine, base.quarantine),
            ("reject", t.reject, base.reject),
        ] {
            if value > base_value {
                return Err(refused_422(format!(
                    "порог {name} = {value} выше базового {base_value}: организация может только \
                     ужесточить (порог ниже — действие раньше)"
                )));
            }
        }
    }
    stores.thresholds.set(level, t);
    thresholds_view(a, level).map_err(api)
}

/// Источник по идентификатору; нет — `NotFound`.
async fn source_of(a: &Admin, id: &SourceId) -> std::result::Result<TiSource, Error> {
    let stores = risk(a)?;
    stores
        .store
        .sources()
        .await?
        .into_iter()
        .find(|s| &s.id == id)
        .ok_or(Error::NotFound)
}

/// Загруженный файл (пакет, список): тип — 415, размер — 413 (`admin.risk.max_package_bytes`).
fn file_body(
    a: &Admin,
    headers: &HeaderMap,
    body: &Bytes,
) -> std::result::Result<(), RefusedResponse> {
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if ct != OCTET_STREAM {
        return Err(problem(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            &format!("файл — {OCTET_STREAM}, получен {ct:?}"),
        ));
    }
    let max = a.cfg.risk.max_package_bytes;
    if body.len() > max {
        return Err(problem(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!(
                "файл — не больше {} КиБ, получено {} КиБ",
                max / 1024,
                body.len().div_ceil(1024)
            ),
        ));
    }
    Ok(())
}

/// Хранимые пакеты после действия (активация, откат) — ответ.
async fn packages_view(a: &Admin) -> std::result::Result<Json<PackagesView>, RefusedResponse> {
    let stores = risk(a).map_err(api)?;
    let packages = stores.store.packages().await.map_err(api)?;
    Ok(Json(PackagesView {
        packages: packages.into_iter().map(Into::into).collect(),
    }))
}

/// `Invalid` — 422 с причиной (номер пакета не растёт, смягчение), прочее — как есть.
fn invalid_422(e: Error) -> RefusedResponse {
    matches!(e, Error::Invalid(_))
        .then(|| refused_422(e.to_string()))
        .unwrap_or_else(|| api(e))
}

// ---------- Маршруты: признаки ----------

/// Действующий каталог уровня установки: активный пакет поставщика с изменениями установки, без
/// политик организаций; «осиротевшие» изменения — с признаком `orphaned`. Только администратор установки.
#[utoipa::path(get, path = "/api/v1/risk/signals", tag = "risk",
    responses((status = 200, body = SignalsView), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 503, body = Problem)))]
async fn list_installation_signals(
    State(a): State<Arc<Admin>>,
) -> std::result::Result<Json<SignalsView>, Refused> {
    Ok(Json(signals_view(&a, RiskLevel::Installation).await?))
}

/// Изменение признака поставщика (`tp.*`: вес, действие, режим) или свой признак (`org.*`, целиком) —
/// создание тем же `PUT`. Установка меняет значения как угодно; вес выше предела — 422.
#[utoipa::path(put, path = "/api/v1/risk/signals/{id}", tag = "risk",
    params(("id" = String, Path, description = "Признак: `tp.*` — поставщика, `org.*` — свой")),
    request_body = SignalBody,
    responses((status = 200, body = SignalView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem),
        (status = 422, description = "вес выше предела", body = RiskProblem),
        (status = 503, body = Problem)))]
async fn put_installation_signal(
    State(a): State<Arc<Admin>>,
    Path(id): Path<String>,
    Json(body): Json<SignalBody>,
) -> std::result::Result<Response, RefusedResponse> {
    let id = signal_id(&id).map_err(|d| problem(StatusCode::BAD_REQUEST, &d))?;
    put_signal(&a, RiskLevel::Installation, id, body).await
}

/// Сброс изменения уровня установки (у пакета — значение пакета) или удаление своего признака
/// `org.*`. Изменения на уровне нет — 404.
#[utoipa::path(delete, path = "/api/v1/risk/signals/{id}", tag = "risk",
    params(("id" = String, Path, description = "Признак: `tp.*` — поставщика, `org.*` — свой")),
    responses((status = 200, body = SignalView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn reset_installation_signal(
    State(a): State<Arc<Admin>>,
    Path(id): Path<String>,
) -> std::result::Result<Response, RefusedResponse> {
    let id = signal_id(&id).map_err(|d| problem(StatusCode::BAD_REQUEST, &d))?;
    reset_signal(&a, RiskLevel::Installation, id).await
}

/// Действующий каталог организации: пакет поставщика, изменения установки и организации; по признаку
/// `source` — уровень, давший отличие. Администраторы и оператор (чтение).
#[utoipa::path(get, path = "/api/v1/orgs/{org}/risk/signals", tag = "risk",
    params(("org" = String, Path, description = "Организация (UUID)")),
    responses((status = 200, body = SignalsView), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn list_org_signals(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
) -> std::result::Result<Json<SignalsView>, Refused> {
    Ok(Json(signals_view(&a, RiskLevel::Org(org)).await?))
}

/// Изменение признака поставщика или свой признак уровня организации — только в сторону строгости:
/// вес не ниже, действие не мягче, «применять» вместо «только отчёт». Мягче — 422 problem+json с
/// `errors: [{signal, field, value, base}]` и пояснением по-русски.
#[utoipa::path(put, path = "/api/v1/orgs/{org}/risk/signals/{id}", tag = "risk",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("id" = String, Path, description = "Признак: `tp.*` — поставщика, `org.*` — свой")),
    request_body = SignalBody,
    responses((status = 200, body = SignalView), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 422, description = "организация мягче установки", body = RiskProblem),
        (status = 503, body = Problem)))]
async fn put_org_signal(
    State(a): State<Arc<Admin>>,
    Path((org, id)): Path<(TenantId, String)>,
    Json(body): Json<SignalBody>,
) -> std::result::Result<Response, RefusedResponse> {
    let id = signal_id(&id).map_err(|d| problem(StatusCode::BAD_REQUEST, &d))?;
    put_signal(&a, RiskLevel::Org(org), id, body).await
}

/// Сброс изменения уровня организации — действуют установка и пакет; удаление своего признака
/// `org.*`. Изменения на уровне нет — 404.
#[utoipa::path(delete, path = "/api/v1/orgs/{org}/risk/signals/{id}", tag = "risk",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("id" = String, Path, description = "Признак: `tp.*` — поставщика, `org.*` — свой")),
    responses((status = 200, body = SignalView), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 503, body = Problem)))]
async fn reset_org_signal(
    State(a): State<Arc<Admin>>,
    Path((org, id)): Path<(TenantId, String)>,
) -> std::result::Result<Response, RefusedResponse> {
    let id = signal_id(&id).map_err(|d| problem(StatusCode::BAD_REQUEST, &d))?;
    reset_signal(&a, RiskLevel::Org(org), id).await
}

// ---------- Маршруты: пороги ----------

/// Пороги действий установки: свои, действующие и уровень-источник. Только администратор установки.
#[utoipa::path(get, path = "/api/v1/risk/thresholds", tag = "risk",
    responses((status = 200, body = ThresholdsView), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 503, body = Problem)))]
async fn get_installation_thresholds(
    State(a): State<Arc<Admin>>,
) -> std::result::Result<Json<ThresholdsView>, Refused> {
    Ok(Json(thresholds_view(&a, RiskLevel::Installation)?))
}

/// Замена порогов установки целиком: баллы, с которых действуют действия (пометка, «Спам», карантин,
/// отказ). Порядок нарушен — 422.
#[utoipa::path(put, path = "/api/v1/risk/thresholds", tag = "risk",
    request_body = ThresholdsBody,
    responses((status = 200, body = ThresholdsView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem),
        (status = 422, description = "пороги не растут с действием", body = Problem),
        (status = 503, body = Problem)))]
async fn put_installation_thresholds(
    State(a): State<Arc<Admin>>,
    Json(body): Json<ThresholdsBody>,
) -> std::result::Result<Json<ThresholdsView>, RefusedResponse> {
    Ok(Json(
        put_thresholds(&a, RiskLevel::Installation, body).await?,
    ))
}

/// Пороги организации: свои (`null` — не заданы), действующие и уровень-источник.
#[utoipa::path(get, path = "/api/v1/orgs/{org}/risk/thresholds", tag = "risk",
    params(("org" = String, Path, description = "Организация (UUID)")),
    responses((status = 200, body = ThresholdsView), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn get_org_thresholds(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
) -> std::result::Result<Json<ThresholdsView>, Refused> {
    Ok(Json(thresholds_view(&a, RiskLevel::Org(org))?))
}

/// Замена порогов организации целиком — только не мягче установки: порог выше базового (действие
/// позже) — 422 с пояснением.
#[utoipa::path(put, path = "/api/v1/orgs/{org}/risk/thresholds", tag = "risk",
    params(("org" = String, Path, description = "Организация (UUID)")),
    request_body = ThresholdsBody,
    responses((status = 200, body = ThresholdsView), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 422, description = "порог выше базового или порядок нарушен", body = Problem),
        (status = 503, body = Problem)))]
async fn put_org_thresholds(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
    Json(body): Json<ThresholdsBody>,
) -> std::result::Result<Json<ThresholdsView>, RefusedResponse> {
    Ok(Json(put_thresholds(&a, RiskLevel::Org(org), body).await?))
}

// ---------- Маршруты: пакеты ----------

/// Хранимые пакеты поставщика: действующий и N прошлых (`risk.package.keep`), по убыванию номера.
/// Только администратор установки.
#[utoipa::path(get, path = "/api/v1/risk/packages", tag = "risk",
    responses((status = 200, body = PackagesView), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 503, body = Problem)))]
async fn list_packages(
    State(a): State<Arc<Admin>>,
) -> std::result::Result<Json<PackagesView>, Refused> {
    let packages = risk(&a)?.store.packages().await?;
    Ok(Json(PackagesView {
        packages: packages.into_iter().map(Into::into).collect(),
    }))
}

/// Загрузка файла пакета поставщика (закрытый контур, офлайн-импорт): проверка узла — подпись Ed25519
/// доверенным ключом, lint и пробный прогон на образцах (APP-78). Проверен — пакет поставлен (202) и
/// не активен; отчёт (что изменится — новые признаки в «только отчёт») виден до активации. Чужая
/// подпись, непрошедший lint или не растущий номер — 422 с причиной; тип не тот — 415; больше
/// `admin.risk.max_package_bytes` — 413.
#[utoipa::path(post, path = "/api/v1/risk/packages", tag = "risk",
    request_body(content = String, content_type = "application/octet-stream",
        description = "Файл пакета поставщика (подпись Ed25519, до admin.risk.max_package_bytes)"),
    responses((status = 202, description = "пакет проверен и поставлен, не активен", body = PackageReportView),
        (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem),
        (status = 413, description = "больше admin.risk.max_package_bytes", body = Problem),
        (status = 415, description = "не application/octet-stream", body = Problem),
        (status = 422, description = "чужая подпись, lint или номер не растёт", body = Problem),
        (status = 503, body = Problem)))]
async fn upload_package(
    State(a): State<Arc<Admin>>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Response, RefusedResponse> {
    let stores = risk(&a).map_err(api)?;
    file_body(&a, &headers, &body)?;
    // Проверка узла: подпись, lint, пробный прогон (APP-78); неудача — 422 с причиной.
    let verified = stores.node.verify_package(&body).await.map_err(|e| {
        matches!(e, Error::Invalid(_))
            .then(|| refused_422(e.to_string()))
            .unwrap_or_else(|| api(e))
    })?;
    let mut manifest = verified.manifest;
    // Что изменится: новые признаки — «только отчёт», изменения администратора сохраняются (решение 126 в).
    let old = base_catalog(&*stores.store).await.map_err(api)?;
    let update = Catalog::apply_update(&old, &mut manifest.signals);
    let signals = u64::try_from(manifest.signals.len()).unwrap_or(u64::MAX);
    stores.store.put_package(&manifest).await.map_err(|e| {
        matches!(e, Error::Invalid(_))
            .then(|| refused_422(e.to_string()))
            .unwrap_or_else(|| api(e))
    })?;
    let view = PackageReportView {
        version: manifest.version,
        key_id: manifest.key_id,
        samples: verified.samples,
        signals,
        update,
    };
    Ok((StatusCode::ACCEPTED, Json(view)).into_response())
}

/// Активация поставленного пакета: номер строго больше действующего (не растёт — 422), нет пакета —
/// 404. Прошлые сверх `risk.package.keep` удаляются.
#[utoipa::path(post, path = "/api/v1/risk/packages/{version}/activate", tag = "risk",
    params(("version" = u64, Path, description = "Номер версии поставленного пакета")),
    responses((status = 200, body = PackagesView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 404, body = Problem),
        (status = 422, description = "номер не растёт", body = Problem), (status = 503, body = Problem)))]
async fn activate_package(
    State(a): State<Arc<Admin>>,
    Path(version): Path<u64>,
) -> std::result::Result<Json<PackagesView>, RefusedResponse> {
    let store = risk(&a).map_err(api)?.store.clone();
    store.activate(version).await.map_err(invalid_422)?;
    packages_view(&a).await
}

/// Откат на хранимую версию (действующий и N прошлых): нет — 404. Номер новой поставки всё равно
/// только растёт.
#[utoipa::path(post, path = "/api/v1/risk/packages/{version}/rollback", tag = "risk",
    params(("version" = u64, Path, description = "Номер версии отката (хранимой)")),
    responses((status = 200, body = PackagesView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn rollback_package(
    State(a): State<Arc<Admin>>,
    Path(version): Path<u64>,
) -> std::result::Result<Json<PackagesView>, RefusedResponse> {
    let store = risk(&a).map_err(api)?.store.clone();
    store.rollback(version).await.map_err(invalid_422)?;
    packages_view(&a).await
}

// ---------- Маршруты: источники TI ----------

/// Источники TI установки по идентификатору: в поставке (пакетом), «ключ заказчика» и импорт. Только
/// администратор установки.
#[utoipa::path(get, path = "/api/v1/risk/sources", tag = "risk",
    responses((status = 200, body = SourcesView), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 503, body = Problem)))]
async fn list_ti_sources(
    State(a): State<Arc<Admin>>,
) -> std::result::Result<Json<SourcesView>, Refused> {
    let sources = risk(&a)?.store.sources().await?;
    Ok(Json(SourcesView {
        sources: sources.iter().map(TiSourceView::from).collect(),
    }))
}

/// Новый источник TI: коннектор «ключ заказчика» (фид своим ключом) или импорт (txt, CSV, RPZ, MISP,
/// TAXII/STIX). Ключ — только ссылка на хранилище секретов (`{"secret": "путь#поле"}`); значение
/// ключа в теле — 400. Уровень «в поставке» создаёт только пакет поставщика — 400. Недопустимый
/// источник (TTL, запрещённые фиды) — 400.
#[utoipa::path(post, path = "/api/v1/risk/sources", tag = "risk",
    request_body = NewTiSourceBody,
    responses((status = 200, body = TiSourceView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 503, body = Problem)))]
async fn create_source(
    State(a): State<Arc<Admin>>,
    Json(body): Json<NewTiSourceBody>,
) -> std::result::Result<Json<TiSourceView>, RefusedResponse> {
    bundled_refused(body.tier)?;
    let source = body.source().map_err(api)?;
    source.validate().map_err(api)?;
    let stores = risk(&a).map_err(api)?;
    stores.store.put_source(&source).await.map_err(api)?;
    Ok(Json(TiSourceView::from(&source)))
}

/// Источник TI; нет — 404.
#[utoipa::path(get, path = "/api/v1/risk/sources/{id}", tag = "risk",
    params(("id" = String, Path, description = "Источник TI")),
    responses((status = 200, body = TiSourceView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn get_source(
    State(a): State<Arc<Admin>>,
    Path(id): Path<String>,
) -> std::result::Result<Json<TiSourceView>, RefusedResponse> {
    let id = source_id(&id).map_err(|d| problem(StatusCode::BAD_REQUEST, &d))?;
    Ok(Json(TiSourceView::from(
        &source_of(&a, &id).await.map_err(api)?,
    )))
}

/// Замена источника целиком (без идентификатора — он в пути). Источник «в поставке» меняет только
/// пакет поставщика — 400; ключ — только ссылка на хранилище секретов (значение — 400).
#[utoipa::path(put, path = "/api/v1/risk/sources/{id}", tag = "risk",
    params(("id" = String, Path, description = "Источник TI")),
    request_body = TiSourceBody,
    responses((status = 200, body = TiSourceView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn put_source(
    State(a): State<Arc<Admin>>,
    Path(id): Path<String>,
    Json(body): Json<TiSourceBody>,
) -> std::result::Result<Json<TiSourceView>, RefusedResponse> {
    let id = source_id(&id).map_err(|d| problem(StatusCode::BAD_REQUEST, &d))?;
    let old = source_of(&a, &id).await.map_err(api)?;
    if old.tier == Tier::Bundled {
        return Err(bundled_refused_text("меняет"));
    }
    let source = TiSource {
        id: old.id,
        tier: body.tier,
        kind: body.kind,
        format: body.format,
        ttl: body.ttl,
        stale: body.stale,
        license: body.license,
        tenants: body.tenants,
        key: body.key,
        auth: body.auth,
        origin: body.origin,
    };
    bundled_refused(source.tier)?;
    source.validate().map_err(api)?;
    let stores = risk(&a).map_err(api)?;
    stores.store.put_source(&source).await.map_err(api)?;
    Ok(Json(TiSourceView::from(&source)))
}

/// Удаление источника TI; нет — 404. Источник «в поставке» ведёт пакет поставщика — 400. Версии
/// списков и учёт остаются.
#[utoipa::path(delete, path = "/api/v1/risk/sources/{id}", tag = "risk",
    params(("id" = String, Path, description = "Источник TI")),
    responses((status = 200, description = "удалённый источник", body = TiSourceView), (status = 400, body = Problem),
        (status = 401, body = Problem), (status = 403, description = "не администратор установки", body = Problem),
        (status = 404, body = Problem), (status = 503, body = Problem)))]
async fn delete_source(
    State(a): State<Arc<Admin>>,
    Path(id): Path<String>,
) -> std::result::Result<Json<TiSourceView>, RefusedResponse> {
    let id = source_id(&id).map_err(|d| problem(StatusCode::BAD_REQUEST, &d))?;
    let old = source_of(&a, &id).await.map_err(api)?;
    if old.tier == Tier::Bundled {
        return Err(bundled_refused_text("ведёт"));
    }
    let stores = risk(&a).map_err(api)?;
    stores.store.delete_source(&id).await.map_err(api)?;
    Ok(Json(TiSourceView::from(&old)))
}

/// Источник уровня «в поставке» — только пакет поставщика (400).
fn bundled_refused(tier: Tier) -> std::result::Result<(), RefusedResponse> {
    match tier {
        Tier::Bundled => Err(bundled_refused_text("создаёт")),
        _ => Ok(()),
    }
}

/// Текст отказа для уровня «в поставке».
fn bundled_refused_text(verb: &str) -> RefusedResponse {
    problem(
        StatusCode::BAD_REQUEST,
        &format!("источник уровня «в поставке» {verb} только пакет поставщика"),
    )
}

/// Импорт файла списка источника (закрытый контур): разбор формата делает узел (APP-78), версия
/// становится текущей. Источника нет — 404; тип не тот — 415; больше `admin.risk.max_package_bytes` — 413.
#[utoipa::path(post, path = "/api/v1/risk/sources/{id}/import", tag = "risk",
    params(("id" = String, Path, description = "Источник TI")),
    request_body(content = String, content_type = "application/octet-stream",
        description = "Файл списка TI (формат источника, до admin.risk.max_package_bytes)"),
    responses((status = 200, body = ListVersionView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 404, body = Problem),
        (status = 413, description = "больше admin.risk.max_package_bytes", body = Problem),
        (status = 415, description = "не application/octet-stream", body = Problem),
        (status = 503, body = Problem)))]
async fn import_source(
    State(a): State<Arc<Admin>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> std::result::Result<Json<ListVersionView>, RefusedResponse> {
    let id = source_id(&id).map_err(|d| problem(StatusCode::BAD_REQUEST, &d))?;
    let source = source_of(&a, &id).await.map_err(api)?;
    file_body(&a, &headers, &body)?;
    let stores = risk(&a).map_err(api)?;
    let version = stores.node.import_list(&source, &body).await.map_err(api)?;
    stores.store.put_list_version(&version).await.map_err(api)?;
    Ok(Json(version.into()))
}

/// Обновление источника сейчас (коннектор узла, APP-79): выгрузка фида, версия списка становится
/// текущей. Источника нет — 404; ошибка выгрузки — как есть.
#[utoipa::path(post, path = "/api/v1/risk/sources/{id}/refresh", tag = "risk",
    params(("id" = String, Path, description = "Источник TI")),
    responses((status = 200, body = ListVersionView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn refresh_source(
    State(a): State<Arc<Admin>>,
    Path(id): Path<String>,
) -> std::result::Result<Json<ListVersionView>, RefusedResponse> {
    let id = source_id(&id).map_err(|d| problem(StatusCode::BAD_REQUEST, &d))?;
    let source = source_of(&a, &id).await.map_err(api)?;
    let stores = risk(&a).map_err(api)?;
    let version = stores.node.refresh_source(&source).await.map_err(api)?;
    stores.store.put_list_version(&version).await.map_err(api)?;
    Ok(Json(version.into()))
}

/// Учёт источника по организациям (MSSP): суммы обращений и совпадений с `since` (сутки периода
/// складываются). Источника нет — 404.
#[utoipa::path(get, path = "/api/v1/risk/sources/{id}/usage", tag = "risk",
    params(("id" = String, Path, description = "Источник TI"), UsageParams),
    responses((status = 200, body = UsageView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn source_usage(
    State(a): State<Arc<Admin>>,
    Path(id): Path<String>,
    Query(q): Query<UsageParams>,
) -> std::result::Result<Json<UsageView>, Refused> {
    let id = source_id(&id).map_err(|d| Refused::Problem(StatusCode::BAD_REQUEST, d))?;
    source_of(&a, &id).await?;
    let stores = risk(&a)?;
    let since = q.since.unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let entries: Vec<UsageEntry> = stores.store.usage(&id, since).await?;
    // Суммы по организациям: сутки периода складываются.
    let mut totals: BTreeMap<TenantId, (u64, u64)> = BTreeMap::new();
    for e in entries {
        let total = totals.entry(e.tenant).or_insert((0, 0));
        total.0 += e.lookups;
        total.1 += e.hits;
    }
    Ok(Json(UsageView {
        source: id.to_string(),
        since,
        usage: totals
            .into_iter()
            .map(|(tenant, (lookups, hits))| UsageTotalView {
                tenant: tenant.to_string(),
                lookups,
                hits,
            })
            .collect(),
    }))
}

// ---------- Маршруты: срабатывания ----------

/// Журнал срабатываний организации (свежие первыми, постранично): применённые и «только отчёт»
/// (решение 126 а). Условия — по «и»: признак, режим, интервал. Продолжение — `next` следующего
/// запроса (как `until`); срабатывания одного момента (письмо — несколько признаков) не разрезаются
/// страницей. Администраторы и оператор (только `GET`).
#[utoipa::path(get, path = "/api/v1/orgs/{org}/risk/hits", tag = "risk",
    params(("org" = String, Path, description = "Организация (UUID)"), HitsParams),
    responses((status = 200, body = HitsView), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 503, body = Problem)))]
async fn list_risk_hits(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
    Query(q): Query<HitsParams>,
) -> std::result::Result<Json<HitsView>, Refused> {
    let stores = risk(&a)?;
    let signal = match q.signal.as_deref() {
        None | Some("") => None,
        Some(raw) => Some(SignalId::new(raw).map_err(|_| {
            Refused::Problem(
                StatusCode::BAD_REQUEST,
                format!("signal {raw:?}: идентификатор — [a-z0-9._-], до 64 символов"),
            )
        })?),
    };
    let mode = match q.mode.as_deref() {
        None | Some("") => None,
        Some("report") => Some(Mode::Report),
        Some("enforce") => Some(Mode::Enforce),
        Some(other) => {
            return Err(Refused::Problem(
                StatusCode::BAD_REQUEST,
                format!("mode {other:?}: report или enforce"),
            ));
        }
    };
    // Страница берётся с запасом: режим фильтруется после хранилища, а срабатывания одного момента
    // не разрезаются страницей.
    let page_size = a.cfg.page(q.limit);
    let fetch = a.cfg.max_page_size.max(page_size);
    let query = tp_contracts::risk::HitsQuery {
        signal,
        message: None,
        since: q.since,
        until: q.until,
        limit: fetch,
    };
    query.validate()?;
    let fetched = stores.store.hits(org, &query).await?;
    let may_have_more = fetched.len() == fetch;
    let oldest = fetched.last().map(|r| r.at);
    let matching: Vec<HitRecord> = fetched
        .into_iter()
        .filter(|r| mode.is_none_or(|m| r.mode == m))
        .collect();
    let mut page: Vec<HitRecord> = matching.iter().take(page_size).cloned().collect();
    // Границу страницы двигаем до конца срабатываний того же момента.
    if let Some(last) = page.last() {
        let boundary = last.at;
        for r in matching.iter().skip(page.len()) {
            if r.at != boundary {
                break;
            }
            page.push(r.clone());
        }
    }
    let next = if page.len() < matching.len() || may_have_more {
        page.last().map(|r| r.at).or(oldest).and_then(|at| {
            at.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
    } else {
        None
    };
    Ok(Json(HitsView {
        hits: page.into_iter().map(Into::into).collect(),
        next,
    }))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use tp_contracts::risk::{Detector, Hit, HitSource, PackageState, Semver};

    use super::*;
    use crate::testenv::{Env, config};

    fn manifest(version: u64, weight: u16, key_id: &str) -> PackageManifest {
        PackageManifest {
            format: tp_contracts::risk::PACKAGE_FORMAT,
            version,
            created: OffsetDateTime::UNIX_EPOCH,
            min_node: Semver::new(0, 1, 0),
            key_id: key_id.to_owned(),
            signals: vec![Signal {
                id: SignalId::new("tp.encrypted_archive").expect("id"),
                detector: Detector::EncryptedArchive,
                weight,
                threshold: 0,
                action: RiskAction::None,
                mode: Mode::Enforce,
                origin: Origin::Vendor,
                since: OffsetDateTime::UNIX_EPOCH,
            }],
            lists: Vec::new(),
            samples: Vec::new(),
        }
    }

    /// Пакет версии 1 активен: признак `tp.encrypted_archive` весом 6.
    async fn seeded() -> Env {
        let env = Env::new();
        env.risk
            .put_package(&manifest(1, 6, "vendor"))
            .await
            .expect("package");
        env.risk.activate(1).await.expect("activate");
        env
    }

    fn org_path(rest: &str) -> String {
        format!("/api/v1/orgs/{}/risk/{rest}", TenantId::DEFAULT)
    }

    /// Загрузка файла (пакет, список) с типом содержимого.
    async fn upload(
        env: &Env,
        path: &str,
        token: &str,
        content_type: &str,
        bytes: &[u8],
    ) -> (StatusCode, Value) {
        let req = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, content_type)
            .body(Body::from(bytes.to_vec()))
            .expect("request");
        let resp = env.router.clone().oneshot(req).await.expect("response");
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let v = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into_owned()))
        };
        (status, v)
    }

    /// Приёмка ADM-51: `PUT` признака установки — 200 и запись аудита; свой признак `org.*` создаётся
    /// тем же `PUT`; каталог показывает источник значения и «осиротевшие» изменения.
    #[tokio::test]
    async fn installation_signal_put_and_audit() {
        let env = seeded().await;
        let path = "/api/v1/risk/signals/tp.encrypted_archive";

        // Каталог уровня установки: признак пакета без изменений.
        let (s, _, b) = env
            .call("GET", RISK_SIGNALS_ROUTE, Some("root"), None)
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let list = b["signals"].as_array().expect("signals");
        assert_eq!(list.len(), 1, "{b}");
        assert_eq!(list[0]["id"], json!("tp.encrypted_archive"));
        assert_eq!(list[0]["weight"], json!(6));
        assert_eq!(list[0]["source"], Value::Null);
        assert_eq!(list[0]["orphaned"], json!(false));

        // Изменение веса — 200, аудит; каталог показывает источник «установка».
        let (s, _, b) = env
            .call("PUT", path, Some("root"), Some(json!({"weight": 3})))
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["weight"], json!(3));
        assert_eq!(b["source"], json!("installation"));
        let log: Vec<_> = env
            .audit
            .records()
            .into_iter()
            .filter(|r| r.method == "PUT" && r.path == path)
            .collect();
        assert_eq!(log.len(), 1, "изменение — в журнале аудита");
        assert_eq!(log[0].status, 200);
        assert_eq!(log[0].route, RISK_SIGNAL_ROUTE);
        assert_eq!(log[0].tenant, None, "уровень установки");

        // Свой признак `org.*` — тем же `PUT` (уровень установки: для всех организаций).
        let own = "/api/v1/risk/signals/org.ext-file";
        let body = json!({"detector": "disk_image_or_shortcut", "weight": 2, "threshold": 40,
                          "action": "tag", "mode": "enforce"});
        let (s, _, b) = env.call("PUT", own, Some("root"), Some(body)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["id"], json!("org.ext-file"));
        assert_eq!(b["source"], json!("installation"));
        // Неполный свой признак и детектор у признака поставщика — 400; чужой префикс — 400.
        let (s, _, _) = env
            .call("PUT", own, Some("root"), Some(json!({"weight": 1})))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _, _) = env
            .call(
                "PUT",
                path,
                Some("root"),
                Some(json!({"detector": "encrypted_archive"})),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _, _) = env
            .call(
                "PUT",
                "/api/v1/risk/signals/plain",
                Some("root"),
                Some(json!({"weight": 1})),
            )
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        // Вес выше предела — 422.
        let (s, _, _) = env
            .call("PUT", path, Some("root"), Some(json!({"weight": 101})))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

        // «Осиротевшее» изменение: признака нет в пакете — показывается, не удаляется молча.
        let gone = "/api/v1/risk/signals/tp.removed-by-vendor";
        let (s, _, b) = env
            .call("PUT", gone, Some("root"), Some(json!({"weight": 5})))
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["orphaned"], json!(true));
        assert_eq!(b["detector"], Value::Null);
        assert_eq!(b["source"], json!("installation"));
        let (_, _, b) = env
            .call("GET", RISK_SIGNALS_ROUTE, Some("root"), None)
            .await;
        assert_eq!(b["signals"].as_array().expect("list").len(), 3, "{b}");

        // Сброс: у пакета — значение пакета; изменения уровня нет — 404.
        let (s, _, b) = env.call("DELETE", path, Some("root"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["weight"], json!(6), "значение пакета");
        assert_eq!(b["source"], Value::Null);
        let (s, _, _) = env.call("DELETE", path, Some("root"), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "сброшено — нечего сбрасывать");
        // Свой признак удаляется сбросом.
        let (s, _, _) = env.call("DELETE", own, Some("root"), None).await;
        assert_eq!(s, StatusCode::OK);
        // Осиротевшее изменение сбрасывается.
        let (s, _, b) = env.call("DELETE", gone, Some("root"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["orphaned"], json!(true), "показано удалённым");
    }

    /// Приёмка ADM-51: организация смягчает — 422 problem+json с `errors: [{signal, field, value,
    /// base}]` и пояснением по-русски; ужесточает — 200; права — организация, установка, оператор.
    #[tokio::test]
    async fn org_only_tightens() {
        let env = seeded().await;
        let path = format!("{}/tp.encrypted_archive", org_path("signals"));

        // Снижение веса — 422 с перечнем.
        let (s, h, b) = env
            .call("PUT", &path, Some("org"), Some(json!({"weight": 3})))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert_eq!(h["content-type"], "application/problem+json");
        assert_eq!(b["status"], json!(422));
        assert_eq!(
            b["errors"],
            json!([{"signal": "tp.encrypted_archive", "field": "weight", "value": "3",
                    "base": "6"}])
        );
        assert!(
            b["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("ужесточить"),
            "{}",
            b["detail"]
        );
        // Действие мягче и «только отчёт» — тоже 422 (установка поставила Quarantine).
        env.call(
            "PUT",
            "/api/v1/risk/signals/tp.encrypted_archive",
            Some("root"),
            Some(json!({"action": "quarantine"})),
        )
        .await;
        let (s, _, b) = env
            .call("PUT", &path, Some("org"), Some(json!({"action": "junk"})))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert_eq!(b["errors"][0]["field"], json!("action"));
        let (s, _, b) = env
            .call("PUT", &path, Some("org"), Some(json!({"mode": "report"})))
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert_eq!(b["errors"][0]["field"], json!("mode"));

        // Ужесточение — 200, источник значения — организация.
        let (s, _, b) = env
            .call("PUT", &path, Some("org"), Some(json!({"weight": 9})))
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["source"], json!({"org": TenantId::DEFAULT.to_string()}));
        // Каталог организации видит признак установки (Quarantine) поверх пакета.
        let (_, _, b) = env
            .call("GET", &org_path("signals"), Some("org"), None)
            .await;
        let signals = b["signals"].as_array().expect("signals");
        assert_eq!(signals.len(), 1, "{b}");
        assert_eq!(signals[0]["weight"], json!(9));
        assert_eq!(signals[0]["action"], json!("quarantine"));
        // Свой признак организации.
        let own = format!("{}/org.own-rule", org_path("signals"));
        let body = json!({"detector": "reply_to_changed", "weight": 4, "threshold": 0,
                          "action": "none", "mode": "report"});
        let (s, _, b) = env.call("PUT", &own, Some("org"), Some(body)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["origin"], json!("admin"));

        // Сброс изменения организации; своего изменения нет — 404.
        let (s, _, b) = env.call("DELETE", &path, Some("org"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["weight"], json!(6));
        let (s, _, _) = env.call("DELETE", &path, Some("org"), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        // Права: организация не читает уровень установки; оператор читает каталог и не меняет.
        let (s, _, _) = env.call("GET", RISK_SIGNALS_ROUTE, Some("org"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, _) = env
            .call("GET", RISK_SIGNALS_ROUTE, Some("operator"), None)
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, _) = env
            .call("GET", &org_path("signals"), Some("operator"), None)
            .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = env
            .call("PUT", &path, Some("operator"), Some(json!({"weight": 9})))
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }

    /// Приёмка ADM-51: загрузка пакета — 202 с отчётом; чужая подпись и не растущий номер — 422 с
    /// причиной; активация и откат — 200, неизвестная версия отката — 404; тип не тот — 415, больше
    /// предела — 413; организации и оператору — 403.
    #[tokio::test]
    async fn packages_upload_activate_rollback() {
        let env = seeded().await;
        let second = manifest(2, 8, "vendor");
        let bytes = serde_json::to_vec(&second).expect("json");

        // Загрузка — 202 и отчёт: пакет поставлен, но не активен.
        let (s, _, b) = upload(&env, RISK_PACKAGES_ROUTE, "root", OCTET_STREAM, &bytes).await;
        assert_eq!(s, StatusCode::ACCEPTED, "{b}");
        assert_eq!(b["version"], json!(2));
        assert_eq!(b["key_id"], json!("vendor"));
        assert_eq!(b["signals"], json!(1));
        assert_eq!(
            b["update"]["changed"],
            json!(["tp.encrypted_archive"]),
            "{b}"
        );
        let (s, _, b) = env
            .call("GET", RISK_PACKAGES_ROUTE, Some("root"), None)
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(
            b["packages"],
            json!([{"version": 2, "state": "previous"}, {"version": 1, "state": "active"}]),
            "новый пакет не активен"
        );

        // Активация — 200; откат на 1 — 200; откат на неизвестную версию — 404.
        let (s, _, b) = env
            .call(
                "POST",
                "/api/v1/risk/packages/2/activate",
                Some("root"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["packages"][0], json!({"version": 2, "state": "active"}));
        let (_, _, b) = env
            .call("GET", RISK_SIGNALS_ROUTE, Some("root"), None)
            .await;
        assert_eq!(
            b["signals"][0]["weight"],
            json!(8),
            "каталог — нового пакета"
        );
        let (s, _, _) = env
            .call(
                "POST",
                "/api/v1/risk/packages/1/rollback",
                Some("root"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, b) = env
            .call(
                "POST",
                "/api/v1/risk/packages/99/rollback",
                Some("root"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{b}");
        // Активация не растущего номера — 422.
        let (s, _, b) = env
            .call(
                "POST",
                "/api/v1/risk/packages/1/activate",
                Some("root"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");

        // Чужая подпись — 422 с причиной; тот же номер повторно — 422 (не растёт).
        let stranger = manifest(3, 8, "stranger");
        let (s, _, b) = upload(
            &env,
            RISK_PACKAGES_ROUTE,
            "root",
            OCTET_STREAM,
            &serde_json::to_vec(&stranger).expect("json"),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert!(
            b["detail"].as_str().unwrap_or_default().contains("подпись"),
            "{}",
            b["detail"]
        );
        let (s, _, b) = upload(&env, RISK_PACKAGES_ROUTE, "root", OCTET_STREAM, &bytes).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert!(
            b["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("не растёт"),
            "{}",
            b["detail"]
        );

        // Тип не тот — 415; больше предела — 413.
        let (s, _, _) = upload(
            &env,
            RISK_PACKAGES_ROUTE,
            "root",
            "application/json",
            &bytes,
        )
        .await;
        assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let cfg = crate::server::AdminConfig {
            risk: RiskApiConfig {
                max_package_bytes: 1024,
            },
            ..config()
        };
        let small = Env::with(cfg, Vec::new());
        let big = vec![b'x'; 2048];
        let (s, _, _) = upload(&small, RISK_PACKAGES_ROUTE, "root", OCTET_STREAM, &big).await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);

        // Права: организация и оператор пакетов не касаются.
        for token in ["org", "operator"] {
            let (s, _, _) = env
                .call("GET", RISK_PACKAGES_ROUTE, Some(token), None)
                .await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{token}");
            let (s, _, _) = upload(&env, RISK_PACKAGES_ROUTE, token, OCTET_STREAM, &bytes).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{token}");
        }
        // Установка и активация — в журнале аудита.
        let log: Vec<_> = env
            .audit
            .records()
            .into_iter()
            .filter(|r| r.route.contains("packages"))
            .collect();
        assert!(log.len() >= 3, "загрузка, активация, откат: {log:?}");
        assert!(
            log.iter()
                .all(|r| (200..300).contains(&r.status) || r.status == 422)
        );
    }

    /// Источник TI для тела запроса.
    fn source_body(id: &str) -> Value {
        json!({
            "id": id, "tier": "customer_key",
            "kind": {"http": {"url": "https://feodo.tracker.abuse.ch/downloads/ipblocklist/"}},
            "format": "txt", "ttl": "1h",
            "stale": {"reduce": {"percent": 50}},
            "license": {"terms_url": "https://abuse.ch/terms/", "commercial": true},
            "tenants": "all", "key": {"secret": "thepost/db#api_key"},
            "auth": {"header": {"name": "Auth-Key"}}, "origin": "vendor"
        })
    }

    /// Приёмка ADM-51: источники TI — CRUD; ключ-значение в теле — 400; `Bundled` в `POST` — 400;
    /// импорт файла — версия списка; обновление; учёт — суммы по организациям.
    #[tokio::test]
    async fn sources_crud_import_usage() {
        let env = Env::new();
        let (s, _, b) = env
            .call(
                "POST",
                RISK_SOURCES_ROUTE,
                Some("root"),
                Some(source_body("feodo")),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["id"], json!("feodo"));
        assert_eq!(b["key"], json!({"secret": "thepost/db#api_key"}), "{b}");

        // Ключ-значение (не ссылка) — 400; Bundled — 400; нет источника — 404.
        let mut plaintext = source_body("leak");
        plaintext["key"] = json!("secret-value");
        let (s, _, _) = env
            .call("POST", RISK_SOURCES_ROUTE, Some("root"), Some(plaintext))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let mut bundled = source_body("openphish");
        bundled["tier"] = json!("bundled");
        let (s, _, b) = env
            .call("POST", RISK_SOURCES_ROUTE, Some("root"), Some(bundled))
            .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        let (s, _, _) = env
            .call("GET", "/api/v1/risk/sources/unknown", Some("root"), None)
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        // Замена целиком; список; учёт по организациям.
        let (s, _, b) = env
            .call(
                "PUT",
                "/api/v1/risk/sources/feodo",
                Some("root"),
                Some(json!({
                    "tier": "import", "kind": "file", "format": "txt", "ttl": "30m",
                    "stale": "report",
                    "license": {"terms_url": "https://example.org/", "commercial": true},
                    "tenants": {"only": [TenantId::DEFAULT.to_string()]},
                    "key": null, "auth": "none", "origin": "own"
                })),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["ttl"], json!("30m"));
        let (s, _, b) = env
            .call("GET", RISK_SOURCES_ROUTE, Some("root"), None)
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["sources"].as_array().expect("sources").len(), 1);
        let feodo = SourceId::new("feodo").expect("id");
        env.risk
            .record_usage(&feodo, TenantId::DEFAULT, 10, 2)
            .await
            .expect("usage");
        env.risk
            .record_usage(&feodo, env.other_tenant, 5, 1)
            .await
            .expect("usage");
        let (s, _, b) = env
            .call(
                "GET",
                "/api/v1/risk/sources/feodo/usage",
                Some("root"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(
            b["usage"],
            json!([
                {"tenant": TenantId::DEFAULT.to_string(), "lookups": 10, "hits": 2},
                {"tenant": env.other_tenant.to_string(), "lookups": 5, "hits": 1},
            ]),
            "суммы по организациям"
        );

        // Импорт файла списка — версия становится текущей; тип не тот — 415.
        let list: &[u8] = b"1.2.3.4\n5.6.7.8\n\n9.9.9.9\n";
        let (s, _, b) = upload(
            &env,
            "/api/v1/risk/sources/feodo/import",
            "root",
            OCTET_STREAM,
            list,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["entries"], json!(3), "пустые строки не считаются");
        assert_eq!(b["list"], json!("feodo"));
        assert_eq!(b["sha256"].as_str().map(str::len), Some(64), "hex");
        let (s, _, _) = upload(
            &env,
            "/api/v1/risk/sources/feodo/import",
            "root",
            "text/plain",
            list,
        )
        .await;
        assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);

        // Обновление сейчас — новая версия (коннектор памяти).
        let (s, _, b) = env
            .call(
                "POST",
                "/api/v1/risk/sources/feodo/refresh",
                Some("root"),
                None,
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["list"], json!("feodo"));

        // Удаление; повтор — 404.
        let (s, _, b) = env
            .call("DELETE", "/api/v1/risk/sources/feodo", Some("root"), None)
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["id"], json!("feodo"));
        let (s, _, _) = env
            .call("DELETE", "/api/v1/risk/sources/feodo", Some("root"), None)
            .await;
        assert_eq!(s, StatusCode::NOT_FOUND);

        // Права: организация и оператор источников не касаются (403).
        for token in ["org", "operator"] {
            let (s, _, _) = env.call("GET", RISK_SOURCES_ROUTE, Some(token), None).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{token}");
        }
    }

    /// Приёмка ADM-51: пороги — умолчания, замена установки, организация не мягче (выше — 422);
    /// срабатывания — журнал организации постранично с фильтрами, оператор — только чтение; без
    /// хранилища — 503.
    #[tokio::test]
    async fn thresholds_and_hits() {
        let env = seeded().await;
        let (s, _, b) = env
            .call("GET", RISK_THRESHOLDS_ROUTE, Some("root"), None)
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["own"], Value::Null);
        assert_eq!(
            b["effective"],
            json!({"tag": 1, "junk": 6, "quarantine": 10, "reject": 15}),
            "константы контракта"
        );
        assert_eq!(b["source"], Value::Null);
        // Порядок нарушен — 422; замена — 200.
        let (s, _, _) = env
            .call(
                "PUT",
                RISK_THRESHOLDS_ROUTE,
                Some("root"),
                Some(json!({"tag": 2, "junk": 1, "quarantine": 10, "reject": 15})),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
        let (s, _, b) = env
            .call(
                "PUT",
                RISK_THRESHOLDS_ROUTE,
                Some("root"),
                Some(json!({"tag": 2, "junk": 7, "quarantine": 11, "reject": 16})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["source"], json!("installation"));
        // Организация: действуют установки; выше базового — 422, не выше — 200.
        let (s, _, b) = env
            .call("GET", &org_path("thresholds"), Some("org"), None)
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["own"], Value::Null);
        assert_eq!(b["source"], json!("installation"));
        let (s, _, b) = env
            .call(
                "PUT",
                &org_path("thresholds"),
                Some("org"),
                Some(json!({"tag": 3, "junk": 8, "quarantine": 11, "reject": 16})),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert!(
            b["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("базового"),
            "{}",
            b["detail"]
        );
        let (s, _, b) = env
            .call(
                "PUT",
                &org_path("thresholds"),
                Some("org"),
                Some(json!({"tag": 1, "junk": 5, "quarantine": 9, "reject": 14})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["source"], json!({"org": TenantId::DEFAULT.to_string()}));
        let (s, _, _) = env
            .call("PUT", RISK_THRESHOLDS_ROUTE, Some("org"), None)
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);

        // Срабатывания: два вердикта (применённый и «только отчёт») — журнал организации.
        let verdict = |report: bool| Verdict {
            score: 6,
            hits: if report {
                Vec::new()
            } else {
                vec![Hit {
                    signal: SignalId::new("tp.encrypted_archive").expect("id"),
                    strength: 100,
                    weight: 6,
                    source: HitSource::Detector,
                }]
            },
            report_only: if report {
                vec![Hit {
                    signal: SignalId::new("tp.report").expect("id"),
                    strength: 80,
                    weight: 4,
                    source: HitSource::Sieve,
                }]
            } else {
                Vec::new()
            },
            action: RiskAction::Junk,
            drops_reply: false,
        };
        env.risk
            .record_hits(TenantId::DEFAULT, BlobHash([1u8; 32]), &verdict(false))
            .await
            .expect("hits");
        env.risk
            .record_hits(TenantId::DEFAULT, BlobHash([2u8; 32]), &verdict(true))
            .await
            .expect("hits");
        let (s, _, b) = env.call("GET", &org_path("hits"), Some("org"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let hits = b["hits"].as_array().expect("hits");
        assert_eq!(hits.len(), 2, "по записи на вердикт: {b}");
        assert_eq!(hits[0]["mode"], json!("report"), "свежие первыми");
        assert_eq!(hits[1]["mode"], json!("enforce"));
        assert_eq!(b["next"], Value::Null, "всё влезло");
        // Фильтры: признак и режим; страница с продолжением.
        let url = format!("{}?signal=tp.report", org_path("hits"));
        let (s, _, b) = env.call("GET", &url, Some("org"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["hits"].as_array().expect("hits").len(), 1);
        // Некорректный режим и признак — 400.
        let url = format!("{}?mode=soft", org_path("hits"));
        let (s, _, _) = env.call("GET", &url, Some("org"), None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let url = format!("{}?signal=NOPE", org_path("hits"));
        let (s, _, _) = env.call("GET", &url, Some("org"), None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        // Без хранилища справочника — 503.
        let bare = Env::without_risk();
        let (s, _, _) = bare
            .call("GET", RISK_SIGNALS_ROUTE, Some("root"), None)
            .await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        let (s, _, _) = bare.call("GET", &org_path("hits"), Some("org"), None).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Схема: маршруты справочника с операциями и 422; тела и ответы — туда и обратно (ADM-13).
    #[test]
    fn openapi_and_roundtrip() {
        let spec = serde_json::to_value(crate::server::openapi_spec()).expect("spec");
        let paths = &spec["paths"];
        for (path, methods) in [
            (RISK_SIGNALS_ROUTE, &["get"][..]),
            (RISK_SIGNAL_ROUTE, &["put", "delete"]),
            (ORG_RISK_SIGNALS_ROUTE, &["get"]),
            (ORG_RISK_SIGNAL_ROUTE, &["put", "delete"]),
            (RISK_THRESHOLDS_ROUTE, &["get", "put"]),
            (ORG_RISK_THRESHOLDS_ROUTE, &["get", "put"]),
            (RISK_PACKAGES_ROUTE, &["get", "post"]),
            (RISK_PACKAGE_ACTIVATE_ROUTE, &["post"]),
            (RISK_PACKAGE_ROLLBACK_ROUTE, &["post"]),
            (RISK_SOURCES_ROUTE, &["get", "post"]),
            (RISK_SOURCE_ROUTE, &["get", "put", "delete"]),
            (RISK_SOURCE_IMPORT_ROUTE, &["post"]),
            (RISK_SOURCE_REFRESH_ROUTE, &["post"]),
            (RISK_SOURCE_USAGE_ROUTE, &["get"]),
            (ORG_RISK_HITS_ROUTE, &["get"]),
        ] {
            for m in methods {
                assert!(paths[path][m].is_object(), "{m} {path}");
            }
        }
        assert!(
            paths[ORG_RISK_SIGNAL_ROUTE]["put"]["responses"]["422"].is_object(),
            "смягчение организации — 422"
        );
        for name in [
            "RiskProblem",
            "SignalView",
            "SignalBody",
            "ThresholdsView",
            "PackageReportView",
            "TiSourceView",
            "HitsView",
        ] {
            assert!(spec["components"]["schemas"][name].is_object(), "{name}");
        }

        fn roundtrip<T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
            v: T,
        ) {
            let json = serde_json::to_value(&v).expect("serialize");
            let back: T = serde_json::from_value(json.clone()).expect("deserialize");
            assert_eq!(back, v, "{json}");
        }
        roundtrip(SignalBody::default());
        roundtrip(SignalBody {
            detector: Some(Detector::EncryptedArchive),
            weight: Some(6),
            threshold: Some(10),
            action: Some(RiskAction::Quarantine),
            mode: Some(Mode::Report),
        });
        roundtrip(ThresholdsBody {
            tag: 1,
            junk: 6,
            quarantine: 10,
            reject: 15,
        });
        roundtrip(RiskProblem {
            status: 422,
            title: "Unprocessable Entity".into(),
            detail: "организация может только ужесточить".into(),
            errors: vec![PolicyViolation {
                signal: SignalId::new("tp.x").expect("id"),
                field: "weight".to_owned(),
                value: "3".to_owned(),
                base: "6".to_owned(),
            }],
        });
        let _ = PackageState::Active;
    }

    /// Память проверки узла: доверенный ключ принимает, чужой — нет; число образцов — из манифеста.
    #[tokio::test]
    async fn mem_node_checks_signature() {
        let node = MemRiskNode::default().with_trusted_key("second");
        let mut m = manifest(9, 1, "vendor");
        m.samples = vec![tp_contracts::risk::SampleFile {
            path: "sample/1.eml".into(),
            sha256: BlobHash([7u8; 32]),
            expect: vec![SignalId::new("tp.encrypted_archive").expect("id")],
        }];
        let verified = node
            .verify_package(&serde_json::to_vec(&m).expect("json"))
            .await
            .expect("verified");
        assert_eq!(verified.samples, 1);
        m.key_id = "stranger".to_owned();
        assert!(
            node.verify_package(&serde_json::to_vec(&m).expect("json"))
                .await
                .is_err()
        );
    }
}
