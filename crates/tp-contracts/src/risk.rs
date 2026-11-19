//! Справочник аномалий и threat intelligence (CTR-95; CONTRACTS.md#Risk; SRS 4.3, 4.9; решение 126,
//! исследование `docs/research/2026-11-14-anomaly-ti.md`).
//!
//! Каталог признаков — типизированная политика по образцу матрицы доверия (решение 124), а не второй язык
//! правил: признак — [`Detector`] на Rust с параметрами, вес, порог силы срабатывания, собственное действие
//! и режим «только отчёт»/«применять». Балл письма — сумма весов сработавших признаков; пороги каталога
//! ([`Thresholds`]) переводят балл в действие; действует самое строгое из действия по баллу, собственных
//! действий признаков и вердикта Rspamd. Уровни — установка → организация ([`RiskLevel`]): установка меняет
//! значения как угодно (вплоть до 0), организация — только в сторону строгости. Детекторы — первые пять
//! признаков снимают признак ответа (решение 126 г).
//!
//! Набор поставщика приходит подписанным пакетом ([`PackageManifest`]; подпись Ed25519 — как карты Rspamd):
//! обновление заменяет только признаки поставщика и сохраняет изменения администратора (модель Stalwart),
//! новые признаки — «только отчёт». TI — три уровня (решение 126 е–к): в поставке — только фиды с
//! коммерческой лицензией ([`FORBIDDEN_BUNDLED`] — запрет lint), «ключ заказчика», импорт по стандартам;
//! ГосСОПКА и ФинЦЕРТ — только импорт с организациями.
//!
//! Практика: символы с баллами и порогами — Rspamd; вендорские правила отдельно от локальных — Stalwart;
//! подписанные карты с откатом — Rspamd. Отличие: детекторы — типизированный Rust-код, а не выражения или
//! Lua; организация может только ужесточить; признак «только отчёт» — с журналом срабатываний.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::bus::{Event, EventKind};
use crate::error::{Error, Result};
use crate::ids::{BlobHash, TenantId};
use crate::secrets::SecretRef;

/// Наибольшая длина идентификатора (признака, списка, источника), байт.
pub const MAX_ID_LEN: usize = 64;

/// Префикс признаков поставщика (зарезервирован).
pub const VENDOR_PREFIX: &str = "tp.";

/// Префикс признаков администратора (зарезервирован).
pub const ADMIN_PREFIX: &str = "org.";

/// Наибольший вес признака (уровень установки может менять веса как угодно, но не выше предела).
pub const MAX_WEIGHT: u16 = 100;

/// Наибольшая сила срабатывания детектора ([`Signal::threshold`], [`Fired::strength`]).
pub const MAX_STRENGTH: u8 = 100;

/// Формат пакета поставщика ([`PackageManifest::format`]); текущий — 1.
pub const PACKAGE_FORMAT: u32 = 1;

/// Сколько прошлых пакетов хранится для отката по умолчанию (секция `risk.package.keep`).
pub const DEFAULT_PACKAGE_KEEP: usize = 5;

/// Процент снижения веса признаков устаревшего источника по умолчанию ([`StaleAction::Reduce`]).
pub const DEFAULT_STALE_REDUCE_PERCENT: u8 = 50;

/// Хосты и имена фидов, запрещённые в пакете поставщика (`tier: Bundled`; решение 126 ж–и): lint отклоняет
/// пакет с таким источником. Снять запрет можно только решением владельца и изменением константы.
pub const FORBIDDEN_BUNDLED: &[&str] = &[
    // 126 ж: коммерческое использование прямо запрещено условиями правообладателя.
    "openphish.com",               // OpenPhish Community
    "safebrowsing.googleapis.com", // Google Safe Browsing
    "otx.alienvault.com",          // AlienVault OTX
    "zen.spamhaus.org",            // бесплатные Spamhaus ZEN/DBL/ZRD
    "dbl.spamhaus.org",
    "zrd.spamhaus.org",
    // 126 з: российские фиды — уровень «ключ заказчика»; раздача — только по OEM-договору.
    "taxii.tip.kaspersky.com", // Kaspersky Threat Data Feeds (TAXII портала TIP)
    "tip.kaspersky.com",       // портал TIP Kaspersky (HTTPS-фиды с сертификатом клиента)
    "bi.zone",                 // BI.ZONE Threat Intelligence
    "f6.ru",                   // F6 Threat Intelligence
    "ptsecurity.com",          // PT Threat Intelligence Feeds
    "rt-solar.ru",             // Solar TI Feeds
    // 126 и: RST Cloud — до договора наш ключ только для стендов, раздача запрещена ToS.
    "rstcloud.net",
    "api.rstcloud.net",
];

/// Значение (хост или имя фида) — под запретом поставки: точное совпадение с [`FORBIDDEN_BUNDLED`] или
/// поддомен хоста из списка.
pub fn forbidden_bundled(value: &str) -> bool {
    let v = value.to_ascii_lowercase();
    FORBIDDEN_BUNDLED
        .iter()
        .any(|f| v == *f || v.ends_with(&format!(".{f}")))
}

/// Проверяет идентификатор (признака, списка, источника): 1–[`MAX_ID_LEN`] байт `[a-z0-9._-]`.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

macro_rules! string_id {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Идентификатор из строки; недопустимый ([`valid_id`]) — `Error::Invalid`.
            pub fn new(id: impl Into<String>) -> Result<Self> {
                let id = id.into();
                valid_id(&id)
                    .then(|| $name(id))
                    .ok_or_else(|| Error::invalid(concat!("risk: bad ", stringify!($name))))
            }

            /// Значение.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl FromStr for $name {
            type Err = Error;

            fn from_str(s: &str) -> Result<Self> {
                $name::new(s)
            }
        }
    };
}

string_id!(
    /// Идентификатор признака каталога: префикс `tp.` — признаки поставщика, `org.` — администратора
    /// (согласованность с [`Origin`] проверяет [`Signal::validate`]).
    SignalId
);
string_id!(
    /// Идентификатор списка TI ([`ListFile`], [`ListVersion`]).
    ListId
);
string_id!(
    /// Идентификатор источника TI ([`TiSource`]).
    SourceId
);

// ---------- Признак ----------

/// Происхождение признака каталога.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// Признак поставщика (пакет, префикс `tp.`).
    Vendor,
    /// Признак администратора (префикс `org.`).
    Admin,
}

/// Поле письма для детектора совпадения со списком TI ([`Detector::ListMatch`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
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

/// Детектор признака — типизированный Rust-код с параметрами (решение 126 г); неизвестный вид — ошибка
/// разбора с именем вида. Первые пять — признаки беседы (память [`crate::thread::ThreadFacts`], решение
/// 125 д): срабатывание снимает признак ответа ([`Detector::drops_reply`], решение 126 г).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Detector {
    /// Новый для беседы тип вложения.
    ThreadNewAttachmentType,
    /// Архив с паролем (ZIP с флагом шифрования, 7z и RAR с зашифрованным заголовком).
    EncryptedArchive,
    /// Образ диска или ярлык: ISO, IMG, VHD, LNK.
    DiskImageOrShortcut,
    /// Ссылка на новый для беседы домен (регистрируемый домен по Public Suffix List).
    ThreadNewLinkDomain,
    /// Смена `Reply-To` относительно беседы.
    ReplyToChanged,
    /// Совпадение поля письма со списком TI ([`ListId`]).
    ListMatch {
        /// Список.
        list: ListId,
        /// Поле письма.
        field: Field,
    },
}

impl Detector {
    /// Срабатывание детектора снимает признак «ответ на наше письмо» (решение 126 г): пять признаков
    /// беседы; совпадение со списком TI — не снимает.
    pub fn drops_reply(&self) -> bool {
        !matches!(self, Detector::ListMatch { .. })
    }
}

/// Собственное действие признака. От мягкого к строгому ([`Ord`]); `None` — признак действует только
/// баллом.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RiskAction {
    /// Ничего (только балл).
    #[default]
    None,
    /// Пометить письмо (флаг/заголовок).
    Tag,
    /// В папку «Спам».
    Junk,
    /// В карантин.
    Quarantine,
    /// Отказать письмо.
    Reject,
}

impl RiskAction {
    /// Значение в JSON и сообщениях об ошибке.
    pub const fn as_str(self) -> &'static str {
        match self {
            RiskAction::None => "none",
            RiskAction::Tag => "tag",
            RiskAction::Junk => "junk",
            RiskAction::Quarantine => "quarantine",
            RiskAction::Reject => "reject",
        }
    }
}

impl fmt::Display for RiskAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Режим признака: «только отчёт» или «применять» (решение 126 а). `Report` — срабатывания видны в журнале
/// ([`RiskStore::hits`]), балл и действие не применяются; новые признаки поставщика приходят в `Report`.
/// От мягкого к строгому: организация меняет `Report` только на `Enforce`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Только отчёт: срабатывания в журнале, балл и действие не применяются.
    Report,
    /// Применять: балл и действие действуют.
    Enforce,
}

impl Mode {
    /// Значение в JSON и сообщениях об ошибке.
    pub const fn as_str(self) -> &'static str {
        match self {
            Mode::Report => "report",
            Mode::Enforce => "enforce",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Признак каталога (решение 126 а).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signal {
    /// Идентификатор: префикс `tp.` у поставщика, `org.` у администратора ([`Signal::validate`]).
    pub id: SignalId,
    /// Детектор.
    pub detector: Detector,
    /// Вес в балле письма, ≤ [`MAX_WEIGHT`].
    pub weight: u16,
    /// Минимальная сила срабатывания детектора, 0–[`MAX_STRENGTH`]: ниже — признак не срабатывает.
    pub threshold: u8,
    /// Собственное действие (вместе с баллом; действует самое строгое).
    pub action: RiskAction,
    /// Режим: `Report` — только журнал.
    pub mode: Mode,
    /// Происхождение: согласовано с префиксом идентификатора.
    pub origin: Origin,
    /// Дата появления признака (для срока «только отчёт» — `risk.report_only_days`, APP-78).
    pub since: OffsetDateTime,
}

impl Signal {
    /// Проверка: идентификатор — [`valid_id`] с префиксом, согласованным с `origin` (`tp.` — поставщик,
    /// `org.` — администратор, прочих префиксов нет); вес ≤ [`MAX_WEIGHT`], порог ≤ [`MAX_STRENGTH`].
    /// Иначе — `Error::Invalid`.
    pub fn validate(&self) -> Result<()> {
        let id = self.id.as_str();
        if !valid_id(id) {
            return Err(Error::invalid("risk: недопустимый идентификатор признака"));
        }
        let prefix_ok = match self.origin {
            Origin::Vendor => id.starts_with(VENDOR_PREFIX),
            Origin::Admin => id.starts_with(ADMIN_PREFIX),
        };
        if !prefix_ok {
            return Err(Error::invalid(format!(
                "risk: {id}: префикс не соответствует происхождению {:?}",
                self.origin
            )));
        }
        if self.weight > MAX_WEIGHT {
            return Err(Error::invalid(format!(
                "risk: {id}: вес {} выше предела {MAX_WEIGHT}",
                self.weight
            )));
        }
        if self.threshold > MAX_STRENGTH {
            return Err(Error::invalid(format!(
                "risk: {id}: порог {} выше {MAX_STRENGTH}",
                self.threshold
            )));
        }
        Ok(())
    }
}

/// Пороги действий каталога (решение 126 а): балл, с которого действует действие (по умолчанию — константы
/// умолчаний Rspamd-масштаба: 1, 6, 10, 15).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Балл, с которого письмо помечается.
    pub tag: u32,
    /// Балл, с которого письмо идёт в «Спам».
    pub junk: u32,
    /// Балл, с которого письмо идёт в карантин.
    pub quarantine: u32,
    /// Балл, с которого письмо отвергается.
    pub reject: u32,
}

impl Default for Thresholds {
    /// 1 / 6 / 10 / 15.
    fn default() -> Self {
        Thresholds {
            tag: 1,
            junk: 6,
            quarantine: 10,
            reject: 15,
        }
    }
}

impl Thresholds {
    /// Действие по баллу (действует самое строгое из нескольких): балл от `reject` — [`RiskAction::Reject`],
    /// от `quarantine` — `Quarantine`, от `junk` — `Junk`, от `tag` — `Tag`, ниже — `None`.
    pub fn action(&self, score: u32) -> RiskAction {
        if score >= self.reject {
            RiskAction::Reject
        } else if score >= self.quarantine {
            RiskAction::Quarantine
        } else if score >= self.junk {
            RiskAction::Junk
        } else if score >= self.tag {
            RiskAction::Tag
        } else {
            RiskAction::None
        }
    }
}

// ---------- Уровни и изменения администратора ----------

/// Уровень политики справочника: установка → организация (решение 126 а). Порядок от верхнего к нижнему.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Установка — меняет значения как угодно (вплоть до 0, но не выше [`MAX_WEIGHT`]).
    Installation,
    /// Организация — только в сторону строгости.
    Org(TenantId),
}

impl RiskLevel {
    /// Организация уровня (`None` — установка).
    pub fn tenant(&self) -> Option<TenantId> {
        match self {
            RiskLevel::Installation => None,
            RiskLevel::Org(t) => Some(*t),
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Installation => f.write_str("installation"),
            RiskLevel::Org(t) => write!(f, "org {t}"),
        }
    }
}

/// Изменение администратора поверх признака поставщика (решение 126 в, модель Stalwart): заданные поля
/// заменяют значения пакета, незаданные — наследуются.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SignalOverride {
    /// Вес.
    #[serde(default)]
    pub weight: Option<u16>,
    /// Собственное действие.
    #[serde(default)]
    pub action: Option<RiskAction>,
    /// Режим.
    #[serde(default)]
    pub mode: Option<Mode>,
}

impl SignalOverride {
    /// Применяет заданные поля к признаку.
    fn apply(self, signal: &mut Signal) {
        if let Some(weight) = self.weight {
            signal.weight = weight;
        }
        if let Some(action) = self.action {
            signal.action = action;
        }
        if let Some(mode) = self.mode {
            signal.mode = mode;
        }
    }
}

/// Политика уровня: изменения поверх признаков поставщика и полные признаки администратора ([`Origin::Admin`]).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RiskPolicy {
    /// Изменения поверх признака поставщика по идентификатору (`tp.*`).
    #[serde(default)]
    pub overrides: BTreeMap<SignalId, SignalOverride>,
    /// Полные признаки администратора (`org.*`).
    #[serde(default)]
    pub signals: Vec<Signal>,
}

/// Несоответствие политики организации базовым значениям (для отказа `Invalid` и пометки): организация
/// смягчила признак — вес ниже, действие мягче или `Report` вместо `Enforce`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyViolation {
    /// Признак.
    pub signal: SignalId,
    /// Поле: `weight`, `action`, `mode`.
    pub field: String,
    /// Заданное значение.
    pub value: String,
    /// Базовое значение (уровней ниже).
    pub base: String,
}

impl fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{} = {} (базовое {})",
            self.signal, self.field, self.value, self.base
        )
    }
}

impl RiskPolicy {
    /// Проверяет структуру: изменения — только поверх признаков поставщика (`tp.*`) с весом не выше
    /// [`MAX_WEIGHT`]; полные признаки — [`Signal::validate`] без повторов идентификаторов. Иначе —
    /// `Error::Invalid`.
    pub fn check(&self) -> Result<()> {
        for (id, o) in &self.overrides {
            if !id.as_str().starts_with(VENDOR_PREFIX) {
                return Err(Error::invalid(format!(
                    "risk: изменение {id} — только поверх признака поставщика ({VENDOR_PREFIX}*)"
                )));
            }
            if o.weight.is_some_and(|w| w > MAX_WEIGHT) {
                return Err(Error::invalid(format!(
                    "risk: изменение {id}: вес выше предела {MAX_WEIGHT}"
                )));
            }
        }
        let mut ids: Vec<&SignalId> = self.signals.iter().map(|s| &s.id).collect();
        ids.sort_unstable();
        let mut sorted = ids.clone();
        sorted.dedup();
        if ids != sorted {
            return Err(Error::invalid(
                "risk: повтор идентификатора признака администратора",
            ));
        }
        for s in &self.signals {
            s.validate()?;
        }
        Ok(())
    }

    /// Проверяет политику уровня по действующим значениям уровней ниже: `base` — [`Catalog::effective`]
    /// пакета поставщика и уровней ниже. Установка меняет значения как угодно; организация — только в
    /// сторону строгости: вес не ниже, действие не мягче, `Report` вместо `Enforce` — `Error::Invalid` с
    /// перечнем [`PolicyViolation`] `{signal, field, value, base}`. Изменение признака, которого нет в
    /// пакете, — не ошибка («осиротевшее», решение 126 в).
    pub fn validate(&self, base: &EffectiveCatalog, level: RiskLevel) -> Result<()> {
        self.check()?;
        if !matches!(level, RiskLevel::Org(_)) {
            return Ok(());
        }
        let mut violations = Vec::new();
        for (id, o) in &self.overrides {
            let Some(b) = base.get(id) else {
                continue;
            };
            if let Some(weight) = o.weight
                && weight < b.signal.weight
            {
                violations.push(PolicyViolation {
                    signal: id.clone(),
                    field: "weight".to_owned(),
                    value: weight.to_string(),
                    base: b.signal.weight.to_string(),
                });
            }
            if let Some(action) = o.action
                && action < b.signal.action
            {
                violations.push(PolicyViolation {
                    signal: id.clone(),
                    field: "action".to_owned(),
                    value: action.to_string(),
                    base: b.signal.action.to_string(),
                });
            }
            if o.mode == Some(Mode::Report) && b.signal.mode == Mode::Enforce {
                violations.push(PolicyViolation {
                    signal: id.clone(),
                    field: "mode".to_owned(),
                    value: Mode::Report.to_string(),
                    base: Mode::Enforce.to_string(),
                });
            }
        }
        if violations.is_empty() {
            return Ok(());
        }
        let list = violations
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        Err(Error::invalid(format!(
            "risk: организация может только ужесточить: {list}"
        )))
    }
}

// ---------- Действующий каталог и обновление ----------

/// Действующий признак: значение и уровень-источник.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveSignal {
    /// Действующее значение (пакет поставщика и изменения уровней).
    pub signal: Signal,
    /// Признак пакета поставщика до изменений уровней; `None` — признак администратора.
    pub base: Option<Signal>,
    /// Уровень, давший отличие от пакета; `None` — признак пакета без изменений.
    pub source: Option<RiskLevel>,
}

/// Действующий каталог: признаки уровней и пороги действий.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EffectiveCatalog {
    /// Признаки по возрастанию идентификатора.
    pub signals: Vec<EffectiveSignal>,
    /// Пороги действий (константы контракта; настройка — будущие волны).
    pub thresholds: Thresholds,
}

impl EffectiveCatalog {
    /// Признак по идентификатору.
    pub fn get(&self, id: &SignalId) -> Option<&EffectiveSignal> {
        self.signals.iter().find(|e| &e.signal.id == id)
    }
}

/// Итог обновления пакета поставщика (решение 126 б–в): «что изменится» для администратора и activation.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct UpdateReport {
    /// Добавленные признаки (приходят в [`Mode::Report`]).
    pub added: Vec<SignalId>,
    /// Удалённые из пакета без изменений администратора.
    pub removed: Vec<SignalId>,
    /// Изменённые пакетом (детектор, вес, порог, действие, режим).
    pub changed: Vec<SignalId>,
    /// Изменения администратора признаков, которых больше нет в пакете: не удаляются молча, показываются
    /// как «осиротевшие» (решение 126 в).
    pub orphaned_overrides: Vec<SignalId>,
}

/// Комбинатор уровней каталога (чистые функции, как [`crate::trust::effective`]).
#[derive(Debug, Clone, Copy, Default)]
pub struct Catalog;

impl Catalog {
    /// Действующий каталог уровней (решение 126 а): признаки пакета поставщика `vendor`, поверх —
    /// изменения и признаки администратора политики установки, затем организации ([`EffectiveSignal::source`]
    /// — уровень, давший отличие). Пороги — константы контракта.
    pub fn effective(
        vendor: &[Signal],
        installation: Option<&RiskPolicy>,
        org: Option<(RiskLevel, &RiskPolicy)>,
    ) -> EffectiveCatalog {
        let mut signals: BTreeMap<SignalId, EffectiveSignal> = BTreeMap::new();
        for s in vendor {
            signals.insert(
                s.id.clone(),
                EffectiveSignal {
                    signal: s.clone(),
                    base: Some(s.clone()),
                    source: None,
                },
            );
        }
        let mut apply = |policy: &RiskPolicy, level: RiskLevel| {
            for (id, o) in &policy.overrides {
                if let Some(entry) = signals.get_mut(id) {
                    o.apply(&mut entry.signal);
                    entry.source = Some(level);
                }
            }
            for s in &policy.signals {
                signals.insert(
                    s.id.clone(),
                    EffectiveSignal {
                        signal: s.clone(),
                        base: None,
                        source: Some(level),
                    },
                );
            }
        };
        if let Some(policy) = installation {
            apply(policy, RiskLevel::Installation);
        }
        if let Some((level, policy)) = org {
            apply(policy, level);
        }
        EffectiveCatalog {
            signals: signals.into_values().collect(),
            thresholds: Thresholds::default(),
        }
    }

    /// Готовит новый пакет поставщика к установке и считает, что изменится (решение 126 б–в): заменяются
    /// только признаки `Origin::Vendor`, изменения администратора и его признаки (в политиках уровней)
    /// сохраняются — модель Stalwart; признаки, которых не было в действующем каталоге `old`, переводятся
    /// в [`Mode::Report`] (файл `new_vendor` меняется на месте); признак, удалённый из пакета с живым
    /// изменением администратора, — в [`UpdateReport::orphaned_overrides`].
    pub fn apply_update(old: &EffectiveCatalog, new_vendor: &mut [Signal]) -> UpdateReport {
        let mut report = UpdateReport::default();
        for s in new_vendor.iter_mut() {
            match old.get(&s.id) {
                None => {
                    s.mode = Mode::Report;
                    report.added.push(s.id.clone());
                }
                Some(old) => {
                    if old.base.as_ref().is_some_and(|b| *b != *s) {
                        report.changed.push(s.id.clone());
                    }
                }
            }
        }
        for e in &old.signals {
            let is_vendor = e.base.is_some();
            let still = new_vendor.iter().any(|s| s.id == e.signal.id);
            if is_vendor && !still {
                if e.source.is_some() {
                    report.orphaned_overrides.push(e.signal.id.clone());
                } else {
                    report.removed.push(e.signal.id.clone());
                }
            }
        }
        report
    }
}

// ---------- Вердикт ----------

/// Откуда пришло срабатывание признака.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HitSource {
    /// Детектор Rust (конвейер, SMTP-52).
    Detector,
    /// Команда `signal` скрипта администратора (расширение `vnd.thepost.risk`, SIEVE-15).
    Sieve,
}

/// Сработавший признак в вердикте.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hit {
    /// Признак.
    pub signal: SignalId,
    /// Сила срабатывания детектора, 0–[`MAX_STRENGTH`].
    pub strength: u8,
    /// Вес признака в балле.
    pub weight: u16,
    /// Источник срабатывания.
    pub source: HitSource,
}

/// Срабатывание на входе вердикта: признак действующего каталога и сила срабатывания детектора.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fired {
    /// Признак действующего каталога.
    pub signal: Signal,
    /// Сила срабатывания: признак срабатывает при `strength ≥ signal.threshold`.
    pub strength: u8,
    /// Источник срабатывания (детектор или скрипт Sieve).
    pub source: HitSource,
}

/// Вердикт справочника по письму: балл, срабатывания и действие.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Verdict {
    /// Балл — сумма весов сработавших признаков в режиме [`Mode::Enforce`].
    pub score: u32,
    /// Сработавшие признаки в режиме [`Mode::Enforce`].
    pub hits: Vec<Hit>,
    /// Сработавшие признаки в режиме [`Mode::Report`] (только журнал; балл и действие не меняют).
    pub report_only: Vec<Hit>,
    /// Действие: самое строгое из действия по баллу и собственных действий признаков `Enforce`
    /// ([`Verdict::from_fired`], [`Verdict::combine`]).
    pub action: RiskAction,
    /// Сработал признак, снимающий признак «ответ на наше письмо» ([`Detector::drops_reply`], решение 126 г).
    pub drops_reply: bool,
}

impl Verdict {
    /// Вердикт по сработавшим признакам действующего каталога: срабатывание — `strength ≥`
    /// [`Signal::threshold`]; признак [`Mode::Enforce`] — в [`Verdict::hits`] и балл, [`Mode::Report`] —
    /// в [`Verdict::report_only`] (балл и действие не меняет); действие — самое строгое из действия по
    /// баллу ([`Thresholds::action`]) и собственных действий сработавших признаков `Enforce`.
    pub fn from_fired(catalog: &EffectiveCatalog, fired: &[Fired]) -> Self {
        let mut verdict = Verdict::default();
        for f in fired {
            if f.strength < f.signal.threshold {
                continue;
            }
            let hit = Hit {
                signal: f.signal.id.clone(),
                strength: f.strength,
                weight: f.signal.weight,
                source: f.source,
            };
            match f.signal.mode {
                Mode::Enforce => {
                    verdict.score += u32::from(f.signal.weight);
                    verdict.action = verdict.action.max(f.signal.action);
                    if f.signal.detector.drops_reply() {
                        verdict.drops_reply = true;
                    }
                    verdict.hits.push(hit);
                }
                Mode::Report => verdict.report_only.push(hit),
            }
        }
        let by_score = catalog.thresholds.action(verdict.score);
        verdict.action = verdict.action.max(by_score);
        verdict
    }

    /// Действие с учётом вердикта Rspamd (действие Rspamd приводит вызывающий к [`RiskAction`]): самое
    /// строгое ([`Ord`]) из действия вердикта и `rspamd`; итог — в [`Verdict::action`] (решение 126 а).
    pub fn combine(&mut self, rspamd: RiskAction) -> RiskAction {
        self.action = self.action.max(rspamd);
        self.action
    }
}

// ---------- Пакет поставщика ----------

/// Версия узла `MAJOR.MINOR.PATCH` ([`PackageManifest::min_node`]): формат пакета наш, пре-релизы и сборки
/// не предусмотрены; сравнение — по тройке чисел.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Semver {
    /// Старшая.
    pub major: u64,
    /// Минорная.
    pub minor: u64,
    /// Патч.
    pub patch: u64,
}

impl Semver {
    /// Версия из тройки чисел.
    pub const fn new(major: u64, minor: u64, patch: u64) -> Self {
        Semver {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for Semver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl FromStr for Semver {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let mut parts = s.split('.');
        let mut next = || {
            parts
                .next()
                .and_then(|p| p.parse::<u64>().ok())
                .ok_or_else(|| Error::invalid(format!("risk: не версия узла: {s:?}")))
        };
        let (major, minor, patch) = (next()?, next()?, next()?);
        if parts.next().is_some() {
            return Err(Error::invalid(format!("risk: не версия узла: {s:?}")));
        }
        Ok(Semver {
            major,
            minor,
            patch,
        })
    }
}

impl TryFrom<String> for Semver {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}

impl From<Semver> for String {
    fn from(v: Semver) -> Self {
        v.to_string()
    }
}

/// Вид записей списка TI ([`ListFile`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListKind {
    /// IP-адреса и подсети.
    Ip,
    /// Домены.
    Domain,
    /// URL.
    Url,
    /// SHA-256 файлов.
    Sha256,
}

/// Файл списка TI в пакете поставщика.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListFile {
    /// Идентификатор списка.
    pub id: ListId,
    /// Путь файла в пакете.
    pub path: String,
    /// SHA-256 файла.
    pub sha256: BlobHash,
    /// Число записей.
    pub entries: u64,
    /// Вид записей.
    pub kind: ListKind,
    /// Источник TI (атрибуция в лицензии источника).
    pub source: SourceId,
}

/// Образец письма пакета для пробного прогона (решение 126 б): детекторы и каталог на образцах пакета —
/// признаки совпадают с `expect`, иначе отказ установки.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleFile {
    /// Путь файла в пакете.
    pub path: String,
    /// SHA-256 файла.
    pub sha256: BlobHash,
    /// Ожидаемые признаки (пусто — образец «чистого» письма: контроль ложных срабатываний).
    pub expect: Vec<SignalId>,
}

/// Манифест пакета поставщика (решение 126 б). Подпись — отдельные байты Ed25519 над каноническим JSON
/// манифеста (файл `manifest.sig` пакета); проверку делает узел (APP-78) ключом из `risk.trusted_keys`
/// по `key_id` — контракт описывает формат, ключи и подпись не хранит.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Формат пакета; [`PACKAGE_FORMAT`].
    pub format: u32,
    /// Номер версии: только растёт; пакет со старым или тем же номером не ставится.
    pub version: u64,
    /// Момент сборки (UTC).
    pub created: OffsetDateTime,
    /// Минимальная версия узла.
    pub min_node: Semver,
    /// Идентификатор ключа подписи (открытый ключ — в `risk.trusted_keys`).
    pub key_id: String,
    /// Признаки каталога (`Origin::Vendor`).
    pub signals: Vec<Signal>,
    /// Списки TI.
    pub lists: Vec<ListFile>,
    /// Образцы для пробного прогона.
    pub samples: Vec<SampleFile>,
}

impl PackageManifest {
    /// Проверка: формат — [`PACKAGE_FORMAT`]; признаки — [`Signal::validate`] без повторов
    /// идентификаторов; у списков и образцов — пути без пустых, идентификаторы допустимы. Иначе —
    /// `Error::Invalid`. Подпись, хэши файлов и lint (запрещённые источники, известные детекторы,
    /// пробный прогон) — узел (APP-78).
    pub fn validate(&self) -> Result<()> {
        if self.format != PACKAGE_FORMAT {
            return Err(Error::invalid(format!(
                "risk: формат пакета {} (ожидается {PACKAGE_FORMAT})",
                self.format
            )));
        }
        let mut ids: Vec<&SignalId> = self.signals.iter().map(|s| &s.id).collect();
        ids.sort_unstable();
        let mut sorted = ids.clone();
        sorted.dedup();
        if ids != sorted {
            return Err(Error::invalid(
                "risk: повтор идентификатора признака в пакете",
            ));
        }
        for s in &self.signals {
            if s.origin != Origin::Vendor {
                return Err(Error::invalid(
                    "risk: в пакете — только признаки поставщика (Origin::Vendor)",
                ));
            }
            s.validate()?;
        }
        for l in &self.lists {
            if l.path.is_empty() {
                return Err(Error::invalid("risk: пустой путь файла списка"));
            }
        }
        for s in &self.samples {
            if s.path.is_empty() {
                return Err(Error::invalid("risk: пустой путь образца"));
            }
        }
        Ok(())
    }
}

/// Состояние хранимого пакета ([`RiskStore::packages`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageState {
    /// Действующий каталог пакета.
    Active,
    /// Хранимый для отката (не больше `risk.package.keep`).
    Previous,
    /// Отклонён при проверке (подпись, lint, пробный прогон) — отчёт `report`; активный пакет не меняется.
    Rejected {
        /// Отчёт проверки (что не так).
        report: String,
    },
}

/// Хранимый пакет: номер и состояние.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageEntry {
    /// Номер версии.
    pub version: u64,
    /// Состояние.
    pub state: PackageState,
}

// ---------- Источники TI ----------

/// Уровень источника TI (решение 126 е–з).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// В поставке — раздаёт вендор подписанным пакетом; только фиды с коммерческой лицензией.
    Bundled,
    /// Ключ заказчика — заказчик включает фид своим ключом или подпиской, вендор не раздаёт.
    CustomerKey,
    /// Импорт по стандартам (txt, CSV, RPZ, MISP, TAXII/STIX) — своё TI, ГосСОПКА, ФинЦЕРТ.
    Import,
}

impl Tier {
    /// Значение в JSON и сообщениях об ошибке.
    pub const fn as_str(self) -> &'static str {
        match self {
            Tier::Bundled => "bundled",
            Tier::CustomerKey => "customer_key",
            Tier::Import => "import",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Происхождение данных источника (решение 126 к) — для журнала и отчётов.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TiOrigin {
    /// Вендор фида.
    Vendor,
    /// ГосСОПКА (НКЦКИ) — импорт из TIP или файла заказчика.
    GosSopka,
    /// ФинЦЕРТ Банка России — импорт из TIP или файла заказчика.
    FinCert,
    /// Собственные индикаторы заказчика.
    Own,
}

impl TiOrigin {
    /// Значение в JSON и сообщениях об ошибке.
    pub const fn as_str(self) -> &'static str {
        match self {
            TiOrigin::Vendor => "vendor",
            TiOrigin::GosSopka => "gossopka",
            TiOrigin::FinCert => "fincert",
            TiOrigin::Own => "own",
        }
    }
}

impl fmt::Display for TiOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Доставка и параметры источника TI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// Фид по HTTP(S).
    Http {
        /// Адрес.
        url: String,
    },
    /// Коллекция TAXII 2.1 (решение 126 з: Kaspersky, BI.ZONE, F6, TIP заказчика).
    Taxii {
        /// API root.
        api_root: String,
        /// Коллекция.
        collection: String,
    },
    /// Файл в каталоге импорта (`risk.import.dir`; закрытый контур — файл кладут руками или зеркалом).
    File,
}

/// Авторизация источника TI (решение 126 з–и): секрет (значение заголовка, пароль, токен, сертификат
/// клиента) — из [`TiSource::key`] хранилища секретов; `Header` — имя заголовка (`X-Api-Key` у RST Cloud,
/// `Auth-Key` у abuse.ch), `Basic` — имя пользователя (Kaspersky TAXII: `taxii`), `ClientCert` —
/// сертификат клиента HTTPS-фидов Kaspersky.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HttpAuth {
    /// Без авторизации.
    None,
    /// Свой заголовок; имя здесь, значение — секрет.
    Header {
        /// Имя заголовка.
        name: String,
    },
    /// Basic; пользователь здесь, пароль — секрет.
    Basic {
        /// Имя пользователя.
        user: String,
    },
    /// Bearer-токен из секрета.
    Bearer,
    /// Сертификат клиента из секрета.
    ClientCert,
}

/// Формат фида источника TI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedFormat {
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

/// Действие при устаревании источника (решение 126 е): вес признаков снижается или признак переводится
/// в «только отчёт», с предупреждением в `thepost doctor` и журнале; молча не отключается — варианта
/// «отключить» нет.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StaleAction {
    /// Снизить вес признаков источника на `percent` процентов.
    Reduce {
        /// Процент снижения, 0–100.
        percent: u8,
    },
    /// Перевести признаки в «только отчёт».
    Report,
}

impl Default for StaleAction {
    /// [`StaleAction::Reduce`] с [`DEFAULT_STALE_REDUCE_PERCENT`].
    fn default() -> Self {
        StaleAction::Reduce {
            percent: DEFAULT_STALE_REDUCE_PERCENT,
        }
    }
}

/// Лицензия источника TI (решение 126 е, ж): условия и атрибуция.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct License {
    /// Адрес условий использования.
    pub terms_url: String,
    /// Атрибуция (ссылка, дата, © — Spamhaus DROP/EDROP); `None` — не требуется.
    pub attribution: Option<String>,
    /// Коммерческое использование разрешено условиями.
    pub commercial: bool,
}

/// Организации, которым доступен источник.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tenants {
    /// Все организации установки.
    All,
    /// Только перечисленные (импорт ГосСОПКА/ФинЦЕРТ — всегда; непусто).
    Only(Vec<TenantId>),
}

/// Источник TI (решение 126 е–к): фид в поставке, коннектор «ключ заказчика» или импорт. Коннектор —
/// пресет к [`SourceKind::Http`] и [`SourceKind::Taxii`] с [`FeedFormat`], отдельного парсера под
/// вендора нет.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TiSource {
    /// Идентификатор.
    pub id: SourceId,
    /// Уровень: в поставке, ключ заказчика, импорт.
    pub tier: Tier,
    /// Доставка.
    pub kind: SourceKind,
    /// Формат.
    pub format: FeedFormat,
    /// Срок жизни данных (TTL): старше — устаревший.
    pub ttl: Duration,
    /// Действие при устаревании («отключить» нет).
    pub stale: StaleAction,
    /// Лицензия.
    pub license: License,
    /// Организации, которым доступен.
    pub tenants: Tenants,
    /// Секрет (ключ, токен, сертификат) — ссылка на хранилище секретов.
    pub key: Option<SecretRef>,
    /// Авторизация (секрет — из `key`).
    pub auth: HttpAuth,
    /// Происхождение — для журнала и отчётов.
    pub origin: TiOrigin,
}

impl TiSource {
    /// Хосты источника (для проверки [`FORBIDDEN_BUNDLED`]): `Http` — адрес, `Taxii` — api root, `File` —
    /// пусто.
    pub fn hosts(&self) -> Vec<String> {
        match &self.kind {
            SourceKind::Http { url } | SourceKind::Taxii { api_root: url, .. } => {
                vec![url_host(url).unwrap_or_default().to_owned()]
            }
            SourceKind::File => Vec::new(),
        }
    }

    /// Проверка: `Bundled` — только фиды с разрешённым коммерческим использованием (`license.commercial`)
    /// и без запрещённых поставки хостов и имён ([`FORBIDDEN_BUNDLED`], решение 126 ж–и) и не
    /// ГосСОПКА/ФинЦЕРТ; `Import` ГосСОПКА/ФинЦЕРТ — только с организациями (`tenants: Only`, решение 126 к);
    /// `Reduce` — до 100 процентов; адреса `Http`/`Taxii` и колонка `Csv` непусты; `Only` непусто.
    /// Иначе — `Error::Invalid`.
    pub fn validate(&self) -> Result<()> {
        if self.ttl.is_zero() {
            return Err(Error::invalid(format!(
                "risk: источник {}: нулевой TTL",
                self.id
            )));
        }
        if let StaleAction::Reduce { percent } = self.stale
            && percent > MAX_STRENGTH
        {
            return Err(Error::invalid(format!(
                "risk: источник {}: снижение веса выше 100%",
                self.id
            )));
        }
        if let Tenants::Only(list) = &self.tenants
            && list.is_empty()
        {
            return Err(Error::invalid(format!(
                "risk: источник {}: пустой список организаций",
                self.id
            )));
        }
        match &self.kind {
            SourceKind::Http { url } if url.is_empty() => {
                return Err(Error::invalid(format!(
                    "risk: источник {}: пустой адрес фида",
                    self.id
                )));
            }
            SourceKind::Taxii { api_root, .. } if api_root.is_empty() => {
                return Err(Error::invalid(format!(
                    "risk: источник {}: пустой api root",
                    self.id
                )));
            }
            _ => {}
        }
        if let FeedFormat::Csv { column } = &self.format
            && column.is_empty()
        {
            return Err(Error::invalid(format!(
                "risk: источник {}: пустая колонка CSV",
                self.id
            )));
        }
        match self.tier {
            Tier::Bundled => {
                if !self.license.commercial {
                    return Err(Error::invalid(format!(
                        "risk: источник {}/{}: в поставке — только фиды с коммерческой лицензией",
                        self.tier, self.id
                    )));
                }
                if matches!(self.origin, TiOrigin::GosSopka | TiOrigin::FinCert) {
                    return Err(Error::invalid(format!(
                        "risk: источник {}/{}: {} — только импорт",
                        self.tier, self.id, self.origin
                    )));
                }
                if forbidden_bundled(self.id.as_str()) {
                    return Err(Error::invalid(format!(
                        "risk: источник {}/{} запрещён к поставке",
                        self.tier, self.id
                    )));
                }
                for host in self.hosts() {
                    if forbidden_bundled(&host) {
                        return Err(Error::invalid(format!(
                            "risk: источник {}/{}: хост {host} запрещён к поставке",
                            self.tier, self.id
                        )));
                    }
                }
            }
            Tier::Import => {
                if matches!(self.origin, TiOrigin::GosSopka | TiOrigin::FinCert)
                    && self.tenants == Tenants::All
                {
                    return Err(Error::invalid(format!(
                        "risk: источник {}/{}: импорт {} — только с организациями (tenants: Only)",
                        self.tier, self.id, self.origin
                    )));
                }
            }
            Tier::CustomerKey => {}
        }
        Ok(())
    }
}

/// Хост адреса: без схемы, пути и порта (`https://feed.example.org:8443/path` → `feed.example.org`;
/// IPv6-адрес — без скобок и порта).
fn url_host(raw: &str) -> Option<&str> {
    let rest = raw.split_once("://").map(|(_, r)| r).unwrap_or(raw);
    let end = rest.find(&['/', '?', '#'][..]).unwrap_or(rest.len());
    let authority = &rest[..end];
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    // Порт — после хоста; IPv6-адрес — в скобках, порт после ']'.
    let host = match host.split_once(']') {
        Some((bracketed, _)) => bracketed.strip_prefix('[').unwrap_or(bracketed),
        None => host.split_once(':').map(|(h, _)| h).unwrap_or(host),
    };
    (!host.is_empty()).then_some(host)
}

// ---------- Списки и учёт ----------

/// Маркировка TLP (RFC 5017) версии списка из источника: STIX `object_marking_refs` или теги MISP
/// `tlp:*`; `None` — маркировки нет.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tlp {
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

/// Версия списка TI: содержимое — в BLOB (`blob` — ссылка на объект), ставится текущей.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListVersion {
    /// Список.
    pub list: ListId,
    /// Источник.
    pub source: SourceId,
    /// SHA-256 содержимого.
    pub sha256: BlobHash,
    /// Ссылка на объект содержимого в BLOB.
    pub blob: String,
    /// Число записей.
    pub entries: u64,
    /// Момент загрузки (UTC).
    pub fetched_at: OffsetDateTime,
    /// Маркировка TLP из источника.
    pub tlp: Option<Tlp>,
}

/// Учёт обращений к источнику TI за сутки (по организациям — MSSP, решение 126 е).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageEntry {
    /// Источник.
    pub source: SourceId,
    /// Организация.
    pub tenant: TenantId,
    /// Сутки учёта (UTC, начало дня).
    pub day: OffsetDateTime,
    /// Обращения (проверки полей письма по спискам источника).
    pub lookups: u64,
    /// Совпадения.
    pub hits: u64,
}

/// Запрос срабатываний ([`RiskStore::hits`]). Условия объединяются по «и»; `None` — без условия.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitsQuery {
    /// Только этот признак.
    pub signal: Option<SignalId>,
    /// Только это письмо.
    pub message: Option<BlobHash>,
    /// Начало интервала, включительно.
    pub since: Option<OffsetDateTime>,
    /// Конец интервала, не включительно.
    pub until: Option<OffsetDateTime>,
    /// Не больше записей, ≥ 1.
    pub limit: usize,
}

impl HitsQuery {
    /// Запрос всех срабатываний организации на `limit` записей.
    pub fn all(limit: usize) -> Self {
        HitsQuery {
            signal: None,
            message: None,
            since: None,
            until: None,
            limit,
        }
    }

    /// Проверка: `limit ≥ 1`, `since < until`; иначе — `Error::Invalid`.
    pub fn validate(&self) -> Result<()> {
        if self.limit == 0 {
            return Err(Error::invalid(
                "risk: лимит срабатываний должен быть положительным",
            ));
        }
        if let (Some(since), Some(until)) = (self.since, self.until)
            && since >= until
        {
            return Err(Error::invalid("risk: пустой интервал срабатываний"));
        }
        Ok(())
    }

    /// Запись удовлетворяет условиям запроса.
    pub fn matches(&self, r: &HitRecord) -> bool {
        self.signal.as_ref().is_none_or(|s| s == &r.signal)
            && self.message.is_none_or(|m| m == r.message)
            && self.since.is_none_or(|s| r.at >= s)
            && self.until.is_none_or(|u| r.at < u)
    }
}

/// Запись о срабатывании признака (журнал срабатываний; «только отчёт» — здесь же, с режимом).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HitRecord {
    /// Организация.
    pub tenant: TenantId,
    /// Письмо (SHA-256; считает вызывающий).
    pub message: BlobHash,
    /// Признак.
    pub signal: SignalId,
    /// Сила срабатывания.
    pub strength: u8,
    /// Вес признака при срабатывании.
    pub weight: u16,
    /// Режим признака при срабатывании: `Report` — только журнал.
    pub mode: Mode,
    /// Момент (UTC).
    pub at: OffsetDateTime,
}

// ---------- Хранилище ----------

/// Сигнал об изменении справочника аномалий ([`EventKind::RiskChanged`]): после фиксации активации или
/// отката пакета, политики уровня, источника TI или версии списка. Узлы сбрасывают кэш действующего
/// каталога и списков; публикует тот, кто меняет.
pub fn risk_changed() -> Event {
    Event {
        tenant: TenantId::DEFAULT,
        account: None,
        kind: EventKind::RiskChanged,
    }
}

/// Справочник аномалий и TI (решение 126): пакеты поставщика, политики уровней, источники, версии списков,
/// учёт обращений и журнал срабатываний. Реализация — `tp-meta` (META-87); in-memory — `tp-testkit`.
/// Проверку пакета (подпись, lint, пробный прогон) делает узел (APP-78) до `put_package` и `activate`.
#[async_trait]
pub trait RiskStore: Send + Sync + 'static {
    /// Действующий каталог организации ([`Catalog::effective`]): активный пакет, политика установки и
    /// организации. Чужая организация видит только свои политики.
    async fn effective(&self, tenant: TenantId) -> Result<EffectiveCatalog>;

    /// Записывает проверенный пакет: номер больше любого хранимого (иначе `Invalid`), манифест допустим
    /// ([`PackageManifest::validate`]). Пакет не активен до [`RiskStore::activate`].
    async fn put_package(&self, manifest: &PackageManifest) -> Result<()>;

    /// Делает пакет активным: номер строго больше активного, иначе `Invalid`; нет пакета — `NotFound`.
    /// Прошлые сверх `risk.package.keep` удаляются.
    async fn activate(&self, version: u64) -> Result<()>;

    /// Откат на хранимую версию ([`RiskStore::packages`]): нет — `NotFound`. Откат меняет активный пакет,
    /// номер новой поставки всё равно только растёт.
    async fn rollback(&self, version: u64) -> Result<()>;

    /// Хранимые пакеты: активный и N прошлых (`risk.package.keep`), по убыванию номера.
    async fn packages(&self) -> Result<Vec<PackageEntry>>;

    /// Политика уровня; не задана — `None` (действуют уровень выше и пакет). Чужой организации видна
    /// только своя политика.
    async fn policy(&self, level: RiskLevel) -> Result<Option<RiskPolicy>>;

    /// Записывает политику уровня целиком: [`RiskPolicy::validate`] по действующим значениям уровней ниже
    /// (установка — [`Catalog::effective`] активного пакета, организация — с политикой установки).
    /// Пустая политика удаляет уровень. После фиксации — сигнал [`risk_changed`].
    async fn set_policy(&self, level: RiskLevel, policy: &RiskPolicy) -> Result<()>;

    /// Удаляет политику уровня (пакет и уровень выше продолжают действовать); нет — не ошибка. После
    /// фиксации — сигнал [`risk_changed`].
    async fn reset_policy(&self, level: RiskLevel) -> Result<()>;

    /// Источники TI по идентификатору.
    async fn sources(&self) -> Result<Vec<TiSource>>;

    /// Записывает или заменяет источник ([`TiSource::validate`]).
    async fn put_source(&self, source: &TiSource) -> Result<()>;

    /// Удаляет источник; нет — не ошибка.
    async fn delete_source(&self, id: &SourceId) -> Result<()>;

    /// Записывает версию списка текущей: источник должен быть известен (иначе `Invalid`).
    async fn put_list_version(&self, version: &ListVersion) -> Result<()>;

    /// Текущая версия списка; нет — `None`.
    async fn list_current(&self, list: &ListId) -> Result<Option<ListVersion>>;

    /// Учитывает обращения к источнику за текущие сутки (UTC) организации `tenant`: `lookups` проверок,
    /// `hits` совпадений (MSSP — по каждой организации, решение 126 е).
    async fn record_usage(
        &self,
        source: &SourceId,
        tenant: TenantId,
        lookups: u64,
        hits: u64,
    ) -> Result<()>;

    /// Учёт источника по суткам (UTC) от `since` включительно, по возрастанию суток.
    async fn usage(&self, source: &SourceId, since: OffsetDateTime) -> Result<Vec<UsageEntry>>;

    /// Записывает срабатывания вердикта в журнал: `hits` с режимом `Enforce`, `report_only` — `Report`
    /// (решение 126 а: срабатывания «только отчёт» видны в журнале). `message` — SHA-256 письма.
    async fn record_hits(
        &self,
        tenant: TenantId,
        message: BlobHash,
        verdict: &Verdict,
    ) -> Result<()>;

    /// Журнал срабатываний организации (свежие первыми), не больше `filter.limit`; некорректный запрос —
    /// `Invalid`. Чужая организация срабатываний другой не видит.
    async fn hits(&self, tenant: TenantId, filter: &HitsQuery) -> Result<Vec<HitRecord>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(id: &str, weight: u16) -> Signal {
        Signal {
            id: SignalId::new(id).expect("id"),
            detector: Detector::EncryptedArchive,
            weight,
            threshold: 0,
            action: RiskAction::None,
            mode: Mode::Enforce,
            origin: Origin::Vendor,
            since: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn admin_signal(id: &str, weight: u16) -> Signal {
        Signal {
            id: SignalId::new(id).expect("id"),
            origin: Origin::Admin,
            ..signal(id, weight)
        }
    }

    fn fired(s: &Signal, strength: u8) -> Fired {
        Fired {
            signal: s.clone(),
            strength,
            source: HitSource::Detector,
        }
    }

    #[test]
    fn object_safe() {
        fn _store(_: std::sync::Arc<dyn RiskStore>) {}
    }

    #[test]
    fn ids_and_prefixes() {
        for ok in [
            "tp.encrypted_archive",
            "org.custom-rule",
            "a",
            &"x".repeat(MAX_ID_LEN),
        ] {
            assert!(valid_id(ok), "{ok:?}");
            assert!(SignalId::new(ok).is_ok(), "{ok:?}");
        }
        for bad in [
            "",
            "UPPER",
            "с пробелом",
            "a b",
            &"x".repeat(MAX_ID_LEN + 1),
            "tp.rust\n",
        ] {
            assert!(!valid_id(bad), "{bad:?}");
            assert!(SignalId::new(bad).is_err(), "{bad:?}");
        }
        // Префикс — происхождение.
        assert!(signal("tp.x", 1).validate().is_ok());
        assert!(admin_signal("org.x", 1).validate().is_ok());
        for bad in [
            signal("org.x", 1),      // Vendor с префиксом администратора
            admin_signal("tp.x", 1), // Admin с префиксом поставщика
            Signal {
                id: SignalId::new("plain").expect("id"),
                origin: Origin::Vendor,
                ..signal("tp.x", 1)
            },
        ] {
            assert!(matches!(bad.validate(), Err(Error::Invalid(_))), "{bad:?}");
        }
        // Вес и порог.
        assert!(matches!(
            signal("tp.x", MAX_WEIGHT + 1).validate(),
            Err(Error::Invalid(_))
        ));
        assert!(signal("tp.x", MAX_WEIGHT).validate().is_ok());
        let over_threshold = Signal {
            threshold: MAX_STRENGTH + 1,
            ..signal("tp.x", 1)
        };
        assert!(matches!(over_threshold.validate(), Err(Error::Invalid(_))));
    }

    #[test]
    fn detectors() {
        // Пять признаков беседы снимают признак ответа; совпадение со списком — нет.
        for d in [
            Detector::ThreadNewAttachmentType,
            Detector::EncryptedArchive,
            Detector::DiskImageOrShortcut,
            Detector::ThreadNewLinkDomain,
            Detector::ReplyToChanged,
        ] {
            assert!(d.drops_reply(), "{d:?}");
        }
        assert!(
            !Detector::ListMatch {
                list: ListId::new("feodo-ip").expect("list"),
                field: Field::SenderIp,
            }
            .drops_reply()
        );
        // serde: известные виды — snake_case, неизвестный — ошибка с именем вида.
        let json = serde_json::to_string(&Detector::EncryptedArchive).expect("json");
        assert_eq!(json, "\"encrypted_archive\"");
        let list_match = Detector::ListMatch {
            list: ListId::new("feodo-ip").expect("list"),
            field: Field::LinkDomain,
        };
        let back: Detector =
            serde_json::from_str(&serde_json::to_string(&list_match).expect("json"))
                .expect("parse");
        assert_eq!(back, list_match);
        let err = serde_json::from_str::<Detector>("\"lua_rule\"").expect_err("unknown");
        assert!(
            err.to_string().contains("lua_rule"),
            "имя вида в ошибке: {err}"
        );
        assert_eq!(
            serde_json::to_string(&Field::AttachmentSha256).expect("json"),
            "\"attachment_sha256\""
        );
    }

    #[test]
    fn thresholds_and_actions() {
        assert_eq!(
            Thresholds::default(),
            Thresholds {
                tag: 1,
                junk: 6,
                quarantine: 10,
                reject: 15
            }
        );
        let t = Thresholds::default();
        assert_eq!(t.action(0), RiskAction::None);
        assert_eq!(t.action(1), RiskAction::Tag);
        assert_eq!(t.action(6), RiskAction::Junk);
        assert_eq!(t.action(10), RiskAction::Quarantine);
        assert_eq!(t.action(15), RiskAction::Reject);
        assert_eq!(t.action(1000), RiskAction::Reject);
        // Строгость: None < Tag < Junk < Quarantine < Reject.
        assert!(RiskAction::None < RiskAction::Tag);
        assert!(RiskAction::Tag < RiskAction::Junk);
        assert!(RiskAction::Junk < RiskAction::Quarantine);
        assert!(RiskAction::Quarantine < RiskAction::Reject);
        // Режим: Report < Enforce.
        assert!(Mode::Report < Mode::Enforce);
        assert_eq!(
            serde_json::to_string(&RiskAction::Quarantine).expect("json"),
            "\"quarantine\""
        );
        assert_eq!(
            serde_json::to_string(&Mode::Report).expect("json"),
            "\"report\""
        );
    }

    #[test]
    fn effective_without_policies_is_package() {
        let vendor = vec![signal("tp.a", 4), signal("tp.b", 7)];
        let catalog = Catalog::effective(&vendor, None, None);
        assert_eq!(catalog.thresholds, Thresholds::default());
        assert_eq!(catalog.signals.len(), 2);
        for e in &catalog.signals {
            assert_eq!(e.source, None);
            assert_eq!(e.base.as_ref(), Some(&e.signal));
        }
        // По возрастанию идентификатора.
        assert_eq!(catalog.signals[0].signal.id.as_str(), "tp.a");
        assert_eq!(
            catalog
                .get(&SignalId::new("tp.b").expect("id"))
                .map(|e| e.signal.weight),
            Some(7)
        );
        assert!(
            catalog
                .get(&SignalId::new("tp.none").expect("id"))
                .is_none()
        );
    }

    #[test]
    fn effective_levels() {
        let tenant = TenantId::new();
        let org_level = RiskLevel::Org(tenant);
        let vendor = vec![signal("tp.a", 6)];
        // Установка меняет как угодно — вплоть до 0 (признак не влияет на балл, но попадает в hits).
        let mut inst = RiskPolicy::default();
        inst.overrides.insert(
            SignalId::new("tp.a").expect("id"),
            SignalOverride {
                weight: Some(0),
                ..SignalOverride::default()
            },
        );
        let catalog = Catalog::effective(&vendor, Some(&inst), None);
        let a = catalog.get(&SignalId::new("tp.a").expect("id")).expect("a");
        assert_eq!(
            (a.signal.weight, a.source),
            (0, Some(RiskLevel::Installation))
        );
        let verdict = Verdict::from_fired(&catalog, &[fired(&a.signal, 100)]);
        assert_eq!(verdict.score, 0, "вес 0 — не влияет на балл");
        assert_eq!(verdict.hits.len(), 1, "но попадает в hits");
        assert_eq!(verdict.action, RiskAction::None);

        // Организация — только ужесточить: вес выше установки, действие строже, Enforce вместо Report.
        let mut org = RiskPolicy::default();
        org.overrides.insert(
            SignalId::new("tp.a").expect("id"),
            SignalOverride {
                weight: Some(9),
                action: Some(RiskAction::Junk),
                ..SignalOverride::default()
            },
        );
        let catalog = Catalog::effective(&vendor, Some(&inst), Some((org_level, &org)));
        let a = catalog.get(&SignalId::new("tp.a").expect("id")).expect("a");
        assert_eq!(
            (a.signal.weight, a.signal.action, a.source),
            (9, RiskAction::Junk, Some(org_level))
        );

        // Признаки администратора обоих уровней; организация перекрывает установку.
        let inst = RiskPolicy {
            signals: vec![admin_signal("org.x", 2)],
            ..Default::default()
        };
        let org = RiskPolicy {
            signals: vec![admin_signal("org.x", 5), admin_signal("org.y", 3)],
            ..Default::default()
        };
        let catalog = Catalog::effective(&[], Some(&inst), Some((org_level, &org)));
        assert_eq!(catalog.signals.len(), 2);
        let x = catalog
            .get(&SignalId::new("org.x").expect("id"))
            .expect("x");
        let y = catalog
            .get(&SignalId::new("org.y").expect("id"))
            .expect("y");
        assert_eq!(x.signal.weight, 5);
        assert_eq!(x.source, Some(org_level));
        assert_eq!(y.source, Some(org_level));
        assert_eq!(x.base, None, "признак администратора — без пакета");
    }

    #[test]
    fn validate_org_only_tightens() {
        let tenant = TenantId::new();
        let vendor = vec![signal("tp.a", 6)];
        let base = Catalog::effective(&vendor, None, None);
        // Установка — любые значения.
        let mut any = RiskPolicy::default();
        any.overrides.insert(
            SignalId::new("tp.a").expect("id"),
            SignalOverride {
                weight: Some(0),
                action: Some(RiskAction::None),
                mode: Some(Mode::Report),
            },
        );
        assert_eq!(
            any.validate(&base, RiskLevel::Installation),
            Ok(()),
            "установка смягчает как угодно"
        );
        // Организация: вес ниже, действие мягче, Report вместо Enforce — Invalid с полями.
        let cases = [
            SignalOverride {
                weight: Some(5),
                ..SignalOverride::default()
            },
            SignalOverride {
                action: Some(RiskAction::None),
                ..SignalOverride::default()
            },
            SignalOverride {
                mode: Some(Mode::Report),
                ..SignalOverride::default()
            },
        ];
        for o in cases {
            let mut org = RiskPolicy::default();
            org.overrides.insert(SignalId::new("tp.a").expect("id"), o);
            let err = org
                .validate(&base, RiskLevel::Org(tenant))
                .expect_err("смягчение");
            let Error::Invalid(msg) = err else {
                panic!("не Invalid: {err:?}");
            };
            assert!(msg.contains("tp.a"), "{msg}");
        }
        // Жёстче — можно: вес выше, действие строже, Enforce.
        let mut org = RiskPolicy::default();
        org.overrides.insert(
            SignalId::new("tp.a").expect("id"),
            SignalOverride {
                weight: Some(100),
                action: Some(RiskAction::Reject),
                mode: Some(Mode::Enforce),
            },
        );
        assert_eq!(org.validate(&base, RiskLevel::Org(tenant)), Ok(()));
        // База — с политикой установки: ниже установки нельзя, выше установки (но мягче пакета) — можно?
        // Нет: вес не ниже действующего значения уровней ниже.
        let mut inst = RiskPolicy::default();
        inst.overrides.insert(
            SignalId::new("tp.a").expect("id"),
            SignalOverride {
                weight: Some(20),
                ..SignalOverride::default()
            },
        );
        let base = Catalog::effective(&vendor, Some(&inst), None);
        let mut org = RiskPolicy::default();
        org.overrides.insert(
            SignalId::new("tp.a").expect("id"),
            SignalOverride {
                weight: Some(19),
                ..SignalOverride::default()
            },
        );
        let err = org
            .validate(&base, RiskLevel::Org(tenant))
            .expect_err("ниже установки");
        let Error::Invalid(msg) = err else {
            panic!("не Invalid: {err:?}");
        };
        assert!(
            msg.contains("weight") && msg.contains("19") && msg.contains("20"),
            "{msg}"
        );
        // Изменение признака, которого нет в пакете, — не ошибка («осиротевшее»).
        let mut orphan = RiskPolicy::default();
        orphan.overrides.insert(
            SignalId::new("tp.gone").expect("id"),
            SignalOverride {
                weight: Some(1),
                ..SignalOverride::default()
            },
        );
        assert_eq!(orphan.validate(&base, RiskLevel::Org(tenant)), Ok(()));
        // Структурные проверки: изменение поверх признака администратора, вес выше предела, повторы.
        let mut bad = RiskPolicy::default();
        bad.overrides.insert(
            SignalId::new("org.x").expect("id"),
            SignalOverride::default(),
        );
        assert!(matches!(bad.check(), Err(Error::Invalid(_))));
        let mut bad = RiskPolicy::default();
        bad.overrides.insert(
            SignalId::new("tp.a").expect("id"),
            SignalOverride {
                weight: Some(MAX_WEIGHT + 1),
                ..SignalOverride::default()
            },
        );
        assert!(matches!(bad.check(), Err(Error::Invalid(_))));
        let bad = RiskPolicy {
            signals: vec![admin_signal("org.x", 1), admin_signal("org.x", 2)],
            ..Default::default()
        };
        assert!(matches!(bad.check(), Err(Error::Invalid(_))));
    }

    #[test]
    fn apply_update_stalwart_model() {
        let a = SignalId::new("tp.a").expect("id");
        let b = SignalId::new("tp.b").expect("id");
        let c = SignalId::new("tp.c").expect("id");
        // Действующий каталог: признак a с изменением администратора, признак b без изменений.
        let mut policy = RiskPolicy::default();
        policy.overrides.insert(
            a.clone(),
            SignalOverride {
                weight: Some(9),
                ..SignalOverride::default()
            },
        );
        let old = Catalog::effective(&[signal("tp.a", 6), signal("tp.b", 3)], Some(&policy), None);
        // Новый пакет: a (изменён вес пакета), c (новый), b удалён.
        let mut new_vendor = vec![
            signal("tp.a", 7),
            Signal {
                mode: Mode::Enforce,
                ..signal("tp.c", 2)
            },
        ];
        let report = Catalog::apply_update(&old, &mut new_vendor);
        assert_eq!(report.added, [&c]);
        assert_eq!(report.removed, [&b], "b без изменений администратора");
        assert_eq!(report.changed, [&a], "пакет изменил вес");
        assert!(
            report.orphaned_overrides.is_empty(),
            "a остался в пакете: {report:?}"
        );
        // Новый признак — Mode::Report, оставшийся — как в пакете.
        assert_eq!(
            new_vendor.iter().find(|s| s.id == c).expect("c").mode,
            Mode::Report
        );
        assert_eq!(
            new_vendor.iter().find(|s| s.id == a).expect("a").mode,
            Mode::Enforce
        );
        // Признак с изменением администратора удалён — осиротевшее изменение.
        let old_with_b_override = {
            let mut p = policy.clone();
            p.overrides.insert(
                b.clone(),
                SignalOverride {
                    weight: Some(9),
                    ..SignalOverride::default()
                },
            );
            Catalog::effective(&[signal("tp.a", 6), signal("tp.b", 3)], Some(&p), None)
        };
        let mut new_vendor = vec![signal("tp.a", 6)];
        let report = Catalog::apply_update(&old_with_b_override, &mut new_vendor);
        assert_eq!(report.removed, Vec::<SignalId>::new());
        assert_eq!(report.orphaned_overrides, [&b]);
        // Изменение администратора переживает обновление: каталог после обновления с той же политикой.
        let updated = Catalog::effective(&new_vendor, Some(&policy), None);
        let a_effective = updated.get(&a).expect("a");
        assert_eq!(
            (a_effective.signal.weight, a_effective.source),
            (9, Some(RiskLevel::Installation)),
            "изменение администратора переживает обновление"
        );
    }

    #[test]
    fn verdict_from_fired_and_combine() {
        let mut vendor = vec![signal("tp.a", 4), signal("tp.b", 20)];
        // Собственное действие у a — карантин; b — только балл.
        vendor[0].action = RiskAction::Quarantine;
        // c — «только отчёт» с большим весом.
        vendor.push(Signal {
            mode: Mode::Report,
            weight: 90,
            ..signal("tp.c", 90)
        });
        // d — не срабатывает: сила ниже порога.
        vendor.push(Signal {
            threshold: 80,
            weight: 50,
            ..signal("tp.d", 50)
        });
        let catalog = Catalog::effective(&vendor, None, None);
        let by_id = |id: &str| {
            catalog
                .get(&SignalId::new(id).expect("id"))
                .expect("signal")
                .signal
                .clone()
        };
        let fired_hits = [
            fired(&by_id("tp.a"), 60),
            fired(&by_id("tp.b"), 100),
            fired(&by_id("tp.c"), 100),
            fired(&by_id("tp.d"), 79),
        ];
        let mut verdict = Verdict::from_fired(&catalog, &fired_hits);
        // a + b = 24; c (Report) балл не меняет; d не сработал.
        assert_eq!(verdict.score, 24);
        assert_eq!(verdict.hits.len(), 2);
        assert_eq!(verdict.report_only.len(), 1, "Report — только журнал");
        assert_eq!(verdict.report_only[0].signal.as_str(), "tp.c");
        // Действие: max(по баллу 24 ≥ reject 15 → Reject, собственное a — Quarantine) = Reject.
        assert_eq!(verdict.action, RiskAction::Reject);
        assert!(!verdict.drops_reply, "детекторы беседы не сработали");

        // combine: самое строгое из действия вердикта и Rspamd.
        assert_eq!(verdict.combine(RiskAction::Junk), RiskAction::Reject);
        assert_eq!(verdict.action, RiskAction::Reject);
        let mut mild = Verdict::from_fired(&catalog, &[]);
        assert_eq!(mild.score, 0);
        assert_eq!(mild.action, RiskAction::None);
        assert_eq!(mild.combine(RiskAction::Junk), RiskAction::Junk);
        assert_eq!(mild.action, RiskAction::Junk);

        // drops_reply: сработал признак беседы.
        let mut thread_signal = signal("tp.reply_to_changed", 1);
        thread_signal.detector = Detector::ReplyToChanged;
        let catalog = Catalog::effective(&[thread_signal.clone()], None, None);
        let verdict = Verdict::from_fired(&catalog, &[fired(&thread_signal, 100)]);
        assert!(verdict.drops_reply);

        // Sieve-источник срабатывания и сила ниже порога.
        let mut strict = signal("tp.strict", 3);
        strict.threshold = 80;
        let catalog = Catalog::effective(&[strict.clone()], None, None);
        let verdict = Verdict::from_fired(
            &catalog,
            &[Fired {
                signal: strict,
                strength: 80,
                source: HitSource::Sieve,
            }],
        );
        assert_eq!(verdict.hits.len(), 1);
        assert_eq!(verdict.hits[0].source, HitSource::Sieve);
        assert_eq!(
            serde_json::to_string(&HitSource::Sieve).expect("json"),
            "\"sieve\""
        );
    }

    fn source(id: &str, tier: Tier, kind: SourceKind, origin: TiOrigin) -> TiSource {
        TiSource {
            id: SourceId::new(id).expect("id"),
            tier,
            kind,
            format: FeedFormat::Txt,
            ttl: Duration::from_secs(3600),
            stale: StaleAction::default(),
            license: License {
                terms_url: "https://feed.example/terms".to_owned(),
                attribution: Some("© feed.example".to_owned()),
                commercial: true,
            },
            tenants: Tenants::All,
            key: None,
            auth: HttpAuth::None,
            origin,
        }
    }

    #[test]
    fn ti_source_tiers() {
        // Хорошие источники уровней.
        assert!(
            source(
                "feodo",
                Tier::Bundled,
                SourceKind::Http {
                    url: "https://feodo.tracker.abuse.ch/downloads/ipblocklist.json".to_owned()
                },
                TiOrigin::Vendor,
            )
            .validate()
            .is_ok(),
            "Feodo Tracker — CC0, в поставке можно"
        );
        assert!(
            source("own", Tier::Import, SourceKind::File, TiOrigin::Own,)
                .validate()
                .is_ok()
        );
        // Ключ заказчика: российские фиды — можно (не раздаём).
        assert!(
            source(
                "kaspersky-tip",
                Tier::CustomerKey,
                SourceKind::Taxii {
                    api_root: "https://taxii.tip.kaspersky.com/v2".to_owned(),
                    collection: "malicious_url".to_owned(),
                },
                TiOrigin::Vendor,
            )
            .validate()
            .is_ok()
        );
        // Bundled с запрещённым хостом — Invalid (в том числе Kaspersky TAXII и RST).
        for (id, url) in [
            ("openphish", "https://openphish.com/feed.txt"),
            ("kaspersky", "https://taxii.tip.kaspersky.com/v2"),
            ("rst", "https://api.rstcloud.net/v1/ip?type=csv"),
            ("subdomain", "https://feeds.tip.kaspersky.com/latest.json"),
        ] {
            let bad = source(
                id,
                Tier::Bundled,
                SourceKind::Http {
                    url: url.to_owned(),
                },
                TiOrigin::Vendor,
            );
            let err = bad.validate().expect_err("запрещён к поставке");
            assert!(matches!(err, Error::Invalid(_)), "{err:?}");
        }
        // Bundled: некоммерческая лицензия и ГосСОПКА/ФинЦЕРТ — Invalid.
        let mut bad = source(
            "phishing-database",
            Tier::Bundled,
            SourceKind::Http {
                url: "https://phishing.example/feed.txt".to_owned(),
            },
            TiOrigin::Vendor,
        );
        bad.license.commercial = false;
        assert!(matches!(bad.validate(), Err(Error::Invalid(_))));
        for origin in [TiOrigin::GosSopka, TiOrigin::FinCert] {
            let bad = source("gossopka", Tier::Bundled, SourceKind::File, origin);
            assert!(
                matches!(bad.validate(), Err(Error::Invalid(_))),
                "{origin:?}"
            );
        }
        // Import ГосСОПКА/ФинЦЕРТ без Only — Invalid; с Only — можно; прочие импорты — с All можно.
        for origin in [TiOrigin::GosSopka, TiOrigin::FinCert] {
            let bad = source("import", Tier::Import, SourceKind::File, origin);
            assert!(
                matches!(bad.validate(), Err(Error::Invalid(_))),
                "{origin:?}"
            );
            let ok = TiSource {
                tenants: Tenants::Only(vec![TenantId::new()]),
                ..source("import", Tier::Import, SourceKind::File, origin)
            };
            assert_eq!(ok.validate(), Ok(()), "{origin:?}");
        }
        assert!(
            source("own", Tier::Import, SourceKind::File, TiOrigin::Own)
                .validate()
                .is_ok(),
            "своё TI — без ограничений организаций"
        );
        // «Отключить» нет: только Reduce (по умолчанию 50%) и Report.
        assert_eq!(
            StaleAction::default(),
            StaleAction::Reduce {
                percent: DEFAULT_STALE_REDUCE_PERCENT
            }
        );
        let bad = TiSource {
            stale: StaleAction::Reduce { percent: 101 },
            ..source("over", Tier::Import, SourceKind::File, TiOrigin::Own)
        };
        assert!(matches!(bad.validate(), Err(Error::Invalid(_))));
        // Структурные проверки: пустые адрес и колонка, пустой Only, нулевой TTL.
        let bad = TiSource {
            kind: SourceKind::Http { url: String::new() },
            ..source("empty", Tier::Import, SourceKind::File, TiOrigin::Own)
        };
        assert!(matches!(bad.validate(), Err(Error::Invalid(_))));
        let bad = TiSource {
            format: FeedFormat::Csv {
                column: String::new(),
            },
            ..source("csv", Tier::Import, SourceKind::File, TiOrigin::Own)
        };
        assert!(matches!(bad.validate(), Err(Error::Invalid(_))));
        let bad = TiSource {
            tenants: Tenants::Only(Vec::new()),
            ..source("only", Tier::Import, SourceKind::File, TiOrigin::Own)
        };
        assert!(matches!(bad.validate(), Err(Error::Invalid(_))));
        let bad = TiSource {
            ttl: Duration::ZERO,
            ..source("ttl", Tier::Import, SourceKind::File, TiOrigin::Own)
        };
        assert!(matches!(bad.validate(), Err(Error::Invalid(_))));
    }

    #[test]
    fn forbidden_list_and_hosts() {
        assert!(FORBIDDEN_BUNDLED.contains(&"taxii.tip.kaspersky.com"));
        assert!(FORBIDDEN_BUNDLED.contains(&"rstcloud.net"));
        assert!(forbidden_bundled("api.rstcloud.net"));
        assert!(forbidden_bundled("TAXII.TIP.KASPERSKY.COM"));
        assert!(forbidden_bundled("feed.tip.kaspersky.com"));
        assert!(!forbidden_bundled("kaspersky.example.org"));
        assert!(!forbidden_bundled("notrstcloud.net.example"));
        // Хост из адреса: схема, порт, путь, userinfo и IPv6-скобки убираются.
        assert_eq!(
            url_host("https://feed.example.org:8443/path?q=1"),
            Some("feed.example.org")
        );
        assert_eq!(
            url_host("https://user@feed.example.org/"),
            Some("feed.example.org")
        );
        assert_eq!(url_host("http://[2001:db8::1]:8080/x"), Some("2001:db8::1"));
        assert_eq!(url_host("feed.example.org"), Some("feed.example.org"));
        assert_eq!(url_host("https://"), None);
    }

    #[test]
    fn semver_and_manifest() {
        let v = Semver::new(1, 2, 3);
        assert_eq!(v.to_string(), "1.2.3");
        assert_eq!("1.2.3".parse::<Semver>(), Ok(v));
        assert!(Semver::new(1, 2, 3) < Semver::new(1, 3, 0));
        assert!(Semver::new(2, 0, 0) > Semver::new(1, 99, 99));
        for bad in ["1.2", "1.2.x", "1.2.3.4", ""] {
            assert!(bad.parse::<Semver>().is_err(), "{bad:?}");
        }
        assert_eq!(
            serde_json::to_string(&v).expect("json"),
            "\"1.2.3\"",
            "в JSON — строка"
        );
        let back: Semver = serde_json::from_str("\"1.2.3\"").expect("parse");
        assert_eq!(back, v);

        let manifest = PackageManifest {
            format: PACKAGE_FORMAT,
            version: 4,
            created: OffsetDateTime::UNIX_EPOCH,
            min_node: Semver::new(0, 1, 0),
            key_id: "vendor-2026".to_owned(),
            signals: vec![signal("tp.a", 4)],
            lists: vec![ListFile {
                id: ListId::new("feodo-ip").expect("list"),
                path: "lists/feodo-ip.txt".to_owned(),
                sha256: BlobHash([1u8; 32]),
                entries: 1200,
                kind: ListKind::Ip,
                source: SourceId::new("feodo").expect("source"),
            }],
            samples: vec![SampleFile {
                path: "samples/emotet.eml".to_owned(),
                sha256: BlobHash([2u8; 32]),
                expect: vec![SignalId::new("tp.a").expect("id")],
            }],
        };
        manifest.validate().expect("valid");
        let json = serde_json::to_string(&manifest).expect("json");
        assert!(json.contains("\"min_node\":\"0.1.0\""), "{json}");
        let back: PackageManifest = serde_json::from_str(&json).expect("parse");
        assert_eq!(back, manifest);
        // Формат, повторы, недопустимые признаки и пути.
        assert!(matches!(
            PackageManifest {
                format: 2,
                ..manifest.clone()
            }
            .validate(),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            PackageManifest {
                signals: vec![signal("tp.a", 1), signal("tp.a", 2)],
                ..manifest.clone()
            }
            .validate(),
            Err(Error::Invalid(_))
        ));
        assert!(
            matches!(
                PackageManifest {
                    signals: vec![admin_signal("org.x", 1)],
                    ..manifest.clone()
                }
                .validate(),
                Err(Error::Invalid(_))
            ),
            "в пакете — признаки поставщика"
        );
        assert!(matches!(
            PackageManifest {
                samples: vec![SampleFile {
                    path: String::new(),
                    sha256: BlobHash([2u8; 32]),
                    expect: Vec::new(),
                }],
                ..manifest
            }
            .validate(),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn hits_query_and_event() {
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time");
        let id = SignalId::new("tp.a").expect("id");
        let rec = |at| HitRecord {
            tenant: TenantId::DEFAULT,
            message: BlobHash([7u8; 32]),
            signal: id.clone(),
            strength: 90,
            weight: 4,
            mode: Mode::Enforce,
            at,
        };
        let r = rec(at);
        assert!(HitsQuery::all(10).validate().is_ok());
        assert!(HitsQuery::all(10).matches(&r));
        let mut q = HitsQuery::all(10);
        q.signal = Some(id);
        assert!(q.matches(&r));
        q.signal = Some(SignalId::new("tp.b").expect("id"));
        assert!(!q.matches(&r));
        let mut q = HitsQuery::all(10);
        q.message = Some(BlobHash([7u8; 32]));
        assert!(q.matches(&r));
        q.message = Some(BlobHash([8u8; 32]));
        assert!(!q.matches(&r));
        let mut q = HitsQuery::all(10);
        q.since = Some(at);
        q.until = Some(at + time::Duration::SECOND);
        assert!(q.matches(&r) && q.validate().is_ok());
        q.until = Some(at);
        assert!(!q.matches(&r) && q.validate().is_err());
        assert!(matches!(
            HitsQuery::all(0).validate(),
            Err(Error::Invalid(_))
        ));
        // Сигнал risk_changed — системный.
        let e = risk_changed();
        assert_eq!(e.tenant, TenantId::DEFAULT);
        assert_eq!(e.account, None);
        assert!(e.kind.is_system());
        assert_eq!(e.kind, EventKind::RiskChanged);
    }
}
