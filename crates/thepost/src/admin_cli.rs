//! `thepost admin <ресурс> <действие>` — CLI Admin API (APP-11, SRS 5.2): интерфейс без собственной логики поверх
//! общего клиента [`tp_admin_client`] (решение 118, ADM-44).
//!
//! - Адрес — `--url`, иначе `THEPOST_ADMIN_URL`, иначе `http.admin.listen` из config.yaml (`allow_plaintext` — `http`,
//!   иначе `https`; сертификат на другое имя — `--ca-file` или `--insecure`).
//! - Вход — `Authorization: Bearer`: сессия Admin API (`tps_…`) или токен OIDC; значение — `THEPOST_ADMIN_TOKEN`
//!   (или `--token`, но ключ виден в списке процессов). Сессию выдаёт [`ApiAction::Login`] — вход по паролю
//!   администратора (`POST /api/v1/session`, решение 117): пароль — из терминала без эха или `--password-stdin`,
//!   не из аргумента; `--oidc` — вход у поставщика `auth.oidc` с устройства (RFC 8628, клиент — `cli.oidc`).
//!   Одноразовый токен `admin init` (`tpa_…`) клиент не принимает.
//! - Организация — `--org`, иначе `THEPOST_ADMIN_ORG`, иначе организация администратора (`GET /api/v1/whoami`).
//! - Вывод — таблица или ответ API (`--json`); и то и другое — из типизированного ответа tp-admin. Подсветка —
//!   [`tp_admin_client::style`] (решение 120, ADM-46): `--color auto|always|never`, в файл и конвейер — без ESC;
//!   данные — в stdout, ошибки и подсказки — в stderr.
//!
//! Команды проверяются против роутера tp-admin.

use std::io::Write as _;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Subcommand};
use reqwest::Url;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tp_admin::AdminRole;
use tp_admin::accounts::{
    AccountInfo, AccountPatch, AccountQuery, NewAccount, Organization, Policies, PolicyBody,
};
use tp_admin::app_passwords::{AppPasswordInfo, IssuedAppPassword, NewAppPassword};
use tp_admin::audit::{AuditPage, AuditParams};
use tp_admin::branding::{BrandingBody, BrandingView};
use tp_admin::delivery::{DeliveryParams, DeliveryResults};
use tp_admin::groups::{GroupInfo, GroupPatch, NewGroup};
use tp_admin::resources::{NewResource, ResourceInfo, ResourcePatch, ResourceTypeBody};
use tp_admin::retention::{PageQuery, RestoredMessage, TrashPage};
use tp_admin::risk::{
    HitsView, ListVersionView, NewTiSourceBody, PackageEntryView, PackageReportView, PackagesView,
    SignalBody, SignalView, SignalsView, SourcesView, ThresholdsBody, ThresholdsView, TiSourceBody,
    TiSourceView, UsageView,
};
use tp_admin::server::WhoAmI;
use tp_admin::sieve::{Script, ScriptBody, ScriptText, VacationBody};
use tp_admin::threads::{
    ThreadFindParams, ThreadHoldBody, ThreadHoldView, ThreadHoldsView, ThreadView,
};
use tp_admin::transport::{
    DomainBody, DomainList, DomainWritten, RouteBody, RouteList, SourceBody, SourceList,
    VersionQuery, Written,
};
use tp_admin::trust::{TrustBody, TrustView};
use tp_admin_client::oidc::{DeviceLogin, DeviceSettings, prompt_text};
use tp_admin_client::ops::*;
use tp_admin_client::style::{self, ColorChoice, Theme, value_text};
use tp_admin_client::{
    Client, DEFAULT_TIMEOUT_SECS, ENV_ORG, ENV_TOKEN, ENV_URL, NO_BODY, Options, query, setting,
};
use tp_contracts::branding::{BrandColor, CliRole, Role};
use tp_contracts::groups::{GroupMember, SenderRestriction};
use tp_contracts::journal::JournalScope;
use tp_contracts::transport::{
    AcceptedDomain, DestinationPolicy, DomainKind, SourceKind, SourceMatch, TlsRequirement,
    TrustedSource,
};
use tp_contracts::trust::{PeerKind, TrustFunction};
use tp_contracts::{AccountId, DomainId, GroupId};

use crate::sections::{self, AUTH, AuthSection, CLI, CliOidc, CliSection, HTTP, HttpSection};

/// Подключение к Admin API (общие ключи `thepost admin`; `admin init` их не использует).
#[derive(Debug, Clone, Args)]
pub struct ApiArgs {
    /// Адрес Admin API (по умолчанию — THEPOST_ADMIN_URL или http.admin.listen из config.yaml).
    #[arg(long, global = true)]
    pub url: Option<String>,
    /// Токен: сессия tps_… или токен OIDC (по умолчанию — THEPOST_ADMIN_TOKEN; ключ виден в списке процессов).
    #[arg(long, global = true)]
    pub token: Option<String>,
    /// Организация, UUID (по умолчанию — THEPOST_ADMIN_ORG или организация администратора).
    #[arg(long, global = true)]
    pub org: Option<String>,
    /// Вывод — ответ Admin API в JSON.
    #[arg(long, global = true)]
    pub json: bool,
    /// Корневые сертификаты (PEM) для проверки TLS Admin API.
    #[arg(long, global = true)]
    pub ca_file: Option<PathBuf>,
    /// Не проверять сертификат TLS (как curl -k) — только для loopback узла с сертификатом на другое имя.
    #[arg(long, global = true)]
    pub insecure: bool,
    /// Предельное время запроса, секунд.
    #[arg(long, global = true, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub timeout: u64,
    /// Цвет вывода: auto — только на терминал (учитывает NO_COLOR, CLICOLOR_FORCE, TERM=dumb), always, never.
    #[arg(long, global = true, value_enum, default_value_t = ColorArg::Auto)]
    pub color: ColorArg,
}

/// Значение `--color`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorArg {
    /// Цвет — только на терминал.
    Auto,
    /// Всегда.
    Always,
    /// Никогда.
    Never,
}

impl ColorArg {
    fn choice(self) -> ColorChoice {
        match self {
            Self::Auto => ColorChoice::Auto,
            Self::Always => ColorChoice::Always,
            Self::Never => ColorChoice::Never,
        }
    }
}

impl Default for ApiArgs {
    fn default() -> Self {
        Self {
            url: None,
            token: None,
            org: None,
            json: false,
            ca_file: None,
            insecure: false,
            timeout: DEFAULT_TIMEOUT_SECS,
            // Вызов из кода (тесты) — текст без ESC; из командной строки — `--color`, по умолчанию auto.
            color: ColorArg::Never,
        }
    }
}

impl ApiArgs {
    /// Оформление stdout (данные).
    fn theme(&self) -> Theme {
        Theme::stdout(self.color.choice())
    }

    /// Оформление stderr (ошибки и подсказки).
    fn err_theme(&self) -> Theme {
        Theme::stderr(self.color.choice())
    }

    /// Канал к Admin API по `--ca-file`, `--insecure` (с предупреждением в stderr) и `--timeout`.
    fn options(&self) -> Options {
        if self.insecure {
            eprintln!("thepost: admin: сертификат TLS Admin API не проверяется (--insecure)");
        }
        Options {
            ca_file: self.ca_file.clone(),
            insecure: self.insecure,
            timeout: Duration::from_secs(self.timeout),
        }
    }
}

/// Команды Admin API.
#[derive(Debug, Clone, Subcommand)]
pub enum ApiAction {
    /// Вход администратора по паролю — сессия Admin API (tps_…); пароль — из терминала без эха или --password-stdin.
    /// --oidc — вход у поставщика OIDC с устройства.
    Login {
        /// Имя входа администратора (адрес; пароль — каталога или выданный thepost admin init).
        #[arg(long, required_unless_present = "oidc", conflicts_with = "oidc")]
        user: Option<String>,
        /// Пароль — первой строкой stdin (сценарии), а не из терминала.
        #[arg(long, conflicts_with = "oidc")]
        password_stdin: bool,
        /// Вход у поставщика auth.oidc с устройства (RFC 8628, клиент — cli.oidc): адрес и код — в stderr, токен
        /// OIDC — строкой в stdout, без записи в историю оболочки:
        /// export THEPOST_ADMIN_TOKEN="$(thepost admin login --oidc)".
        #[arg(long)]
        oidc: bool,
    },
    /// Текущий администратор и его роли.
    Whoami,
    /// Учётные записи.
    Account {
        /// Действие.
        #[command(subcommand)]
        action: Box<AccountAction>,
    },
    /// Пароли приложений учётной записи (IMAP, SMTP, JMAP).
    AppPassword {
        /// Действие.
        #[command(subcommand)]
        action: AppPasswordAction,
    },
    /// Политика уровня (организация, домен, ящик): квота, сроки хранения, лимиты отправки.
    Policy {
        /// Действие.
        #[command(subcommand)]
        action: Box<PolicyAction>,
    },
    /// Группы рассылки организации.
    Group {
        /// Действие.
        #[command(subcommand)]
        action: Box<GroupAction>,
    },
    /// Ресурсы бронирования организации: переговорные и оборудование.
    Resources {
        /// Действие.
        #[command(subcommand)]
        action: Box<ResourceAction>,
    },
    /// Корзина учётной записи: просмотр и восстановление писем.
    Trash {
        /// Действие.
        #[command(subcommand)]
        action: TrashAction,
    },
    /// Журнал аудита Admin API.
    Audit {
        /// Действие.
        #[command(subcommand)]
        action: Box<AuditAction>,
    },
    /// Журнал доставки: поиск писем.
    Delivery {
        /// Действие.
        #[command(subcommand)]
        action: Box<DeliveryAction>,
    },
    /// Журнал переписки (роль «аудитор журнала»): поиск, запись, выгрузка .eml, проверка цепочки.
    Journal {
        /// Действие.
        #[command(subcommand)]
        action: Box<JournalAction>,
    },
    /// Беседы учётных записей: беседа письма, удержание (включая будущие письма) и выгрузка.
    Thread {
        /// Действие.
        #[command(subcommand)]
        action: Box<ThreadAction>,
    },
    /// Транспорт: принятые домены, доверенные источники, политики доменов назначения.
    Transport {
        /// Ресурс.
        #[command(subcommand)]
        action: Box<TransportAction>,
    },
    /// Правила Sieve учётной записи: просмотр, правка, включение и отключение за пользователя.
    Sieve {
        /// Действие.
        #[command(subcommand)]
        action: SieveAction,
    },
    /// Автоответ учётной записи: просмотр, включение и выключение за пользователя.
    Vacation {
        /// Действие.
        #[command(subcommand)]
        action: Box<VacationAction>,
    },
    /// Брендинг: название, основной цвет, роли цветов и знак (уровень установки; --org — организация).
    Branding {
        /// Действие.
        #[command(subcommand)]
        action: Box<BrandingAction>,
    },
    /// Политика доверия «кто — кому — что»: уровни установка → организация → группа, домены-партнёры
    /// (уровень установки — без ключей, организации — --org, группы — --group).
    Trust {
        /// Действие.
        #[command(subcommand)]
        action: Box<TrustAction>,
    },
    /// Признаки риска и TI: каталог и пороги уровней, пакеты поставщика, источники TI, срабатывания
    /// (пороги и признаки: установка — без ключей, организация — с --org; пакеты и источники — установка).
    Risk {
        /// Действие.
        #[command(subcommand)]
        action: Box<RiskAction>,
    },
}

/// Действия со справочником аномалий и TI.
#[derive(Debug, Clone, Subcommand)]
pub enum RiskAction {
    /// Каталог признаков: вес, действие, режим, источник значения; «осиротевшие» изменения — с пометкой.
    Signals {
        /// Действие.
        #[command(subcommand)]
        action: Box<SignalsAction>,
    },
    /// Пороги действий: баллы, с которых действуют действия (без --org — установка).
    Thresholds {
        /// Действие.
        #[command(subcommand)]
        action: Box<ThresholdsAction>,
    },
    /// Пакеты поставщика (администратор установки): список, загрузка файла, активация, откат.
    Package {
        /// Действие.
        #[command(subcommand)]
        action: Box<PackageAction>,
    },
    /// Источники TI (администратор установки): список, добавление, замена, удаление, импорт, обновление, учёт.
    Source {
        /// Действие.
        #[command(subcommand)]
        action: Box<RiskSourceAction>,
    },
    /// Журнал срабатываний организации (применённые и «только отчёт»).
    Hits(HitsArgs),
}

/// Действия с каталогом признаков.
#[derive(Debug, Clone, Subcommand)]
pub enum SignalsAction {
    /// Действующий каталог уровня (без --org — установка, с --org — организация).
    List,
    /// Изменение признака поставщика `tp.*` (вес, действие, режим; организация — только строже) или
    /// свой признак `org.*` (задаётся целиком).
    Set {
        /// Признак: `tp.encrypted_archive` или свой `org.rule-name`.
        id: String,
        /// Вес, 0–100.
        #[arg(long)]
        weight: Option<u16>,
        /// Собственное действие: none, tag, junk, quarantine, reject.
        #[arg(long)]
        action: Option<String>,
        /// Режим: report (только журнал), enforce (применять).
        #[arg(long)]
        mode: Option<String>,
        /// Детектор (только свой признак `org.*`): thread_new_attachment_type, encrypted_archive,
        /// disk_image_or_shortcut, thread_new_link_domain, reply_to_changed, list_match.
        #[arg(long)]
        detector: Option<String>,
        /// Порог силы срабатывания, 0–100 (только свой признак).
        #[arg(long)]
        threshold: Option<u8>,
    },
    /// Сброс изменения уровня (у пакета — значение пакета) или удаление своего признака `org.*`.
    Reset {
        /// Признак.
        id: String,
    },
}

/// Действия с порогами действий.
#[derive(Debug, Clone, Subcommand)]
pub enum ThresholdsAction {
    /// Пороги уровня: свои, действующие и уровень-источник.
    Show,
    /// Замена порогов уровня целиком (все четыре).
    Set {
        /// Балл пометки письма.
        #[arg(long)]
        tag: u32,
        /// Балл перемещения в «Спам».
        #[arg(long)]
        junk: u32,
        /// Балл карантина.
        #[arg(long)]
        quarantine: u32,
        /// Балл отказа.
        #[arg(long)]
        reject: u32,
    },
}

/// Действия с пакетами поставщика.
#[derive(Debug, Clone, Subcommand)]
pub enum PackageAction {
    /// Хранимые пакеты: активный и прошлые, по убыванию номера.
    List,
    /// Загрузка файла пакета (закрытый контур): проверка (подпись, пробный прогон) и постановка —
    /// без активации; отчёт — что изменится.
    Import {
        /// Файл пакета поставщика.
        file: PathBuf,
    },
    /// Активация поставленного пакета (номер строго больше действующего).
    Activate {
        /// Номер версии.
        version: u64,
    },
    /// Откат на хранимую версию.
    Rollback {
        /// Номер версии.
        version: u64,
    },
}

/// Действия с источниками TI.
#[derive(Debug, Clone, Subcommand)]
pub enum RiskSourceAction {
    /// Источники: уровень, доставка, формат, TTL, лицензия.
    List,
    /// Новый источник. Файл — JSON источника (`id`, `tier`, `kind`, `format`, `ttl`, …); ключ —
    /// `{"secret": "путь#поле"}`.
    Add {
        /// Файл с источником (JSON, UTF-8); `-` — stdin.
        #[arg(long, value_name = "ПУТЬ")]
        file: PathBuf,
    },
    /// Замена источника целиком. Файл — JSON параметров без идентификатора.
    Set {
        /// Источник.
        id: String,
        /// Файл с параметрами (JSON, UTF-8); `-` — stdin.
        #[arg(long, value_name = "ПУТЬ")]
        file: PathBuf,
    },
    /// Удаление источника.
    Rm {
        /// Источник.
        id: String,
    },
    /// Импорт файла списка источника (закрытый контур).
    Import {
        /// Источник.
        id: String,
        /// Файл списка (формат источника).
        file: PathBuf,
    },
    /// Обновление источника сейчас (коннектор узла).
    Refresh {
        /// Источник.
        id: String,
    },
    /// Учёт источника по организациям (MSSP): суммы обращений и совпадений.
    Usage {
        /// Источник.
        id: String,
        /// Учёт с этого момента (RFC 3339).
        #[arg(long)]
        since: Option<String>,
    },
}

/// Параметры журнала срабатываний.
#[derive(Debug, Clone, Args)]
pub struct HitsArgs {
    /// Только этот признак.
    #[arg(long)]
    pub signal: Option<String>,
    /// Режим: report — только отчёт, enforce — применённые.
    #[arg(long)]
    pub mode: Option<String>,
    /// Начало интервала (RFC 3339).
    #[arg(long)]
    pub since: Option<String>,
    /// Конец интервала (RFC 3339), не включительно.
    #[arg(long)]
    pub until: Option<String>,
    /// Не больше N записей.
    #[arg(long)]
    pub limit: Option<usize>,
}

/// Действия с политикой доверия.
#[derive(Debug, Clone, Subcommand)]
pub enum TrustAction {
    /// Политика уровня и действующая матрица; --account — действующая для учётной записи (с её группами).
    Show {
        /// Группа: идентификатор (UUID), имя или адрес (уровень группы в организации).
        #[arg(long)]
        group: Option<String>,
        /// Учётная запись: идентификатор (UUID) или имя входа (действующая политика).
        #[arg(long, conflicts_with = "group")]
        account: Option<String>,
    },
    /// Замена политики уровня целиком. Файл — JSON с клетками политики (`invite_new`, `itip_updates`,
    /// `auto_reply`, `mdn`, `auto_forward`, `freebusy`, `sharing`, `group_post`, у организации — `partners` и
    /// `auto_forward_domains`); клетки нет или null — наследуется уровнем выше.
    Set {
        /// Группа: идентификатор (UUID), имя или адрес.
        #[arg(long)]
        group: Option<String>,
        /// Файл с политикой (JSON, UTF-8); `-` — stdin.
        #[arg(long, value_name = "ПУТЬ")]
        file: PathBuf,
    },
    /// Сброс политики уровня — действуют уровень выше и умолчания.
    Reset {
        /// Группа: идентификатор (UUID), имя или адрес.
        #[arg(long)]
        group: Option<String>,
    },
    /// Домены-партнёры организации (уровень организации).
    Partners {
        /// Действие.
        #[command(subcommand)]
        action: PartnersAction,
    },
}

/// Действия с доменами-партнёрами.
#[derive(Debug, Clone, Subcommand)]
pub enum PartnersAction {
    /// Домены-партнёры организации.
    List,
    /// Замена списка доменов-партнёров перечисленными (без доменов — пусто). Свой принятый домен — 422.
    Set {
        /// Домены-партнёры (нижний регистр, A-label IDN).
        #[arg(value_name = "ДОМЕН")]
        domains: Vec<String>,
    },
}

/// Действия с брендингом.
#[derive(Debug, Clone, Subcommand)]
pub enum BrandingAction {
    /// Брендинг уровня: свой набор и действующий (без --org — установка, с --org — организация).
    Show,
    /// Изменение набора уровня: название, основной цвет и отдельные роли; остальное набора сохраняется.
    Set {
        /// Название продукта (1–64 символа).
        #[arg(long)]
        name: Option<String>,
        /// Основной цвет #RRGGBB — источник незаданных ролей бренда уровня.
        #[arg(long)]
        primary: Option<String>,
        /// Роль цвета: <тема>.<роль>=#RRGGBB (light.sel=#E3107F, dark.text=#161616, cli.head=#2A8BC4);
        /// повторяется. Темы — light, dark, cli; роли — design/tokens.toml.
        #[arg(long = "role", value_name = "ТЕМА.РОЛЬ=#RRGGBB")]
        role: Vec<String>,
    },
    /// Сброс набора уровня — действует брендинг уровня выше (организация — установки, установка — IT TASK).
    Reset,
    /// Знак уровня.
    Logo {
        /// Действие.
        #[command(subcommand)]
        action: LogoAction,
    },
}

/// Действия со знаком.
#[derive(Debug, Clone, Subcommand)]
pub enum LogoAction {
    /// Знак из файла PNG (до 256 КБ, до 1024×1024; без названия и цветов уровня тоже ставится).
    Set {
        /// Файл PNG.
        file: PathBuf,
    },
    /// Убрать знак уровня (название и цвета остаются).
    Reset,
}

/// Действия с учётными записями.
#[derive(Debug, Clone, Subcommand)]
pub enum AccountAction {
    /// Новая локальная учётная запись в принятом домене; пароль — `app-password create`.
    Create {
        /// Имя входа (адрес).
        login: String,
        /// Отображаемое имя (по умолчанию — имя входа).
        #[arg(long)]
        name: Option<String>,
    },
    /// Учётные записи по возрастанию имени входа (страницы Admin API — по ссылке Link rel="next"); --login — поиск одной.
    List {
        /// Поиск по имени входа (без учёта регистра); несовместимо с --prefix, --after и --limit.
        #[arg(long, conflicts_with_all = ["prefix", "after", "limit"])]
        login: Option<String>,
        /// Имя входа начинается с префикса (без учёта регистра).
        #[arg(long)]
        prefix: Option<String>,
        /// Продолжение после этого имени входа (из подсказки предыдущего вывода с --limit).
        #[arg(long, value_name = "ИМЯ_ВХОДА")]
        after: Option<String>,
        /// Не больше N записей (по умолчанию — все).
        #[arg(long, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        limit: Option<usize>,
    },
    /// Учётная запись по идентификатору или имени входа.
    Get {
        /// Идентификатор (UUID) или имя входа.
        account: String,
    },
    /// Блокировка входа локальной учётной записи: новый вход запрещён, открытые сеансы не разрываются.
    /// Запись каталога блокируется в каталоге (ответ 409).
    Block {
        /// Идентификатор (UUID) или имя входа.
        account: String,
    },
    /// Снятие блокировки входа локальной учётной записи.
    Unblock {
        /// Идентификатор (UUID) или имя входа.
        account: String,
    },
    /// Смена отображаемого имени локальной учётной записи (у записи каталога — 409).
    Rename {
        /// Идентификатор (UUID) или имя входа.
        account: String,
        /// Новое отображаемое имя (непустое, одна строка).
        name: String,
    },
    /// Псевдонимы и скрытие из книги «Организация» локальной учётной записи (у записи каталога — 409, их ведёт
    /// каталог). Нужен хотя бы один ключ.
    Set {
        /// Идентификатор (UUID) или имя входа.
        account: String,
        /// Псевдоним — адрес в принятом домене организации, не занятый учётной записью, группой или контактом (иначе
        /// 409). Ключ повторяется; заданные псевдонимы заменяют прежние.
        #[arg(long = "alias", value_name = "АДРЕС", conflicts_with = "no_aliases")]
        aliases: Vec<String>,
        /// Снять все псевдонимы.
        #[arg(long)]
        no_aliases: bool,
        /// Скрыть из книги «Организация» (`true`) или показать в ней (`false`); книга меняется не позже чем через
        /// `maintenance.gal_interval`.
        #[arg(long, value_name = "true|false")]
        hidden_from_gal: Option<bool>,
    },
}

/// Действия с паролями приложений.
#[derive(Debug, Clone, Subcommand)]
pub enum AppPasswordAction {
    /// Выпуск пароля: значение показывается один раз.
    Create {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
        /// Подпись («Телефон», «Thunderbird дома»).
        #[arg(long, default_value = "")]
        label: String,
    },
    /// Пароли учётной записи, включая отозванные (без значений).
    List {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
    },
    /// Отзыв пароля.
    Revoke {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
        /// Идентификатор пароля (из `app-password list`).
        id: String,
    },
}

/// Действия с политикой уровня; уровень — организация, `--domain` или `--account`.
#[derive(Debug, Clone, Subcommand)]
pub enum PolicyAction {
    /// Политика: заданное на уровне и действующее с учётом вышестоящих (организация → домен → ящик).
    Get {
        /// Уровень.
        #[command(flatten)]
        level: PolicyLevel,
    },
    /// Замена политики уровня целиком. Файл — JSON с полями политики (quota_bytes, trash_retention, retention,
    /// send_per_hour, rcpts_per_hour, max_recipients, dkim_selector, milter_profile, trash_purge, archive_after,
    /// archive_quota_bytes); поля нет или null — не задано на уровне.
    Set {
        /// Уровень.
        #[command(flatten)]
        level: PolicyLevel,
        /// Файл с политикой (JSON, UTF-8); `-` — stdin.
        #[arg(long, value_name = "ПУТЬ")]
        file: PathBuf,
    },
}

/// Уровень политики: без ключей — организация.
#[derive(Debug, Clone, Args)]
pub struct PolicyLevel {
    /// Принятый домен: идентификатор (UUID) или имя.
    #[arg(long, conflicts_with = "account")]
    pub domain: Option<String>,
    /// Учётная запись: идентификатор (UUID) или имя входа.
    #[arg(long)]
    pub account: Option<String>,
}

/// Действия с группами рассылки; группа — идентификатор (UUID), имя или адрес.
#[derive(Debug, Clone, Subcommand)]
pub enum GroupAction {
    /// Группы организации.
    List,
    /// Группа: адрес, участники, ограничение отправителей, модераторы.
    Get {
        /// Группа: идентификатор (UUID), имя или адрес.
        group: String,
    },
    /// Новая группа (не из каталога).
    Create {
        /// Отображаемое имя.
        name: String,
        /// Адрес рассылки (без адреса — группа только для вложения).
        #[arg(long)]
        address: Option<String>,
        /// Участник — учётная запись: идентификатор (UUID) или имя входа (можно повторять).
        #[arg(long = "account", value_name = "УЧЁТНАЯ_ЗАПИСЬ")]
        accounts: Vec<String>,
        /// Участник — вложенная группа: идентификатор (UUID), имя или адрес (можно повторять).
        #[arg(long = "group", value_name = "ГРУППА")]
        groups: Vec<String>,
    },
    /// Удаление группы (не из каталога); письма её очереди модерации отклоняются с уведомлением.
    Delete {
        /// Группа: идентификатор (UUID), имя или адрес.
        group: String,
    },
    /// Участники группы; --set — замена участников перечисленными (без --account и --group — пусто).
    Members {
        /// Группа: идентификатор (UUID), имя или адрес.
        group: String,
        /// Заменить участников (у группы каталога участников ведёт каталог — 400).
        #[arg(long)]
        set: bool,
        /// Участник — учётная запись: идентификатор (UUID) или имя входа (можно повторять).
        #[arg(long = "account", value_name = "УЧЁТНАЯ_ЗАПИСЬ", requires = "set")]
        accounts: Vec<String>,
        /// Участник — вложенная группа: идентификатор (UUID), имя или адрес (можно повторять).
        #[arg(long = "group", value_name = "ГРУППА", requires = "set")]
        groups: Vec<String>,
    },
}

/// Тип ресурса для `--type` и `set-type`: переговорная или оборудование.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ResourceTypeArg {
    /// Помещение (переговорная).
    Room,
    /// Оборудование.
    Equipment,
}

impl ResourceTypeArg {
    fn body(self) -> ResourceTypeBody {
        match self {
            Self::Room => ResourceTypeBody::Room,
            Self::Equipment => ResourceTypeBody::Equipment,
        }
    }
}

/// Тип ресурса по-русски: «помещение» или «оборудование».
fn resource_type_name(t: ResourceTypeBody) -> &'static str {
    match t {
        ResourceTypeBody::Room => "помещение",
        ResourceTypeBody::Equipment => "оборудование",
    }
}

/// Действия с ресурсами бронирования; ресурс — идентификатор (UUID) или имя входа.
#[derive(Debug, Clone, Subcommand)]
pub enum ResourceAction {
    /// Ресурсы организации по возрастанию имени входа: тип и правила бронирования.
    List,
    /// Новый ресурс: учётная запись в принятом домене организации и правила бронирования по умолчанию
    /// (автоматическое принятие без пересечений).
    Create {
        /// Имя входа — адрес в принятом домене организации.
        login: String,
        /// Отображаемое имя (по умолчанию — имя входа).
        #[arg(long)]
        name: Option<String>,
        /// Тип ресурса: room (переговорная, по умолчанию) или equipment (оборудование).
        #[arg(long = "type", value_enum, default_value_t = ResourceTypeArg::Room)]
        resource_type: ResourceTypeArg,
    },
    /// Смена типа ресурса (имя и правила бронирования не меняются; у ресурса из каталога — 409).
    SetType {
        /// Ресурс: идентификатор (UUID) или имя входа.
        resource: String,
        /// Новый тип: room (переговорная) или equipment (оборудование).
        resource_type: ResourceTypeArg,
    },
}

/// Действия с корзиной учётной записи.
#[derive(Debug, Clone, Subcommand)]
pub enum TrashAction {
    /// Письма корзины, новые первыми, и действующий срок корзины.
    List {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
        /// Скрытые письма («очистить корзину» с hide): пользователь их не видит.
        #[arg(long)]
        hidden: bool,
        /// Тема и отправитель писем: только администратору, запрос пишется в журнал аудита.
        #[arg(long)]
        subject: bool,
        /// Смещение от начала списка (из подсказки предыдущей страницы).
        #[arg(long, default_value_t = 0)]
        offset: usize,
        /// Размер страницы (по умолчанию и наибольший — из конфигурации узла).
        #[arg(long, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        limit: Option<usize>,
    },
    /// Восстановление письма в исходную папку (нет — во «Входящие») с тем же идентификатором.
    Restore {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
        /// Письмо (UUID, из `trash list`).
        message: String,
        /// Скрытое письмо (из `trash list --hidden`).
        #[arg(long)]
        hidden: bool,
    },
}

/// Действия с журналом аудита.
#[derive(Debug, Clone, Subcommand)]
pub enum AuditAction {
    /// Записи по возрастанию номера; условия — по «и», хотя бы одно обязательно.
    Search {
        /// Начало интервала, RFC 3339 (например, 2026-12-01T00:00:00Z), включительно.
        #[arg(long, value_name = "ВРЕМЯ")]
        since: Option<String>,
        /// Конец интервала, RFC 3339, не включительно.
        #[arg(long, value_name = "ВРЕМЯ")]
        until: Option<String>,
        /// Администратор: имя входа или UUID учётной записи.
        #[arg(long)]
        actor: Option<String>,
        /// Метод HTTP (PUT, POST, PATCH, DELETE).
        #[arg(long)]
        method: Option<String>,
        /// Начало шаблона маршрута: /api/v1/orgs/{org}/transport — все маршруты транспорта.
        #[arg(long)]
        route: Option<String>,
        /// Размер страницы (по умолчанию и наибольший — из конфигурации узла).
        #[arg(long, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        limit: Option<usize>,
        /// Продолжение: номер из подсказки предыдущей страницы.
        #[arg(long)]
        after: Option<u64>,
    },
}

/// Действия с журналом доставки.
#[derive(Debug, Clone, Subcommand)]
pub enum DeliveryAction {
    /// События по возрастанию времени; условия — по «и».
    Search {
        /// Отправитель конверта (точно, без учёта регистра).
        #[arg(long)]
        sender: Option<String>,
        /// Один из получателей (точно, без учёта регистра).
        #[arg(long)]
        recipient: Option<String>,
        /// Message-ID без угловых скобок.
        #[arg(long)]
        message_id: Option<String>,
        /// Начало интервала, RFC 3339 (например, 2026-12-01T00:00:00Z), включительно.
        #[arg(long, value_name = "ВРЕМЯ")]
        since: Option<String>,
        /// Конец интервала, RFC 3339, не включительно.
        #[arg(long, value_name = "ВРЕМЯ")]
        until: Option<String>,
        /// Размер страницы (по умолчанию и наибольший — из конфигурации узла).
        #[arg(long, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        limit: Option<usize>,
        /// Продолжение: позиция из подсказки предыдущей страницы (с теми же условиями).
        #[arg(long)]
        after: Option<String>,
    },
}

/// Действия с журналом переписки (SRS 4.9, 5.2; ADM-52): роль «аудитор журнала»; администраторам
/// организации и инсталляции содержимое журнала недоступно. Правила журналирования (ADM-53) —
/// администратор организации.
#[derive(Debug, Clone, Subcommand)]
pub enum JournalAction {
    /// Записи по возрастанию времени; условия — по «и».
    Search {
        /// Отправитель конверта (точно, без учёта регистра).
        #[arg(long)]
        sender: Option<String>,
        /// Один из получателей записи, включая скрытых (точно, без учёта регистра).
        #[arg(long)]
        recipient: Option<String>,
        /// Message-ID без угловых скобок.
        #[arg(long)]
        message_id: Option<String>,
        /// Правило журналирования.
        #[arg(long)]
        rule: Option<String>,
        /// Начало интервала, RFC 3339 (например, 2026-12-01T00:00:00Z), включительно.
        #[arg(long, value_name = "ВРЕМЯ")]
        since: Option<String>,
        /// Конец интервала, RFC 3339, не включительно.
        #[arg(long, value_name = "ВРЕМЯ")]
        until: Option<String>,
        /// Размер страницы (по умолчанию и наибольший — из конфигурации узла).
        #[arg(long, value_parser = clap::builder::RangedU64ValueParser::<usize>::new().range(1..))]
        limit: Option<usize>,
        /// Продолжение: позиция из подсказки предыдущей страницы (с теми же условиями).
        #[arg(long)]
        after: Option<String>,
    },
    /// Запись журнала: конверт и хеш цепочки.
    Get {
        /// Запись журнала: идентификатор (UUID, из `journal search`).
        id: String,
    },
    /// Выгрузка записи: .eml с конвертом — в файл `--output` или в stdout.
    Export {
        /// Запись журнала: идентификатор (UUID, из `journal search`).
        id: String,
        /// Файл для .eml (по умолчанию — stdout).
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },
    /// Отчёт целостности хеш-цепочки индекса журнала организации.
    Verify,
    /// Правила журналирования (ADM-53): администратор организации.
    Rule {
        /// Действие.
        #[command(subcommand)]
        action: Box<JournalRuleAction>,
    },
}

/// Действия с правилами журналирования (ADM-53, решение #171): цель — организация, группа или ящик,
/// направление In/Out/Both; изменение действует без перезапуска узла.
#[derive(Debug, Clone, Subcommand)]
pub enum JournalRuleAction {
    /// Правила в порядке наследования: ящик > группа > организация.
    List,
    /// Создать или заменить правило: цель — `--group` или `--account`, иначе вся организация.
    /// Изменение конвейер подхватывает без перезапуска.
    Set {
        /// Идентификатор правила (до 64 символов, без пробелов).
        id: String,
        /// Группа: идентификатор (UUID), имя или адрес.
        #[arg(long, conflicts_with = "account")]
        group: Option<String>,
        /// Ящик: идентификатор (UUID) или имя входа.
        #[arg(long)]
        account: Option<String>,
        /// Направление: входящее, исходящее или оба.
        #[arg(long, value_enum, default_value_t = DirectionArg::Both)]
        direction: DirectionArg,
        /// Создать или заменить правило выключенным (по умолчанию — включено).
        #[arg(long)]
        disabled: bool,
    },
    /// Удалить правило. Записи журнала не трогает: изменение действует на будущие письма.
    Delete {
        /// Идентификатор правила (из `journal rule list`).
        id: String,
    },
}

/// Направление правила журналирования для CLI (`in`, `out`, `both`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum DirectionArg {
    /// Доставляемое в ящики организации.
    In,
    /// Отправляемое клиентом.
    Out,
    /// Оба направления.
    Both,
}

impl From<DirectionArg> for tp_contracts::journal::JournalDirection {
    fn from(d: DirectionArg) -> Self {
        match d {
            DirectionArg::In => Self::In,
            DirectionArg::Out => Self::Out,
            DirectionArg::Both => Self::Both,
        }
    }
}

/// Действия с беседами (ADM-50): удержание целиком, включая будущие письма (как Google Vault), и выгрузка.
#[derive(Debug, Clone, Subcommand)]
pub enum ThreadAction {
    /// Беседа письма: удержание и письма в порядке привязки.
    Find {
        /// Учётная запись: имя входа или UUID.
        account: String,
        /// Письмо учётной записи (UUID, из `trash list`, `moderation` или `thread find`).
        #[arg(long, value_name = "UUID")]
        message_id: String,
    },
    /// Удерживает беседу: письма, включая будущие, не удаляются окончательно.
    Hold {
        /// Учётная запись: имя входа или UUID.
        account: String,
        /// Беседа (UUID, из `thread find`).
        thread: String,
        /// Основание (дело, требование, регламент).
        #[arg(long)]
        reason: String,
    },
    /// Снимает удержание: письма снова удаляются окончательно по сроку корзины.
    Unhold {
        /// Учётная запись: имя входа или UUID.
        account: String,
        /// Беседа (UUID, из `thread find`).
        thread: String,
    },
    /// Удержанные беседы организации: кто, когда и основание.
    Holds,
    /// Выгрузка беседы: письма .eml в архиве ZIP, включая удалённые в корзину и скрытые, — в файл или stdout.
    Export {
        /// Учётная запись: имя входа или UUID.
        account: String,
        /// Беседа (UUID, из `thread find`).
        thread: String,
        /// Файл для архива ZIP (по умолчанию — stdout).
        #[arg(long, short = 'o')]
        output: Option<PathBuf>,
    },
}

/// Ресурсы транспорта; каждая запись — по версии снимка последнего чтения (устарела — 409, повторите команду).
#[derive(Debug, Clone, Subcommand)]
pub enum TransportAction {
    /// Принятые домены организации.
    Domain {
        /// Действие.
        #[command(subcommand)]
        action: DomainAction,
    },
    /// Доверенные источники организации: шлюзы и приложения, отправляющие почту без входа.
    Source {
        /// Действие.
        #[command(subcommand)]
        action: SourceAction,
    },
    /// Политики доменов назначения: TLS, smart host, исходящий адрес.
    Route {
        /// Действие.
        #[command(subcommand)]
        action: RouteAction,
    },
}

/// Действия с принятыми доменами.
#[derive(Debug, Clone, Subcommand)]
pub enum DomainAction {
    /// Принятые домены организации.
    List,
    /// Новый принятый домен.
    Create {
        /// Имя домена.
        name: String,
        /// Внутренняя пересылка на узел host[:port] вместо собственного домена (authoritative).
        #[arg(long)]
        relay: Option<String>,
    },
    /// Удаление принятого домена.
    Delete {
        /// Домен: идентификатор (UUID) или имя.
        domain: String,
    },
}

/// Действия с доверенными источниками организации.
#[derive(Debug, Clone, Subcommand)]
pub enum SourceAction {
    /// Доверенные источники организации.
    List,
    /// Создание или замена источника: откуда (сети или сертификат клиента) и кто (шлюз или приложение).
    Set {
        /// Имя источника ([a-z0-9._-], до 64 символов).
        name: String,
        /// Сеть источника, CIDR (можно повторять).
        #[arg(
            long = "network",
            value_name = "CIDR",
            required_unless_present = "client_cert"
        )]
        networks: Vec<String>,
        /// Имя (dNSName) в сертификате клиента (mTLS) вместо сетей.
        #[arg(long, conflicts_with = "networks")]
        client_cert: Option<String>,
        /// Приложение (отправляет от перечисленных адресов) вместо шлюза.
        #[arg(long)]
        application: bool,
        /// Адрес отправителя приложения: user@domain или @domain (можно повторять).
        #[arg(long = "sender", value_name = "ШАБЛОН", requires = "application")]
        senders: Vec<String>,
        /// Приложению разрешены внешние получатели.
        #[arg(long, requires = "application")]
        external: bool,
        /// Шлюз: принимать адрес исходного клиента из XCLIENT/XFORWARD.
        #[arg(long, conflicts_with = "application")]
        xclient: bool,
        /// Шлюз: доверять Authentication-Results и ARC с этим authserv-id.
        #[arg(long, conflicts_with = "application")]
        authserv_id: Option<String>,
    },
    /// Удаление источника организации.
    Delete {
        /// Имя источника.
        name: String,
    },
}

/// Требование TLS политики домена назначения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum TlsMode {
    /// TLS, если сервер предлагает.
    #[default]
    Opportunistic,
    /// Обязательный TLS с проверкой сертификата; иначе — временный отказ доставки.
    Required,
}

/// Действия с политиками доменов назначения.
#[derive(Debug, Clone, Subcommand)]
pub enum RouteAction {
    /// Политики доменов назначения организации.
    List,
    /// Создание или замена политики домена назначения.
    Set {
        /// Шаблон: example.org, *.example.org (поддомены) или * (все внешние).
        pattern: String,
        /// Требование TLS.
        #[arg(long, value_enum, default_value_t = TlsMode::Opportunistic)]
        tls: TlsMode,
        /// Закреплённый ключ сервера: SHA-256 SubjectPublicKeyInfo, hex (можно повторять); вместо --tls.
        #[arg(long = "pin", value_name = "SHA256", conflicts_with = "tls")]
        pins: Vec<String>,
        /// Отправка через узел host[:port] вместо MX.
        #[arg(long)]
        smart_host: Option<String>,
        /// Исходящий IP-адрес.
        #[arg(long, value_name = "IP")]
        egress_ip: Option<String>,
    },
    /// Удаление политики домена назначения.
    Delete {
        /// Шаблон (как в `transport route list`).
        pattern: String,
    },
}

/// Действия с правилами Sieve учётной записи (решение 62, ADM-17); каждое изменение — в журнале аудита Admin API.
#[derive(Debug, Clone, Subcommand)]
pub enum SieveAction {
    /// Скрипты учётной записи: имя, размер, какой активен.
    List {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
    },
    /// Текст скрипта (в stdout — как записан).
    Get {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
        /// Имя скрипта (из `sieve list`).
        name: String,
    },
    /// Создание или замена текста скрипта: текст проверяется, активность сохраняется.
    Put {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
        /// Имя скрипта.
        name: String,
        /// Файл с текстом скрипта (UTF-8); `-` — stdin.
        #[arg(long, value_name = "ПУТЬ")]
        file: PathBuf,
    },
    /// Включение скрипта: он выполняется при доставке, прежний активный отключается.
    Activate {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
        /// Имя скрипта (из `sieve list`).
        name: String,
    },
    /// Отключение правил: активного скрипта нет, тексты остаются.
    Deactivate {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
    },
    /// Удаление скрипта; активный не удаляется (409) — сначала `sieve deactivate`.
    Delete {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
        /// Имя скрипта (из `sieve list`).
        name: String,
    },
    /// Скрипт организации: выполняется при доставке каждого письма до скрипта пользователя.
    Org {
        /// Действие.
        #[command(subcommand)]
        action: OrgSieveAction,
    },
}

/// Действия со скриптом организации (решение 76); каждое изменение — в журнале аудита Admin API.
#[derive(Debug, Clone, Subcommand)]
pub enum OrgSieveAction {
    /// Текст скрипта организации (в stdout — как записан); не задан — 404.
    Get,
    /// Запись скрипта организации: текст проверяется до записи.
    ///
    /// Скрипты организации и пользователя выполняются подряд, их действия копятся. Запрещающее правило
    /// организации пишите как `discard; stop;` — после одного `discard;` скрипт пользователя всё равно
    /// выполнится, и его `keep` отменит запрет.
    Put {
        /// Файл с текстом скрипта (UTF-8); `-` — stdin.
        #[arg(long, value_name = "ПУТЬ")]
        file: PathBuf,
    },
    /// Удаление скрипта организации; повторное удаление — не ошибка.
    Delete,
}

/// Действия с автоответом учётной записи (модель JMAP VacationResponse); каждое изменение — в журнале аудита.
#[derive(Debug, Clone, Subcommand)]
pub enum VacationAction {
    /// Автоответ учётной записи; не задан — выключен.
    Get {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
    },
    /// Включение автоответа (`--off` — выключение). Незаданные параметры остаются прежними.
    Set {
        /// Учётная запись: идентификатор (UUID) или имя входа.
        account: String,
        /// Выключить автоответ; текст, тема и срок сохраняются.
        #[arg(long)]
        off: bool,
        /// Начало действия, RFC 3339 (например, 2026-12-01T00:00:00Z); `-` — сразу.
        #[arg(long, value_name = "ВРЕМЯ")]
        from: Option<String>,
        /// Конец действия (не включая), RFC 3339; `-` — бессрочно.
        #[arg(long, value_name = "ВРЕМЯ")]
        to: Option<String>,
        /// Тема ответа; `-` — по умолчанию («Автоответ: <тема письма>»).
        #[arg(long)]
        subject: Option<String>,
        /// Текст ответа.
        #[arg(long, conflicts_with = "text_file")]
        text: Option<String>,
        /// Файл с текстом ответа (UTF-8); `-` — stdin.
        #[arg(long, value_name = "ПУТЬ")]
        text_file: Option<PathBuf>,
        /// Файл с текстом ответа HTML (UTF-8).
        #[arg(long, value_name = "ПУТЬ")]
        html_file: Option<PathBuf>,
        /// Тема ответа чужим отправителям; `-` — по умолчанию. Пока не задана — наружу ответа нет (RFC 3834).
        #[arg(long)]
        external_subject: Option<String>,
        /// Текст ответа чужим отправителям (вместе с --external-subject).
        #[arg(long)]
        external_text: Option<String>,
    },
}

/// Результат команды: текст для stdout или сообщение об ошибке.
type CliResult<T> = std::result::Result<T, String>;

/// Поле ответа `v` как в JSON Admin API (даты — RFC 3339, форматом tp-admin); `null` или нет поля — «—».
fn json_field<T: Serialize>(v: &T, field: &str) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::Object(mut fields)) => fields
            .remove(field)
            .map_or_else(|| "—".to_owned(), |v| value_text(&v)),
        _ => "—".to_owned(),
    }
}

/// `thepost admin <ресурс> <действие>`: код возврата (0 — успех, 1 — отказ или ошибка).
pub async fn command(config: &Path, args: ApiArgs, action: ApiAction) -> i32 {
    if matches!(action, ApiAction::Login { oidc: true, .. }) {
        return oidc_command(config, &args).await;
    }
    match run(config, &args, action).await {
        Ok(out) => {
            style::print(args.theme(), &out);
            0
        }
        Err(msg) => {
            let t = args.err_theme();
            style::eprint(t, &style::error(t, &msg));
            1
        }
    }
}

async fn run(config: &Path, args: &ApiArgs, action: ApiAction) -> CliResult<String> {
    let options = args.options();
    if let ApiAction::Login {
        user: Some(user),
        password_stdin,
        ..
    } = &action
    {
        let password = read_password(*password_stdin).await?;
        let client = Client::anonymous(base_url(config, args)?, &options)?;
        return login(&client, args, user, password).await;
    }
    let token = tp_admin_client::token(args.token.clone())?;
    let client = Client::new(base_url(config, args)?, token, &options)?;
    execute(&client, args, action).await
}

/// `login --oidc` — вход с устройства по config.yaml `config`: приглашение — в stderr, токен доступа — строкой
/// в stdout, чтобы он не попал в историю оболочки: `export THEPOST_ADMIN_TOKEN="$(…)"`.
async fn oidc_command(config: &Path, args: &ApiArgs) -> i32 {
    match oidc_login(config).await {
        Ok(token) => {
            println!("{token}");
            eprintln!(
                "thepost: admin: токен OIDC получен; без записи в историю оболочки: \
                 export {ENV_TOKEN}=\"$(thepost admin login --oidc)\""
            );
            0
        }
        Err(msg) => {
            let t = args.err_theme();
            style::eprint(t, &style::error(t, &msg));
            1
        }
    }
}

/// Токен OIDC: поставщик — `auth.oidc`, клиент — `cli.oidc`, ключ канала — из хранилища секретов узла.
async fn oidc_login(config: &Path) -> CliResult<String> {
    let registry = sections::registry().map_err(|e| e.to_string())?;
    let path = config.to_owned();
    let cfg = tokio::task::spawn_blocking(move || registry.load(&path))
        .await
        .map_err(|e| format!("чтение конфигурации прервано: {e}"))?
        .map_err(|e| format!("{}: {e}", config.display()))?;
    let auth = cfg
        .section::<AuthSection>(AUTH)
        .map_err(|e| format!("{}: секция auth: {e}", config.display()))?;
    let oidc = auth.oidc.as_ref().ok_or_else(|| {
        format!(
            "{}: нет auth.oidc — поставщик OIDC не настроен",
            config.display()
        )
    })?;
    let cli = cfg
        .section::<CliSection>(CLI)
        .map_err(|e| format!("{}: секция cli: {e}", config.display()))?;
    let settings = device_settings(&cli.oidc)?;
    let secrets = crate::secrets::store(&cfg, None)
        .await
        .map_err(|e| format!("{}: хранилище секретов: {e}", config.display()))?;
    let login = DeviceLogin::new(oidc, settings, cfg.profile(), secrets.as_ref()).await?;
    Ok(login.login(|code| eprint!("{}", prompt_text(code))).await?)
}

/// Настройки входа с устройства из `cli.oidc`; без `client_id` вход недоступен.
fn device_settings(cli: &CliOidc) -> CliResult<DeviceSettings> {
    cli.check().map_err(|e| e.to_string())?;
    let client_id = cli.client_id.clone().ok_or_else(|| {
        "не задан cli.oidc.client_id — идентификатор открытого клиента (public client) с разрешённым \
         Device Authorization Grant у поставщика OIDC"
            .to_owned()
    })?;
    Ok(DeviceSettings {
        client_id,
        scope: cli.scope.clone(),
        poll_interval: cli.poll_interval,
        slow_down_step: cli.slow_down_step,
        max_wait: cli.max_wait,
    })
}

/// Пароль входа: первая строка stdin (`--password-stdin`) или ввод в терминале без эха; чтение — вне потоков async.
async fn read_password(stdin: bool) -> CliResult<String> {
    let read = move || -> std::io::Result<String> {
        if stdin {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Ok(line.trim_end_matches(['\r', '\n']).to_owned())
        } else {
            rpassword::prompt_password("Пароль: ")
        }
    };
    let password = tokio::task::spawn_blocking(read)
        .await
        .map_err(|e| format!("чтение пароля: {e}"))?
        .map_err(|e| {
            if stdin {
                format!("пароль из stdin: {e}")
            } else {
                format!("пароль из терминала: {e} (без терминала — --password-stdin)")
            }
        })?;
    if password.is_empty() {
        return Err("пустой пароль".to_owned());
    }
    Ok(password)
}

/// Вход по паролю: сессия Admin API (`POST /api/v1/session`), значение — один раз в stdout.
pub async fn login(
    client: &Client,
    args: &ApiArgs,
    user: &str,
    password: String,
) -> CliResult<String> {
    let s = client.login(user, password).await?;
    let text = format!(
        "{}Значение сессии показывается один раз. Дальше: export {ENV_TOKEN}=<сессия>\n",
        record(&[
            ("Сессия", s.session.clone()),
            ("Действует до", json_field(&s, "expires_at")),
            ("Администратор", s.login.clone()),
            ("Организация", s.tenant.clone()),
            ("Роли", roles(&s.roles)),
        ])
    );
    out(args, &s, text)
}

/// Адрес Admin API: `--url`, `THEPOST_ADMIN_URL` или `http.admin` из config.yaml.
fn base_url(config: &Path, args: &ApiArgs) -> CliResult<Url> {
    let raw = match setting(args.url.clone(), ENV_URL) {
        Some(u) => u,
        None => url_from_config(config)?,
    };
    Ok(tp_admin_client::base_url(&raw)?)
}

/// `https://<http.admin.listen>` (`http://` при `allow_plaintext`); адрес — только внутренний (проверка секции).
fn url_from_config(config: &Path) -> CliResult<String> {
    let hint = format!("укажите --url или {ENV_URL}");
    let cfg = sections::registry()
        .and_then(|r| r.load(config))
        .map_err(|e| format!("{}: {e} ({hint})", config.display()))?;
    let http = cfg
        .section::<HttpSection>(HTTP)
        .map_err(|e| format!("{}: секция http: {e} ({hint})", config.display()))?;
    let listener = http.admin.as_ref().ok_or_else(|| {
        format!(
            "{}: нет http.admin — Admin API на узле не слушает ({hint})",
            config.display()
        )
    })?;
    let scheme = if listener.allow_plaintext {
        "http"
    } else {
        "https"
    };
    Ok(format!("{scheme}://{}", listener.listen))
}

/// Вывод команды: ответ в JSON (`--json`) или текст `text`.
fn out<T: Serialize>(args: &ApiArgs, v: &T, text: String) -> CliResult<String> {
    if args.json {
        style::json(args.theme(), v)
            .map(|j| format!("{j}\n"))
            .map_err(|e| e.to_string())
    } else {
        Ok(text)
    }
}

/// Выполняет команду через `client`; текст для stdout.
pub async fn execute(client: &Client, args: &ApiArgs, action: ApiAction) -> CliResult<String> {
    match action {
        ApiAction::Login { .. } => Err(
            "login — вход по паролю или у поставщика OIDC (thepost admin login), не запрос с сессией".to_owned(),
        ),
        ApiAction::Whoami => {
            let w = client.whoami().await?;
            out(args, &w, whoami_record(&w))
        }
        ApiAction::Account { action } => {
            let org = client.org(args.org.clone()).await?;
            match *action {
                AccountAction::Create { login, name } => {
                    let hint = format!("thepost admin account get {login}");
                    let body = NewAccount {
                        login,
                        display_name: name,
                    };
                    let a: AccountInfo = client
                        .call(ACCOUNT_CREATE, &[org.as_str()], &[], Some(&body))
                        .await
                        .map_err(|e| e.hint(409, hint))?;
                    out(args, &a, account_record(&a))
                }
                AccountAction::List {
                    login: Some(login), ..
                } => {
                    let found = find_accounts(client, &org, login).await?;
                    let t = args.theme();
                    let rows: Vec<Vec<String>> =
                        found.iter().map(|a| style::account_row(t, a)).collect();
                    out(args, &found, style::table(t, style::ACCOUNT_COLUMNS, &rows))
                }
                AccountAction::List {
                    login: None,
                    prefix,
                    after,
                    limit,
                } => {
                    let (found, more) =
                        list_accounts(client, &org, prefix.clone(), after, limit).await?;
                    let t = args.theme();
                    let rows: Vec<Vec<String>> =
                        found.iter().map(|a| style::account_row(t, a)).collect();
                    let mut text = style::table(t, style::ACCOUNT_COLUMNS, &rows);
                    if let Some(last) = found.last().filter(|_| more) {
                        // `after` следующей страницы — как в ссылке rel="next": последнее показанное имя входа.
                        let prefix = prefix.map(|p| format!(" --prefix {p}")).unwrap_or_default();
                        text.push_str(&style::more(
                            t,
                            &format!(
                                "Показано {}; есть ещё. Следующая страница: thepost admin account list{prefix} \
                                 --after {} --limit {}",
                                found.len(),
                                last.login.to_lowercase(),
                                found.len()
                            ),
                        ));
                    }
                    out(args, &found, text)
                }
                AccountAction::Get { account } => {
                    let id = account_id(client, &org, &account).await?;
                    let a: AccountInfo = client
                        .call(ACCOUNT_GET, &[org.as_str(), id.as_str()], &[], NO_BODY)
                        .await?;
                    out(args, &a, account_record(&a))
                }
                AccountAction::Block { account } => {
                    let patch = AccountPatch {
                        enabled: Some(false),
                        ..AccountPatch::default()
                    };
                    let a = patch_account(client, &org, &account, &patch).await?;
                    out(args, &a, account_record(&a))
                }
                AccountAction::Unblock { account } => {
                    let patch = AccountPatch {
                        enabled: Some(true),
                        ..AccountPatch::default()
                    };
                    let a = patch_account(client, &org, &account, &patch).await?;
                    out(args, &a, account_record(&a))
                }
                AccountAction::Rename { account, name } => {
                    let patch = AccountPatch {
                        display_name: Some(name),
                        ..AccountPatch::default()
                    };
                    let a = patch_account(client, &org, &account, &patch).await?;
                    out(args, &a, account_record(&a))
                }
                AccountAction::Set {
                    account,
                    aliases,
                    no_aliases,
                    hidden_from_gal,
                } => {
                    let aliases = (no_aliases || !aliases.is_empty()).then_some(aliases);
                    if aliases.is_none() && hidden_from_gal.is_none() {
                        return Err(
                            "нужен хотя бы один ключ: --alias, --no-aliases, --hidden-from-gal"
                                .to_owned(),
                        );
                    }
                    let patch = AccountPatch {
                        aliases,
                        hidden_from_gal,
                        ..AccountPatch::default()
                    };
                    let id = account_id(client, &org, &account).await?;
                    let params = [org.as_str(), id.as_str()];
                    let before: AccountInfo =
                        client.call(ACCOUNT_GET, &params, &[], NO_BODY).await?;
                    let a: AccountInfo = client
                        .call(ACCOUNT_PATCH, &params, &[], Some(&patch))
                        .await?;
                    out(
                        args,
                        &a,
                        style::changes(args.theme(), ACCOUNT_PATCH, &before, &a),
                    )
                }
            }
        }
        ApiAction::AppPassword { action } => {
            let org = client.org(args.org.clone()).await?;
            match action {
                AppPasswordAction::Create { account, label } => {
                    let id = account_id(client, &org, &account).await?;
                    let body = NewAppPassword { label };
                    let p: IssuedAppPassword = client
                        .call(
                            APP_PASSWORD_CREATE,
                            &[org.as_str(), id.as_str()],
                            &[],
                            Some(&body),
                        )
                        .await?;
                    let text = format!(
                        "{}Пароль показывается один раз.\n",
                        record(&[
                            ("Пароль", p.password.clone()),
                            ("Идентификатор", p.info.id.clone()),
                            ("Подпись", or_dash(&p.info.label)),
                            ("Выпущен", json_field(&p.info, "created_at")),
                        ])
                    );
                    out(args, &p, text)
                }
                AppPasswordAction::List { account } => {
                    let id = account_id(client, &org, &account).await?;
                    let list: Vec<AppPasswordInfo> = client
                        .call(
                            APP_PASSWORD_LIST,
                            &[org.as_str(), id.as_str()],
                            &[],
                            NO_BODY,
                        )
                        .await?;
                    let rows: Vec<Vec<String>> = list
                        .iter()
                        .map(|p| {
                            vec![
                                p.id.clone(),
                                or_dash(&p.label),
                                json_field(p, "created_at"),
                                json_field(p, "revoked_at"),
                            ]
                        })
                        .collect();
                    out(
                        args,
                        &list,
                        style::table(
                            args.theme(),
                            &["ИДЕНТИФИКАТОР", "ПОДПИСЬ", "ВЫПУЩЕН", "ОТОЗВАН"],
                            &rows,
                        ),
                    )
                }
                AppPasswordAction::Revoke { account, id } => {
                    let account = account_id(client, &org, &account).await?;
                    client
                        .call_empty(
                            APP_PASSWORD_REVOKE,
                            &[org.as_str(), account.as_str(), id.as_str()],
                            &[],
                            NO_BODY,
                        )
                        .await?;
                    out(args, &(), format!("Пароль {id} отозван.\n"))
                }
            }
        }
        ApiAction::Policy { action } => policy_command(client, args, *action).await,
        ApiAction::Group { action } => group_command(client, args, *action).await,
        ApiAction::Resources { action } => resource_command(client, args, *action).await,
        ApiAction::Branding { action } => branding_command(client, args, *action).await,
        ApiAction::Trust { action } => trust_command(client, args, *action).await,
        ApiAction::Risk { action } => risk_command(client, args, *action).await,
        ApiAction::Trash { action } => trash_command(client, args, action).await,
        ApiAction::Audit { action } => audit_command(client, args, *action).await,
        ApiAction::Delivery { action } => delivery_command(client, args, *action).await,
        ApiAction::Journal { action } => journal_command(client, args, *action).await,
        ApiAction::Thread { action } => thread_command(client, args, *action).await,
        ApiAction::Transport { action } => {
            let org = client.org(args.org.clone()).await?;
            match *action {
                TransportAction::Domain { action } => {
                    domain_command(client, args, &org, action).await
                }
                TransportAction::Source { action } => {
                    source_command(client, args, &org, action).await
                }
                TransportAction::Route { action } => {
                    route_command(client, args, &org, action).await
                }
            }
        }
        ApiAction::Sieve { action } => {
            let org = client.org(args.org.clone()).await?;
            match action {
                SieveAction::List { account } => {
                    let id = account_id(client, &org, &account).await?;
                    let list: Vec<Script> = client
                        .call(SIEVE_LIST, &[org.as_str(), id.as_str()], &[], NO_BODY)
                        .await?;
                    let rows: Vec<Vec<String>> = list
                        .iter()
                        .map(|s| {
                            let active = if s.active { "да" } else { "нет" };
                            vec![s.name.clone(), s.size.to_string(), active.to_owned()]
                        })
                        .collect();
                    out(
                        args,
                        &list,
                        style::table(args.theme(), &["ИМЯ", "РАЗМЕР", "АКТИВЕН"], &rows),
                    )
                }
                SieveAction::Get { account, name } => {
                    let id = account_id(client, &org, &account).await?;
                    let script: ScriptBody = client
                        .call(
                            SIEVE_GET,
                            &[org.as_str(), id.as_str(), name.as_str()],
                            &[],
                            NO_BODY,
                        )
                        .await?;
                    let text = script.text.clone();
                    out(args, &script, text)
                }
                SieveAction::Put {
                    account,
                    name,
                    file,
                } => {
                    let body = ScriptText {
                        text: input_text(file).await?,
                    };
                    let id = account_id(client, &org, &account).await?;
                    client
                        .call_empty(
                            SIEVE_PUT,
                            &[org.as_str(), id.as_str(), name.as_str()],
                            &[],
                            Some(&body),
                        )
                        .await?;
                    out(args, &(), format!("Скрипт {name} записан.\n"))
                }
                SieveAction::Activate { account, name } => {
                    let id = account_id(client, &org, &account).await?;
                    client
                        .call_empty(
                            SIEVE_ACTIVATE,
                            &[org.as_str(), id.as_str(), name.as_str()],
                            &[],
                            NO_BODY,
                        )
                        .await?;
                    out(args, &(), format!("Скрипт {name} включён.\n"))
                }
                SieveAction::Deactivate { account } => {
                    let id = account_id(client, &org, &account).await?;
                    client
                        .call_empty(SIEVE_DEACTIVATE, &[org.as_str(), id.as_str()], &[], NO_BODY)
                        .await?;
                    out(args, &(), "Правила отключены.\n".to_owned())
                }
                SieveAction::Delete { account, name } => {
                    let id = account_id(client, &org, &account).await?;
                    client
                        .call_empty(
                            SIEVE_DELETE,
                            &[org.as_str(), id.as_str(), name.as_str()],
                            &[],
                            NO_BODY,
                        )
                        .await?;
                    out(args, &(), format!("Скрипт {name} удалён.\n"))
                }
                SieveAction::Org { action } => match action {
                    OrgSieveAction::Get => {
                        let script: ScriptText = client
                            .call(ORG_SIEVE_GET, &[org.as_str()], &[], NO_BODY)
                            .await?;
                        let text = script.text.clone();
                        out(args, &script, text)
                    }
                    OrgSieveAction::Put { file } => {
                        let body = ScriptText {
                            text: input_text(file).await?,
                        };
                        client
                            .call_empty(ORG_SIEVE_PUT, &[org.as_str()], &[], Some(&body))
                            .await?;
                        out(args, &(), "Скрипт организации записан.\n".to_owned())
                    }
                    OrgSieveAction::Delete => {
                        client
                            .call_empty(ORG_SIEVE_DELETE, &[org.as_str()], &[], NO_BODY)
                            .await?;
                        out(args, &(), "Скрипт организации удалён.\n".to_owned())
                    }
                },
            }
        }
        ApiAction::Vacation { action } => {
            let org = client.org(args.org.clone()).await?;
            match *action {
                VacationAction::Get { account } => {
                    let id = account_id(client, &org, &account).await?;
                    let v: VacationBody = client
                        .call(VACATION_GET, &[org.as_str(), id.as_str()], &[], NO_BODY)
                        .await?;
                    out(args, &v, vacation_record(&v))
                }
                VacationAction::Set {
                    account,
                    off,
                    from,
                    to,
                    subject,
                    text,
                    text_file,
                    html_file,
                    external_subject,
                    external_text,
                } => {
                    let text = match text_file {
                        Some(file) => Some(input_text(file).await?),
                        None => text,
                    };
                    let html = match html_file {
                        Some(file) => Some(input_text(file).await?),
                        None => None,
                    };
                    let id = account_id(client, &org, &account).await?;
                    let params = [org.as_str(), id.as_str()];
                    let current: VacationBody =
                        client.call(VACATION_GET, &params, &[], NO_BODY).await?;
                    let change = VacationChange {
                        enabled: !off,
                        from,
                        to,
                        subject,
                        text,
                        html,
                        external_subject,
                        external_text,
                    };
                    let body = change.apply(&current)?;
                    let v: VacationBody =
                        client.call(VACATION_PUT, &params, &[], Some(&body)).await?;
                    out(
                        args,
                        &v,
                        style::changes(args.theme(), VACATION_PUT, &current, &v),
                    )
                }
            }
        }
    }
}

/// Уровень политики с идентификатором из пути операции.
enum Level {
    Org,
    Domain(String),
    Account(String),
}

/// Уровень `level`: домен и учётная запись — по идентификатору или имени.
async fn level(client: &Client, org: &str, level: PolicyLevel) -> CliResult<Level> {
    Ok(match (level.domain, level.account) {
        (Some(domain), _) => Level::Domain(domain_id(client, org, &domain).await?),
        (None, Some(account)) => Level::Account(account_id(client, org, &account).await?),
        (None, None) => Level::Org,
    })
}

/// `thepost admin policy …`.
async fn policy_command(
    client: &Client,
    args: &ApiArgs,
    action: PolicyAction,
) -> CliResult<String> {
    let org = client.org(args.org.clone()).await?;
    match action {
        PolicyAction::Get { level: l } => {
            let l = level(client, &org, l).await?;
            let p = policies(client, &org, &l).await?;
            out(args, &p, policy_table(args.theme(), &p))
        }
        PolicyAction::Set { level: l, file } => {
            let text = input_text(file).await?;
            let body: PolicyBody =
                serde_json::from_str(&text).map_err(|e| format!("политика (JSON): {e}"))?;
            let l = level(client, &org, l).await?;
            let before = policies(client, &org, &l).await?.policy;
            let (op, id) = match &l {
                Level::Org => (ORG_POLICY_PUT, None),
                Level::Domain(id) => (DOMAIN_POLICY_PUT, Some(id.as_str())),
                Level::Account(id) => (ACCOUNT_POLICY_PUT, Some(id.as_str())),
            };
            let params: Vec<&str> = [Some(org.as_str()), id].into_iter().flatten().collect();
            let p: PolicyBody = client.call(op, &params, &[], Some(&body)).await?;
            out(args, &p, style::changes(args.theme(), op, &before, &p))
        }
    }
}

/// Политика уровня `l`: заданное на уровне и действующее.
async fn policies(client: &Client, org: &str, l: &Level) -> CliResult<Policies> {
    Ok(match l {
        Level::Org => {
            let o: Organization = client.call(ORG_GET, &[org], &[], NO_BODY).await?;
            o.policies
        }
        Level::Domain(id) => {
            client
                .call(DOMAIN_POLICY_GET, &[org, id.as_str()], &[], NO_BODY)
                .await?
        }
        Level::Account(id) => {
            let a: AccountInfo = client
                .call(ACCOUNT_GET, &[org, id.as_str()], &[], NO_BODY)
                .await?;
            a.policies
        }
    })
}

/// Поля политики: заданное на уровне и действующее (`effective`); не задано — «—».
fn policy_table(t: Theme, p: &Policies) -> String {
    let fields = |p: &PolicyBody| match serde_json::to_value(p) {
        Ok(serde_json::Value::Object(fields)) => fields,
        _ => serde_json::Map::new(),
    };
    let effective = fields(&p.effective);
    let rows: Vec<Vec<String>> = fields(&p.policy)
        .iter()
        .map(|(name, v)| {
            let e = effective
                .get(name)
                .map_or_else(|| "—".to_owned(), value_text);
            vec![name.clone(), value_text(v), e]
        })
        .collect();
    style::table(t, &["ПОЛЕ", "НА УРОВНЕ", "ДЕЙСТВУЕТ"], &rows)
}

/// `thepost admin group …`.
async fn group_command(client: &Client, args: &ApiArgs, action: GroupAction) -> CliResult<String> {
    let org = client.org(args.org.clone()).await?;
    match action {
        GroupAction::List => {
            let list = groups(client, &org).await?;
            let rows: Vec<Vec<String>> = list.iter().map(group_row).collect();
            out(
                args,
                &list,
                style::table(args.theme(), GROUP_COLUMNS, &rows),
            )
        }
        GroupAction::Get { group } => {
            let id = group_id(client, &org, &group).await?;
            let g: GroupInfo = client.call(GROUP_GET, &[&org, &id], &[], NO_BODY).await?;
            out(args, &g, group_record(&g))
        }
        GroupAction::Create {
            name,
            address,
            accounts,
            groups,
        } => {
            let body = NewGroup {
                name,
                address,
                members: members(client, &org, accounts, groups).await?,
                senders: SenderRestriction::default(),
                moderators: Vec::new(),
                hidden_from_gal: false,
            };
            let g: GroupInfo = client
                .call(GROUP_CREATE, &[&org], &[], Some(&body))
                .await
                .map_err(|e| e.hint(409, "thepost admin group list"))?;
            out(args, &g, group_record(&g))
        }
        GroupAction::Delete { group } => {
            let id = group_id(client, &org, &group).await?;
            client
                .call_empty(GROUP_DELETE, &[&org, &id], &[], NO_BODY)
                .await?;
            out(args, &(), format!("Группа {group} удалена.\n"))
        }
        GroupAction::Members {
            group,
            set,
            accounts,
            groups,
        } => {
            let id = group_id(client, &org, &group).await?;
            let params = [org.as_str(), id.as_str()];
            let g: GroupInfo = if set {
                let patch = GroupPatch {
                    members: Some(members(client, &org, accounts, groups).await?),
                    ..GroupPatch::default()
                };
                client.call(GROUP_PATCH, &params, &[], Some(&patch)).await?
            } else {
                client.call(GROUP_GET, &params, &[], NO_BODY).await?
            };
            let rows: Vec<Vec<String>> = g
                .members
                .iter()
                .map(|m| {
                    let (kind, id) = member(m);
                    vec![kind.to_owned(), id.clone(), name_of(&g, id)]
                })
                .collect();
            out(
                args,
                &g.members,
                style::table(args.theme(), &["ВИД", "ИДЕНТИФИКАТОР", "ИМЯ"], &rows),
            )
        }
    }
}

const GROUP_COLUMNS: &[&str] = &["ИДЕНТИФИКАТОР", "ИМЯ", "АДРЕС", "УЧАСТНИКОВ"];

/// Группы организации.
async fn groups(client: &Client, org: &str) -> CliResult<Vec<GroupInfo>> {
    Ok(client.call(GROUP_LIST, &[org], &[], NO_BODY).await?)
}

/// Идентификатор группы: UUID как есть, иначе единственная группа с таким именем или адресом (без учёта регистра).
async fn group_id(client: &Client, org: &str, group: &str) -> CliResult<String> {
    if group.parse::<GroupId>().is_ok() {
        return Ok(group.to_owned());
    }
    let want = group.to_lowercase();
    let list = groups(client, org).await?;
    let found: Vec<&GroupInfo> = list
        .iter()
        .filter(|g| {
            g.name.to_lowercase() == want
                || g.address
                    .as_deref()
                    .is_some_and(|a| a.to_lowercase() == want)
        })
        .collect();
    match found.as_slice() {
        [g] => Ok(g.id.clone()),
        [] => Err(format!("группа {group} не найдена")),
        _ => Err(format!(
            "групп с именем {group} несколько — укажите идентификатор (из group list)"
        )),
    }
}

/// Участники: учётные записи (идентификатор или имя входа) и группы (идентификатор, имя или адрес).
async fn members(
    client: &Client,
    org: &str,
    accounts: Vec<String>,
    groups: Vec<String>,
) -> CliResult<Vec<GroupMember>> {
    let mut out = Vec::with_capacity(accounts.len() + groups.len());
    for a in accounts {
        let id = account_id(client, org, &a).await?;
        let id = id
            .parse::<AccountId>()
            .map_err(|e| format!("учётная запись {id}: {e}"))?;
        out.push(GroupMember::Account(id));
    }
    for g in groups {
        let id = group_id(client, org, &g).await?;
        let id = id
            .parse::<GroupId>()
            .map_err(|e| format!("группа {id}: {e}"))?;
        out.push(GroupMember::Group(id));
    }
    Ok(out)
}

/// Вид и идентификатор участника.
fn member(m: &GroupMember) -> (&'static str, String) {
    match m {
        GroupMember::Account(id) => ("учётная запись", id.to_string()),
        GroupMember::Group(id) => ("группа", id.to_string()),
    }
}

/// Имя по идентификатору из словаря `names` ответа; нет в словаре — «—» (записи уже нет).
fn name_of(g: &GroupInfo, id: String) -> String {
    g.names.get(&id).cloned().unwrap_or_else(|| "—".to_owned())
}

/// Группа — строка таблицы [`GROUP_COLUMNS`].
fn group_row(g: &GroupInfo) -> Vec<String> {
    vec![
        g.id.clone(),
        g.name.clone(),
        optional(g.address.as_ref()),
        g.members.len().to_string(),
    ]
}

/// Группа — строки «подпись: значение»; участники и модераторы — по именам.
fn group_record(g: &GroupInfo) -> String {
    let names = |ids: Vec<String>| {
        let list: Vec<String> = ids.into_iter().map(|id| name_of(g, id)).collect();
        or_dash(&list.join(", "))
    };
    let senders =
        serde_json::to_value(&g.senders).map_or_else(|_| "—".to_owned(), |v| value_text(&v));
    record(&[
        ("Идентификатор", g.id.clone()),
        ("Имя", g.name.clone()),
        ("Адрес", optional(g.address.as_ref())),
        ("Из каталога", optional(g.external_id.as_ref())),
        (
            "Участники",
            names(g.members.iter().map(|m| member(m).1).collect()),
        ),
        ("Отправители", senders),
        (
            "Модераторы",
            names(g.moderators.iter().map(ToString::to_string).collect()),
        ),
        (
            "Скрыта из GAL",
            if g.hidden_from_gal { "да" } else { "нет" }.to_owned(),
        ),
    ])
}

/// `thepost admin resources …`.
async fn resource_command(
    client: &Client,
    args: &ApiArgs,
    action: ResourceAction,
) -> CliResult<String> {
    let org = client.org(args.org.clone()).await?;
    match action {
        ResourceAction::List => {
            let list = resources(client, &org).await?;
            let rows: Vec<Vec<String>> = list.iter().map(resource_row).collect();
            out(
                args,
                &list,
                style::table(args.theme(), RESOURCE_COLUMNS, &rows),
            )
        }
        ResourceAction::Create {
            login,
            name,
            resource_type,
        } => {
            let body = NewResource {
                login,
                display_name: name,
                resource_type: resource_type.body(),
                booking_policy: None,
            };
            let r: ResourceInfo = client
                .call(RESOURCES_CREATE, &[org.as_str()], &[], Some(&body))
                .await
                .map_err(|e| e.hint(409, "thepost admin resources list"))?;
            out(args, &r, resource_record(&r))
        }
        ResourceAction::SetType {
            resource,
            resource_type,
        } => {
            let id = resource_id(client, &org, &resource).await?;
            let params = [org.as_str(), id.as_str()];
            let before: ResourceInfo = client.call(RESOURCE_GET, &params, &[], NO_BODY).await?;
            let patch = ResourcePatch {
                resource_type: resource_type.body(),
            };
            let r: ResourceInfo = client
                .call(RESOURCE_PATCH, &params, &[], Some(&patch))
                .await?;
            out(
                args,
                &r,
                style::changes(args.theme(), RESOURCE_PATCH, &before, &r),
            )
        }
    }
}

const RESOURCE_COLUMNS: &[&str] = &["ИДЕНТИФИКАТОР", "ИМЯ ВХОДА", "ИМЯ", "ТИП"];

/// Ресурсы организации.
async fn resources(client: &Client, org: &str) -> CliResult<Vec<ResourceInfo>> {
    Ok(client.call(RESOURCES_LIST, &[org], &[], NO_BODY).await?)
}

/// Идентификатор ресурса: UUID как есть, иначе ресурс с таким именем входа (без учёта регистра).
async fn resource_id(client: &Client, org: &str, resource: &str) -> CliResult<String> {
    if resource.parse::<AccountId>().is_ok() {
        return Ok(resource.to_owned());
    }
    let want = resource.to_lowercase();
    resources(client, org)
        .await?
        .iter()
        .find(|r| r.account.login.to_lowercase() == want)
        .map(|r| r.account.id.clone())
        .ok_or_else(|| format!("ресурс {resource} не найден"))
}

/// Ресурс — строка таблицы [`RESOURCE_COLUMNS`].
fn resource_row(r: &ResourceInfo) -> Vec<String> {
    let name = if r.account.display_name.is_empty() {
        "—".to_owned()
    } else {
        r.account.display_name.clone()
    };
    vec![
        r.account.id.clone(),
        r.account.login.clone(),
        name,
        resource_type_name(r.resource_type).to_owned(),
    ]
}

/// Ресурс — строки «подпись: значение».
fn resource_record(r: &ResourceInfo) -> String {
    record(&[
        ("Идентификатор", r.account.id.clone()),
        ("Имя входа", r.account.login.clone()),
        ("Имя", r.account.display_name.clone()),
        ("Тип", resource_type_name(r.resource_type).to_owned()),
        ("Из каталога", optional(r.account.external_id.as_ref())),
    ])
}

/// `thepost admin branding …`: уровень — установка без `--org`, организация с `--org`.
async fn branding_command(
    client: &Client,
    args: &ApiArgs,
    action: BrandingAction,
) -> CliResult<String> {
    // Уровень: --org (или THEPOST_ADMIN_ORG) — организация, иначе — установка.
    let org = setting(args.org.clone(), ENV_ORG);
    let params: Vec<String> = match org {
        None => Vec::new(),
        Some(o) => {
            o.parse::<tp_contracts::TenantId>()
                .map_err(|e| format!("организация {o:?}: {e}"))?;
            vec![o]
        }
    };
    let p = params.iter().map(String::as_str).collect::<Vec<_>>();
    let level = || match params.is_empty() {
        true => (BRANDING_GET, BRANDING_PUT, BRANDING_RESET),
        false => (ORG_BRANDING_GET, ORG_BRANDING_PUT, ORG_BRANDING_RESET),
    };
    match action {
        BrandingAction::Show => {
            let (get, _, _) = level();
            let v: BrandingView = client.call(get, &p, &[], NO_BODY).await?;
            out(args, &v, branding_record(&v))
        }
        BrandingAction::Set {
            name,
            primary,
            role,
        } => {
            let (get, put, _) = level();
            // Текущий набор уровня с наложением ключей: `set` меняет только заданное.
            let view: BrandingView = client.call(get, &p, &[], NO_BODY).await?;
            let own = view.own;
            let mut body = BrandingBody {
                product_name: own.as_ref().and_then(|o| o.product_name.clone()),
                primary: own.as_ref().and_then(|o| o.primary),
                light: own.as_ref().map(|o| o.light.clone()).unwrap_or_default(),
                dark: own.as_ref().map(|o| o.dark.clone()).unwrap_or_default(),
                cli: own.as_ref().map(|o| o.cli.clone()).unwrap_or_default(),
            };
            if let Some(name) = name {
                body.product_name = Some(name);
            }
            if let Some(p) = primary {
                body.primary = Some(p.parse().map_err(|e| format!("--primary: {e}"))?);
            }
            for one in role {
                let (slot, color) = one
                    .split_once('=')
                    .ok_or_else(|| format!("--role {one:?}: нужно <тема>.<роль>=#RRGGBB"))?;
                let color: BrandColor =
                    color.parse().map_err(|e| format!("--role {one:?}: {e}"))?;
                let (theme, role) = slot
                    .split_once('.')
                    .ok_or_else(|| format!("--role {one:?}: тема — light, dark или cli"))?;
                match theme {
                    "light" => {
                        let r = Role::ALL
                            .into_iter()
                            .find(|r| r.as_str() == role)
                            .ok_or_else(|| {
                                format!(
                                    "--role {one:?}: неизвестная роль {role:?} (design/tokens.toml)"
                                )
                            })?;
                        body.light.insert(r, color);
                    }
                    "dark" => {
                        let r = Role::ALL
                            .into_iter()
                            .find(|r| r.as_str() == role)
                            .ok_or_else(|| {
                                format!(
                                    "--role {one:?}: неизвестная роль {role:?} (design/tokens.toml)"
                                )
                            })?;
                        body.dark.insert(r, color);
                    }
                    "cli" => {
                        let r = CliRole::ALL
                            .into_iter()
                            .find(|r| r.as_str() == role)
                            .ok_or_else(|| {
                                format!(
                                    "--role {one:?}: неизвестная роль {role:?} (design/tokens.toml)"
                                )
                            })?;
                        body.cli.insert(r, color);
                    }
                    other => {
                        return Err(format!(
                            "--role {one:?}: тема {other:?} — light, dark или cli"
                        ));
                    }
                }
            }
            let v: BrandingView = client
                .call(put, &p, &[], Some(&body))
                .await
                .map_err(|e| e.hint(422, "пары ниже порога контраста — смените цвет или роль"))?;
            out(args, &v, branding_record(&v))
        }
        BrandingAction::Reset => {
            let (_, _, reset) = level();
            let v: BrandingView = client.call(reset, &p, &[], NO_BODY).await?;
            out(args, &v, branding_record(&v))
        }
        BrandingAction::Logo { action } => {
            let op = match (params.is_empty(), matches!(action, LogoAction::Set { .. })) {
                (true, true) => BRANDING_LOGO_PUT,
                (false, true) => ORG_BRANDING_LOGO_PUT,
                (true, false) => BRANDING_LOGO_RESET,
                (false, false) => ORG_BRANDING_LOGO_RESET,
            };
            match action {
                LogoAction::Set { file } => {
                    let png = tokio::fs::read(&file)
                        .await
                        .map_err(|e| format!("{}: {e}", file.display()))?;
                    let v: BrandingView = client
                        .put_branding_logo(op, &p, png)
                        .await
                        .map_err(|e| e.hint(415, "знак — файл PNG (image/png)"))?;
                    out(args, &v, branding_record(&v))
                }
                LogoAction::Reset => {
                    let v: BrandingView = client.call(op, &p, &[], NO_BODY).await?;
                    out(args, &v, branding_record(&v))
                }
            }
        }
    }
}

/// Брендинг уровня — строки «подпись: значение».
fn branding_record(v: &BrandingView) -> String {
    let name = v
        .effective
        .product_name
        .clone()
        .unwrap_or_else(|| "IT TASK".to_owned());
    let logo = match v.effective.logo {
        None => "встроенный IT TASK".to_owned(),
        Some(l) => format!("{} (PNG {}×{}, {} байт)", l.hash, l.width, l.height, l.size),
    };
    let set = match &v.own {
        None => "не задан — действует уровень выше".to_owned(),
        Some(o) => format!(
            "название {}, основной {}, роли: light {}, dark {}, cli {}",
            o.product_name.as_deref().unwrap_or("—"),
            o.primary.map(|c| c.to_string()).as_deref().unwrap_or("—"),
            o.light.len(),
            o.dark.len(),
            o.cli.len()
        ),
    };
    record(&[
        ("Название", name),
        ("Знак", logo),
        ("Свой набор уровня", set),
    ])
}

/// Уровень политики доверия для команд `trust`: установка без `--org`, организация с ним (или `--group`,
/// `--account` — организация по умолчанию администратора).
enum TrustTarget {
    /// Уровень установки.
    Installation,
    /// Уровень организации.
    Org(String),
    /// Уровень группы (организация, группа).
    Group(String, String),
    /// Действующая для учётной записи (организация, учётная запись).
    Account(String, String),
}

impl TrustTarget {
    /// Операции уровня (`GET`, `PUT`, `DELETE`) и параметры пути.
    fn ops(&self) -> (Op, Op, Op, Vec<String>) {
        match self {
            TrustTarget::Installation => (TRUST_GET, TRUST_PUT, TRUST_RESET, Vec::new()),
            TrustTarget::Org(org) => (
                ORG_TRUST_GET,
                ORG_TRUST_PUT,
                ORG_TRUST_RESET,
                vec![org.clone()],
            ),
            TrustTarget::Group(org, group) => (
                GROUP_TRUST_GET,
                GROUP_TRUST_PUT,
                GROUP_TRUST_RESET,
                vec![org.clone(), group.clone()],
            ),
            TrustTarget::Account(org, account) => (
                ACCOUNT_TRUST_GET,
                ACCOUNT_TRUST_GET,
                ACCOUNT_TRUST_GET,
                vec![org.clone(), account.clone()],
            ),
        }
    }
}

/// Уровень `trust …`: `--group` и `--account` — в организации из `--org` (иначе организации администратора);
/// без них уровень установки выбирает `--org`/`THEPOST_ADMIN_ORG` (нет — установка, как у брендинга).
async fn trust_target(
    client: &Client,
    args: &ApiArgs,
    group: Option<String>,
    account: Option<String>,
) -> CliResult<TrustTarget> {
    if let Some(account) = account {
        let org = client.org(args.org.clone()).await?;
        let id = account_id(client, &org, &account).await?;
        return Ok(TrustTarget::Account(org, id));
    }
    if let Some(group) = group {
        let org = client.org(args.org.clone()).await?;
        let id = group_id(client, &org, &group).await?;
        return Ok(TrustTarget::Group(org, id));
    }
    Ok(match setting(args.org.clone(), ENV_ORG) {
        None => TrustTarget::Installation,
        Some(o) => {
            o.parse::<tp_contracts::TenantId>()
                .map_err(|e| format!("организация {o:?}: {e}"))?;
            TrustTarget::Org(o)
        }
    })
}

/// `thepost admin trust …`.
async fn trust_command(client: &Client, args: &ApiArgs, action: TrustAction) -> CliResult<String> {
    match action {
        TrustAction::Show { group, account } => {
            let target = trust_target(client, args, group, account).await?;
            let (get, _, _, params) = target.ops();
            let p = params.iter().map(String::as_str).collect::<Vec<_>>();
            let v: TrustView = client.call(get, &p, &[], NO_BODY).await?;
            out(args, &v, trust_text(args.theme(), &v))
        }
        TrustAction::Set { group, file } => {
            let text = input_text(file).await?;
            let body: TrustBody =
                serde_json::from_str(&text).map_err(|e| format!("политика доверия (JSON): {e}"))?;
            let target = trust_target(client, args, group, None).await?;
            let (get, put, _, params) = target.ops();
            let p = params.iter().map(String::as_str).collect::<Vec<_>>();
            let before: TrustView = client.call(get, &p, &[], NO_BODY).await?;
            let after: TrustView = client
                .call(put, &p, &[], Some(&body))
                .await
                .map_err(|e| e.hint(422, "значения не выше потолка уровня выше (trust show)"))?;
            out(
                args,
                &after,
                style::changes(args.theme(), put, &before.own, &after.own),
            )
        }
        TrustAction::Reset { group } => {
            let target = trust_target(client, args, group, None).await?;
            let (_, _, reset, params) = target.ops();
            let p = params.iter().map(String::as_str).collect::<Vec<_>>();
            let v: TrustView = client.call(reset, &p, &[], NO_BODY).await?;
            out(args, &v, trust_text(args.theme(), &v))
        }
        TrustAction::Partners { action } => {
            let org = client.org(args.org.clone()).await?;
            let params = [org.as_str()];
            match action {
                PartnersAction::List => {
                    let v: TrustView = client.call(ORG_TRUST_GET, &params, &[], NO_BODY).await?;
                    let domains = v
                        .own
                        .as_ref()
                        .map(|o| o.partners.clone())
                        .unwrap_or_default();
                    let rows: Vec<Vec<String>> = domains.iter().map(|d| vec![d.clone()]).collect();
                    out(
                        args,
                        &domains,
                        style::table(args.theme(), &["ДОМЕН"], &rows),
                    )
                }
                PartnersAction::Set { domains } => {
                    let before: TrustView =
                        client.call(ORG_TRUST_GET, &params, &[], NO_BODY).await?;
                    let mut body = match &before.own {
                        Some(own) => TrustBody::from(own),
                        None => TrustBody::default(),
                    };
                    body.partners = domains;
                    let after: TrustView = client
                        .call(ORG_TRUST_PUT, &params, &[], Some(&body))
                        .await
                        .map_err(|e| {
                            e.hint(422, "домены — канонические (нижний регистр), свой принятый домен нельзя")
                        })?;
                    out(
                        args,
                        &after,
                        style::changes(args.theme(), ORG_TRUST_PUT, &before.own, &after.own),
                    )
                }
            }
        }
    }
}

/// `thepost admin risk …` (ADM-51): признаки и пороги уровней (установка без `--org`, организация с
/// ним), пакеты поставщика, источники TI и журнал срабатываний организации.
async fn risk_command(client: &Client, args: &ApiArgs, action: RiskAction) -> CliResult<String> {
    match action {
        RiskAction::Signals { action } => {
            let level = risk_level(args)?;
            match *action {
                SignalsAction::List => {
                    let (op, _, params) = signal_ops(&level);
                    let p = params.iter().map(String::as_str).collect::<Vec<_>>();
                    let v: SignalsView = client.call(op, &p, &[], NO_BODY).await?;
                    let rows: Vec<Vec<String>> = v
                        .signals
                        .iter()
                        .map(|s| {
                            vec![
                                s.id.clone(),
                                signal_detector_text(s),
                                optional(s.weight.as_ref()),
                                optional(s.action.as_ref()),
                                optional(s.mode.as_ref()),
                                signal_source_text(s),
                            ]
                        })
                        .collect();
                    out(
                        args,
                        &v,
                        style::table(
                            args.theme(),
                            &[
                                "ПРИЗНАК",
                                "ДЕТЕКТОР",
                                "ВЕС",
                                "ДЕЙСТВИЕ",
                                "РЕЖИМ",
                                "ИСТОЧНИК",
                            ],
                            &rows,
                        ),
                    )
                }
                SignalsAction::Set {
                    id,
                    weight,
                    action: act,
                    mode,
                    detector,
                    threshold,
                } => {
                    let body = SignalBody {
                        weight,
                        action: act.as_deref().map(risk_action_arg).transpose()?,
                        mode: mode.as_deref().map(mode_arg).transpose()?,
                        detector: detector.as_deref().map(detector_arg).transpose()?,
                        threshold,
                    };
                    let (_, op, mut params) = signal_ops(&level);
                    params.push(id.clone());
                    let p = params.iter().map(String::as_str).collect::<Vec<_>>();
                    let v: SignalView =
                        client.call(op, &p, &[], Some(&body)).await.map_err(|e| {
                            e.hint(
                                422,
                                "организация может только ужесточить (risk signals list)",
                            )
                        })?;
                    out(args, &v, signal_record(&v))
                }
                SignalsAction::Reset { id } => {
                    let (_, _, mut params) = signal_ops(&level);
                    params.push(id.clone());
                    let p = params.iter().map(String::as_str).collect::<Vec<_>>();
                    let op = match &level {
                        RiskLevel::Installation => RISK_SIGNAL_RESET,
                        RiskLevel::Org(_) => ORG_RISK_SIGNAL_RESET,
                    };
                    let v: SignalView = client.call(op, &p, &[], NO_BODY).await?;
                    out(args, &v, format!("Изменение признака {id} сброшено.\n"))
                }
            }
        }
        RiskAction::Thresholds { action } => {
            let level = risk_level(args)?;
            let (get, put): (Op, Op) = match &level {
                RiskLevel::Installation => (RISK_THRESHOLDS_GET, RISK_THRESHOLDS_PUT),
                RiskLevel::Org(_) => (ORG_RISK_THRESHOLDS_GET, ORG_RISK_THRESHOLDS_PUT),
            };
            let params = level.params();
            let p = params.iter().map(String::as_str).collect::<Vec<_>>();
            match *action {
                ThresholdsAction::Show => {
                    let v: ThresholdsView = client.call(get, &p, &[], NO_BODY).await?;
                    out(args, &v, thresholds_record(&v))
                }
                ThresholdsAction::Set {
                    tag,
                    junk,
                    quarantine,
                    reject,
                } => {
                    let body = ThresholdsBody {
                        tag,
                        junk,
                        quarantine,
                        reject,
                    };
                    let v: ThresholdsView =
                        client.call(put, &p, &[], Some(&body)).await.map_err(|e| {
                            e.hint(422, "пороги растут с действием и не мягче уровня выше")
                        })?;
                    out(args, &v, thresholds_record(&v))
                }
            }
        }
        RiskAction::Package { action } => match *action {
            PackageAction::List => {
                let v: PackagesView = client.call(RISK_PACKAGES_LIST, &[], &[], NO_BODY).await?;
                let rows: Vec<Vec<String>> = v
                    .packages
                    .iter()
                    .map(|p| vec![p.version.to_string(), package_state_text(p)])
                    .collect();
                out(
                    args,
                    &v,
                    style::table(args.theme(), &["ВЕРСИЯ", "СОСТОЯНИЕ"], &rows),
                )
            }
            PackageAction::Import { file } => {
                let bytes = input_bytes(file).await?;
                let r: PackageReportView = client
                    .call_octet(RISK_PACKAGE_IMPORT, &[], bytes)
                    .await
                    .map_err(|e| {
                        e.hint(
                            422,
                            "подпись, lint и номер версии пакета (risk package list)",
                        )
                    })?;
                let u = &r.update;
                let text = format!(
                    "{}Пакет версии {} проверен и поставлен, не активен: thepost admin risk package activate {}\n",
                    record(&[
                        ("Версия", r.version.to_string()),
                        ("Ключ подписи", r.key_id.clone()),
                        ("Образцов прогона", r.samples.to_string()),
                        ("Признаков", r.signals.to_string()),
                        (
                            "Изменится",
                            format!(
                                "добавлено {}, изменено {}, удалено {}, осиротевших изменений {}",
                                u.added.len(),
                                u.changed.len(),
                                u.removed.len(),
                                u.orphaned_overrides.len()
                            )
                        ),
                    ]),
                    r.version,
                    r.version
                );
                out(args, &r, text)
            }
            PackageAction::Activate { version } => {
                let v: PackagesView = client
                    .call(RISK_PACKAGE_ACTIVATE, &[&version.to_string()], &[], NO_BODY)
                    .await
                    .map_err(|e| e.hint(422, "номер версии только растёт (risk package list)"))?;
                out(args, &v, format!("Пакет версии {version} активирован.\n"))
            }
            PackageAction::Rollback { version } => {
                let v: PackagesView = client
                    .call(RISK_PACKAGE_ROLLBACK, &[&version.to_string()], &[], NO_BODY)
                    .await?;
                out(args, &v, format!("Откат на пакет версии {version}.\n"))
            }
        },
        RiskAction::Source { action } => match *action {
            RiskSourceAction::List => {
                let v: SourcesView = client.call(RISK_SOURCES_LIST, &[], &[], NO_BODY).await?;
                let rows: Vec<Vec<String>> = v
                    .sources
                    .iter()
                    .map(|s| {
                        vec![
                            s.id.clone(),
                            s.tier.to_string(),
                            source_kind_text(s),
                            json_field(s, "format"),
                            json_field(s, "ttl"),
                        ]
                    })
                    .collect();
                out(
                    args,
                    &v,
                    style::table(
                        args.theme(),
                        &["ИСТОЧНИК", "УРОВЕНЬ", "ДОСТАВКА", "ФОРМАТ", "TTL"],
                        &rows,
                    ),
                )
            }
            RiskSourceAction::Add { file } => {
                let text = input_text(file).await?;
                let body: NewTiSourceBody =
                    serde_json::from_str(&text).map_err(|e| format!("источник TI (JSON): {e}"))?;
                let v: TiSourceView = client
                    .call(RISK_SOURCE_CREATE, &[], &[], Some(&body))
                    .await
                    .map_err(|e| {
                        e.hint(
                            400,
                            "ключ — ссылка {\"secret\": \"путь#поле\"}; bundled — только пакетом",
                        )
                    })?;
                out(args, &v, source_record(&v))
            }
            RiskSourceAction::Set { id, file } => {
                let text = input_text(file).await?;
                let body: TiSourceBody =
                    serde_json::from_str(&text).map_err(|e| format!("источник TI (JSON): {e}"))?;
                let v: TiSourceView = client
                    .call(RISK_SOURCE_PUT, &[&id], &[], Some(&body))
                    .await?;
                out(args, &v, source_record(&v))
            }
            RiskSourceAction::Rm { id } => {
                let v: TiSourceView = client
                    .call(RISK_SOURCE_DELETE, &[&id], &[], NO_BODY)
                    .await?;
                out(args, &v, format!("Источник {id} удалён.\n"))
            }
            RiskSourceAction::Import { id, file } => {
                let bytes = input_bytes(file).await?;
                let v: ListVersionView =
                    client.call_octet(RISK_SOURCE_IMPORT, &[&id], bytes).await?;
                out(args, &v, list_version_record(&v))
            }
            RiskSourceAction::Refresh { id } => {
                let v: ListVersionView = client
                    .call(RISK_SOURCE_REFRESH, &[&id], &[], NO_BODY)
                    .await?;
                out(args, &v, list_version_record(&v))
            }
            RiskSourceAction::Usage { id, since } => {
                let query = since
                    .as_deref()
                    .map(|sv| vec![("since".to_owned(), sv.to_owned())])
                    .unwrap_or_default();
                let v: UsageView = client
                    .call(RISK_SOURCE_USAGE, &[&id], &query, NO_BODY)
                    .await?;
                let rows: Vec<Vec<String>> = v
                    .usage
                    .iter()
                    .map(|u| vec![u.tenant.clone(), u.lookups.to_string(), u.hits.to_string()])
                    .collect();
                out(
                    args,
                    &v,
                    style::table(
                        args.theme(),
                        &["ОРГАНИЗАЦИЯ", "ОБРАЩЕНИЯ", "СОВПАДЕНИЯ"],
                        &rows,
                    ),
                )
            }
        },
        RiskAction::Hits(hits) => {
            let org = client.org(args.org.clone()).await?;
            let params: serde_json::Value = serde_json::json!({
                "signal": hits.signal, "mode": hits.mode, "since": hits.since,
                "until": hits.until, "limit": hits.limit,
            });
            let v: HitsView = client
                .call(ORG_RISK_HITS, &[&org], &query(&params)?, NO_BODY)
                .await?;
            let rows: Vec<Vec<String>> = v
                .hits
                .iter()
                .map(|h| {
                    vec![
                        json_field(h, "at"),
                        h.signal.clone(),
                        h.message.clone(),
                        h.strength.to_string(),
                        h.weight.to_string(),
                        h.mode.to_string(),
                    ]
                })
                .collect();
            let mut text = style::table(
                args.theme(),
                &["МОМЕНТ", "ПРИЗНАК", "ПИСЬМО", "СИЛА", "ВЕС", "РЕЖИМ"],
                &rows,
            );
            if let Some(next) = &v.next {
                text.push_str(&style::more(
                    args.theme(),
                    &format!("Есть ещё. Следующая страница: те же условия и --until {next}"),
                ));
            }
            out(args, &v, text)
        }
    }
}

/// Уровень команд `risk` без `--org`/`THEPOST_ADMIN_ORG` — установка, с ними — организация (как у
/// брендинга и политики доверия).
fn risk_level(args: &ApiArgs) -> CliResult<RiskLevel> {
    Ok(match setting(args.org.clone(), ENV_ORG) {
        None => RiskLevel::Installation,
        Some(o) => {
            let org = o
                .parse::<tp_contracts::TenantId>()
                .map_err(|e| format!("организация {o:?}: {e}"))?;
            RiskLevel::Org(org.to_string())
        }
    })
}

/// Уровень справочника для команд `risk`.
enum RiskLevel {
    /// Уровень установки.
    Installation,
    /// Уровень организации (UUID).
    Org(String),
}

impl RiskLevel {
    /// Параметры пути маршрутов уровня.
    fn params(&self) -> Vec<String> {
        match self {
            RiskLevel::Installation => Vec::new(),
            RiskLevel::Org(org) => vec![org.clone()],
        }
    }
}

/// Операции признака уровня: `PUT` и параметры пути (`DELETE` — рядом).
fn signal_ops(level: &RiskLevel) -> (Op, Op, Vec<String>) {
    let params = level.params();
    match level {
        RiskLevel::Installation => (RISK_SIGNALS_LIST, RISK_SIGNAL_PUT, params),
        RiskLevel::Org(_) => (ORG_RISK_SIGNALS_LIST, ORG_RISK_SIGNAL_PUT, params),
    }
}

/// Собственное действие признака из аргумента (none, tag, junk, quarantine, reject).
fn risk_action_arg(raw: &str) -> CliResult<tp_contracts::risk::RiskAction> {
    serde_json::from_value(serde_json::json!(raw))
        .map_err(|e| format!("действие {raw:?}: none, tag, junk, quarantine, reject ({e})"))
}

/// Режим признака из аргумента (report, enforce).
fn mode_arg(raw: &str) -> CliResult<tp_contracts::risk::Mode> {
    serde_json::from_value(serde_json::json!(raw))
        .map_err(|e| format!("режим {raw:?}: report или enforce ({e})"))
}

/// Детектор своего признака из аргумента.
fn detector_arg(raw: &str) -> CliResult<tp_contracts::risk::Detector> {
    serde_json::from_value(serde_json::json!(raw)).map_err(|e| format!("детектор {raw:?}: {e}"))
}

/// Признак — строки «подпись: значение».
fn signal_record(s: &SignalView) -> String {
    record(&[
        ("Признак", s.id.clone()),
        ("Детектор", signal_detector_text(s)),
        ("Вес", optional(s.weight.as_ref())),
        ("Порог силы", optional(s.threshold.as_ref())),
        ("Действие", optional(s.action.as_ref())),
        ("Режим", optional(s.mode.as_ref())),
        ("Источник значения", signal_source_text(s)),
    ])
}

/// Детектор признака для таблицы и записи; осиротевшее изменение — пометка.
fn signal_detector_text(s: &SignalView) -> String {
    if let Some(d) = &s.detector {
        return serde_json::to_value(d).map_or_else(|_| "—".to_owned(), |v| value_text(&v));
    }
    if s.orphaned {
        "осиротевшее изменение".to_owned()
    } else {
        "—".to_owned()
    }
}

/// Источник значения признака для таблицы.
fn signal_source_text(s: &SignalView) -> String {
    match &s.source {
        None => "пакет".to_owned(),
        Some(tp_contracts::risk::RiskLevel::Installation) => "установка".to_owned(),
        Some(tp_contracts::risk::RiskLevel::Org(_)) => "организация".to_owned(),
    }
}

/// Состояние пакета по-русски.
fn package_state_text(p: &PackageEntryView) -> String {
    match &p.state {
        tp_contracts::risk::PackageState::Active => "действующий".to_owned(),
        tp_contracts::risk::PackageState::Previous => "прошлый".to_owned(),
        tp_contracts::risk::PackageState::Rejected { report } => format!("отклонён: {report}"),
    }
}

/// Доставка источника для таблицы.
fn source_kind_text(s: &TiSourceView) -> String {
    match &s.kind {
        tp_contracts::risk::SourceKind::Http { url } => url.clone(),
        tp_contracts::risk::SourceKind::Taxii { api_root, .. } => api_root.clone(),
        tp_contracts::risk::SourceKind::File => "файл".to_owned(),
    }
}

/// Источник TI — строки «подпись: значение».
fn source_record(s: &TiSourceView) -> String {
    record(&[
        ("Источник", s.id.clone()),
        ("Уровень", s.tier.to_string()),
        ("Доставка", source_kind_text(s)),
        ("Формат", json_field(s, "format")),
        ("TTL", json_field(s, "ttl")),
        (
            "Ключ",
            s.key
                .as_ref()
                .map(|k| k.to_string())
                .unwrap_or_else(|| "—".to_owned()),
        ),
        ("Происхождение", s.origin.to_string()),
    ])
}

/// Версия списка — строки «подпись: значение».
fn list_version_record(v: &ListVersionView) -> String {
    record(&[
        ("Список", v.list.clone()),
        ("Источник", v.source.clone()),
        ("SHA-256", v.sha256.clone()),
        ("Записей", v.entries.to_string()),
        ("Загружен", json_field(v, "fetched_at")),
    ])
}

/// Пороги — строки «подпись: значение».
fn thresholds_record(v: &ThresholdsView) -> String {
    record(&[
        (
            "Свои",
            v.own
                .as_ref()
                .map(|t| {
                    format!(
                        "пометка {}, спам {}, карантин {}, отказ {}",
                        t.tag, t.junk, t.quarantine, t.reject
                    )
                })
                .unwrap_or_else(|| "—".to_owned()),
        ),
        (
            "Действующие",
            format!(
                "пометка {}, спам {}, карантин {}, отказ {}",
                v.effective.tag, v.effective.junk, v.effective.quarantine, v.effective.reject
            ),
        ),
        ("Источник", thresholds_source_text(v)),
    ])
}

/// Источник действующих порогов по-русски.
fn thresholds_source_text(v: &ThresholdsView) -> String {
    match &v.source {
        None => "константы каталога".to_owned(),
        Some(tp_contracts::risk::RiskLevel::Installation) => "установка".to_owned(),
        Some(tp_contracts::risk::RiskLevel::Org(_)) => "организация".to_owned(),
    }
}

/// Политика доверия — действующая матрица (значения по клеткам, «выше потолка» и «закреплено») и домены уровня.
fn trust_text(t: Theme, v: &TrustView) -> String {
    let m = &v.effective.matrix;
    let cell = |f: TrustFunction, peer: PeerKind| {
        let mut s = m.get(f, peer).to_string();
        if v.effective
            .over_ceiling
            .iter()
            .any(|o| o.function == f && o.peer == peer)
        {
            s.push_str(" (выше потолка)");
        }
        if v.fixed.get(f, peer) {
            s.push_str(" (закреплено)");
        }
        s
    };
    let rows: Vec<Vec<String>> = TrustFunction::ALL
        .into_iter()
        .map(|f| {
            vec![
                trust_function_ru(f).to_owned(),
                cell(f, PeerKind::Own),
                cell(f, PeerKind::Partner),
                cell(f, PeerKind::Neighbor),
                cell(f, PeerKind::External),
            ]
        })
        .collect();
    let mut text = style::table(
        t,
        &["ФУНКЦИЯ", "СВОИ", "ПАРТНЁР", "СОСЕД", "ИНТЕРНЕТ"],
        &rows,
    );
    if let Some(own) = &v.own {
        let list = |domains: &[String]| {
            if domains.is_empty() {
                "—".to_owned()
            } else {
                domains.join(", ")
            }
        };
        text.push_str(&format!(
            "Домены-партнёры: {}\nДомены автопересылки: {}\n",
            list(&own.partners),
            list(&own.auto_forward_domains)
        ));
    }
    text
}

/// Функция матрицы по-русски (как в `docs/ADMIN-GUIDE.md`).
fn trust_function_ru(f: TrustFunction) -> &'static str {
    match f {
        TrustFunction::InviteNew => "Новое приглашение",
        TrustFunction::ItipUpdates => "Ответ и отмена",
        TrustFunction::AutoReply => "Автоответ",
        TrustFunction::Mdn => "Уведомление о прочтении",
        TrustFunction::AutoForward => "Автопересылка",
        TrustFunction::FreeBusy => "Занятость",
        TrustFunction::Sharing => "Общий доступ",
        TrustFunction::GroupPost => "Письма в группы",
    }
}

/// `thepost admin trash …`.
async fn trash_command(client: &Client, args: &ApiArgs, action: TrashAction) -> CliResult<String> {
    let org = client.org(args.org.clone()).await?;
    match action {
        TrashAction::List {
            account,
            hidden,
            subject,
            offset,
            limit,
        } => {
            let id = account_id(client, &org, &account).await?;
            let op = if hidden {
                TRASH_HIDDEN_LIST
            } else {
                TRASH_LIST
            };
            let query = query(&PageQuery {
                offset,
                limit,
                include: subject.then(|| "subject".to_owned()),
            })?;
            let page: TrashPage = client.call(op, &[&org, &id], &query, NO_BODY).await?;
            let mut cols = vec!["ПИСЬМО", "ПАПКА", "РАЗМЕР", "УДАЛЕНО", "УДАЛЯЕТСЯ"];
            if subject {
                cols.extend(["ТЕМА", "ОТПРАВИТЕЛЬ"]);
            }
            let rows: Vec<Vec<String>> = page
                .items
                .iter()
                .map(|e| {
                    let mut row = vec![
                        e.message.clone(),
                        e.origin.clone(),
                        e.size.to_string(),
                        json_field(e, "deleted_at"),
                        json_field(e, "expires_at"),
                    ];
                    if subject {
                        for v in [&e.subject, &e.from] {
                            row.push(optional(v.clone().flatten().as_ref()));
                        }
                    }
                    row
                })
                .collect();
            let retention = match page.trash_retention {
                Some(_) => json_field(&page, "trash_retention"),
                None => "по умолчанию узла".to_owned(),
            };
            let mut text = format!(
                "{}Срок корзины: {retention}\n",
                style::table(args.theme(), &cols, &rows)
            );
            if let Some(next) = page.next_offset {
                text.push_str(&style::more(
                    args.theme(),
                    &format!("Есть ещё. Следующая страница: --offset {next}"),
                ));
            }
            out(args, &page, text)
        }
        TrashAction::Restore {
            account,
            message,
            hidden,
        } => {
            let id = account_id(client, &org, &account).await?;
            let op = if hidden {
                TRASH_HIDDEN_RESTORE
            } else {
                TRASH_RESTORE
            };
            let r: RestoredMessage = client
                .call(op, &[&org, &id, &message], &[], NO_BODY)
                .await?;
            let text = format!("Письмо {} восстановлено, UID {}.\n", r.message, r.uid);
            out(args, &r, text)
        }
    }
}

/// `thepost admin audit search`: одна страница; продолжение — подсказкой `--after`.
async fn audit_command(client: &Client, args: &ApiArgs, action: AuditAction) -> CliResult<String> {
    let AuditAction::Search {
        since,
        until,
        actor,
        method,
        route,
        limit,
        after,
    } = action;
    let org = client.org(args.org.clone()).await?;
    let params: AuditParams = from_json(
        serde_json::json!({
            "since": since, "until": until, "actor": actor, "method": method, "route": route,
            "limit": limit, "after": after,
        }),
        "журнал аудита",
    )?;
    let page: AuditPage = client
        .call(AUDIT_SEARCH, &[&org], &query(&params)?, NO_BODY)
        .await?;
    let rows: Vec<Vec<String>> = page
        .entries
        .iter()
        .map(|e| {
            let r = &e.record;
            vec![
                e.seq.to_string(),
                json_field(r, "at"),
                r.actor_login.clone(),
                r.method.clone(),
                r.route.clone(),
                r.status.to_string(),
            ]
        })
        .collect();
    let mut text = style::table(
        args.theme(),
        &[
            "НОМЕР",
            "МОМЕНТ",
            "АДМИНИСТРАТОР",
            "МЕТОД",
            "МАРШРУТ",
            "КОД",
        ],
        &rows,
    );
    if let Some(next) = page.next {
        text.push_str(&style::more(
            args.theme(),
            &format!("Есть ещё. Следующая страница: те же условия и --after {next}"),
        ));
    }
    out(args, &page, text)
}

/// `thepost admin delivery search`: одна страница; продолжение — подсказкой `--after`.
async fn delivery_command(
    client: &Client,
    args: &ApiArgs,
    action: DeliveryAction,
) -> CliResult<String> {
    let DeliveryAction::Search {
        sender,
        recipient,
        message_id,
        since,
        until,
        limit,
        after,
    } = action;
    let org = client.org(args.org.clone()).await?;
    let params: DeliveryParams = from_json(
        serde_json::json!({
            "sender": sender, "recipient": recipient, "message_id": message_id, "since": since,
            "until": until, "limit": limit, "after": after,
        }),
        "журнал доставки",
    )?;
    let page: DeliveryResults = client
        .call(DELIVERY_SEARCH, &[&org], &query(&params)?, NO_BODY)
        .await?;
    let rows: Vec<Vec<String>> = page
        .events
        .iter()
        .map(|e| {
            vec![
                json_field(e, "at"),
                json_field(e, "kind"),
                or_dash(&e.sender),
                e.recipients.join(", "),
                json_field(e, "decision"),
                optional(e.reason.as_ref()),
            ]
        })
        .collect();
    let mut text = style::table(
        args.theme(),
        &[
            "МОМЕНТ",
            "СОБЫТИЕ",
            "ОТПРАВИТЕЛЬ",
            "ПОЛУЧАТЕЛИ",
            "РЕШЕНИЕ",
            "ПРИЧИНА",
        ],
        &rows,
    );
    if let Some(next) = &page.next {
        text.push_str(&style::more(
            args.theme(),
            &format!("Есть ещё. Следующая страница: те же условия и --after {next}"),
        ));
    }
    out(args, &page, text)
}

/// `thepost admin journal search`: одна страница; продолжение — подсказкой `--after`.
async fn journal_command(
    client: &Client,
    args: &ApiArgs,
    action: JournalAction,
) -> CliResult<String> {
    let org = client.org(args.org.clone()).await?;
    match action {
        JournalAction::Search {
            sender,
            recipient,
            message_id,
            rule,
            since,
            until,
            limit,
            after,
        } => {
            let params: tp_admin::journal::JournalParams = from_json(
                serde_json::json!({
                    "sender": sender, "recipient": recipient, "message_id": message_id,
                    "rule": rule, "since": since, "until": until, "limit": limit, "after": after,
                }),
                "журнал переписки",
            )?;
            let page: tp_admin::journal::JournalPageView = client
                .call(JOURNAL_SEARCH, &[&org], &query(&params)?, NO_BODY)
                .await?;
            let rows: Vec<Vec<String>> = page
                .entries
                .iter()
                .map(|e| {
                    vec![
                        json_field(&e.record, "at"),
                        e.record.sender.clone(),
                        e.record.recipients.join(", "),
                        or_dash(e.record.message_id.as_deref().unwrap_or_default()),
                        e.record.rule.clone(),
                        e.id.clone(),
                    ]
                })
                .collect();
            let mut text = style::table(
                args.theme(),
                &[
                    "МОМЕНТ",
                    "ОТПРАВИТЕЛЬ",
                    "ПОЛУЧАТЕЛИ",
                    "MESSAGE-ID",
                    "ПРАВИЛО",
                    "ЗАПИСЬ",
                ],
                &rows,
            );
            if let Some(next) = &page.next {
                text.push_str(&style::more(
                    args.theme(),
                    &format!("Есть ещё. Следующая страница: те же условия и --after {next}"),
                ));
            }
            out(args, &page, text)
        }
        JournalAction::Get { id } => {
            let e: tp_admin::journal::JournalEntryView =
                client.call(JOURNAL_GET, &[&org, &id], &[], NO_BODY).await?;
            out(args, &e, journal_entry_record(&e))
        }
        JournalAction::Export { id, output } => {
            let eml = client.bytes(JOURNAL_EXPORT, &[&org, &id]).await?;
            match output {
                Some(path) => {
                    std::fs::write(&path, &eml).map_err(|e| format!("{}: {e}", path.display()))?;
                    let text = format!(
                        "Запись {id} выгружена в {} ({} байт).\n",
                        path.display(),
                        eml.len()
                    );
                    out(
                        args,
                        &serde_json::json!({"written": path.display().to_string()}),
                        text,
                    )
                }
                // .eml — не обязательно UTF-8: в stdout байты как есть, без оформления.
                None => std::io::stdout()
                    .write_all(&eml)
                    .map_err(|e| e.to_string())
                    .map(|()| String::new()),
            }
        }
        JournalAction::Verify => {
            let r: tp_admin::journal::ChainReportView =
                client.call(JOURNAL_VERIFY, &[&org], &[], NO_BODY).await?;
            let text = if r.ok {
                record(&[
                    ("Проверено записей", r.records.to_string()),
                    ("Цепочка целостна", "да".to_owned()),
                ])
            } else {
                record(&[
                    ("Проверено записей", r.records.to_string()),
                    ("Цепочка целостна", "нет".to_owned()),
                    ("Первая запись с нарушением", optional(r.broken_at.as_ref())),
                ])
            };
            out(args, &r, text)
        }
        JournalAction::Rule { action } => journal_rule_command(client, args, &org, *action).await,
    }
}

/// `thepost admin journal rule list/set/delete` (ADM-53): правила журналирования — администратор
/// организации; аудитор журнала правил не видит.
async fn journal_rule_command(
    client: &Client,
    args: &ApiArgs,
    org: &str,
    action: JournalRuleAction,
) -> CliResult<String> {
    match action {
        JournalRuleAction::List => {
            let list: tp_admin::journal::JournalRulesView = client
                .call(JOURNAL_RULES_LIST, &[org], &[], NO_BODY)
                .await?;
            let rows: Vec<Vec<String>> = list
                .rules
                .iter()
                .map(|r| {
                    vec![
                        r.id.clone(),
                        rule_scope(&r.scope),
                        rule_direction(r.direction).to_owned(),
                        yes_no(r.enabled),
                    ]
                })
                .collect();
            let text = format!(
                "{}Порядок наследования: ящик > группа > организация.\n",
                style::table(
                    args.theme(),
                    &["ПРАВИЛО", "ЦЕЛЬ", "НАПРАВЛЕНИЕ", "ВКЛЮЧЕНО"],
                    &rows,
                )
            );
            out(args, &list, text)
        }
        JournalRuleAction::Set {
            id,
            group,
            account,
            direction,
            disabled,
        } => {
            let scope = match (group, account) {
                (Some(g), _) => JournalScope::Group(
                    group_id(client, org, &g)
                        .await?
                        .parse()
                        .map_err(|e| format!("группа {g}: {e}"))?,
                ),
                (None, Some(a)) => JournalScope::Mailbox(
                    account_id(client, org, &a)
                        .await?
                        .parse()
                        .map_err(|e| format!("учётная запись {a}: {e}"))?,
                ),
                (None, None) => JournalScope::Org,
            };
            let body = tp_admin::journal::JournalRuleBody {
                scope,
                direction: direction.into(),
                enabled: !disabled,
            };
            let r: tp_admin::journal::JournalRuleView = client
                .call(JOURNAL_RULE_PUT, &[org, &id], &[], Some(&body))
                .await?;
            let text = format!(
                "{}Изменение конвейер подхватывает без перезапуска (следующие письма).\n",
                rule_record(&r)
            );
            out(args, &r, text)
        }
        JournalRuleAction::Delete { id } => {
            let r: tp_admin::journal::JournalRuleView = client
                .call(JOURNAL_RULE_DELETE, &[org, &id], &[], NO_BODY)
                .await?;
            out(args, &r, format!("Правило {id} удалено.\n"))
        }
    }
}

/// Правило журналирования — строки «подпись: значение».
fn rule_record(r: &tp_admin::journal::JournalRuleView) -> String {
    record(&[
        ("Правило", r.id.clone()),
        ("Организация", r.tenant.clone()),
        ("Цель", rule_scope(&r.scope)),
        ("Направление", rule_direction(r.direction).to_owned()),
        ("Включено", yes_no(r.enabled)),
    ])
}

/// Область правила — текст таблицы и записи.
fn rule_scope(scope: &JournalScope) -> String {
    match scope {
        JournalScope::Org => "организация".to_owned(),
        JournalScope::Group(g) => format!("группа {g}"),
        JournalScope::Mailbox(a) => format!("ящик {a}"),
    }
}

/// Направление правила — имя из API.
fn rule_direction(direction: tp_contracts::journal::JournalDirection) -> &'static str {
    match direction {
        tp_contracts::journal::JournalDirection::In => "in",
        tp_contracts::journal::JournalDirection::Out => "out",
        tp_contracts::journal::JournalDirection::Both => "both",
    }
}

/// Да/нет для таблиц.
fn yes_no(yes: bool) -> String {
    if yes {
        "да".to_owned()
    } else {
        "нет".to_owned()
    }
}

/// `thepost admin thread …`: беседа письма, удержание, список удержаний и выгрузка (ADM-50).
async fn thread_command(
    client: &Client,
    args: &ApiArgs,
    action: ThreadAction,
) -> CliResult<String> {
    let org = client.org(args.org.clone()).await?;
    match action {
        ThreadAction::Find {
            account,
            message_id,
        } => {
            let id = account_id(client, &org, &account).await?;
            let params = ThreadFindParams {
                message_id: Some(
                    message_id
                        .parse()
                        .map_err(|e| format!("--message-id {message_id:?}: {e}"))?,
                ),
            };
            let v: ThreadView = client
                .call(THREAD_FIND, &[&org, &id], &query(&params)?, NO_BODY)
                .await?;
            let mut text = record(&[
                ("Беседа", v.thread.clone()),
                (
                    "Удержание",
                    match &v.hold {
                        Some(h) => format!("{} ({}) — {}", h.by, json_field(h, "at"), h.reason),
                        None => "нет".to_owned(),
                    },
                ),
                ("Писем в беседе", v.messages.len().to_string()),
            ]);
            text.push_str("Письма (в порядке привязки):\n");
            text.push_str(&v.messages.join("\n"));
            text.push('\n');
            out(args, &v, text)
        }
        ThreadAction::Hold {
            account,
            thread,
            reason,
        } => {
            let id = account_id(client, &org, &account).await?;
            let hold: ThreadHoldView = client
                .call(
                    THREAD_HOLD,
                    &[&org, &id, &thread],
                    &[],
                    Some(&serde_json::to_value(ThreadHoldBody { reason }).expect("json")),
                )
                .await?;
            let text = format!(
                "Беседа {thread} удержана: {} ({}) — {}.\n",
                hold.by,
                json_field(&hold, "at"),
                hold.reason
            );
            out(args, &hold, text)
        }
        ThreadAction::Unhold { account, thread } => {
            let id = account_id(client, &org, &account).await?;
            client
                .call_empty(THREAD_UNHOLD, &[&org, &id, &thread], &[], NO_BODY)
                .await?;
            let text = format!("Удержание беседы {thread} снято.\n");
            out(
                args,
                &serde_json::json!({"thread": thread, "hold": null}),
                text,
            )
        }
        ThreadAction::Holds => {
            let page: ThreadHoldsView = client.call(THREAD_HOLDS, &[&org], &[], NO_BODY).await?;
            let rows: Vec<Vec<String>> = page
                .holds
                .iter()
                .map(|h| {
                    vec![
                        h.account.clone(),
                        h.thread.clone(),
                        h.hold.by.clone(),
                        json_field(&h.hold, "at"),
                        h.hold.reason.clone(),
                    ]
                })
                .collect();
            let text = if rows.is_empty() {
                style::more(args.theme(), "Удержанных бесед нет.")
            } else {
                style::table(
                    args.theme(),
                    &["УЧЁТНАЯ ЗАПИСЬ", "БЕСЕДА", "КТО", "КОГДА", "ОСНОВАНИЕ"],
                    &rows,
                )
            };
            out(args, &page, text)
        }
        ThreadAction::Export {
            account,
            thread,
            output,
        } => {
            let id = account_id(client, &org, &account).await?;
            let zip = client.bytes(THREAD_EXPORT, &[&org, &id, &thread]).await?;
            match output {
                Some(path) => {
                    std::fs::write(&path, &zip).map_err(|e| format!("{}: {e}", path.display()))?;
                    let text = format!(
                        "Беседа {thread} выгружена в {} ({} байт).\n",
                        path.display(),
                        zip.len()
                    );
                    out(
                        args,
                        &serde_json::json!({"written": path.display().to_string(), "bytes": zip.len()}),
                        text,
                    )
                }
                // Архив — двоичный: в stdout байты как есть, без оформления.
                None => std::io::stdout()
                    .write_all(&zip)
                    .map_err(|e| e.to_string())
                    .map(|()| String::new()),
            }
        }
    }
}

/// Запись журнала — строки «подпись: значение».
fn journal_entry_record(e: &tp_admin::journal::JournalEntryView) -> String {
    let r = &e.record;
    record(&[
        ("Запись", e.id.clone()),
        ("Организация", r.tenant.clone()),
        ("Момент", json_field(r, "at")),
        ("Отправитель", or_dash(&r.sender)),
        ("Получатели", r.recipients.join(", ")),
        ("Message-ID", optional(r.message_id.as_ref())),
        ("Правило", r.rule.clone()),
        ("Хеш цепочки", e.hash.clone()),
    ])
}

/// Структура запроса tp-admin из значений ключей CLI: разбор и проверка — её serde (время — RFC 3339).
fn from_json<T: DeserializeOwned>(v: serde_json::Value, what: &str) -> CliResult<T> {
    serde_json::from_value(v)
        .map_err(|e| format!("{what}: {e} (время — RFC 3339, например 2026-12-01T00:00:00Z)"))
}

/// `thepost admin transport domain …`.
async fn domain_command(
    client: &Client,
    args: &ApiArgs,
    org: &str,
    action: DomainAction,
) -> CliResult<String> {
    match action {
        DomainAction::List => {
            let list = domains(client, org).await?;
            let rows: Vec<Vec<String>> = list.domains.iter().map(domain_row).collect();
            let text = format!(
                "{}Версия снимка: {}\n",
                style::table(args.theme(), DOMAIN_COLUMNS, &rows),
                list.version
            );
            out(args, &list, text)
        }
        DomainAction::Create { name, relay } => {
            let version = domains(client, org).await?.version;
            let kind = match relay {
                Some(next_hop) => DomainKind::InternalRelay { next_hop },
                None => DomainKind::Authoritative,
            };
            let body = DomainBody {
                version,
                name,
                kind,
            };
            let w: DomainWritten = client.call(DOMAIN_CREATE, &[org], &[], Some(&body)).await?;
            let fields: Vec<(&str, String)> = DOMAIN_COLUMNS
                .iter()
                .copied()
                .zip(domain_row(&w.domain))
                .collect();
            let text = format!("{}Версия снимка: {}\n", record(&fields), w.version);
            out(args, &w, text)
        }
        DomainAction::Delete { domain } => {
            let list = domains(client, org).await?;
            let id = find_domain(&list, &domain)?;
            let query = query(&VersionQuery {
                version: list.version,
            })?;
            let w: Written = client
                .call(DOMAIN_DELETE, &[org, &id], &query, NO_BODY)
                .await?;
            let text = format!("Домен {domain} удалён. Версия снимка: {}\n", w.version);
            out(args, &w, text)
        }
    }
}

/// Идентификатор принятого домена в `list`: UUID как есть, иначе по имени (без учёта регистра).
fn find_domain(list: &DomainList, domain: &str) -> CliResult<String> {
    if domain.parse::<DomainId>().is_ok() {
        return Ok(domain.to_owned());
    }
    let name = domain.trim_end_matches('.');
    list.domains
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case(name))
        .map(|d| d.id.to_string())
        .ok_or_else(|| format!("принятый домен {domain} не найден"))
}

/// Идентификатор принятого домена организации по идентификатору или имени.
async fn domain_id(client: &Client, org: &str, domain: &str) -> CliResult<String> {
    if domain.parse::<DomainId>().is_ok() {
        return Ok(domain.to_owned());
    }
    find_domain(&domains(client, org).await?, domain)
}

const SOURCE_COLUMNS: &[&str] = &["ИМЯ", "ОТКУДА", "ВИД"];

/// `thepost admin transport source …`.
async fn source_command(
    client: &Client,
    args: &ApiArgs,
    org: &str,
    action: SourceAction,
) -> CliResult<String> {
    let sources = move || async move {
        client
            .call::<(), SourceList>(SOURCE_LIST, &[org], &[], NO_BODY)
            .await
    };
    match action {
        SourceAction::List => {
            let list = sources().await?;
            let rows: Vec<Vec<String>> = list.sources.iter().map(source_row).collect();
            let text = format!(
                "{}Версия снимка: {}\n",
                style::table(args.theme(), SOURCE_COLUMNS, &rows),
                list.version
            );
            out(args, &list, text)
        }
        SourceAction::Set {
            name,
            networks,
            client_cert,
            application,
            senders,
            external,
            xclient,
            authserv_id,
        } => {
            let matcher = match client_cert {
                Some(subject) => serde_json::json!({ "client_cert": { "subject": subject } }),
                None => serde_json::json!({ "networks": networks }),
            };
            let kind = if application {
                serde_json::json!({ "application": { "senders": senders, "external": external } })
            } else {
                serde_json::json!({ "gateway": { "xclient": xclient, "authserv_id": authserv_id } })
            };
            let list = sources().await?;
            let body: SourceBody = from_json(
                serde_json::json!({ "version": list.version, "matcher": matcher, "kind": kind }),
                "источник",
            )?;
            let w: Written = client
                .call(SOURCE_PUT, &[org, &name], &[], Some(&body))
                .await?;
            // Было/стало — запись источника в снимке до и после (новый источник — «было» пусто).
            let find = |list: SourceList| {
                list.sources
                    .into_iter()
                    .find(|s| s.name.eq_ignore_ascii_case(&name))
            };
            let before = find(list);
            let after = find(sources().await?);
            out(
                args,
                &w,
                style::changes(args.theme(), SOURCE_PUT, &before, &after),
            )
        }
        SourceAction::Delete { name } => {
            let query = query(&VersionQuery {
                version: sources().await?.version,
            })?;
            let w: Written = client
                .call(SOURCE_DELETE, &[org, &name], &query, NO_BODY)
                .await?;
            let text = format!("Источник {name} удалён. Версия снимка: {}\n", w.version);
            out(args, &w, text)
        }
    }
}

/// Доверенный источник — строка таблицы [`SOURCE_COLUMNS`].
fn source_row(s: &TrustedSource) -> Vec<String> {
    let join = |items: Vec<String>| items.join(", ");
    let matcher = match &s.matcher {
        SourceMatch::Networks(nets) => join(nets.iter().map(ToString::to_string).collect()),
        SourceMatch::ClientCert { subject } => format!("сертификат {subject}"),
    };
    let kind = match &s.kind {
        SourceKind::Gateway {
            xclient,
            authserv_id,
        } => {
            let mut k = "шлюз".to_owned();
            if *xclient {
                k.push_str(", XCLIENT");
            }
            if let Some(id) = authserv_id {
                k.push_str(&format!(", authserv-id {id}"));
            }
            k
        }
        SourceKind::Application { senders, external } => format!(
            "приложение: {}{}",
            join(senders.iter().map(ToString::to_string).collect()),
            if *external {
                ", внешние получатели"
            } else {
                ""
            }
        ),
    };
    vec![s.name.clone(), matcher, kind]
}

const ROUTE_COLUMNS: &[&str] = &["ШАБЛОН", "TLS", "SMART HOST", "ИСХОДЯЩИЙ IP"];

/// `thepost admin transport route …`.
async fn route_command(
    client: &Client,
    args: &ApiArgs,
    org: &str,
    action: RouteAction,
) -> CliResult<String> {
    let routes = move || async move {
        client
            .call::<(), RouteList>(ROUTE_LIST, &[org], &[], NO_BODY)
            .await
    };
    match action {
        RouteAction::List => {
            let list = routes().await?;
            let rows: Vec<Vec<String>> = list.routes.iter().map(route_row).collect();
            let text = format!(
                "{}Версия снимка: {}\n",
                style::table(args.theme(), ROUTE_COLUMNS, &rows),
                list.version
            );
            out(args, &list, text)
        }
        RouteAction::Set {
            pattern,
            tls,
            pins,
            smart_host,
            egress_ip,
        } => {
            let tls = match (tls, pins.is_empty()) {
                (_, false) => TlsRequirement::Pinned { spki_sha256: pins },
                (TlsMode::Opportunistic, true) => TlsRequirement::Opportunistic,
                (TlsMode::Required, true) => TlsRequirement::Required,
            };
            let egress_ip = egress_ip
                .map(|ip| {
                    ip.parse::<IpAddr>()
                        .map_err(|e| format!("--egress-ip {ip}: {e}"))
                })
                .transpose()?;
            let list = routes().await?;
            let body = RouteBody {
                version: list.version,
                tls,
                smart_host,
                egress_ip,
            };
            let w: Written = client
                .call(ROUTE_PUT, &[org, &pattern], &[], Some(&body))
                .await?;
            // Было/стало — политика в снимке до и после (шаблон узел приводит к нижнему регистру).
            let find = |list: RouteList| {
                list.routes
                    .into_iter()
                    .find(|r| r.pattern.eq_ignore_ascii_case(&pattern))
            };
            let before = find(list);
            let after = find(routes().await?);
            out(
                args,
                &w,
                style::changes(args.theme(), ROUTE_PUT, &before, &after),
            )
        }
        RouteAction::Delete { pattern } => {
            let query = query(&VersionQuery {
                version: routes().await?.version,
            })?;
            let w: Written = client
                .call(ROUTE_DELETE, &[org, &pattern], &query, NO_BODY)
                .await?;
            let text = format!("Политика {pattern} удалена. Версия снимка: {}\n", w.version);
            out(args, &w, text)
        }
    }
}

/// Политика домена назначения — строка таблицы [`ROUTE_COLUMNS`].
fn route_row(r: &DestinationPolicy) -> Vec<String> {
    let tls = match &r.tls {
        TlsRequirement::Opportunistic => "opportunistic".to_owned(),
        TlsRequirement::Required => "required".to_owned(),
        TlsRequirement::Pinned { spki_sha256 } => format!("pinned: {}", spki_sha256.join(", ")),
    };
    vec![
        r.pattern.clone(),
        tls,
        optional(r.smart_host.as_ref()),
        optional(r.egress_ip.as_ref()),
    ]
}

/// Параметры `vacation set`: `None` — поле без изменений, `-` — сброс (`from`, `to`, `subject`,
/// `external_subject`).
struct VacationChange {
    enabled: bool,
    from: Option<String>,
    to: Option<String>,
    subject: Option<String>,
    text: Option<String>,
    html: Option<String>,
    external_subject: Option<String>,
    external_text: Option<String>,
}

impl VacationChange {
    /// Автоответ `current` с изменениями; время разбирает сама структура tp-admin (RFC 3339).
    fn apply(self, current: &VacationBody) -> CliResult<VacationBody> {
        let mut v = serde_json::to_value(current).map_err(|e| e.to_string())?;
        v["enabled"] = self.enabled.into();
        let reset = |s: String| {
            if s == "-" {
                serde_json::Value::Null
            } else {
                s.into()
            }
        };
        for (field, value) in [
            ("from", self.from.map(reset)),
            ("to", self.to.map(reset)),
            ("subject", self.subject.map(reset)),
            ("text_body", self.text.map(Into::into)),
            ("html_body", self.html.map(Into::into)),
            ("external_subject", self.external_subject.map(reset)),
            ("external_text_body", self.external_text.map(Into::into)),
        ] {
            if let Some(value) = value {
                v[field] = value;
            }
        }
        serde_json::from_value(v).map_err(|e| {
            format!("автоответ: {e} (время — RFC 3339, например 2026-12-01T00:00:00Z)")
        })
    }
}

/// Автоответ — строки «подпись: значение».
fn vacation_record(v: &VacationBody) -> String {
    let field = |name: &str| or_dash(&json_field(v, name));
    let external = if v.external_subject.is_none() && v.external_text_body.is_none() {
        "нет — чужим ответа не уходит".to_owned()
    } else {
        format!(
            "{} / {}",
            or_dash(&json_field(v, "external_subject")),
            or_dash(&json_field(v, "external_text_body"))
        )
    };
    record(&[
        ("Включён", if v.enabled { "да" } else { "нет" }.to_owned()),
        ("С", field("from")),
        ("По", field("to")),
        ("Тема", field("subject")),
        ("Текст", field("text_body")),
        ("Текст HTML", field("html_body")),
        ("Внешний ответ", external),
        ("Внешний текст HTML", field("external_html_body")),
    ])
}

/// `PATCH` учётной записи `account` (идентификатор или имя входа).
async fn patch_account(
    client: &Client,
    org: &str,
    account: &str,
    patch: &AccountPatch,
) -> CliResult<AccountInfo> {
    let id = account_id(client, org, account).await?;
    Ok(client
        .call(ACCOUNT_PATCH, &[org, id.as_str()], &[], Some(patch))
        .await?)
}

/// Текст из файла `file` (`-` — stdin); чтение — вне потоков async.
async fn input_text(file: PathBuf) -> CliResult<String> {
    tokio::task::spawn_blocking(move || {
        if file.as_os_str() == "-" {
            std::io::read_to_string(std::io::stdin()).map_err(|e| format!("stdin: {e}"))
        } else {
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Файл целиком байтами (пакет поставщика, список TI); `-` — stdin.
async fn input_bytes(file: PathBuf) -> CliResult<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        if file.as_os_str() == "-" {
            let mut bytes = Vec::new();
            std::io::Read::read_to_end(&mut std::io::stdin(), &mut bytes)
                .map_err(|e| format!("stdin: {e}"))?;
            Ok(bytes)
        } else {
            std::fs::read(&file).map_err(|e| format!("{}: {e}", file.display()))
        }
    })
    .await
    .map_err(|e| e.to_string())?
}

const DOMAIN_COLUMNS: &[&str] = &["ИДЕНТИФИКАТОР", "ДОМЕН", "ВИД"];

/// Текущий администратор — строки «подпись: значение».
fn whoami_record(w: &WhoAmI) -> String {
    record(&[
        ("Администратор", w.login.clone()),
        ("Организация", w.tenant.clone()),
        ("Учётная запись", w.account.clone()),
        ("Роли", roles(&w.roles)),
    ])
}

/// Учётная запись — строки «подпись: значение».
fn account_record(a: &AccountInfo) -> String {
    record(&[
        ("Идентификатор", a.id.clone()),
        ("Имя входа", a.login.clone()),
        ("Имя", or_dash(&a.display_name)),
        ("Вход разрешён", a.enabled.to_string()),
        ("Псевдонимы", or_dash(&a.aliases.join(", "))),
        (
            "Скрыта из книги «Организация»",
            a.hidden_from_gal.to_string(),
        ),
        ("Домен", a.domain.clone()),
        ("Занято, байт", a.quota.used_bytes.to_string()),
        ("Писем", a.quota.messages.to_string()),
        ("Квота, байт", optional(a.quota.limit_bytes.as_ref())),
    ])
}

/// Принятый домен — строка таблицы [`DOMAIN_COLUMNS`].
fn domain_row(d: &AcceptedDomain) -> Vec<String> {
    let kind = match &d.kind {
        DomainKind::Authoritative => "authoritative".to_owned(),
        DomainKind::InternalRelay { next_hop } => format!("internal_relay → {next_hop}"),
    };
    vec![d.id.to_string(), d.name.clone(), kind]
}

/// Роли через запятую (имена — как в API).
fn roles(roles: &[AdminRole]) -> String {
    roles
        .iter()
        .map(|r| match serde_json::to_value(r) {
            Ok(serde_json::Value::String(s)) => s,
            _ => format!("{r:?}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Строка; пустая — «—».
fn or_dash(s: &str) -> String {
    if s.is_empty() {
        "—".to_owned()
    } else {
        s.to_owned()
    }
}

/// Необязательное значение; нет — «—».
fn optional<T: ToString>(v: Option<&T>) -> String {
    v.map_or_else(|| "—".to_owned(), ToString::to_string)
}

/// Учётные записи с именем входа `login`.
async fn find_accounts(client: &Client, org: &str, login: String) -> CliResult<Vec<AccountInfo>> {
    let query = query(&AccountQuery {
        login: Some(login),
        ..AccountQuery::default()
    })?;
    Ok(client.call(ACCOUNT_FIND, &[org], &query, NO_BODY).await?)
}

/// Список учётных записей: страницы Admin API по ссылке `rel="next"`, не больше `limit` записей (`None` — все);
/// второе значение — остались записи сверх `limit`.
async fn list_accounts(
    client: &Client,
    org: &str,
    prefix: Option<String>,
    after: Option<String>,
    limit: Option<usize>,
) -> CliResult<(Vec<AccountInfo>, bool)> {
    let query = query(&AccountQuery {
        prefix,
        after,
        limit,
        login: None,
    })?;
    Ok(client.pages(ACCOUNT_FIND, &[org], query, limit).await?)
}

/// Идентификатор учётной записи: UUID как есть, иначе поиск по имени входа.
async fn account_id(client: &Client, org: &str, account: &str) -> CliResult<String> {
    if account.parse::<AccountId>().is_ok() {
        return Ok(account.to_owned());
    }
    find_accounts(client, org, account.to_owned())
        .await?
        .into_iter()
        .next()
        .map(|a| a.id)
        .ok_or_else(|| format!("учётная запись {account} не найдена"))
}

/// Принятые домены организации и версия снимка кластера (для записи — из последнего чтения).
async fn domains(client: &Client, org: &str) -> CliResult<DomainList> {
    Ok(client.call(DOMAIN_LIST, &[org], &[], NO_BODY).await?)
}

/// Строки «подпись: значение».
fn record(fields: &[(&str, String)]) -> String {
    let width = fields
        .iter()
        .map(|(t, _)| t.chars().count())
        .max()
        .unwrap_or(0);
    fields
        .iter()
        .map(|(title, value)| {
            format!(
                "{}:{} {}\n",
                title,
                pad("", width - title.chars().count()),
                value
            )
        })
        .collect()
}

fn pad(s: &str, w: usize) -> String {
    format!("{s}{}", " ".repeat(w.saturating_sub(s.chars().count())))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use serde_json::{Value, json};
    use tp_admin::sharing::SharingStores;
    use tp_admin::{AdminConfig, AdminRole, Deps, InitRequest, RoleBinding};
    use tp_contracts::TenantId;
    use tp_contracts::auth::Principal;
    use tp_contracts::ext::DecisionHooks;
    use tp_testkit::{
        Clock, FakeAuthenticator, MemAbuseBlocks, MemAppPasswords, MemAuditLog, MemBlobIndex,
        MemBlobStore, MemBranding, MemDeliveryLog, MemEventBus, MemGroups, MemJournal,
        MemLocalAdminTokens, MemMetadata, MemModeration, MemPolicies, MemQuota, MemSieve,
        MemThreads, MemTransport, MemTrash, MemTrust, SystemClock,
    };
    use tp_testkit::{MemAddressBook, MemDav, MemMailboxAudit, MemSenderLists, MemSyncGate};

    use super::*;

    #[test]
    fn parses_admin_commands() {
        use clap::Parser;

        use crate::cli::{AdminAction, Cli, Command};

        let cli = Cli::try_parse_from([
            "thepost", "admin", "account", "create", "a@b.test", "--name", "А", "--json",
        ])
        .expect("account create");
        let Command::Admin { api, action } = cli.command else {
            panic!("{:?}", cli.command)
        };
        assert!(api.json);
        let AdminAction::Api(ApiAction::Account { action }) = action else {
            panic!("{action:?}")
        };
        assert!(matches!(
            *action,
            AccountAction::Create { ref login, name: Some(_) } if login == "a@b.test"
        ));
        let cli = Cli::try_parse_from([
            "thepost",
            "admin",
            "--url",
            "https://127.0.0.1:8443",
            "transport",
            "domain",
            "create",
            "b.test",
            "--org",
            "00000000-0000-0000-0000-000000000001",
        ])
        .expect("transport domain create");
        let Command::Admin { api, action } = cli.command else {
            panic!("{:?}", cli.command)
        };
        assert_eq!(api.url.as_deref(), Some("https://127.0.0.1:8443"));
        assert!(api.org.is_some());
        let AdminAction::Api(ApiAction::Transport { action }) = action else {
            panic!("{action:?}")
        };
        assert!(matches!(
            *action,
            TransportAction::Domain {
                action: DomainAction::Create { relay: None, .. }
            }
        ));
        let cli =
            Cli::try_parse_from(["thepost", "admin", "login", "--oidc"]).expect("login --oidc");
        assert!(matches!(
            cli.command,
            Command::Admin {
                action: AdminAction::Api(ApiAction::Login {
                    oidc: true,
                    user: None,
                    ..
                }),
                ..
            }
        ));
        let cli = Cli::try_parse_from([
            "thepost",
            "admin",
            "journal",
            "rule",
            "set",
            "team-in",
            "--group",
            "board",
            "--direction",
            "in",
            "--disabled",
        ])
        .expect("journal rule set");
        let Command::Admin { action, .. } = cli.command else {
            panic!("{:?}", cli.command)
        };
        let AdminAction::Api(ApiAction::Journal { action }) = action else {
            panic!("{action:?}")
        };
        let JournalAction::Rule { action } = *action else {
            panic!("{action:?}")
        };
        let JournalRuleAction::Set { id, group, .. } = *action else {
            panic!("{action:?}")
        };
        assert_eq!((id.as_str(), group.as_deref()), ("team-in", Some("board")));
        let cli = Cli::try_parse_from([
            "thepost",
            "admin",
            "--org",
            "00000000-0000-0000-0000-000000000001",
            "trust",
            "set",
            "--file",
            "-",
        ])
        .expect("trust set");
        let Command::Admin { action, .. } = cli.command else {
            panic!("{:?}", cli.command)
        };
        let AdminAction::Api(ApiAction::Trust { action }) = action else {
            panic!("{action:?}")
        };
        assert!(matches!(
            *action,
            TrustAction::Set {
                group: None,
                file: ref f,
            } if f.as_os_str() == "-"
        ));
        let cli = Cli::try_parse_from([
            "thepost",
            "admin",
            "risk",
            "signals",
            "set",
            "tp.encrypted_archive",
            "--weight",
            "9",
        ])
        .expect("risk signals set");
        let Command::Admin { action, .. } = cli.command else {
            panic!("{:?}", cli.command)
        };
        let AdminAction::Api(ApiAction::Risk { action }) = action else {
            panic!("{action:?}")
        };
        let RiskAction::Signals { action } = *action else {
            panic!("{action:?}")
        };
        let SignalsAction::Set {
            ref id,
            weight: Some(9),
            ..
        } = *action
        else {
            panic!("{action:?}")
        };
        assert_eq!(id, "tp.encrypted_archive");
        for args in [
            &["thepost", "admin", "risk", "signals", "list"][..],
            &[
                "thepost",
                "admin",
                "--org",
                "00000000-0000-0000-0000-000000000001",
                "risk",
                "signals",
                "list",
            ],
            &["thepost", "admin", "risk", "signals", "reset", "org.x"],
            &["thepost", "admin", "risk", "thresholds", "show"],
            &[
                "thepost",
                "admin",
                "risk",
                "thresholds",
                "set",
                "--tag",
                "2",
                "--junk",
                "7",
                "--quarantine",
                "11",
                "--reject",
                "16",
            ],
            &["thepost", "admin", "risk", "package", "list"],
            &["thepost", "admin", "risk", "package", "import", "pkg.json"],
            &["thepost", "admin", "risk", "package", "activate", "2"],
            &["thepost", "admin", "risk", "package", "rollback", "1"],
            &["thepost", "admin", "risk", "source", "list"],
            &["thepost", "admin", "risk", "source", "add", "--file", "-"],
            &[
                "thepost", "admin", "risk", "source", "set", "feodo", "--file", "-",
            ],
            &["thepost", "admin", "risk", "source", "rm", "feodo"],
            &[
                "thepost", "admin", "risk", "source", "import", "feodo", "list.txt",
            ],
            &["thepost", "admin", "risk", "source", "refresh", "feodo"],
            &["thepost", "admin", "risk", "source", "usage", "feodo"],
            &["thepost", "admin", "risk", "hits"],
            &[
                "thepost", "admin", "risk", "hits", "--signal", "tp.x", "--mode", "report",
            ],
        ] {
            assert!(Cli::try_parse_from(args).is_ok(), "{args:?}");
        }
        // Пароль — не аргумент: только --user и --password-stdin; без --user (и без --oidc) — ошибка разбора.
        let cli = Cli::try_parse_from([
            "thepost",
            "admin",
            "login",
            "--user",
            "a@b.test",
            "--password-stdin",
        ])
        .expect("login --user");
        assert!(matches!(
            cli.command,
            Command::Admin {
                action: AdminAction::Api(ApiAction::Login {
                    user: Some(_),
                    password_stdin: true,
                    oidc: false
                }),
                ..
            }
        ));
        for bad in [
            &["thepost", "admin", "login"][..],
            &[
                "thepost",
                "admin",
                "login",
                "--user",
                "a@b.test",
                "--password",
                "x",
            ],
            &["thepost", "admin", "login", "--user", "a@b.test", "--oidc"],
        ] {
            assert!(Cli::try_parse_from(bad).is_err(), "{bad:?}");
        }
        for args in [
            &["thepost", "admin", "login", "--user", "a@b.test"][..],
            &["thepost", "admin", "whoami"],
            &[
                "thepost",
                "admin",
                "app-password",
                "create",
                "a@b.test",
                "--label",
                "x",
            ],
            &[
                "thepost",
                "admin",
                "app-password",
                "revoke",
                "a@b.test",
                "id1",
            ],
            &["thepost", "admin", "transport", "domain", "list"],
            &[
                "thepost",
                "admin",
                "transport",
                "domain",
                "delete",
                "b.test",
            ],
            &["thepost", "admin", "transport", "source", "list"],
            &[
                "thepost",
                "admin",
                "transport",
                "source",
                "set",
                "gw",
                "--network",
                "192.0.2.0/24",
                "--network",
                "2001:db8::/32",
                "--xclient",
                "--authserv-id",
                "mx.b.test",
            ],
            &[
                "thepost",
                "admin",
                "transport",
                "source",
                "set",
                "mfu",
                "--client-cert",
                "mfu.b.test",
                "--application",
                "--sender",
                "@b.test",
                "--external",
            ],
            &["thepost", "admin", "transport", "source", "delete", "gw"],
            &["thepost", "admin", "transport", "route", "list"],
            &[
                "thepost",
                "admin",
                "transport",
                "route",
                "set",
                "*.b.test",
                "--tls",
                "required",
                "--smart-host",
                "relay.b.test:587",
                "--egress-ip",
                "192.0.2.1",
            ],
            &[
                "thepost",
                "admin",
                "transport",
                "route",
                "set",
                "*",
                "--pin",
                "ab",
                "--pin",
                "cd",
            ],
            &["thepost", "admin", "transport", "route", "delete", "*"],
            &["thepost", "admin", "policy", "get"],
            &["thepost", "admin", "policy", "get", "--domain", "b.test"],
            &[
                "thepost",
                "admin",
                "policy",
                "set",
                "--account",
                "a@b.test",
                "--file",
                "-",
            ],
            &["thepost", "admin", "group", "list"],
            &["thepost", "admin", "group", "get", "Отдел"],
            &[
                "thepost",
                "admin",
                "group",
                "create",
                "Отдел",
                "--address",
                "o@b.test",
                "--account",
                "a@b.test",
                "--group",
                "Вложенная",
            ],
            &["thepost", "admin", "group", "delete", "Отдел"],
            &["thepost", "admin", "group", "members", "Отдел"],
            &["thepost", "admin", "group", "members", "Отдел", "--set"],
            &[
                "thepost",
                "admin",
                "group",
                "members",
                "Отдел",
                "--set",
                "--account",
                "a@b.test",
            ],
            &["thepost", "admin", "trash", "list", "a@b.test"],
            &[
                "thepost",
                "admin",
                "trash",
                "list",
                "a@b.test",
                "--hidden",
                "--subject",
                "--offset",
                "2",
                "--limit",
                "2",
            ],
            &[
                "thepost", "admin", "trash", "restore", "a@b.test", "m1", "--hidden",
            ],
            &[
                "thepost",
                "admin",
                "thread",
                "find",
                "a@b.test",
                "--message-id",
                "m1",
            ],
            &[
                "thepost",
                "admin",
                "thread",
                "hold",
                "a@b.test",
                "t1",
                "--reason",
                "дело №1",
            ],
            &["thepost", "admin", "thread", "unhold", "a@b.test", "t1"],
            &["thepost", "admin", "thread", "holds"],
            &[
                "thepost", "admin", "thread", "export", "a@b.test", "t1", "-o", "t.zip",
            ],
            &["thepost", "admin", "thread", "export", "a@b.test", "t1"],
            &[
                "thepost",
                "admin",
                "audit",
                "search",
                "--since",
                "2026-12-01T00:00:00Z",
                "--actor",
                "a@b.test",
                "--method",
                "put",
                "--route",
                "/api/v1/orgs/{org}/transport",
                "--after",
                "3",
            ],
            &[
                "thepost",
                "admin",
                "delivery",
                "search",
                "--sender",
                "a@b.test",
                "--recipient",
                "c@d.test",
                "--message-id",
                "x@b.test",
                "--until",
                "2026-12-01T00:00:00Z",
                "--after",
                "p",
                "--limit",
                "5",
            ],
            &[
                "thepost", "admin", "account", "list", "--after", "a@b.test", "--limit", "2",
            ],
            &["thepost", "admin", "sieve", "list", "a@b.test"],
            &["thepost", "admin", "sieve", "get", "a@b.test", "main"],
            &[
                "thepost", "admin", "sieve", "put", "a@b.test", "main", "--file", "-",
            ],
            &["thepost", "admin", "sieve", "activate", "a@b.test", "main"],
            &["thepost", "admin", "sieve", "deactivate", "a@b.test"],
            &["thepost", "admin", "sieve", "delete", "a@b.test", "main"],
            &["thepost", "admin", "sieve", "org", "get"],
            &["thepost", "admin", "sieve", "org", "put", "--file", "-"],
            &["thepost", "admin", "sieve", "org", "delete", "--json"],
            &["thepost", "admin", "vacation", "get", "a@b.test"],
            &["thepost", "admin", "vacation", "set", "a@b.test", "--off"],
            &[
                "thepost",
                "admin",
                "vacation",
                "set",
                "a@b.test",
                "--from",
                "2026-12-01T00:00:00Z",
                "--to",
                "-",
                "--subject",
                "Отпуск",
                "--text-file",
                "-",
                "--html-file",
                "a.html",
            ],
            &["thepost", "admin", "account", "block", "a@b.test"],
            &["thepost", "admin", "account", "unblock", "a@b.test"],
            &["thepost", "admin", "account", "rename", "a@b.test", "Анна"],
            &["thepost", "admin", "account", "list", "--login", "a@b.test"],
            &["thepost", "admin", "account", "list"],
            &[
                "thepost", "admin", "account", "list", "--prefix", "a", "--limit", "10",
            ],
            &["thepost", "admin", "resources", "list"],
            &["thepost", "admin", "resources", "create", "r@b.test"],
            &[
                "thepost",
                "admin",
                "resources",
                "create",
                "r@b.test",
                "--type",
                "equipment",
            ],
            &[
                "thepost",
                "admin",
                "resources",
                "set-type",
                "r@b.test",
                "room",
            ],
            &["thepost", "admin", "init", "--email", "a@b.test"],
        ] {
            Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
        for args in [
            &[
                "thepost", "admin", "account", "list", "--login", "a@b.test", "--prefix", "a",
            ][..],
            &[
                "thepost", "admin", "account", "list", "--login", "a@b.test", "--limit", "1",
            ],
            &["thepost", "admin", "account", "list", "--limit", "0"],
            &["thepost", "admin", "sieve", "put", "a@b.test", "main"],
            &["thepost", "admin", "sieve", "activate", "a@b.test"],
            &["thepost", "admin", "sieve", "delete", "a@b.test"],
            &["thepost", "admin", "sieve", "org", "put"],
            &["thepost", "admin", "vacation", "set"],
            &[
                "thepost",
                "admin",
                "vacation",
                "set",
                "a@b.test",
                "--text",
                "а",
                "--text-file",
                "-",
            ],
            &["thepost", "admin", "account", "rename", "a@b.test"],
            &[
                "thepost", "admin", "account", "list", "--login", "a@b.test", "--after", "a@b.test",
            ],
            &["thepost", "admin", "domain", "list"],
            &[
                "thepost",
                "admin",
                "resources",
                "create",
                "r@b.test",
                "--type",
                "car",
            ],
            &["thepost", "admin", "resources", "set-type", "r@b.test"],
            &["thepost", "admin", "transport", "domain", "add", "b.test"],
            &["thepost", "admin", "transport", "source", "set", "gw"],
            &[
                "thepost",
                "admin",
                "transport",
                "source",
                "set",
                "gw",
                "--network",
                "192.0.2.0/24",
                "--client-cert",
                "mfu.b.test",
            ],
            &[
                "thepost",
                "admin",
                "transport",
                "source",
                "set",
                "gw",
                "--network",
                "192.0.2.0/24",
                "--sender",
                "@b.test",
            ],
            &[
                "thepost",
                "admin",
                "transport",
                "source",
                "set",
                "gw",
                "--network",
                "192.0.2.0/24",
                "--application",
                "--xclient",
            ],
            &[
                "thepost",
                "admin",
                "transport",
                "route",
                "set",
                "*",
                "--tls",
                "required",
                "--pin",
                "ab",
            ],
            &[
                "thepost",
                "admin",
                "transport",
                "route",
                "set",
                "*",
                "--tls",
                "never",
            ],
            &[
                "thepost",
                "admin",
                "policy",
                "get",
                "--domain",
                "b.test",
                "--account",
                "a@b.test",
            ],
            &["thepost", "admin", "policy", "set"],
            &[
                "thepost",
                "admin",
                "group",
                "members",
                "Отдел",
                "--account",
                "a@b.test",
            ],
            &["thepost", "admin", "trash", "restore", "a@b.test"],
            &["thepost", "admin", "audit", "search", "--after", "x"],
        ] {
            assert!(Cli::try_parse_from(args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn url_from_config_yaml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.yaml");
        let base = DEV_CONFIG;
        std::fs::write(
            &path,
            format!(
                "{base}http:\n  admin: {{ listen: \"127.0.0.1:9443\", allow_plaintext: true }}\n"
            ),
        )
        .expect("write");
        assert_eq!(
            url_from_config(&path).expect("url"),
            "http://127.0.0.1:9443"
        );
        std::fs::write(
            &path,
            format!("{base}http:\n  admin: {{ listen: \"[::1]:8443\" }}\n"),
        )
        .expect("write");
        assert_eq!(url_from_config(&path).expect("url"), "https://[::1]:8443");
        let err = url_from_config(&dir.path().join("nope.yaml")).expect_err("no config");
        assert!(err.contains(ENV_URL), "{err}");
    }

    #[test]
    fn renders_record() {
        let w = WhoAmI {
            tenant: TenantId::DEFAULT.to_string(),
            account: AccountId::new().to_string(),
            login: "a".into(),
            roles: vec![AdminRole::InstallationAdmin, AdminRole::Operator],
        };
        let r = whoami_record(&w);
        assert!(
            r.contains("Роли:") && r.contains("installation_admin, operator"),
            "{r}"
        );
    }

    /// Admin API tp-admin на хранилищах testkit на loopback: локальный вход подключён, `oidc` — токен OIDC
    /// администратора инсталляции, `ja` — аудитор журнала; страница списков — 2 записи (переход по `Link`
    /// в каждом списке длиннее). Третий результат — журнал переписки для записи тестовых писем, четвёртый —
    /// почтовое хранилище (доставка писем бесед, ADM-50).
    async fn admin_api() -> (
        Arc<tp_admin::Admin>,
        Url,
        MemJournal,
        tp_mailstore::Store,
        MemMetadata,
    ) {
        admin_api_with(tp_auth::AbuseConfig::default()).await
    }

    /// То же с защитой от перебора `abuse`. Учётные данные проверяет путь входа узла ([`crate::services::Guarded`]):
    /// пароль — `PasswordAuthenticator` с паролями приложений, Bearer — `oidc`; адрес клиента — из соединения.
    async fn admin_api_with(
        abuse: tp_auth::AbuseConfig,
    ) -> (
        Arc<tp_admin::Admin>,
        Url,
        MemJournal,
        tp_mailstore::Store,
        MemMetadata,
    ) {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let index = MemBlobIndex::new(clock.clone());
        let meta = MemMetadata::new(clock.clone()).with_blob_index(index.clone());
        let quota = MemQuota::new(&meta);
        let policies = MemPolicies::new(&meta);
        let trash = MemTrash::new(&meta).with_policies(policies.clone());
        let threads = MemThreads::new();
        let blobs = MemBlobStore::new(clock);
        let store = tp_mailstore::Store::new(tp_mailstore::Deps {
            blobs: Arc::new(blobs.clone()),
            index: Arc::new(index),
            messages: Arc::new(meta.clone()),
            changes: Arc::new(meta.clone()),
            trash: Arc::new(trash.clone()),
            quota: Arc::new(quota.clone()),
            bus: Arc::new(MemEventBus::default()),
            threads: Some(Arc::new(threads.clone())),
            hooks: DecisionHooks::default(),
        });
        let app_passwords = tp_auth::AppPasswords::new(
            Arc::new(MemAppPasswords::new(&meta)),
            tp_auth::PasswordConfig::default(),
        )
        .expect("app passwords");
        let bearer = FakeAuthenticator::default();
        bearer.add_token(
            "oidc",
            Principal {
                tenant: TenantId::DEFAULT,
                account: AccountId::new(),
                login: "root@example.test".into(),
                groups: BTreeSet::from(["mail-root".to_owned()]),
                scopes: None,
            },
        );
        bearer.add_token(
            "ja",
            Principal {
                tenant: TenantId::DEFAULT,
                account: AccountId::new(),
                login: "ja@example.test".into(),
                groups: BTreeSet::from(["compliance".to_owned()]),
                scopes: None,
            },
        );
        bearer.add_token(
            "org",
            Principal {
                tenant: TenantId::DEFAULT,
                account: AccountId::new(),
                login: "org@example.test".into(),
                groups: BTreeSet::from(["mail-admins".to_owned()]),
                scopes: None,
            },
        );
        let password = tp_auth::PasswordAuthenticator::new(tp_auth::Accounts::new(
            TenantId::DEFAULT,
            Arc::new(meta.clone()),
        ))
        .with_app_passwords(app_passwords.clone());
        let router = tp_auth::CredentialsRouter::default()
            .password(Arc::new(password))
            .bearer(Arc::new(bearer));
        let auth = crate::services::Guarded::new(
            Arc::new(router),
            tp_auth::AbuseGuard::new(abuse, Arc::new(MemAbuseBlocks::default())),
            Arc::new(meta.clone()),
            TenantId::DEFAULT,
        );
        let groups = MemGroups::new();
        let deps = Deps {
            auth: Arc::new(auth),
            audit_log: Arc::new(MemAuditLog::new()),
            delivery: Arc::new(MemDeliveryLog::new()),
            groups: Arc::new(groups.clone()),
            moderation: Arc::new(MemModeration::default()),
            modules: Vec::new(),
            accounts: Arc::new(meta.clone()),
            quota: Arc::new(quota),
            policies: Arc::new(policies.clone()),
            resolver: Arc::new(policies),
            trash: Arc::new(trash),
            store: Arc::new(store.clone()),
            app_passwords,
            contacts: Arc::new(MemAddressBook::new()),
            org: Arc::new(MemAddressBook::new()),
            dynamic: Arc::new(MemAddressBook::new()),
            senders: Arc::new(MemSenderLists::new()),
            mailbox_audit: Arc::new(MemMailboxAudit::new()),
            sync: Arc::new(MemSyncGate::new()),
            oidc_issuer: None,
        };
        let cfg = AdminConfig {
            roles: vec![
                RoleBinding {
                    role: AdminRole::InstallationAdmin,
                    logins: vec![],
                    groups: vec!["mail-root".into()],
                },
                RoleBinding {
                    role: AdminRole::JournalAuditor,
                    logins: vec![],
                    groups: vec!["compliance".into()],
                },
                RoleBinding {
                    role: AdminRole::OrganizationAdmin,
                    logins: vec![],
                    groups: vec!["mail-admins".into()],
                },
            ],
            page_size: 2,
            max_page_size: 2,
            ..AdminConfig::default()
        };
        let journal = MemJournal::new();
        let admin = Arc::new(
            tp_admin::Admin::new(deps, cfg)
                .expect("admin")
                .with_transport(Arc::new(MemTransport::new()))
                .with_trust(Arc::new(
                    MemTrust::new().with_groups(Arc::new(groups.clone())),
                ))
                .with_journal(Arc::new(journal.clone()))
                .with_journal_rules(Arc::new(journal.clone()))
                // Беседы и объекты писем — те же, что у приёма писем (MS-21): выгрузка беседы читает
                // скрытые письма по объектам (ADM-50).
                .with_threads(Arc::new(threads.clone()))
                // Справочник аномалий (ADM-51): хранилище tp-testkit, проверка пакета — память tp-admin.
                .with_risk(
                    Arc::new(tp_testkit::MemRisk::new(Arc::new(SystemClock))),
                    Arc::new(tp_admin::risk::MemRiskNode::default()),
                )
                .with_held_blobs(Arc::new(blobs.clone()))
                .with_sieve(Arc::new(MemSieve::new()), check_script)
                .with_org_script_check(check_org_script)
                .with_local_tokens(Arc::new(MemLocalAdminTokens::new()))
                .with_sharing(SharingStores {
                    acl: Arc::new(MemDav::new()),
                    delegates: Arc::new(meta.clone()),
                    resources: Arc::new(meta.clone()),
                    policy: Arc::new(meta.clone()),
                    collections: Arc::new(MemDav::new()),
                })
                .with_branding(
                    Arc::new(MemBranding::default()),
                    Arc::new(MemBlobStore::new(Arc::new(SystemClock))),
                ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let router = admin
            .clone()
            .router()
            .into_make_service_with_connect_info::<std::net::SocketAddr>();
        tokio::spawn(async move { axum::serve(listener, router).await });
        let url = Url::parse(&format!("http://{addr}")).expect("url");
        (admin, url, journal, store, meta)
    }

    /// Приёмка ADM-41: перебор пароля с одного адреса — блокировка `AbuseGuard` по адресу клиента, после неё и
    /// верный пароль не принимается (401).
    #[tokio::test]
    async fn password_login_bruteforce_is_blocked() {
        let (admin, url, _, _, _) = admin_api_with(tp_auth::AbuseConfig {
            ip_failures: 3,
            ..tp_auth::AbuseConfig::default()
        })
        .await;
        let granted = admin
            .init(&InitRequest {
                email: "admin@example.test".into(),
                display_name: None,
                force: false,
            })
            .await
            .expect("init");
        let anon = Client::anonymous(url, &Options::default()).expect("client");
        let args = ApiArgs::default();
        for _ in 0..3 {
            let err = login(&anon, &args, &granted.login, "wrong".into())
                .await
                .expect_err("неверный пароль");
            assert!(err.contains("401"), "{err}");
        }
        let err = login(&anon, &args, &granted.login, granted.password.clone())
            .await
            .expect_err("адрес заблокирован");
        assert!(err.contains("401"), "{err}");
    }

    /// Проверка скрипта, как у узла: `tp_sieve::compile` с пределами секции `sieve`; у тестовой секции глубина
    /// вложенности меньше умолчания, чтобы отказ по пределу секции был виден.
    fn check_script(text: &str) -> Vec<tp_admin::ScriptError> {
        let section = tp_sieve::SieveConfig {
            max_nesting: 2,
            ..tp_sieve::SieveConfig::default()
        };
        tp_sieve::compile(text.as_bytes(), &section.limits())
            .err()
            .unwrap_or_default()
            .into_iter()
            .map(|d| tp_admin::ScriptError {
                line: d.line,
                column: d.column,
                message: d.message,
            })
            .collect()
    }

    /// Профиль «админский» тестов (вместо профиля SIEVE-14 узла): `vacation` запрещён; `redirect` на адрес,
    /// чей домен не принятый домен организации и не домен автопересылки, — ошибка.
    fn check_org_script(
        text: &str,
        internal: &[String],
        forward: &[String],
    ) -> Vec<tp_admin::ScriptError> {
        let mut errors = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let column_of = |needle: &str| {
                line.find(needle)
                    .map(|at| line[..at].chars().count() as u32 + 1)
            };
            if let Some(column) = column_of("vacation") {
                errors.push(tp_admin::ScriptError {
                    line: i as u32 + 1,
                    column,
                    message: "vacation в скрипте организации запрещён".into(),
                });
            }
            if let Some(column) = column_of("redirect") {
                let domain = line
                    .split('"')
                    .nth(1)
                    .unwrap_or_default()
                    .rsplit_once('@')
                    .map(|(_, d)| d.to_owned())
                    .unwrap_or_default();
                if !internal.contains(&domain) && !forward.contains(&domain) {
                    errors.push(tp_admin::ScriptError {
                        line: i as u32 + 1,
                        column,
                        message: format!(
                            "redirect на внешний адрес {domain:?}: автопересылка туда не открыта"
                        ),
                    });
                }
            }
        }
        errors
    }

    /// `account …`.
    fn account_action(action: AccountAction) -> ApiAction {
        ApiAction::Account {
            action: Box::new(action),
        }
    }

    /// `group …`.
    fn group_action(action: GroupAction) -> ApiAction {
        ApiAction::Group {
            action: Box::new(action),
        }
    }

    /// `transport domain …`.
    fn domain_action(action: DomainAction) -> ApiAction {
        transport(TransportAction::Domain { action })
    }

    fn transport(action: TransportAction) -> ApiAction {
        ApiAction::Transport {
            action: Box::new(action),
        }
    }

    fn client(url: &Url, token: &str) -> Client {
        Client::new(url.clone(), token.to_owned(), &Options::default()).expect("client")
    }

    async fn exec(c: &Client, json: bool, action: ApiAction) -> CliResult<String> {
        let args = ApiArgs {
            json,
            ..ApiArgs::default()
        };
        execute(c, &args, action).await
    }

    /// Приёмка ADM-51: команды `thepost admin risk …` против Admin API — каталог, изменение и сброс
    /// признака (организация мягче — ошибка 422), пороги, пакет (загрузка с отчётом, активация, откат),
    /// источник TI (добавление, импорт, обновление, удаление), срабатывания организации.
    #[tokio::test]
    async fn risk_commands_against_admin_api() {
        let (_admin, url, _, _, _) = admin_api().await;
        let root = client(&url, "oidc");
        let org = client(&url, "org");

        // Пакет версии 1 — файлом; отчёт показывает, что изменится; активация — отдельное действие.
        let dir = tempfile::tempdir().expect("tempdir");
        let package = dir.path().join("package.json");
        let manifest = tp_contracts::risk::PackageManifest {
            format: tp_contracts::risk::PACKAGE_FORMAT,
            version: 1,
            created: time::OffsetDateTime::UNIX_EPOCH,
            min_node: tp_contracts::risk::Semver::new(0, 1, 0),
            key_id: "vendor".to_owned(),
            signals: vec![tp_contracts::risk::Signal {
                id: tp_contracts::risk::SignalId::new("tp.encrypted_archive").expect("id"),
                detector: tp_contracts::risk::Detector::EncryptedArchive,
                weight: 6,
                threshold: 0,
                action: tp_contracts::risk::RiskAction::None,
                mode: tp_contracts::risk::Mode::Enforce,
                origin: tp_contracts::risk::Origin::Vendor,
                since: time::OffsetDateTime::UNIX_EPOCH,
            }],
            lists: Vec::new(),
            samples: Vec::new(),
        };
        std::fs::write(&package, serde_json::to_vec(&manifest).expect("json")).expect("write");
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Package {
                    action: Box::new(PackageAction::Import {
                        file: package.clone(),
                    }),
                }),
            },
        )
        .await
        .expect("package import");
        assert!(out.contains("проверен и поставлен, не активен"), "{out}");
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Package {
                    action: Box::new(PackageAction::Activate { version: 1 }),
                }),
            },
        )
        .await
        .expect("package activate");
        assert!(out.contains("активирован"), "{out}");
        let out = exec(
            &root,
            true,
            ApiAction::Risk {
                action: Box::new(RiskAction::Package {
                    action: Box::new(PackageAction::List),
                }),
            },
        )
        .await
        .expect("package list");
        assert!(out.contains("\"active\""), "{out}");

        // Каталог и изменение признака установки; свой признак организации.
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Signals {
                    action: Box::new(SignalsAction::List),
                }),
            },
        )
        .await
        .expect("signals list");
        assert!(out.contains("tp.encrypted_archive"), "{out}");
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Signals {
                    action: Box::new(SignalsAction::Set {
                        id: "tp.encrypted_archive".to_owned(),
                        weight: Some(3),
                        action: None,
                        mode: None,
                        detector: None,
                        threshold: None,
                    }),
                }),
            },
        )
        .await
        .expect("signals set");
        let flat = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains("Вес: 3"), "{out}");
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Signals {
                    action: Box::new(SignalsAction::Reset {
                        id: "tp.encrypted_archive".to_owned(),
                    }),
                }),
            },
        )
        .await
        .expect("signals reset");
        assert!(out.contains("сброшено"), "{out}");
        // Организация мягче — ошибка с подсказкой; строже — ок.
        let err = exec(
            &org,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Signals {
                    action: Box::new(SignalsAction::Set {
                        id: "tp.encrypted_archive".to_owned(),
                        weight: Some(1),
                        action: None,
                        mode: None,
                        detector: None,
                        threshold: None,
                    }),
                }),
            },
        )
        .await
        .expect_err("мягче");
        assert!(err.contains("422"), "{err}");
        let org_args = ApiArgs {
            org: Some(TenantId::DEFAULT.to_string()),
            ..ApiArgs::default()
        };
        let out = execute(
            &org,
            &org_args,
            ApiAction::Risk {
                action: Box::new(RiskAction::Signals {
                    action: Box::new(SignalsAction::Set {
                        id: "tp.encrypted_archive".to_owned(),
                        weight: Some(9),
                        action: None,
                        mode: None,
                        detector: None,
                        threshold: None,
                    }),
                }),
            },
        )
        .await
        .expect("строже");
        let flat = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains("Вес: 9"), "{out}");

        // Пороги: показ и замена установки; организация видит действующими пороги установки.
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Thresholds {
                    action: Box::new(ThresholdsAction::Set {
                        tag: 2,
                        junk: 7,
                        quarantine: 11,
                        reject: 16,
                    }),
                }),
            },
        )
        .await
        .expect("thresholds set");
        let flat = out.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains("отказ 16"), "{out}");
        let out = execute(
            &org,
            &org_args,
            ApiAction::Risk {
                action: Box::new(RiskAction::Thresholds {
                    action: Box::new(ThresholdsAction::Show),
                }),
            },
        )
        .await
        .expect("org thresholds");
        assert!(out.contains("установка"), "{out}");

        // Источник TI: добавление из файла, список, импорт списка, обновление, учёт, удаление.
        let source = dir.path().join("source.json");
        std::fs::write(
            &source,
            serde_json::to_string_pretty(&serde_json::json!({
                "id": "feodo", "tier": "customer_key",
                "kind": {"http": {"url": "https://feodo.tracker.abuse.ch/ipblocklist/"}},
                "format": "txt", "ttl": "1h",
                "stale": {"reduce": {"percent": 50}},
                "license": {"terms_url": "https://abuse.ch/terms/", "commercial": true},
                "tenants": "all", "key": {"secret": "thepost/db#api_key"},
                "auth": {"header": {"name": "Auth-Key"}}, "origin": "vendor"
            }))
            .expect("json"),
        )
        .expect("write");
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Source {
                    action: Box::new(RiskSourceAction::Add { file: source }),
                }),
            },
        )
        .await
        .expect("source add");
        assert!(out.contains("feodo"), "{out}");
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Source {
                    action: Box::new(RiskSourceAction::List),
                }),
            },
        )
        .await
        .expect("source list");
        assert!(out.contains("customer_key"), "{out}");
        let list = dir.path().join("list.txt");
        std::fs::write(&list, b"1.2.3.4\n5.6.7.8\n").expect("write");
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Source {
                    action: Box::new(RiskSourceAction::Import {
                        id: "feodo".to_owned(),
                        file: list,
                    }),
                }),
            },
        )
        .await
        .expect("source import");
        assert!(out.contains("Записей: 2"), "{out}");
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Source {
                    action: Box::new(RiskSourceAction::Refresh {
                        id: "feodo".to_owned(),
                    }),
                }),
            },
        )
        .await
        .expect("source refresh");
        assert!(out.contains("feodo"), "{out}");
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Source {
                    action: Box::new(RiskSourceAction::Usage {
                        id: "feodo".to_owned(),
                        since: None,
                    }),
                }),
            },
        )
        .await
        .expect("source usage");
        assert!(out.contains("ОРГАНИЗАЦИЯ"), "{out}");
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Source {
                    action: Box::new(RiskSourceAction::Rm {
                        id: "feodo".to_owned(),
                    }),
                }),
            },
        )
        .await
        .expect("source rm");
        assert!(out.contains("удалён"), "{out}");

        // Срабатывания организации: пустой журнал — пустая таблица.
        let out = execute(
            &org,
            &org_args,
            ApiAction::Risk {
                action: Box::new(RiskAction::Hits(HitsArgs {
                    signal: None,
                    mode: None,
                    since: None,
                    until: None,
                    limit: None,
                })),
            },
        )
        .await
        .expect("hits");
        assert!(out.contains("ПРИЗНАК"), "{out}");

        // Откат пакета — на хранимую версию.
        let out = exec(
            &root,
            false,
            ApiAction::Risk {
                action: Box::new(RiskAction::Package {
                    action: Box::new(PackageAction::Rollback { version: 1 }),
                }),
            },
        )
        .await
        .expect("package rollback");
        assert!(out.contains("Откат"), "{out}");
    }

    /// Имена входа `account list --json` без `--login`.
    async fn list_logins(c: &Client, prefix: Option<&str>, limit: Option<usize>) -> Vec<String> {
        let action = AccountAction::List {
            login: None,
            prefix: prefix.map(str::to_owned),
            after: None,
            limit,
        };
        let json = exec(c, true, account_action(action))
            .await
            .expect("account list");
        let v: Value = serde_json::from_str(&json).expect("json");
        v.as_array()
            .expect("array")
            .iter()
            .map(|a| a["login"].as_str().expect("login").to_owned())
            .collect()
    }

    /// Приёмка ADM-52: журнал переписки в CLI — поиск по страницам, запись, выгрузка `.eml`, проверка
    /// цепочки; команды ведёт аудитор журнала (`ja`), администратору инсталляции содержимое — 403.
    #[tokio::test]
    async fn journal_commands_against_admin_api() {
        use tp_contracts::journal::JournalStore as _;
        use tp_contracts::journal::{JournalDirection, JournalRule, JournalScope};

        let (_admin, url, journal, _, _) = admin_api().await;
        let ja = client(&url, "ja");
        let root = client(&url, "oidc");
        let json = |out: CliResult<String>| -> Value {
            serde_json::from_str(&out.expect("ответ")).expect("json")
        };
        let d = TenantId::DEFAULT;
        let rule = JournalRule {
            id: "org-all".to_owned(),
            tenant: d,
            scope: JournalScope::Org,
            direction: JournalDirection::Both,
            enabled: true,
        };
        for (at, sender, rcpt, mid) in [
            (
                1_800_000_000,
                "a@external.test",
                "anna@res.test",
                "m1@external.test",
            ),
            (
                1_800_000_060,
                "b@external.test",
                "bob@res.test",
                "m2@external.test",
            ),
        ] {
            journal
                .append(
                    &rule,
                    &tp_contracts::journal::JournalRecord {
                        tenant: d,
                        sender: sender.to_owned(),
                        recipients: vec![rcpt.to_owned()],
                        message_id: Some(mid.to_owned()),
                        at: time::OffsetDateTime::from_unix_timestamp(at).expect("time"),
                        rule: rule.id.clone(),
                    },
                    bytes::Bytes::from(format!("Message-ID: <{mid}>\r\nSubject: x\r\n\r\nbody")),
                )
                .await
                .expect("append");
        }

        let search = |sender: Option<&str>, limit: Option<usize>, after: Option<String>| {
            ApiAction::Journal {
                action: Box::new(JournalAction::Search {
                    sender: sender.map(str::to_owned),
                    recipient: None,
                    message_id: None,
                    rule: None,
                    since: None,
                    until: None,
                    limit,
                    after,
                }),
            }
        };
        // Поиск: страницы по подсказке --after, обе записи организации.
        let (mut seen, mut after) = (Vec::new(), None);
        for _ in 0..5 {
            let page = json(exec(&ja, true, search(None, Some(1), after.clone())).await);
            seen.push(
                page["entries"][0]["record"]["sender"]
                    .as_str()
                    .expect("sender")
                    .to_owned(),
            );
            let text = exec(&ja, false, search(None, Some(1), after.clone()))
                .await
                .expect("search text");
            after = page["next"]
                .as_str()
                .map(|s| s.to_owned())
                .filter(|_| text.contains("--after"));
            if after.is_none() {
                assert!(!text.contains("Есть ещё"), "{text}");
                break;
            }
        }
        assert_eq!(seen, ["a@external.test", "b@external.test"], "{seen:?}");

        // Фильтр по отправителю и по получателю (в том числе скрытому — записью журнала).
        let page = json(exec(&ja, true, search(Some("B@EXTERNAL.TEST"), None, None)).await);
        assert_eq!(
            page["entries"][0]["record"]["message_id"],
            "m2@external.test"
        );
        let by_rcpt = JournalAction::Search {
            sender: None,
            recipient: Some("ANNA@res.test".into()),
            message_id: None,
            rule: None,
            since: None,
            until: None,
            limit: None,
            after: None,
        };
        let page = json(
            exec(
                &ja,
                true,
                ApiAction::Journal {
                    action: Box::new(by_rcpt),
                },
            )
            .await,
        );
        assert_eq!(page["entries"].as_array().expect("entries").len(), 1);

        // Запись: конверт и хеш цепочки.
        let id = page["entries"][0]["id"].as_str().expect("id").to_owned();
        let entry = json(
            exec(
                &ja,
                true,
                ApiAction::Journal {
                    action: Box::new(JournalAction::Get { id: id.clone() }),
                },
            )
            .await,
        );
        assert_eq!(entry["record"]["rule"], "org-all");
        assert_eq!(entry["hash"].as_str().expect("hash").len(), 64);
        let text = exec(
            &ja,
            false,
            ApiAction::Journal {
                action: Box::new(JournalAction::Get { id: id.clone() }),
            },
        )
        .await
        .expect("entry text");
        assert!(text.contains("Получатели:  anna@res.test"), "{text}");

        // Выгрузка: .eml с конвертом — в файл; администратору инсталляции — 403.
        let dir = tempfile::tempdir().expect("tempdir");
        let out = dir.path().join("m1.eml");
        exec(
            &ja,
            false,
            ApiAction::Journal {
                action: Box::new(JournalAction::Export {
                    id: id.clone(),
                    output: Some(out.clone()),
                }),
            },
        )
        .await
        .expect("export");
        let eml = std::fs::read(&out).expect("eml");
        assert!(
            eml.starts_with(b"X-ThePost-Journal-Sender: a@external.test\r\n"),
            "{}",
            String::from_utf8_lossy(&eml)
        );
        let err = exec(
            &root,
            false,
            ApiAction::Journal {
                action: Box::new(JournalAction::Export { id, output: None }),
            },
        )
        .await
        .expect_err("installation admin");
        assert!(err.contains("403"), "{err}");

        // Проверка цепочки: обе записи, целостна.
        let report = json(
            exec(
                &ja,
                true,
                ApiAction::Journal {
                    action: Box::new(JournalAction::Verify),
                },
            )
            .await,
        );
        assert_eq!(report["records"], 2);
        assert_eq!(report["ok"], true);
        let text = exec(
            &ja,
            false,
            ApiAction::Journal {
                action: Box::new(JournalAction::Verify),
            },
        )
        .await
        .expect("verify text");
        assert!(
            text.contains("Цепочка целостна") && text.contains("да") && !text.contains("нет"),
            "{text}"
        );
    }

    /// Приёмка ADM-50: беседы в CLI — беседа письма, удержание и снятие (кто и основание), список удержаний,
    /// выгрузка беседы ZIP (письмо корзины включено); аудитору журнала выгрузка — 403.
    #[tokio::test]
    async fn thread_commands_against_admin_api() {
        use tp_contracts::mailstore::{Delivery, IngestRequest, MailStore};
        use tp_contracts::meta::{AccountScope, Flags, SpecialUse};

        /// Письмо во «Входящие» с заголовками беседы (привязка приёма, CTR-94).
        async fn deliver(
            store: &tp_mailstore::Store,
            meta: &MemMetadata,
            scope: AccountScope,
            message_id: &str,
            in_reply_to: Option<&str>,
            subject: &str,
        ) -> tp_contracts::MessageId {
            let inbox = meta
                .mailbox_by_role(scope, SpecialUse::Inbox)
                .expect("inbox");
            let reply = in_reply_to
                .map(|p| format!("In-Reply-To: <{p}>\r\nReferences: <{p}>\r\n"))
                .unwrap_or_default();
            let raw = format!(
                "From: a@example.com\r\nTo: a@threads.test\r\nMessage-ID: <{message_id}>\r\n{reply}Subject: {subject}\r\n\r\nbody\r\n"
            );
            let chunks: Vec<tp_contracts::Result<bytes::Bytes>> = vec![Ok(bytes::Bytes::from(raw))];
            let got = store
                .ingest(IngestRequest {
                    tenant: scope.tenant,
                    mail_from: "a@example.com".into(),
                    raw: Box::pin(futures::stream::iter(chunks)),
                    deliveries: vec![Delivery {
                        account: scope.account,
                        mailbox: inbox,
                        extra_headers: vec![],
                        flags: Flags::default(),
                    }],
                    received_at: time::OffsetDateTime::now_utc(),
                })
                .await
                .expect("ingest");
            got.delivered[0].message
        }

        let (_admin, url, _journal, store, meta) = admin_api().await;
        let c = client(&url, "oidc");
        let ja = client(&url, "ja");
        let login = || "a@threads.test".to_owned();

        // Учётная запись: домен и `account create`.
        exec(
            &c,
            false,
            ApiAction::Transport {
                action: Box::new(TransportAction::Domain {
                    action: DomainAction::Create {
                        name: "threads.test".into(),
                        relay: None,
                    },
                }),
            },
        )
        .await
        .expect("domain");
        let created = exec(
            &c,
            true,
            account_action(AccountAction::Create {
                login: login(),
                name: None,
            }),
        )
        .await
        .expect("account create");
        let v: Value = serde_json::from_str(&created).expect("json");
        let account: tp_contracts::AccountId = v["id"].as_str().expect("id").parse().expect("uuid");
        let scope = AccountScope {
            tenant: TenantId::DEFAULT,
            account,
        };
        let thread = |action: ThreadAction| ApiAction::Thread {
            action: Box::new(action),
        };
        let find = |message: tp_contracts::MessageId| {
            thread(ThreadAction::Find {
                account: login(),
                message_id: message.to_string(),
            })
        };

        // Два письма одной беседы: ответ присоединяется (In-Reply-To).
        let first = deliver(&store, &meta, scope, "one@external.test", None, "первое").await;
        let reply = deliver(
            &store,
            &meta,
            scope,
            "two@external.test",
            Some("one@external.test"),
            "ответ",
        )
        .await;

        // Беседа письма: удержания нет, оба письма в порядке привязки.
        let out = exec(&c, true, find(first)).await.expect("find");
        let v: Value = serde_json::from_str(&out).expect("json");
        assert_eq!(v["hold"], Value::Null, "{v}");
        assert_eq!(
            v["messages"],
            json!([first.to_string(), reply.to_string()]),
            "{v}"
        );
        let id = v["thread"].as_str().expect("thread").to_owned();
        let text = exec(&c, false, find(first)).await.expect("find text");
        assert!(text.contains("Удержание") && text.contains("нет"), "{text}");

        // Удержание: основание и кто; список удержаний организации; повторный find это видит.
        exec(
            &c,
            false,
            thread(ThreadAction::Hold {
                account: login(),
                thread: id.clone(),
                reason: "дело №9".into(),
            }),
        )
        .await
        .expect("hold");
        let out = exec(&c, true, find(first)).await.expect("find");
        let v: Value = serde_json::from_str(&out).expect("json");
        assert_eq!(v["hold"]["reason"], "дело №9", "{v}");
        assert_eq!(v["hold"]["by"], "root@example.test", "{v}");
        let out = exec(&c, true, thread(ThreadAction::Holds))
            .await
            .expect("holds");
        let v: Value = serde_json::from_str(&out).expect("json");
        assert_eq!(v["holds"].as_array().expect("holds").len(), 1, "{v}");
        assert_eq!(v["holds"][0]["thread"], id, "{v}");
        let text = exec(&c, false, thread(ThreadAction::Holds))
            .await
            .expect("holds text");
        assert!(text.contains("дело №9"), "{text}");

        // Выгрузка: письмо, удалённое в корзину, — в архиве; аудитору журнала — 403.
        store.delete_to_trash(scope, &[first]).await.expect("trash");
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("thread.zip");
        exec(
            &c,
            false,
            thread(ThreadAction::Export {
                account: login(),
                thread: id.clone(),
                output: Some(file.clone()),
            }),
        )
        .await
        .expect("export");
        let bytes = std::fs::read(&file).expect("zip");
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(&bytes)).expect("архив");
        assert_eq!(zip.len(), 2, "оба письма беседы, включая корзину");
        let mut names: Vec<String> = (0..zip.len())
            .map(|i| {
                zip.by_index(i)
                    .expect("запись")
                    .name()
                    .expect("имя")
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![format!("1-{first}.eml"), format!("2-{reply}.eml")],
            "{names:?}"
        );
        let mut entry = zip.by_name(&names[0]).expect("запись");
        let mut eml = String::new();
        std::io::Read::read_to_string(&mut entry, &mut eml).expect("чтение");
        assert!(eml.contains("Subject: первое"), "{eml}");
        let err = exec(
            &ja,
            false,
            thread(ThreadAction::Export {
                account: login(),
                thread: id.clone(),
                output: None,
            }),
        )
        .await
        .expect_err("аудитору журнала нельзя");
        assert!(err.contains("403"), "{err}");

        // Снятие: список удержаний пуст, удержания нет.
        exec(
            &c,
            false,
            thread(ThreadAction::Unhold {
                account: login(),
                thread: id,
            }),
        )
        .await
        .expect("unhold");
        let text = exec(&c, false, thread(ThreadAction::Holds))
            .await
            .expect("holds");
        assert!(text.contains("Удержанных бесед нет"), "{text}");
        let out = exec(&c, true, find(first)).await.expect("find");
        let v: Value = serde_json::from_str(&out).expect("json");
        assert_eq!(v["hold"], Value::Null, "{v}");
    }

    /// Приёмка ADM-53: `thepost admin journal rule list/set/delete` — администратор организации ведёт
    /// правила (цель, направление, включение), изменение конвейер читает без перезапуска; несуществующая
    /// область — отказ с подсказкой; аудитор журнала правил не видит (403).
    #[tokio::test]
    async fn journal_rule_commands_against_admin_api() {
        use tp_contracts::journal::JournalRuleStore as _;

        let (_admin, url, journal, _, _) = admin_api().await;
        let org_admin = client(&url, "org");
        let ja = client(&url, "ja");
        let json = |out: CliResult<String>| -> Value {
            serde_json::from_str(&out.expect("ответ")).expect("json")
        };
        let rule = |id: &str,
                    group: Option<String>,
                    account: Option<String>,
                    direction: DirectionArg,
                    disabled: bool| {
            ApiAction::Journal {
                action: Box::new(JournalAction::Rule {
                    action: Box::new(JournalRuleAction::Set {
                        id: id.to_owned(),
                        group,
                        account,
                        direction,
                        disabled,
                    }),
                }),
            }
        };
        let d = TenantId::DEFAULT;

        // Задание: организация целиком, оба направления, включено (по умолчанию).
        let v = json(
            exec(
                &org_admin,
                true,
                rule("all-mail", None, None, DirectionArg::Both, false),
            )
            .await,
        );
        assert_eq!(v["id"], "all-mail");
        assert_eq!(v["scope"], "org");
        assert_eq!(v["direction"], "both");
        assert_eq!(v["enabled"], true);
        let text = exec(
            &org_admin,
            false,
            rule("all-mail", None, None, DirectionArg::Both, false),
        )
        .await
        .expect("set text");
        assert!(
            text.contains("Цель:")
                && text.contains("организация")
                && text.contains("без перезапуска"),
            "{text}"
        );

        // Изменение видно конвейеру без перезапуска: порт читает на каждом письме (SMTP-53).
        assert_eq!(
            journal
                .rules(d)
                .await
                .expect("правила")
                .iter()
                .map(|r| r.id.clone())
                .collect::<Vec<_>>(),
            vec!["all-mail".to_owned()]
        );

        // Несуществующая группа и ящик — отказ с подсказкой (422).
        for (what, group, account) in [
            ("группа", Some(GroupId::new().to_string()), None),
            ("ящик", None, Some(AccountId::new().to_string())),
        ] {
            let err = exec(
                &org_admin,
                false,
                rule("team", group, account, DirectionArg::In, false),
            )
            .await
            .expect_err("области нет");
            assert!(err.contains("422") && err.contains(what), "{what}: {err}");
        }

        // Замена: выключение того же правила, дубликат идентификатора не плодится.
        let v = json(
            exec(
                &org_admin,
                true,
                rule("all-mail", None, None, DirectionArg::In, true),
            )
            .await,
        );
        assert_eq!(v["enabled"], false);
        assert_eq!(v["direction"], "in");
        let list = json(exec(&org_admin, true, journal_rule_list()).await);
        assert_eq!(list["rules"].as_array().expect("rules").len(), 1);
        let text = exec(&org_admin, false, journal_rule_list())
            .await
            .expect("list text");
        assert!(
            text.contains("all-mail")
                && text.contains("нет")
                && text.contains("ящик > группа > организация"),
            "{text}"
        );

        // Аудитор журнала правил не видит: чтение и запись — 403.
        for action in [
            journal_rule_list(),
            rule("all-mail", None, None, DirectionArg::Both, false),
            journal_rule_delete("all-mail"),
        ] {
            let err = exec(&ja, false, action).await.expect_err("аудитор журнала");
            assert!(err.contains("403"), "{err}");
        }

        // Удаление: подсказка; повтор — 404; список пуст.
        let text = exec(&org_admin, false, journal_rule_delete("all-mail"))
            .await
            .expect("delete text");
        assert!(text.contains("удалено"), "{text}");
        let err = exec(&org_admin, false, journal_rule_delete("all-mail"))
            .await
            .expect_err("правила нет");
        assert!(err.contains("404"), "{err}");
        let list = json(exec(&org_admin, true, journal_rule_list()).await);
        assert_eq!(list["rules"].as_array().expect("rules").len(), 0);
        assert!(journal.rules(d).await.expect("правила").is_empty());
    }

    /// `journal rule list`.
    fn journal_rule_list() -> ApiAction {
        ApiAction::Journal {
            action: Box::new(JournalAction::Rule {
                action: Box::new(JournalRuleAction::List),
            }),
        }
    }

    /// `journal rule delete <id>`.
    fn journal_rule_delete(id: &str) -> ApiAction {
        ApiAction::Journal {
            action: Box::new(JournalAction::Rule {
                action: Box::new(JournalRuleAction::Delete { id: id.to_owned() }),
            }),
        }
    }

    /// Сценарий пилота без curl: admin init → login → домены, учётная запись, пароль приложения, whoami;
    /// вход по токену OIDC.
    #[tokio::test]
    async fn pilot_flow_against_admin_api() {
        let (admin, url, _, _, _) = admin_api().await;
        let granted = admin
            .init(&InitRequest {
                email: "admin@example.test".into(),
                display_name: None,
                force: false,
            })
            .await
            .expect("init");

        // Вход по паролю admin init: сессия; неверный пароль — 401 с подсказкой.
        let anon = Client::anonymous(url.clone(), &Options::default()).expect("client");
        let json_args = ApiArgs {
            json: true,
            ..ApiArgs::default()
        };
        let session: Value = serde_json::from_str(
            &login(&anon, &json_args, &granted.login, granted.password.clone())
                .await
                .expect("login"),
        )
        .expect("json");
        let session = session["session"].as_str().expect("session").to_owned();
        assert!(session.starts_with("tps_"), "{session}");
        let err = login(&anon, &ApiArgs::default(), &granted.login, "wrong".into())
            .await
            .expect_err("неверный пароль");
        assert!(err.contains("401") && err.contains("пароль"), "{err}");
        let err = exec(&anon, false, ApiAction::Whoami)
            .await
            .expect_err("без сессии");
        assert!(err.contains("401"), "{err}");

        let s = client(&url, &session);
        let who = exec(&s, false, ApiAction::Whoami).await.expect("whoami");
        assert!(
            who.contains("admin@example.test") && who.contains("installation_admin"),
            "{who}"
        );

        // Домен admin init уже принят; добавление второго.
        let domains = exec(&s, false, domain_action(DomainAction::List))
            .await
            .expect("domains");
        assert!(domains.contains("example.test"), "{domains}");
        let added = exec(
            &s,
            true,
            domain_action(DomainAction::Create {
                name: "Second.Test".into(),
                relay: None,
            }),
        )
        .await
        .expect("transport domain create");
        let added: Value = serde_json::from_str(&added).expect("json");
        assert_eq!(added["domain"]["name"], "second.test");

        // Учётная запись: создание, поиск, пароль приложения по имени входа.
        let created = exec(
            &s,
            false,
            account_action(AccountAction::Create {
                login: "a@second.test".into(),
                name: Some("Анна".into()),
            }),
        )
        .await
        .expect("account create");
        assert!(
            created.contains("a@second.test") && created.contains("Анна"),
            "{created}"
        );
        let dup = exec(
            &s,
            false,
            account_action(AccountAction::Create {
                login: "a@second.test".into(),
                name: None,
            }),
        )
        .await
        .expect_err("занято");
        assert!(dup.contains("409"), "{dup}");
        let listed = exec(
            &s,
            false,
            account_action(AccountAction::List {
                login: Some("A@second.test".into()),
                prefix: None,
                after: None,
                limit: None,
            }),
        )
        .await
        .expect("account list");
        assert_eq!(listed.lines().count(), 2, "{listed}");

        // Список без --login: страницы по 2 записи по ссылке Link, префикс, предел.
        for login in ["c@second.test", "B@second.test"] {
            let action = AccountAction::Create {
                login: login.into(),
                name: None,
            };
            exec(&s, false, account_action(action))
                .await
                .expect("account create");
        }
        assert_eq!(
            list_logins(&s, None, None).await,
            [
                "a@second.test",
                "admin@example.test",
                "b@second.test",
                "c@second.test"
            ]
        );
        assert_eq!(
            list_logins(&s, Some("A"), None).await,
            ["a@second.test", "admin@example.test"]
        );
        assert_eq!(
            list_logins(&s, None, Some(3)).await,
            ["a@second.test", "admin@example.test", "b@second.test"]
        );
        let text = exec(
            &s,
            false,
            account_action(AccountAction::List {
                login: None,
                prefix: None,
                after: None,
                limit: Some(3),
            }),
        )
        .await
        .expect("limit text");
        assert_eq!(text.lines().count(), 5, "{text}");
        assert!(text.contains("есть ещё"), "{text}");
        let text = exec(
            &s,
            false,
            account_action(AccountAction::List {
                login: None,
                prefix: Some("c".into()),
                after: None,
                limit: None,
            }),
        )
        .await
        .expect("prefix text");
        assert!(
            text.contains("c@second.test") && !text.contains("есть ещё"),
            "{text}"
        );
        let issued = exec(
            &s,
            true,
            ApiAction::AppPassword {
                action: AppPasswordAction::Create {
                    account: "a@second.test".into(),
                    label: "swaks".into(),
                },
            },
        )
        .await
        .expect("app-password create");
        let issued: Value = serde_json::from_str(&issued).expect("json");
        assert!(!issued["password"].as_str().unwrap_or_default().is_empty());
        let id = issued["id"].as_str().expect("id").to_owned();
        exec(
            &s,
            false,
            ApiAction::AppPassword {
                action: AppPasswordAction::Revoke {
                    account: "a@second.test".into(),
                    id: id.clone(),
                },
            },
        )
        .await
        .expect("revoke");
        let list = exec(
            &s,
            true,
            ApiAction::AppPassword {
                action: AppPasswordAction::List {
                    account: "a@second.test".into(),
                },
            },
        )
        .await
        .expect("app-password list");
        let list: Value = serde_json::from_str(&list).expect("json");
        assert_eq!(list[0]["id"], id.as_str());
        assert!(list[0]["revoked_at"].is_string(), "{list}");

        let missing = exec(
            &s,
            false,
            account_action(AccountAction::Get {
                account: "nobody@second.test".into(),
            }),
        )
        .await
        .expect_err("нет записи");
        assert!(missing.contains("не найдена"), "{missing}");

        // Токен OIDC — тот же вход Bearer; неверный — 401 с подсказкой.
        let oidc = exec(&client(&url, "oidc"), false, ApiAction::Whoami)
            .await
            .expect("oidc");
        assert!(oidc.contains("root@example.test"), "{oidc}");
        let bad = exec(&client(&url, "bogus"), false, ApiAction::Whoami)
            .await
            .expect_err("bogus");
        assert!(bad.contains("401") && bad.contains("admin login"), "{bad}");

        // Внутренняя пересылка и удаление домена по версии снимка последнего чтения.
        let third = exec(
            &s,
            true,
            domain_action(DomainAction::Create {
                name: "third.test".into(),
                relay: Some("mx.third.test:25".into()),
            }),
        )
        .await
        .expect("transport domain create relay");
        let third: Value = serde_json::from_str(&third).expect("json");
        assert!(
            third["domain"]["kind"]["internal_relay"].is_object(),
            "{third}"
        );
        let id = third["domain"]["id"]
            .as_str()
            .expect("domain id")
            .to_owned();
        let removed = exec(
            &s,
            false,
            domain_action(DomainAction::Delete { domain: id }),
        )
        .await
        .expect("transport domain delete");
        assert!(removed.contains("удалён"), "{removed}");
        let domains = exec(&s, false, domain_action(DomainAction::List))
            .await
            .expect("domains");
        assert!(!domains.contains("third.test"), "{domains}");
    }

    /// ADM-17 (решение 62): администратор из CLI записывает пользователю правило пересылки, включает, отключает;
    /// неверный текст — отказ с позицией ошибки, в хранилище не попадает.
    #[tokio::test]
    async fn sieve_commands_against_admin_api() {
        let (_admin, url, _, _, _) = admin_api().await;
        let c = client(&url, "oidc");
        let sieve = |action| ApiAction::Sieve { action };
        let account = || "a@rules.test".to_owned();
        let name = || "пересылка".to_owned();
        for action in [
            domain_action(DomainAction::Create {
                name: "rules.test".into(),
                relay: None,
            }),
            account_action(AccountAction::Create {
                login: account(),
                name: None,
            }),
        ] {
            exec(&c, false, action).await.expect("подготовка");
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("rule.sieve");
        let text = "redirect \"outside@example.net\";\n";
        std::fs::write(&file, text).expect("write");
        let put = |file: &Path| {
            sieve(SieveAction::Put {
                account: account(),
                name: name(),
                file: file.to_owned(),
            })
        };
        let done = exec(&c, false, put(&file)).await.expect("put");
        assert_eq!(done, "Скрипт пересылка записан.\n");
        let on = sieve(SieveAction::Activate {
            account: account(),
            name: name(),
        });
        exec(&c, false, on).await.expect("activate");

        let list = || sieve(SieveAction::List { account: account() });
        let listed = exec(&c, false, list()).await.expect("list");
        let row = listed.lines().nth(1).expect("строка");
        assert!(row.contains("пересылка") && row.ends_with("да"), "{listed}");
        let get = || {
            sieve(SieveAction::Get {
                account: account(),
                name: name(),
            })
        };
        assert_eq!(exec(&c, false, get()).await.as_deref(), Ok(text));

        // Неверный текст: 422 с позицией, прежний текст на месте.
        let bad = dir.path().join("bad.sieve");
        std::fs::write(&bad, "keep;\nнеизвестно;\n").expect("write");
        let err = exec(&c, false, put(&bad)).await.expect_err("422");
        assert!(err.contains("422") && err.contains("строка 2"), "{err}");
        // Текст верен, но вложенность больше предела секции `sieve`: отказ узла с позицией, как при доставке.
        let deep = dir.path().join("deep.sieve");
        let deep_text = "if true { if true { if true { if true { keep; } } } }
";
        assert!(
            tp_sieve::compile(deep_text.as_bytes(), &tp_sieve::Limits::default()).is_ok(),
            "с пределами по умолчанию скрипт верен"
        );
        std::fs::write(&deep, deep_text).expect("write");
        let err = exec(&c, false, put(&deep)).await.expect_err("422");
        assert!(err.contains("422") && err.contains("строка 1"), "{err}");
        let missing = dir.path().join("нет.sieve");
        let err = exec(&c, false, put(&missing)).await.expect_err("нет файла");
        assert!(err.contains("нет.sieve"), "{err}");
        assert_eq!(exec(&c, false, get()).await.as_deref(), Ok(text));

        // Отключение: скрипт остаётся, активного нет.
        let off = sieve(SieveAction::Deactivate { account: account() });
        let done = exec(&c, false, off).await.expect("deactivate");
        assert_eq!(done, "Правила отключены.\n");
        let json = exec(&c, true, list()).await.expect("list");
        let v: Value = serde_json::from_str(&json).expect("json");
        assert_eq!(v[0]["name"], "пересылка");
        assert_eq!(v[0]["active"], false);
        let on = sieve(SieveAction::Activate {
            account: account(),
            name: "другой".into(),
        });
        let err = exec(&c, false, on).await.expect_err("404");
        assert!(err.contains("404"), "{err}");

        let bad_file = bad.clone();
        // Удаление: активный скрипт — 409, после отключения удаляется; повторно — 404.
        let on = sieve(SieveAction::Activate {
            account: account(),
            name: name(),
        });
        exec(&c, false, on).await.expect("activate");
        let delete = || {
            sieve(SieveAction::Delete {
                account: account(),
                name: name(),
            })
        };
        let err = exec(&c, false, delete()).await.expect_err("409");
        assert!(err.contains("409"), "{err}");
        let off = sieve(SieveAction::Deactivate { account: account() });
        exec(&c, false, off).await.expect("deactivate");
        let done = exec(&c, false, delete()).await.expect("delete");
        assert_eq!(done, "Скрипт пересылка удалён.\n");
        let json = exec(&c, true, list()).await.expect("list");
        assert_eq!(serde_json::from_str::<Value>(&json).ok(), Some(json!([])));
        let err = exec(&c, false, delete()).await.expect_err("404");
        assert!(err.contains("404"), "{err}");

        // Автоответ: не задан — выключен; включение, выключение с сохранением текста, сброс срока.
        let vacation = |action| ApiAction::Vacation {
            action: Box::new(action),
        };
        let get = || vacation(VacationAction::Get { account: account() });
        let set = || VacationChange {
            enabled: true,
            from: None,
            to: None,
            subject: None,
            text: None,
            html: None,
            external_subject: None,
            external_text: None,
        };
        let apply = |off: bool, ch: VacationChange| {
            vacation(VacationAction::Set {
                account: account(),
                off,
                from: ch.from,
                to: ch.to,
                subject: ch.subject,
                text: ch.text,
                text_file: None,
                html_file: None,
                external_subject: ch.external_subject,
                external_text: ch.external_text,
            })
        };
        let shown = exec(&c, false, get()).await.expect("vacation get");
        assert!(shown.starts_with("Включён"), "{shown}");
        assert!(shown.lines().next().is_some_and(|l| l.ends_with("нет")));
        let on = apply(
            false,
            VacationChange {
                from: Some("2026-12-01T00:00:00Z".into()),
                to: Some("2026-12-15T00:00:00+03:00".into()),
                subject: Some("В отпуске".into()),
                text: Some("Вернусь 15 декабря.".into()),
                ..set()
            },
        );
        let v: Value = serde_json::from_str(&exec(&c, true, on).await.expect("set")).expect("json");
        assert_eq!(v["enabled"], true);
        assert_eq!(v["subject"], "В отпуске");
        assert_eq!(v["text_body"], "Вернусь 15 декабря.");
        assert_eq!(v["from"], "2026-12-01T00:00:00Z");
        let shown = exec(&c, false, get()).await.expect("vacation get");
        assert!(
            shown.contains("В отпуске") && shown.contains("2026-12-01"),
            "{shown}"
        );
        let off = exec(&c, true, apply(true, set())).await.expect("off");
        let v: Value = serde_json::from_str(&off).expect("json");
        assert_eq!(v["enabled"], false);
        assert_eq!(v["text_body"], "Вернусь 15 декабря.");
        assert_eq!(v["from"], "2026-12-01T00:00:00Z");
        let reset = apply(
            false,
            VacationChange {
                from: Some("-".into()),
                to: Some("-".into()),
                subject: Some("-".into()),
                ..set()
            },
        );
        let v: Value =
            serde_json::from_str(&exec(&c, true, reset).await.expect("reset")).expect("json");
        assert_eq!(v["enabled"], true);
        assert_eq!(
            (&v["from"], &v["to"], &v["subject"]),
            (&json!(null), &json!(null), &json!(null))
        );
        let bad = apply(
            false,
            VacationChange {
                from: Some("завтра".into()),
                ..set()
            },
        );
        let err = exec(&c, false, bad).await.expect_err("время");
        assert!(err.contains("RFC 3339"), "{err}");
        // Текст из файла.
        let reply = dir.path().join("reply.txt");
        std::fs::write(&reply, "Из файла.\n").expect("write");
        let from_file = vacation(VacationAction::Set {
            account: account(),
            off: false,
            from: None,
            to: None,
            subject: None,
            text: None,
            text_file: Some(reply),
            html_file: None,
            external_subject: None,
            external_text: None,
        });
        let v: Value =
            serde_json::from_str(&exec(&c, true, from_file).await.expect("file")).expect("json");
        assert_eq!(v["text_body"], "Из файла.\n");

        // Внешний текст (CTR-93): чужим — только он, пока не задан — наружу ничего.
        let external = apply(
            false,
            VacationChange {
                external_subject: Some("В отпуске".into()),
                external_text: Some("Вернусь в январе.".into()),
                ..set()
            },
        );
        let v: Value =
            serde_json::from_str(&exec(&c, true, external).await.expect("external")).expect("json");
        assert_eq!(v["external_subject"], "В отпуске");
        assert_eq!(v["external_text_body"], "Вернусь в январе.");
        let shown = exec(&c, false, get()).await.expect("vacation get");
        assert!(shown.contains("Вернусь в январе."), "{shown}");
        let external_reset = apply(
            false,
            VacationChange {
                external_subject: Some("-".into()),
                ..set()
            },
        );
        let v: Value = serde_json::from_str(
            &exec(&c, true, external_reset)
                .await
                .expect("external reset"),
        )
        .expect("json");
        assert_eq!(v["external_subject"], json!(null));

        // Скрипт организации: не задан — 404; запись, чтение, 422 с позицией, удаление (повторное — не ошибка).
        let org = |action| sieve(SieveAction::Org { action });
        let err = exec(&c, false, org(OrgSieveAction::Get))
            .await
            .expect_err("404");
        assert!(err.contains("404"), "{err}");
        let rule = dir.path().join("org.sieve");
        let org_text = "if address :is \"from\" \"spam@example.net\" { discard; stop; }\n";
        std::fs::write(&rule, org_text).expect("write");
        let put = |file: &Path| {
            org(OrgSieveAction::Put {
                file: file.to_owned(),
            })
        };
        let done = exec(&c, false, put(&rule)).await.expect("org put");
        assert_eq!(done, "Скрипт организации записан.\n");
        assert_eq!(
            exec(&c, false, org(OrgSieveAction::Get)).await.as_deref(),
            Ok(org_text)
        );
        let err = exec(&c, false, put(&bad_file)).await.expect_err("422");
        assert!(err.contains("422") && err.contains("строка 2"), "{err}");
        assert_eq!(
            exec(&c, false, org(OrgSieveAction::Get)).await.as_deref(),
            Ok(org_text)
        );
        // Профиль «админский» (ADM-49): vacation запрещён; redirect на внешний адрес при закрытой
        // автопересылке — 422 со строкой и столбцом.
        let vacation = dir.path().join("org-vacation.sieve");
        std::fs::write(&vacation, "vacation :days 3 \"Уехал\";\n").expect("write");
        let err = exec(&c, false, put(&vacation)).await.expect_err("vacation");
        assert!(err.contains("422") && err.contains("строка 1"), "{err}");
        let redirect = dir.path().join("org-redirect.sieve");
        std::fs::write(&redirect, "redirect \"x@gmail.com\";\n").expect("write");
        let err = exec(&c, false, put(&redirect)).await.expect_err("redirect");
        assert!(
            err.contains("422") && err.contains("gmail.com") && err.contains("строка 1"),
            "{err}"
        );
        assert_eq!(
            exec(&c, false, org(OrgSieveAction::Get)).await.as_deref(),
            Ok(org_text)
        );
        for _ in 0..2 {
            let done = exec(&c, false, org(OrgSieveAction::Delete))
                .await
                .expect("org delete");
            assert_eq!(done, "Скрипт организации удалён.\n");
        }
        let err = exec(&c, false, org(OrgSieveAction::Get))
            .await
            .expect_err("404");
        assert!(err.contains("404"), "{err}");
    }

    #[test]
    fn org_put_help_explains_order() {
        use clap::CommandFactory;

        let mut cmd = crate::cli::Cli::command();
        let mut cmd = &mut cmd;
        for name in ["admin", "sieve", "org", "put"] {
            cmd = cmd.find_subcommand_mut(name).expect(name);
        }
        let help = cmd.render_long_help().to_string();
        assert!(
            help.contains("discard; stop;") && help.contains("подряд"),
            "{help}"
        );
    }

    #[tokio::test]
    async fn account_block_against_admin_api() {
        let (_admin, url, _, _, _) = admin_api().await;
        let c = client(&url, "oidc");
        let login = || "a@block.test".to_owned();
        let account = account_action;
        for action in [
            domain_action(DomainAction::Create {
                name: "block.test".into(),
                relay: None,
            }),
            account(AccountAction::Create {
                login: login(),
                name: None,
            }),
        ] {
            exec(&c, false, action).await.expect("подготовка");
        }
        let enabled = |out: CliResult<String>| {
            let v: Value = serde_json::from_str(&out.expect("ответ")).expect("json");
            (v["enabled"].clone(), v["display_name"].clone())
        };
        let block = account(AccountAction::Block { account: login() });
        assert_eq!(enabled(exec(&c, true, block).await).0, false);
        let get = || account(AccountAction::Get { account: login() });
        let shown = exec(&c, false, get()).await.expect("get");
        assert!(shown.contains("false"), "{shown}");
        let unblock = account(AccountAction::Unblock { account: login() });
        assert_eq!(enabled(exec(&c, true, unblock).await).0, true);
        let rename = account(AccountAction::Rename {
            account: login(),
            name: "Анна".into(),
        });
        assert_eq!(
            enabled(exec(&c, true, rename).await),
            (json!(true), json!("Анна"))
        );
        let rename = account(AccountAction::Rename {
            account: login(),
            name: String::new(),
        });
        let err = exec(&c, false, rename).await.expect_err("400");
        assert!(err.contains("400"), "{err}");
        let missing = account(AccountAction::Block {
            account: "нет@block.test".into(),
        });
        assert!(exec(&c, false, missing).await.is_err());
    }

    /// ADM-42: `account set` — псевдонимы (замена и снятие) и скрытие из книги «Организация»; домен не принят — 409;
    /// без ключей — ошибка без запроса.
    #[tokio::test]
    async fn account_set_against_admin_api() {
        let (_admin, url, _, _, _) = admin_api().await;
        let c = client(&url, "oidc");
        let login = || "a@alias.test".to_owned();
        let account = account_action;
        for action in [
            domain_action(DomainAction::Create {
                name: "alias.test".into(),
                relay: None,
            }),
            account(AccountAction::Create {
                login: login(),
                name: None,
            }),
        ] {
            exec(&c, false, action).await.expect("подготовка");
        }
        let set = |aliases: &[&str], no_aliases: bool, hidden_from_gal: Option<bool>| {
            account(AccountAction::Set {
                account: login(),
                aliases: aliases.iter().map(|a| (*a).to_owned()).collect(),
                no_aliases,
                hidden_from_gal,
            })
        };
        let fields = |out: CliResult<String>| {
            let v: Value = serde_json::from_str(&out.expect("ответ")).expect("json");
            (v["aliases"].clone(), v["hidden_from_gal"].clone())
        };
        let out = exec(
            &c,
            true,
            set(&["B@alias.test", "c@alias.test"], false, None),
        )
        .await;
        assert_eq!(
            fields(out),
            (json!(["b@alias.test", "c@alias.test"]), json!(false))
        );
        let out = exec(&c, true, set(&[], false, Some(true))).await;
        assert_eq!(
            fields(out),
            (json!(["b@alias.test", "c@alias.test"]), json!(true))
        );
        let shown = exec(&c, false, set(&[], true, Some(false)))
            .await
            .expect("set");
        // Было/стало — только изменённые поля: псевдонимы сняты, скрытие из книги снято.
        assert!(
            shown.contains("- aliases: [\"b@alias.test\",\"c@alias.test\"]\n+ aliases: []\n")
                && shown.contains("- hidden_from_gal: true\n+ hidden_from_gal: false\n")
                && !shown.contains("login")
                && shown.contains(
                    "✓ Сохранено · запись аудита: thepost admin audit search --method PATCH"
                ),
            "{shown}"
        );
        let get = account(AccountAction::Get { account: login() });
        assert_eq!(fields(exec(&c, true, get).await), (json!([]), json!(false)));
        let err = exec(&c, false, set(&["x@other.test"], false, None))
            .await
            .expect_err("409");
        assert!(err.contains("409"), "{err}");
        let err = exec(&c, false, set(&[], false, None))
            .await
            .expect_err("без ключей");
        assert!(err.contains("--alias"), "{err}");
    }

    /// `--after` из подсказки вывода (`… --after <имя входа>`); нет подсказки — `None`.
    fn after_hint(text: &str) -> Option<String> {
        text.split("--after ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .map(str::to_owned)
    }

    /// ADM-37: `account list --after` с подсказки предыдущей страницы — все записи по порядку без пропусков и
    /// повторов; подсказка сохраняет `--prefix`.
    #[tokio::test]
    async fn account_list_after_pages() {
        let (_admin, url, _, _, _) = admin_api().await;
        let c = client(&url, "oidc");
        let domain = DomainAction::Create {
            name: "page.test".into(),
            relay: None,
        };
        exec(&c, false, domain_action(domain))
            .await
            .expect("domain");
        let logins: Vec<String> = (1..=5).map(|i| format!("u{i}@page.test")).collect();
        for login in logins.iter().rev() {
            let action = AccountAction::Create {
                login: login.clone(),
                name: None,
            };
            exec(&c, false, account_action(action))
                .await
                .expect("account create");
        }
        let list = |after: Option<String>| {
            account_action(AccountAction::List {
                login: None,
                prefix: Some("u".into()),
                after,
                limit: Some(2),
            })
        };
        let mut seen = Vec::new();
        let mut after = None;
        for _ in 0..logins.len() {
            let page: Value = serde_json::from_str(
                &exec(&c, true, list(after.clone()))
                    .await
                    .expect("page json"),
            )
            .expect("json");
            seen.extend(
                page.as_array()
                    .expect("array")
                    .iter()
                    .map(|a| a["login"].as_str().expect("login").to_owned()),
            );
            let text = exec(&c, false, list(after.clone())).await.expect("page");
            after = after_hint(&text);
            match &after {
                Some(next) => {
                    assert!(text.contains("--prefix u"), "{text}");
                    assert_eq!(seen.last(), Some(next), "{text}");
                }
                None => break,
            }
        }
        assert_eq!(after, None, "последняя страница без подсказки");
        assert_eq!(seen, logins);
    }

    /// Начало config.yaml профиля dev без внешних секретов.
    const DEV_CONFIG: &str = "domain: example.test\nprofile: dev\nroles: [admin]\nservice_http:\n  allow_plaintext: true\ndatabase:\n  url: postgres://thepost@db/thepost?sslmode=disable\n  tls: { allow_plaintext: true }\nblob:\n  url: file:///var/lib/thepost/blob\n";

    /// ADM-39: `login --oidc` — вход с устройства у поставщика `auth.oidc` (заглушка RFC 8628): код устройства,
    /// затем токен (код возврата 0); без `cli.oidc.client_id` — отказ без запроса токена.
    #[tokio::test]
    async fn login_oidc_gets_token() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        use axum::routing::{get, post};
        use axum::{Json, Router};

        let polls = Arc::new(AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let issuer = format!("http://{}", listener.local_addr().expect("addr"));
        let doc = json!({
            "issuer": issuer,
            "device_authorization_endpoint": format!("{issuer}/device"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/jwks"),
        });
        let device = json!({
            "device_code": "dev-1",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://sso.example.test/device",
            "expires_in": 600,
            "interval": 0,
        });
        let counter = polls.clone();
        let router = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || async move { Json(doc) }),
            )
            .route("/device", post(move || async move { Json(device) }))
            .route(
                "/token",
                post(move || {
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::SeqCst);
                        Json(json!({ "access_token": "at-1", "token_type": "Bearer" }))
                    }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, router).await });

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.yaml");
        let config = |cli: &str| {
            format!(
                "{DEV_CONFIG}http:\n  admin: {{ listen: \"127.0.0.1:9443\", allow_plaintext: true }}\n\
                 auth:\n  oidc:\n    issuer: \"{issuer}\"\n    audience: [thepost]\n    \
                 tls: {{ allow_plaintext: true }}\n{cli}"
            )
        };
        let login = || ApiAction::Login {
            user: None,
            password_stdin: false,
            oidc: true,
        };
        std::fs::write(&path, config("cli:\n  oidc:\n    client_id: thepost-cli\n"))
            .expect("write");
        assert_eq!(command(&path, ApiArgs::default(), login()).await, 0);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        std::fs::write(&path, config("")).expect("write");
        assert_eq!(command(&path, ApiArgs::default(), login()).await, 1);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn login_help_explains_oidc() {
        use clap::CommandFactory;

        let mut cmd = crate::cli::Cli::command();
        let mut cmd = &mut cmd;
        for name in ["admin", "login"] {
            cmd = cmd.find_subcommand_mut(name).expect(name);
        }
        let help = cmd.render_long_help().to_string();
        assert!(
            help.contains("--oidc") && help.contains("RFC 8628") && help.contains(ENV_TOKEN),
            "{help}"
        );
    }

    /// `cli.oidc` без `client_id` — вход с устройства недоступен (понятная ошибка до запросов к поставщику);
    /// с ним — настройки клиента как в секции.
    #[test]
    fn device_settings_need_client_id() {
        let e = device_settings(&CliOidc::default()).expect_err("no client");
        assert!(e.contains("cli.oidc.client_id"), "{e}");
        let s = device_settings(&CliOidc {
            client_id: Some("thepost-cli".into()),
            ..CliOidc::default()
        })
        .expect("settings");
        assert_eq!(s.client_id, "thepost-cli");
        assert_eq!(s.scope, "openid");
        assert_eq!(s.max_wait, CliOidc::default().max_wait);
    }

    /// ADM-38: политики, группы, корзина, журнал аудита, журнал доставки, источники и маршруты транспорта —
    /// каждая команда против роутера tp-admin.
    #[tokio::test]
    async fn resource_commands_against_admin_api() {
        let (_admin, url, _, _, _) = admin_api().await;
        let c = client(&url, "oidc");
        let a = || "a@res.test".to_owned();
        let b = || "b@res.test".to_owned();
        let domain = DomainAction::Create {
            name: "res.test".into(),
            relay: None,
        };
        exec(&c, false, domain_action(domain))
            .await
            .expect("domain");
        for login in [a(), b()] {
            let action = AccountAction::Create { login, name: None };
            exec(&c, false, account_action(action))
                .await
                .expect("account");
        }
        let json = |out: CliResult<String>| -> Value {
            serde_json::from_str(&out.expect("ответ")).expect("json")
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let write = |name: &str, text: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, text).expect("write");
            path
        };

        // Политика: организация, ящик, домен; действующее значение наследуется сверху.
        let policy = |action| ApiAction::Policy {
            action: Box::new(action),
        };
        let level = |domain: Option<&str>, account: Option<String>| PolicyLevel {
            domain: domain.map(str::to_owned),
            account,
        };
        let file = write(
            "org.json",
            r#"{"quota_bytes": 1000, "trash_retention": "30d"}"#,
        );
        let set = PolicyAction::Set {
            level: level(None, None),
            file,
        };
        assert_eq!(json(exec(&c, true, policy(set)).await)["quota_bytes"], 1000);
        let set = PolicyAction::Set {
            level: level(None, Some(a())),
            file: write("account.json", r#"{"send_per_hour": 5}"#),
        };
        exec(&c, false, policy(set)).await.expect("account policy");
        let get = |l| policy(PolicyAction::Get { level: l });
        let got = json(exec(&c, true, get(level(None, Some(a())))).await);
        assert_eq!(got["policy"]["send_per_hour"], 5);
        assert_eq!(got["policy"]["quota_bytes"], Value::Null);
        assert_eq!(got["effective"]["quota_bytes"], 1000);
        let text = exec(&c, false, get(level(None, None)))
            .await
            .expect("org policy");
        assert!(
            text.contains("ДЕЙСТВУЕТ")
                && text
                    .lines()
                    .any(|l| l.starts_with("quota_bytes") && l.contains("1000")),
            "{text}"
        );
        let got = json(exec(&c, true, get(level(Some("RES.test"), None))).await);
        assert_eq!(got["policy"]["trash_retention"], Value::Null);
        assert!(got["effective"]["trash_retention"].is_string(), "{got}");
        let set = PolicyAction::Set {
            level: level(None, None),
            file: write("bad.json", r#"{"quota": 1}"#),
        };
        let err = exec(&c, false, policy(set)).await.expect_err("поле");
        assert!(err.contains("quota"), "{err}");

        // Группы: создание с участником, список, чтение по адресу, замена участников, удаление.
        let group = group_action;
        let create = GroupAction::Create {
            name: "Отдел".into(),
            address: Some("otdel@res.test".into()),
            accounts: vec![a()],
            groups: vec![],
        };
        let created = json(exec(&c, true, group(create)).await);
        let a_id = created["members"][0]["account"]
            .as_str()
            .expect("account")
            .to_owned();
        assert_eq!(created["names"][a_id.as_str()], "a@res.test");
        let listed = exec(&c, false, group(GroupAction::List))
            .await
            .expect("group list");
        assert!(
            listed.contains("Отдел") && listed.contains("otdel@res.test"),
            "{listed}"
        );
        let shown = exec(
            &c,
            false,
            group(GroupAction::Get {
                group: "OTDEL@res.test".into(),
            }),
        )
        .await
        .expect("group get");
        assert!(
            shown.contains("a@res.test") && shown.contains("anyone"),
            "{shown}"
        );
        let members = |set, accounts| {
            group(GroupAction::Members {
                group: "отдел".into(),
                set,
                accounts,
                groups: vec![],
            })
        };
        let replaced = json(exec(&c, true, members(true, vec![b()])).await);
        assert_eq!(replaced.as_array().map(Vec::len), Some(1), "{replaced}");
        let shown = exec(&c, false, members(false, vec![]))
            .await
            .expect("members");
        assert!(
            shown.contains("b@res.test") && !shown.contains("a@res.test"),
            "{shown}"
        );
        let delete = GroupAction::Delete {
            group: "Отдел".into(),
        };
        exec(&c, false, group(delete)).await.expect("group delete");
        let get = GroupAction::Get {
            group: "Отдел".into(),
        };
        let err = exec(&c, false, group(get)).await.expect_err("нет группы");
        assert!(err.contains("не найдена"), "{err}");

        // Корзина: пустая видимая и скрытая, срок — действующий; восстановление чужого письма — отказ узла.
        let trash = |action| ApiAction::Trash { action };
        for hidden in [false, true] {
            let list = TrashAction::List {
                account: a(),
                hidden,
                subject: true,
                offset: 0,
                limit: None,
            };
            let text = exec(&c, false, trash(list)).await.expect("trash list");
            assert!(
                text.starts_with("нет записей")
                    && text.contains("Срок корзины:")
                    && !text.contains("по умолчанию"),
                "{text}"
            );
        }
        for (hidden, path) in [
            (false, "/trash/{message}/restore: 4"),
            (true, "/trash/hidden/{message}/restore: 404"),
        ] {
            let restore = TrashAction::Restore {
                account: a(),
                message: tp_contracts::MessageId::new().to_string(),
                hidden,
            };
            let err = exec(&c, false, trash(restore))
                .await
                .expect_err("нет письма");
            assert!(err.contains(path), "{err}");
        }

        // Журнал аудита: записи политик (PUT) по одной на страницу через подсказку --after, без повторов.
        let audit = |since: Option<&str>, after| ApiAction::Audit {
            action: Box::new(AuditAction::Search {
                since: since.map(str::to_owned),
                until: None,
                actor: None,
                method: Some("put".into()),
                route: None,
                limit: Some(1),
                after,
            }),
        };
        let (mut routes, mut seqs, mut after) = (Vec::new(), Vec::new(), None);
        for _ in 0..10 {
            let page = json(exec(&c, true, audit(None, after)).await);
            for e in page["entries"].as_array().expect("entries") {
                routes.push(e["route"].as_str().expect("route").to_owned());
                seqs.push(e["seq"].as_u64().expect("seq"));
            }
            let text = exec(&c, false, audit(None, after))
                .await
                .expect("audit text");
            after = page["next"].as_u64();
            assert_eq!(after_hint(&text), after.map(|n| n.to_string()), "{text}");
            if after.is_none() {
                break;
            }
        }
        assert_eq!(after, None, "последняя страница без подсказки");
        assert!(seqs.windows(2).all(|w| w[0] < w[1]), "{seqs:?}");
        for route in [
            "/api/v1/orgs/{org}/policy",
            "/api/v1/orgs/{org}/accounts/{account}/policy",
        ] {
            assert!(routes.iter().any(|r| r == route), "{routes:?}");
        }
        let err = exec(&c, false, audit(Some("завтра"), None))
            .await
            .expect_err("время");
        assert!(err.contains("RFC 3339"), "{err}");

        // Журнал доставки: поиск по отправителю.
        let search = DeliveryAction::Search {
            sender: Some(a()),
            recipient: None,
            message_id: None,
            since: Some("2026-01-01T00:00:00Z".into()),
            until: None,
            limit: None,
            after: None,
        };
        let found = exec(
            &c,
            false,
            ApiAction::Delivery {
                action: Box::new(search),
            },
        )
        .await
        .expect("delivery");
        assert_eq!(found, "нет записей\n");

        // Доверенные источники: шлюз по сети, приложение по сертификату; удаление; неверная сеть — отказ.
        let source = |action| transport(TransportAction::Source { action });
        let set = |name: &str, networks: Vec<&str>, cert: Option<&str>, senders: Vec<&str>| {
            source(SourceAction::Set {
                name: name.into(),
                networks: networks.into_iter().map(str::to_owned).collect(),
                client_cert: cert.map(str::to_owned),
                application: !senders.is_empty(),
                senders: senders.into_iter().map(str::to_owned).collect(),
                external: false,
                xclient: cert.is_none(),
                authserv_id: cert.is_none().then(|| "mx.res.test".to_owned()),
            })
        };
        let done = exec(&c, false, set("gw", vec!["192.0.2.0/24"], None, vec![]))
            .await
            .expect("source gw");
        assert!(
            done.contains("+ name: gw")
                && done.contains("+ matcher: ")
                && !done.contains("- name")
                && done.contains(
                    "✓ Сохранено · запись аудита: thepost admin audit search --method PUT"
                ),
            "{done}"
        );
        // Повтор с другой сетью — только изменённое поле.
        let again = exec(&c, false, set("gw", vec!["198.51.100.0/24"], None, vec![]))
            .await
            .expect("source gw again");
        assert!(
            again.contains("198.51.100.0/24")
                && !again.contains("name:")
                && !again.contains("kind:"),
            "{again}"
        );
        exec(
            &c,
            false,
            set("mfu", vec![], Some("mfu.res.test"), vec!["@res.test"]),
        )
        .await
        .expect("source mfu");
        let listed = exec(&c, false, source(SourceAction::List))
            .await
            .expect("source list");
        for part in [
            "198.51.100.0/24",
            "XCLIENT",
            "authserv-id mx.res.test",
            "сертификат mfu.res.test",
            "приложение: @res.test",
        ] {
            assert!(listed.contains(part), "{part}: {listed}");
        }
        let delete = SourceAction::Delete { name: "gw".into() };
        exec(&c, false, source(delete))
            .await
            .expect("source delete");
        let listed = json(exec(&c, true, source(SourceAction::List)).await);
        assert_eq!(
            listed["sources"].as_array().map(Vec::len),
            Some(1),
            "{listed}"
        );
        let err = exec(&c, false, set("bad", vec!["не сеть"], None, vec![]))
            .await
            .expect_err("сеть");
        assert!(err.starts_with("источник:"), "{err}");

        // Политики доменов назначения: TLS, smart host, закреплённый ключ; удаление; неверный адрес — отказ.
        let route = |action| transport(TransportAction::Route { action });
        let set = |pattern: &str, tls, pins: Vec<String>, egress_ip: Option<&str>| {
            route(RouteAction::Set {
                pattern: pattern.into(),
                tls,
                pins,
                smart_host: Some("relay.example.net:587".into()),
                egress_ip: egress_ip.map(str::to_owned),
            })
        };
        let done = exec(
            &c,
            false,
            set("Example.org", TlsMode::Required, vec![], Some("192.0.2.1")),
        )
        .await
        .expect("route set");
        assert!(
            done.contains("+ pattern: example.org")
                && done.contains("+ tls: required")
                && done.contains("✓ Сохранено"),
            "{done}"
        );
        let pin = "ab".repeat(32);
        let pinned = format!("pinned: {pin}");
        exec(
            &c,
            false,
            set("*", TlsMode::Opportunistic, vec![pin.clone()], None),
        )
        .await
        .expect("route pin");
        let listed = exec(&c, false, route(RouteAction::List))
            .await
            .expect("route list");
        for part in [
            "example.org",
            "required",
            "relay.example.net:587",
            "192.0.2.1",
            pinned.as_str(),
        ] {
            assert!(listed.contains(part), "{part}: {listed}");
        }
        let delete = RouteAction::Delete {
            pattern: "example.org".into(),
        };
        exec(&c, false, route(delete)).await.expect("route delete");
        let listed = json(exec(&c, true, route(RouteAction::List)).await);
        assert_eq!(
            listed["routes"].as_array().map(Vec::len),
            Some(1),
            "{listed}"
        );
        let err = exec(
            &c,
            false,
            set("x.test", TlsMode::Required, vec![], Some("не адрес")),
        )
        .await
        .expect_err("адрес");
        assert!(err.contains("--egress-ip"), "{err}");
    }

    /// Приёмка ADM-47: ресурсы бронирования в CLI — создание без типа (переговорная) и с типом (оборудование),
    /// колонка «Тип» в `resources list`, смена типа по адресу, неизвестный адрес — ошибка.
    #[tokio::test]
    async fn booking_resources_against_admin_api() {
        let (_admin, url, _, _, _) = admin_api().await;
        let c = client(&url, "oidc");
        exec(
            &c,
            false,
            domain_action(DomainAction::Create {
                name: "res.test".into(),
                relay: None,
            }),
        )
        .await
        .expect("domain");
        let resources = |action: ResourceAction| ApiAction::Resources {
            action: Box::new(action),
        };
        let create = |login: &str, t: ResourceTypeArg| {
            resources(ResourceAction::Create {
                login: login.into(),
                name: None,
                resource_type: t,
            })
        };

        // Без типа — помещение; с типом — оборудование.
        let room = exec(&c, true, create("room@res.test", ResourceTypeArg::Room))
            .await
            .expect("create room");
        let room: Value = serde_json::from_str(&room).expect("json");
        assert_eq!(room["resource_type"], "room");
        assert_eq!(room["booking_policy"]["auto_accept"], true);
        let projector = exec(
            &c,
            true,
            create("projector@res.test", ResourceTypeArg::Equipment),
        )
        .await
        .expect("create projector");
        let projector: Value = serde_json::from_str(&projector).expect("json");
        assert_eq!(projector["resource_type"], "equipment");

        // Список — колонка «Тип».
        let listed = exec(&c, false, resources(ResourceAction::List))
            .await
            .expect("resources list");
        for part in [
            "ИМЯ ВХОДА",
            "ТИП",
            "projector@res.test",
            "оборудование",
            "room@res.test",
            "помещение",
        ] {
            assert!(listed.contains(part), "{part}: {listed}");
        }

        // Смена типа по адресу (без учёта регистра); вывод — было/стало; тип сохраняется.
        let set_type = resources(ResourceAction::SetType {
            resource: "ROOM@res.test".into(),
            resource_type: ResourceTypeArg::Equipment,
        });
        let changed = exec(&c, false, set_type).await.expect("set-type");
        assert!(
            changed.contains("resource_type") && changed.contains("equipment"),
            "{changed}"
        );
        let list = exec(&c, true, resources(ResourceAction::List))
            .await
            .expect("list json");
        let list: Value = serde_json::from_str(&list).expect("json");
        let types: Vec<(&str, &str)> = list
            .as_array()
            .expect("list")
            .iter()
            .filter_map(|r| Some((r["login"].as_str()?, r["resource_type"].as_str()?)))
            .collect();
        assert_eq!(
            types,
            [
                ("projector@res.test", "equipment"),
                ("room@res.test", "equipment")
            ],
            "{list}"
        );

        // Неизвестный адрес — ошибка; имя занято — 409 с подсказкой.
        let err = exec(
            &c,
            false,
            resources(ResourceAction::SetType {
                resource: "nope@res.test".into(),
                resource_type: ResourceTypeArg::Room,
            }),
        )
        .await
        .expect_err("нет ресурса");
        assert!(err.contains("не найден"), "{err}");
        let err = exec(&c, false, create("room@res.test", ResourceTypeArg::Room))
            .await
            .expect_err("имя занято");
        assert!(
            err.contains("409") && err.contains("thepost admin resources list"),
            "{err}"
        );
    }

    /// ADM-48: брендинг — show/set/reset/logo против роутера tp-admin; `set` меняет только заданное,
    /// контраст ниже порога — 422 с пояснением; открытый маршрут — без входа.
    #[tokio::test]
    async fn branding_commands_against_admin_api() {
        let (_admin, url, _, _, _) = admin_api().await;
        let c = client(&url, "oidc");
        let branding = |action: BrandingAction| ApiAction::Branding {
            action: Box::new(action),
        };
        let json = |out: CliResult<String>| -> Value {
            serde_json::from_str(&out.expect("ответ")).expect("json")
        };

        // Без наборов — IT TASK; set меняет только заданное (флаги поверх текущего набора).
        let show = json(exec(&c, true, branding(BrandingAction::Show)).await);
        assert_eq!(show["own"], Value::Null);
        assert_eq!(show["effective"]["palette"]["light"]["sel"], "#E3107F");
        let set = exec(
            &c,
            false,
            branding(BrandingAction::Set {
                name: Some("Почта Ромашка".into()),
                primary: Some("#177CAA".into()),
                role: vec!["light.selI=#D7E2EA".into(), "cli.head=#2A8BC4".into()],
            }),
        )
        .await
        .expect("branding set");
        assert!(set.contains("Почта Ромашка"), "{set}");
        // Второй set без --primary сохраняет основной цвет и роли (набор не обнуляется).
        let show = json(
            exec(
                &c,
                true,
                branding(BrandingAction::Set {
                    name: Some("Ромашка".into()),
                    primary: None,
                    role: vec![],
                }),
            )
            .await,
        );
        assert_eq!(show["own"]["product_name"], "Ромашка");
        assert_eq!(show["own"]["primary"], "#177CAA");
        assert_eq!(show["own"]["light"]["selI"], "#D7E2EA");
        assert_eq!(show["own"]["cli"]["head"], "#2A8BC4");

        // Контраст ниже порога — 422 с пояснением по-русски.
        let err = exec(
            &c,
            false,
            branding(BrandingAction::Set {
                name: None,
                primary: None,
                role: vec!["light.sel=#F5E663".into()],
            }),
        )
        .await
        .expect_err("контраст");
        assert!(err.contains("422") && err.contains("светлая тема"), "{err}");

        // Знак из файла (PNG 12×6); logo reset убирает знак; несуществующий файл — понятная ошибка.
        let dir = tempfile::tempdir().expect("tempdir");
        let logo = dir.path().join("logo.png");
        std::fs::write(&logo, LOGO_PNG).expect("write");
        let set = exec(
            &c,
            false,
            branding(BrandingAction::Logo {
                action: LogoAction::Set { file: logo.clone() },
            }),
        )
        .await
        .expect("logo set");
        assert!(set.contains("PNG 12×6"), "{set}");
        let err = exec(
            &c,
            false,
            branding(BrandingAction::Logo {
                action: LogoAction::Set {
                    file: dir.path().join("нет.png"),
                },
            }),
        )
        .await
        .expect_err("нет файла");
        assert!(err.contains("нет.png"), "{err}");
        let show = json(
            exec(
                &c,
                true,
                branding(BrandingAction::Logo {
                    action: LogoAction::Reset,
                }),
            )
            .await,
        );
        assert_eq!(show["own"]["logo"], Value::Null);

        // Уровень организации: --org; без --org — уровень установки.
        let mut args = ApiArgs {
            org: Some(TenantId::DEFAULT.to_string()),
            ..ApiArgs::default()
        };
        let set = execute(
            &c,
            &args,
            branding(BrandingAction::Set {
                name: Some("Ромашка-Орг".into()),
                primary: None,
                role: vec![],
            }),
        )
        .await
        .expect("org set");
        assert!(set.contains("Ромашка-Орг"), "{set}");
        args.org = None;
        let show = json(exec(&c, true, branding(BrandingAction::Show)).await);
        assert_eq!(
            show["effective"]["product_name"], "Ромашка",
            "без --org — уровень установки"
        );

        // Открытый маршрут — без входа: домен имени входа даёт организацию (её набор поверх установки),
        // без домена — брендинг установки.
        exec(
            &c,
            false,
            domain_action(DomainAction::Create {
                name: "res.test".into(),
                relay: None,
            }),
        )
        .await
        .expect("domain");
        let anon = Client::anonymous(url, &Options::default()).expect("client");
        let public = anon
            .public_branding(Some("res.test"))
            .await
            .expect("public");
        assert_eq!(public.product_name.as_deref(), Some("Ромашка-Орг"));
        assert!(public.logo.is_none());
        let public = anon.public_branding(None).await.expect("public");
        assert_eq!(public.product_name.as_deref(), Some("Ромашка"));
    }

    /// ADM-49: политика доверия в CLI — show/set/reset уровней, партнёры, действующая для учётной записи;
    /// клетки выше потолка — 422 с подсказкой; изменения — в журнале аудита.
    #[tokio::test]
    async fn trust_commands_against_admin_api() {
        let (_admin, url, _, _, _) = admin_api().await;
        let c = client(&url, "oidc");
        let trust = |action: TrustAction| ApiAction::Trust {
            action: Box::new(action),
        };
        let json = |out: CliResult<String>| -> Value {
            serde_json::from_str(&out.expect("ответ")).expect("json")
        };
        // Уровень организации: --org явный (как у брендинга, без него — уровень установки).
        let org = |as_json: bool, action: TrustAction| {
            let c = c.clone();
            async move {
                let args = ApiArgs {
                    org: Some(TenantId::DEFAULT.to_string()),
                    json: as_json,
                    ..ApiArgs::default()
                };
                execute(&c, &args, trust(action)).await
            }
        };

        // Уровень установки: show — умолчания и закреплённые клетки.
        let show = json(
            exec(
                &c,
                true,
                trust(TrustAction::Show {
                    group: None,
                    account: None,
                }),
            )
            .await,
        );
        assert_eq!(show["own"], Value::Null);
        assert_eq!(
            show["effective"]["matrix"]["invite_new"]["partner"],
            "button"
        );
        assert_eq!(show["fixed"]["freebusy"]["neighbor"], true);
        let shown = exec(
            &c,
            false,
            trust(TrustAction::Show {
                group: None,
                account: None,
            }),
        )
        .await
        .expect("trust show");
        for part in ["ФУНКЦИЯ", "Новое приглашение", "закреплено"]
        {
            assert!(shown.contains(part), "{part}: {shown}");
        }

        // Организация: set из файла — различие было/стало (клетка и партнёры).
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("trust.json");
        std::fs::write(
            &file,
            "{\"invite_new\": {\"partner\": \"auto\"}, \"partners\": [\"partner.example\"]}",
        )
        .expect("write");
        let set = org(false, TrustAction::Set { group: None, file })
            .await
            .expect("trust set");
        assert!(
            set.contains("+ invite_new") && set.contains("+ partners") && set.contains("Сохранено"),
            "{set}"
        );
        let show = json(
            org(
                true,
                TrustAction::Show {
                    group: None,
                    account: None,
                },
            )
            .await,
        );
        assert_eq!(show["own"]["invite_new"]["partner"], "auto");
        assert_eq!(show["own"]["partners"], json!(["partner.example"]));
        assert_eq!(show["effective"]["matrix"]["invite_new"]["partner"], "auto");
        let shown = org(
            false,
            TrustAction::Show {
                group: None,
                account: None,
            },
        )
        .await
        .expect("trust show org");
        assert!(
            shown.contains("Домены-партнёры: partner.example"),
            "{shown}"
        );

        // Выше потолка контракта — 422 с подсказкой.
        let wide = dir.path().join("wide.json");
        std::fs::write(&wide, "{\"invite_new\": {\"external\": \"auto\"}}").expect("write");
        let err = org(
            false,
            TrustAction::Set {
                group: None,
                file: wide,
            },
        )
        .await
        .expect_err("выше потолка");
        assert!(err.contains("422") && err.contains("потолка"), "{err}");

        // Партнёры: список и замена; неканоническая запись — 422. Замена — до снижения потолка
        // установки: она переотправляет сохранённую политику целиком, и клетка «авто» организации
        // выше сниженного потолка дала бы законные 422.
        let listed = org(
            false,
            TrustAction::Partners {
                action: PartnersAction::List,
            },
        )
        .await
        .expect("partners list");
        assert!(listed.contains("partner.example"), "{listed}");
        let err = org(
            false,
            TrustAction::Partners {
                action: PartnersAction::Set {
                    domains: vec!["P.EXAMPLE".into()],
                },
            },
        )
        .await
        .expect_err("неканонический");
        assert!(err.contains("422"), "{err}");
        org(
            false,
            TrustAction::Partners {
                action: PartnersAction::Set {
                    domains: vec!["p.example".into()],
                },
            },
        )
        .await
        .expect("partners set");
        let listed = json(
            org(
                true,
                TrustAction::Partners {
                    action: PartnersAction::List,
                },
            )
            .await,
        );
        assert_eq!(listed, json!(["p.example"]));

        // Снижение потолка установки: организация шире — «выше потолка» в show организации.
        let cap = dir.path().join("cap.json");
        std::fs::write(&cap, "{\"invite_new\": {\"partner\": \"button\"}}").expect("write");
        exec(
            &c,
            false,
            trust(TrustAction::Set {
                group: None,
                file: cap,
            }),
        )
        .await
        .expect("installation cap");
        let show = json(
            org(
                true,
                TrustAction::Show {
                    group: None,
                    account: None,
                },
            )
            .await,
        );
        assert_eq!(
            show["effective"]["over_ceiling"][0]["peer"], "partner",
            "{show}"
        );

        // Действующая для учётной записи (по имени входа): своей политики нет.
        exec(
            &c,
            false,
            domain_action(DomainAction::Create {
                name: "trust.test".into(),
                relay: None,
            }),
        )
        .await
        .expect("domain");
        let account = account_action(AccountAction::Create {
            login: "user@trust.test".into(),
            name: None,
        });
        exec(&c, false, account).await.expect("account");
        let show = json(
            org(
                true,
                TrustAction::Show {
                    group: None,
                    account: Some("user@trust.test".into()),
                },
            )
            .await,
        );
        assert_eq!(show["own"], Value::Null);
        assert_eq!(
            show["effective"]["matrix"]["invite_new"]["partner"], "button",
            "клетка организации обрезана потолком установки"
        );

        // Сброс организации — умолчания; повтор — не ошибка. Аудит: изменения с маршрутом доверия.
        for _ in 0..2 {
            org(false, TrustAction::Reset { group: None })
                .await
                .expect("trust reset");
        }
        let show = json(
            org(
                true,
                TrustAction::Show {
                    group: None,
                    account: None,
                },
            )
            .await,
        );
        assert_eq!(show["own"], Value::Null);
        // Аудит: изменения с маршрутом доверия; страница списков в тесте — 2 записи, идём по `next`.
        let mut trust_ops: Vec<String> = Vec::new();
        let mut trust_entries: Vec<Value> = Vec::new();
        let mut after = None;
        for _ in 0..10 {
            let audit = ApiAction::Audit {
                action: Box::new(AuditAction::Search {
                    since: None,
                    until: None,
                    actor: None,
                    method: None,
                    route: Some("/api/v1".into()),
                    limit: None,
                    after,
                }),
            };
            let page = json(exec(&c, true, audit).await);
            for e in page["entries"].as_array().expect("entries") {
                if e["route"].as_str().is_some_and(|r| r.contains("/trust")) {
                    trust_ops.push(e["route"].as_str().expect("route").to_owned());
                    trust_entries.push(e.clone());
                }
            }
            after = page["next"].as_u64();
            if after.is_none() {
                break;
            }
        }
        assert!(
            trust_ops.len() >= 4,
            "изменения политики — в журнале аудита: {trust_ops:?}"
        );
        // Решение владельца 19.11 (issue #108): журнал аудита несёт пару «старое → новое».
        let first = trust_entries
            .iter()
            .find(|e| e["method"] == "PUT" && e["status"] == 200)
            .expect("первое изменение");
        assert_eq!(first["details"]["what"], "trust");
        assert_eq!(first["details"]["to"]["invite_new"]["partner"], "auto");
        let resets: Vec<&Value> = trust_entries
            .iter()
            .filter(|e| e["method"] == "DELETE")
            .collect();
        assert_eq!(
            resets.len(),
            2,
            "сброс организации — дважды: {trust_entries:?}"
        );
        assert_eq!(resets[0]["details"]["what"], "trust");
        assert_eq!(resets[0]["details"]["to"], Value::Null);
        assert_eq!(
            resets[0]["details"]["from"]["partners"],
            json!(["p.example"])
        );
        // Повторный сброс — прежней политики уже нет.
        assert_eq!(resets[1]["details"]["from"], Value::Null);
        assert_eq!(resets[1]["details"]["to"], Value::Null);
    }

    /// PNG 12×6 (сплошной #177CAA) для знака в тестах.
    const LOGO_PNG: &[u8] = &[
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 12, 0, 0, 0, 6, 8,
        6, 0, 0, 0, 247, 238, 127, 129, 0, 0, 0, 19, 73, 68, 65, 84, 120, 218, 99, 16, 175, 89,
        245, 159, 20, 204, 48, 18, 53, 0, 0, 254, 195, 160, 225, 13, 63, 71, 128, 0, 0, 0, 0, 73,
        69, 78, 68, 174, 66, 96, 130,
    ];
}
