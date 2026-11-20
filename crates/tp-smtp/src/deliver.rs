//! Локальная доставка (SRS 4.1, CONTRACTS.md#MailStore): разрешение получателей (учётные записи, псевдонимы и
//! группы каталога), заголовки `Return-Path` и `Received`, [`MailStore::ingest`] одним вызовом на письмо.
//!
//! [`Delivery`] — обработчик сессий ([`Handler`]) обеих ролей:
//! - локальный домен — только принятый домен организации узла ([`Delivery::with_transport`], `ClusterTransport`,
//!   решение 96); получатель в нём — учётные записи, на которые он разрешается; неизвестный — `550 5.1.1`;
//!   переполненный ящик — `452 4.2.2` или `552 5.2.2` (`delivery.quota_reject`) до `DATA`;
//! - группа рассылки ([`Delivery::with_groups`], [`crate::groups`]): отправитель вне круга — `550 5.7.1` на `RCPT`,
//!   письмо модерируемой группы — в очередь модерации, иначе группа раскрывается: учётные записи — в ящики,
//!   почтовые контакты — внешним адресатам; динамическая группа — по фильтру на момент доставки (SMTP-26);
//! - внешний получатель: smtp-in — `550 5.7.1` (не открытый релей), submission — в очередь исходящей почты
//!   ([`Outbound`], [`crate::queue::Queue`]); узел без очереди (`Deps::outbound` = `None`) — `451 4.3.2`;
//! - submission после входа — только адреса отправителя вошедшего пользователя (SMTP-45, аналог
//!   `reject_sender_login_mismatch`): `MAIL FROM` — свой адрес, псевдоним или право Send As, иначе `553 5.7.1`;
//!   `From` — ещё и Send on Behalf (без `Sender` узел добавляет его), `Sender` — как `MAIL FROM`, иначе `550 5.7.1`
//!   на данных; права — `Authorizer::send_right` ([`Delivery::with_authz`], общий с JMAP). smtp-in не проверяется;
//! - submission: до доставки и очереди — `DecisionHooks::on_submission` (`Deny` — `550 5.7.1`; дополнения:
//!   заголовки в начало письма, копии в папки и внешним адресам);
//! - журнал доставки ([`Delivery::with_tracking`], [`crate::tracking`]): приём, отказы, доставка, модерация,
//!   уведомления, приём iTIP;
//! - адреса пересылки модулей (`Ingested::forward`, решение 2026-10-31-ingest-envelope; `CopyTo::Address`):
//!   локальные — сразу в ящики тем же `ingest` (SMTP-28), внешние — в очередь [`Outbound`] с отправителем SRS и
//!   ARC-подписью ([`Delivery::with_forwarding`], [`crate::forward`]); уведомление на адрес SRS — обратно
//!   исходному отправителю (подделанный или просроченный адрес — `550 5.1.1`);
//! - виды принятых доменов (SMTP-21): полномочный — неизвестный адрес `550 5.1.1`; внутренняя ретрансляция — неизвестный адрес принимается и ставится в очередь
//!   (smtp-out доставляет его на `next_hop` домена); домен другой организации — `451 4.3.0` (узел обслуживает
//!   одну организацию);
//! - доверенные источники ([`crate::sources`], SMTP-20): приложение — внешние получатели только при `external`,
//!   без проверок SPF/DKIM/DMARC; шлюз без данных об исходном клиенте — результаты проверок шлюза;
//! - фильтры Milter ([`crate::milter`]) двух направлений: приём — smtp-in; исходящая почта — submission и
//!   [`Delivery::submit`] (JMAP EmailSubmission, SMTP-27), до правил потока: отказ фильтра — отказ отправки,
//!   изменённые заголовки — дальше по ним;
//! - справочник аномалий ([`Delivery::with_risk`], [`crate::risk`], SMTP-52): после `DATA`, до Milter и
//!   Sieve — детекторы каталога признаков по письму и памяти бесед, балл по каталогу организации
//!   получателя и действия: `tag` — заголовок `X-ThePost-Risk`, `junk`/`quarantine` — «Спам» узла,
//!   `reject` — `550 5.7.1` в сессии (при расхождении организаций — карантин отказавшим); признак
//!   беседы снимает признак ответа, сработавшие — в журнал срабатываний каталога и метрики;
//! - правила потока почты ([`Delivery::with_mail_flow`], `MailFlow`, SMTP-22) — один раз на письмо: smtp-in после
//!   Milter, submission и [`Delivery::submit`] — до точек принятия решений и очереди; `Reject` — `550 5.7.1`,
//!   `Drop` — `250` без доставки, изменённые конверт и тело — дальше по ним, `matched` — в журнал доставки;
//!   `Moderate` (SMTP-30, CTR-43) — письмо в очередь модерации, отправителю — `250` (`SubmitStatus::Queued`
//!   вне сессии), модератору — уведомление ([`crate::deliver::moderation`]); без хранилища очереди — `451`;
//! - правила Sieve получателей ([`Delivery::with_rules`], [`crate::sieve`], SMTP-31, SMTP-32) — для каждого
//!   локального получателя (smtp-in, submission, [`Delivery::submit`]) после правил потока и до `ingest`: папки и
//!   флаги, отброс, перенаправление, автоответ; перенаправленное письмо и внутренний автоответ — через правила
//!   получателя с проверкой петли ([`Delivery::relay`], SMTP-34);
//! - конвейер обработки (SMTP-54, SRS 4.9; CTR-96): доставка выполняет этапы ядра в порядке реестра
//!   [`tp_contracts::pipeline`] ([`Delivery::pipeline`]) — проверки сессии (`MAIL`, `RCPT`), Milter (`DATA`),
//!   журналирование, Sieve ящика, итоговый контроль, доставка/очередь; модульные этапы — [`Delivery::with_stage`]
//!   (точки расширения SRS 2.5 до и после Sieve ящика, задел под SRS 4.10); итоговый контроль действий
//!   ([`Delivery::with_org_policy`]) после Sieve и модулей: запрет внешней пересылки организации
//!   (`forbid_external_forward`) перехватывает `redirect` из скрипта ящика — нарушение отказывает письму с
//!   причиной в журнале доставки; служебные письма (DSN, отбивки, MDN) этапы правил минуют (`SystemMessage`);
//! - журналирование переписки (SMTP-53, SRS 4.9; CTR-97): письмо, подошедшее под правило журналирования
//!   организации ([`Delivery::with_journal`]), копируется в отдельный бакет журнала целиком с конвертом —
//!   этапом ядра до Sieve ящика и этапов модулей: `discard`/`stop` скрипта получателя запись не отменяют,
//!   получатели записи — конверт на момент конвейера (скрытые Bcc и раскрытые из групп);
//! - матрица доверия (решение 124, SMTP-50, [`Delivery::with_trust`]): тип абонента (`PeerKind`) вычисляется для
//!   каждого письма — submission со входом и [`Delivery::submit`] — свой, smtp-in — по домену `From` и DMARC
//!   (партнёр — домен из [`TrustStore::partner_of`] с пройденным DMARC, RFC 9989; заголовкам
//!   `Authentication-Results` чужого шлюза и `remote-host` не доверяем — RFC 8601 §5, RFC 5183). Действующая
//!   матрица получателя — [`TrustStore::effective_for`], ошибка чтения — закрытая матрица и запись в журнал узла,
//!   письмо доставляется. По матрице: автоответ чужим (только внешний текст, письмо в группу — без ответа
//!   участников), MDN наружу, `group_post` групп рассылки, автопересылка (`redirect`, пересылки модулей) —
//!   домен из `auto_forward_domains`; DSN чужим — с общей диагностикой, отказ по политике — в сессии без
//!   уведомления потом; сбой скрипта организации — `451 4.3.0`;
//! - приглашения iTIP в письмах ([`Delivery::with_itip`], [`crate::itip`]): письмо с частью `text/calendar;
//!   method=…` после доставки в ящик передаётся `ItipDelivery` получателя с типом отправителя (решение 123):
//!   submission и [`Delivery::submit`] — внутреннее планирование (решение 78, SMTP-36), smtp-in — iMIP (SMTP-33);
//!   снаружи — только почта: что применять, решает матрица доверия приёма (`TrustMatrix::inbound`); письмо остаётся в ящике,
//!   итог приёма — событие `Itip` журнала доставки (SMTP-37), сбой — только запись в журнал узла.
//! - личные списки отправителей ящика ([`Delivery::with_sender_lists`], `SenderLists`, SMTP-25) — при каждой
//!   доставке в ящик (smtp-in, submission, [`Delivery::submit`], пересылки и перенаправления): письмо
//!   заблокированного отправителя — в «Спам», надёжного — во «Входящие» поверх карантина фильтра Milter; сверяется
//!   `From` письма, затем отправитель конверта. Письмо с проваленным DMARC остаётся в «Спаме» и от «надёжного»:
//!   его адрес мог быть подделан;
//! - спам — максимально рано мимо всех автоматических механизмов (SMTP-55, решение #112): письмо с вердиктом
//!   спама попадает в папку «Спам», и больше с ним ничего не происходит — правила получателя не выполняются
//!   (автоответ, перенаправление и приём iTIP гасились вердиктом и раньше — SMTP-50, DSN тоже), а ручная
//!   iTIP-обработка (accept/tentative/decline/counter) письма из «Спама» отклоняется сервером в точке приёма
//!   запроса клиента ([`Delivery::junk_itip_refusal`], [`Delivery::with_messages`]);
//! - решения модератора (`tp_contracts::groups::Moderation`, CTR-31, CTR-43; FIX-01, `moderation`): одобренное письмо
//!   очереди модерации — участникам группы или исходным получателям правила потока без повторной модерации, отказ —
//!   уведомление отправителю (RFC 3464) с причиной модератора.
//!
//! Отправка вне сессии SMTP (JMAP `EmailSubmission/set`) — [`Delivery::submit`] и `impl Outbound for Delivery`
//! (CMP-04, контракт `tp_contracts::queue::Outbound`, CTR-28): локальные получатели доставляются сразу тем же
//! `ingest`, внешние — в очередь (без очереди — `SubmitStatus::Failed` с `451 4.3.0`, SMTP-28); статус по получателю.
//! Вошедший пользователь (`Outbound::submit`, CTR-82) — субъект прав отправки приглашений (с группами) и
//! отправитель правил потока (`FlowInput::principal`).
//! Отложенная отправка и её отмена (`Outbound::schedule`, `cancel_scheduled`; SMTP-24) — `scheduled`.
//! Лимиты писем и адресатов в час учётной записи отправителя — общие с submission ([`Delivery::with_send_limits`],
//! [`crate::limits`], SMTP-43).
//!
//! Адресация ([`crate::address`]): получатели переписываются до разрешения, отправитель — после проверок, по
//! таблице организации из снимка настроек транспорта ([`Delivery::with_transport`], `TenantTransport::rewrites`);
//! подадрес `user+tag` доставляется в ящик `user` с `Delivered-To: user+tag@…`, неизвестный адрес домена — на
//! адрес для всей почты домена (псевдоним каталога `@domain`), если он задан.
//!
//! Каталог (псевдонимы, адреса учётных записей, группы) читается полным снимком и кэшируется на
//! `delivery.directory_refresh`; учётная запись — [`AccountStore::by_login`]. Проверки SPF, DKIM, DMARC и ARC
//! входящей почты — [`crate::authcheck`]: их заголовки добавляются к письму, письмо с проваленным DMARC
//! (`quarantine`, `reject`) доставляется в «Спам». Затем письмо проверяют фильтры Milter ([`crate::milter`]):
//! отказ фильтра — ответ на `DATA`, карантин — «Спам» (smtp-in) или отказ (submission).

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use bytes::Bytes;
use time::OffsetDateTime;
use tp_contracts::auth::{Authorizer, DirChange, DirCursor, Directory, Principal, SendRight};
use tp_contracts::blob::{BlobIndex, BlobStore};
use tp_contracts::ext::{CopyTo, Decision, DecisionHooks, SubmissionInfo};
use tp_contracts::groups::{DistributionGroup, MAX_RULE_NAME_LEN};
use tp_contracts::journal::JournalDirection;
use tp_contracts::mailstore::{Delivery as MailDelivery, IngestRequest, Ingested, MailStore};
use tp_contracts::meta::{
    Account, AccountScope, AccountStore, Mailbox, MailboxStore, MessageQuery, MessageStore, Policy,
    PolicyResolver, SpecialUse,
};
use tp_contracts::pipeline::{ActionSet, OrgPolicy, PipelinePoint, StageRegistry};
use tp_contracts::queue::{DsnRet, Outbound, SubmitStatus, Submitted};
use tp_contracts::reply::{ReplyEvidence, SentLog, age_since};
use tp_contracts::retention::Quota;
use tp_contracts::risk::RiskAction;
use tp_contracts::schedule::{ItipDelivery, ItipMessage, ItipMethod};
use tp_contracts::senders::{SenderLists, SenderVerdict};
use tp_contracts::sharing::DelegateStore;
use tp_contracts::sieve::{AutoReply, DeliveryRules, MailboxRef, RulesInput, RulesOutcome};
use tp_contracts::transport::{
    AcceptedDomain, BlobRef, DomainKind, EnvelopeSide, FlowDirection, FlowEnvelope, FlowInput,
    FlowOutcome, FlowVerdict, MailFlow,
};
use tp_contracts::trust::{
    CellValue, GroupPost, PeerContext, PeerKind, Toggle, TrustFunction, TrustLevel, TrustMatrix,
    TrustStore, effective,
};
use tp_contracts::{AccountId, Error, MailboxId, QueueId, Result, TenantId};

use crate::address::Addressing;
use crate::authcheck::AuthCheck;
use crate::config::MilterDirection;
use crate::config::{DeliveryConfig, QuotaReject, SmtpConfig};
use crate::dsn::{self, DsnSink};
use crate::forward::Forwarding;
use crate::groups::{Groups, Hold};
use crate::itip;
use crate::limits::{self, SendLimits};
use crate::metrics::{BatvOutcome, SmtpMetrics};
use crate::milter::{self, Milters, Verdict};
use crate::reply::{self, BatvAddress, ReplyMarks};
use crate::risk::{self, Risk};
use crate::routes::Routes;
use crate::server::{Envelope, Handler, Mode, Reply, is_positive, reply};
use crate::sieve::{self, Hop, Sieved, VacationRate};
use crate::sources;
use crate::srs::SrsError;
use crate::tracking::{self, Mail, Step, Tracking, Trail};
use tp_contracts::delivery::{DeliveryDecision as Dd, DeliveryEventKind as Ek, itip_record};

/// Зависимости доставки, выбранные приложением.
#[derive(Clone)]
pub struct Deps {
    /// Организация, которой принадлежат локальные домены узла (модуль «Мультитенантность» — позже).
    pub tenant: TenantId,
    /// Почтовое хранилище.
    pub store: Arc<dyn MailStore>,
    /// Учётные записи.
    pub accounts: Arc<dyn AccountStore>,
    /// Папки: «Входящие» и «Спам» получателя.
    pub mailboxes: Arc<dyn MailboxStore>,
    /// Каталог: псевдонимы, адреса учётных записей, группы. `None` — только имена входа.
    pub directory: Option<Arc<dyn Directory>>,
    /// Квоты: переполненный ящик отклоняется на `RCPT`.
    pub quota: Option<Arc<dyn Quota>>,
    /// Очередь исходящей почты; `None` — узел не отправляет наружу (submission: `451` внешним получателям).
    pub outbound: Option<Arc<dyn Outbound>>,
    /// Точки принятия решений модулей (`on_submission`; `on_delivery` вызывает хранилище).
    pub hooks: DecisionHooks,
    /// Проверки SPF, DKIM, DMARC, ARC входящей почты (smtp-in); `None` — без проверок.
    pub authcheck: Option<Arc<AuthCheck>>,
    /// Фильтры Milter; `None` — без фильтров.
    pub milter: Option<Arc<Milters>>,
}

impl fmt::Debug for Deps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Deps")
            .field("tenant", &self.tenant)
            .field("directory", &self.directory.is_some())
            .field("outbound", &self.outbound.is_some())
            .field("authcheck", &self.authcheck.is_some())
            .field("milter", &self.milter.is_some())
            .finish_non_exhaustive()
    }
}

/// Куда разрешился адрес получателя.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// Локальные учётные записи (адрес, псевдоним или группа).
    Local(Vec<Account>),
    /// Домен не локальный.
    External,
    /// Локальный домен, но адреса нет (или все учётные записи отключены).
    Unknown,
}

/// Снимок каталога: адрес → имена входа.
#[derive(Debug, Default)]
struct Snapshot {
    addresses: HashMap<String, BTreeSet<String>>,
    /// Адреса групп рассылки каталога (без записи в [`Groups`]): письмо по ним — письмо в группу (SMTP-50:
    /// участники не отвечают отправителю автоответом).
    mailing: HashSet<String>,
}

/// Наибольшая глубина вложенности групп каталога.
const MAX_GROUP_DEPTH: usize = 8;

/// Тип части письма iTIP (быстрая проверка до разбора, SMTP-55).
const TEXT_CALENDAR: &[u8] = b"text/calendar";

/// Предел просмотра папки «Спам» при проверке ручного iTIP-ответа (SMTP-55): приглашение старше последних
/// [`JUNK_SCAN`] писем не находится — ответ проходит; «Спам» обычно невелик и чистится пользователем.
const JUNK_SCAN: usize = 1000;

/// Получатель после переписывания и разрешения.
struct Target {
    /// Адрес после переписывания (`TenantTransport::rewrite`).
    address: String,
    resolved: Resolved,
    /// Подадрес (`user+tag`): полный адрес для заголовка `Delivered-To` копии.
    delivered_to: Option<String>,
    /// Адрес — группа рассылки [`Groups`] (ограничения отправителей, модерация).
    group: Option<DistributionGroup>,
    /// Адрес — группа рассылки (каталог или [`Groups`]): письмо пришло в группу, участники не отвечают
    /// отправителю автоответом (SMTP-50, Exchange `SendOofMessageToOriginatorEnabled`).
    mailing: bool,
    /// Адреса почтовых контактов в составе группы (SMTP-26): внешняя доставка.
    contacts: Vec<String>,
    /// Неизвестный адрес домена внутренней ретрансляции: в очередь (на `next_hop` домена).
    relay: bool,
    /// Принятый домен другой организации.
    foreign: bool,
}

/// Правила потока почты и хранилище объектов писем для них.
#[derive(Clone)]
struct FlowDeps {
    flow: Arc<dyn MailFlow>,
    blobs: Arc<dyn BlobStore>,
    index: Arc<dyn BlobIndex>,
}

/// Чьё письмо разрешается: отправителя (ограничения и модерация групп) или модуля (копии и пересылки точек
/// принятия решений — группы только раскрываются).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Отправитель: учётная запись организации или `None` — внешний.
    Sender(Option<AccountId>),
    /// Копия или пересылка модуля.
    Module,
}

/// Решение клетки `group_post` матрицы доверия для письма в группу (SMTP-50).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostAction {
    /// В очередь модерации (у группы есть модераторы).
    Hold,
    /// Отказ: группа закрыта для типа отправителя или модерировать некому.
    Deny,
    /// Как сейчас: ограничения и модерация самой группы.
    Pass,
}

/// Локальная доставка и обработчик транзакций SMTP.
pub struct Delivery {
    deps: Deps,
    hostname: String,
    cfg: DeliveryConfig,
    addressing: Addressing,
    /// Снимки настроек транспорта: таблица переписывания адресов организации.
    transport: Option<Arc<Routes>>,
    snapshot: Mutex<Option<(Instant, Arc<Snapshot>)>>,
    groups: Option<Groups>,
    tracking: Option<Tracking>,
    forwarding: Option<Arc<Forwarding>>,
    flow: Option<FlowDeps>,
    rules: Option<Arc<dyn DeliveryRules>>,
    itip: Option<Arc<dyn ItipDelivery>>,
    /// Политика доверия организации (решение 124, SMTP-50): действующая матрица получателей, домены-партнёры
    /// и домены автопересылки. Без неё — безопасные умолчания контракта ([`TrustMatrix::default`]).
    trust: Option<Arc<dyn TrustStore>>,
    /// Права отправки от чужого адреса (Send As, Send on Behalf) для приглашений из почтового клиента (SMTP-36).
    authz: Option<Arc<dyn Authorizer>>,
    /// Представители учётных записей (APP-69): право планирования от имени организатора у приглашений
    /// представителя (`SENT-BY`, SMTP-38).
    delegates: Option<Arc<dyn DelegateStore>>,
    senders: Option<Arc<dyn SenderLists>>,
    /// Политики организации (SMTP-40): профиль Milter, лимиты сеанса submission ([`Handler::policy`]).
    policies: Option<Arc<dyn PolicyResolver>>,
    /// Письма учётных записей ([`MessageStore`]): проверка ручного iTIP-ответа на письмо в «Спаме» (SMTP-55).
    /// Без хранилища проверка не выполняется.
    messages: Option<Arc<dyn MessageStore>>,
    vacation_rate: VacationRate,
    /// `delivery.redirect_hops`.
    redirect_hops: u32,
    /// `delivery.redirect_total`.
    redirect_total: u32,
    /// Лимиты отправки учётной записи в час для [`Delivery::submit`] (SMTP-43), общие с сеансами submission.
    send_limits: Option<Arc<SendLimits>>,
    /// `smtp.limits.max_tracked_accounts`.
    max_tracked: usize,
    /// Журналирование конвейера (SMTP-53): правила организации и хранилище записей; до подключения —
    /// этап не пишет ничего.
    journal: Option<journal::Journaling>,
    /// Конвейер обработки (SMTP-54, CTR-96): этапы ядра в порядке контракта и модульные этапы
    /// ([`Delivery::with_stage`]).
    pipeline: StageRegistry,
    /// Политика организации для итогового контроля действий (SMTP-54); по умолчанию выключена.
    org_policy: OrgPolicy,
    /// Метка ответа (SMTP-51): признак «ответ на наше письмо» по записи об отправленном, метки Message-ID.
    reply: Option<Arc<ReplyMarks>>,
    /// Запись об отправленном (SMTP-51, CTR-94): поиск исходного письма для признака ответа.
    sent: Option<Arc<dyn SentLog>>,
    /// Справочник аномалий на smtp-in (SMTP-52, решение 126): детекторы каталога, балл и действия.
    risk: Option<Arc<Risk>>,
    /// Метрики (SMTP-51: признак ответа и BATV).
    metrics: Option<Arc<SmtpMetrics>>,
    /// `smtp.reply.max_age`.
    reply_max_age: std::time::Duration,
}

impl fmt::Debug for Delivery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Delivery")
            .field("deps", &self.deps)
            .field("hostname", &self.hostname)
            .finish_non_exhaustive()
    }
}

/// Письмо отправки вне сессии SMTP после правил потока.
struct Flowed {
    mail_from: String,
    rcpts: Vec<String>,
    raw: Bytes,
}

/// Итог [`Delivery::pre_submit`].
enum Pre {
    /// Судьба письма решена: статус всем получателям.
    Done(SubmitStatus),
    /// Дальше — доставка и очередь.
    Go(Flowed),
}

/// Что известно о письме для выбора папки получателя: вердикт проверок и фильтров и отправитель — для личных
/// списков отправителей ящика (SMTP-25).
struct Filing {
    /// Письмо — спам: DMARC не пройден (`quarantine`, `reject`) или карантин фильтра Milter.
    junk: bool,
    /// Подлинность отправителя не подтверждена (DMARC не пройден): «надёжный» отправитель спам не отменяет —
    /// адрес мог быть подделан.
    forged: bool,
    /// Адреса отправителя для списков: `From` письма, затем отправитель конверта.
    senders: Vec<String>,
}

impl Filing {
    fn new(junk: bool, forged: bool, mail_from: &str, raw: &[u8]) -> Self {
        let mut senders = Vec::new();
        if let Some(from) = mail_parser::MessageParser::default()
            .parse_headers(raw)
            .as_ref()
            .and_then(|m| m.from()?.first()?.address())
        {
            senders.push(from.to_owned());
        }
        if !mail_from.is_empty() && !senders.iter().any(|s| s.eq_ignore_ascii_case(mail_from)) {
            senders.push(mail_from.to_owned());
        }
        Self {
            junk,
            forged,
            senders,
        }
    }
}

/// Контекст правил одного письма (SMTP-50, SMTP-51): тип абонента отправителя, признак «ответ на наше
/// письмо», ящики-«Спам» и участники групп рассылки (без автоответа) — общий для всех получателей письма.
struct RuleContext<'a> {
    peer: PeerKind,
    /// Признак «ответ на наше письмо» (SMTP-51): [`PeerContext::reply`] для клеток `ReplyOnly` матрицы
    /// (автоответ, MDN) и правил.
    reply: bool,
    junk: &'a HashSet<AccountId>,
    group: &'a HashSet<AccountId>,
}

impl<'a> RuleContext<'a> {
    fn new(
        peer: PeerKind,
        reply: bool,
        junk: &'a HashSet<AccountId>,
        group: &'a HashSet<AccountId>,
    ) -> Self {
        Self {
            peer,
            reply,
            junk,
            group,
        }
    }
}

/// Письмо, подготовленное к доставке.
struct Prepared {
    deliveries: Vec<(String, MailDelivery)>,
    /// Учётные записи, которым письмо доставляется как спам (папка «Спам»).
    junk: HashSet<AccountId>,
    /// Учётные записи, получившие письмо через группу рассылки: участники не отвечают отправителю автоответом
    /// (SMTP-50, RFC 3834; Exchange `SendOofMessageToOriginatorEnabled`).
    group: HashSet<AccountId>,
    /// Внешние адреса (после переписывания).
    external: Vec<String>,
    /// Адреса для очереди без пересылки: неизвестные адреса доменов внутренней ретрансляции, исходные
    /// отправители уведомлений на адреса SRS.
    relayed: Vec<String>,
    /// Внешние получатели в исходной записи (статусы отправки).
    queued: Vec<String>,
    /// Модерируемые группы: исходный адрес получателя и группа (по одной записи на группу).
    held: Vec<(String, DistributionGroup)>,
    /// Организации доставок (карантин каталога признаков — по организациям, SMTP-52).
    orgs: Vec<(AccountId, TenantId)>,
    /// Получатели, которым письмо не доставлено после приёма (уведомление отправителю).
    failed: Vec<dsn::Recipient>,
}

impl Delivery {
    /// Доставка с зависимостями `deps` и параметрами секции `smtp`.
    pub fn new(deps: Deps, cfg: &SmtpConfig) -> Self {
        Self {
            deps,
            hostname: cfg.hostname.clone(),
            cfg: cfg.delivery.clone(),
            addressing: Addressing::new(&cfg.addressing),
            transport: None,
            snapshot: Mutex::new(None),
            groups: None,
            tracking: None,
            forwarding: None,
            flow: None,
            rules: None,
            itip: None,
            trust: None,
            authz: None,
            delegates: None,
            senders: None,
            policies: None,
            messages: None,
            vacation_rate: VacationRate::new(cfg.delivery.vacation_rate),
            redirect_hops: cfg.delivery.redirect_hops,
            redirect_total: cfg.delivery.redirect_total,
            send_limits: None,
            max_tracked: cfg.limits.max_tracked_accounts,
            journal: None,
            pipeline: pipeline::core_registry(),
            org_policy: OrgPolicy::default(),
            reply: None,
            sent: None,
            risk: None,
            metrics: None,
            reply_max_age: cfg.reply.max_age,
        }
    }

    /// Метка ответа (SMTP-51): признак «ответ на наше письмо» — метка Message-ID расшифрована или хэш найден
    /// в записи об отправленном, отправитель `From` — среди адресатов, DMARC pass и возраст ≤
    /// `smtp.reply.max_age` ([`Delivery::with_sent_log`]); заголовок [`reply::REPLY_HEADER`] своего ставится
    /// до Milter, пришедший извне удаляется. Антивирус, URL и DMARC признак ничего не пропускает.
    pub fn with_reply_marks(mut self, reply: Arc<ReplyMarks>) -> Self {
        self.reply = Some(reply);
        self
    }

    /// Справочник аномалий на smtp-in (SMTP-52, решение 126; [`crate::risk`]): после `DATA`, до Milter
    /// и Sieve — детекторы каталога признаков по разобранному письму, балл по действующему каталогу
    /// организации получателя ([`tp_contracts::risk::RiskStore::effective`]) и действия каталога.
    /// Признак беседы снимает признак ответа SMTP-51
    /// ([`tp_contracts::risk::Detector::drops_reply`]); заголовок [`risk::RISK_HEADER`] входящего
    /// удаляется до проверок, свой ставится при действии `tag`; сработавшие — в журнал срабатываний
    /// ([`tp_contracts::risk::RiskStore::record_hits`]) и метрики. Без подключения проверок нет.
    pub fn with_risk(mut self, risk: Arc<Risk>) -> Self {
        self.risk = Some(risk);
        self
    }

    /// Запись об отправленном (SMTP-51, CTR-94): поиск исходного письма для признака ответа. Реализация —
    /// `tp-meta` (META-86), in-memory — `MemSentLog`; пишет очередь при постановке письма с адресатами.
    pub fn with_sent_log(mut self, sent: Arc<dyn SentLog>) -> Self {
        self.sent = Some(sent);
        self
    }

    /// Метрики сессий и очереди (SMTP-11, SMTP-51: признак ответа и BATV).
    pub fn with_metrics(mut self, metrics: Arc<SmtpMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Лимиты отправки в час (SMTP-43) для [`Delivery::submit`] и отложенной отправки (JMAP): писем —
    /// `Policy::send_per_hour`, адресатов — `Policy::rcpts_per_hour` учётной записи отправителя; те же счётчики, что
    /// у сеансов submission (`SessionCtx::send_limits`). Без них отправка вне сессии не ограничена.
    pub fn with_send_limits(mut self, limits: Arc<SendLimits>) -> Self {
        self.send_limits = Some(limits);
        self
    }

    /// Личные списки надёжных и заблокированных отправителей ящиков (SMTP-25): при доставке в ящик письмо
    /// заблокированного отправителя — в «Спам», надёжного — во «Входящие» поверх вердикта фильтров.
    pub fn with_sender_lists(mut self, senders: Arc<dyn SenderLists>) -> Self {
        self.senders = Some(senders);
        self
    }

    /// Письма учётных записей ([`MessageStore`]) для отказа ручной iTIP-обработки спам-письма (SMTP-55, решение
    /// #112): accept/tentative/decline/counter (REPLY или `COUNTER` письма клиента) в ответ на письмо в папке
    /// «Спам» отправителя отклоняется — встречу из спам-письма руками не принять; после переноса письма из
    /// «Спама» — работает. Реализация — `tp-meta` (`PgMeta`), in-memory — `MemMetadata`; роли папок —
    /// [`Deps::mailboxes`]. Без хранилища проверка не выполняется.
    pub fn with_messages(mut self, messages: Arc<dyn MessageStore>) -> Self {
        self.messages = Some(messages);
        self
    }

    /// Письмо — спам для ящика `scope`: вердикт письма с поправкой на списки отправителей ящика. Сверяется `From`
    /// письма, затем отправитель конверта — решает первое совпадение. «Надёжный» не отменяет спам письма с
    /// неподтверждённым отправителем ([`Filing::forged`]).
    async fn junk_for(&self, scope: AccountScope, filing: &Filing) -> Result<bool> {
        let Some(lists) = self.senders.as_ref().filter(|_| !filing.senders.is_empty()) else {
            return Ok(filing.junk);
        };
        let list = lists.sender_list(scope).await?;
        Ok(match filing.senders.iter().find_map(|a| list.verdict(a)) {
            Some(SenderVerdict::Blocked) => true,
            Some(SenderVerdict::Safe) if !filing.forged => false,
            Some(SenderVerdict::Safe) | None => filing.junk,
        })
    }

    /// Правила Sieve получателей ([`crate::sieve`], SMTP-31): для каждого локального получателя после правил потока
    /// и до `ingest` — папки и флаги доставки, отброс, перенаправление и автоответ (SMTP-32, не чаще
    /// `delivery.vacation_rate` в час на учётную запись).
    pub fn with_rules(mut self, rules: Arc<dyn DeliveryRules>) -> Self {
        self.rules = Some(rules);
        self
    }

    /// Приглашения iTIP в письмах: письмо с частью `text/calendar; method=…` после доставки в ящик передаётся `itip`
    /// для каждой учётной записи получателя, если `From` письма совпадает с `ORGANIZER` (сообщения организатора) или
    /// `ATTENDEE` (ответы участника) и ему можно доверять:
    /// - submission и [`Delivery::submit`] (решение 78, SMTP-36) — `From` принадлежит учётной записи отправителя
    ///   (вошедшей в сеанс submission или вошедшему пользователю [`Delivery::submit`] — CTR-82, с группами;
    ///   без сеанса — отправителю конверта): её адрес, псевдоним
    ///   (`Account::addresses`) или право Send As / Send on Behalf ([`Delivery::with_authz`]);
    /// - smtp-in (iMIP, RFC 6047, SMTP-33; в том числе через шлюз Edge) — письмо прошло DMARC.
    ///
    /// Иначе — только письмо. С сообщением передаётся тип отправителя (`PeerKind`, решение 124, SMTP-49): своя
    /// организация — вошедший (внутренний путь); письмо через smtp-in — по домену `From`: адрес своего домена —
    /// внешний, домен-партнёр ([`Delivery::with_partners`]), другая организация установки (MSSP), внешний. Что
    /// применять, бронировать и на что отвечать, решает приём iTIP по матрице доверия
    /// `tp_contracts::trust::TrustMatrix::inbound` (снаружи — только почта; ответы и отмены к существующим
    /// событиям — как у Exchange и Google).
    ///
    /// Представитель (SMTP-38, APP-69): `From` совпал с `SENT-BY` организатора или участника — сообщение передаётся
    /// от имени владельца (`ItipMessage::from`), если отправитель может планировать от его имени: у организатора
    /// есть запись представителя отправителя с `schedule_on_behalf` ([`Delivery::with_delegates`]; у письма из
    /// клиента `From` к тому же принадлежит учётной записи отправителя, [`Delivery::sender_right`]). Право отправки
    /// почты (Send As, Send on Behalf) приглашение представителя не признаёт; без хранилища представителей — только
    /// письмо.
    ///
    /// Письмо в любом случае остаётся в ящике. Итог `itip` (применено или пропущено с причиной) — событие `Itip`
    /// журнала доставки на получателя (SMTP-37, `delivery::itip_record`), сбой — только запись в журнал узла.
    pub fn with_itip(mut self, itip: Arc<dyn ItipDelivery>) -> Self {
        self.itip = Some(itip);
        self
    }

    /// Политика доверия организации (решение 124, SMTP-50): действующая матрица получателей
    /// ([`TrustStore::effective_for`]), домены-партнёры (`TrustStore::partner_of`) и домены автопересылки.
    /// Реализация — `tp-meta` (META-85), in-memory — `tp-testkit::MemTrust`; без хранилища действуют безопасные
    /// умолчания контракта ([`TrustMatrix::default`]): группы закрыты чужим, MDN и автопересылка наружу выключены.
    pub fn with_trust(mut self, trust: Arc<dyn TrustStore>) -> Self {
        self.trust = Some(trust);
        self
    }

    /// Права отправки от чужого адреса (`Authorizer::send_right`): адреса отправителя сеанса submission (SMTP-45) и
    /// приглашения из почтового клиента ([`Delivery::with_itip`], SMTP-36). Без них submission принимает и
    /// внутренним приглашением считает только свой адрес или псевдоним.
    pub fn with_authz(mut self, authz: Arc<dyn Authorizer>) -> Self {
        self.authz = Some(authz);
        self
    }

    /// Представители учётных записей ([`DelegateStore`], APP-69): право отправителя приглашения (`SENT-BY`,
    /// SMTP-38) планировать от имени организатора — по записи представителя с `schedule_on_behalf`, а не по правам
    /// отправки почты. Без хранилища представителей нет — приглашение представителя остаётся письмом.
    pub fn with_delegates(mut self, delegates: Arc<dyn DelegateStore>) -> Self {
        self.delegates = Some(delegates);
        self
    }

    /// Передаёт сообщение iTIP письма `raw` учётным записям `targets` (получатель конверта и учётная запись), кроме
    /// получателей из `failed`; доверие к `From` — по `origin`. Возвращает события `Itip` журнала доставки — итог
    /// [`ItipDelivery::deliver`] для каждого получателя (SMTP-37).
    async fn apply_itip(
        &self,
        id: &str,
        raw: &[u8],
        origin: ItipOrigin<'_>,
        targets: &[(String, AccountId)],
        failed: &[dsn::Recipient],
    ) -> Vec<Step> {
        let mut steps = Vec::new();
        let Some(delivery) = &self.itip else {
            return steps;
        };
        let msg = match itip::extract(raw) {
            None => return steps,
            Some(Err(reason)) => {
                tracing::info!(%id, reason, "smtp: сообщение iTIP не применено");
                return steps;
            }
            Some(Ok(m)) => m,
        };
        let internal = match origin {
            ItipOrigin::Imip { dmarc_pass: false } => {
                tracing::info!(%id, reason = "отправитель не прошёл DMARC", "smtp: сообщение iTIP не применено");
                return steps;
            }
            // Представитель (SENT-BY): подлинность `From` подтверждает DMARC, право планировать от имени
            // организатора — его запись представителя с `schedule_on_behalf` (APP-69). Организатор или отправитель —
            // не учётная запись организации (группа, внешний адрес): записи быть не может.
            ItipOrigin::Imip { dmarc_pass: true } if msg.sent_by.is_some() => {
                match self
                    .schedules_on_behalf(&msg.from, msg.sent_by.as_deref().unwrap_or_default())
                    .await
                {
                    Ok(true) => false,
                    Ok(false) => {
                        tracing::info!(%id, reason = "представитель (SENT-BY) без права планирования от имени", "smtp: сообщение iTIP не применено");
                        return steps;
                    }
                    Err(e) => {
                        tracing::warn!(%id, error = %e, "smtp: сбой проверки представителя приглашения");
                        return steps;
                    }
                }
            }
            ItipOrigin::Imip { dmarc_pass: true } => false,
            ItipOrigin::Internal { account, principal } => {
                // `From` письма (`SENT-BY` у представителя) — адрес отправителя: свой, псевдоним или право Send As
                // (SMTP-36). Право планировать от имени организатора (`SENT-BY`, SMTP-38) — по записи представителя
                // организатора с `schedule_on_behalf` (APP-69): право отправки почты его не заменяет.
                let from = msg.sent_by.as_deref().unwrap_or(&msg.from);
                match self.sender_right(account, principal, from).await {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        tracing::info!(%id, %account, "smtp: From приглашения не принадлежит отправителю, осталось письмом");
                        return steps;
                    }
                    Err(e) => {
                        tracing::warn!(%id, %account, error = %e, "smtp: сбой проверки отправителя приглашения");
                        return steps;
                    }
                }
                if msg.sent_by.is_some() {
                    match self.schedules_on_behalf(&msg.from, from).await {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::info!(%id, %account, "smtp: отправитель — не представитель организатора с правом планирования, осталось письмом");
                            return steps;
                        }
                        Err(e) => {
                            tracing::warn!(%id, %account, error = %e, "smtp: сбой проверки представителя приглашения");
                            return steps;
                        }
                    }
                }
                true
            }
        };
        // Кто отправитель: вошедший — своя организация, письмо через smtp-in — по домену `From` (партнёр — с
        // пройденным DMARC); что ему можно, решает приём iTIP по матрице доверия (решение 124,
        // `TrustMatrix::inbound`).
        let dmarc_pass = match origin {
            ItipOrigin::Imip { dmarc_pass } => dmarc_pass,
            ItipOrigin::Internal { .. } => true,
        };
        let sender = match self.sender_kind(&msg.from, internal, dmarc_pass).await {
            Ok(kind) => kind,
            Err(e) => {
                tracing::warn!(%id, error = %e, "smtp: сбой проверки домена отправителя приглашения");
                return steps;
            }
        };
        let mut seen = HashSet::new();
        for (rcpt, account) in targets {
            if failed.iter().any(|f| f.address.eq_ignore_ascii_case(rcpt)) || !seen.insert(*account)
            {
                continue;
            }
            let to = self
                .addressing
                .split(rcpt)
                .map_or_else(|| rcpt.clone(), |(base, _)| base)
                .to_lowercase();
            let message = ItipMessage {
                recipient: AccountScope {
                    tenant: self.deps.tenant,
                    account: *account,
                },
                to,
                from: msg.from.clone(),
                method: msg.method,
                ics: msg.ics.clone(),
                sender,
                // Итог `processcalendar` правил — передаёт SMTP-50 (решение по issue #89, вариант 1).
                calendar: None,
            };
            match delivery.deliver(&message).await {
                Ok(outcome) => {
                    let (decision, reason) = itip_record(msg.method, &outcome);
                    steps.push(Step::new(Ek::Itip, decision, vec![rcpt.clone()]).reason(reason));
                }
                Err(e) => {
                    tracing::warn!(%id, %account, error = %e, "smtp: сбой приёма iTIP");
                }
            }
        }
        steps
    }

    /// Организация адреса `address`: принятый домен кластера, совпавший с доменом адреса или ближайшим из
    /// родительских (поддомен принадлежит организации домена); `None` — домен вне установки.
    async fn org_of(&self, address: &str) -> Result<Option<TenantId>> {
        let Some((_, domain)) = address.rsplit_once('@') else {
            return Ok(None);
        };
        let domain = domain.to_lowercase();
        let mut name = domain.as_str();
        loop {
            if let Some(d) = self.accepted(name).await? {
                return Ok(Some(d.tenant));
            }
            match name.split_once('.') {
                Some((_, parent)) if parent.contains('.') => name = parent,
                _ => return Ok(None),
            }
        }
    }

    /// Тип отправителя `from` относительно организации узла (решение 123 → 124, SMTP-49/50). Своя организация
    /// ([`PeerKind::Own`]) — по входу, а не по домену: внутренний путь (`internal` — submission со входом,
    /// [`Delivery::submit`]), `From` которого принадлежит вошедшей учётной записи. Письмо через smtp-in — по
    /// домену `From` (ближайший принятый домен — сам или родитель): домен своей организации —
    /// [`PeerKind::External`] (DMARC проходит и сторонний сервис, разрешённый в SPF или DKIM домена),
    /// домен-партнёр ([`TrustStore::partner_of`]) — [`PeerKind::Partner`] только с пройденным DMARC
    /// (выравнивание адреса `From`, RFC 9989), принятый домен другой организации установки —
    /// [`PeerKind::Neighbor`], иначе — [`PeerKind::External`]. Заголовкам `Authentication-Results` не от своего
    /// шлюза и `remote-host` не доверяем — тип вычисляет ядро по своим проверкам (RFC 8601 §5, RFC 5183).
    async fn sender_kind(&self, from: &str, internal: bool, dmarc_pass: bool) -> Result<PeerKind> {
        if internal {
            return Ok(PeerKind::Own);
        }
        let org = self.org_of(from).await?;
        if org == Some(self.deps.tenant) {
            return Ok(PeerKind::External);
        }
        let domain = from.rsplit_once('@').map(|(_, d)| d.to_lowercase());
        let partner = match (&self.trust, domain.as_deref()) {
            (Some(trust), Some(d)) => trust.partner_of(self.deps.tenant, d).await?,
            _ => false,
        };
        Ok(match () {
            _ if partner && dmarc_pass => PeerKind::Partner,
            _ if org.is_some() => PeerKind::Neighbor,
            _ => PeerKind::External,
        })
    }

    /// Тип абонента адреса исходящего получателя (SMTP-50): домен принятого домена организации — [`PeerKind::Own`],
    /// домен-партнёр — [`PeerKind::Partner`], принятый домен другой организации установки —
    /// [`PeerKind::Neighbor`], иначе — [`PeerKind::External`]. DMARC не проверяется: это домен адресата, а не
    /// отправитель письма.
    async fn rcpt_kind(&self, address: &str) -> Result<PeerKind> {
        let org = self.org_of(address).await?;
        if org == Some(self.deps.tenant) {
            return Ok(PeerKind::Own);
        }
        let domain = address.rsplit_once('@').map(|(_, d)| d.to_lowercase());
        let partner = match (&self.trust, domain.as_deref()) {
            (Some(trust), Some(d)) => trust.partner_of(self.deps.tenant, d).await?,
            _ => false,
        };
        Ok(if partner {
            PeerKind::Partner
        } else if org.is_some() {
            PeerKind::Neighbor
        } else {
            PeerKind::External
        })
    }

    /// Тип абонента отправителя на `RCPT` (до `DATA` письма ещё нет): submission и приложение организации — свой,
    /// smtp-in — по домену конверта. Партнёр здесь без подтверждения DMARC — предположительно (обычно конверт
    /// выровнен с `From`); `DATA` перепроверит по `From` и DMARC и может только сузить тип.
    async fn rcpt_peer(&self, env: &Envelope) -> Result<PeerKind> {
        if env.mode == Mode::Submission || sender_account(env, self.deps.tenant).is_some() {
            return Ok(PeerKind::Own);
        }
        if let Some((s, _)) = sources::application(env.source.as_deref())
            && s.tenant == Some(self.deps.tenant)
        {
            return Ok(PeerKind::Own);
        }
        let from = if env.mail_from.is_empty() {
            env.helo.as_str()
        } else {
            env.mail_from.as_str()
        };
        let org = self.org_of(from).await?;
        if org == Some(self.deps.tenant) {
            return Ok(PeerKind::External);
        }
        let domain = from.rsplit_once('@').map(|(_, d)| d.to_lowercase());
        let partner = match (&self.trust, domain.as_deref()) {
            (Some(trust), Some(d)) => trust.partner_of(self.deps.tenant, d).await?,
            _ => false,
        };
        Ok(if partner {
            PeerKind::Partner
        } else if org.is_some() {
            PeerKind::Neighbor
        } else {
            PeerKind::External
        })
    }

    /// Действующая матрица доверия учётной записи (решение 124 б): [`TrustStore::effective_for`] — установка →
    /// организация → группы учётной записи, из нескольких групп — самое узкое. Ошибка чтения — закрытая матрица
    /// ([`TrustMatrix::closed`]) и запись в журнал узла, письмо доставляется как письмо. Без хранилища —
    /// умолчания контракта.
    async fn matrix_for(&self, scope: AccountScope) -> TrustMatrix {
        let Some(trust) = &self.trust else {
            return TrustMatrix::default();
        };
        match trust.effective_for(scope.tenant, scope.account).await {
            Ok(e) => e.matrix,
            Err(e) => {
                tracing::warn!(
                    tenant = %scope.tenant,
                    account = %scope.account,
                    error = %e,
                    "smtp: политика доверия не прочитана — закрытая матрица, письмо доставляется"
                );
                TrustMatrix::closed()
            }
        }
    }

    /// Матрица уровня организации (без групп учётной записи) и домены автопересылки организации
    /// ([`TrustPolicy::auto_forward_domains`]): точки решения без учётной записи — копии и пересылки модулей.
    async fn org_matrix(&self) -> Result<(TrustMatrix, Vec<String>)> {
        let Some(trust) = &self.trust else {
            return Ok((TrustMatrix::default(), Vec::new()));
        };
        let inst = trust.policy(TrustLevel::Installation).await?;
        let org = trust.policy(TrustLevel::Org(self.deps.tenant)).await?;
        let domains = org
            .as_ref()
            .map(|p| p.auto_forward_domains.clone())
            .unwrap_or_default();
        let matrix = effective(
            inst.as_ref(),
            org.as_ref().map(|p| (TrustLevel::Org(self.deps.tenant), p)),
            &[],
        )
        .matrix;
        Ok((matrix, domains))
    }

    /// Действующее значение [`GroupPost`] группы для отправителя типа `peer` (SMTP-50, решение 124 г): уровень
    /// группы — политика самой группы ([`TrustLevel::Group`]), иначе организации, иначе установки и умолчания.
    /// `group` = `None` — группа каталога без записи в [`Groups`]: уровня группы нет. Без хранилища — умолчания
    /// контракта: своим открыто, чужим закрыто.
    async fn group_post(
        &self,
        group: Option<&DistributionGroup>,
        peer: PeerKind,
    ) -> Result<GroupPost> {
        let Some(trust) = &self.trust else {
            return Ok(TrustMatrix::default().group_post.get(peer));
        };
        let inst = trust.policy(TrustLevel::Installation).await?;
        let org = trust.policy(TrustLevel::Org(self.deps.tenant)).await?;
        let group_policy = match group {
            Some(g) => {
                trust
                    .policy(TrustLevel::Group(self.deps.tenant, g.id))
                    .await?
            }
            None => None,
        };
        let groups = match (group, group_policy.as_ref()) {
            (Some(g), Some(p)) => vec![(TrustLevel::Group(self.deps.tenant, g.id), p)],
            _ => Vec::new(),
        };
        let matrix = effective(
            inst.as_ref(),
            org.as_ref().map(|p| (TrustLevel::Org(self.deps.tenant), p)),
            &groups,
        )
        .matrix;
        Ok(matrix.group_post.get(peer))
    }

    /// Решение клетки `group_post` для письма (SMTP-50): `Hold` — очередь модерации (у группы есть модераторы),
    /// `Deny` — отказ (группа закрыта, модерировать некому), `Pass` — как сейчас (модерация самой группы сужает
    /// и дальше).
    async fn post_action(
        &self,
        group: Option<&DistributionGroup>,
        peer: PeerKind,
    ) -> Result<PostAction> {
        Ok(match self.group_post(group, peer).await? {
            GroupPost::Closed => PostAction::Deny,
            GroupPost::Moderated if group.is_some_and(|g| g.moderated()) => PostAction::Hold,
            GroupPost::Moderated => PostAction::Deny,
            GroupPost::Open => PostAction::Pass,
        })
    }

    /// Можно ли переслать письмо на внешний адрес `to` правилом или модулем (SMTP-50, решение 124 г): адрес
    /// локальный — пересылка внутри; клетка `auto_forward` действующей матрицы для типа адреса включена или домен
    /// — из `auto_forward_domains` организации. Почтовые контакты в составе группы — не автопересылка:
    /// администратор задал их явно.
    async fn forward_to(&self, matrix: &TrustMatrix, domains: &[String], to: &str) -> Result<bool> {
        let kind = self.rcpt_kind(to).await?;
        if kind == PeerKind::Own {
            return Ok(true);
        }
        let domain = to.rsplit_once('@').map_or("", |(_, d)| d);
        Ok(matrix.auto_forward.get(kind) == Toggle::On
            || domains.iter().any(|d| d.eq_ignore_ascii_case(domain)))
    }

    /// Отчёты о прочтении (MDN, RFC 8098) из submission и [`Delivery::submit`] получателям, которым клетка `mdn`
    /// их матрицы запрещает MDN, не отправляются (SMTP-50): получатель убирается до доставки и очереди,
    /// отправителю — `250` (машинный отчёт его программы, а не ошибка); событие журнала доставки. Свои — матрица
    /// учётной записи, чужие — матрица организации.
    async fn mdn_rcpts(
        &self,
        id: &str,
        rcpts: &[String],
        org: &TrustMatrix,
    ) -> Result<(Vec<String>, Vec<Step>)> {
        let mut allowed = Vec::new();
        let mut steps = Vec::new();
        for rcpt in rcpts {
            let kind = self.rcpt_kind(rcpt).await?;
            let on = match kind {
                PeerKind::Own => match self.resolve(rcpt).await? {
                    Resolved::Local(accounts) if !accounts.is_empty() => {
                        self.matrix_for(AccountScope {
                            tenant: accounts[0].tenant,
                            account: accounts[0].id,
                        })
                        .await
                        .mdn
                        .own
                    }
                    _ => org.mdn.own,
                },
                _ => org.mdn.get(kind),
            };
            if on == Toggle::On {
                allowed.push(rcpt.clone());
            } else {
                tracing::info!(%id, %rcpt, %kind, "smtp: MDN не отправлен — политика доверия");
                steps.push(
                    Step::new(Ek::Deliver, Dd::Discard, vec![rcpt.clone()])
                        .reason("MDN не отправлен: политика"),
                );
            }
        }
        Ok((allowed, steps))
    }

    /// Право учётной записи `account` организации узла на адрес отправителя `from` (решение 78, SMTP-45): её адрес
    /// или псевдоним (`Account::addresses`) — [`SendRight::SendAs`], иначе право Send As / Send on Behalf из ACL
    /// узла (`Authorizer::send_right`, [`Delivery::with_authz`]; та же проверка, что у JMAP). `None` — адрес чужой.
    /// Субъект проверки прав — `principal` сеанса submission или вошедший пользователь [`Delivery::submit`]
    /// (CTR-82: с группами); без него (отправка без сеанса, выпуск отложенной отправки) — учётная запись
    /// отправителя конверта без групп.
    async fn sender_right(
        &self,
        account: AccountId,
        principal: Option<&Principal>,
        from: &str,
    ) -> Result<Option<SendRight>> {
        if principal.is_some_and(|p| p.account == account && p.login.eq_ignore_ascii_case(from)) {
            return Ok(Some(SendRight::SendAs));
        }
        let tenant = self.deps.tenant;
        let Some(acc) = self.deps.accounts.get(tenant, account).await? else {
            return Ok(None);
        };
        if acc.addresses().iter().any(|a| a.eq_ignore_ascii_case(from)) {
            return Ok(Some(SendRight::SendAs));
        }
        let Some(authz) = &self.authz else {
            return Ok(None);
        };
        let own;
        let principal = match principal {
            Some(p) => p,
            None => {
                own = Principal {
                    tenant,
                    account,
                    login: acc.login,
                    groups: BTreeSet::new(),
                    scopes: None,
                };
                &own
            }
        };
        authz.send_right(principal, from).await
    }

    /// Отправитель `sender` (адрес `From`, `SENT-BY`) может планировать от имени организатора `owner`
    /// (APP-69): оба — учётные записи организации узла (ровно по одной; группа и внешний адрес права не имеют),
    /// у организатора есть запись представителя отправителя с `schedule_on_behalf`
    /// ([`Delivery::with_delegates`]). Без хранилища представителей — нет.
    async fn schedules_on_behalf(&self, owner: &str, sender: &str) -> Result<bool> {
        let Some(delegates) = &self.delegates else {
            return Ok(false);
        };
        let owner = self.sender_by_address(owner).await?;
        let sender = self.sender_by_address(sender).await?;
        let (Some(owner), Some(sender)) = (owner, sender) else {
            return Ok(false);
        };
        Ok(delegates
            .delegates(AccountScope {
                tenant: self.deps.tenant,
                account: owner,
            })
            .await?
            .into_iter()
            .any(|d| d.delegate == sender && d.schedule_on_behalf))
    }

    /// Отказ ручной iTIP-обработки спам-письма (SMTP-55, решение #112; RFC 9671 §5 — календарные данные спама
    /// не обрабатываются): `Some(reply)` — письмо отклоняется, приглашение не вносится в календарь, клиент
    /// получает отказ. Ручной запрос клиента — письмо с `text/calendar; method=REPLY` (accept, tentative,
    /// decline) или `COUNTER`, отправленное вошедшим пользователем (submission, [`Delivery::submit`]):
    /// приглашение, на которое он отвечает (`In-Reply-To`/`References` → `Message-ID`, RFC 5322 §3.6.4), лежит в
    /// папке «Спам» его ящика. После переноса приглашения из «Спама» — обрабатывается. Вердикт входящего письма
    /// проверяется раньше — приём iTIP получателям из «Спама» не вызывается ([`itip_targets`]); без хранилища
    /// писем ([`Delivery::with_messages`]) или при его сбое проверка пропускается (сбой — не отказ).
    async fn junk_itip_refusal(
        &self,
        principal: Option<&Principal>,
        raw: &[u8],
    ) -> Result<Option<Reply>> {
        let Some(messages) = &self.messages else {
            return Ok(None);
        };
        let Some(p) = principal.filter(|p| p.tenant == self.deps.tenant) else {
            return Ok(None);
        };
        // Быстрая проверка до разбора: часть `text/calendar` в письме.
        if !raw
            .windows(TEXT_CALENDAR.len())
            .any(|w| w.eq_ignore_ascii_case(TEXT_CALENDAR))
        {
            return Ok(None);
        }
        // Ответ клиента на приглашение (не приглашение и не отмена — внутреннее планирование, решение 78).
        let Some(Ok(msg)) = itip::extract(raw) else {
            return Ok(None);
        };
        if !matches!(msg.method, ItipMethod::Reply | ItipMethod::Counter) {
            return Ok(None);
        }
        let referenced = referenced_ids(raw);
        if referenced.is_empty() {
            return Ok(None);
        }
        let scope = AccountScope {
            tenant: p.tenant,
            account: p.account,
        };
        let Ok(list) = self.deps.mailboxes.list(scope).await else {
            tracing::warn!(account = %p.account, "smtp: папки не прочитаны — проверка ручного iTIP пропущена");
            return Ok(None);
        };
        let Some(junk) = list
            .iter()
            .find(|m| m.role == Some(SpecialUse::Junk))
            .map(|m| m.id)
        else {
            return Ok(None);
        };
        let Ok(letters) = messages
            .list(scope, junk, MessageQuery::All, JUNK_SCAN)
            .await
        else {
            tracing::warn!(account = %p.account, "smtp: «Спам» не прочитан — проверка ручного iTIP пропущена");
            return Ok(None);
        };
        if !letters.iter().any(|m| {
            m.meta
                .envelope
                .message_id
                .as_deref()
                .is_some_and(|id| referenced.iter().any(|r| r == id))
        }) {
            return Ok(None);
        }
        tracing::info!(account = %p.account, method = %msg.method, "smtp: ручной iTIP-ответ на письмо в «Спаме» отклонён");
        Ok(Some(reply(
            550,
            [5, 7, 1],
            "Scheduling response refused: invitation is in the Junk folder",
        )))
    }

    /// Отправитель конверта сеанса submission (SMTP-45, аналог `reject_sender_login_mismatch`): пустой (`<>`), свой
    /// адрес, псевдоним или адрес с правом Send As ([`Delivery::sender_right`]); иначе — `553 5.7.1`. Send on Behalf
    /// конверт не меняет: письмо от имени владельца уходит с адресом представителя (как `forbiddenMailFrom` JMAP).
    /// smtp-in и приложение без входа (адреса — `sources`) не проверяются.
    async fn check_mail_from(&self, env: &Envelope) -> Result<Option<Reply>> {
        let Some(p) = submitter(env) else {
            return Ok(None);
        };
        if env.mail_from.is_empty() {
            return Ok(None);
        }
        let right = if p.tenant == self.deps.tenant {
            self.sender_right(p.account, Some(p), &env.mail_from)
                .await?
        } else {
            None
        };
        if right == Some(SendRight::SendAs) {
            return Ok(None);
        }
        tracing::info!(id = %env.id, account = %p.account, "smtp: отправитель конверта не принадлежит вошедшему пользователю");
        Ok(Some(reply(
            553,
            [5, 7, 1],
            "Sender address not owned by authenticated user",
        )))
    }

    /// Заголовки `From` и `Sender` письма сеанса submission (SMTP-45): каждый адрес `From` — свой, псевдоним или с
    /// правом Send As / Send on Behalf, адрес `Sender` — свой, псевдоним или с правом Send As ([`Delivery::sender_right`]);
    /// иначе — `550 5.7.1` (RFC 5321, 4.3.2: `553` на `DATA` не предусмотрен). `From` по праву Send on Behalf без
    /// `Sender` — `Ok(Some(адрес))`: заголовок `Sender` с именем входа добавляется к письму, как у JMAP. Нет `From` —
    /// нечего подделывать, письмо принимается.
    async fn check_headers(
        &self,
        env: &Envelope,
        raw: &[u8],
    ) -> Result<std::result::Result<Option<String>, Reply>> {
        let Some(p) = submitter(env) else {
            return Ok(Ok(None));
        };
        let refuse = |what: &str| -> Result<std::result::Result<Option<String>, Reply>> {
            tracing::info!(id = %env.id, account = %p.account, header = what, "smtp: заголовок отправителя не принадлежит вошедшему пользователю");
            Ok(Err(reply(
                550,
                [5, 7, 1],
                format!("{what} address not owned by authenticated user"),
            )))
        };
        if p.tenant != self.deps.tenant {
            return refuse("From");
        }
        let fields = sender_fields(raw);
        let mut on_behalf = false;
        for (name, addrs) in &fields {
            // Поле без адреса (группа без участников, неразборчивое значение) — не проверить, отказ.
            if addrs.is_empty() {
                return refuse(name);
            }
            for addr in addrs {
                match self.sender_right(p.account, Some(p), addr).await? {
                    Some(SendRight::SendAs) => {}
                    Some(SendRight::SendOnBehalf) if *name == "From" => on_behalf = true,
                    Some(SendRight::SendOnBehalf) | None => return refuse(name),
                }
            }
        }
        let has_sender = fields.iter().any(|(name, _)| *name == "Sender");
        Ok(Ok((on_behalf && !has_sender).then(|| p.login.clone())))
    }

    /// Пересылка наружу: SRS-переписывание отправителя и ARC-подпись ([`crate::forward`], SMTP-23); приём
    /// уведомлений на адреса SRS.
    pub fn with_forwarding(mut self, forwarding: Arc<Forwarding>) -> Self {
        self.forwarding = Some(forwarding);
        self
    }

    /// Правила потока почты (`Registry::mail_flow`, SMTP-22); тело письма передаётся модулю объектом `blobs`
    /// (одна ссылка `index` на время вызова).
    pub fn with_mail_flow(
        mut self,
        flow: Arc<dyn MailFlow>,
        blobs: Arc<dyn BlobStore>,
        index: Arc<dyn BlobIndex>,
    ) -> Self {
        self.flow = Some(FlowDeps { flow, blobs, index });
        self
    }

    /// Принятый домен кластера по имени (снимок настроек транспорта); без снимков — `None`.
    async fn accepted(&self, domain: &str) -> Result<Option<AcceptedDomain>> {
        match &self.transport {
            None => Ok(None),
            Some(routes) => Ok(routes.cluster().await?.domain(domain).cloned()),
        }
    }

    /// Домен — локальный: принятый домен организации узла.
    async fn local_domain(&self, domain: &str) -> Result<bool> {
        let domain = domain.to_lowercase();
        Ok(self
            .accepted(&domain)
            .await?
            .is_some_and(|d| d.tenant == self.deps.tenant))
    }

    /// Адрес SRS нашего домена: `Some(Ok)` — исходный адрес, `Some(Err)` — подделан или просрочен; `None` — не SRS.
    async fn srs_reverse(
        &self,
        address: &str,
    ) -> Result<Option<std::result::Result<String, SrsError>>> {
        let Some(fwd) = &self.forwarding else {
            return Ok(None);
        };
        let Some(domain) = fwd.srs_domain() else {
            return Ok(None);
        };
        let looks = address.rsplit_once('@').is_some_and(|(l, d)| {
            d.eq_ignore_ascii_case(domain)
                && l.len() > 5
                && l.get(..4).is_some_and(|t| {
                    t.eq_ignore_ascii_case("SRS0") || t.eq_ignore_ascii_case("SRS1")
                })
        });
        if !looks {
            return Ok(None);
        }
        let Some(srs) = fwd.srs().await? else {
            return Ok(None);
        };
        Ok(Some(srs.reverse(address, OffsetDateTime::now_utc())))
    }

    /// Журнал доставки (SMTP-17, [`crate::tracking`]): приём, отказы, доставка, модерация, уведомления.
    pub fn with_tracking(mut self, tracking: Tracking) -> Self {
        self.tracking = Some(tracking);
        self
    }

    /// Записывает события письма в журнал доставки (если подключён).
    async fn track(&self, sender: &str, message_id: Option<&str>, steps: Vec<Step>) {
        if let Some(t) = &self.tracking {
            let mail = Mail {
                tenant: self.deps.tenant,
                sender,
                message_id,
                queue_id: None,
                at: OffsetDateTime::now_utc(),
            };
            t.write(&mail, steps).await;
        }
    }

    /// Снимки настроек транспорта `routes`: принятые домены (`ClusterTransport`) — единственный источник
    /// локальных доменов, таблица переписывания адресов конверта организации (SMTP-29,
    /// `TenantTransport::rewrites`). Снимок перечитывается после сигнала `TransportChanged` — [`Routes::watch`]
    /// запускает владелец снимков (один на узел, общий со smtp-out). Без снимков локальных доменов нет и адреса
    /// не переписываются; снимок недоступен — временная ошибка.
    pub fn with_transport(mut self, routes: Arc<Routes>) -> Self {
        self.transport = Some(routes);
        self
    }

    /// Политики организации (SMTP-40, решение 97): профиль Milter письма (`Policy::milter_profile`; submission —
    /// цепочка учётной записи отправителя, smtp-in — уровень организации) и лимиты сеанса submission
    /// ([`Handler::policy`]: `max_recipients`, `send_per_hour`, `rcpts_per_hour`). Без политик — умолчания
    /// полей `Policy`.
    pub fn with_policies(mut self, policies: Arc<dyn PolicyResolver>) -> Self {
        self.policies = Some(policies);
        self
    }

    /// Политика учётной записи `account`: цепочка «организация → основной домен → учётная запись»; учётной
    /// записи нет — уровень организации.
    async fn account_policy(&self, tenant: TenantId, account: AccountId) -> Result<Policy> {
        let Some(policies) = &self.policies else {
            return Ok(Policy::default());
        };
        match self.deps.accounts.get(tenant, account).await? {
            Some(a) => {
                policies
                    .resolve(tenant, Some(a.domain), Some(a.id), None)
                    .await
            }
            None => policies.resolve(tenant, None, None, None).await,
        }
    }

    /// Политика письма транзакции `env`: субъект AUTH — его учётная запись, иначе — организация узла.
    async fn message_policy(&self, env: &Envelope) -> Result<Policy> {
        match (&env.principal, &self.policies) {
            (_, None) => Ok(Policy::default()),
            (Some(p), Some(_)) => self.account_policy(p.tenant, p.account).await,
            (None, Some(policies)) => policies.resolve(self.deps.tenant, None, None, None).await,
        }
    }

    /// Адрес конверта `address` организации `tenant` после переписывания для стороны `side`; `None` — правила нет.
    async fn rewrite(
        &self,
        tenant: TenantId,
        address: &str,
        side: EnvelopeSide,
    ) -> Result<Option<String>> {
        match &self.transport {
            None => Ok(None),
            Some(routes) => Ok(routes.tenant(tenant).await?.rewrite(address, side)),
        }
    }

    /// Группы рассылки с ограничениями отправителей и модерацией (SMTP-16, [`crate::groups`]).
    pub fn with_groups(mut self, groups: Groups) -> Self {
        self.groups = Some(groups);
        self
    }

    /// Разрешает адрес получателя: переписывание ([`crate::address`]), затем адрес целиком, адрес без тега
    /// подадреса, адрес для всей почты домена (псевдоним каталога `@domain`).
    pub async fn resolve(&self, address: &str) -> Result<Resolved> {
        Ok(self.target(address).await?.resolved)
    }

    async fn target(&self, address: &str) -> Result<Target> {
        let address = self
            .rewrite(self.deps.tenant, address, EnvelopeSide::Recipient)
            .await?
            .unwrap_or_else(|| address.to_owned());
        let lower = address.to_lowercase();
        let target = |resolved, delivered_to, mailing| Target {
            address: address.clone(),
            resolved,
            delivered_to,
            group: None,
            mailing,
            contacts: Vec::new(),
            relay: false,
            foreign: false,
        };
        let Some((_, domain)) = lower.rsplit_once('@') else {
            return Ok(target(Resolved::Unknown, None, false));
        };
        let Some(accepted) = self.accepted(domain).await? else {
            return Ok(target(Resolved::External, None, false));
        };
        if accepted.tenant != self.deps.tenant {
            return Ok(Target {
                foreign: true,
                ..target(Resolved::External, None, false)
            });
        }
        let relay = matches!(accepted.kind, DomainKind::InternalRelay { .. });
        let snap = self.snapshot().await?;
        if let Some(groups) = &self.groups
            && let Some(group) = groups.by_address(self.deps.tenant, &lower).await?
        {
            let members = groups.members(self.deps.tenant, &group).await?;
            let mut accounts = Vec::new();
            for id in members.accounts {
                if let Some(acc) = self.deps.accounts.get(self.deps.tenant, id).await?
                    && acc.enabled
                {
                    accounts.push(acc);
                }
            }
            return Ok(Target {
                group: Some(group),
                contacts: members.contacts,
                ..target(Resolved::Local(accounts), None, true)
            });
        }
        if let Some(accounts) = self.lookup(&snap, &lower).await? {
            return Ok(target(
                Resolved::Local(accounts),
                None,
                snap.mailing.contains(&lower),
            ));
        }
        if let Some((base, _tag)) = self.addressing.split(&lower)
            && let Some(accounts) = self.lookup(&snap, &base).await?
        {
            return Ok(target(
                Resolved::Local(accounts),
                Some(address.clone()),
                snap.mailing.contains(&base),
            ));
        }
        let catch_all = format!("@{domain}");
        if snap.addresses.contains_key(&catch_all)
            && let Some(accounts) = self.lookup(&snap, &catch_all).await?
        {
            return Ok(target(Resolved::Local(accounts), None, false));
        }
        if relay {
            // Адрес вне каталога в домене внутренней ретрансляции — на старый сервер (`next_hop`).
            return Ok(Target {
                relay: true,
                ..target(Resolved::External, None, false)
            });
        }
        Ok(target(Resolved::Unknown, None, false))
    }

    /// Включённые учётные записи адреса `address` (нижний регистр): по снимку каталога или как имя входа.
    async fn lookup(&self, snap: &Snapshot, address: &str) -> Result<Option<Vec<Account>>> {
        let logins = match snap.addresses.get(address) {
            Some(logins) => logins.iter().cloned().collect(),
            None => vec![address.to_owned()],
        };
        let mut accounts = Vec::new();
        for login in logins {
            if let Some(acc) = self
                .deps
                .accounts
                .by_login(self.deps.tenant, &login)
                .await?
                && acc.enabled
                && !accounts.iter().any(|a: &Account| a.id == acc.id)
            {
                accounts.push(acc);
            }
        }
        Ok((!accounts.is_empty()).then_some(accounts))
    }

    async fn snapshot(&self) -> Result<Arc<Snapshot>> {
        if let Some((at, snap)) = &*lock(&self.snapshot)
            && at.elapsed() < self.cfg.directory_refresh
        {
            return Ok(snap.clone());
        }
        let snap = Arc::new(self.load_snapshot().await?);
        *lock(&self.snapshot) = Some((Instant::now(), snap.clone()));
        Ok(snap)
    }

    async fn load_snapshot(&self) -> Result<Snapshot> {
        let Some(dir) = &self.deps.directory else {
            return Ok(Snapshot::default());
        };
        let tenant = self.deps.tenant;
        // external_id → (имя входа, адреса); группы: external_id → (адрес, члены).
        let mut accounts = HashMap::new();
        let mut cursor: Option<DirCursor> = None;
        loop {
            let page = dir.accounts_since(tenant, cursor.as_ref(), 1000).await?;
            for change in page.changes {
                match change {
                    DirChange::Upsert(a) if a.enabled => {
                        accounts.insert(a.external_id.clone(), (a.login, a.emails));
                    }
                    DirChange::Upsert(a) => {
                        accounts.remove(&a.external_id);
                    }
                    DirChange::Removed { external_id } => {
                        accounts.remove(&external_id);
                    }
                }
            }
            cursor = Some(page.next);
            if !page.has_more {
                break;
            }
        }
        let mut groups = HashMap::new();
        let mut cursor: Option<DirCursor> = None;
        loop {
            let page = dir.groups_since(tenant, cursor.as_ref(), 1000).await?;
            for change in page.changes {
                match change {
                    DirChange::Upsert(g) => {
                        groups.insert(g.external_id.clone(), (g.email, g.members));
                    }
                    DirChange::Removed { external_id } => {
                        groups.remove(&external_id);
                    }
                }
            }
            cursor = Some(page.next);
            if !page.has_more {
                break;
            }
        }
        // Имена входа по external_id учётной записи или группы (с раскрытием вложенных групп).
        let expand = |root: &str| {
            let mut out = BTreeSet::new();
            let mut seen = HashSet::new();
            let mut stack = vec![(root.to_owned(), 0usize)];
            while let Some((id, depth)) = stack.pop() {
                if !seen.insert(id.clone()) {
                    continue;
                }
                if let Some((login, _)) = accounts.get(&id) {
                    out.insert(login.to_lowercase());
                } else if let Some((_, members)) = groups.get(&id)
                    && depth < MAX_GROUP_DEPTH
                {
                    stack.extend(members.iter().map(|m| (m.clone(), depth + 1)));
                }
            }
            out
        };
        let mut addresses: HashMap<String, BTreeSet<String>> = HashMap::new();
        let mut mailing = HashSet::new();
        for (login, emails) in accounts.values() {
            for email in emails {
                addresses
                    .entry(email.to_lowercase())
                    .or_default()
                    .insert(login.to_lowercase());
            }
        }
        for (id, (email, _)) in &groups {
            if let Some(email) = email {
                mailing.insert(email.to_lowercase());
                addresses
                    .entry(email.to_lowercase())
                    .or_default()
                    .extend(expand(id));
            }
        }
        for alias in dir.aliases(tenant).await? {
            addresses
                .entry(alias.address.to_lowercase())
                .or_default()
                .extend(expand(&alias.target));
        }
        Ok(Snapshot { addresses, mailing })
    }

    /// Папка доставки: «Спам» (`junk`) или «Входящие».
    async fn mailbox(&self, scope: AccountScope, junk: bool) -> Result<MailboxId> {
        let list = self.deps.mailboxes.list(scope).await?;
        let find = |role| list.iter().find(|m| m.role == Some(role)).map(|m| m.id);
        let found = if junk {
            find(SpecialUse::Junk).or_else(|| find(SpecialUse::Inbox))
        } else {
            find(SpecialUse::Inbox)
        };
        found.ok_or_else(|| Error::Internal(format!("account {} has no inbox", scope.account)))
    }

    /// Разрешает всех получателей конверта: доставки (по одной на учётную запись), внешние адреса,
    /// модерируемые группы. Отправитель вне круга группы (принят на `RCPT` до изменения группы, отправка
    /// из JMAP) — в `failed`. `peer` — тип абонента отправителя (для `group_post`, SMTP-50); копии модулей
    /// (`Origin::Module`) группы только раскрываются. Отказ по политике (закрытая группа, неизвестный адрес)
    /// уведомления отправителю не даёт ([`dsn::Recipient::notify`]): он должен был прозвучать в сессии
    /// до `250` (RFC 5321 §6.2).
    async fn prepare(
        &self,
        id: &str,
        rcpts: &[String],
        filing: &Filing,
        origin: Origin,
        peer: PeerKind,
    ) -> Result<Prepared> {
        let mut out = Prepared {
            deliveries: Vec::new(),
            junk: HashSet::new(),
            group: HashSet::new(),
            external: Vec::new(),
            relayed: Vec::new(),
            queued: Vec::new(),
            held: Vec::new(),
            orgs: Vec::new(),
            failed: Vec::new(),
        };
        for rcpt in rcpts {
            match self.srs_reverse(rcpt).await? {
                Some(Ok(original)) => {
                    // Уведомление на адрес SRS — исходному отправителю.
                    push_unique(&mut out.relayed, vec![original]);
                    out.queued.push(rcpt.clone());
                    continue;
                }
                Some(Err(e)) => {
                    tracing::info!(%id, error = %e, "smtp: адрес SRS отклонён");
                    out.failed.push(dsn::Recipient::new(
                        rcpt.clone(),
                        dsn::Action::Failed,
                        BAD_SRS,
                    ));
                    continue;
                }
                None => {}
            }
            let target = self.target(rcpt).await?;
            if let (Some(group), Origin::Sender(sender)) = (&target.group, origin) {
                if !self.group_allows(group, sender).await? {
                    tracing::info!(%id, group = %group.id, "smtp: отправитель вне круга группы рассылки");
                    out.failed.push(denied(rcpt.clone(), GROUP_DENIED));
                    continue;
                }
                // Матрица доверия (SMTP-50): письма в группу — по типу отправителя; `Moderated` — в очередь
                // модерации, `Closed` — отказ (на `RCPT` он уже прозвучал), `Open` — как сейчас (модерация
                // самой группы сужает и дальше). Модератор группы своё письмо не задерживает.
                match self.post_action(Some(group), peer).await {
                    Ok(PostAction::Hold)
                        if !sender.is_some_and(|s| group.moderators.contains(&s)) =>
                    {
                        if !out.held.iter().any(|(_, g)| g.id == group.id) {
                            out.held.push((rcpt.clone(), group.clone()));
                        }
                        continue;
                    }
                    Ok(PostAction::Deny) => {
                        tracing::info!(%id, group = %group.id, %peer, "smtp: группа закрыта для типа абонента");
                        out.failed.push(denied(rcpt.clone(), GROUP_DENIED));
                        continue;
                    }
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
                if group.requires_moderation(sender) {
                    if !out.held.iter().any(|(_, g)| g.id == group.id) {
                        out.held.push((rcpt.clone(), group.clone()));
                    }
                    continue;
                }
            } else if target.mailing && matches!(origin, Origin::Sender(_)) {
                // Группа каталога без записи в [`Groups`]: ограничений и модераторов нет — только матрица;
                // `Moderated` без модераторов — отказ (решать некому).
                match self.post_action(None, peer).await {
                    Ok(PostAction::Pass) => {}
                    Ok(_) => {
                        tracing::info!(%id, address = %rcpt, %peer, "smtp: группа закрыта для типа абонента");
                        out.failed.push(denied(rcpt.clone(), GROUP_DENIED));
                        continue;
                    }
                    Err(e) => return Err(e),
                }
            }
            // Контакты в составе группы — внешним адресатам (очередь; письмо извне — пересылкой).
            push_unique(&mut out.external, target.contacts);
            match target.resolved {
                Resolved::Local(accounts) => {
                    for acc in accounts {
                        let direct = out.deliveries.iter().any(|(_, d)| d.account == acc.id);
                        self.push_delivery(
                            &mut out,
                            rcpt,
                            &acc,
                            target.delivered_to.as_deref(),
                            filing,
                        )
                        .await?;
                        if target.mailing && !direct {
                            out.group.insert(acc.id);
                        }
                    }
                }
                Resolved::External => {
                    let list = if target.relay {
                        &mut out.relayed
                    } else {
                        &mut out.external
                    };
                    push_unique(list, vec![target.address]);
                    out.queued.push(rcpt.clone());
                }
                // Получатель принят на RCPT, но исчез из каталога (или неизвестен при отправке из JMAP):
                // письмо ему не доставляется; отказ по политике — без уведомления отправителю (RFC 5321 §6.2).
                Resolved::Unknown => {
                    tracing::warn!(%id, "smtp: локальный получатель не найден");
                    out.failed
                        .push(denied(rcpt.clone(), "550 5.1.1 mailbox unavailable"));
                }
            }
        }
        Ok(out)
    }

    /// Добавляет доставку письма получателя `rcpt` в ящик учётной записи `acc` (одна на учётную запись): папка —
    /// «Входящие» или «Спам» по [`Delivery::junk_for`]; `delivered_to` — полный адрес с подадресом.
    async fn push_delivery(
        &self,
        out: &mut Prepared,
        rcpt: &str,
        acc: &Account,
        delivered_to: Option<&str>,
        filing: &Filing,
    ) -> Result<()> {
        if out.deliveries.iter().any(|(_, d)| d.account == acc.id) {
            return Ok(());
        }
        let scope = AccountScope {
            tenant: acc.tenant,
            account: acc.id,
        };
        let junk = self.junk_for(scope, filing).await?;
        if junk {
            out.junk.insert(acc.id);
        }
        let mailbox = self.mailbox(scope, junk).await?;
        out.orgs.push((acc.id, acc.tenant));
        out.deliveries.push((
            rcpt.to_owned(),
            MailDelivery {
                account: acc.id,
                mailbox,
                extra_headers: delivered_to
                    .iter()
                    .map(|a| ("Delivered-To".to_owned(), clean(a)))
                    .collect(),
                flags: Default::default(),
            },
        ));
        Ok(())
    }

    /// Может ли `sender` писать в группу (без [`Groups`] групп-адресатов нет — да).
    async fn group_allows(
        &self,
        group: &DistributionGroup,
        sender: Option<AccountId>,
    ) -> Result<bool> {
        match &self.groups {
            Some(g) => g.allowed(self.deps.tenant, group, sender).await,
            None => Ok(true),
        }
    }

    /// Учётная запись отправителя по адресу (отправка вне сессии SMTP: адрес проверил вызывающий):
    /// ровно одна учётная запись организации, иначе — внешний.
    async fn sender_by_address(&self, mail_from: &str) -> Result<Option<AccountId>> {
        if mail_from.is_empty() {
            return Ok(None);
        }
        Ok(match self.target(mail_from).await? {
            Target {
                resolved: Resolved::Local(accounts),
                group: None,
                ..
            } if accounts.len() == 1 => Some(accounts[0].id),
            _ => None,
        })
    }

    /// Ставит письмо `raw` в очереди модерации групп `held`.
    async fn hold_all(
        &self,
        held: &[(String, DistributionGroup)],
        mail_from: &str,
        sender: Option<AccountId>,
        raw: &Bytes,
        at: OffsetDateTime,
    ) -> Result<()> {
        let Some(groups) = &self.groups else {
            return Ok(());
        };
        for (_, group) in held {
            let id = groups
                .hold(Hold {
                    tenant: self.deps.tenant,
                    group,
                    sender: mail_from,
                    sender_account: sender,
                    message_id: crate::tracking::message_id(raw),
                    raw: raw.clone(),
                    at,
                })
                .await?;
            tracing::info!(group = %group.id, held = %id, "smtp: письмо ждёт решения модератора группы");
        }
        Ok(())
    }

    /// Заголовки трассировки (RFC 5321, 4.4): `Return-Path` и `Received`.
    fn trace_headers(&self, env: &Envelope, received_at: OffsetDateTime) -> String {
        let proto = match (
            env.smtputf8,
            env.esmtp,
            env.conn.tls,
            env.principal.is_some(),
        ) {
            (true, _, true, true) => "UTF8SMTPSA",
            (true, _, true, false) => "UTF8SMTPS",
            (true, _, false, true) => "UTF8SMTPA",
            (true, _, false, false) => "UTF8SMTP",
            (false, true, true, true) => "ESMTPSA",
            (false, true, true, false) => "ESMTPS",
            (false, true, false, true) => "ESMTPA",
            (false, true, false, false) => "ESMTP",
            (false, false, _, _) => "SMTP",
        };
        let ip = match env.conn.client.ip() {
            std::net::IpAddr::V4(ip) => ip.to_string(),
            std::net::IpAddr::V6(ip) => format!("IPv6:{ip}"),
        };
        // Дата RFC 5322 — mail-builder (UTC).
        let date = mail_builder::headers::date::Date::new(received_at.unix_timestamp()).to_rfc822();
        let mut h = format!(
            "Return-Path: <{}>\r\nReceived: from {} ([{ip}])\r\n\tby {} (The Post) with {proto} id {}",
            clean(&env.mail_from),
            clean(&env.helo),
            self.hostname,
            env.id,
        );
        // Адрес получателя — только при одном получателе: остальные не должны видеть друг друга.
        if let [rcpt] = env.rcpts.as_slice() {
            h.push_str(&format!("\r\n\tfor <{}>", clean(rcpt)));
        }
        h.push_str(&format!(";\r\n\t{date}\r\n"));
        h
    }

    async fn ingest(
        &self,
        mail_from: &str,
        raw: Bytes,
        deliveries: Vec<MailDelivery>,
        received_at: OffsetDateTime,
    ) -> Result<Ingested> {
        self.deps
            .store
            .ingest(IngestRequest {
                tenant: self.deps.tenant,
                mail_from: mail_from.to_owned(),
                raw: Box::pin(futures::stream::once(async move { Ok(raw) })),
                deliveries,
                received_at,
            })
            .await
    }

    /// `ingest`; превышение квоты — повтор без переполненных ящиков (их адреса — в `failed`, отправителю
    /// уведомление).
    async fn ingest_all(
        &self,
        id: &str,
        mail_from: &str,
        raw: Bytes,
        mut deliveries: Vec<(String, MailDelivery)>,
        received_at: OffsetDateTime,
        failed: &mut Vec<dsn::Recipient>,
    ) -> Result<Ingested> {
        let all = deliveries.iter().map(|(_, d)| d.clone()).collect();
        match self.ingest(mail_from, raw.clone(), all, received_at).await {
            Err(Error::QuotaExceeded) => {}
            other => return other,
        }
        let Some(quota) = &self.deps.quota else {
            return Err(Error::QuotaExceeded);
        };
        let mut fits = Vec::new();
        let mut full = Vec::new();
        for (rcpt, d) in deliveries.drain(..) {
            let scope = AccountScope {
                tenant: self.deps.tenant,
                account: d.account,
            };
            match quota.check(scope, raw.len() as u64).await {
                Ok(()) => fits.push(d),
                Err(Error::QuotaExceeded) => {
                    tracing::warn!(%id, account = %d.account, "smtp: ящик переполнен, письмо не доставлено");
                    // Копия точки принятия решений (без адреса) уведомления не даёт.
                    if !rcpt.is_empty() && !full.contains(&rcpt) {
                        full.push(rcpt);
                    }
                }
                Err(e) => return Err(e),
            }
        }
        if fits.is_empty() {
            return Err(Error::QuotaExceeded);
        }
        let out = self.ingest(mail_from, raw, fits, received_at).await?;
        failed.extend(
            full.into_iter()
                .map(|r| dsn::Recipient::new(r, dsn::Action::Failed, "552 5.2.2 mailbox full")),
        );
        Ok(out)
    }

    /// Ставит в очередь исходящей почты внешних получателей и пересылки; `owner` — учётная запись отправителя
    /// (CTR-74: шард её ящика), `None` — пересылка, уведомление, письмо без отправителя-учётной записи.
    async fn queue_out(
        &self,
        id: &str,
        owner: Option<AccountId>,
        mail_from: &str,
        rcpts: Vec<String>,
        raw: Bytes,
    ) -> Result<()> {
        if rcpts.is_empty() {
            return Ok(());
        }
        match &self.deps.outbound {
            Some(q) => {
                q.enqueue(self.deps.tenant, owner, mail_from, &rcpts, raw)
                    .await
            }
            None => {
                // Узел без очереди: внешних получателей submission не принимает (RCPT — 451, `submit` —
                // `SubmitStatus::Failed`), здесь остаются только внешние пересылки и копии модулей.
                tracing::warn!(
                    %id,
                    count = rcpts.len(),
                    "smtp: очередь исходящей почты не подключена, пересылка не выполнена"
                );
                Ok(())
            }
        }
    }

    /// Копии точки принятия решений на адреса (`CopyTo::Address`): локальные — доставки в ящики (без адреса
    /// получателя: копия уведомления отправителю не даёт и адрес ему не раскрывает), внешние — в очередь.
    /// Автопересылка на внешний адрес (SMTP-50, решение 124 г) — только при включённой клетке `auto_forward` или
    /// домене из `auto_forward_domains`: иначе копия не пересылается (только журнал доставки).
    async fn add_copies(
        &self,
        id: &str,
        prepared: &mut Prepared,
        addresses: &[String],
        filing: &Filing,
        steps: &mut Vec<Step>,
    ) -> Result<()> {
        if addresses.is_empty() {
            return Ok(());
        }
        let mut copies = self
            .prepare(id, addresses, filing, Origin::Module, PeerKind::Own)
            .await?;
        copies.external.append(&mut copies.relayed);
        let (matrix, domains) = self.org_matrix().await?;
        let mut external = Vec::new();
        for a in copies.external {
            if self.forward_to(&matrix, &domains, &a).await? {
                external.push(a);
            } else {
                tracing::info!(%id, address = %a, "smtp: копия на внешний адрес не переслана — политика автопересылки");
                steps.push(
                    Step::new(Ek::Deliver, Dd::Discard, vec![a])
                        .reason("forward skipped: auto-forward policy"),
                );
            }
        }
        for (_, d) in copies.deliveries {
            if !prepared
                .deliveries
                .iter()
                .any(|(_, x)| x.account == d.account)
            {
                if copies.junk.contains(&d.account) {
                    prepared.junk.insert(d.account);
                }
                if let Some((_, tenant)) = copies.orgs.iter().find(|(a, _)| *a == d.account) {
                    prepared.orgs.push((d.account, *tenant));
                }
                prepared.deliveries.push((String::new(), d));
            }
        }
        push_unique(&mut prepared.external, external);
        Ok(())
    }

    /// Пересылки модулей (`Ingested::forward`): локальные адреса — сразу в ящики (CMP-04, SMTP-28), их
    /// пересылки — так же, пока есть учётные записи, ещё не получившие письмо (`delivered`; защита от
    /// петель). Неизвестный адрес и переполненный ящик — только в журнал: адрес пересылки отправителю не
    /// раскрывается. Внешние адреса — автопересылка (SMTP-50): только при включённой клетке `auto_forward` или
    /// домене из `auto_forward_domains`, запрещённая пересылка — событие журнала. Возвращает внешние адреса —
    /// для очереди.
    #[allow(clippy::too_many_arguments)]
    async fn forward(
        &self,
        id: &str,
        mail_from: &str,
        raw: &Bytes,
        mut forward: Vec<String>,
        filing: &Filing,
        received_at: OffsetDateTime,
        mut delivered: HashSet<AccountId>,
        steps: &mut Vec<Step>,
    ) -> Result<Vec<String>> {
        let mut external = Vec::new();
        while !forward.is_empty() {
            let p = self
                .prepare(id, &forward, filing, Origin::Module, PeerKind::Own)
                .await?;
            push_unique(&mut external, p.external);
            push_unique(&mut external, p.relayed);
            let deliveries: Vec<_> = p
                .deliveries
                .into_iter()
                .filter(|(_, d)| delivered.insert(d.account))
                .map(|(_, d)| (String::new(), d))
                .collect();
            if deliveries.is_empty() {
                break;
            }
            let mut ignored = Vec::new();
            forward = match self
                .ingest_all(
                    id,
                    mail_from,
                    raw.clone(),
                    deliveries,
                    received_at,
                    &mut ignored,
                )
                .await
            {
                Ok(ingested) => ingested.forward,
                Err(Error::QuotaExceeded) => {
                    tracing::warn!(%id, "smtp: пересылка не доставлена, ящики переполнены");
                    Vec::new()
                }
                Err(e) => return Err(e),
            }
        }
        // Внешние адреса пересылки — автопересылка (решение 124 г): без включённой клетки или домена письмо
        // наружу не уходит.
        let (matrix, domains) = self.org_matrix().await?;
        let mut allowed = Vec::new();
        for a in external {
            if self.forward_to(&matrix, &domains, &a).await? {
                allowed.push(a);
            } else {
                tracing::info!(%id, address = %a, "smtp: пересылка на внешний адрес не выполнена — политика автопересылки");
                steps.push(
                    Step::new(Ek::Deliver, Dd::Discard, vec![a])
                        .reason("forward skipped: auto-forward policy"),
                );
            }
        }
        Ok(allowed)
    }

    /// Пересылка наружу (SMTP-23): отправитель конверта — SRS (кроме локальных отправителей и уведомлений),
    /// письмо — с ARC-подписью узла; `ip` — адрес клиента, от которого письмо принято.
    async fn queue_forward(
        &self,
        id: &str,
        mail_from: &str,
        rcpts: Vec<String>,
        mut raw: Bytes,
        ip: Option<std::net::IpAddr>,
    ) -> Result<()> {
        if rcpts.is_empty() {
            return Ok(());
        }
        let Some(fwd) = &self.forwarding else {
            return self.queue_out(id, None, mail_from, rcpts, raw).await;
        };
        let mut sender = mail_from.to_owned();
        if let Some((_, domain)) = mail_from.rsplit_once('@')
            && !self.local_domain(domain).await?
            && let Some(srs) = fwd.srs().await?
            && let Some(s) = srs.forward(mail_from, OffsetDateTime::now_utc())
        {
            sender = s;
        }
        if let (Some(sealer), Some(ac)) = (fwd.sealer().await?, &self.deps.authcheck)
            && let Some(set) = ac.seal(&sealer, &raw, ip).await
        {
            let mut m = Vec::with_capacity(set.len() + raw.len());
            m.extend_from_slice(set.as_bytes());
            m.extend_from_slice(&raw);
            raw = Bytes::from(m);
        }
        self.queue_out(id, None, &sender, rcpts, raw).await
    }

    /// Правила потока почты (SMTP-22): тело — объектом BLOB на время вызова; изменённое тело — прочитано, ссылка на
    /// объект модуля снята. Без модуля — `None`.
    async fn mail_flow(
        &self,
        mut input: FlowInput,
        raw: &Bytes,
    ) -> Result<Option<(FlowOutcome, Option<Bytes>)>> {
        let Some(f) = &self.flow else {
            return Ok(None);
        };
        let key = crate::queue::store_blob(
            f.blobs.as_ref(),
            f.index.as_ref(),
            input.tenant,
            None,
            raw.clone(),
        )
        .await?;
        input.message = BlobRef {
            key,
            size: raw.len() as u64,
        };
        let outcome = f.flow.apply(&input).await;
        crate::queue::release_blob(f.index.as_ref(), &key).await;
        let outcome = outcome?;
        let body = match &outcome.message {
            Some(m) if m.key != key => {
                let read = read_blob(f.blobs.as_ref(), &m.key).await;
                crate::queue::release_blob(f.index.as_ref(), &m.key).await;
                Some(read?)
            }
            _ => None,
        };
        if let Some(route) = &outcome.route {
            // Очередь маршрут правила не хранит (CONTRACTS.md#Queue): политика — по домену назначения.
            tracing::info!(%route, "smtp: маршрут правила потока не применён, политика — по домену назначения");
        }
        Ok(Some((outcome, body)))
    }

    /// Принимает письмо: проверки, фильтры, доставка и очередь. Ответ фильтра (отказ, отброс) — `Ok(Some)`.
    async fn accept(&self, env: &Envelope, raw: Bytes, trail: &mut Trail) -> Result<Option<Reply>> {
        let received_at = OffsetDateTime::now_utc();
        // Признак «ответ на наше письмо» из заголовка извне не принимается (SMTP-51): удаляется до проверок,
        // свой узел ставит после проверок — до Milter. Заголовок балла каталога (SMTP-52) — так же.
        let mut raw = if env.mode == Mode::Inbound {
            let raw = reply::strip_header(&raw, reply::REPLY_HEADER);
            reply::strip_header(&raw, risk::RISK_HEADER)
        } else {
            raw
        };
        // BATV (SMTP-51): валидная метка bounce-адреса снимается (доставка без метки в адресе).
        let env_owned;
        let env = if env.mode == Mode::Inbound {
            match self.batv_strip_rcpts(env).await? {
                Some(rcpts) => {
                    env_owned = Envelope {
                        rcpts,
                        ..env.clone()
                    };
                    &env_owned
                }
                None => env,
            }
        } else {
            env
        };
        // Message-ID письма submission без него задаёт сервер — меткой ответа (SMTP-51); Message-ID клиента
        // не заменяется (решение 125 в).
        if env.mode == Mode::Submission {
            raw = self.ensure_mark(env, raw).await;
        }
        trail.message_id = tracking::message_id(&raw);
        // Адреса отправителя в заголовках — до проверок и фильтров: письмо от чужого имени дальше не идёт.
        let sender_header = match self.check_headers(env, &raw).await? {
            Ok(s) => s,
            Err(r) => return Ok(Some(r)),
        };
        // Ручная iTIP-обработка спам-письма (SMTP-55): accept/tentative/decline/counter клиента в ответ на
        // письмо в «Спаме» отправителя отклоняется — встречу из спам-письма руками не принять.
        if let Some(r) = self.junk_itip_refusal(submitter(env), &raw).await? {
            return Ok(Some(r));
        }
        let app = sources::application(env.source.as_deref()).is_some();
        let check = match (&self.deps.authcheck, env.mode) {
            // Приложение организации: проверки отправителя не нужны.
            (Some(_), Mode::Inbound) if app => None,
            (Some(ac), Mode::Inbound) => {
                // Шлюз без данных об исходном клиенте — результаты его проверок.
                let gateway = match sources::gateway_authserv(env.source.as_deref()) {
                    Some(id) if env.gateway.is_none() => ac.gateway(&raw, id).await,
                    _ => None,
                };
                Some(match gateway {
                    Some(g) => g,
                    None => ac.check(env, &raw).await,
                })
            }
            _ => None,
        };
        // Отправитель конверта переписывается после проверок (SPF — по исходному).
        let rewritten = self
            .rewrite(self.deps.tenant, &env.mail_from, EnvelopeSide::Sender)
            .await?
            .map(|mail_from| Envelope {
                mail_from,
                ..env.clone()
            });
        let env = rewritten.as_ref().unwrap_or(env);
        // DMARC не пройден при политике quarantine/reject — в «Спам».
        let forged = check.as_ref().is_some_and(|c| c.junk);
        let mut junk = forged;
        let mut headers = self.trace_headers(env, received_at);
        if let Some(login) = &sender_header {
            // Send on Behalf: `Sender` — вошедший пользователь (RFC 5322, 3.6.2).
            headers.push_str(&format!("Sender: {}\r\n", clean(login)));
        }
        if let Some(c) = &check {
            // Authentication-Results и Received-SPF — выше Received этого узла (RFC 8601, 7208).
            headers.insert_str(0, &c.headers);
        }
        let mut full = Vec::with_capacity(headers.len() + raw.len());
        full.extend_from_slice(headers.as_bytes());
        full.extend_from_slice(&raw);
        let mut full = Bytes::from(full);
        // Признак «ответ на наше письмо» (SMTP-51): `In-Reply-To`, затем `References` — метка расшифрована или
        // хэш Message-ID найден в записи об отправленном; отправитель `From` — среди адресатов записи, DMARC
        // pass с выравниванием и возраст ≤ `smtp.reply.max_age` — всё сразу. Своей меткой — до Milter
        // (Rspamd снижает балл, DEP-56); проверки признак не отменяет (антивирус, URL, DMARC — как всем).
        let mut flagged = self
            .detect_reply(env, &full, check.as_ref().is_some_and(|c| c.dmarc_pass))
            .await;
        // Каталог признаков (SMTP-52, решение 126): детекторы после `DATA`, до Milter и Sieve — по
        // разобранному письму и памяти бесед получателей. Детектор беседы снимает признак ответа
        // (решение 126 г); заголовка `X-ThePost-Reply-Anomaly` нет — вместо него [`risk::RISK_HEADER`].
        let mut risk_scan = self.risk_scan(env, &full).await;
        if risk_scan.as_ref().is_some_and(|s| s.drops_reply) {
            flagged = false;
        }
        if flagged {
            let mut marked = Vec::with_capacity(full.len() + reply::REPLY_HEADER.len() + 8);
            marked.extend_from_slice(format!("{}: yes\r\n", reply::REPLY_HEADER).as_bytes());
            marked.extend_from_slice(&full);
            full = Bytes::from(marked);
        }
        let mail = milter::Mail::of(env);
        // Действие Rspamd (фильтр Milter) для каталога признаков (SMTP-52): отказ и отброс фильтра —
        // ответ в сессии, карантин — в балл ([`tp_contracts::risk::Verdict::combine`]).
        let mut milter_action = RiskAction::None;
        if let Some(m) = self
            .deps
            .milter
            .as_ref()
            .filter(|m| m.applies(mail.direction))
        {
            let profile = self.message_policy(env).await?.milter_profile;
            let out = m.check(&mail, full, profile.as_deref()).await;
            match out.verdict {
                Verdict::Accept => {}
                Verdict::Refuse(r) => return Ok(Some(r)),
                Verdict::Discard => {
                    trail.decision = Some(Dd::Discard);
                    return Ok(Some(reply(250, [2, 0, 0], format!("OK id={}", env.id))));
                }
            }
            if let Some(reason) = &out.quarantine {
                tracing::info!(id = %env.id, %reason, "smtp: письмо в карантине фильтра");
                match env.mode {
                    Mode::Inbound => junk = true,
                    Mode::Submission => {
                        return Ok(Some(reply(
                            550,
                            [5, 7, 1],
                            "Message held by content filter",
                        )));
                    }
                }
            }
            full = out.message;
            // Вердикт Rspamd — действие для каталога (карантин фильтра; отказ и отброс выше — сессия).
            milter_action = out
                .quarantine
                .is_some()
                .then_some(RiskAction::Quarantine)
                .unwrap_or(RiskAction::None);
        }
        // Действия каталога (SMTP-52): самое строгое из балла, действий признаков и Rspamd
        // ([`tp_contracts::risk::Verdict::combine`]). `reject` — `550 5.7.1` в сессии всем; при
        // расхождении организаций — карантин отказавшим после приёма (письмом не отказываем —
        // backscatter); `junk`/`quarantine` — «Спам» узла; сработавшие — уже в журнале каталога.
        let mut risk_reject_orgs = Vec::new();
        if let (Some(r), Some(scan)) = (self.risk.as_ref(), risk_scan.as_mut()) {
            r.combine_rspamd(scan, milter_action);
            if scan.all_reject() {
                tracing::info!(id = %env.id, reason = %scan.event_reason(), "smtp: письмо отклонено каталогом признаков");
                trail.steps.push(
                    Step::new(Ek::Reject, Dd::Reject, env.rcpts.clone())
                        .reason(scan.event_reason()),
                );
                return Ok(Some(reply(550, [5, 7, 1], risk::REJECT_TEXT)));
            }
            risk_reject_orgs = scan.reject_orgs();
            if scan.action() >= RiskAction::Junk {
                junk = true;
            }
        }
        // Точка Data конвейера (SMTP-54): модульные этапы — условия по содержимому, отказ всему письму
        // (Milter ядра уже отработал; правила потока — ниже).
        let flow = pipeline::flow_of(env.mode);
        let system = pipeline::system_message(
            &env.mail_from,
            env.mode == Mode::Submission && dsn::is_mdn(&full),
        );
        if let Some(reason) = self.data_point(flow, &env.mail_from, &full, system).await? {
            tracing::info!(id = %env.id, %reason, "smtp: письмо отклонено этапом конвейера на DATA");
            return Ok(Some(stage_reject(trail, env.rcpts.clone(), &reason)));
        }
        // Правила потока — после Milter, до точек принятия решений, доставки и очереди; один раз на письмо.
        let input = FlowInput {
            tenant: self.deps.tenant,
            direction: match env.mode {
                Mode::Inbound => FlowDirection::Inbound,
                Mode::Submission => FlowDirection::Submission,
            },
            principal: env.principal.clone(),
            source: env.source.as_ref().map(|s| s.name.clone()),
            envelope: FlowEnvelope {
                mail_from: env.mail_from.clone(),
                rcpt_to: env.rcpts.clone(),
            },
            message: placeholder_blob(self.deps.tenant),
        };
        let flowed;
        let mut env = env;
        if let Some((outcome, body)) = self.mail_flow(input, &full).await? {
            if !outcome.matched.is_empty() {
                trail.steps.push(
                    Step::new(Ek::Receive, Dd::Accept, env.rcpts.clone())
                        .reason(format!("mail flow rules: {}", outcome.matched.join(", "))),
                );
            }
            match outcome.verdict {
                FlowVerdict::Accept if !outcome.envelope.rcpt_to.is_empty() => {}
                FlowVerdict::Accept | FlowVerdict::Drop => {
                    tracing::info!(id = %env.id, "smtp: письмо удалено правилом потока");
                    trail.decision = Some(Dd::Discard);
                    return Ok(Some(reply(250, [2, 0, 0], format!("OK id={}", env.id))));
                }
                FlowVerdict::Reject(text) => {
                    tracing::info!(id = %env.id, "smtp: письмо отклонено правилом потока");
                    let text = clean(&text);
                    let text = if text.is_empty() {
                        "Message rejected by mail flow rule".to_owned()
                    } else {
                        text
                    };
                    return Ok(Some(reply(550, [5, 7, 1], text)));
                }
                FlowVerdict::Moderate { moderators } => {
                    // SMTP-30: письмо — в очередь модерации (CTR-43), отправителю — 250, модератору —
                    // уведомление. Без хранилища очереди или модераторов — временный отказ: письмо не теряется.
                    let rule = rule_name(&outcome.matched);
                    let sender = sender_account(env, self.deps.tenant);
                    let held = self
                        .hold_by_rule(
                            self.deps.tenant,
                            &env.id,
                            &rule,
                            moderators,
                            &outcome.envelope.mail_from,
                            sender,
                            &outcome.envelope.rcpt_to,
                            &full,
                        )
                        .await?;
                    if held {
                        trail.steps.push(
                            Step::new(Ek::Deliver, Dd::Hold, outcome.envelope.rcpt_to.clone())
                                .reason(format!("held for moderation by flow rule: {rule}")),
                        );
                        return Ok(Some(reply(250, [2, 0, 0], format!("OK id={}", env.id))));
                    }
                    tracing::warn!(id = %env.id, "smtp: очередь модерации недоступна — письмо правила потока не принято");
                    return Ok(Some(reply(
                        451,
                        [4, 7, 0],
                        "Moderation by mail flow rule is not available, try again later",
                    )));
                }
            }
            if let Some(body) = body {
                full = body;
            }
            if outcome.envelope.mail_from != env.mail_from || outcome.envelope.rcpt_to != env.rcpts
            {
                flowed = Envelope {
                    mail_from: outcome.envelope.mail_from,
                    rcpts: outcome.envelope.rcpt_to,
                    ..env.clone()
                };
                env = &flowed;
            }
        }
        let mut copies = Vec::new();
        if env.mode == Mode::Submission
            && let Some(principal) = &env.principal
            && !self.deps.hooks.is_empty()
        {
            let info = SubmissionInfo {
                principal: principal.clone(),
                mail_from: env.mail_from.clone(),
                rcpt_to: env.rcpts.clone(),
                size: full.len() as u64,
            };
            match self.deps.hooks.on_submission(&info).await? {
                Decision::Allow => {}
                Decision::Deny(reason) => {
                    tracing::info!(id = %env.id, %reason, "smtp: отправка запрещена точкой принятия решений");
                    return Ok(Some(reply(550, [5, 7, 1], "Message rejected by policy")));
                }
                Decision::Augment(a) => {
                    let mut h = String::new();
                    for (name, value) in &a.headers {
                        h.push_str(&format!("{}: {}\r\n", clean(name), clean(value)));
                    }
                    let mut m = Vec::with_capacity(h.len() + full.len());
                    m.extend_from_slice(h.as_bytes());
                    m.extend_from_slice(&full);
                    full = Bytes::from(m);
                    copies = a.copies;
                }
            }
        }
        if junk {
            trail.decision = Some(Dd::Quarantine);
        }
        let sender = sender_account(env, self.deps.tenant);
        let filing = Filing::new(junk, forged, &env.mail_from, &full);
        let filing = &filing;
        // Тип абонента письма (SMTP-50): submission и приложение организации — свой; smtp-in — по домену `From`
        // и DMARC (партнёр — домен из списка партнёров с пройденным DMARC, RFC 9989).
        let peer = self
            .message_peer(
                env.mode,
                app,
                &full,
                check.as_ref().is_some_and(|c| c.dmarc_pass),
            )
            .await;
        // Отчёт о прочтении (MDN, RFC 8098) получателям с выключенной клеткой `mdn` не отправляется:
        // отправителю — `250` (машинный отчёт его программы), событие журнала доставки.
        let rcpts = if env.mode == Mode::Submission && dsn::is_mdn(&full) {
            let (org, _) = self.org_matrix().await?;
            let (allowed, steps) = self.mdn_rcpts(&env.id, &env.rcpts, &org).await?;
            trail.steps.extend(steps);
            allowed
        } else {
            env.rcpts.clone()
        };
        let mut prepared = self
            .prepare(&env.id, &rcpts, filing, Origin::Sender(sender), peer)
            .await?;
        let mut copy_to = Vec::new();
        for copy in copies {
            match copy {
                CopyTo::Mailbox(d) => {
                    if !prepared
                        .deliveries
                        .iter()
                        .any(|(_, x)| x.account == d.account && x.mailbox == d.mailbox)
                    {
                        prepared.deliveries.push((String::new(), d));
                    }
                }
                CopyTo::Address(a) => copy_to.push(a),
            }
        }
        self.add_copies(&env.id, &mut prepared, &copy_to, filing, &mut trail.steps)
            .await?;
        // Каталог признаков (SMTP-52): организации под действием `reject` при расхождении с другими —
        // карантин их доставок (отказ после приёма невозможен — backscatter).
        if !risk_reject_orgs.is_empty() {
            self.quarantine_orgs(&mut prepared, &risk_reject_orgs).await;
        }
        // Этап журналирования ядра (SMTP-53, CTR-96: первый этап точки BeforeMailboxSieve) — до модульных
        // этапов и Sieve ящика: запись не зависит от ящика, `discard`/`stop` скрипта получателя её не
        // отменяют. Служебные письма (DSN, MDN) — `SystemMessage`: не журналируются.
        if system.is_none() {
            let direction = match env.mode {
                Mode::Inbound => JournalDirection::In,
                Mode::Submission => JournalDirection::Out,
            };
            self.journal_message(
                &env.id,
                direction,
                &env.mail_from,
                &rcpts,
                &full,
                received_at,
            )
            .await?;
        }
        // Модульные этапы до Sieve ящика (SMTP-54): по каждому локальному получателю; отказ — всему письму.
        for rcpt in local_rcpts(&prepared.deliveries) {
            if let Some(reason) = self
                .delivery_point(
                    PipelinePoint::BeforeMailboxSieve,
                    flow,
                    &env.mail_from,
                    &rcpt,
                    &full,
                    None,
                    system,
                )
                .await?
            {
                tracing::info!(id = %env.id, %rcpt, %reason, "smtp: письмо отклонено этапом конвейера до Sieve");
                return Ok(Some(stage_reject(trail, vec![rcpt], &reason)));
            }
        }
        // Внешние получатели smtp-in от обычного клиента — только перенаправления правил потока: пересылка.
        let redirect = env.mode == Mode::Inbound && !app;
        let mut forwarded = Vec::new();
        let mut rcpts = std::mem::take(&mut prepared.relayed);
        if redirect {
            forwarded = std::mem::take(&mut prepared.external);
        } else {
            push_unique(&mut rcpts, std::mem::take(&mut prepared.external));
        }
        let mut failed = std::mem::take(&mut prepared.failed);
        // Учётные записи получателей — до правил: пересылка модулей им же письмо не доставляет (петли).
        let delivered = accounts_of(&prepared.deliveries);
        let mut forward = Vec::new();
        let Sieved {
            redirect: hops,
            mut replies,
            steps: mut sieve_steps,
            org_failed,
            actions,
            signals,
        } = self
            .apply_rules(
                &env.id,
                &env.mail_from,
                &full,
                &mut prepared.deliveries,
                &RuleContext::new(peer, flagged, &prepared.junk, &prepared.group),
                false,
                true,
                risk_scan.as_ref(),
            )
            .await?;
        if !org_failed.is_empty() {
            // Сбой скрипта организации (SIEVE-14): письмо не доставляется в обход скрипта — временный отказ.
            return Ok(Some(reply(
                451,
                [4, 3, 0],
                "Sieve organization script failed, try again later",
            )));
        }
        // Признаки команды `signal` скрипта организации (SIEVE-15, CTR-95) — после Sieve, с пределом
        // веса (SMTP-52): балл и действие пересчитаны; `reject` после приёма — карантин отказавшим
        // организациям (письмом не отказываем — backscatter), `junk` — так же в «Спам» узла.
        if let (Some(r), Some(scan)) = (self.risk.as_ref(), risk_scan.as_mut()) {
            r.apply_sieve(scan, &signals).await;
            if scan.action() >= RiskAction::Junk {
                let orgs = scan.junk_orgs();
                self.quarantine_orgs(&mut prepared, &orgs).await;
            }
        }
        // Точки после Sieve и итоговый контроль действий (SMTP-54): итоговый набор действий получателя —
        // перенаправления скрипта ящика, копии и адресаты. Запрет внешней пересылки организации
        // (`forbid_external_forward`) перехватывает redirect из скрипта ящика: нарушение — отказ письму с
        // причиной в журнале доставки. Служебные письма этапы правил минуют.
        for (rcpt, redirect) in &actions {
            let acts = ActionSet {
                redirect: redirect.clone(),
                copies: copy_to.clone(),
                recipients: rcpts.clone(),
            };
            let mut reason = self
                .delivery_point(
                    PipelinePoint::AfterMailboxSieve,
                    flow,
                    &env.mail_from,
                    rcpt,
                    &full,
                    Some(acts.clone()),
                    system,
                )
                .await?;
            if reason.is_none() && system.is_none() {
                reason = self.final_action_check(&acts).await?;
                if reason.is_some() {
                    tracing::info!(id = %env.id, %rcpt, "smtp: письмо отклонено итоговым контролем действий");
                }
            }
            if reason.is_none() {
                reason = self
                    .delivery_point(
                        PipelinePoint::FinalActionCheck,
                        flow,
                        &env.mail_from,
                        rcpt,
                        &full,
                        Some(acts),
                        system,
                    )
                    .await?;
            }
            if let Some(reason) = reason {
                tracing::info!(id = %env.id, %rcpt, %reason, "smtp: письмо отклонено после Sieve");
                return Ok(Some(stage_reject(trail, vec![rcpt.clone()], &reason)));
            }
        }
        // Каталог признаков (SMTP-52): итоговый вердикт письма — заголовок [`risk::RISK_HEADER`] с
        // баллом и признаками при действии `tag` и строже, событие журнала доставки с баллом,
        // признаками и действием (`thepost admin delivery show` его показывает). Правила письма
        // заголовок не видят — факты им отдают контекст (CTR-95 `RulesInput::risk`).
        if let Some(scan) = risk_scan.as_ref() {
            if scan.action() >= RiskAction::Tag {
                let value = scan.header_value();
                let mut marked =
                    Vec::with_capacity(full.len() + risk::RISK_HEADER.len() + value.len() + 8);
                marked
                    .extend_from_slice(format!("{}: {}\r\n", risk::RISK_HEADER, value).as_bytes());
                marked.extend_from_slice(&full);
                full = Bytes::from(marked);
            }
            if !scan.empty() && scan.has_findings() {
                trail.steps.push(
                    Step::new(Ek::Receive, Dd::Accept, env.rcpts.clone())
                        .reason(scan.event_reason()),
                );
            }
        }
        // Очередь модерации — до доставки: её сбой — временный отказ без частичной доставки (после проверки
        // скрипта организации — письмо не задерживается перед временным отказом).
        self.hold_all(&prepared.held, &env.mail_from, sender, &full, received_at)
            .await?;
        let local = local_rcpts(&prepared.deliveries);
        let spam = junk_rcpts(&prepared.deliveries, &prepared.junk);
        // iTIP — входящей почте с проверками отправителя (iMIP) и письму вошедшего пользователя (решение 78), вне
        // «Спама»: адресу `From` без DMARC или без связи с отправителем доверять нельзя.
        let origin = match (&check, sender) {
            (Some(c), _) => Some(ItipOrigin::Imip {
                dmarc_pass: c.dmarc_pass,
            }),
            (None, Some(account)) => Some(ItipOrigin::Internal {
                account,
                principal: env.principal.as_ref(),
            }),
            (None, None) => None,
        }
        .filter(|_| self.itip.is_some());
        let itip_to = itip_targets(origin.is_some(), &prepared.deliveries, &prepared.junk);
        if !prepared.deliveries.is_empty() {
            let ingested = self
                .ingest_all(
                    &env.id,
                    &env.mail_from,
                    full.clone(),
                    prepared.deliveries,
                    received_at,
                    &mut failed,
                )
                .await?;
            push_unique(&mut forward, ingested.forward);
        }
        let itip_steps = match origin.filter(|_| !itip_to.is_empty()) {
            Some(origin) => {
                self.apply_itip(&env.id, &full, origin, &itip_to, &failed)
                    .await
            }
            None => Vec::new(),
        };
        let external = self
            .forward(
                &env.id,
                &env.mail_from,
                &full,
                forward,
                filing,
                received_at,
                delivered,
                &mut trail.steps,
            )
            .await?;
        push_unique(&mut forwarded, external);
        let relayed = self
            .relay(
                &env.id,
                &env.mail_from,
                hops,
                filing,
                received_at,
                Some(env.conn.client.ip()),
                peer,
            )
            .await?;
        sieve::merge_replies(&mut replies, relayed.replies);
        sieve_steps.extend(relayed.steps);
        self.queue_out(&env.id, sender, &env.mail_from, rcpts, full.clone())
            .await?;
        self.queue_forward(
            &env.id,
            &env.mail_from,
            forwarded,
            full.clone(),
            Some(env.conn.client.ip()),
        )
        .await?;
        outcome_steps(&mut trail.steps, &prepared.held, &local, &failed, &spam);
        trail.steps.extend(itip_steps);
        trail.steps.extend(sieve_steps);
        self.send_replies(&env.id, &env.mail_from, &full, replies, &mut trail.steps)
            .await;
        // Принятое и недоставленное — уведомление на адрес конверта (RFC 3464 §2). Письмо в «Спаме» и карантине
        // фильтра не уведомляется (backscatter, SMTP-50 — как EOP отбрасывает сомнительное без NDR); отказы по
        // политике уведомлений не дают ([`dsn::Recipient::notify`]).
        let failed: Vec<dsn::Recipient> = if junk {
            Vec::new()
        } else {
            failed.iter().filter(|f| f.notify).cloned().collect()
        };
        if !failed.is_empty() && !env.mail_from.is_empty() {
            let sent = self
                .bounce(&env.id, &env.mail_from, &failed, &full, received_at)
                .await;
            trail.steps.push(dsn_step(&env.mail_from, sent));
        }
        Ok(None)
    }

    /// Уведомление о недоставке после приёма (`250` уже не отменить); сбой — только в журнал. Получателю не
    /// своей организации — с общей диагностикой (решение 124, RFC 3464 §4.2).
    async fn bounce(
        &self,
        id: &str,
        mail_from: &str,
        rcpts: &[dsn::Recipient],
        original: &[u8],
        received_at: OffsetDateTime,
    ) -> bool {
        let plain = self.dsn_plain(mail_from).await;
        let raw = dsn::build(&dsn::Report {
            hostname: &self.hostname,
            to: mail_from,
            envid: None,
            arrival: received_at,
            now: OffsetDateTime::now_utc(),
            retry_until: None,
            rcpts,
            original,
            ret: DsnRet::Headers,
            id,
            plain,
        });
        if let Err(e) = self
            .send_dsn(self.deps.tenant, mail_from, Bytes::from(raw))
            .await
        {
            tracing::warn!(%id, error = %e, "smtp: уведомление о недоставке не отправлено");
            return false;
        }
        true
    }

    /// Уведомление о недоставке адресу `to` — с общей диагностикой: получатель не своей организации (решение 124,
    /// RFC 3464 §4.2 — без имён узлов, внутренних адресов и имён фильтров). Ошибка разрешения — общая (безопасно).
    async fn dsn_plain(&self, to: &str) -> bool {
        !matches!(self.resolve(to).await, Ok(Resolved::Local(_)))
    }

    /// Тип абонента письма сессии (SMTP-50): submission (вошедший или приложение организации) — свой; smtp-in —
    /// по домену `From` (нет `From` — конверт) с DMARC. Сбой чтения политики — внешний (безопасное умолчание),
    /// письмо доставляется.
    async fn message_peer(&self, mode: Mode, app: bool, raw: &[u8], dmarc_pass: bool) -> PeerKind {
        if mode == Mode::Submission || app {
            return PeerKind::Own;
        }
        let from = from_address(raw).unwrap_or_default();
        match self.sender_kind(&from, false, dmarc_pass).await {
            Ok(kind) => kind,
            Err(e) => {
                tracing::warn!(error = %e, "smtp: тип абонента не вычислен — внешний");
                PeerKind::External
            }
        }
    }

    /// Message-ID письма submission без него — меткой ответа (SMTP-51, решение 125 в): домен метки — домен
    /// `From`, иначе имя узла. Сбой метки — только в журнал (письмо уходит с тем, что есть).
    async fn ensure_mark(&self, env: &Envelope, raw: Bytes) -> Bytes {
        let Some(marks) = &self.reply else {
            return raw;
        };
        let domain = from_address(&raw)
            .and_then(|a| a.rsplit_once('@').map(|(_, d)| d.to_lowercase()))
            .unwrap_or_else(|| self.hostname.clone());
        match marks
            .ensure_message_id(raw.clone(), &domain, OffsetDateTime::now_utc())
            .await
        {
            Ok((raw, _, _)) => raw,
            Err(e) => {
                tracing::warn!(id = %env.id, error = %e, "smtp: метка Message-ID не поставлена");
                raw
            }
        }
    }

    /// Признак «ответ на наше письмо» (SMTP-51, решение 125 а) — только smtp-in с проверками отправителя:
    /// `In-Reply-To`, затем `References` — метка расшифрована (ключ известен, время не в будущем) или хэш
    /// Message-ID найден в записи об отправленном; затем отправитель `From` — среди адресатов записи, DMARC
    /// pass с выравниванием и возраст ≤ `smtp.reply.max_age`. Ошибка чтения записи — признака нет (безопасное
    /// умолчание), письмо доставляется.
    async fn detect_reply(&self, env: &Envelope, raw: &[u8], dmarc_pass: bool) -> bool {
        if env.mode != Mode::Inbound || self.sent.is_none() {
            return false;
        }
        let refs = referenced_ids(raw);
        if refs.is_empty() {
            return false;
        }
        let flagged = 'flag: {
            let Some(marks) = &self.reply else {
                break 'flag false;
            };
            let Some(sent) = &self.sent else {
                break 'flag false;
            };
            let now = OffsetDateTime::now_utc();
            let sender = from_address(raw).unwrap_or_default();
            // Метка Message-ID: без БД, доказывает «наше и свежее» (решение 125 в).
            for id in &refs {
                let opened = match marks.open(id, now).await {
                    Ok(o) => o,
                    Err(e) => {
                        tracing::warn!(id = %env.id, error = %e, "smtp: метка ответа не проверена");
                        None
                    }
                };
                let record = match opened {
                    Some(opened) => sent.by_tag(self.deps.tenant, &opened.tag).await,
                    None => Ok(None),
                };
                let confirmed = match record {
                    Ok(Some(record)) => ReplyEvidence {
                        age: age_since(record.sent_at, now),
                        sent: record,
                    }
                    .confirms(&sender, self.reply_max_age),
                    Ok(None) => false,
                    Err(e) => {
                        tracing::warn!(id = %env.id, error = %e, "smtp: запись об отправленном не прочитана");
                        false
                    }
                };
                if confirmed {
                    break 'flag true;
                }
            }
            // Хэш Message-ID клиента (как Rspamd `replies`): письму с чужим Message-ID отвечают по записи.
            for id in &refs {
                let found = match sent
                    .by_message_id_hash(self.deps.tenant, &ReplyMarks::hash_of(id))
                    .await
                {
                    Ok(found) => found,
                    Err(e) => {
                        tracing::warn!(id = %env.id, error = %e, "smtp: запись об отправленном не прочитана");
                        break;
                    }
                };
                for record in found {
                    let evidence = ReplyEvidence {
                        age: age_since(record.sent_at, now),
                        sent: record,
                    };
                    if evidence.confirms(&sender, self.reply_max_age) {
                        break 'flag true;
                    }
                }
            }
            false
        };
        let flagged = flagged && dmarc_pass;
        if let Some(m) = &self.metrics {
            m.reply_flag(flagged);
        }
        flagged
    }

    /// Проверка письма каталогом признаков (SMTP-52): только smtp-in с подключённым и включённым
    /// каталогом ([`Risk::enabled`]). Локальные получатели и их организации — из каталога узла
    /// ([`Delivery::resolve`]); письмо разбирается один раз, вердикт — по каждой организации. Без
    /// каталога или вне smtp-in — `None` (проверки нет).
    async fn risk_scan(&self, env: &Envelope, raw: &Bytes) -> Option<risk::Scan> {
        let r = self
            .risk
            .as_ref()
            .filter(|r| r.enabled() && env.mode == Mode::Inbound)?;
        let mut locals: Vec<(AccountId, TenantId)> = Vec::new();
        for rcpt in &env.rcpts {
            let Ok(Resolved::Local(accounts)) = self.resolve(rcpt).await else {
                continue;
            };
            for acc in accounts {
                if !locals.iter().any(|(a, _)| *a == acc.id) {
                    locals.push((acc.id, acc.tenant));
                }
            }
        }
        Some(r.scan(env.conn.client.ip(), raw, &locals).await)
    }

    /// Карантин доставкам организаций `orgs` (каталог признаков SMTP-52: `reject` при расхождении
    /// организаций или итог после Sieve): письма — в «Спам» узла, событие — `Quarantine`. Отказ после
    /// приёма невозможен (backscatter), письмом не отказываем.
    async fn quarantine_orgs(&self, prepared: &mut Prepared, orgs: &[TenantId]) {
        for (account, tenant) in &prepared.orgs {
            if !orgs.contains(tenant) {
                continue;
            }
            let scope = AccountScope {
                tenant: *tenant,
                account: *account,
            };
            let Ok(junk) = self.mailbox(scope, true).await else {
                continue;
            };
            for (_, d) in prepared
                .deliveries
                .iter_mut()
                .filter(|(_, d)| d.account == *account)
            {
                d.mailbox = junk;
            }
            prepared.junk.insert(*account);
        }
    }

    /// BATV (SMTP-51): валидная метка адреса-получателя снимается — доставка без метки в адресе. `None` —
    /// адреса не менялись (метки нет, BATV не настроен или метка не сошлась: в `enforce` такой адрес уже
    /// отклонён на `RCPT`, в `log` — адрес как есть).
    async fn batv_strip_rcpts(&self, env: &Envelope) -> Result<Option<Vec<String>>> {
        let Some(marks) = &self.reply else {
            return Ok(None);
        };
        let Some(batv) = marks.batv() else {
            return Ok(None);
        };
        let now = OffsetDateTime::now_utc();
        let mut changed = false;
        let mut rcpts = Vec::with_capacity(env.rcpts.len());
        for rcpt in &env.rcpts {
            match batv.open(rcpt, now).await? {
                Some(BatvAddress::Stripped(address)) => {
                    changed = true;
                    rcpts.push(address);
                }
                _ => rcpts.push(rcpt.clone()),
            }
        }
        Ok(changed.then_some(rcpts))
    }

    /// BATV-адрес получателя на `RCPT` (SMTP-51): валидная метка снимается — дальше идёт адрес без метки
    /// (`true` — метка была валидна, отсутствие метки у bounce не проверяется). Невалидная (чужой ключ,
    /// просрочена, подделка) у bounce (`MAIL FROM: <>`) — `550 5.7.1` в `enforce` ([`Batv::enforce`]), в
    /// `log` — журнал и метрика, адрес как есть; у обычного письма — адрес как есть. Сбой чтения ключа —
    /// адрес как есть (сбой не должен терять почту).
    async fn batv_rcpt_of(
        &self,
        env: &Envelope,
        rcpt: &str,
    ) -> std::result::Result<(String, bool), Reply> {
        let Some(marks) = &self.reply else {
            return Ok((rcpt.to_owned(), false));
        };
        let Some(batv) = marks.batv() else {
            return Ok((rcpt.to_owned(), false));
        };
        let now = OffsetDateTime::now_utc();
        match batv.open(rcpt, now).await {
            Ok(Some(BatvAddress::Stripped(address))) => {
                if let Some(m) = &self.metrics {
                    m.batv_bounce(BatvOutcome::Valid);
                }
                Ok((address, true))
            }
            Ok(Some(BatvAddress::Invalid(why))) => {
                tracing::info!(id = %env.id, address = %rcpt, reason = why, "smtp: BATV-метка адреса не сошлась");
                if let Some(m) = &self.metrics {
                    m.batv_bounce(BatvOutcome::Invalid);
                }
                if env.mode == Mode::Inbound && env.mail_from.is_empty() && batv.enforce() {
                    return Err(reply(550, [5, 7, 1], "Bad or missing BATV signature"));
                }
                Ok((rcpt.to_owned(), false))
            }
            Ok(None) => Ok((rcpt.to_owned(), false)),
            Err(e) => {
                tracing::warn!(id = %env.id, address = %rcpt, error = %e, "smtp: BATV-метка адреса не проверена");
                Ok((rcpt.to_owned(), false))
            }
        }
    }

    /// BATV-проверка адреса-получателя на `RCPT` (SMTP-51): письмо с пустым `MAIL FROM` (bounce) на локальный
    /// адрес без валидной метки — `550 5.7.1` в `enforce`, в `log` — только журнал и метрика. `marked` —
    /// валидная метка была снята ранее ([`Delivery::batv_rcpt_of`]); адрес из `smtp.batv.exempt` метки не
    /// требует. Вызывается из [`Delivery::check_rcpt_core`] после разрешения адреса.
    async fn batv_check_rcpt(
        &self,
        env: &Envelope,
        rcpt: &str,
        local: bool,
        marked: bool,
    ) -> Option<Reply> {
        if marked {
            return None;
        }
        let Some(marks) = &self.reply else {
            return None;
        };
        let batv = marks.batv()?;
        if env.mode != Mode::Inbound || !env.mail_from.is_empty() || !local {
            return None;
        }
        if batv.exempt_of(rcpt) {
            return None;
        }
        if let Some(m) = &self.metrics {
            m.batv_bounce(BatvOutcome::Missing);
        }
        tracing::info!(id = %env.id, address = %rcpt, "smtp: bounce на адрес без BATV-метки");
        batv.enforce()
            .then(|| reply(550, [5, 7, 1], "Bad or missing BATV signature"))
    }

    /// Обработка письма отправки вне сессии SMTP до доставки и очереди: фильтры Milter исходящей почты
    /// (SMTP-27) из профиля политики организации (SMTP-40), правила потока (один раз на письмо) и переписывание
    /// отправителя. `Done` — судьба письма решена фильтром или правилом (отказ, удаление, задержано модерацией —
    /// SMTP-30, всем получателям `SubmitStatus::Queued`).
    async fn pre_submit(
        &self,
        id: &str,
        tenant: TenantId,
        user: Option<&Principal>,
        mail_from: &str,
        rcpts: &[String],
        mut raw: Bytes,
    ) -> Result<Pre> {
        // Ручная iTIP-обработка спам-письма (SMTP-55): отправка вне сессии (JMAP) — тот же отказ, что и
        // submission; письмо в «Спаме» — ответ на него не отправляется.
        if let Some(r) = self.junk_itip_refusal(user, &raw).await? {
            let step = Step::new(Ek::Reject, tracking::decision(&r), rcpts.to_vec())
                .reason(tracking::reason(&r));
            self.track(mail_from, tracking::message_id(&raw).as_deref(), vec![step])
                .await;
            return Ok(Pre::Done(SubmitStatus::Failed(tracking::reason(&r))));
        }
        let outbound = MilterDirection::Outbound;
        if let Some(m) = self.deps.milter.as_ref().filter(|m| m.applies(outbound)) {
            let profile = match &self.policies {
                Some(p) => p.resolve(tenant, None, None, None).await?.milter_profile,
                None => None,
            };
            let mail = milter::Mail {
                direction: outbound,
                id,
                client: None,
                login: None,
                mail_from,
                rcpts,
            };
            let out = m.check(&mail, raw, profile.as_deref()).await;
            let refused = match out.verdict {
                Verdict::Accept => out.quarantine.map(|reason| {
                    tracing::info!(%id, %reason, "smtp: письмо в карантине фильтра");
                    reply(550, [5, 7, 1], "Message held by content filter")
                }),
                Verdict::Refuse(r) => Some(r),
                Verdict::Discard => {
                    let step = Step::new(Ek::Receive, Dd::Discard, rcpts.to_vec());
                    self.track(
                        mail_from,
                        tracking::message_id(&out.message).as_deref(),
                        vec![step],
                    )
                    .await;
                    return Ok(Pre::Done(SubmitStatus::Delivered));
                }
            };
            if let Some(r) = refused {
                let step = Step::new(Ek::Reject, tracking::decision(&r), rcpts.to_vec())
                    .reason(tracking::reason(&r));
                self.track(
                    mail_from,
                    tracking::message_id(&out.message).as_deref(),
                    vec![step],
                )
                .await;
                return Ok(Pre::Done(SubmitStatus::Failed(tracking::reason(&r))));
            }
            raw = out.message;
        }
        let mut flowed_rcpts = None;
        let input = FlowInput {
            tenant,
            direction: FlowDirection::Submission,
            principal: user.cloned(),
            source: None,
            envelope: FlowEnvelope {
                mail_from: mail_from.to_owned(),
                rcpt_to: rcpts.to_vec(),
            },
            message: placeholder_blob(tenant),
        };
        let mut flowed_from = None;
        if let Some((outcome, body)) = self.mail_flow(input, &raw).await? {
            let mut moderate = None;
            let status = match outcome.verdict {
                FlowVerdict::Accept if !outcome.envelope.rcpt_to.is_empty() => None,
                FlowVerdict::Accept | FlowVerdict::Drop => Some(SubmitStatus::Delivered),
                FlowVerdict::Reject(text) => {
                    Some(SubmitStatus::Failed(format!("550 5.7.1 {}", clean(&text))))
                }
                FlowVerdict::Moderate { moderators } => {
                    moderate = Some(moderators);
                    None
                }
            };
            if !outcome.matched.is_empty() {
                let step = Step::new(Ek::Receive, Dd::Accept, rcpts.to_vec())
                    .reason(format!("mail flow rules: {}", outcome.matched.join(", ")));
                self.track(mail_from, tracking::message_id(&raw).as_deref(), vec![step])
                    .await;
            }
            if let Some(moderators) = moderate {
                // SMTP-30: письмо — в очередь модерации; отправке вне сессии SMTP — `Queued` (ждёт модерации).
                let rule = rule_name(&outcome.matched);
                let sender = self.sender_by_address(mail_from).await?;
                let held = self
                    .hold_by_rule(
                        tenant,
                        id,
                        &rule,
                        moderators,
                        &outcome.envelope.mail_from,
                        sender,
                        &outcome.envelope.rcpt_to,
                        &raw,
                    )
                    .await?;
                if held {
                    let step = Step::new(Ek::Deliver, Dd::Hold, outcome.envelope.rcpt_to.clone())
                        .reason(format!("held for moderation by flow rule: {rule}"));
                    self.track(mail_from, tracking::message_id(&raw).as_deref(), vec![step])
                        .await;
                    return Ok(Pre::Done(SubmitStatus::Queued));
                }
                return Ok(Pre::Done(SubmitStatus::Failed(
                    "451 4.7.0 moderation by mail flow rule is not available".into(),
                )));
            }
            if let Some(status) = status {
                return Ok(Pre::Done(status));
            }
            if let Some(body) = body {
                raw = body;
            }
            flowed_from = Some(outcome.envelope.mail_from);
            flowed_rcpts = Some(outcome.envelope.rcpt_to);
        }
        let rcpts = flowed_rcpts.as_deref().unwrap_or(rcpts);
        let mail_from = flowed_from.as_deref().unwrap_or(mail_from);
        let rewritten = self
            .rewrite(tenant, mail_from, EnvelopeSide::Sender)
            .await?;
        let mail_from = rewritten.as_deref().unwrap_or(mail_from);
        Ok(Pre::Go(Flowed {
            mail_from: mail_from.to_owned(),
            rcpts: rcpts.to_vec(),
            raw,
        }))
    }

    /// Доставка письма отправки после [`Delivery::pre_submit`]: локальным получателям — в ящики (группы, правила
    /// Sieve, пересылки), внешним — в очередь. `user` — вошедший пользователь отправки (CTR-82: субъект прав
    /// Send As / Send on Behalf приглашений, с группами; `None` — отправка без сеанса, выпуск отложенной отправки).
    /// Статус — по каждому адресу `rcpts`. `bounce` — уведомить отправителя
    /// о недоставленных; выпуск отложенной отправки ([`LocalRelease`]) уведомляет сам, по итогам записи очереди.
    #[allow(clippy::too_many_arguments)] // CTR-82: вошедший пользователь; конвенция репо (как apply_rules)
    async fn dispatch(
        &self,
        id: &str,
        owner: Option<AccountId>,
        user: Option<&Principal>,
        mail_from: &str,
        rcpts: &[String],
        raw: Bytes,
        bounce: bool,
    ) -> Result<Vec<(String, SubmitStatus)>> {
        let sender = self.sender_by_address(mail_from).await?;
        let filing = Filing::new(false, false, mail_from, &raw);
        let filing = &filing;
        // Отправка вне сессии SMTP — путь вошедшего (CTR-82): тип абонента — свой (SMTP-50).
        let peer = PeerKind::Own;
        // Отчёт о прочтении (MDN, RFC 8098) получателям с выключенной клеткой `mdn` не отправляется (SMTP-50);
        // события политики (MDN, запрещённая автопересылка) — в журнал доставки. MDN — служебное письмо
        // (SystemMessage, CTR-96): этапы правил конвейера его минуют, не журналируется (SMTP-53).
        let mut policy_steps = Vec::new();
        let system = pipeline::system_message(mail_from, dsn::is_mdn(&raw));
        let rcpts = if dsn::is_mdn(&raw) {
            let (org, _) = self.org_matrix().await?;
            let (allowed, steps) = self.mdn_rcpts(id, rcpts, &org).await?;
            policy_steps.extend(steps);
            allowed
        } else {
            rcpts.to_vec()
        };
        let mut prepared = self
            .prepare(id, &rcpts, filing, Origin::Sender(sender), peer)
            .await?;
        let received_at = OffsetDateTime::now_utc();
        self.hold_all(&prepared.held, mail_from, sender, &raw, received_at)
            .await?;
        let queue = self.deps.outbound.is_some();
        if !queue && !prepared.external.is_empty() {
            no_outbound(id, prepared.external.len());
        }
        let mut failed = prepared.failed;
        // Письмо локальным получателям — с заголовками трассировки; правила и пересылки — по нему.
        let full = if prepared.deliveries.is_empty() {
            raw.clone()
        } else {
            let mut full = self
                .submit_headers(id, mail_from, &rcpts, received_at)
                .into_bytes();
            full.extend_from_slice(&raw);
            Bytes::from(full)
        };
        let delivered = accounts_of(&prepared.deliveries);
        let mut forward = Vec::new();
        // Этап журналирования ядра (SMTP-53) — до модульных этапов и Sieve ящика (CTR-96): копия письма и
        // конверт по правилам организации, отправка — направление Out. Служебные письма не журналируются.
        if system.is_none() {
            self.journal_message(
                id,
                JournalDirection::Out,
                mail_from,
                &rcpts,
                &full,
                received_at,
            )
            .await?;
        }
        // Модульные этапы до Sieve ящика (SMTP-54): по каждому локальному получателю; отказ — всему письму
        // (статусы получателей ниже).
        for rcpt in local_rcpts(&prepared.deliveries) {
            if let Some(reason) = self
                .delivery_point(
                    PipelinePoint::BeforeMailboxSieve,
                    FlowDirection::Submission,
                    mail_from,
                    &rcpt,
                    &full,
                    None,
                    system,
                )
                .await?
            {
                tracing::info!(%id, %rcpt, %reason, "smtp: отправка отклонена этапом конвейера до Sieve");
                return Ok(self.refused(mail_from, &raw, &rcpts, &reason).await);
            }
        }
        let Sieved {
            redirect: hops,
            mut replies,
            steps: mut sieve_steps,
            org_failed,
            actions,
            ..
        } = self
            .apply_rules(
                id,
                mail_from,
                &full,
                &mut prepared.deliveries,
                &RuleContext::new(peer, false, &prepared.junk, &prepared.group),
                false,
                true,
                None,
            )
            .await?;
        // Сбой скрипта организации (SIEVE-14): доставка в обход скрипта невозможна — `SubmitStatus::Failed` с
        // временным отказом (SMTP-50), без уведомления (статус — у вызывающего).
        for rcpt in org_failed {
            failed.push(denied(rcpt, ORG_SCRIPT_FAILED));
        }
        // Точки после Sieve и итоговый контроль действий (SMTP-54): итоговый набор действий получателя по
        // `OrgPolicy` — запрет внешней пересылки перехватывает `redirect` из скрипта ящика; нарушение —
        // отказ отправке с причиной в журнале доставки. Служебные письма этапы правил минуют.
        for (rcpt, redirect) in &actions {
            let acts = ActionSet {
                redirect: redirect.clone(),
                copies: Vec::new(),
                recipients: rcpts.clone(),
            };
            let mut reason = self
                .delivery_point(
                    PipelinePoint::AfterMailboxSieve,
                    FlowDirection::Submission,
                    mail_from,
                    rcpt,
                    &full,
                    Some(acts.clone()),
                    system,
                )
                .await?;
            if reason.is_none() && system.is_none() {
                reason = self.final_action_check(&acts).await?;
            }
            if reason.is_none() {
                reason = self
                    .delivery_point(
                        PipelinePoint::FinalActionCheck,
                        FlowDirection::Submission,
                        mail_from,
                        rcpt,
                        &full,
                        Some(acts),
                        system,
                    )
                    .await?;
            }
            if let Some(reason) = reason {
                tracing::info!(%id, %rcpt, %reason, "smtp: отправка отклонена после Sieve");
                return Ok(self.refused(mail_from, &raw, &rcpts, &reason).await);
            }
        }
        let local_list = local_rcpts(&prepared.deliveries);
        let spam = junk_rcpts(&prepared.deliveries, &prepared.junk);
        // Приглашение из почтового клиента (решение 78) — от учётной записи отправителя конверта.
        let itip_to = itip_targets(
            sender.is_some() && self.itip.is_some(),
            &prepared.deliveries,
            &prepared.junk,
        );
        if !prepared.deliveries.is_empty() {
            let local: Vec<String> = prepared.deliveries.iter().map(|(r, _)| r.clone()).collect();
            match self
                .ingest_all(
                    id,
                    mail_from,
                    full.clone(),
                    prepared.deliveries,
                    received_at,
                    &mut failed,
                )
                .await
            {
                Ok(ingested) => push_unique(&mut forward, ingested.forward),
                // Все ящики переполнены: письмо принято отправкой, отправителю — уведомление.
                Err(Error::QuotaExceeded) => {
                    for r in local {
                        if !failed.iter().any(|f| f.address == r) {
                            failed.push(dsn::Recipient::new(
                                r,
                                dsn::Action::Failed,
                                "552 5.2.2 mailbox full",
                            ));
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        let itip_steps = match sender.filter(|_| !itip_to.is_empty()) {
            Some(account) => {
                let origin = ItipOrigin::Internal {
                    account,
                    principal: user,
                };
                self.apply_itip(id, &full, origin, &itip_to, &failed).await
            }
            None => Vec::new(),
        };
        let forward = self
            .forward(
                id,
                mail_from,
                &full,
                forward,
                filing,
                received_at,
                delivered,
                &mut policy_steps,
            )
            .await?;
        let relayed = self
            .relay(id, mail_from, hops, filing, received_at, None, peer)
            .await?;
        sieve::merge_replies(&mut replies, relayed.replies);
        sieve_steps.extend(relayed.steps);
        let statuses: Vec<(String, SubmitStatus)> = rcpts
            .iter()
            .map(|r| {
                let status =
                    if let Some(f) = failed.iter().find(|f| f.address.eq_ignore_ascii_case(r)) {
                        SubmitStatus::Failed(f.reply.clone())
                    } else if prepared.held.iter().any(|(x, _)| x.eq_ignore_ascii_case(r)) {
                        // Ждёт решения модератора группы.
                        SubmitStatus::Queued
                    } else if prepared.queued.iter().any(|x| x.eq_ignore_ascii_case(r)) {
                        if queue {
                            SubmitStatus::Queued
                        } else {
                            SubmitStatus::Failed(NO_OUTBOUND.into())
                        }
                    } else {
                        SubmitStatus::Delivered
                    };
                (r.clone(), status)
            })
            .collect();
        let mut out = if queue { prepared.external } else { Vec::new() };
        if queue {
            push_unique(&mut out, prepared.relayed);
        }
        self.queue_out(id, owner, mail_from, out, raw.clone())
            .await?;
        self.queue_forward(id, mail_from, forward, raw.clone(), None)
            .await?;
        let mut steps = vec![Step::new(Ek::Receive, Dd::Accept, rcpts.to_vec())];
        outcome_steps(&mut steps, &prepared.held, &local_list, &failed, &spam);
        steps.extend(itip_steps);
        steps.extend(sieve_steps);
        steps.extend(policy_steps);
        self.send_replies(id, mail_from, &full, replies, &mut steps)
            .await;
        // Уведомление — только о принятых и недоставленных (RFC 3464 §2), не по политике и не сбою скрипта
        // организации (SMTP-50: их статус — у вызывающего).
        let notified: Vec<dsn::Recipient> = failed.iter().filter(|f| f.notify).cloned().collect();
        if bounce && !notified.is_empty() && !mail_from.is_empty() {
            let sent = self
                .bounce(id, mail_from, &notified, &raw, received_at)
                .await;
            steps.push(dsn_step(mail_from, sent));
        }
        self.track(mail_from, tracking::message_id(&raw).as_deref(), steps)
            .await;
        tracing::info!(%id, count = rcpts.len(), "smtp: отправка вне сессии обработана");
        Ok(statuses)
    }

    /// Отказ этапа конвейера отправки вне сессии (SMTP-54): причина — в журнал доставки, всем получателям —
    /// `SubmitStatus::Failed` с тем же текстом (статус — у вызывающего, без уведомления).
    async fn refused(
        &self,
        mail_from: &str,
        raw: &[u8],
        rcpts: &[String],
        reason: &str,
    ) -> Vec<(String, SubmitStatus)> {
        let steps = vec![Step::new(Ek::Reject, Dd::Reject, rcpts.to_vec()).reason(clean(reason))];
        self.track(mail_from, tracking::message_id(raw).as_deref(), steps)
            .await;
        let line = format!("550 5.7.1 {}", clean(reason));
        rcpts
            .iter()
            .map(|r| (r.clone(), SubmitStatus::Failed(line.clone())))
            .collect()
    }

    /// Отправка от имени пользователя вне сессии SMTP (JMAP `EmailSubmission/set`, CMP-04): получатели в
    /// принятых доменах организации (адреса, псевдонимы и группы каталога)
    /// доставляются сразу через [`MailStore::ingest`] — как входящая почта, без очереди, MX, MTA-STS и DANE;
    /// внешние — в очередь исходящей почты ([`Deps::outbound`]) письмом `raw` без изменений. Пересылки модулей
    /// на локальные адреса — сразу в ящики, на внешние — в очередь.
    ///
    /// `user` — вошедший пользователь отправки (CTR-82, контракт [`Outbound::submit`]): по нему проверяется
    /// принадлежность `From` приглашения (права Send As / Send on Behalf с группами,
    /// [`Delivery::sender_right`]); `None` — отправка без сеанса (права проверил вызывающий).
    ///
    /// Неизвестный локальный адрес и переполненный ящик — статус [`SubmitStatus::Failed`] и уведомление о
    /// недоставке отправителю (как для входящей почты). Узел без очереди: внешние получатели —
    /// `SubmitStatus::Failed` с временной ошибкой [`NO_OUTBOUND`] без уведомления (статус получает отправитель),
    /// локальные доставляются. Ошибка хранилища, каталога или очереди — `Err`.
    /// Другая организация (`tenant` ≠ `Deps::tenant`) — все получатели в очередь, как до CMP-04 (без очереди —
    /// все `Failed`).
    ///
    /// Лимиты отправки ([`Delivery::with_send_limits`], SMTP-43): письмо учётной записи, превысившее за скользящий
    /// час `send_per_hour` писем или `rcpts_per_hour` адресатов, не отправляется — все получатели `Failed` с
    /// `451 4.7.1`, событие отказа — в журнал доставки.
    pub async fn submit(
        &self,
        tenant: TenantId,
        owner: Option<AccountId>,
        user: Option<&Principal>,
        mail_from: &str,
        rcpts: &[String],
        raw: Bytes,
    ) -> Result<Submitted> {
        if let Some(line) = self.over_send_limit(tenant, mail_from, rcpts, &raw).await? {
            return Ok(Submitted::all(rcpts, SubmitStatus::Failed(line)));
        }
        let id = crate::server::next_id();
        let requested = rcpts;
        let Flowed {
            mail_from,
            rcpts,
            raw,
        } = match self
            .pre_submit(&id, tenant, user, mail_from, rcpts, raw)
            .await?
        {
            Pre::Done(status) => return Ok(Submitted::all(requested, status)),
            Pre::Go(m) => m,
        };
        let (mail_from, rcpts) = (mail_from.as_str(), rcpts.as_slice());
        if tenant != self.deps.tenant {
            let status = match &self.deps.outbound {
                Some(q) => {
                    q.enqueue(tenant, owner, mail_from, rcpts, raw).await?;
                    SubmitStatus::Queued
                }
                None => {
                    no_outbound(&id, rcpts.len());
                    SubmitStatus::Failed(NO_OUTBOUND.into())
                }
            };
            return Ok(Submitted::all(requested, status));
        }
        let statuses = self
            .dispatch(&id, owner, user, mail_from, rcpts, raw, true)
            .await?;
        // Статус — по получателям запроса: адрес, убранный правилом потока, считается обработанным.
        let statuses = requested
            .iter()
            .map(|r| {
                let status = statuses
                    .iter()
                    .find(|(x, _): &&(String, SubmitStatus)| x.eq_ignore_ascii_case(r))
                    .map_or(SubmitStatus::Delivered, |(_, s)| s.clone());
                (r.clone(), status)
            })
            .collect();
        Ok(Submitted { rcpts: statuses })
    }

    /// Лимиты отправки в час вне сессии SMTP ([`Delivery::with_send_limits`], SMTP-43) — для [`Delivery::submit`] и
    /// [`Delivery::schedule`]: отправитель `mail_from` — учётная запись организации узла, письмо — `send_per_hour`
    /// писем и `rcpts_per_hour` адресатов её политики за скользящий час. Допущенное письмо учитывается сразу (до
    /// отправки или постановки). Превышен предел — ответ `451 4.7.1` и событие отказа в журнале доставки. Без
    /// лимитов, для другой организации и внешнего отправителя — без ограничения.
    async fn over_send_limit(
        &self,
        tenant: TenantId,
        mail_from: &str,
        rcpts: &[String],
        raw: &Bytes,
    ) -> Result<Option<String>> {
        let Some(l) = &self.send_limits else {
            return Ok(None);
        };
        if tenant != self.deps.tenant {
            return Ok(None);
        }
        let Some(account) = self.sender_by_address(mail_from).await? else {
            return Ok(None);
        };
        let policy = self.account_policy(tenant, account).await?;
        let key = account.to_string();
        let now = Instant::now();
        let exceeded = if !l.allow_message_at(policy.send_per_hour_or_default(), &key, now) {
            limits::MESSAGES_EXCEEDED
        } else if !l.allow_rcpts_at(policy.rcpts_per_hour_or_default(), &key, rcpts.len(), now) {
            limits::RCPTS_EXCEEDED
        } else {
            l.record_at(self.max_tracked, &key, rcpts.len(), now);
            return Ok(None);
        };
        let line = format!("451 4.7.1 {exceeded}");
        let step = Step::new(Ek::Reject, Dd::Defer, rcpts.to_vec()).reason(line.clone());
        self.track(mail_from, tracking::message_id(raw).as_deref(), vec![step])
            .await;
        tracing::info!(
            rcpts = rcpts.len(),
            "smtp: отправка вне сессии отклонена лимитом в час"
        );
        Ok(Some(line))
    }

    /// Правила Sieve получателей письма `raw` (SMTP-31): доставка с адресом получателя заменяется доставками в папки
    /// правил (несколько папок — несколько доставок одного `ingest`; `discard` и `redirect` без копии — ни одной);
    /// копии модулей (без адреса) — без правил. Сбой правил — доставка в папку по умолчанию («Входящие», при
    /// `junk` — «Спам»). Письмо со спам-вердиктом получателя — мимо всех автоматических механизмов (SMTP-55):
    /// правила не выполняются, письмо — в «Спаме», и только. Возвращает перенаправления, автоответы (не для писем
    /// в «Спам» и по матрице доверия) и события журнала.
    ///
    /// Матрица доверия (SMTP-50): правила получают тип абонента `ctx.peer` и действующую матрицу получателя
    /// ([`TrustStore::effective_for`]); автоответ чужим — только при включённой клетке `auto_reply`, письмо в
    /// группу — без автоответа участников; `redirect` на внешний адрес — только при включённой автопересылке,
    /// запрещённое перенаправление не отменяет доставку в ящик. Сбой скрипта организации (SIEVE-14) —
    /// [`Sieved::org_failed`]: сессия даёт `451 4.3.0` (`session`), вне сессии письмо — во «Входящих», как при
    /// сбое скрипта пользователя.
    ///
    /// Петля перенаправлений (SMTP-34, [`crate::sieve`]): ящик уже есть в цепочке письма, цепочка длиннее
    /// `delivery.redirect_hops` или исчерпан `delivery.redirect_total` (`over`) — правила ящика не применяются,
    /// письмо — в папку по умолчанию, запись в журнал доставки.
    #[allow(clippy::too_many_arguments)] // конвенция репо (как у `forward`)
    #[allow(clippy::too_many_arguments)] // вердикт каталога признаков письма (SMTP-52); конвенция репо
    async fn apply_rules(
        &self,
        id: &str,
        mail_from: &str,
        raw: &Bytes,
        deliveries: &mut Vec<(String, MailDelivery)>,
        ctx: &RuleContext<'_>,
        over: bool,
        session: bool,
        risk_scan: Option<&risk::Scan>,
    ) -> Result<Sieved> {
        let mut out = Sieved::default();
        let Some(rules) = &self.rules else {
            return Ok(out);
        };
        let chain = sieve::chain(raw);
        let (_, domains) = self.org_matrix().await?;
        let mut result = Vec::with_capacity(deliveries.len());
        for (rcpt, d) in std::mem::take(deliveries) {
            if rcpt.is_empty() {
                result.push((rcpt, d));
                continue;
            }
            if ctx.junk.contains(&d.account) {
                // Спам — максимально рано мимо всех автоматических механизмов (SMTP-55, решение #112):
                // письмо лежит в «Спаме», и никакие действия правил к нему не применяются — ни папки и флаги,
                // ни отброс, ни перенаправление, ни автоответ, ни `processcalendar` (автоответ, перенаправление
                // и приём iTIP уже гасились вердиктом в SMTP-50); будущие действия гасятся здесь же.
                tracing::info!(%id, account = %d.account, "smtp: письмо в «Спаме» — правила получателя не применяются");
                out.steps.push(
                    Step::new(Ek::Deliver, Dd::Accept, vec![rcpt.clone()])
                        .reason("sieve: rules skipped, junk; junk folder"),
                );
                result.push((rcpt, d));
                continue;
            }
            let token = sieve::chain_token(d.account);
            let looped = if chain.contains(&token) {
                Some("mailbox already in redirect chain")
            } else if chain.len() > self.redirect_hops as usize {
                Some("redirect hop limit")
            } else if over {
                Some("redirect limit per message")
            } else {
                None
            };
            if let Some(why) = looped {
                tracing::info!(%id, account = %d.account, reason = why, "smtp: петля перенаправлений, правила Sieve не применены");
                out.steps.push(
                    Step::new(Ek::Deliver, Dd::Accept, vec![rcpt.clone()])
                        .reason(format!("sieve: rules skipped, {why}; default folder")),
                );
                result.push((rcpt, d));
                continue;
            }
            let scope = AccountScope {
                tenant: self.deps.tenant,
                account: d.account,
            };
            let input = RulesInput {
                scope,
                recipient: rcpt.clone(),
                mail_from: mail_from.to_owned(),
                message: raw.clone(),
                mailboxes: self.deps.mailboxes.list(scope).await?,
                // Тип абонента — от пути письма (CTR-93, SMTP-50): заголовкам письма не доверяем
                // (RFC 8601 §5, RFC 5183); матрица — действующая для получателя. Признак «ответ на
                // наше письмо» ставит SMTP-51 по записи об отправленном (CTR-94): клетки `ReplyOnly`
                // (автоответ, MDN) между `Off` и `On` открываются только им.
                peer: PeerContext {
                    kind: ctx.peer,
                    reply: ctx.reply,
                },
                matrix: self.matrix_for(scope).await,
                // Вердикт справочника аномалий до Sieve и факт доверенной беседы (CTR-95, решение 126 д):
                // детекторы и балл — SMTP-52 по действующему каталогу организации и памяти беседы
                // ([`crate::risk`]); вне smtp-in — без срабатываний. Беседа доверенная — у получателя
                // есть письма в беседе (память непуста); признак ответа — [`PeerContext::reply`].
                risk: risk_scan
                    .map(|s| s.verdict_for(scope.tenant))
                    .unwrap_or_default(),
                thread_trusted: risk_scan.is_some_and(|s| s.trusted.contains(&d.account)),
            };
            let mut notes = Vec::new();
            let outcome = match rules.evaluate(&input).await {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!(%id, account = %d.account, error = %e, "smtp: правила Sieve не выполнены, доставка во «Входящие»");
                    notes.push(format!("rules failed ({e}), default folder"));
                    RulesOutcome::implicit_keep()
                }
            };
            if !outcome.errors.is_empty() {
                tracing::info!(%id, account = %d.account, count = outcome.errors.len(), "smtp: ошибки выполнения правил Sieve");
                notes.push(format!("errors: {}", outcome.errors.join("; ")));
            }
            // Признаки `signal` скрипта организации (SIEVE-15) — каталогу письма (SMTP-52): без повторов
            // (скрипт организации один на получателей).
            for s in outcome.signals {
                if !out.signals.iter().any(|(id, _)| id == &s.0) {
                    out.signals.push(s);
                }
            }
            // Сбой скрипта организации (SIEVE-14): в обход скрипта доставка невозможна — временный отказ (SMTP-50).
            if outcome
                .errors
                .iter()
                .any(|e| e.starts_with(ORG_SCRIPT_ERROR))
            {
                tracing::warn!(%id, account = %d.account, "smtp: сбой скрипта организации — письмо не доставляется");
                if session {
                    out.steps.push(
                        Step::new(Ek::Deliver, Dd::Defer, vec![rcpt.clone()])
                            .reason("sieve: org script failed"),
                    );
                    out.org_failed.push(rcpt);
                    continue;
                }
                notes.push("org script failed, default folder".into());
            }
            if outcome.calendar.is_some() {
                // Итог `processcalendar` правил (CTR-93): передаётся приёму iTIP (SMTP-50) — виден в журнале
                // доставки; вносит приглашение не шире матрицы получателя приём (DAV-44).
                notes.push("processcalendar".into());
            }
            let mut kept: Vec<MailDelivery> = Vec::new();
            for keep in &outcome.keep {
                let mailbox = self
                    .keep_mailbox(id, scope, &input.mailboxes, &keep.mailbox, d.mailbox)
                    .await;
                match &keep.mailbox {
                    MailboxRef::Inbox => {}
                    MailboxRef::Id(m) => notes.push(format!("fileinto mailbox {m}")),
                    MailboxRef::Name { name, .. } => {
                        notes.push(format!("fileinto {}", clean(name)))
                    }
                }
                if let Some(k) = kept.iter_mut().find(|k| k.mailbox == mailbox) {
                    k.flags.extend(keep.flags.iter().cloned());
                    continue;
                }
                kept.push(MailDelivery {
                    account: d.account,
                    mailbox,
                    extra_headers: d.extra_headers.clone(),
                    flags: keep.flags.clone(),
                });
            }
            if outcome.discard {
                notes.push("discard".into());
            }
            // Перенаправления: внешние адреса — автопересылка (решение 124 г), запрещённые политикой не
            // выполняются; письмо (без копии) остаётся в ящике.
            let mut redirect = Vec::new();
            let mut skipped = Vec::new();
            for to in outcome.redirect {
                if self
                    .forward_to(&input.matrix, &domains, &to)
                    .await
                    .unwrap_or_else(|e| {
                        tracing::warn!(%id, address = %to, error = %e, "smtp: автопересылка не проверена — не выполняется");
                        false
                    })
                {
                    redirect.push(to);
                } else {
                    skipped.push(to);
                }
            }
            // Итоговые действия получателя (SMTP-54): перенаправления — этапам после Sieve и итоговому контролю.
            out.actions.push((rcpt.clone(), redirect.clone()));
            let redirected = !redirect.is_empty();
            if redirected {
                notes.push(format!("redirect {}", redirect.join(", ")));
                out.redirect.push(Hop {
                    raw: sieve::stamp(raw, &token),
                    to: redirect,
                });
            }
            if !skipped.is_empty() {
                tracing::info!(%id, account = %d.account, "smtp: перенаправление наружу не выполнено — политика автопересылки");
                notes.push(format!(
                    "redirect skipped by policy: {}",
                    skipped.join(", ")
                ));
            }
            if kept.is_empty() && !redirected && !outcome.discard && !skipped.is_empty() {
                // Единственное перенаправление запрещено — письмо остаётся в ящике (implicit keep).
                kept.push(MailDelivery {
                    account: d.account,
                    mailbox: d.mailbox,
                    extra_headers: d.extra_headers.clone(),
                    flags: Default::default(),
                });
            }
            match outcome.vacation {
                Some(_) if ctx.junk.contains(&d.account) => {
                    notes.push("auto-reply skipped: junk".into())
                }
                // Клетка auto_reply для типа абонента; ReplyOnly решает признак ответа на наше
                // письмо (CTR-94, решение 125 а) — его ставит SMTP-51, до неё — нет ответа.
                Some(_)
                    if input
                        .matrix
                        .effective(TrustFunction::AutoReply, &PeerContext::new(ctx.peer))
                        != CellValue::Toggle(Toggle::On) =>
                {
                    notes.push("auto-reply skipped: policy".into())
                }
                Some(_) if ctx.group.contains(&d.account) => {
                    // Письмо пришло в группу рассылки: участники отправителю не отвечают (SMTP-50, RFC 3834 §2).
                    notes.push("auto-reply skipped: mailing group".into())
                }
                Some(reply) => out.replies.push((scope, reply)),
                None => {}
            }
            if kept.is_empty() && notes.is_empty() {
                notes.push("no delivery".into());
            }
            if !notes.is_empty() {
                let decision = if kept.is_empty() && !redirected {
                    Dd::Discard
                } else {
                    Dd::Accept
                };
                out.steps.push(
                    Step::new(Ek::Deliver, decision, vec![rcpt.clone()])
                        .reason(format!("sieve: {}", notes.join("; "))),
                );
            }
            result.extend(kept.into_iter().map(|k| (rcpt.clone(), k)));
        }
        *deliveries = result;
        Ok(out)
    }

    /// Перенаправления правил и внутренние автоответы (SMTP-34, решение 61): письмо каждого перенаправления
    /// доставляется как любое письмо — локальным адресатам через их правила (их перенаправления — так же, пока
    /// цепочка не оборвётся: [`Delivery::apply_rules`]), внешним — в очередь с SRS и ARC. `peer` — тип абонента
    /// исходного отправителя (SMTP-50): правила получателя перенаправления видят то же письмо; внутренний
    /// автоответ — от своей учётной записи. Неизвестный адрес и переполненный ящик — только в журнал. Возвращает
    /// автоответы и события журнала доставки.
    #[allow(clippy::too_many_arguments)] // peer — тип абонента письма (SMTP-50); конвенция репо (как у `forward`)
    async fn relay(
        &self,
        id: &str,
        mail_from: &str,
        hops: Vec<Hop>,
        filing: &Filing,
        received_at: OffsetDateTime,
        ip: Option<std::net::IpAddr>,
        peer: PeerKind,
    ) -> Result<Sieved> {
        let mut out = Sieved::default();
        let mut hops = VecDeque::from(hops);
        let mut done = 0u32;
        while let Some(hop) = hops.pop_front() {
            let over = done >= self.redirect_total;
            done = done.saturating_add(1);
            let mut p = self
                .prepare(id, &hop.to, filing, Origin::Module, peer)
                .await?;
            let mut external = std::mem::take(&mut p.external);
            push_unique(&mut external, std::mem::take(&mut p.relayed));
            let delivered = accounts_of(&p.deliveries);
            let mut hop_steps = Vec::new();
            let sieved = self
                .apply_rules(
                    id,
                    mail_from,
                    &hop.raw,
                    &mut p.deliveries,
                    &RuleContext::new(peer, false, &p.junk, &p.group),
                    over,
                    false,
                    None,
                )
                .await?;
            if !p.deliveries.is_empty() {
                let mut ignored = Vec::new();
                match self
                    .ingest_all(
                        id,
                        mail_from,
                        hop.raw.clone(),
                        p.deliveries,
                        received_at,
                        &mut ignored,
                    )
                    .await
                {
                    Ok(ingested) => {
                        let more = self
                            .forward(
                                id,
                                mail_from,
                                &hop.raw,
                                ingested.forward,
                                filing,
                                received_at,
                                delivered,
                                &mut hop_steps,
                            )
                            .await?;
                        push_unique(&mut external, more);
                    }
                    Err(Error::QuotaExceeded) => {
                        tracing::warn!(%id, "smtp: перенаправление не доставлено, ящики переполнены");
                    }
                    Err(e) => return Err(e),
                }
            }
            self.queue_forward(id, mail_from, external, hop.raw, ip)
                .await?;
            hops.extend(sieved.redirect);
            sieve::merge_replies(&mut out.replies, sieved.replies);
            out.steps.extend(sieved.steps);
            out.steps.extend(hop_steps);
        }
        Ok(out)
    }

    /// Папка доставки правила: `Inbox` — папка по умолчанию `default` («Входящие» или «Спам»); неизвестная папка без
    /// `:create`, чужая папка и сбой создания — тоже она.
    async fn keep_mailbox(
        &self,
        id: &str,
        scope: AccountScope,
        list: &[Mailbox],
        target: &MailboxRef,
        default: MailboxId,
    ) -> MailboxId {
        match target {
            MailboxRef::Inbox => default,
            MailboxRef::Id(m) if list.iter().any(|x| x.id == *m) => *m,
            MailboxRef::Id(_) => default,
            MailboxRef::Name { name, create } => {
                if let Some(m) = sieve::find_path(list, name) {
                    return m;
                }
                if !*create {
                    return default;
                }
                match sieve::create_path(self.deps.mailboxes.as_ref(), scope, list, name).await {
                    Ok(Some(m)) => m,
                    Ok(None) => default,
                    Err(e) => {
                        tracing::warn!(%id, error = %e, "smtp: папка правила Sieve не создана, доставка в папку по умолчанию");
                        default
                    }
                }
            }
        }
    }

    /// Автоответы правил на письмо `raw` от `mail_from` (SMTP-32): защита от петель RFC 3834
    /// ([`sieve::suppressed`]) и частота `delivery.vacation_rate`, затем письмо [`sieve::build_reply`] с конвертом
    /// `<>`: внешнему адресату — в очередь, локальному — через его правила ([`Delivery::relay`]). Сбой — только в
    /// журналы: исходное письмо уже доставлено.
    async fn send_replies(
        &self,
        id: &str,
        mail_from: &str,
        raw: &[u8],
        replies: Vec<(AccountScope, AutoReply)>,
        steps: &mut Vec<Step>,
    ) {
        for (n, (scope, reply)) in replies.into_iter().enumerate() {
            let step = |decision, reason: String| {
                Step::new(Ek::Receive, decision, vec![reply.to.clone()])
                    .sender("")
                    .reason(reason)
            };
            let skip = sieve::suppressed(mail_from, raw, &reply)
                .or_else(|| (!self.vacation_rate.allow(scope.account)).then_some("rate limit"));
            if let Some(why) = skip {
                tracing::info!(%id, account = %scope.account, reason = why, "smtp: автоответ не отправлен");
                steps.push(step(Dd::Discard, format!("auto-reply suppressed: {why}")));
                continue;
            }
            let msg = sieve::build_reply(
                &reply,
                &self.hostname,
                &format!("{id}.{n}"),
                OffsetDateTime::now_utc(),
            );
            match self
                .deliver_reply(id, scope.account, &reply.to, Bytes::from(msg))
                .await
            {
                Ok((how, more)) => {
                    steps.push(step(Dd::Accept, format!("auto-reply {how}")));
                    steps.extend(more);
                }
                Err(e) => {
                    tracing::warn!(%id, account = %scope.account, error = %e, "smtp: автоответ не отправлен");
                    steps.push(step(Dd::Defer, format!("auto-reply not sent: {e}")));
                }
            }
        }
    }

    /// Письмо автоответа `raw` учётной записи `from` адресату `to` с конвертом `<>`: локальному — как любое письмо,
    /// через его правила (в цепочке перенаправлений — ящик отвечающего: вернуть ему ответ правилом можно, но его
    /// правила к ответу не применяются; на автоответ не отвечают), внешнему — в очередь исходящей почты. Возвращает,
    /// куда отправлено, и события журнала доставки правил получателя.
    async fn deliver_reply(
        &self,
        id: &str,
        from: AccountId,
        to: &str,
        raw: Bytes,
    ) -> Result<(&'static str, Vec<Step>)> {
        match self.resolve(to).await? {
            Resolved::Local(_) => {
                let hop = Hop {
                    raw: sieve::stamp(&raw, &sieve::chain_token(from)),
                    to: vec![to.to_owned()],
                };
                let filing = Filing::new(false, false, "", &hop.raw);
                // Автоответ — от учётной записи организации: тип абонента для правил получателя — свой.
                let sieved = self
                    .relay(
                        id,
                        "",
                        vec![hop],
                        &filing,
                        OffsetDateTime::now_utc(),
                        None,
                        PeerKind::Own,
                    )
                    .await?;
                Ok(("delivered", sieved.steps))
            }
            Resolved::External if self.deps.outbound.is_some() => {
                self.send_dsn(self.deps.tenant, to, raw).await?;
                Ok(("queued", Vec::new()))
            }
            Resolved::External => Err(Error::UNAVAILABLE),
            Resolved::Unknown => Err(Error::NotFound),
        }
    }

    /// Заголовки трассировки письма, отправленного вне сессии SMTP ([`Delivery::submit`]).
    fn submit_headers(
        &self,
        id: &str,
        mail_from: &str,
        rcpts: &[String],
        received_at: OffsetDateTime,
    ) -> String {
        let date = mail_builder::headers::date::Date::new(received_at.unix_timestamp()).to_rfc822();
        let mut h = format!(
            "Return-Path: <{}>\r\nReceived: by {} (The Post) id {id}",
            clean(mail_from),
            self.hostname,
        );
        if let [rcpt] = rcpts {
            h.push_str(&format!("\r\n\tfor <{}>", clean(rcpt)));
        }
        h.push_str(&format!(";\r\n\t{date}\r\n"));
        h
    }
}

/// Отправка через [`Delivery`]: локальные получатели — сразу в ящики, внешние — в очередь (CMP-04).
/// Приложение подключает её вместо [`crate::queue::Queue`] для JMAP `EmailSubmission/set`.
#[async_trait]
impl Outbound for Delivery {
    async fn enqueue(
        &self,
        tenant: TenantId,
        owner: Option<AccountId>,
        mail_from: &str,
        rcpts: &[String],
        raw: Bytes,
    ) -> Result<()> {
        let sent = Delivery::submit(self, tenant, owner, None, mail_from, rcpts, raw).await?;
        // Узел без очереди и ни одной доставки: письмо никуда не попало — ошибка, повтор безопасен.
        // Иначе внешним получателям — только `Failed` в журнале (повтор задвоил бы локальную доставку).
        let lost = |s: &SubmitStatus| matches!(s, SubmitStatus::Failed(r) if r == NO_OUTBOUND);
        if !sent.rcpts.is_empty() && sent.rcpts.iter().all(|(_, s)| lost(s)) {
            return Err(Error::UNAVAILABLE);
        }
        Ok(())
    }

    async fn submit(
        &self,
        tenant: TenantId,
        owner: Option<AccountId>,
        user: Option<&Principal>,
        mail_from: &str,
        rcpts: &[String],
        raw: Bytes,
    ) -> Result<Submitted> {
        Delivery::submit(self, tenant, owner, user, mail_from, rcpts, raw).await
    }

    async fn schedule(
        &self,
        tenant: TenantId,
        owner: Option<AccountId>,
        mail_from: &str,
        rcpts: &[String],
        raw: Bytes,
        release_at: OffsetDateTime,
    ) -> Result<QueueId> {
        Delivery::schedule(self, tenant, owner, mail_from, rcpts, raw, release_at).await
    }

    async fn cancel_scheduled(&self, tenant: TenantId, queue: QueueId) -> Result<()> {
        Delivery::cancel_scheduled(self, tenant, queue).await
    }
}

/// Статус внешнего получателя [`Delivery::submit`] на узле без очереди исходящей почты (временная ошибка).
pub const NO_OUTBOUND: &str = "451 4.3.0 outbound queue unavailable";

/// Внешние получатели на узле без очереди исходящей почты — в журнал.
fn no_outbound(id: &str, count: usize) {
    tracing::warn!(
        %id,
        count,
        "smtp: очередь исходящей почты не подключена, внешним адресам отправка недоступна"
    );
}

/// Учётные записи доставок.
fn accounts_of(deliveries: &[(String, MailDelivery)]) -> HashSet<AccountId> {
    deliveries.iter().map(|(_, d)| d.account).collect()
}

/// Дописывает адреса `more` в `list` без повторов (регистр не учитывается).
fn push_unique(list: &mut Vec<String>, more: Vec<String>) {
    for a in more {
        if !list.iter().any(|x| x.eq_ignore_ascii_case(&a)) {
            list.push(a);
        }
    }
}

/// Уведомление о доставке: локальному адресату — во «Входящие», внешнему — в очередь исходящей почты.
#[async_trait]
impl DsnSink for Delivery {
    async fn send_dsn(&self, tenant: TenantId, to: &str, raw: Bytes) -> Result<()> {
        match self.resolve(to).await? {
            Resolved::Local(accounts) => {
                let mut deliveries = Vec::new();
                for acc in accounts {
                    let scope = AccountScope {
                        tenant: acc.tenant,
                        account: acc.id,
                    };
                    deliveries.push(MailDelivery {
                        account: acc.id,
                        mailbox: self.mailbox(scope, false).await?,
                        extra_headers: Vec::new(),
                        flags: Default::default(),
                    });
                }
                self.deps
                    .store
                    .ingest(IngestRequest {
                        tenant,
                        mail_from: String::new(),
                        raw: Box::pin(futures::stream::once(async move { Ok(raw) })),
                        deliveries,
                        received_at: OffsetDateTime::now_utc(),
                    })
                    .await
                    .map(|_| ())
            }
            Resolved::External => match &self.deps.outbound {
                Some(q) => q.enqueue(tenant, None, "", &[to.to_owned()], raw).await,
                None => {
                    tracing::warn!(
                        "smtp: уведомление внешнему адресу без очереди исходящей почты не отправлено"
                    );
                    Ok(())
                }
            },
            Resolved::Unknown => {
                tracing::warn!("smtp: адресат уведомления о доставке не найден");
                Ok(())
            }
        }
    }
}

#[async_trait]
impl Handler for Delivery {
    async fn policy(&self, principal: &Principal) -> Result<Policy> {
        self.account_policy(principal.tenant, principal.account)
            .await
    }

    async fn sender(&self, env: &Envelope) -> Option<Reply> {
        let core = match self.check_mail_from(env).await {
            Ok(r) => r,
            Err(e) => Some(temporary(&e)),
        };
        // Точка MailFrom конвейера (SMTP-54): модульные этапы — условия по конверту, отказ всему письму
        // (проверки сессии ядра уже отработали).
        let r = match core {
            Some(r) => Some(r),
            None => {
                self.envelope_point(PipelinePoint::MailFrom, env, None)
                    .await
            }
        };
        if let Some(r) = &r {
            let step = Step::new(Ek::Reject, tracking::decision(r), Vec::new())
                .reason(tracking::reason(r));
            self.track(&env.mail_from, None, vec![step]).await;
        }
        r
    }

    async fn limited(&self, env: &Envelope, reply: &Reply) {
        let step = Step::new(Ek::Reject, tracking::decision(reply), env.rcpts.clone())
            .reason(tracking::reason(reply));
        self.track(&env.mail_from, None, vec![step]).await;
    }

    async fn rcpt(&self, env: &Envelope, rcpt: &str) -> Reply {
        let r = self.check_rcpt(env, rcpt).await;
        if !is_positive(&r) {
            let step = Step::new(Ek::Reject, tracking::decision(&r), vec![rcpt.to_owned()])
                .reason(tracking::reason(&r));
            self.track(&env.mail_from, None, vec![step]).await;
        }
        r
    }

    async fn data(&self, env: &Envelope, raw: Bytes) -> Reply {
        let mut trail = Trail::default();
        let r = match self.accept(env, raw, &mut trail).await {
            Ok(Some(r)) => r,
            Ok(None) => reply(250, [2, 0, 0], format!("OK id={}", env.id)),
            Err(Error::QuotaExceeded) => reply(552, [5, 2, 2], "Mailbox full"),
            Err(Error::Invalid(m)) => {
                tracing::info!(id = %env.id, error = %m, "smtp: письмо отклонено");
                reply(554, [5, 6, 0], "Message rejected")
            }
            Err(Error::Forbidden) => reply(554, [5, 7, 1], "Message rejected"),
            Err(e) => temporary(&e),
        };
        if self.tracking.is_some() {
            let head = if is_positive(&r) {
                Step::new(
                    Ek::Receive,
                    trail.decision.unwrap_or(Dd::Accept),
                    env.rcpts.clone(),
                )
            } else {
                Step::new(Ek::Reject, tracking::decision(&r), env.rcpts.clone())
                    .reason(tracking::reason(&r))
            };
            let mut steps = vec![head];
            steps.append(&mut trail.steps);
            self.track(&env.mail_from, trail.message_id.as_deref(), steps)
                .await;
        }
        r
    }
}

impl Delivery {
    /// Проверка получателя до ответа `250` (SRS 4.1): существование, группа рассылки, квота; затем точка
    /// `RcptTo` конвейера (SMTP-54) — модульные этапы по конверту, отказ — отдельному получателю.
    async fn check_rcpt(&self, env: &Envelope, rcpt: &str) -> Reply {
        let core = self.check_rcpt_core(env, rcpt).await;
        self.rcpt_point(env, rcpt, core).await
    }

    /// Проверки ядра получателя (SMTP-54: точка `RcptTo` конвейера после них).
    async fn check_rcpt_core(&self, env: &Envelope, rcpt: &str) -> Reply {
        let queue_ok = || {
            if self.deps.outbound.is_some() {
                reply(250, [2, 1, 5], "OK")
            } else {
                reply(451, [4, 3, 2], "Outbound delivery not available")
            }
        };
        // BATV (SMTP-51): метка валидного bounce-адреса снимается; невалидная (чужой ключ, просрочена,
        // подделка) у bounce — `550 5.7.1` в `enforce`, в `log` — журнал и метрика (адрес дальше не разрешится).
        let (rcpt, marked) = match self.batv_rcpt_of(env, rcpt).await {
            Ok(pair) => pair,
            Err(r) => return r,
        };
        match self.srs_reverse(&rcpt).await {
            Ok(Some(Ok(_))) => return queue_ok(),
            Ok(Some(Err(e))) => {
                tracing::info!(id = %env.id, error = %e, "smtp: адрес SRS отклонён");
                return reply(550, [5, 1, 1], "Bad SRS address");
            }
            Ok(None) => {}
            Err(e) => return temporary(&e),
        }
        let target = match self.target(&rcpt).await {
            Ok(t) => t,
            Err(e) => return temporary(&e),
        };
        // Bounce на локальный адрес без метки BATV (SMTP-51): отказ в `enforce`, журнал в `log`.
        if let Some(r) = self
            .batv_check_rcpt(
                env,
                &rcpt,
                matches!(target.resolved, Resolved::Local(_)),
                marked,
            )
            .await
        {
            return r;
        }
        if target.foreign {
            tracing::warn!(id = %env.id, "smtp: принятый домен другой организации на этом узле не обслуживается");
            return reply(451, [4, 3, 0], "Domain not served by this node");
        }
        if target.relay {
            return queue_ok();
        }
        let app = sources::application(env.source.as_deref());
        if let Some((s, _)) = app
            && s.tenant != Some(self.deps.tenant)
        {
            tracing::warn!(id = %env.id, source = %s.name, "smtp: источник-приложение другой организации");
            return reply(451, [4, 3, 0], "Source not served by this node");
        }
        if let Some(group) = &target.group {
            let sender = sender_account(env, self.deps.tenant);
            match self.group_allows(group, sender).await {
                Ok(true) => {}
                Ok(false) => {
                    tracing::info!(id = %env.id, group = %group.id, "smtp: отправитель вне круга группы рассылки");
                    return reply(550, [5, 7, 1], "Sender not allowed to send to this group");
                }
                Err(e) => return temporary(&e),
            }
            // Матрица доверия (SMTP-50, решение 124 г): письма в группу — по типу отправителя. До `DATA` письма
            // нет — тип по домену конверта (партнёр предположительно), `DATA` перепроверит по `From` и DMARC.
            // Ограничения отправителей группы сужают и дальше.
            let peer = match self.rcpt_peer(env).await {
                Ok(peer) => peer,
                Err(e) => return temporary(&e),
            };
            match self.post_action(Some(group), peer).await {
                Ok(PostAction::Deny) => {
                    tracing::info!(id = %env.id, group = %group.id, %peer, "smtp: группа закрыта для типа абонента");
                    return reply(550, [5, 7, 1], "Sender not allowed to send to this group");
                }
                // Письмо ждёт решения модератора: квоты членов не проверяются.
                Ok(PostAction::Hold) => return reply(250, [2, 1, 5], "OK"),
                Ok(PostAction::Pass) => {}
                Err(e) => return temporary(&e),
            }
            // Письмо модерируемой группы ждёт решения модератора: квоты членов не проверяются.
            if group.requires_moderation(sender) {
                return reply(250, [2, 1, 5], "OK");
            }
        } else if target.mailing {
            // Группа каталога без записи в [`Groups`]: только матрица; `Moderated` без модераторов — отказ.
            let peer = match self.rcpt_peer(env).await {
                Ok(peer) => peer,
                Err(e) => return temporary(&e),
            };
            match self.post_action(None, peer).await {
                Ok(PostAction::Pass) => {}
                Ok(_) => {
                    tracing::info!(id = %env.id, address = %rcpt, %peer, "smtp: группа закрыта для типа абонента");
                    return reply(550, [5, 7, 1], "Sender not allowed to send to this group");
                }
                Err(e) => return temporary(&e),
            }
        }
        match target.resolved {
            Resolved::Local(accounts) => {
                if let Some(quota) = &self.deps.quota {
                    for acc in &accounts {
                        let scope = AccountScope {
                            tenant: acc.tenant,
                            account: acc.id,
                        };
                        match quota.check(scope, 0).await {
                            Ok(()) => {}
                            Err(Error::QuotaExceeded)
                                if accounts.len() == 1 && target.group.is_none() =>
                            {
                                return match self.cfg.quota_reject {
                                    QuotaReject::Temporary => reply(452, [4, 2, 2], "Mailbox full"),
                                    QuotaReject::Permanent => reply(552, [5, 2, 2], "Mailbox full"),
                                };
                            }
                            // Группа: переполненный ящик одного члена не отклоняет адрес.
                            Err(Error::QuotaExceeded) => {}
                            Err(e) => return temporary(&e),
                        }
                    }
                }
                reply(250, [2, 1, 5], "OK")
            }
            // Приложение: внешние получатели — только по разрешению источника.
            Resolved::External if app.is_some_and(|(_, external)| !external) => {
                reply(550, [5, 7, 1], "Relaying denied for this source")
            }
            Resolved::External if app.is_some() => queue_ok(),
            Resolved::External => match env.mode {
                Mode::Inbound => reply(550, [5, 7, 1], "Relaying denied"),
                Mode::Submission if self.deps.outbound.is_some() => reply(250, [2, 1, 5], "OK"),
                // Узел без очереди исходящей почты внешних получателей не принимает.
                Mode::Submission => reply(451, [4, 3, 2], "Outbound delivery not available"),
            },
            Resolved::Unknown => reply(550, [5, 1, 1], "Mailbox unavailable"),
        }
    }
}

/// Исходные адреса локальных получателей доставок без повторов (копии модулей — без адреса — не входят).
fn local_rcpts(deliveries: &[(String, MailDelivery)]) -> Vec<String> {
    let mut out = Vec::new();
    push_unique(
        &mut out,
        deliveries
            .iter()
            .filter(|(r, _)| !r.is_empty())
            .map(|(r, _)| r.clone())
            .collect(),
    );
    out
}

/// Получатели, письмо которым доставляется в «Спам» (учётные записи `junk`).
fn junk_rcpts(deliveries: &[(String, MailDelivery)], junk: &HashSet<AccountId>) -> Vec<String> {
    let mut out = Vec::new();
    push_unique(
        &mut out,
        deliveries
            .iter()
            .filter(|(r, d)| !r.is_empty() && junk.contains(&d.account))
            .map(|(r, _)| r.clone())
            .collect(),
    );
    out
}

/// Отказ этапа конвейера в сессии приёма (SMTP-54): понятная причина — в журнал доставки и SMTP-ответ.
fn stage_reject(trail: &mut Trail, rcpts: Vec<String>, reason: &str) -> Reply {
    trail
        .steps
        .push(Step::new(Ek::Reject, Dd::Reject, rcpts).reason(clean(reason)));
    reply(550, [5, 7, 1], clean(reason))
}

/// События журнала доставки после приёма: модерация, доставка в ящики (`local` без `failed`), отказы
/// получателям.
fn outcome_steps(
    steps: &mut Vec<Step>,
    held: &[(String, DistributionGroup)],
    local: &[String],
    failed: &[dsn::Recipient],
    junk: &[String],
) {
    for (rcpt, _) in held {
        steps.push(
            Step::new(Ek::Deliver, Dd::Hold, vec![rcpt.clone()]).reason("held for moderation"),
        );
    }
    let delivered: Vec<String> = local
        .iter()
        .filter(|r| !failed.iter().any(|f| f.address.eq_ignore_ascii_case(r)))
        .cloned()
        .collect();
    let (spam, inbox): (Vec<String>, Vec<String>) =
        delivered.into_iter().partition(|r| junk.contains(r));
    if !inbox.is_empty() {
        steps.push(Step::new(Ek::Deliver, Dd::Accept, inbox));
    }
    if !spam.is_empty() {
        steps.push(Step::new(Ek::Deliver, Dd::Accept, spam).reason("junk folder"));
    }
    for f in failed {
        steps.push(
            Step::new(
                Ek::Reject,
                tracking::decision_of_line(&f.reply),
                vec![f.address.clone()],
            )
            .reason(f.reply.clone()),
        );
    }
}

/// Событие уведомления о недоставке отправителю `to`: отправлено (`Accept`) или нет (`Defer`).
fn dsn_step(to: &str, sent: bool) -> Step {
    let (decision, reason) = if sent {
        (Dd::Accept, "failure notification")
    } else {
        (Dd::Defer, "failure notification not sent")
    };
    Step::new(Ek::Dsn, decision, vec![to.to_owned()])
        .sender("")
        .reason(reason)
}

/// Отказ отправителю вне круга группы рассылки после приёма.
const GROUP_DENIED: &str = "550 5.7.1 sender not allowed to send to this group";

/// Отказ по политике после приёма (группа закрыта, неизвестный адрес): без уведомления отправителю — он должен
/// был прозвучать в сессии до `250` (SMTP-50, RFC 5321 §6.2), только статус и журнал доставки.
fn denied(address: String, reply: &'static str) -> dsn::Recipient {
    dsn::Recipient {
        notify: false,
        ..dsn::Recipient::new(address, dsn::Action::Failed, reply)
    }
}

/// Сбой скрипта организации при выполнении (SIEVE-14): доставка в обход скрипта невозможна — временный отказ
/// (SMTP-50); в сессии smtp-in — `451`, в [`Delivery::submit`] — `SubmitStatus::Failed` с тем же кодом.
const ORG_SCRIPT_FAILED: &str = "451 4.3.0 sieve organization script failed";

/// Префикс ошибки выполнения скрипта организации в [`RulesOutcome::errors`] (ставит `tp-sieve`).
const ORG_SCRIPT_ERROR: &str = "скрипт организации";

/// Отказ адресу SRS: подпись не сходится или срок истёк.
const BAD_SRS: &str = "550 5.1.1 bad SRS address";

/// Ссылка-заглушка до записи тела ([`Delivery::mail_flow`] заменяет её объектом письма).
fn placeholder_blob(tenant: TenantId) -> BlobRef {
    BlobRef {
        key: tp_contracts::BlobKey {
            tenant,
            hash: tp_contracts::BlobHash([0; 32]),
            generation: tp_contracts::Gen::INITIAL,
        },
        size: 0,
    }
}

/// Объект BLOB целиком.
pub(crate) async fn read_blob(blobs: &dyn BlobStore, key: &tp_contracts::BlobKey) -> Result<Bytes> {
    use futures::TryStreamExt;
    let chunks: Vec<Bytes> = blobs.get(key, None).await?.try_collect().await?;
    Ok(chunks.concat().into())
}

/// Откуда письмо с iTIP и чем подтверждается его `From` ([`Delivery::with_itip`]).
#[derive(Debug, Clone, Copy)]
enum ItipOrigin<'a> {
    /// smtp-in (iMIP, SMTP-33): письмо прошло DMARC.
    Imip { dmarc_pass: bool },
    /// Почтовый клиент (submission, [`Delivery::submit`]; решение 78): учётная запись отправителя конверта и
    /// субъект проверки прав — вошедший пользователь сеанса submission или [`Delivery::submit`] (CTR-82, с
    /// группами), `None` — отправка без сеанса.
    Internal {
        account: AccountId,
        principal: Option<&'a Principal>,
    },
}

/// Получатели сообщения iTIP: доставки с адресом получателя (не копии модулей) вне «Спама»; при `enabled` = ложь —
/// никого.
fn itip_targets(
    enabled: bool,
    deliveries: &[(String, MailDelivery)],
    junk: &HashSet<AccountId>,
) -> Vec<(String, AccountId)> {
    if !enabled {
        return Vec::new();
    }
    deliveries
        .iter()
        .filter(|(r, d)| !r.is_empty() && !junk.contains(&d.account))
        .map(|(r, d)| (r.clone(), d.account))
        .collect()
}

/// Учётная запись отправителя транзакции: аутентифицированный пользователь организации; smtp-in — внешний.
fn sender_account(env: &Envelope, tenant: TenantId) -> Option<AccountId> {
    env.principal
        .as_ref()
        .filter(|p| env.mode == Mode::Submission && p.tenant == tenant)
        .map(|p| p.account)
}

/// Имя правила потока для очереди модерации (SMTP-30): первое сработавшее ([`FlowOutcome::matched`]),
/// без управляющих, до [`MAX_RULE_NAME_LEN`] символов ([`HeldMessage::validate`]); пусто — запасное имя.
fn rule_name(matched: &[String]) -> String {
    let name: String = matched
        .first()
        .map(String::as_str)
        .unwrap_or_default()
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_RULE_NAME_LEN)
        .collect();
    let name = name.trim();
    if name.is_empty() {
        "mail flow rule".into()
    } else {
        name.to_owned()
    }
}

/// Вошедший пользователь сеанса submission (SMTP-45): его адреса отправителя проверяются; smtp-in и приложение без
/// входа — `None`.
fn submitter(env: &Envelope) -> Option<&Principal> {
    env.principal
        .as_ref()
        .filter(|_| env.mode == Mode::Submission)
}

/// Поля `From` и `Sender` письма (каждое вхождение, по порядку) с их адресами; адресов нет — поле не разобрано.
fn sender_fields(raw: &[u8]) -> Vec<(&'static str, Vec<String>)> {
    use mail_parser::HeaderName;
    let Some(msg) = mail_parser::MessageParser::default().parse_headers(raw) else {
        return Vec::new();
    };
    msg.headers()
        .iter()
        .filter_map(|h| match h.name {
            HeaderName::From => Some(("From", &h.value)),
            HeaderName::Sender => Some(("Sender", &h.value)),
            _ => None,
        })
        .map(|(name, value)| {
            let addrs = value
                .as_address()
                .map(|a| {
                    a.iter()
                        .filter_map(|a| a.address())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            (name, addrs)
        })
        .collect()
}

/// Первый адрес `From` письма (домен определяет тип абонента входящего, решение 124): нет `From` — `None`.
/// Заголовкам `Authentication-Results` чужого шлюза и `remote-host` не доверяем — тип вычисляет ядро
/// (RFC 8601 §5, RFC 5183).
fn from_address(raw: &[u8]) -> Option<String> {
    sender_fields(raw)
        .into_iter()
        .find(|(name, _)| *name == "From")
        .and_then(|(_, addrs)| addrs.into_iter().next())
}

/// `Message-ID` (`<…>`) писем, на которые ссылается ответ: `In-Reply-To`, затем `References`
/// (RFC 5322 §3.6.4) — по ним ручной iTIP-ответ находят исходное приглашение (SMTP-55).
fn referenced_ids(raw: &[u8]) -> Vec<String> {
    use mail_parser::{HeaderName, HeaderValue};
    let Some(msg) = mail_parser::MessageParser::default().parse_headers(raw) else {
        return Vec::new();
    };
    let mut ids = Vec::new();
    for name in [HeaderName::InReplyTo, HeaderName::References] {
        for value in msg.header_values(name) {
            // `Message-Id`-заголовок — строка или список строк (скобки снимаются).
            let list = match value {
                HeaderValue::Text(id) => vec![id.as_ref()],
                HeaderValue::TextList(list) => list.iter().map(|id| id.as_ref()).collect(),
                _ => Vec::new(),
            };
            for id in list {
                let id = id.trim_matches(|c| c == '<' || c == '>');
                if !id.is_empty() {
                    ids.push(format!("<{id}>"));
                }
            }
        }
    }
    ids
}

/// Временная ошибка (`451 4.3.0`): хранилище или каталог недоступны.
fn temporary(e: &Error) -> Reply {
    tracing::warn!(error = %e, "smtp: временная ошибка");
    reply(451, [4, 3, 0], "Temporary failure, try again later")
}

/// Значение для заголовка: без управляющих символов (CR, LF) — защита от внедрения заголовков.
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub mod journal;
mod moderation;
mod pipeline;
mod scheduled;

#[cfg(test)]
mod tests;
