//! Политика доверия: типы абонентов, функции, уровни, потолок, безопасные умолчания (CTR-93; CONTRACTS.md#Trust;
//! SRS 4; решение 124, исследование `docs/research/2026-11-14-trust-matrix.md`).
//!
//! Матрица доверия — «кто — кому — что»: тип абонента ([`PeerKind`]) × функция ([`TrustFunction`]). Это типизированная
//! политика уровней установка → организация → группа с потолком сверху и безопасными умолчаниями, а не правила
//! почтового потока: значение уровня не выше действующего значения уровня выше ([`HARD_CEILING`] — потолок самой
//! установки), из нескольких групп учётной записи действует самое узкое, ошибка чтения политики — закрытая матрица
//! ([`TrustMatrix::closed`]), почта при этом доставляется. Часть клеток закреплена контрактом и не настраивается
//! никем ([`booking_allowed`] и др.; прочие методы iTIP и бронирование чужих — в [`TrustMatrix::inbound`]).
//!
//! Практика: уровни с потолком — Google (настройки по OU, группа важнее OU, пользователь в пределах администратора),
//! Zimbra (COS → учётная запись); партнёры отдельной сущностью — Exchange Organization Relationship и Remote Domain;
//! при конфликте побеждает запрет — правила почтового потока Exchange. Отличие — проверка схемой и закреплённые
//! клетки: одной строкой не открыть всё.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::bus::{Event, EventKind};
use crate::error::{Error, Result};
use crate::ids::{AccountId, GroupId, TenantId};
use crate::schedule::InboundAction;
use crate::transport::normalize_domain;

// ---------- Типы абонентов и значения функций ----------

/// Тип абонента относительно организации (решение 124 а) — «кто» матрицы, для обоих направлений: отправитель
/// входящего письма и получатель исходящего. Свои — вошедшие в систему (submission со входом, JMAP, CalDAV,
/// CardDAV), а не «наш» домен в `From`: DMARC не проверяет local-part, сторонний сервис из SPF или DKIM домена
/// его проходит (RFC 9989 §2.2, §4.1; RFC 8601 §5 — чужим `Authentication-Results` не доверяем). Сосед по установке
/// (другая организация, MSSP) — как интернет, пока его домен не заведён партнёром.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerKind {
    /// Своя организация — вошедший в систему.
    Own,
    /// Домен из списка партнёров организации ([`TrustPolicy::partners`]), письмо с DMARC pass и выравниванием.
    Partner,
    /// Другая организация той же установки (MSSP), не партнёр.
    Neighbor,
    /// Остальные, в том числе письмо через smtp-in с адресом своей организации.
    External,
}

impl PeerKind {
    /// Все типы, от своего к интернету.
    pub const ALL: [PeerKind; 4] = [
        PeerKind::Own,
        PeerKind::Partner,
        PeerKind::Neighbor,
        PeerKind::External,
    ];

    /// Значение в JSON и сообщениях об ошибке.
    pub const fn as_str(self) -> &'static str {
        match self {
            PeerKind::Own => "own",
            PeerKind::Partner => "partner",
            PeerKind::Neighbor => "neighbor",
            PeerKind::External => "external",
        }
    }
}

impl fmt::Display for PeerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Контекст точки решения (smtp-in, submission, правила Sieve): тип абонента и признак «ответ на наше письмо»
/// (решение 125 а). Признак ставит вызывающий по всем трём условиям: DMARC pass с выравниванием (RFC 9989),
/// отправитель — среди адресатов исходного письма (запись об отправленном — `crate::reply::SentLog`),
/// письму не больше `smtp.reply.max_age`. По нему [`TrustMatrix::effective`] решает клетки
/// [`Toggle::ReplyOnly`] — значения «только ответ на наше письмо» у клеток автоответа и MDN наружу.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerContext {
    /// Тип абонента относительно организации.
    pub kind: PeerKind,
    /// Письмо — ответ на наше письмо ([`Toggle::ReplyOnly`] решается как [`Toggle::On`]).
    pub reply: bool,
}

impl PeerContext {
    /// Контекст без признака ответа.
    pub const fn new(kind: PeerKind) -> Self {
        PeerContext { kind, reply: false }
    }

    /// Контекст с признаком ответа.
    pub const fn reply(kind: PeerKind) -> Self {
        PeerContext { kind, reply: true }
    }
}

/// Новое приглашение (`REQUEST` события, которого у получателя нет): письмо с кнопкой или автодобавление.
/// От узкого к широкому; [`Default`] — узкое значение (отсутствующий ключ JSON — безопасное умолчание клетки).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum InviteMode {
    /// Письмо с частью `text/calendar` и кнопкой «Добавить» в клиенте; сервер в календарь не вносит (Google
    /// «только известные отправители», защита от календарного спама, RFC 5546 §6.1.5).
    #[default]
    Button,
    /// Вносится в календарь по умолчанию (`PARTSTAT=NEEDS-ACTION`) — только партнёрам, если открыл администратор.
    Auto,
}

impl InviteMode {
    /// Значение в JSON и сообщениях об ошибке.
    pub const fn as_str(self) -> &'static str {
        match self {
            InviteMode::Button => "button",
            InviteMode::Auto => "auto",
        }
    }
}

impl fmt::Display for InviteMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Выключено или включено ([`TrustFunction::ItipUpdates`], [`TrustFunction::AutoReply`], [`TrustFunction::Mdn`],
/// [`TrustFunction::AutoForward`]). От узкого к широкому. [`Toggle::ReplyOnly`] — только для клеток
/// [`TrustFunction::AutoReply`] и [`TrustFunction::Mdn`] (решение 125 а): действие разрешено, лишь если письмо —
/// ответ на наше; решает [`TrustMatrix::effective`] по [`PeerContext`].
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Toggle {
    /// Выключено: письмо остаётся письмом, наружу ничего не уходит.
    #[default]
    Off,
    /// Только ответ на наше письмо (запись об отправленном — `crate::reply::SentLog`); иначе — как [`Toggle::Off`].
    ReplyOnly,
    /// Включено.
    On,
}

impl Toggle {
    /// Значение в JSON и сообщениях об ошибке.
    pub const fn as_str(self) -> &'static str {
        match self {
            Toggle::Off => "off",
            Toggle::ReplyOnly => "reply_only",
            Toggle::On => "on",
        }
    }
}

impl fmt::Display for Toggle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Уровень детализации занятости ([`TrustFunction::FreeBusy`]) и общего доступа с публикацией
/// ([`TrustFunction::Sharing`]). От узкого к широкому; `All` — только своей организации.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Detail {
    /// Ничего не отдаётся.
    #[default]
    None,
    /// «Свободен/занят» — интервалы без содержания (Exchange `AvailabilityOnly`).
    FreeBusy,
    /// Ограниченные подробности: время, тема, место.
    Limited,
    /// Подробности — полный просмотр без изменения.
    Details,
    /// Всё, включая изменение (чтение и запись — только своим).
    All,
}

impl Detail {
    /// Значение в JSON и сообщениях об ошибке.
    pub const fn as_str(self) -> &'static str {
        match self {
            Detail::None => "none",
            Detail::FreeBusy => "free_busy",
            Detail::Limited => "limited",
            Detail::Details => "details",
            Detail::All => "all",
        }
    }
}

impl fmt::Display for Detail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Письма в группы рассылки ([`TrustFunction::GroupPost`]) от типа абонента. От узкого к широкому.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum GroupPost {
    /// Закрыта: письмо чужого отклоняется в сессии SMTP `550 5.7.1` (Exchange
    /// `RequireSenderAuthenticationEnabled=$true`).
    #[default]
    Closed,
    /// С модерацией: письмо задерживается для решения модератора; отказ модератора чужому не уведомляется
    /// (источник backscatter).
    Moderated,
    /// Открыта: ограничения группы (`senders`) действуют как для своих.
    Open,
}

impl GroupPost {
    /// Значение в JSON и сообщениях об ошибке.
    pub const fn as_str(self) -> &'static str {
        match self {
            GroupPost::Closed => "closed",
            GroupPost::Moderated => "moderated",
            GroupPost::Open => "open",
        }
    }
}

impl fmt::Display for GroupPost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Значение по клетке — объединение значений функций (для [`OverCeiling`] и адресации клеток). Сравнение имеет
/// смысл только внутри одной функции ([`TrustFunction`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellValue {
    /// Клетка [`TrustFunction::InviteNew`].
    Invite(InviteMode),
    /// Клетки [`TrustFunction::ItipUpdates`], [`TrustFunction::AutoReply`], [`TrustFunction::Mdn`],
    /// [`TrustFunction::AutoForward`].
    Toggle(Toggle),
    /// Клетки [`TrustFunction::FreeBusy`], [`TrustFunction::Sharing`].
    Detail(Detail),
    /// Клетка [`TrustFunction::GroupPost`].
    Post(GroupPost),
}

impl fmt::Display for CellValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CellValue::Invite(v) => v.fmt(f),
            CellValue::Toggle(v) => v.fmt(f),
            CellValue::Detail(v) => v.fmt(f),
            CellValue::Post(v) => v.fmt(f),
        }
    }
}

/// Приватный мост значений функций в [`CellValue`].
trait Cell: Copy + Ord {
    /// Значение клетки как [`CellValue`].
    fn as_cell(self) -> CellValue;
}

impl Cell for InviteMode {
    fn as_cell(self) -> CellValue {
        CellValue::Invite(self)
    }
}

impl Cell for Toggle {
    fn as_cell(self) -> CellValue {
        CellValue::Toggle(self)
    }
}

impl Cell for Detail {
    fn as_cell(self) -> CellValue {
        CellValue::Detail(self)
    }
}

impl Cell for GroupPost {
    fn as_cell(self) -> CellValue {
        CellValue::Post(self)
    }
}

/// Функция матрицы — «что» клетки; адресация клеток для Admin API, ошибок и источников.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustFunction {
    /// Новое приглашение (`REQUEST`) — [`InviteMode`].
    InviteNew,
    /// `REPLY`, `CANCEL` и обновление `REQUEST` к существующим событиям — [`Toggle`].
    ItipUpdates,
    /// Автоответ чужим — [`Toggle`] (внешний текст — [`crate::sieve::Vacation`]; пока не задан, наружу ничего).
    AutoReply,
    /// Уведомление о прочтении (MDN) наружу — [`Toggle`] (RFC 8098).
    Mdn,
    /// Автопересылка наружу (`redirect`, пересылка ящика) — [`Toggle`]; домены —
    /// [`TrustPolicy::auto_forward_domains`].
    AutoForward,
    /// Занятость (free/busy) — [`Detail`].
    FreeBusy,
    /// Общий доступ и публикация календарей — [`Detail`].
    Sharing,
    /// Письма в группы рассылки — [`GroupPost`].
    GroupPost,
}

impl TrustFunction {
    /// Все функции.
    pub const ALL: [TrustFunction; 8] = [
        TrustFunction::InviteNew,
        TrustFunction::ItipUpdates,
        TrustFunction::AutoReply,
        TrustFunction::Mdn,
        TrustFunction::AutoForward,
        TrustFunction::FreeBusy,
        TrustFunction::Sharing,
        TrustFunction::GroupPost,
    ];

    /// Имя клетки в JSON и сообщениях об ошибке.
    pub const fn as_str(self) -> &'static str {
        match self {
            TrustFunction::InviteNew => "invite_new",
            TrustFunction::ItipUpdates => "itip_updates",
            TrustFunction::AutoReply => "auto_reply",
            TrustFunction::Mdn => "mdn",
            TrustFunction::AutoForward => "auto_forward",
            TrustFunction::FreeBusy => "freebusy",
            TrustFunction::Sharing => "sharing",
            TrustFunction::GroupPost => "group_post",
        }
    }
}

impl fmt::Display for TrustFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Значения по типам абонентов — колонки матрицы. В JSON — объект `{"own": …, "partner": …, "neighbor": …,
/// "external": …}`; отсутствующие ключи — не задано (в [`TrustPolicy`] — наследование уровня выше).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PerPeer<T> {
    /// Своя организация.
    #[serde(default)]
    pub own: T,
    /// Домен-партнёр.
    #[serde(default)]
    pub partner: T,
    /// Сосед по установке.
    #[serde(default)]
    pub neighbor: T,
    /// Интернет.
    #[serde(default)]
    pub external: T,
}

impl<T: Copy> PerPeer<T> {
    /// Значение для типа абонента.
    pub fn get(&self, peer: PeerKind) -> T {
        match peer {
            PeerKind::Own => self.own,
            PeerKind::Partner => self.partner,
            PeerKind::Neighbor => self.neighbor,
            PeerKind::External => self.external,
        }
    }
}

impl<T> PerPeer<T> {
    /// Изменяет значение для типа абонента.
    pub fn set(&mut self, peer: PeerKind, value: T) {
        match peer {
            PeerKind::Own => self.own = value,
            PeerKind::Partner => self.partner = value,
            PeerKind::Neighbor => self.neighbor = value,
            PeerKind::External => self.external = value,
        }
    }
}

impl<T: Ord + Copy> PerPeer<T> {
    /// Самое узкое значение по каждой клетке (запрет побеждает — как в правилах почтового потока Exchange).
    pub fn narrow_with(&self, other: &PerPeer<T>) -> PerPeer<T> {
        PerPeer {
            own: self.own.min(other.own),
            partner: self.partner.min(other.partner),
            neighbor: self.neighbor.min(other.neighbor),
            external: self.external.min(other.external),
        }
    }
}

impl<T: Default> Default for PerPeer<T> {
    fn default() -> Self {
        PerPeer {
            own: T::default(),
            partner: T::default(),
            neighbor: T::default(),
            external: T::default(),
        }
    }
}

// ---------- Матрица ----------

/// Матрица доверия: по клетке на функцию и тип абонента (решение 124; таблица «Матрица по умолчанию»
/// `docs/ADMIN-GUIDE.md#матрица-по-умолчанию`). Умолчания безопасные: чужим — только почта и `REPLY`/`CANCEL` к
/// существующим событиям; [`TrustMatrix::closed`] — закрытая матрица при ошибке чтения политики.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustMatrix {
    /// Новое приглашение (`REQUEST`): свои — вносится, чужим — письмо с кнопкой.
    pub invite_new: PerPeer<InviteMode>,
    /// `REPLY`, `CANCEL` и обновление `REQUEST` к существующим событиям: включено всем (выключается).
    pub itip_updates: PerPeer<Toggle>,
    /// Автоответ: включено всем, чужим — только внешним текстом; клетка может быть [`Toggle::ReplyOnly`]
    /// (решение 125 а) — автоответ чужому только на ответ на наше письмо.
    pub auto_reply: PerPeer<Toggle>,
    /// MDN наружу: своим — уходит, чужим — нет; клетка может быть [`Toggle::ReplyOnly`] (решение 125 а) —
    /// уведомление уходит только на ответ на наше письмо.
    pub mdn: PerPeer<Toggle>,
    /// Автопересылка наружу: своим — можно, чужим — нет (главный путь утечки данных).
    pub auto_forward: PerPeer<Toggle>,
    /// Занятость: своим — свободен/занят, чужим — не отдаётся.
    pub freebusy: PerPeer<Detail>,
    /// Общий доступ и публикация: своим — по выбору владельца, чужим — нет.
    pub sharing: PerPeer<Detail>,
    /// Письма в группы рассылки: своим — можно, чужим — закрыто.
    pub group_post: PerPeer<GroupPost>,
}

impl Default for TrustMatrix {
    /// Таблица «Матрица по умолчанию» ADMIN-GUIDE (решение 124 в–г).
    fn default() -> Self {
        TrustMatrix {
            invite_new: PerPeer {
                own: InviteMode::Auto,
                partner: InviteMode::Button,
                neighbor: InviteMode::Button,
                external: InviteMode::Button,
            },
            itip_updates: PerPeer {
                own: Toggle::On,
                partner: Toggle::On,
                neighbor: Toggle::On,
                external: Toggle::On,
            },
            auto_reply: PerPeer {
                own: Toggle::On,
                partner: Toggle::On,
                neighbor: Toggle::On,
                external: Toggle::On,
            },
            mdn: PerPeer {
                own: Toggle::On,
                partner: Toggle::Off,
                neighbor: Toggle::Off,
                external: Toggle::Off,
            },
            auto_forward: PerPeer {
                own: Toggle::On,
                partner: Toggle::Off,
                neighbor: Toggle::Off,
                external: Toggle::Off,
            },
            freebusy: PerPeer {
                own: Detail::FreeBusy,
                partner: Detail::None,
                neighbor: Detail::None,
                external: Detail::None,
            },
            sharing: PerPeer {
                own: Detail::All,
                partner: Detail::None,
                neighbor: Detail::None,
                external: Detail::None,
            },
            group_post: PerPeer {
                own: GroupPost::Open,
                partner: GroupPost::Closed,
                neighbor: GroupPost::Closed,
                external: GroupPost::Closed,
            },
        }
    }
}

impl TrustMatrix {
    /// Закрытая матрица — ошибка чтения политики: все клетки чужих в самом узком значении, почта доставляется.
    /// Клетки своих — как в умолчаниях (своя организация работает).
    pub fn closed() -> Self {
        let mut m = TrustMatrix::default();
        for peer in PeerKind::ALL {
            if peer == PeerKind::Own {
                continue;
            }
            m.invite_new.set(peer, InviteMode::Button);
            m.itip_updates.set(peer, Toggle::Off);
            m.auto_reply.set(peer, Toggle::Off);
            m.mdn.set(peer, Toggle::Off);
            m.auto_forward.set(peer, Toggle::Off);
            m.freebusy.set(peer, Detail::None);
            m.sharing.set(peer, Detail::None);
            m.group_post.set(peer, GroupPost::Closed);
        }
        m
    }

    /// Самое узкое значение по каждой клетке (уровни и группы комбинируются запретом).
    pub fn narrow(&self, other: &TrustMatrix) -> TrustMatrix {
        TrustMatrix {
            invite_new: self.invite_new.narrow_with(&other.invite_new),
            itip_updates: self.itip_updates.narrow_with(&other.itip_updates),
            auto_reply: self.auto_reply.narrow_with(&other.auto_reply),
            mdn: self.mdn.narrow_with(&other.mdn),
            auto_forward: self.auto_forward.narrow_with(&other.auto_forward),
            freebusy: self.freebusy.narrow_with(&other.freebusy),
            sharing: self.sharing.narrow_with(&other.sharing),
            group_post: self.group_post.narrow_with(&other.group_post),
        }
    }

    /// Значение клетки.
    pub fn get(&self, function: TrustFunction, peer: PeerKind) -> CellValue {
        match function {
            TrustFunction::InviteNew => self.invite_new.get(peer).as_cell(),
            TrustFunction::ItipUpdates => self.itip_updates.get(peer).as_cell(),
            TrustFunction::AutoReply => self.auto_reply.get(peer).as_cell(),
            TrustFunction::Mdn => self.mdn.get(peer).as_cell(),
            TrustFunction::AutoForward => self.auto_forward.get(peer).as_cell(),
            TrustFunction::FreeBusy => self.freebusy.get(peer).as_cell(),
            TrustFunction::Sharing => self.sharing.get(peer).as_cell(),
            TrustFunction::GroupPost => self.group_post.get(peer).as_cell(),
        }
    }

    /// Действующее значение клетки в точке решения (решение 125 а): как [`TrustMatrix::get`] по
    /// [`PeerContext::kind`], клетки [`Toggle::ReplyOnly`] — по [`PeerContext::reply`]: ответ на наше письмо —
    /// [`Toggle::On`], иначе — [`Toggle::Off`]. Остальные значения проходят как есть.
    pub fn effective(&self, function: TrustFunction, ctx: &PeerContext) -> CellValue {
        match self.get(function, ctx.kind) {
            CellValue::Toggle(Toggle::ReplyOnly) => {
                CellValue::Toggle(if ctx.reply { Toggle::On } else { Toggle::Off })
            }
            value => value,
        }
    }

    /// Матрица приёма iTIP (решение 123, уточнено решением 124 в): своей организации — всё; чужим новое
    /// приглашение — по клетке [`TrustMatrix::invite_new`], `REPLY`, `CANCEL` и обновление `REQUEST` — по
    /// [`TrustMatrix::itip_updates`], только к существующему событию (тот же UID, отправитель — участник или
    /// организатор события; RFC 5546 §6.1.1–6.1.2, RFC 6638 §11.2) — проверяет приём. Бронирование ресурсов и
    /// прочие методы iTIP (`ADD`, `REFRESH`, `COUNTER`, `DECLINECOUNTER`, `PUBLISH`) чужим — только письмо при
    /// любой политике: клетки закреплены (решение 123 б–в).
    pub fn inbound(&self, kind: PeerKind, action: InboundAction) -> InboundDecision {
        use InboundAction::{Booking, Cancel, Invite, Other, Reply, Update};
        match (kind, action) {
            (PeerKind::Own, _) => InboundDecision::Apply,
            (_, Booking | Other) => InboundDecision::MailOnly,
            (_, Invite) => match self.invite_new.get(kind) {
                InviteMode::Auto => InboundDecision::Apply,
                InviteMode::Button => InboundDecision::MailOnly,
            },
            (_, Update | Reply | Cancel) => match self.itip_updates.get(kind) {
                Toggle::On => InboundDecision::ApplyIfExisting,
                // ReplyOnly задуман для клеток auto_reply и mdn (решение 125 а); на прочих клетках —
                // как Off: приём iTIP не привязан к признаку ответа.
                Toggle::Off | Toggle::ReplyOnly => InboundDecision::MailOnly,
            },
        }
    }
}

/// Итог матрицы приёма iTIP: что узел делает с сообщением (письмо при любом итоге остаётся в ящике).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboundDecision {
    /// Применяется: событие в календаре, статус участника, отмена.
    Apply,
    /// Применяется только к существующему событию: тот же UID, отправитель — участник (`REPLY`) или организатор
    /// (`CANCEL`, обновление `REQUEST`) этого события; нет события — только письмо.
    ApplyIfExisting,
    /// Только письмо: сервер ничего не вносит и не отвечает.
    MailOnly,
}

impl InboundDecision {
    /// Значение в JSON и журналах.
    pub const fn as_str(self) -> &'static str {
        match self {
            InboundDecision::Apply => "apply",
            InboundDecision::ApplyIfExisting => "apply_if_existing",
            InboundDecision::MailOnly => "mail_only",
        }
    }
}

impl fmt::Display for InboundDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Потолок самой установки — закреплённые верхние границы контракта (решение 124 б, в): никто не поднимает
/// значение клетки выше. `invite_new` соседям и интернету — не выше кнопки; занятость соседям и интернету —
/// `none`; партнёру — до ограниченных подробностей; `all` — только своей организации; прочие функции — до
/// максимума (значения по умолчанию уже безопасны, выключаются всегда).
pub const HARD_CEILING: TrustMatrix = TrustMatrix {
    invite_new: PerPeer {
        own: InviteMode::Auto,
        partner: InviteMode::Auto,
        neighbor: InviteMode::Button,
        external: InviteMode::Button,
    },
    itip_updates: PerPeer {
        own: Toggle::On,
        partner: Toggle::On,
        neighbor: Toggle::On,
        external: Toggle::On,
    },
    auto_reply: PerPeer {
        own: Toggle::On,
        partner: Toggle::On,
        neighbor: Toggle::On,
        external: Toggle::On,
    },
    mdn: PerPeer {
        own: Toggle::On,
        partner: Toggle::On,
        neighbor: Toggle::On,
        external: Toggle::On,
    },
    auto_forward: PerPeer {
        own: Toggle::On,
        partner: Toggle::On,
        neighbor: Toggle::On,
        external: Toggle::On,
    },
    freebusy: PerPeer {
        own: Detail::Details,
        partner: Detail::Limited,
        neighbor: Detail::None,
        external: Detail::None,
    },
    sharing: PerPeer {
        own: Detail::All,
        partner: Detail::Details,
        neighbor: Detail::Details,
        external: Detail::Details,
    },
    group_post: PerPeer {
        own: GroupPost::Open,
        partner: GroupPost::Open,
        neighbor: GroupPost::Open,
        external: GroupPost::Open,
    },
};

/// Бронирование ресурсов (переговорные, оборудование) — только своя организация (закреплено; Exchange
/// `ProcessExternalMeetingMessages=$false`): сообщение чужого ресурсу — только письмо, без брони и без ответа.
pub const fn booking_allowed(peer: PeerKind) -> bool {
    matches!(peer, PeerKind::Own)
}

/// GAL и поиск по адресной книге — только своя организация (закреплено): соседям и интернету ничего (утечка
/// каталога между арендаторами).
pub const fn gal_allowed(peer: PeerKind) -> bool {
    matches!(peer, PeerKind::Own)
}

/// Делегирование (права на календари, `SENT-BY`) и отправка от имени (`Send As`, `Send On Behalf`) — только своя
/// организация (закреплено): партнёрство доверия к делегированию не даёт.
pub const fn delegation_allowed(peer: PeerKind) -> bool {
    matches!(peer, PeerKind::Own)
}

/// DSN чужим — без диагностики, внутренних имён узлов и адресов (закреплено; RFC 3464 §4.2, RFC 5321 §6.2):
/// `true` только своей организации.
pub const fn dsn_diagnostics(peer: PeerKind) -> bool {
    matches!(peer, PeerKind::Own)
}

// ---------- Уровни и политика ----------

/// Уровень политики: установка → организация → группа. Порядок от верхнего к нижнему.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    /// Установка — потолки для всех организаций (меняет администратор установки).
    Installation,
    /// Организация — значения организации, домены-партнёры и домены автопересылки.
    Org(TenantId),
    /// Группа — значения для учётных записей группы; для «Писем в группы» — для самой группы.
    Group(TenantId, GroupId),
}

impl TrustLevel {
    /// Организация уровня (`None` — установка).
    pub fn tenant(&self) -> Option<TenantId> {
        match self {
            TrustLevel::Installation => None,
            TrustLevel::Org(t) | TrustLevel::Group(t, _) => Some(*t),
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustLevel::Installation => f.write_str("installation"),
            TrustLevel::Org(t) => write!(f, "org {t}"),
            TrustLevel::Group(t, g) => write!(f, "group {t}/{g}"),
        }
    }
}

/// Политика уровня — частичная: клетки `None` наследуют действующее значение уровня выше. `partners` и
/// `auto_forward_domains` — только у организации (в [`TrustStore::set_policy`] на других уровнях — `Invalid`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TrustPolicy {
    /// Новое приглашение.
    #[serde(default)]
    pub invite_new: PerPeer<Option<InviteMode>>,
    /// `REPLY`, `CANCEL` и обновление `REQUEST` к существующим событиям.
    #[serde(default)]
    pub itip_updates: PerPeer<Option<Toggle>>,
    /// Автоответ.
    #[serde(default)]
    pub auto_reply: PerPeer<Option<Toggle>>,
    /// MDN наружу.
    #[serde(default)]
    pub mdn: PerPeer<Option<Toggle>>,
    /// Автопересылка наружу.
    #[serde(default)]
    pub auto_forward: PerPeer<Option<Toggle>>,
    /// Занятость.
    #[serde(default)]
    pub freebusy: PerPeer<Option<Detail>>,
    /// Общий доступ и публикация.
    #[serde(default)]
    pub sharing: PerPeer<Option<Detail>>,
    /// Письма в группы рассылки.
    #[serde(default)]
    pub group_post: PerPeer<Option<GroupPost>>,
    /// Домены-партнёры организации: канонические имена (нижний регистр, A-label IDN — [`normalize_domain`]);
    /// домен соседней организации может быть партнёром, свой принятый домен — нет ([`TrustPolicy::validate`]).
    #[serde(default)]
    pub partners: Vec<String>,
    /// Домены, куда разрешена автопересылка (при `auto_forward = On`); канонические имена.
    #[serde(default)]
    pub auto_forward_domains: Vec<String>,
}

impl TrustPolicy {
    /// Заданное значение клетки (`None` — наследуется уровнем выше).
    pub fn cell(&self, function: TrustFunction, peer: PeerKind) -> Option<CellValue> {
        match function {
            TrustFunction::InviteNew => self.invite_new.get(peer).map(Cell::as_cell),
            TrustFunction::ItipUpdates => self.itip_updates.get(peer).map(Cell::as_cell),
            TrustFunction::AutoReply => self.auto_reply.get(peer).map(Cell::as_cell),
            TrustFunction::Mdn => self.mdn.get(peer).map(Cell::as_cell),
            TrustFunction::AutoForward => self.auto_forward.get(peer).map(Cell::as_cell),
            TrustFunction::FreeBusy => self.freebusy.get(peer).map(Cell::as_cell),
            TrustFunction::Sharing => self.sharing.get(peer).map(Cell::as_cell),
            TrustFunction::GroupPost => self.group_post.get(peer).map(Cell::as_cell),
        }
    }

    /// Клетки выше потолка — перечень для отказа и пометки.
    fn over_ceiling(&self, ceiling: &Ceiling) -> Vec<OverCeiling> {
        let mut over = Vec::new();
        check_cells(
            &self.invite_new,
            &ceiling.matrix.invite_new,
            ceiling,
            TrustFunction::InviteNew,
            &mut over,
        );
        check_cells(
            &self.itip_updates,
            &ceiling.matrix.itip_updates,
            ceiling,
            TrustFunction::ItipUpdates,
            &mut over,
        );
        check_cells(
            &self.auto_reply,
            &ceiling.matrix.auto_reply,
            ceiling,
            TrustFunction::AutoReply,
            &mut over,
        );
        check_cells(
            &self.mdn,
            &ceiling.matrix.mdn,
            ceiling,
            TrustFunction::Mdn,
            &mut over,
        );
        check_cells(
            &self.auto_forward,
            &ceiling.matrix.auto_forward,
            ceiling,
            TrustFunction::AutoForward,
            &mut over,
        );
        check_cells(
            &self.freebusy,
            &ceiling.matrix.freebusy,
            ceiling,
            TrustFunction::FreeBusy,
            &mut over,
        );
        check_cells(
            &self.sharing,
            &ceiling.matrix.sharing,
            ceiling,
            TrustFunction::Sharing,
            &mut over,
        );
        check_cells(
            &self.group_post,
            &ceiling.matrix.group_post,
            ceiling,
            TrustFunction::GroupPost,
            &mut over,
        );
        over
    }

    /// Проверяет политику по действующему потолку `ceiling` (у установки — [`Ceiling::hard`]) и домены. Клетки
    /// выше потолка — `Error::Invalid` с перечнем [`OverCeiling`] `{function, peer, value, ceiling, level}`
    /// (422 Admin API с потолком и уровнем, откуда он пришёл). Домены `partners` и `auto_forward_domains` —
    /// канонические ([`normalize_domain`]), без повторов; домен из принятых доменов своей организации
    /// (`accepted`) в `partners` — `Invalid`.
    pub fn validate(&self, ceiling: &Ceiling, accepted: &[String]) -> Result<()> {
        check_domains(&self.partners, "partners")?;
        check_domains(&self.auto_forward_domains, "auto_forward_domains")?;
        if let Some(d) = self.partners.iter().find(|d| accepted.contains(d)) {
            return Err(Error::invalid(format!(
                "принятый домен организации не может быть партнёром: {d}"
            )));
        }
        let over = self.over_ceiling(ceiling);
        if over.is_empty() {
            return Ok(());
        }
        let list = over
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        Err(Error::invalid(format!("клетки выше потолка: {list}")))
    }
}

/// Домены списка: канонические, без повторов; иначе — `Invalid`.
fn check_domains(domains: &[String], what: &str) -> Result<()> {
    for d in domains {
        if normalize_domain(d) != Ok(d.clone()) {
            return Err(Error::invalid(format!(
                "домен {d:?} в {what} не канонический"
            )));
        }
    }
    let mut sorted = domains.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != domains.len() {
        return Err(Error::invalid(format!("повтор домена в {what}")));
    }
    Ok(())
}

/// Заданные клетки `cells` выше потолка — в `over` (уровень потолка — из `source.sources`).
fn check_cells<T: Cell>(
    cells: &PerPeer<Option<T>>,
    ceiling: &PerPeer<T>,
    source: &Ceiling,
    function: TrustFunction,
    over: &mut Vec<OverCeiling>,
) {
    for peer in PeerKind::ALL {
        if let Some(value) = cells.get(peer)
            && value > ceiling.get(peer)
        {
            over.push(OverCeiling {
                function,
                peer,
                value: value.as_cell(),
                ceiling: ceiling.get(peer).as_cell(),
                level: source.sources.get_of(function, peer),
            });
        }
    }
}

/// Клетка выше потолка: значение уровня шире действующего значения уровня выше. В отказе `Invalid` (422) и в
/// пометке [`Effective::over_ceiling`] («выше потолка» на экране администратора).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverCeiling {
    /// Функция клетки.
    pub function: TrustFunction,
    /// Тип абонента клетки.
    pub peer: PeerKind,
    /// Заданное значение.
    pub value: CellValue,
    /// Потолок.
    pub ceiling: CellValue,
    /// Уровень, давший потолок; `None` — умолчание контракта ([`HARD_CEILING`] или [`TrustMatrix::default`]).
    pub level: Option<TrustLevel>,
}

impl fmt::Display for OverCeiling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{} = {} выше потолка {}",
            self.function, self.peer, self.value, self.ceiling
        )?;
        match &self.level {
            Some(level) => write!(f, " (уровень {level})"),
            None => f.write_str(" (умолчание контракта)"),
        }
    }
}

/// Источник значения по клеткам: уровень, давший значение; `None` — умолчание контракта. Обрезанная потолком
/// клетка — источник потолка.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TrustSources {
    /// [`TrustFunction::InviteNew`].
    #[serde(default)]
    pub invite_new: PerPeer<Option<TrustLevel>>,
    /// [`TrustFunction::ItipUpdates`].
    #[serde(default)]
    pub itip_updates: PerPeer<Option<TrustLevel>>,
    /// [`TrustFunction::AutoReply`].
    #[serde(default)]
    pub auto_reply: PerPeer<Option<TrustLevel>>,
    /// [`TrustFunction::Mdn`].
    #[serde(default)]
    pub mdn: PerPeer<Option<TrustLevel>>,
    /// [`TrustFunction::AutoForward`].
    #[serde(default)]
    pub auto_forward: PerPeer<Option<TrustLevel>>,
    /// [`TrustFunction::FreeBusy`].
    #[serde(default)]
    pub freebusy: PerPeer<Option<TrustLevel>>,
    /// [`TrustFunction::Sharing`].
    #[serde(default)]
    pub sharing: PerPeer<Option<TrustLevel>>,
    /// [`TrustFunction::GroupPost`].
    #[serde(default)]
    pub group_post: PerPeer<Option<TrustLevel>>,
}

impl TrustSources {
    fn get_of(&self, function: TrustFunction, peer: PeerKind) -> Option<TrustLevel> {
        match function {
            TrustFunction::InviteNew => self.invite_new.get(peer),
            TrustFunction::ItipUpdates => self.itip_updates.get(peer),
            TrustFunction::AutoReply => self.auto_reply.get(peer),
            TrustFunction::Mdn => self.mdn.get(peer),
            TrustFunction::AutoForward => self.auto_forward.get(peer),
            TrustFunction::FreeBusy => self.freebusy.get(peer),
            TrustFunction::Sharing => self.sharing.get(peer),
            TrustFunction::GroupPost => self.group_post.get(peer),
        }
    }

    fn set_of(&mut self, function: TrustFunction, peer: PeerKind, level: Option<TrustLevel>) {
        match function {
            TrustFunction::InviteNew => self.invite_new.set(peer, level),
            TrustFunction::ItipUpdates => self.itip_updates.set(peer, level),
            TrustFunction::AutoReply => self.auto_reply.set(peer, level),
            TrustFunction::Mdn => self.mdn.set(peer, level),
            TrustFunction::AutoForward => self.auto_forward.set(peer, level),
            TrustFunction::FreeBusy => self.freebusy.set(peer, level),
            TrustFunction::Sharing => self.sharing.set(peer, level),
            TrustFunction::GroupPost => self.group_post.set(peer, level),
        }
    }
}

/// Действующий потолок уровня: значение уровня выше и по клетке уровень, давшее его. У установки потолок —
/// [`HARD_CEILING`] контракта ([`Ceiling::hard`], источники — `None`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Ceiling {
    /// Значения потолка по клеткам.
    pub matrix: TrustMatrix,
    /// По клетке — уровень, давший потолок; `None` — умолчание контракта.
    #[serde(default)]
    pub sources: TrustSources,
}

impl Ceiling {
    /// Потолок контракта ([`HARD_CEILING`]) — потолок политики установки.
    pub fn hard() -> Self {
        Ceiling {
            matrix: HARD_CEILING,
            sources: TrustSources::default(),
        }
    }
}

/// Действующая матрица учётной записи ([`effective`], `TrustStore::effective_for`): для `trust show --account`
/// и точек решения узла.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Effective {
    /// Действующие значения: клетка — ближайший заданный уровень (установка → организация → группа), из
    /// нескольких групп — самое узкое, шире потолка — обрезано.
    pub matrix: TrustMatrix,
    /// Потолок групп — действующее значение организации (без политики организации — установки; без политик —
    /// [`HARD_CEILING`]).
    pub ceiling: Ceiling,
    /// По клетке — уровень, давший значение; `None` — умолчание контракта.
    pub source: TrustSources,
    /// Клетки, обрезанные потолком: значение уровня шире действующего значения уровня выше («выше потолка»).
    pub over_ceiling: Vec<OverCeiling>,
}

/// Действующая матрица уровней (решение 124 б): значение клетки — ближайший заданный уровень (установка →
/// организация → группа), не задан ни одним — умолчание ([`TrustMatrix::default`]); значение шире потолка
/// обрезается до потолка и попадает в [`Effective::over_ceiling`]. Потолок уровня — явные клетки уровня выше, не
/// заданы — уровень выше, у установки — [`HARD_CEILING`]; из нескольких групп — самое узкое по каждой клетке
/// (при равенстве — первая группа по [`TrustLevel`]). `org` — политика организации с её уровнем, `groups` —
/// политики групп учётной записи с их уровнями.
pub fn effective(
    installation: Option<&TrustPolicy>,
    org: Option<(TrustLevel, &TrustPolicy)>,
    groups: &[(TrustLevel, &TrustPolicy)],
) -> Effective {
    // Установка: значения — явные клетки или умолчание; потолок — контракт.
    let (mut matrix, mut source) = overlay_values(
        installation,
        &TrustLevel::Installation,
        &TrustMatrix::default(),
        &TrustSources::default(),
    );
    let mut over = Vec::new();
    // Потолок организации — явные клетки установки поверх контракта.
    let org_ceiling = overlay_ceiling(installation, &TrustLevel::Installation, &Ceiling::hard());
    let group_ceiling = match org {
        // Значения организации: явные клетки поверх установки; шире потолка — обрезаны (помечены). Потолок
        // групп — явные клетки организации поверх потолка организации.
        Some((level, policy)) => {
            overlay_values_into(&mut matrix, &mut source, policy, &level);
            clamp_level(&mut matrix, &mut source, &org_ceiling, &mut over);
            overlay_ceiling(Some(policy), &level, &org_ceiling)
        }
        None => org_ceiling,
    };

    // Группы: база — организация; заданная клетка сужает, шире потолка — обрезана (помечена).
    let mut sorted: Vec<(TrustLevel, &TrustPolicy)> = groups.to_vec();
    sorted.sort_by_key(|(level, _)| *level);
    for (level, policy) in sorted {
        for function in TrustFunction::ALL {
            for peer in PeerKind::ALL {
                let Some(value) = policy.cell(function, peer) else {
                    continue;
                };
                let ceiling = group_ceiling.matrix.get(function, peer);
                if value > ceiling {
                    over.push(OverCeiling {
                        function,
                        peer,
                        value,
                        ceiling,
                        level: group_ceiling.sources.get_of(function, peer),
                    });
                } else if value < matrix.get(function, peer) {
                    set_cell(&mut matrix, function, peer, value);
                    source.set_of(function, peer, Some(level));
                }
            }
        }
    }
    Effective {
        matrix,
        ceiling: group_ceiling,
        source,
        over_ceiling: over,
    }
}

/// Значения уровня: явные клетки политики (источник — `level`) поверх `base`.
fn overlay_values(
    policy: Option<&TrustPolicy>,
    level: &TrustLevel,
    base: &TrustMatrix,
    base_src: &TrustSources,
) -> (TrustMatrix, TrustSources) {
    let mut matrix = *base;
    let mut source = base_src.clone();
    if let Some(policy) = policy {
        overlay_values_into(&mut matrix, &mut source, policy, level);
    }
    (matrix, source)
}

/// Явные клетки политики поверх значений.
fn overlay_values_into(
    matrix: &mut TrustMatrix,
    source: &mut TrustSources,
    policy: &TrustPolicy,
    level: &TrustLevel,
) {
    for function in TrustFunction::ALL {
        for peer in PeerKind::ALL {
            if let Some(value) = policy.cell(function, peer) {
                set_cell(matrix, function, peer, value);
                source.set_of(function, peer, Some(*level));
            }
        }
    }
}

/// Потолок уровня: явные клетки политики поверх базового потолка (у установки — контракт).
fn overlay_ceiling(policy: Option<&TrustPolicy>, level: &TrustLevel, base: &Ceiling) -> Ceiling {
    let mut ceiling = base.clone();
    if let Some(policy) = policy {
        for function in TrustFunction::ALL {
            for peer in PeerKind::ALL {
                if let Some(value) = policy.cell(function, peer) {
                    set_cell(&mut ceiling.matrix, function, peer, value);
                    ceiling.sources.set_of(function, peer, Some(*level));
                }
            }
        }
    }
    ceiling
}

/// Обрезает значения уровня до потолка: клетка шире — значение потолка (источник — его уровень), клетка — в
/// `over`.
fn clamp_level(
    matrix: &mut TrustMatrix,
    source: &mut TrustSources,
    ceiling: &Ceiling,
    over: &mut Vec<OverCeiling>,
) {
    for function in TrustFunction::ALL {
        for peer in PeerKind::ALL {
            let value = matrix.get(function, peer);
            let ceil = ceiling.matrix.get(function, peer);
            if value > ceil {
                over.push(OverCeiling {
                    function,
                    peer,
                    value,
                    ceiling: ceil,
                    level: ceiling.sources.get_of(function, peer),
                });
                set_cell(matrix, function, peer, ceil);
                source.set_of(function, peer, ceiling.sources.get_of(function, peer));
            }
        }
    }
}

/// Меняет значение клетки матрицы.
fn set_cell(matrix: &mut TrustMatrix, function: TrustFunction, peer: PeerKind, value: CellValue) {
    match value {
        CellValue::Invite(v) => matrix.invite_new.set(peer, v),
        CellValue::Toggle(v) => match function {
            TrustFunction::ItipUpdates => matrix.itip_updates.set(peer, v),
            TrustFunction::AutoReply => matrix.auto_reply.set(peer, v),
            TrustFunction::Mdn => matrix.mdn.set(peer, v),
            _ => matrix.auto_forward.set(peer, v),
        },
        CellValue::Detail(v) => match function {
            TrustFunction::FreeBusy => matrix.freebusy.set(peer, v),
            _ => matrix.sharing.set(peer, v),
        },
        CellValue::Post(v) => matrix.group_post.set(peer, v),
    }
}

// ---------- Хранилище ----------

/// Сигнал об изменении политики доверия уровня `level` ([`EventKind::TrustChanged`]): после фиксации
/// [`TrustStore::set_policy`] и [`TrustStore::reset_policy`]. Узлы сбрасывают кэш действующей матрицы; уровень
/// установки — с `TenantId::DEFAULT`.
pub fn trust_changed(level: TrustLevel) -> Event {
    Event {
        tenant: level.tenant().unwrap_or(TenantId::DEFAULT),
        account: None,
        kind: EventKind::TrustChanged { level },
    }
}

/// Политики доверия (решение 124): уровни установка → организация → группа, домены-партнёры. Реализация —
/// `tp-meta` (META-85), in-memory — `tp-testkit::MemTrust`. Группы учётной записи — через членство; домены
/// партнёров — для вычисления [`PeerKind`] отправителя (точка подключения — smtp-in).
#[async_trait]
pub trait TrustStore: Send + Sync + 'static {
    /// Политика уровня; не задана — `None` (действуют уровень выше и умолчания). Политику чужой организации
    /// видит только она.
    async fn policy(&self, level: TrustLevel) -> Result<Option<TrustPolicy>>;

    /// Записывает политику уровня целиком. Проверяет [`TrustPolicy::validate`] по действующему потолку уровня
    /// (у установки — [`HARD_CEILING`], у организации — действующее значение установки, у группы — организации);
    /// клетки выше потолка — `Invalid` с перечнем. `partners` и `auto_forward_domains` задаёт только организация
    /// (иначе — `Invalid`). После фиксации — сигнал [`trust_changed`].
    async fn set_policy(&self, level: TrustLevel, policy: &TrustPolicy) -> Result<()>;

    /// Удаляет политику уровня (уровень выше и умолчания продолжают действовать); нет — не ошибка. После
    /// фиксации — сигнал [`trust_changed`].
    async fn reset_policy(&self, level: TrustLevel) -> Result<()>;

    /// Действующая матрица учётной записи ([`effective`]): установка → организация → группы учётной записи
    /// (через членство), из нескольких групп — самое узкое. Чужая организация или несуществующая учётная запись —
    /// как без политик организации и групп.
    async fn effective_for(&self, tenant: TenantId, account: AccountId) -> Result<Effective>;

    /// Домен `domain` — партнёр организации `tenant` ([`TrustPolicy::partners`]). Недопустимый домен — `Invalid`.
    async fn partner_of(&self, tenant: TenantId, domain: &str) -> Result<bool>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn org_raise() -> TrustPolicy {
        let mut p = TrustPolicy::default();
        p.invite_new.partner = Some(InviteMode::Auto);
        p
    }

    #[test]
    fn object_safe() {
        fn _store(_: std::sync::Arc<dyn TrustStore>) {}
    }

    #[test]
    fn defaults_are_safe() {
        let d = TrustMatrix::default();
        // Чужим — только почта и REPLY/CANCEL к существующим событиям.
        for peer in [PeerKind::Partner, PeerKind::Neighbor, PeerKind::External] {
            assert_eq!(d.invite_new.get(peer), InviteMode::Button);
            assert_eq!(d.itip_updates.get(peer), Toggle::On);
            assert_eq!(d.auto_reply.get(peer), Toggle::On);
            assert_eq!(d.mdn.get(peer), Toggle::Off);
            assert_eq!(d.auto_forward.get(peer), Toggle::Off);
            assert_eq!(d.freebusy.get(peer), Detail::None);
            assert_eq!(d.sharing.get(peer), Detail::None);
            assert_eq!(d.group_post.get(peer), GroupPost::Closed);
        }
        assert_eq!(d.invite_new.own, InviteMode::Auto);
        assert_eq!(d.freebusy.own, Detail::FreeBusy);
        assert_eq!(d.sharing.own, Detail::All);
        assert_eq!(d.group_post.own, GroupPost::Open);
        // Умолчания не выше потолка контракта.
        for f in TrustFunction::ALL {
            for peer in PeerKind::ALL {
                assert!(
                    d.get(f, peer) <= HARD_CEILING.get(f, peer),
                    "{f}.{peer}: {} > {}",
                    d.get(f, peer),
                    HARD_CEILING.get(f, peer)
                );
            }
        }
        // Закрытая матрица тоже не выше потолка и не шире умолчаний.
        for f in TrustFunction::ALL {
            for peer in PeerKind::ALL {
                let (c, d) = (TrustMatrix::closed().get(f, peer), d.get(f, peer));
                assert!(c <= d, "{f}.{peer}: закрытая шире умолчания");
            }
        }
    }

    #[test]
    fn closed_matrix() {
        let c = TrustMatrix::closed();
        for peer in [PeerKind::Partner, PeerKind::Neighbor, PeerKind::External] {
            assert_eq!(c.invite_new.get(peer), InviteMode::Button);
            assert_eq!(c.itip_updates.get(peer), Toggle::Off);
            assert_eq!(c.auto_reply.get(peer), Toggle::Off);
            assert_eq!(c.freebusy.get(peer), Detail::None);
            assert_eq!(c.group_post.get(peer), GroupPost::Closed);
        }
        // Свои работают.
        assert_eq!(c.invite_new.own, TrustMatrix::default().invite_new.own);
    }

    #[test]
    fn hard_ceiling_invariants() {
        // All — только Own; занятость соседям и интернету закреплена.
        for f in [TrustFunction::FreeBusy, TrustFunction::Sharing] {
            for peer in [PeerKind::Partner, PeerKind::Neighbor, PeerKind::External] {
                assert_ne!(HARD_CEILING.get(f, peer), CellValue::Detail(Detail::All));
            }
        }
        assert_eq!(HARD_CEILING.freebusy.neighbor, Detail::None);
        assert_eq!(HARD_CEILING.freebusy.external, Detail::None);
        assert_eq!(HARD_CEILING.invite_new.neighbor, InviteMode::Button);
        assert_eq!(HARD_CEILING.invite_new.external, InviteMode::Button);
        assert_eq!(HARD_CEILING.freebusy.partner, Detail::Limited);
        assert_eq!(HARD_CEILING.freebusy.own, Detail::Details);
        assert_eq!(HARD_CEILING.sharing.own, Detail::All);
        for peer in PeerKind::ALL {
            assert_eq!(booking_allowed(peer), peer == PeerKind::Own);
            assert_eq!(gal_allowed(peer), peer == PeerKind::Own);
            assert_eq!(delegation_allowed(peer), peer == PeerKind::Own);
            assert_eq!(dsn_diagnostics(peer), peer == PeerKind::Own);
        }
    }

    #[test]
    fn reply_only_toggle() {
        // Порядок от узкого к широкому: Off < ReplyOnly < On (запрет побеждает).
        assert!(Toggle::Off < Toggle::ReplyOnly);
        assert!(Toggle::ReplyOnly < Toggle::On);
        let mut m = TrustMatrix::default();
        m.mdn.partner = Toggle::ReplyOnly;
        assert_eq!(
            serde_json::to_string(&Toggle::ReplyOnly).expect("json"),
            "\"reply_only\""
        );
        assert_eq!(
            serde_json::to_string(&CellValue::Toggle(Toggle::ReplyOnly)).expect("json"),
            "{\"toggle\":\"reply_only\"}"
        );
        // Ответ на наше письмо — как On, прочие письма — как Off; клетки без ReplyOnly — как есть.
        let reply = PeerContext::reply(PeerKind::Partner);
        let plain = PeerContext::new(PeerKind::Partner);
        assert_eq!(
            m.effective(TrustFunction::Mdn, &reply),
            CellValue::Toggle(Toggle::On)
        );
        assert_eq!(
            m.effective(TrustFunction::Mdn, &plain),
            CellValue::Toggle(Toggle::Off)
        );
        assert_eq!(
            m.effective(TrustFunction::AutoReply, &plain),
            CellValue::Toggle(Toggle::On)
        );
        assert_eq!(
            m.effective(TrustFunction::FreeBusy, &reply),
            CellValue::Detail(Detail::None)
        );
        // Сужение берёт узкое: ReplyOnly не шире On, но уже Off.
        let mut wide = TrustMatrix::default();
        wide.mdn.partner = Toggle::On;
        assert_eq!(wide.mdn.narrow_with(&m.mdn).partner, Toggle::ReplyOnly);
        let mut off = TrustMatrix::default();
        off.mdn.partner = Toggle::Off;
        assert_eq!(m.mdn.narrow_with(&off.mdn).partner, Toggle::Off);
        // Умолчания и закрытая матрица клеток ReplyOnly не содержат (значения по умолчанию не меняются).
        for f in [TrustFunction::AutoReply, TrustFunction::Mdn] {
            for peer in PeerKind::ALL {
                let has_reply_only = |matrix: &TrustMatrix| {
                    matches!(matrix.get(f, peer), CellValue::Toggle(Toggle::ReplyOnly))
                };
                assert!(!has_reply_only(&TrustMatrix::default()));
                assert!(!has_reply_only(&TrustMatrix::closed()));
            }
        }
    }

    #[test]
    fn inbound_matrix() {
        use InboundAction::{Booking, Cancel, Invite, Other, Reply, Update};
        let m = TrustMatrix::default();
        for action in [Invite, Update, Reply, Cancel, Other, Booking] {
            assert_eq!(m.inbound(PeerKind::Own, action), InboundDecision::Apply);
        }
        // REPLY, CANCEL и обновление чужих — только к существующему событию.
        for peer in [PeerKind::Partner, PeerKind::Neighbor, PeerKind::External] {
            for action in [Update, Reply, Cancel] {
                assert_eq!(
                    m.inbound(peer, action),
                    InboundDecision::ApplyIfExisting,
                    "{peer} {action:?}"
                );
            }
            // Новое приглашение — кнопка; прочие методы и бронирование — закреплено.
            assert_eq!(m.inbound(peer, Invite), InboundDecision::MailOnly);
            assert_eq!(m.inbound(peer, Other), InboundDecision::MailOnly);
            assert_eq!(m.inbound(peer, Booking), InboundDecision::MailOnly);
        }
        // REQUEST партнёра при Auto — вносится.
        let mut open = TrustMatrix::default();
        open.invite_new.partner = InviteMode::Auto;
        assert_eq!(
            open.inbound(PeerKind::Partner, Invite),
            InboundDecision::Apply
        );
        // Выключенные обновления — только письмо.
        let mut off = TrustMatrix::default();
        off.itip_updates.external = Toggle::Off;
        assert_eq!(
            off.inbound(PeerKind::External, Reply),
            InboundDecision::MailOnly
        );
        // Бронирование чужих — при любой политике.
        let mut wide = TrustMatrix::closed();
        wide.invite_new.partner = InviteMode::Auto;
        assert_eq!(
            wide.inbound(PeerKind::Partner, Booking),
            InboundDecision::MailOnly
        );
    }

    #[test]
    fn effective_without_policies_is_default() {
        let e = effective(None, None, &[]);
        assert_eq!(e.matrix, TrustMatrix::default());
        assert_eq!(e.ceiling.matrix, HARD_CEILING);
        assert_eq!(e.source, TrustSources::default());
        assert!(e.over_ceiling.is_empty());
    }

    #[test]
    fn effective_org_raise_and_installation_cap() {
        let tenant = TenantId::new();
        // Организация поднимает invite_new.partner до Auto — действует.
        let e = effective(None, Some((TrustLevel::Org(tenant), &org_raise())), &[]);
        assert_eq!(e.matrix.invite_new.partner, InviteMode::Auto);
        assert_eq!(e.source.invite_new.partner, Some(TrustLevel::Org(tenant)));
        assert_eq!(e.ceiling.matrix.invite_new.partner, InviteMode::Auto);

        // Установка снижает потолок до Button — Auto обрезан и помечен over_ceiling.
        let mut inst = TrustPolicy::default();
        inst.invite_new.partner = Some(InviteMode::Button);
        let e = effective(
            Some(&inst),
            Some((TrustLevel::Org(tenant), &org_raise())),
            &[],
        );
        assert_eq!(e.matrix.invite_new.partner, InviteMode::Button, "обрезан");
        assert_eq!(e.over_ceiling.len(), 1, "{:?}", e.over_ceiling);
        let cell = &e.over_ceiling[0];
        assert_eq!(cell.function, TrustFunction::InviteNew);
        assert_eq!(cell.peer, PeerKind::Partner);
        assert_eq!(cell.value, CellValue::Invite(InviteMode::Auto));
        assert_eq!(cell.ceiling, CellValue::Invite(InviteMode::Button));
        assert_eq!(cell.level, Some(TrustLevel::Installation));
        // Источник обрезанной клетки — уровень потолка.
        assert_eq!(e.source.invite_new.partner, Some(TrustLevel::Installation));
    }

    #[test]
    fn effective_groups_narrowest() {
        let tenant = TenantId::new();
        let g1 = GroupId::new();
        let g2 = GroupId::new();
        // Организация открывает занятость партнёру и MDN.
        let mut org = TrustPolicy::default();
        org.freebusy.partner = Some(Detail::FreeBusy);
        org.mdn.partner = Some(Toggle::On);
        // Группы: каждая сужает свою клетку.
        let mut a = TrustPolicy::default();
        a.freebusy.partner = Some(Detail::None);
        let mut b = TrustPolicy::default();
        b.mdn.partner = Some(Toggle::Off);
        let groups = vec![
            (TrustLevel::Group(tenant, g1), &a),
            (TrustLevel::Group(tenant, g2), &b),
        ];
        let e = effective(None, Some((TrustLevel::Org(tenant), &org)), &groups);
        // Самое узкое по каждой клетке.
        assert_eq!(e.matrix.freebusy.partner, Detail::None);
        assert_eq!(e.matrix.mdn.partner, Toggle::Off);
        assert!(e.over_ceiling.is_empty(), "{:?}", e.over_ceiling);
        // Источник — группа, давшая значение.
        assert_eq!(
            e.source.freebusy.partner,
            Some(TrustLevel::Group(tenant, g1))
        );
        assert_eq!(e.source.mdn.partner, Some(TrustLevel::Group(tenant, g2)));
        // Группа шире организации — обрезана и помечена.
        let mut narrow_org = TrustPolicy::default();
        narrow_org.freebusy.partner = Some(Detail::None);
        let e = effective(
            None,
            Some((TrustLevel::Org(tenant), &narrow_org)),
            &[(TrustLevel::Group(tenant, g1), &org)],
        );
        assert_eq!(e.matrix.freebusy.partner, Detail::None);
        assert_eq!(e.over_ceiling.len(), 1, "{:?}", e.over_ceiling);
        assert_eq!(e.over_ceiling[0].value, CellValue::Detail(Detail::FreeBusy));
        assert_eq!(e.over_ceiling[0].ceiling, CellValue::Detail(Detail::None));
        assert_eq!(e.over_ceiling[0].level, Some(TrustLevel::Org(tenant)));
    }

    #[test]
    fn validate_rejects_over_ceiling() {
        // freebusy.external = FreeBusy — выше потолка (None, закреплено).
        let mut p = TrustPolicy::default();
        p.freebusy.external = Some(Detail::FreeBusy);
        let err = p.validate(&Ceiling::hard(), &[]).expect_err("выше потолка");
        let Error::Invalid(msg) = err else {
            panic!("не Invalid: {err:?}");
        };
        assert!(msg.contains("freebusy.external"), "{msg}");
        assert!(msg.contains("free_busy"), "{msg}");
        assert!(msg.contains("none"), "{msg}");

        // invite_new.neighbor = Auto — выше потолка (Button, закреплено).
        let mut p = TrustPolicy::default();
        p.invite_new.neighbor = Some(InviteMode::Auto);
        let err = p.validate(&Ceiling::hard(), &[]).expect_err("выше потолка");
        let Error::Invalid(msg) = err else {
            panic!("не Invalid: {err:?}");
        };
        assert!(msg.contains("invite_new.neighbor"), "{msg}");
        assert!(msg.contains("auto"), "{msg}");
        assert!(msg.contains("button"), "{msg}");

        // В пределах потолка — проходит.
        assert_eq!(org_raise().validate(&Ceiling::hard(), &[]), Ok(()));

        // Потолок организации уже: группа не может шире организации.
        let tenant = TenantId::new();
        let mut narrow = TrustPolicy::default();
        narrow.mdn.partner = Some(Toggle::Off);
        let org_ceiling = effective(None, Some((TrustLevel::Org(tenant), &narrow)), &[]).ceiling;
        let mut p = TrustPolicy::default();
        p.mdn.partner = Some(Toggle::On);
        assert!(p.validate(&org_ceiling, &[]).is_err());
        p.mdn.partner = Some(Toggle::Off);
        assert_eq!(p.validate(&org_ceiling, &[]), Ok(()));
    }

    #[test]
    fn validate_domains() {
        let mut p = org_raise();
        p.partners = vec!["partner.example".into(), "PARTNER.EXAMPLE".into()];
        assert!(p.validate(&Ceiling::hard(), &[]).is_err(), "неканонический");
        p.partners = vec!["partner.example".into(), "partner.example".into()];
        assert!(p.validate(&Ceiling::hard(), &[]).is_err(), "повтор");
        p.partners = vec!["xn--e1afmkfd.xn--p1ai".into()];
        p.auto_forward_domains = vec!["example.net".into()];
        assert_eq!(p.validate(&Ceiling::hard(), &[]), Ok(()));
        // Свой принятый домен партнёром быть не может.
        assert!(
            p.validate(&Ceiling::hard(), &["xn--e1afmkfd.xn--p1ai".to_owned()])
                .is_err()
        );
    }

    #[test]
    fn trust_changed_event() {
        let tenant = TenantId::new();
        let e = trust_changed(TrustLevel::Org(tenant));
        assert_eq!(e.tenant, tenant);
        assert_eq!(e.account, None);
        assert!(e.kind.is_system());
        assert_eq!(
            e.kind,
            EventKind::TrustChanged {
                level: TrustLevel::Org(tenant)
            }
        );
        let e = trust_changed(TrustLevel::Installation);
        assert_eq!(e.tenant, TenantId::DEFAULT);
    }

    #[test]
    fn serde_snake_case() {
        let mut p = TrustPolicy::default();
        p.invite_new.partner = Some(InviteMode::Auto);
        p.freebusy.partner = Some(Detail::Limited);
        let s = serde_json::to_string(&p).expect("json");
        assert!(s.contains("\"invite_new\""), "{s}");
        assert!(s.contains("\"partner\":\"auto\""), "{s}");
        assert!(s.contains("\"freebusy\""), "{s}");
        assert!(s.contains("\"limited\""), "{s}");
        // Частичная запись читается (клетки — Option).
        let p: TrustPolicy =
            serde_json::from_str("{\"invite_new\": {\"partner\": \"auto\"}}").expect("parse");
        assert_eq!(p.invite_new.partner, Some(InviteMode::Auto));
        assert_eq!(p.invite_new.own, None);
        assert_eq!(
            serde_json::to_string(&CellValue::Detail(Detail::FreeBusy)).expect("json"),
            "{\"detail\":\"free_busy\"}"
        );
        assert_eq!(
            serde_json::to_string(&InboundDecision::ApplyIfExisting).expect("json"),
            "\"apply_if_existing\""
        );
        assert_eq!(
            serde_json::to_string(&PeerKind::Neighbor).expect("json"),
            "\"neighbor\""
        );
    }
}
