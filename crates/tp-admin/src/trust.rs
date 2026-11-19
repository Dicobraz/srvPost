//! Политика доверия в Admin API (решение 124, ADM-49; CONTRACTS.md#Trust, CTR-93): матрица «кто — кому — что»
//! на уровнях установка → организация → группа, домены-партнёры и домены автопересылки.
//!
//! - Маршруты: установка — `GET|PUT|DELETE /api/v1/trust` (администратор установки); организация — те же методы
//!   под `/api/v1/orgs/{org}/trust`; группа — под `/api/v1/orgs/{org}/groups/{group}/trust` (администратор
//!   организации и установки; `GET` — и оператор); действующая для учётной записи — `GET
//!   /api/v1/orgs/{org}/accounts/{account}/trust`. Права и журнал аудита — общий слой доступа ([`crate::server`]):
//!   каждая запись несёт уровень (шаблон маршрута и `{org}`/`{group}`); состав изменения (клетки старые и новые,
//!   партнёры добавленные и удалённые) CLI показывает различием до/после (`trust set`) — детали записи журнала —
//!   вопрос #108.
//! - `GET` уровня — [`TrustView`]: своя политика (`own`), действующая матрица ([`Effective`]: значения, потолок,
//!   источник по клеткам, клетки выше потолка) и закреплённые клетки контракта ([`TrustFixed`]).
//! - `PUT` — замена политики уровня целиком ([`TrustBody`]; незаданные клетки наследуют уровень выше, у организации
//!   — `partners` и `auto_forward_domains`). Проверка потолка — [`TrustPolicy::validate`] по действующему потолку
//!   уровня выше: клетки выше — 422 problem+json с `errors: [{function, peer, value, ceiling, level}]` и пояснением
//!   по-русски; домен-партнёр из принятых доменов своей организации — тоже 422. Снижение потолка не отклоняется:
//!   значения ниже по иерархии шире нового потолка отдаются с `over_ceiling`. Хранилище подключает
//!   [`Admin::with_trust`]; без него маршруты отвечают 503.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::{Deserialize, Serialize};
use tp_contracts::trust::{
    Ceiling, CellValue, Detail, Effective, GroupPost, HARD_CEILING, InviteMode, OverCeiling,
    PeerKind, PerPeer, Toggle, TrustFunction, TrustLevel, TrustPolicy, TrustStore, effective,
};
use tp_contracts::{AccountId, Error, GroupId, TenantId};
use utoipa::{OpenApi, ToSchema};

use crate::branding::RefusedResponse;
use crate::extract::{Json, Path};
use crate::server::{Admin, ApiError, Problem, Refused};

/// Политика доверия установки (только администратор установки, [`crate::AdminRole::permits`]).
pub const INSTALLATION_TRUST: &str = "/api/v1/trust";
/// Политика доверия организации.
pub const ORG_TRUST: &str = "/api/v1/orgs/{org}/trust";
/// Политика доверия группы.
pub const GROUP_TRUST: &str = "/api/v1/orgs/{org}/groups/{group}/trust";
/// Действующая политика учётной записи.
pub const ACCOUNT_TRUST: &str = "/api/v1/orgs/{org}/accounts/{account}/trust";

// ---------- Схемы OpenAPI контрактов `tp_contracts::trust` (в `serde` — тот же вид); значений типов нет ----------

/// Новое приглашение: письмо с кнопкой или автодобавление.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = InviteMode)]
pub enum InviteModeSchema {
    /// Письмо с частью `text/calendar` и кнопкой «Добавить» в клиенте.
    Button,
    /// Вносится в календарь по умолчанию — только партнёрам, если открыл администратор.
    Auto,
}

/// Выключено или включено.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = Toggle)]
pub enum ToggleSchema {
    /// Выключено.
    Off,
    /// Включено.
    On,
}

/// Уровень детализации занятости и общего доступа.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = Detail)]
pub enum DetailSchema {
    /// Ничего не отдаётся.
    None,
    /// «Свободен/занят» — интервалы без содержания.
    FreeBusy,
    /// Ограниченные подробности: время, тема, место.
    Limited,
    /// Подробности — полный просмотр без изменения.
    Details,
    /// Всё, включая изменение (только своей организации).
    All,
}

/// Письма в группы рассылки от типа абонента.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = GroupPost)]
pub enum GroupPostSchema {
    /// Закрыта: письмо чужого отклоняется в сессии SMTP.
    Closed,
    /// С модерацией.
    Moderated,
    /// Открыта: ограничения группы действуют как для своих.
    Open,
}

/// Значение по клетке (адресация клеток в ошибках).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = CellValue)]
pub enum CellValueSchema {
    /// Клетка «новое приглашение».
    Invite(InviteModeSchema),
    /// Клетки обновлений, автоответа, MDN, автопересылки.
    Toggle(ToggleSchema),
    /// Клетки занятости и общего доступа.
    Detail(DetailSchema),
    /// Клетка «письма в группы».
    Post(GroupPostSchema),
}

/// Тип абонента матрицы.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = PeerKind)]
pub enum PeerKindSchema {
    /// Своя организация.
    Own,
    /// Домен-партнёр.
    Partner,
    /// Сосед по установке (MSSP).
    Neighbor,
    /// Интернет.
    External,
}

/// Функция матрицы.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = TrustFunction)]
pub enum TrustFunctionSchema {
    /// Новое приглашение (`REQUEST`).
    InviteNew,
    /// `REPLY`, `CANCEL` и обновление `REQUEST` к существующим событиям.
    ItipUpdates,
    /// Автоответ.
    AutoReply,
    /// Уведомление о прочтении (MDN) наружу.
    Mdn,
    /// Автопересылка наружу.
    AutoForward,
    /// Занятость (free/busy).
    FreeBusy,
    /// Общий доступ и публикация календарей.
    Sharing,
    /// Письма в группы рассылки.
    GroupPost,
}

/// Уровень политики: установка → организация → группа.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[schema(as = TrustLevel)]
pub enum TrustLevelSchema {
    /// Установка — потолки для всех организаций.
    Installation,
    /// Организация (UUID).
    Org(String),
    /// Группа (UUID организации, UUID группы).
    Group(String, String),
}

/// Значения по типам абонентов — колонки матрицы (клетки политики; `null` — наследуется уровнем выше).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PerPeerInviteOption)]
pub struct PerPeerInviteOptionSchema {
    /// Своя организация.
    pub own: Option<InviteModeSchema>,
    /// Домен-партнёр.
    pub partner: Option<InviteModeSchema>,
    /// Сосед по установке.
    pub neighbor: Option<InviteModeSchema>,
    /// Интернет.
    pub external: Option<InviteModeSchema>,
}

/// [`PerPeerInviteOptionSchema`] для выключено/включено.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PerPeerToggleOption)]
pub struct PerPeerToggleOptionSchema {
    /// Своя организация.
    pub own: Option<ToggleSchema>,
    /// Домен-партнёр.
    pub partner: Option<ToggleSchema>,
    /// Сосед по установке.
    pub neighbor: Option<ToggleSchema>,
    /// Интернет.
    pub external: Option<ToggleSchema>,
}

/// [`PerPeerInviteOptionSchema`] для детализации.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PerPeerDetailOption)]
pub struct PerPeerDetailOptionSchema {
    /// Своя организация.
    pub own: Option<DetailSchema>,
    /// Домен-партнёр.
    pub partner: Option<DetailSchema>,
    /// Сосед по установке.
    pub neighbor: Option<DetailSchema>,
    /// Интернет.
    pub external: Option<DetailSchema>,
}

/// [`PerPeerInviteOptionSchema`] для писем в группы.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PerPeerGroupPostOption)]
pub struct PerPeerGroupPostOptionSchema {
    /// Своя организация.
    pub own: Option<GroupPostSchema>,
    /// Домен-партнёр.
    pub partner: Option<GroupPostSchema>,
    /// Сосед по установке.
    pub neighbor: Option<GroupPostSchema>,
    /// Интернет.
    pub external: Option<GroupPostSchema>,
}

/// Колонки матрицы со значениями (действующая матрица).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PerPeerInvite)]
pub struct PerPeerInviteSchema {
    /// Своя организация.
    pub own: InviteModeSchema,
    /// Домен-партнёр.
    pub partner: InviteModeSchema,
    /// Сосед по установке.
    pub neighbor: InviteModeSchema,
    /// Интернет.
    pub external: InviteModeSchema,
}

/// [`PerPeerInviteSchema`] для выключено/включено.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PerPeerToggle)]
pub struct PerPeerToggleSchema {
    /// Своя организация.
    pub own: ToggleSchema,
    /// Домен-партнёр.
    pub partner: ToggleSchema,
    /// Сосед по установке.
    pub neighbor: ToggleSchema,
    /// Интернет.
    pub external: ToggleSchema,
}

/// [`PerPeerInviteSchema`] для детализации.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PerPeerDetail)]
pub struct PerPeerDetailSchema {
    /// Своя организация.
    pub own: DetailSchema,
    /// Домен-партнёр.
    pub partner: DetailSchema,
    /// Сосед по установке.
    pub neighbor: DetailSchema,
    /// Интернет.
    pub external: DetailSchema,
}

/// [`PerPeerInviteSchema`] для писем в группы.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PerPeerGroupPost)]
pub struct PerPeerGroupPostSchema {
    /// Своя организация.
    pub own: GroupPostSchema,
    /// Домен-партнёр.
    pub partner: GroupPostSchema,
    /// Сосед по установке.
    pub neighbor: GroupPostSchema,
    /// Интернет.
    pub external: GroupPostSchema,
}

/// По клетке — уровень, давший значение (`null` — умолчание контракта).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PerPeerTrustLevel)]
pub struct PerPeerTrustLevelSchema {
    /// Своя организация.
    pub own: Option<TrustLevelSchema>,
    /// Домен-партнёр.
    pub partner: Option<TrustLevelSchema>,
    /// Сосед по установке.
    pub neighbor: Option<TrustLevelSchema>,
    /// Интернет.
    pub external: Option<TrustLevelSchema>,
}

/// Закреплённые клетки контракта: по клетке — ничем не меняется.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = PerPeerBool)]
pub struct PerPeerBoolSchema {
    /// Своя организация.
    pub own: bool,
    /// Домен-партнёр.
    pub partner: bool,
    /// Сосед по установке.
    pub neighbor: bool,
    /// Интернет.
    pub external: bool,
}

/// Политика уровня (клетки `null` наследуют уровень выше; `partners` и `auto_forward_domains` — только организация).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = TrustPolicy)]
pub struct TrustPolicySchema {
    /// Новое приглашение.
    pub invite_new: PerPeerInviteOptionSchema,
    /// `REPLY`, `CANCEL` и обновление `REQUEST` к существующим событиям.
    pub itip_updates: PerPeerToggleOptionSchema,
    /// Автоответ.
    pub auto_reply: PerPeerToggleOptionSchema,
    /// MDN наружу.
    pub mdn: PerPeerToggleOptionSchema,
    /// Автопересылка наружу.
    pub auto_forward: PerPeerToggleOptionSchema,
    /// Занятость.
    pub freebusy: PerPeerDetailOptionSchema,
    /// Общий доступ и публикация.
    pub sharing: PerPeerDetailOptionSchema,
    /// Письма в группы рассылки.
    pub group_post: PerPeerGroupPostOptionSchema,
    /// Домены-партнёры организации (канонические имена; свой принятый домен — 422).
    pub partners: Vec<String>,
    /// Домены, куда разрешена автопересылка (при `auto_forward.external = on`).
    pub auto_forward_domains: Vec<String>,
}

/// Действующая матрица: по клетке на функцию и тип абонента.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = TrustMatrix)]
pub struct TrustMatrixSchema {
    /// Новое приглашение.
    pub invite_new: PerPeerInviteSchema,
    /// Ответ и отмена к существующим событиям.
    pub itip_updates: PerPeerToggleSchema,
    /// Автоответ.
    pub auto_reply: PerPeerToggleSchema,
    /// MDN наружу.
    pub mdn: PerPeerToggleSchema,
    /// Автопересылка наружу.
    pub auto_forward: PerPeerToggleSchema,
    /// Занятость.
    pub freebusy: PerPeerDetailSchema,
    /// Общий доступ и публикация.
    pub sharing: PerPeerDetailSchema,
    /// Письма в группы рассылки.
    pub group_post: PerPeerGroupPostSchema,
}

/// Источник значения по клеткам: уровень, давший значение; `null` — умолчание контракта.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = TrustSources)]
pub struct TrustSourcesSchema {
    /// Новое приглашение.
    pub invite_new: PerPeerTrustLevelSchema,
    /// Ответ и отмена.
    pub itip_updates: PerPeerTrustLevelSchema,
    /// Автоответ.
    pub auto_reply: PerPeerTrustLevelSchema,
    /// MDN наружу.
    pub mdn: PerPeerTrustLevelSchema,
    /// Автопересылка наружу.
    pub auto_forward: PerPeerTrustLevelSchema,
    /// Занятость.
    pub freebusy: PerPeerTrustLevelSchema,
    /// Общий доступ и публикация.
    pub sharing: PerPeerTrustLevelSchema,
    /// Письма в группы рассылки.
    pub group_post: PerPeerTrustLevelSchema,
}

/// Действующий потолок уровня: значения уровня выше и по клетке уровень, давшее его.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = Ceiling)]
pub struct CeilingSchema {
    /// Значения потолка по клеткам.
    pub matrix: TrustMatrixSchema,
    /// По клетке — уровень, давший потолок; `null` — умолчание контракта.
    pub sources: TrustSourcesSchema,
}

/// Клетка выше потолка.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = OverCeiling)]
pub struct OverCeilingSchema {
    /// Функция клетки.
    pub function: TrustFunctionSchema,
    /// Тип абонента клетки.
    pub peer: PeerKindSchema,
    /// Заданное значение.
    pub value: CellValueSchema,
    /// Потолок.
    pub ceiling: CellValueSchema,
    /// Уровень, давший потолок; `null` — умолчание контракта (закреплено).
    pub level: Option<TrustLevelSchema>,
}

/// Действующая матрица с потолком и источниками.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = Effective)]
pub struct EffectiveSchema {
    /// Действующие значения.
    pub matrix: TrustMatrixSchema,
    /// Действующий потолок.
    pub ceiling: CeilingSchema,
    /// По клетке — уровень, давший значение.
    pub source: TrustSourcesSchema,
    /// Клетки, обрезанные потолком («выше потолка»).
    pub over_ceiling: Vec<OverCeilingSchema>,
}

/// Закреплённые клетки контракта ([`TrustFixed`]) — по клетке (никто не меняет: потолок равен самому узкому
/// значению, умолчание — оно же).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = TrustFixed)]
pub struct TrustFixedSchema {
    /// Новое приглашение.
    pub invite_new: PerPeerBoolSchema,
    /// Ответ и отмена.
    pub itip_updates: PerPeerBoolSchema,
    /// Автоответ.
    pub auto_reply: PerPeerBoolSchema,
    /// MDN наружу.
    pub mdn: PerPeerBoolSchema,
    /// Автопересылка наружу.
    pub auto_forward: PerPeerBoolSchema,
    /// Занятость.
    pub freebusy: PerPeerBoolSchema,
    /// Общий доступ и публикация.
    pub sharing: PerPeerBoolSchema,
    /// Письма в группы рассылки.
    pub group_post: PerPeerBoolSchema,
}

// ---------- Тело и ответы ----------

/// Замена политики уровня целиком: незаданные клетки наследуют уровень выше; `partners` и
/// `auto_forward_domains` задаёт только организация. Закреплённых клеток (бронирование, GAL, делегирование,
/// DSN, прочие методы iTIP) в политике нет — их тела нет и быть не может (400).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct TrustBody {
    /// Новое приглашение.
    #[serde(default)]
    #[schema(value_type = PerPeerInviteOptionSchema)]
    pub invite_new: PerPeer<Option<InviteMode>>,
    /// `REPLY`, `CANCEL` и обновление `REQUEST` к существующим событиям.
    #[serde(default)]
    #[schema(value_type = PerPeerToggleOptionSchema)]
    pub itip_updates: PerPeer<Option<Toggle>>,
    /// Автоответ.
    #[serde(default)]
    #[schema(value_type = PerPeerToggleOptionSchema)]
    pub auto_reply: PerPeer<Option<Toggle>>,
    /// MDN наружу.
    #[serde(default)]
    #[schema(value_type = PerPeerToggleOptionSchema)]
    pub mdn: PerPeer<Option<Toggle>>,
    /// Автопересылка наружу.
    #[serde(default)]
    #[schema(value_type = PerPeerToggleOptionSchema)]
    pub auto_forward: PerPeer<Option<Toggle>>,
    /// Занятость.
    #[serde(default)]
    #[schema(value_type = PerPeerDetailOptionSchema)]
    pub freebusy: PerPeer<Option<Detail>>,
    /// Общий доступ и публикация.
    #[serde(default)]
    #[schema(value_type = PerPeerDetailOptionSchema)]
    pub sharing: PerPeer<Option<Detail>>,
    /// Письма в группы рассылки.
    #[serde(default)]
    #[schema(value_type = PerPeerGroupPostOptionSchema)]
    pub group_post: PerPeer<Option<GroupPost>>,
    /// Домены-партнёры (только уровень организации): канонические имена — нижний регистр, A-label IDN.
    #[serde(default)]
    pub partners: Vec<String>,
    /// Домены, куда разрешена автопересылка (только уровень организации); канонические имена.
    #[serde(default)]
    pub auto_forward_domains: Vec<String>,
}

impl From<TrustBody> for TrustPolicy {
    fn from(b: TrustBody) -> Self {
        Self {
            invite_new: b.invite_new,
            itip_updates: b.itip_updates,
            auto_reply: b.auto_reply,
            mdn: b.mdn,
            auto_forward: b.auto_forward,
            freebusy: b.freebusy,
            sharing: b.sharing,
            group_post: b.group_post,
            partners: b.partners,
            auto_forward_domains: b.auto_forward_domains,
        }
    }
}

impl From<&TrustPolicy> for TrustBody {
    fn from(p: &TrustPolicy) -> Self {
        Self {
            invite_new: p.invite_new,
            itip_updates: p.itip_updates,
            auto_reply: p.auto_reply,
            mdn: p.mdn,
            auto_forward: p.auto_forward,
            freebusy: p.freebusy,
            sharing: p.sharing,
            group_post: p.group_post,
            partners: p.partners.clone(),
            auto_forward_domains: p.auto_forward_domains.clone(),
        }
    }
}

/// Закреплённые клетки контракта: по клетке — не меняется никем (потолок [`HARD_CEILING`] равен самому узкому
/// значению, умолчание — оно же; бронирование, GAL, делегирование, DSN и прочие методы iTIP закреплены целиком
/// и клетками политики не являются).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustFixed {
    /// Новое приглашение.
    pub invite_new: PerPeer<bool>,
    /// Ответ и отмена.
    pub itip_updates: PerPeer<bool>,
    /// Автоответ.
    pub auto_reply: PerPeer<bool>,
    /// MDN наружу.
    pub mdn: PerPeer<bool>,
    /// Автопересылка наружу.
    pub auto_forward: PerPeer<bool>,
    /// Занятость.
    pub freebusy: PerPeer<bool>,
    /// Общий доступ и публикация.
    pub sharing: PerPeer<bool>,
    /// Письма в группы рассылки.
    pub group_post: PerPeer<bool>,
}

impl TrustFixed {
    /// Закреплённые клетки контракта.
    pub fn contract() -> Self {
        let narrowest = |f: TrustFunction| match f {
            TrustFunction::InviteNew => CellValue::Invite(InviteMode::Button),
            TrustFunction::ItipUpdates
            | TrustFunction::AutoReply
            | TrustFunction::Mdn
            | TrustFunction::AutoForward => CellValue::Toggle(Toggle::Off),
            TrustFunction::FreeBusy | TrustFunction::Sharing => CellValue::Detail(Detail::None),
            TrustFunction::GroupPost => CellValue::Post(GroupPost::Closed),
        };
        let mut fixed = TrustFixed {
            invite_new: PerPeer::default(),
            itip_updates: PerPeer::default(),
            auto_reply: PerPeer::default(),
            mdn: PerPeer::default(),
            auto_forward: PerPeer::default(),
            freebusy: PerPeer::default(),
            sharing: PerPeer::default(),
            group_post: PerPeer::default(),
        };
        for f in TrustFunction::ALL {
            for peer in PeerKind::ALL {
                let fixed_cell = HARD_CEILING.get(f, peer) == narrowest(f);
                match f {
                    TrustFunction::InviteNew => fixed.invite_new.set(peer, fixed_cell),
                    TrustFunction::ItipUpdates => fixed.itip_updates.set(peer, fixed_cell),
                    TrustFunction::AutoReply => fixed.auto_reply.set(peer, fixed_cell),
                    TrustFunction::Mdn => fixed.mdn.set(peer, fixed_cell),
                    TrustFunction::AutoForward => fixed.auto_forward.set(peer, fixed_cell),
                    TrustFunction::FreeBusy => fixed.freebusy.set(peer, fixed_cell),
                    TrustFunction::Sharing => fixed.sharing.set(peer, fixed_cell),
                    TrustFunction::GroupPost => fixed.group_post.set(peer, fixed_cell),
                }
            }
        }
        fixed
    }

    /// Клетка закреплена.
    pub fn get(&self, function: TrustFunction, peer: PeerKind) -> bool {
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
}

/// Политика уровня и действующая матрица.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TrustView {
    /// Политика уровня; `null` — уровень не задан (наследует уровень выше). У учётной записи своей политики нет.
    #[schema(value_type = Option<TrustPolicySchema>)]
    pub own: Option<TrustPolicy>,
    /// Действующая матрица: у группы — как для участника одной этой группы, у учётной записи — со всеми её
    /// группами (самое узкое).
    #[schema(value_type = EffectiveSchema)]
    pub effective: Effective,
    /// Клетки, закреплённые контрактом (не меняются ни на одном уровне).
    #[schema(value_type = TrustFixedSchema)]
    pub fixed: TrustFixed,
}

/// Отказ записи политики: клетки выше потолка или недопустимые домены (RFC 9457 с расширением `errors`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TrustProblem {
    /// Код HTTP (422).
    pub status: u16,
    /// Краткое описание кода.
    pub title: String,
    /// Клетки выше потолка по-русски, через «; » (у доменов — причина).
    pub detail: String,
    /// Клетки выше потолка (`level` — уровень, давший потолок; `null` — закреплено контрактом).
    #[schema(value_type = Vec<OverCeilingSchema>)]
    pub errors: Vec<OverCeiling>,
}

/// Маршруты политики доверия за слоем доступа.
pub(crate) fn routes(r: Router<Arc<Admin>>) -> Router<Arc<Admin>> {
    r.route(
        INSTALLATION_TRUST,
        get(get_installation_trust)
            .put(put_installation_trust)
            .delete(reset_installation_trust),
    )
    .route(
        ORG_TRUST,
        get(get_org_trust)
            .put(put_org_trust)
            .delete(reset_org_trust),
    )
    .route(
        GROUP_TRUST,
        get(get_group_trust)
            .put(put_group_trust)
            .delete(reset_group_trust),
    )
    .route(ACCOUNT_TRUST, get(get_account_trust))
}

/// Спецификация OpenAPI маршрутов модуля.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        get_installation_trust,
        put_installation_trust,
        reset_installation_trust,
        get_org_trust,
        put_org_trust,
        reset_org_trust,
        get_group_trust,
        put_group_trust,
        reset_group_trust,
        get_account_trust
    ),
    components(schemas(
        InviteModeSchema,
        ToggleSchema,
        DetailSchema,
        GroupPostSchema,
        CellValueSchema,
        PeerKindSchema,
        TrustFunctionSchema,
        TrustLevelSchema,
        PerPeerInviteOptionSchema,
        PerPeerToggleOptionSchema,
        PerPeerDetailOptionSchema,
        PerPeerGroupPostOptionSchema,
        PerPeerInviteSchema,
        PerPeerToggleSchema,
        PerPeerDetailSchema,
        PerPeerGroupPostSchema,
        PerPeerTrustLevelSchema,
        PerPeerBoolSchema,
        TrustPolicySchema,
        TrustMatrixSchema,
        TrustSourcesSchema,
        CeilingSchema,
        OverCeilingSchema,
        EffectiveSchema,
        TrustFixedSchema,
        TrustBody,
        TrustView,
        TrustProblem
    ))
)]
pub(crate) struct Doc;

// ---------- Внутренние помощники ----------

impl Admin {
    /// Подключает политику доверия ([`crate::trust`]): уровни, домены-партнёры.
    pub fn with_trust(mut self, store: Arc<dyn TrustStore>) -> Self {
        self.trust = Some(store);
        self
    }
}

/// Хранилище политик; не подключено — 503.
fn store(a: &Admin) -> std::result::Result<&Arc<dyn TrustStore>, Error> {
    a.trust.as_ref().ok_or(Error::UNAVAILABLE)
}

/// Политика уровня или `None`.
async fn policy(a: &Admin, level: TrustLevel) -> std::result::Result<Option<TrustPolicy>, Error> {
    store(a)?.policy(level).await
}

/// Ответ уровня: своя политика, действующая матрица (у группы — как для участника одной этой группы) и
/// закреплённые клетки.
async fn view(a: &Admin, level: TrustLevel) -> std::result::Result<TrustView, Error> {
    let own = policy(a, level).await?;
    let inst = policy(a, TrustLevel::Installation).await?;
    let effective = match level {
        TrustLevel::Installation => effective(inst.as_ref(), None, &[]),
        TrustLevel::Org(t) => {
            let org = own.as_ref().map(|p| (TrustLevel::Org(t), p));
            effective(inst.as_ref(), org, &[])
        }
        TrustLevel::Group(t, _) => {
            let org = policy(a, TrustLevel::Org(t)).await?;
            let org = org.as_ref().map(|p| (TrustLevel::Org(t), p));
            let groups: Vec<(TrustLevel, &TrustPolicy)> =
                own.as_ref().map(|p| (level, p)).into_iter().collect();
            effective(inst.as_ref(), org, &groups)
        }
    };
    Ok(TrustView {
        own,
        effective,
        fixed: TrustFixed::contract(),
    })
}

/// Действующий потолок записи уровня `level` и принятые домены его организации (для проверки `partners`):
/// у установки — потолок контракта, у организации — явные клетки установки, у группы — организации
/// (то же проверяет хранилище в `set_policy`: MemTrust tp-testkit и PgMeta).
async fn write_ceiling(
    a: &Admin,
    level: TrustLevel,
) -> std::result::Result<(Ceiling, Vec<String>), Error> {
    let tenant = level.tenant();
    let inst = policy(a, TrustLevel::Installation).await?;
    let (ceiling, accepted) = match tenant {
        None => (Ceiling::hard(), Vec::new()),
        Some(t) => {
            // Потолок уровня: организация пишет в пределах значений установки (без своей политики — она и
            // есть записываемое), группа — в пределах действующих значений организации.
            let ceiling = match level {
                TrustLevel::Group(..) => {
                    let org = policy(a, TrustLevel::Org(t)).await?;
                    let org = org.as_ref().map(|p| (TrustLevel::Org(t), p));
                    effective(inst.as_ref(), org, &[]).ceiling
                }
                _ => effective(inst.as_ref(), None, &[]).ceiling,
            };
            (ceiling, accepted_domains(a, t).await?)
        }
    };
    Ok((ceiling, accepted))
}

/// Принятые домены организации (транспорт; без него — пусто: список проверить нельзя, домен-партнёр свой
/// домен отклонит хранилище).
async fn accepted_domains(a: &Admin, tenant: TenantId) -> std::result::Result<Vec<String>, Error> {
    let Some(transport) = &a.transport else {
        return Ok(Vec::new());
    };
    Ok(transport
        .cluster()
        .await?
        .domains
        .into_iter()
        .filter(|d| d.tenant == tenant)
        .map(|d| d.name)
        .collect())
}

/// Источник потолка по клетке ([`TrustSources`] с приватным доступом — по функции).
fn source_of(
    s: &tp_contracts::trust::TrustSources,
    f: TrustFunction,
    peer: PeerKind,
) -> Option<TrustLevel> {
    match f {
        TrustFunction::InviteNew => s.invite_new.get(peer),
        TrustFunction::ItipUpdates => s.itip_updates.get(peer),
        TrustFunction::AutoReply => s.auto_reply.get(peer),
        TrustFunction::Mdn => s.mdn.get(peer),
        TrustFunction::AutoForward => s.auto_forward.get(peer),
        TrustFunction::FreeBusy => s.freebusy.get(peer),
        TrustFunction::Sharing => s.sharing.get(peer),
        TrustFunction::GroupPost => s.group_post.get(peer),
    }
}

/// Заданные клетки политики выше потолка (структурный перечень для 422; сравнение — как у
/// [`TrustPolicy::validate`], чей текст не несёт полей).
fn over_ceiling(policy: &TrustPolicy, ceiling: &Ceiling) -> Vec<OverCeiling> {
    let mut over = Vec::new();
    for f in TrustFunction::ALL {
        for peer in PeerKind::ALL {
            let Some(value) = policy.cell(f, peer) else {
                continue;
            };
            let ceil = ceiling.matrix.get(f, peer);
            if value > ceil {
                over.push(OverCeiling {
                    function: f,
                    peer,
                    value,
                    ceiling: ceil,
                    level: source_of(&ceiling.sources, f, peer),
                });
            }
        }
    }
    over
}

/// Функция по-русски.
fn function_ru(f: TrustFunction) -> &'static str {
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

/// Тип абонента по-русски.
fn peer_ru(p: PeerKind) -> &'static str {
    match p {
        PeerKind::Own => "свои",
        PeerKind::Partner => "партнёр",
        PeerKind::Neighbor => "сосед",
        PeerKind::External => "интернет",
    }
}

/// Значение клетки по-русски.
fn value_ru(v: CellValue) -> &'static str {
    match v {
        CellValue::Invite(InviteMode::Button) => "письмо с кнопкой",
        CellValue::Invite(InviteMode::Auto) => "авто",
        CellValue::Toggle(Toggle::Off) => "выключено",
        CellValue::Toggle(Toggle::On) => "включено",
        CellValue::Detail(Detail::None) => "нет",
        CellValue::Detail(Detail::FreeBusy) => "свободен/занят",
        CellValue::Detail(Detail::Limited) => "ограниченные подробности",
        CellValue::Detail(Detail::Details) => "подробности",
        CellValue::Detail(Detail::All) => "всё",
        CellValue::Post(GroupPost::Closed) => "закрыто",
        CellValue::Post(GroupPost::Moderated) => "с модерацией",
        CellValue::Post(GroupPost::Open) => "открыто",
    }
}

/// Клетка выше потолка по-русски: «Новое приглашение, сосед: «авто» выше потолка «письмо с кнопкой» (закреплено)».
fn over_ru(o: &OverCeiling) -> String {
    let level = match o.level {
        None => " (закреплено)".to_owned(),
        Some(level) => format!(" (потолок: уровень {level})"),
    };
    format!(
        "{}, {}: «{}» выше потолка «{}»{level}",
        function_ru(o.function),
        peer_ru(o.peer),
        value_ru(o.value),
        value_ru(o.ceiling)
    )
}

/// Ответ 422 problem+json (RFC 9457) с расширением `errors`.
fn refused(problem: TrustProblem) -> RefusedResponse {
    let status = StatusCode::UNPROCESSABLE_ENTITY;
    let mut resp = (status, axum::Json(problem)).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    resp.into()
}

/// 422 с пояснением без перечня клеток (домены).
fn refused_detail(detail: String) -> RefusedResponse {
    refused(TrustProblem {
        status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
        title: StatusCode::UNPROCESSABLE_ENTITY
            .canonical_reason()
            .unwrap_or_default()
            .to_owned(),
        detail,
        errors: Vec::new(),
    })
}

/// Записывает политику уровня: проверка потолка и доменов — 422, ошибка хранилища (включая `partners` не на
/// уровне организации) — как есть; ответ — вид уровня после записи.
async fn put(
    a: &Admin,
    level: TrustLevel,
    body: TrustBody,
) -> std::result::Result<Json<TrustView>, RefusedResponse> {
    let err = |e: Error| RefusedResponse::from(ApiError(e).into_response());
    let policy: TrustPolicy = body.into();
    let (ceiling, accepted) = match write_ceiling(a, level).await {
        Ok(c) => c,
        Err(e) => return Err(err(e)),
    };
    let over = over_ceiling(&policy, &ceiling);
    if !over.is_empty() {
        let detail = over.iter().map(over_ru).collect::<Vec<_>>().join("; ");
        return Err(refused(TrustProblem {
            status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
            title: StatusCode::UNPROCESSABLE_ENTITY
                .canonical_reason()
                .unwrap_or_default()
                .to_owned(),
            detail: format!("клетки выше потолка: {detail}"),
            errors: over,
        }));
    }
    if let Err(e) = policy.validate(&ceiling, &accepted) {
        let Error::Invalid(detail) = e else {
            return Err(err(e));
        };
        return Err(refused_detail(detail));
    }
    let store = match store(a) {
        Ok(s) => s,
        Err(e) => return Err(err(e)),
    };
    if let Err(e) = store.set_policy(level, &policy).await {
        // Хранилище проверяет то же (`partners` не на уровне организации и пр.) — тоже 422.
        if let Error::Invalid(detail) = &e {
            return Err(refused_detail(detail.clone()));
        }
        return Err(err(e));
    }
    match view(a, level).await {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(err(e)),
    }
}

/// Группа организации существует; нет — 404.
async fn group_exists(a: &Admin, org: TenantId, group: GroupId) -> std::result::Result<(), Error> {
    a.d.groups
        .get(org, group)
        .await?
        .ok_or(Error::NotFound)
        .map(drop)
}

// ---------- Маршруты ----------

/// Политика доверия установки: своя, действующая и закреплённые клетки. Уровень установки читает и меняет
/// только администратор установки.
#[utoipa::path(get, path = "/api/v1/trust", tag = "trust",
    responses((status = 200, body = TrustView), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 503, body = Problem)))]
async fn get_installation_trust(
    State(a): State<Arc<Admin>>,
) -> std::result::Result<Json<TrustView>, Refused> {
    Ok(Json(view(&a, TrustLevel::Installation).await?))
}

/// Заменяет политику установки целиком (потолки для всех организаций). Клетки выше потолка контракта —
/// 422 problem+json с `errors`; закреплённых клеток в теле нет (`booking` и пр. — 400); хранилище не
/// подключено — 503.
#[utoipa::path(put, path = "/api/v1/trust", tag = "trust",
    request_body = TrustBody,
    responses((status = 200, body = TrustView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem),
        (status = 422, description = "клетки выше потолка контракта", body = TrustProblem),
        (status = 503, body = Problem)))]
async fn put_installation_trust(
    State(a): State<Arc<Admin>>,
    Json(body): Json<TrustBody>,
) -> std::result::Result<Json<TrustView>, RefusedResponse> {
    put(&a, TrustLevel::Installation, body).await
}

/// Сбрасывает политику установки к потолку контракта (`HARD_CEILING`); организации и группы продолжают
/// действовать со своими политиками. Сброс незаданного уровня — не ошибка.
#[utoipa::path(delete, path = "/api/v1/trust", tag = "trust",
    responses((status = 200, body = TrustView), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 503, body = Problem)))]
async fn reset_installation_trust(
    State(a): State<Arc<Admin>>,
) -> std::result::Result<Json<TrustView>, Refused> {
    store(&a)?.reset_policy(TrustLevel::Installation).await?;
    Ok(Json(view(&a, TrustLevel::Installation).await?))
}

/// Политика доверия организации: своя, действующая (организация поверх установки) и закреплённые клетки.
#[utoipa::path(get, path = "/api/v1/orgs/{org}/trust", tag = "trust",
    params(("org" = String, Path, description = "Организация (UUID)")),
    responses((status = 200, body = TrustView), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn get_org_trust(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
) -> std::result::Result<Json<TrustView>, Refused> {
    Ok(Json(view(&a, TrustLevel::Org(org)).await?))
}

/// Заменяет политику организации целиком: клетки (не выше действующих значений установки) и списки
/// `partners`, `auto_forward_domains`. Клетки выше потолка — 422 problem+json с `errors` и уровнем, откуда
/// потолок; домен-партнёр из принятых доменов организации — 422; чужая организация — 403, неизвестная — 404.
#[utoipa::path(put, path = "/api/v1/orgs/{org}/trust", tag = "trust",
    params(("org" = String, Path, description = "Организация (UUID)")),
    request_body = TrustBody,
    responses((status = 200, body = TrustView), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, body = Problem), (status = 422, description = "клетки выше потолка или недопустимые домены", body = TrustProblem),
        (status = 503, body = Problem)))]
async fn put_org_trust(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
    Json(body): Json<TrustBody>,
) -> std::result::Result<Json<TrustView>, RefusedResponse> {
    put(&a, TrustLevel::Org(org), body).await
}

/// Сбрасывает политику организации — действуют установка и умолчания. Сброс незаданного уровня — не ошибка.
#[utoipa::path(delete, path = "/api/v1/orgs/{org}/trust", tag = "trust",
    params(("org" = String, Path, description = "Организация (UUID)")),
    responses((status = 200, body = TrustView), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn reset_org_trust(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
) -> std::result::Result<Json<TrustView>, Refused> {
    store(&a)?.reset_policy(TrustLevel::Org(org)).await?;
    Ok(Json(view(&a, TrustLevel::Org(org)).await?))
}

/// Политика доверия группы: своя, действующая (группа поверх организации) и закреплённые клетки. Группа
/// организации; несуществующая — 404.
#[utoipa::path(get, path = "/api/v1/orgs/{org}/groups/{group}/trust", tag = "trust",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("group" = String, Path, description = "Группа (UUID)")),
    responses((status = 200, body = TrustView), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn get_group_trust(
    State(a): State<Arc<Admin>>,
    Path((org, group)): Path<(TenantId, GroupId)>,
) -> std::result::Result<Json<TrustView>, Refused> {
    group_exists(&a, org, group).await?;
    Ok(Json(view(&a, TrustLevel::Group(org, group)).await?))
}

/// Заменяет политику группы целиком (клетки не выше действующих значений организации; списки доменов — только
/// у организации, здесь — 422). Клетки выше потолка — 422 problem+json с `errors`.
#[utoipa::path(put, path = "/api/v1/orgs/{org}/groups/{group}/trust", tag = "trust",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("group" = String, Path, description = "Группа (UUID)")),
    request_body = TrustBody,
    responses((status = 200, body = TrustView), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, description = "организация или группа не найдена", body = Problem),
        (status = 422, description = "клетки выше потолка или домены не на своём уровне", body = TrustProblem),
        (status = 503, body = Problem)))]
async fn put_group_trust(
    State(a): State<Arc<Admin>>,
    Path((org, group)): Path<(TenantId, GroupId)>,
    Json(body): Json<TrustBody>,
) -> std::result::Result<Json<TrustView>, RefusedResponse> {
    if let Err(e) = group_exists(&a, org, group).await {
        return Err(RefusedResponse::from(ApiError(e).into_response()));
    }
    put(&a, TrustLevel::Group(org, group), body).await
}

/// Сбрасывает политику группы — действуют организация и умолчания. Сброс незаданного уровня — не ошибка.
#[utoipa::path(delete, path = "/api/v1/orgs/{org}/groups/{group}/trust", tag = "trust",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("group" = String, Path, description = "Группа (UUID)")),
    responses((status = 200, body = TrustView), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn reset_group_trust(
    State(a): State<Arc<Admin>>,
    Path((org, group)): Path<(TenantId, GroupId)>,
) -> std::result::Result<Json<TrustView>, Refused> {
    group_exists(&a, org, group).await?;
    store(&a)?
        .reset_policy(TrustLevel::Group(org, group))
        .await?;
    Ok(Json(view(&a, TrustLevel::Group(org, group)).await?))
}

/// Действующая политика учётной записи: установка → организация → группы учётной записи (из нескольких —
/// самое узкое), по клетке — источник и признак «выше потолка».
#[utoipa::path(get, path = "/api/v1/orgs/{org}/accounts/{account}/trust", tag = "trust",
    params(("org" = String, Path, description = "Организация (UUID)"),
        ("account" = String, Path, description = "Учётная запись (UUID)")),
    responses((status = 200, body = TrustView), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn get_account_trust(
    State(a): State<Arc<Admin>>,
    Path((org, account)): Path<(TenantId, AccountId)>,
) -> std::result::Result<Json<TrustView>, Refused> {
    crate::accounts::account(&a, org, account).await?;
    let effective = store(&a)?.effective_for(org, account).await?;
    Ok(Json(TrustView {
        own: None,
        effective,
        fixed: TrustFixed::contract(),
    }))
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::{Value, json};
    use tp_contracts::GroupId;
    use tp_contracts::trust::{Detail, InviteMode};

    use super::*;
    use crate::testenv::{Env, config};

    fn org_trust() -> String {
        format!("/api/v1/orgs/{}/trust", TenantId::DEFAULT)
    }

    fn group_trust(group: GroupId) -> String {
        format!("/api/v1/orgs/{}/groups/{group}/trust", TenantId::DEFAULT)
    }

    /// Приёмка ADM-49: замена политики организации в пределах потолка — 200 и запись аудита; клетки выше
    /// потолка контракта — 422 с `errors`; `booking` в теле — 400; снижение потолка установки — организация
    /// отдаёт `over_ceiling`.
    #[tokio::test]
    async fn put_org_policy_and_ceiling() {
        let env = Env::new();
        let path = org_trust();

        // Пустой `GET`: уровня нет, действующая матрица — умолчания.
        let (s, _, b) = env.call("GET", &path, Some("operator"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["own"], Value::Null);
        assert_eq!(
            b["effective"]["matrix"]["invite_new"]["partner"],
            json!("button")
        );
        assert_eq!(b["fixed"]["freebusy"]["neighbor"], json!(true));
        assert_eq!(b["fixed"]["mdn"]["external"], json!(false));

        // В пределах потолка: партнёру «авто» — 200, аудит.
        let body = json!({"invite_new": {"partner": "auto"}, "partners": ["partner.example"]});
        let (s, _, b) = env.call("PUT", &path, Some("org"), Some(body)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["own"]["invite_new"]["partner"], json!("auto"));
        assert_eq!(
            b["effective"]["matrix"]["invite_new"]["partner"],
            json!("auto")
        );
        let log = env.audit.records();
        assert_eq!(log.len(), 1, "изменение — в журнале аудита");
        assert_eq!(log[0].route, ORG_TRUST);
        assert_eq!(log[0].status, 200);
        assert_eq!(log[0].tenant, Some(TenantId::DEFAULT));
        // Политика записана в хранилище (Env.trust — то же хранилище, что у Admin API).
        let mut written = TrustPolicy::default();
        written.invite_new.partner = Some(InviteMode::Auto);
        written.partners = vec!["partner.example".into()];
        assert_eq!(
            env.trust.policy(TrustLevel::Org(TenantId::DEFAULT)).await,
            Ok(Some(written))
        );

        // Выше потолка контракта: новое приглашение интернету — кнопка, закреплено.
        let body = json!({"invite_new": {"external": "auto"}});
        let (s, h, b) = env.call("PUT", &path, Some("org"), Some(body)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert_eq!(h["content-type"], "application/problem+json");
        assert_eq!(b["status"], 422);
        assert_eq!(
            b["errors"],
            json!([{"function": "invite_new", "peer": "external", "value": {"invite": "auto"},
                    "ceiling": {"invite": "button"}, "level": null}])
        );
        assert!(
            b["detail"].as_str().expect("detail").contains(
                "Новое приглашение, интернет: «авто» выше потолка «письмо с кнопкой» (закреплено)"
            ),
            "{}",
            b["detail"]
        );
        // Политика не изменилась.
        let (_, _, b) = env.call("GET", &path, Some("org"), None).await;
        assert_eq!(b["own"]["invite_new"]["external"], Value::Null);

        // Закреплённая функция в теле — 400.
        let body = json!({"booking": {"external": "on"}});
        let (s, _, _) = env.call("PUT", &path, Some("org"), Some(body)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        // Снижение потолка установки не отклоняется; организация шире — `over_ceiling`.
        let inst = json!({"invite_new": {"partner": "button"}});
        let (s, _, _) = env
            .call("PUT", INSTALLATION_TRUST, Some("root"), Some(inst))
            .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, b) = env.call("GET", &path, Some("org"), None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(
            b["effective"]["matrix"]["invite_new"]["partner"],
            json!("button"),
            "обрезана до потолка"
        );
        assert_eq!(b["effective"]["over_ceiling"][0]["peer"], json!("partner"));
        assert_eq!(
            b["effective"]["over_ceiling"][0]["level"],
            json!("installation")
        );
        // Шире нового потолка организация больше не пишет.
        let body = json!({"invite_new": {"partner": "auto"}});
        let (s, _, b) = env.call("PUT", &path, Some("org"), Some(body)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert_eq!(b["errors"][0]["ceiling"], json!({"invite": "button"}));

        // Аудит: пишется каждый запрос — PUT организации (200, 422, 400), PUT установки, её 422; GET не пишется.
        let log = env.audit.records();
        assert_eq!(log.len(), 5, "{log:?}");
    }

    /// Приёмка ADM-49: права — администратор организации не меняет уровень установки и чужую организацию;
    /// оператор — только `GET`; домен-партнёр из принятых доменов организации — 422.
    #[tokio::test]
    async fn roles_and_partner_domains() {
        let env = Env::new();
        let path = org_trust();

        // Уровень установки — только администратор установки.
        let (s, _, _) = env.call("GET", INSTALLATION_TRUST, Some("org"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, _) = env
            .call("GET", INSTALLATION_TRUST, Some("operator"), None)
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, _) = env
            .call("PUT", INSTALLATION_TRUST, Some("root"), Some(json!({})))
            .await;
        assert_eq!(s, StatusCode::OK);

        // Чужая организация: своя — 403 (до проверки существования), чужой администратор — 404.
        let other = format!("/api/v1/orgs/{}/trust", env.other_tenant);
        let (s, _, _) = env.call("GET", &other, Some("org"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, b) = env.call("GET", &other, Some("other"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}: свой уровень — читает");

        // Оператор читает, но не меняет.
        let (s, _, _) = env.call("GET", &path, Some("operator"), None).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = env
            .call("PUT", &path, Some("operator"), Some(json!({})))
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, _) = env.call("DELETE", &path, Some("operator"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);

        // Домен-партнёр из принятых доменов организации — 422.
        env.put_domain(TenantId::DEFAULT, "example.org").await;
        let body = json!({"partners": ["example.org"]});
        let (s, _, b) = env.call("PUT", &path, Some("org"), Some(body)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert!(
            b["detail"]
                .as_str()
                .unwrap_or_default()
                .contains("партнёром")
        );
        // Другой домен организации — можно: соседняя организация — партнёр.
        let body = json!({"partners": ["neighbor.example"]});
        let (s, _, b) = env.call("PUT", &path, Some("org"), Some(body)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["own"]["partners"], json!(["neighbor.example"]));
        // Неканоническая запись — 422.
        let body = json!({"partners": ["Neighbor.Example"]});
        let (s, _, _) = env.call("PUT", &path, Some("org"), Some(body)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

        // Сброс организации — 200; повторный сброс — не ошибка.
        for _ in 0..2 {
            let (s, _, b) = env.call("DELETE", &path, Some("org"), None).await;
            assert_eq!(s, StatusCode::OK, "{b}");
        }
        let (_, _, b) = env.call("GET", &path, Some("org"), None).await;
        assert_eq!(b["own"], Value::Null);
    }

    /// Приёмка ADM-49: группа шире организации — 422; действующая для учётной записи в двух группах — самое
    /// узкое и `source` по каждой клетке; несуществующая группа — 404.
    #[tokio::test]
    async fn groups_and_account_view() {
        let env = Env::new();
        let account = env.account("user@example.org").await;
        let (g1, g2) = (GroupId::new(), GroupId::new());
        for (name, g) in [("а", g1), ("б", g2)] {
            env.group(TenantId::DEFAULT, name, g, account.account).await;
        }
        let path1 = group_trust(g1);
        let path2 = group_trust(g2);

        // Организация открывает занятость партнёру и MDN партнёру.
        let org = json!({"freebusy": {"partner": "free_busy"}, "mdn": {"partner": "on"}});
        let (s, _, _) = env.call("PUT", &org_trust(), Some("org"), Some(org)).await;
        assert_eq!(s, StatusCode::OK);

        // Группа шире организации — 422 (потолок группы — действующее значение организации).
        let wide = json!({"mdn": {"partner": "on"}, "freebusy": {"partner": "limited"}});
        let (s, _, b) = env.call("PUT", &path1, Some("org"), Some(wide)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert_eq!(b["errors"][0]["function"], json!("free_busy"));
        assert_eq!(
            b["errors"][0]["level"],
            json!({"org": TenantId::DEFAULT.to_string()})
        );

        // Две группы: каждая сужает свою клетку — у учётной записи самое узкое, источник — группа.
        let (s, _, _) = env
            .call(
                "PUT",
                &path1,
                Some("org"),
                Some(json!({"freebusy": {"partner": "none"}})),
            )
            .await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = env
            .call(
                "PUT",
                &path2,
                Some("org"),
                Some(json!({"mdn": {"partner": "off"}})),
            )
            .await;
        assert_eq!(s, StatusCode::OK);
        let account_path = format!(
            "/api/v1/orgs/{}/accounts/{}/trust",
            TenantId::DEFAULT,
            account.account
        );
        let (s, _, b) = env.call("GET", &account_path, Some("operator"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["own"], Value::Null);
        assert_eq!(
            b["effective"]["matrix"]["freebusy"]["partner"],
            json!("none")
        );
        assert_eq!(b["effective"]["matrix"]["mdn"]["partner"], json!("off"));
        assert_eq!(
            b["effective"]["source"]["freebusy"]["partner"],
            json!({"group": [TenantId::DEFAULT.to_string(), g1.to_string()]})
        );
        assert_eq!(
            b["effective"]["source"]["mdn"]["partner"],
            json!({"group": [TenantId::DEFAULT.to_string(), g2.to_string()]})
        );

        // `partners` на уровне группы — 422 (задаёт только организация).
        let (s, _, b) = env
            .call(
                "PUT",
                &path1,
                Some("org"),
                Some(json!({"partners": ["x.example"]})),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");

        // Несуществующая группа — 404; сброс — 200.
        let missing = group_trust(GroupId::new());
        let (s, _, _) = env.call("GET", &missing, Some("org"), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _, _) = env.call("DELETE", &path2, Some("org"), None).await;
        assert_eq!(s, StatusCode::OK);
        let (_, _, b) = env.call("GET", &account_path, Some("org"), None).await;
        assert_eq!(b["effective"]["matrix"]["mdn"]["partner"], json!("on"));

        // Хранилище не подключено — 503.
        let bare = crate::server::Admin::new(crate::testenv::deps(), config()).expect("admin");
        assert!(matches!(
            store(&bare).err(),
            Some(Error::Unavailable { .. })
        ));
    }

    /// Схема: маршруты доверия с типами ответов и 422; `TrustBody`/`TrustView` — туда и обратно (ADM-13).
    #[test]
    fn openapi_and_roundtrip() {
        let spec = serde_json::to_value(crate::server::openapi_spec()).expect("spec");
        let paths = &spec["paths"];
        for (path, methods) in [
            (INSTALLATION_TRUST, &["get", "put", "delete"][..]),
            (ORG_TRUST, &["get", "put", "delete"]),
            (GROUP_TRUST, &["get", "put", "delete"]),
            (ACCOUNT_TRUST, &["get"]),
        ] {
            for m in methods {
                assert!(paths[path][m].is_object(), "{m} {path}");
            }
        }
        assert!(
            paths[ORG_TRUST]["put"]["responses"]["422"].is_object(),
            "{paths}"
        );
        assert!(spec["components"]["schemas"]["TrustProblem"].is_object());
        assert!(spec["components"]["schemas"]["TrustView"].is_object());
        assert!(
            spec["components"]["schemas"]["TrustPolicy"]["properties"]["partners"].is_object(),
            "схема политики с доменами"
        );

        fn roundtrip<T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
            v: T,
        ) {
            let json = serde_json::to_value(&v).expect("serialize");
            let back: T = serde_json::from_value(json.clone()).expect("deserialize");
            assert_eq!(back, v, "{json}");
        }
        roundtrip(TrustBody::default());
        let mut body = TrustBody::default();
        body.invite_new.partner = Some(InviteMode::Auto);
        body.partners = vec!["partner.example".into()];
        body.auto_forward_domains = vec!["example.net".into()];
        body.freebusy.own = Some(Detail::Details);
        body.group_post.external = Some(tp_contracts::trust::GroupPost::Moderated);
        roundtrip(body.clone());
        assert_eq!(
            TrustPolicy::from(body).invite_new.partner,
            Some(InviteMode::Auto)
        );
        assert!(TrustFixed::contract().get(TrustFunction::InviteNew, PeerKind::Neighbor));
        assert!(!TrustFixed::contract().get(TrustFunction::Mdn, PeerKind::External));
        roundtrip(TrustView {
            own: None,
            effective: effective(None, None, &[]),
            fixed: TrustFixed::contract(),
        });
        roundtrip(TrustProblem {
            status: 422,
            title: "Unprocessable Entity".into(),
            detail: "клетки выше потолка".into(),
            errors: vec![OverCeiling {
                function: TrustFunction::InviteNew,
                peer: PeerKind::External,
                value: CellValue::Invite(InviteMode::Auto),
                ceiling: CellValue::Invite(InviteMode::Button),
                level: None,
            }],
        });
    }
}
