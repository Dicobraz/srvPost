//! Внешний доступ к календарям: источники занятости и публикации (CONTRACTS.md#Calendar; SRS 4.4, 1.3;
//! решение 2026-11-04-calendar-external-api; CTR-36).
//!
//! Занятость внешних адресов для `Availability/get` (`urn:thepost:availability`, JMAP-19) узел собирает из
//! встроенных источников — пользователи организации ([`crate::schedule::FreeBusy`]), ссылки занятости
//! (FBURL из GAL и контактов), шаблон домена-партнёра из политики — и из зарегистрированных источников:
//! модуль «Федерация календарей» (SRS 1.3) добавляет свои при запуске через [`AvailabilitySource`]
//! ([`crate::ext::Registry::add_availability_source`]). Адрес без доступной занятости — «нет данных»
//! ([`AvailabilityResult::NoData`]), а не «свободен» (SRS 4.4).
//!
//! Публикация календаря по ссылке — только чтение, токен в адресе, уровень детализации не выше политики
//! ([`CalendarPublications`]); потребители — JMAP `urn:thepost:calendarpublish` (JMAP-20) и CalDAV-публикация
//! ICS (DAV-20); хранение — `tp-meta` (META-34, токен — только хэш).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::dav::{CollectionId, Span};
use crate::error::Result;
use crate::ids::PublicationId;
use crate::meta::{AccountScope, Address};
use crate::schedule::BusyPeriod;
use crate::trust::{Detail, Effective, HARD_CEILING};

/// Итог запроса занятости одного адреса к источнику ([`AvailabilitySource::lookup`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityResult {
    /// Занятость: периоды (`[start, end)`, UTC) — пересекающиеся с интервалом запроса, обрезанные по нему
    /// и нормализованные ([`crate::schedule::merge_busy`]), и уровень детализации, с которым они отдаются
    /// (не выше политики организации адреса; содержание выше уровня срезает отдающий).
    Busy(Vec<BusyPeriod>, Detail),
    /// Нет данных: адрес вне источника, внешний сервер недоступен. Не «свободен»: клиент показывает
    /// «нет данных» (SRS 4.4).
    NoData,
}

/// Источник занятости внешних адресов — точка расширения (SRS 1.3, 2.5): модуль «Федерация календарей»
/// регистрирует свои источники при запуске ([`crate::ext::Registry::add_availability_source`]; имя уникально,
/// повтор — `Conflict`, [`crate::ext::Registry::availability_sources`] — в порядке регистрации). Встроенные
/// источники узла (`organization` — пользователи организации, `link` — ссылки FBURL, `partner` — шаблон
/// домена-партнёра) — не через эту точку; источник модуля в ответе `Availability/get` (JMAP-19) помечается
/// `source: federation`.
#[async_trait]
pub trait AvailabilitySource: Send + Sync + 'static {
    /// Имя источника (журналы, диагностика).
    fn name(&self) -> &str;

    /// Занятость адресов в интервале `span`: по записи на каждый адрес в порядке `addresses`, повторы — один
    /// раз, адрес в ответе как в запросе. Периоды — пересекающиеся с интервалом, обрезанные по нему и
    /// нормализованные ([`crate::schedule::merge_busy`]); `span.end = None` — без верхней границы, `end ≤ start`
    /// — пустой интервал. Ошибок нет: адрес без доступной занятости (вне источника, внешний сервер недоступен) —
    /// [`AvailabilityResult::NoData`], не «свободен»; причины — в журнале источника. Детализация — не выше
    /// политики организации адреса.
    async fn lookup(&self, addresses: &[Address], span: Span)
    -> Vec<(Address, AvailabilityResult)>;
}

/// Действующий потолок уровня детализации публикаций учётной записи: клетка `sharing` для интернета в
/// действующей матрице доверия ([`Effective`]: `TrustStore::effective_for` — установка → организация → группы),
/// не выше закреплённого потолка контракта ([`HARD_CEILING`]). Реализации
/// [`CalendarPublications::ceiling`] вычисляют им по своему [`crate::trust::TrustStore`].
pub fn publication_ceiling(effective: &Effective) -> Detail {
    effective
        .matrix
        .sharing
        .external
        .min(HARD_CEILING.sharing.external)
}

/// Ссылка публикации календаря (SRS 4.4): только чтение, токен в адресе, уровень детализации не выше политики.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalendarPublication {
    /// Идентификатор (JMAP `CalendarPublication`); новый при каждом выпуске.
    pub id: PublicationId,
    /// Владелец календаря.
    pub scope: AccountScope,
    /// Календарь ([`crate::dav::DavStore`]); существование проверяет вызывающий.
    pub calendar: CollectionId,
    /// Уровень детализации по ссылке: `free_busy` — занят/свободен, `limited` — тема и время, `details` —
    /// полностью (SRS 4.4); не [`Detail::None`].
    pub detail: Detail,
    /// Срок жизни ссылки; `None` — без срока. После срока отдача по ссылке — как по отозванной; истёкшие
    /// удаляет обслуживание хранилища.
    pub expires: Option<OffsetDateTime>,
    /// Токен в открытом виде — адрес ссылки собирает вызывающий по схеме развёртывания. Заполняется только
    /// в результате [`CalendarPublications::create`]; в [`CalendarPublications::list`] — `None`: в хранилище
    /// — только хэш токена (META-34), адрес отдаётся один раз при создании (JMAP-20).
    pub token: Option<String>,
}

/// Публикации календарей: выпуск, список и отзыв ссылок только для чтения (SRS 4.4, решение
/// 2026-11-04-calendar-external-api; CTR-36). Хранилище общее для узлов; выдачу и отзыв ссылки в журнал
/// аудита записывает вызывающий (SRS 4.4). Реализация — `tp-meta` (META-34, RLS, токен — только хэш);
/// in-memory — `tp-testkit::MemCalendarPublications`, набор — `suite::calendar::calendar_publications`.
#[async_trait]
pub trait CalendarPublications: Send + Sync + 'static {
    /// Действующий потолок уровня детализации публикаций учётной записи ([`publication_ceiling`] по
    /// [`crate::trust::TrustStore`]). Ссылка с уровнем выше потолка не выдаётся; ужесточение политики
    /// существующие ссылки не отзывает — отдачу по ссылке ограничивает сервер.
    async fn ceiling(&self, scope: AccountScope) -> Result<Detail>;

    /// Выпускает ссылку: новый [`PublicationId`] и токен ([`CalendarPublication::token`]); в хранилище —
    /// только хэш. Уровень выше потолка ([`CalendarPublications::ceiling`]) — `Forbidden`;
    /// [`Detail::None`] или `expires` не позже текущего момента — `Invalid`.
    async fn create(
        &self,
        scope: AccountScope,
        calendar: CollectionId,
        detail: Detail,
        expires: Option<OffsetDateTime>,
    ) -> Result<CalendarPublication>;

    /// Ссылки учётной записи, по возрастанию `id` (= время создания, UUID v7); `token` — `None`. Отозванных
    /// нет (отзыв удаляет запись), истёкшие — до удаления обслуживанием.
    async fn list(&self, scope: AccountScope) -> Result<Vec<CalendarPublication>>;

    /// Отзывает ссылку (удаляет запись). Нет или чужой учётной записи — `NotFound`; повторный отзыв — тоже.
    async fn revoke(&self, scope: AccountScope, id: PublicationId) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{GroupId, TenantId};
    use crate::trust::{TrustLevel, TrustPolicy, effective};
    use time::Duration;

    #[test]
    fn object_safe() {
        fn _source(_: std::sync::Arc<dyn AvailabilitySource>) {}
        fn _publications(_: std::sync::Arc<dyn CalendarPublications>) {}
    }

    #[test]
    fn availability_result_serde() {
        let r = AvailabilityResult::Busy(
            vec![BusyPeriod {
                start: OffsetDateTime::UNIX_EPOCH,
                end: OffsetDateTime::UNIX_EPOCH + Duration::hours(1),
                kind: crate::schedule::BusyKind::Busy,
            }],
            Detail::FreeBusy,
        );
        let s = serde_json::to_string(&r).expect("serialize");
        assert_eq!(
            serde_json::from_str::<AvailabilityResult>(&s).expect("parse"),
            r
        );
        let s = serde_json::to_string(&AvailabilityResult::NoData).expect("serialize");
        assert_eq!(s, "\"no_data\"");
        assert_eq!(
            serde_json::from_str::<AvailabilityResult>(&s).expect("parse"),
            AvailabilityResult::NoData
        );
    }

    #[test]
    fn ceiling_follows_matrix_and_hard_ceiling() {
        let mut org = TrustPolicy::default();
        org.sharing.external = Some(Detail::FreeBusy);
        let mut group = TrustPolicy::default();
        group.sharing.external = Some(Detail::None);
        let mut wide = TrustPolicy::default();
        wide.sharing.external = Some(Detail::All);

        // Умолчание: интернета — ничего.
        assert_eq!(
            publication_ceiling(&effective(None, None, &[])),
            Detail::None
        );
        // Организация поднимает до «занят/свободен».
        assert_eq!(
            publication_ceiling(&effective(Some(&org), None, &[])),
            Detail::FreeBusy
        );
        // Группа учётной записи сужает до ничего.
        let groups = [(TrustLevel::Group(TenantId::new(), GroupId::new()), &group)];
        assert_eq!(
            publication_ceiling(&effective(Some(&org), None, &groups)),
            Detail::None
        );
        // Выше закреплённого потолка интернета (`details`) организация не поднимет.
        assert_eq!(
            publication_ceiling(&effective(Some(&wide), None, &[])),
            Detail::Details
        );
    }
}
