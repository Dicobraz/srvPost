//! In-memory источник занятости и публикации календарей (CONTRACTS.md#Calendar; CTR-36).
//!
//! [`MemAvailabilitySource`] — источник занятости с настраиваемыми ответами (тесты протоколов, JMAP-19);
//! [`MemCalendarPublications`] — [`CalendarPublications`] поверх [`TrustStore`] (потолок детализации —
//! [`publication_ceiling`]; тест поднимает его политикой `MemTrust`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use time::OffsetDateTime;
use tp_contracts::calendar::{
    AvailabilityResult, AvailabilitySource, CalendarPublication, CalendarPublications,
    publication_ceiling,
};
use tp_contracts::dav::{CollectionId, Span};
use tp_contracts::meta::{AccountScope, Address};
use tp_contracts::schedule::{BusyPeriod, merge_busy};
use tp_contracts::trust::{Detail, TrustStore};
use tp_contracts::{Error, PublicationId, Result};

use crate::infra::{Clock, SystemClock, lock};

// ---------- Источник занятости ----------

#[derive(Debug, Default)]
struct SourceState {
    /// Ответы по адресу (email): периоды как заданы (обрезка и склейка — при запросе) и детализация.
    busy: HashMap<String, (Vec<BusyPeriod>, Detail)>,
    /// «Источник недоступен»: все адреса — `NoData`.
    unavailable: bool,
    calls: Vec<(Vec<Address>, Span)>,
}

/// Источник занятости в памяти; клоны разделяют состояние. Ответы задаёт тест
/// ([`MemAvailabilitySource::set_busy`]); адреса без ответа и «недоступный» источник отвечают
/// [`AvailabilityResult::NoData`]. Имя — [`MemAvailabilitySource::new`].
#[derive(Debug, Clone, Default)]
pub struct MemAvailabilitySource {
    name: String,
    state: Arc<Mutex<SourceState>>,
}

impl MemAvailabilitySource {
    /// Источник с именем `name` и без ответов.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            state: Arc::default(),
        }
    }

    /// Задаёт ответ для адреса `email`: периоды (как заданы) и уровень детализации.
    pub fn set_busy(&self, email: &str, periods: Vec<BusyPeriod>, detail: Detail) {
        let mut st = lock(&self.state);
        st.busy.insert(email.to_owned(), (periods, detail));
    }

    /// Убирает ответ: адрес — `NoData`.
    pub fn remove(&self, email: &str) {
        lock(&self.state).busy.remove(email);
    }

    /// «Источник недоступен»: все адреса — `NoData`, независимо от ответов.
    pub fn set_unavailable(&self, unavailable: bool) {
        lock(&self.state).unavailable = unavailable;
    }

    /// Вызовы [`AvailabilitySource::lookup`] в порядке поступления (адреса и интервалы как пришло).
    pub fn calls(&self) -> Vec<(Vec<Address>, Span)> {
        lock(&self.state).calls.clone()
    }
}

/// Обрезка периода по интервалу запроса (`span.end = None` — без верхней границы); не пересекается — `None`.
fn clip_to_span(p: &BusyPeriod, span: &Span) -> Option<BusyPeriod> {
    let start = p.start.max(span.start);
    let end = span.end.map_or(p.end, |e| p.end.min(e));
    (start < end).then_some(BusyPeriod {
        start,
        end,
        kind: p.kind,
    })
}

/// Периоды источника внутри интервала запроса: обрезка и нормализация.
fn busy_in(periods: &[BusyPeriod], span: &Span, detail: Detail) -> AvailabilityResult {
    let mut clipped = Vec::new();
    for p in periods {
        if let Some(p) = clip_to_span(p, span) {
            clipped.push(p);
        }
    }
    AvailabilityResult::Busy(merge_busy(clipped), detail)
}

#[async_trait]
impl AvailabilitySource for MemAvailabilitySource {
    fn name(&self) -> &str {
        &self.name
    }

    async fn lookup(
        &self,
        addresses: &[Address],
        span: Span,
    ) -> Vec<(Address, AvailabilityResult)> {
        let mut st = lock(&self.state);
        st.calls.push((addresses.to_vec(), span));
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for a in addresses {
            if !seen.insert(a.email.as_str()) {
                continue;
            }
            let result = if st.unavailable {
                AvailabilityResult::NoData
            } else {
                match st.busy.get(a.email.as_str()) {
                    Some((periods, detail)) => busy_in(periods, &span, *detail),
                    None => AvailabilityResult::NoData,
                }
            };
            out.push((a.clone(), result));
        }
        out
    }
}

// ---------- Публикации календарей ----------

fn fault(st: &mut VecDeque<Error>) -> Result<()> {
    st.pop_front().map_or(Ok(()), Err)
}

#[derive(Debug, Default)]
struct PublicationsState {
    links: Vec<CalendarPublication>,
    tokens: HashMap<PublicationId, String>,
    faults: VecDeque<Error>,
}

/// [`CalendarPublications`] в памяти; клоны разделяют данные. Потолок детализации — [`publication_ceiling`]
/// по [`TrustStore`] (`MemCalendarPublications::new`); время — [`Clock`] (сроки `expires` проверяются по
/// нему; по умолчанию [`SystemClock`], в тестах сроков — `ManualClock`). Токен хранится рядом с записью
/// (в реальном хранилище — только хэш, META-34).
#[derive(Clone)]
pub struct MemCalendarPublications {
    trust: Arc<dyn TrustStore>,
    clock: Arc<dyn Clock>,
    state: Arc<Mutex<PublicationsState>>,
}

impl fmt::Debug for MemCalendarPublications {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemCalendarPublications")
            .finish_non_exhaustive()
    }
}

impl MemCalendarPublications {
    /// Пустое хранилище с потолком по `trust` и системными часами.
    pub fn new(trust: Arc<dyn TrustStore>) -> Self {
        MemCalendarPublications {
            trust,
            clock: Arc::new(SystemClock),
            state: Arc::default(),
        }
    }

    /// Время — `clock` (сроки `expires` проверяются по нему).
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Все записи (токен — `None`) по возрастанию `id`, для проверок тестов полос.
    pub fn links(&self) -> Vec<CalendarPublication> {
        let mut links = lock(&self.state).links.clone();
        links.sort_by_key(|l| l.id);
        links
    }

    /// Следующая операция вернёт `err` (очередь, по одной на операцию).
    pub fn fail_next(&self, err: Error) {
        lock(&self.state).faults.push_back(err);
    }
}

#[async_trait]
impl CalendarPublications for MemCalendarPublications {
    async fn ceiling(&self, scope: AccountScope) -> Result<Detail> {
        let effective = self
            .trust
            .effective_for(scope.tenant, scope.account)
            .await?;
        Ok(publication_ceiling(&effective))
    }

    async fn create(
        &self,
        scope: AccountScope,
        calendar: CollectionId,
        detail: Detail,
        expires: Option<OffsetDateTime>,
    ) -> Result<CalendarPublication> {
        let ceiling = self.ceiling(scope).await?;
        let mut st = lock(&self.state);
        fault(&mut st.faults)?;
        let now = self.clock.now();
        if detail == Detail::None {
            return Err(Error::invalid("публикация без уровня детализации"));
        }
        if detail > ceiling {
            return Err(Error::Forbidden);
        }
        if expires.is_some_and(|e| e <= now) {
            return Err(Error::invalid("срок ссылки не позже текущего момента"));
        }
        let id = PublicationId::new();
        let token = format!("cal-{}", PublicationId::new());
        let link = CalendarPublication {
            id,
            scope,
            calendar,
            detail,
            expires,
            token: None,
        };
        st.links.push(link.clone());
        st.tokens.insert(id, token.clone());
        Ok(CalendarPublication {
            token: Some(token),
            ..link
        })
    }

    async fn list(&self, scope: AccountScope) -> Result<Vec<CalendarPublication>> {
        let mut st = lock(&self.state);
        fault(&mut st.faults)?;
        let mut mine: Vec<_> = st
            .links
            .iter()
            .filter(|l| l.scope == scope)
            .cloned()
            .collect();
        mine.sort_by_key(|l| l.id);
        Ok(mine)
    }

    async fn revoke(&self, scope: AccountScope, id: PublicationId) -> Result<()> {
        let mut st = lock(&self.state);
        fault(&mut st.faults)?;
        let pos = st.links.iter().position(|l| l.scope == scope && l.id == id);
        match pos {
            Some(i) => {
                st.links.remove(i);
                st.tokens.remove(&id);
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::calendar::{PublicationsFixture, calendar_publications};
    use crate::{ManualClock, MemTrust};
    use std::time::Duration;
    use tp_contracts::schedule::BusyKind;
    use tp_contracts::trust::{TrustLevel, TrustPolicy};
    use tp_contracts::{AccountId, TenantId};

    fn t(h: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + time::Duration::hours(h)
    }

    /// Момент по часам [`ManualClock`]: `ManualClock::default()` стоит в `at(0)`.
    fn at(seconds: i64) -> OffsetDateTime {
        let epoch = OffsetDateTime::UNIX_EPOCH;
        let start = epoch.replace_year(2026).expect("2026 год существует");
        start + time::Duration::seconds(seconds)
    }

    fn busy(s: i64, e: i64, kind: BusyKind) -> BusyPeriod {
        BusyPeriod {
            start: t(s),
            end: t(e),
            kind,
        }
    }

    fn addr(email: &str) -> Address {
        Address {
            name: None,
            email: email.into(),
        }
    }

    #[tokio::test]
    async fn source_lookup_and_calls() {
        let src = MemAvailabilitySource::new("federation");
        src.set_busy(
            "a@partner.example",
            vec![busy(1, 5, BusyKind::Busy), busy(4, 6, BusyKind::Busy)],
            Detail::FreeBusy,
        );
        src.set_busy(
            "b@partner.example",
            vec![busy(10, 12, BusyKind::Tentative)],
            Detail::Limited,
        );

        // Повторы адреса — один раз; периоды обрезаны и склеены; неизвестный адрес — NoData.
        let span = Span {
            start: t(2),
            end: Some(t(5)),
        };
        let asked = [
            addr("a@partner.example"),
            addr("b@partner.example"),
            addr("a@partner.example"),
            addr("c@partner.example"),
        ];
        let out = src.lookup(&asked, span).await;
        assert_eq!(out.len(), 3, "повтор адреса — один раз");
        assert_eq!(out[0].0, addr("a@partner.example"), "адрес как в запросе");
        assert_eq!(
            out[0].1,
            AvailabilityResult::Busy(vec![busy(2, 5, BusyKind::Busy)], Detail::FreeBusy)
        );
        assert_eq!(
            out[1].1,
            AvailabilityResult::Busy(Vec::new(), Detail::Limited),
            "вне интервала — свободен"
        );
        assert_eq!(out[2].1, AvailabilityResult::NoData);

        // Без верхней границы — периоды от начала интервала.
        let open = Span {
            start: t(0),
            end: None,
        };
        let out = src.lookup(&[addr("a@partner.example")], open).await;
        assert_eq!(
            out[0].1,
            AvailabilityResult::Busy(vec![busy(1, 6, BusyKind::Busy)], Detail::FreeBusy)
        );

        // Недоступный источник — все NoData; вызовы записаны.
        src.set_unavailable(true);
        let day = Span {
            start: t(0),
            end: Some(t(24)),
        };
        let out = src.lookup(&[addr("a@partner.example")], day).await;
        assert_eq!(out[0].1, AvailabilityResult::NoData);
        assert_eq!(src.calls().len(), 3);
        let (asked, asked_span) = &src.calls()[0];
        assert_eq!(asked.len(), 4);
        assert_eq!(*asked_span, span);
    }

    #[tokio::test]
    async fn passes_publications_suite() {
        let trust = Arc::new(MemTrust::new());
        let publ = MemCalendarPublications::new(trust.clone());
        calendar_publications(&publ, &trust, &PublicationsFixture::new()).await;
    }

    #[tokio::test]
    async fn publications_faults_and_clock() {
        let clock = ManualClock::default();
        let trust = Arc::new(MemTrust::new());
        let base = MemCalendarPublications::new(trust.clone());
        let publ = base.with_clock(clock.shared());
        let scope = AccountScope {
            tenant: TenantId::new(),
            account: AccountId::new(),
        };
        let cal = CollectionId::new();

        // Без политики выпуск запрещён; сбой хранилища воспроизводится один раз.
        assert_eq!(
            publ.create(scope, cal, Detail::FreeBusy, None).await,
            Err(Error::Forbidden)
        );
        publ.fail_next(Error::UNAVAILABLE);
        assert!(publ.list(scope).await.is_err());
        assert!(publ.links().is_empty());
        publ.fail_next(Error::Conflict);
        assert_eq!(
            publ.revoke(scope, PublicationId::new()).await,
            Err(Error::Conflict)
        );

        // Политика разрешает занят/свободен: срок проверяется по часам хранилища.
        let mut policy = TrustPolicy::default();
        policy.sharing.external = Some(Detail::FreeBusy);
        trust
            .set_policy(TrustLevel::Org(scope.tenant), &policy)
            .await
            .expect("policy");
        let past = at(-60);
        let late = publ.create(scope, cal, Detail::FreeBusy, Some(past));
        assert!(matches!(late.await, Err(Error::Invalid(_))));
        let future = at(3600);
        let link = publ
            .create(scope, cal, Detail::FreeBusy, Some(future))
            .await
            .expect("срок в будущем");
        clock.advance(Duration::from_secs(7200));
        assert_eq!(publ.links().len(), 1, "истёкшие хранилище само не удаляет");
        assert_eq!(publ.revoke(scope, link.id).await, Ok(()));
        assert!(publ.links().is_empty());
    }
}
