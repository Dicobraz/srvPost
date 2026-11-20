//! Публикация календаря ICS и ссылка занятости без входа (DAV-20, DAV-21; SRS 4.4, решение
//! 2026-11-04-calendar-external-api).
//!
//! Маршруты монтирует узел рядом с основными маршрутами DAV ([`crate::server::router`]): `GET`
//! `/dav/pub/<токен>.ics` — календарь по ссылке только для чтения, `GET` `/dav/freebusy/<токен>.vfb` —
//! `VFREEBUSY` владельца ссылки на интервал (`start` и `end`, RFC 3339 UTC; Internet Free/Busy Outlook
//! и внешние серверы). Входа нет: токен в адресе — единственное доказательство права; `OPTIONS`, `HEAD`
//! и условный `GET` (`If-None-Match` — 304) — как обычно. Ответы — `ETag` (по состоянию календаря или
//! учётной записи) и `Cache-Control: public, max-age=60`.
//!
//! Токен ищет хранилище публикаций ([`PublicationLookup`]; `PgMeta` — системной транзакцией по хэшу,
//! META-34): отозванная, истёкшая ссылка или неверный токен — 404, без различения причин. Уровень
//! детализации отдачи — уровень ссылки, обрезанный действующим потолком политики организации
//! ([`publication_ceiling`]): ужесточение политики существующие ссылки не отзывает — отдачу
//! ограничивает сервер (CTR-36, DAV-44); потолок «ничего» — ссылка перестаёт отвечать. Уровни:
//! `free_busy` — события без содержания (интервалы занятости), `limited` — время, тема и место,
//! `details` — как хранится. Ссылке занятости нужен уровень не ниже `free_busy`. Частота запросов —
//! по токену (`dav.pub_rate_limit`; исчерпана — 429 с `Retry-After`), интервал занятости — не больше
//! `dav.max_freebusy_span` (предел — политика узла).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use calcard::common::PartialDateTime;
use calcard::icalendar::{
    ICalendar, ICalendarComponent, ICalendarComponentType, ICalendarEntry, ICalendarFreeBusyType,
    ICalendarParameter, ICalendarPeriod, ICalendarProperty, ICalendarValue,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tp_contracts::Result;
use tp_contracts::calendar::{CalendarPublication, publication_ceiling};
use tp_contracts::dav::{CollectionKind, DavStore, TimeRange};
use tp_contracts::meta::AccountScope;
use tp_contracts::schedule::{BusyKind, BusyPeriod, FreeBusy, Period};
use tp_contracts::trust::{Detail, Effective, TrustMatrix, TrustStore, effective};

use crate::config::DavConfig;
use crate::itip;
use crate::props;
// Ошибка хранилища публикаций и календарей — как в основных маршрутах DAV.
use crate::server::{status, store_error};

/// Поиск ссылки публикации по токену без входа (DAV-20). Реализация — хранилище публикаций
/// (`PgMeta::publication_by_token` — системная транзакция по хэшу, META-34; in-memory — тесты):
/// отозванная, истёкшая ссылка и неверный токен — `Ok(None)`.
#[async_trait]
pub trait PublicationLookup: Send + Sync + 'static {
    async fn publication_by_token(&self, token: &str) -> Result<Option<CalendarPublication>>;
}

/// Зависимости маршрутов публикации ([`router`]).
#[derive(Clone)]
pub struct PublishDeps {
    /// Календари: объекты опубликованного календаря и состояние учётной записи для `ETag` занятости.
    pub store: Arc<dyn DavStore>,
    /// Поиск ссылки по токену ([`PublicationLookup`]).
    pub publications: Arc<dyn PublicationLookup>,
    /// Занятость учётных записей (VFREEBUSY по ссылке).
    pub freebusy: Arc<dyn FreeBusy>,
    /// Политики доверия (DAV-44): действующий потолок уровня ссылки; `None` — умолчания контракта.
    /// Реализация — `tp-meta` (META-85), in-memory — `tp-testkit::MemTrust`.
    pub trust: Option<Arc<dyn TrustStore>>,
}

impl fmt::Debug for PublishDeps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublishDeps")
            .field("limits", &self.store.limits())
            .field("trust", &self.trust.is_some())
            .finish_non_exhaustive()
    }
}

/// Состояние маршрутов публикации.
struct Publish {
    d: PublishDeps,
    cfg: DavConfig,
    /// Окна частоты запросов по токену ([`allow`]).
    rate: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl Publish {
    /// Действующий потолок уровня детализации ссылок учётной записи (DAV-44): клетка `sharing` для
    /// интернета действующей матрицы доверия. Ошибка чтения политики — закрытая матрица
    /// ([`TrustMatrix::closed`]).
    async fn ceiling(&self, scope: AccountScope) -> Detail {
        let Some(trust) = &self.d.trust else {
            return publication_ceiling(&effective(None, None, &[]));
        };
        match trust.effective_for(scope.tenant, scope.account).await {
            Ok(e) => publication_ceiling(&e),
            Err(e) => {
                tracing::warn!(error = %e, "publish: политика доверия не прочитана — закрытая матрица");
                publication_ceiling(&Effective {
                    matrix: TrustMatrix::closed(),
                    ..effective(None, None, &[])
                })
            }
        }
    }

    /// Ссылка по токену после проверки частоты запросов; нет или лимит — `Err` с ответом.
    async fn link(
        &self,
        token: &str,
        now: Instant,
    ) -> std::result::Result<CalendarPublication, Box<Response>> {
        match allow(&self.rate, token, self.cfg.pub_rate_limit, now) {
            Ok(()) => {}
            Err(retry) => {
                tracing::debug!(retry_after = ?retry, "publish: частота запросов ссылки исчерпана");
                let mut resp = status(StatusCode::TOO_MANY_REQUESTS);
                if let Ok(v) = HeaderValue::from_str(&retry.as_secs().max(1).to_string()) {
                    resp.headers_mut().insert(header::RETRY_AFTER, v);
                }
                return Err(Box::new(resp));
            }
        }
        match self.d.publications.publication_by_token(token).await {
            Ok(Some(p)) => Ok(p),
            Ok(None) => Err(Box::new(status(StatusCode::NOT_FOUND))),
            Err(e) => Err(Box::new(store_error(&e))),
        }
    }
}

/// Маршруты публикации: `/dav/pub/{*path}` и `/dav/freebusy/{*path}` (см. описание модуля).
/// TLS и слушатель — у вызывающего (`tp-platform`).
pub fn router(d: PublishDeps, cfg: DavConfig) -> Router {
    let state = Arc::new(Publish {
        d,
        cfg,
        rate: Mutex::new(HashMap::new()),
    });
    Router::new()
        .route("/dav/pub/{*path}", any(published))
        .route("/dav/freebusy/{*path}", any(freebusy_link))
        .with_state(state)
}

/// Токен из пути: ровно один сегмент с суффиксом `ext` (токен — `cal-` и hex, процентовки нет).
fn token_of<'a>(path: &'a str, area: &str, ext: &str) -> Option<&'a str> {
    let rest = path.strip_prefix(area)?;
    if rest.contains('/') {
        return None;
    }
    let token = rest.strip_suffix(ext)?;
    (!token.is_empty()).then_some(token)
}

fn lock(
    rate: &Mutex<HashMap<String, VecDeque<Instant>>>,
) -> MutexGuard<'_, HashMap<String, VecDeque<Instant>>> {
    rate.lock().expect("блокировка окон частоты")
}

/// Окно частоты запросов — минута.
const WINDOW: Duration = Duration::from_secs(60);

/// Число отслеживаемых токенов, при превышении которого окна без запросов за минуту выбрасываются.
const MAX_TOKENS: usize = 100_000;

/// Кэшировать ответы ссылок intermediaries могут недолго: отзыв должен подействовать быстро.
const CACHE: &str = "public, max-age=60";

/// Запрос токена `token` разрешён (`Ok(())`) или лимит исчерпан (`Err` — время до восполнения).
/// `limit = 0` — ограничение выключено.
fn allow(
    rate: &Mutex<HashMap<String, VecDeque<Instant>>>,
    token: &str,
    limit: u32,
    now: Instant,
) -> std::result::Result<(), Duration> {
    if limit == 0 {
        return Ok(());
    }
    let mut map = lock(rate);
    if map.len() > MAX_TOKENS {
        map.retain(|_, w| w.back().is_some_and(|t| now.duration_since(*t) < WINDOW));
    }
    let window = map.entry(token.to_owned()).or_default();
    while window
        .front()
        .is_some_and(|t| now.duration_since(*t) >= WINDOW)
    {
        window.pop_front();
    }
    if window.len() >= usize::try_from(limit).unwrap_or(usize::MAX) {
        let oldest = window.front().copied().unwrap_or(now);
        return Err(WINDOW.saturating_sub(now.duration_since(oldest)));
    }
    window.push_back(now);
    Ok(())
}

/// Ссылка `If-None-Match` совпала с `etag` (или `*`; слабая форма `W/` тоже): условный `GET`
/// отдаёт 304.
fn not_modified(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',').map(str::trim).any(|t| {
                let t = t.strip_prefix("W/").unwrap_or(t);
                t == "*" || t.trim_matches('"') == etag
            })
        })
}

/// Ответ с телом календаря или занятости (`head` — без тела), всегда с `ETag` и `Cache-Control`.
fn calendar_response(code: StatusCode, etag: &str, body: String, head: bool) -> Response {
    let mut resp = Response::new(if head {
        Body::empty()
    } else {
        Body::from(body)
    });
    *resp.status_mut() = code;
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/calendar; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE));
    if let Ok(v) = HeaderValue::from_str(&format!("\"{etag}\"")) {
        h.insert(header::ETAG, v);
    }
    resp
}

/// 304 с теми же `ETag` и `Cache-Control`.
fn not_modified_response(etag: &str) -> Response {
    let mut resp = StatusCode::NOT_MODIFIED.into_response();
    let h = resp.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE));
    if let Ok(v) = HeaderValue::from_str(&format!("\"{etag}\"")) {
        h.insert(header::ETAG, v);
    }
    resp
}

/// `OPTIONS` без входа: клиенты узнают методы до запроса.
fn options() -> Response {
    let mut resp = StatusCode::OK.into_response();
    let h = resp.headers_mut();
    h.insert(
        header::ALLOW,
        HeaderValue::from_static("OPTIONS, GET, HEAD"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    resp
}

/// Методы, кроме `GET`/`HEAD`/`OPTIONS`.
fn not_allowed() -> Response {
    let mut resp = StatusCode::METHOD_NOT_ALLOWED.into_response();
    resp.headers_mut().insert(
        header::ALLOW,
        HeaderValue::from_static("OPTIONS, GET, HEAD"),
    );
    resp
}

/// `GET`/`HEAD` `/dav/pub/<токен>.ics`.
async fn published(State(st): State<Arc<Publish>>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let method = parts.method.as_str();
    if method == "OPTIONS" {
        return options();
    }
    if method != "GET" && method != "HEAD" {
        return not_allowed();
    }
    let Some(token) = token_of(parts.uri.path(), "/dav/pub/", ".ics") else {
        return status(StatusCode::NOT_FOUND);
    };
    let p = match st.link(token, Instant::now()).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    let level = st.ceiling(p.scope).await.min(p.detail);
    if level == Detail::None {
        return status(StatusCode::NOT_FOUND);
    }
    let c = match st.d.store.get_collection(p.scope, p.calendar).await {
        Ok(Some(c)) => c,
        Ok(None) => return status(StatusCode::NOT_FOUND),
        Err(e) => return store_error(&e),
    };
    if c.kind != CollectionKind::Calendar {
        return status(StatusCode::NOT_FOUND);
    }
    let objects = match st
        .d
        .store
        .in_range(p.scope, c.id, TimeRange::default())
        .await
    {
        Ok(o) => o,
        Err(e) => return store_error(&e),
    };
    let etag = format!("pub-{}-{}", c.state, level.as_str());
    if not_modified(&parts.headers, &etag) {
        return not_modified_response(&etag);
    }
    let body = published_ics(&objects, level);
    calendar_response(StatusCode::OK, &etag, body, method == "HEAD")
}

/// `GET`/`HEAD` `/dav/freebusy/<токен>.vfb`.
async fn freebusy_link(State(st): State<Arc<Publish>>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let method = parts.method.as_str();
    if method == "OPTIONS" {
        return options();
    }
    if method != "GET" && method != "HEAD" {
        return not_allowed();
    }
    let Some(token) = token_of(parts.uri.path(), "/dav/freebusy/", ".vfb") else {
        return status(StatusCode::NOT_FOUND);
    };
    let p = match st.link(token, Instant::now()).await {
        Ok(p) => p,
        Err(resp) => return *resp,
    };
    if st.ceiling(p.scope).await.min(p.detail) < Detail::FreeBusy {
        return status(StatusCode::NOT_FOUND);
    }
    let range = match interval(parts.uri.query()) {
        Ok(range) => range,
        Err(code) => return status(code),
    };
    let max = time::Duration::try_from(st.cfg.max_freebusy_span).unwrap_or(time::Duration::MAX);
    if range.end - range.start > max {
        tracing::debug!("publish: интервал занятости длиннее предела");
        return status(StatusCode::BAD_REQUEST);
    }
    let busy = match st
        .d
        .freebusy
        .query(p.scope.tenant, &[p.scope.account], range)
        .await
    {
        Ok(mut b) => b.pop().map(|(_, periods)| periods).unwrap_or_default(),
        Err(e) => return store_error(&e),
    };
    let state = match st.d.store.state(p.scope, CollectionKind::Calendar).await {
        Ok(s) => s,
        Err(e) => return store_error(&e),
    };
    let etag = format!(
        "fb-{}-{}-{}",
        state,
        range.start.unix_timestamp(),
        range.end.unix_timestamp()
    );
    if not_modified(&parts.headers, &etag) {
        return not_modified_response(&etag);
    }
    let body = freebusy_ics(range, &busy);
    calendar_response(StatusCode::OK, &etag, body, method == "HEAD")
}

/// Интервал запроса занятости: параметры `start` и `end` (RFC 3339, UTC — с суффиксом `Z`); нет
/// параметров, не разбираются или конец не позже начала — `Err` с 400.
fn interval(query: Option<&str>) -> std::result::Result<Period, StatusCode> {
    let param = |name: &str| -> Option<&str> {
        query?.split('&').find_map(|p| {
            let (k, v) = p.split_once('=')?;
            (k == name).then_some(v)
        })
    };
    const BAD: StatusCode = StatusCode::BAD_REQUEST;
    let at = |v: Option<&str>| -> std::result::Result<OffsetDateTime, StatusCode> {
        v.map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or(BAD)
            .and_then(|s| OffsetDateTime::parse(s, &Rfc3339).map_err(|_| BAD))
    };
    let range = Period {
        start: at(param("start"))?,
        end: at(param("end"))?,
    };
    if range.validate().is_err() {
        return Err(BAD);
    }
    Ok(range)
}

/// Свойство события на уровне `level`: `free_busy` — только интервалы занятости (и служебные
/// свойства повторов, статуса и прозрачности), `limited` — ещё тема и место.
fn keep(e: &ICalendarEntry, level: Detail) -> bool {
    let when = matches!(
        e.name,
        ICalendarProperty::Dtstamp
            | ICalendarProperty::Uid
            | ICalendarProperty::Dtstart
            | ICalendarProperty::Dtend
            | ICalendarProperty::Duration
            | ICalendarProperty::Rrule
            | ICalendarProperty::Rdate
            | ICalendarProperty::Exdate
            | ICalendarProperty::RecurrenceId
            | ICalendarProperty::Status
            | ICalendarProperty::Transp
    );
    match level {
        Detail::Limited => {
            when || matches!(
                e.name,
                ICalendarProperty::Summary | ICalendarProperty::Location
            )
        }
        _ => when,
    }
}

/// Тело опубликованного календаря: один `VCALENDAR` с компонентами объектов `objects` на уровне
/// `level`. Объект, который не разбирается, пропускается; часовые пояса (`VTIMEZONE`) — как есть,
/// напоминания (`VALARM`) на уровнях ниже `details` — долой.
fn published_ics(objects: &[tp_contracts::dav::DavObject], level: Detail) -> String {
    let mut root = ICalendarComponent::new(ICalendarComponentType::VCalendar);
    root.add_property(ICalendarProperty::Version, "2.0");
    root.add_property(ICalendarProperty::Prodid, props::PRODID);
    root.add_property(ICalendarProperty::Calscale, "GREGORIAN");
    let mut out = ICalendar {
        components: vec![root],
    };
    for o in objects {
        let Ok(ical) = ICalendar::parse(&o.body) else {
            continue;
        };
        let Some(src) = ical.components.first() else {
            continue;
        };
        for &id in &src.component_ids {
            let Some(c) = ical.component_by_id(id) else {
                continue;
            };
            let tz = c.component_type == ICalendarComponentType::VTimezone;
            let mut c = c.clone();
            if level == Detail::Details || level == Detail::All || tz {
                // Как хранится (и пояса — всегда): с вложенными компонентами и всеми свойствами.
                itip::push(&mut out, &ical, c, true);
            } else {
                c.entries.retain(|e| keep(e, level));
                itip::push(&mut out, &ical, c, false);
            }
        }
    }
    out.to_string()
}

/// Тело ссылки занятости: `VFREEBUSY` с интервалом запроса и периодами `busy` по видам занятости.
fn freebusy_ics(range: Period, busy: &[BusyPeriod]) -> String {
    let mut root = ICalendarComponent::new(ICalendarComponentType::VCalendar);
    root.add_property(ICalendarProperty::Version, "2.0");
    root.add_property(ICalendarProperty::Prodid, props::PRODID);
    root.component_ids.push(1);
    let utc = |t: OffsetDateTime| PartialDateTime::from_utc_timestamp(t.unix_timestamp());
    let mut fb = ICalendarComponent::new(ICalendarComponentType::VFreebusy);
    fb.add_dtstamp(PartialDateTime::now());
    fb.add_property(ICalendarProperty::Dtstart, utc(range.start));
    fb.add_property(ICalendarProperty::Dtend, utc(range.end));
    for (kind, fbtype) in [
        (BusyKind::Busy, ICalendarFreeBusyType::Busy),
        (BusyKind::Tentative, ICalendarFreeBusyType::BusyTentative),
        (
            BusyKind::Unavailable,
            ICalendarFreeBusyType::BusyUnavailable,
        ),
    ] {
        let values: Vec<ICalendarValue> = busy
            .iter()
            .filter(|p| p.kind == kind)
            .map(|p| {
                ICalendarValue::Period(ICalendarPeriod::Range {
                    start: utc(p.start),
                    end: utc(p.end),
                })
            })
            .collect();
        if !values.is_empty() {
            fb.entries.push(
                ICalendarEntry::new(ICalendarProperty::Freebusy)
                    .with_param(ICalendarParameter::fbtype(fbtype))
                    .with_values(values),
            );
        }
    }
    ICalendar {
        components: vec![root, fb],
    }
    .to_string()
}
