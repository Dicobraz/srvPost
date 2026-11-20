//! DAV-20, DAV-21: публикация календаря ICS (`/dav/pub/<токен>.ics`) и ссылка занятости
//! (`/dav/freebusy/<токен>.vfb`) без входа: уровни детализации, потолок политики, отзыв и срок,
//! `ETag` и `Cache-Control`, ограничение частоты, предел интервала.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use time::OffsetDateTime;
use tower::ServiceExt;
use tp_contracts::calendar::CalendarPublication;
use tp_contracts::dav::{CollectionId, CollectionKind};
use tp_contracts::meta::AccountScope;
use tp_contracts::trust::{Detail, TrustLevel, TrustPolicy, TrustStore};
use tp_contracts::{PublicationId, Result};
use tp_testkit::MemTrust;

use super::{Env, Resp, event};
use crate::config::DavConfig;
use crate::publish::{PublicationLookup, PublishDeps, router};

/// `GET` маршрутов публикации; статус ответа.
async fn status_of(app: &Router, path: &str) -> StatusCode {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path)
                .body(Body::empty())
                .expect("запрос"),
        )
        .await
        .expect("infallible");
    resp.status()
}

/// Ссылки публикаций в памяти: выданные ссылки хранит целиком (токен включительно), ищет по
/// точному совпадению токена, истёкшие не отвечает — как хранилище (`PgMeta::publication_by_token`,
/// META-34: отозванная, истёкшая и неверный токен — `None`).
#[derive(Clone, Default)]
struct FakePubs(Arc<Mutex<Vec<CalendarPublication>>>);

impl FakePubs {
    fn put(&self, p: CalendarPublication) {
        self.0.lock().expect("ссылки").push(p);
    }

    fn revoke(&self, token: &str) {
        self.0
            .lock()
            .expect("ссылки")
            .retain(|p| p.token.as_deref() != Some(token));
    }
}

#[async_trait]
impl PublicationLookup for FakePubs {
    async fn publication_by_token(&self, token: &str) -> Result<Option<CalendarPublication>> {
        let links = self.0.lock().expect("ссылки");
        Ok(links
            .iter()
            .find(|p| {
                p.token.as_deref() == Some(token)
                    && p.expires.is_none_or(|e| e > OffsetDateTime::now_utc())
            })
            .cloned())
    }
}

/// Сервер DAV с входом (наполнение календаря), маршруты публикации и политики доверия.
struct Fixture {
    dav: Env,
    app: Router,
    pubs: FakePubs,
    trust: MemTrust,
    scope: AccountScope,
    cal: CollectionId,
}

impl Fixture {
    /// Календарь «calendar» с событием `event` (PUT от владельца), политика организации
    /// `sharing.external = level`, маршруты публикации поверх того же хранилища.
    async fn new(level: Detail) -> Self {
        Self::with_events(level, &[(event("e-1", "Планёрка").as_str(), "e-1.ics")]).await
    }

    async fn with_events(level: Detail, events: &[(&str, &str)]) -> Self {
        let dav = Env::new();
        dav.calendar("calendar").await;
        for (body, name) in events {
            let r = dav
                .send(
                    "PUT",
                    &format!("/dav/calendars/ivan@example.org/calendar/{name}"),
                    &[("content-type", "text/calendar")],
                    body,
                )
                .await;
            assert!(r.status.is_success(), "PUT {name}: {}", r.status);
        }
        let trust = MemTrust::new();
        let mut policy = TrustPolicy::default();
        policy.sharing.external = Some(level);
        trust
            .set_policy(TrustLevel::Org(dav.scope.tenant), &policy)
            .await
            .expect("политика организации");
        let pubs = FakePubs::default();
        let app = router(
            PublishDeps {
                store: Arc::new(dav.store.clone()),
                publications: Arc::new(pubs.clone()),
                freebusy: Arc::new(dav.store.clone()),
                trust: Some(Arc::new(trust.clone())),
            },
            DavConfig::default(),
        );
        let scope = dav.scope;
        let cal = dav
            .collection(CollectionKind::Calendar, "calendar")
            .await
            .expect("календарь")
            .id;
        Self {
            dav,
            app,
            pubs,
            trust,
            scope,
            cal,
        }
    }

    /// Ссылка публикации календаря с уровнем `detail` и токеном `token`.
    fn link(&self, token: &str, detail: Detail) -> CalendarPublication {
        CalendarPublication {
            id: PublicationId::new(),
            scope: self.scope,
            calendar: self.cal,
            detail,
            expires: None,
            token: Some(token.to_owned()),
        }
    }

    /// Запрос к маршрутам публикации без входа.
    async fn send(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> Resp {
        let mut b = Request::builder()
            .method(Method::from_bytes(method.as_bytes()).expect("метод"))
            .uri(path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let resp = self
            .app
            .clone()
            .oneshot(b.body(Body::empty()).expect("запрос"))
            .await
            .expect("infallible");
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.expect("тело");
        Resp {
            status,
            headers,
            body: String::from_utf8(bytes.to_vec()).expect("utf-8"),
        }
    }

    async fn get(&self, path: &str) -> Resp {
        self.send("GET", path, &[]).await
    }
}

const TOKEN: &str = "cal-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
/// Событие с содержанием: тема, место, описание, участники, напоминание.
const RICH: &str = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//RU\r\nBEGIN:VEVENT\r\n\
UID:e-rich\r\nDTSTAMP:20260101T000000Z\r\nDTSTART:20260105T100000Z\r\nDTEND:20260105T110000Z\r\n\
SUMMARY:Планёрка\r\nLOCATION:Переговорная 4\r\nDESCRIPTION:Обсудить план\r\n\
ORGANIZER;CN=Иван:mailto:ivan@example.org\r\n\
ATTENDEE:mailto:maria@example.org\r\nTRANSP:OPAQUE\r\nSTATUS:CONFIRMED\r\n\
BEGIN:VALARM\r\nACTION:DISPLAY\r\nDESCRIPTION:Напоминание\r\nTRIGGER:-PT10M\r\nEND:VALARM\r\n\
END:VEVENT\r\nEND:VCALENDAR\r\n";

/// Три уровня детализации на одном событии: `details` — всё (с напоминанием), `limited` — время,
/// тема и место, `free_busy` — только интервалы.
#[tokio::test]
async fn detail_levels() {
    let fx = Fixture::with_events(
        Detail::Details,
        &[
            (RICH, "e-rich.ics"),
            (event("e-2", "Обед").as_str(), "e-2.ics"),
        ],
    )
    .await;
    for (token, detail) in [
        ("cal-d-details", Detail::Details),
        ("cal-d-limited", Detail::Limited),
        ("cal-d-freebusy", Detail::FreeBusy),
    ] {
        fx.pubs.put(fx.link(token, detail));
    }

    let r = fx.get("/dav/pub/cal-d-details.ics").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        r.header("content-type"),
        Some("text/calendar; charset=utf-8")
    );
    assert_eq!(
        r.header("cache-control"),
        Some("public, max-age=60"),
        "{}",
        r.body
    );
    // Как хранится: темы, места, участники и напоминание на месте.
    for line in [
        "SUMMARY:Планёрка",
        "LOCATION:Переговорная 4",
        "DESCRIPTION:Обсудить план",
        "ATTENDEE:mailto:maria@example.org",
        "BEGIN:VALARM",
        "SUMMARY:Обед",
    ] {
        assert!(r.body.contains(line), "{line}: {}", r.body);
    }

    let r = fx.get("/dav/pub/cal-d-limited.ics").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    for line in ["SUMMARY:Планёрка", "LOCATION:Переговорная 4"] {
        assert!(r.body.contains(line), "{line}: {}", r.body);
    }
    for gone in ["DESCRIPTION:", "ATTENDEE:", "ORGANIZER:", "VALARM"] {
        assert!(!r.body.contains(gone), "{gone}: {}", r.body);
    }

    let r = fx.get("/dav/pub/cal-d-freebusy.ics").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("DTSTART:20260105T100000Z"), "{}", r.body);
    for gone in [
        "SUMMARY:",
        "LOCATION:",
        "DESCRIPTION:",
        "VALARM",
        "ATTENDEE:",
    ] {
        assert!(!r.body.contains(gone), "{gone}: {}", r.body);
    }
}

/// Потолок политики ограничивает отдачу по ссылке: ужесточение политики с `Details` до `free_busy`
/// урезает содержание и меняет `ETag`; потолок «ничего» — ссылка не отвечает (DAV-44).
#[tokio::test]
async fn policy_ceiling_limits_serving() {
    let fx = Fixture::new(Detail::Details).await;
    fx.pubs.put(fx.link("cal-capped", Detail::Details));
    let r = fx.get("/dav/pub/cal-capped.ics").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(r.body.contains("SUMMARY:Планёрка"), "{}", r.body);
    let full = r.header("etag").expect("ETag").to_owned();

    let mut policy = TrustPolicy::default();
    policy.sharing.external = Some(Detail::FreeBusy);
    fx.trust
        .set_policy(TrustLevel::Org(fx.scope.tenant), &policy)
        .await
        .expect("политика");
    let r = fx.get("/dav/pub/cal-capped.ics").await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(
        !r.body.contains("SUMMARY:"),
        "содержание урезано: {}",
        r.body
    );
    assert!(r.body.contains("DTSTART:20260105T100000Z"), "{}", r.body);
    assert_ne!(r.header("etag"), Some(full.as_str()), "{}", r.body);

    fx.trust
        .set_policy(TrustLevel::Org(fx.scope.tenant), &TrustPolicy::default())
        .await
        .expect("политика");
    assert_eq!(
        fx.get("/dav/pub/cal-capped.ics").await.status,
        StatusCode::NOT_FOUND
    );
}

/// Отозванная, истёкшая ссылка и неверный токен — 404 без различения причин; чужие формы пути и
/// методы не обслуживаются.
#[tokio::test]
async fn revoked_expired_and_bad_requests() {
    let fx = Fixture::new(Detail::FreeBusy).await;
    let mut expired = fx.link("cal-expired", Detail::FreeBusy);
    expired.expires = Some(OffsetDateTime::now_utc() - time::Duration::hours(1));
    fx.pubs.put(expired);
    fx.pubs.put(fx.link(TOKEN, Detail::FreeBusy));
    assert_eq!(
        fx.get(&format!("/dav/pub/{TOKEN}.ics")).await.status,
        StatusCode::OK
    );

    // Отзыв — по токену больше не отдаётся; неверный токен и срок — тоже 404.
    fx.pubs.revoke(TOKEN);
    for path in [
        format!("/dav/pub/{TOKEN}.ics"),
        "/dav/pub/cal-expired.ics".to_owned(),
        "/dav/pub/cal-unknown-link.ics".to_owned(),
        "/dav/pub/.ics".to_owned(),
        "/dav/pub/".to_owned(),
        format!("/dav/pub/{TOKEN}"),
        format!("/dav/pub/{TOKEN}.vfb"),
        "/dav/pub/a/b.ics".to_owned(),
    ] {
        let r = fx.get(&path).await;
        assert_eq!(r.status, StatusCode::NOT_FOUND, "{path}");
    }

    let r = fx.send("POST", &format!("/dav/pub/{TOKEN}.ics"), &[]).await;
    assert_eq!(r.status, StatusCode::METHOD_NOT_ALLOWED, "{}", r.body);
    let r = fx
        .send("OPTIONS", &format!("/dav/pub/{TOKEN}.ics"), &[])
        .await;
    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.header("allow"), Some("OPTIONS, GET, HEAD"));
}

/// `ETag` меняется с календарём и совпадает при повторе; условный `GET` с `If-None-Match` — 304.
#[tokio::test]
async fn etag_and_conditional_get() {
    let fx = Fixture::new(Detail::FreeBusy).await;
    fx.pubs.put(fx.link(TOKEN, Detail::FreeBusy));
    let r = fx.get(&format!("/dav/pub/{TOKEN}.ics")).await;
    let etag = r.header("etag").expect("ETag").to_owned();
    let again = fx.get(&format!("/dav/pub/{TOKEN}.ics")).await;
    assert_eq!(again.header("etag"), Some(etag.as_str()));

    let r = fx
        .send(
            "GET",
            &format!("/dav/pub/{TOKEN}.ics"),
            &[("if-none-match", &etag)],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_MODIFIED, "{}", r.body);
    assert_eq!(r.header("etag"), Some(etag.as_str()));
    assert_eq!(r.header("cache-control"), Some("public, max-age=60"));

    // Слабая форма и список тоже совпадают.
    let weak = format!("W/{etag}");
    let r = fx
        .send(
            "GET",
            &format!("/dav/pub/{TOKEN}.ics"),
            &[("if-none-match", &weak)],
        )
        .await;
    assert_eq!(r.status, StatusCode::NOT_MODIFIED);

    // Изменение календаря — новый ETag.
    fx.dav
        .put_event("calendar", "e-1.ics", "e-1", "Планёрка изменена")
        .await;
    let r = fx.get(&format!("/dav/pub/{TOKEN}.ics")).await;
    assert_ne!(r.header("etag"), Some(etag.as_str()), "{}", r.body);
    assert!(r.body.contains("Планёрка изменена"), "{}", r.body);
}

/// Ограничение частоты по токену (`dav.pub_rate_limit`): исчерпан — 429 с `Retry-After`; у другого
/// токена своё окно.
#[tokio::test]
async fn rate_limit() {
    let dav = Env::new();
    let trust = MemTrust::new();
    let mut policy = TrustPolicy::default();
    policy.sharing.external = Some(Detail::FreeBusy);
    trust
        .set_policy(TrustLevel::Org(dav.scope.tenant), &policy)
        .await
        .expect("политика");
    let pubs = FakePubs::default();
    let app = router(
        PublishDeps {
            store: Arc::new(dav.store.clone()),
            publications: Arc::new(pubs.clone()),
            freebusy: Arc::new(dav.store.clone()),
            trust: Some(Arc::new(trust.clone())),
        },
        DavConfig {
            pub_rate_limit: 2,
            ..DavConfig::default()
        },
    );
    let cal = dav.calendar("calendar").await;
    let mk = |token: &'static str| CalendarPublication {
        id: PublicationId::new(),
        scope: dav.scope,
        calendar: cal.id,
        detail: Detail::FreeBusy,
        expires: None,
        token: Some(token.to_owned()),
    };
    pubs.put(mk("cal-rl-1"));
    pubs.put(mk("cal-rl-2"));

    let path1 = "/dav/pub/cal-rl-1.ics";
    assert_eq!(status_of(&app, path1).await, StatusCode::OK);
    assert_eq!(status_of(&app, path1).await, StatusCode::OK);
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(path1)
                .body(Body::empty())
                .expect("запрос"),
        )
        .await
        .expect("infallible");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok()),
        Some("60")
    );
    // Другой токен — своё окно.
    assert_eq!(
        status_of(&app, "/dav/pub/cal-rl-2.ics").await,
        StatusCode::OK
    );
}

/// Ссылка занятости: `VFREEBUSY` владельца на интервал; предел интервала (`dav.max_freebusy_span`)
/// и отсутствующие параметры — 400; отозванная ссылка и уровень ниже `free_busy` — 404.
#[tokio::test]
async fn freebusy_link() {
    let fx = Fixture::new(Detail::FreeBusy).await;
    fx.pubs.put(fx.link(TOKEN, Detail::FreeBusy));
    fx.pubs.put(fx.link("cal-fb-limited", Detail::Limited));

    let r = fx
        .get("/dav/freebusy/cal-unknown-fb.vfb?start=2026-01-01T00:00:00Z&end=2026-01-10T00:00:00Z")
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);

    let r = fx
        .get("/dav/freebusy/cal-fb-limited.vfb?start=2026-01-01T00:00:00Z&end=2026-01-10T00:00:00Z")
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND, "{}", r.body);

    let r = fx
        .get(&format!(
            "/dav/freebusy/{TOKEN}.vfb?start=2026-01-01T00:00:00Z&end=2026-01-10T00:00:00Z"
        ))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(
        r.header("content-type"),
        Some("text/calendar; charset=utf-8")
    );
    for line in [
        "BEGIN:VFREEBUSY",
        "DTSTART:20260101T000000Z",
        "DTEND:20260110T000000Z",
        "FREEBUSY;FBTYPE=BUSY:20260105T100000Z/20260105T110000Z",
    ] {
        assert!(r.body.contains(line), "{line}: {}", r.body);
    }

    // Параметры: нет, неверные, интервал вывернут, длиннее предела — 400.
    for query in [
        "",
        "?start=2026-01-01T00:00:00Z",
        "?start=2026-01-01&end=2026-01-10",
        "?start=2026-01-10T00:00:00Z&end=2026-01-01T00:00:00Z",
        "?start=2026-01-01T00:00:00Z&end=2027-03-01T00:00:00Z",
    ] {
        let r = fx.get(&format!("/dav/freebusy/{TOKEN}.vfb{query}")).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{query}: {}", r.body);
    }

    // Отзыв — 404.
    fx.pubs.revoke(TOKEN);
    let r = fx
        .get(&format!(
            "/dav/freebusy/{TOKEN}.vfb?start=2026-01-01T00:00:00Z&end=2026-01-10T00:00:00Z"
        ))
        .await;
    assert_eq!(r.status, StatusCode::NOT_FOUND);
}
