//! Веб-клиент The Post (SRS 1.3, WEB-01): статика `web/dist`, вшитая в бинарный файл (`rust-embed`, фича `embed`).
//!
//! Маршруты `/mail/*` добавляет к слушателю JMAP `thepost` (`crates/thepost/src/webmail.rs`, фича `webmail`):
//! `GET /mail/*` — файл сборки; неизвестный путь вне `assets/` — `index.html` (маршруты SPA); `/mail` → `/mail/`;
//! `GET /mail/config.json` — конфигурация входа для SPA (WEB-02): поставщик OIDC (`issuer`, `client_id`,
//! `scope`, `end_session`) и флаг входа по паролю приложения — только публичные сведения, без секретов.
//! Ответы несут `Content-Security-Policy` без внешних источников и `X-Frame-Options: DENY`, как у веб-консоли;
//! файлы `assets/` (имя с хэшем содержимого) кэшируются надолго, остальное — с перепроверкой. Без фичи `embed`
//! или без сборки клиента — страница «веб-клиент не собран» (конфигурация входа отдаётся и без сборки —
//! её читает SPA, а она без сборки не запускается). Включение — секция `modules.webmail`
//! (`enabled: true`); выключенный модуль маршрутов не добавляет.
//!
//! Данные клиент берёт через JMAP того же узла (same-origin, решение 2026-11-20) — вход по OIDC прямо из SPA
//! (WEB-02, `oidc-client-ts`: authorization code + PKCE, тихий renew по refresh-токену — скрытый iframe не
//! нужен, `frame-src` не расширяется), поэтому `connect_src` нужен для источника поставщика OIDC — запросы
//! к discovery и token endpoint.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use schemars::JsonSchema;
use serde::Deserialize;
use tp_contracts::config::duration;
use tp_contracts::{Error, Result};

/// Адрес веб-клиента; совпадает с `base` сборки (`web/vite.config.ts`).
const MAIL: &str = "/mail/";

/// Политика содержимого: только свой источник. Встроенные стили — для CSS клиента, `data:` — значки и шрифты.
const CSP_HEAD: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
                        img-src 'self' data:; font-src 'self' data:; connect-src 'self'";
const CSP_TAIL: &str =
    "; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

/// Страница вместо веб-клиента, когда его сборки в бинарном файле нет.
const NOT_BUILT: &str = concat!(
    "<!doctype html>\n<html lang=\"ru\">\n<head><meta charset=\"UTF-8\">",
    "<title>The Post — веб-клиент не собран</title></head>\n<body>\n<h1>Веб-клиент не собран</h1>\n",
    "<p>Этот бинарный файл собран без веб-клиента. JMAP, DAV и <code>thepost admin</code> работают.</p>\n",
    "<p>Как собрать веб-клиент — <a href=\"",
    env!("CARGO_PKG_REPOSITORY"),
    "/blob/main/docs/DEV.md\">docs/DEV.md</a>.</p>\n</body>\n</html>\n"
);

/// Поставщик OIDC для входа из SPA (WEB-02): SPA сама получает токен (authorization code + PKCE,
/// `oidc-client-ts`), JMAP уже проверяет `Bearer` (`tp-jmap/core/http.rs`). `issuer` — адрес discovery
/// (`{issuer}/.well-known/openid-configuration`), `client_id` — публичный клиент (секрета нет),
/// `scope` (по умолчанию `openid`), `end_session` — адрес выхода «везде», если discovery поставщика
/// его не отдаёт.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
pub struct Oidc {
    /// Адрес поставщика (discovery issuer), например `https://idp.example.org/realms/post`.
    pub issuer: String,
    /// Идентификатор клиента у поставщика (публичный, PKCE — без секрета).
    pub client_id: String,
    /// Запрашиваемые области (`openid profile email`); без ключа — `openid`.
    pub scope: Option<String>,
    /// Адрес выхода «везде» (end session); без ключа — берётся из discovery, а если и там нет —
    /// выход только локальный.
    pub end_session: Option<String>,
}

/// Подсекция `modules.webmail` (раздача веб-клиента слушателем JMAP): параметры статики и входа.
/// Включение — ключ `enabled` секции модуля (платформа), здесь его нет.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default)]
pub struct Config {
    /// Срок кэширования файлов с хэшем в имени (`assets/`).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub asset_max_age: Duration,
    /// Дополнительные источники `connect-src` (поставщик OIDC, например `https://idp.example.org`); по умолчанию — нет.
    pub connect_src: Vec<String>,
    /// Поставщик OIDC (WEB-02); нет секции — вход только по паролю приложения (Basic).
    pub oidc: Option<Oidc>,
    /// Fallback: форма «логин + пароль приложения» при настроенном OIDC (без OIDC вход Basic и так есть).
    pub basic_login: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            asset_max_age: Duration::from_secs(365 * 24 * 3600),
            connect_src: Vec::new(),
            oidc: None,
            basic_login: false,
        }
    }
}

/// Хост адреса `https://узел[:порт][/путь]`: нет схемы, хоста или пробелов — `None`.
fn https_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    let ok = !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'))
        && !url.chars().any(char::is_whitespace);
    ok.then_some(host)
}

/// Маркер области OIDC (RFC 6749 §3.3, `scope-token`): буквы, цифры и `!#$%&'*+.^_`|~-`.
fn scope_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+.^_`|~-".contains(c))
}

impl Config {
    /// Вход по паролю приложения: включён явно или OIDC не настроен (тогда это единственный способ).
    pub fn basic_login(&self) -> bool {
        self.basic_login || self.oidc.is_none()
    }

    /// Проверяет значения: источники `connect_src` — `https://узел[:порт]` без пути и служебных знаков;
    /// `oidc.issuer` и `oidc.end_session` — `https://`-адреса без пробелов и фрагментов (у `issuer` — ещё
    /// и без запроса: discovery дописывает путь к нему), `client_id` и `scope` — непустые.
    pub fn check(&self) -> Result<()> {
        for src in &self.connect_src {
            let host = src.strip_prefix("https://").unwrap_or_default();
            let ok = !host.is_empty()
                && host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':' | '[' | ']'));
            if !ok {
                return Err(Error::invalid(format!(
                    "modules.webmail: connect_src {src:?} — ожидается https://узел[:порт]"
                )));
            }
        }
        if let Some(oidc) = &self.oidc {
            let issuer_ok = https_host(&oidc.issuer).is_some()
                && !oidc.issuer.contains(['?', '#'])
                && !oidc.issuer.split('/').any(|seg| seg == "..");
            if !issuer_ok {
                return Err(Error::invalid(format!(
                    "modules.webmail: oidc.issuer {:?} — ожидается https://узел[:порт][/путь]",
                    oidc.issuer
                )));
            }
            let id_ok = !oidc.client_id.trim().is_empty()
                && oidc.client_id == oidc.client_id.trim()
                && !oidc.client_id.chars().any(char::is_whitespace);
            if !id_ok {
                return Err(Error::invalid(format!(
                    "modules.webmail: oidc.client_id {:?} — непустой, без пробелов по краям и внутри",
                    oidc.client_id
                )));
            }
            if let Some(scope) = &oidc.scope {
                if !scope.split(' ').all(scope_token) {
                    return Err(Error::invalid(format!(
                        "modules.webmail: oidc.scope {scope:?} — маркеры области через пробел (RFC 6749)"
                    )));
                }
            }
            if let Some(end) = &oidc.end_session {
                if https_host(end).is_none() || end.contains('#') {
                    return Err(Error::invalid(format!(
                        "modules.webmail: oidc.end_session {end:?} — ожидается https://адрес[?запрос]"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Конфигурация входа для SPA (`GET /mail/config.json`): только публичные сведения — поставщик
    /// OIDC (`scope` без ключа — `openid`) и флаг входа по паролю приложения; секретов нет.
    pub fn config_json(&self) -> String {
        let oidc = self.oidc.as_ref().map(|o| {
            serde_json::json!({
                "issuer": o.issuer,
                "client_id": o.client_id,
                "scope": o.scope.as_deref().unwrap_or("openid"),
                "end_session": o.end_session,
            })
        });
        serde_json::json!({ "oidc": oidc, "basic": self.basic_login() }).to_string()
    }

    fn csp(&self) -> HeaderValue {
        let mut csp = String::from(CSP_HEAD);
        for src in &self.connect_src {
            csp.push(' ');
            csp.push_str(src);
        }
        csp.push_str(CSP_TAIL);
        // Значения проверены `check`; непроверенная конфигурация — политика без дополнительных источников.
        HeaderValue::from_str(&csp).unwrap_or_else(|_| {
            HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'")
        })
    }
}

/// Источник файлов сборки по пути относительно `web/dist`.
pub type Lookup = fn(&str) -> Option<Cow<'static, [u8]>>;

#[cfg(feature = "embed")]
mod embedded {
    use std::borrow::Cow;

    /// Сборка веб-клиента; каталога может не быть — тогда файлов нет.
    #[derive(rust_embed::RustEmbed)]
    #[folder = "../../web/dist"]
    #[allow_missing = true]
    struct Dist;

    pub(super) fn lookup(path: &str) -> Option<Cow<'static, [u8]>> {
        <Dist as rust_embed::RustEmbed>::get(path).map(|f| f.data)
    }
}

/// Вшитая сборка веб-клиента; без фичи `embed` файлов нет.
pub fn embedded() -> Lookup {
    #[cfg(feature = "embed")]
    {
        embedded::lookup
    }
    #[cfg(not(feature = "embed"))]
    {
        |_| None
    }
}

struct Site {
    lookup: Lookup,
    csp: HeaderValue,
    asset_cache: HeaderValue,
    config_json: String,
}

enum Found {
    File {
        mime: &'static str,
        hashed: bool,
        body: Cow<'static, [u8]>,
    },
    NotBuilt,
    Missing,
}

/// Тип содержимого по расширению: только то, что бывает в сборке веб-клиента.
fn mime(path: &str) -> &'static str {
    match path.rsplit_once('.').map(|(_, ext)| ext) {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("webmanifest") => "application/manifest+json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("webp") => "image/webp",
        Some("ico") => "image/x-icon",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("txt") => "text/plain; charset=utf-8",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

fn resolve(lookup: Lookup, path: &str) -> Found {
    if path.split('/').any(|seg| seg == "..") {
        return Found::Missing;
    }
    if !path.is_empty() {
        if let Some(body) = lookup(path) {
            return Found::File {
                mime: mime(path),
                hashed: path.starts_with("assets/"),
                body,
            };
        }
        // Пропавший файл `assets/` не подменяется страницей. По расширению судить нельзя: в маршрутах SPA
        // бывает точка (`folder/INBOX`).
        if path.starts_with("assets/") {
            return Found::Missing;
        }
    }
    match lookup("index.html") {
        Some(body) => Found::File {
            mime: "text/html; charset=utf-8",
            hashed: false,
            body,
        },
        None => Found::NotBuilt,
    }
}

async fn serve(site: Arc<Site>, path: String) -> Response {
    let lookup = site.lookup;
    // В отладочной сборке `rust-embed` читает файлы с диска — вне потоков async.
    let found = tokio::task::spawn_blocking(move || resolve(lookup, &path)).await;
    let html = HeaderValue::from_static("text/html; charset=utf-8");
    let no_cache = HeaderValue::from_static("no-cache");
    let mut resp = match found {
        Ok(Found::File { mime, hashed, body }) => {
            let cache = if hashed {
                site.asset_cache.clone()
            } else {
                no_cache
            };
            let mut r = body.into_owned().into_response();
            r.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(mime));
            r.headers_mut().insert(header::CACHE_CONTROL, cache);
            r
        }
        Ok(Found::NotBuilt) => {
            let mut r = (StatusCode::SERVICE_UNAVAILABLE, NOT_BUILT).into_response();
            r.headers_mut().insert(header::CONTENT_TYPE, html);
            r.headers_mut().insert(header::CACHE_CONTROL, no_cache);
            r
        }
        Ok(Found::Missing) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    secure(&mut resp, &site.csp);
    resp
}

/// Конфигурация входа для SPA (WEB-02): строится из секции `modules.webmail` при старте — файлов
/// сборки не требует; перепроверка — как у статики.
async fn serve_config(site: Arc<Site>) -> Response {
    let mut resp = Response::new(axum::body::Body::from(site.config_json.clone()));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    secure(&mut resp, &site.csp);
    resp
}

/// Заголовки безопасности ответа веб-клиента: те же, что у веб-консоли.
fn secure(resp: &mut Response, csp: &HeaderValue) {
    let h = resp.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, csp.clone());
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
}

/// Добавляет маршруты веб-клиента к маршрутизатору (включение решает вызывающий: секция
/// `modules.webmail`); статика открыта, данные — только через JMAP того же слушателя.
pub fn routes<S>(r: Router<S>, cfg: &Config, lookup: Lookup) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let max_age = format!("public, max-age={}, immutable", cfg.asset_max_age.as_secs());
    let site = Arc::new(Site {
        lookup,
        csp: cfg.csp(),
        asset_cache: HeaderValue::from_str(&max_age)
            .unwrap_or_else(|_| HeaderValue::from_static("no-cache")),
        config_json: cfg.config_json(),
    });
    let index = site.clone();
    let config = site.clone();
    r.route("/mail", get(|| async { Redirect::temporary(MAIL) }))
        .route(MAIL, get(move || serve(index, String::new())))
        .route("/mail/config.json", get(move || serve_config(config)))
        .route(
            "/mail/{*path}",
            get(move |Path(path): Path<String>| serve(site, path)),
        )
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::Request;

    use super::*;

    fn dist(path: &str) -> Option<Cow<'static, [u8]>> {
        match path {
            "index.html" => Some(Cow::Borrowed(b"<!doctype html><div id=root>")),
            "assets/index-C0ffee12.js" => Some(Cow::Borrowed(b"console.log(1)")),
            "favicon.svg" => Some(Cow::Borrowed(b"<svg/>")),
            _ => None,
        }
    }

    fn empty(_: &str) -> Option<Cow<'static, [u8]>> {
        None
    }

    async fn call(
        cfg: &Config,
        lookup: Lookup,
        uri: &str,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        let router: Router = routes(Router::new(), cfg, lookup);
        let req = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        let resp = tower::ServiceExt::oneshot(router, req)
            .await
            .expect("response");
        let (parts, body) = resp.into_parts();
        let body = axum::body::to_bytes(body, usize::MAX).await.expect("body");
        (parts.status, parts.headers, body.to_vec())
    }

    #[tokio::test]
    async fn index_and_asset() {
        let cfg = Config::default();
        let (s, h, b) = call(&cfg, dist, "/mail/").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(h[header::CACHE_CONTROL], "no-cache");
        assert!(b.starts_with(b"<!doctype html>"));

        let (s, h, b) = call(&cfg, dist, "/mail/assets/index-C0ffee12.js").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], "text/javascript; charset=utf-8");
        assert_eq!(
            h[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(b, b"console.log(1)");

        let (s, h, _) = call(&cfg, dist, "/mail/favicon.svg").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], "image/svg+xml");
        assert_eq!(h[header::CACHE_CONTROL], "no-cache");
    }

    #[tokio::test]
    async fn spa_route_and_missing_asset() {
        let cfg = Config::default();
        // Deep-link маршрута SPA (приёмка WEB-01: /mail/folder/x) — страница, а не 404.
        let (s, h, b) = call(&cfg, dist, "/mail/folder/x").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert!(b.starts_with(b"<!doctype html>"));

        let (s, _, _) = call(&cfg, dist, "/mail/assets/gone-12345678.js").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _, _) = call(&cfg, dist, "/mail/../index.html").await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn redirects_to_mail() {
        let cfg = Config::default();
        let (s, h, _) = call(&cfg, dist, "/mail").await;
        assert_eq!(s, StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(h[header::LOCATION], "/mail/");
    }

    #[tokio::test]
    async fn security_headers() {
        let cfg = Config {
            connect_src: vec!["https://idp.example.org".into()],
            ..Config::default()
        };
        cfg.check().expect("config");
        for (lookup, uri) in [
            (dist as Lookup, "/mail/"),
            (dist, "/mail/assets/index-C0ffee12.js"),
            (empty, "/mail/"),
            (empty, "/mail/config.json"),
        ] {
            let (_, h, _) = call(&cfg, lookup, uri).await;
            let csp = h[header::CONTENT_SECURITY_POLICY].to_str().expect("csp");
            assert!(csp.starts_with("default-src 'self'; script-src 'self';"));
            assert!(csp.contains("connect-src 'self' https://idp.example.org;"));
            assert!(csp.contains("frame-ancestors 'none'"));
            assert!(!csp.contains("http://") && !csp.contains('*'));
            assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
            assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        }
        let (_, h, _) = call(&Config::default(), dist, "/mail/").await;
        let csp = h[header::CONTENT_SECURITY_POLICY].to_str().expect("csp");
        assert!(!csp.contains("https://"));
    }

    /// Конфигурация входа (WEB-02): с OIDC — issuer/client_id/scope/end_session, секретов нет;
    /// политика содержимого same-origin (`connect-src 'self'`) запрос конфигурации не режет;
    /// работает и без сборки клиента — SPA без сборки не запускается.
    #[tokio::test]
    async fn config_json_with_oidc() {
        let cfg = Config {
            connect_src: vec!["https://idp.example.org".into()],
            oidc: Some(Oidc {
                issuer: "https://idp.example.org/realms/post".into(),
                client_id: "thepost-webmail".into(),
                scope: Some("openid profile email".into()),
                end_session: Some("https://idp.example.org/realms/post/logout".into()),
            }),
            ..Config::default()
        };
        cfg.check().expect("config");
        let (s, h, b) = call(&cfg, empty, "/mail/config.json").await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], "application/json");
        assert_eq!(h[header::CACHE_CONTROL], "no-cache");
        let csp = h[header::CONTENT_SECURITY_POLICY].to_str().expect("csp");
        assert!(csp.contains("connect-src 'self'"));
        let json: serde_json::Value = serde_json::from_slice(&b).expect("json");
        let oidc = json["oidc"].as_object().expect("oidc");
        assert_eq!(oidc["issuer"], "https://idp.example.org/realms/post");
        assert_eq!(oidc["client_id"], "thepost-webmail");
        assert_eq!(oidc["scope"], "openid profile email");
        assert_eq!(
            oidc["end_session"],
            "https://idp.example.org/realms/post/logout"
        );
        assert_eq!(json["basic"], false);
        let text = String::from_utf8(b).expect("utf-8");
        assert!(!text.contains("secret"), "{text}");
    }

    #[tokio::test]
    async fn config_json_without_oidc() {
        // Без OIDC вход по паролю приложения — единственный способ; с OIDC fallback включается явно.
        let (s, _, b) = call(&Config::default(), empty, "/mail/config.json").await;
        assert_eq!(s, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&b).expect("json");
        assert_eq!(json["oidc"], serde_json::Value::Null);
        assert_eq!(json["basic"], true);

        let with_oidc = Config {
            oidc: Some(Oidc {
                issuer: "https://idp.example.org".into(),
                client_id: "thepost-webmail".into(),
                scope: None,
                end_session: None,
            }),
            ..Config::default()
        };
        let json: serde_json::Value = serde_json::from_str(&with_oidc.config_json()).expect("json");
        assert_eq!(json["oidc"]["scope"], "openid");
        assert_eq!(json["oidc"]["end_session"], serde_json::Value::Null);
        assert_eq!(json["basic"], false);
        let fallback = Config {
            basic_login: true,
            ..with_oidc
        };
        let json: serde_json::Value = serde_json::from_str(&fallback.config_json()).expect("json");
        assert_eq!(json["basic"], true);
    }

    #[test]
    fn oidc_check() {
        let ok = |issuer: &str| Config {
            oidc: Some(Oidc {
                issuer: issuer.into(),
                client_id: "thepost-webmail".into(),
                scope: Some("openid profile".into()),
                end_session: Some("https://idp.example.org/logout?post_logout=1".into()),
            }),
            ..Config::default()
        };
        ok("https://idp.example.org").check().expect("config");
        ok("https://idp.example.org:8443/realms/post")
            .check()
            .expect("config");
        for value in [
            "http://idp.example.org",
            "https://",
            "https://idp.example.org/../../admin",
            "https://idp.example.org?next=https://evil",
            "https://idp.example.org#frag",
            "https://idp .example.org",
            "*",
        ] {
            let bad = ok(value);
            assert!(bad.check().is_err(), "{value}");
        }
        let bad = |oidc: Oidc| Config {
            oidc: Some(oidc),
            ..Config::default()
        };
        for client_id in ["", "  thepost  ", "two words"] {
            let bad = bad(Oidc {
                issuer: "https://idp.example.org".into(),
                client_id: client_id.into(),
                scope: None,
                end_session: None,
            });
            assert!(bad.check().is_err(), "client_id {client_id:?}");
        }
        for scope in ["openid;alert(1)", "openid\u{00a0}profile", "openid,"] {
            let bad = bad(Oidc {
                issuer: "https://idp.example.org".into(),
                client_id: "thepost-webmail".into(),
                scope: Some(scope.into()),
                end_session: None,
            });
            assert!(bad.check().is_err(), "scope {scope:?}");
        }
        for end_session in [
            "http://idp.example.org/logout",
            "https://idp.example.org#x",
            "not-a-url",
        ] {
            let bad = bad(Oidc {
                issuer: "https://idp.example.org".into(),
                client_id: "thepost-webmail".into(),
                scope: None,
                end_session: Some(end_session.into()),
            });
            assert!(bad.check().is_err(), "end_session {end_session:?}");
        }
        // Секция в целом: неизвестные ключи молча пропускаются, как у остальных полей конфигурации.
        let cfg: Config = serde_json::from_value(serde_json::json!({
            "oidc": { "issuer": "https://idp.example.org", "client_id": "thepost-webmail" },
            "basic_login": true,
            "dayz": 3,
        }))
        .expect("config");
        assert_eq!(
            cfg,
            Config {
                oidc: Some(Oidc {
                    issuer: "https://idp.example.org".into(),
                    client_id: "thepost-webmail".into(),
                    scope: None,
                    end_session: None,
                }),
                basic_login: true,
                ..Config::default()
            }
        );
    }

    #[tokio::test]
    async fn not_built_page() {
        let (s, h, b) = call(&Config::default(), empty, "/mail/folder").await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(h[header::CONTENT_TYPE], "text/html; charset=utf-8");
        let text = String::from_utf8(b).expect("utf-8");
        assert!(text.contains("Веб-клиент не собран"));
        assert!(text.contains("/docs/DEV.md"));
    }

    #[test]
    fn config_check() {
        let ok = Config {
            connect_src: vec!["https://idp.example.org:8443".into()],
            ..Config::default()
        };
        ok.check().expect("config");
        for src in [
            "http://idp.example.org",
            "https://",
            "https://a b",
            "https://a; script-src *",
            "*",
        ] {
            let bad = Config {
                connect_src: vec![src.into()],
                ..Config::default()
            };
            assert!(bad.check().is_err(), "{src}");
        }
        let cfg: Config =
            serde_json::from_value(serde_json::json!({ "asset_max_age": "1h" })).expect("config");
        assert_eq!(cfg.asset_max_age, Duration::from_secs(3600));
        // Неизвестные ключи секции платформа извещает предупреждением (мягкий режим), конфигурация клиента
        // их молча пропускает — как flatten-поля модулей.
        let extra: Config =
            serde_json::from_value(serde_json::json!({ "dayz": 3 })).expect("config");
        assert_eq!(extra, Config::default());
    }
}
