//! Веб-клиент (SRS 1.3, WEB-01; полоса mod-webmail): маршруты `/mail/*` на слушателе JMAP — вшитая
//! статика `web/dist` (крейт `tp-webmail`, фича `webmail`). Включение — секция `modules.webmail`
//! платформы (SRS 2.5): `enabled: true` — маршруты есть; `false` или секции нет — маршрутов нет;
//! `enabled: true` в сборке без фичи `webmail` — ошибка конфигурации («module is not built in»).
//! По умолчанию модуль выключен (конвенция `modules.<имя>`), веб-консоль включена по умолчанию —
//! отличие осознанное: клиент ещё каркас.
//!
//! Файл правит полоса mod-webmail (`lanes.toml`), остальные файлы крейта — полоса app.

use tp_contracts::{Error, Result};
use tp_platform::{Config, SectionRegistry};

use crate::modules::ModuleSection;

/// Имя секции `modules.<имя>`.
pub const SECTION: &str = "webmail";

/// Регистрирует секцию `modules.webmail` в реестре секций (вызывается из `sections::registry`).
pub fn register(r: &mut SectionRegistry) -> Result<()> {
    r.add_module::<ModuleSection>(SECTION)
}

/// Конфигурация раздачи из секции `modules.webmail` (ключ `enabled` платформа забирает себе).
fn config(cfg: &Config) -> Result<tp_webmail::Config> {
    let section = cfg.module::<ModuleSection>(SECTION)?;
    let config: tp_webmail::Config =
        serde_json::from_value(serde_json::Value::Object(section.as_ref().clone()))
            .map_err(|e| Error::invalid(format!("modules.{SECTION}: {e}")))?;
    config.check()?;
    Ok(config)
}

/// Добавляет маршруты `/mail/*` (`tp_webmail::routes`) к маршрутизатору слушателя JMAP, если модуль
/// включён; выключенный модуль маршрутизатор не меняет.
pub fn merge(router: axum::Router, cfg: &Config) -> Result<axum::Router> {
    if !cfg.module_enabled(SECTION) {
        return Ok(router);
    }
    Ok(tp_webmail::routes(
        router,
        &config(cfg)?,
        tp_webmail::embedded(),
    ))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};

    use super::*;

    /// Минимальная конфигурация (без секций ролей — merge их не читает). Реестр — `sections::registry`:
    /// секция `modules.webmail` в нём уже зарегистрирована (фича `webmail` включена — тесты собираются).
    const BASE: &str = "
domain: example.org
profile: dev
service_http:
  allow_plaintext: true
database:
  url: postgres://thepost@localhost/thepost?sslmode=disable
  tls: { allow_plaintext: true }
blob:
  url: file:///var/lib/thepost/blob
";

    fn cfg(yaml: &str) -> Config {
        crate::sections::registry()
            .expect("registry")
            .parse(&format!("{BASE}{yaml}"), Vec::new())
            .expect("config")
    }

    async fn status(cfg: &Config, uri: &str) -> StatusCode {
        let router = merge(axum::Router::new(), cfg).expect("merge");
        let req = Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        let resp = tower::ServiceExt::oneshot(router, req).await.expect("resp");
        resp.status()
    }

    #[test]
    fn module_section_registered() {
        let cfg = cfg("modules:\n  webmail: { enabled: true, asset_max_age: 1h }\n");
        assert!(cfg.module_enabled(SECTION));
        let config = config(&cfg).expect("config");
        assert_eq!(config.asset_max_age, std::time::Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn enabled_serves_mail_disabled_is_404() {
        // Выключенный модуль (по умолчанию и с явным false) маршрутов не добавляет.
        for yaml in ["", "modules:\n  webmail: { enabled: false }\n"] {
            let cfg = cfg(yaml);
            assert!(!cfg.module_enabled(SECTION));
            for uri in ["/mail", "/mail/", "/mail/folder/x"] {
                assert_eq!(status(&cfg, uri).await, StatusCode::NOT_FOUND, "{uri}");
            }
        }
        // Включённый: /mail ведёт на /mail/; статика без сборки — страница «веб-клиент не собран»
        // (в тестах отладочная сборка, web/dist на CI тестов нет).
        let cfg = cfg("modules:\n  webmail: { enabled: true }\n");
        assert_eq!(status(&cfg, "/mail").await, StatusCode::TEMPORARY_REDIRECT);
        let s = status(&cfg, "/mail/").await;
        assert!(
            s == StatusCode::OK || s == StatusCode::SERVICE_UNAVAILABLE,
            "GET /mail/: {s}"
        );
    }

    #[tokio::test]
    async fn bad_connect_src_fails_merge() {
        let cfg = cfg(
            "modules:\n  webmail: { enabled: true, connect_src: [\"http://idp.example.org\"] }\n",
        );
        let e = merge(axum::Router::new(), &cfg).expect_err("ошибка");
        assert!(
            e.to_string()
                .contains("modules.webmail: connect_src \"http://idp.example.org\""),
            "{e}"
        );
    }
}
