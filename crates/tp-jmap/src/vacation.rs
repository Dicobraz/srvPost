//! Автоответ: `VacationResponse/get`, `VacationResponse/set` (RFC 8621 §8; JMAP-23) поверх
//! [`SieveStore::vacation`](tp_contracts::sieve::SieveStore::vacation) и `set_vacation`.
//!
//! Объект один на учётную запись (`id` = `singleton`): создать или удалить его нельзя (`singleton`), другой `id` —
//! `notFound`. Состояние — [`SieveStore::state`](tp_contracts::sieve::SieveStore::state) (общее со скриптами Sieve);
//! push — тип `VacationResponse` по сигналу `SieveChanged`.
//!
//! Внешний текст (CTR-93, JMAP-47): свойства `externalSubject`, `externalTextBody`, `externalHtmlBody` — расширение
//! под capability [`THEPOST_VACATION`](crate::core::THEPOST_VACATION) (`urn:thepost:vacation`, как `ExternalMessage`
//! Exchange): без неё в `using` клиент видит стандартный объект, внешние свойства неизвестны (`invalidProperties`) и
//! внешний текст не меняется. Пустой внешний текст — чужим ответа нет ([`Vacation::has_external`]).

use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tp_contracts::Error;
use tp_contracts::sieve::Vacation;

use crate::core::Ctx;
use crate::core::THEPOST_VACATION;
use crate::core::error::{MethodError, MethodResult, set_error};
use crate::core::request::{GetArgs, SetArgs, SetOutcome, object, parse_args, select};
use crate::email_get::utc_date;

/// Идентификатор единственного объекта.
const SINGLETON: &str = "singleton";

/// Объект `VacationResponse`; `ext` — внешний текст под [`THEPOST_VACATION`] (без неё клиент видит стандартный
/// объект RFC 8621).
fn vacation_object(v: &Vacation, ext: bool) -> Map<String, Value> {
    let mut m = object(json!({
        "id": SINGLETON,
        "isEnabled": v.enabled,
        "fromDate": v.from.map_or(Value::Null, utc_date),
        "toDate": v.to.map_or(Value::Null, utc_date),
        "subject": v.subject,
        "textBody": v.text_body,
        "htmlBody": v.html_body,
    }));
    if ext {
        m.insert("externalSubject".into(), json!(v.external_subject));
        m.insert("externalTextBody".into(), json!(v.external_text_body));
        m.insert("externalHtmlBody".into(), json!(v.external_html_body));
    }
    m
}

/// `VacationResponse/get`.
pub(crate) async fn get(
    ctx: &mut Ctx<'_>,
    args: Map<String, Value>,
) -> MethodResult<Map<String, Value>> {
    let a: GetArgs = parse_args(args)?;
    ctx.check_account(&a.account_id)?;
    ctx.check_get_limit(a.ids.as_ref())?;
    let store = ctx.jmap.sieve_store()?;
    let state = store.state(ctx.scope).await?;
    let me = vacation_object(
        &store.vacation(ctx.scope).await?,
        ctx.uses(THEPOST_VACATION),
    );
    let (mut list, mut not_found) = (Vec::new(), Vec::new());
    match &a.ids {
        None => list.push(me),
        Some(ids) => {
            for i in ids {
                if i == SINGLETON {
                    if list.is_empty() {
                        list.push(me.clone());
                    }
                } else {
                    not_found.push(i.clone());
                }
            }
        }
    }
    let list: Vec<Value> = list
        .into_iter()
        .map(|o| Value::Object(select(o, a.properties.as_deref())))
        .collect();
    Ok(object(json!({
        "accountId": a.account_id,
        "state": state.to_string(),
        "list": list,
        "notFound": not_found,
    })))
}

fn opt_date(v: &Value) -> Option<Option<OffsetDateTime>> {
    match v {
        Value::Null => Some(None),
        Value::String(s) => OffsetDateTime::parse(s, &Rfc3339).ok().map(Some),
        _ => None,
    }
}

fn opt_string(v: &Value) -> Option<Option<String>> {
    match v {
        Value::Null => Some(None),
        Value::String(s) => Some(Some(s.clone())),
        _ => None,
    }
}

/// Применяет патч к автоответу; `ext` — внешние свойства под [`THEPOST_VACATION`] (без неё — неизвестны). Ошибка —
/// объект `SetError`.
fn apply_patch(v: &mut Vacation, patch: &Value, ext: bool) -> Result<(), Value> {
    let Value::Object(p) = patch else {
        return Err(set_error("invalidPatch", None, &[]));
    };
    let mut bad: Vec<&str> = Vec::new();
    for (key, val) in p {
        let ok = match key.as_str() {
            "id" => val == SINGLETON,
            "isEnabled" => val.as_bool().map(|b| v.enabled = b).is_some(),
            "fromDate" => opt_date(val).map(|d| v.from = d).is_some(),
            "toDate" => opt_date(val).map(|d| v.to = d).is_some(),
            "subject" => opt_string(val).map(|s| v.subject = s).is_some(),
            "textBody" => opt_string(val).map(|s| v.text_body = s).is_some(),
            "htmlBody" => opt_string(val).map(|s| v.html_body = s).is_some(),
            "externalSubject" if ext => opt_string(val).map(|s| v.external_subject = s).is_some(),
            "externalTextBody" if ext => {
                opt_string(val).map(|s| v.external_text_body = s).is_some()
            }
            "externalHtmlBody" if ext => {
                opt_string(val).map(|s| v.external_html_body = s).is_some()
            }
            _ => false,
        };
        if !ok {
            bad.push(key);
        }
    }
    if !bad.is_empty() {
        return Err(set_error("invalidProperties", None, &bad));
    }
    if let Err(e) = v.validate() {
        let why = match &e {
            Error::Invalid(m) => m.clone(),
            e => e.to_string(),
        };
        return Err(set_error("invalidProperties", Some(&why), &[]));
    }
    Ok(())
}

/// `VacationResponse/set`: только изменение объекта `singleton`.
pub(crate) async fn set(
    ctx: &mut Ctx<'_>,
    args: Map<String, Value>,
) -> MethodResult<Map<String, Value>> {
    let a: SetArgs = parse_args(args)?;
    ctx.check_account(&a.account_id)?;
    a.check_limit(ctx.jmap.cfg.max_objects_in_set)?;
    let store = ctx.jmap.sieve_store()?;
    let old = store.state(ctx.scope).await?.to_string();
    if a.if_in_state.as_ref().is_some_and(|s| *s != old) {
        return Err(MethodError::new("stateMismatch"));
    }
    let mut out = SetOutcome::default();
    for (cid, _) in a.create.unwrap_or_default() {
        out.not_created
            .insert(cid, set_error("singleton", None, &[]));
    }
    for id in a.destroy.unwrap_or_default() {
        out.not_destroyed
            .insert(id, set_error("singleton", None, &[]));
    }
    for (id, patch) in a.update.unwrap_or_default() {
        if id != SINGLETON {
            out.not_updated.insert(id, set_error("notFound", None, &[]));
            continue;
        }
        let ext = ctx.uses(THEPOST_VACATION);
        let mut v = store.vacation(ctx.scope).await?;
        if let Err(e) = apply_patch(&mut v, &patch, ext) {
            out.not_updated.insert(id, e);
            continue;
        }
        match store.set_vacation(ctx.scope, v).await {
            Ok(_) => {
                crate::sieve::rules_changed(ctx, "vacation").await;
                out.updated.insert(id, Value::Null);
            }
            Err(Error::Invalid(m)) => {
                out.not_updated
                    .insert(id, set_error("invalidProperties", Some(&m), &[]));
            }
            Err(e) => return Err(e.into()),
        }
    }
    let new = store.state(ctx.scope).await?.to_string();
    Ok(out.response(&a.account_id, &old, &new))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use tp_contracts::sieve::SieveStore;

    use crate::testenv::Env;

    const USING: &[&str] = &[
        "urn:ietf:params:jmap:core",
        "urn:ietf:params:jmap:vacationresponse",
    ];

    /// Стандартная возможность плюс внешняя (JMAP-47): внешний текст автоответа.
    const USING_EXT: &[&str] = &[
        "urn:ietf:params:jmap:core",
        "urn:ietf:params:jmap:vacationresponse",
        crate::core::THEPOST_VACATION,
    ];

    async fn call(env: &Env, method: &str, args: Value) -> Value {
        let resp = env
            .request(json!({"using": USING, "methodCalls": [[method, args, "c0"]]}))
            .await;
        let name = &resp["methodResponses"][0][0];
        assert!(name == method || name == "error", "{resp}");
        resp["methodResponses"][0][1].clone()
    }

    async fn call_ext(env: &Env, method: &str, args: Value) -> Value {
        let resp = env
            .request(json!({"using": USING_EXT, "methodCalls": [[method, args, "c0"]]}))
            .await;
        let name = &resp["methodResponses"][0][0];
        assert!(name == method || name == "error", "{resp}");
        resp["methodResponses"][0][1].clone()
    }

    #[tokio::test]
    async fn session_lists_capability() {
        let env = Env::new().await;
        let s = env
            .jmap
            .session(&env.principal, "https://mail.example.org")
            .await;
        assert!(s["capabilities"][USING[1]].is_object(), "{s}");
        // Внешний текст автоответа — рядом со стандартной возможностью (JMAP-47).
        assert!(s["capabilities"][USING_EXT[2]].is_object(), "{s}");
        assert_eq!(s["primaryAccounts"][USING[1]], env.account());
        assert_eq!(s["primaryAccounts"][USING_EXT[2]], env.account());
        // Без хранилища Sieve обеих возможностей нет.
        let bare = Env::bare().await;
        let s = bare
            .jmap
            .session(&bare.principal, "https://mail.example.org")
            .await;
        assert!(s["capabilities"][USING[1]].is_null(), "{s}");
        assert!(s["capabilities"][USING_EXT[2]].is_null(), "{s}");
    }

    #[tokio::test]
    async fn enable_with_dates_then_disable() {
        let env = Env::new().await;
        let acc = env.account();
        let r = call(&env, "VacationResponse/get", json!({"accountId": acc})).await;
        assert_eq!(r["list"][0]["id"], "singleton", "{r}");
        assert_eq!(r["list"][0]["isEnabled"], false);
        let state0 = r["state"].clone();

        let r = call(
            &env,
            "VacationResponse/set",
            json!({"accountId": acc, "ifInState": state0, "update": {"singleton": {
                "isEnabled": true,
                "fromDate": "2026-12-01T00:00:00+03:00",
                "toDate": "2026-12-10T00:00:00Z",
                "subject": "В отпуске",
                "textBody": "Вернусь 10 декабря",
            }}}),
        )
        .await;
        assert!(
            r["updated"]["singleton"].is_null() && r["notUpdated"].is_null(),
            "{r}"
        );
        assert_ne!(r["oldState"], r["newState"], "{r}");

        let v = env.sieve.vacation(env.scope).await.expect("vacation");
        assert!(v.enabled);
        assert_eq!(v.subject.as_deref(), Some("В отпуске"));
        let r = call(
            &env,
            "VacationResponse/get",
            json!({"accountId": acc, "ids": ["singleton", "other"]}),
        )
        .await;
        assert_eq!(r["notFound"], json!(["other"]));
        assert_eq!(
            r["list"],
            json!([{
                "id": "singleton",
                "isEnabled": true,
                "fromDate": "2026-11-30T21:00:00Z",
                "toDate": "2026-12-10T00:00:00Z",
                "subject": "В отпуске",
                "textBody": "Вернусь 10 декабря",
                "htmlBody": null,
            }])
        );

        let r = call(
            &env,
            "VacationResponse/set",
            json!({"accountId": acc, "update": {"singleton": {"isEnabled": false}}}),
        )
        .await;
        assert!(r["notUpdated"].is_null(), "{r}");
        let v = env.sieve.vacation(env.scope).await.expect("vacation");
        assert!(!v.enabled);
        assert_eq!(
            v.subject.as_deref(),
            Some("В отпуске"),
            "остальное сохраняется"
        );
    }

    #[tokio::test]
    async fn set_errors() {
        let env = Env::new().await;
        let acc = env.account();
        let r = call(
            &env,
            "VacationResponse/set",
            json!({"accountId": acc,
                   "create": {"c1": {"isEnabled": true}},
                   "update": {"other": {"isEnabled": true}},
                   "destroy": ["singleton"]}),
        )
        .await;
        assert_eq!(r["notUpdated"]["other"]["type"], "notFound", "{r}");
        assert_eq!(r["notCreated"]["c1"]["type"], "singleton", "{r}");
        assert_eq!(r["notDestroyed"]["singleton"]["type"], "singleton", "{r}");
        assert_eq!(r["oldState"], r["newState"]);

        // Начало позже конца и неизвестное свойство.
        let r = call(
            &env,
            "VacationResponse/set",
            json!({"accountId": acc, "update": {"singleton": {
                "fromDate": "2026-12-10T00:00:00Z", "toDate": "2026-12-01T00:00:00Z"}}}),
        )
        .await;
        assert_eq!(
            r["notUpdated"]["singleton"]["type"], "invalidProperties",
            "{r}"
        );
        let r = call(
            &env,
            "VacationResponse/set",
            json!({"accountId": acc, "update": {"singleton": {"isEnabled": "yes", "x": 1}}}),
        )
        .await;
        assert_eq!(
            r["notUpdated"]["singleton"]["properties"],
            json!(["isEnabled", "x"]),
            "{r}"
        );
        let r = call(
            &env,
            "VacationResponse/set",
            json!({"accountId": acc, "ifInState": "nope", "update": {}}),
        )
        .await;
        assert_eq!(r["type"], "stateMismatch", "{r}");
    }

    /// Без хранилища Sieve capability нет: запрос с ней — `unknownCapability`.
    #[tokio::test]
    async fn absent_without_store() {
        let env = Env::bare().await;
        let s = env
            .jmap
            .session(&env.principal, "https://mail.example.org")
            .await;
        assert!(s["capabilities"][USING[1]].is_null(), "{s}");
        let resp = env
            .request(json!({"using": USING, "methodCalls": [
                ["VacationResponse/get", {"accountId": env.account()}, "c0"]]}))
            .await;
        assert_eq!(
            resp["type"], "urn:ietf:params:jmap:error:unknownCapability",
            "{resp}"
        );
    }

    /// Внешний текст автоответа (CTR-93, JMAP-47): свойства `external*` видны и меняются только под
    /// `urn:thepost:vacation`; без неё клиент видит стандартный объект RFC 8621, внешние свойства неизвестны
    /// (`invalidProperties`) и внешний текст не меняется.
    #[tokio::test]
    async fn external_text_under_capability() {
        let env = Env::new().await;
        let acc = env.account();

        // Без `urn:thepost:vacation` объект стандартный: внешних свойств нет, задать их нельзя.
        let r = call(&env, "VacationResponse/get", json!({"accountId": acc})).await;
        assert!(r["list"][0]["externalSubject"].is_null(), "{r}");
        let r = call(
            &env,
            "VacationResponse/set",
            json!({"accountId": acc, "update": {"singleton": {"isEnabled": true,
                "externalSubject": "Away", "externalTextBody": "Out of office"}}}),
        )
        .await;
        assert_eq!(
            r["notUpdated"]["singleton"]["type"], "invalidProperties",
            "{r}"
        );
        assert_eq!(
            r["notUpdated"]["singleton"]["properties"],
            json!(["externalSubject", "externalTextBody"]),
            "{r}"
        );
        let v = env.sieve.vacation(env.scope).await.expect("vacation");
        assert!(
            v.external_subject.is_none() && v.external_text_body.is_none(),
            "{v:?}"
        );

        // Под возможностью — внешний текст сохраняется рядом со стандартным.
        let r = call_ext(
            &env,
            "VacationResponse/set",
            json!({"accountId": acc, "update": {"singleton": {"isEnabled": true,
                "subject": "В отпуске", "externalSubject": "Away",
                "externalTextBody": "Out of office until December 10"}}}),
        )
        .await;
        assert!(
            r["updated"]["singleton"].is_null() && r["notUpdated"].is_null(),
            "{r}"
        );
        let v = env.sieve.vacation(env.scope).await.expect("vacation");
        assert_eq!(v.external_subject.as_deref(), Some("Away"));
        assert_eq!(
            v.external_text_body.as_deref(),
            Some("Out of office until December 10")
        );

        // Без возможности внешние свойства не видны и не меняются: стандартный патч внешний текст не трогает.
        let r = call(&env, "VacationResponse/get", json!({"accountId": acc})).await;
        assert_eq!(r["list"][0]["subject"], "В отпуске", "{r}");
        assert!(r["list"][0]["externalSubject"].is_null(), "{r}");
        let r = call(
            &env,
            "VacationResponse/set",
            json!({"accountId": acc,
                "update": {"singleton": {"subject": "В отпуске до 10 декабря"}}}),
        )
        .await;
        assert!(r["notUpdated"].is_null(), "{r}");
        let v = env.sieve.vacation(env.scope).await.expect("vacation");
        assert_eq!(
            v.subject.as_deref(),
            Some("В отпуске до 10 декабря"),
            "стандартный текст меняется"
        );
        assert_eq!(
            v.external_text_body.as_deref(),
            Some("Out of office until December 10"),
            "внешний текст не меняется"
        );

        // С возможностью объект содержит и внешний текст.
        let r = call_ext(&env, "VacationResponse/get", json!({"accountId": acc})).await;
        assert_eq!(r["list"][0]["externalSubject"], "Away", "{r}");
        assert_eq!(
            r["list"][0]["externalTextBody"], "Out of office until December 10",
            "{r}"
        );
    }
}
