//! Делегированный доступ к чужим ящикам почты в JMAP (JMAP-49): `Email/query`, `Email/queryChanges`,
//! `Email/get` по чужому `accountId` от представителя поверх ACL папок (RFC 4314) — единый слой прав
//! с группами и `anyone` ([`AclStore`](tp_contracts::acl::AclStore); в узле над ним —
//! [`Authorizer`](tp_contracts::auth::Authorizer) `tp_auth::AclAuthorizer`, CTR-82), [`Jmap::with_acl`].
//!
//! - Открытие ящика — как пространство имён общих папок IMAP: папки владельца, открытые субъекту правом
//!   `l` ([`AclStore::shared_mailboxes`](tp_contracts::acl::AclStore::shared_mailboxes)), с их
//!   действующими правами. Чужой `accountId` без общих папок (и неизвестный, и без подключённого
//!   хранилища) — `noAccess`: существование ящика не раскрывается.
//! - Видимость — модель общего доступа календарей и книг (JMAP-32): аккаунт владельца в сессии с
//!   `isPersonal` = `false` и capability почты (без создания папок); письмо читается только из папки с
//!   правом `r` (как SELECT/FETCH в IMAP) — фильтр по папке без права даёт пустой результат, письмо из
//!   неё — `notFound`, изменения журнала чужих папок не сообщаются.
//! - Отправка от чужого имени — существующий путь `Outbound::submit` с вошедшим пользователем (CTR-82) и
//!   записью аудита `SendAs`/`SendOnBehalf`, здесь не меняется. Поиск по тексту (`text`/`body`) в чужом
//!   ящике — запись `Search` в журнал аудита до выдачи (решение 114, JMAP-43; [`crate::audit::search`]).
//!
//! Кэш `Email/query` и `Email/get` для представителя выключен: записи кэша лежат в пространстве
//! владельца и охватывают все его папки.

use std::collections::HashMap;
use std::str::FromStr;

use tp_contracts::acl::{ANYONE, SharedMailbox, validate_identifier};
use tp_contracts::auth::{Principal, Rights};
use tp_contracts::{AccountId, MailboxId, Result};

use crate::core::Jmap;
use crate::core::error::{MethodError, MethodResult};

/// Есть ли у прав `rights` хоть одно из прав `any` (изменение писем, пополнение папки).
fn has_any(rights: Rights, any: Rights) -> bool {
    !(rights - (rights - any)).is_empty()
}

/// Права записи в папке: `s`, `w`, `t`, `e`, `i` — как READ-WRITE у SELECT в IMAP плюс APPEND (`i`).
fn write_rights() -> Rights {
    Rights::SEEN | Rights::WRITE | Rights::DELETE_MESSAGES | Rights::EXPUNGE | Rights::INSERT
}

/// Идентификаторы субъекта в ACL: имя входа и группы, допустимые в ACL, без `anyone` (его хранилище
/// добавляет само) — как `tp_auth::AclAuthorizer` и общие папки IMAP.
fn identifiers(p: &Principal) -> Vec<String> {
    std::iter::once(&p.login)
        .chain(&p.groups)
        .filter(|id| !id.eq_ignore_ascii_case(ANYONE) && validate_identifier(id, false).is_ok())
        .cloned()
        .collect()
}

/// Общие папки почты чужих учётных записей, доступные субъекту по ACL (право `l`); ACL не подключены —
/// пусто.
async fn shared(jmap: &Jmap, p: &Principal) -> Result<Vec<SharedMailbox>> {
    let Some(acl) = &jmap.acl else {
        return Ok(Vec::new());
    };
    Ok(acl
        .shared_mailboxes(p.tenant, &identifiers(p))
        .await?
        .into_iter()
        .filter(|s| s.account != p.account)
        .collect())
}

/// Открывает аккаунт почты владельца `owner`: действующие права субъекта на его общие папки. Общих папок
/// нет (в том числе неизвестный `accountId` и ACL без подключённого хранилища) — `noAccess`.
pub(crate) async fn open(
    jmap: &Jmap,
    p: &Principal,
    owner: &str,
) -> MethodResult<HashMap<MailboxId, Rights>> {
    let no_access = || MethodError::new("noAccess");
    let owner = AccountId::from_str(owner).map_err(|_| no_access())?;
    let rights: HashMap<_, _> = shared(jmap, p)
        .await?
        .into_iter()
        .filter(|s| s.account == owner)
        .map(|s| (s.mailbox, s.rights))
        .collect();
    if rights.is_empty() {
        return Err(no_access());
    }
    Ok(rights)
}

/// Чужой аккаунт почты в сессии: владелец и признаки.
pub(crate) struct MailAccount {
    /// Владелец.
    pub owner: AccountId,
    /// Имя аккаунта — имя входа владельца.
    pub name: String,
    /// Ни на одну общую папку нет права записи.
    pub read_only: bool,
}

/// Чужие аккаунты почты субъекта для сессии (по владельцам общих папок); ошибка хранилища — пусто с
/// записью в журнал узла.
pub(crate) async fn session_accounts(jmap: &Jmap, p: &Principal) -> Vec<MailAccount> {
    let write = write_rights();
    let boxes = match shared(jmap, p).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "jmap: общие папки почты для сессии не прочитаны");
            return Vec::new();
        }
    };
    // Владелец → читает ли хоть одну папку с правом записи.
    let mut by_owner: HashMap<AccountId, bool> = HashMap::new();
    for s in boxes {
        let writable = has_any(s.rights, write);
        by_owner
            .entry(s.account)
            .and_modify(|w| *w |= writable)
            .or_insert(writable);
    }
    let mut out = Vec::new();
    for (owner, writable) in by_owner {
        let account = match jmap.d.accounts.get(p.tenant, owner).await {
            Ok(Some(a)) => a,
            Ok(None) => continue,
            Err(e) => {
                tracing::warn!(error = %e, "jmap: владелец общих папок почты не прочитан");
                continue;
            }
        };
        out.push(MailAccount {
            owner,
            name: account.login,
            read_only: !writable,
        });
    }
    out.sort_by_key(|a| a.owner);
    out
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use tp_contracts::auth::{Principal, Rights};
    use tp_contracts::meta::SpecialUse;
    use tp_contracts::sharing::CollectionRights as R;

    use crate::testenv::{Env, mail};

    const USING: &[&str] = &["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"];

    /// Один вызов от имени `who`: аргументы ответа (или ошибки метода).
    async fn call(env: &Env, who: &Principal, method: &str, args: Value) -> Value {
        let req = json!({"using": USING, "methodCalls": [[method, args, "c0"]]});
        let resp = env
            .jmap
            .api(who, req.to_string().as_bytes())
            .await
            .expect("api");
        serde_json::to_value(resp).expect("serialize")["methodResponses"][0][1].clone()
    }

    /// Представитель читает чужой ящик по ACL: сессия — `isPersonal` = `false`; Email/query и Email/get —
    /// только папки с правом `r`, скрытая папка и письмо из неё — как несуществующие; без права, с правом
    /// только `l` и неизвестный `accountId` — `noAccess`/пусто; владелец видит всё; `Email/set` от
    /// представителя аккаунт не открывает.
    #[tokio::test]
    async fn reads_shared_folders_only() {
        let env = Env::new().await;
        let inbox = env.mailbox(SpecialUse::Inbox);
        let archive = env.mailbox(SpecialUse::Archive);
        let shared = env
            .deliver(
                inbox,
                &mail("Договор", "boris@x.org", "", "текст договора"),
                Default::default(),
            )
            .await;
        let hidden = env
            .deliver(
                archive,
                &mail("Личное", "a@x.org", "", "тайна"),
                Default::default(),
            )
            .await;
        let boss = env.user("boss@example.org").await;
        let acc = env.account();

        // Без права — noAccess на все три метода, аккаунта в сессии нет.
        for (method, args) in [
            ("Email/query", json!({"accountId": acc})),
            (
                "Email/queryChanges",
                json!({"accountId": acc, "sinceQueryState": "0"}),
            ),
            (
                "Email/get",
                json!({"accountId": acc, "ids": [shared.to_string()]}),
            ),
        ] {
            let r = call(&env, &boss, method, args).await;
            assert_eq!(r["type"], "noAccess", "{method}: {r}");
        }
        let r = call(&env, &boss, "Email/query", json!({"accountId": "чужой"})).await;
        assert_eq!(r["type"], "noAccess", "{r}");
        let s = env.jmap.session(&boss, "").await;
        assert!(s["accounts"][&acc].is_null(), "{s}");

        // Чтение входящих: аккаунт в сессии с capability почты, только чтение.
        env.acl
            .set_acl(env.scope, inbox, &boss.login, Rights::LOOKUP | Rights::READ)
            .await
            .expect("acl");
        let s = env.jmap.session(&boss, "").await;
        let a = &s["accounts"][&acc];
        assert_eq!(a["isPersonal"], false, "{s}");
        assert_eq!(a["isReadOnly"], true, "{s}");
        assert_eq!(a["name"], "user@example.org", "{s}");
        assert_eq!(
            a["accountCapabilities"]["urn:ietf:params:jmap:mail"]["mayCreateTopLevelMailbox"],
            false,
            "{s}"
        );
        assert!(
            a["accountCapabilities"]["urn:ietf:params:jmap:submission"].is_null(),
            "{s}"
        );

        // Email/query: только общие папки; скрытая — как несуществующая; её текст не ищется.
        let r = call(&env, &boss, "Email/query", json!({"accountId": acc})).await;
        assert_eq!(r["ids"], json!([shared.to_string()]), "{r}");
        let r = call(
            &env,
            &boss,
            "Email/query",
            json!({"accountId": acc, "filter": {"inMailbox": inbox.to_string()}}),
        )
        .await;
        assert_eq!(r["ids"], json!([shared.to_string()]), "{r}");
        let r = call(
            &env,
            &boss,
            "Email/query",
            json!({"accountId": acc, "filter": {"inMailbox": archive.to_string()}}),
        )
        .await;
        assert_eq!(r["ids"], json!([]), "{r}");
        let r = call(
            &env,
            &boss,
            "Email/query",
            json!({"accountId": acc, "filter": {"text": "тайна"}}),
        )
        .await;
        assert_eq!(r["ids"], json!([]), "{r}");

        // Email/get: общее письмо читается, скрытое — notFound; без ids — только общие папки.
        let r = call(
            &env,
            &boss,
            "Email/get",
            json!({"accountId": acc, "ids": [shared.to_string(), hidden.to_string()],
                "properties": ["subject"]}),
        )
        .await;
        assert_eq!(r["list"][0]["subject"], "Договор", "{r}");
        assert_eq!(r["notFound"], json!([hidden.to_string()]), "{r}");
        let r = call(
            &env,
            &boss,
            "Email/get",
            json!({"accountId": acc, "properties": ["subject"]}),
        )
        .await;
        assert_eq!(r["list"].as_array().map(Vec::len), Some(1), "{r}");

        // Право `l` без `r`: ящик открыт, папка видна, письма не читаются.
        env.acl
            .set_acl(env.scope, inbox, &boss.login, Rights::LOOKUP)
            .await
            .expect("acl");
        let r = call(&env, &boss, "Email/query", json!({"accountId": acc})).await;
        assert_eq!(r["ids"], json!([]), "{r}");
        let r = call(
            &env,
            &boss,
            "Email/get",
            json!({"accountId": acc, "ids": [shared.to_string()]}),
        )
        .await;
        assert_eq!(r["notFound"], json!([shared.to_string()]), "{r}");

        // Владелец видит всё; Email/set представителя аккаунт не открывает.
        let r = call(
            &env,
            &env.principal,
            "Email/query",
            json!({"accountId": acc}),
        )
        .await;
        assert_eq!(r["ids"].as_array().map(Vec::len), Some(2), "{r}");
        let r = call(
            &env,
            &boss,
            "Email/set",
            json!({"accountId": acc, "destroy": [shared.to_string()]}),
        )
        .await;
        assert_eq!(r["type"], "accountNotFound", "{r}");
    }

    /// `Email/queryChanges` представителя: новое письмо общей папки — в `added`, изменения скрытой папки
    /// не сообщаются.
    #[tokio::test]
    async fn query_changes_of_delegate() {
        let env = Env::new().await;
        let inbox = env.mailbox(SpecialUse::Inbox);
        let archive = env.mailbox(SpecialUse::Archive);
        env.deliver(
            inbox,
            &mail("Первое", "a@x.org", "", "текст"),
            Default::default(),
        )
        .await;
        let boss = env.user("boss@example.org").await;
        env.acl
            .set_acl(env.scope, inbox, &boss.login, Rights::LOOKUP | Rights::READ)
            .await
            .expect("acl");
        let acc = env.account();
        let q = call(
            &env,
            &boss,
            "Email/query",
            json!({"accountId": acc, "sort": [{"property": "receivedAt", "isAscending": true}]}),
        )
        .await;
        let state = q["queryState"].clone();
        let fresh = env
            .deliver(
                inbox,
                &mail("Второе", "b@x.org", "", "ещё"),
                Default::default(),
            )
            .await;
        env.deliver(
            archive,
            &mail("Скрытое", "c@x.org", "", "тайна"),
            Default::default(),
        )
        .await;
        let r = call(
            &env,
            &boss,
            "Email/queryChanges",
            json!({"accountId": acc, "sinceQueryState": state, "calculateTotal": true}),
        )
        .await;
        assert_eq!(r["removed"], json!([]), "{r}");
        assert_eq!(
            r["added"],
            json!([{ "id": fresh.to_string(), "index": 1 }]),
            "{r}"
        );
        assert_eq!(r["total"], 2, "{r}");
    }

    /// Владелец общих календарей и папок почты — один аккаунт сессии с обеими capability (JMAP-32 +
    /// JMAP-49), `isReadOnly` — по обеим.
    #[tokio::test]
    async fn session_merges_dav_and_mail() {
        let env = Env::sharing().await;
        let cal = crate::calendars::tests::create_calendar(&env, "Проекты").await;
        let boss = env.user("boss@example.org").await;
        let acc = env.account();
        env.collections.set_rights(
            boss.account,
            env.principal.account,
            cal.parse().expect("cal"),
            R::READ,
        );
        env.acl
            .set_acl(
                env.scope,
                env.mailbox(SpecialUse::Inbox),
                &boss.login,
                Rights::LOOKUP | Rights::READ,
            )
            .await
            .expect("acl");
        let s = env.jmap.session(&boss, "").await;
        let a = &s["accounts"][&acc];
        assert_eq!(a["isPersonal"], false, "{s}");
        assert_eq!(a["isReadOnly"], true, "{s}");
        assert!(
            a["accountCapabilities"]["urn:ietf:params:jmap:calendars"].is_object(),
            "{s}"
        );
        assert!(
            a["accountCapabilities"]["urn:ietf:params:jmap:mail"].is_object(),
            "{s}"
        );
        let r = call(&env, &boss, "Email/query", json!({"accountId": acc})).await;
        assert!(r["ids"].is_array(), "{r}");
    }
}
