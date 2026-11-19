//! Действия по беседе (JMAP-48, решение 125 е; capability `urn:thepost:params:jmap:thread`): объект
//! `ThreadRule` — «что делать с письмами беседы», как EWS `ApplyConversationAction`.
//!
//! Свойства: `id` и `threadId` — беседа (`T` + `ThreadId`, [`crate::core`] JMAP-48), `action` —
//! `alwaysMove` (с `mailboxId`), `ignore`, `alwaysKeyword` (с `keyword`). Правило одно на беседу
//! (замена целиком) и действует на будущие письма беседы — приём применяет его в той же транзакции
//! (MS-21: папка вместо выбранной правилами, корзина, ключевое слово); `applyToExisting` применяет
//! правило и к прежним письмам — одной операцией на беседу, теми же действиями `Email/set` (перенос,
//! корзина, ключевое слово). «Игнорировать» переносит будущие письма в корзину, а не удаляет навсегда:
//! окончательное удаление — по сроку корзины.
//!
//! Удержание беседы (CTR-94) — не пользователя: в объекте не видно и им не снимается, письма
//! удержанной беседы удаляются в корзину как обычно, окончательное удаление запрещает хук
//! `ThreadHoldHook` при очистке корзины.
//!
//! Журнала изменений у правил нет (контракт CTR-94 хранит текущее правило), поэтому `state` — сводка
//! текущих правил, а `ThreadRule/changes` — `cannotCalculateChanges`: клиент перечитывает
//! `ThreadRule/get` (RFC 8620 §5.2). Перечисление (`ids` = `null`, `state`) — по письмам учётной
//! записи: правило беседы без писем не перечисляется, но доступно по идентификатору.

use std::str::FromStr;

use serde::Deserialize;
use serde_json::{Map, Value, json};
use tp_contracts::audit::AuditAction;
use tp_contracts::meta::{Flag, FlagOp, Flags, Message, SpecialUse};
use tp_contracts::thread::ThreadRule;
use tp_contracts::{Error, MailboxId, MessageId, ThreadId};

use crate::core::error::{MethodError, MethodResult, set_error};
use crate::core::request::{
    ChangesArgs, GetArgs, SetArgs, SetOutcome, object, parse_args, parse_state, select,
};
use crate::core::{Ctx, bound_thread_id, digest, parse_thread_id};

/// Значение capability учётной записи: правило одно на беседу.
pub(crate) fn account_capability() -> Value {
    json!({ "maxRulesPerThread": 1 })
}

/// Действие из свойств объекта: `action` и параметр при нём.
fn parse_action(o: &Map<String, Value>) -> Result<ThreadRule, Value> {
    let known = ["action", "id", "threadId", "mailboxId", "keyword"];
    let bad: Vec<&str> = o
        .keys()
        .filter(|k| !known.contains(&k.as_str()))
        .map(String::as_str)
        .collect();
    if !bad.is_empty() {
        return Err(set_error("invalidProperties", None, &bad));
    }
    let action = o
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| set_error("invalidProperties", None, &["action"]))?;
    match action {
        "alwaysMove" => {
            let id = o
                .get("mailboxId")
                .and_then(Value::as_str)
                .ok_or_else(|| set_error("invalidProperties", None, &["mailboxId"]))?;
            MailboxId::from_str(id)
                .map(ThreadRule::AlwaysMove)
                .map_err(|_| set_error("invalidProperties", None, &["mailboxId"]))
        }
        "ignore" => Ok(ThreadRule::Ignore),
        "alwaysKeyword" => {
            let kw = o
                .get("keyword")
                .and_then(Value::as_str)
                .ok_or_else(|| set_error("invalidProperties", None, &["keyword"]))?;
            if crate::email_set::flag_of(kw).is_none() {
                return Err(set_error("invalidProperties", None, &["keyword"]));
            }
            Ok(ThreadRule::AlwaysKeyword(kw.to_lowercase()))
        }
        _ => Err(set_error("invalidProperties", None, &["action"])),
    }
}

/// Объект ThreadRule: `id` и `threadId` — беседа, `action` с параметром.
fn rule_object(id: &str, rule: &ThreadRule) -> Map<String, Value> {
    let mut o = object(json!({"id": id, "threadId": id}));
    match rule {
        ThreadRule::AlwaysMove(m) => {
            o.insert("action".into(), json!("alwaysMove"));
            o.insert("mailboxId".into(), json!(m.to_string()));
        }
        ThreadRule::Ignore => {
            o.insert("action".into(), json!("ignore"));
        }
        ThreadRule::AlwaysKeyword(kw) => {
            o.insert("action".into(), json!("alwaysKeyword"));
            o.insert("keyword".into(), json!(kw));
        }
    }
    o
}

/// Беседы учётной записи с письмами: привязки существующих писем без повторов.
async fn bound_threads(ctx: &Ctx<'_>) -> MethodResult<Vec<ThreadId>> {
    let msgs = ctx.jmap.messages_in(ctx.scope, None).await?;
    let tids = ctx.jmap.thread_ids(ctx.scope, &msgs).await?;
    let mut out: Vec<ThreadId> = tids.values().filter_map(|t| parse_thread_id(t)).collect();
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Существующие письма беседы (по привязке писем учётной записи), с папкой — для переноса и аудита.
async fn existing(ctx: &Ctx<'_>, thread: ThreadId) -> MethodResult<Vec<Message>> {
    let msgs = ctx.jmap.messages_in(ctx.scope, None).await?;
    let tids = ctx.jmap.thread_ids(ctx.scope, &msgs).await?;
    Ok(msgs
        .into_iter()
        .filter(|m| {
            tids.get(&m.id)
                .is_some_and(|t| parse_thread_id(t) == Some(thread))
        })
        .collect())
}

/// Сводка текущих правил — `state` (`ifInState`): меняется с любым правилом.
async fn state(ctx: &Ctx<'_>) -> MethodResult<String> {
    let store = ctx.jmap.threads_store()?;
    let mut parts = Vec::new();
    for t in bound_threads(ctx).await? {
        if let Some(rule) = store.rule(ctx.scope, t).await? {
            parts.push(format!("{t}:{rule}"));
        }
    }
    Ok(digest(parts.join("\n").as_bytes()))
}

/// `ThreadRule/get`: беседы по идентификаторам или все с правилами (`ids` = `null` — по письмам
/// учётной записи, правило беседы без писем не перечисляется).
pub(crate) async fn get(
    ctx: &mut Ctx<'_>,
    args: Map<String, Value>,
) -> MethodResult<Map<String, Value>> {
    let a: GetArgs = parse_args(args)?;
    ctx.check_account(&a.account_id)?;
    ctx.check_get_limit(a.ids.as_ref())?;
    let store = ctx.jmap.threads_store()?;
    let st = state(ctx).await?;
    let mut list = Vec::new();
    let mut not_found = Vec::new();
    match &a.ids {
        Some(ids) => {
            for id in ids {
                let real = ctx.resolve_id(id);
                let found = match parse_thread_id(real) {
                    Some(t) => store
                        .rule(ctx.scope, t)
                        .await?
                        .map(|rule| rule_object(real, &rule)),
                    // Идентификатор не беседы привязки (запасной расчёт по ключу цепочки, чужая
                    // строка) — правил у него быть не может.
                    None => None,
                };
                match found {
                    Some(o) => list.push(Value::Object(select(o, a.properties.as_deref()))),
                    None => not_found.push(id.clone()),
                }
            }
        }
        None => {
            for t in bound_threads(ctx).await? {
                if let Some(rule) = store.rule(ctx.scope, t).await? {
                    list.push(Value::Object(select(
                        rule_object(&bound_thread_id(t), &rule),
                        a.properties.as_deref(),
                    )));
                }
            }
        }
    }
    Ok(object(json!({
        "accountId": a.account_id,
        "state": st,
        "list": list,
        "notFound": not_found,
    })))
}

/// Аргументы `ThreadRule/set`: `/set` и `applyToExisting` — применить правило к прежним письмам
/// беседы (по умолчанию правило действует только на будущие письма, MS-21).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleSetArgs {
    #[serde(flatten)]
    set: SetArgs,
    #[serde(default)]
    apply_to_existing: bool,
}

/// Применяет правило к существующим письмам беседы — одной операцией на беседу, теми же действиями,
/// что `Email/set`: `AlwaysMove` — перенос, `Ignore` — в корзину (окончательное удаление — только по
/// сроку корзины; письмо уже в корзине остаётся, срок не перезапускается), `AlwaysKeyword` —
/// ключевое слово.
async fn apply_existing(
    ctx: &Ctx<'_>,
    thread: ThreadId,
    rule: &ThreadRule,
    trash: Option<MailboxId>,
) -> MethodResult<()> {
    let msgs = existing(ctx, thread).await?;
    if msgs.is_empty() {
        return Ok(());
    }
    let d = &ctx.jmap.d;
    match rule {
        ThreadRule::AlwaysMove(to) => {
            let ids: Vec<MessageId> = msgs.iter().map(|m| m.id).collect();
            d.store.move_to(ctx.scope, &ids, *to).await?;
            let audit: Vec<(MailboxId, MessageId)> = ids.iter().map(|m| (*to, *m)).collect();
            crate::audit::owner_messages(ctx, AuditAction::Move, &audit).await;
        }
        ThreadRule::Ignore => {
            // Письма не из корзины — в корзину; уже в корзине — без изменений (срок не перезапускается).
            let trashing: Vec<&Message> =
                msgs.iter().filter(|m| Some(m.mailbox) != trash).collect();
            if trashing.is_empty() {
                return Ok(());
            }
            let ids: Vec<MessageId> = trashing.iter().map(|m| m.id).collect();
            let audit: Vec<(MailboxId, MessageId)> =
                trashing.iter().map(|m| (m.mailbox, m.id)).collect();
            d.store.delete_to_trash(ctx.scope, &ids).await?;
            crate::audit::owner_messages(ctx, AuditAction::Delete, &audit).await;
        }
        ThreadRule::AlwaysKeyword(kw) => {
            let ids: Vec<MessageId> = msgs.iter().map(|m| m.id).collect();
            let flags: Flags = [Flag::Keyword(kw.clone())].into();
            d.store
                .set_flags(ctx.scope, &ids, FlagOp::Add(flags), None)
                .await?;
        }
    }
    Ok(())
}

/// `ThreadRule/set`: правило одно на беседу, замена целиком (`update` задаёт действие заново),
/// удаление правила не возвращает письма (как EWS). `applyToExisting` — применить к прежним письмам.
pub(crate) async fn set(
    ctx: &mut Ctx<'_>,
    args: Map<String, Value>,
) -> MethodResult<Map<String, Value>> {
    let a: RuleSetArgs = parse_args(args)?;
    ctx.check_account(&a.set.account_id)?;
    a.set.check_limit(ctx.jmap.cfg.max_objects_in_set)?;
    let store = ctx.jmap.threads_store()?;
    let old = state(ctx).await?;
    if a.set.if_in_state.as_ref().is_some_and(|s| *s != old) {
        return Err(MethodError::new("stateMismatch"));
    }
    let mut out = SetOutcome::default();
    // Правила успешно заданных бесед — для `applyToExisting`.
    let mut applied: Vec<(ThreadId, ThreadRule)> = Vec::new();

    for (cid, obj) in a.set.create.unwrap_or_default() {
        let Value::Object(o) = &obj else {
            out.not_created
                .insert(cid, set_error("invalidProperties", None, &[]));
            continue;
        };
        let id = o
            .get("threadId")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let real = ctx.resolve_id(id).to_owned();
        let thread = match parse_thread_id(&real) {
            Some(t) => t,
            None => {
                out.not_created
                    .insert(cid, set_error("invalidProperties", None, &["threadId"]));
                continue;
            }
        };
        let mut fields = o.clone();
        fields.remove("threadId");
        let rule = match parse_action(&fields) {
            Ok(r) => r,
            Err(e) => {
                out.not_created.insert(cid, e);
                continue;
            }
        };
        // Папка `alwaysMove` — существует (перенос в удалённую папку не осмыслен).
        let bad_mailbox = match &rule {
            ThreadRule::AlwaysMove(to) => mailbox_exists(ctx, *to).await?.is_none(),
            _ => false,
        };
        if bad_mailbox {
            out.not_created
                .insert(cid, set_error("invalidProperties", None, &["mailboxId"]));
            continue;
        }
        match store.set_rule(ctx.scope, thread, Some(rule.clone())).await {
            Ok(()) => {
                let id = bound_thread_id(thread);
                ctx.created.insert(cid.clone(), id.clone());
                out.created.insert(cid, json!({"id": id, "threadId": id}));
                applied.push((thread, rule));
            }
            Err(Error::NotFound) => {
                out.not_created
                    .insert(cid, set_error("notFound", None, &["threadId"]));
            }
            Err(e) => return Err(e.into()),
        }
    }

    for (id, patch) in a.set.update.unwrap_or_default() {
        let real = ctx.resolve_id(&id);
        let Some(thread) = parse_thread_id(real) else {
            out.not_updated.insert(id, set_error("notFound", None, &[]));
            continue;
        };
        let Value::Object(o) = &patch else {
            out.not_updated
                .insert(id, set_error("invalidPatch", None, &[]));
            continue;
        };
        let rule = match parse_action(o) {
            Ok(r) => r,
            Err(e) => {
                out.not_updated.insert(id, e);
                continue;
            }
        };
        let bad_mailbox = match &rule {
            ThreadRule::AlwaysMove(to) => mailbox_exists(ctx, *to).await?.is_none(),
            _ => false,
        };
        if bad_mailbox {
            out.not_updated
                .insert(id, set_error("invalidProperties", None, &["mailboxId"]));
            continue;
        }
        match store.set_rule(ctx.scope, thread, Some(rule.clone())).await {
            Ok(()) => {
                out.updated.insert(id, Value::Null);
                applied.push((thread, rule));
            }
            Err(Error::NotFound) => {
                out.not_updated.insert(id, set_error("notFound", None, &[]));
            }
            Err(e) => return Err(e.into()),
        }
    }

    for id in a.set.destroy.unwrap_or_default() {
        let real = ctx.resolve_id(&id);
        match parse_thread_id(real) {
            Some(thread) => match store.set_rule(ctx.scope, thread, None).await {
                Ok(()) => {
                    out.destroyed.push(id);
                }
                Err(Error::NotFound) => {
                    out.not_destroyed
                        .insert(id, set_error("notFound", None, &[]));
                }
                Err(e) => return Err(e.into()),
            },
            None => {
                out.not_destroyed
                    .insert(id, set_error("notFound", None, &[]));
            }
        }
    }

    if a.apply_to_existing {
        let trash = ctx
            .jmap
            .d
            .mailboxes
            .list(ctx.scope)
            .await?
            .into_iter()
            .find_map(|m| (m.role == Some(SpecialUse::Trash)).then_some(m.id));
        for (thread, rule) in &applied {
            apply_existing(ctx, *thread, rule, trash).await?;
        }
    }

    let new = state(ctx).await?;
    Ok(out.response(&a.set.account_id, &old, &new))
}

/// `ThreadRule/changes`: журнала изменений у правил нет (контракт CTR-94 хранит текущее правило) —
/// всегда `cannotCalculateChanges`, клиент перечитывает `ThreadRule/get` (RFC 8620 §5.2).
pub(crate) async fn changes(
    ctx: &mut Ctx<'_>,
    args: Map<String, Value>,
) -> MethodResult<Map<String, Value>> {
    let a: ChangesArgs = parse_args(args)?;
    ctx.check_account(&a.account_id)?;
    ctx.jmap.threads_store()?;
    parse_state(&a.since_state)?;
    Err(MethodError::new("cannotCalculateChanges"))
}

/// Существует ли папка (для `alwaysMove`).
async fn mailbox_exists(ctx: &Ctx<'_>, id: MailboxId) -> MethodResult<Option<MailboxId>> {
    Ok(ctx.jmap.d.mailboxes.get(ctx.scope, id).await?.map(|m| m.id))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use time::OffsetDateTime;
    use tp_contracts::MessageId;
    use tp_contracts::ext::Decision;
    use tp_contracts::meta::SpecialUse;
    use tp_contracts::thread::{ThreadHold, ThreadStore as _};

    use crate::core::parse_thread_id;
    use crate::testenv::{Env, mail};

    const USING: &[&str] = &[
        "urn:ietf:params:jmap:core",
        "urn:ietf:params:jmap:mail",
        "urn:thepost:params:jmap:thread",
    ];

    /// Один вызов с capability бесед: `[имя, аргументы]` ответа.
    async fn call(env: &Env, method: &str, args: Value) -> (String, Value) {
        let resp = env
            .request(json!({ "using": USING, "methodCalls": [[method, args, "c0"]] }))
            .await;
        let r = resp["methodResponses"][0].clone();
        (r[0].as_str().unwrap_or_default().to_owned(), r[1].clone())
    }

    /// `threadId` письма из `Email/get`.
    async fn thread_id_of(env: &Env, m: MessageId) -> String {
        env.call(
            "Email/get",
            json!({"accountId": env.account(), "ids": [m.to_string()],
                "properties": ["threadId"]}),
            "Email/get",
        )
        .await["list"][0]["threadId"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    }

    /// Папка почты с ролью `role`.
    async fn mailbox(env: &Env, role: SpecialUse) -> String {
        env.mailbox(role).to_string()
    }

    /// Приёмка JMAP-48: ответ получает `threadId` исходного письма — идентификатор беседы привязки
    /// (`T` + `ThreadId`), `Thread/get` собирает письма беседы, свёртка цепочек — по привязке.
    #[tokio::test]
    async fn reply_gets_thread_of_original() {
        let env = Env::new().await;
        let inbox = env.mailbox(SpecialUse::Inbox);
        let a = env
            .deliver(
                inbox,
                &mail("Deal", "peer@x.net", "Message-ID: <a@x>\r\n", "1"),
                Default::default(),
            )
            .await;
        let b = env
            .deliver(
                inbox,
                &mail(
                    "Re: Deal",
                    "peer@x.net",
                    "Message-ID: <b@x>\r\nIn-Reply-To: <a@x>\r\nReferences: <a@x>\r\n",
                    "2",
                ),
                Default::default(),
            )
            .await;
        let (ta, tb) = (thread_id_of(&env, a).await, thread_id_of(&env, b).await);
        assert_eq!(ta, tb, "ответ — в беседе исходного письма");
        assert!(
            parse_thread_id(&ta).is_some(),
            "идентификатор — привязка (T + UUID): {ta}"
        );
        let g = env
            .call(
                "Thread/get",
                json!({"accountId": env.account(), "ids": [ta]}),
                "Thread/get",
            )
            .await;
        assert_eq!(
            g["list"][0]["emailIds"],
            json!([a.to_string(), b.to_string()])
        );
        // Свёртка цепочек — по привязке: одна беседа — одно письмо.
        let q = env
            .call(
                "Email/query",
                json!({"accountId": env.account(), "collapseThreads": true}),
                "Email/query",
            )
            .await;
        assert_eq!(q["ids"].as_array().map(Vec::len), Some(1));
    }

    /// Приёмка JMAP-48: письмо, ссылающееся на две беседы, попадает в более раннюю, `threadId` писем
    /// не меняется (беседы не сливаются задним числом).
    #[tokio::test]
    async fn thread_id_never_changes_on_cross_reference() {
        let env = Env::new().await;
        let inbox = env.mailbox(SpecialUse::Inbox);
        let letter = |mid: &str, refs: &str| {
            mail(
                "Deal",
                "peer@x.net",
                &format!("Message-ID: <{mid}@x>\r\n{refs}"),
                "текст",
            )
        };
        let a = env
            .deliver(inbox, &letter("a", ""), Default::default())
            .await;
        let b = env
            .deliver(inbox, &letter("b", ""), Default::default())
            .await;
        let (ta0, tb0) = (thread_id_of(&env, a).await, thread_id_of(&env, b).await);
        assert_ne!(ta0, tb0);
        // Письмо ссылается на обе беседы.
        let c = env
            .deliver(
                inbox,
                &letter("c", "In-Reply-To: <b@x>\r\nReferences: <a@x> <b@x>\r\n"),
                Default::default(),
            )
            .await;
        let (ta1, tb1, tc1) = (
            thread_id_of(&env, a).await,
            thread_id_of(&env, b).await,
            thread_id_of(&env, c).await,
        );
        assert_eq!(ta0, ta1, "threadId письма не меняется");
        assert_eq!(tb0, tb1, "threadId письма не меняется");
        assert_eq!(tc1, ta0, "ссылка на две беседы — в более раннюю");
        let g = env
            .call(
                "Thread/get",
                json!({"accountId": env.account(), "ids": [ta1, tb1]}),
                "Thread/get",
            )
            .await;
        assert_eq!(
            g["list"][0]["emailIds"],
            json!([a.to_string(), c.to_string()])
        );
        assert_eq!(g["list"][1]["emailIds"], json!([b.to_string()]));
    }

    /// Приёмка JMAP-48: `alwaysMove` переносит следующее письмо беседы в заданную папку; правило видно
    /// в `ThreadRule/get`, перечисление (`ids` = `null`) находит его, замена целиком.
    #[tokio::test]
    async fn always_move_moves_next_letter() {
        let env = Env::new().await;
        let acc = env.account();
        let inbox = env.mailbox(SpecialUse::Inbox);
        let a = env
            .deliver(
                inbox,
                &mail("Deal", "peer@x.net", "Message-ID: <a@x>\r\n", "1"),
                Default::default(),
            )
            .await;
        let tid = thread_id_of(&env, a).await;
        let r = env
            .call(
                "Mailbox/set",
                json!({"accountId": acc, "create": {"d": {"name": "Deals"}}}),
                "Mailbox/set",
            )
            .await;
        let deals = r["created"]["d"]["id"].as_str().expect("deals").to_owned();

        let (name, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "create": {"r1": {
                "threadId": tid, "action": "alwaysMove", "mailboxId": deals}}}),
        )
        .await;
        assert_eq!(name, "ThreadRule/set", "{r}");
        assert_eq!(r["created"]["r1"]["id"], json!(tid), "{r}");
        assert_ne!(r["oldState"], r["newState"], "правило меняет состояние");

        let (name, g) = call(
            &env,
            "ThreadRule/get",
            json!({"accountId": acc, "ids": [tid]}),
        )
        .await;
        assert_eq!(name, "ThreadRule/get", "{g}");
        assert_eq!(
            g["list"][0],
            json!({"id": tid, "threadId": tid, "action": "alwaysMove", "mailboxId": deals}),
            "{g}"
        );
        // Перечисление — все правила.
        let (_, all) = call(&env, "ThreadRule/get", json!({"accountId": acc})).await;
        assert_eq!(all["list"].as_array().map(Vec::len), Some(1), "{all}");

        // Следующее письмо беседы — в папке правила.
        let next = env
            .deliver(
                inbox,
                &mail(
                    "Re: Deal",
                    "peer@x.net",
                    "Message-ID: <n@x>\r\nIn-Reply-To: <a@x>\r\n",
                    "2",
                ),
                Default::default(),
            )
            .await;
        let e = env
            .call(
                "Email/get",
                json!({"accountId": acc, "ids": [next.to_string()],
                    "properties": ["mailboxIds", "threadId"]}),
                "Email/get",
            )
            .await;
        assert_eq!(
            e["list"][0]["mailboxIds"],
            json!({deals.clone(): true}),
            "папка правила вместо выбранной"
        );
        assert_eq!(e["list"][0]["threadId"], json!(tid));

        // Замена целиком: update задаёт действие заново.
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "update": {&tid: {"action": "ignore"}}}),
        )
        .await;
        assert_eq!(r["updated"], json!({&tid: null}), "{r}");
        let (_, g) = call(
            &env,
            "ThreadRule/get",
            json!({"accountId": acc, "ids": [tid]}),
        )
        .await;
        assert_eq!(g["list"][0]["action"], "ignore", "{g}");
        // Удаление правила.
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "destroy": [&tid]}),
        )
        .await;
        assert_eq!(r["destroyed"], json!([tid]), "{r}");
        let (_, g) = call(
            &env,
            "ThreadRule/get",
            json!({"accountId": acc, "ids": [tid]}),
        )
        .await;
        assert_eq!(g["notFound"], json!([tid]), "{g}");
    }

    /// `applyToExisting` применяет правило к прежним письмам беседы: перенос, корзина, ключевое слово —
    /// одной операцией, теми же действиями, что `Email/set`.
    #[tokio::test]
    async fn apply_to_existing_touches_old_letters() {
        let env = Env::new().await;
        let acc = env.account();
        let inbox = env.mailbox(SpecialUse::Inbox);
        let letter = |mid: &str| {
            mail(
                "Re: Deal",
                "peer@x.net",
                &format!("Message-ID: <{mid}@x>\r\nIn-Reply-To: <a@x>\r\nReferences: <a@x>\r\n"),
                "текст",
            )
        };
        env.deliver(
            inbox,
            &mail("Deal", "peer@x.net", "Message-ID: <a@x>\r\n", "0"),
            Default::default(),
        )
        .await;
        let a = env.deliver(inbox, &letter("a"), Default::default()).await;
        let b = env.deliver(inbox, &letter("b"), Default::default()).await;
        let tid = thread_id_of(&env, a).await;

        // Ключевое слово — на все прежние письма беседы.
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "applyToExisting": true, "create": {"k": {
                "threadId": tid, "action": "alwaysKeyword", "keyword": "$deal"}}}),
        )
        .await;
        assert!(r["created"]["k"].is_object(), "{r}");
        let e = env
            .call(
                "Email/get",
                json!({"accountId": acc, "ids": [a.to_string(), b.to_string()],
                    "properties": ["keywords"]}),
                "Email/get",
            )
            .await;
        assert_eq!(e["list"][0]["keywords"], json!({"$deal": true}), "{e}");
        assert_eq!(e["list"][1]["keywords"], json!({"$deal": true}), "{e}");

        // Перенос — все письма беседы в заданную папку.
        let m = env
            .call(
                "Mailbox/set",
                json!({"accountId": acc, "create": {"d": {"name": "Deals"}}}),
                "Mailbox/set",
            )
            .await;
        let deals = m["created"]["d"]["id"].as_str().expect("deals").to_owned();
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "applyToExisting": true,
                "update": {&tid: {"action": "alwaysMove", "mailboxId": deals}}}),
        )
        .await;
        assert_eq!(r["updated"], json!({&tid: null}), "{r}");
        let e = env
            .call(
                "Email/get",
                json!({"accountId": acc, "ids": [a.to_string(), b.to_string()],
                    "properties": ["mailboxIds"]}),
                "Email/get",
            )
            .await;
        assert_eq!(
            e["list"][0]["mailboxIds"],
            json!({deals.clone(): true}),
            "{e}"
        );
        assert_eq!(
            e["list"][1]["mailboxIds"],
            json!({deals.clone(): true}),
            "{e}"
        );

        // «Игнорировать» — прежние письма в корзине (окончательное удаление — по сроку корзины).
        let trash = mailbox(&env, SpecialUse::Trash).await;
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "applyToExisting": true,
                "update": {&tid: {"action": "ignore"}}}),
        )
        .await;
        assert_eq!(r["updated"], json!({&tid: null}), "{r}");
        let e = env
            .call(
                "Email/get",
                json!({"accountId": acc, "ids": [a.to_string(), b.to_string()],
                    "properties": ["mailboxIds"]}),
                "Email/get",
            )
            .await;
        assert_eq!(
            e["list"][0]["mailboxIds"],
            json!({trash.clone(): true}),
            "{e}"
        );
        assert_eq!(e["list"][1]["mailboxIds"], json!({&trash: true}), "{e}");

        // Без applyToExisting прежние письма не трогаются: новое правило — только будущим письмам
        // (следующее письмо беседы получает новое ключевое слово, прежние — прежнее).
        let c = env.deliver(inbox, &letter("c"), Default::default()).await;
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "create": {"k2": {
                "threadId": tid, "action": "alwaysKeyword", "keyword": "later"}}}),
        )
        .await;
        assert!(r["created"]["k2"].is_object(), "{r}");
        let e = env
            .call(
                "Email/get",
                json!({"accountId": acc, "ids": [a.to_string(), c.to_string()],
                    "properties": ["keywords"]}),
                "Email/get",
            )
            .await;
        assert_eq!(e["list"][0]["keywords"], json!({"$deal": true}), "{e}");
        assert_eq!(e["list"][1]["keywords"], json!({"later": true}), "{e}");
    }

    /// Приёмка JMAP-48: без capability `urn:thepost:params:jmap:thread` методы неизвестны; с ней —
    /// известны, сессия объявляет capability.
    #[tokio::test]
    async fn methods_unknown_without_capability() {
        let env = Env::new().await;
        let acc = env.account();
        // Сессия объявляет capability (хранилище бесед подключено).
        let s = env.jmap.session(&env.principal, "https://x.example").await;
        assert!(
            s["capabilities"]
                .as_object()
                .is_some_and(|c| c.contains_key("urn:thepost:params:jmap:thread")),
            "{s}"
        );
        // Без capability в `using` — unknownMethod (для каждого метода).
        for method in ["ThreadRule/get", "ThreadRule/set", "ThreadRule/changes"] {
            let r = env
                .calls(json!([[method, {"accountId": acc, "sinceState": "0"}, "c0"]]))
                .await;
            assert_eq!(r[0][0], "error", "{method}: {}", r[0]);
            assert_eq!(r[0][1]["type"], "unknownMethod", "{method}: {}", r[0]);
        }
        // С capability — известны.
        let (name, _) = call(&env, "ThreadRule/get", json!({"accountId": acc, "ids": []})).await;
        assert_eq!(name, "ThreadRule/get");
    }

    /// Правила: ошибки объектов — неизвестная беседа, действие, папка, ключевое слово; `ifInState`;
    /// `ThreadRule/changes` — `cannotCalculateChanges` (журнала нет, клиент перечитывает `get`).
    #[tokio::test]
    async fn rule_errors_and_changes() {
        let env = Env::new().await;
        let acc = env.account();
        let inbox = env.mailbox(SpecialUse::Inbox);
        let a = env
            .deliver(
                inbox,
                &mail("Deal", "peer@x.net", "Message-ID: <a@x>\r\n", "1"),
                Default::default(),
            )
            .await;
        let tid = thread_id_of(&env, a).await;

        // Неизвестная беседа (UUID есть, беседы нет).
        let stray = format!("T{}", tp_contracts::ThreadId::new());
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "create": {"x": {
                "threadId": stray, "action": "ignore"}}}),
        )
        .await;
        assert_eq!(r["notCreated"]["x"]["type"], "notFound", "{r}");
        // Идентификатор не беседы (запасной расчёт по ключу цепочки).
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "create": {
                "x": {"threadId": "T0123456789ab", "action": "ignore"}}}),
        )
        .await;
        assert_eq!(r["notCreated"]["x"]["type"], "invalidProperties", "{r}");
        assert_eq!(
            r["notCreated"]["x"]["properties"],
            json!(["threadId"]),
            "{r}"
        );
        // Неизвестное действие и параметры.
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "create": {"x": {"threadId": tid, "action": "delete"}}}),
        )
        .await;
        assert_eq!(r["notCreated"]["x"]["type"], "invalidProperties", "{r}");
        assert_eq!(r["notCreated"]["x"]["properties"], json!(["action"]), "{r}");
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "create": {"x": {
                "threadId": tid, "action": "alwaysMove", "mailboxId": "nope"}}}),
        )
        .await;
        assert_eq!(
            r["notCreated"]["x"]["properties"],
            json!(["mailboxId"]),
            "{r}"
        );
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "create": {"x": {
                "threadId": tid, "action": "alwaysKeyword", "keyword": "два слова"}}}),
        )
        .await;
        assert_eq!(
            r["notCreated"]["x"]["properties"],
            json!(["keyword"]),
            "{r}"
        );

        // ifInState — состояние правил.
        let (_, g) = call(&env, "ThreadRule/get", json!({"accountId": acc})).await;
        let st = g["state"].clone();
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "ifInState": "bogus",
                "create": {"x": {"threadId": tid, "action": "ignore"}}}),
        )
        .await;
        assert_eq!(r["type"], "stateMismatch", "{r}");
        let (_, r) = call(
            &env,
            "ThreadRule/set",
            json!({"accountId": acc, "ifInState": st,
                "create": {"x": {"threadId": tid, "action": "ignore"}}}),
        )
        .await;
        assert!(r["created"]["x"].is_object(), "{r}");

        // Журнала изменений у правил нет — cannotCalculateChanges.
        let (name, r) = call(
            &env,
            "ThreadRule/changes",
            json!({"accountId": acc, "sinceState": "0"}),
        )
        .await;
        assert_eq!(name, "error", "{r}");
        assert_eq!(r["type"], "cannotCalculateChanges", "{r}");
    }

    /// Удержание беседы пользователю не видно и не снимается им: в объекте правил его нет, письма
    /// удержанной беседы удаляются в корзину как обычно, окончательное удаление запрещает хук
    /// (CTR-94) — письмо хранится скрыто.
    #[tokio::test]
    async fn held_thread_deletes_to_trash_and_is_not_exposed() {
        let env = Env::new().await;
        let acc = env.account();
        let inbox = env.mailbox(SpecialUse::Inbox);
        let a = env
            .deliver(
                inbox,
                &mail("Deal", "peer@x.net", "Message-ID: <a@x>\r\n", "1"),
                Default::default(),
            )
            .await;
        let tid = thread_id_of(&env, a).await;
        let thread = parse_thread_id(&tid).expect("привязка");
        env.threads
            .set_hold(
                env.scope,
                thread,
                Some(ThreadHold {
                    by: "compliance".into(),
                    at: OffsetDateTime::now_utc(),
                    reason: "case-42".into(),
                }),
            )
            .await
            .expect("hold");

        // В действиях по беседе удержания нет (правило не задано — notFound, полей удержания нет).
        let (_, g) = call(
            &env,
            "ThreadRule/get",
            json!({"accountId": acc, "ids": [tid]}),
        )
        .await;
        assert_eq!(g["notFound"], json!([tid]), "{g}");
        let (_, all) = call(&env, "ThreadRule/get", json!({"accountId": acc})).await;
        assert_eq!(all["list"], json!([]), "{all}");

        // Удаление — в корзину как обычно.
        let trash = mailbox(&env, SpecialUse::Trash).await;
        let r = env
            .call(
                "Email/set",
                json!({"accountId": acc, "destroy": [a.to_string()]}),
                "Email/set",
            )
            .await;
        assert_eq!(r["destroyed"], json!([a.to_string()]), "{r}");
        let e = env
            .call(
                "Email/get",
                json!({"accountId": acc, "ids": [a.to_string()], "properties": ["mailboxIds"]}),
                "Email/get",
            )
            .await;
        assert_eq!(e["list"][0]["mailboxIds"], json!({&trash: true}), "{e}");

        // Окончательное удаление запрещает хук удержанной беседы (CTR-94): режим стирания — выбор
        // пользователя, хук запрещает — письмо исчезает у пользователя, но хранится скрыто.
        env.policies.set_trash_purge_rule(
            env.scope.tenant,
            tp_contracts::meta::PolicyTarget::Tenant,
            Some(tp_contracts::retention::TrashPurgeRule {
                mode: tp_contracts::retention::TrashPurge::Erase,
                user_can_choose: true,
            }),
        );
        env.request(json!({
            "using": ["urn:ietf:params:jmap:core", "urn:thepost:params:jmap:settings"],
            "methodCalls": [["UserSettings/set", {"accountId": acc,
                "update": {"singleton": {"trashPurge": "erase"}}}, "s"]],
        }))
        .await;
        env.hook
            .set_final_delete(Decision::Deny("thread hold: case-42".into()));
        let r = env
            .call(
                "Email/set",
                json!({"accountId": acc, "destroy": [a.to_string()]}),
                "Email/set",
            )
            .await;
        assert_eq!(r["destroyed"], json!([a.to_string()]), "{r}");
        let hidden = env
            .trash
            .list_hidden(env.scope, 0, 100)
            .await
            .expect("hidden");
        assert_eq!(hidden.len(), 1, "хранилось скрыто, не стёрто");
        // Сам хук удержанной беседы запрещает по привязке (ThreadHoldHook, CTR-94).
        assert!(
            env.hook
                .calls()
                .iter()
                .any(|c| matches!(c, tp_testkit::HookCall::FinalDelete(_))),
            "точка принятия решений вызвана"
        );
    }
}
