//! Набор проверок [`ThreadStore`] и [`ThreadHoldHook`] (CTR-94, CONTRACTS.md#Thread; решение 125 е–ж):
//! in-memory `MemThreads` и `PgMeta` (META-86) проходят одни и те же проверки.

use std::sync::Arc;

use time::OffsetDateTime;
use tp_contracts::ext::{Decision, DecisionHooks, FinalDelete};
use tp_contracts::meta::AccountScope;
use tp_contracts::thread::{ThreadFacts, ThreadHold, ThreadHoldHook, ThreadRule, ThreadStore};
use tp_contracts::{Error, MailboxId, MessageId, ThreadId};

/// Ключи присоединения набора: `own` — Message-ID письма отправителя, `reply` — ссылка ответа,
/// `second` — ссылка на вторую беседу (письмо, ссылающееся на две).
const OWN: &str = "<own-id@example.org>";
const REPLY: &str = "<reply-id@example.net>";
const SECOND: &str = "<second-id@example.net>";

/// Удержание набора.
fn hold() -> ThreadHold {
    ThreadHold {
        by: "compliance".into(),
        at: OffsetDateTime::UNIX_EPOCH,
        reason: "case-42".into(),
    }
}

/// Хук базовой поставки над хранилищем набора.
fn hold_hook(store: Arc<dyn ThreadStore>) -> DecisionHooks {
    DecisionHooks::new(vec![Arc::new(ThreadHoldHook::new(store))])
}

/// Удаление письма набора.
fn final_delete(scope: AccountScope, message: MessageId, thread: Option<ThreadId>) -> FinalDelete {
    FinalDelete {
        scope,
        mailbox: MailboxId::new(),
        message,
        received_at: OffsetDateTime::UNIX_EPOCH,
        thread,
    }
}

/// Набор проверок [`ThreadStore`] (решение 125 е–ж). Хранилище в начале пустое; `scope` и `other` — разные
/// учётные записи одной организации.
///
/// Ответ присоединяется к беседе исходного письма по `In-Reply-To`/`References`; письмо без ссылок — новая
/// беседа; письмо, ссылающееся на две беседы, — в более раннюю; `ThreadId` письма не меняется; ключи и
/// беседы не пересекают учётные записи; память беседы ([`ThreadFacts`]) — без повторов, свежие в конце;
/// действие по беседе ([`ThreadRule`]) задаётся и снимается целиком; пределы памяти — из конфигурации
/// реализации. Удержание и хук — [`hold_rules`].
pub async fn thread(store: Arc<dyn ThreadStore>, scope: AccountScope, other: AccountScope) {
    // Ответ присоединяется к беседе исходного письма; привязка письма неизменяема.
    let m1 = MessageId::new();
    let t1 = store.bind(scope, m1, &[OWN]).await.expect("bind m1");
    assert_eq!(store.bind(scope, m1, &[OWN]).await, Ok(t1), "не меняется");
    let m2 = MessageId::new();
    assert_eq!(
        store.bind(scope, m2, &[REPLY, OWN]).await,
        Ok(t1),
        "ответ — в беседу исходного письма"
    );
    // Письмо без ссылок — новая беседа.
    let m3 = MessageId::new();
    let t3 = store.bind(scope, m3, &[]).await.expect("bind m3");
    assert_ne!(t3, t1, "без ссылок — новая беседа");
    // Ссылка на две беседы — в более раннюю (t1 создана раньше), беседы не сливаются.
    let m4 = MessageId::new();
    assert_eq!(
        store.bind(scope, m4, &[OWN, SECOND, REPLY]).await,
        Ok(t1),
        "ссылка на две беседы — в раннюю"
    );
    assert_eq!(
        store.messages(scope, t3, 10).await,
        Ok(vec![m3]),
        "беседы не сливаются"
    );

    // Письма беседы — в порядке привязки; предел выборки и нулевой предел.
    assert_eq!(store.messages(scope, t1, 10).await, Ok(vec![m1, m2, m4]));
    assert_eq!(store.messages(scope, t1, 2).await, Ok(vec![m1, m2]));
    assert!(matches!(
        store.messages(scope, t1, 0).await,
        Err(Error::Invalid(_))
    ));
    // Беседа письма; чужая учётная запись привязок не видит.
    assert_eq!(store.thread_of(scope, m2).await, Ok(Some(t1)));
    assert_eq!(store.thread_of(scope, MessageId::new()).await, Ok(None));
    assert_eq!(store.thread_of(other, m2).await, Ok(None));

    // Ключи не пересекают учётные записи: тот же ключ у другой учётной записи — новая беседа.
    let m5 = MessageId::new();
    let t5 = store.bind(other, m5, &[OWN]).await.expect("bind other");
    assert_ne!(t5, t1, "беседы не пересекают учётные записи");
    assert_eq!(store.messages(other, t1, 5).await, Ok(Vec::new()));

    // Память беседы для аномалий (решение 125 д): без повторов, сверх пределов реализации вытесняются
    // самые старые; нет беседы — NotFound; чужая учётная запись — пусто.
    let facts = ThreadFacts {
        attachments: vec!["application/pdf".into()],
        link_domains: vec!["a.example".into()],
        reply_to: vec!["x@example.net".into()],
    };
    store
        .remember_facts(scope, t1, &facts)
        .await
        .expect("remember");
    assert_eq!(store.facts(scope, t1).await, Ok(facts.clone()));
    store
        .remember_facts(
            scope,
            t1,
            &ThreadFacts {
                attachments: vec![
                    "application/zip".into(),
                    "application/pdf".into(),
                    "image/png".into(),
                ],
                link_domains: vec!["a.example".into(), "b.example".into()],
                reply_to: vec!["y@example.net".into()],
            },
        )
        .await
        .expect("remember again");
    let merged = store.facts(scope, t1).await.expect("facts");
    assert_eq!(
        merged.attachments,
        vec!["application/pdf", "application/zip", "image/png"],
        "повторы не добавляются"
    );
    assert_eq!(
        merged.link_domains,
        vec!["a.example", "b.example"],
        "свежие в конце"
    );
    assert_eq!(
        merged.reply_to,
        vec!["x@example.net", "y@example.net"],
        "свежие в конце"
    );
    let limits = store.limits();
    assert!(
        limits.max_attachments >= merged.attachments.len(),
        "{limits:?}"
    );
    assert!(
        limits.max_link_domains >= merged.link_domains.len(),
        "{limits:?}"
    );
    assert!(limits.max_reply_to >= merged.reply_to.len(), "{limits:?}");
    assert!(
        matches!(
            store.remember_facts(scope, ThreadId::new(), &facts).await,
            Err(Error::NotFound)
        ),
        "нет беседы"
    );
    assert_eq!(store.facts(other, t1).await, Ok(ThreadFacts::new()));

    // Действие по беседе (EWS ApplyConversationAction): задаётся и снимается целиком.
    let mailbox = MailboxId::new();
    let rule = ThreadRule::AlwaysMove(mailbox);
    assert_eq!(store.rule(scope, t1).await, Ok(None));
    store.set_rule(scope, t1, Some(rule)).await.expect("rule");
    assert_eq!(
        store.rule(scope, t1).await,
        Ok(Some(ThreadRule::AlwaysMove(mailbox)))
    );
    assert_eq!(store.rule(other, t1).await, Ok(None));
    assert!(matches!(
        store
            .set_rule(
                scope,
                t1,
                Some(ThreadRule::AlwaysKeyword("два слова".into()))
            )
            .await,
        Err(Error::Invalid(_))
    ));
    assert!(
        matches!(
            store
                .set_rule(scope, ThreadId::new(), Some(ThreadRule::Ignore))
                .await,
            Err(Error::NotFound)
        ),
        "нет беседы"
    );
    store.set_rule(scope, t1, None).await.expect("rule remove");
    assert_eq!(store.rule(scope, t1).await, Ok(None));
}

/// Проверки удержания беседы ([`ThreadHold`]) и хука [`ThreadHoldHook`] (решение 125 е): отдельная функция —
/// удержание снимается в конце, набор оставляет хранилище без удержаний.
pub async fn hold_rules(store: Arc<dyn ThreadStore>, scope: AccountScope) {
    let hooks = hold_hook(store.clone());
    let m1 = MessageId::new();
    let t1 = store.bind(scope, m1, &[OWN]).await.expect("bind");
    assert_eq!(store.hold(scope, t1).await, Ok(None));
    assert_eq!(
        hooks
            .before_final_delete(&final_delete(scope, m1, None))
            .await,
        Ok(Decision::Allow)
    );

    // Удержание: некорректное — Invalid, беседы нет — NotFound; повторная установка заменяет.
    let mut bad = hold();
    bad.by = String::new();
    assert!(matches!(
        store.set_hold(scope, t1, Some(bad)).await,
        Err(Error::Invalid(_))
    ));
    assert!(
        matches!(
            store.set_hold(scope, ThreadId::new(), Some(hold())).await,
            Err(Error::NotFound)
        ),
        "нет беседы"
    );
    store.set_hold(scope, t1, Some(hold())).await.expect("hold");
    assert_eq!(store.hold(scope, t1).await, Ok(Some(hold())));
    let longer = ThreadHold {
        reason: "case-43".into(),
        ..hold()
    };
    store
        .set_hold(scope, t1, Some(longer.clone()))
        .await
        .expect("hold again");
    assert_eq!(store.hold(scope, t1).await, Ok(Some(longer)));

    // Окончательное удаление письма удержанной беседы — Deny: и с беседой в записи, и когда хук
    // разрешает беседу по письму (`thread` в записи нет). Письмо, привязанное после установки
    // удержания, удержано так же (удержание на беседу целиком, включая будущие письма).
    let m2 = MessageId::new();
    assert_eq!(
        store.bind(scope, m2, &[OWN]).await,
        Ok(t1),
        "письмо после удержания — в той же беседе"
    );
    assert_eq!(
        hooks
            .before_final_delete(&final_delete(scope, m2, None))
            .await,
        Ok(Decision::Deny("thread hold: case-43".into())),
        "будущее письмо удержано"
    );
    assert_eq!(
        hooks
            .before_final_delete(&final_delete(scope, m1, Some(t1)))
            .await,
        Ok(Decision::Deny("thread hold: case-43".into()))
    );
    assert_eq!(
        hooks
            .before_final_delete(&final_delete(
                scope,
                MessageId::new(),
                Some(ThreadId::new())
            ))
            .await,
        Ok(Decision::Allow),
        "беседа без удержания"
    );

    // Снятие удержания — удаление разрешается.
    store.set_hold(scope, t1, None).await.expect("hold remove");
    assert_eq!(store.hold(scope, t1).await, Ok(None));
    assert_eq!(
        hooks
            .before_final_delete(&final_delete(scope, m1, None))
            .await,
        Ok(Decision::Allow)
    );
}
