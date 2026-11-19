//! META-86: беседы на PostgreSQL — общие наборы `tp_testkit::suite::thread` и `hold_rules`, транзакция
//! приёма (сбой откатывает письмо и привязку), применённые политики в транзакции, фоновая привязка
//! существующих писем по `thread_key`.

mod common;

use std::sync::Arc;

use time::OffsetDateTime;
use tp_contracts::meta::{AccountKind, AccountScope, AccountStore, AccountUpsert};
use tp_contracts::thread::{ThreadFacts, ThreadHold, ThreadRule, ThreadStore};
use tp_contracts::{MailboxId, MessageId, TenantId};
use tp_meta::{PgMeta, schema};
use tp_testkit::suite;

/// Ключи присоединения набора (как в `suite::thread`).
const OWN: &str = "<own-pg@example.org>";
const REPLY: &str = "<reply-pg@example.net>";

/// Учётная запись в заданной организации (наборы проверяют изоляцию записей учётных записей одной
/// организации).
async fn account_in(meta: &PgMeta, tenant: TenantId, login: &str) -> AccountScope {
    let (domain, name) = common::domain(meta.pool(), tenant).await;
    let acc = meta
        .upsert(
            tenant,
            AccountUpsert {
                domain,
                login: format!("{login}@{name}"),
                display_name: login.into(),
                external_id: None,
                enabled: true,
                aliases: Vec::new(),
                kind: AccountKind::User,
                hidden_from_gal: false,
                resource_type: None,
            },
        )
        .await
        .expect("upsert");
    AccountScope {
        tenant,
        account: acc.id,
    }
}

#[tokio::test]
async fn passes_contract_suite() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let tenant = common::tenant(meta.pool()).await;
    let scope = account_in(&meta, tenant, "pg-threads-a").await;
    let other = account_in(&meta, tenant, "pg-threads-b").await;
    let store: Arc<dyn ThreadStore> = Arc::new(meta.clone());
    suite::thread(store.clone(), scope, other).await;
    suite::hold_rules(store, scope).await;
}

/// Сбой в середине приёма (MS-21) откатывает транзакцию: привязка без письма и письмо без беседы не
/// остаются, ключи откатившейся привязки не зарегистрированы.
#[tokio::test]
async fn ingest_failure_rolls_back_message_and_thread() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let scope = common::account(&meta).await;
    let mut tx = schema::begin(meta.pool(), scope.tenant)
        .await
        .expect("begin");
    let m1 = MessageId::new();
    let thread = meta
        .bind_tx(&mut tx, scope, m1, &[OWN])
        .await
        .expect("bind_tx");
    meta.remember_facts_tx(
        &mut tx,
        scope,
        thread,
        &ThreadFacts {
            attachments: vec!["application/pdf".into()],
            ..ThreadFacts::default()
        },
    )
    .await
    .expect("facts_tx");
    // Применённые политики беседы видны в той же транзакции, отдельное соединение не нужно.
    assert_eq!(meta.hold_tx(&mut tx, scope, thread).await, Ok(None));
    assert_eq!(meta.rule_tx(&mut tx, scope, thread).await, Ok(None));

    // Сбой в середине приёма — откат.
    assert!(
        sqlx::query("SELECT 1/0").execute(&mut *tx).await.is_err(),
        "сбой в середине приёма"
    );
    tx.rollback().await.expect("откат");

    let store: Arc<dyn ThreadStore> = Arc::new(meta.clone());
    // Привязки нет, память беседы пуста, ключи не зарегистрированы: то же ключ — новая беседа.
    assert_eq!(store.thread_of(scope, m1).await, Ok(None));
    assert_eq!(store.facts(scope, thread).await, Ok(ThreadFacts::new()));
    let m2 = MessageId::new();
    let fresh = store.bind(scope, m2, &[OWN]).await.expect("bind");
    assert_ne!(
        fresh, thread,
        "ключи откатившейся привязки не зарегистрированы"
    );
    assert_eq!(store.messages(scope, fresh, 10).await, Ok(vec![m2]));
}

/// Привязка и память беседы в транзакции приёма фиксируются вместе; применённые политики (удержание,
/// действие) видны в транзакции нового письма — будущие письма удержаны так же.
#[tokio::test]
async fn ingest_tx_sees_thread_policies() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let scope = common::account(&meta).await;
    let store: Arc<dyn ThreadStore> = Arc::new(meta.clone());
    let m1 = MessageId::new();
    let t1 = store.bind(scope, m1, &[OWN]).await.expect("bind");
    let hold = ThreadHold {
        by: "compliance".into(),
        at: OffsetDateTime::UNIX_EPOCH,
        reason: "case-pg-86".into(),
    };
    store
        .set_hold(scope, t1, Some(hold))
        .await
        .expect("set_hold");
    store
        .set_rule(scope, t1, Some(ThreadRule::Ignore))
        .await
        .expect("set_rule");

    // Транзакция приёма ответа: привязка — в беседу исходного письма, политики — той же транзакцией.
    let mut tx = schema::begin(meta.pool(), scope.tenant)
        .await
        .expect("begin");
    let m2 = MessageId::new();
    assert_eq!(
        meta.bind_tx(&mut tx, scope, m2, &[REPLY, OWN]).await,
        Ok(t1),
        "ответ — в беседу исходного письма"
    );
    let found = meta
        .hold_tx(&mut tx, scope, t1)
        .await
        .expect("hold_tx")
        .expect("удержание беседы");
    assert_eq!(found.reason, "case-pg-86");
    assert_eq!(
        meta.rule_tx(&mut tx, scope, t1).await,
        Ok(Some(ThreadRule::Ignore))
    );
    meta.remember_facts_tx(
        &mut tx,
        scope,
        t1,
        &ThreadFacts {
            link_domains: vec!["a.example".into()],
            ..ThreadFacts::default()
        },
    )
    .await
    .expect("facts_tx");
    tx.commit().await.expect("commit");

    // После фиксации — привязка и слияние памяти на месте, удержание действует (будущее письмо тоже).
    assert_eq!(store.thread_of(scope, m2).await, Ok(Some(t1)));
    assert_eq!(
        store.messages(scope, t1, 10).await,
        Ok(vec![m1, m2]),
        "порядок привязки"
    );
    let facts = store.facts(scope, t1).await.expect("facts");
    assert_eq!(facts.link_domains, vec!["a.example"]);
    assert_eq!(
        store.hold(scope, t1).await,
        Ok(Some(ThreadHold {
            by: "compliance".into(),
            at: OffsetDateTime::UNIX_EPOCH,
            reason: "case-pg-86".into(),
        }))
    );
}

/// Письмо учётной записи в таблице `messages` с заданным `thread_key` и моментом приёма
/// (`uid`/`modseq` — из времени приёма: уникальны и возрастают в порядке вставки).
async fn insert_message(
    meta: &PgMeta,
    scope: AccountScope,
    mailbox: MailboxId,
    message: MessageId,
    key: &str,
    received: OffsetDateTime,
) {
    let mut tx = schema::begin(meta.pool(), scope.tenant)
        .await
        .expect("begin");
    sqlx::query(
        "INSERT INTO messages (tenant_id, account_id, message_id, mailbox_id, uid, modseq, size,
                               received_at, skeleton_hash, skeleton_gen, thread_key, meta)
         VALUES ($1, $2, $3, $4, $5, $6, 1, $7, '\\x00'::bytea, 0, $8, '{}')",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(message.as_uuid())
    .bind(mailbox.as_uuid())
    .bind(received.unix_timestamp())
    .bind(received.unix_timestamp())
    .bind(received)
    .bind(key)
    .execute(&mut *tx)
    .await
    .expect("insert message");
    tx.commit().await.expect("commit");
}

/// Фоновая привязка существующих писем по `thread_key`: письма одной цепочки — в одну беседу, в порядке
/// приёма; уже привязанное письмо не переносится; когда привязывать нечего — `0`.
#[tokio::test]
async fn background_binding_by_thread_key() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let scope = common::account(&meta).await;
    let mailbox = MailboxId::new();
    // Письма учётной записи: chain-1 — три письма (в порядке приёма), chain-2 — одно; письмо chain-1
    // с собственным Message-ID привязано вручную (привязка неизменяема).
    let mut received = OffsetDateTime::now_utc() - time::Duration::minutes(10);
    let m1 = MessageId::new();
    let m2 = MessageId::new();
    let m3 = MessageId::new();
    let m4 = MessageId::new();
    let m5 = MessageId::new();
    insert_message(&meta, scope, mailbox, m1, "chain-1", received).await;
    received += time::Duration::minutes(1);
    insert_message(&meta, scope, mailbox, m2, "chain-1", received).await;
    received += time::Duration::minutes(1);
    insert_message(&meta, scope, mailbox, m3, "chain-1", received).await;
    received += time::Duration::minutes(1);
    insert_message(&meta, scope, mailbox, m4, "chain-2", received).await;
    let store: Arc<dyn ThreadStore> = Arc::new(meta.clone());
    let t5 = store
        .bind(scope, m5, &["<m5@example.org>"])
        .await
        .expect("bind m5");
    received += time::Duration::minutes(1);
    insert_message(&meta, scope, mailbox, m5, "chain-1", received).await;

    let bound = meta
        .bind_unthreaded_messages(scope, 100)
        .await
        .expect("фоновая привязка");
    assert_eq!(bound, 4, "привязаны четыре непривязанных письма");
    let t1 = store
        .thread_of(scope, m1)
        .await
        .expect("thread_of m1")
        .expect("m1");
    assert_eq!(
        store.thread_of(scope, m2).await,
        Ok(Some(t1)),
        "одна цепочка — одна беседа"
    );
    assert_eq!(store.thread_of(scope, m3).await, Ok(Some(t1)));
    let t4 = store
        .thread_of(scope, m4)
        .await
        .expect("thread_of m4")
        .expect("m4");
    assert_ne!(t4, t1, "другая цепочка — другая беседа");
    assert_eq!(
        store.messages(scope, t1, 10).await,
        Ok(vec![m1, m2, m3]),
        "порядок привязки — порядок приёма"
    );
    assert_eq!(
        store.thread_of(scope, m5).await,
        Ok(Some(t5)),
        "привязка письма неизменяема"
    );
    // Ключ цепочки зарегистрирован: ответ по нему попадает в ту же беседу.
    let m6 = MessageId::new();
    assert_eq!(store.bind(scope, m6, &["chain-1"]).await, Ok(t1));

    // Повторный вызов — привязывать нечего.
    assert_eq!(meta.bind_unthreaded_messages(scope, 100).await, Ok(0));
    assert!(matches!(
        meta.bind_unthreaded_messages(scope, 0).await,
        Err(tp_contracts::Error::Invalid(_))
    ));
}
