//! Снимки папок для сеансов (PERF-03): общий снимок одной папки на соединения, свежесть по
//! журналу, бюджеты и выключение. Снимок правится сессией через `Arc::make_mut` — до первого
//! изменения копии у сессии нет, свежий SELECT после изменений в другой сессии — пересборка.

use std::sync::Arc;

use tp_contracts::mailstore::MailStore;
use tp_contracts::meta::{Flag, FlagOp, MessageQuery, MessageStore, SpecialUse};

use super::{Client, Env};
use crate::config::SnapshotsConfig;
use crate::snapshot::Snapshots;

const PLAIN: &[u8] = b"From: a@example.org\r\nTo: b@example.org\r\nSubject: hi\r\n\r\nHello\r\n";

async fn env_client() -> (Env, Client) {
    let env = Env::new().await;
    let c = env.logged_in().await;
    (env, c)
}

#[tokio::test]
async fn select_of_same_folder_is_one_snapshot() {
    let (env, mut c) = env_client().await;
    let inbox = env.mailbox(SpecialUse::Inbox);
    env.deliver(inbox, PLAIN, Default::default()).await;
    env.deliver(inbox, PLAIN, Default::default()).await;
    assert!(c.cmd("A1 SELECT INBOX").await.contains("* 2 EXISTS"));
    assert_eq!(env.snapshots.entry_count(), 1);
    // Другая сессия того же слушателя: тот же снимок папки, запись одна.
    let mut d = env.logged_in().await;
    assert!(d.cmd("B1 SELECT INBOX").await.contains("* 2 EXISTS"));
    assert_eq!(env.snapshots.entry_count(), 1);
    // Выборка другой папки — своя запись.
    assert!(d.cmd("B2 SELECT Trash").await.contains("B2 OK"));
    assert_eq!(env.snapshots.entry_count(), 2);
}

#[tokio::test]
async fn delivery_after_snapshot_is_visible_to_new_select() {
    let (env, mut c) = env_client().await;
    let inbox = env.mailbox(SpecialUse::Inbox);
    env.deliver(inbox, PLAIN, Default::default()).await;
    assert!(c.cmd("A1 SELECT INBOX").await.contains("* 1 EXISTS"));
    // Доставка после снимка: у выбранной сессии по журналу, новый SELECT — пересборка снимка.
    env.deliver(inbox, PLAIN, Default::default()).await;
    let mut d = env.logged_in().await;
    assert!(d.cmd("B1 SELECT INBOX").await.contains("* 2 EXISTS"));
    assert_eq!(env.snapshots.entry_count(), 1);
}

#[tokio::test]
async fn flag_change_after_snapshot_moves_first_unseen() {
    let (env, mut c) = env_client().await;
    let inbox = env.mailbox(SpecialUse::Inbox);
    env.deliver(inbox, PLAIN, Default::default()).await;
    env.deliver(inbox, PLAIN, Default::default()).await;
    // Оба письма непрочитаны: первое непрочитанное — номер 1.
    let r = c.cmd("A1 SELECT INBOX").await;
    assert!(r.contains("[UNSEEN 1]"), "{r}");
    let first = env
        .meta
        .list(env.scope(), inbox, MessageQuery::All, 10)
        .await
        .expect("list")
        .remove(0)
        .id;
    env.store
        .set_flags(
            env.scope(),
            &[first],
            FlagOp::Add([Flag::Seen].into()),
            None,
        )
        .await
        .expect("set_flags");
    // Новый SELECT: флаг в снимке после пересборки, первое непрочитанное — номер 2.
    let mut d = env.logged_in().await;
    let r = d.cmd("B1 SELECT INBOX").await;
    assert!(r.contains("[UNSEEN 2]"), "{r}");
}

#[tokio::test]
async fn expunge_by_one_session_rebuilds_snapshot_for_another() {
    let (env, mut c) = env_client().await;
    let inbox = env.mailbox(SpecialUse::Inbox);
    for _ in 0..2 {
        env.deliver(inbox, PLAIN, Default::default()).await;
    }
    assert!(c.cmd("A1 SELECT INBOX").await.contains("* 2 EXISTS"));
    assert!(
        c.cmd("A2 STORE 1 +FLAGS (\\Deleted)")
            .await
            .contains("A2 OK")
    );
    assert_eq!(
        c.cmd("A3 EXPUNGE").await,
        "* 1 EXPUNGE\r\nA3 OK EXPUNGE completed\r\n"
    );
    // Сессия правит свой снимок (CoW), кэш не портится до пересборки; новый SELECT — по журналу.
    let mut d = env.logged_in().await;
    assert!(d.cmd("B1 SELECT INBOX").await.contains("* 1 EXISTS"));
    // Сессия A продолжает видеть своё состояние: 1 письмо, номер 1 — прежнее письмо 2.
    assert_eq!(
        c.cmd("A4 FETCH 1:* UID").await,
        "* 1 FETCH (UID 2)\r\nA4 OK FETCH completed\r\n"
    );
}

#[tokio::test]
async fn mailbox_over_limit_is_refused() {
    let mut env = Env::new().await;
    env.config.limits.max_mailbox_messages = 2;
    let inbox = env.mailbox(SpecialUse::Inbox);
    for _ in 0..3 {
        env.deliver(inbox, PLAIN, Default::default()).await;
    }
    let mut c = env.logged_in().await;
    let r = c.cmd("A1 SELECT INBOX").await;
    assert!(r.contains("A1 NO [LIMIT]"), "{r}");
}

#[tokio::test]
async fn eviction_by_max_entries() {
    let env = Env::new().await;
    let snapshots = Arc::new(Snapshots::new(SnapshotsConfig {
        max_entries: 1,
        ..SnapshotsConfig::default()
    }));
    let mut c = env.client_snapshots(snapshots.clone(), true).await;
    assert!(
        c.cmd("L1 LOGIN user@example.org secret")
            .await
            .contains("L1 OK")
    );
    assert!(c.cmd("A1 SELECT INBOX").await.contains("A1 OK"));
    assert_eq!(snapshots.entry_count(), 1);
    assert!(c.cmd("A2 SELECT Trash").await.contains("A2 OK"));
    assert_eq!(snapshots.entry_count(), 1);
    // «Входящие» вытеснены — следующий SELECT пересобирает.
    assert!(c.cmd("A3 SELECT INBOX").await.contains("A3 OK"));
    assert_eq!(snapshots.entry_count(), 1);
}

#[tokio::test]
async fn disabled_cache_keeps_select_correct() {
    let env = Env::new().await;
    let snapshots = Arc::new(Snapshots::new(SnapshotsConfig {
        max_bytes: 0,
        ..SnapshotsConfig::default()
    }));
    let inbox = env.mailbox(SpecialUse::Inbox);
    env.deliver(inbox, PLAIN, Default::default()).await;
    let mut c = env.client_snapshots(snapshots.clone(), true).await;
    assert!(
        c.cmd("L1 LOGIN user@example.org secret")
            .await
            .contains("L1 OK")
    );
    assert!(c.cmd("A1 SELECT INBOX").await.contains("* 1 EXISTS"));
    env.deliver(inbox, PLAIN, Default::default()).await;
    assert!(c.cmd("A2 UNSELECT").await.contains("A2 OK"));
    assert!(c.cmd("A3 SELECT INBOX").await.contains("* 2 EXISTS"));
    assert_eq!(snapshots.entry_count(), 0);
}
