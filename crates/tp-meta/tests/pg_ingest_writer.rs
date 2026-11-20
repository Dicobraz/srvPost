//! PERF-09: писатели приёма — конкурентные вставки писем одной учётной записи.
//!
//! 25 параллельных вставок в одну учётную запись: все вернулись; UID папки уникальны и идут подряд;
//! `ModSeq` — подряд без дыр, журнал изменений покрывает каждое письмо записью `created` с теми же
//! UID и `ModSeq`. Повтор — на учётной записи второго шарда: записи идут через писателя учётной
//! записи на её шарде ([`tp_meta::writers`]).

mod common;

use std::collections::BTreeMap;

use time::OffsetDateTime;
use tp_contracts::meta::{
    AccountScope, ChangeLog, Inserted, MailboxStore, MessageStore, NewMessage, SpecialUse,
};
use tp_contracts::{BlobHash, BlobKey, Gen, MailboxId, ModSeq, Uid};
use tp_meta::PgMeta;

fn message(scope: AccountScope) -> NewMessage {
    let mut h = [0u8; 32];
    h[..16].copy_from_slice(uuid::Uuid::now_v7().as_bytes());
    NewMessage {
        skeleton: BlobKey {
            tenant: scope.tenant,
            hash: BlobHash(h),
            generation: Gen::INITIAL,
        },
        parts: Vec::new(),
        size: 100,
        received_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("ts"),
        flags: Default::default(),
        meta: Default::default(),
    }
}

async fn inbox(meta: &PgMeta, scope: AccountScope) -> MailboxId {
    MailboxStore::list(meta, scope)
        .await
        .expect("list")
        .into_iter()
        .find(|m| m.role == Some(SpecialUse::Inbox))
        .expect("inbox")
        .id
}

/// `tasks` параллельных задач по `per_task` вставок в папку `ib` учётной записи `scope`.
async fn insert_parallel(
    meta: &PgMeta,
    scope: AccountScope,
    ib: MailboxId,
    tasks: usize,
    per_task: usize,
) -> Vec<Inserted> {
    let mut handles = Vec::new();
    for _ in 0..tasks {
        let meta = meta.clone();
        handles.push(tokio::spawn(async move {
            let mut out = Vec::with_capacity(per_task);
            for _ in 0..per_task {
                out.push(
                    MessageStore::insert(&meta, scope, ib, message(scope))
                        .await
                        .expect("insert"),
                );
            }
            out
        }));
    }
    let mut all = Vec::new();
    for h in handles {
        all.extend(h.await.expect("join"));
    }
    all
}

/// Все вставки вернулись; UID папки уникальны и последовательны, больший UID — больший `ModSeq`;
/// `ModSeq` — подряд без дыр, журнал изменений покрывает каждое письмо записью `created` с теми же
/// UID и `ModSeq`.
async fn check_one_writer(
    meta: &PgMeta,
    scope: AccountScope,
    ib: MailboxId,
    inserted: &[Inserted],
) {
    let total = inserted.len();
    assert!(total > 0);
    // UID уникальны и последовательны; больший UID — больший ModSeq (порядок выдачи совпадает).
    let mut by_uid: Vec<&Inserted> = inserted.iter().collect();
    by_uid.sort_by_key(|i| i.uid);
    let expected: Vec<Uid> = (1..=total as u32).map(Uid).collect();
    assert_eq!(
        by_uid.iter().map(|i| i.uid).collect::<Vec<_>>(),
        expected,
        "UID подряд без дыр"
    );
    assert!(by_uid.windows(2).all(|w| w[1].modseq > w[0].modseq));
    // ModSeq подряд без дыр.
    let mut modseqs: Vec<u64> = inserted.iter().map(|i| i.modseq.0).collect();
    modseqs.sort_unstable();
    assert!(
        modseqs.windows(2).all(|w| w[1] == w[0] + 1),
        "ModSeq подряд без дыр"
    );
    // Журнал изменений покрывает каждое письмо: запись `created` с теми же UID и ModSeq.
    let ch = meta
        .message_changes(scope, Some(ib), ModSeq::ZERO, 100_000)
        .await
        .expect("changes");
    assert!(!ch.has_more);
    let created: BTreeMap<_, _> = ch
        .created
        .iter()
        .map(|c| (c.id, (c.uid, c.modseq)))
        .collect();
    assert_eq!(created.len(), total, "журнал покрывает каждое письмо");
    for i in inserted {
        assert_eq!(
            created.get(&i.id),
            Some(&(i.uid, i.modseq)),
            "письмо {} в журнале",
            i.id
        );
    }
    let st = meta.status(scope, ib).await.expect("status");
    assert_eq!(st.uid_next, Uid(total as u32 + 1));
    assert_eq!(st.highest_modseq, ModSeq(*modseqs.last().expect("modseq")));
}

#[tokio::test]
async fn parallel_inserts_one_writer() {
    const TASKS: usize = 25;
    const PER_TASK: usize = 4;
    let Some(meta) = common::meta().await else {
        return;
    };
    let scope = common::account(&meta).await;
    let ib = inbox(&meta, scope).await;
    let inserted = insert_parallel(&meta, scope, ib, TASKS, PER_TASK).await;
    assert_eq!(inserted.len(), TASKS * PER_TASK, "все вставки вернулись");
    check_one_writer(&meta, scope, ib, &inserted).await;
}

#[tokio::test]
async fn parallel_inserts_on_shard() {
    const TASKS: usize = 25;
    let Some(t) = common::two_shards().await else {
        return;
    };
    let org = t.tenant().await;
    let b = t.account_on(org, t.shard).await;
    let ib = inbox(&t.meta, b).await;
    let inserted = insert_parallel(&t.meta, b, ib, TASKS, 1).await;
    assert_eq!(inserted.len(), TASKS, "все вставки вернулись");
    check_one_writer(&t.meta, b, ib, &inserted).await;
    t.drop_db().await;
}
