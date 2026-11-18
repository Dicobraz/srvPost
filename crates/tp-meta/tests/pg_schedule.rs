//! META-51: планирование встреч на PostgreSQL — наборы `tp_testkit::suite::freebusy` и `suite::itip`, сигналы
//! входящих, RLS новых таблиц, занятость учётных записей разных шардов.
//! META-54: набор `suite::freebusy_recurring` — разворот повторов при запросе.
//! META-69: набор `suite::itip::inbox_log` (журнал входящих) и очистка надгробий входящих.

mod common;

use std::sync::Arc;

use sqlx::AssertSqlSafe;
use time::{Duration, OffsetDateTime};
use tp_contracts::dav::{
    Collection, CollectionKind, Component, DavStore, ObjectIndex, Precondition, PutOutcome, Span,
};
use tp_contracts::meta::{AccountKind, AccountScope, AccountStore, AccountUpsert};
use tp_contracts::schedule::{BusyKind, BusyPeriod, InboxMessage, ItipMethod, Period};
use tp_contracts::{AccountId, DomainId, Error, ModSeq, TenantId};
use tp_meta::dav::DavConfig;
use tp_meta::{MetaConfig, PgMeta, schema};
use tp_testkit::MemEventBus;
use tp_testkit::suite;
use tp_testkit::suite::dav::{DavFixture, LIMITS};

fn config() -> MetaConfig {
    MetaConfig {
        dav: DavConfig::with_limits(LIMITS),
        ..MetaConfig::default()
    }
}

/// Учётная запись организации `tenant` с доменом `domain`.
async fn account_in(meta: &PgMeta, tenant: TenantId, domain: (DomainId, &str)) -> AccountScope {
    let acc = meta
        .upsert(
            tenant,
            AccountUpsert {
                domain: domain.0,
                login: format!("u{}@{}", uuid::Uuid::now_v7().simple(), domain.1),
                display_name: "User".into(),
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

/// Хранилище с лимитами набора и учётные записи набора без данных.
async fn fixture() -> Option<(PgMeta, DavFixture)> {
    let pool = common::pool().await?;
    let meta = PgMeta::new(pool.clone(), config());
    let tenant = common::tenant(&pool).await;
    let (domain, name) = common::domain(&pool, tenant).await;
    let owner = account_in(&meta, tenant, (domain, &name)).await;
    let peer = account_in(&meta, tenant, (domain, &name)).await;
    let fx = DavFixture {
        owner,
        peer,
        foreign: AccountScope {
            tenant: common::tenant(&pool).await,
            account: owner.account,
        },
    };
    Some((meta, fx))
}

fn at(h: i64) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::days(20_000) + Duration::hours(h)
}

fn busy(s: i64, e: i64) -> BusyPeriod {
    BusyPeriod {
        start: at(s),
        end: at(e),
        kind: BusyKind::Busy,
    }
}

fn message(uid: &str) -> InboxMessage {
    InboxMessage {
        method: ItipMethod::Request,
        uid: uid.into(),
        from: "boss@partner.example".into(),
        body: "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".into(),
    }
}

/// Событие `name` календаря `cal` с периодами занятости `periods`.
async fn put_event(
    meta: &PgMeta,
    scope: AccountScope,
    cal: &Collection,
    name: &str,
    periods: Vec<BusyPeriod>,
) {
    let index = ObjectIndex {
        busy: periods,
        schedule_tag: Some("st".into()),
        ..ObjectIndex::new(
            Component::Event,
            name,
            Some(Span {
                start: at(0),
                end: None,
            }),
        )
    };
    let out = meta
        .put_object(
            scope,
            cal.id,
            name,
            "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n".into(),
            index,
            Precondition::Any,
        )
        .await
        .expect("put");
    assert!(matches!(out, PutOutcome::Stored(_)));
}

#[tokio::test]
async fn passes_freebusy_suite() {
    let Some((meta, fx)) = fixture().await else {
        return;
    };
    suite::freebusy(&meta, &meta, &fx).await;
}

/// META-54: еженедельная встреча без конца видна через 3 года, исключённая дата не занята.
#[tokio::test]
async fn passes_freebusy_recurring_suite() {
    let Some((meta, fx)) = fixture().await else {
        return;
    };
    suite::freebusy_recurring(&meta, &meta, &fx).await;
}

#[tokio::test]
async fn passes_itip_suite() {
    let Some((meta, fx)) = fixture().await else {
        return;
    };
    suite::itip(&meta, &fx).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbox_signals_after_commit() {
    let Some(pool) = common::pool().await else {
        return;
    };
    let bus = Arc::new(MemEventBus::default());
    let meta = PgMeta::new(pool, MetaConfig::default()).with_bus(bus.clone());
    let scope = common::account(&meta).await;
    suite::itip::signals(&meta, bus.as_ref(), scope).await;
}

/// CTR-65, META-69: журнал входящих — набор `suite::itip::inbox_log`.
#[tokio::test]
async fn passes_inbox_log_suite() {
    let Some((meta, fx)) = fixture().await else {
        return;
    };
    suite::itip::inbox_log(&meta, fx.owner).await;
}

/// META-69: очистка надгробий DAV убирает и надгробия входящих и поднимает границу: токен до очистки — `Conflict`,
/// токен на границе действует; свежие надгробия (срок по умолчанию) остаются.
#[tokio::test]
async fn inbox_tombstones_purge_raises_floor() {
    let Some(pool) = common::pool().await else {
        return;
    };
    let meta = PgMeta::new(pool, MetaConfig::default());
    let scope = common::account(&meta).await;
    let a = meta
        .inbox_put(scope, "a.ics", message("u1"))
        .await
        .expect("put a");
    meta.inbox_put(scope, "b.ics", message("u2"))
        .await
        .expect("put b");
    let gone = meta.inbox_delete(scope, "a.ics").await.expect("delete a");
    meta.purge_dav_tombstones().await.expect("purge");
    assert_eq!(
        meta.inbox_changes(scope, a.modseq, 10)
            .await
            .expect("свежее надгробие")
            .destroyed,
        vec![a.id]
    );

    let purged = meta
        .purge_dav_tombstones_before(OffsetDateTime::now_utc() + Duration::minutes(1))
        .await
        .expect("purge");
    assert!(purged >= 1, "очищено {purged}");
    assert_eq!(
        meta.inbox_changes(scope, a.modseq, 10).await,
        Err(Error::Conflict),
        "токен до очистки"
    );
    let at_floor = meta
        .inbox_changes(scope, gone, 10)
        .await
        .expect("на границе");
    assert!(at_floor.destroyed.is_empty() && at_floor.created.is_empty());
    assert_eq!(at_floor.new_state, gone);
    assert_eq!(
        meta.inbox_changes(scope, ModSeq::ZERO, 10)
            .await
            .expect("полная")
            .created
            .len(),
        1
    );
}

/// Перезапись объекта заменяет индекс занятости, удаление объекта и коллекции — убирает его строки.
#[tokio::test]
async fn busy_rows_follow_object() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let scope = common::account(&meta).await;
    let cal = Collection::new(CollectionKind::Calendar, "work");
    meta.create_collection(scope, cal.clone())
        .await
        .expect("create");
    let rows = async || -> i64 {
        let mut tx = schema::begin(meta.pool(), scope.tenant)
            .await
            .expect("begin");
        let n = sqlx::query_scalar("SELECT count(*) FROM dav_busy WHERE account_id = $1")
            .bind(scope.account.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .expect("count");
        tx.rollback().await.expect("rollback");
        n
    };
    // Одинаковые периоды в индексе допустимы и читаются как записаны.
    let twice = vec![busy(1, 2), busy(1, 2), busy(5, 6)];
    put_event(&meta, scope, &cal, "a", twice.clone()).await;
    put_event(&meta, scope, &cal, "b", vec![busy(8, 9)]).await;
    assert_eq!(rows().await, 4);
    let got = meta
        .get_object(scope, cal.id, "a")
        .await
        .expect("get")
        .expect("a");
    assert_eq!(got.index.busy, twice);
    let by_id = meta
        .objects_by_id(scope, &[got.id])
        .await
        .expect("objects_by_id");
    assert_eq!(by_id[0].index, got.index);

    put_event(&meta, scope, &cal, "a", vec![busy(3, 4)]).await;
    assert_eq!(rows().await, 2);
    put_event(&meta, scope, &cal, "a", Vec::new()).await;
    assert_eq!(rows().await, 1);
    let got = meta
        .get_object(scope, cal.id, "a")
        .await
        .expect("get")
        .expect("a");
    assert!(got.index.busy.is_empty());
    meta.delete_object(scope, cal.id, "b", Precondition::Any)
        .await
        .expect("delete");
    assert_eq!(rows().await, 0);
    put_event(&meta, scope, &cal, "c", vec![busy(1, 2)]).await;
    meta.delete_collection(scope, cal.id)
        .await
        .expect("delete collection");
    assert_eq!(rows().await, 0);
    let period = Period {
        start: at(0),
        end: at(48),
    };
    assert_eq!(
        meta.query(scope.tenant, &[scope.account], period).await,
        Ok(vec![(scope.account, Vec::new())])
    );
}

/// Чужая организация не видит строк занятости и входящих (RLS, роль узлов `thepost_app`).
#[tokio::test]
async fn rls_hides_other_tenants() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let owner = common::account(&meta).await;
    let cal = Collection::new(CollectionKind::Calendar, "work");
    meta.create_collection(owner, cal.clone())
        .await
        .expect("create");
    put_event(&meta, owner, &cal, "a", vec![busy(1, 2)]).await;
    meta.inbox_put(owner, "a.ics", message("u1"))
        .await
        .expect("inbox_put");
    meta.inbox_put(owner, "b.ics", message("u2"))
        .await
        .expect("inbox_put");
    meta.inbox_delete(owner, "b.ics")
        .await
        .expect("inbox_delete");
    let other = common::tenant(meta.pool()).await;
    let counts = async |tenant: TenantId| -> Vec<i64> {
        let mut tx = schema::begin(meta.pool(), tenant).await.expect("begin");
        sqlx::query("SET LOCAL ROLE thepost_app")
            .execute(&mut *tx)
            .await
            .expect("role");
        let mut out = Vec::new();
        for table in ["dav_busy", "dav_inbox", "dav_inbox_tombstones"] {
            let n: i64 = sqlx::query_scalar(AssertSqlSafe(format!(
                "SELECT count(*) FROM {table} WHERE account_id = $1"
            )))
            .bind(owner.account.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .expect("count");
            out.push(n);
        }
        // Запись в чужую организацию запрещена политикой.
        let err = sqlx::query(
            "INSERT INTO dav_inbox (tenant_id, account_id, item_id, name, method, uid, sender, body, etag, modseq,
                                    created_modseq)
             VALUES ($1, $2, $3, 'x.ics', 'REQUEST', 'u', 'a@b.example', '', '1', 1, 1)",
        )
        .bind(if tenant == owner.tenant {
            other.as_uuid()
        } else {
            owner.tenant.as_uuid()
        })
        .bind(owner.account.as_uuid())
        .bind(uuid::Uuid::now_v7())
        .execute(&mut *tx)
        .await
        .expect_err("чужая организация");
        assert!(matches!(schema::db_err(err), Error::Forbidden));
        tx.rollback().await.expect("rollback");
        out
    };
    assert_eq!(counts(owner.tenant).await, [1, 1, 1]);
    assert_eq!(counts(other).await, [0, 0, 0]);
}

/// Занятость и входящие учётной записи второго шарда — в БД этого шарда; запрос занятости собирает учётные
/// записи обоих шардов.
#[tokio::test]
async fn schedule_lives_on_account_shard() {
    let Some(t) = common::two_shards().await else {
        return;
    };
    let tenant = t.tenant().await;
    let on_main = t
        .account_on(tenant.clone(), tp_meta::shards::ShardId::MAIN)
        .await;
    let on_shard = t.account_on(tenant.clone(), t.shard).await;
    let cal = Collection::new(CollectionKind::Calendar, "work");
    for (scope, period) in [(on_main, busy(1, 2)), (on_shard, busy(3, 4))] {
        t.meta
            .create_collection(scope, Collection { ..cal.clone() })
            .await
            .expect("create");
        put_event(&t.meta, scope, &cal, "a", vec![period]).await;
    }
    t.meta
        .inbox_put(on_shard, "a.ics", message("u1"))
        .await
        .expect("inbox_put");
    for table in ["dav_busy", "dav_inbox"] {
        let count = async |pool: &tp_meta::pool::DbPool| -> i64 {
            let mut tx = schema::begin_system(pool).await.expect("begin");
            let n = sqlx::query_scalar(AssertSqlSafe(format!(
                "SELECT count(*) FROM {table} WHERE account_id = $1"
            )))
            .bind(on_shard.account.as_uuid())
            .fetch_one(&mut *tx)
            .await
            .expect("count");
            tx.rollback().await.expect("rollback");
            n
        };
        assert_eq!(count(&t.shard_pool).await, 1, "{table}");
        assert_eq!(count(t.main.meta.pool()).await, 0, "{table}");
    }
    assert_eq!(
        t.meta
            .inbox_list(on_shard)
            .await
            .expect("inbox_list")
            .items
            .len(),
        1
    );
    let nobody = AccountId::new();
    let got = t
        .meta
        .query(
            tenant.0,
            &[on_shard.account, nobody, on_main.account],
            Period {
                start: at(0),
                end: at(48),
            },
        )
        .await
        .expect("query");
    assert_eq!(
        got,
        vec![
            (on_shard.account, vec![busy(3, 4)]),
            (nobody, Vec::new()),
            (on_main.account, vec![busy(1, 2)]),
        ]
    );
    t.drop_db().await;
}
