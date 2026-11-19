//! META-86: запись об отправленном на PostgreSQL — общий набор `tp_testkit::suite::reply`, уникальность
//! метки между организациями, RLS, миграция поверх предыдущей (таблицы SentLog и бесед).

mod common;

use sqlx::{AssertSqlSafe, Executor};
use time::OffsetDateTime;
use tp_contracts::reply::{MessageIdHash, SentLog, SentRecord};
use tp_contracts::{AccountId, Error, TenantId};
use tp_meta::schema;
use tp_testkit::suite;

/// Набор `suite::reply` и уникальность метки — на чистой БД: `purge_before` удаляет записи всех
/// организаций по точным счётам, параллельным тестам общей БД нельзя попадать под очистку.
#[tokio::test]
async fn passes_contract_suite() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let meta = &db.meta;
    suite::reply(
        meta,
        common::tenant(meta.pool()).await,
        common::tenant(meta.pool()).await,
    )
    .await;

    // Метка уникальна в инсталляции: вторая организация с той же меткой — `Conflict`, свою запись она
    // не видит (RLS), повтор своей записи идемпотентен.
    let a = common::tenant(meta.pool()).await;
    let b = common::tenant(meta.pool()).await;
    let record = |tenant: TenantId| SentRecord {
        tenant,
        account: AccountId::new(),
        tag: vec![7u8; 16],
        message_id_hash: MessageIdHash([9u8; 32]),
        recipients: vec!["bob@partner.example".into()],
        thread: None,
        sent_at: OffsetDateTime::UNIX_EPOCH,
    };
    SentLog::record(meta, record(a))
        .await
        .expect("первая запись");
    assert_eq!(
        SentLog::record(meta, record(b)).await,
        Err(Error::Conflict),
        "метка уникальна в инсталляции"
    );
    SentLog::record(meta, record(a))
        .await
        .expect("повтор идемпотентен");
    assert_eq!(SentLog::by_tag(meta, b, &[7u8; 16]).await, Ok(None));
    assert!(
        SentLog::by_tag(meta, a, &[7u8; 16])
            .await
            .expect("by_tag")
            .is_some()
    );
    SentLog::purge_before(meta, OffsetDateTime::now_utc())
        .await
        .expect("purge");
    assert_eq!(SentLog::by_tag(meta, a, &[7u8; 16]).await, Ok(None));
    db.drop_db().await;
}

/// RLS записи об отправленном: организация видит только свои строки, запись в чужую организацию — `42501`.
#[tokio::test]
async fn sent_log_is_tenant_isolated() {
    let Some(pool) = common::pool().await else {
        return;
    };
    // Суперпользователь обходит RLS: проверяем от имени обычной роли.
    common::conn(&pool)
        .await
        .execute(
        "DO $$ BEGIN CREATE ROLE tp_meta_sent_rls NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
         GRANT USAGE ON SCHEMA public TO tp_meta_sent_rls;
         GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO tp_meta_sent_rls;",
    )
    .await
    .expect("роль");

    let a = common::tenant(&pool).await;
    let b = common::tenant(&pool).await;
    let insert = "INSERT INTO sent_log (tenant_id, account_id, tag, message_id_hash, recipients, sent_at)
                  VALUES ($1, $2, '\\x0102'::bytea, '\\x0304'::bytea, ARRAY['bob@partner.example'], now())";
    let mut tx = schema::begin(&pool, a).await.expect("begin");
    sqlx::query(insert)
        .bind(a.as_uuid())
        .bind(AccountId::new().as_uuid())
        .execute(&mut *tx)
        .await
        .expect("запись A");
    tx.commit().await.expect("commit");

    // В контексте организации A — её строка; запись в чужую организацию — отказ RLS.
    let mut tx = schema::begin(&pool, a).await.expect("begin");
    tx.execute("SET LOCAL ROLE tp_meta_sent_rls")
        .await
        .expect("роль");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM sent_log")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 1);
    let err = sqlx::query(insert)
        .bind(b.as_uuid())
        .bind(AccountId::new().as_uuid())
        .execute(&mut *tx)
        .await
        .expect_err("чужая организация");
    let code = err
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned());
    assert_eq!(code.as_deref(), Some("42501"));
    tx.rollback().await.expect("rollback");

    // В контексте организации B — ни одной строки.
    let mut tx = schema::begin(&pool, b).await.expect("begin");
    tx.execute("SET LOCAL ROLE tp_meta_sent_rls")
        .await
        .expect("роль");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM sent_log")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 0);
    tx.rollback().await.expect("rollback");
}

/// Миграция применяется поверх предыдущей схемы (данные схемы 1.0 не теряются), повторный запуск
/// ничего не меняет; таблицы записи об отправленном и бесед с RLS.
#[tokio::test]
async fn migration_applies_over_previous_and_is_idempotent() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let meta = &db.meta;
    let pool = meta.pool();
    // Данные предыдущей схемы: организация по умолчанию и домен теста.
    let (_, domain) = common::domain(pool, TenantId::DEFAULT).await;

    // Таблицы миграции на месте, RLS включён и принудителен, политика — у каждой.
    let tables = vec![
        "sent_log",
        "threads",
        "thread_messages",
        "thread_keys",
        "thread_holds",
        "thread_rules",
    ];
    let enforced: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class
         WHERE relname = ANY($1) AND relrowsecurity AND relforcerowsecurity",
    )
    .bind(&tables)
    .fetch_one(&mut *common::conn(pool).await)
    .await
    .expect("rls");
    assert_eq!(enforced, tables.len() as i64);
    let policies: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_policies WHERE tablename = ANY($1) AND policyname = 'tenant_isolation'",
    )
    .bind(&tables)
    .fetch_one(&mut *common::conn(pool).await)
    .await
    .expect("policies");
    assert_eq!(policies, tables.len() as i64);

    // Повторный запуск миграций ничего не меняет.
    schema::migrate(pool).await.expect("повтор");
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&mut *common::conn(pool).await)
        .await
        .expect("count");
    assert_eq!(applied, schema::migrator().iter().count() as i64);

    // Поверх предыдущей: снимаем объекты последней миграции и запись о ней — повторное применение
    // восстанавливает таблицы, данные схемы 1.0 не тронуты.
    for table in &tables {
        common::conn(pool)
            .await
            .execute(AssertSqlSafe(format!("DROP TABLE IF EXISTS {table}")))
            .await
            .expect("drop");
    }
    sqlx::query("DROP SEQUENCE IF EXISTS thread_seq")
        .execute(&mut *common::conn(pool).await)
        .await
        .expect("drop seq");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 2")
        .execute(&mut *common::conn(pool).await)
        .await
        .expect("unapply");
    schema::migrate(pool).await.expect("поверх предыдущей");
    let enforced: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class
         WHERE relname = ANY($1) AND relrowsecurity AND relforcerowsecurity",
    )
    .bind(&tables)
    .fetch_one(&mut *common::conn(pool).await)
    .await
    .expect("rls");
    assert_eq!(enforced, tables.len() as i64);
    let name: String = sqlx::query_scalar("SELECT name FROM tenants WHERE name = 'default'")
        .fetch_one(&mut *common::conn(pool).await)
        .await
        .expect("организация по умолчанию на месте");
    assert_eq!(name, "default");
    let found: i64 = sqlx::query_scalar("SELECT count(*) FROM domains WHERE name = $1")
        .bind(&domain)
        .fetch_one(&mut *common::conn(pool).await)
        .await
        .expect("домен на месте");
    assert_eq!(found, 1);

    db.drop_db().await;
}
