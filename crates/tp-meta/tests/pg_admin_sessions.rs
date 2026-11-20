//! META-64: сессии Admin API на PostgreSQL — общий набор `tp_testkit::suite::admin_sessions` (CTR-61),
//! очистка порциями, RLS, миграция поверх предыдущей.

mod common;

use std::collections::BTreeSet;

use sqlx::{AssertSqlSafe, Executor};
use time::{Duration, OffsetDateTime};
use tp_contracts::admin_session::{AdminSession, AdminSessions};
use tp_contracts::{AccountId, TenantId};
use tp_meta::schema;
use tp_testkit::suite;

/// Сессия для теста: организация, имя входа, срок.
fn session(tenant: TenantId, login: &str, expires_at: OffsetDateTime) -> AdminSession {
    let (a, b) = (AccountId::new(), AccountId::new());
    AdminSession {
        hash: format!("{:032x}{:032x}", a.as_uuid().as_u128(), b.as_uuid().as_u128()),
        principal: tp_contracts::auth::Principal {
            tenant,
            account: a,
            login: login.into(),
            groups: BTreeSet::new(),
            scopes: None,
        },
        roles: vec!["organization_admin".into()],
        expires_at,
    }
}

/// Общий набор CTR-61 — на чистой БД: `purge_expired` удаляет истёкшие всех организаций по точным
/// счётам, параллельным тестам общей БД нельзя попадать под очистку.
#[tokio::test]
async fn passes_contract_suite() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    suite::admin_sessions(&db.meta).await;
    db.drop_db().await;
}

/// Очистка порциями: больше `PURGE_PORTION` истёкших удаляются одним `purge_expired` (по счёту),
/// живые сессии всех организаций остаются.
#[tokio::test]
async fn purge_expired_in_portions() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let meta = &db.meta;
    let pool = meta.pool();
    let now = OffsetDateTime::now_utc();

    // Порция очистки tp-meta — 10 000: expired — на две порции с остатком, живые — остаются.
    let (tenant_a, tenant_b) = (common::tenant(pool).await, common::tenant(pool).await);
    let mut tx = schema::begin_system(pool).await.expect("begin");
    sqlx::query(
        "INSERT INTO admin_sessions (hash, tenant_id, account_id, login, groups, roles, expires_at)
         SELECT lpad(g::text, 64, '0'), $1, gen_random_uuid(), 'bulk@example.org', '[]', '[]', $3
         FROM generate_series(1, $2) AS g",
    )
    .bind(tenant_a.as_uuid())
    .bind(23_456_i64)
    .bind(now - Duration::seconds(1))
    .execute(&mut *tx)
    .await
    .expect("bulk expired");
    tx.commit().await.expect("commit");

    let live_a = session(tenant_a, "live-a@example.org", now + Duration::seconds(600));
    let live_b = session(tenant_b, "live-b@example.org", now + Duration::seconds(600));
    meta.put(live_a.clone()).await.expect("put a");
    meta.put(live_b.clone()).await.expect("put b");

    let removed = meta.purge_expired(now).await.expect("purge");
    assert_eq!(removed, 23_456, "истёкшие всех организаций");
    // Повтор — пусто (число удалённых при повторе — только оставшиеся).
    let again = meta.purge_expired(now).await.expect("purge again");
    assert_eq!(again, 0);
    // Живые на месте, истёкшая (граница включительно) не читается.
    assert_eq!(meta.get(&live_a.hash).await.expect("get a"), Some(live_a));
    assert_eq!(meta.get(&live_b.hash).await.expect("get b"), Some(live_b));
    let boundary = session(tenant_a, "boundary@example.org", now);
    meta.put(boundary.clone()).await.expect("put boundary");
    assert_eq!(meta.get(&boundary.hash).await.expect("get"), None);
    let removed = meta.purge_expired(now).await.expect("purge boundary");
    assert_eq!(removed, 1, "expires_at <= now — удаляется");
    db.drop_db().await;
}

/// RLS сессий: организация видит и вставляет только свои строки (проверка от имени обычной роли —
/// суперпользователь CI обходит RLS).
#[tokio::test]
async fn sessions_are_tenant_isolated() {
    let Some(pool) = common::pool().await else {
        return;
    };
    common::conn(&pool)
        .await
        .execute(
            "DO $$ BEGIN CREATE ROLE tp_meta_sessions_rls NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
             GRANT USAGE ON SCHEMA public TO tp_meta_sessions_rls;
             GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO tp_meta_sessions_rls;",
        )
        .await
        .expect("роль");

    let a = common::tenant(&pool).await;
    let b = common::tenant(&pool).await;
    let now = OffsetDateTime::now_utc();
    let hash = format!("{:064x}", a.as_uuid().as_u128());
    let insert = "INSERT INTO admin_sessions (hash, tenant_id, account_id, login, groups, roles, expires_at)
                  VALUES ($1, $2, $3, 'admin@example.org', '[]', '[]', $4)";
    let mut tx = schema::begin(&pool, a).await.expect("begin");
    sqlx::query(insert)
        .bind(&hash)
        .bind(a.as_uuid())
        .bind(AccountId::new().as_uuid())
        .bind(now + Duration::seconds(600))
        .execute(&mut *tx)
        .await
        .expect("запись A");
    tx.commit().await.expect("commit");

    // В контексте организации A — её строка; вставка в чужую организацию — отказ RLS.
    let mut tx = schema::begin(&pool, a).await.expect("begin");
    tx.execute("SET LOCAL ROLE tp_meta_sessions_rls")
        .await
        .expect("роль");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_sessions")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 1);
    let err = sqlx::query(insert)
        .bind(format!("{:064x}", b.as_uuid().as_u128()))
        .bind(b.as_uuid())
        .bind(AccountId::new().as_uuid())
        .bind(now + Duration::seconds(600))
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
    tx.execute("SET LOCAL ROLE tp_meta_sessions_rls")
        .await
        .expect("роль");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM admin_sessions")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 0);
    tx.rollback().await.expect("rollback");
}

/// Миграция применяется поверх предыдущей схемы, повторный запуск ничего не меняет; таблица
/// сессий с RLS (включён и принудителен, политика — на месте).
#[tokio::test]
async fn migration_applies_over_previous_and_is_idempotent() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let pool = db.meta.pool();

    let enforced: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class
         WHERE relname = 'admin_sessions' AND relrowsecurity AND relforcerowsecurity",
    )
    .fetch_one(&mut *common::conn(pool).await)
    .await
    .expect("rls");
    assert_eq!(enforced, 1);
    let policies: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_policies
         WHERE tablename = 'admin_sessions' AND policyname = 'tenant_isolation'",
    )
    .fetch_one(&mut *common::conn(pool).await)
    .await
    .expect("policies");
    assert_eq!(policies, 1);

    // Повторный запуск миграций ничего не меняет; снятая таблица восстанавливается повтором.
    schema::migrate(pool).await.expect("повтор");
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&mut *common::conn(pool).await)
        .await
        .expect("count");
    assert_eq!(applied, schema::migrator().iter().count() as i64);
    common::conn(&pool)
        .await
        .execute(AssertSqlSafe("DROP TABLE IF EXISTS admin_sessions".into()))
        .await
        .expect("drop");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 5")
        .execute(&mut *common::conn(pool).await)
        .await
        .expect("unapply");
    schema::migrate(pool).await.expect("поверх предыдущей");
    let enforced: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM pg_class
         WHERE relname = 'admin_sessions' AND relrowsecurity AND relforcerowsecurity",
    )
    .fetch_one(&mut *common::conn(pool).await)
    .await
    .expect("rls");
    assert_eq!(enforced, 1);

    db.drop_db().await;
}

/// Сессия принадлежит организации: удаление организации (каскад) удаляет её сессии, чтение и выход
/// по хэшу работают по всем организациям (системная транзакция).
#[tokio::test]
async fn tenant_cascade_and_system_access() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let meta = &db.meta;
    let pool = meta.pool();
    let now = OffsetDateTime::now_utc();
    let tenant = common::tenant(pool).await;
    let s = session(tenant, "admin@example.org", now + Duration::seconds(600));
    meta.put(s.clone()).await.expect("put");
    assert_eq!(meta.get(&s.hash).await.expect("get"), Some(s.clone()));
    meta.delete(&s.hash).await.expect("delete");
    assert_eq!(meta.get(&s.hash).await.expect("get deleted"), None);

    let s = session(tenant, "admin2@example.org", now + Duration::seconds(600));
    meta.put(s.clone()).await.expect("put");
    common::conn(pool)
        .await
        .execute(AssertSqlSafe(format!(
            "DELETE FROM tenants WHERE tenant_id = '{}'",
            tenant.as_uuid()
        )))
        .await
        .expect("drop tenant");
    assert_eq!(meta.get(&s.hash).await.expect("get"), None, "каскад");
    db.drop_db().await;
}
