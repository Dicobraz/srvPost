//! META-01: миграции на чистую БД, идемпотентность, RLS по организации. META-89: свёртывание журнала
//! миграций старой цепочки у установки, обновлённой до свёртывания (beta.2).

mod common;

use std::str::FromStr;

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Executor, PgPool};
use tp_contracts::{Error, TenantId};
use tp_meta::pool::DbPool;
use tp_meta::schema;

#[tokio::test]
async fn migrations_apply_on_clean_db_and_are_idempotent() {
    let Some(url) = common::pg_url() else { return };
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&url)
        .await
        .expect("connect");
    let db = format!("tp_meta_{}", uuid::Uuid::now_v7().simple());
    admin
        .execute(AssertSqlSafe(format!("CREATE DATABASE {db}")))
        .await
        .expect("create database");

    let opts = PgConnectOptions::from_str(&url).expect("url").database(&db);
    let pool = common::db(
        PgPoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await
            .expect("connect clean"),
    );
    schema::migrate(&pool).await.expect("first");
    schema::migrate(&pool).await.expect("second");
    // Параллельный старт нескольких узлов.
    let runs: Vec<_> = (0..3)
        .map(|_| {
            let pool = pool.clone();
            tokio::spawn(async move { schema::migrate(&pool).await })
        })
        .collect();
    for r in runs {
        r.await.expect("join").expect("concurrent");
    }

    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&mut *common::conn(&pool).await)
        .await
        .expect("count");
    assert_eq!(applied, schema::migrator().iter().count() as i64);

    let mut tx = schema::begin(&pool, TenantId::DEFAULT)
        .await
        .expect("begin");
    let name: String = sqlx::query_scalar("SELECT name FROM tenants")
        .fetch_one(&mut *tx)
        .await
        .expect("default tenant");
    assert_eq!(name, "default");
    tx.rollback().await.expect("rollback");
    pool.close().await;

    admin
        .execute(AssertSqlSafe(format!("DROP DATABASE {db} WITH (FORCE)")))
        .await
        .expect("drop database");
}

#[tokio::test]
async fn rls_hides_other_tenants() {
    let Some(pool) = common::pool().await else {
        return;
    };
    // Суперпользователь обходит RLS: проверяем от имени обычной роли.
    common::conn(&pool)
        .await
        .execute(
        "DO $$ BEGIN CREATE ROLE tp_meta_rls NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
         GRANT USAGE ON SCHEMA public TO tp_meta_rls;
         GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO tp_meta_rls;",
    )
    .await
    .expect("role");

    let a = common::tenant(&pool).await;
    let b = common::tenant(&pool).await;
    let (_, da) = common::domain(&pool, a).await;
    let (_, db) = common::domain(&pool, b).await;
    let names = vec![da.clone(), db.clone()];
    let count = "SELECT count(*) FROM domains WHERE name = ANY($1)";

    // Без организации — ни одной строки.
    let mut tx = pool.begin().await.expect("begin");
    tx.execute("SET LOCAL ROLE tp_meta_rls")
        .await
        .expect("role");
    let n: i64 = sqlx::query_scalar(count)
        .bind(&names)
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 0);
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM tenants")
        .fetch_one(&mut *tx)
        .await
        .expect("tenants");
    assert_eq!(n, 0);
    tx.rollback().await.expect("rollback");

    // В контексте организации A — только её строки; запись в чужую организацию запрещена.
    let mut tx = schema::begin(&pool, a).await.expect("begin");
    tx.execute("SET LOCAL ROLE tp_meta_rls")
        .await
        .expect("role");
    let visible: Vec<String> = sqlx::query_scalar("SELECT name FROM domains WHERE name = ANY($1)")
        .bind(&names)
        .fetch_all(&mut *tx)
        .await
        .expect("select");
    assert_eq!(visible, vec![da]);
    let err = sqlx::query("INSERT INTO domains (tenant_id, domain_id, name) VALUES ($1, $2, $3)")
        .bind(b.as_uuid())
        .bind(uuid::Uuid::now_v7())
        .bind(format!("x{}", db))
        .execute(&mut *tx)
        .await
        .expect_err("чужая организация");
    let code = err
        .as_database_error()
        .and_then(|e| e.code())
        .map(|c| c.into_owned());
    assert_eq!(code.as_deref(), Some("42501"));
    tx.rollback().await.expect("rollback");

    // Системная транзакция видит все организации.
    let mut tx = schema::begin_system(&pool).await.expect("begin");
    tx.execute("SET LOCAL ROLE tp_meta_rls")
        .await
        .expect("role");
    let n: i64 = sqlx::query_scalar(count)
        .bind(&names)
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 2);
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn unknown_tenant_insert_is_rejected() {
    let Some(pool) = common::pool().await else {
        return;
    };
    // Домен несуществующей организации: нарушение внешнего ключа → Invalid.
    let ghost = TenantId::new();
    let mut tx = schema::begin(&pool, ghost).await.expect("begin");
    let err = sqlx::query("INSERT INTO domains (tenant_id, domain_id, name) VALUES ($1, $2, $3)")
        .bind(ghost.as_uuid())
        .bind(uuid::Uuid::now_v7())
        .bind(format!("g{}.test", ghost.as_uuid().simple()))
        .execute(&mut *tx)
        .await
        .expect_err("fk");
    assert!(matches!(schema::db_err(err), Error::Invalid(_)));
}

/// Чистая БД и пул к ней: `(админ-пул, пул БД, имя БД)` — имя для удаления в конце теста.
async fn fresh(url: &str) -> (PgPool, DbPool, String) {
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .expect("подключение к TEST_DATABASE_URL");
    let db = format!("tp_meta_{}", uuid::Uuid::now_v7().simple());
    admin
        .execute(AssertSqlSafe(format!("CREATE DATABASE {db}")))
        .await
        .expect("create database");
    let opts = PgConnectOptions::from_str(url).expect("url").database(&db);
    let pool = common::db(
        PgPoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await
            .expect("подключение к чистой БД"),
    );
    (admin, pool, db)
}

/// Удаляет чистую БД теста.
async fn drop_db(admin: PgPool, db: &str) {
    admin
        .execute(AssertSqlSafe(format!("DROP DATABASE {db} WITH (FORCE)")))
        .await
        .expect("drop database");
}

/// Заменяет журнал миграций записями версий `1…=last` с прежними (не базовыми) контрольными суммами —
/// как у установки, обновлявшейся миграциями по одной (beta.2).
async fn set_journal(pool: &DbPool, last: i64) {
    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("DELETE FROM _sqlx_migrations")
        .execute(&mut *tx)
        .await
        .expect("delete journal");
    for v in 1..=last {
        sqlx::query(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
             VALUES ($1, $2, TRUE, $3, -1)",
        )
        .bind(v)
        .bind(format!("migration {v:04}"))
        .bind(vec![v as u8, 1, 2])
        .execute(&mut *tx)
        .await
        .expect("insert journal");
    }
    tx.commit().await.expect("commit");
}

/// META-89: узел, обновлённый до beta.2 (в журнале — записи старой цепочки 0001…0044), стартует
/// бинарником с базовой схемой без сноса базы: журнал сворачивается в одну свернувшую запись с
/// пометкой «свёрнута», данные до обновления остаются, повторный и параллельный старт — без ошибок.
#[tokio::test]
async fn pre_base_journal_is_folded_and_data_survives() {
    let Some(url) = common::pg_url() else { return };
    let (admin, pool, db) = fresh(&url).await;

    // Накатить схему: состояние базы после полной цепочки 0001…0044 побайтово равно базовой схеме
    // (META-71), поэтому подмена журнала на beta.2 воспроизводит обновляемый узел.
    schema::migrate(&pool).await.expect("схема");
    let tenant = common::tenant(&pool).await;
    let (domain_id, domain_name) = common::domain(&pool, tenant).await;
    set_journal(&pool, schema::FOLDED_LAST_VERSION).await;

    // Бинарник с базовой схемой стартует: записи версий старой цепочки, которых в нём нет, — не ошибка.
    schema::migrate(&pool)
        .await
        .expect("старт на журнале beta.2");

    let mut conn = common::conn(&pool).await;
    // В журнале — одна свернувшая запись базовой схемы с пометкой «свёрнута».
    let (version, description): (i64, String) =
        sqlx::query_as("SELECT version, description FROM _sqlx_migrations")
            .fetch_one(&mut *conn)
            .await
            .expect("свернувшая запись");
    assert_eq!(version, 1);
    assert!(
        description.contains("свёрнута"),
        "пометка «свёрнута» в описании свернувшей записи: {description}"
    );
    // Данные до обновления на месте.
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM domains WHERE tenant_id = $1 AND domain_id = $2")
            .bind(tenant.as_uuid())
            .bind(domain_id.as_uuid())
            .fetch_one(&mut *conn)
            .await
            .expect("домен до обновления");
    assert_eq!(count, 1, "домен {domain_name} не потерян");
    drop(conn);

    // Повторный и параллельный старт: журнал не меняется.
    schema::migrate(&pool).await.expect("повторный старт");
    let runs: Vec<_> = (0..3)
        .map(|_| {
            let pool = pool.clone();
            tokio::spawn(async move { schema::migrate(&pool).await })
        })
        .collect();
    for run in runs {
        run.await.expect("join").expect("параллельный старт");
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&mut *common::conn(&pool).await)
        .await
        .expect("журнал после повторных стартов");
    assert_eq!(count, 1);

    pool.close().await;
    drop_db(admin, &db).await;
}

/// META-89: база новее бинарника — послевыпусковая версия, отсутствующая в резолвере, остаётся
/// ошибкой: свёртывание применяется только к журналу старой цепочки с контрольной суммой не от
/// базовой схемы.
#[tokio::test]
async fn missing_post_base_version_is_an_error() {
    let Some(url) = common::pg_url() else { return };
    let (admin, pool, db) = fresh(&url).await;
    schema::migrate(&pool).await.expect("схема");

    // База «следующего» бинарника: базовая схема и применённая поверх послевыпусковая миграция.
    let mut conn = common::conn(&pool).await;
    sqlx::query(
        "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
         VALUES ($1, 'post base', TRUE, $2, -1)",
    )
    .bind(schema::FOLDED_LAST_VERSION + 1)
    .bind(vec![7u8; 4])
    .execute(&mut *conn)
    .await
    .expect("запись послевыпусковой миграции");
    drop(conn);

    let err = schema::migrate(&pool)
        .await
        .expect_err("база новее бинарника");
    let text = err.to_string();
    assert!(
        text.contains("was previously applied but is missing"),
        "ошибка мигратора об отсутствующей версии: {text}"
    );

    pool.close().await;
    drop_db(admin, &db).await;
}

/// META-89: неполная старая цепочка (бета обновлялась не до последней миграции свёртывания) не
/// сворачивается молча: её схема не равна базовой — обновление такой беты, пересоздание базы.
#[tokio::test]
async fn partial_old_chain_is_not_folded() {
    let Some(url) = common::pg_url() else { return };
    let (admin, pool, db) = fresh(&url).await;
    schema::migrate(&pool).await.expect("схема");
    set_journal(&pool, schema::FOLDED_LAST_VERSION - 1).await;

    let err = schema::migrate(&pool)
        .await
        .expect_err("неполная старая цепочка");
    let text = err.to_string();
    assert!(
        text.contains("was previously applied but is missing"),
        "ошибка мигратора об отсутствующей версии: {text}"
    );

    pool.close().await;
    drop_db(admin, &db).await;
}
