//! Политика доверия на PostgreSQL (META-85; CTR-93): набор `tp-testkit::suite::trust`, схема (уровни,
//! ограничения, каскад группы), RLS, внешний текст автоответа. Без `TEST_DATABASE_URL` тесты
//! пропускаются.

mod common;

use sqlx::Executor;
use tp_contracts::groups::{DistributionGroup, GroupMember, GroupStore, SenderRestriction};
use tp_contracts::meta::{AccountKind, AccountStore, AccountUpsert};
use tp_contracts::sieve::{SieveStore, Vacation};
use tp_contracts::trust::{Toggle, TrustLevel, TrustPolicy, TrustStore};
use tp_contracts::{AccountId, DomainId, GroupId, TenantId};
use tp_meta::{PgMeta, schema};
use tp_testkit::suite;

/// Код ошибки PostgreSQL.
fn code(e: &sqlx::Error) -> String {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
        .unwrap_or_default()
}

/// Учётная запись организации `tenant` (уровни групп действуют на неё через членство).
async fn account_in(meta: &PgMeta, tenant: TenantId, domain: (DomainId, &str)) -> AccountId {
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
    acc.id
}

/// Набор на своей чистой БД: уровень установки — один на БД, параллельные тесты общей БД его бы делили.
#[tokio::test]
async fn trust_passes_contract_suite() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let meta = &db.meta;
    let tenant = common::tenant(meta.pool()).await;
    let foreign = common::tenant(meta.pool()).await;
    let (domain, name) = common::domain(meta.pool(), tenant).await;
    let account = account_in(meta, tenant, (domain, &name)).await;
    suite::trust(meta, meta, tenant, foreign, account).await;
    db.drop_db().await;
}

/// Выполняет запрос в своей системной транзакции: успех — фиксация, ошибка — откат (после ошибки
/// транзакция PostgreSQL уже отменена — общая транзакция для нескольких проверок не годится). `$1` —
/// организация, если задана.
async fn attempt(
    pool: &tp_meta::pool::DbPool,
    sql: &str,
    tenant: Option<TenantId>,
) -> Result<(), sqlx::Error> {
    let mut tx = schema::begin_system(pool).await.expect("begin system");
    let out = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
        .bind(tenant.map(|t| *t.as_uuid()))
        .execute(&mut *tx)
        .await
        .map(|_| ());
    if out.is_ok() {
        tx.commit().await.expect("commit");
    } else {
        tx.rollback().await.expect("rollback");
    }
    out
}

/// Схема: повторное применение — пустая операция; вторая строка уровня установки и повтор
/// домена-партнёра — ошибки ограничений; домен не в нижнем регистре — CHECK; удаление группы удаляет
/// её политику.
#[tokio::test]
async fn schema_constraints_and_group_cascade() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let meta = &db.meta;
    let pool = meta.pool();
    // Повторное применение схемы ничего не меняет.
    schema::migrate(pool).await.expect("повторная миграция");

    let tenant = common::tenant(pool).await;
    attempt(
        pool,
        "INSERT INTO trust_policies (tenant_id, group_id) VALUES ($1, NULL)",
        None,
    )
    .await
    .expect("строка установки");
    let err = attempt(
        pool,
        "INSERT INTO trust_policies (tenant_id, group_id) VALUES ($1, NULL)",
        None,
    )
    .await
    .expect_err("вторая строка установки");
    assert_eq!(code(&err), "23505", "единственность уровня установки");
    // Повтор домена-партнёра — уникальность (tenant, domain).
    attempt(
        pool,
        "INSERT INTO trust_partner_domains (tenant_id, domain) VALUES ($1, 'partner.example')",
        Some(tenant),
    )
    .await
    .expect("домен-партнёр");
    let err = attempt(
        pool,
        "INSERT INTO trust_partner_domains (tenant_id, domain) VALUES ($1, 'partner.example')",
        Some(tenant),
    )
    .await
    .expect_err("повтор домена-партнёра");
    assert_eq!(code(&err), "23505");
    // Домен в нижнем регистре — CHECK.
    let err = attempt(
        pool,
        "INSERT INTO trust_partner_domains (tenant_id, domain) VALUES ($1, 'Partner.example')",
        Some(tenant),
    )
    .await
    .expect_err("домен не в нижнем регистре");
    assert_eq!(code(&err), "23514");

    // Удаление группы удаляет её политику (каскад).
    let group = DistributionGroup {
        id: GroupId::new(),
        tenant,
        name: "trust-cascade".into(),
        address: Some("trust-cascade@suite.example".into()),
        external_id: None,
        members: vec![GroupMember::Account(AccountId::new())],
        senders: SenderRestriction::default(),
        moderators: Vec::new(),
        hidden_from_gal: false,
    };
    let level = TrustLevel::Group(tenant, group.id);
    GroupStore::put(meta, group.clone()).await.expect("put");
    let mut policy = TrustPolicy::default();
    policy.mdn.partner = Some(Toggle::On);
    meta.set_policy(level, &policy).await.expect("set");
    assert_eq!(meta.policy(level).await, Ok(Some(policy)));
    meta.remove(tenant, group.id).await.expect("remove");
    assert_eq!(
        meta.policy(level).await,
        Ok(None),
        "политика группы удалена"
    );
    db.drop_db().await;
}

/// RLS: чужая организация не читает политику и партнёров другой; строку установки читают все
/// организации, пишет её только системная транзакция. Суперпользователь обходит RLS — проверки под
/// обычной ролью.
#[tokio::test]
async fn rls_tenant_isolation_and_installation_read() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let meta = &db.meta;
    let pool = meta.pool();
    common::conn(pool)
        .await
        .execute(
            "DO $$ BEGIN CREATE ROLE tp_meta_trust_rls NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
             GRANT USAGE ON SCHEMA public TO tp_meta_trust_rls;
             GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO tp_meta_trust_rls;",
        )
        .await
        .expect("role");

    let tenant = common::tenant(pool).await;
    let foreign = common::tenant(pool).await;

    let mut org = TrustPolicy::default();
    org.mdn.partner = Some(Toggle::On);
    org.partners = vec!["partner.example".into()];
    meta.set_policy(TrustLevel::Org(tenant), &org)
        .await
        .expect("set");
    // Строка установки — системной транзакцией.
    let mut tx = schema::begin_system(pool).await.expect("begin system");
    sqlx::query(
        "INSERT INTO trust_policies (tenant_id, group_id, cells) VALUES (NULL, NULL, '{}')",
    )
    .execute(&mut *tx)
    .await
    .expect("строка установки");
    tx.commit().await.expect("commit");

    let mut tx = schema::begin(pool, foreign).await.expect("begin foreign");
    tx.execute("SET LOCAL ROLE tp_meta_trust_rls")
        .await
        .expect("role");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM trust_policies")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 1, "видна только строка установки");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM trust_partner_domains")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 0, "партнёры чужой организации не видны");
    let err = sqlx::query(
        "INSERT INTO trust_policies (tenant_id, group_id, cells) VALUES (NULL, NULL, '{}')",
    )
    .execute(&mut *tx)
    .await
    .expect_err("организация не пишет уровень установки");
    assert_eq!(code(&err), "42501");
    tx.rollback().await.expect("rollback");

    // Своя организация видит свою политику и партнёров.
    let mut tx = schema::begin(pool, tenant).await.expect("begin own");
    tx.execute("SET LOCAL ROLE tp_meta_trust_rls")
        .await
        .expect("role");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM trust_policies")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 2, "своя строка и строка установки");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM trust_partner_domains")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 1);
    tx.rollback().await.expect("rollback");
    db.drop_db().await;
}

/// Внешний текст автоответа (CTR-93): колонки хранилища, `NULL` по умолчанию — наружу ответа нет.
#[tokio::test]
async fn vacation_external_text_roundtrip() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let scope = common::account(&meta).await;
    assert_eq!(
        meta.vacation(scope).await.expect("vacation"),
        Vacation::default(),
        "нет строки — умолчание без внешнего текста"
    );
    let vacation = Vacation {
        enabled: true,
        subject: Some("В отпуске".into()),
        text_body: Some("Вернусь скоро.".into()),
        external_subject: Some("Out of office".into()),
        external_text_body: Some("Back later.".into()),
        ..Vacation::default()
    };
    meta.set_vacation(scope, vacation.clone())
        .await
        .expect("set");
    assert_eq!(meta.vacation(scope).await.expect("vacation"), vacation);
    assert!(vacation.has_external());
    // Сброс внешнего текста очищает колонки.
    let cleared = Vacation {
        external_subject: None,
        external_text_body: None,
        ..vacation
    };
    meta.set_vacation(scope, cleared.clone())
        .await
        .expect("set");
    assert_eq!(meta.vacation(scope).await.expect("vacation"), cleared);
    assert!(!cleared.has_external());
}
