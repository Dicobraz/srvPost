//! Справочник аномалий и TI на PostgreSQL (META-87; CTR-95): набор `tp-testkit::suite::risk`, схема
//! (рост номера пакета, единственный действующий, хранение прошлых), источники и версии списков
//! (текущая — последняя по `fetched_at`, `expires_at` — TTL источника), RLS и учёт обращений, очистка
//! срабатываний. Без `TEST_DATABASE_URL` тесты пропускаются.

mod common;

use std::time::Duration;

use sqlx::Executor;
use time::OffsetDateTime;
use tp_contracts::risk::{
    Detector, FeedFormat, Hit, HitSource, HitsQuery, HttpAuth, License, ListId, ListVersion, Mode,
    Origin, PACKAGE_FORMAT, PackageEntry, PackageManifest, PackageState, RiskAction, RiskLevel,
    RiskPolicy, RiskStore, Semver, Signal, SignalId, SignalOverride, SourceId, SourceKind, Tenants,
    TiOrigin, TiSource, Tier, Verdict,
};
use tp_contracts::{BlobHash, Error, TenantId};
use tp_meta::risk::RiskConfig;
use tp_meta::{MetaConfig, schema};
use tp_testkit::suite;

/// Код ошибки PostgreSQL.
fn code(e: &sqlx::Error) -> String {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
        .unwrap_or_default()
}

/// Признак пакета теста: `tp.suite` веса `weight` в режиме `Enforce`.
fn signal(weight: u16) -> Signal {
    Signal {
        id: SignalId::new("tp.suite").expect("id"),
        detector: Detector::EncryptedArchive,
        weight,
        threshold: 0,
        action: RiskAction::None,
        mode: Mode::Enforce,
        origin: Origin::Vendor,
        since: OffsetDateTime::UNIX_EPOCH,
    }
}

/// Пакет теста версии `version` с признаком веса `weight`.
fn manifest(version: u64, weight: u16) -> PackageManifest {
    PackageManifest {
        format: PACKAGE_FORMAT,
        version,
        created: OffsetDateTime::UNIX_EPOCH,
        min_node: Semver::new(0, 1, 0),
        key_id: "suite".to_owned(),
        signals: vec![signal(weight)],
        lists: Vec::new(),
        samples: Vec::new(),
    }
}

/// Вердикт теста: применённое и «только отчёт» срабатывания.
fn verdict() -> Verdict {
    Verdict {
        score: 7,
        hits: vec![Hit {
            signal: SignalId::new("tp.suite").expect("id"),
            strength: 100,
            weight: 7,
            source: HitSource::Detector,
        }],
        report_only: vec![Hit {
            signal: SignalId::new("tp.suite.report").expect("id"),
            strength: 90,
            weight: 5,
            source: HitSource::Sieve,
        }],
        action: RiskAction::Junk,
        drops_reply: false,
    }
}

/// Набор на своей чистой БД: уровни установки общие для БД, параллельные тесты общей БД их бы делили.
#[tokio::test]
async fn risk_passes_contract_suite() {
    let cfg = MetaConfig {
        risk: RiskConfig { package_keep: 1 },
        ..MetaConfig::default()
    };
    let Some(db) = common::fresh_meta_with(cfg).await else {
        return;
    };
    suite::risk(&db.meta, 1).await;
    db.drop_db().await;
}

/// Выполняет запрос в своей системной транзакции: успех — фиксация, ошибка — откат (после ошибки
/// транзакция PostgreSQL уже отменена).
async fn attempt(pool: &tp_meta::pool::DbPool, sql: &str) -> Result<(), sqlx::Error> {
    let mut tx = schema::begin_system(pool).await.expect("begin system");
    let out = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
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

/// Схема: повторное применение — пустая операция; пакет с меньшим и тем же номером — ошибка
/// ограничения (номер только растёт), второй действующий — уникальность, состояние вне списка — CHECK.
#[tokio::test]
async fn schema_constraints() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let pool = db.meta.pool();
    // Повторное применение схемы ничего не меняет (поверх предыдущих версий).
    schema::migrate(pool).await.expect("повторная миграция");

    attempt(
        pool,
        "INSERT INTO risk_packages (version, manifest, key_id) VALUES (10, '{}', 'k')",
    )
    .await
    .expect("пакет 10");
    for bad in [9, 10] {
        let err = attempt(
            pool,
            &format!(
                "INSERT INTO risk_packages (version, manifest, key_id) VALUES ({bad}, '{{}}', 'k')"
            ),
        )
        .await
        .expect_err("номер не растёт");
        assert_eq!(code(&err), "23514", "номер {bad} не растёт");
    }
    // Один действующий — частичный уникальный индекс.
    attempt(
        pool,
        "UPDATE risk_packages SET state = 'active' WHERE version = 10",
    )
    .await
    .expect("действующий");
    attempt(
        pool,
        "INSERT INTO risk_packages (version, manifest, key_id) VALUES (11, '{}', 'k')",
    )
    .await
    .expect("пакет 11");
    let err = attempt(
        pool,
        "UPDATE risk_packages SET state = 'active' WHERE version = 11",
    )
    .await
    .expect_err("второй действующий");
    assert_eq!(code(&err), "23505", "единственность действующего");
    // Состояние вне списка — CHECK.
    let err = attempt(
        pool,
        "UPDATE risk_packages SET state = 'broken' WHERE version = 11",
    )
    .await
    .expect_err("состояние вне списка");
    assert_eq!(code(&err), "23514");
    db.drop_db().await;
}

/// Хранение при `keep = 2`: после четвёртой установки — действующий и два прошлых (приёмка).
#[tokio::test]
async fn packages_keep_two_previous() {
    let cfg = MetaConfig {
        risk: RiskConfig { package_keep: 2 },
        ..MetaConfig::default()
    };
    let Some(db) = common::fresh_meta_with(cfg).await else {
        return;
    };
    let meta = &db.meta;
    let base = TenantId::new().as_uuid().as_u128() as u64 % 1_000_000_000;
    for v in 1..=4u64 {
        meta.put_package(&manifest(base + v, u16::try_from(v).expect("вес")))
            .await
            .expect("put");
        meta.activate(base + v).await.expect("activate");
    }
    let mut packages = meta.packages().await.expect("packages");
    packages.retain(|p| p.version > base);
    let entry = |version: u64, state| PackageEntry { version, state };
    assert_eq!(
        packages,
        vec![
            entry(base + 4, PackageState::Active),
            entry(base + 3, PackageState::Previous),
            entry(base + 2, PackageState::Previous),
        ],
        "активный и два прошлых по убыванию"
    );
    db.drop_db().await;
}

/// RLS: чужая организация не читает политику (кроме строки установки), учёт и срабатывания другой;
/// строку установки пишет только системная транзакция. Учёт за сутки суммируется; очистка срабатываний
/// старше границы — роль maintenance. Проверки под обычной ролью (суперпользователь обходит RLS).
#[tokio::test]
async fn rls_tenant_isolation_usage_and_purge() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let meta = &db.meta;
    let pool = meta.pool();
    common::conn(pool)
        .await
        .execute(
            "DO $$ BEGIN CREATE ROLE tp_meta_risk_rls NOLOGIN; EXCEPTION WHEN duplicate_object THEN NULL; END $$;
             GRANT USAGE ON SCHEMA public TO tp_meta_risk_rls;
             GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA public TO tp_meta_risk_rls;",
        )
        .await
        .expect("роль");

    let tenant = common::tenant(pool).await;
    let foreign = common::tenant(pool).await;

    // Политика организации и установки, учёт и срабатывания.
    let mut policy = RiskPolicy::default();
    policy.overrides.insert(
        SignalId::new("tp.suite").expect("id"),
        SignalOverride {
            weight: Some(2),
            ..SignalOverride::default()
        },
    );
    meta.set_policy(RiskLevel::Org(tenant), &policy)
        .await
        .expect("set org");
    meta.set_policy(RiskLevel::Installation, &policy)
        .await
        .expect("set installation");
    let source = SourceId::new(format!("rls-{}", TenantId::new())).expect("источник");
    meta.record_usage(&source, tenant, 10, 1)
        .await
        .expect("usage");
    meta.record_usage(&source, tenant, 5, 2)
        .await
        .expect("usage");
    meta.record_hits(tenant, BlobHash([7u8; 32]), &verdict())
        .await
        .expect("hits");

    // Учёт обращений дважды за сутки — сумма.
    let usage = meta
        .usage(&source, OffsetDateTime::UNIX_EPOCH)
        .await
        .expect("usage");
    assert_eq!(usage.len(), 1);
    assert_eq!((usage[0].lookups, usage[0].hits), (15, 3), "суммируется");

    // Чужая организация: строка установки читается, своя и чужая политика организаций — нет.
    let mut tx = schema::begin(pool, foreign).await.expect("begin foreign");
    tx.execute("SET LOCAL ROLE tp_meta_risk_rls")
        .await
        .expect("роль");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM risk_policies")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 1, "видна только строка установки");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM ti_usage")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 0, "учёт чужой организации не виден");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM risk_hits")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 0, "срабатывания чужой организации не видны");
    let err = sqlx::query("INSERT INTO risk_policies (tenant_id, policy) VALUES (NULL, '{}')")
        .execute(&mut *tx)
        .await
        .expect_err("организация не пишет уровень установки");
    assert_eq!(code(&err), "42501");
    tx.rollback().await.expect("rollback");

    // Своя организация: своя политика и строка установки, свой учёт и срабатывания.
    let mut tx = schema::begin(pool, tenant).await.expect("begin own");
    tx.execute("SET LOCAL ROLE tp_meta_risk_rls")
        .await
        .expect("роль");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM risk_policies")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 2, "своя строка и строка установки");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM ti_usage")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 1, "свой учёт");
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM risk_hits")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(n, 2, "Enforce и Report");
    tx.rollback().await.expect("rollback");

    // Очистка срабатываний старше границы — задание роли maintenance.
    let deleted = meta
        .purge_risk_hits_before(OffsetDateTime::now_utc() + time::Duration::days(1))
        .await
        .expect("purge");
    assert_eq!(deleted, 2);
    assert!(
        meta.hits(tenant, &HitsQuery::all(10))
            .await
            .expect("hits")
            .is_empty()
    );
    db.drop_db().await;
}

/// Источники TI и версии списков: источник заменяется целиком, запрещённый к поставке — `Invalid`;
/// текущая версия списка — последняя по `fetched_at`, `expires_at` — TTL источника; неизвестный
/// источник и пустая ссылка — `Invalid`; удаление источника идемпотентно.
#[tokio::test]
async fn sources_and_list_versions() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let feodo = TiSource {
        id: SourceId::new(format!("feodo-{}", TenantId::new())).expect("источник"),
        tier: Tier::Bundled,
        kind: SourceKind::Http {
            url: "https://feodo.tracker.abuse.ch/downloads/ipblocklist.json".to_owned(),
        },
        format: FeedFormat::Txt,
        ttl: Duration::from_secs(3600),
        stale: Default::default(),
        license: License {
            terms_url: "https://abuse.ch/terms".to_owned(),
            attribution: None,
            commercial: true,
        },
        tenants: Tenants::All,
        key: None,
        auth: HttpAuth::None,
        origin: TiOrigin::Vendor,
    };
    meta.put_source(&feodo).await.expect("put source");
    let mut sources = meta.sources().await.expect("sources");
    sources.retain(|s| s.id == feodo.id);
    assert_eq!(sources, vec![feodo.clone()], "источник записан как есть");

    // Запрещённый к поставке хост — Invalid.
    let mut forbidden = feodo.clone();
    forbidden.kind = SourceKind::Http {
        url: "https://api.rstcloud.net/v1/ip".to_owned(),
    };
    assert!(matches!(
        meta.put_source(&forbidden).await,
        Err(Error::Invalid(_))
    ));

    // Версии списка: новая по fetched_at становится текущей.
    let list = ListId::new(format!("feodo-ip-{}", TenantId::new())).expect("список");
    let old = ListVersion {
        list: list.clone(),
        source: feodo.id.clone(),
        sha256: BlobHash([1u8; 32]),
        blob: format!("pg/{list}"),
        entries: 1200,
        fetched_at: OffsetDateTime::UNIX_EPOCH,
        tlp: None,
    };
    meta.put_list_version(&old).await.expect("put");
    let fresh = ListVersion {
        sha256: BlobHash([2u8; 32]),
        fetched_at: OffsetDateTime::UNIX_EPOCH + time::Duration::days(1),
        ..old.clone()
    };
    meta.put_list_version(&fresh).await.expect("put again");
    assert_eq!(
        meta.list_current(&list).await.expect("current"),
        Some(fresh.clone()),
        "текущая — последняя по fetched_at"
    );
    // Повтор с теми же значениями — не ошибка.
    meta.put_list_version(&fresh).await.expect("повтор");

    // expires_at — fetched_at + TTL источника.
    let mut conn = common::conn(meta.pool()).await;
    let expires_at: OffsetDateTime = sqlx::query_scalar(
        "SELECT expires_at FROM ti_list_versions WHERE list = $1 AND sha256 = $2",
    )
    .bind(list.as_str())
    .bind(&fresh.sha256.0[..])
    .fetch_one(&mut *conn)
    .await
    .expect("expires");
    drop(conn);
    assert_eq!(expires_at, fresh.fetched_at + time::Duration::hours(1));

    // Неизвестный источник и пустая ссылка на содержимое — Invalid.
    let mut bad = fresh.clone();
    bad.source = SourceId::new(format!("unknown-{}", TenantId::new())).expect("источник");
    assert!(matches!(
        meta.put_list_version(&bad).await,
        Err(Error::Invalid(_))
    ));
    let mut bad = fresh.clone();
    bad.blob = String::new();
    assert!(matches!(
        meta.put_list_version(&bad).await,
        Err(Error::Invalid(_))
    ));

    // Удаление источника идемпотентно; без источника новая версия списка не ставится.
    meta.delete_source(&feodo.id).await.expect("delete");
    meta.delete_source(&feodo.id)
        .await
        .expect("повтор удаления");
    let mut next = fresh;
    next.sha256 = BlobHash([3u8; 32]);
    next.fetched_at += time::Duration::days(2);
    assert!(matches!(
        meta.put_list_version(&next).await,
        Err(Error::Invalid(_))
    ));
    let mut sources = meta.sources().await.expect("sources");
    sources.retain(|s| s.id == feodo.id);
    assert!(sources.is_empty(), "источник удалён");
}
