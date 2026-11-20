//! Публикации календарей и шаблоны занятости доменов-партнёров на PostgreSQL (META-34; CTR-36):
//! набор `tp-testkit::suite::calendar`, поиск по токену без организации, обслуживание истёкших,
//! схема и RLS. Без `TEST_DATABASE_URL` тесты пропускаются.

mod common;

use std::time::Duration;

use sqlx::AssertSqlSafe;
use time::OffsetDateTime;
use tp_contracts::calendar::CalendarPublications;
use tp_contracts::dav::CollectionId;
use tp_contracts::meta::{AccountKind, AccountScope, AccountStore, AccountUpsert};
use tp_contracts::trust::{Detail, TrustLevel, TrustPolicy, TrustStore};
use tp_contracts::{Error, TenantId};
use tp_meta::{PgMeta, schema};
use tp_testkit::suite::calendar::{PublicationsFixture, calendar_publications};

/// Код ошибки PostgreSQL.
fn code(e: &sqlx::Error) -> String {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
        .unwrap_or_default()
}

/// Ещё одна учётная запись организации `owner`.
async fn account_like(meta: &PgMeta, owner: AccountScope) -> AccountScope {
    let (domain, name) = common::domain(meta.pool(), owner.tenant).await;
    let acc = meta
        .upsert(
            owner.tenant,
            AccountUpsert {
                domain,
                login: format!("u{}@{name}", uuid::Uuid::now_v7().simple()),
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
        tenant: owner.tenant,
        account: acc.id,
    }
}

/// Фикстура набора публикаций: учётные записи в существующих организациях (набор создаёт
/// организации сам — на PostgreSQL они должны быть в каталоге).
async fn fixture(meta: &PgMeta) -> PublicationsFixture {
    let owner = common::account(meta).await;
    PublicationsFixture {
        owner,
        peer: account_like(meta, owner).await,
        foreign: common::account(meta).await,
    }
}

/// Политика организации: интернета — «занят/свободен» (выпуск ссылок разрешён).
async fn allow_free_busy(meta: &PgMeta, tenant: TenantId) {
    let mut policy = TrustPolicy::default();
    policy.sharing.external = Some(Detail::FreeBusy);
    meta.set_policy(TrustLevel::Org(tenant), &policy)
        .await
        .expect("политика организации");
}

/// Выполняет запрос в системной транзакции: успех — фиксация, ошибка — откат (после ошибки
/// транзакция PostgreSQL уже отменена — общая транзакция для нескольких проверок не годится).
/// `$1` — организация, `$2` — учётная запись, `$3` — публикация, `$4` — календарь.
async fn attempt(
    pool: &tp_meta::pool::DbPool,
    sql: &str,
    scope: AccountScope,
    publication: uuid::Uuid,
    calendar: CollectionId,
) -> Result<(), sqlx::Error> {
    let mut tx = schema::begin_system(pool).await.expect("begin system");
    let out = sqlx::query(sqlx::AssertSqlSafe(sql.to_owned()))
        .bind(scope.tenant.as_uuid())
        .bind(scope.account.as_uuid())
        .bind(publication)
        .bind(calendar.as_uuid())
        .execute(&mut *tx)
        .await;
    if out.is_ok() {
        tx.commit().await.expect("commit");
    } else {
        tx.rollback().await.expect("rollback");
    }
    out.map(|_| ())
}

/// Набор на своей чистой БД: уровень установки — один на БД, параллельные тесты общей БД его бы
/// делили (потолок набора считает действующую матрицу доверия).
#[tokio::test]
async fn calendar_publications_passes_contract_suite() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let meta = &db.meta;
    let fx = fixture(meta).await;
    calendar_publications(meta, meta, &fx).await;
    db.drop_db().await;
}

/// Поиск по токену без организации: по хэшу, отозванной и истёкшей ссылки нет; обслуживание
/// удаляет истёкшие; отзыв удаляет запись.
#[tokio::test]
async fn token_lookup_revocation_and_expiry() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let owner = common::account(&meta).await;
    allow_free_busy(&meta, owner.tenant).await;
    let cal = CollectionId::new();
    let a = meta
        .create(owner, cal, Detail::FreeBusy, None)
        .await
        .expect("создать ссылку");
    let token = a.token.clone().expect("токен выдаётся один раз");

    // По токену — запись (токен не несёт организацию); не тот токен — нет.
    let found = meta
        .publication_by_token(&token)
        .await
        .expect("поиск")
        .expect("найдена");
    assert_eq!((found.id, found.scope, found.calendar), (a.id, owner, cal));
    assert_eq!(found.detail, Detail::FreeBusy);
    assert_eq!(found.expires, None);
    assert_eq!(found.token, None, "в хранилище токена нет");
    assert_eq!(
        meta.publication_by_token("cal-нет такой ссылки")
            .await
            .expect("поиск"),
        None
    );

    // Срок в будущем сохраняется: в ответе — как запросили (в хранилище — с точностью микросекунд).
    let expires = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let b = meta
        .create(owner, cal, Detail::FreeBusy, Some(expires))
        .await
        .expect("создать ссылку со сроком");
    assert_eq!(b.expires, Some(expires));
    assert_eq!(meta.list(owner).await.expect("список").len(), 2);

    // Обслуживание: до срока ссылки живут; после — истёкшая удалена (поиск по ней и список пусты).
    // Удаление идёт по всем организациям — число удалённых по всей установке не проверяем.
    meta.expire_publications(OffsetDateTime::now_utc())
        .await
        .expect("обслуживание");
    assert_eq!(meta.list(owner).await.expect("список").len(), 2);
    meta.expire_publications(OffsetDateTime::now_utc() + time::Duration::hours(2))
        .await
        .expect("обслуживание");
    assert!(
        meta.publication_by_token(b.token.as_deref().expect("токен b"))
            .await
            .expect("поиск")
            .is_none()
    );
    assert_eq!(meta.list(owner).await.expect("список").len(), 1);

    // Истёкшая, но ещё не убранная обслуживанием ссылка по токену не отдаётся — отдачу по ней
    // прекращает хранилище (DAV-20), до уборки она остаётся в списке.
    let c = meta
        .create(
            owner,
            cal,
            Detail::FreeBusy,
            Some(OffsetDateTime::now_utc() + time::Duration::seconds(1)),
        )
        .await
        .expect("создать ссылку со сроком");
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(
        meta.publication_by_token(c.token.as_deref().expect("токен c"))
            .await
            .expect("поиск")
            .is_none()
    );
    assert_eq!(meta.list(owner).await.expect("список").len(), 2);

    // Отзыв: по токену больше не отдаётся, из списка исчезла (истёкшая c — до обслуживания);
    // повтор — NotFound. Обслуживание убирает и её.
    let a = meta
        .publication_by_token(&token)
        .await
        .expect("поиск")
        .expect("найдена");
    assert_eq!(meta.revoke(owner, a.id).await, Ok(()));
    assert_eq!(
        meta.publication_by_token(&token).await.expect("поиск"),
        None
    );
    assert_eq!(meta.list(owner).await.expect("список").len(), 1);
    assert_eq!(meta.revoke(owner, a.id).await, Err(Error::NotFound));
    meta.expire_publications(OffsetDateTime::now_utc() + time::Duration::hours(2))
        .await
        .expect("обслуживание");
    assert!(meta.list(owner).await.expect("список").is_empty());
}

/// Схема: недопустимый уровень, срок не позже выдачи и повтор хэша — ошибки ограничений;
/// чужая организация строк не видит (RLS, роль узлов `thepost_app`).
#[tokio::test]
async fn schema_constraints_and_rls() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let owner = common::account(&meta).await;
    let foreign = common::account(&meta).await;
    allow_free_busy(&meta, owner.tenant).await;
    let cal = CollectionId::new();
    let a = meta
        .create(owner, cal, Detail::FreeBusy, None)
        .await
        .expect("создать ссылку");

    // Уровень вне политики выпуска — CHECK; срок не позже выдачи — CHECK.
    let pub_id = *a.id.as_uuid();
    let bad_detail = attempt(
        meta.pool(),
        "INSERT INTO calendar_publications
             (tenant_id, account_id, publication_id, calendar_id, detail, token_hash)
         VALUES ($1, $2, $3, $4, 'all', repeat('a', 64))",
        owner,
        pub_id,
        cal,
    )
    .await
    .expect_err("уровень 'all' вне политики выпуска");
    assert_eq!(code(&bad_detail), "23514");
    let late = attempt(
        meta.pool(),
        "INSERT INTO calendar_publications
             (tenant_id, account_id, publication_id, calendar_id, detail, token_hash,
              created_at, expires_at)
         VALUES ($1, $2, $3, $4, 'free_busy', repeat('b', 64), now(), now())",
        owner,
        uuid::Uuid::now_v7(),
        cal,
    )
    .await
    .expect_err("срок не позже выдачи");
    assert_eq!(code(&late), "23514");

    // Хэш токена уникален по инсталляции: повтор чужого хэша — ошибка ограничений.
    let (hash,): (String,) = sqlx::query_as(
        "SELECT token_hash FROM calendar_publications
         WHERE tenant_id = $1 AND account_id = $2 AND publication_id = $3",
    )
    .bind(owner.tenant.as_uuid())
    .bind(owner.account.as_uuid())
    .bind(pub_id)
    .fetch_one(&mut common::conn(meta.pool()).await)
    .await
    .expect("хэш");
    let mut tx = schema::begin(meta.pool(), foreign.tenant)
        .await
        .expect("begin");
    let dup = sqlx::query(
        "INSERT INTO calendar_publications
             (tenant_id, account_id, publication_id, calendar_id, detail, token_hash)
         VALUES ($1, $2, $3, $4, 'free_busy', $5)",
    )
    .bind(foreign.tenant.as_uuid())
    .bind(foreign.account.as_uuid())
    .bind(uuid::Uuid::now_v7())
    .bind(CollectionId::new().as_uuid())
    .bind(&hash)
    .execute(&mut *tx)
    .await
    .expect_err("повтор хэша");
    assert_eq!(code(&dup), "23505");
    tx.rollback().await.expect("rollback");

    // RLS: строку видит только своя организация (роль узлов `thepost_app`).
    let counts = async |tenant: TenantId| -> i64 {
        let mut tx = schema::begin(meta.pool(), tenant).await.expect("begin");
        sqlx::query("SET LOCAL ROLE thepost_app")
            .execute(&mut *tx)
            .await
            .expect("role");
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM calendar_publications")
            .fetch_one(&mut *tx)
            .await
            .expect("count");
        tx.rollback().await.expect("rollback");
        n
    };
    assert_eq!(counts(owner.tenant).await, 1);
    assert_eq!(counts(foreign.tenant).await, 0);
}

/// Шаблоны занятости доменов-партнёров — политика организации: только домен-партнёр, шаблон
/// https с `{user}`, замена и снятие, изоляция организаций; список партнёров шаблоны не трогает.
#[tokio::test]
async fn partner_availability_templates() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let owner = common::account(&meta).await;
    let foreign = common::account(&meta).await;
    let domain = "corp.example";
    let template = "https://{domain}/fb?u={user}";

    // Домен не партнёр — Invalid; недопустимый шаблон — Invalid.
    let err = meta
        .set_partner_availability_template(owner.tenant, domain, Some(template.into()))
        .await
        .expect_err("домен не партнёр");
    assert!(matches!(err, Error::Invalid(_)));
    let mut policy = TrustPolicy::default();
    policy.partners = vec![domain.into()];
    meta.set_policy(TrustLevel::Org(owner.tenant), &policy)
        .await
        .expect("партнёры");
    for bad in ["http://{user}", "https://fb.example/?u=user"] {
        let err = meta
            .set_partner_availability_template(owner.tenant, domain, Some(bad.into()))
            .await
            .expect_err("шаблон не годится");
        assert!(matches!(err, Error::Invalid(_)), "{bad}");
    }

    // Домен канонизируется: шаблон виден и по исходной записи домена.
    meta.set_partner_availability_template(owner.tenant, "Corp.Example.", Some(template.into()))
        .await
        .expect("задать шаблон");
    assert_eq!(
        meta.partner_availability_template(owner.tenant, domain)
            .await
            .expect("шаблон")
            .as_deref(),
        Some(template)
    );
    let list = meta
        .partner_availability(owner.tenant)
        .await
        .expect("список");
    assert_eq!(
        list,
        vec![tp_meta::calendar::PartnerAvailability {
            domain: domain.into(),
            template: template.into()
        }]
    );
    assert!(
        meta.partner_availability(foreign.tenant)
            .await
            .expect("чужой список")
            .is_empty()
    );
    assert_eq!(
        meta.partner_availability_template(foreign.tenant, domain)
            .await
            .expect("чужой шаблон"),
        None
    );

    // Замена шаблона, затем снятие; снятие отсутствующего — не ошибка.
    let other = "https://fb.{domain}/{user}.xml";
    meta.set_partner_availability_template(owner.tenant, domain, Some(other.into()))
        .await
        .expect("заменить шаблон");
    assert_eq!(
        meta.partner_availability_template(owner.tenant, domain)
            .await
            .expect("шаблон")
            .as_deref(),
        Some(other)
    );
    meta.set_partner_availability_template(owner.tenant, domain, None)
        .await
        .expect("снять шаблон");
    assert!(
        meta.partner_availability(owner.tenant)
            .await
            .expect("список")
            .is_empty()
    );
    meta.set_partner_availability_template(owner.tenant, domain, None)
        .await
        .expect("снять отсутствующий");

    // Список партнёров меняет политика доверия целиком — строки шаблонов она не трогает
    // (шаблон неактуального домена безвреден).
    meta.set_partner_availability_template(owner.tenant, domain, Some(template.into()))
        .await
        .expect("задать шаблон");
    meta.set_policy(TrustLevel::Org(owner.tenant), &TrustPolicy::default())
        .await
        .expect("пустая политика");
    assert_eq!(
        meta.partner_availability(owner.tenant)
            .await
            .expect("список")
            .len(),
        1
    );
}
