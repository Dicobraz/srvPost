//! Журнал переписки на PostgreSQL (META-88; CTR-97): набор `suite::journal` на `PgJournal`, правила
//! журналирования (организация, группа, ящик), RLS, только добавление (триггер), повторное применение
//! схемы без потерь, восстановление индекса после обрыва между фазами записи. Подмена записи и потеря
//! индекса — SQL теста от имени владельца схемы (роль приложения триггером останавливается). Без
//! `TEST_DATABASE_URL` тесты пропускаются.

mod common;

use std::sync::Arc;

use time::OffsetDateTime;
use tp_contracts::groups::{DistributionGroup, GroupMember, GroupStore, SenderRestriction};
use tp_contracts::ids::{AccountId, GroupId, JournalId, TenantId};
use tp_contracts::journal::{
    JournalAudit, JournalDirection, JournalQuery, JournalRecord, JournalRecords, JournalRule,
    JournalScope, JournalStore,
};
use tp_contracts::meta::{AccountKind, AccountStore, AccountUpsert};
use tp_contracts::{DomainId, Error};
use tp_meta::PgMeta;
use tp_meta::journal::PgJournal;
use tp_meta::schema;
use tp_testkit::{MemJournalRecords, suite};

/// Код ошибки PostgreSQL.
fn code(e: &sqlx::Error) -> String {
    e.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c.into_owned())
        .unwrap_or_default()
}

/// Учётная запись организации `tenant` (правило на ящик и его удаление каскадом).
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

/// Набор контракта CTR-97 на PostgreSQL: запись, поиск по всем полям со страницами, выгрузка,
/// цепочка, подмена (SQL от владельца схемы, триггер только на добавление останавливает роль
/// приложения), потеря индекса и восстановление из хранилища записей.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn journal_passes_contract_suite() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let pool = meta.pool().clone();
    let tenant = common::tenant(&pool).await;
    let journal = PgJournal::new(meta, Arc::new(MemJournalRecords::new()));
    // Подмена записи без пересчёта цепочки: только владелец схемы, отключив триггер только на
    // добавление (роль приложения и узел так не могут). Организацию передаёт набор: записи — в её
    // собственной организации.
    let tamper_pool = pool.clone();
    let corrupt = move |tenant: TenantId, id: JournalId| {
        tokio::task::block_in_place(|| {
            let pool = &tamper_pool;
            tokio::runtime::Handle::current().block_on(async move {
                let mut tx = schema::begin_system(pool).await.expect("system");
                sqlx::query("ALTER TABLE journal.entries DISABLE TRIGGER tp_append_only")
                    .execute(&mut *tx)
                    .await
                    .expect("disable trigger");
                sqlx::query(
                    "UPDATE journal.entries SET sender = 'tampered@example.invalid',
                                                    sender_key = 'tampered@example.invalid'
                     WHERE tenant_id = $1 AND id = $2",
                )
                .bind(*tenant.as_uuid())
                .bind(*id.as_uuid())
                .execute(&mut *tx)
                .await
                .expect("подмена");
                sqlx::query("ALTER TABLE journal.entries ENABLE TRIGGER tp_append_only")
                    .execute(&mut *tx)
                    .await
                    .expect("enable trigger");
                tx.commit().await.expect("commit");
            })
        })
    };
    // Потеря индекса (записи хранилища не трогаются) — той же функцией, которой чинит restore.
    let clear_pool = pool.clone();
    let drop_index = move || {
        tokio::task::block_in_place(|| {
            let pool = &clear_pool;
            tokio::runtime::Handle::current().block_on(async move {
                let mut tx = schema::begin_system(pool).await.expect("system");
                sqlx::query("SELECT public.tp_journal_clear($1)")
                    .bind(*tenant.as_uuid())
                    .execute(&mut *tx)
                    .await
                    .expect("очистка индекса");
                tx.commit().await.expect("commit");
            })
        })
    };
    suite::journal(&journal, &corrupt, &drop_index).await;
}

/// Запись журнала для правила `rule` организации `tenant`.
fn record(tenant: TenantId, rule: &str, secs: i64) -> JournalRecord {
    JournalRecord {
        tenant,
        sender: "sender@external.example".to_owned(),
        recipients: vec!["anna@internal.example".to_owned()],
        message_id: Some(format!("m{secs}@external.example")),
        at: OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time")
            + time::Duration::seconds(secs),
        rule: rule.to_owned(),
    }
}

/// Правила журналирования: организация, группа и ящик в одной организации; замена целиком,
/// выключение, удаление; каскад на удаление группы; чужая организация правил не видит.
#[tokio::test]
async fn rules_org_group_mailbox() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let pool = meta.pool().clone();
    let tenant = common::tenant(&pool).await;
    let foreign = common::tenant(&pool).await;
    let (domain, name) = common::domain(&pool, tenant).await;
    let account = account_in(&meta, tenant, (domain, &name)).await;
    let group = DistributionGroup {
        id: GroupId::new(),
        tenant,
        name: "Журналируемая группа".to_owned(),
        address: Some(format!("team@{name}")),
        external_id: None,
        members: vec![GroupMember::Account(account)],
        senders: SenderRestriction::Anyone,
        moderators: Vec::new(),
        hidden_from_gal: false,
    };
    meta.put(group.clone()).await.expect("группа");

    let journal = PgJournal::new(meta.clone(), Arc::new(MemJournalRecords::new()));
    // Общий набор правил (ADM-53): список, замена, приоритет наследования областей, изоляция
    // организаций — в своей организации набора. Организации набора — отдельные существующие
    // (правила — данные существующих организаций: внешний ключ), ящик и группа — существующие.
    let (suite_tenant, suite_foreign) = (common::tenant(&pool).await, common::tenant(&pool).await);
    suite::journal_rules(&journal, suite_tenant, suite_foreign, account, group.id).await;
    let org = JournalRule {
        id: "all-mail".to_owned(),
        tenant,
        scope: JournalScope::Org,
        direction: JournalDirection::Both,
        enabled: true,
    };
    let grp = JournalRule {
        id: "team-in".to_owned(),
        tenant,
        scope: JournalScope::Group(group.id),
        direction: JournalDirection::In,
        enabled: true,
    };
    let box_rule = JournalRule {
        id: "director".to_owned(),
        tenant,
        scope: JournalScope::Mailbox(account),
        direction: JournalDirection::Out,
        enabled: false,
    };
    journal.set_rule(&org).await.expect("правило организации");
    journal.set_rule(&grp).await.expect("правило группы");
    journal.set_rule(&box_rule).await.expect("правило ящика");
    // Некорректный идентификатор — Invalid (проверка контракта).
    let bad = JournalRule {
        id: "has space".to_owned(),
        ..org.clone()
    };
    assert!(matches!(
        journal.set_rule(&bad).await,
        Err(Error::Invalid(_))
    ));
    let mut rules = journal.rules(tenant).await.expect("правила");
    assert_eq!(rules.len(), 3, "правила организации, группы и ящика");
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(rules[0].id, "all-mail");
    assert_eq!(rules[1].scope, JournalScope::Mailbox(account));
    assert_eq!(rules[1].direction, JournalDirection::Out);
    assert!(!rules[1].enabled);
    assert_eq!(rules[2].scope, JournalScope::Group(group.id));
    assert_eq!(rules[2].direction, JournalDirection::In);
    // Замена целиком: выключенное правило организации.
    let off = JournalRule {
        enabled: false,
        ..org.clone()
    };
    journal.set_rule(&off).await.expect("замена");
    let rules = journal.rules(tenant).await.expect("правила");
    assert_eq!(rules.len(), 3);
    assert!(
        !rules
            .iter()
            .find(|r| r.id == "all-mail")
            .expect("есть")
            .enabled
    );

    // Чужая организация правил не видит; то же имя идентификатора у неё независимо.
    assert!(journal.rules(foreign).await.expect("чужие").is_empty());
    let foreign_rule = JournalRule {
        id: "all-mail".to_owned(),
        tenant: foreign,
        scope: JournalScope::Org,
        direction: JournalDirection::Both,
        enabled: true,
    };
    journal
        .set_rule(&foreign_rule)
        .await
        .expect("правило чужой");
    assert_eq!(journal.rules(tenant).await.expect("правила").len(), 3);
    assert_eq!(journal.rules(foreign).await.expect("чужие").len(), 1);

    // Удаление правила; удаление группы удаляет её правило (каскад).
    journal
        .delete_rule(tenant, "director")
        .await
        .expect("удаление");
    meta.remove(tenant, group.id)
        .await
        .expect("удаление группы");
    let rules = journal.rules(tenant).await.expect("правила");
    assert_eq!(
        rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        vec!["all-mail"],
        "правило группы ушло с группой, ящика — удалено"
    );
    // Правило на неизвестную группу — Invalid (внешний ключ).
    let ghost = JournalRule {
        id: "ghost".to_owned(),
        tenant,
        scope: JournalScope::Group(GroupId::new()),
        direction: JournalDirection::Both,
        enabled: true,
    };
    assert!(matches!(
        journal.set_rule(&ghost).await,
        Err(Error::Invalid(_))
    ));
}

/// RLS: записи индекса и правила видит только своя организация; вставка чужой организации
/// отклоняется (WITH CHECK), даже системная выборка видит свою организацию.
#[tokio::test]
async fn entries_and_rules_rls() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let pool = meta.pool().clone();
    let tenant = common::tenant(&pool).await;
    let foreign = common::tenant(&pool).await;
    let journal = PgJournal::new(meta.clone(), Arc::new(MemJournalRecords::new()));
    let rule = JournalRule {
        id: "rls".to_owned(),
        tenant,
        scope: JournalScope::Org,
        direction: JournalDirection::Both,
        enabled: true,
    };
    journal
        .append(
            &rule,
            &record(tenant, "rls", 0),
            tp_contracts::Bytes::from_static(b"Subject: rls\r\n\r\nbody"),
        )
        .await
        .expect("append");

    // Роль узла: тестовое соединение — владелец схемы, RLS для него действует только с ролью
    // приложения (как в тестах RLS pg_dav, pg_trust).
    let mut tx = schema::begin(&pool, foreign).await.expect("begin");
    sqlx::query("SET LOCAL ROLE thepost_app")
        .execute(&mut *tx)
        .await
        .expect("role");
    let seen: i64 = sqlx::query_scalar("SELECT count(*) FROM journal.entries")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(seen, 0, "чужая организация записей индекса не видит");
    let rules: i64 = sqlx::query_scalar("SELECT count(*) FROM journal.rules")
        .fetch_one(&mut *tx)
        .await
        .expect("count");
    assert_eq!(rules, 0, "чужая организация правил не видит");
    tx.commit().await.expect("commit");

    // Вставка строки чужой организации из транзакции foreign отклоняется (WITH CHECK); после ошибки
    // RLS транзакция прервана — каждая проверка в своей транзакции. seq = 2: запись организации
    // `tenant` уже под номером 1 (уникальность пары организация-номер проверяется раньше политики).
    let err = {
        let mut tx = schema::begin(&pool, foreign).await.expect("begin");
        sqlx::query("SET LOCAL ROLE thepost_app")
            .execute(&mut *tx)
            .await
            .expect("role");
        let err = sqlx::query(
            "INSERT INTO journal.entries (tenant_id, seq, id, sender, sender_key, recipients, rcpt_keys,
                                          at, rule, storage, canonical, prev_hash, hash)
             VALUES ($1, 2, gen_random_uuid(), 's@x.example', 's@x.example', ARRAY['r@x.example'],
                     ARRAY['r@x.example'], now(), 'r', 'mem/x', '{}',
                     '\\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
                     '\\x0100000000000000000000000000000000000000000000000000000000000000'::bytea)",
        )
        .bind(*tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect_err("вставка чужой организации");
        tx.rollback().await.expect("rollback");
        err
    };
    assert_eq!(code(&err), "42501");
    let err = {
        let mut tx = schema::begin(&pool, foreign).await.expect("begin");
        sqlx::query("SET LOCAL ROLE thepost_app")
            .execute(&mut *tx)
            .await
            .expect("role");
        let err = sqlx::query(
            "INSERT INTO journal.rules (tenant_id, id, scope_kind, direction, enabled)
             VALUES ($1, 'x', 'org', 'both', true)",
        )
        .bind(*tenant.as_uuid())
        .execute(&mut *tx)
        .await
        .expect_err("вставка правила чужой организации");
        tx.rollback().await.expect("rollback");
        err
    };
    assert_eq!(code(&err), "42501");

    // Своей организации записи видны и доступны аудиторскому поиску.
    let cap = JournalAudit::grant();
    let page = journal
        .search(&cap, &JournalQuery::all(tenant, 10))
        .await
        .expect("search");
    assert_eq!(page.entries.len(), 1);
}

/// Индекс только на добавление: UPDATE и DELETE отклоняются триггером даже системной транзакцией
/// (роль владельца схемы — тоже: FORCE RLS и триггер; очистка — только tp_journal_clear).
#[tokio::test]
async fn entries_are_append_only() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let pool = meta.pool().clone();
    let tenant = common::tenant(&pool).await;
    let journal = PgJournal::new(meta, Arc::new(MemJournalRecords::new()));
    let rule = JournalRule {
        id: "imm".to_owned(),
        tenant,
        scope: JournalScope::Org,
        direction: JournalDirection::Both,
        enabled: true,
    };
    journal
        .append(
            &rule,
            &record(tenant, "imm", 0),
            tp_contracts::Bytes::from_static(b"Subject: imm\r\n\r\nbody"),
        )
        .await
        .expect("append");

    for sql in [
        "UPDATE journal.entries SET sender = 'x@example.invalid', sender_key = 'x@example.invalid'",
        "DELETE FROM journal.entries",
    ] {
        let mut tx = schema::begin_system(&pool).await.expect("system");
        let full = format!(
            "{sql} WHERE tenant_id = '{}'",
            tenant.as_uuid().hyphenated()
        );
        let err = sqlx::query(sqlx::AssertSqlSafe(full))
            .execute(&mut *tx)
            .await
            .expect_err("триггер только на добавление");
        assert_eq!(code(&err), "42501", "изменение и удаление запрещены: {sql}");
        tx.rollback().await.expect("rollback");
    }
}

/// Восстановление после обрыва между фазами записи (запись в бакете есть, строки индекса нет):
/// `restore_index` добирает хвост, продолжая цепочку; повторное применение схемы данных не трогает.
#[tokio::test]
async fn restore_picks_up_tail_and_schema_reapply_keeps_data() {
    let Some(meta) = common::meta().await else {
        return;
    };
    let pool = meta.pool().clone();
    let tenant = common::tenant(&pool).await;
    let records = Arc::new(MemJournalRecords::new());
    let journal = PgJournal::new(meta, records.clone());
    let cap = JournalAudit::grant();
    let rule = JournalRule {
        id: "tail".to_owned(),
        tenant,
        scope: JournalScope::Org,
        direction: JournalDirection::Both,
        enabled: true,
    };
    journal
        .append(
            &rule,
            &record(tenant, "tail", 0),
            tp_contracts::Bytes::from_static(b"Subject: one\r\n\r\nbody one"),
        )
        .await
        .expect("append 1");
    // Обрыв между фазами: запись попала в хранилище, но не в индекс.
    let orphan = record(tenant, "tail", 7);
    let orphan_id = JournalId::new();
    records
        .put(
            orphan_id,
            &orphan,
            tp_contracts::Bytes::from_static(b"Subject: two\r\n\r\nbody two"),
        )
        .await
        .expect("put");
    let page = journal
        .search(&cap, &JournalQuery::all(tenant, 10))
        .await
        .expect("search");
    assert_eq!(page.entries.len(), 1, "хвоста в индексе нет");

    // Повторное применение схемы — пустая операция, данные на месте.
    schema::migrate(&pool).await.expect("повтор миграций");
    let page = journal
        .search(&cap, &JournalQuery::all(tenant, 10))
        .await
        .expect("search");
    assert_eq!(page.entries.len(), 1, "миграция данные не тронула");

    let restored = journal.restore_index(tenant).await.expect("restore");
    assert_eq!(restored, 2, "хвост добран из хранилища записей");
    let page = journal
        .search(&cap, &JournalQuery::all(tenant, 10))
        .await
        .expect("search");
    assert_eq!(page.entries.len(), 2);
    let report = journal.verify_chain(&cap, tenant).await.expect("verify");
    assert!(
        report.ok && report.broken_at.is_none(),
        "цепочка продолжена"
    );
    assert_eq!(report.records, 2);
    // Выгрузка «осиротевшей» записи работает и после восстановления.
    let eml = journal
        .export(&cap, tenant, orphan_id)
        .await
        .expect("export");
    assert!(eml.ends_with(b"body two"));
}
