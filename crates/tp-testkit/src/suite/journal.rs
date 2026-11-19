//! Набор проверок хранилища журнала (CTR-97; CONTRACTS.md#Journal; SRS 4.9).

use bytes::Bytes;
use time::OffsetDateTime;
use tp_contracts::Error;
use tp_contracts::ids::{JournalId, TenantId};
use tp_contracts::journal::{
    JournalAudit, JournalDirection, JournalQuery, JournalRecord, JournalRule, JournalRuleStore,
    JournalScope, JournalStore, journal_eml,
};

/// Набор проверок `JournalStore` (CTR-97): запись содержит скрытых и раскрытых из групп получателей и
/// не отменяется последующим `discard` в скрипте ящика (этап ядра журналирует до Sieve, записи
/// неизменяемы); поиск по всем полям запроса со страницами; `export` — .eml с конвертом; `verify_chain`
/// ловит подмену записи; `restore_index` восстанавливает индекс из хранилища записей.
///
/// `corrupt(tenant, id)` — подменяет запись `id` организации `tenant` в хранилище без пересчёта
/// цепочки (для in-memory — [`crate::MemJournal::tamper`], для PostgreSQL — SQL теста полосы);
/// `drop_index()` — теряет индекс, не трогая хранилище записей. Организация набора — новая: чужие
/// записи не мешают.
pub async fn journal(
    store: &dyn JournalStore,
    corrupt: &(dyn Fn(TenantId, JournalId) + Send + Sync),
    drop_index: &(dyn Fn() + Send + Sync),
) {
    let tenant = TenantId::new();
    let cap = JournalAudit::grant();
    let rule = JournalRule {
        id: "suite-rule".to_owned(),
        tenant,
        scope: JournalScope::Org,
        direction: JournalDirection::Both,
        enabled: true,
    };
    let at = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time");
    // Все получатели — включая скрытого (BCC) и раскрытых из группы; их готовит этап ядра.
    let record = |secs: i64, mid: &str| JournalRecord {
        tenant,
        sender: "sender@external.example".to_owned(),
        recipients: vec![
            "anna@internal.example".to_owned(),
            "hidden@internal.example".to_owned(),
            "member1@internal.example".to_owned(),
            "member2@internal.example".to_owned(),
        ],
        message_id: Some(mid.to_owned()),
        at: at + time::Duration::seconds(secs),
        rule: rule.id.clone(),
    };
    let (rec1, rec2) = (
        record(0, "m1@external.example"),
        record(10, "m2@external.example"),
    );
    let msg1 =
        Bytes::from_static(b"Message-ID: <m1@external.example>\r\nSubject: one\r\n\r\nbody one");
    let msg2 =
        Bytes::from_static(b"Message-ID: <m2@external.example>\r\nSubject: two\r\n\r\nbody two");
    let id1 = store
        .append(&rule, &rec1, msg1.clone())
        .await
        .expect("append 1");
    store.append(&rule, &rec2, msg2).await.expect("append 2");

    // Правило и запись должны согласовываться; пустое письмо — Invalid.
    let mut mismatched = record(20, "m3@external.example");
    mismatched.rule = "other-rule".to_owned();
    assert!(matches!(
        store.append(&rule, &mismatched, msg1.clone()).await,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        store
            .append(
                &JournalRule {
                    id: "suite-foreign".to_owned(),
                    tenant: TenantId::new(),
                    scope: JournalScope::Org,
                    direction: JournalDirection::Both,
                    enabled: true
                },
                &record(21, "m4@external.example"),
                Bytes::new()
            )
            .await,
        Err(Error::Invalid(_))
    ));

    // Поиск по всем полям запроса: отправитель, получатель (включая скрытого), Message-ID, правило,
    // интервал; страницы с курсором.
    let ids = |query: JournalQuery| async move {
        store
            .search(&cap, &query)
            .await
            .expect("search")
            .entries
            .iter()
            .map(|e| e.record.message_id.clone())
            .collect::<Vec<_>>()
    };
    let mut all = JournalQuery::all(tenant, 10);
    all.sender = Some("SENDER@external.example".to_owned());
    assert_eq!(
        ids(all).await,
        vec![
            Some("m1@external.example".into()),
            Some("m2@external.example".into())
        ],
        "отправитель без учёта регистра"
    );
    let mut hidden = JournalQuery::all(tenant, 10);
    hidden.recipient = Some("hidden@internal.example".to_owned());
    assert_eq!(ids(hidden).await.len(), 2, "поиск по скрытому получателю");
    let mut by_mid = JournalQuery::all(tenant, 10);
    by_mid.message_id = Some("m2@external.example".to_owned());
    assert_eq!(ids(by_mid).await, vec![Some("m2@external.example".into())]);
    let mut by_rule = JournalQuery::all(tenant, 10);
    by_rule.rule = Some("suite-rule".to_owned());
    assert_eq!(ids(by_rule).await.len(), 2);
    let mut interval = JournalQuery::all(tenant, 10);
    interval.since = Some(at);
    interval.until = Some(at + time::Duration::seconds(5));
    assert_eq!(
        ids(interval).await,
        vec![Some("m1@external.example".into())],
        "интервал [since, until)"
    );
    let mut bad = JournalQuery::all(tenant, 0);
    assert!(matches!(
        store.search(&cap, &bad).await,
        Err(Error::Invalid(_))
    ));
    bad.limit = 10;
    bad.until = Some(at);
    bad.since = Some(at);
    assert!(matches!(
        store.search(&cap, &bad).await,
        Err(Error::Invalid(_))
    ));
    // Чужая организация записей не видит.
    assert_eq!(
        ids(JournalQuery::all(TenantId::new(), 10)).await,
        Vec::<Option<String>>::new()
    );
    // Страницы: полная страница — с курсором, продолжение — строго после неё.
    let page1 = store
        .search(&cap, &JournalQuery::all(tenant, 1))
        .await
        .expect("page 1");
    assert_eq!(page1.entries.len(), 1);
    let next = page1.next.clone().expect("полная страница — с курсором");
    let mut page2q = JournalQuery::all(tenant, 10);
    page2q.after = Some(next);
    let page2 = store.search(&cap, &page2q).await.expect("page 2");
    assert_eq!(page2.entries.len(), 1);
    assert!(page2.next.is_none(), "вторая — последняя");
    assert_ne!(page1.entries[0].id, page2.entries[0].id);

    // Запись не отменяется скриптом ящика: `discard` в Sieve происходит позже этапа журналирования,
    // записи журнала неизменяемы — поиск по-прежнему находит всё.
    let mut after_discard = JournalQuery::all(tenant, 10);
    after_discard.message_id = Some("m1@external.example".to_owned());
    assert_eq!(
        ids(after_discard).await.len(),
        1,
        "discard не отменяет запись"
    );

    // export: .eml с конвертом.
    let eml = store.export(&cap, tenant, id1).await.expect("export");
    assert_eq!(eml, journal_eml(&rec1, &msg1).expect("canon eml"));
    assert!(eml.starts_with(b"X-ThePost-Journal-Sender: sender@external.example\r\n"));
    assert!(eml.ends_with(b"body one"));
    assert!(store.export(&cap, TenantId::new(), id1).await.is_err());
    assert!(matches!(
        store.export(&cap, tenant, JournalId::new()).await,
        Err(Error::NotFound)
    ));

    // Цепочка целостна.
    let report = store.verify_chain(&cap, tenant).await.expect("verify");
    assert!(report.ok && report.broken_at.is_none());
    assert_eq!(report.records, 2);

    // Индекс восстанавливается из хранилища записей.
    drop_index();
    let restored = store.restore_index(tenant).await.expect("restore");
    assert_eq!(restored, 2);
    assert_eq!(ids(JournalQuery::all(tenant, 10)).await.len(), 2);
    let report = store.verify_chain(&cap, tenant).await.expect("verify");
    assert!(report.ok && report.broken_at.is_none());

    // Подмена записи обнаруживается.
    corrupt(tenant, id1);
    let report = store.verify_chain(&cap, tenant).await.expect("verify");
    assert!(!report.ok, "подмена поймана");
    assert_eq!(report.broken_at, Some(id1));
    assert_eq!(report.records, 2);
}

/// Набор проверок правил журналирования — порт [`JournalRuleStore`] (ADM-53, решение #171): список,
/// задание (замена целиком по идентификатору), выключение, удаление, изоляция организаций и приоритет
/// наследования областей (ящик > группа > организация). Изменение видно сразу, без перезапуска:
/// каждое чтение `rules` — то, что конвейер прочитал бы на следующем письме (SMTP-53), и правило из
/// него действует по [`JournalRule::covers`]. Организация набора — новая.
pub async fn journal_rules(store: &dyn JournalRuleStore) {
    let tenant = TenantId::new();
    assert!(
        store.rules(tenant).await.expect("rules").is_empty(),
        "в новой организации правил нет"
    );

    // Три правила: организация, группа и ящик (существование области проверяет вызывающий — здесь
    // механика порта).
    let (account, group) = (tp_contracts::AccountId::new(), tp_contracts::GroupId::new());
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
        scope: JournalScope::Group(group),
        direction: JournalDirection::In,
        enabled: true,
    };
    let mailbox = JournalRule {
        id: "director".to_owned(),
        tenant,
        scope: JournalScope::Mailbox(account),
        direction: JournalDirection::Out,
        enabled: false,
    };
    store.set_rule(&org).await.expect("правило организации");
    store.set_rule(&grp).await.expect("правило группы");
    store.set_rule(&mailbox).await.expect("правило ящика");
    let rules = store.rules(tenant).await.expect("rules");
    assert_eq!(rules.len(), 3);
    // Порядок порта — по возрастанию идентификаторов; приоритет наследования — ящик > группа >
    // организация (сортирует вызывающий, [`JournalScope::priority`]).
    assert_eq!(
        rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        vec!["all-mail", "director", "team-in"],
        "по идентификаторам"
    );
    let mut by_priority = rules.clone();
    by_priority.sort_by_key(|r| (r.scope.priority(), r.id.clone()));
    assert_eq!(
        by_priority
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        vec!["director", "team-in", "all-mail"],
        "ящик > группа > организация"
    );

    // Замена целиком: направление и состояние меняются, число правил — то же; новое правило читается
    // тем же хранилищем сразу (конвейер читает на каждом письме — перезапуска не нужно).
    let off = JournalRule {
        enabled: false,
        direction: JournalDirection::In,
        ..org.clone()
    };
    store.set_rule(&off).await.expect("замена");
    let rules = store.rules(tenant).await.expect("rules");
    assert_eq!(rules.len(), 3, "замена, не добавление");
    let read = rules.iter().find(|r| r.id == "all-mail").expect("есть");
    assert_eq!(read, &off);
    // Правило из чтения действует по covers: выключенные правила писем не касаются, включённое
    // правило группы покрывает её члена.
    assert!(!read.covers(JournalDirection::In, None, &[], &[]));
    assert!(!mailbox.covers(JournalDirection::Out, Some(account), &[], &[]));
    assert!(grp.covers(JournalDirection::In, Some(account), &[], &[account]));

    // Изоляция организаций: чужая организация правил не видит, её правило не мешает.
    let foreign = TenantId::new();
    assert!(store.rules(foreign).await.expect("чужие").is_empty());
    let foreign_rule = JournalRule {
        id: "all-mail".to_owned(),
        tenant: foreign,
        scope: JournalScope::Org,
        direction: JournalDirection::Both,
        enabled: true,
    };
    store.set_rule(&foreign_rule).await.expect("правило чужой");
    assert_eq!(store.rules(tenant).await.expect("rules").len(), 3);
    assert_eq!(store.rules(foreign).await.expect("чужие").len(), 1);

    // Недопустимый идентификатор — Invalid (проверка контракта).
    let bad = JournalRule {
        id: "has space".to_owned(),
        ..org.clone()
    };
    assert!(matches!(store.set_rule(&bad).await, Err(Error::Invalid(_))));

    // Удаление: правило исчезает из чтения сразу; нет правила — не ошибка; записи не трогает.
    store
        .delete_rule(tenant, "team-in")
        .await
        .expect("удаление");
    store
        .delete_rule(tenant, "team-in")
        .await
        .expect("повтор удаления — не ошибка");
    let rules = store.rules(tenant).await.expect("rules");
    assert_eq!(
        rules.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
        vec!["all-mail", "director"],
        "правило группы удалено, чужая организация не задета"
    );
    assert_eq!(store.rules(foreign).await.expect("чужие").len(), 1);
}
