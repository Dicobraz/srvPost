//! Набор проверок [`SentLog`] (CTR-94, CONTRACTS.md#Reply; решение 125 в): in-memory `MemSentLog` и `PgMeta`
//! (META-86) проходят одни и те же проверки.

use std::time::Duration;

use time::OffsetDateTime;
use tp_contracts::reply::{MessageIdHash, ReplyEvidence, SentLog, SentRecord};
use tp_contracts::{AccountId, Error, TenantId};

/// Момент отправки записи `n` набора.
fn sent_at(n: i64) -> OffsetDateTime {
    OffsetDateTime::UNIX_EPOCH + Duration::from_secs(n.unsigned_abs() * 60)
}

/// Тестовый хэш Message-ID (32 байта): контракты SHA-256 не считают, форма значения для набора достаточна.
fn test_hash(s: &str) -> MessageIdHash {
    let mut out = [0u8; 32];
    for (i, b) in s.bytes().enumerate() {
        out[i % 32] = out[i % 32].wrapping_add(b.wrapping_mul(31));
    }
    MessageIdHash(out)
}

/// Запись набора: метка `tag`, хэш от `hash`, адресаты `recipients`, организация `tenant`, отправка — `at`-я
/// минута от начала эпохи.
fn record(tenant: TenantId, tag: u8, hash: &str, at: i64, recipients: &[&str]) -> SentRecord {
    SentRecord {
        tenant,
        account: AccountId::new(),
        tag: vec![tag; 8],
        message_id_hash: test_hash(hash),
        recipients: recipients.iter().map(|s| s.to_string()).collect(),
        thread: None,
        sent_at: sent_at(at),
    }
}

/// Набор проверок [`SentLog`] (решение 125 в). Хранилище в начале пустое; `tenant` и `foreign` — разные
/// организации.
///
/// Запись и поиск по метке и хэшу Message-ID; чужая организация не видит чужих записей; повтор записи с той
/// же меткой идемпотентен, с другим содержимым — `Conflict`; некорректная запись — `Invalid`;
/// `purge_before` удаляет старые записи всех организаций; [`ReplyEvidence::confirms`] — отправитель среди
/// адресатов и возраст письма.
pub async fn reply(log: &dyn SentLog, tenant: TenantId, foreign: TenantId) {
    // Пустое хранилище: поиска нет, очистка ничего не удаляет.
    assert_eq!(log.by_tag(tenant, &[1u8; 8]).await, Ok(None));
    assert_eq!(
        log.by_message_id_hash(tenant, &test_hash("none")).await,
        Ok(Vec::new())
    );
    assert_eq!(log.purge_before(sent_at(60)).await, Ok(0));

    // Запись: метка, хэш, канонические адресаты. Некорректная запись — без изменений.
    let mut first = record(tenant, 1, "h1", 10, &["BOB@Partner.example"]);
    assert!(
        matches!(log.record(first.clone()).await, Err(Error::Invalid(_))),
        "адресат не в канонической форме"
    );
    first.recipients = vec!["bob@partner.example".into()];
    assert_eq!(log.record(first.clone()).await, Ok(()));
    assert_eq!(
        log.record(first.clone()).await,
        Ok(()),
        "повтор идемпотентен"
    );
    let mut clash = first.clone();
    clash.account = AccountId::new();
    assert_eq!(
        log.record(clash).await,
        Err(Error::Conflict),
        "та же метка с другим содержимым"
    );

    // Поиск по метке: своя организация находит, чужая — нет; неизвестная метка — нет.
    let tag = vec![1u8; 8];
    assert_eq!(log.by_tag(tenant, &tag).await, Ok(Some(first.clone())));
    assert_eq!(log.by_tag(foreign, &tag).await, Ok(None));
    assert_eq!(log.by_tag(tenant, &[9u8; 8]).await, Ok(None));

    // Второе письмо с тем же Message-ID клиента (переслано себе) и запись чужой организации.
    let resent = record(
        tenant,
        2,
        "h1",
        70,
        &["bob@partner.example", "carol@external.example"],
    );
    log.record(resent.clone()).await.expect("resent");
    let foreign_record = record(foreign, 3, "h2", 45, &["dave@external.example"]);
    log.record(foreign_record.clone()).await.expect("foreign");
    assert_eq!(
        log.by_message_id_hash(tenant, &test_hash("h1")).await,
        Ok(vec![resent.clone(), first.clone()]),
        "новые первыми"
    );
    assert_eq!(
        log.by_message_id_hash(foreign, &test_hash("h1")).await,
        Ok(Vec::new()),
        "чужая организация не видит"
    );
    assert_eq!(
        log.by_message_id_hash(tenant, &test_hash("h2")).await,
        Ok(Vec::new())
    );
    let foreign_tag = vec![3u8; 8];
    assert_eq!(
        log.by_tag(foreign, &foreign_tag).await,
        Ok(Some(foreign_record.clone()))
    );

    // Признак ответа: отправитель — адресат записи и письмо не старше max_age; DMARC проверяет вызывающий.
    let evidence = ReplyEvidence {
        sent: resent.clone(),
        age: age_of(&resent, sent_at(80)),
    };
    assert!(evidence.confirms("bob@partner.example", Duration::from_secs(30 * 60)));
    assert!(evidence.confirms("CAROL@External.example", Duration::from_secs(30 * 60)));
    assert!(!evidence.confirms("eve@example.net", Duration::from_secs(30 * 60)));
    assert!(!evidence.confirms("bob@partner.example", Duration::from_secs(5 * 60)));
    let evidence = ReplyEvidence {
        sent: first.clone(),
        age: age_of(&first, sent_at(80)),
    };
    assert!(
        !evidence.confirms("bob@partner.example", Duration::from_secs(30 * 60)),
        "исходное письмо старше max_age"
    );

    // Очистка старых записей — все организации: первое письмо и чужая запись удалены, второе письмо свои
    // пока остаётся.
    assert_eq!(log.purge_before(sent_at(50)).await, Ok(2));
    assert_eq!(log.by_tag(tenant, &tag).await, Ok(None));
    assert_eq!(log.by_tag(foreign, &foreign_tag).await, Ok(None));
    assert_eq!(
        log.by_message_id_hash(tenant, &test_hash("h1")).await,
        Ok(vec![resent.clone()])
    );
    // До конца: свежие записи тоже удаляются по сроку, повторная очистка — ничего.
    assert_eq!(log.purge_before(sent_at(200)).await, Ok(1));
    assert_eq!(log.by_tag(tenant, &vec![2u8; 8]).await, Ok(None));
    assert_eq!(log.purge_before(sent_at(200)).await, Ok(0));
}

/// Возраст записи на момент `now` ([`tp_contracts::reply::age_since`]).
fn age_of(record: &SentRecord, now: OffsetDateTime) -> Duration {
    tp_contracts::reply::age_since(record.sent_at, now)
}
