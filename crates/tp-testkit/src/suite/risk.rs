//! Набор проверок [`RiskStore`] (CTR-95, CONTRACTS.md#Risk; решение 126): in-memory `MemRisk` и `PgMeta`
//! (META-87) проходят одни и те же проверки.

use time::OffsetDateTime;
use tp_contracts::risk::{
    Detector, Hit, HitSource, HitsQuery, Mode, Origin, PACKAGE_FORMAT, PackageEntry,
    PackageManifest, PackageState, RiskAction, RiskLevel, RiskPolicy, RiskStore, Semver, Signal,
    SignalId, SignalOverride, Verdict,
};
use tp_contracts::{BlobHash, Error, TenantId};

/// Признак набора: `tp.suite` веса `weight` в режиме `Enforce`.
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

/// Пакет набора версии `version` с признаком веса `weight`.
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

/// Вердикт набора: применённое и «только отчёт» срабатывания.
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

fn override_of(signal: &str, weight: u16) -> RiskPolicy {
    let mut policy = RiskPolicy::default();
    policy.overrides.insert(
        SignalId::new(signal).expect("id"),
        SignalOverride {
            weight: Some(weight),
            ..SignalOverride::default()
        },
    );
    policy
}

/// Вес признака `id` в действующем каталоге организации `tenant`.
async fn weight_of(store: &dyn RiskStore, id: &SignalId, tenant: TenantId) -> u16 {
    store
        .effective(tenant)
        .await
        .expect("effective")
        .get(id)
        .expect("tp.suite в каталоге")
        .signal
        .weight
}

/// Набор проверок [`RiskStore`] (решение 126): номер пакета только растёт (повторный и меньший — `Invalid`,
/// активация не растущего — `Invalid`, отсутствующего — `NotFound`), откат — на хранимую версию, хранится
/// активный и не больше `keep` прошлых; действующий каталог — значения активного пакета, изменения уровней
/// поверх (установка — как угодно, организация — только ужесточить: ниже установки — `Invalid`); чужая
/// организация не видит политику и срабатывания другой; учёт обращений суммируется по суткам.
pub async fn risk(store: &dyn RiskStore, keep: usize) {
    // Номера пакета — с уникальной базы: чужие пакеты хранилища не мешают.
    let base = TenantId::new().as_uuid().as_u128() as u64 % 1_000_000_000;
    let (v1, v2, v3) = (base + 1, base + 2, base + 3);
    let id = SignalId::new("tp.suite").expect("id");
    let entry = |version: u64, state| PackageEntry { version, state };

    // Пакеты: рост номера и активация.
    store.put_package(&manifest(v1, 1)).await.expect("put v1");
    assert!(
        matches!(store.activate(v3).await, Err(Error::NotFound)),
        "нет пакета"
    );
    assert!(
        matches!(store.rollback(v3).await, Err(Error::NotFound)),
        "откат на отсутствующий"
    );
    store.activate(v1).await.expect("activate v1");
    assert!(
        matches!(
            store.put_package(&manifest(v1, 1)).await,
            Err(Error::Invalid(_))
        ),
        "тот же номер"
    );
    assert!(
        matches!(
            store.put_package(&manifest(base, 1)).await,
            Err(Error::Invalid(_))
        ),
        "меньший номер"
    );
    store.put_package(&manifest(v2, 2)).await.expect("put v2");
    assert!(
        matches!(store.activate(v1).await, Err(Error::Invalid(_))),
        "активация не растущего номера"
    );
    store.activate(v2).await.expect("activate v2");

    // Действующий каталог без политик — значения пакета.
    let tenant = TenantId::new();
    assert_eq!(weight_of(store, &id, tenant).await, 2);

    // Хранение: активный и не больше `keep` прошлых; откат — на хранимую.
    store.put_package(&manifest(v3, 3)).await.expect("put v3");
    store.activate(v3).await.expect("activate v3");
    let mut packages = store.packages().await.expect("packages");
    packages.retain(|p| p.version > base && p.version <= v3);
    let mut expected = vec![
        entry(v3, PackageState::Active),
        entry(v2, PackageState::Previous),
    ];
    if keep > 1 {
        expected.push(entry(v1, PackageState::Previous));
    }
    assert_eq!(packages, expected, "активный и {keep} прошлых по убыванию");
    if keep < 2 {
        assert!(
            matches!(store.rollback(v1).await, Err(Error::NotFound)),
            "сверх keep откат невозможен"
        );
    }
    store.rollback(v2).await.expect("rollback v2");
    assert_eq!(
        weight_of(store, &id, tenant).await,
        2,
        "откат меняет действующий пакет"
    );
    let mut packages = store.packages().await.expect("packages");
    packages.retain(|p| p.version > base && p.version <= v3);
    let expected = vec![
        entry(v3, PackageState::Previous),
        entry(v2, PackageState::Active),
    ];
    assert_eq!(
        packages, expected,
        "после отката прежний активный — прошлый"
    );

    // Установка меняет как угодно: вес 0 — признак не влияет на балл (значение каталога).
    store
        .set_policy(RiskLevel::Installation, &override_of("tp.suite", 0))
        .await
        .expect("install 0");
    assert_eq!(weight_of(store, &id, tenant).await, 0);
    // Организация — только ужесточить: ниже установки нельзя, выше — можно.
    store
        .set_policy(RiskLevel::Installation, &override_of("tp.suite", 20))
        .await
        .expect("install 20");
    assert!(
        matches!(
            store
                .set_policy(RiskLevel::Org(tenant), &override_of("tp.suite", 19))
                .await,
            Err(Error::Invalid(_))
        ),
        "организация ниже установки"
    );
    store
        .set_policy(RiskLevel::Org(tenant), &override_of("tp.suite", 21))
        .await
        .expect("org 21");
    assert_eq!(weight_of(store, &id, tenant).await, 21);

    // Чужая организация не видит политику и действует по пакету и установке.
    let foreign = TenantId::new();
    assert_eq!(
        store.policy(RiskLevel::Org(foreign)).await,
        Ok(None),
        "политика чужой организации не видна"
    );
    assert_eq!(
        weight_of(store, &id, foreign).await,
        20,
        "пакет и установка, без политики организации"
    );
    // Сброс: организация — установка, установка — пакет.
    store
        .reset_policy(RiskLevel::Org(tenant))
        .await
        .expect("org reset");
    assert_eq!(
        weight_of(store, &id, tenant).await,
        20,
        "установка действует"
    );
    store
        .reset_policy(RiskLevel::Installation)
        .await
        .expect("install reset");
    assert_eq!(weight_of(store, &id, tenant).await, 2, "пакет");
    assert_eq!(
        store.reset_policy(RiskLevel::Org(TenantId::new())).await,
        Ok(()),
        "сброс пустого уровня — не ошибка"
    );

    // Срабатывания: применённые и «только отчёт» (с режимом), чужая организация не видит.
    let message = BlobHash([9u8; 32]);
    store
        .record_hits(tenant, message, &verdict())
        .await
        .expect("record hits");
    let hits = store.hits(tenant, &HitsQuery::all(10)).await.expect("hits");
    assert_eq!(hits.len(), 2, "Enforce и Report");
    assert_eq!(hits[0].mode, Mode::Enforce);
    assert_eq!(hits[0].message, message);
    assert_eq!(hits[1].mode, Mode::Report, "«только отчёт» — в журнале");
    let mut only_report = HitsQuery::all(10);
    only_report.signal = Some(SignalId::new("tp.suite.report").expect("id"));
    assert_eq!(
        store.hits(tenant, &only_report).await.expect("hits").len(),
        1
    );
    assert!(
        store
            .hits(foreign, &HitsQuery::all(10))
            .await
            .expect("hits")
            .is_empty(),
        "срабатывания чужой организации не видны"
    );

    // Учёт обращений: суммируется по суткам и организациям.
    let source =
        tp_contracts::risk::SourceId::new(format!("suite-{}", TenantId::new())).expect("source");
    store
        .record_usage(&source, tenant, 10, 1)
        .await
        .expect("usage");
    store
        .record_usage(&source, tenant, 5, 2)
        .await
        .expect("usage");
    store
        .record_usage(&source, foreign, 7, 0)
        .await
        .expect("usage");
    let usage = store
        .usage(&source, OffsetDateTime::UNIX_EPOCH)
        .await
        .expect("usage");
    let mine = usage
        .iter()
        .find(|e| e.tenant == tenant)
        .expect("учёт организации");
    assert_eq!((mine.lookups, mine.hits), (15, 3), "суммируется");
    assert_eq!(usage.iter().filter(|e| e.tenant == foreign).count(), 1);
}
