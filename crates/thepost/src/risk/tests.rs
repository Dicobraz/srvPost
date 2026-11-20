//! Тесты справочника аномалий на узле (APP-78): проверка пакета (подпись, хэши, lint, пробный прогон),
//! установка v2 поверх v1 с сохранением веса администратора, отказ «номер не растёт», откат, офлайн-
//! импорт из каталога, срок «только отчёт», Admin API-путь (проверка → активация), сборка `risk pack`.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures::StreamExt as _;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair as KeyPair;
use ring::signature::KeyPair as _;
use time::OffsetDateTime;
use tp_admin::risk::RiskNode as _;
use tp_contracts::blob::BlobStore;
use tp_contracts::bus::EventBus;
use tp_contracts::lease::LeaseStore;
use tp_contracts::risk::{
    Catalog, Detector, Field, HitSource, ListFile, ListId, ListKind, Mode, PackageManifest,
    RiskAction, RiskLevel, RiskPolicy, RiskStore, SampleFile, Semver, Signal, SignalId,
    SignalOverride, SourceId, TiSource, Verdict,
};
use tp_contracts::{Error, TenantId};
use tp_smtp::risk::RiskEnviron as _;
use tp_testkit::{Clock, ManualClock, MemBlobStore, MemEventBus, MemLease, MemRisk};

use super::{
    AdminNode, Installer, RiskCache, RiskUpdate, UpdateOutcome, Verifier, archive_of,
    canonical_manifest, pack, sha256,
};
use crate::sections::RiskSection;

const VENDOR: &str = "vendor";

/// Ключ подписи для тестов.
fn keypair() -> KeyPair {
    let doc = KeyPair::generate_pkcs8(&SystemRandom::new()).expect("генерация ключа");
    KeyPair::from_pkcs8(doc.as_ref()).expect("PKCS#8")
}

/// Публичный ключ проверки для тестов.
fn public(key: &KeyPair) -> Vec<u8> {
    key.public_key().as_ref().to_vec()
}

/// Отдельный «чужой» ключ (подпись не доверенным).
fn foreign_keypair() -> KeyPair {
    keypair()
}

/// Верификатор с одним доверенным ключом `vendor`.
fn verifier(key: &KeyPair) -> Verifier {
    Verifier::with_key(VENDOR, public(key))
}

/// Время из часов тестов (`MemRisk`, BLOB и лизы требуют `Clock`).
fn clock() -> Arc<dyn Clock> {
    Arc::new(ManualClock::new(OffsetDateTime::now_utc()))
}

/// Признак каталога.
fn signal(id: &str, detector: Detector, weight: u16) -> Signal {
    Signal {
        id: SignalId::new(id).expect("id"),
        detector,
        weight,
        threshold: 0,
        action: RiskAction::None,
        mode: Mode::Enforce,
        origin: tp_contracts::risk::Origin::Vendor,
        since: OffsetDateTime::UNIX_EPOCH,
    }
}

/// Источник TI поставки для списков пакета (коммерческий, без запрещённых хостов).
fn source() -> TiSource {
    TiSource {
        id: SourceId::new("vendor-feed").expect("id"),
        tier: tp_contracts::risk::Tier::Bundled,
        kind: tp_contracts::risk::SourceKind::File,
        format: tp_contracts::risk::FeedFormat::Txt,
        ttl: Duration::from_secs(86_400),
        stale: tp_contracts::risk::StaleAction::default(),
        license: tp_contracts::risk::License {
            terms_url: "https://vendor.example/terms".to_owned(),
            attribution: Some("© vendor".to_owned()),
            commercial: true,
        },
        tenants: tp_contracts::risk::Tenants::All,
        key: None,
        auth: tp_contracts::risk::HttpAuth::None,
        origin: tp_contracts::risk::TiOrigin::Vendor,
    }
}

/// Образец письма: `attach` — вложение `report.lnk` (образ диска/ярлык, детектор
/// `disk_image_or_shortcut`); `from` — адрес отправителя (детектор списка TI по `from_domain`).
fn letter(from: &str, attach: bool) -> Vec<u8> {
    if !attach {
        return format!("From: {from}\r\nSubject: hello\r\n\r\nplain text\r\n").into_bytes();
    }
    let lnk = [0x4Cu8, 0x00, 0x00, 0x00, 0x01, 0x14, 0x00, 0x00];
    let b64 = base64::engine::general_purpose::STANDARD.encode(lnk);
    let mut s = String::new();
    s.push_str("From: Boss <");
    s.push_str(from);
    s.push_str(">\r\nSubject: report\r\nMIME-Version: 1.0\r\n");
    s.push_str("Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n");
    s.push_str("--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n");
    s.push_str("--b\r\nContent-Disposition: attachment; filename=\"report.lnk\"\r\n");
    s.push_str("Content-Transfer-Encoding: base64\r\n\r\n");
    s.push_str(&b64);
    s.push_str("\r\n--b--\r\n");
    s.into_bytes()
}

/// Список «плохие домены» (строка — домен, `#` — комментарий).
fn bad_domains(path: &str) -> (ListFile, Vec<u8>) {
    let bytes = b"evil.example
# comment
phish.example
"
    .to_vec();
    (
        ListFile {
            id: ListId::new("bad-domains").expect("id"),
            path: path.to_owned(),
            sha256: sha256(&bytes),
            entries: 2,
            kind: ListKind::Domain,
            source: SourceId::new("vendor-feed").expect("id"),
        },
        bytes,
    )
}

/// Собирает байты пакета: манифест (хэши файлов заполняются здесь), подпись `key`, источники, файлы.
fn build_package(
    key: &KeyPair,
    key_id: &str,
    version: u64,
    signals: Vec<Signal>,
    lists: Vec<(ListFile, Vec<u8>)>,
    samples: Vec<(SampleFile, Vec<u8>)>,
    sources: Vec<TiSource>,
) -> Vec<u8> {
    let mut manifest = PackageManifest {
        format: tp_contracts::risk::PACKAGE_FORMAT,
        version,
        created: OffsetDateTime::UNIX_EPOCH,
        min_node: Semver::new(0, 1, 0),
        key_id: key_id.to_owned(),
        signals,
        lists: Vec::new(),
        samples: Vec::new(),
    };
    let mut files = super::PackageFiles::default();
    for (mut list, bytes) in lists {
        list.sha256 = sha256(&bytes);
        files.insert(list.path.clone(), bytes);
        manifest.lists.push(list);
    }
    for (mut sample, bytes) in samples {
        sample.sha256 = sha256(&bytes);
        files.insert(sample.path.clone(), bytes);
        manifest.samples.push(sample);
    }
    let signature = key
        .sign(&canonical_manifest(&manifest).expect("канонический json"))
        .as_ref()
        .to_vec();
    let verified = super::Verified {
        manifest,
        signature: Some(signature),
        sources,
        files,
        update: Default::default(),
        samples: 0,
    };
    archive_of(&verified).expect("архив")
}

/// Признак «образ диска или ярлык».
fn disk_signal() -> Signal {
    signal(
        "tp.disk_image_or_shortcut",
        Detector::DiskImageOrShortcut,
        8,
    )
}

/// Признак «домен `From` в списке TI».
fn list_signal() -> Signal {
    signal(
        "tp.from_bad_domain",
        Detector::ListMatch {
            list: ListId::new("bad-domains").expect("id"),
            field: Field::FromDomain,
        },
        4,
    )
}

/// Полный пакет v1: два признака, список TI и три образца (вложение-образ, домен из списка,
/// чистое письмо — контроль ложных срабатываний).
fn package_v1(key: &KeyPair, version: u64) -> Vec<u8> {
    let (list, list_bytes) = bad_domains("lists/bad-domains.txt");
    let samples = vec![
        (
            SampleFile {
                path: "samples/lnk.eml".to_owned(),
                sha256: sha256(&[]),
                expect: vec![SignalId::new("tp.disk_image_or_shortcut").expect("id")],
            },
            letter("clean@example.org", true),
        ),
        (
            SampleFile {
                path: "samples/from-list.eml".to_owned(),
                sha256: sha256(&[]),
                expect: vec![SignalId::new("tp.from_bad_domain").expect("id")],
            },
            letter("boss@evil.example", false),
        ),
        (
            SampleFile {
                path: "samples/clean.eml".to_owned(),
                sha256: sha256(&[]),
                expect: Vec::new(),
            },
            letter("clean@example.org", false),
        ),
    ];
    build_package(
        key,
        VENDOR,
        version,
        vec![disk_signal(), list_signal()],
        vec![(list, list_bytes)],
        samples,
        vec![source()],
    )
}

/// Пакет без списков и образцов (проверки подписи, хэшей, номера).
fn package_plain(key: &KeyPair, version: u64) -> Vec<u8> {
    build_package(
        key,
        VENDOR,
        version,
        vec![signal(
            "tp.encrypted_archive",
            Detector::EncryptedArchive,
            6,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
}

/// Кэш справочника над `MemRisk` без шины (тесты).
fn cache(store: &MemRisk, _blob: &MemBlobStore) -> Arc<RiskCache> {
    Arc::new(RiskCache::new(
        Arc::new(store.clone()),
        None,
        RiskSection::default(),
    ))
}

/// Установщик над кэшем и BLOB в памяти.
fn installer(store: Arc<RiskCache>, blob: &MemBlobStore) -> Installer {
    Installer::new(store, Arc::new(blob.clone()) as Arc<dyn BlobStore>)
}

/// Полный сценарий приёмки: v2 поверх v1 с сохранением веса администратора; повтор v2 и v1 —
/// отказ; откат на v1 — каталог v1; изменённый файл списка — отказ по хэшу; чужой ключ — отказ
/// по подписи; сигнал `risk_changed` после записей.
#[tokio::test]
async fn v2_over_v1_keeps_admin_weight_and_rejects_old_versions() {
    let key = keypair();
    let store = MemRisk::new(clock());
    let blob = MemBlobStore::new(clock());
    let bus = MemEventBus::default();
    // Сигналы публикаций читает подписчик (активация и откат публикует кэш узла).
    let mut events = bus.subscribe_system().await.expect("подписка");
    let cache = Arc::new(RiskCache::new(
        Arc::new(store.clone()),
        Some(Arc::new(bus.clone()) as Arc<dyn EventBus>),
        RiskSection::default(),
    ));
    let installer = installer(cache.clone(), &blob);

    // v1: два признака (вес 8 и 4).
    let v1 = package_v1(&key, 1);
    let verified = verifier(&key).verify(&v1, None).expect("v1 проверена");
    assert_eq!(verified.update.added.len(), 2, "всё — новое");
    assert_eq!(verified.samples, 3, "пробный прогон — три образца");
    installer.install(verified).await.expect("v1 установлена");

    // Вес признака меняет администратор установки — 7.
    let mut policy = RiskPolicy::default();
    policy.overrides.insert(
        SignalId::new("tp.from_bad_domain").expect("id"),
        SignalOverride {
            weight: Some(7),
            ..SignalOverride::default()
        },
    );
    cache
        .set_policy(RiskLevel::Installation, &policy)
        .await
        .expect("политика");

    // v2: вес пакета 5 (режим и срок — как у хранимой v1: новые в первом пакете приходят
    // «только отчёт»), действующий вес остаётся 7 (изменение администратора сохранено).
    let v2 = {
        let (list, list_bytes) = bad_domains("lists/bad-domains.txt");
        let mut disk = disk_signal();
        disk.mode = Mode::Report;
        let mut listed = list_signal();
        listed.weight = 5;
        listed.mode = Mode::Report;
        build_package(
            &key,
            VENDOR,
            2,
            vec![disk, listed],
            vec![(list, list_bytes)],
            Vec::new(),
            vec![source()],
        )
    };
    let old = cache
        .effective(TenantId::DEFAULT)
        .await
        .expect("каталог v1");
    let verified = verifier(&key)
        .verify(&v2, Some(&old))
        .expect("v2 проверена");
    assert_eq!(
        verified.update.changed.len(),
        1,
        "изменён один признак пакета"
    );
    installer.install(verified).await.expect("v2 установлена");

    let catalog = cache
        .effective(TenantId::DEFAULT)
        .await
        .expect("каталог v2");
    let from_list = catalog
        .get(&SignalId::new("tp.from_bad_domain").expect("id"))
        .expect("признак");
    assert_eq!(from_list.signal.weight, 7, "вес администратора сохранён");
    assert_eq!(
        from_list.source,
        Some(RiskLevel::Installation),
        "источник значения — уровень установки"
    );
    assert_eq!(
        from_list.base.as_ref().map(|b| b.weight),
        Some(5),
        "пакет v2 — 5"
    );

    // Повтор v2 и v1 — отказ «номер не растёт».
    let old = cache.effective(TenantId::DEFAULT).await.expect("каталог");
    let verified = verifier(&key).verify(&v2, Some(&old)).expect("проверка");
    let err = installer
        .install(verified)
        .await
        .expect_err("повтор v2 — отказ");
    assert!(matches!(err, Error::Invalid(_)), "{err}");
    let verified = verifier(&key).verify(&v1, Some(&old)).expect("проверка");
    let err = installer
        .install(verified)
        .await
        .expect_err("v1 поверх v2 — отказ");
    assert!(err.to_string().contains("не растёт"), "{err}");

    // Откат на v1 — каталог v1, изменение администратора сохранено.
    cache.rollback(1).await.expect("откат");
    let catalog = cache
        .effective(TenantId::DEFAULT)
        .await
        .expect("каталог v1");
    let from_list = catalog
        .get(&SignalId::new("tp.from_bad_domain").expect("id"))
        .expect("признак");
    assert_eq!(
        from_list.base.as_ref().map(|b| b.weight),
        Some(4),
        "пакет v1"
    );
    assert_eq!(from_list.signal.weight, 7, "изменение администратора живо");
    // Повторный откат на ту же хранимую — тоже возможен (номера пакетов не меняются).
    cache.rollback(1).await.expect("откат повторен");

    // Сигнал `risk_changed` опубликован (после фиксации отката).
    let ev = tokio::time::timeout(Duration::from_secs(2), events.next())
        .await
        .expect("сигнал")
        .expect("поток");
    assert_eq!(ev.kind, tp_contracts::bus::EventKind::RiskChanged);

    // Списки пакета — в BLOB и доступны данным детекторов.
    let environ =
        super::NodeEnviron::for_lists(Arc::new(blob.clone()) as Arc<dyn BlobStore>, cache.clone());
    let hit = environ
        .list_contains(
            TenantId::DEFAULT,
            &ListId::new("bad-domains").expect("id"),
            tp_smtp::risk::ListValue::Domain("sub.evil.example"),
        )
        .await
        .expect("поиск");
    assert!(hit, "поддомен из списка TI");
    let miss = environ
        .list_contains(
            TenantId::DEFAULT,
            &ListId::new("bad-domains").expect("id"),
            tp_smtp::risk::ListValue::Domain("clean.example"),
        )
        .await
        .expect("поиск");
    assert!(!miss);
}

/// Чужой ключ — отказ по подписи; лишний файл и изменённый список — отказ по манифесту.
#[tokio::test]
async fn foreign_key_and_tampered_files_are_rejected() {
    let key = keypair();
    let foreign = foreign_keypair();

    // Неизвестный key_id — ключ не доверенный (подпись даже не проверяется).
    let bytes = build_package(
        &foreign,
        "intruder",
        1,
        vec![signal(
            "tp.encrypted_archive",
            Detector::EncryptedArchive,
            6,
        )],
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let err = verifier(&key).verify(&bytes, None).expect_err("чужой ключ");
    assert!(err.to_string().contains("не доверенный"), "{err}");

    // Подпись чужим ключом при доверенном key_id — подпись манифеста не соответствует.
    let bytes = package_plain(&foreign, 1);
    let err = verifier(&key)
        .verify(&bytes, None)
        .expect_err("чужая подпись");
    assert!(err.to_string().contains("подпись манифеста"), "{err}");

    // Изменённый файл списка — хэш не совпадает (файл пакета подменён).
    let tampered = repack_with_list_bytes(&key, 1, b"other.example\r\n");
    let err = verifier(&key)
        .verify(&tampered, None)
        .expect_err("хэш списка");
    assert!(err.to_string().contains("хэшем манифеста"), "{err}");

    // Лишний файл в архиве — lint «каждый файл — по ссылке из манифеста».
    let mut with_extra = package_plain(&key, 1);
    rebuild_with_extra_file(&mut with_extra, "lists/extra.txt", b"x\n");
    let err = verifier(&key)
        .verify(&with_extra, None)
        .expect_err("лишний файл");
    assert!(err.to_string().contains("не упомянут"), "{err}");
}

/// Пересобирает архив с другим содержимым файла списка (подпись манифеста — честная).
fn repack_with_list_bytes(key: &KeyPair, version: u64, list_bytes: &[u8]) -> Vec<u8> {
    let (mut list, honest) = bad_domains("lists/bad-domains.txt");
    list.sha256 = sha256(&honest);
    let manifest = PackageManifest {
        format: tp_contracts::risk::PACKAGE_FORMAT,
        version,
        created: OffsetDateTime::UNIX_EPOCH,
        min_node: Semver::new(0, 1, 0),
        key_id: VENDOR.to_owned(),
        signals: vec![list_signal()],
        lists: vec![list],
        samples: Vec::new(),
    };
    let signature = key
        .sign(&canonical_manifest(&manifest).expect("канонический json"))
        .as_ref()
        .to_vec();
    let verified = super::Verified {
        manifest,
        signature: Some(signature),
        sources: vec![source()],
        files: {
            let mut files = super::PackageFiles::default();
            files.insert("lists/bad-domains.txt", list_bytes.to_vec());
            files
        },
        update: Default::default(),
        samples: 0,
    };
    archive_of(&verified).expect("архив")
}

/// Пересобирает архив с дополнительным файлом (проверка «лишних файлов»).
fn rebuild_with_extra_file(bytes: &mut Vec<u8>, name: &str, data: &[u8]) {
    let cursor = std::io::Cursor::new(std::mem::take(bytes));
    let mut zip = zip::ZipArchive::new(cursor).expect("архив");
    let out = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(out);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).expect("запись");
        let name_in = file.name().expect("имя записи").into_owned();
        writer.start_file(name_in.clone(), options).expect("запись");
        std::io::copy(&mut file, &mut writer).expect("копия");
    }
    writer.start_file(name.to_owned(), options).expect("запись");
    writer.write_all(data).expect("запись");
    *bytes = writer.finish().expect("закрыт").into_inner();
}

/// Образец без ожидаемого признака — `Rejected` с отчётом, активный пакет не меняется.
#[tokio::test]
async fn sample_mismatch_is_rejected_and_active_unchanged() {
    let key = keypair();
    let store = MemRisk::new(clock());
    let blob = MemBlobStore::new(clock());
    let cache = cache(&store, &blob);
    let installer = installer(cache.clone(), &blob);

    // Пакет с честным манифестом — установка.
    let good = package_v1(&key, 1);
    let verified = verifier(&key).verify(&good, None).expect("проверка");
    installer.install(verified).await.expect("установка v1");

    // Пакет v2, где образец «чистого» письма ожидает признак дискового образа — пробный прогон
    // не совпадает: отказ с отчётом, активный пакет не изменился.
    let (list, list_bytes) = bad_domains("lists/bad-domains.txt");
    let broken = build_package(
        &key,
        VENDOR,
        2,
        vec![disk_signal(), list_signal()],
        vec![(list, list_bytes)],
        vec![(
            SampleFile {
                path: "samples/clean.eml".to_owned(),
                sha256: sha256(&[]),
                expect: vec![SignalId::new("tp.disk_image_or_shortcut").expect("id")],
            },
            letter("clean@example.org", false),
        )],
        vec![source()],
    );
    let old = cache.effective(TenantId::DEFAULT).await.expect("каталог");
    let err = verifier(&key)
        .verify(&broken, Some(&old))
        .expect_err("образец");
    assert!(err.to_string().contains("пробный прогон"), "{err}");
    assert!(
        store
            .packages()
            .await
            .expect("пакеты")
            .iter()
            .all(|p| p.version == 1),
        "отклонённый пакет не поставлен, активный — v1"
    );
}

/// `min_node` выше версии узла и неверный формат пакета — отказ lint (схема манифеста).
#[tokio::test]
async fn min_node_and_format_are_checked() {
    let key = keypair();
    let bytes = package_plain(&key, 1);
    let verifier = verifier(&key).with_node_version(Semver::new(0, 0, 1));
    let err = verifier.verify(&bytes, None).expect_err("min_node");
    assert!(err.to_string().contains("не старше"), "{err}");

    // Неверный формат манифеста — отсекается схемой (`PackageManifest::validate`).
    let mut bad = package_plain(&key, 1);
    rewrite_manifest_field(&mut bad, |manifest| manifest.format = 99);
    let err = Verifier::with_key(VENDOR, public(&key))
        .verify(&bad, None)
        .expect_err("формат");
    assert!(err.to_string().contains("формат пакета"), "{err}");
}

/// Переписывает манифест в архиве (проверка схемы выполняется до проверки подписи).
fn rewrite_manifest_field(bytes: &mut Vec<u8>, change: impl FnOnce(&mut PackageManifest)) {
    let cursor = std::io::Cursor::new(std::mem::take(bytes));
    let mut zip = zip::ZipArchive::new(cursor).expect("архив");
    let mut manifest: PackageManifest = {
        let mut file = zip.by_name("manifest.json").expect("манифест");
        let mut text = Vec::new();
        file.read_to_end(&mut text).expect("чтение");
        serde_json::from_slice(&text).expect("json")
    };
    change(&mut manifest);
    let out = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(out);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for i in 0..zip.len() {
        let mut file = zip.by_index(i).expect("запись");
        let name = file.name().expect("имя записи").into_owned();
        writer.start_file(name.clone(), options).expect("запись");
        if name == "manifest.json" {
            writer
                .write_all(&serde_json::to_vec(&manifest).expect("json"))
                .expect("запись");
        } else {
            std::io::copy(&mut file, &mut writer).expect("копия");
        }
    }
    *bytes = writer.finish().expect("закрыт").into_inner();
}

/// Срок «только отчёт»: признак поставщика без решения администратора — `Enforce` в действующем
/// каталоге (хранилище не меняется); с решением администратора — остаётся `Report`.
#[tokio::test]
async fn report_only_signal_ages_into_enforce_without_admin_decision() {
    let key = keypair();
    let store = MemRisk::new(clock());
    let blob = MemBlobStore::new(clock());
    let section = RiskSection {
        report_only_days: 14,
        ..RiskSection::default()
    };
    let cache = Arc::new(RiskCache::new(Arc::new(store.clone()), None, section));
    let installer = installer(cache.clone(), &blob);

    // Новый признак поставщика — Catalog::apply_update переводит его в Report, `since` — месяц назад.
    let bytes = package_plain(&key, 1);
    let mut verified = verifier(&key).verify(&bytes, None).expect("проверка");
    for s in &mut verified.manifest.signals {
        s.mode = Mode::Report;
        s.since = OffsetDateTime::now_utc() - time::Duration::days(30);
    }
    installer.install(verified).await.expect("установка");

    // Срок «только отчёт» (14 сут) вышел — действующий каталог применяет Enforce.
    let id = SignalId::new("tp.encrypted_archive").expect("id");
    let catalog = cache.effective(TenantId::DEFAULT).await.expect("каталог");
    assert_eq!(
        catalog.get(&id).expect("признак").signal.mode,
        Mode::Enforce,
        "признак отработал срок «только отчёт»"
    );
    // Хранилище не меняется — срок считает узел.
    let stored = store.effective(TenantId::DEFAULT).await.expect("хранилище");
    assert_eq!(
        stored.get(&id).expect("признак").signal.mode,
        Mode::Report,
        "хранилище не меняется"
    );

    // Решение администратора (Report поверх признака) — остаётся «только отчёт».
    let mut policy = RiskPolicy::default();
    policy.overrides.insert(
        id.clone(),
        SignalOverride {
            mode: Some(Mode::Report),
            ..SignalOverride::default()
        },
    );
    cache
        .set_policy(RiskLevel::Installation, &policy)
        .await
        .expect("политика");
    let catalog = cache.effective(TenantId::DEFAULT).await.expect("каталог");
    assert_eq!(
        catalog.get(&id).expect("признак").signal.mode,
        Mode::Report,
        "решение администратора — выше срока"
    );
}

/// Закрытый контур: файл в `risk.update.dir` ставится без сети; `risk verify` — тот же отчёт;
/// сбой проверки — прежний пакет работает.
#[tokio::test]
async fn offline_dir_update_installs_and_rejects_bad_packages() {
    let key = keypair();
    let store = MemRisk::new(clock());
    let blob = MemBlobStore::new(clock());
    let dir = tempfile::tempdir().expect("каталог");

    // Первый пакет в каталоге (файл кладут руками или зеркалом).
    let bytes = package_v1(&key, 1);
    std::fs::write(dir.path().join("risk-v1.zip"), &bytes).expect("файл");

    // `thepost risk verify` — тот же отчёт, что у установки (без СУБД всё — добавленное).
    let verified = verifier(&key).verify(&bytes, None).expect("verify");
    assert_eq!(verified.update.added.len(), 2);
    assert_eq!(verified.samples, 3);

    let section = RiskSection {
        update: crate::sections::RiskUpdateSection {
            dir: Some(dir.path().to_owned()),
            auto_activate: true,
            ..crate::sections::RiskUpdateSection::default()
        },
        package: crate::sections::RiskPackageSection {
            dir: Some(dir.path().to_owned()),
        },
        ..RiskSection::default()
    };
    let cache = Arc::new(RiskCache::new(
        Arc::new(store.clone()),
        None,
        section.clone(),
    ));
    let leases = MemLease::new(clock());
    let update = RiskUpdate::new(
        section,
        Arc::new(verifier(&key)),
        Arc::new(installer(cache.clone(), &blob)),
        cache.clone(),
        Arc::new(leases.clone()) as Arc<dyn LeaseStore>,
        "node-a".to_owned(),
    );

    // Пустое хранилище — первый пакет из поставки.
    assert_eq!(
        update.pass().await,
        UpdateOutcome::Installed {
            version: 1,
            activated: true
        },
        "первый пакет поставки установлен и активирован"
    );
    let catalog = cache.effective(TenantId::DEFAULT).await.expect("каталог");
    assert_eq!(catalog.signals.len(), 2);

    // Следующий проход — без новой версии.
    assert_eq!(update.pass().await, UpdateOutcome::UpToDate);

    // Свежая версия в каталоге — ставится при следующем проходе.
    std::fs::write(dir.path().join("risk-v2.zip"), package_v1(&key, 2)).expect("файл");
    assert_eq!(
        update.pass().await,
        UpdateOutcome::Installed {
            version: 2,
            activated: true
        }
    );

    // Пакет с чужой подписью — Rejected с отчётом, прежний пакет работает.
    std::fs::write(
        dir.path().join("risk-v3.zip"),
        package_v1(&foreign_keypair(), 3),
    )
    .expect("файл");
    match update.pass().await {
        UpdateOutcome::Rejected { report } => {
            assert!(report.contains("подпись манифеста"), "{report}");
        }
        other => panic!("ожидался отказ: {other:?}"),
    }
    let catalog = cache.effective(TenantId::DEFAULT).await.expect("каталог");
    assert_eq!(catalog.signals.len(), 2, "прежний пакет работает");
}

/// Сборка `risk pack`: хэши файлов заполняются по содержимому, подпись принимается проверкой,
/// имя файла несёт номер версии (`risk-v<версия>.zip` — источник `risk.update.dir`).
#[tokio::test]
async fn pack_signs_and_verify_accepts_roundtrip() {
    let key = keypair();
    let dir = tempfile::tempdir().expect("каталог");
    let (list, list_bytes) = bad_domains("lists/bad-domains.txt");
    std::fs::create_dir_all(dir.path().join("lists")).expect("каталог списков");
    std::fs::write(dir.path().join(&list.path), &list_bytes).expect("список");
    std::fs::write(
        dir.path().join("sources.json"),
        serde_json::to_vec(&vec![source()]).expect("json"),
    )
    .expect("sources.json");
    // Манифест сборки: хэши списка ещё не заполнены (считает `pack`).
    let zeros = [0u8; 32];
    let hex_zero = "0".repeat(64);
    let manifest = serde_json::json!({
        "format": 1,
        "version": 7,
        "created": "2026-11-20T00:00:00Z",
        "min_node": "0.1.0",
        "key_id": VENDOR,
        "signals": [{
            "id": "tp.from_bad_domain",
            "detector": {"list_match": {"list": "bad-domains", "field": "from_domain"}},
            "weight": 4,
            "threshold": 0,
            "action": "none",
            "mode": "enforce",
            "origin": "vendor",
            "since": "2026-11-20T00:00:00Z"
        }],
        "lists": [{
            "id": "bad-domains",
            "path": "lists/bad-domains.txt",
            "sha256": hex_zero,
            "entries": 2,
            "kind": "domain",
            "source": "vendor-feed"
        }],
        "samples": []
    });
    let manifest_path = dir.path().join("manifest.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("json"),
    )
    .expect("манифест");

    let (bytes, signed) = pack(&manifest_path, &key).expect("сборка");
    assert_eq!(signed.version, 7);
    let out = dir.path().join(format!("risk-v{}.zip", signed.version));
    std::fs::write(&out, &bytes).expect("запись пакета");

    let verified = verifier(&key).verify(&bytes, None).expect("проверка");
    assert_eq!(verified.manifest.version, 7);
    assert_eq!(verified.samples, 0);
    assert_eq!(
        super::package_version(&out),
        Some(7),
        "номер из имени файла"
    );
    // Запись чужим ключом (доверенный key_id) — подпись не соответствует.
    let foreign_bytes = package_plain(&foreign_keypair(), 8);
    let err = verifier(&key)
        .verify(&foreign_bytes, None)
        .expect_err("чужая подпись");
    assert!(err.to_string().contains("подпись манифеста"), "{err}");
}

/// Секция `risk` из yaml: значения и умолчания, проверка источника обновления.
#[test]
fn risk_section_from_yaml() {
    let section: RiskSection = serde_yaml_ng::from_str(
        "trusted_keys:\n  vendor: /usr/share/thepost/risk/vendor.pub\nupdate:\n  url: https://risk.example/pkg\n  auto_activate: false\nreport_only_days: 7",
    )
    .expect("yaml");
    assert_eq!(section.report_only_days, 7);
    assert_eq!(
        section.update.url.as_deref(),
        Some("https://risk.example/pkg")
    );
    assert!(!section.update.auto_activate);
    assert_eq!(
        section.package.dir.as_deref(),
        Some(Path::new("/usr/share/thepost/risk"))
    );
    assert_eq!(
        section.import.dir,
        PathBuf::from("/var/lib/thepost/risk-import")
    );
    assert_eq!(RiskSection::default().report_only_days, 14);
    assert!(
        RiskSection::default().update.auto_activate,
        "по умолчанию — активировать"
    );

    // Оба источника — ошибка; http вне dev — ошибка; в dev — допустим.
    let mut section = RiskSection {
        update: crate::sections::RiskUpdateSection {
            url: Some("https://risk.example/pkg".to_owned()),
            dir: Some(PathBuf::from("/srv/risk")),
            ..crate::sections::RiskUpdateSection::default()
        },
        ..RiskSection::default()
    };
    assert!(section.check(tp_contracts::tls::Profile::Prod).is_err());
    section.update.dir = None;
    section.update.url = Some("http://risk.example/pkg".to_owned());
    assert!(section.check(tp_contracts::tls::Profile::Prod).is_err());
    assert!(section.check(tp_contracts::tls::Profile::Dev).is_ok());
    // Период обновления — положительный.
    let mut zero = RiskSection::default();
    zero.update.interval = Duration::ZERO;
    assert!(zero.check(tp_contracts::tls::Profile::Prod).is_err());
}

/// Вердикт каталога: балл — сумма весов `Enforce`-признаков, действие — по порогам, признак беседы
/// снимает признак ответа; «только отчёт» балл и действие не меняет.
#[test]
fn verdict_score_and_hits_follow_the_catalog() {
    let signals = vec![disk_signal()];
    let catalog = Catalog::effective(&signals, None, None);
    let fired = vec![tp_contracts::risk::Fired {
        signal: signals[0].clone(),
        strength: 100,
        source: HitSource::Detector,
    }];
    let verdict = Verdict::from_fired(&catalog, &fired);
    assert_eq!(verdict.score, 8);
    assert_eq!(verdict.action, RiskAction::Junk, "порог junk — 6");
    assert!(verdict.drops_reply, "признак беседы снимает признак ответа");

    // «Только отчёт» — балл и действие не меняет.
    let mut report_signal = disk_signal();
    report_signal.mode = Mode::Report;
    let catalog = Catalog::effective(&[report_signal.clone()], None, None);
    let fired = vec![tp_contracts::risk::Fired {
        signal: report_signal,
        strength: 100,
        source: HitSource::Detector,
    }];
    let verdict = Verdict::from_fired(&catalog, &fired);
    assert_eq!(verdict.score, 0);
    assert_eq!(verdict.action, RiskAction::None);
    assert_eq!(verdict.report_only.len(), 1, "срабатывание — в журнале");
}

/// Путь Admin API (ADM-51): проверка ставит пакет и укладывает BLOB, активация отдельно — каталог
/// меняет только активация; версии списков и источники становятся текущими при ней.
#[tokio::test]
async fn admin_node_stages_lists_before_activation() {
    let key = keypair();
    let store = MemRisk::new(clock());
    let blob = MemBlobStore::new(clock());
    let cache = cache(&store, &blob);
    let secrets = tp_testkit::MemSecretStore::new(clock());
    let node = AdminNode::new(
        Arc::new(verifier(&key)),
        Arc::new(installer(cache.clone(), &blob)),
        cache.clone(),
        Arc::new(blob.clone()) as Arc<dyn BlobStore>,
        &RiskSection::default(),
        Arc::new(secrets) as Arc<dyn tp_contracts::secrets::SecretStore>,
    );

    // Загрузка пакета через Admin API: проверка + укладка; признаков в действующем каталоге нет.
    let bytes = package_v1(&key, 1);
    let verified = node.verify_package(&bytes).await.expect("проверка");
    assert_eq!(verified.manifest.version, 1);
    // Манифест записывает маршрут Admin API (put_package), активация — отдельно.
    cache
        .put_package(&verified.manifest)
        .await
        .expect("манифест");
    let catalog = cache.effective(TenantId::DEFAULT).await.expect("каталог");
    assert!(
        catalog.signals.is_empty(),
        "пакет без активации каталог не меняет"
    );

    // Активация: признаки и версии списков становятся текущими.
    cache.activate(1).await.expect("активация");
    let catalog = cache.effective(TenantId::DEFAULT).await.expect("каталог");
    assert_eq!(catalog.signals.len(), 2);
    let environ =
        super::NodeEnviron::for_lists(Arc::new(blob.clone()) as Arc<dyn BlobStore>, cache.clone());
    let hit = environ
        .list_contains(
            TenantId::DEFAULT,
            &ListId::new("bad-domains").expect("id"),
            tp_smtp::risk::ListValue::Domain("phish.example"),
        )
        .await
        .expect("поиск");
    assert!(hit, "содержимое списка пакета — в BLOB и в текущей версии");

    // Повторная загрузка той же версии: проверка узла проходит, а запись манифеста (её делает
    // маршрут Admin API) отказывает — «номер не растёт», активный пакет не меняется.
    let verified = node.verify_package(&bytes).await.expect("проверка");
    let err = cache
        .put_package(&verified.manifest)
        .await
        .expect_err("повтор v1");
    assert!(err.to_string().contains("не растёт"), "{err}");
    let catalog = cache.effective(TenantId::DEFAULT).await.expect("каталог");
    assert_eq!(catalog.signals.len(), 2, "активный пакет не изменился");
}
