//! Детекторы каталога признаков и балл письма (SMTP-52, приёмка карточки): архивы с шифрованием,
//! образы и ярлыки под чужим расширением, домены ссылок и память беседы, `Reply-To`, списки TI,
//! устаревший источник и сигналы Sieve.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sha2::Digest;
use time::OffsetDateTime;
use tp_contracts::ids::{AccountId, TenantId};
use tp_contracts::risk::{
    Detector, Field, ListId, Mode, Origin, PACKAGE_FORMAT, PackageManifest, RiskAction, RiskStore,
    Semver, Signal, SignalId, SourceId, StaleAction,
};
use tp_contracts::thread::ThreadFacts;

use super::*;
use crate::config::RiskConfig;
use tp_testkit::{MemRisk, SystemClock};

/// MIME-письмо с вложением `payload` (base64) и именем `name`.
fn mime_with_attachment(name: &str, payload: &[u8]) -> Vec<u8> {
    use base64::Engine;
    format!(
        "From: alice@example.net\r\nSubject: x\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
         --b\r\n\
         Content-Type: application/octet-stream; name=\"{name}\"\r\n\
         Content-Disposition: attachment; filename=\"{name}\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n\
         --b--\r\n",
        base64::engine::general_purpose::STANDARD.encode(payload)
    )
    .into_bytes()
}

/// ZIP-архив в памяти с записью `name` и содержимым `data` (deflate).
fn zip_bytes(name: &str, data: &[u8]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    w.start_file(name, zip::write::SimpleFileOptions::default())
        .expect("start");
    w.write_all(data).expect("write");
    w.finish().expect("finish").into_inner()
}

/// ZIP с общим битом шифрования (запись «защищена паролем»): флаг в локальном заголовке и каталоге.
fn encrypted_zip(name: &str, data: &[u8]) -> Vec<u8> {
    let mut raw = zip_bytes(name, data);
    for i in 0..raw.len().saturating_sub(4) {
        // Локальный заголовок `PK\x03\x04` — флаг со смещением 6; каталог `PK\x01\x02` — со смещением 8.
        if raw[i..i + 4] == *b"PK\x03\x04" {
            raw[i + 6] |= 1;
        } else if raw[i..i + 4] == *b"PK\x01\x02" {
            raw[i + 8] |= 1;
        }
    }
    raw
}

/// 7z-архив: сигнатура, стартовый заголовок и байт вида заголовка (`0x17` — `kEncodedHeader`).
fn seven_zip(header_byte: u8) -> Vec<u8> {
    let mut raw = vec![
        0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, // сигнатура
        0x00, 0x04, // версия
        0, 0, 0, 0, // StartHeaderCRC
        0, 0, 0, 0, 0, 0, 0, 0, // NextHeaderOffset
        0, 0, 0, 0, 0, 0, 0, 0, // NextHeaderSize
        0, 0, 0, 0, // NextHeaderCRC
    ];
    raw.push(header_byte);
    raw
}

/// RAR 5: сигнатура и первый заголовок типа `header_type` (5 — шифрование архива).
fn rar5(header_type: u8) -> Vec<u8> {
    let mut raw = b"Rar!\x1A\x07\x01\x00".to_vec();
    raw.extend_from_slice(&[0, 0, 0, 0]); // CRC32 заголовка
    raw.push(0x07); // размер заголовка (vint)
    raw.push(header_type); // тип (vint)
    raw
}

/// Public Suffix List из строки теста.
fn psl(text: &str) -> publicsuffix::List {
    publicsuffix::List::from_bytes(text.as_bytes()).expect("psl")
}

#[test]
fn zip_encryption_flag() {
    let plain = scan_message(
        &mime_with_attachment("doc.zip", &zip_bytes("a.txt", b"hello")),
        &RiskConfig::default(),
    );
    assert!(!plain.encrypted_archive);
    assert_eq!(plain.attachment_types, ["application/zip"]);
    let encrypted = scan_message(
        &mime_with_attachment("doc.zip", &encrypted_zip("a.txt", b"secret")),
        &RiskConfig::default(),
    );
    assert!(encrypted.encrypted_archive);
    // Записи зашифрованного архива не читаются — тип записей не собирается.
    assert_eq!(encrypted.attachment_types, ["application/zip"]);
}

#[test]
fn zip_nested_attachments() {
    // PDF внутри ZIP: тип по содержимому, с учётом вложенности.
    let pdf = b"%PDF-1.4 test".to_vec();
    let inner = zip_bytes("report.pdf", &pdf);
    let found = scan_message(
        &mime_with_attachment("outer.zip", &inner),
        &RiskConfig::default(),
    );
    assert!(
        found
            .attachment_types
            .contains(&"application/pdf".to_owned())
    );
    // Хэш вложения верхнего уровня — для списков TI.
    assert_eq!(found.attachment_hashes.len(), 1);
}

#[test]
fn seven_zip_encrypted_header() {
    let plain = scan_message(
        &mime_with_attachment("a.7z", &seven_zip(0x01)),
        &RiskConfig::default(),
    );
    assert!(!plain.encrypted_archive);
    let encrypted = scan_message(
        &mime_with_attachment("a.7z", &seven_zip(0x17)),
        &RiskConfig::default(),
    );
    assert!(encrypted.encrypted_archive);
}

#[test]
fn rar5_encryption_header() {
    let plain = scan_message(
        &mime_with_attachment("a.rar", &rar5(0x01)),
        &RiskConfig::default(),
    );
    assert!(!plain.encrypted_archive);
    let encrypted = scan_message(
        &mime_with_attachment("a.rar", &rar5(0x05)),
        &RiskConfig::default(),
    );
    assert!(encrypted.encrypted_archive);
}

/// Приёмка: ISO и LNK под чужим расширением — детектор по сигнатуре, не по имени.
#[test]
fn disk_image_and_shortcut_by_signature() {
    // ISO 9660 под именем .txt.
    let mut iso = vec![0u8; 0x8018];
    iso[0x8001..0x8006].copy_from_slice(b"CD001");
    let found = scan_message(
        &mime_with_attachment("report.txt", &iso),
        &RiskConfig::default(),
    );
    assert!(found.disk_image);
    // Ярлык Windows под именем .jpg.
    let lnk = [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];
    let found = scan_message(
        &mime_with_attachment("photo.jpg", &lnk),
        &RiskConfig::default(),
    );
    assert!(found.disk_image);
    // VHD — подпись `conectix` в последнем секторе.
    let mut vhd = vec![0u8; 1024];
    vhd[512..520].copy_from_slice(b"conectix");
    let found = scan_message(
        &mime_with_attachment("disk.dat", &vhd),
        &RiskConfig::default(),
    );
    assert!(found.disk_image);
    // VHDX — подпись в начале.
    let found = scan_message(
        &mime_with_attachment("disk.dat", b"vhdxfile\x00\x00\x00\x00\x00\x00\x00\x00"),
        &RiskConfig::default(),
    );
    assert!(found.disk_image);
    // По расширению без сигнатуры (первые байты не в памяти узла — разбор не обязателен).
    let found = scan_message(
        &mime_with_attachment("image.iso", b"junk"),
        &RiskConfig::default(),
    );
    assert!(found.disk_image);
    // Обычный текст — не образ.
    let found = scan_message(
        &mime_with_attachment("notes.txt", b"plain"),
        &RiskConfig::default(),
    );
    assert!(!found.disk_image);
}

/// Приёмка: ссылка `a.b.example.co.uk` при беседе с `example.co.uk` — не новая; при беседе с другим
/// доменом — новая (регистрируемый домен по Public Suffix List).
#[test]
fn link_domains_by_psl() {
    let psl = psl("co.uk\n");
    let with_html = b"From: alice@example.net\r\nSubject: x\r\n\r\n\
        see https://a.b.example.co.uk/login and https://old.example/x\r\n"
        .to_vec();
    let found = scan_message(&with_html, &RiskConfig::default());
    assert_eq!(
        found.link_hosts,
        ["a.b.example.co.uk", "old.example"],
        "хосты без порта и учётных данных"
    );
    assert_eq!(
        found.registrable_domains(&psl),
        ["example.co.uk", "old.example"]
    );
    // Память беседы с example.co.uk — новая ссылка есть (old.example), сам домен не нов.
    let memory = ThreadFacts {
        link_domains: vec!["example.co.uk".into()],
        ..ThreadFacts::new()
    };
    assert!(found.new_link_domain(&memory, &psl));
    // Память с обоими доменами — нового нет.
    let memory = ThreadFacts {
        link_domains: vec!["example.co.uk".into(), "old.example".into()],
        ..ThreadFacts::new()
    };
    assert!(!found.new_link_domain(&memory, &psl));
    // Пустая память — базы сравнения нет, детектор молчит.
    assert!(!found.new_link_domain(&ThreadFacts::new(), &psl));
    // Регистрируемый домен `a.b.example.co.uk` — `example.co.uk` (co.uk — суффикс).
    assert_eq!(
        psl.domain(b"a.b.example.co.uk")
            .map(|d| String::from_utf8_lossy(d.as_bytes()).into_owned()),
        Some("example.co.uk".to_owned())
    );
}

/// Приёмка: `Reply-To` сменился — не совпадает с `From` и прежним `Reply-To` беседы.
#[test]
fn reply_to_changed() {
    let raw =
        b"From: Alice <alice@example.net>\r\nReply-To: evil@example.org\r\nSubject: x\r\n\r\nbody"
            .to_vec();
    let found = scan_message(&raw, &RiskConfig::default());
    assert_eq!(found.reply_to, ["evil@example.org"]);
    assert_eq!(found.from.as_deref(), Some("alice@example.net"));
    assert_eq!(found.from_domain.as_deref(), Some("example.net"));
    // Прежний Reply-To беседы — другой адрес: смена.
    let memory = ThreadFacts {
        reply_to: vec!["old@example.net".into()],
        ..ThreadFacts::new()
    };
    assert!(found.reply_to_changed(&memory));
    // Reply-To совпадает с From — не смена.
    let same = b"From: alice@example.net\r\nReply-To: alice@example.net\r\n\r\nx".to_vec();
    let found = scan_message(&same, &RiskConfig::default());
    assert!(!found.reply_to_changed(&memory));
    // Прежний Reply-To совпадает — не смена.
    let memory = ThreadFacts {
        reply_to: vec!["evil@example.org".into()],
        ..ThreadFacts::new()
    };
    let found = scan_message(&raw, &RiskConfig::default());
    assert!(!found.reply_to_changed(&memory));
    // Пустая память — смены не было.
    assert!(!found.reply_to_changed(&ThreadFacts::new()));
}

/// Новый для беседы тип вложения: пустая память молчит, знакомый тип — нет, новый — да.
#[test]
fn thread_new_attachment_type() {
    let found = scan_message(
        &mime_with_attachment("a.zip", &zip_bytes("a.txt", b"x")),
        &RiskConfig::default(),
    );
    assert_eq!(found.attachment_types, ["application/zip"]);
    assert!(
        !found.new_attachment_type(&ThreadFacts::new()),
        "пустая память"
    );
    let memory = ThreadFacts {
        attachments: vec!["application/pdf".into()],
        ..ThreadFacts::new()
    };
    assert!(found.new_attachment_type(&memory));
    let memory = ThreadFacts {
        attachments: vec!["application/zip".into()],
        ..ThreadFacts::new()
    };
    assert!(!found.new_attachment_type(&memory));
}

/// Ключи присоединения: Message-ID, In-Reply-To, References — без угловых скобок, без повторов.
#[test]
fn thread_keys_of_message() {
    let raw = b"Message-ID: <m1@example.net>\r\nIn-Reply-To: <m0@example.net>\r\n\
         References: <m0@example.net> <m00@example.net>\r\n\r\nx"
        .to_vec();
    assert_eq!(
        thread_keys(&raw),
        ["m1@example.net", "m0@example.net", "m00@example.net"]
    );
}

/// Хосты URL: без схемы, пути, порта и учётных данных.
#[test]
fn url_hosts() {
    assert_eq!(
        url_host("https://User:pw@Host.example.org:8443/path?q=1"),
        Some("host.example.org".to_owned())
    );
    assert_eq!(
        url_host("http://[2001:db8::1]:8080/x"),
        Some("2001:db8::1".to_owned())
    );
    assert_eq!(url_host("mailto:a@b"), None);
}

/// Признак каталога `id` с детектором `detector` (пакет поставщика).
fn signal(id: &str, detector: Detector, weight: u16, mode: Mode) -> Signal {
    Signal {
        id: SignalId::new(id).expect("id"),
        detector,
        weight,
        threshold: 0,
        action: RiskAction::None,
        mode,
        origin: Origin::Vendor,
        since: OffsetDateTime::UNIX_EPOCH,
    }
}

/// Данные узла для детекторов: память бесед по учётным записям, списки TI и PSL.
#[derive(Default)]
struct Environ {
    facts: Mutex<HashMap<AccountId, ThreadFacts>>,
    psl: Mutex<Option<Arc<publicsuffix::List>>>,
    /// Совпадения: (список, значение) — значения полей в строковой форме.
    lists: Mutex<HashSet<(String, String)>>,
}

impl Environ {
    fn with_facts(self, account: AccountId, facts: ThreadFacts) -> Self {
        self.facts.lock().expect("lock").insert(account, facts);
        self
    }

    fn with_psl(self, list: publicsuffix::List) -> Self {
        *self.psl.lock().expect("lock") = Some(Arc::new(list));
        self
    }

    fn with_list(self, list: &str, value: &str) -> Self {
        self.lists
            .lock()
            .expect("lock")
            .insert((list.to_owned(), value.to_owned()));
        self
    }

    fn key(value: &ListValue<'_>) -> String {
        match value {
            ListValue::Ip(ip) => ip.to_string(),
            ListValue::Domain(d) => (*d).to_owned(),
            ListValue::Url(u) => (*u).to_owned(),
            ListValue::Sha256(h) => h.iter().map(|b| format!("{b:02x}")).collect(),
        }
    }
}

#[async_trait]
impl RiskEnviron for Environ {
    async fn thread_facts(
        &self,
        _tenant: TenantId,
        account: AccountId,
        _keys: &[String],
    ) -> tp_contracts::Result<ThreadFacts> {
        Ok(self
            .facts
            .lock()
            .expect("lock")
            .get(&account)
            .cloned()
            .unwrap_or_default())
    }

    async fn list_contains(
        &self,
        _tenant: TenantId,
        list: &ListId,
        value: ListValue<'_>,
    ) -> tp_contracts::Result<bool> {
        Ok(self
            .lists
            .lock()
            .expect("lock")
            .contains(&(list.to_string(), Self::key(&value))))
    }

    async fn psl(&self) -> tp_contracts::Result<Option<Arc<publicsuffix::List>>> {
        Ok(self.psl.lock().expect("lock").clone())
    }
}

/// Каталог с признаками `signals` в `MemRisk` (пакет 1 активен) и проверка над `environ`.
async fn risk(signals: Vec<Signal>, environ: Environ) -> (Risk, Arc<MemRisk>) {
    let store = Arc::new(MemRisk::new(Arc::new(SystemClock)));
    store
        .put_package(&PackageManifest {
            format: PACKAGE_FORMAT,
            version: 1,
            created: OffsetDateTime::UNIX_EPOCH,
            min_node: Semver::new(0, 1, 0),
            key_id: "k1".into(),
            signals,
            lists: vec![],
            samples: vec![],
        })
        .await
        .expect("package");
    store.activate(1).await.expect("activate");
    (
        Risk::new(
            RiskConfig::default(),
            store.clone(),
            Arc::new(environ),
            None,
        ),
        store,
    )
}

const PSL_TEXT: &str = "co.uk\n";

/// Приёмка: детектор каталога срабатывает на письме с ISO в доверенной беседе (детектор беседы
/// `disk_image_or_shortcut` — не требует памяти) и не срабатывает на чистом письме.
#[tokio::test]
async fn engine_disk_image_fires_and_records_hits() {
    let tenant = TenantId::DEFAULT;
    let account = AccountId::new();
    let mut iso = vec![0u8; 0x8018];
    iso[0x8001..0x8006].copy_from_slice(b"CD001");
    let raw = mime_with_attachment("report.pdf", &iso);
    let (risk, store) = risk(
        vec![signal(
            "tp.attach.disk_image_or_shortcut",
            Detector::DiskImageOrShortcut,
            3,
            Mode::Enforce,
        )],
        Environ::default(),
    )
    .await;
    let scan = risk
        .scan("192.0.2.1".parse().expect("ip"), &raw, &[(account, tenant)])
        .await;
    assert!(!scan.empty());
    let verdict = scan.verdict_for(tenant);
    assert_eq!(verdict.score, 3);
    assert_eq!(verdict.action, RiskAction::Tag, "балл 3 ≥ порога tag (1)");
    assert!(
        verdict.drops_reply,
        "детектор беседы снимает признак ответа"
    );
    // Срабатывание — в журнале каталога (режим enforce).
    let hits = store
        .hits(tenant, &tp_contracts::risk::HitsQuery::all(10))
        .await
        .expect("hits");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].signal.as_str(), "tp.attach.disk_image_or_shortcut");
    assert_eq!(hits[0].mode, Mode::Enforce);
    assert_eq!(hits[0].strength, 100);
}

/// Приёмка: признак «новый домен» не срабатывает при памяти с `example.co.uk` и срабатывает при
/// другой памяти; признак беседы снимает признак ответа.
#[tokio::test]
async fn engine_link_domain_and_drops_reply() {
    let tenant = TenantId::DEFAULT;
    let account = AccountId::new();
    let raw = b"From: alice@example.net\r\nIn-Reply-To: <m1@example.net>\r\nSubject: x\r\n\r\n\
        see https://a.b.example.co.uk/login\r\n"
        .to_vec();
    let memory = ThreadFacts {
        link_domains: vec!["example.co.uk".into()],
        ..ThreadFacts::new()
    };
    let environ = Environ::default()
        .with_facts(account, memory)
        .with_psl(psl(PSL_TEXT));
    let (risk, _) = risk(
        vec![
            signal(
                "tp.link.new_domain",
                Detector::ThreadNewLinkDomain,
                5,
                Mode::Enforce,
            ),
            signal(
                "tp.reply.new_type",
                Detector::ThreadNewAttachmentType,
                5,
                Mode::Enforce,
            ),
        ],
        environ,
    )
    .await;
    let scan = risk
        .scan("192.0.2.1".parse().expect("ip"), &raw, &[(account, tenant)])
        .await;
    let verdict = scan.verdict_for(tenant);
    // `a.b.example.co.uk` → example.co.uk — не новый; новый тип вложения — памяти вложений нет.
    assert_eq!(verdict.score, 0);
    assert!(!verdict.drops_reply);
    // Та же ссылка при памяти с другим доменом — новый домен: срабатывание, признак ответа снят.
    let memory = ThreadFacts {
        link_domains: vec!["other.example".into()],
        ..ThreadFacts::new()
    };
    let environ = Environ::default()
        .with_facts(account, memory)
        .with_psl(psl(PSL_TEXT));
    let (risk, _) = risk(
        vec![signal(
            "tp.link.new_domain",
            Detector::ThreadNewLinkDomain,
            5,
            Mode::Enforce,
        )],
        environ,
    )
    .await;
    let scan = risk
        .scan("192.0.2.1".parse().expect("ip"), &raw, &[(account, tenant)])
        .await;
    let verdict = scan.verdict_for(tenant);
    assert_eq!(verdict.score, 5);
    assert!(
        verdict.drops_reply,
        "детектор беседы снимает признак ответа"
    );
    // Заголовок X-ThePost-Risk: балл и признак.
    assert_eq!(scan.header_value(), "score=5; signals=tp.link.new_domain");
}

/// Приёмка: признак в режиме «только отчёт» — балл и действие не меняются, срабатывание записано.
#[tokio::test]
async fn engine_report_mode() {
    let tenant = TenantId::DEFAULT;
    let account = AccountId::new();
    let (risk, store) = risk(
        vec![signal(
            "tp.attach.disk_image_or_shortcut",
            Detector::DiskImageOrShortcut,
            100,
            Mode::Report,
        )],
        Environ::default(),
    )
    .await;
    let mut iso = vec![0u8; 0x8018];
    iso[0x8001..0x8006].copy_from_slice(b"CD001");
    let raw = mime_with_attachment("report.pdf", &iso);
    let scan = risk
        .scan("192.0.2.1".parse().expect("ip"), &raw, &[(account, tenant)])
        .await;
    let verdict = scan.verdict_for(tenant);
    assert_eq!(verdict.score, 0, "«только отчёт» — балл не изменился");
    assert_eq!(verdict.action, RiskAction::None);
    assert_eq!(verdict.report_only.len(), 1);
    let hits = store
        .hits(tenant, &tp_contracts::risk::HitsQuery::all(10))
        .await
        .expect("hits");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].mode, Mode::Report);
}

/// Приёмка: совпадение со списком TI (IP, домен From, URL, SHA-256 вложения).
#[tokio::test]
async fn engine_list_match() {
    let tenant = TenantId::DEFAULT;
    let account = AccountId::new();
    let hash: [u8; 32] = sha2::Sha256::digest(b"payload").into();
    let environ = Environ::default()
        .with_list("feodo-ip", "192.0.2.1")
        .with_list("phish-domain", "example.net")
        .with_list("phish-url", "https://a.b.example.co.uk/login")
        .with_list(
            "malware-sha256",
            &hash.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        )
        .with_psl(psl(PSL_TEXT));
    let raw =
        b"From: alice@example.net\r\nSubject: x\r\n\r\nsee https://a.b.example.co.uk/login\r\n"
            .to_vec();
    let (risk, _) = risk(
        vec![
            signal(
                "tp.ti.sender_ip",
                Detector::ListMatch {
                    list: ListId::new("feodo-ip").expect("list"),
                    field: Field::SenderIp,
                },
                4,
                Mode::Enforce,
            ),
            signal(
                "tp.ti.from_domain",
                Detector::ListMatch {
                    list: ListId::new("phish-domain").expect("list"),
                    field: Field::FromDomain,
                },
                4,
                Mode::Enforce,
            ),
            signal(
                "tp.ti.link_domain",
                Detector::ListMatch {
                    list: ListId::new("phish-url").expect("list"),
                    field: Field::LinkDomain,
                },
                4,
                Mode::Enforce,
            ),
            signal(
                "tp.ti.sha256",
                Detector::ListMatch {
                    list: ListId::new("malware-sha256").expect("list"),
                    field: Field::AttachmentSha256,
                },
                4,
                Mode::Enforce,
            ),
        ],
        environ,
    )
    .await;
    // Совпадают IP соединения и домен From; ссылки и хэшей в письме нет.
    let scan = risk
        .scan("192.0.2.1".parse().expect("ip"), &raw, &[(account, tenant)])
        .await;
    let verdict = scan.verdict_for(tenant);
    assert_eq!(verdict.score, 8);
    assert_eq!(verdict.hits.len(), 2);
    // Совпадение по URL ссылки и по SHA-256 вложения (содержимое вложения — `payload`).
    let hash_raw = mime_with_attachment("e.bin", b"payload");
    let environ = Environ::default()
        .with_list("phish-url", "https://a.b.example.co.uk/login")
        .with_list(
            "malware-sha256",
            &hash.iter().map(|b| format!("{b:02x}")).collect::<String>(),
        );
    let (risk, _) = risk(
        vec![
            signal(
                "tp.ti.link_url",
                Detector::ListMatch {
                    list: ListId::new("phish-url").expect("list"),
                    field: Field::LinkUrl,
                },
                4,
                Mode::Enforce,
            ),
            signal(
                "tp.ti.sha256",
                Detector::ListMatch {
                    list: ListId::new("malware-sha256").expect("list"),
                    field: Field::AttachmentSha256,
                },
                4,
                Mode::Enforce,
            ),
        ],
        environ,
    )
    .await;
    let scan = risk
        .scan(
            "192.0.2.9".parse().expect("ip"),
            &hash_raw,
            &[(account, tenant)],
        )
        .await;
    let verdict = scan.verdict_for(tenant);
    assert_eq!(
        verdict.score, 8,
        "и URL ссылки, и SHA-256 вложения в списках"
    );
    let mut ids: Vec<&str> = verdict.hits.iter().map(|h| h.signal.as_str()).collect();
    ids.sort_unstable();
    assert_eq!(ids, ["tp.ti.link_url", "tp.ti.sha256"]);
}

/// Приёмка: устаревший источник с `Reduce { 50 }` — вес признака вдвое меньше.
#[tokio::test]
async fn engine_stale_source_reduces_weight() {
    use tp_contracts::risk::{
        FeedFormat, HttpAuth, License, ListVersion, SourceKind, Tenants, TiOrigin, TiSource, Tier,
    };
    let tenant = TenantId::DEFAULT;
    let account = AccountId::new();
    let (risk, store) = risk(
        vec![signal(
            "tp.ti.sender_ip",
            Detector::ListMatch {
                list: ListId::new("feodo-ip").expect("list"),
                field: Field::SenderIp,
            },
            10,
            Mode::Enforce,
        )],
        Environ::default().with_list("feodo-ip", "192.0.2.1"),
    )
    .await;
    let source = SourceId::new("feodo").expect("source");
    store
        .put_source(&TiSource {
            id: source,
            tier: Tier::CustomerKey,
            kind: SourceKind::Http {
                url: "https://feeds.example/feodo.txt".into(),
            },
            format: FeedFormat::Txt,
            ttl: time::Duration::hours(1),
            stale: StaleAction::Reduce { percent: 50 },
            license: License {
                terms_url: "https://example/license".into(),
                attribution: None,
                commercial: true,
            },
            tenants: Tenants::All,
            key: None,
            auth: HttpAuth::None,
            origin: TiOrigin::Vendor,
        })
        .await
        .expect("source");
    // Версия списка загружена 2 часа назад — старше TTL: источник устарел.
    store
        .put_list_version(&ListVersion {
            list: ListId::new("feodo-ip").expect("list"),
            source: SourceId::new("feodo").expect("source"),
            sha256: tp_contracts::ids::BlobHash([0; 32]),
            blob: "blob".into(),
            entries: 1,
            fetched_at: OffsetDateTime::now_utc() - time::Duration::hours(2),
            tlp: None,
        })
        .await
        .expect("list");
    let raw = b"From: alice@example.net\r\n\r\nx".to_vec();
    let scan = risk
        .scan("192.0.2.1".parse().expect("ip"), &raw, &[(account, tenant)])
        .await;
    let verdict = scan.verdict_for(tenant);
    assert_eq!(
        verdict.score, 5,
        "вес 10 со снижением на 50% — 5 (порог tag)"
    );
    assert_eq!(verdict.action, RiskAction::Tag);
}

/// Признаки команды `signal` скрипта организации (SIEVE-15) прибавляются к баллу с пределом веса.
#[tokio::test]
async fn engine_sieve_signals_with_limit() {
    let tenant = TenantId::DEFAULT;
    let account = AccountId::new();
    let (risk, _) = risk(
        vec![signal(
            "tp.org.custom",
            Detector::ReplyToChanged,
            5,
            Mode::Enforce,
        )],
        Environ::default(),
    )
    .await;
    let mut scan = risk
        .scan(
            "192.0.2.1".parse().expect("ip"),
            b"From: a@b\r\n\r\nx",
            &[(account, tenant)],
        )
        .await;
    assert_eq!(scan.verdict_for(tenant).score, 0);
    let org_rule = SignalId::new("org.custom").expect("id");
    // `signal "org.custom" :weight 3` — вес 3; `signal "tp.org.custom"` — действующий вес каталога (5).
    risk.apply_sieve(
        &mut scan,
        &[
            (org_rule.clone(), Some(3)),
            (SignalId::new("tp.org.custom").expect("id"), None),
        ],
    )
    .await;
    let verdict = scan.verdict_for(tenant);
    assert_eq!(verdict.score, 8);
    assert_eq!(verdict.action, RiskAction::Junk, "балл 8 ≥ порога junk (6)");
    // Предел веса: заданный 100 урезается до `sieve_max_weight` (10).
    risk.apply_sieve(&mut scan, &[(org_rule, Some(100))]).await;
    assert_eq!(scan.verdict_for(tenant).score, 18);
}

/// Каталог без пакета — признаков нет: балл нулевой, действий нет (fail-open).
#[tokio::test]
async fn engine_no_catalog_no_verdict() {
    let tenant = TenantId::DEFAULT;
    let account = AccountId::new();
    let store = Arc::new(MemRisk::new(Arc::new(SystemClock)));
    let risk = Risk::new(
        RiskConfig::default(),
        store,
        Arc::new(Environ::default()),
        None,
    );
    let raw = b"From: alice@example.net\r\n\r\nx".to_vec();
    let scan = risk
        .scan("192.0.2.1".parse().expect("ip"), &raw, &[(account, tenant)])
        .await;
    assert_eq!(scan.action(), RiskAction::None);
    assert!(!scan.has_findings());
    assert_eq!(scan.header_value(), "score=0");
    assert!(!scan.all_reject());
}
