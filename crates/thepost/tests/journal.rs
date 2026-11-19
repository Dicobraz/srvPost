//! Включение журнала в узле (APP-84, SRS 4.9): секция `journal` (APP-83) выключена — доставка без
//! изменений, этапа конвейера нет (записей нет и при заданном правиле); включена — этап конвейера
//! (SMTP-53, `Delivery::with_journal`) пишет запись по правилу Both на организацию: индекс
//! (`journal.entries`, META-88) и бакет хранилища записей (BLOB-18), конверт записи — полный
//! (скрытый получатель конверта и члены группы рассылки раскрыты). Узел профиля SMB
//! (`deploy/config/all.yaml`) против PostgreSQL. Без `TEST_DATABASE_URL` тесты пропускаются.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tp_contracts::delivery::{DeliveryEventKind, DeliveryLog, DeliveryQuery};
use tp_contracts::groups::{DistributionGroup, GroupMember, GroupStore, SenderRestriction};
use tp_contracts::ids::DomainId;
use tp_contracts::journal::{
    JournalAudit, JournalDirection, JournalQuery, JournalRule, JournalScope, JournalStore,
};
use tp_contracts::meta::{AccountKind, AccountStore, AccountUpsert};
use tp_contracts::role::CancellationToken;
use tp_contracts::secrets::{SecretRef, SecretStore};
use tp_contracts::transport::{AcceptedDomain, DomainKind, TransportStore};
use tp_contracts::{AccountId, TenantId};
use tp_meta::{MetaConfig, PgMeta};
use tp_testkit::{MemJournalRecords, MemSecretStore};

use thepost::serve::{Running, ServeOptions, start};

/// Предел ожидания каждого шага (запись журнала, доставка).
const WAIT: Duration = Duration::from_secs(30);

fn testdata(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/testdata")
        .join(name)
}

/// Хранилище секретов узла теста: пароль СУБД и ключ TLS (ссылки по умолчанию).
fn node_secrets(password: Option<String>) -> Arc<MemSecretStore> {
    let secrets = Arc::new(MemSecretStore::default());
    let db: SecretRef = "thepost/db#password".parse().expect("ref");
    secrets.set(&db, password.unwrap_or_else(|| "unused".to_owned()));
    let key: SecretRef = "thepost/tls#key".parse().expect("ref");
    secrets.set(
        &key,
        std::fs::read_to_string(testdata("key.pem")).expect("key.pem"),
    );
    secrets
}

/// Адрес без `sslmode` — открытый канал (профиль dev).
fn dev_url(url: &str) -> String {
    if url.contains("sslmode=") {
        return url.to_owned();
    }
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}sslmode=disable")
}

/// Адрес без пароля и пароль из `user:password@` (без `%XX` — для адреса CI достаточно).
fn split_password(url: &str) -> (String, Option<String>) {
    let Some((scheme, rest)) = url.split_once("://") else {
        return (url.to_owned(), None);
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    match authority.rsplit_once('@') {
        Some((userinfo, host)) => match userinfo.split_once(':') {
            Some((user, password)) => (
                format!("{scheme}://{user}@{host}{tail}"),
                Some(password.to_owned()),
            ),
            None => (url.to_owned(), None),
        },
        None => (url.to_owned(), None),
    }
}

/// Пресет `preset` с секциями теста `own`: секции верхнего уровня, которые задаёт тест, и секции `drop`
/// вырезаются из пресета целиком, поэтому новая секция пресета не даёт повторяющегося ключа.
fn with_sections(preset: &str, own: &str, drop: &[&str]) -> String {
    let top = |line: &str| !line.starts_with([' ', '\t', '#']) && !line.trim().is_empty();
    let names: Vec<&str> = own
        .lines()
        .filter(|l| top(l))
        .filter_map(|l| l.split_once(':').map(|(name, _)| name))
        .chain(drop.iter().copied())
        .collect();
    let mut out = String::new();
    let mut skip = false;
    for line in preset.lines() {
        if top(line) {
            skip = names
                .iter()
                .any(|n| line.strip_prefix(n).is_some_and(|r| r.starts_with(':')));
        }
        if !skip || line.starts_with('#') {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str(own);
    out
}

/// Конфигурация SMB-профиля из поставки с адресами теста: PostgreSQL, каталоги BLOB и индексов,
/// слушатели на `127.0.0.1:0`, тестовый сертификат. `journal: true` — секция журнала включена с
/// локальным каталогом записей (профиль SMB); `false` — секция пресета как есть (умолчание:
/// выключено).
fn config(dir: &Path, db_url: &str, domain: &str, node: &str, journal: bool) -> String {
    let all = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/config/all.yaml"),
    )
    .expect("deploy/config/all.yaml");
    let path = |p: PathBuf| p.display().to_string().replace('\\', "/");
    let journal_section = if journal {
        format!(
            "journal:\n  enabled: true\n  local:\n    dir: \"{}\"\n",
            path(dir.join("journal"))
        )
    } else {
        String::new()
    };
    let own = format!(
        "domain: {domain}
profile: dev
database:
  url: \"{db_url}\"
  password: {{ secret: \"thepost/db#password\" }}
  tls: {{ allow_plaintext: true }}
blob:
  url: file://{blob}
service_http:
  listen: 127.0.0.1:0
  allow_plaintext: true
tls:
  cert_file: \"{cert}\"
meta:
  events:
    node_ttl: 3s
cluster:
  node_id: {node}-{pid}
runtime:
  drain_deadline: 5s
admin:
  init:
    socket: \"{socket}\"
smtp:
  hostname: localhost
  inbound:
    - {{ listen: \"127.0.0.1:0\" }}
imap:
  listeners:
    - {{ listen: \"127.0.0.1:0\", implicit_tls: true }}
sieve:
  managesieve:
    listen:
      - {{ listen: \"127.0.0.1:0\" }}
http:
  jmap: {{ listen: \"127.0.0.1:0\", allow_plaintext: true }}
search:
  index:
    dir: \"{index}\"
  indexer:
    commit_interval: 100ms
{journal_section}",
        blob = path(dir.join("blob")),
        cert = path(testdata("cert.pem")),
        index = path(dir.join("index")),
        socket = path(dir.join("admin.sock")),
        pid = std::process::id(),
    );
    let drop = if journal {
        vec!["secrets", "journal"]
    } else {
        vec!["secrets"]
    };
    let text = with_sections(&all, &own, &drop);
    assert!(text.contains("roles: [all]"), "{text}");
    if journal {
        assert!(text.contains("enabled: true"), "{text}");
    }
    text
}

/// Отдельная база для теста: состав кластера и разделы журнала событий — только узла теста.
async fn create_database(url: &str, prefix: &str) -> (String, String) {
    let name = format!("{prefix}_{}", DomainId::new().as_uuid().simple());
    let admin = sqlx::PgPool::connect(url).await.expect("admin pool");
    sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
        .execute(&admin)
        .await
        .expect("create database");
    admin.close().await;
    let (head, query) = match url.split_once('?') {
        Some((h, q)) => (h, format!("?{q}")),
        None => (url, String::new()),
    };
    let scheme_end = head.find("://").map_or(0, |i| i + 3);
    let base = match head[scheme_end..].find('/') {
        Some(i) => &head[..scheme_end + i],
        None => head,
    };
    (name.clone(), format!("{base}/{name}{query}"))
}

async fn drop_database(url: &str, name: &str) {
    if let Ok(admin) = sqlx::PgPool::connect(url).await {
        let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"
        )))
        .execute(&admin)
        .await;
        admin.close().await;
    }
}

/// Пул `tp-meta` к базе теста без учёта ожидания соединения (наблюдатель-пустышка).
async fn db_pool(url: &str) -> tp_meta::pool::DbPool {
    let pool = sqlx::PgPool::connect(url).await.expect("pool");
    tp_meta::pool::DbPool::new(pool, Arc::new(tp_meta::pool::NoAcquireObserver))
}

/// Адрес слушателя роли.
fn addr(running: &Running, role: &str) -> std::net::SocketAddr {
    *running
        .listeners
        .get(role)
        .first()
        .unwrap_or_else(|| panic!("роль {role} не открыла слушатель"))
}

/// Строки ответа SMTP до последней (`NNN ` без дефиса); возвращает код.
async fn smtp_reply<S: AsyncRead + Unpin>(s: &mut S) -> u16 {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        s.read_exact(&mut byte).await.expect("smtp read");
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            let line = String::from_utf8_lossy(&buf).into_owned();
            buf.clear();
            if line.len() >= 4 && line.as_bytes()[3] == b' ' {
                return line[..3].parse().expect("code");
            }
        }
    }
}

async fn smtp_cmd<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, cmd: &str) -> u16 {
    s.write_all(format!("{cmd}\r\n").as_bytes())
        .await
        .expect("smtp write");
    s.flush().await.expect("smtp flush");
    smtp_reply(s).await
}

/// Приём smtp-in: письмо от `from` получателям `rcpts` (скрытый получатель — в конверте, не в
/// заголовках). Возвращает код ответа на `DATA` (сбой этапа журнала — временный отказ `4xx`).
async fn smtp_send(addr: std::net::SocketAddr, from: &str, rcpts: &[&str], message: &str) -> u16 {
    let mut s = TcpStream::connect(addr).await.expect("smtp connect");
    assert_eq!(smtp_reply(&mut s).await, 220);
    assert_eq!(smtp_cmd(&mut s, "EHLO client.test").await, 250);
    assert_eq!(smtp_cmd(&mut s, &format!("MAIL FROM:<{from}>")).await, 250);
    for rcpt in rcpts {
        assert_eq!(smtp_cmd(&mut s, &format!("RCPT TO:<{rcpt}>")).await, 250);
    }
    assert_eq!(smtp_cmd(&mut s, "DATA").await, 354);
    s.write_all(message.replace('\n', "\r\n").as_bytes())
        .await
        .expect("data");
    let code = smtp_cmd(&mut s, "\r\n.").await;
    assert_eq!(smtp_cmd(&mut s, "QUIT").await, 221);
    code
}

/// Узел теста: база, конфиг, запуск; остановка — [`Node::stop`], база удаляется тестом.
struct Node {
    /// Адрес базы узла (для очистки).
    url_db: String,
    /// Имя базы узла.
    db_name: String,
    shutdown: CancellationToken,
    running: Running,
    meta: PgMeta,
    /// Каталог узла (BLOB, индексы, журнал) — жив, пока узел.
    _dir: tempfile::TempDir,
    /// Путь config.yaml (хранилище записей открывается по секции).
    config_path: PathBuf,
}

impl Node {
    /// Узел с включённым (`journal: true`) или выключенным журналом; `url` — адрес сервера тестов
    /// (профиль dev, без `sslmode`).
    async fn start(url: &str, journal: bool, prefix: &str) -> Self {
        let (db_name, url_db) = create_database(url, prefix).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (db_url, password) = split_password(&url_db);
        let secrets = node_secrets(password);
        let domain = "journal.test";
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, config(dir.path(), &db_url, domain, prefix, journal))
            .expect("config");
        let shutdown = CancellationToken::new();
        let running = start(ServeOptions {
            config: path.clone(),
            secrets: Some(secrets.clone() as Arc<dyn SecretStore>),
            telemetry: false,
            shutdown: shutdown.clone(),
            modules: thepost::modules::BUILTIN,
        })
        .await
        .expect("start");
        let until = tokio::time::Instant::now() + WAIT;
        while !running.health.is_ready() {
            assert!(
                tokio::time::Instant::now() < until,
                "не дождались: узел готов"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let meta = PgMeta::new(db_pool(&url_db).await, MetaConfig::default());
        Self {
            url_db,
            db_name,
            shutdown,
            running,
            meta,
            _dir: dir,
            config_path: path,
        }
    }

    /// Остановка узла: роли завершаются без отказов (как e2e).
    async fn stop(self) {
        let Node {
            shutdown, running, ..
        } = self;
        shutdown.cancel();
        let report = running.wait().await.expect("report");
        assert!(report.failed.is_empty(), "{report:?}");
    }

    /// Принятый домен организации (как `thepost admin domain add`) и учётные записи `logins`.
    async fn accounts(&self, domain: &str, logins: &[&str]) {
        let tenant = TenantId::DEFAULT;
        let id = DomainId::new();
        let version = TransportStore::cluster(&self.meta)
            .await
            .expect("transport")
            .version;
        self.meta
            .put_domain(
                version,
                &AcceptedDomain {
                    id,
                    tenant,
                    name: domain.to_owned(),
                    kind: DomainKind::Authoritative,
                },
            )
            .await
            .expect("accepted domain");
        for login in logins {
            self.meta
                .upsert(
                    tenant,
                    AccountUpsert {
                        domain: id,
                        login: (*login).to_owned(),
                        display_name: login.split('@').next().unwrap_or("user").to_owned(),
                        external_id: None,
                        enabled: true,
                        aliases: Vec::new(),
                        kind: AccountKind::User,
                        hidden_from_gal: false,
                        resource_type: None,
                    },
                )
                .await
                .expect("account");
        }
    }

    /// Идентификатор учётной записи по адресу входа.
    async fn account_id(&self, login: &str) -> AccountId {
        self.meta
            .by_login(TenantId::DEFAULT, login)
            .await
            .expect("by_login")
            .expect("учётная запись")
            .id
    }

    /// Группа рассылки с адресом `address` и участниками `members`.
    async fn group(&self, address: &str, members: &[AccountId]) {
        let group = DistributionGroup {
            id: tp_contracts::GroupId::new(),
            tenant: TenantId::DEFAULT,
            name: address.split('@').next().unwrap_or("team").to_owned(),
            address: Some(address.to_owned()),
            external_id: None,
            members: members.iter().map(|a| GroupMember::Account(*a)).collect(),
            senders: SenderRestriction::Anyone,
            moderators: Vec::new(),
            hidden_from_gal: false,
        };
        group.validate().expect("group");
        self.meta.put(group).await.expect("put group");
    }

    /// Индекс журнала без хранилища записей (правила, поиск, проверка цепочки — только PostgreSQL);
    /// выгрузка и восстановление — [`Node::journal_index`].
    fn mem_index(&self) -> tp_meta::journal::PgJournal {
        tp_meta::journal::PgJournal::new(self.meta.clone(), Arc::new(MemJournalRecords::new()))
    }

    /// Правило журналирования Both на организацию (как Admin API): чтение — на каждое письмо.
    async fn journal_rule(&self, id: &str) {
        let rule = JournalRule {
            id: id.to_owned(),
            tenant: TenantId::DEFAULT,
            scope: JournalScope::Org,
            direction: JournalDirection::Both,
            enabled: true,
        };
        self.mem_index().set_rule(&rule).await.expect("set rule");
    }

    /// Хранилище записей журнала над каталогом секции (второй экземпляр — как у doctor).
    async fn journal_records(&self) -> Arc<tp_blob::JournalRecords> {
        let cfg = thepost::sections::registry()
            .expect("registry")
            .load(&self.config_path)
            .expect("load config");
        let section = (*cfg
            .section::<thepost::sections::JournalSection>(thepost::sections::JOURNAL)
            .expect("journal"))
        .clone();
        thepost::infra::open_journal_records(&cfg, &section, None)
            .await
            .expect("journal records")
    }

    /// Индекс журнала над портом узла ([`thepost::journal::NodeRecords`]): выгрузка читает бакет,
    /// восстановление пересобирает индекс из `scan`.
    async fn journal_index(&self) -> tp_meta::journal::PgJournal {
        tp_meta::journal::PgJournal::new(
            self.meta.clone(),
            Arc::new(thepost::journal::NodeRecords::new(
                self.journal_records().await,
                self.meta.pool().clone(),
            )),
        )
    }

    /// События доставки письма `message_id`: приём и доставки в ящики.
    async fn delivered(&self, message_id: &str) -> Vec<DeliveryEventKind> {
        let query = DeliveryQuery {
            message_id: Some(message_id.to_owned()),
            ..DeliveryQuery::all(10)
        };
        DeliveryLog::search(&self.meta, TenantId::DEFAULT, &query)
            .await
            .expect("delivery log")
            .events
            .iter()
            .map(|e| e.kind)
            .collect()
    }
}

/// Секция `journal` выключена (умолчание пресета): доставка без изменений — этапа конвейера нет,
/// правилу Both на организацию нечего писать (записей индекса нет).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn disabled_section_leaves_delivery_without_journal() {
    let Some(url) = tp_testkit::pg_url() else {
        eprintln!("TEST_DATABASE_URL не задан — тест пропущен");
        return;
    };
    let url = dev_url(&url);
    let node = Node::start(&url, false, "journaloff").await;
    node.accounts("journal.test", &["alice@journal.test"]).await;
    node.journal_rule("r-0042").await;

    // Письмо доставляется как всегда: приём и доставка в ящик — в журнале доставки.
    let message = "From: Bob <bob@sender.test>\nTo: alice@journal.test\n\
                   Subject: journal off\nMessage-ID: <journal-off@sender.test>\n\nbody\n";
    assert_eq!(
        smtp_send(
            addr(&node.running, "smtp-in"),
            "bob@sender.test",
            &["alice@journal.test"],
            message,
        )
        .await,
        250,
        "письмо не принято"
    );
    let until = tokio::time::Instant::now() + WAIT;
    loop {
        let kinds = node.delivered("journal-off@sender.test").await;
        if kinds.contains(&DeliveryEventKind::Receive)
            && kinds.contains(&DeliveryEventKind::Deliver)
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "не дождались: доставка в ящик"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Этапа нет: правило задано, записей индекса не появилось.
    let page = node
        .mem_index()
        .search(
            &JournalAudit::grant(),
            &JournalQuery::all(TenantId::DEFAULT, 10),
        )
        .await
        .expect("search");
    assert!(page.entries.is_empty(), "{page:?}");

    let (url_db, db_name) = (node.url_db.clone(), node.db_name.clone());
    node.stop().await;
    drop_database(&url_db, &db_name).await;
}

/// Секция `journal` включена с правилом Both на организацию: письмо (входящее) записывается — индекс и
/// бакет; конверт записи полный: скрытый получатель конверта (Bcc) и члены группы рассылки раскрыты;
/// доставка в ящики не меняется. Выгрузка записи — .eml с конвертом (порт `read`), восстановление
/// индекса — из `scan` хранилища записей.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enabled_section_journals_full_envelope() {
    let Some(url) = tp_testkit::pg_url() else {
        eprintln!("TEST_DATABASE_URL не задан — тест пропущен");
        return;
    };
    let url = dev_url(&url);
    let node = Node::start(&url, true, "journalon").await;
    node.accounts(
        "journal.test",
        &[
            "alice@journal.test",
            "carol@journal.test",
            "dave@journal.test",
        ],
    )
    .await;
    let (carol, dave) = (
        node.account_id("carol@journal.test").await,
        node.account_id("dave@journal.test").await,
    );
    // Группа team@ (carol, dave) — получатель-адрес конверта; carol — скрытый получатель (Bcc):
    // в заголовках письма — только alice.
    node.group("team@journal.test", &[carol, dave]).await;
    node.journal_rule("r-0042").await;

    let message = "From: Bob <bob@sender.test>\nTo: alice@journal.test\n\
                   Subject: journal on\nMessage-ID: <journal-on@sender.test>\n\nbody\n";
    assert_eq!(
        smtp_send(
            addr(&node.running, "smtp-in"),
            "bob@sender.test",
            &[
                "alice@journal.test",
                "carol@journal.test",
                "team@journal.test"
            ],
            message,
        )
        .await,
        250,
        "письмо не принято (сбой этапа журнала — временный отказ)"
    );

    // Запись появилась: индекс (journal.entries) с полным конвертом.
    let cap = JournalAudit::grant();
    let index = node.journal_index().await;
    let entries = {
        let until = tokio::time::Instant::now() + WAIT;
        loop {
            let page = index
                .search(&cap, &JournalQuery::all(TenantId::DEFAULT, 10))
                .await
                .expect("search");
            if !page.entries.is_empty() {
                break page.entries;
            }
            assert!(
                tokio::time::Instant::now() < until,
                "не дождались: запись журнала"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };
    assert_eq!(entries.len(), 1, "одна запись на письмо: {entries:?}");
    let record = &entries[0].record;
    assert_eq!(record.sender, "bob@sender.test");
    assert_eq!(record.message_id.as_deref(), Some("journal-on@sender.test"));
    assert_eq!(record.rule, "r-0042");
    for address in [
        "alice@journal.test",
        "carol@journal.test",
        "team@journal.test",
        "dave@journal.test",
    ] {
        assert!(
            record
                .recipients
                .iter()
                .any(|r| r.eq_ignore_ascii_case(address)),
            "{address} в конверте записи (скрытый получатель и члены группы раскрыты): {:?}",
            record.recipients
        );
    }

    // Бакет хранилища записей: письмо целиком, цепочки целостны (индекс и хранилище).
    let records = node.journal_records().await;
    let chain = records.chain(TenantId::DEFAULT).await.expect("chain");
    assert_eq!(chain.len(), 1, "запись в бакете");
    let stored = records
        .message(TenantId::DEFAULT, entries[0].id)
        .await
        .expect("message");
    assert!(
        String::from_utf8_lossy(&stored).contains("Subject: journal on"),
        "письмо целиком"
    );
    let report = index
        .verify_chain(&cap, TenantId::DEFAULT)
        .await
        .expect("chain");
    assert!(report.ok && report.records == 1, "{report:?}");
    let storage = records.verify(TenantId::DEFAULT).await.expect("verify");
    assert!(storage.ok && storage.records == 1, "{storage:?}");

    // Выгрузка записи: .eml с конвертом (X-ThePost-Journal-*) — чтение по порту из бакета.
    let eml = index
        .export(&cap, TenantId::DEFAULT, entries[0].id)
        .await
        .expect("export");
    let text = String::from_utf8_lossy(&eml);
    assert!(text.contains("X-ThePost-Journal-Sender: bob@sender.test\r\n"));
    for address in [
        "alice@journal.test",
        "carol@journal.test",
        "team@journal.test",
        "dave@journal.test",
    ] {
        assert!(
            text.contains(&format!("X-ThePost-Journal-Recipient: {address}\r\n")),
            "{address} в конверте выгрузки"
        );
    }
    assert!(text.contains("X-ThePost-Journal-Rule: r-0042\r\n"));
    assert!(text.contains("Subject: journal on"));

    // Восстановление индекса из хранилища записей (порт `scan`): индекс цел — число записей то же.
    assert_eq!(
        index
            .restore_index(TenantId::DEFAULT)
            .await
            .expect("restore"),
        1
    );

    // Доставка в ящики не изменилась: alice, carol (скрытый получатель) и члены группы.
    let until = tokio::time::Instant::now() + WAIT;
    loop {
        let kinds = node.delivered("journal-on@sender.test").await;
        if kinds
            .iter()
            .filter(|k| **k == DeliveryEventKind::Deliver)
            .count()
            >= 3
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "не дождались: доставка в ящики"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let (url_db, db_name) = (node.url_db.clone(), node.db_name.clone());
    node.stop().await;
    drop_database(&url_db, &db_name).await;
}
