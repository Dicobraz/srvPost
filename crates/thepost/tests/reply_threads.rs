//! Сквозной тест признака «ответ на наше письмо» и бесед в узле (APP-77, решения 125 в–е): узел собирает
//! `SentLog` и `ThreadStore` (`PgMeta`, META-86) и ключи меток из хранилища секретов — и передаёт их доставке
//! SMTP, `MailStore`, JMAP и Admin API; памяти в узле не остаётся.
//!
//! Наше письмо наружу через submission получает метку Message-ID (`tp1.<id>.…`, XChaCha20-Poly1305) и
//! BATV-подпись `MAIL FROM` (`prvs=…`), письмо пишется в запись об отправленном. Bounce на адрес без метки —
//! `550 5.7.1` (`smtp.batv.mode: enforce`). Ответ адресата через доверенный шлюз (`Authentication-Results` с
//! `dmarc=pass`) получает `X-ThePost-Reply` и попадает в беседу исходного письма (привязка приёмом, MS-21;
//! JMAP `threadId` обеих писем — одна беседа); удержание беседы через Admin API переживает перезапуск узла.
//! Ротация ключа метки без перезапуска (перечитанная секция `smtp.reply.keys`): ответ на письмо со старым
//! ключом ещё признаётся, новое письмо метится новым.
//!
//! Без `TEST_DATABASE_URL` тест пропускается.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use futures::TryStreamExt;
use serde_json::{Value, json};
use thepost::serve::{Running, ServeOptions, start};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{self, ClientConfig, RootCertStore};
use tp_contracts::TenantId;
use tp_contracts::meta::{
    AccountKind, AccountScope, AccountStore, AccountUpsert, MailboxStore, MessageQuery,
    MessageStore, SpecialUse,
};
use tp_contracts::role::CancellationToken;
use tp_contracts::secrets::{SecretRef, SecretStore};
use tp_contracts::thread::ThreadStore;
use tp_contracts::transport::{
    AcceptedDomain, DomainKind, SourceKind, SourceMatch, TransportStore, TrustedSource,
};
use tp_contracts::{BlobHash, BlobKey, Gen};
use tp_meta::{MetaConfig, PgMeta};
use tp_testkit::MemSecretStore;

/// Предел ожидания каждого шага.
const WAIT: Duration = Duration::from_secs(30);

/// Доверенный шлюз кластера: результаты его проверок (`Authentication-Results`) — вместо DNS.
const AUTHSERV: &str = "gw.example.ru";

fn testdata(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/testdata")
        .join(name)
}

/// Хранилище секретов узла теста: пароль СУБД, ключ TLS и ключи метки ответа (`thepost/reply#k1`, `#k2`).
fn node_secrets(password: Option<String>) -> Arc<MemSecretStore> {
    let secrets = Arc::new(MemSecretStore::default());
    let db: SecretRef = "thepost/db#password".parse().expect("ref");
    secrets.set(&db, password.unwrap_or_else(|| "unused".to_owned()));
    let key: SecretRef = "thepost/tls#key".parse().expect("ref");
    secrets.set(
        &key,
        std::fs::read_to_string(testdata("key.pem")).expect("key.pem"),
    );
    for (field, letter) in [("k1", 'a'), ("k2", 'b')] {
        let r: SecretRef = format!("thepost/reply#{field}").parse().expect("ref");
        secrets.set(&r, letter.to_string().repeat(32));
    }
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

/// Пресет `all` с секциями теста: метки ответа (`smtp.reply.keys`, активный `k1`), BATV в `enforce`,
/// submission и smtp-in на `127.0.0.1:0`, Admin API, быстрые перечитывание конфигурации (ротация ключа)
/// и проходы maintenance (фоновая привязка бесед); без роли smtp-out — письма остаются в очереди.
fn config(dir: &Path, db_url: &str, domain: &str, socket: &Path) -> String {
    let all = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/config/all.yaml"),
    )
    .expect("deploy/config/all.yaml");
    let path = |p: PathBuf| p.display().to_string().replace('\\', "/");
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
  node_id: app77-{pid}
runtime:
  drain_deadline: 5s
smtp:
  hostname: localhost
  inbound:
    - {{ listen: \"127.0.0.1:0\" }}
  submission:
    - {{ listen: \"127.0.0.1:0\", implicit_tls: true }}
  reply:
    keys:
      - id: k1
        secret: {{ secret: \"thepost/reply#k1\" }}
        active: true
  batv:
    mode: enforce
http:
  jmap: {{ listen: \"127.0.0.1:0\", allow_plaintext: true }}
  admin: {{ listen: \"127.0.0.1:0\", allow_plaintext: true }}
imap:
  listeners:
    - {{ listen: \"127.0.0.1:0\", implicit_tls: true }}
sieve:
  managesieve:
    listen:
      - {{ listen: \"127.0.0.1:0\" }}
admin:
  init:
    socket: \"{socket}\"
search:
  index:
    dir: \"{index}\"
  indexer:
    commit_interval: 100ms
maintenance:
  purge_interval: 1h
reload:
  poll_interval: 100ms
",
        blob = path(dir.join("blob")),
        cert = path(testdata("cert.pem")),
        index = path(dir.join("index")),
        socket = path(socket.to_path_buf()),
        pid = std::process::id(),
    );
    // Секции теста заменяют пресетные целиком (включая `smtp`, `maintenance` и `secrets`).
    let top = |line: &str| !line.starts_with([' ', '\t', '#']) && !line.trim().is_empty();
    let names = [
        "domain",
        "profile",
        "database",
        "blob",
        "service_http",
        "tls",
        "meta",
        "cluster",
        "runtime",
        "smtp",
        "http",
        "imap",
        "sieve",
        "admin",
        "roles",
        "search",
        "maintenance",
        "reload",
        "secrets",
    ];
    let mut out = String::new();
    let mut skip = false;
    for line in all.lines() {
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
    format!("{out}roles: [smtp-in, submission, imap, jmap, admin, maintenance]\n{own}")
}

/// Срок ожидания шага: `WAIT` от текущего момента.
fn deadline() -> tokio::time::Instant {
    tokio::time::Instant::now() + WAIT
}

/// Пауза перед повтором; срок истёк — тест не пройден.
async fn retry(until: tokio::time::Instant, what: &str) {
    assert!(tokio::time::Instant::now() < until, "не дождались: {what}");
    tokio::time::sleep(Duration::from_millis(100)).await;
}

/// Отдельная база для теста.
async fn create_database(url: &str) -> (String, String) {
    let name = format!(
        "app77_{}",
        tp_contracts::ids::DomainId::new().as_uuid().simple()
    );
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

/// Принятый домен организации в БД.
async fn accept_domain(meta: &PgMeta, tenant: TenantId, name: &str) -> tp_contracts::ids::DomainId {
    let id = tp_contracts::ids::DomainId::new();
    let version = TransportStore::cluster(meta)
        .await
        .expect("transport")
        .version;
    meta.put_domain(
        version,
        &AcceptedDomain {
            id,
            tenant,
            name: name.to_owned(),
            kind: DomainKind::Authoritative,
        },
    )
    .await
    .expect("accepted domain");
    id
}

/// Адрес слушателя роли.
fn addr(running: &Running, role: &str) -> std::net::SocketAddr {
    *running
        .listeners
        .get(role)
        .first()
        .unwrap_or_else(|| panic!("роль {role} не открыла слушатель"))
}

// ---------- SMTP ----------

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
    smtp_reply(s).await
}

/// Письмо по SMTP от `from` получателю `to` (перевод `\n` в `\r\n`).
async fn smtp_send(addr: std::net::SocketAddr, from: &str, to: &str, message: &str) {
    let mut s = TcpStream::connect(addr).await.expect("smtp connect");
    assert_eq!(smtp_reply(&mut s).await, 220);
    assert_eq!(smtp_cmd(&mut s, "EHLO client.test").await, 250);
    assert_eq!(smtp_cmd(&mut s, &format!("MAIL FROM:<{from}>")).await, 250);
    assert_eq!(smtp_cmd(&mut s, &format!("RCPT TO:<{to}>")).await, 250);
    assert_eq!(smtp_cmd(&mut s, "DATA").await, 354);
    s.write_all(message.replace('\n', "\r\n").as_bytes())
        .await
        .expect("data");
    assert_eq!(smtp_cmd(&mut s, "\r\n.").await, 250, "письмо не принято");
    assert_eq!(smtp_cmd(&mut s, "QUIT").await, 221);
}

/// Ответ `EHLO` целиком (строки расширений).
async fn smtp_ehlo(addr: std::net::SocketAddr) -> String {
    let mut s = TcpStream::connect(addr).await.expect("smtp connect");
    assert_eq!(smtp_reply(&mut s).await, 220);
    s.write_all(b"EHLO client.test\r\n")
        .await
        .expect("smtp write");
    let mut text = String::new();
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        s.read_exact(&mut byte).await.expect("smtp read");
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            let line = String::from_utf8_lossy(&buf).into_owned();
            buf.clear();
            text.push_str(&line);
            if line.len() >= 4 && line.as_bytes()[3] == b' ' {
                return text;
            }
        }
    }
}

// ---------- IMAP ----------

struct Imap<S> {
    s: S,
    tag: u32,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Imap<S> {
    /// Приветствие сервера.
    async fn greeting(&mut self) -> String {
        let mut buf = Vec::new();
        while !buf.ends_with(b"\r\n") {
            let mut byte = [0u8; 1];
            self.s.read_exact(&mut byte).await.expect("imap read");
            buf.push(byte[0]);
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Команда и все ответы до тегированного; `OK` обязателен.
    async fn cmd(&mut self, cmd: &str) -> String {
        self.tag += 1;
        let tag = format!("a{}", self.tag);
        self.s
            .write_all(format!("{tag} {cmd}\r\n").as_bytes())
            .await
            .expect("imap write");
        self.read_until_tagged(&tag, cmd).await
    }

    /// APPEND письма в папку (литерал); `OK` обязателен.
    async fn append(&mut self, mailbox: &str, raw: &[u8]) -> String {
        self.tag += 1;
        let tag = format!("a{}", self.tag);
        self.s
            .write_all(format!("{tag} APPEND \"{mailbox}\" {{{}}}\r\n", raw.len()).as_bytes())
            .await
            .expect("imap write");
        let mut buf = Vec::new();
        while !buf.ends_with(b"\r\n") {
            let mut byte = [0u8; 1];
            self.s.read_exact(&mut byte).await.expect("imap read");
            buf.push(byte[0]);
        }
        let cont = String::from_utf8_lossy(&buf).into_owned();
        assert!(cont.starts_with('+'), "imap APPEND: {cont}");
        self.s.write_all(raw).await.expect("imap literal");
        self.s.write_all(b"\r\n").await.expect("imap eol");
        self.read_until_tagged(&tag, "APPEND").await
    }

    async fn read_until_tagged(&mut self, tag: &str, what: &str) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = self.s.read(&mut chunk).await.expect("imap read");
            assert!(
                n > 0,
                "imap: соединение закрыто; {}",
                String::from_utf8_lossy(&buf)
            );
            buf.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&buf);
            // Только полностью принятые строки: последняя может прийти по частям.
            let complete = &text[..text.rfind("\r\n").unwrap_or(0)];
            if let Some(line) = complete
                .split("\r\n")
                .find(|l| l.starts_with(&format!("{tag} ")))
            {
                assert!(
                    line.starts_with(&format!("{tag} OK")),
                    "imap {what}: {text}"
                );
                return text.into_owned();
            }
        }
    }
}

fn tls_connector() -> TlsConnector {
    let mut roots = RootCertStore::empty();
    let pem = std::fs::read(testdata("cert.pem")).expect("cert");
    roots
        .add(CertificateDer::from_pem_slice(&pem).expect("pem"))
        .expect("root");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(cfg))
}

async fn imap_login(
    addr: std::net::SocketAddr,
    login: &str,
    password: &str,
) -> Imap<tokio_rustls::client::TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(addr).await.expect("imap connect");
    let name = ServerName::try_from("localhost").expect("name");
    let s = tls_connector().connect(name, tcp).await.expect("imap tls");
    let mut imap = Imap { s, tag: 0 };
    assert!(imap.greeting().await.starts_with("* OK"));
    imap.cmd(&format!("LOGIN \"{login}\" \"{password}\"")).await;
    imap
}

/// Число писем из ответа `SELECT` (`* N EXISTS`).
fn exists(select: &str) -> u32 {
    select
        .split("\r\n")
        .find_map(|l| {
            l.strip_prefix("* ")
                .and_then(|r| r.strip_suffix(" EXISTS"))
                .and_then(|n| n.parse().ok())
        })
        .unwrap_or_else(|| panic!("нет EXISTS: {select}"))
}

// ---------- HTTP (Admin API, JMAP) ----------

async fn http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    authorization: &str,
    body: Option<&Value>,
) -> (u16, Vec<u8>) {
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let mut s = TcpStream::connect(addr).await.expect("http connect");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(req.as_bytes()).await.expect("http write");
    s.write_all(body.as_bytes()).await.expect("http body");
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.expect("http read");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("http head");
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
    let code = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    let mut payload = raw[split + 4..].to_vec();
    if head.contains("transfer-encoding: chunked") {
        let mut out = Vec::new();
        let mut rest = payload.as_slice();
        while let Some(eol) = rest.windows(2).position(|w| w == b"\r\n") {
            let size = usize::from_str_radix(
                String::from_utf8_lossy(&rest[..eol])
                    .split(';')
                    .next()
                    .unwrap_or("0")
                    .trim(),
                16,
            )
            .unwrap_or(0);
            if size == 0 {
                break;
            }
            let start = eol + 2;
            out.extend_from_slice(&rest[start..start + size]);
            rest = &rest[start + size + 2..];
        }
        payload = out;
    }
    (code, payload)
}

/// Сокет `admin init` роль admin забирает из общего для процесса места: запуски узлов в тестах — по очереди.
static ADMIN_SOCKET: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `thepost admin init` по локальному сокету узла: ответ узла (`status`, `token`, `password`).
async fn admin_init(socket: &Path, email: &str) -> Value {
    let mut s = tokio::net::UnixStream::connect(socket)
        .await
        .expect("admin init socket");
    s.write_all(format!("{}\n", json!({ "email": email })).as_bytes())
        .await
        .expect("admin init write");
    let mut out = Vec::new();
    s.read_to_end(&mut out).await.expect("admin init read");
    serde_json::from_slice(&out).expect("admin init reply")
}

async fn stop_node(running: Running, shutdown: CancellationToken) {
    shutdown.cancel();
    let report = running.wait().await.expect("report");
    assert!(report.failed.is_empty(), "{report:?}");
}

/// Письмо `letter` наружу через submission от `login` (AUTH PLAIN паролем приложения) получателю `peer`.
async fn submit_letter(
    submission: std::net::SocketAddr,
    login: &str,
    app_password: &str,
    peer: &str,
    letter: &str,
) {
    let tcp = TcpStream::connect(submission).await.expect("submission");
    let name = ServerName::try_from("localhost").expect("name");
    let mut s = tls_connector()
        .connect(name, tcp)
        .await
        .expect("submission tls");
    assert_eq!(smtp_reply(&mut s).await, 220);
    assert_eq!(smtp_cmd(&mut s, "EHLO client.test").await, 250);
    let plain =
        base64::engine::general_purpose::STANDARD.encode(format!("\0{login}\0{app_password}"));
    assert_eq!(smtp_cmd(&mut s, &format!("AUTH PLAIN {plain}")).await, 235);
    assert_eq!(smtp_cmd(&mut s, &format!("MAIL FROM:<{login}>")).await, 250);
    assert_eq!(smtp_cmd(&mut s, &format!("RCPT TO:<{peer}>")).await, 250);
    assert_eq!(smtp_cmd(&mut s, "DATA").await, 354);
    s.write_all(letter.replace('\n', "\r\n").as_bytes())
        .await
        .expect("data");
    assert_eq!(smtp_cmd(&mut s, "\r\n.").await, 250, "письмо не принято");
    assert_eq!(smtp_cmd(&mut s, "QUIT").await, 221);
}

/// Один вызов метода JMAP от `login` (Basic паролем приложения); ответ метода.
async fn jmap_call(
    web: std::net::SocketAddr,
    auth: &str,
    _account: &str,
    method: &str,
    args: Value,
) -> Value {
    let req = json!({
        "using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
        "methodCalls": [[method, args, "c0"]],
    });
    let (code, body) = http(
        web,
        "POST",
        "/jmap/api",
        &format!("Basic {auth}"),
        Some(&req),
    )
    .await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let resp: Value = serde_json::from_slice(&body).expect("json");
    let call = &resp["methodResponses"][0];
    assert_eq!(call[0], method, "{resp}");
    call[1].clone()
}

// ---------- тест ----------

/// APP-77: узел собирает признак «ответ на наше письмо» и беседы — ключи меток из хранилища секретов,
/// `SentLog` и `ThreadStore` из `PgMeta` — и передаёт их доставке SMTP, `MailStore`, JMAP и Admin API.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reply_marks_threads_and_hold() {
    let Some(url) = tp_testkit::pg_url() else {
        eprintln!("TEST_DATABASE_URL не задан — тест пропущен");
        return;
    };
    let url = dev_url(&url);
    let (db_name, url_db) = create_database(&url).await;
    let dir = tempfile::tempdir().expect("tempdir");
    let (db_url, password) = split_password(&url_db);
    let secrets = node_secrets(password);

    let domain = "example.ru".to_owned();
    let socket = dir.path().join("admin.sock");
    let path = dir.path().join("config.yaml");
    let text = config(dir.path(), &db_url, &domain, &socket);
    assert!(text.contains("reply:"), "{text}");
    std::fs::write(&path, &text).expect("config");
    // Сокет `admin init` открывается до запуска узла (как `startup::prepare_serve`).
    let cfg = thepost::sections::registry()
        .expect("registry")
        .load(&path)
        .expect("load config");
    let bound = ADMIN_SOCKET.lock().await;
    thepost::local_admin::bind(&cfg).expect("admin init socket");
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
    let until = deadline();
    while !running.health.is_ready() {
        retry(until, "узел готов").await;
    }
    let smtp = addr(&running, "smtp-in");
    let submission = addr(&running, "submission");

    // Учётная запись alice с паролем приложения; шлюз кластера для 127.0.0.1 — DMARC pass входящих ответов
    // по его `Authentication-Results`.
    let pool = tp_meta::pool::DbPool::new(
        sqlx::PgPool::connect(&url_db).await.expect("pool"),
        Arc::new(tp_meta::pool::NoAcquireObserver),
    );
    let meta = PgMeta::new(pool.clone(), MetaConfig::default());
    let tenant = TenantId::DEFAULT;
    let domain_id = accept_domain(&meta, tenant, &domain).await;
    let login = format!("alice@{domain}");
    let account = meta
        .upsert(
            tenant,
            AccountUpsert {
                domain: domain_id,
                login: login.clone(),
                display_name: "Alice".into(),
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
    let scope = AccountScope {
        tenant,
        account: account.id,
    };
    let apps =
        tp_auth::AppPasswords::new(Arc::new(meta.clone()), tp_auth::PasswordConfig::default())
            .expect("app passwords");
    let (_, secret) = apps.issue(scope, "e2e").await.expect("issue");
    let app_password = secret.expose().to_owned();
    let version = TransportStore::cluster(&meta)
        .await
        .expect("transport")
        .version;
    meta.put_source(
        version,
        &TrustedSource {
            name: "gateway".to_owned(),
            tenant: None,
            matcher: SourceMatch::Networks(vec!["127.0.0.1/32".parse().expect("net")]),
            kind: SourceKind::Gateway {
                xclient: true,
                authserv_id: Some(AUTHSERV.to_owned()),
            },
        },
    )
    .await
    .expect("источник");

    // Снимок транспорта без перезапуска (сигнал `TransportChanged`): шлюзу `EHLO` объявляет `XCLIENT` —
    // результаты его проверок действуют на новые сессии приёма.
    let until = deadline();
    while !smtp_ehlo(smtp).await.contains("XCLIENT") {
        retry(until, "доверенный шлюз действует на новую сессию").await;
    }

    // Исходное письмо беседы: bob пишет alice (приём SMTP через доверенный шлюз, DMARC pass) — во
    // «Входящих» alice, привязка к беседе приёмом (MS-21).
    let peer = "bob@ext.test";
    let orig_id = format!("orig-{}@ext.test", std::process::id());
    let first = format!(
        "Authentication-Results: {AUTHSERV}; spf=pass smtp.mailfrom=ext.test;\n \
         dkim=pass header.d=ext.test; dmarc=pass header.from=ext.test\n\
         From: Bob <{peer}>\nTo: Alice <{login}>\nSubject: Pricing\n\
         Message-ID: <{orig_id}>\n\nCould you send the pricing?\n"
    );
    let mut imap = imap_login(addr(&running, "imap"), &login, &app_password).await;
    smtp_send(smtp, peer, &login, &first).await;
    let until = deadline();
    while exists(&imap.cmd("SELECT INBOX").await) != 1 {
        retry(until, "исходное письмо во «Входящих»").await;
    }

    // 1. Наше письмо наружу (submission, ответ alice, без Message-ID): метка в Message-ID, BATV в
    //    `MAIL FROM` очереди, запись об отправленном.
    let letter = format!(
        "From: Alice <alice@example.ru>\nTo: Bob <bob@ext.test>\nSubject: Re: Pricing\n\
         In-Reply-To: <{orig_id}>\nReferences: <{orig_id}>\n\nHere is the pricing.\n"
    );
    submit_letter(submission, &login, &app_password, peer, &letter).await;

    // Очередь: конверт с BATV-меткой (`prvs=0…` — ключ k1, номер 0), письмо с меткой Message-ID (`tp1.k1.…`),
    // запись об отправленном с адресатом.
    let until = deadline();
    let (mail_from, blob_hash, blob_gen) = loop {
        let mut tx = tp_meta::schema::begin(&pool, tenant).await.expect("begin");
        let row: Option<(String, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT mail_from, blob_hash, blob_gen FROM queue ORDER BY queued_at DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await
        .expect("queue");
        tx.commit().await.expect("commit");
        if let Some(row) = row {
            break row;
        }
        retry(until, "письмо в очереди").await;
    };
    assert!(
        mail_from.starts_with("prvs=0"),
        "BATV в конверте: {mail_from}"
    );
    assert!(mail_from.ends_with(&format!("={login}")), "{mail_from}");
    let sent_rows = || {
        let pool = pool.clone();
        let login = peer.to_owned();
        async move {
            let mut tx = tp_meta::schema::begin(&pool, tenant).await.expect("begin");
            let n: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM sent_log WHERE tenant_id = $1 AND $2 = ANY(recipients)",
            )
            .bind(tenant.as_uuid())
            .bind(&login)
            .fetch_one(&mut *tx)
            .await
            .expect("sent_log");
            tx.commit().await.expect("commit");
            n
        }
    };
    let until = deadline();
    loop {
        if sent_rows().await == 1 {
            break;
        }
        retry(until, "запись об отправленном").await;
    }
    // Письмо очереди из BLOB узла: Message-ID — метка узла.
    let blobs = thepost::infra::open_blob(&cfg, secrets.as_ref())
        .await
        .expect("blob");
    let key = BlobKey {
        tenant,
        hash: BlobHash(blob_hash.try_into().expect("32 байта")),
        generation: Gen(u32::try_from(blob_gen).expect("gen")),
    };
    let raw: Vec<u8> = blobs
        .get(&key, None)
        .await
        .expect("queued letter")
        .try_fold(Vec::new(), |mut acc, chunk| async move {
            acc.extend_from_slice(&chunk);
            Ok(acc)
        })
        .await
        .expect("letter bytes");
    let queued = String::from_utf8_lossy(&raw).into_owned();
    let mark = queued
        .lines()
        .find_map(|l| {
            l.strip_prefix("Message-ID: <")
                .and_then(|v| v.strip_suffix('>'))
        })
        .expect("Message-ID метки")
        .to_owned();
    assert!(mark.starts_with("tp1.k1."), "метка узла: {mark}");
    assert!(mark.ends_with(&format!("@{domain}")), "{mark}");

    // 2. Bounce на адрес без метки — `550 5.7.1` (`smtp.batv.mode: enforce`).
    let mut s = TcpStream::connect(smtp).await.expect("smtp connect");
    assert_eq!(smtp_reply(&mut s).await, 220);
    assert_eq!(smtp_cmd(&mut s, "EHLO gw.test").await, 250);
    assert_eq!(smtp_cmd(&mut s, "MAIL FROM:<>").await, 250);
    assert_eq!(
        smtp_cmd(&mut s, &format!("RCPT TO:<{login}>")).await,
        550,
        "bounce без метки должен быть отклонён"
    );
    assert_eq!(smtp_cmd(&mut s, "QUIT").await, 221);

    // 3. Ответ адресата (DMARC pass по результатам шлюза) на наше письмо — признак `X-ThePost-Reply`
    //    и в беседу исходного письма.
    let reply = format!(
        "Authentication-Results: {AUTHSERV}; spf=pass smtp.mailfrom=ext.test;\n \
         dkim=pass header.d=ext.test; dmarc=pass header.from=ext.test\n\
         From: Bob <{peer}>\nTo: Alice <{login}>\nSubject: Re: Pricing\n\
         In-Reply-To: <{mark}>\nReferences: <{orig_id}> <{mark}>\n\nThanks, received.\n"
    );
    smtp_send(smtp, peer, &login, &reply).await;
    let until = deadline();
    let fetch = loop {
        while exists(&imap.cmd("SELECT INBOX").await) != 2 {
            retry(until, "ответ во «Входящих»").await;
        }
        let fetch = imap.cmd("FETCH 1:2 (BODY.PEEK[])").await;
        if fetch.contains("Thanks, received") {
            break fetch;
        }
        retry(until, "тело ответа").await;
    };
    let bodies: Vec<String> = fetch
        .split("BODY[] {")
        .skip(1)
        .map(|p| p[p.find("\r\n").map(|i| i + 2).unwrap_or(0)..].to_owned())
        .collect();
    assert_eq!(bodies.len(), 2, "{fetch}");
    let answer_body = bodies
        .iter()
        .find(|b| b.contains("Thanks, received"))
        .expect("тело ответа");
    assert!(
        answer_body
            .to_ascii_uppercase()
            .contains("X-THEPOST-REPLY: YES"),
        "признака ответа нет: {fetch}"
    );
    let first_body = bodies
        .iter()
        .find(|b| b.contains("Could you send the pricing"))
        .expect("тело исходного письма");
    assert!(
        !first_body.contains("X-ThePost-Reply"),
        "у исходного письма признака быть не должно: {fetch}"
    );

    // Ответ — в беседе исходного письма (привязка приёмом, MS-21): оба письма — одна беседа.
    let inbox = MailboxStore::list(&meta, scope)
        .await
        .expect("mailboxes")
        .into_iter()
        .find(|m| m.role == Some(SpecialUse::Inbox))
        .expect("inbox")
        .id;
    let inbox_ids = MessageStore::list(&meta, scope, inbox, MessageQuery::All, 10)
        .await
        .expect("list");
    assert_eq!(inbox_ids.len(), 2, "{inbox_ids:?}");
    let (orig, answer) = (inbox_ids[0].id, inbox_ids[1].id);
    let thread = meta
        .thread_of(scope, orig)
        .await
        .expect("thread_of")
        .expect("беседа исходного письма");
    assert_eq!(
        meta.thread_of(scope, answer).await,
        Ok(Some(thread)),
        "ответ — в беседе исходного письма"
    );
    let thread_messages = meta.messages(scope, thread, 10).await.expect("messages");
    assert_eq!(thread_messages, vec![orig, answer], "{thread_messages:?}");

    // JMAP (узел передаёт `ThreadStore` роли jmap, JMAP-48): `threadId` исходного письма и ответа — одна
    // беседа (идентификатор привязанной беседы — `T` + UUID, не запасной расчёт по ключу цепочки).
    let web = addr(&running, "jmap");
    let jmap_auth =
        base64::engine::general_purpose::STANDARD.encode(format!("{login}:{app_password}"));
    let got = jmap_call(
        web,
        &jmap_auth,
        &account.id.to_string(),
        "Email/get",
        json!({
            "accountId": account.id.to_string(),
            "ids": [orig.to_string(), answer.to_string()],
            "properties": ["threadId"],
        }),
    )
    .await;
    let tids: Vec<&str> = got["list"]
        .as_array()
        .expect("list")
        .iter()
        .map(|e| e["threadId"].as_str().unwrap_or_default())
        .collect();
    assert_eq!(tids.len(), 2, "{got}");
    assert_eq!(
        tids[0], tids[1],
        "threadId ответа и исходного письма: {got}"
    );
    assert_eq!(
        tids[0].strip_prefix('T').map(str::len),
        Some(36),
        "идентификатор не привязанной беседы: {got}"
    );

    // 4. Удержание беседы через Admin API (узел передаёт `ThreadStore` роли admin, ADM-50).
    let admin_login = format!("admin@{domain}");
    let granted = admin_init(&socket, &admin_login).await;
    drop(bound);
    assert_eq!(granted["status"], "granted", "{granted}");
    let token = granted["token"].as_str().expect("token").to_owned();
    let admin = addr(&running, "admin");
    let (code, body) = http(
        admin,
        "POST",
        "/api/v1/session",
        &format!("Bearer {token}"),
        None,
    )
    .await;
    assert_eq!(code, 201, "{}", String::from_utf8_lossy(&body));
    let session: Value = serde_json::from_slice(&body).expect("session");
    let bearer = format!("Bearer {}", session["session"].as_str().expect("session"));
    let org = format!("/api/v1/orgs/{tenant}");
    let (code, body) = http(
        admin,
        "PUT",
        &format!("{org}/accounts/{}/threads/{thread}/hold", account.id),
        &bearer,
        Some(&json!({ "reason": "case-77" })),
    )
    .await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    // Беседа письма по Admin API — с удержанием.
    let (code, body) = http(
        admin,
        "GET",
        &format!("{org}/accounts/{}/threads?message_id={orig}", account.id),
        &bearer,
        None,
    )
    .await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let view: Value = serde_json::from_slice(&body).expect("thread view");
    assert_eq!(view["hold"]["reason"], "case-77", "{view}");

    // 5. Ротация ключа метки без перезапуска (перечитанная секция `smtp.reply.keys`, `reload.poll_interval`):
    //    k1 остаётся проверять, k2 подписывает.
    let rotated = text.replace(
        "      - id: k1\n        secret: { secret: \"thepost/reply#k1\" }\n        active: true\n",
        "      - id: k1\n        secret: { secret: \"thepost/reply#k1\" }\n      - id: k2\n        secret: { secret: \"thepost/reply#k2\" }\n        active: true\n",
    );
    assert!(
        rotated.contains("id: k2"),
        "ротация не попала в конфигурацию"
    );
    std::fs::write(&path, &rotated).expect("rotated config");
    // Новое письмо — меткой нового ключа (`tp1.k2.`, BATV `prvs=1…`).
    let second = "From: Alice <alice@example.ru>\nTo: Bob <bob@ext.test>\nSubject: Contract\n\n\
                  Second letter after rotation.\n";
    let until = deadline();
    let (new_from, new_hash, new_gen) = loop {
        submit_letter(submission, &login, &app_password, peer, second).await;
        let mut tx = tp_meta::schema::begin(&pool, tenant).await.expect("begin");
        let row: Option<(String, Vec<u8>, i64)> = sqlx::query_as(
            "SELECT mail_from, blob_hash, blob_gen FROM queue WHERE mail_from LIKE 'prvs=1%' \
             ORDER BY queued_at DESC LIMIT 1",
        )
        .fetch_optional(&mut *tx)
        .await
        .expect("queue");
        tx.commit().await.expect("commit");
        if let Some(row) = row {
            break row;
        }
        retry(until, "письмо меткой нового ключа").await;
    };
    assert!(
        new_from.starts_with("prvs=1"),
        "BATV новым ключом: {new_from}"
    );
    let key = BlobKey {
        tenant,
        hash: BlobHash(new_hash.try_into().expect("32 байта")),
        generation: Gen(u32::try_from(new_gen).expect("gen")),
    };
    let raw: Vec<u8> = blobs
        .get(&key, None)
        .await
        .expect("queued letter")
        .try_fold(Vec::new(), |mut acc, chunk| async move {
            acc.extend_from_slice(&chunk);
            Ok(acc)
        })
        .await
        .expect("letter bytes");
    let second_raw = String::from_utf8_lossy(&raw).into_owned();
    let new_mark = second_raw
        .lines()
        .find_map(|l| {
            l.strip_prefix("Message-ID: <")
                .and_then(|v| v.strip_suffix('>'))
        })
        .expect("Message-ID метки")
        .to_owned();
    assert!(new_mark.starts_with("tp1.k2."), "новая метка: {new_mark}");

    // Ответ на письмо со старым ключом — ещё признаётся (k1 проверяет до конца срока меток).
    let old_reply = format!(
        "Authentication-Results: {AUTHSERV}; dmarc=pass header.from=ext.test\n\
         From: Bob <{peer}>\nTo: Alice <{login}>\nSubject: Re: Pricing\n\
         In-Reply-To: <{mark}>\nReferences: <{orig_id}> <{mark}>\n\nStill answering the old one.\n"
    );
    smtp_send(smtp, peer, &login, &old_reply).await;
    // Ответ на новое письмо — меткой нового ключа.
    let new_reply = format!(
        "Authentication-Results: {AUTHSERV}; dmarc=pass header.from=ext.test\n\
         From: Bob <{peer}>\nTo: Alice <{login}>\nSubject: Re: Contract\n\
         In-Reply-To: <{new_mark}>\nReferences: <{new_mark}>\n\nAnswering the new one.\n"
    );
    smtp_send(smtp, peer, &login, &new_reply).await;
    let until = deadline();
    let fetch = loop {
        while exists(&imap.cmd("SELECT INBOX").await) != 4 {
            retry(until, "ответы после ротации во «Входящих»").await;
        }
        let fetch = imap.cmd("FETCH 1:4 (BODY.PEEK[])").await;
        if fetch.contains("Still answering") && fetch.contains("Answering the new one") {
            break fetch;
        }
        retry(until, "тела ответов после ротации").await;
    };
    let flagged: Vec<&str> = fetch
        .split("BODY[] {")
        .skip(1)
        .map(|part| &part[part.find("\r\n").map(|i| i + 2).unwrap_or(0)..])
        .collect();
    assert_eq!(flagged.len(), 4, "{fetch}");
    let by_body = |needle: &str| {
        flagged
            .iter()
            .find(|p| p.contains(needle))
            .unwrap_or_else(|| panic!("{needle} нет: {fetch}"))
    };
    assert!(
        by_body("Still answering")
            .to_ascii_uppercase()
            .contains("X-THEPOST-REPLY: YES"),
        "ответ на письмо со старым ключом не признан: {fetch}"
    );
    assert!(
        by_body("Answering the new one")
            .to_ascii_uppercase()
            .contains("X-THEPOST-REPLY: YES"),
        "ответ на письмо с новым ключом не признан: {fetch}"
    );

    // 6. Удержание беседы переживает перезапуск узла: тот же Admin API после старта читает его из `PgMeta`.
    drop((imap, blobs));
    stop_node(running, shutdown).await;
    let bound = ADMIN_SOCKET.lock().await;
    thepost::local_admin::bind(&cfg).expect("admin init socket");
    let shutdown = CancellationToken::new();
    let running = start(ServeOptions {
        config: path.clone(),
        secrets: Some(secrets.clone() as Arc<dyn SecretStore>),
        telemetry: false,
        shutdown: shutdown.clone(),
        modules: thepost::modules::BUILTIN,
    })
    .await
    .expect("restart");
    let until = deadline();
    while !running.health.is_ready() {
        retry(until, "узел готов после перезапуска").await;
    }
    let admin = addr(&running, "admin");
    // Вход по паролю администратора (решение 117): сессии — в памяти, токен первого запуска погашен.
    let admin_password = granted["password"].as_str().expect("password").to_owned();
    let (code, body) = http(
        admin,
        "POST",
        "/api/v1/session",
        "none",
        Some(&json!({ "login": admin_login, "password": admin_password })),
    )
    .await;
    assert_eq!(code, 201, "{}", String::from_utf8_lossy(&body));
    let session: Value = serde_json::from_slice(&body).expect("session");
    let bearer = format!("Bearer {}", session["session"].as_str().expect("session"));
    let (code, body) = http(
        admin,
        "GET",
        &format!("{org}/accounts/{}/threads?message_id={orig}", account.id),
        &bearer,
        None,
    )
    .await;
    assert_eq!(code, 200, "{}", String::from_utf8_lossy(&body));
    let view: Value = serde_json::from_slice(&body).expect("thread view");
    assert_eq!(
        view["hold"]["reason"], "case-77",
        "удержание беседы не пережило перезапуск: {view}"
    );
    // Беседа та же: письма на месте (привязка — в PostgreSQL).
    let after = ThreadStore::thread_of(&meta, scope, answer)
        .await
        .expect("thread_of");
    assert_eq!(after, Some(thread));

    drop(bound);
    pool.close().await;
    stop_node(running, shutdown).await;
    drop_database(&url, &db_name).await;
}
