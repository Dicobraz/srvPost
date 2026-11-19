//! Политика доверия в точках решения узла (APP-76, решение 124): узел передаёт `TrustStore` (`PgMeta` с кэшем
//! на узле) в доставку SMTP, приём iTIP, DAV, JMAP и Admin API, и политика действует без перезапуска —
//! приглашение партнёра — письмом с кнопкой, администратор открывает `invite_new.partner = auto` — у следующего
//! письма событие в календаре (`trust_changed` сбрасывает кэш, срок кэша в тесте — час); бронирование от
//! партнёра — без брони; `REPLY` внешнего участника к событию нашего организатора — ответ учтён; письмо в
//! закрытую группу — `550 5.7.1`; `redirect` наружу при закрытой автопересылке — не уходит, письмо остаётся в
//! ящике. После перезапуска узла политика на месте. Чтение политики при недоступном хранилище — закрытая
//! матрица и метрика `tp_trust_closed_total` — проверяют юнит-тесты `thepost::trust` (имитация ошибки
//! хранилища); здесь — признак метрики в `/metrics`.
//!
//! Тип абонента — ядро: письмо через доверенный шлюз с `Authentication-Results` (`dmarc=pass`) и домен
//! `From` из доменов-партнёров организации — партнёр (RFC 9989); без партнёрства — внешний.
//!
//! Узел профиля SMB (`deploy/config/all.yaml`) против PostgreSQL, без роли smtp-out (письма в очереди
//! остаются). Без `TEST_DATABASE_URL` тесты пропускаются.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use serde_json::{Value, json};
use thepost::serve::{Running, ServeOptions, start};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tp_contracts::TenantId;
use tp_contracts::delivery::{DeliveryDecision, DeliveryEventKind, DeliveryLog, DeliveryQuery};
use tp_contracts::groups::{DistributionGroup, GroupStore, SenderRestriction};
use tp_contracts::ids::{DomainId, GroupId};
use tp_contracts::meta::{
    AccountKind, AccountScope, AccountStore, AccountUpsert, MailboxStore, MessageQuery, SpecialUse,
};
use tp_contracts::role::CancellationToken;
use tp_contracts::secrets::{SecretRef, SecretStore};
use tp_contracts::sharing::{BookingPolicy, ResourceStore};
use tp_contracts::sieve::SieveStore;
use tp_contracts::transport::{SourceKind, SourceMatch, TransportStore, TrustedSource};
use tp_meta::{MetaConfig, PgMeta};
use tp_testkit::MemSecretStore;

/// Предел ожидания шага (готовность узла, доставка письма).
const WAIT: Duration = Duration::from_secs(30);

fn testdata(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/testdata")
        .join(name)
}

/// Адрес без `sslmode` — открытый канал (профиль dev).
fn dev_url(url: &str) -> String {
    if url.contains("sslmode=") {
        return url.to_owned();
    }
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}sslmode=disable")
}

/// Адрес без пароля и пароль из `user:password@`.
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

/// Секреты узла теста: пароль СУБД и ключ TLS.
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

/// Пресет `preset` с секциями теста `own` (секции пресета вырезаются целиком).
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

/// Конфигурация узла теста: все роли, кроме smtp-out (письма в очереди остаются), Admin API и сокет
/// `admin init`; срок кэша политики доверия — час, чтобы изменение политики без перезапуска доказало
/// сброс по `trust_changed`, а не истечение срока.
fn config(dir: &Path, db_url: &str, domain: &str, socket: &Path) -> String {
    let all = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/config/all.yaml"),
    )
    .expect("deploy/config/all.yaml");
    let path = |p: PathBuf| p.display().to_string().replace('\\', "/");
    let own = format!(
        "domain: {domain}
profile: dev
roles: [smtp-in, imap, jmap, dav, admin, search, indexer, maintenance]
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
  node_id: trust-{pid}
runtime:
  drain_deadline: 5s
trust:
  cache_ttl: 1h
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
  admin: {{ listen: \"127.0.0.1:0\", allow_plaintext: true }}
search:
  index:
    dir: \"{index}\"
  indexer:
    commit_interval: 100ms
admin:
  init:
    socket: \"{socket}\"
",
        blob = path(dir.join("blob")),
        cert = path(testdata("cert.pem")),
        index = path(dir.join("index")),
        socket = path(socket.to_path_buf()),
        pid = std::process::id(),
    );
    let text = with_sections(&all, &own, &["secrets"]);
    assert!(
        text.contains("roles: [smtp-in, imap, jmap, dav, admin, search, indexer, maintenance]")
    );
    text
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

/// Отдельная база для теста: состав кластера и разделы журнала событий — только узла теста.
async fn create_database(url: &str) -> (String, String) {
    let name = format!("trust_{}", DomainId::new().as_uuid().simple());
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

/// Адрес слушателя роли.
fn addr(running: &Running, role: &str) -> std::net::SocketAddr {
    *running
        .listeners
        .get(role)
        .first()
        .unwrap_or_else(|| panic!("роль {role} не открыла слушатель"))
}

async fn db_pool(url: &str) -> tp_meta::pool::DbPool {
    let pool = sqlx::PgPool::connect(url).await.expect("pool");
    tp_meta::pool::DbPool::new(pool, Arc::new(tp_meta::pool::NoAcquireObserver))
}

/// Писем на адрес `address` в очереди исходящей почты.
async fn queued(pool: &tp_meta::pool::DbPool, address: &str) -> i64 {
    let mut tx = tp_meta::schema::begin(pool, TenantId::DEFAULT)
        .await
        .expect("begin");
    sqlx::query_scalar("SELECT count(*) FROM queue_rcpts WHERE address = $1")
        .bind(address)
        .fetch_one(&mut *tx)
        .await
        .expect("queue")
}

// ---------- SMTP ----------

/// Строки ответа SMTP до последней (`NNN ` без дефиса); возвращает полный текст последней строки.
async fn smtp_line<S: AsyncRead + Unpin>(s: &mut S) -> String {
    let mut buf = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        s.read_exact(&mut byte).await.expect("smtp read");
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            let line = String::from_utf8_lossy(&buf).into_owned();
            buf.clear();
            if line.len() >= 4 && line.as_bytes()[3] == b' ' {
                return line.trim_end().to_owned();
            }
        }
    }
}

async fn smtp_cmd<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, cmd: &str) -> String {
    s.write_all(format!("{cmd}\r\n").as_bytes())
        .await
        .expect("smtp write");
    smtp_line(s).await
}

/// Приветствие сервера (первая строка соединения, без команды).
async fn smtp_greeting<S: AsyncRead + Unpin>(s: &mut S) -> String {
    smtp_line(s).await
}

/// Ответ на `RCPT TO:<to>` в новой сессии от `from` (полный текст, код + текст).
async fn rcpt_reply(addr: std::net::SocketAddr, from: &str, to: &str) -> String {
    let mut s = TcpStream::connect(addr).await.expect("smtp connect");
    assert!(smtp_greeting(&mut s).await.starts_with("220"));
    assert!(
        smtp_cmd(&mut s, "EHLO client.test")
            .await
            .starts_with("250")
    );
    assert!(
        smtp_cmd(&mut s, &format!("MAIL FROM:<{from}>"))
            .await
            .starts_with("250")
    );
    let reply = smtp_cmd(&mut s, &format!("RCPT TO:<{to}>")).await;
    assert!(smtp_cmd(&mut s, "RSET").await.starts_with("250"));
    assert!(smtp_cmd(&mut s, "QUIT").await.starts_with("221"));
    reply
}

/// Ответ `EHLO` новой сессии (объявления слушателя: `XCLIENT` у шлюза и др.).
async fn smtp_ehlo(addr: std::net::SocketAddr) -> String {
    let mut s = TcpStream::connect(addr).await.expect("smtp connect");
    assert!(smtp_greeting(&mut s).await.starts_with("220"));
    let ehlo = smtp_cmd(&mut s, "EHLO client.test").await;
    assert!(smtp_cmd(&mut s, "QUIT").await.starts_with("221"));
    ehlo
}

/// Письмо `message` от `from` к `to` (переводит `\n` в `\r\n`).
async fn smtp_send(addr: std::net::SocketAddr, from: &str, to: &str, message: &str) {
    let mut s = TcpStream::connect(addr).await.expect("smtp connect");
    assert!(smtp_greeting(&mut s).await.starts_with("220"));
    assert!(
        smtp_cmd(&mut s, "EHLO client.test")
            .await
            .starts_with("250")
    );
    assert!(
        smtp_cmd(&mut s, &format!("MAIL FROM:<{from}>"))
            .await
            .starts_with("250")
    );
    assert!(
        smtp_cmd(&mut s, &format!("RCPT TO:<{to}>"))
            .await
            .starts_with("250")
    );
    assert!(smtp_cmd(&mut s, "DATA").await.starts_with("354"));
    s.write_all(message.replace('\n', "\r\n").as_bytes())
        .await
        .expect("data");
    assert!(
        smtp_cmd(&mut s, "\r\n.").await.starts_with("250"),
        "письмо не принято"
    );
    assert!(smtp_cmd(&mut s, "QUIT").await.starts_with("221"));
}

/// Письмо iTIP `method` от `from` к `to` через доверенный шлюз: `Authentication-Results` шлюза (`dmarc=pass`
/// домена отправителя) — вместо DNS (RFC 9989, SMTP-20). `organizer` — адрес `ORGANIZER` объекта. Возвращает
/// Message-ID без скобок (ключ журнала).
#[allow(clippy::too_many_arguments)]
async fn smtp_itip(
    addr: std::net::SocketAddr,
    authserv: &str,
    from: &str,
    to: &str,
    organizer: &str,
    method: &str,
    uid: &str,
    attendees: &str,
) -> String {
    let domain = from.rsplit_once('@').map(|(_, d)| d).expect("домен");
    let ics = format!(
        "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//trust//e2e//EN\nMETHOD:{method}\nBEGIN:VEVENT\n\
         UID:{uid}\nDTSTAMP:20261112T100000Z\nDTSTART:20270115T070000Z\n\
         DTEND:20270115T080000Z\nSEQUENCE:0\nSUMMARY:Trust {method}\n\
         ORGANIZER:mailto:{organizer}\n{attendees}END:VEVENT\nEND:VCALENDAR\n"
    );
    let message_id = format!("{uid}@trust.test");
    let message = format!(
        "Authentication-Results: {authserv}; spf=pass smtp.mailfrom={domain};\n \
         dkim=pass header.d={domain}; dmarc=pass header.from={domain}\n\
         From: Peer <{from}>\nTo: <{to}>\nSubject: {method} {uid}\n\
         Message-ID: <{message_id}>\nDate: Thu, 12 Nov 2026 10:00:00 +0000\n\
         MIME-Version: 1.0\nContent-Type: text/calendar; method={method}; charset=utf-8\n\n{ics}"
    );
    smtp_send(addr, from, to, &message).await;
    message_id
}

// ---------- Admin API ----------

/// Запрос HTTP/1.1 Admin API с заголовком `Authorization`: код и тело.
async fn http(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    authorization: &str,
    body: Option<&Value>,
) -> (u16, String) {
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let mut s = TcpStream::connect(addr).await.expect("http connect");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.expect("http write");
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.expect("http read");
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, payload) = text.split_once("\r\n\r\n").expect("http head");
    let code = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    (code, payload.to_owned())
}

/// Сокет `admin init` роль admin забирает из общего для процесса места: узлы тестов — по очереди.
static ADMIN_SOCKET: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// `thepost admin init` по локальному сокету узла.
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

// ---------- DAV ----------

/// Запрос DAV с телом `body` и заголовками `headers` (строки с `\r\n`): ответ целиком.
async fn dav_body(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    authorization: &str,
    headers: &str,
    body: &str,
) -> String {
    let mut s = TcpStream::connect(addr).await.expect("dav connect");
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: {authorization}\r\n{headers}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).await.expect("dav write");
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.expect("dav read");
    String::from_utf8_lossy(&raw).into_owned()
}

/// Запрос DAV с телом iCalendar.
async fn dav_send(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    authorization: &str,
    headers: &str,
    ics: &str,
) -> String {
    let headers = format!("Content-Type: text/calendar; charset=utf-8\r\n{headers}");
    dav_body(addr, method, path, authorization, &headers, ics).await
}

/// Запрос DAV с телом XML и заголовком `Depth`.
async fn dav_xml(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    authorization: &str,
    depth: &str,
    xml: &str,
) -> String {
    let headers = format!("Content-Type: application/xml; charset=utf-8\r\nDepth: {depth}\r\n");
    dav_body(addr, method, path, authorization, &headers, xml).await
}

/// Адреса ответа `PROPFIND`.
fn dav_hrefs(listing: &str) -> Vec<String> {
    listing
        .split("<d:href>")
        .skip(1)
        .filter_map(|r| r.split("</d:href>").next().map(str::to_owned))
        .collect()
}

/// Календари дома `home` (заодно создаёт календари по умолчанию — PROPFIND дома).
async fn dav_calendars(web: std::net::SocketAddr, home: &str, basic: &str) -> Vec<String> {
    let listed = dav_xml(web, "PROPFIND", home, basic, "1", "").await;
    assert!(listed.starts_with("HTTP/1.1 207"), "{listed}");
    dav_hrefs(&listed)
        .into_iter()
        .filter(|h| h != home && !h.ends_with("/inbox/") && !h.ends_with("/outbox/"))
        .collect()
}

/// `PARTSTAT` участника `address` в тексте iCalendar (строки развёрнуты по RFC 5545 §3.1).
fn partstat(ics: &str, address: &str) -> Option<String> {
    let unfolded = ics.replace("\r\n ", "").replace("\r\n\t", "");
    let target = format!("mailto:{}", address.to_ascii_lowercase());
    let line = unfolded
        .lines()
        .find(|l| l.starts_with("ATTENDEE") && l.to_ascii_lowercase().ends_with(&target))?;
    let rest = &line[line.find("PARTSTAT=")? + "PARTSTAT=".len()..];
    rest.split([';', ':']).next().map(str::to_owned)
}

// ---------- Узел теста ----------

/// Узел теста: своя база, администратор (`admin init`) с сессией Admin API. Запущенный узел — `Option`
/// (`Running::wait` требует владения — остановка забирает его; `running()` — текущий узел).
struct Node {
    url: String,
    db_name: String,
    config_path: PathBuf,
    secrets: Arc<MemSecretStore>,
    _dir: tempfile::TempDir,
    shutdown: CancellationToken,
    running: Option<Running>,
    pool: tp_meta::pool::DbPool,
    meta: PgMeta,
    bearer: String,
}

impl Node {
    /// Запуск узла; `None` — без `TEST_DATABASE_URL`.
    async fn start() -> Option<Self> {
        let Some(url) = tp_testkit::pg_url() else {
            eprintln!("TEST_DATABASE_URL не задан — тест пропущен");
            return None;
        };
        let url = dev_url(&url);
        let (db_name, url_db) = create_database(&url).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (db_url, password) = split_password(&url_db);
        let secrets = node_secrets(password);

        // Схема и доверенный шлюз — до запуска узла: снимок транспорта роли smtp-in загрузится уже с ним
        // (сигнал `TransportChanged` из тестовой `PgMeta` узлу не достанется — шины у неё нет).
        let pool = db_pool(&url_db).await;
        tp_meta::schema::migrate(&pool).await.expect("migrate");
        let meta = PgMeta::new(pool.clone(), MetaConfig::default());
        let authserv = "gw.example.ru";
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
                    authserv_id: Some(authserv.to_owned()),
                },
            },
        )
        .await
        .expect("источник");

        let domain = "example.ru";
        let socket = dir.path().join("admin.sock");
        let path = dir.path().join("config.yaml");
        std::fs::write(&path, config(dir.path(), &db_url, domain, &socket)).expect("config");
        // Локальный сокет `admin init` открывается до запуска узла (как `startup::prepare_serve`).
        let cfg = thepost::sections::registry()
            .expect("registry")
            .load(&path)
            .expect("load config");
        let bound = ADMIN_SOCKET.lock().await;
        thepost::local_admin::bind(&cfg).expect("admin init socket");
        let shutdown = CancellationToken::new();
        let running = Self::launch(&path, secrets.clone(), shutdown.clone()).await;

        // Администратор — он же администратор теста политики: учётная запись и принятый домен заведены
        // `admin init`.
        let login = format!("admin@{domain}");
        let granted = admin_init(&socket, &login).await;
        assert_eq!(granted["status"], "granted", "{granted}");
        let token = granted["token"].as_str().expect("token").to_owned();
        let (code, body) = http(
            addr(&running, "admin"),
            "POST",
            "/api/v1/session",
            &format!("Bearer {token}"),
            None,
        )
        .await;
        assert_eq!(code, 201, "{body}");
        let session: Value = serde_json::from_str(&body).expect("session");
        let bearer = format!("Bearer {}", session["session"].as_str().expect("session"));
        drop(bound);
        Some(Self {
            url,
            db_name,
            config_path: path,
            secrets,
            _dir: dir,
            shutdown,
            running: Some(running),
            pool,
            meta,
            bearer,
        })
    }

    /// Запуск узла по готовому конфигу (и повторный — после остановки): ожидание готовности.
    async fn launch(
        path: &Path,
        secrets: Arc<MemSecretStore>,
        shutdown: CancellationToken,
    ) -> Running {
        let running = start(ServeOptions {
            config: path.to_path_buf(),
            secrets: Some(secrets.clone() as Arc<dyn SecretStore>),
            telemetry: false,
            shutdown: shutdown.clone(),
            modules: thepost::modules::BUILTIN,
        })
        .await
        .expect("start");
        let until = deadline();
        while !running.health.is_ready() {
            assert!(
                tokio::time::Instant::now() < until,
                "не дождались: узел готов"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        running
    }

    /// Учётная запись организации `kind` с адресом `login` в принятом домене `domain_id`; возвращает скоуп
    /// и пароль приложения (`Basic` для CalDAV).
    async fn account(
        &self,
        domain_id: DomainId,
        login: &str,
        kind: AccountKind,
    ) -> (AccountScope, String) {
        let tenant = TenantId::DEFAULT;
        let account = self
            .meta
            .upsert(
                tenant,
                AccountUpsert {
                    domain: domain_id,
                    login: login.to_owned(),
                    display_name: login.split('@').next().unwrap_or(login).to_owned(),
                    external_id: None,
                    enabled: true,
                    aliases: Vec::new(),
                    kind,
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
        let apps = tp_auth::AppPasswords::new(
            Arc::new(self.meta.clone()),
            tp_auth::PasswordConfig::default(),
        )
        .expect("app passwords");
        let (_, secret) = apps.issue(scope, "trust").await.expect("issue");
        let auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{login}:{}", secret.expose()));
        (scope, format!("Basic {auth}"))
    }

    /// Группа рассылки с адресом `address` (без ограничений и модераторов).
    async fn group(&self, address: &str) {
        let group = DistributionGroup {
            id: GroupId::new(),
            tenant: TenantId::DEFAULT,
            name: "Все".to_owned(),
            address: Some(address.to_owned()),
            external_id: None,
            members: Vec::new(),
            senders: SenderRestriction::Anyone,
            moderators: Vec::new(),
            hidden_from_gal: false,
        };
        GroupStore::put(&self.meta, group).await.expect("group");
    }

    /// Политика организации через Admin API (`PUT /api/v1/orgs/{org}/trust`) — замена целиком.
    async fn put_org_trust(&self, admin: std::net::SocketAddr, policy: Value) {
        let (code, body) = http(
            admin,
            "PUT",
            &format!("/api/v1/orgs/{}/trust", TenantId::DEFAULT),
            &self.bearer,
            Some(&policy),
        )
        .await;
        assert_eq!(code, 200, "{body}");
    }

    /// Политика организации (`GET /api/v1/orgs/{org}/trust`).
    async fn get_org_trust(&self, admin: std::net::SocketAddr) -> Value {
        let (code, body) = http(
            admin,
            "GET",
            &format!("/api/v1/orgs/{}/trust", TenantId::DEFAULT),
            &self.bearer,
            None,
        )
        .await;
        assert_eq!(code, 200, "{body}");
        serde_json::from_str(&body).expect("trust view")
    }

    /// Доверенный шлюз кластера для 127.0.0.1 (заведён до запуска узла): результаты его проверок — вместо
    /// DNS. Ждёт объявления `XCLIENT` — признак снимка с шлюзом, и возвращает authserv-id.
    async fn gateway(&self, smtp: std::net::SocketAddr) -> String {
        let until = deadline();
        while !smtp_ehlo(smtp).await.contains("XCLIENT") {
            retry(until, "шлюз действует на новую сессию").await;
        }
        "gw.example.ru".to_owned()
    }

    /// Событие приёма iTIP письма `message_id` получателю `rcpt`: `(решение, причина)` — ждёт появления.
    async fn itip_decision(&self, message_id: &str, rcpt: &str) -> (DeliveryDecision, String) {
        let query = DeliveryQuery {
            message_id: Some(message_id.to_owned()),
            recipient: Some(rcpt.to_owned()),
            ..DeliveryQuery::all(50)
        };
        let tenant = TenantId::DEFAULT;
        let until = deadline();
        loop {
            let log = DeliveryLog::search(&self.meta, tenant, &query)
                .await
                .expect("delivery log");
            if let Some(e) = log
                .events
                .iter()
                .find(|e| e.kind == DeliveryEventKind::Itip)
            {
                return (e.decision, e.reason.clone().unwrap_or_default());
            }
            retry(until, "приём iTIP в журнале доставки").await;
        }
    }

    /// Доставлено письмо `message_id` получателю `rcpt` (событие `Deliver` в журнале доставки).
    async fn delivered(&self, message_id: &str, rcpt: &str) -> bool {
        let query = DeliveryQuery {
            message_id: Some(message_id.to_owned()),
            recipient: Some(rcpt.to_owned()),
            ..DeliveryQuery::all(50)
        };
        DeliveryLog::search(&self.meta, TenantId::DEFAULT, &query)
            .await
            .expect("delivery log")
            .events
            .iter()
            .any(|e| e.kind == DeliveryEventKind::Deliver)
    }

    /// Объект с `UID` в календарях учётной записи `scope`: текст iCalendar.
    async fn event_by_uid(&self, scope: AccountScope, uid: &str) -> Option<String> {
        use tp_contracts::dav::{CollectionKind, DavStore};
        for c in DavStore::list_collections(&self.meta, scope, CollectionKind::Calendar)
            .await
            .expect("calendars")
        {
            if let Some(o) = DavStore::object_by_uid(&self.meta, scope, c.id, uid)
                .await
                .expect("object")
            {
                return Some(o.body);
            }
        }
        None
    }

    /// Писем во «Входящих» учётной записи `scope`.
    async fn inbox_count(&self, scope: AccountScope) -> usize {
        let mailboxes = MailboxStore::list(&self.meta, scope)
            .await
            .expect("mailboxes");
        let inbox = mailboxes
            .iter()
            .find(|m| m.role == Some(SpecialUse::Inbox))
            .expect("Входящие");
        tp_contracts::meta::MessageStore::list(
            &self.meta,
            scope,
            inbox.id,
            MessageQuery::All,
            usize::MAX,
        )
        .await
        .expect("messages")
        .len()
    }

    /// Текущий запущенный узел.
    fn running(&self) -> &Running {
        self.running.as_ref().expect("узел запущен")
    }

    /// Остановка узла.
    async fn stop(&mut self) {
        self.shutdown.cancel();
        let running = self.running.take().expect("узел запущен");
        let report = running.wait().await.expect("wait");
        assert!(report.failed.is_empty(), "{report:?}");
    }

    /// Повторный запуск узла на той же базе и конфигурации (политика — на месте после перезапуска).
    async fn restart(&mut self) {
        let cfg = thepost::sections::registry()
            .expect("registry")
            .load(&self.config_path)
            .expect("load config");
        let bound = ADMIN_SOCKET.lock().await;
        thepost::local_admin::bind(&cfg).expect("admin init socket");
        let shutdown = CancellationToken::new();
        self.running =
            Some(Self::launch(&self.config_path, self.secrets.clone(), shutdown.clone()).await);
        drop(bound);
        self.shutdown = shutdown;
    }

    /// Остановка узла и удаление базы.
    async fn finish(mut self) {
        self.stop().await;
        self.pool.close().await;
        drop_database(&self.url, &self.db_name).await;
    }
}

/// Приёмка APP-76: политика доверия действует в точках решения узла без перезапуска и после него.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trust_policy_in_node() {
    let Some(mut node) = Node::start().await else {
        return;
    };
    // Метрика закрытых чтений политики зарегистрирована (нулевая).
    let metrics = node.running().metrics.encode().expect("metrics");
    assert!(metrics.contains("tp_trust_closed_total"), "{metrics}");

    let smtp = addr(node.running(), "smtp-in");
    let web = addr(node.running(), "jmap");
    let admin = addr(node.running(), "admin");

    // Учётные записи: получатель приглашений, переговорная, организатор, получатель правила `redirect`;
    // календари по умолчанию (PROPFIND дома), группа рассылки, правила бронирования переговорной. Домен
    // `example.ru` уже принят (`admin init`) — берём его идентификатор из снимка транспорта.
    let domain_id = TransportStore::cluster(&node.meta)
        .await
        .expect("transport")
        .domain("example.ru")
        .map(|d| d.id)
        .expect("домен admin init");
    let (alice_scope, alice_basic) = node
        .account(domain_id, "alice@example.ru", AccountKind::User)
        .await;
    let (room_scope, room_basic) = node
        .account(domain_id, "room@example.ru", AccountKind::Resource)
        .await;
    let (carol_scope, carol_basic) = node
        .account(domain_id, "carol@example.ru", AccountKind::User)
        .await;
    let (dave_scope, _) = node
        .account(domain_id, "dave@example.ru", AccountKind::User)
        .await;
    node.group("all@example.ru").await;
    let alice_home = "/dav/calendars/alice@example.ru/";
    let carol_home = "/dav/calendars/carol@example.ru/";
    dav_calendars(web, alice_home, &alice_basic).await;
    dav_calendars(web, "/dav/calendars/room@example.ru/", &room_basic).await;
    dav_calendars(web, carol_home, &carol_basic).await;
    ResourceStore::set_booking_policy(
        &node.meta,
        room_scope,
        Some(BookingPolicy {
            horizon: None,
            ..BookingPolicy::default()
        }),
    )
    .await
    .expect("правила бронирования");

    // Партнёр организации и доверенный шлюз; политика уровня организации — только партнёрство
    // (приглашение партнёру — письмо с кнопкой, умолчание).
    let authserv = node.gateway(smtp).await;
    node.put_org_trust(admin, json!({ "partners": ["partner.example"] }))
        .await;
    let view = node.get_org_trust(admin).await;
    assert_eq!(
        view["effective"]["matrix"]["invite_new"]["partner"], "button",
        "{view}"
    );

    // 1. REQUEST партнёра — письмо без события (умолчание: кнопка).
    let uid1 = "trust-partner-button";
    let message_id = smtp_itip(
        smtp,
        &authserv,
        "ivan@partner.example",
        "alice@example.ru",
        "ivan@partner.example",
        "REQUEST",
        uid1,
        "ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:alice@example.ru\n",
    )
    .await;
    let (decision, reason) = node.itip_decision(&message_id, "alice@example.ru").await;
    assert_eq!(decision, DeliveryDecision::Discard, "{reason}");
    assert!(reason.starts_with("REQUEST:"), "{reason}");
    assert!(
        node.event_by_uid(alice_scope, uid1).await.is_none(),
        "приглашение партнёра внесено при кнопке"
    );

    // 2. Администратор открывает `invite_new.partner = auto` — событие у следующего письма, без перезапуска
    // (срок кэша — час: без сброса по `trust_changed` действовала бы прежняя матрица).
    node.put_org_trust(
        admin,
        json!({ "invite_new": { "partner": "auto" }, "partners": ["partner.example"] }),
    )
    .await;
    let uid2 = "trust-partner-auto";
    let message_id = smtp_itip(
        smtp,
        &authserv,
        "ivan@partner.example",
        "alice@example.ru",
        "ivan@partner.example",
        "REQUEST",
        uid2,
        "ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:alice@example.ru\n",
    )
    .await;
    let (decision, reason) = node.itip_decision(&message_id, "alice@example.ru").await;
    assert_eq!(decision, DeliveryDecision::Accept, "{reason}");
    assert_eq!(reason, "REQUEST", "{reason}");
    let until = deadline();
    while node.event_by_uid(alice_scope, uid2).await.is_none() {
        retry(until, "приглашение партнёра в календаре").await;
    }

    // 3. Бронирование: своё — бронь в календаре переговорной и ответ организатору; партнёром — только письмо:
    // бронирования нет (закреплено), ответа партнёру нет.
    let alice_calendar = dav_calendars(web, alice_home, &alice_basic)
        .await
        .first()
        .expect("календарь alice")
        .clone();
    let own_invite = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//thepost//e2e//EN\r\nBEGIN:VEVENT\r\n\
         UID:trust-own-book\r\nDTSTAMP:20261112T100000Z\r\nDTSTART:20270116T090000Z\r\n\
         DTEND:20270116T100000Z\r\nSEQUENCE:0\r\nSUMMARY:Own room\r\n\
         ORGANIZER:mailto:alice@example.ru\r\n\
         ATTENDEE;PARTSTAT=ACCEPTED:mailto:alice@example.ru\r\n\
         ATTENDEE;CUTYPE=ROOM;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:room@example.ru\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n";
    let put = dav_send(
        web,
        "PUT",
        &format!("{alice_calendar}trust-own-book.ics"),
        &alice_basic,
        "If-None-Match: *\r\n",
        own_invite,
    )
    .await;
    assert!(put.starts_with("HTTP/1.1 201"), "{put}");
    let until = deadline();
    while node
        .event_by_uid(room_scope, "trust-own-book")
        .await
        .is_none()
    {
        retry(until, "бронь своей организации в календаре переговорной").await;
    }
    let uid3 = "trust-partner-room";
    let message_id = smtp_itip(
        smtp,
        &authserv,
        "ivan@partner.example",
        "room@example.ru",
        "ivan@partner.example",
        "REQUEST",
        uid3,
        "ATTENDEE;CUTYPE=ROOM;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:room@example.ru\n",
    )
    .await;
    let (decision, reason) = node.itip_decision(&message_id, "room@example.ru").await;
    assert_eq!(decision, DeliveryDecision::Discard, "{reason}");
    assert!(
        node.event_by_uid(room_scope, uid3).await.is_none(),
        "партнёр забронировал ресурс"
    );
    assert_eq!(
        queued(&node.pool, "ivan@partner.example").await,
        0,
        "ответ партнёру на бронирование"
    );

    // 4. REPLY внешнего участника к событию нашего организатора — ответ учтён (PARTSTAT), прочие свойства
    // из письма не берутся.
    let organizer_ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//thepost//e2e//EN\r\nBEGIN:VEVENT\r\n\
         UID:trust-reply\r\nDTSTAMP:20261112T100000Z\r\nDTSTART:20270117T070000Z\r\n\
         DTEND:20270117T080000Z\r\nSEQUENCE:0\r\nSUMMARY:Our meeting\r\n\
         ORGANIZER:mailto:carol@example.ru\r\n\
         ATTENDEE;PARTSTAT=ACCEPTED:mailto:carol@example.ru\r\n\
         ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:bob@external.test\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n";
    let carol_calendar = dav_calendars(web, carol_home, &carol_basic)
        .await
        .first()
        .expect("календарь carol")
        .clone();
    let put = dav_send(
        web,
        "PUT",
        &format!("{carol_calendar}trust-reply.ics"),
        &carol_basic,
        "If-None-Match: *\r\n",
        organizer_ics,
    )
    .await;
    assert!(put.starts_with("HTTP/1.1 201"), "{put}");
    // Приглашение внешнему участнику — в очереди (нет роли smtp-out), у участника — NEEDS-ACTION.
    let until = deadline();
    while queued(&node.pool, "bob@external.test").await < 1 {
        retry(until, "приглашение внешнему в очереди").await;
    }
    assert_eq!(
        partstat(
            &node
                .event_by_uid(carol_scope, "trust-reply")
                .await
                .expect("событие"),
            "bob@external.test"
        )
        .as_deref(),
        Some("NEEDS-ACTION")
    );
    // Ответ внешнего участника (через шлюз, `dmarc=pass`): меняется только его PARTSTAT — место из письма
    // не берётся.
    let reply_id = smtp_itip(
        smtp,
        &authserv,
        "bob@external.test",
        "carol@example.ru",
        "carol@example.ru",
        "REPLY",
        "trust-reply",
        "ATTENDEE;PARTSTAT=ACCEPTED:mailto:bob@external.test\n\
         REQUEST-STATUS:2.0;Success\nLOCATION:Подмена места\n",
    )
    .await;
    let (decision, reason) = node.itip_decision(&reply_id, "carol@example.ru").await;
    assert_eq!(decision, DeliveryDecision::Accept, "{reason}");
    assert_eq!(reason, "REPLY", "{reason}");
    let until = deadline();
    let answered = loop {
        let body = node
            .event_by_uid(carol_scope, "trust-reply")
            .await
            .expect("событие");
        if partstat(&body, "bob@external.test").as_deref() == Some("ACCEPTED") {
            break body;
        }
        retry(until, "ответ участника в событии организатора").await;
    };
    assert!(!answered.contains("Подмена"), "{answered}");

    // 5. Внешнее письмо в закрытую группу — `550 5.7.1` на RCPT (умолчание чужим закрыто); своим — открыто.
    let reply = rcpt_reply(smtp, "bob@external.test", "all@example.ru").await;
    assert!(
        reply.starts_with("550 5.7.1"),
        "группа открыта чужому: {reply}"
    );
    let reply = rcpt_reply(smtp, "alice@example.ru", "all@example.ru").await;
    assert!(reply.starts_with("250"), "своему закрыто: {reply}");

    // 6. `redirect` наружу при закрытой автопересылке — не уходит, письмо остаётся в ящике.
    SieveStore::put(
        &node.meta,
        dave_scope,
        "forward",
        "redirect \"out@other.test\";\r\n".to_owned(),
    )
    .await
    .expect("script");
    SieveStore::activate(&node.meta, dave_scope, Some("forward"))
        .await
        .expect("activate");
    let message_id = format!("trust-redirect-{}@trust.test", std::process::id());
    let message = format!(
        "Authentication-Results: {authserv}; spf=pass smtp.mailfrom=external.test;\n \
         dkim=pass header.d=external.test; dmarc=pass header.from=external.test\n\
         From: Bob <bob@external.test>\nTo: <dave@example.ru>\nSubject: Redirect me\n\
         Message-ID: <{message_id}>\nDate: Thu, 12 Nov 2026 10:05:00 +0000\n\
         MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\nHello.\n"
    );
    smtp_send(smtp, "bob@external.test", "dave@example.ru", &message).await;
    let until = deadline();
    while !node.delivered(&message_id, "dave@example.ru").await {
        retry(until, "письмо доставлено dave").await;
    }
    assert_eq!(
        queued(&node.pool, "out@other.test").await,
        0,
        "redirect наружу выполнен при закрытой автопересылке"
    );
    assert_eq!(
        node.inbox_count(dave_scope).await,
        1,
        "письмо осталось в ящике получателя"
    );

    // Политика недоступна в e2e не имитируется: закрытая матрица и метрика — юнит-тесты `thepost::trust`.

    // 7. После перезапуска политика на месте: та же матрица и тот же итог у нового приглашения партнёра.
    node.stop().await;
    node.restart().await;
    let admin = addr(node.running(), "admin");
    let view = node.get_org_trust(admin).await;
    assert_eq!(
        view["own"]["invite_new"]["partner"],
        json!({ "partner": "auto" }),
        "{view}"
    );
    assert_eq!(
        view["effective"]["matrix"]["invite_new"]["partner"], "auto",
        "{view}"
    );
    let smtp = addr(node.running(), "smtp-in");
    let authserv = node.gateway(smtp).await;
    let uid5 = "trust-partner-restart";
    let message_id = smtp_itip(
        smtp,
        &authserv,
        "ivan@partner.example",
        "alice@example.ru",
        "ivan@partner.example",
        "REQUEST",
        uid5,
        "ATTENDEE;PARTSTAT=NEEDS-ACTION;RSVP=TRUE:mailto:alice@example.ru\n",
    )
    .await;
    let (decision, reason) = node.itip_decision(&message_id, "alice@example.ru").await;
    assert_eq!(decision, DeliveryDecision::Accept, "{reason}");
    let until = deadline();
    while node.event_by_uid(alice_scope, uid5).await.is_none() {
        retry(until, "приглашение партнёра в календаре после перезапуска").await;
    }
    // Действующая матрица учётной записи через Admin API (`GET …/accounts/{account}/trust`).
    let (code, body) = http(
        admin,
        "GET",
        &format!(
            "/api/v1/orgs/{}/accounts/{}/trust",
            TenantId::DEFAULT,
            alice_scope.account
        ),
        &node.bearer,
        None,
    )
    .await;
    assert_eq!(code, 200, "{body}");
    let view: Value = serde_json::from_str(&body).expect("account trust");
    assert_eq!(
        view["effective"]["matrix"]["invite_new"]["partner"], "auto",
        "{view}"
    );

    node.finish().await;
}
