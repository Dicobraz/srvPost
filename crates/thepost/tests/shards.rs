//! Шарды и реплики СУБД в узле (APP-47): справочник из двух шардов (две БД одного PostgreSQL) — письмо
//! в ящик учётной записи второго шарда доставляется (данные ящика — в БД шарда), IMAP IDLE получает
//! сигнал (шина LISTEN/NOTIFY по шардам справочника), фоновая роль maintenance читает с реплики
//! (`database.read_replica`, метрики пула `replica`). Узел применяет миграции схемы на шардах
//! ([`ShardDirectory::migrate`]).
//!
//! Без `TEST_DATABASE_URL` тесты пропускаются.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use thepost::serve::{Running, ServeOptions, start};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tp_contracts::meta::{AccountKind, AccountStore, AccountUpsert};
use tp_contracts::role::CancellationToken;
use tp_contracts::secrets::SecretRef;
use tp_contracts::transport::{AcceptedDomain, DomainKind, TransportStore};
use tp_meta::pool::{DbPool, NoAcquireObserver};
use tp_meta::shards::{ShardDirectory, ShardResolver as _};
use tp_meta::{MetaConfig, PgMeta};
use tp_testkit::MemSecretStore;

/// Предел ожидания шага.
const WAIT: Duration = Duration::from_secs(30);

fn testdata(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/testdata")
        .join(name)
}

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

/// Отдельная база для теста: имя и адрес.
async fn create_database(url: &str, tag: &str) -> (String, String) {
    let name = format!(
        "{tag}_{}",
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

/// Конфигурация узла теста: роли smtp-in, imap и maintenance, шина LISTEN/NOTIFY, реплика основной БД
/// (та же база: сервер не в восстановлении — отставание нулевое); ключ TLS — секрет `tls.key`.
fn config(dir: &Path, db_url: &str, cert: &Path) -> String {
    let path = |p: &Path| p.display().to_string().replace('\\', "/");
    format!(
        "domain: example.org\nprofile: dev\nroles: [smtp-in, imap, maintenance]\n\
         service_http:\n  listen: 127.0.0.1:0\n  allow_plaintext: true\n\
         tls:\n  cert_file: \"{cert}\"\n\
         database:\n  url: \"{db_url}\"\n  password: {{ secret: \"thepost/db#password\" }}\n  tls: {{ allow_plaintext: true }}\n\
         \x20 read_replica: \"{db_url}\"\n\
         blob:\n  url: file://{blob}\n\
         bus:\n  kind: postgres\n\
         meta:\n  events:\n    node_ttl: 3s\n\
         cluster:\n  node_id: shard-{pid}\n\
         runtime:\n  drain_deadline: 5s\n\
         smtp:\n  hostname: localhost\n  inbound:\n    - {{ listen: \"127.0.0.1:0\" }}\n\
         imap:\n  listeners:\n    - {{ listen: \"127.0.0.1:0\", implicit_tls: true }}\n\
         search:\n  index:\n    dir: \"{index}\"\n",
        cert = path(cert),
        blob = path(&dir.join("blob")),
        index = path(&dir.join("index")),
        pid = std::process::id(),
    )
}

/// Пул к базе `url` без наблюдателя ожидания соединения (тест не измеряет пулы СУБД).
async fn connect_db(url: &str) -> DbPool {
    let pool = sqlx::PgPool::connect(url).await.expect("pool");
    DbPool::new(pool, Arc::new(NoAcquireObserver))
}

/// Учётных строк `table` учётной записи `account` в базе `pool` (все организации).
async fn rows_in_shard(pool: &DbPool, table: &str, account: tp_contracts::AccountId) -> i64 {
    let mut tx = tp_meta::schema::begin_system(pool).await.expect("begin");
    let n: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM {table} WHERE account_id = $1"
    )))
    .bind(account.as_uuid())
    .fetch_one(&mut *tx)
    .await
    .expect("count");
    tx.commit().await.expect("commit");
    n
}

/// GET по служебному HTTP: тело ответа (с разбором `chunked`).
async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
    let mut s = TcpStream::connect(addr).await.expect("http connect");
    s.write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .expect("write");
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.expect("read");
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("http head");
    let head = String::from_utf8_lossy(&raw[..split]).to_ascii_lowercase();
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
    String::from_utf8_lossy(&payload).into_owned()
}

/// Строки ответа SMTP до последней (`NNN ` без дефиса); возвращает код.
async fn smtp_reply(s: &mut TcpStream) -> u16 {
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

async fn smtp_cmd(s: &mut TcpStream, cmd: &str) -> u16 {
    s.write_all(format!("{cmd}\r\n").as_bytes())
        .await
        .expect("smtp write");
    smtp_reply(s).await
}

/// TLS-соединение с IMAP-слушателем (implicit), вход, `SELECT INBOX` и `IDLE` (команды посылаются подряд).
async fn imap_idle(
    addr: std::net::SocketAddr,
    login: &str,
    password: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut roots = RootCertStore::empty();
    let pem = std::fs::read(testdata("cert.pem")).expect("cert");
    roots
        .add(CertificateDer::from_pem_slice(&pem).expect("pem"))
        .expect("root");
    let cfg = ClientConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(addr).await.expect("imap connect");
    let name = ServerName::try_from("localhost").expect("name");
    let mut s = TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
        .expect("imap tls");
    // Вход и выбор папки.
    for cmd in [
        format!("a1 LOGIN \"{login}\" \"{password}\""),
        "a2 SELECT INBOX".to_owned(),
        "a3 IDLE".to_owned(),
    ] {
        s.write_all(format!("{cmd}\r\n").as_bytes())
            .await
            .expect("imap write");
    }
    s
}

/// Строки ответа IMAP до строки с `needle` включительно (в пределах срока).
async fn imap_wait_for(s: &mut tokio_rustls::client::TlsStream<TcpStream>, needle: &str) -> String {
    let mut buf = Vec::new();
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "не дождались {needle:?}: {}",
            String::from_utf8_lossy(&buf)
        );
        let mut chunk = [0u8; 4096];
        let read = tokio::time::timeout(Duration::from_secs(2), s.read(&mut chunk)).await;
        match read {
            Ok(Ok(0)) => panic!(
                "imap: соединение закрыто; {}",
                String::from_utf8_lossy(&buf)
            ),
            Err(_) => continue,
            Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(Err(e)) => panic!("imap read: {e}"),
        }
        let text = String::from_utf8_lossy(&buf).into_owned();
        if text.contains(needle) {
            return text;
        }
    }
}

/// APP-47: два шарда — письмо в ящик второго шарда доставляется и лежит в БД шарда, IDLE получает сигнал,
/// фоновая роль читает с реплики (метрики пула `replica`), миграции схемы узел применил на шарде.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_shards_delivery_idle_and_replica_reads() {
    let Some(url) = tp_testkit::pg_url() else {
        eprintln!("TEST_DATABASE_URL не задан — тест пропущен");
        return;
    };
    let url = dev_url(&url);
    let (main_db, url_main) = create_database(&url, "e2e_shard_main").await;
    let (shard_db, url_shard) = create_database(&url, "e2e_shard_two").await;
    let (main_url, password) = split_password(&url_main);
    let (shard_url, shard_password) = split_password(&url_shard);
    let secrets = Arc::new(MemSecretStore::default());
    let db: SecretRef = "thepost/db#password".parse().expect("ref");
    secrets.set(&db, password.unwrap_or_else(|| "unused".to_owned()));
    let shard_cred: SecretRef = "thepost/shard1#password".parse().expect("ref");
    secrets.set(
        &shard_cred,
        shard_password.unwrap_or_else(|| "unused".to_owned()),
    );

    // Схема каталога в основной БД (её применит узел, но строку шарда тест вносит до запуска) — миграции
    // выполняет тест, чтобы добавить шард до старта узла.
    let main_pool = connect_db(&url_main).await;
    tp_meta::schema::migrate(&main_pool).await.expect("migrate");
    sqlx::query("UPDATE shards SET accepts_new = false WHERE shard_id = 0")
        .execute(&mut *main_pool.acquire().await.expect("conn"))
        .await
        .expect("main accepts_new off");
    sqlx::query(
        "INSERT INTO shards (shard_id, name, dsn, credentials, accepts_new, site) \
         VALUES (1, 'second', $1, $2, true, 'dc2')",
    )
    .bind(&shard_url)
    .bind(shard_cred.to_string())
    .execute(&mut *main_pool.acquire().await.expect("conn"))
    .await
    .expect("shard row");

    // Справочник теста: учётную запись размещает на шарде с `accepts_new` (схему шарда применит узел).
    let dir_cfg = tp_meta::pool::PoolConfig {
        url: main_url.clone(),
        tls: tp_contracts::tls::InternalTls {
            allow_plaintext: true,
            ..tp_contracts::tls::InternalTls::default()
        },
        profile: tp_contracts::tls::Profile::Dev,
        ..tp_meta::pool::PoolConfig::default()
    };
    let dir = Arc::new(ShardDirectory::new(
        main_pool.clone(),
        dir_cfg,
        secrets.clone(),
        |_, _| Arc::new(NoAcquireObserver),
    ));
    let meta = PgMeta::new(main_pool.clone(), MetaConfig::default()).with_shards(dir);
    let tenant = tp_contracts::TenantId::DEFAULT;
    let domain = "example.org";
    let domain_id = {
        let id = tp_contracts::ids::DomainId::new();
        let version = TransportStore::cluster(&meta)
            .await
            .expect("transport")
            .version;
        meta.put_domain(
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
        id
    };
    let login = format!("bob@{domain}");
    let account = meta
        .upsert(
            tenant,
            AccountUpsert {
                domain: domain_id,
                login: login.clone(),
                display_name: "Bob".into(),
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
    let scope = tp_contracts::meta::AccountScope {
        tenant,
        account: account.id,
    };
    // Учётная запись — на втором шарде.
    assert_eq!(
        dir.shard_of(scope).await.expect("shard of account"),
        tp_contracts::ids::ShardId(1),
        "учётная запись размещена на втором шарде"
    );
    let apps =
        tp_auth::AppPasswords::new(Arc::new(meta.clone()), tp_auth::PasswordConfig::default())
            .expect("app passwords");
    let (_, secret) = apps.issue(scope, "e2e").await.expect("issue");
    let app_password = secret.expose().to_owned();

    // Узел: миграции основной БД применены тестом, шарда — узлом (`migrate_on_start`).
    let dir_node = tempfile::tempdir().expect("tempdir");
    let path = dir_node.path().join("config.yaml");
    std::fs::write(
        &path,
        config(dir_node.path(), &main_url, &testdata("cert.pem")),
    )
    .expect("config");
    let shutdown = CancellationToken::new();
    let node_secrets = {
        let key: SecretRef = "thepost/tls#key".parse().expect("ref");
        secrets.set(
            &key,
            std::fs::read_to_string(testdata("key.pem")).expect("key.pem"),
        );
        secrets.clone()
    };
    let running = start(ServeOptions {
        config: path,
        secrets: Some(node_secrets as Arc<dyn tp_contracts::secrets::SecretStore>),
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
            "узел не готов: {:?}",
            running.health.roles_status()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Схему шарда применил узел: таблица ящиков на шарде существует, ящик учётной записи на месте.
    let shard_pool = connect_db(&url_shard).await;
    let boxes: i64 = sqlx::query_scalar("SELECT count(*) FROM mailboxes")
        .fetch_one(&mut *shard_pool.acquire().await.expect("conn"))
        .await
        .expect("shard schema");
    assert!(boxes >= 1, "системные папки учётной записи — на шарде");

    // IDLE учётной записи второго шарда — до доставки письма.
    let mut idle = imap_idle(addr(&running, "imap"), &login, &app_password).await;
    // Сервер подтвердил вход, выбор папки и режим IDLE.
    let idling = imap_wait_for(&mut idle, "+").await;
    assert!(
        idling.contains("idling") || idling.contains('+'),
        "{idling}"
    );

    // Приём SMTP: письмо в ящик учётной записи второго шарда.
    let word = format!("shard{}", std::process::id());
    let message = format!(
        "From: Alice <alice@sender.test>\nTo: Bob <{login}>\nSubject: Shard delivery\n\
         Message-ID: <{word}@sender.test>\n\nTwo shards, one node.\n"
    );
    let mut smtp = TcpStream::connect(addr(&running, "smtp-in"))
        .await
        .expect("smtp connect");
    assert_eq!(smtp_reply(&mut smtp).await, 220);
    assert_eq!(smtp_cmd(&mut smtp, "EHLO client.test").await, 250);
    assert_eq!(
        smtp_cmd(&mut smtp, "MAIL FROM:<alice@sender.test>").await,
        250
    );
    assert_eq!(
        smtp_cmd(&mut smtp, &format!("RCPT TO:<{login}>")).await,
        250
    );
    assert_eq!(smtp_cmd(&mut smtp, "DATA").await, 354);
    smtp.write_all(message.replace('\n', "\r\n").as_bytes())
        .await
        .expect("data");
    assert_eq!(smtp_cmd(&mut smtp, "\r\n.").await, 250, "письмо не принято");
    assert_eq!(smtp_cmd(&mut smtp, "QUIT").await, 221);

    // Данные письма — в БД второго шарда, не в основной.
    let until = tokio::time::Instant::now() + WAIT;
    while rows_in_shard(&shard_pool, "messages", account.id).await == 0 {
        assert!(
            tokio::time::Instant::now() < until,
            "письмо не доставлено на шард"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        rows_in_shard(&shard_pool, "mailboxes", account.id).await >= 1,
        "ящик учётной записи — на шарде"
    );
    assert_eq!(
        rows_in_shard(&main_pool, "messages", account.id).await,
        0,
        "письма учётной записи — не в основной БД"
    );

    // IDLE получил сигнал о доставке (шина LISTEN/NOTIFY по шардам справочника).
    let seen = imap_wait_for(&mut idle, "EXISTS").await;
    assert!(seen.contains("EXISTS"), "{seen}");
    idle.write_all(b"DONE\r\n").await.expect("done");
    drop(idle);

    // Фоновая роль (maintenance) читает с реплики: соединения пула `replica` открыты.
    let until = tokio::time::Instant::now() + WAIT;
    loop {
        let metrics = http_get(running.service_addr, "/metrics").await;
        let idle = metrics
            .lines()
            .find_map(|l| l.strip_prefix("tp_db_pool_idle{pool=\"replica\"} "))
            .and_then(|v| v.trim().parse::<f64>().ok())
            .unwrap_or(0.0);
        if idle > 0.0 {
            assert!(
                metrics.contains("tp_db_pool_max{pool=\"replica\"}"),
                "{metrics}"
            );
            break;
        }
        assert!(
            tokio::time::Instant::now() < until,
            "фоновая роль не читала с реплики: {metrics}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    shutdown.cancel();
    let report = running.wait().await.expect("wait");
    assert!(report.failed.is_empty(), "{report:?}");
    shard_pool.close().await;
    main_pool.close().await;
    drop_database(&url, &main_db).await;
    drop_database(&url, &shard_db).await;
}

/// Адрес слушателя роли.
fn addr(running: &Running, role: &str) -> std::net::SocketAddr {
    *running
        .listeners
        .get(role)
        .first()
        .unwrap_or_else(|| panic!("роль {role} не открыла слушатель"))
}
