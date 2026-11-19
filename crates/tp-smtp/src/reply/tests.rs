//! Метка ответа (SMTP-51): Message-ID `tp1.<id>.<base32>@<домен>`, BATV `prvs=…`, заголовки признака.

use std::sync::Arc;

use rand::RngExt;
use time::OffsetDateTime;
use tp_contracts::secrets::SecretRef;
use tp_testkit::{MemSecretStore, SystemClock};

use super::*;

fn now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time")
}

fn config(ids: &[(&str, bool)]) -> ReplyConfig {
    let keys = ids
        .iter()
        .map(|(id, active)| ReplyKeyConfig {
            id: (*id).to_owned(),
            secret: SecretRef::new("thepost/reply", id).expect("ref"),
            active: *active,
        })
        .collect();
    ReplyConfig {
        keys,
        ..ReplyConfig::default()
    }
}

/// Метка с одним активным ключом `k1`.
fn marks(store: &MemSecretStore) -> ReplyMarks {
    ReplyMarks::new(Arc::new(store.clone()), config(&[("k1", true)]))
}

/// Готовая метка Message-ID и её случайное значение.
async fn mark_of(marks: &ReplyMarks) -> (String, Vec<u8>) {
    marks
        .message_id("example.org", now())
        .await
        .expect("mark")
        .expect("active key")
}

fn secret32(store: &MemSecretStore) {
    store.set(
        &SecretRef::new("thepost/reply", "k1").expect("ref"),
        "a".repeat(32),
    );
}

#[tokio::test]
async fn message_id_shape_and_open() {
    let store = MemSecretStore::new(Arc::new(SystemClock));
    secret32(&store);
    let marks = marks(&store);
    let (mid, tag) = mark_of(&marks).await;
    // Форма `tp1.<id>.<base32>@<домен>`, домен в нижнем регистре, base32 без дополнения.
    let (local, domain) = mid.split_once('@').expect("domain");
    assert_eq!(domain, "example.org");
    let mut parts = local.split('.');
    assert_eq!(parts.next(), Some("tp1"));
    assert_eq!(parts.next(), Some("k1"));
    let b32 = parts.next().expect("payload");
    assert!(parts.next().is_none());
    assert!(base32_ok(b32), "{b32}");
    // Payload — nonce (24), случайное значение (16), время (8), имитоприставка (16).
    assert_eq!(
        base32_decode(b32).expect("decode").len(),
        NONCE_LEN + TAG_LEN + TIME_LEN + 16
    );
    // Случайное значение — идентификатор записи, 16 байт.
    assert_eq!(tag.len(), TAG_LEN);

    // Проверка: с угловыми скобками и без; время внутри метки — момент постановки.
    let opened = marks
        .open(&format!("<{mid}>"), now() + time::Duration::minutes(5))
        .await
        .expect("open")
        .expect("our mark");
    assert_eq!(opened.tag, tag);
    assert_eq!(opened.at, now());
    assert!(
        marks
            .open(&mid, now() + time::Duration::minutes(5))
            .await
            .expect("open")
            .is_some(),
        "без угловых скобок тоже проверяется"
    );

    // Другая метка — другое случайное значение.
    let (mid2, tag2) = mark_of(&marks).await;
    assert_ne!(mid, mid2);
    assert_ne!(tag, tag2);
}

#[tokio::test]
async fn open_rejects_foreign_and_tampered() {
    let store = MemSecretStore::new(Arc::new(SystemClock));
    secret32(&store);
    let marks = marks(&store);
    let (mid, _) = mark_of(&marks).await;

    // Чужой ключ (id вне набора) — не наш.
    let foreign = mid.replacen("tp1.k1.", "tp1.k2.", 1);
    assert!(marks.open(&foreign, now()).await.expect("open").is_none());

    // Подделка payload: меняется бит base32 — имитоприставка AEAD не сойдётся.
    let (local, domain) = mid.split_once('@').expect("split");
    let mut tampered = local.to_owned();
    let last = tampered.pop().expect("non-empty");
    tampered.push(if last == 'A' { 'B' } else { 'A' });
    assert!(
        marks
            .open(&format!("{tampered}@{domain}"), now())
            .await
            .expect("open")
            .is_none(),
        "подделка payload"
    );

    // Не формат метки вовсе.
    for not_mark in [
        "a1b@example.org",
        "tp1.@example.org",
        "tp2.k1.X@example.org",
        "",
    ] {
        assert!(
            marks.open(not_mark, now()).await.expect("open").is_none(),
            "{not_mark}"
        );
    }

    // Метка от домена another.example не сходится с AAD этой (binding к домену).
    let (other, _) = marks
        .message_id("Another.Example.", now())
        .await
        .expect("mark")
        .expect("mark");
    let (other_local, other_dom) = other.split_once('@').expect("split");
    assert_eq!(
        other_dom, "another.example",
        "домен в нижнем регистре, без точки"
    );
    let swapped = format!("{other_local}@example.org");
    assert!(
        marks.open(&swapped, now()).await.expect("open").is_none(),
        "метка привязана к домену"
    );

    // Время метки в будущем больше допускаемого рассогласования — не подтверждается.
    let (future_mid, _) = marks
        .message_id("example.org", now() + time::Duration::hours(2))
        .await
        .expect("mark")
        .expect("mark");
    assert!(
        marks
            .open(&future_mid, now())
            .await
            .expect("open")
            .is_none(),
        "время метки в будущем"
    );

    // Короткий ключ в хранилище — метки не ставятся.
    let short = MemSecretStore::new(Arc::new(SystemClock));
    short.set(
        &SecretRef::new("thepost/reply", "k1").expect("ref"),
        "too-short",
    );
    assert!(
        ReplyMarks::new(Arc::new(short), config(&[("k1", true)]))
            .message_id("example.org", now())
            .await
            .is_err(),
        "ключ короче 32 байт"
    );
}

#[tokio::test]
async fn marks_disabled_without_keys() {
    let store = MemSecretStore::new(Arc::new(SystemClock));
    let marks = ReplyMarks::new(Arc::new(store), ReplyConfig::default());
    assert!(
        marks
            .message_id("example.org", now())
            .await
            .expect("mark")
            .is_none(),
        "ключей нет — метки выключены"
    );
    // Активного ключа нет — тоже.
    let store = MemSecretStore::new(Arc::new(SystemClock));
    secret32(&store);
    let marks = ReplyMarks::new(Arc::new(store), config(&[("k1", false)]));
    assert!(
        marks
            .message_id("example.org", now())
            .await
            .expect("mark")
            .is_none()
    );
}

const LETTER: &str =
    "From: Alice <alice@example.org>\r\nTo: bob@partner.example\r\nSubject: hi\r\n\r\nHello.\r\n";

#[tokio::test]
async fn ensure_message_id_marks_only_without_it() {
    let store = MemSecretStore::new(Arc::new(SystemClock));
    secret32(&store);
    let marks = marks(&store);

    // Без Message-ID — ставится метка (заголовок в начало письма).
    let raw = bytes::Bytes::from_static(LETTER.as_bytes());
    let (out, id, tag) = marks
        .ensure_message_id(raw.clone(), "example.org", now())
        .await
        .expect("ensure");
    assert!(tag.is_some(), "метка поставлена");
    let id = id.expect("message id");
    assert!(id.starts_with("tp1.k1."), "{id}");
    assert!(
        out.starts_with(format!("Message-ID: <{id}>\r\n").as_bytes()),
        "{}",
        String::from_utf8_lossy(&out)
    );
    assert!(
        String::from_utf8_lossy(&out).contains("Hello."),
        "тело на месте"
    );

    // Message-ID клиента — не заменяется (решение 125 в).
    let client = format!("Message-ID: <client-1@mail.example.net>\r\n{LETTER}");
    let (out, id, tag) = marks
        .ensure_message_id(bytes::Bytes::from(client), "example.org", now())
        .await
        .expect("ensure");
    assert_eq!(tag, None);
    assert_eq!(id.as_deref(), Some("client-1@mail.example.net"));
    assert!(
        out.starts_with(b"Message-ID: <client-1@mail.example.net>"),
        "{}",
        String::from_utf8_lossy(&out)
    );
}

#[tokio::test]
async fn replace_message_id_for_node_letters() {
    let store = MemSecretStore::new(Arc::new(SystemClock));
    secret32(&store);
    let marks = marks(&store);

    // DSN/автоответ узла: прежний Message-ID заменяется меткой.
    let dsn = format!("Message-ID: <dsn.42@mx.example.org>\r\n{LETTER}");
    let (out, tag) = marks
        .replace_message_id(bytes::Bytes::from(dsn), "example.org", now())
        .await
        .expect("replace");
    assert!(tag.is_some());
    let head = String::from_utf8_lossy(&out);
    assert!(head.starts_with("Message-ID: <tp1.k1."), "{head}");
    assert!(!head.contains("dsn.42@mx.example.org"), "{head}");

    // Уже наша метка — письмо без изменений.
    let (out, tag) = marks
        .replace_message_id(out, "example.org", now())
        .await
        .expect("replace");
    assert_eq!(tag, None, "метка уже стоит");
    assert!(
        String::from_utf8_lossy(&out).starts_with("Message-ID: <tp1.k1."),
        "{}",
        String::from_utf8_lossy(&out)
    );

    // Метки выключены — письмо без изменений.
    let empty = ReplyMarks::new(
        Arc::new(MemSecretStore::new(Arc::new(SystemClock))),
        ReplyConfig::default(),
    );
    let (out, tag) = empty
        .replace_message_id(bytes::Bytes::from(dsn.clone()), "example.org", now())
        .await
        .expect("replace");
    assert_eq!(tag, None);
    assert!(String::from_utf8_lossy(&out).contains("dsn.42@mx.example.org"));
}

/// BATV поверх ключей метки: `enforce`, срок 7 дней, два exempt-адреса.
fn batv(store: &MemSecretStore) -> Batv {
    marks(store)
        .with_batv(&crate::config::BatvConfig {
            mode: crate::config::BatvMode::Enforce,
            valid_for: std::time::Duration::from_secs(7 * 24 * 3600),
            exempt: vec!["news@example.org".into(), "lists.example.net".into()],
        })
        .batv()
        .expect("batv")
        .clone()
}

#[tokio::test]
async fn batv_sign_shape_and_rules() {
    let store = MemSecretStore::new(Arc::new(SystemClock));
    secret32(&store);
    let batv = batv(&store);

    // Форма `prvs=KDDDSSSSSS=local@domain`.
    let tagged = batv
        .sign("alice@example.org", now())
        .await
        .expect("sign")
        .expect("tagged");
    let (local, domain) = tagged.split_once('@').expect("domain");
    assert_eq!(domain, "example.org");
    let rest = local.strip_prefix("prvs=").expect("prvs");
    let (val, orig) = rest.split_once('=').expect("value");
    assert_eq!(orig, "alice");
    let (k, ddd, hmac) = (val.as_bytes()[0], &val[1..4], &val[4..]);
    assert_eq!(k, b'0', "первый ключ набора");
    assert!(
        ddd.len() == 3 && ddd.bytes().all(|c| c.is_ascii_digit()),
        "{ddd}"
    );
    assert_eq!(hmac.len(), 6, "{val}");

    // Детерминированность: та же секунда — та же метка (повторы и greylisting видят ту же метку).
    assert_eq!(
        batv.sign("alice@example.org", now()).await.expect("sign"),
        Some(tagged.clone())
    );

    // Пустой отправитель (DSN), SRS-пересылка, уже подписанный и exempt — без метки.
    for bare in [
        "",
        "srs0=abc@example.net",
        "SRS1=xyz=alice@example.net",
        tagged.as_str(),
        "news@example.org",
        "list@lists.example.net",
        "news@LISTS.EXAMPLE.NET",
    ] {
        assert!(
            batv.sign(bare, now()).await.expect("sign").is_none(),
            "{bare}"
        );
    }

    // Ключей нет — без метки.
    let empty = ReplyMarks::new(
        Arc::new(MemSecretStore::new(Arc::new(SystemClock))),
        ReplyConfig::default(),
    )
    .with_batv(&Default::default())
    .batv()
    .expect("batv")
    .clone();
    assert!(
        empty
            .sign("alice@example.org", now())
            .await
            .expect("sign")
            .is_none()
    );
}

#[tokio::test]
async fn batv_open_strips_valid_only() {
    let store = MemSecretStore::new(Arc::new(SystemClock));
    secret32(&store);
    let batv = batv(&store);
    let tagged = batv
        .sign("alice@example.org", now())
        .await
        .expect("sign")
        .expect("tagged");

    // Валидная метка снимается — доставка без метки в адресе.
    let stripped = batv
        .open(&tagged, now() + time::Duration::days(3))
        .await
        .expect("open");
    assert_eq!(
        stripped,
        Some(BatvAddress::Stripped("alice@example.org".into()))
    );

    // Чужой ключ (номер вне набора) — метка не подтверждается.
    let foreign = tagged.replacen("prvs=0", "prvs=9", 1);
    assert_eq!(
        batv.open(&foreign, now()).await.expect("open"),
        Some(BatvAddress::Invalid("foreign key")),
        "{foreign}"
    );

    // Подделка адреса после метки — HMAC не сойдётся.
    let forged = tagged.replace("alice@", "carol@");
    assert_eq!(
        batv.open(&forged, now()).await.expect("open"),
        Some(BatvAddress::Invalid("bad hmac")),
        "{forged}"
    );

    // Другой домен с той же меткой — не сойдётся (адрес входит в подпись).
    let (local, _) = tagged.split_once('@').expect("split");
    let swapped = format!("{local}@another.example");
    assert_eq!(
        batv.open(&swapped, now()).await.expect("open"),
        Some(BatvAddress::Invalid("bad hmac"))
    );

    // Просроченная: срок 7 дней — на 30-й день метка истекла.
    assert_eq!(
        batv.open(&tagged, now() + time::Duration::days(30))
            .await
            .expect("open"),
        Some(BatvAddress::Invalid("expired"))
    );

    // Не формат BATV — `None` (адрес как есть).
    for plain in ["alice@example.org", "prvs=@example.org"] {
        assert_eq!(
            batv.open(plain, now()).await.expect("open"),
            None,
            "{plain}"
        );
    }
    // Плохой номер ключа — не подтверждается.
    assert_eq!(
        batv.open("prvs=X0123456789=alice@example.org", now())
            .await
            .expect("open"),
        Some(BatvAddress::Invalid("bad key number"))
    );
}

#[tokio::test]
async fn batv_rotation_by_key_index() {
    let store = MemSecretStore::new(Arc::new(SystemClock));
    store.set(
        &SecretRef::new("thepost/reply", "k1").expect("ref"),
        "a".repeat(32),
    );
    store.set(
        &SecretRef::new("thepost/reply", "k9").expect("ref"),
        "b".repeat(32),
    );
    // Активный — второй в наборе: K = 1 (номер в наборе).
    let marks = ReplyMarks::new(Arc::new(store), config(&[("k1", false), ("k9", true)]))
        .with_batv(&Default::default());
    let batv = marks.batv().expect("batv").clone();
    let tagged = batv
        .sign("alice@example.org", now())
        .await
        .expect("sign")
        .expect("tagged");
    assert!(tagged.starts_with("prvs=1"), "{tagged}");
    // Метка снимается, проверка — по ключу с тем же номером набора.
    assert_eq!(
        batv.open(&tagged, now()).await.expect("open"),
        Some(BatvAddress::Stripped("alice@example.org".into()))
    );
}

#[test]
fn exempt_lookup() {
    let store = MemSecretStore::new(Arc::new(SystemClock));
    let batv = batv(&store);
    assert!(batv.exempt_of("news@example.org"));
    assert!(batv.exempt_of("NEWS@Example.org"), "без учёта регистра");
    assert!(batv.exempt_of("list@lists.example.net"), "домен без адреса");
    assert!(!batv.exempt_of("alice@example.org"));
    assert!(!batv.exempt_of("news@other.example"));
}

#[test]
fn base32_roundtrip() {
    for len in [0usize, 1, 4, 5, 6, 19, 32, 64] {
        let mut data = vec![0u8; len];
        rand::rng().fill(&mut data[..]);
        let encoded = base32(&data);
        assert!(!encoded.contains('='), "{encoded}");
        assert!(base32_ok(&encoded), "{encoded}");
        assert_eq!(base32_decode(&encoded), Some(data.clone()), "{encoded}");
        // Без учёта регистра.
        assert_eq!(base32_decode(&encoded.to_lowercase()), Some(data.clone()));
    }
    // Чужие символы и лишние биты.
    assert_eq!(base32_decode("abc1"), None, "1 вне алфавита");
    assert_eq!(base32_decode("A"), None, "хвостовые биты не нули");
    assert_eq!(base32_decode("B"), None);
    assert_eq!(base32_decode("E"), Some(vec![4]));
}

#[test]
fn header_helpers() {
    let letter = "From: a@example.org\r\nX-ThePost-Reply: yes\r\nSubject: t\r\n\
                  X-ThePost-Reply: no\r\n folded\r\n\r\nbody";
    let stripped = strip_header(letter.as_bytes(), "X-ThePost-Reply");
    assert_eq!(
        String::from_utf8_lossy(&stripped),
        "From: a@example.org\r\nSubject: t\r\n\r\nbody",
        "свёрнутый заголовок удаляется целиком"
    );
    // Заголовка нет — письмо без изменений.
    assert_eq!(
        strip_header(letter.as_bytes(), "X-ThePost-Spam"),
        bytes::Bytes::copy_from_slice(letter.as_bytes())
    );

    // Замена: все вхождения — одним значением.
    let replaced = replace_header(letter.as_bytes(), "X-ThePost-Reply", "yes");
    assert_eq!(
        String::from_utf8_lossy(&replaced),
        "From: a@example.org\r\nX-ThePost-Reply: yes\r\nSubject: t\r\n\r\nbody"
    );
    // Заголовка нет — ставится в начало.
    let added = replace_header(b"From: a\r\n\r\nbody", "Message-ID", "<x@y>");
    assert_eq!(
        String::from_utf8_lossy(&added),
        "Message-ID: <x@y>\r\nFrom: a\r\n\r\nbody"
    );
}

#[test]
fn split_mark_shape() {
    // Payload настоящей метки — 64 байта (nonce, значение, время, имитоприставка).
    let wire = base32(&vec![7u8; NONCE_LEN + TAG_LEN + TIME_LEN + 16]);
    let (id, domain, decoded) =
        split_mark(&format!("<tp1.a1.b9.{wire}@example.org>")).expect("mark");
    assert_eq!(id, "a1.b9", "id ключа может содержать точки");
    assert_eq!(domain, "example.org");
    assert_eq!(decoded, vec![7u8; 64]);
    // Короткий payload, чужой формат — не метка.
    assert!(split_mark("<tp1.k1.ABCDEFGH@example.org>").is_none());
    assert!(split_mark("<client-1@mail.example.net>").is_none());
    assert!(split_mark("").is_none());
}

#[test]
fn hash_is_canonical_sha256() {
    let a = ReplyMarks::hash_of("<A1b@Example.ORG>");
    let b = ReplyMarks::hash_of("a1b@example.org");
    assert_eq!(a, b, "каноническая форма — без скобок, нижний регистр");
    let digest = sha2::Sha256::digest(
        tp_contracts::reply::canonical_message_id("a1b@example.org").as_bytes(),
    );
    let bytes: &[u8] = a.as_bytes();
    assert_eq!(bytes, digest.as_slice());
}
