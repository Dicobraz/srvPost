//! Запись об отправленном и признак «ответ на наше письмо» (CONTRACTS.md#Reply; решение 125 а, в;
//! исследование `docs/research/2026-11-14-replies-threads.md`).
//!
//! Ответ на наше письмо — признак доверия, а не исключение из проверок: он уменьшает спам-балл и служит
//! условием в матрице доверия ([`crate::trust::Toggle::ReplyOnly`] у клеток автоответа и MDN наружу).
//! Признак ставится, только если выполнены все три условия (проверяет `tp-smtp`): DMARC pass с выравниванием
//! (RFC 9989); отправитель — один из адресатов исходного письма по записи об отправленном ([`SentLog`]);
//! исходному письму не больше `smtp.reply.max_age`. Антивирус, проверка URL и DMARC выполняются всегда —
//! ответ ничего не пропускает (Emotet, Qakbot, TA577 доставляли нагрузку именно ответами; MITRE T1534).
//!
//! Практика: Rspamd `replies` — хэши Message-ID исходящих и символ `REPLY` (−4), `known_senders`;
//! auto-allow и «известные отправители» Mimecast/Outlook/Defender — тоже со спам-проверкой. Message-ID
//! исходящих несёт зашифрованную метку (AEAD): случайное значение, время, id ключа; метка проверяется без
//! БД и доказывает только «наше и свежее», адресат сверяется по записи об отправленном. Message-ID клиента
//! не заменяется (иначе ломается копия в «Отправленных» и цепочка у самого пользователя) — запись ведётся
//! по хэшу ([`canonical_message_id`], [`MessageIdHash`]), как в Rspamd `replies`.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::ids::{AccountId, TenantId, ThreadId};
use crate::secrets::SecretRef;
use crate::transport::normalize_domain;

/// Наибольший размер метки Message-ID (`SentRecord::tag`), байт. Метка — случайное значение, время и id
/// ключа в AEAD (XChaCha20-Poly1305), 128 байт — с запасом.
pub const MAX_TAG_LEN: usize = 128;

/// Каноническая форма Message-ID для записи и поиска ответов: без угловых скобок, обрезка пробелов по краям,
/// нижний регистр ASCII. SHA-256 этой строки — [`MessageIdHash`] (считает вызывающий: крейт контрактов не
/// знает хэшей). Сопоставление без учёта регистра — практика Gmail и Rspamd; две разные записи, различающиеся
/// только регистром local-part, дали бы ложное совпадение, но запись сама по себе доверия не даёт: признак
/// ответа требует ещё DMARC и совпадения отправителя с адресатом (решение 125 а).
pub fn canonical_message_id(raw: &str) -> String {
    let s = raw.trim();
    let s = s
        .strip_prefix('<')
        .and_then(|s| s.strip_suffix('>'))
        .unwrap_or(s);
    s.trim().to_ascii_lowercase()
}

/// Каноническая форма адресата: домен — нижний регистр, A-label IDN (Unicode — punycode, затем
/// [`normalize_domain`]); local-part — как задан. Некорректный адрес — `Invalid`.
pub fn normalize_recipient(addr: &str) -> Result<String> {
    let Some((local, domain)) = addr.rsplit_once('@') else {
        return Err(Error::invalid(format!("адрес без домена: {addr:?}")));
    };
    if local.is_empty() || domain.is_empty() {
        return Err(Error::invalid(format!("неполный адрес: {addr:?}")));
    }
    let ascii = if domain.is_ascii() {
        domain.to_owned()
    } else {
        idna::domain_to_ascii(domain)
            .map_err(|_| Error::invalid(format!("invalid domain {domain:?}")))?
    };
    Ok(format!("{local}@{}", normalize_domain(&ascii)?))
}

/// SHA-256 канонической формы Message-ID клиента ([`canonical_message_id`]): ключ записи об отправленном
/// для ответов с чужим Message-ID (решение 125 в). `Display`, `FromStr` и serde — 64 символа hex в нижнем
/// регистре.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageIdHash(pub [u8; 32]);

impl MessageIdHash {
    /// Байты хэша.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for MessageIdHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut buf = [0u8; 64];
        for (i, b) in self.0.iter().enumerate() {
            buf[2 * i] = HEX[usize::from(b >> 4)];
            buf[2 * i + 1] = HEX[usize::from(b & 0x0f)];
        }
        // Только ASCII-символы hex.
        f.write_str(std::str::from_utf8(&buf).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for MessageIdHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageIdHash({self})")
    }
}

impl FromStr for MessageIdHash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let b = s.as_bytes();
        if b.len() != 64 {
            return Err(Error::invalid("MessageIdHash: expected 64 hex chars"));
        }
        let nibble = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        };
        let mut out = [0u8; 32];
        for (i, pair) in b.as_chunks::<2>().0.iter().enumerate() {
            let (Some(h), Some(l)) = (nibble(pair[0]), nibble(pair[1])) else {
                return Err(Error::invalid("MessageIdHash: not hex"));
            };
            out[i] = (h << 4) | l;
        }
        Ok(MessageIdHash(out))
    }
}

impl Serialize for MessageIdHash {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MessageIdHash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Запись об отправленном письме внешним и партнёрским адресатам (решение 125 в): ключ проверки признака
/// «ответ на наше письмо». Метка (`tag`) — случайное значение расшифрованной метки Message-ID (шифрует
/// `tp-smtp`, контракт формата не знает); письмо с Message-ID клиента — по [`SentRecord::message_id_hash`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SentRecord {
    /// Организация отправителя.
    pub tenant: TenantId,
    /// Учётная запись отправителя.
    pub account: AccountId,
    /// Метка Message-ID — расшифрованное значение (случайное значение, время, id ключа); у записи уникальна,
    /// повтор доставки — та же запись.
    pub tag: Vec<u8>,
    /// SHA-256 канонического Message-ID клиента ([`canonical_message_id`]).
    pub message_id_hash: MessageIdHash,
    /// Адресаты письма — внешние и партнёрские ([`normalize_recipient`], каноническая форма).
    pub recipients: Vec<String>,
    /// Беседа отправленного письма, если известна (привязка письма — `crate::thread::ThreadStore`).
    pub thread: Option<ThreadId>,
    /// Момент отправки (постановки в очередь).
    pub sent_at: OffsetDateTime,
}

impl SentRecord {
    /// Проверяет запись: адресаты непусты и в канонической форме ([`normalize_recipient`]), метка не пустая
    /// и не больше [`MAX_TAG_LEN`]. Иначе — `Invalid`.
    pub fn validate(&self) -> Result<()> {
        if self.tag.is_empty() || self.tag.len() > MAX_TAG_LEN {
            return Err(Error::invalid(format!(
                "размер метки вне 1..={MAX_TAG_LEN}"
            )));
        }
        if self.recipients.is_empty() {
            return Err(Error::invalid("нет адресатов записи об отправленном"));
        }
        for r in &self.recipients {
            if normalize_recipient(r)?.as_str() != r.as_str() {
                return Err(Error::invalid(format!(
                    "адресат {r:?} не в канонической форме"
                )));
            }
        }
        Ok(())
    }
}

/// Итог проверки признака «ответ на наше письмо» (решение 125 а): запись об отправленном, на которую
/// ссылается ответ, и возраст исходного письма. Оставшиеся условия — DMARC и совпадение отправителя —
/// [`ReplyEvidence::confirms`] и вызывающий (`tp-smtp`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplyEvidence {
    /// Запись об отправленном (найдена по метке или хэшу Message-ID).
    pub sent: SentRecord,
    /// Возраст исходного письма (сейчас минус [`SentRecord::sent_at`]).
    pub age: Duration,
}

impl ReplyEvidence {
    /// Отправитель `sender` (канонизируется) — среди адресатов записи и письмо не старше `max_age`
    /// (`smtp.reply.max_age`). local-part сравнивается без учёта регистра (каноническая форма хранит
    /// как задано, RFC 5321 2.3.11). DMARC проверяет вызывающий; все три условия сразу — признак ответа.
    pub fn confirms(&self, sender: &str, max_age: Duration) -> bool {
        let Ok(sender) = normalize_recipient(sender) else {
            return false;
        };
        self.age <= max_age
            && self
                .sent
                .recipients
                .iter()
                .any(|r| r.eq_ignore_ascii_case(&sender))
    }
}

/// Возраст письма с момента `sent_at` — для [`ReplyEvidence`] и признака ответа (момент в будущем —
/// нулевой возраст, `try_into` насыщается в нуле).
pub fn age_since(sent_at: OffsetDateTime, now: OffsetDateTime) -> Duration {
    (now - sent_at).try_into().unwrap_or(Duration::ZERO)
}

/// Ключ метки ответа (решение 125 в): значение — в хранилище секретов ([`SecretRef`]), идентификатор —
/// открытым префиксом в метке (`tp1.<id>.…`, BATV `K`). Активный ключ подписывает новые метки, прежние
/// проверяют до конца срока метки; ротация — замена набора конфигурации (hot reload), без перезапуска.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyKey {
    /// Идентификатор ключа в метке: 1–16 байт `[a-z0-9][a-z0-9.-]*` на границе слова — безопасно внутри
    /// local-part Message-ID и BATV-метки.
    pub id: String,
    /// Ключ в хранилище секретов (значение — байты ключа).
    pub secret: SecretRef,
    /// Активный: подписывает новые метки. В наборе ([`ReplyKeys`]) — ровно один.
    #[serde(default)]
    pub active: bool,
}

impl ReplyKey {
    /// Проверяет идентификатор ключа. Иначе — `Invalid`.
    pub fn validate(&self) -> Result<()> {
        valid_key_id(&self.id)
    }
}

/// Проверяет идентификатор ключа метки: 1–16 байт, `[a-z0-9][a-z0-9.-]*`, на границах — буква или цифра.
pub fn valid_key_id(id: &str) -> Result<()> {
    let b = id.as_bytes();
    let inner = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-';
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    let ok = (1..=16).contains(&b.len())
        && b.first().is_some_and(|c| edge(*c))
        && b.last().is_some_and(|c| edge(*c))
        && b.iter().all(|c| inner(*c));
    if ok {
        Ok(())
    } else {
        Err(Error::invalid(
            "идентификатор ключа метки: 1–16 байт [a-z0-9.-], на границах — буква или цифра",
        ))
    }
}

/// Набор ключей меток ответа (секция `smtp.reply.keys`): активный подписывает, все проверяют
/// ([`ReplyKeys::for_id`]). Пустой набор — метки не ставятся и не проверяются.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReplyKeys {
    /// Ключи; идентификаторы без повторов.
    #[serde(default)]
    pub keys: Vec<ReplyKey>,
}

impl ReplyKeys {
    /// Проверяет набор: каждый ключ ([`ReplyKey::validate`]), идентификаторы без повторов, при непустом
    /// наборе активный ровно один. Иначе — `Invalid`.
    pub fn validate(&self) -> Result<()> {
        for k in &self.keys {
            k.validate()?;
        }
        let mut ids: Vec<&str> = self.keys.iter().map(|k| k.id.as_str()).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return Err(Error::invalid("повтор идентификатора ключа метки"));
        }
        if !self.keys.is_empty() && self.keys.iter().filter(|k| k.active).count() != 1 {
            return Err(Error::invalid(
                "при непустом наборе ключей активный ровно один",
            ));
        }
        Ok(())
    }

    /// Активный ключ (подписывает новые метки).
    pub fn active(&self) -> Option<&ReplyKey> {
        self.keys.iter().find(|k| k.active)
    }

    /// Ключ с идентификатором `id` (проверка метки по открытому префиксу).
    pub fn for_id(&self, id: &str) -> Option<&ReplyKey> {
        self.keys.iter().find(|k| k.id == id)
    }
}

/// Запись об отправленном (решение 125 в): только добавление и поиск, содержимого писем нет. Реализация —
/// `tp-meta` (META-86), in-memory — `tp-testkit::MemSentLog`; пишет `tp-smtp` при постановке в очередь письма
/// с внешними или партнёрскими адресатами (SMTP-51). Срок хранения — не меньше `smtp.reply.max_age`
/// (по умолчанию 30 суток), очистка — [`SentLog::purge_before`] из роли maintenance; реализация хранит
/// не дольше своей секции конфигурации, но не короче максимального срока признака.
#[async_trait]
pub trait SentLog: Send + Sync + 'static {
    /// Записывает письмо. Запись с той же меткой и тем же содержимым — не ошибка (повтор постановки в
    /// очередь идемпотентен); с другой — `Conflict` (метка уникальна). Некорректная запись — `Invalid`.
    async fn record(&self, record: SentRecord) -> Result<()>;

    /// Запись по метке Message-ID (ответ с нашей меткой: расшифровал — нашёл исходное письмо). Чужая
    /// организация и нет записи — `None`.
    async fn by_tag(&self, tenant: TenantId, tag: &[u8]) -> Result<Option<SentRecord>>;

    /// Записи по хэшу Message-ID клиента (ответ с чужим Message-ID, как Rspamd `replies`), по `sent_at`
    /// по убыванию. Чужая организация — пусто.
    async fn by_message_id_hash(
        &self,
        tenant: TenantId,
        hash: &MessageIdHash,
    ) -> Result<Vec<SentRecord>>;

    /// Удаляет записи всех организаций с `sent_at < before` (maintenance), возвращает число.
    async fn purge_before(&self, before: OffsetDateTime) -> Result<usize>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn object_safe() {
        fn _log(_: Arc<dyn SentLog>) {}
    }

    fn sha(s: &str) -> [u8; 32] {
        // Тестовый «хэш»: контракт не считает SHA-256 (хэшируют реализации); для проверки формы достаточно
        // стабильного 32-байтового значения.
        let mut out = [0u8; 32];
        for (i, b) in s.bytes().enumerate() {
            out[i % 32] = out[i % 32]
                .wrapping_add(b)
                .wrapping_mul(31)
                .wrapping_add(i as u8);
        }
        out
    }

    #[test]
    fn canonical_message_id_forms() {
        assert_eq!(
            canonical_message_id("<A1b@Example.ORG>"),
            "a1b@example.org",
            "угловые скобки и регистр"
        );
        assert_eq!(
            canonical_message_id("  <mid@.example>  "),
            "mid@.example",
            "пробелы по краям"
        );
        assert_eq!(canonical_message_id("no-brackets@x"), "no-brackets@x");
        assert_eq!(
            canonical_message_id("<a@x"),
            "<a@x",
            "парная скобка — целиком"
        );
        assert_eq!(canonical_message_id(""), "");
    }

    #[test]
    fn normalize_recipient_form() {
        assert_eq!(
            normalize_recipient("User@ПРИМЕР.РФ").expect("rf"),
            "User@xn--e1afmkfd.xn--p1ai",
            "домен — нижний регистр, A-label; local-part как задан"
        );
        assert_eq!(
            normalize_recipient("u@Example.COM").expect("ok"),
            "u@example.com"
        );
        for bad in ["", "@example.org", "u@", "без домена"] {
            assert!(normalize_recipient(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn message_id_hash_hex_and_serde() {
        let h = MessageIdHash(sha("a1b@example.org"));
        let hex = h.to_string();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, hex.to_ascii_lowercase());
        assert_eq!(hex.parse::<MessageIdHash>().expect("parse"), h);
        assert!("zz".parse::<MessageIdHash>().is_err());
        assert!("a".repeat(64).parse::<MessageIdHash>().is_ok());
        let json = serde_json::to_string(&h).expect("json");
        assert_eq!(json, format!("\"{hex}\""));
        assert_eq!(
            serde_json::from_str::<MessageIdHash>(&json).expect("from json"),
            h
        );
        assert!(format!("{h:?}").contains("MessageIdHash"));
    }

    #[test]
    fn record_validate() {
        let tag = vec![7u8; 8];
        let mut r = SentRecord {
            tenant: TenantId::DEFAULT,
            account: AccountId::new(),
            tag: tag.clone(),
            message_id_hash: MessageIdHash(sha("mid@example.org")),
            recipients: vec!["bob@partner.example".into()],
            thread: None,
            sent_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert_eq!(r.validate(), Ok(()));
        r.recipients.clear();
        assert!(r.validate().is_err(), "нет адресатов");
        r.recipients = vec!["BOB@Partner.example".into()];
        assert!(r.validate().is_err(), "не канонический адресат");
        r.recipients = vec!["bob@partner.example".into()];
        r.tag = Vec::new();
        assert!(r.validate().is_err(), "пустая метка");
        r.tag = vec![1u8; MAX_TAG_LEN + 1];
        assert!(r.validate().is_err(), "метка длиннее предела");
        r.tag = vec![1u8; MAX_TAG_LEN];
        assert_eq!(r.validate(), Ok(()));
    }

    #[test]
    fn evidence_confirms_sender_and_age() {
        let record = |recipients: Vec<&str>| SentRecord {
            tenant: TenantId::DEFAULT,
            account: AccountId::new(),
            tag: vec![1u8; 8],
            message_id_hash: MessageIdHash(sha("mid@example.org")),
            recipients: recipients.iter().map(|s| s.to_string()).collect(),
            thread: None,
            sent_at: OffsetDateTime::UNIX_EPOCH,
        };
        let sent = record(vec!["bob@partner.example", "carol@external.example"]);
        let ev = ReplyEvidence {
            sent,
            age: Duration::from_secs(3600),
        };
        assert!(
            ev.confirms("BOB@PARTNER.example", Duration::from_secs(30 * 24 * 3600)),
            "отправитель — адресат, адрес канонизируется"
        );
        assert!(
            !ev.confirms("eve@example.net", Duration::from_secs(30 * 24 * 3600)),
            "отправитель не адресат"
        );
        assert!(
            !ev.confirms("bob@partner.example", Duration::from_secs(3599)),
            "письмо старше max_age"
        );
        assert!(
            ev.confirms("bob@partner.example", Duration::from_secs(3600)),
            "возраст ровно max_age — ещё подтверждает"
        );
        assert!(!ev.confirms("не адрес", Duration::from_secs(3600)));
    }

    #[test]
    fn age_since_saturates() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let d = |s: i64| Duration::from_secs(s.max(0) as u64);
        let shift = |s: i64| now + time::Duration::seconds(s);
        assert_eq!(age_since(shift(-10), now), d(10), "момент в прошлом");
        assert_eq!(age_since(now, now), Duration::ZERO);
        // Момент в будущем — нулевой возраст (насыщение).
        assert_eq!(age_since(shift(10), now), d(0));
    }

    #[test]
    fn keys_validate_and_lookup() {
        let keys = |list: Vec<ReplyKey>| ReplyKeys { keys: list };
        let key = |id: &str, active: bool| ReplyKey {
            id: id.into(),
            secret: SecretRef::new("thepost/reply", id).expect("ref"),
            active,
        };
        let pair = keys(vec![key("k1", true), key("k2", false)]);
        assert_eq!(pair.validate(), Ok(()));
        assert_eq!(pair.active().map(|k| k.id.as_str()), Some("k1"));
        assert_eq!(pair.for_id("k2").map(|k| k.active), Some(false));
        assert!(pair.for_id("k3").is_none());

        // Ровно один активный.
        assert!(
            keys(vec![key("k1", false), key("k2", false)])
                .validate()
                .is_err()
        );
        assert!(
            keys(vec![key("k1", true), key("k2", true)])
                .validate()
                .is_err()
        );
        // Пустой набор допустим — метки выключены.
        assert_eq!(ReplyKeys::default().validate(), Ok(()));
        assert!(ReplyKeys::default().active().is_none());
        // Повтор идентификатора и плохой идентификатор.
        assert!(
            keys(vec![key("k1", true), key("k1", false)])
                .validate()
                .is_err()
        );
        let long = "k".repeat(17);
        for bad in ["", "K", "-k", "k-", "k_k", long.as_str()] {
            assert!(valid_key_id(bad).is_err(), "{bad:?}");
        }
        assert!(valid_key_id("a1.b-c9").is_ok());
        // Частичная запись конфигурации читается.
        let parsed: ReplyKeys = serde_json::from_str(
            r#"{"keys": [{"id": "k1", "secret": {"secret": "thepost/reply#k1"}, "active": true}]}"#,
        )
        .expect("parse");
        assert_eq!(parsed.validate(), Ok(()));
    }
}
