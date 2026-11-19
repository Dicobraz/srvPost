//! Метка ответа (SMTP-51, решение 125 в; CONTRACTS.md#Reply): зашифрованная метка Message-ID, BATV и признак
//! «ответ на наше письмо».
//!
//! - [`ReplyMarks`] — метка Message-ID исходящих: левая часть `tp1.<id ключа>.<base32>@<домен>` — XChaCha20-Poly1305
//!   (AEAD, DEPS-18) от случайного значения и времени; шифруется, чтобы не раскрывать время и ящик, id ключа —
//!   открытым префиксом (ротация без перезапуска, [`ReplyMarks::update`]). Ключи — в хранилище секретов
//!   ([`tp_contracts::secrets`], CTR-94), значение — не меньше 32 байт. Метка ставится, где Message-ID задаёт
//!   сервер ([`ReplyMarks::ensure_message_id`], [`ReplyMarks::replace_message_id`]): письмо submission и
//!   [`crate::Delivery::submit`] без Message-ID, автоответы, DSN, iMIP узла. Message-ID клиента не заменяется —
//!   запись об отправленном ведётся по его хэшу (решение 125 в). Проверка ([`ReplyMarks::open`]) — без БД: метка
//!   доказывает только «наше и свежее» (ключ известен, время не в будущем), адресат сверяется по записи
//!   [`tp_contracts::reply::SentLog`].
//! - [`Batv`] — BATV (draft-levine-smtp-batv-01): `MAIL FROM` исходящих — `prvs=KDDDSSSSSS=local@domain`
//!   (K — номер ключа, DDD — день истечения, SSSSSS — первые 3 байта HMAC-SHA1 от `K`+`DDD`+исходного адреса);
//!   срок `smtp.batv.valid_for` (7 дней), адреса и домены `smtp.batv.exempt` метку не получают. Ключи — те же
//!   (`smtp.reply.keys`), K — номер ключа в наборе (0–9). Приём: письмо с пустым `MAIL FROM` на локальный адрес
//!   без валидной метки — `550 5.7.1` на `RCPT` в режиме `enforce` ([`BatvMode`]); с валидной — метка снимается
//!   ([`Batv::open`]), доставка; режим `log` — только журнал и метрика.
//!
//! Признак «ответ на наше письмо» (решение 125 а) ставит [`crate::Delivery`] по `In-Reply-To`/`References`:
//! метка расшифрована или хэш Message-ID найден в записи об отправленном, отправитель `From` — среди адресатов
//! записи, DMARC pass с выравниванием и возраст ≤ `smtp.reply.max_age` — все условия сразу. Антивирус, URL и
//! DMARC признак ничего не пропускает (Emotet, Qakbot, TA577 доставляли нагрузку ответами; MITRE T1534).
//!
//! Практика: Rspamd `replies` — «cookie» в Message-ID (зашифрованная метка, срок), BATV/SRS — усечённый
//! HMAC-SHA1; SpamAssassin VBounce. Своей криптографии нет — крейты RustCrypto (решение 2026-10-31).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use chacha20poly1305::aead::common::getrandom::SysRng;
use chacha20poly1305::aead::rand_core::UnwrapErr;
use chacha20poly1305::aead::{Aead, Generate, KeyInit, Payload};
use chacha20poly1305::{Key, KeySizeUser, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tp_contracts::reply::MessageIdHash;
use tp_contracts::secrets::SecretStore;
use tp_contracts::{Error, Result};

use crate::config::{BatvMode, ReplyConfig, ReplyKeyConfig};

/// Префикс левой части метки Message-ID: `tp1.<id>.<base32>@<домен>`.
pub const MARK_PREFIX: &str = "tp1";

/// Заголовок признака «ответ на наше письмо» (DEP-56: Rspamd по нему снижает балл). Пришедший извне
/// удаляется до проверок; свой узел ставит до Milter (SMTP-51).
pub const REPLY_HEADER: &str = "X-ThePost-Reply";

/// Случайное значение метки, байт: идентификатор записи об отправленном (`SentRecord::tag`).
const TAG_LEN: usize = 16;

/// Время в метке, байт (unix-секунды, big-endian).
const TIME_LEN: usize = 8;

/// Nonce XChaCha20-Poly1305, байт (24 — можно брать случайным, DEPS-18).
const NONCE_LEN: usize = 24;

/// Метка времени в будущем: допускаемая рассинхронизация часов (метку ставит и проверяет один узел
/// установки; запас — на кластер и перечитывание ключей).
const SKEW: time::Duration = time::Duration::hours(1);

/// Наибольший номер ключа BATV (K — один десятичный знак, draft-levine-smtp-batv-01).
const BATV_KEYS: usize = 10;

/// Расшифрованная метка Message-ID: случайное значение (ключ записи об отправленном) и время.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMark {
    /// Случайное значение метки (`SentRecord::tag`).
    pub tag: Vec<u8>,
    /// Момент постановки письма (внутри метки; не в будущем).
    pub at: OffsetDateTime,
}

/// Ключи в кэше: момент загрузки → материал.
type KeyCache = HashMap<String, (Instant, Arc<[u8]>)>;

/// Набор ключей и их кэш (разделяются клонами [`ReplyMarks`]).
#[derive(Debug, Default)]
struct KeyState {
    keys: RwLock<Arc<Vec<ReplyKeyConfig>>>,
    cache: Mutex<KeyCache>,
}

/// Метка ответа: ключи из хранилища секретов, метки Message-ID исходящих и BATV (секция `smtp.batv`).
/// Клоны разделяют набор ключей и кэш.
#[derive(Clone)]
pub struct ReplyMarks {
    secrets: Arc<dyn SecretStore>,
    st: Arc<KeyState>,
    refresh: Duration,
    /// BATV поверх тех же ключей.
    batv: Option<Box<Batv>>,
}

impl fmt::Debug for ReplyMarks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Материал ключей в отладочный вывод не попадает.
        f.debug_struct("ReplyMarks")
            .field("keys", &read(&self.st.keys).len())
            .field("batv", &self.batv.is_some())
            .finish()
    }
}

impl ReplyMarks {
    /// Метки по секции `smtp.reply` с ключами из `secrets` (без BATV — [`ReplyMarks::with_batv`]).
    pub fn new(secrets: Arc<dyn SecretStore>, cfg: ReplyConfig) -> Self {
        Self {
            secrets,
            st: Arc::new(KeyState {
                keys: RwLock::new(Arc::new(cfg.keys.clone())),
                cache: Mutex::new(HashMap::new()),
            }),
            refresh: cfg.key_refresh,
            batv: None,
        }
    }

    /// BATV поверх ключей метки (секция `smtp.batv`): подпись `MAIL FROM` исходящих и проверка адресов
    /// bounce на приёме.
    pub fn with_batv(mut self, cfg: &crate::config::BatvConfig) -> Self {
        self.batv = Some(Box::new(Batv {
            marks: self.clone(),
            mode: cfg.mode,
            valid_for: cfg.valid_for,
            exempt: cfg.exempt.clone(),
        }));
        self
    }

    /// BATV этой метки; `None` — секция `smtp.batv` не задана.
    pub fn batv(&self) -> Option<&Batv> {
        self.batv.as_deref()
    }

    /// Новая версия секции (hot reload): ключи перечитываются, прежние продолжают проверять метки до конца
    /// их срока.
    pub fn update(&self, cfg: ReplyConfig) {
        *self
            .st
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(cfg.keys.clone());
        lock(&self.st.cache).clear();
    }

    /// Метки выключены (ключей нет).
    fn disabled(&self) -> bool {
        read(&self.st.keys).is_empty()
    }

    /// Материал ключа из хранилища секретов (кэш на `smtp.reply.key_refresh`); `None` — ключа нет в наборе.
    async fn material(&self, id: &str) -> Result<Option<Arc<[u8]>>> {
        let Some(key) = read(&self.st.keys).iter().find(|k| k.id == id).cloned() else {
            return Ok(None);
        };
        if let Some((at, m)) = lock(&self.st.cache).get(&key.id).cloned()
            && at.elapsed() < self.refresh
        {
            return Ok(Some(m));
        }
        let secret = self.secrets.get(&key.secret).await?;
        let bytes = secret.expose().as_bytes();
        if bytes.len() < XChaCha20Poly1305::key_size() {
            return Err(Error::invalid(format!(
                "ключ метки {}: не меньше {} байт",
                key.id,
                XChaCha20Poly1305::key_size()
            )));
        }
        let material: Arc<[u8]> = Arc::from(bytes);
        lock(&self.st.cache).insert(key.id.clone(), (Instant::now(), material.clone()));
        Ok(Some(material))
    }

    /// Действующий (активный) ключ и его номер в наборе.
    fn active(&self) -> Option<(usize, ReplyKeyConfig)> {
        read(&self.st.keys)
            .iter()
            .enumerate()
            .find(|(_, k)| k.active)
            .map(|(i, k)| (i, k.clone()))
    }

    /// Метка Message-ID `tp1.<id>.<base32>@<domain>` и случайное значение (для записи об отправленном);
    /// `None` — метки выключены (ключей нет) или активного ключа нет.
    pub async fn message_id(
        &self,
        domain: &str,
        now: OffsetDateTime,
    ) -> Result<Option<(String, Vec<u8>)>> {
        if self.disabled() {
            return Ok(None);
        }
        let Some((_, key)) = self.active() else {
            return Ok(None);
        };
        let Some(material) = self.material(&key.id).await? else {
            return Ok(None);
        };
        let mut rng = UnwrapErr(SysRng);
        let tag: [u8; TAG_LEN] = Generate::generate_from_rng(&mut rng);
        let mut pt = Vec::with_capacity(TAG_LEN + TIME_LEN);
        pt.extend_from_slice(&tag);
        pt.extend_from_slice(&now.unix_timestamp().to_be_bytes());
        let cipher_key = Key::try_from(&material[..]).expect("длина ключа проверена");
        let cipher = XChaCha20Poly1305::new(&cipher_key);
        // Nonce 24 байта случайный (XChaCha20: столкновения практически исключены, DEPS-18).
        let nonce: XNonce = Generate::generate_from_rng(&mut rng);
        let aad = format!("{MARK_PREFIX}.{}@{}", key.id, domain_of(domain));
        let mut wire = nonce.to_vec();
        wire.extend_from_slice(
            &cipher
                .encrypt(
                    &nonce,
                    Payload {
                        msg: &pt,
                        aad: aad.as_bytes(),
                    },
                )
                .map_err(|_| Error::internal("метка Message-ID: ошибка шифрования"))?,
        );
        let mid = format!(
            "{MARK_PREFIX}.{}.{}@{}",
            key.id,
            base32(&wire),
            domain_of(domain)
        );
        Ok(Some((mid, tag.to_vec())))
    }

    /// Проверяет метку в Message-ID `message_id` (с угловыми скобками или без): ключ известен, время не в
    /// будущем. `None` — не метка нашего формата, чужой или убранный ключ, подделка.
    pub async fn open(&self, message_id: &str, now: OffsetDateTime) -> Result<Option<OpenedMark>> {
        let Some((id, domain, wire)) = split_mark(message_id) else {
            return Ok(None);
        };
        let Some(material) = self.material(&id).await? else {
            return Ok(None);
        };
        let (nonce, ct) = wire.split_at(NONCE_LEN);
        let cipher_key = Key::try_from(&material[..]).expect("длина ключа проверена");
        let cipher = XChaCha20Poly1305::new(&cipher_key);
        let aad = format!("{MARK_PREFIX}.{id}@{}", domain_of(&domain));
        let nonce = XNonce::try_from(nonce).expect("nonce метки");
        let pt = match cipher.decrypt(
            &nonce,
            Payload {
                msg: ct,
                aad: aad.as_bytes(),
            },
        ) {
            Ok(pt) => pt,
            // Подделка или чужой ключ — метка не подтверждается.
            Err(_) => return Ok(None),
        };
        if pt.len() != TAG_LEN + TIME_LEN {
            return Ok(None);
        }
        let (tag, time) = pt.split_at(TAG_LEN);
        let at = OffsetDateTime::from_unix_timestamp(i64::from_be_bytes(
            time.try_into().expect("8 байт"),
        ))
        .map_err(|e| Error::invalid(format!("метка Message-ID: время ({e})")))?;
        if at > now + SKEW {
            return Ok(None);
        }
        Ok(Some(OpenedMark {
            tag: tag.to_vec(),
            at,
        }))
    }

    /// Message-ID письма без угловых скобок и пробелов; `None` — заголовка нет.
    pub(crate) fn current_id(raw: &[u8]) -> Option<String> {
        let msg = mail_parser::MessageParser::default().parse_headers(raw)?;
        let id = msg.message_id()?;
        let id = id.trim().trim_matches(|c| c == '<' || c == '>').trim();
        (!id.is_empty()).then(|| id.to_owned())
    }

    /// Ставит метку письма без Message-ID (письмо submission и отправка вне сессии: клиент не задал
    /// Message-ID): заголовок в начало. Возвращает письмо, итоговый Message-ID (клиентский или метка) и
    /// случайное значение метки (`None` — Message-ID был или метки выключены).
    pub async fn ensure_message_id(
        &self,
        raw: bytes::Bytes,
        domain: &str,
        now: OffsetDateTime,
    ) -> Result<(bytes::Bytes, Option<String>, Option<Vec<u8>>)> {
        if let Some(id) = Self::current_id(&raw) {
            return Ok((raw, Some(id), None));
        }
        match self.message_id(domain, now).await? {
            Some((mid, tag)) => Ok((
                prepend_header(&raw, "Message-ID", &format!("<{mid}>")),
                Some(mid),
                Some(tag),
            )),
            None => Ok((raw, None, None)),
        }
    }

    /// Заменяет Message-ID письма на метку (письма узла: DSN, автоответы — их Message-ID задаёт сервер);
    /// уже стоит наша метка — письмо без изменений. Возвращает письмо и случайное значение метки (`None` —
    /// метки выключены или уже стоят).
    pub async fn replace_message_id(
        &self,
        raw: bytes::Bytes,
        domain: &str,
        now: OffsetDateTime,
    ) -> Result<(bytes::Bytes, Option<Vec<u8>>)> {
        if Self::current_id(&raw).is_some_and(|id| {
            id.rsplit_once('@')
                .is_some_and(|(local, _)| local.starts_with(MARK_PREFIX))
        }) {
            return Ok((raw, None));
        }
        let Some((mid, tag)) = self.message_id(domain, now).await? else {
            return Ok((raw, None));
        };
        Ok((
            replace_header(&raw, "Message-ID", &format!("<{mid}>")),
            Some(tag),
        ))
    }

    /// SHA-256 канонического Message-ID — ключ записи об отправленном для ответов с чужим Message-ID
    /// (решение 125 в, как Rspamd `replies`).
    pub fn hash_of(message_id: &str) -> MessageIdHash {
        let digest =
            Sha256::digest(tp_contracts::reply::canonical_message_id(message_id).as_bytes());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&digest);
        MessageIdHash(hash)
    }
}

/// BATV (draft-levine-smtp-batv-01): подпись `MAIL FROM` исходящих и проверка адресов bounce на приёме.
/// Ключи — набор метки (`smtp.reply.keys`): K — номер ключа в наборе (0–9, активный подписывает).
#[derive(Clone)]
pub struct Batv {
    marks: ReplyMarks,
    mode: BatvMode,
    valid_for: Duration,
    exempt: Vec<String>,
}

impl fmt::Debug for Batv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Batv")
            .field("mode", &self.mode)
            .field("valid_for", &self.valid_for)
            .finish()
    }
}

/// Итог проверки адреса BATV на приёме.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatvAddress {
    /// Метка валидна: адрес без метки (доставка).
    Stripped(String),
    /// Метки нет или не сходится: bounce (пустой `MAIL FROM`) отклоняется в `enforce` ([`Batv::enforce`]),
    /// в `log` — только журнал и метрика. Причина — для журнала.
    Invalid(&'static str),
}

impl Batv {
    /// Режим проверки адресов bounce.
    pub fn mode(&self) -> BatvMode {
        self.mode
    }

    /// Адреса bounce проверяются по метке (`smtp.batv.mode: enforce`).
    pub fn enforce(&self) -> bool {
        self.mode == BatvMode::Enforce
    }

    /// Подписывает отправителя конверта `from` (исходящие наружу): `prvs=KDDDSSSSSS=local@domain`.
    /// `None` — без метки (значение то же): пустой отправитель (DSN `<>`), адрес SRS-пересылки, адрес или
    /// домен из `smtp.batv.exempt`, уже подписанный адрес, ключи метки не заданы или активный вне номеров 0–9.
    /// Считается один раз при постановке в очередь и хранится в записи: повторы и greylisting видят ту же метку.
    pub async fn sign(&self, from: &str, now: OffsetDateTime) -> Result<Option<String>> {
        if from.is_empty() {
            return Ok(None);
        }
        let Some((local, _)) = from.rsplit_once('@') else {
            return Ok(None);
        };
        let srs = local.len() > 4
            && matches!(
                local.get(..4).map(str::to_ascii_uppercase).as_deref(),
                Some("SRS0") | Some("SRS1")
            );
        if srs
            || local
                .get(..5)
                .is_some_and(|t| t.eq_ignore_ascii_case("prvs="))
            || self.exempt_of(from)
        {
            return Ok(None);
        }
        let Some((index, key)) = self.marks.active() else {
            return Ok(None);
        };
        if index >= BATV_KEYS {
            tracing::warn!(key = %key.id, "batv: номер ключа вне 0–9, MAIL FROM без метки");
            return Ok(None);
        }
        let Some(material) = self.marks.material(&key.id).await? else {
            return Ok(None);
        };
        let k = index as u8 + b'0';
        let ddd = expiry(now, self.valid_for);
        let hash = prvs_hash(&material, k, &ddd, from);
        Ok(Some(format!("prvs={}{}{}={from}", k as char, ddd, hash)))
    }

    /// Проверяет адрес `address` (получатель bounce): валидная метка снимается. `None` — адрес не в формате
    /// BATV (без `prvs=`), без домена.
    pub async fn open(&self, address: &str, now: OffsetDateTime) -> Result<Option<BatvAddress>> {
        let Some((val, original, domain)) = split_prvs(address) else {
            return Ok(None);
        };
        let val = val.as_bytes();
        let Some(&k) = val.first() else {
            return Ok(None);
        };
        if !k.is_ascii_digit() {
            return Ok(Some(BatvAddress::Invalid("bad key number")));
        }
        let key = read(&self.marks.st.keys)
            .get(usize::from(k - b'0'))
            .cloned();
        let Some(key) = key else {
            return Ok(Some(BatvAddress::Invalid("foreign key")));
        };
        let ddd = match val.get(1..4) {
            Some(d) if d.iter().all(|c| c.is_ascii_digit()) => {
                String::from_utf8_lossy(d).into_owned()
            }
            _ => return Ok(Some(BatvAddress::Invalid("bad expiry day"))),
        };
        let Some(given) = val.get(4..10).and_then(|g| std::str::from_utf8(g).ok()) else {
            return Ok(Some(BatvAddress::Invalid("bad hmac")));
        };
        let from = format!("{original}@{domain}");
        let material = self.marks.material(&key.id).await?;
        let want = prvs_hash(material.as_deref().unwrap_or_default(), k, &ddd, &from);
        if !given.eq_ignore_ascii_case(&want) {
            return Ok(Some(BatvAddress::Invalid("bad hmac")));
        }
        let Ok(day) = ddd.parse::<u32>() else {
            return Ok(Some(BatvAddress::Invalid("bad expiry day")));
        };
        if expired(days(now), day) {
            return Ok(Some(BatvAddress::Invalid("expired")));
        }
        Ok(Some(BatvAddress::Stripped(from)))
    }

    /// Адрес или его домен — в `smtp.batv.exempt` (рассылки, ezmlm): метка не ставится и не требуется.
    pub fn exempt_of(&self, address: &str) -> bool {
        let domain = address.rsplit_once('@').map(|(_, d)| d).unwrap_or_default();
        self.exempt
            .iter()
            .any(|x| x.eq_ignore_ascii_case(address) || x.eq_ignore_ascii_case(domain))
    }
}

/// Дни от 1970-01-01 (низкие три цифры — DDD, draft-levine-smtp-batv-01).
fn days(now: OffsetDateTime) -> u32 {
    (now.unix_timestamp().div_euclid(86_400).rem_euclid(1000)) as u32
}

/// День истечения метки (строка из трёх цифр): сегодня + `valid_for` (срок ограничен половиной цикла 1000
/// дней — окно неоднозначности проверки).
fn expiry(now: OffsetDateTime, valid_for: Duration) -> String {
    let days = (valid_for.as_secs() / 86_400).min(498);
    let d = now.unix_timestamp().div_euclid(86_400) + i64::try_from(days).unwrap_or(0) + 1;
    format!("{:03}", d.rem_euclid(1000))
}

/// Истекла ли метка: день `ddd` в прошлом (сравнение по модулю 1000 без знака, draft §4.2.2; окно
/// неоднозначности — полцикла).
fn expired(today: u32, ddd: u32) -> bool {
    let age = (today + 1000 - ddd % 1000) % 1000;
    (1..=500).contains(&age)
}

/// HMAC-SHA1 (draft-levine-smtp-batv-01) от `K`, `DDD` и исходного адреса: первые 3 байта, hex (6 знаков).
fn prvs_hash(key: &[u8], k: u8, ddd: &str, from: &str) -> String {
    let mut mac =
        <Hmac<Sha1> as KeyInit>::new_from_slice(key).expect("HMAC принимает любую длину ключа");
    mac.update(&[k]);
    mac.update(ddd.as_bytes());
    mac.update(from.as_bytes());
    let out = mac.finalize().into_bytes();
    out[..3].iter().map(|b| format!("{b:02x}")).collect()
}

/// Разбор `prvs=KDDDSSSSSS=local@domain`: значение метки, локальная часть и домен исходного адреса.
fn split_prvs(address: &str) -> Option<(&str, &str, &str)> {
    let (local, domain) = address.rsplit_once('@')?;
    let rest = local
        .get(..5)
        .filter(|t| t.eq_ignore_ascii_case("prvs="))
        .map(|_| &local[5..])?;
    let (val, orig) = rest.split_once('=')?;
    (val.len() == 10 && !orig.is_empty() && !domain.is_empty()).then_some((val, orig, domain))
}

/// Разбор Message-ID с меткой: id ключа, домен и байты base32; `None` — не формат `tp1.<id>.<b32>@<домен>`.
/// Разбор без байтовых срезов (Message-ID задаёт отправитель — срез может не попасть в границу символа).
fn split_mark(message_id: &str) -> Option<(String, String, Vec<u8>)> {
    let trimmed = message_id.trim().trim_start_matches('<');
    let (local, domain) = trimmed.split_once('@')?;
    let domain = domain.trim_end_matches('>').to_owned();
    // Голова — `tp1.` (без учёта регистра), хвост — payload base32; срезы — только по ASCII-точкам
    // (Message-ID задаёт отправитель, граница символа не гарантирована).
    let head = MARK_PREFIX.len();
    if local.len() < head + 2 || !local.is_char_boundary(head) || !local.is_char_boundary(head + 1)
    {
        return None;
    }
    if !local[..head].eq_ignore_ascii_case(MARK_PREFIX) || local.as_bytes()[head] != b'.' {
        return None;
    }
    let (id, b32) = local[head + 1..].rsplit_once('.')?;
    if id.is_empty() || !base32_ok(b32) {
        return None;
    }
    let wire = base32_decode(b32)?;
    // Nonce (24) + случайное значение (16) + время (8) + имитоприставка AEAD (16).
    (wire.len() == NONCE_LEN + TAG_LEN + TIME_LEN + 16).then(|| (id.to_owned(), domain, wire))
}

/// Заголовок `Name: value` перед письмом (строка одна, без сворачивания).
fn prepend_header(raw: &[u8], name: &str, value: &str) -> bytes::Bytes {
    let mut out = Vec::with_capacity(name.len() + value.len() + 4 + raw.len());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(b": ");
    out.extend_from_slice(value.as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(raw);
    bytes::Bytes::from(out)
}

/// Заменяет все заголовки `Name` письма одним значением `value` (свёрнутые строки заголовка — целиком);
/// заголовка нет — ставится в начало.
fn replace_header(raw: &[u8], name: &str, value: &str) -> bytes::Bytes {
    let mut out = Vec::with_capacity(raw.len() + name.len() + value.len());
    let mut replaced = false;
    for line in header_lines(raw) {
        let is = std::str::from_utf8(line)
            .ok()
            .and_then(|l| l.split_once(':'))
            .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name));
        if !is {
            out.extend_from_slice(line);
            continue;
        }
        if replaced {
            continue;
        }
        replaced = true;
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if replaced {
        bytes::Bytes::from(out)
    } else {
        prepend_header(raw, name, value)
    }
}

/// Удаляет все заголовки `name` (значения и свёрнутые строки) из письма; нет — письмо без изменений.
/// Так узел убирает пришедший извне `X-ThePost-Reply` до проверок (SMTP-51).
pub(crate) fn strip_header(raw: &[u8], name: &str) -> bytes::Bytes {
    let mut out = Vec::with_capacity(raw.len());
    let mut changed = false;
    for line in header_lines(raw) {
        let is = std::str::from_utf8(line)
            .ok()
            .and_then(|l| l.split_once(':'))
            .is_some_and(|(n, _)| n.trim().eq_ignore_ascii_case(name));
        if is {
            changed = true;
            continue;
        }
        out.extend_from_slice(line);
    }
    if changed {
        bytes::Bytes::from(out)
    } else {
        bytes::Bytes::copy_from_slice(raw)
    }
}

/// Строки заголовков письма (каждая с CRLF; свёрнутое продолжение — WSP в начале строки — входит в ту же
/// строку), затем пустая строка и тело одной «строкой».
fn header_lines(raw: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let (mut start, mut i) = (0usize, 0usize);
    while i < raw.len() {
        if raw[i..].starts_with(b"\r\n") {
            if raw.get(i + 2).is_some_and(|c| *c == b' ' || *c == b'\t') {
                i += 2;
                continue;
            }
            out.push(&raw[start..i + 2]);
            start = i + 2;
        }
        i += 1;
    }
    if start < raw.len() {
        out.push(&raw[start..]);
    }
    out
}

/// Домен для метки: нижний регистр, без конечной точки.
fn domain_of(domain: &str) -> String {
    domain.trim_end_matches('.').to_lowercase()
}

/// Алфавит base32 (RFC 4648).
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Кодировка base32 без дополнения (`=` в local-part Message-ID недопустим).
fn base32(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Только символы base32 (без учёта регистра, без дополнения).
fn base32_ok(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphabetic() || (b'2'..=b'7').contains(&c))
}

/// Разбор base32 (без учёта регистра, без дополнения); `None` — чужие символы или лишние биты.
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let pos = |c: u8| match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a')),
        b'2'..=b'7' => Some(u32::from(c - b'2') + 26),
        _ => None,
    };
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in s.as_bytes() {
        acc = (acc << 5) | pos(c)?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    // Хвостовые биты должны быть нулями (каноническая запись).
    (bits == 0 || (acc & ((1 << bits) - 1)) == 0).then_some(out)
}

/// Случайное значение метки для записи об отправленном письма с Message-ID клиента (решение 125 в: замена
/// сломала бы копию в «Отправленных» — запись ведётся по хэшу, случайное значение только для уникальности).
pub(crate) fn random_tag() -> Vec<u8> {
    let mut rng = UnwrapErr(SysRng);
    let tag: [u8; TAG_LEN] = Generate::generate_from_rng(&mut rng);
    tag.to_vec()
}

fn read<T: Clone>(l: &RwLock<T>) -> T {
    l.read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
