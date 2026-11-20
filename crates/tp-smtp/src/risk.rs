//! Справочник аномалий на smtp-in (SMTP-52, решение 126; CONTRACTS.md#Risk; SRS 4.3, 5.5).
//!
//! После `DATA`, до Milter и Sieve, письмо разбирают детекторы каталога
//! ([`tp_contracts::risk::Detector`]): вложения с учётом вложенности (архивы в архивах) до
//! `smtp.risk.max_depth`, содержимое до `smtp.risk.max_scan_bytes` (практика Exchange — первые
//! 150 КБ), ссылки текстовых и HTML-частей, `Reply-To`. Архивы с паролем (ZIP с флагом шифрования
//! записи, 7z с зашифрованным заголовком `kEncodedHeader`, RAR 5 с заголовком шифрования архива) и
//! образы диска с ярлыками (ISO, IMG, VHD, VHDX, LNK) узнаются по сигнатурам или расширению, без
//! распаковки; тип вложения — по содержимому (`infer`) и расширению; домены ссылок — регистрируемые
//! (`publicsuffix` по списку из пакета поставщика).
//!
//! Балл письма — вердикт [`tp_contracts::risk::Verdict`] по действующему каталогу организации
//! получателя ([`tp_contracts::risk::RiskStore::effective`]); признаки устаревшего источника TI — по
//! [`tp_contracts::risk::StaleAction`] (вес снижен или «только отчёт», предупреждение в метриках).
//! Сработавший признак беседы снимает признак ответа SMTP-51 ([`Detector::drops_reply`], решение
//! 126 г) — заголовка `X-ThePost-Reply-Anomaly` нет, вместо него [`RISK_HEADER`]. Действие каталога —
//! самое строгое из действия по баллу, собственных действий признаков и вердикта Rspamd
//! ([`Verdict::combine`], после Milter): `tag` — заголовок [`RISK_HEADER`], `junk`/`quarantine` —
//! «Спам»/карантин узла, `reject` — `550 5.7.1` в сессии; отказ адресатам одних организаций при
//! расхождении с другими — карантин им (после приёма письмом не отказываем — backscatter). Признаки
//! [`Mode::Report`] — только в журнал срабатываний ([`RiskStore::record_hits`]) и метрики. Признаки от
//! команды `signal` скрипта организации (SIEVE-15) прибавляются к баллу после Sieve — с пределом веса
//! `smtp.risk.sieve_max_weight`; их действие после приёма — тоже карантин.
//!
//! Память бесед получателей (CTR-94 [`ThreadFacts`]), индексы списков TI и Public Suffix List узел
//! передаёт через [`RiskEnviron`] (APP-78, APP-79; в тестах — память). Подключение —
//! [`crate::Delivery::with_risk`]; детекторы ничего не пропускают: сбой чтения каталога, памяти или
//! списков — проверка без срабатываний, письмо доставляется.
//!
//! Практика: условия Exchange «защищено паролем», «исполняемое содержимое» с учётом вложенности и
//! первыми 150 КБ; символы Rspamd с баллом и порогами действий, `multimap` по `filename` и `url`,
//! модуль `phishing`; ISO/IMG/LNK как носители нагрузки после отключения макросов (Proofpoint).
//! Отличие: признаки и веса — из подписанного каталога, новые — «только отчёт»; отказ — только в
//! сессии SMTP.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use mail_parser::{MessageParser, PartKind};
use publicsuffix::Psl;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tp_contracts::Result;
use tp_contracts::ids::{AccountId, BlobHash, TenantId};
use tp_contracts::reply::normalize_recipient;
use tp_contracts::risk::{
    Detector, EffectiveCatalog, Field, Fired, HitSource, ListId, Mode, RiskAction, RiskStore,
    Signal, SignalId, SourceId, StaleAction, Verdict,
};
use tp_contracts::thread::ThreadFacts;

use crate::config::RiskConfig;
use crate::metrics::SmtpMetrics;

/// Заголовок балла и признаков каталога (SMTP-52; вместо `X-ThePost-Reply-Anomaly` решения 125 д).
/// Входящий с тем же именем удаляется до проверок; свой ставится после Sieve при действии `tag`.
pub const RISK_HEADER: &str = "X-ThePost-Risk";

/// Ответ SMTP при действии `reject` в сессии (балл и признаки — в журнале доставки).
pub const REJECT_TEXT: &str = "Message rejected by risk policy";

/// Наибольшее число ссылок письма (предел сканирования, как у памяти беседы в `tp-mailstore`).
const MAX_LINKS: usize = 64;

/// Наибольшая длина значения ссылки (строки URL) в байтах.
const MAX_URL_LEN: usize = 2048;

/// Байт содержимого записи архива для типа по содержимому (`infer` читает голову).
const ENTRY_HEAD: usize = 4096;

/// Значение поля письма для проверки по списку TI ([`Field`]; APP-79 — префиксы IP `ipnet`, домены,
/// URL, SHA-256 за интерфейсом [`RiskEnviron::list_contains`]).
#[derive(Debug, Clone)]
pub enum ListValue<'a> {
    /// IP-адрес (отправитель соединения).
    Ip(IpAddr),
    /// Домен (ссылки или `From`, нижний регистр).
    Domain(&'a str),
    /// URL ссылки (как в тексте письма).
    Url(&'a str),
    /// SHA-256 вложения.
    Sha256(&'a [u8; 32]),
}

/// Данные узла для детекторов и балла (APP-78, APP-79): память бесед получателей (CTR-94), индексы
/// списков TI и Public Suffix List из пакета поставщика. Реализация — приложение; в тестах — память.
#[async_trait]
pub trait RiskEnviron: Send + Sync + 'static {
    /// Память беседы получателя `account` с письмами по ключам присоединения `keys` (`Message-ID`,
    /// `In-Reply-To`, `References`; CTR-94 [`ThreadFacts`]). Пустая — беседы нет.
    async fn thread_facts(
        &self,
        tenant: TenantId,
        account: AccountId,
        keys: &[String],
    ) -> Result<ThreadFacts>;

    /// Значение `value` есть в списке `list` организации `tenant` (индексы активных версий списков).
    /// Списка нет — `false`.
    async fn list_contains(
        &self,
        tenant: TenantId,
        list: &ListId,
        value: ListValue<'_>,
    ) -> Result<bool>;

    /// Public Suffix List пакета поставщика (решение 126 г); `None` — пакета нет, детектор «новый
    /// домен» молчит.
    async fn psl(&self) -> Result<Option<Arc<publicsuffix::List>>>;
}

/// Что нашли детекторы в письме — безотносительно каталога (один разбор на письмо, вердикты — по
/// организациям получателей).
#[derive(Debug, Default, Clone)]
pub struct Findings {
    /// Типы вложений письма (`media/subtype`, включая вложенные архивы до `max_depth`).
    pub attachment_types: Vec<String>,
    /// SHA-256 вложений (списки TI по полю `attachment_sha256`).
    pub attachment_hashes: Vec<[u8; 32]>,
    /// Архив с паролем: ZIP с флагом шифрования записи, 7z с зашифрованным заголовком, RAR 5 с
    /// заголовком шифрования архива (по сигнатурам, без распаковки).
    pub encrypted_archive: bool,
    /// Образ диска или ярлык: ISO, IMG, VHD, VHDX, LNK — по сигнатуре или расширению.
    pub disk_image: bool,
    /// Хосты ссылок письма (текст и HTML, нижний регистр, без порта и учётных данных).
    pub link_hosts: Vec<String>,
    /// URL ссылок письма (как в тексте, для списков TI по полю `link_url`).
    pub link_urls: Vec<String>,
    /// Значения `Reply-To` письма (канонические адреса, [`normalize_recipient`]).
    pub reply_to: Vec<String>,
    /// Адрес `From` (канонический; нет — `None`).
    pub from: Option<String>,
    /// Домен `From` (нижний регистр; нет — `None`).
    pub from_domain: Option<String>,
}

impl Findings {
    /// Новый для беседы тип вложения: в памяти есть типы ([`ThreadFacts::attachments`]) и письмо
    /// приносит тип, которого там не было. Пустая память — базы сравнения нет, детектор молчит.
    pub fn new_attachment_type(&self, facts: &ThreadFacts) -> bool {
        !facts.attachments.is_empty()
            && self
                .attachment_types
                .iter()
                .any(|t| !facts.attachments.contains(t))
    }

    /// Новый для беседы регистрируемый домен ссылки: в памяти есть домены и письмо приносит домен,
    /// которого там не было ([`publicsuffix`] по списку из пакета). Пустая память — детектор молчит.
    pub fn new_link_domain(&self, facts: &ThreadFacts, psl: &publicsuffix::List) -> bool {
        !facts.link_domains.is_empty()
            && self
                .registrable_domains(psl)
                .iter()
                .any(|d| !facts.link_domains.iter().any(|x| x.eq_ignore_ascii_case(d)))
    }

    /// `Reply-To` сменился: есть, не совпадает с адресом `From` и с прежним `Reply-To` беседы.
    /// Память без `Reply-To` — смены не было, детектор молчит (решение 126 г).
    pub fn reply_to_changed(&self, facts: &ThreadFacts) -> bool {
        !facts.reply_to.is_empty()
            && self
                .reply_to
                .iter()
                .any(|rt| self.from.as_deref() != Some(rt) && !facts.reply_to.contains(rt))
    }

    /// Регистрируемые домены ссылок письма ([`publicsuffix`] по списку из пакета; без списка — пусто).
    fn registrable_domains(&self, psl: &publicsuffix::List) -> Vec<String> {
        let mut out = Vec::new();
        for host in &self.link_hosts {
            if let Some(d) = psl.domain(host.as_bytes()) {
                let d = String::from_utf8_lossy(d.as_bytes()).to_ascii_lowercase();
                if !out.contains(&d) {
                    out.push(d);
                }
            }
        }
        out
    }
}

/// Разбирает письмо детекторами: вложения (включая архивы в архивах до `RiskConfig::max_depth`),
/// ссылки текстовых и HTML-частей, `Reply-To`, `From`. Битое MIME и чужие форматы не ошибка: что
/// не разобралось — пусто (fail-open). Части вложенных писем перечисляет разбор (`parts`, mail-parser 1.0),
/// пределы самого парсера (глубина, число частей) — защита от MIME-бомб.
pub fn scan_message(raw: &[u8], limits: &RiskConfig) -> Findings {
    let mut out = Findings::default();
    let Some(msg) = MessageParser::new().parse(raw) else {
        return out;
    };
    // Адрес и домен `From` (первый адрес) и `Reply-To` — из заголовков письма.
    if let Some(a) = msg.from().and_then(|a| a.first()).and_then(|a| a.address())
        && let Ok(a) = normalize_recipient(a)
    {
        out.from = Some(a.clone());
        out.from_domain = a.rsplit_once('@').map(|(_, d)| d.to_ascii_lowercase());
    }
    if let Some(list) = msg.reply_to() {
        for a in list.mailboxes().filter_map(|a| a.address()) {
            if let Ok(a) = normalize_recipient(a)
                && !out.reply_to.contains(&a)
            {
                out.reply_to.push(a);
            }
        }
    }
    let mut budget = limits.max_scan_bytes;
    for part in msg.parts() {
        // Текст и HTML — для ссылок (память беседы сканирует их так же, `tp-mailstore` MS-21).
        if matches!(part.kind(), PartKind::Text | PartKind::Html)
            && let Some(text) = part.text()
        {
            scan_links(text.as_bytes(), &mut out, &mut budget);
        }
        // Вложение — по распоряжению `attachment` (типы памяти беседы — те же части, CTR-94).
        if !part
            .content_disposition()
            .is_some_and(|d| d.is_attachment())
        {
            continue;
        }
        let decoded = part.decoded();
        let decoded: &[u8] = &decoded;
        let t = attachment_type(&part);
        if !out.attachment_types.contains(&t) {
            out.attachment_types.push(t);
        }
        hash_attachment(decoded, &mut out);
        inspect_content(
            decoded,
            part.attachment_name(),
            &mut out,
            &mut budget,
            limits.max_depth,
        );
    }
    out
}

/// Тип вложения `media/subtype` — как его запоминает память беседы (`tp-mailstore`, CTR-94):
/// тип по содержимому письма; без подтипа — умолчание (`text/plain`, прочие `octet-stream`).
fn attachment_type(part: &mail_parser::MessagePart<'_>) -> String {
    match part.content_type() {
        Some(ct) => format!(
            "{}/{}",
            ct.ctype().to_ascii_lowercase(),
            ct.subtype()
                .map_or_else(|| default_subtype(ct.ctype()), str::to_ascii_lowercase)
        ),
        None => "text/plain".to_owned(),
    }
}

/// Подтип по умолчанию для типа без подтипа (как в `tp-mailstore`).
fn default_subtype(media_type: &str) -> String {
    if media_type.eq_ignore_ascii_case("text") {
        "plain".to_owned()
    } else {
        "octet-stream".to_owned()
    }
}

/// Хэш вложения целиком (оно уже в памяти узла): списки TI содержат хэши полных файлов.
fn hash_attachment(decoded: &[u8], out: &mut Findings) {
    let mut h = Sha256::new();
    h.update(decoded);
    let hash: [u8; 32] = h.finalize().into();
    if !out.attachment_hashes.contains(&hash) {
        out.attachment_hashes.push(hash);
    }
}

/// Разбор содержимого вложения: образы диска и ярлыки по сигнатуре или расширению; архивы —
/// шифрование по заголовкам и вложенные вложения до предела глубины (`max_depth`).
fn inspect_content(
    decoded: &[u8],
    name: Option<&str>,
    out: &mut Findings,
    budget: &mut usize,
    max_depth: usize,
) {
    let ext = name
        .and_then(|n| n.rsplit_once('.'))
        .map(|(_, e)| e.to_ascii_lowercase());
    // Образ диска или ярлык (решение 126 г): сигнатура содержимого или расширение имени.
    if disk_image_or_shortcut(decoded, ext.as_deref()) {
        out.disk_image = true;
    }
    // ZIP: флаг шифрования записей и вложенные вложения (архив в архиве до предела глубины);
    // разбор — по содержимому до предела сканирования (каталог ZIP в конце файла).
    if decoded.starts_with(b"PK\x03\x04") || decoded.starts_with(b"PK\x05\x06") {
        if decoded.len() <= *budget {
            scan_zip(decoded, out, budget, max_depth);
        }
        return;
    }
    // 7z: шифрование заголовка архива — первый байт заголовка после стартового (32 байта):
    // `kHeader` (0x01) — открыт, `kEncodedHeader` (0x17) — зашифрован (AES-256).
    if decoded.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        if decoded.len() > 32 && decoded[32] == 0x17 {
            out.encrypted_archive = true;
        }
        return;
    }
    // RAR 5: заголовок шифрования архива (тип записи 5) сразу после сигнатуры.
    if decoded.starts_with(b"Rar!\x1A\x07\x01\x00") && rar5_encrypted(decoded) {
        out.encrypted_archive = true;
    }
}

/// ISO, IMG, VHD, VHDX или LNK — по сигнатуре содержимого или расширению имени (решение 126 г;
/// носители нагрузки после отключения макросов, Proofpoint).
fn disk_image_or_shortcut(decoded: &[u8], ext: Option<&str>) -> bool {
    const MEDIA_EXT: [&str; 5] = ["iso", "img", "vhd", "vhdx", "lnk"];
    if ext.is_some_and(|e| MEDIA_EXT.contains(&e)) {
        return true;
    }
    // ISO 9660: `CD001` в первичном дескрипторе тома (сектор 16, смещение 1).
    if decoded.len() > 0x8006 && decoded[0x8001..0x8006] == *b"CD001" {
        return true;
    }
    // VHD: подпись `conectix` в последнем секторе (копия футера в конце файла).
    if decoded.len() >= 512 && decoded[decoded.len() - 512..decoded.len() - 504] == *b"conectix" {
        return true;
    }
    // VHDX: подпись `vhdxfile` в начале.
    if decoded.starts_with(b"vhdxfile") {
        return true;
    }
    // Ярлык Windows ([MS-SHLLINK]): `4C 00 00 00`, версия заголовка `01 14`.
    decoded.starts_with(&[0x4C, 0x00, 0x00, 0x00, 0x01, 0x14])
}

/// Записи ZIP: флаг шифрования (`ZipFile::encrypted`) и вложенные вложения до предела глубины.
/// Битый или неподдерживаемый архив — не ошибка (fail-open).
fn scan_zip(decoded: &[u8], out: &mut Findings, budget: &mut usize, max_depth: usize) {
    let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(decoded)) else {
        return;
    };
    for i in 0..archive.len() {
        let Ok(file) = archive.by_index(i) else {
            continue;
        };
        if file.encrypted() {
            // Флаг шифрования записи (общий бит заголовка) — архив вскрывается паролем.
            out.encrypted_archive = true;
            continue;
        }
        if file.is_dir() {
            continue;
        }
        let name = file.name_raw();
        let ext = name
            .iter()
            .rposition(|b| *b == b'.')
            .map(|i| {
                name[i + 1..]
                    .iter()
                    .map(|b| (*b).to_ascii_lowercase() as char)
                    .collect::<String>()
            })
            .filter(|e| !e.is_empty());
        if max_depth == 0 {
            continue;
        }
        // Запись — вложение архива: тип по содержимому головы (по алгоритмам вне сборки записи
        // не читаются — fail-open), дальше — архивы и образы в записи.
        let mut head = Vec::new();
        if file.take(ENTRY_HEAD as u64).read_to_end(&mut head).is_err() {
            continue;
        }
        if let Some(t) = infer::get(&head).map(|t| t.mime_type().to_ascii_lowercase())
            && !out.attachment_types.contains(&t)
        {
            out.attachment_types.push(t);
        }
        inspect_content(&head, ext.as_deref(), out, budget, max_depth - 1);
    }
}

/// Заголовок шифрования архива RAR 5: тип записи 5 сразу после сигнатуры (8 байт); поля заголовка —
/// `vint` (7 бит на байт, старший бит — продолжение).
fn rar5_encrypted(decoded: &[u8]) -> bool {
    let mut i = 8;
    let next = |decoded: &[u8], i: &mut usize| -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let b = *decoded.get(*i)?;
            *i += 1;
            value |= u64::from(b & 0x7F) << shift;
            if b & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    };
    // CRC32 записи, размер заголовка, тип заголовка: 5 — шифрование архива (HEAD_ENCRYPT).
    i += 4;
    let Some(_size) = next(decoded, &mut i) else {
        return false;
    };
    next(decoded, &mut i) == Some(5)
}

/// Ссылки текста или HTML (`http`/`https`): URL как в тексте и хост без порта и учётных данных,
/// нижний регистр. Обрезается бюджетом письма (`budget` — байт на сканирование ссылок).
fn scan_links(text: &[u8], out: &mut Findings, budget: &mut usize) {
    if out.link_urls.len() >= MAX_LINKS || *budget == 0 {
        return;
    }
    let take = text.len().min(*budget);
    *budget -= take;
    let text = String::from_utf8_lossy(&text[..take]);
    for m in url_regex().find_iter(&text) {
        if out.link_urls.len() >= MAX_LINKS {
            break;
        }
        let mut url = m.as_str();
        if url.len() > MAX_URL_LEN {
            // Граница символа: многобайтовый URL не режется посреди символа (паника на `&s[..n]`).
            let mut end = MAX_URL_LEN;
            while !url.is_char_boundary(end) {
                end -= 1;
            }
            url = &url[..end];
        }
        if !out.link_urls.iter().any(|x| x == url) {
            out.link_urls.push(url.to_owned());
        }
        if let Some(host) = url_host(url)
            && !out.link_hosts.contains(&host)
        {
            out.link_hosts.push(host);
        }
    }
}

/// Шаблон ссылок `http`/`https` (компилируется один раз; `regex` — линейное время на недоверенном
/// тексте, DEPS-19).
fn url_regex() -> &'static regex::Regex {
    static URL: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    URL.get_or_init(|| regex::Regex::new(r#"https?://[^\s<>"`\x00-\x20]+"#).expect("static regex"))
}

/// Хост URL: без схемы, пути, порта и учётных данных (IPv6 — без скобок), нижний регистр.
fn url_host(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    let host = match authority.split_once(']') {
        Some((bracketed, _)) => bracketed.strip_prefix('[')?,
        None => authority
            .split_once(':')
            .map(|(h, _)| h)
            .unwrap_or(authority),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

/// Итог проверки письма каталогом: вердикт каждой организации-получателя, факт доверенной беседы
/// получателей и хэш письма (журнал срабатываний).
pub(crate) struct Scan {
    /// Каталог организации и вердикт по ней ([`Verdict::combine`] с Rspamd — после Milter).
    orgs: BTreeMap<TenantId, OrgVerdict>,
    /// Сработал детектор беседы ([`Detector::drops_reply`]): признак ответа снимается (решение 126 г).
    pub drops_reply: bool,
    /// Получатели с непустой памятью беседы по ключам письма (CTR-95 `thread_trusted` правил Sieve).
    pub trusted: Vec<AccountId>,
}

/// Вердикт организации: действующий каталог и вердикт по письму.
struct OrgVerdict {
    catalog: EffectiveCatalog,
    verdict: Verdict,
}

impl Scan {
    /// Итоговое действие по письму — самое строгое по организациям.
    pub(crate) fn action(&self) -> RiskAction {
        self.orgs
            .values()
            .map(|o| o.verdict.action)
            .max()
            .unwrap_or(RiskAction::None)
    }

    /// Организации, чей вердикт — `reject` (карантин им при расхождении с другими — backscatter).
    pub(crate) fn reject_orgs(&self) -> Vec<TenantId> {
        self.reject_orgs_set().into_iter().collect()
    }

    /// Организации, чей вердикт — `junk` или строже (карантин им после Sieve — SMTP-52).
    pub(crate) fn junk_orgs(&self) -> Vec<TenantId> {
        self.orgs
            .iter()
            .filter(|(_, o)| o.verdict.action >= RiskAction::Junk)
            .map(|(t, _)| *t)
            .collect()
    }

    /// Организации под действием `reject` — множество.
    fn reject_orgs_set(&self) -> HashSet<TenantId> {
        self.orgs
            .iter()
            .filter(|(_, o)| o.verdict.action >= RiskAction::Reject)
            .map(|(t, _)| *t)
            .collect()
    }

    /// Проверки не было (нет организаций-получателей — каталог не прочитан, письма не было): событий
    /// каталога не будет.
    pub(crate) fn empty(&self) -> bool {
        self.orgs.is_empty()
    }

    /// Все организации-получатели под действием `reject` (и они есть): отказ в сессии всему письму.
    pub(crate) fn all_reject(&self) -> bool {
        !self.orgs.is_empty()
            && self
                .orgs
                .values()
                .all(|o| o.verdict.action >= RiskAction::Reject)
    }

    /// Вердикт организации `tenant` (правилам Sieve — CTR-95 `RulesInput::risk`); организации нет в
    /// проверке — вердикт без срабатываний.
    pub(crate) fn verdict_for(&self, tenant: TenantId) -> Verdict {
        self.orgs
            .get(&tenant)
            .map(|o| o.verdict.clone())
            .unwrap_or_default()
    }

    /// Значение заголовка [`RISK_HEADER`]: наибольший балл и признаки всех организаций —
    /// `score=N; signals=a,b` (признаков нет — `score=N`).
    pub(crate) fn header_value(&self) -> String {
        let score = self
            .orgs
            .values()
            .map(|o| o.verdict.score)
            .max()
            .unwrap_or_default();
        let ids = self.signal_ids();
        if ids.is_empty() {
            format!("score={score}")
        } else {
            format!("score={score}; signals={}", ids.join(","))
        }
    }

    /// Сработавшие признаки всех организаций (enforce и «только отчёт»), без повторов.
    fn signal_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self
            .orgs
            .values()
            .flat_map(|o| {
                o.verdict
                    .hits
                    .iter()
                    .chain(o.verdict.report_only.iter())
                    .map(|h| h.signal.as_str())
            })
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Есть срабатывания (enforce или «только отчёт») — событие журнала доставки о них скажет.
    pub(crate) fn has_findings(&self) -> bool {
        !self.signal_ids().is_empty()
    }

    /// Причина для события журнала доставки: балл, признаки и действие.
    pub(crate) fn event_reason(&self) -> String {
        format!("risk: {}, action={}", self.header_value(), self.action())
    }
}

/// Справочник аномалий на smtp-in: конфигурация ([`RiskConfig`]), каталог ([`RiskStore`] — APP-78)
/// и данные узла для детекторов ([`RiskEnviron`] — APP-78/79). Подключается
/// [`crate::Delivery::with_risk`]; клоны разделяют хранилища.
pub struct Risk {
    cfg: RiskConfig,
    store: Arc<dyn RiskStore>,
    environ: Arc<dyn RiskEnviron>,
    metrics: Option<Arc<SmtpMetrics>>,
}

impl std::fmt::Debug for Risk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Risk")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl Risk {
    /// Проверка по конфигурации `cfg`, каталогу `store` и данным узла `environ`.
    pub fn new(
        cfg: RiskConfig,
        store: Arc<dyn RiskStore>,
        environ: Arc<dyn RiskEnviron>,
        metrics: Option<Arc<SmtpMetrics>>,
    ) -> Self {
        Self {
            cfg,
            store,
            environ,
            metrics,
        }
    }

    /// Проверка включена (секция `smtp.risk`).
    pub fn enabled(&self) -> bool {
        self.cfg.enabled
    }

    /// Проверяет письмо детекторами и каталогом каждой организации локальных получателей `locals`
    /// (после `DATA`, до Milter и Sieve). Сбой чтения каталога или памяти — проверка без срабатываний
    /// (fail-open); таймаут [`RiskConfig::detector_timeout`] — то же, с предупреждением.
    /// Срабатывания записываются в журнал ([`RiskStore::record_hits`]) и метрики.
    pub(crate) async fn scan(
        &self,
        sender_ip: IpAddr,
        raw: &[u8],
        locals: &[(AccountId, TenantId)],
    ) -> Scan {
        let started = Instant::now();
        let scan = tokio::time::timeout(
            self.cfg.detector_timeout,
            self.scan_inner(sender_ip, raw, locals),
        )
        .await;
        if let Some(m) = &self.metrics {
            m.risk_detector(started.elapsed().as_secs_f64());
        }
        match scan {
            Ok(scan) => scan,
            Err(_) => {
                tracing::warn!(
                    timeout = ?self.cfg.detector_timeout,
                    "smtp: проверка каталога признаков не уложилась в таймаут — письмо без срабатываний"
                );
                Scan {
                    orgs: BTreeMap::new(),
                    drops_reply: false,
                    trusted: Vec::new(),
                }
            }
        }
    }

    /// Проверка без таймаута ([`Risk::scan`]).
    async fn scan_inner(
        &self,
        sender_ip: IpAddr,
        raw: &[u8],
        locals: &[(AccountId, TenantId)],
    ) -> Scan {
        let findings = scan_message(raw, &self.cfg);
        // Ключи присоединения к беседе (`Message-ID`, `In-Reply-To`, `References` — CTR-94): по ним
        // реализация [`RiskEnviron::thread_facts`] находит память бесед получателя.
        let keys = thread_keys(raw);
        let mut trusted = Vec::new();
        let mut facts: BTreeMap<TenantId, ThreadFacts> = BTreeMap::new();
        for (account, tenant) in locals {
            let memory = self
                .environ
                .thread_facts(*tenant, *account, &keys)
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, "smtp: память беседы не прочитана — детекторы беседы молчат");
                    ThreadFacts::new()
                });
            if memory.attachments.is_empty()
                && memory.link_domains.is_empty()
                && memory.reply_to.is_empty()
            {
                continue;
            }
            if !trusted.contains(account) {
                trusted.push(*account);
            }
            // Детекторы беседы организации — по памяти первого её получателя.
            facts.entry(*tenant).or_insert(memory);
        }
        // Public Suffix List пакета поставщика: без него детектор «новый домен» молчит.
        let psl = match self.environ.psl().await {
            Ok(psl) => psl,
            Err(e) => {
                tracing::warn!(error = %e, "smtp: список суффиксов не прочитан — детектор «новый домен» молчит");
                None
            }
        };
        let mut orgs = BTreeMap::new();
        let message = message_hash(raw);
        for tenant in locals.iter().map(|(_, t)| *t).collect::<BTreeSet<_>>() {
            let catalog = match self.store.effective(tenant).await {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!(error = %e, "smtp: каталог признаков не прочитан — письмо без балла");
                    continue;
                }
            };
            let facts = facts.get(&tenant).cloned().unwrap_or_else(ThreadFacts::new);
            let fired = self
                .fired(
                    tenant,
                    &catalog,
                    &findings,
                    &facts,
                    psl.as_deref(),
                    sender_ip,
                )
                .await;
            let verdict = Verdict::from_fired(&catalog, &fired);
            self.metrics_of(&verdict);
            // Срабатывания — в журнал каталога (`Enforce` и «только отчёт», CTR-95 `record_hits`);
            // сбой журнала письмо не останавливает.
            if (!verdict.hits.is_empty() || !verdict.report_only.is_empty())
                && let Err(e) = self.store.record_hits(tenant, message, &verdict).await
            {
                tracing::warn!(error = %e, "smtp: срабатывания каталога не записаны");
            }
            orgs.insert(tenant, OrgVerdict { catalog, verdict });
        }
        let drops_reply = orgs.values().any(|o| o.verdict.drops_reply);
        Scan {
            orgs,
            drops_reply,
            trusted,
        }
    }

    /// Срабатывания признаков действующего каталога организации: детекторы письма против каждого
    /// признака; совпадение со списком TI — по интерфейсу узла.
    async fn fired(
        &self,
        tenant: TenantId,
        catalog: &EffectiveCatalog,
        findings: &Findings,
        facts: &ThreadFacts,
        psl: Option<&publicsuffix::List>,
        sender_ip: IpAddr,
    ) -> Vec<Fired> {
        let mut out = Vec::new();
        let mut warned = HashSet::new();
        for effective in &catalog.signals {
            let Some((signal, strength)) = self
                .fired_signal(
                    tenant,
                    &effective.signal,
                    findings,
                    facts,
                    psl,
                    sender_ip,
                    &mut warned,
                )
                .await
            else {
                continue;
            };
            out.push(Fired {
                signal,
                strength,
                source: HitSource::Detector,
            });
        }
        out
    }

    /// Срабатывание одного признака: детектор по письму, сила 100 у детерминированных находок;
    /// порог силы ([`Signal::threshold`]) проверяет [`Verdict::from_fired`]. Возвращает признак с
    /// поправкой устаревания (вес, режим) и силу; `None` — не сработал.
    #[allow(clippy::too_many_arguments)] // контекст письма шести детекторов; конвенция репо
    async fn fired_signal(
        &self,
        tenant: TenantId,
        signal: &Signal,
        findings: &Findings,
        facts: &ThreadFacts,
        psl: Option<&publicsuffix::List>,
        sender_ip: IpAddr,
        warned: &mut HashSet<SourceId>,
    ) -> Option<(Signal, u8)> {
        let hit = match &signal.detector {
            Detector::ThreadNewAttachmentType => findings.new_attachment_type(facts),
            Detector::EncryptedArchive => findings.encrypted_archive,
            Detector::DiskImageOrShortcut => findings.disk_image,
            Detector::ReplyToChanged => findings.reply_to_changed(facts),
            Detector::ThreadNewLinkDomain => {
                psl.is_some_and(|p| findings.new_link_domain(facts, p))
            }
            Detector::ListMatch { list, field } => {
                return self
                    .fired_list(tenant, signal, list, *field, findings, sender_ip, warned)
                    .await;
            }
        };
        hit.then(|| (signal.clone(), 100))
    }

    /// Совпадение поля письма со списком TI (значения поля — по интерфейсу узла). Устаревший
    /// источник — [`StaleAction`] (решение 126 е): вес снижен на процент или признак «только отчёт»,
    /// предупреждение в журнале узла и метриках (один раз на письмо на источник). Возвращает признак
    /// с поправкой и силу; `None` — совпадения нет. Сбой чтения — список считается свежим (fail-open).
    #[allow(clippy::too_many_arguments)]
    async fn fired_list(
        &self,
        tenant: TenantId,
        signal: &Signal,
        list: &ListId,
        field: Field,
        findings: &Findings,
        sender_ip: IpAddr,
        warned: &mut HashSet<SourceId>,
    ) -> Option<(Signal, u8)> {
        let mut signal = signal.clone();
        let mut reduce = 0u8;
        if let Some((source, stale)) = self.stale_source(list).await {
            match stale {
                StaleAction::Reduce { percent } => reduce = percent,
                StaleAction::Report => signal.mode = Mode::Report,
            }
            if warned.insert(source.clone()) {
                tracing::warn!(
                    source = %source,
                    list = %list,
                    "smtp: источник списка TI устарел — вес признака снижен или признак «только отчёт»"
                );
                if let Some(m) = &self.metrics {
                    m.risk_stale(source.as_str());
                }
            }
        }
        let hit = match field {
            Field::SenderIp => self
                .environ
                .list_contains(tenant, list, ListValue::Ip(sender_ip))
                .await
                .unwrap_or(false),
            Field::FromDomain => match findings.from_domain.as_deref() {
                Some(d) => self
                    .environ
                    .list_contains(tenant, list, ListValue::Domain(d))
                    .await
                    .unwrap_or(false),
                None => false,
            },
            Field::LinkDomain => {
                // Домены ссылок — регистрируемые (решение 126 г); без списка суффиксов — совпадения нет.
                let domains = match self.environ.psl().await.unwrap_or(None) {
                    Some(psl) => findings.registrable_domains(&psl),
                    None => Vec::new(),
                };
                for d in &domains {
                    if self
                        .environ
                        .list_contains(tenant, list, ListValue::Domain(d))
                        .await
                        .unwrap_or(false)
                    {
                        return Some((signal, 100));
                    }
                }
                return None;
            }
            Field::LinkUrl => {
                for url in &findings.link_urls {
                    if self
                        .environ
                        .list_contains(tenant, list, ListValue::Url(url))
                        .await
                        .unwrap_or(false)
                    {
                        return Some((signal, 100));
                    }
                }
                return None;
            }
            Field::AttachmentSha256 => {
                for hash in &findings.attachment_hashes {
                    if self
                        .environ
                        .list_contains(tenant, list, ListValue::Sha256(hash))
                        .await
                        .unwrap_or(false)
                    {
                        return Some((signal, 100));
                    }
                }
                return None;
            }
        };
        if !hit {
            return None;
        }
        // Вес с поправкой на устаревание ([`StaleAction::Reduce`]).
        if reduce > 0 {
            let w = signal.weight;
            signal.weight = w.saturating_sub(u16::from(reduce) * w / 100);
        }
        Some((signal, 100))
    }

    /// Источник списка и факт устаревания: версия списка старше `TTL` источника. `None` — списка,
    /// версии или источника нет, либо чтение не удалось.
    async fn stale_source(&self, list: &ListId) -> Option<(SourceId, StaleAction)> {
        let version = match self.store.list_current(list).await {
            Ok(Some(v)) => v,
            _ => return None,
        };
        let sources = self.store.sources().await.ok()?;
        let source = sources.iter().find(|s| s.id == version.source)?;
        let ttl = time::Duration::try_from(source.ttl).unwrap_or_default();
        (version.fetched_at + ttl <= OffsetDateTime::now_utc())
            .then(|| (source.id.clone(), source.stale))
    }

    /// Метрики срабатываний вердикта: по признаку и режиму ([`Mode`]).
    fn metrics_of(&self, verdict: &Verdict) {
        let Some(m) = &self.metrics else {
            return;
        };
        for h in &verdict.hits {
            m.risk_signal(h.signal.as_str(), Mode::Enforce.as_str());
        }
        for h in &verdict.report_only {
            m.risk_signal(h.signal.as_str(), Mode::Report.as_str());
        }
    }

    /// Действие Rspamd (вердикт Milter) — в вердикт каждой организации: самое строгое
    /// ([`Verdict::combine`], решение 126 а).
    pub(crate) fn combine_rspamd(&self, scan: &mut Scan, rspamd: RiskAction) {
        for o in scan.orgs.values_mut() {
            o.verdict.combine(rspamd);
        }
    }

    /// Признаки команды `signal` скрипта организации (SIEVE-15) после Sieve: вес заданный или
    /// действующий каталога (`org.`-признакам без веса — 1), не выше [`RiskConfig::sieve_max_weight`].
    /// Балл и действие каждой организации пересчитываются; сработавшие — в метрики.
    pub(crate) async fn apply_sieve(&self, scan: &mut Scan, signals: &[(SignalId, Option<u16>)]) {
        for (id, weight) in signals {
            for o in scan.orgs.values_mut() {
                let weight = match weight {
                    Some(w) => (*w).min(self.cfg.sieve_max_weight),
                    None => o
                        .catalog
                        .get(id)
                        .map(|e| e.signal.weight)
                        .unwrap_or(1)
                        .min(self.cfg.sieve_max_weight),
                };
                o.verdict.score += u32::from(weight);
                o.verdict.action = o
                    .verdict
                    .action
                    .max(o.catalog.thresholds.action(o.verdict.score));
            }
            if let Some(m) = &self.metrics {
                m.risk_signal(id.as_str(), Mode::Enforce.as_str());
            }
        }
    }
}

/// Хэш письма для записей журнала срабатываний ([`BlobHash`] — SHA-256; его считает вызывающий
/// [`RiskStore::record_hits`]).
pub fn message_hash(raw: &[u8]) -> BlobHash {
    let mut h = Sha256::new();
    h.update(raw);
    BlobHash(h.finalize().into())
}

/// Ключи присоединения письма к беседе (`Message-ID`, `In-Reply-To`, `References`, без угловых
/// скобок; канонизирует реализация [`RiskEnviron::thread_facts`] — как [`tp_contracts::thread::join_key`]).
fn thread_keys(raw: &[u8]) -> Vec<String> {
    let Some(msg) = MessageParser::new().parse_headers(raw) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    if let Some(id) = msg.message_id() {
        keys.push(id.to_owned());
    }
    for id in msg
        .in_reply_to()
        .into_iter()
        .chain(msg.references())
        .flat_map(|l| l.iter())
    {
        let id = id.trim_matches(|c| c == '<' || c == '>').trim();
        if !id.is_empty() && !keys.iter().any(|x| x == id) {
            keys.push(id.to_owned());
        }
    }
    keys
}

#[cfg(test)]
mod tests;
