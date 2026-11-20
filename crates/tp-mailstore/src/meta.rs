//! Метаданные письма для протоколов (CONTRACTS.md#MailStore `MessageMeta`; SRS 4.2), вычисляются при приёме.
//!
//! Разбор — `mail-parser`; значения заголовков декодированы (encoded-word, RFC 2231).
//! - [`Envelope`] (IMAP ENVELOPE): поля — как в заголовках письма, без подстановок IMAP (`Sender` по `From`
//!   добавляет протокол); дата — со смещением из заголовка (JMAP `sentAt`); `Message-ID` и `In-Reply-To` —
//!   идентификаторы в угловых скобках, несколько — через пробел; адреса групп RFC 5322 — участниками группы.
//! - [`BodyPart`] (IMAP BODYSTRUCTURE, JMAP bodyStructure): пути — как у частей [`crate::split`]: корень письма —
//!   `""`, дети составной части — `p.1`, `p.2`, ...; вложенное `message/rfc822` с путём `p` содержит корень письма:
//!   составной — с путём `p`, несоставной — `p.1`. Размер — тела части в кодировке передачи; строки — у `text/*`
//!   и `message/rfc822`. Тип по умолчанию — `text/plain`.
//! - `preview` — начало текста (`text/plain` или текст из HTML) с пробелами, сжатыми до одного, не длиннее
//!   [`PREVIEW_CHARS`] символов; тело в UTF-8 с ошибочной меткой `charset` читается как UTF-8.
//!
//! Кодировки — полный набор `mail-parser` (`full_encoding`, encoding_rs): результат не зависит от того,
//! включили ли его другие крейты сборки.
//! - `thread_key` — первый идентификатор `References`, иначе `In-Reply-To`, иначе собственный `Message-ID`
//!   (письмо — начало цепочки), в угловых скобках; без идентификаторов — `subject:` и тема без `Re:`/`Fwd:`
//!   в нижнем регистре; пустая строка — нет ни идентификаторов, ни темы.
//! - `has_attachment` — есть части-вложения (в том числе встроенные изображения).

use std::borrow::Cow;

use mail_parser::{Encoding, Message, MessageParser, MessagePart, MessageRef, PartKind, TextList};
use time::{OffsetDateTime, UtcOffset};
use tp_contracts::meta::{Address, BodyPart, Envelope, MessageMeta};
use tp_contracts::reply::normalize_recipient;
use tp_contracts::thread::ThreadFacts;
use tp_contracts::transport::normalize_domain;

pub use crate::split::MimeLimits;

/// Предел превью, символов (JMAP `preview`, RFC 8621 4.1.4; CONTRACTS.md `MessageMeta::preview`).
pub const PREVIEW_CHARS: usize = 256;

/// Наибольшее число доменов ссылок, извлекаемых из одного письма (MS-21): сверх — сканирование
/// останавливается (хранилище беседы ограничивает список своими пределами, CTR-94 `ThreadLimits`).
pub const MAX_LINKS_FOUND: usize = 256;

/// Метаданные письма с пределами разбора по умолчанию.
pub fn message_meta(raw: &[u8]) -> MessageMeta {
    message_meta_with(raw, MimeLimits::default())
}

/// Метаданные письма. Не падает на битом MIME: что не разобралось, остаётся пустым; части глубже
/// и сверх `limits` в `body` не описываются.
pub fn message_meta_with(raw: &[u8], limits: MimeLimits) -> MessageMeta {
    analyze(raw, limits).meta
}

/// Разбор письма для приёма: метаданные для протоколов и вход беседы (MS-21, CTR-94) — один разбор.
pub fn analyze(raw: &[u8], limits: MimeLimits) -> Analyzed {
    // mail-parser 1.0: пределы разбора задаёт [`MimeLimits`] на обходе дерева (SRS 6.8), как в 0.11 —
    // глубина парсера не ограничивается, иначе части за встроенным пределом 1.0 выпадают из BODYSTRUCTURE.
    let Some(msg) = MessageParser::new().max_depth(usize::MAX).parse(raw) else {
        return Analyzed {
            meta: MessageMeta {
                body: leaf_default(String::new()),
                ..MessageMeta::default()
            },
            thread: ThreadInput::default(),
        };
    };
    let meta = MessageMeta {
        envelope: envelope(&msg),
        body: message_body(msg.root(), "", 0, &mut Budget { limits, parts: 0 }),
        preview: preview(&msg),
        thread_key: thread_key(&msg),
        has_attachment: msg.attachments().len() > 0,
    };
    let thread = thread_input(&msg, &meta);
    Analyzed { meta, thread }
}

/// Итог разбора письма: метаданные и вход беседы.
#[derive(Debug, Clone)]
pub struct Analyzed {
    /// Метаданные письма.
    pub meta: MessageMeta,
    /// Ключи присоединения и память беседы для аномалий.
    pub thread: ThreadInput,
}

/// Вход беседы при приёме (MS-21): ключи присоединения — значения `Message-ID`, `In-Reply-To`,
/// `References` (канонизирует их `ThreadStore::bind`, CTR-94 `join_key`), и память для аномалий
/// (решение 125 д): типы вложений, домены ссылок, `Reply-To`.
#[derive(Debug, Default, Clone)]
pub struct ThreadInput {
    /// Ключи присоединения к беседе (сырые значения заголовков).
    pub keys: Vec<String>,
    /// Память беседы для аномалий.
    pub facts: ThreadFacts,
}

/// Вход беседы из разобранного письма: ключи присоединения и память для аномалий.
fn thread_input(msg: &Message<'_>, meta: &MessageMeta) -> ThreadInput {
    let mut keys = Vec::new();
    if let Some(id) = msg.message_id() {
        keys.push(id.to_owned());
    }
    keys.extend(ids(msg.in_reply_to()).into_iter().map(str::to_owned));
    keys.extend(ids(msg.references()).into_iter().map(str::to_owned));
    let mut attachments = Vec::new();
    attachment_types(&meta.body, &mut attachments);
    ThreadInput {
        keys,
        facts: ThreadFacts {
            attachments,
            link_domains: link_domains(msg),
            reply_to: meta
                .envelope
                .reply_to
                .iter()
                .filter_map(|a| normalize_recipient(&a.email).ok())
                .collect(),
        },
    }
}

/// Типы вложений письма (`media/subtype`, disposition `attachment`), без повторов.
fn attachment_types(part: &BodyPart, out: &mut Vec<String>) {
    if part
        .disposition
        .as_ref()
        .is_some_and(|(kind, _)| kind == "attachment")
    {
        let t = format!("{}/{}", part.media_type, part.subtype);
        if !out.contains(&t) {
            out.push(t);
        }
    }
    for child in &part.children {
        attachment_types(child, out);
    }
}

/// Домены ссылок письма (`http`/`https` из текстовых частей), канонические, без повторов.
fn link_domains(msg: &Message<'_>) -> Vec<String> {
    let mut out = Vec::new();
    for part in msg.root().parts() {
        let text = match part.kind() {
            PartKind::Text | PartKind::Html => match part.text() {
                Some(text) => text,
                None => continue,
            },
            _ => continue,
        };
        scan_links(&text, &mut out);
        if out.len() >= MAX_LINKS_FOUND {
            break;
        }
    }
    out
}

/// Байт authority-части URL: имя узла с портом и учётными данными (отделяются в [`host_of`]).
fn is_host_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'-' | b'.' | b'_' | b'~' | b'%' | b'@' | b':' | b'[' | b']'
        )
}

/// `http://`/`https://` в позиции `i` (без учёта регистра) — длина схемы со слэшами.
fn scheme_at(b: &[u8], i: usize) -> Option<usize> {
    let found = |s: &[u8]| b.len() >= i + s.len() && b[i..i + s.len()].eq_ignore_ascii_case(s);
    if found(b"https://") {
        Some(8)
    } else if found(b"http://") {
        Some(7)
    } else {
        None
    }
}

/// Имя узла из authority-части URL: без учётных данных (`user@`) и порта (`:8080`); IPv6 в скобках
/// и прочие не-домены отбрасывает нормализация домена.
fn host_of(authority: &str) -> &str {
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    match host.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

/// Домены ссылок `http`/`https` из текста (декодированного; quoted-printable и base64 уже сняты):
/// имя узла — до первого символа вне authority, в канонической форме, без повторов.
fn scan_links(text: &str, out: &mut Vec<String>) {
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let Some(scheme) = scheme_at(b, i) else {
            i += 1;
            continue;
        };
        let start = i + scheme;
        let end = start
            + b[start..]
                .iter()
                .position(|&c| !is_host_byte(c))
                .unwrap_or(b.len() - start);
        if let Ok(domain) = normalize_domain(host_of(&text[start..end]))
            && !out.contains(&domain)
        {
            out.push(domain);
        }
        i = end.max(start);
    }
}

fn envelope(msg: &Message<'_>) -> Envelope {
    let addrs = |a: Option<mail_parser::AddressList<'_>>| -> Vec<Address> {
        a.map(|a| {
            a.mailboxes()
                .filter_map(|addr| {
                    Some(Address {
                        name: addr.name().map(str::to_owned),
                        email: addr.address()?.to_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
    };
    let in_reply_to = ids(msg.in_reply_to());
    Envelope {
        date: msg.date().and_then(datetime),
        subject: msg.subject().map(str::to_owned),
        from: addrs(msg.from()),
        sender: addrs(msg.sender()),
        reply_to: addrs(msg.reply_to()),
        to: addrs(msg.to()),
        cc: addrs(msg.cc()),
        bcc: addrs(msg.bcc()),
        in_reply_to: (!in_reply_to.is_empty()).then(|| bracketed(&in_reply_to)),
        message_id: msg.message_id().map(|id| bracketed(&[id])),
    }
}

/// Дата заголовка со смещением из него; недопустимая — `None`.
fn datetime(d: mail_parser::DateTime) -> Option<OffsetDateTime> {
    if !d.is_valid() {
        return None;
    }
    let sign = if d.tz_before_gmt { -1 } else { 1 };
    let offset = sign * (i32::from(d.tz_hour) * 3600 + i32::from(d.tz_minute) * 60);
    let offset = UtcOffset::from_whole_seconds(offset).ok()?;
    OffsetDateTime::from_unix_timestamp(d.to_timestamp())
        .ok()?
        .checked_to_offset(offset)
}

/// Идентификаторы сообщений заголовка (без угловых скобок).
fn ids<'a>(value: Option<TextList<'a>>) -> Vec<&'a str> {
    value.map(|list| list.iter().collect()).unwrap_or_default()
}

fn bracketed(ids: &[&str]) -> String {
    ids.iter()
        .map(|id| format!("<{id}>"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Пределы описания частей: обойдено частей.
struct Budget {
    limits: MimeLimits,
    parts: usize,
}

/// Корень письма (верхнего или вложенного с путём `base`).
fn message_body(msg: MessageRef<'_>, base: &str, depth: usize, b: &mut Budget) -> BodyPart {
    let root = msg.root_part();
    if root.is_multipart() {
        node(root, base.to_owned(), base, depth, b)
    } else {
        let body = child_path(base, 1);
        let path = if base.is_empty() {
            String::new()
        } else {
            body.clone()
        };
        node(root, path, &body, depth, b)
    }
}

/// Узел части с путём `path`; `base` — путь, от которого нумеруются дети составной части
/// и части вложенного письма (у корня несоставного письма отличается от `path`, как в split).
fn node(part: MessagePart<'_>, path: String, base: &str, depth: usize, b: &mut Budget) -> BodyPart {
    b.parts += 1;
    let (media_type, subtype, params) = match part.content_type() {
        Some(ct) => (
            ct.ctype().to_ascii_lowercase(),
            ct.subtype()
                .map_or_else(|| default_subtype(ct.ctype()), str::to_ascii_lowercase),
            attributes(ct.attributes()),
        ),
        None => ("text".to_owned(), "plain".to_owned(), Vec::new()),
    };
    // Тело части в кодировке передачи: у вложенного письма без кодирования передачи — срез исходного
    // буфера, у закодированного — срез раскодированных байтов (`raw_body` учитывает источник части).
    let body = part.raw_body();
    let lines = (media_type == "text" || (media_type == "message" && subtype == "rfc822"))
        .then(|| u32::try_from(body.iter().filter(|&&b| b == b'\n').count()).unwrap_or(u32::MAX));
    let mut children = Vec::new();
    if depth < b.limits.max_depth {
        match part.kind() {
            PartKind::Multipart => {
                for (n, child) in part.children().enumerate() {
                    if b.parts >= b.limits.max_parts {
                        break;
                    }
                    let p = child_path(base, n + 1);
                    children.push(node(child, p.clone(), &p, depth + 1, b));
                }
            }
            PartKind::Message(nested) if b.parts < b.limits.max_parts => {
                children.push(message_body(nested, base, depth + 1, b));
            }
            _ => {}
        }
    }
    BodyPart {
        part: path,
        media_type,
        subtype,
        params,
        content_id: part.content_id().map(|id| bracketed(&[id])),
        description: part.content_description().map(str::to_owned),
        encoding: part.content_transfer_encoding().map(str::to_owned),
        disposition: part
            .content_disposition()
            .map(|d| (d.ctype().to_ascii_lowercase(), attributes(d.attributes()))),
        language: ids(part.content_language())
            .into_iter()
            .map(str::to_owned)
            .collect(),
        location: part.content_location().map(str::to_owned),
        size: u64::from(part.offset_end().saturating_sub(part.offset_body())),
        lines,
        children,
    }
}

fn attributes<'m>(attrs: impl Iterator<Item = (&'m str, &'m str)>) -> Vec<(String, String)> {
    attrs
        .map(|(name, value)| (name.to_ascii_lowercase(), value.to_owned()))
        .collect()
}

fn default_subtype(media_type: &str) -> String {
    if media_type.eq_ignore_ascii_case("text") {
        "plain"
    } else {
        "octet-stream"
    }
    .to_owned()
}

fn leaf_default(part: String) -> BodyPart {
    BodyPart {
        part,
        media_type: "text".to_owned(),
        subtype: "plain".to_owned(),
        ..BodyPart::default()
    }
}

fn child_path(base: &str, n: usize) -> String {
    if base.is_empty() {
        n.to_string()
    } else {
        format!("{base}.{n}")
    }
}

/// Начало текста письма: пробельные символы сжаты до одного пробела, не длиннее [`PREVIEW_CHARS`].
fn preview(msg: &Message<'_>) -> String {
    let text: Cow<'_, str> = match mislabeled_utf8(msg) {
        Some(text) => Cow::Borrowed(text),
        None => msg.body_preview(usize::MAX).unwrap_or_default(),
    };
    let mut out = String::new();
    let mut n = 0;
    'words: for (i, word) in text.split_whitespace().enumerate() {
        for ch in (i > 0).then_some(' ').into_iter().chain(word.chars()) {
            if n == PREVIEW_CHARS {
                break 'words;
            }
            out.push(ch);
            n += 1;
        }
    }
    out.truncate(out.trim_end().len());
    out
}

/// Текст первой текстовой части, если он записан в UTF-8 вопреки метке `charset`: тело без кодирования
/// передачи не декодировалось по метке (есть U+FFFD), но как UTF-8 корректно. Частая ошибка почтовых
/// клиентов; без проверки превью зависело бы от набора кодировок `mail-parser`.
fn mislabeled_utf8<'a>(msg: &'a Message<'_>) -> Option<&'a str> {
    let part = msg.text_body().next()?;
    if !matches!(part.kind(), PartKind::Text) || part.encoding() != Encoding::None {
        return None;
    }
    let text = part.text()?;
    if !text.contains(char::REPLACEMENT_CHARACTER) {
        return None;
    }
    std::str::from_utf8(part.raw_body()).ok()
}

fn thread_key(msg: &Message<'_>) -> String {
    let root = ids(msg.references())
        .first()
        .copied()
        .or_else(|| ids(msg.in_reply_to()).first().copied())
        .or_else(|| msg.message_id());
    if let Some(id) = root {
        return bracketed(&[id]);
    }
    match msg.thread_name().map(str::trim) {
        Some(subject) if !subject.is_empty() => format!("subject:{}", subject.to_lowercase()),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_corpus() {
        for mail in tp_testkit::corpus::corpus().expect("corpus") {
            let meta = message_meta(&mail.raw);
            assert!(
                meta.preview.chars().count() <= PREVIEW_CHARS,
                "{}",
                mail.name
            );
            insta::assert_json_snapshot!(mail.name.clone(), meta);
        }
    }

    #[tokio::test]
    async fn ingest_stores_meta() {
        use tp_contracts::mailstore::{Delivery, IngestRequest, MailStore};
        use tp_contracts::meta::{Flags, MessageStore, SpecialUse};

        let env = crate::testenv::Env::new();
        let scope = env.meta.account("a@example.org").await.expect("acc");
        let inbox = env
            .meta
            .mailbox_by_role(scope, SpecialUse::Inbox)
            .expect("inbox");
        let raw = tp_testkit::corpus::corpus_mail("rfc822-with-attachment")
            .expect("mail")
            .raw;
        let done = env
            .store
            .ingest(IngestRequest {
                tenant: scope.tenant,
                mail_from: String::new(),
                raw: crate::testenv::stream(&raw, 1024),
                deliveries: vec![Delivery {
                    account: scope.account,
                    mailbox: inbox,
                    extra_headers: vec![("Delivered-To".into(), "a@example.org".into())],
                    flags: Flags::new(),
                }],
                received_at: OffsetDateTime::now_utc(),
            })
            .await
            .expect("ingest");
        let m = MessageStore::get(&env.meta, scope, done.delivered[0].message)
            .await
            .expect("get")
            .expect("msg");
        assert_eq!(m.meta, message_meta(&raw));
        assert!(m.meta.has_attachment);
    }

    #[test]
    fn thread_key_links_replies() {
        let root = message_meta(b"Message-ID: <a@x>\r\nSubject: Plan\r\n\r\nbody\r\n");
        let reply = message_meta(
            b"Message-ID: <b@x>\r\nIn-Reply-To: <a@x>\r\nSubject: Re: Plan\r\n\r\nok\r\n",
        );
        let deep = message_meta(
            b"Message-ID: <c@x>\r\nReferences: <a@x> <b@x>\r\nIn-Reply-To: <b@x>\r\n\r\nok\r\n",
        );
        let other = message_meta(b"Message-ID: <d@x>\r\nSubject: Plan\r\n\r\nbody\r\n");
        assert_eq!(root.thread_key, "<a@x>");
        assert_eq!(reply.thread_key, root.thread_key);
        assert_eq!(deep.thread_key, root.thread_key);
        assert_ne!(other.thread_key, root.thread_key);
        assert_eq!(reply.envelope.in_reply_to.as_deref(), Some("<a@x>"));
        let anon = message_meta(b"Subject: Fwd: Re: Plan \r\n\r\nx\r\n");
        assert_eq!(anon.thread_key, "subject:plan");
        assert_eq!(message_meta(b"\r\n\r\n").thread_key, "");
    }

    #[test]
    fn nested_parts_count_lines() {
        let inner = "Subject: in

one
two
";
        let wrap = |cte: &str, body: &str| {
            format!(
                "Content-Type: multipart/mixed; boundary=b

--b
                 Content-Type: message/rfc822
{cte}
{body}
--b--
"
            )
        };
        let plain = message_meta(wrap("", inner).as_bytes());
        assert_eq!(plain.body.children[0].children[0].lines, Some(2));
        // Вложение в base64: смещения — в декодированных байтах вложения.
        let b64 = "U3ViamVjdDogaW4NCg0Kb25lDQp0d28NCg==";
        let encoded = message_meta(
            wrap(
                "Content-Transfer-Encoding: base64
",
                b64,
            )
            .as_bytes(),
        );
        assert_eq!(encoded.body.children[0].children[0].lines, Some(2));
    }

    #[test]
    fn preview_is_compact() {
        let body = format!(
            "Subject: x\r\n\r\n  one\r\n\r\n\ttwo   {}\r\n",
            "щ".repeat(400)
        );
        let meta = message_meta(body.as_bytes());
        assert!(meta.preview.starts_with("one two щщ"));
        assert_eq!(meta.preview.chars().count(), PREVIEW_CHARS);
    }

    #[test]
    fn thread_input_keys_and_reply_to() {
        // Ключи присоединения: собственный Message-ID, In-Reply-To, References — все значения.
        let raw = b"Message-ID: <c@x>\r\nIn-Reply-To: <b@x>\r\nReferences: <a@x> <b@x>\r\n\
                    Reply-To: Sales <SALES@Example.COM>\r\nSubject: Re: Plan\r\n\r\nok\r\n";
        let input = analyze(raw, MimeLimits::default()).thread;
        assert_eq!(input.keys, ["c@x", "b@x", "a@x", "b@x"]);
        assert_eq!(
            input.facts.reply_to,
            ["SALES@example.com"],
            "домен — нижний регистр, local-part — как задан"
        );
        assert!(input.facts.attachments.is_empty());
        assert!(input.facts.link_domains.is_empty());
        let bare = analyze(b"Subject: x\r\n\r\nbody\r\n", MimeLimits::default()).thread;
        assert!(bare.keys.is_empty());
    }

    #[test]
    fn thread_input_attachment_types() {
        let raw = "Subject: docs\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/mixed; boundary=b\r\n\r\n\
             --b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n\
             --b\r\nContent-Type: application/pdf; name=plan.pdf\r\n\
             Content-Disposition: attachment; filename=plan.pdf\r\n\r\n%PDF\r\n\
             --b\r\nContent-Type: application/pdf\r\n\
             Content-Disposition: ATTACHMENT\r\n\r\n%PDF again\r\n\
             --b--\r\n";
        let input = analyze(raw.as_bytes(), MimeLimits::default()).thread;
        assert_eq!(
            input.facts.attachments,
            ["application/pdf"],
            "типы вложений без повторов, без учёта регистра disposition"
        );
    }

    #[test]
    fn link_scan_finds_canonical_domains() {
        let mut out = Vec::new();
        scan_links(
            "Пишите на HTTPS://Vendor.Example/pricing, http://shop.example.net:8080/x и \
             https://user@portal.example.org — но не ftp://old.example, не http:// и не www.bare.example.",
            &mut out,
        );
        assert_eq!(
            out,
            ["vendor.example", "shop.example.net", "portal.example.org"],
            "схема без учёта регистра, порт и учётные данные сняты, прочие схемы мимо"
        );
        let mut empty = Vec::new();
        scan_links(
            "http://\r\nhttp:///path http://[::1]/x http://xn--e1afmkfd.xn--p1ai/",
            &mut empty,
        );
        assert_eq!(
            empty,
            ["xn--e1afmkfd.xn--p1ai"],
            "пустые и IPv6 — мимо, A-label принят"
        );
    }
}
