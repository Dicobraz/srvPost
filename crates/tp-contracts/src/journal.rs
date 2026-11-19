//! Журналирование переписки (CONTRACTS.md#Journal; SRS 4.9, 5.2; CTR-97).
//!
//! Журналирование по модели Exchange Journaling — базовая поставка: правило задаётся на организацию,
//! группу или ящик с направлением; выполняется этапом ядра конвейера ([`crate::pipeline`], точка
//! `BeforeMailboxSieve`, до скрипта ящика и этапов модулей) — скрипт ящика (`discard`, `stop`) и правила
//! модулей запись не отменяют. Одна запись на письмо: письмо целиком и конверт (отправитель, все
//! получатели, включая скрытых и раскрытых из групп). Хранилище записей — отдельное от BLOB ящиков
//! (SRS 4.9: дедупликация внутри журнала, блокировка объектов не затрагивает хранилище ящиков); контракт
//! бэкенда не знает: реализация — полоса blob (BLOB-18), индекс — META-88. Доступ — только роль
//! «аудитор журнала» (SRS 5.2): токен [`JournalAudit`]; пользователи и администраторы правил журнал не
//! видят, через IMAP и JMAP он не доступен. Целостность индекса (хеш-цепочка) проверяют thepost doctor
//! и Admin API.

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::identity::valid_address;
use crate::ids::{AccountId, BlobHash, GroupId, JournalId, TenantId};

/// Наибольшая длина идентификатора правила, байт.
pub const MAX_RULE_ID_LEN: usize = 64;

/// Наибольшая длина Message-ID записи, байт (предел строки заголовка RFC 5322).
pub const MAX_MESSAGE_ID_LEN: usize = 998;

/// Хеш первой записи цепочки (32 нулевых байта): `hash₁ = SHA-256(chain_input(GENESIS_HASH, record₁))`.
pub const GENESIS_HASH: BlobHash = BlobHash([0u8; 32]);

/// Проверяет идентификатор правила: 1–[`MAX_RULE_ID_LEN`] байт без пробелов и управляющих.
pub fn valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_RULE_ID_LEN
        && !id.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// Направление письма для правила журналирования.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JournalDirection {
    /// Доставляемое в ящики организации (входящее, включая внутреннюю почту получателю).
    In,
    /// Отправляемое клиентом (submission, JMAP EmailSubmission).
    Out,
    /// Оба направления.
    Both,
}

/// Область правила журналирования: организация, группа рассылки или ящик.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalScope {
    /// Организация целиком.
    Org,
    /// Группа рассылки: отправитель или получатель — член группы ([`JournalRule::covers`], раскрытие —
    /// вызывающий).
    Group(GroupId),
    /// Ящик (учётная запись).
    Mailbox(AccountId),
}

/// Правило журналирования (SRS 4.9): задаётся на организацию, группу или ящик с направлением.
/// Хранение и Admin API — волны полос; этап ядра подбирает правила по конверту и направлению.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRule {
    /// Идентификатор ([`valid_rule_id`]); в записи журнала — [`JournalRecord::rule`].
    pub id: String,
    /// Организация правила.
    pub tenant: TenantId,
    /// Область.
    pub scope: JournalScope,
    /// Направление.
    pub direction: JournalDirection,
    /// Включено.
    pub enabled: bool,
}

impl JournalRule {
    /// Проверка идентификатора; иначе — `Error::Invalid`.
    pub fn validate(&self) -> Result<()> {
        if !valid_rule_id(&self.id) {
            return Err(Error::invalid("journal: bad rule id"));
        }
        Ok(())
    }

    /// Правило покрывает письмо: включено, направление совпадает ([`JournalDirection::Both`] — любое;
    /// для записи журнала вызывающий передаёт `In` или `Out`), область покрывает отправителя или
    /// получателя: организация — любые письма; ящик — совпадение учётной записи; группа — учётная запись
    /// в `members` (раскрытие группы — вызывающий, `GroupStore::expand`).
    pub fn covers(
        &self,
        direction: JournalDirection,
        sender: Option<AccountId>,
        rcpts: &[AccountId],
        members: &[AccountId],
    ) -> bool {
        if !self.enabled {
            return false;
        }
        if self.direction != JournalDirection::Both && self.direction != direction {
            return false;
        }
        match self.scope {
            JournalScope::Org => true,
            JournalScope::Mailbox(account) => sender == Some(account) || rcpts.contains(&account),
            JournalScope::Group(_) => {
                let in_group = |a: &AccountId| members.contains(a);
                sender.as_ref().is_some_and(in_group) || rcpts.iter().any(in_group)
            }
        }
    }
}

/// Запись журнала: конверт письма (SRS 4.9). Письмо целиком передаётся в
/// [`JournalStore::append`] отдельно; получатели — все, включая скрытых (BCC) и раскрытых из групп
/// рассылки (раскрывает этап ядра до записи). Одна запись на письмо (на правило).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRecord {
    /// Организация.
    pub tenant: TenantId,
    /// Отправитель конверта (`MAIL FROM`); пустой — уведомление о доставке.
    pub sender: String,
    /// Все получатели конверта, включая скрытых и раскрытых из групп.
    pub recipients: Vec<String>,
    /// Message-ID без угловых скобок; `None` — нет.
    pub message_id: Option<String>,
    /// Момент письма (UTC); в каноническом JSON — строка RFC 3339: её приводит к timestamptz
    /// проверка цепочки чистым SQL (`journal.tp_consistent`).
    #[serde(with = "time::serde::rfc3339")]
    pub at: OffsetDateTime,
    /// Правило ([`JournalRule::id`]).
    pub rule: String,
}

impl JournalRecord {
    /// Проверка: отправитель и получатели — адреса, получатели не пусты, Message-ID — до
    /// [`MAX_MESSAGE_ID_LEN`] байт без пробелов и управляющих, правило — [`valid_rule_id`].
    /// Иначе — `Error::Invalid`.
    pub fn validate(&self) -> Result<()> {
        let plain = |s: &str, max: usize| {
            !s.is_empty()
                && s.len() <= max
                && !s.chars().any(|c| c.is_whitespace() || c.is_control())
        };
        if !valid_address(&self.sender) {
            return Err(Error::invalid("journal: bad sender address"));
        }
        if self.recipients.is_empty() {
            return Err(Error::invalid("journal: record must have recipients"));
        }
        if let Some(bad) = self.recipients.iter().find(|r| !valid_address(r)) {
            return Err(Error::invalid(format!("journal: bad recipient {bad:?}")));
        }
        if let Some(mid) = &self.message_id
            && !plain(mid, MAX_MESSAGE_ID_LEN)
        {
            return Err(Error::invalid("journal: bad message id"));
        }
        if !valid_rule_id(&self.rule) {
            return Err(Error::invalid("journal: bad rule id"));
        }
        Ok(())
    }

    /// Каноническое представление для хеш-цепочки индекса (детерминированный JSON записи).
    pub fn canonical(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

/// Образ входа хеш-цепочки индекса (SRS 4.9): `hash = SHA-256(prev_hash ‖ canonical(record))` —
/// 32 байта хеша предыдущей записи организации (у первой — [`GENESIS_HASH`]), затем каноническое
/// представление записи. Алгоритм и образ фиксированы контрактом: индекс (META-88) и проверки
/// (thepost doctor, Admin API) сходятся на одних значениях.
pub fn chain_input(prev: &BlobHash, record: &JournalRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 256);
    out.extend_from_slice(prev.as_bytes());
    out.extend_from_slice(&record.canonical());
    out
}

/// Право роли «аудитор журнала» (SRS 5.2): доступ к записям журнала. Выдаёт авторизация Admin API по
/// роли; параметр [`JournalStore::search`], [`JournalStore::export`], [`JournalStore::verify_chain`].
/// Пользователи и администраторы правил журнал не видят; через IMAP и JMAP не доступен.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JournalAudit {
    _private: (),
}

impl JournalAudit {
    /// Пропуск: выдаёт авторизация Admin API роли «аудитор журнала».
    pub fn grant() -> Self {
        JournalAudit { _private: () }
    }
}

/// Запрос к журналу. Условия объединяются по «и»; `None` — без условия.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalQuery {
    /// Организация (записи чужих организаций не видны).
    pub tenant: TenantId,
    /// Отправитель конверта (точное совпадение без учёта регистра ASCII).
    pub sender: Option<String>,
    /// Один из получателей записи — включая скрытых и раскрытых из групп (точное совпадение без учёта
    /// регистра ASCII).
    pub recipient: Option<String>,
    /// Message-ID (точное совпадение).
    pub message_id: Option<String>,
    /// Правило ([`JournalRule::id`], точное совпадение).
    pub rule: Option<String>,
    /// Начало интервала, включительно.
    pub since: Option<OffsetDateTime>,
    /// Конец интервала, не включительно.
    pub until: Option<OffsetDateTime>,
    /// Не более записей на страницу, ≥ 1 (иначе `Error::Invalid`).
    pub limit: usize,
    /// Продолжение после страницы с этой позицией.
    pub after: Option<JournalCursor>,
}

impl JournalQuery {
    /// Запрос без условий (кроме организации) на `limit` записей.
    pub fn all(tenant: TenantId, limit: usize) -> Self {
        JournalQuery {
            tenant,
            sender: None,
            recipient: None,
            message_id: None,
            rule: None,
            since: None,
            until: None,
            limit,
            after: None,
        }
    }

    /// Проверка: `limit ≥ 1`, `since < until`; иначе — `Error::Invalid`.
    pub fn validate(&self) -> Result<()> {
        if self.limit == 0 {
            return Err(Error::invalid("journal query limit must be positive"));
        }
        if let (Some(since), Some(until)) = (self.since, self.until)
            && since >= until
        {
            return Err(Error::invalid("journal query interval is empty"));
        }
        Ok(())
    }

    /// Запись удовлетворяет условиям запроса (кроме организации и позиции).
    pub fn matches(&self, r: &JournalRecord) -> bool {
        self.sender
            .as_deref()
            .is_none_or(|s| s.eq_ignore_ascii_case(&r.sender))
            && self
                .recipient
                .as_deref()
                .is_none_or(|want| r.recipients.iter().any(|r| r.eq_ignore_ascii_case(want)))
            && self
                .message_id
                .as_deref()
                .is_none_or(|m| r.message_id.as_deref() == Some(m))
            && self.rule.as_deref().is_none_or(|rule| rule == r.rule)
            && self.since.is_none_or(|s| r.at >= s)
            && self.until.is_none_or(|u| r.at < u)
    }
}

/// Позиция продолжения поиска; непрозрачна, действительна для того же запроса.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JournalCursor(pub String);

/// Страница журнала: записи в порядке (`at`, `id`); `next` — у полной страницы.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalPage {
    /// Записи страницы.
    pub entries: Vec<JournalEntry>,
    /// Позиция следующей страницы.
    pub next: Option<JournalCursor>,
}

/// Запись индекса журнала.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalEntry {
    /// Идентификатор записи.
    pub id: JournalId,
    /// Конверт.
    pub record: JournalRecord,
    /// Хеш цепочки (`SHA-256(chain_input(prev, record))`); проверяется [`JournalStore::verify_chain`].
    pub hash: BlobHash,
}

/// Итог проверки хеш-цепочки индекса организации.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainReport {
    /// Число проверенных записей.
    pub records: u64,
    /// Цепочка целостна.
    pub ok: bool,
    /// Первая запись с нарушением (хеш не сходится); `None` — нарушений нет.
    pub broken_at: Option<JournalId>,
}

/// Выгрузка записи: .eml с конвертом (модель journal report Exchange; отличие — конверт в добавляемых
/// заголовках `X-ThePost-Journal-*`, без обёртки-вложения). Строки заголовков добавляются перед
/// исходными заголовками письма: `Sender` (отправитель конверта), `Recipient` (каждый получатель),
/// `Message-Id`, `Rule`, `Date` (unix-секунды). Запись проверяется ([`JournalRecord::validate`]).
pub fn journal_eml(record: &JournalRecord, message: &[u8]) -> Result<Bytes> {
    record.validate()?;
    let mut out = String::new();
    out.push_str("X-ThePost-Journal-Sender: ");
    out.push_str(&record.sender);
    out.push_str("\r\n");
    for rcpt in &record.recipients {
        out.push_str("X-ThePost-Journal-Recipient: ");
        out.push_str(rcpt);
        out.push_str("\r\n");
    }
    if let Some(mid) = &record.message_id {
        out.push_str("X-ThePost-Journal-Message-Id: ");
        out.push_str(mid);
        out.push_str("\r\n");
    }
    out.push_str("X-ThePost-Journal-Rule: ");
    out.push_str(&record.rule);
    out.push_str("\r\nX-ThePost-Journal-Date: ");
    out.push_str(&record.at.unix_timestamp().to_string());
    out.push_str("\r\n");
    let mut whole = out.into_bytes();
    whole.extend_from_slice(message);
    Ok(Bytes::from(whole))
}

/// Хранилище журнала (SRS 4.9): записи — письмо целиком с конвертом, индекс — для поиска и проверки
/// целостности. Хранилище записей — отдельное от BLOB ящиков, с дедупликацией внутри журнала и
/// блокировкой объектов (S3 Object Lock; режим и срок — настройка установки); контракт бэкенда не знает.
/// Записи неизменяемы: методов изменения и удаления нет, срок хранения продлевается только
/// (SRS 4.9). Реализация — полоса blob (BLOB-18), индекс — META-88; in-memory — `tp-testkit`.
#[async_trait]
pub trait JournalStore: Send + Sync + 'static {
    /// Записывает копию письма в журнал по правилу (этап ядра конвейера, до Sieve ящика; одна запись на
    /// письмо на правило — повторный вызов этапа создаёт новую запись). `record.rule` должен совпадать с
    /// `rule.id`, `record.tenant` — с `rule.tenant`; пустое письмо — `Error::Invalid`.
    async fn append(
        &self,
        rule: &JournalRule,
        record: &JournalRecord,
        message: Bytes,
    ) -> Result<JournalId>;

    /// Поиск по индексу (аудитор журнала; SRS 5.2). Порядок — (`at`, `id`); некорректный запрос или
    /// позиция — `Error::Invalid`.
    async fn search(&self, cap: &JournalAudit, query: &JournalQuery) -> Result<JournalPage>;

    /// Выгрузка записи: .eml с конвертом ([`journal_eml`]). Нет записи — `Error::NotFound`.
    async fn export(&self, cap: &JournalAudit, tenant: TenantId, id: JournalId) -> Result<Bytes>;

    /// Проверка хеш-цепочки индекса организации (thepost doctor, Admin API; аудитор журнала):
    /// `hash = SHA-256(chain_input(prev, record))`.
    async fn verify_chain(&self, cap: &JournalAudit, tenant: TenantId) -> Result<ChainReport>;

    /// Восстановление индекса из хранилища записей (maintenance): возвращает число восстановленных
    /// записей организации.
    async fn restore_index(&self, tenant: TenantId) -> Result<u64>;
}

/// Хранилище записей журнала (SRS 4.9) — порт индекса (META-88): письмо целиком с конвертом в отдельном
/// от BLOB ящиков бакете журнала с дедупликацией внутри журнала и блокировкой объектов (режим и срок —
/// настройка установки). Контракт бэкенда не знает: реализация — полоса blob (BLOB-18, S3 с Object Lock
/// или локальный диск), in-memory — `tp-testkit`. Записи неизменяемы: методов изменения и удаления нет.
///
/// Запись адресуется по [`JournalId`]; `put` возвращает ссылку на запись в хранилище (ключ объекта) —
/// индекс хранит её для поиска и диагностики (thepost doctor). Двухфазная запись журнала: сначала
/// `put` (идемпотентен, вне транзакции БД — обращения к BLOB в открытой транзакции запрещены), затем
/// строка индекса в PostgreSQL; при обрыве между фазами индекс чинит [`JournalStore::restore_index`].
#[async_trait]
pub trait JournalRecords: Send + Sync + 'static {
    /// Записывает запись `id` — конверт и письмо целиком; повторная запись того же `id` — не ошибка
    /// (возвращает ту же ссылку). Возвращает ссылку на запись (ключ объекта хранилища).
    async fn put(&self, id: JournalId, record: &JournalRecord, message: Bytes) -> Result<String>;

    /// Читает запись — конверт и письмо целиком; нет записи — `Error::NotFound`.
    async fn read(&self, id: JournalId) -> Result<(JournalRecord, Bytes)>;

    /// Конверты записей организации по возрастанию `id` (порядок добавления): восстановление индекса.
    /// Письма не читает — для цепочки хешей достаточно конвертов.
    async fn scan(&self, tenant: TenantId) -> Result<Vec<(JournalId, JournalRecord, String)>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(scope: JournalScope, direction: JournalDirection, enabled: bool) -> JournalRule {
        JournalRule {
            id: "r-0042".to_owned(),
            tenant: TenantId::DEFAULT,
            scope,
            direction,
            enabled,
        }
    }

    fn record() -> JournalRecord {
        JournalRecord {
            tenant: TenantId::DEFAULT,
            sender: "sender@external.example".to_owned(),
            recipients: vec![
                "anna@internal.example".to_owned(),
                "hidden@internal.example".to_owned(),
            ],
            message_id: Some("m1@external.example".to_owned()),
            at: OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time"),
            rule: "r-0042".to_owned(),
        }
    }

    #[test]
    fn rule_covers() {
        let (anna, bob) = (AccountId::new(), AccountId::new());
        let org = rule(JournalScope::Org, JournalDirection::Both, true);
        assert!(org.covers(JournalDirection::In, None, &[], &[]));
        assert!(org.covers(JournalDirection::Out, Some(bob), &[anna], &[]));
        // Направление и выключенное правило.
        let inbox_only = rule(JournalScope::Org, JournalDirection::In, true);
        assert!(!inbox_only.covers(JournalDirection::Out, Some(anna), &[], &[]));
        assert!(
            !rule(JournalScope::Org, JournalDirection::Both, false).covers(
                JournalDirection::In,
                None,
                &[],
                &[]
            )
        );
        // Ящик: отправитель или получатель.
        let mailbox = rule(JournalScope::Mailbox(anna), JournalDirection::Both, true);
        assert!(mailbox.covers(JournalDirection::In, Some(anna), &[bob], &[]));
        assert!(mailbox.covers(JournalDirection::In, Some(bob), &[anna], &[]));
        assert!(!mailbox.covers(JournalDirection::In, Some(bob), &[bob], &[]));
        // Группа: членство в members (отправитель или получатель).
        let group = rule(
            JournalScope::Group(GroupId::new()),
            JournalDirection::Both,
            true,
        );
        assert!(group.covers(JournalDirection::In, Some(anna), &[bob], &[bob]));
        assert!(group.covers(JournalDirection::Out, Some(bob), &[anna], &[anna]));
        assert!(!group.covers(
            JournalDirection::In,
            Some(anna),
            &[bob],
            &[AccountId::new()]
        ));
    }

    #[test]
    fn record_validate() {
        record().validate().expect("valid");
        for bad in [
            JournalRecord {
                sender: "no-at".to_owned(),
                ..record()
            },
            JournalRecord {
                recipients: Vec::new(),
                ..record()
            },
            JournalRecord {
                recipients: vec!["anna@internal.example".into(), "no-at".into()],
                ..record()
            },
            JournalRecord {
                message_id: Some("has space@x".to_owned()),
                ..record()
            },
            JournalRecord {
                rule: String::new(),
                ..record()
            },
        ] {
            assert!(matches!(bad.validate(), Err(Error::Invalid(_))), "{bad:?}");
        }
        assert!(matches!(
            rule(JournalScope::Org, JournalDirection::Both, true).validate(),
            Ok(())
        ));
        assert!(!valid_rule_id("a b"));
        assert!(!valid_rule_id(&"x".repeat(MAX_RULE_ID_LEN + 1)));
    }

    #[test]
    fn query_matches() {
        fn with(r: &JournalRecord, f: impl FnOnce(&mut JournalQuery)) -> JournalQuery {
            let mut query = JournalQuery::all(r.tenant, 10);
            f(&mut query);
            query.validate().expect("query");
            query
        }
        let r = record();
        assert!(with(&r, |_| {}).matches(&r));
        assert!(!with(&r, |x| x.sender = Some("OTHER@external.example".into())).matches(&r));
        assert!(with(&r, |x| x.sender = Some("Sender@EXTERNAL.example".into())).matches(&r));
        // Получатель — любой из записи, включая скрытого, без учёта регистра.
        assert!(with(&r, |x| x.recipient = Some("hidden@internal.example".into())).matches(&r));
        assert!(with(&r, |x| x.recipient = Some("ANNA@internal.example".into())).matches(&r));
        assert!(!with(&r, |x| x.recipient = Some("bob@internal.example".into())).matches(&r));
        assert!(with(&r, |x| x.message_id = Some("m1@external.example".into())).matches(&r));
        assert!(with(&r, |x| x.rule = Some("r-0042".into())).matches(&r));
        assert!(!with(&r, |x| x.rule = Some("r-0043".into())).matches(&r));
        // Интервал [since, until).
        let at = r.at;
        assert!(with(&r, |x| x.since = Some(at)).matches(&r));
        assert!(!with(&r, |x| x.since = Some(at + time::Duration::SECOND)).matches(&r));
        assert!(with(&r, |x| x.until = Some(at + time::Duration::SECOND)).matches(&r));
        assert!(!with(&r, |x| x.until = Some(at)).matches(&r));
        // limit ≥ 1, непустой интервал.
        assert!(matches!(
            JournalQuery::all(r.tenant, 0).validate(),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            JournalQuery {
                since: Some(at),
                until: Some(at),
                ..JournalQuery::all(r.tenant, 1)
            }
            .validate(),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn canonical_and_chain_input() {
        let r = record();
        let c1 = r.canonical();
        assert_eq!(c1, record().canonical(), "детерминирован");
        assert_eq!(c1, serde_json::to_vec(&r).expect("json"));
        let other = JournalRecord {
            sender: "x@external.example".to_owned(),
            ..record()
        };
        assert_ne!(c1, other.canonical());

        let mut input = GENESIS_HASH.as_bytes().to_vec();
        input.extend_from_slice(&c1);
        assert_eq!(chain_input(&GENESIS_HASH, &r), input);
        assert_eq!(GENESIS_HASH, BlobHash([0u8; 32]));
        assert_ne!(
            chain_input(&GENESIS_HASH, &r),
            chain_input(&BlobHash([1u8; 32]), &r)
        );
    }

    #[test]
    fn eml_with_envelope() {
        let r = record();
        let body = b"Message-ID: <m1@external.example>\r\nSubject: one\r\n\r\nbody";
        let eml = journal_eml(&r, body).expect("eml");
        assert!(eml.starts_with(b"X-ThePost-Journal-Sender: sender@external.example\r\n"));
        let text = String::from_utf8_lossy(&eml);
        assert!(text.contains("X-ThePost-Journal-Recipient: anna@internal.example\r\n"));
        assert!(text.contains("X-ThePost-Journal-Recipient: hidden@internal.example\r\n"));
        assert!(text.contains("X-ThePost-Journal-Message-Id: m1@external.example\r\n"));
        assert!(text.contains("X-ThePost-Journal-Rule: r-0042\r\n"));
        assert!(text.contains("X-ThePost-Journal-Date: 1800000000\r\n"));
        assert!(text.ends_with("Subject: one\r\n\r\nbody"));
        assert_eq!(
            journal_eml(&r, body).expect("eml again"),
            eml,
            "детерминирован"
        );
        // Недопустимая запись — Invalid.
        let bad = JournalRecord {
            sender: "no-at".to_owned(),
            ..record()
        };
        assert!(matches!(journal_eml(&bad, body), Err(Error::Invalid(_))));
    }

    #[test]
    fn serde_kinds() {
        assert_eq!(
            serde_json::to_string(&JournalDirection::Both).expect("json"),
            "\"both\""
        );
        assert_eq!(
            serde_json::to_string(&JournalScope::Org).expect("json"),
            "\"org\""
        );
        let mailbox = JournalScope::Mailbox(AccountId::new());
        let back: JournalScope =
            serde_json::from_str(&serde_json::to_string(&mailbox).expect("json")).expect("scope");
        assert_eq!(back, mailbox);
        let r = record();
        let back: JournalRecord = serde_json::from_slice(&r.canonical()).expect("record");
        assert_eq!(back, r);
    }
}
