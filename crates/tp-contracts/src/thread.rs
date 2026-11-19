//! Беседы учётной записи: привязка писем, удержание и действия по беседе (CONTRACTS.md#Thread;
//! RFC 8621 §3, RFC 5256; решение 125 е–ж).
//!
//! Беседа — объект JMAP Thread с неизменяемым `threadId` и единица политик: удержание целиком, включая
//! будущие письма (как Google Vault), действия по беседе — «всегда перемещать», «игнорировать» (как EWS
//! `ApplyConversationAction`). Привязка письма — по `In-Reply-To`/`References` среди писем учётной записи,
//! иначе новая беседа; беседы задним числом не сливаются (RFC 8621 допускает слияние с новыми id писем,
//! мы не сливаем): письмо, ссылающееся на две беседы, попадает в более раннюю, `threadId` письма не меняется.
//! Принадлежность к беседе вычисляется по полям, которые задаёт клиент, и подделывается (RFC 5256, раздел
//! безопасности) — беседа не основа решений безопасности (решение 125 ж): журналирование, DLP и решения
//! конвейера — по отдельным письмам.
//!
//! # Транзакция приёма (MS-21)
//!
//! [`ThreadStore::bind`], память беседы ([`ThreadStore::remember_facts`]) и применённые политики беседы
//! выполняются в той же транзакции БД, что вставка письма при `MailStore::ingest` («письмо + беседа +
//! применённые политики» — одна транзакция, решение 125 е): сбой привязки откатывает письмо целиком,
//! письмо без беседы и привязка без письма не остаются (META-86 — методы над транзакцией `ingest`, без
//! отдельного соединения; in-memory реализация атомарна по построению).

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::error::{Error, Result};
use crate::ext::{Decision, DecisionHook, FinalDelete};
use crate::ids::{MailboxId, MessageId, ThreadId};
use crate::meta::AccountScope;

use crate::reply::canonical_message_id;

/// Наибольшее число значений `Reply-To` в памяти беседы, по умолчанию ([`ThreadLimits`]). Смена `Reply-To` —
/// признак аномалии (решение 125 д), значений немного.
pub const DEFAULT_MAX_REPLY_TO: usize = 8;

/// Наибольшее число типов вложений в памяти беседы, по умолчанию ([`ThreadLimits`]).
pub const DEFAULT_MAX_ATTACHMENTS: usize = 64;

/// Наибольшее число доменов ссылок в памяти беседы, по умолчанию ([`ThreadLimits`]).
pub const DEFAULT_MAX_LINK_DOMAINS: usize = 64;

/// Ключ присоединения письма к беседе: каноническая форма Message-ID ([`canonical_message_id`]) — без
/// угловых скобок, обрезанный, в нижнем регистре ASCII. Пустая строка — ключа нет (вызывающий пропускает).
/// Ключи — значения `Message-ID`, `In-Reply-To` и `References` (RFC 5322 §3.6.4): принадлежность к беседе
/// вычисляется по полям, которые задаёт клиент, — для доставки это удобно, для решений безопасности
/// подделывается (RFC 5256).
pub fn join_key(raw: &str) -> String {
    canonical_message_id(raw)
}

/// Пределы памяти беседы для аномалий (решение 125 д) — секция конфигурации реализации (SRS 5.5). Превышение
/// не ошибка: вытесняются самые старые значения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadLimits {
    /// Число типов вложений (`media/subtype`).
    pub max_attachments: usize,
    /// Число доменов ссылок (канонические имена).
    pub max_link_domains: usize,
    /// Число значений `Reply-To` (канонические адреса).
    pub max_reply_to: usize,
}

impl Default for ThreadLimits {
    fn default() -> Self {
        ThreadLimits {
            max_attachments: DEFAULT_MAX_ATTACHMENTS,
            max_link_domains: DEFAULT_MAX_LINK_DOMAINS,
            max_reply_to: DEFAULT_MAX_REPLY_TO,
        }
    }
}

/// Память беседы для аномалий (решение 125 д): типы вложений, домены ссылок, `Reply-To`. Заполняется при
/// приёме (`tp-smtp`, `MailStore::ingest` — MS-21, SMTP-51), детекторы аномалий читают её (решение 126,
/// SMTP-52). Списки без повторов, при превышении пределов ([`ThreadLimits`]) вытесняются самые старые.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ThreadFacts {
    /// Типы вложений беседы (`media/subtype`, например `application/pdf`).
    pub attachments: Vec<String>,
    /// Домены ссылок беседы (канонические имена — нижний регистр, A-label).
    pub link_domains: Vec<String>,
    /// Значения `Reply-To` беседы (адреса в канонической форме — домен в нижнем регистре, A-label).
    pub reply_to: Vec<String>,
}

impl ThreadFacts {
    /// Пустая память.
    pub fn new() -> Self {
        Self::default()
    }

    /// Добавляет значения `other` без повторов и обрезает списки по пределам (самые старые — в начале —
    /// вытесняются). Чистая функция, используется реализациями [`ThreadStore::remember_facts`].
    pub fn merge(mut self, other: &ThreadFacts, limits: &ThreadLimits) -> Self {
        let push = |list: &mut Vec<String>, items: &[String], max: usize| {
            for v in items {
                if !list.iter().any(|x| x == v) {
                    list.push(v.clone());
                }
            }
            let extra = list.len().saturating_sub(max);
            list.drain(..extra);
        };
        push(
            &mut self.attachments,
            &other.attachments,
            limits.max_attachments,
        );
        push(
            &mut self.link_domains,
            &other.link_domains,
            limits.max_link_domains,
        );
        push(&mut self.reply_to, &other.reply_to, limits.max_reply_to);
        self
    }
}

/// Удержание беседы (решение 125 е, как Google Vault): действует на все письма беседы, включая будущие —
/// привязанное после установки письмо удержано так же. Окончательное удаление письма удержанной беседы —
/// [`Decision::Deny`] в базовой поставке ([`ThreadHoldHook`]); модуль «Соответствие требованиям» видит
/// беседу в [`FinalDelete::thread`] для своих правил.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThreadHold {
    /// Кто удержал (вход администратора или имя модуля).
    pub by: String,
    /// Когда установлен.
    pub at: OffsetDateTime,
    /// Основание (дело, требование, регламент).
    pub reason: String,
}

impl ThreadHold {
    /// Проверяет: `by` — 1–255 байт без управляющих, `reason` — 1–1000 байт без управляющих. Иначе — `Invalid`.
    pub fn validate(&self) -> Result<()> {
        let ok = |s: &str, max: usize| {
            !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
        };
        if !ok(&self.by, 255) {
            return Err(Error::invalid("ThreadHold.by: 1–255 байт без управляющих"));
        }
        if !ok(&self.reason, 1000) {
            return Err(Error::invalid(
                "ThreadHold.reason: 1–1000 байт без управляющих",
            ));
        }
        Ok(())
    }
}

/// Действие по беседе (решение 125 е; EWS `ApplyConversationAction`): применяется ко всем письмам беседы,
/// включая будущие (MS-21 — при приёме вместо выбора правил Sieve).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadRule {
    /// Все письма беседы — в заданную папку (EWS `AlwaysMove`).
    AlwaysMove(MailboxId),
    /// Все письма беседы — в корзину («игнорировать», Outlook Ignore; EWS `AlwaysDelete`).
    Ignore,
    /// Ключевое слово (JMAP keyword, IMAP флаг) на все письма беседы (EWS `AlwaysCategorize`).
    AlwaysKeyword(String),
}

impl ThreadRule {
    /// Проверяет: ключевое слово — 1–255 байт без пробелов и управляющих (как JMAP keyword). Иначе — `Invalid`.
    pub fn validate(&self) -> Result<()> {
        match self {
            ThreadRule::AlwaysMove(_) => Ok(()),
            ThreadRule::Ignore => Ok(()),
            ThreadRule::AlwaysKeyword(kw) => {
                let ok = !kw.is_empty()
                    && kw.len() <= 255
                    && !kw.bytes().any(|b| b.is_ascii_whitespace())
                    && !kw.chars().any(char::is_control);
                if ok {
                    Ok(())
                } else {
                    Err(Error::invalid(
                        "ThreadRule::AlwaysKeyword: 1–255 байт без пробелов и управляющих",
                    ))
                }
            }
        }
    }
}

impl fmt::Display for ThreadRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreadRule::AlwaysMove(m) => write!(f, "always_move {m}"),
            ThreadRule::Ignore => f.write_str("ignore"),
            ThreadRule::AlwaysKeyword(kw) => write!(f, "always_keyword {kw}"),
        }
    }
}

/// Беседы учётной записи: привязка писем, память для аномалий, удержание и действия (решение 125 е–ж).
/// Реализация — `tp-meta` (META-86), in-memory — `tp-testkit::MemThreads`; вызывают `MailStore::ingest`
/// (MS-21) и Admin API (ADM-50). Методы выполняются в транзакции приёма — см. модульную документацию.
///
/// Беседы не пересекаются между учётными записями и организациями: одинаковые ключи в разных учётных
/// записях дают разные беседы (ключ виден всем участникам и пересылкам — доверять ему между учётными
/// записями нельзя).
#[async_trait]
pub trait ThreadStore: Send + Sync + 'static {
    /// Пределы памяти беседы (секция конфигурации реализации; [`ThreadLimits::default`] по умолчанию).
    fn limits(&self) -> ThreadLimits {
        ThreadLimits::default()
    }

    /// Привязывает письмо к беседе учётной записи (привязка письма неизменяема — [`ThreadId`] не меняется,
    /// RFC 8621 §3). `keys` — значения Message-ID/`In-Reply-To`/`References` письма ([`join_key`] канонизирует
    /// каждый элемент, пустые пропускаются): среди писем учётной записи ищется беседа по ключам присоединения —
    /// письмо попадает в самую раннюю из найденных (беседы не сливаются), иначе создаётся новая беседа.
    /// Все ключи, включая собственный Message-ID, регистрируются за беседой — будущие ответы находят её.
    /// Повторная привязка письма возвращает прежнюю беседу и ничего не меняет.
    async fn bind(
        &self,
        scope: AccountScope,
        message: MessageId,
        keys: &[&str],
    ) -> Result<ThreadId>;

    /// Беседа письма; письма нет в привязках (чужая учётная запись, письмо до привязки) — `None`.
    async fn thread_of(&self, scope: AccountScope, message: MessageId) -> Result<Option<ThreadId>>;

    /// Письма беседы в порядке привязки, не больше `limit` (`limit` = 0 — `Invalid`). Чужая учётная запись
    /// и нет беседы — пусто.
    async fn messages(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        limit: usize,
    ) -> Result<Vec<MessageId>>;

    /// Дополняет память беседы для аномалий (решение 125 д); списки без повторов, сверх пределов
    /// ([`ThreadLimits`]) вытесняются самые старые. Беседы нет — `NotFound`. Выполняется в транзакции приёма.
    async fn remember_facts(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        facts: &ThreadFacts,
    ) -> Result<()>;

    /// Память беседы (пустая — [`ThreadFacts::new`]). Чужая учётная запись — пустая.
    async fn facts(&self, scope: AccountScope, thread: ThreadId) -> Result<ThreadFacts>;

    /// Удержание беседы (решение 125 е); не установлено — `None`.
    async fn hold(&self, scope: AccountScope, thread: ThreadId) -> Result<Option<ThreadHold>>;

    /// Устанавливает (`Some`) или снимает (`None`) удержание беседы; некорректное удержание — `Invalid`,
    /// беседы нет — `NotFound`. Повторная установка заменяет (`by`, `at`, `reason` — последней установки).
    async fn set_hold(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        hold: Option<ThreadHold>,
    ) -> Result<()>;

    /// Действие по беседе ([`ThreadRule`], EWS `ApplyConversationAction`); не задано — `None`.
    async fn rule(&self, scope: AccountScope, thread: ThreadId) -> Result<Option<ThreadRule>>;

    /// Задаёт (`Some`) или удаляет (`None`) действие по беседе; некорректное — `Invalid`, беседы нет —
    /// `NotFound`. Замена целиком.
    async fn set_rule(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        rule: Option<ThreadRule>,
    ) -> Result<()>;
}

/// Хук базовой поставки (решение 125 е): окончательное удаление письма удержанной беседы — [`Decision::Deny`].
/// Регистрирует приложение (`Registry::add_decision_hook`), беседу берёт из [`FinalDelete::thread`], а если
/// вызывающий её не знает — разрешает по письму ([`ThreadStore::thread_of`]). Модуль «Соответствие требованиям»
/// ставит свой хук после этого и видит беседу для своих правил.
pub struct ThreadHoldHook {
    threads: Arc<dyn ThreadStore>,
}

impl ThreadHoldHook {
    /// Хук над хранилищем бесед.
    pub fn new(threads: Arc<dyn ThreadStore>) -> Self {
        ThreadHoldHook { threads }
    }
}

impl fmt::Debug for ThreadHoldHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ThreadHoldHook").finish_non_exhaustive()
    }
}

#[async_trait]
impl DecisionHook for ThreadHoldHook {
    fn name(&self) -> &str {
        "thread_hold"
    }

    async fn before_final_delete(&self, op: &FinalDelete) -> Result<Decision> {
        let thread = match op.thread {
            Some(t) => t,
            None => match self.threads.thread_of(op.scope, op.message).await? {
                Some(t) => t,
                // Письмо без беседы — удержания нет.
                None => return Ok(Decision::Allow),
            },
        };
        match self.threads.hold(op.scope, thread).await? {
            Some(hold) => Ok(Decision::Deny(format!("thread hold: {}", hold.reason))),
            None => Ok(Decision::Allow),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::AccountId;
    use crate::ids::TenantId;
    use futures::executor::block_on;

    #[test]
    fn object_safe() {
        fn _store(_: Arc<dyn ThreadStore>) {}
        fn _hook(_: Arc<dyn DecisionHook>) {}
    }

    fn scope() -> AccountScope {
        AccountScope {
            tenant: TenantId::DEFAULT,
            account: AccountId::new(),
        }
    }

    #[test]
    fn join_key_canonical() {
        assert_eq!(join_key("<A1b@Example.ORG>"), "a1b@example.org");
        assert_eq!(join_key("  Mid@X  "), "mid@x");
        assert_eq!(join_key(""), "", "пустой ключ вызывающий пропускает");
    }

    #[test]
    fn facts_merge_and_limits() {
        let limits = ThreadLimits {
            max_attachments: 3,
            max_link_domains: 3,
            max_reply_to: 1,
        };
        let a = ThreadFacts {
            attachments: vec!["application/pdf".into()],
            link_domains: vec!["a.example".into()],
            reply_to: vec!["old@example.net".into()],
        };
        let b = ThreadFacts {
            attachments: vec![
                "application/pdf".into(),
                "application/zip".into(),
                "image/png".into(),
            ],
            link_domains: vec!["b.example".into(), "a.example".into()],
            reply_to: vec!["new@example.net".into(), "newer@example.net".into()],
        };
        let merged = a.merge(&b, &limits);
        // Без повторов; сверх предела вытесняются самые старые (в начале).
        assert_eq!(
            merged.attachments,
            vec!["application/pdf", "application/zip", "image/png"]
        );
        assert_eq!(merged.link_domains, vec!["a.example", "b.example"]);
        assert_eq!(merged.reply_to, vec!["newer@example.net"]);
        assert_eq!(ThreadFacts::new(), ThreadFacts::default());
    }

    #[test]
    fn facts_serde() {
        let f = ThreadFacts {
            attachments: vec!["application/zip".into()],
            ..ThreadFacts::default()
        };
        let s = serde_json::to_string(&f).expect("json");
        assert_eq!(serde_json::from_str::<ThreadFacts>(&s).expect("parse"), f);
    }

    #[test]
    fn hold_validate() {
        let h = |by: &str, reason: &str| ThreadHold {
            by: by.into(),
            at: OffsetDateTime::UNIX_EPOCH,
            reason: reason.into(),
        };
        assert_eq!(h("admin", "дело №1").validate(), Ok(()));
        assert!(h("", "дело").validate().is_err());
        assert!(h("admin", "").validate().is_err());
        assert!(h("a".repeat(256).as_str(), "дело").validate().is_err());
        assert!(h("admin", "r".repeat(1001).as_str()).validate().is_err());
        let long_by = "a".repeat(255);
        assert_eq!(h(long_by.as_str(), "дело").validate(), Ok(()));
        let json = serde_json::to_string(&h("admin", "дело")).expect("json");
        assert!(
            json.contains("\"by\"") && json.contains("\"reason\""),
            "{json}"
        );
    }

    #[test]
    fn rule_validate_and_display() {
        let r = |kw: &str| ThreadRule::AlwaysKeyword(kw.into());
        assert_eq!(r("$label1").validate(), Ok(()));
        assert_eq!(ThreadRule::Ignore.validate(), Ok(()));
        assert_eq!(ThreadRule::AlwaysMove(MailboxId::new()).validate(), Ok(()));
        assert!(r("").validate().is_err());
        assert!(r("два слова").validate().is_err());
        assert!(r("k".repeat(256).as_str()).validate().is_err());
        assert_eq!(ThreadRule::Ignore.to_string(), "ignore");
        assert_eq!(r("$label1").to_string(), "always_keyword $label1");
        let json = serde_json::to_string(&ThreadRule::Ignore).expect("json");
        assert_eq!(json, "\"ignore\"");
        let json = serde_json::to_string(&ThreadRule::AlwaysMove(MailboxId::new())).expect("json");
        assert!(json.starts_with("{\"always_move\":"), "{json}");
    }

    /// Хук запрещает удаление письма удержанной беседы, беседу разрешает по письму (`thread: None`).
    struct MemThreadsStub {
        held: std::sync::Mutex<std::collections::HashSet<ThreadId>>,
    }

    impl MemThreadsStub {
        fn with_held(thread: ThreadId) -> Arc<Self> {
            let mut held = std::collections::HashSet::new();
            held.insert(thread);
            Arc::new(MemThreadsStub {
                held: std::sync::Mutex::new(held),
            })
        }
    }

    #[async_trait]
    impl ThreadStore for MemThreadsStub {
        async fn bind(&self, _: AccountScope, _: MessageId, _: &[&str]) -> Result<ThreadId> {
            Err(Error::Internal("stub".into()))
        }

        async fn thread_of(&self, _: AccountScope, _: MessageId) -> Result<Option<ThreadId>> {
            Ok(Some(ThreadId::new()))
        }

        async fn messages(&self, _: AccountScope, _: ThreadId, _: usize) -> Result<Vec<MessageId>> {
            Ok(Vec::new())
        }

        async fn remember_facts(
            &self,
            _: AccountScope,
            _: ThreadId,
            _: &ThreadFacts,
        ) -> Result<()> {
            Ok(())
        }

        async fn facts(&self, _: AccountScope, _: ThreadId) -> Result<ThreadFacts> {
            Ok(ThreadFacts::new())
        }

        async fn hold(&self, _: AccountScope, thread: ThreadId) -> Result<Option<ThreadHold>> {
            Ok(self
                .held
                .lock()
                .map(|h| h.contains(&thread))
                .unwrap_or(false)
                .then(|| ThreadHold {
                    by: "compliance".into(),
                    at: OffsetDateTime::UNIX_EPOCH,
                    reason: "case-42".into(),
                }))
        }

        async fn set_hold(
            &self,
            _: AccountScope,
            _: ThreadId,
            _: Option<ThreadHold>,
        ) -> Result<()> {
            Err(Error::Internal("stub".into()))
        }

        async fn rule(&self, _: AccountScope, _: ThreadId) -> Result<Option<ThreadRule>> {
            Ok(None)
        }

        async fn set_rule(
            &self,
            _: AccountScope,
            _: ThreadId,
            _: Option<ThreadRule>,
        ) -> Result<()> {
            Err(Error::Internal("stub".into()))
        }
    }

    #[test]
    fn hold_hook_denies_held_thread() {
        let held = ThreadId::new();
        let hook = ThreadHoldHook::new(MemThreadsStub::with_held(held));
        let op = |thread: Option<ThreadId>| FinalDelete {
            scope: scope(),
            mailbox: MailboxId::new(),
            message: MessageId::new(),
            received_at: OffsetDateTime::UNIX_EPOCH,
            thread,
        };
        // Беседа из записи — удержана.
        assert_eq!(
            block_on(hook.before_final_delete(&op(Some(held)))),
            Ok(Decision::Deny("thread hold: case-42".into()))
        );
        // Беседы нет в записи — разрешает по письму (тоже удержана — заглушка отвечает одной беседой).
        assert_eq!(
            block_on(hook.before_final_delete(&op(None))),
            Ok(Decision::Deny("thread hold: case-42".into()))
        );
        // Другая беседа не удержана.
        assert_eq!(
            block_on(hook.before_final_delete(&op(Some(ThreadId::new())))),
            Ok(Decision::Allow)
        );
        assert_eq!(hook.name(), "thread_hold");
    }
}
