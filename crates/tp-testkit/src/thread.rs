//! In-memory беседы ([`ThreadStore`], CTR-94; CONTRACTS.md#Thread): [`MemThreads`] — привязка писем,
//! память для аномалий, удержание и действия по беседе. Каждая операция — один захват состояния
//! («письмо + беседа + политики» — атомарно по построению).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tp_contracts::meta::AccountScope;
use tp_contracts::thread::{
    ThreadFacts, ThreadHold, ThreadLimits, ThreadRule, ThreadStore, join_key,
};
use tp_contracts::{Error, MessageId, Result, ThreadId};

use crate::infra::lock;

#[derive(Debug, Default)]
struct ThreadEntry {
    /// Порядок создания (более ранняя беседа — по нему).
    seq: u64,
    /// Письма в порядке привязки.
    messages: Vec<MessageId>,
    /// Ключи присоединения в порядке регистрации.
    keys: Vec<String>,
    facts: ThreadFacts,
}

#[derive(Debug, Default)]
struct Account {
    next_seq: u64,
    threads: HashMap<ThreadId, ThreadEntry>,
    /// Привязка письма (неизменяема).
    message_of: HashMap<MessageId, ThreadId>,
    /// Ключ присоединения → беседа; повтор ключа первую привязку не меняет.
    key_of: HashMap<String, ThreadId>,
    holds: HashMap<ThreadId, ThreadHold>,
    rules: HashMap<ThreadId, ThreadRule>,
}

#[derive(Debug, Default)]
struct State {
    accounts: HashMap<AccountScope, Account>,
    limits: Option<ThreadLimits>,
}

/// Беседы в памяти; клоны разделяют данные. Беседы не пересекаются между учётными записями: одинаковые
/// ключи в разных учётных записях дают разные беседы.
#[derive(Clone)]
pub struct MemThreads {
    state: Arc<Mutex<State>>,
}

impl Default for MemThreads {
    fn default() -> Self {
        Self::new()
    }
}

impl MemThreads {
    /// Пустое хранилище с пределами по умолчанию.
    pub fn new() -> Self {
        MemThreads {
            state: Arc::default(),
        }
    }

    /// Пределы памяти бесед ([`ThreadLimits`]); умолчание — [`ThreadLimits::default`].
    pub fn with_limits(self, limits: ThreadLimits) -> Self {
        lock(&self.state).limits = Some(limits);
        self
    }
}

impl fmt::Debug for MemThreads {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemThreads").finish_non_exhaustive()
    }
}

fn account<'a>(st: &'a mut State, scope: &AccountScope) -> &'a mut Account {
    st.accounts.entry(*scope).or_default()
}

impl Account {
    /// Новая беседа: идентификатор и порядок создания.
    fn new_thread(&mut self) -> ThreadId {
        let seq = self.next_seq;
        self.next_seq += 1;
        let thread = ThreadId::new();
        self.threads.insert(
            thread,
            ThreadEntry {
                seq,
                messages: Vec::new(),
                keys: Vec::new(),
                facts: ThreadFacts::default(),
            },
        );
        thread
    }
}

#[async_trait]
impl ThreadStore for MemThreads {
    fn limits(&self) -> ThreadLimits {
        lock(&self.state)
            .limits
            .unwrap_or_else(ThreadLimits::default)
    }

    async fn bind(
        &self,
        scope: AccountScope,
        message: MessageId,
        keys: &[&str],
    ) -> Result<ThreadId> {
        // Канонические ключи без пустых и повторов.
        let mut keys: Vec<String> = keys.iter().map(|k| join_key(k)).collect();
        keys.retain(|k| !k.is_empty());
        keys.sort_unstable();
        keys.dedup();
        let mut st = lock(&self.state);
        let acc = account(&mut st, &scope);
        // Привязка письма неизменяема: повторная привязка — прежняя беседа.
        if let Some(thread) = acc.message_of.get(&message) {
            return Ok(*thread);
        }
        // Самая ранняя из бесед, найденных по ключам (беседы не сливаются); нет — новая беседа.
        let found = keys
            .iter()
            .filter_map(|k| acc.key_of.get(k))
            .copied()
            .min_by_key(|t| (acc.threads.get(t).map(|e| e.seq), *t));
        let thread = match found {
            Some(thread) => thread,
            None => acc.new_thread(),
        };
        // Регистрируем письмо и его ключи за беседой (первая привязка ключа не меняется).
        if let Some(entry) = acc.threads.get_mut(&thread) {
            entry.messages.push(message);
            for k in &keys {
                if !entry.keys.iter().any(|x| x == k) {
                    entry.keys.push(k.clone());
                }
                acc.key_of.entry(k.clone()).or_insert(thread);
            }
        }
        acc.message_of.insert(message, thread);
        Ok(thread)
    }

    async fn thread_of(&self, scope: AccountScope, message: MessageId) -> Result<Option<ThreadId>> {
        let st = lock(&self.state);
        Ok(st
            .accounts
            .get(&scope)
            .and_then(|a| a.message_of.get(&message))
            .copied())
    }

    async fn messages(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        limit: usize,
    ) -> Result<Vec<MessageId>> {
        if limit == 0 {
            return Err(Error::invalid("limit беседы: не меньше 1"));
        }
        let st = lock(&self.state);
        Ok(st
            .accounts
            .get(&scope)
            .and_then(|a| a.threads.get(&thread))
            .map(|e| e.messages.iter().take(limit).copied().collect())
            .unwrap_or_default())
    }

    async fn remember_facts(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        facts: &ThreadFacts,
    ) -> Result<()> {
        let limits = self.limits();
        let mut st = lock(&self.state);
        let acc = account(&mut st, &scope);
        let entry = acc.threads.get_mut(&thread).ok_or(Error::NotFound)?;
        entry.facts = std::mem::take(&mut entry.facts).merge(facts, &limits);
        Ok(())
    }

    async fn facts(&self, scope: AccountScope, thread: ThreadId) -> Result<ThreadFacts> {
        let st = lock(&self.state);
        Ok(st
            .accounts
            .get(&scope)
            .and_then(|a| a.threads.get(&thread))
            .map(|e| e.facts.clone())
            .unwrap_or_default())
    }

    async fn hold(&self, scope: AccountScope, thread: ThreadId) -> Result<Option<ThreadHold>> {
        let st = lock(&self.state);
        Ok(st
            .accounts
            .get(&scope)
            .and_then(|a| a.holds.get(&thread))
            .cloned())
    }

    async fn set_hold(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        hold: Option<ThreadHold>,
    ) -> Result<()> {
        if let Some(hold) = &hold {
            hold.validate()?;
        }
        let mut st = lock(&self.state);
        let acc = account(&mut st, &scope);
        if !acc.threads.contains_key(&thread) {
            return Err(Error::NotFound);
        }
        if let Some(hold) = hold {
            acc.holds.insert(thread, hold);
        } else {
            acc.holds.remove(&thread);
        }
        Ok(())
    }

    async fn rule(&self, scope: AccountScope, thread: ThreadId) -> Result<Option<ThreadRule>> {
        let st = lock(&self.state);
        Ok(st
            .accounts
            .get(&scope)
            .and_then(|a| a.rules.get(&thread))
            .cloned())
    }

    async fn set_rule(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        rule: Option<ThreadRule>,
    ) -> Result<()> {
        if let Some(rule) = &rule {
            rule.validate()?;
        }
        let mut st = lock(&self.state);
        let acc = account(&mut st, &scope);
        if !acc.threads.contains_key(&thread) {
            return Err(Error::NotFound);
        }
        if let Some(rule) = rule {
            acc.rules.insert(thread, rule);
        } else {
            acc.rules.remove(&thread);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite;

    #[tokio::test]
    async fn suite_mem_threads() {
        let store = MemThreads::new();
        let scope = AccountScope {
            tenant: TenantId::new(),
            account: AccountId::new(),
        };
        let other = AccountScope {
            tenant: scope.tenant,
            account: AccountId::new(),
        };
        suite::thread(Arc::new(store.clone()), scope, other).await;
        suite::hold_rules(Arc::new(store), scope).await;
    }

    #[tokio::test]
    async fn limits_follow_config() {
        let limits = ThreadLimits {
            max_attachments: 3,
            ..ThreadLimits::default()
        };
        let store = MemThreads::new().with_limits(limits);
        assert_eq!(store.limits(), limits);
        assert_eq!(MemThreads::new().limits(), ThreadLimits::default());
    }
}
