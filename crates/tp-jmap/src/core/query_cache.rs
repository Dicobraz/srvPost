//! Кэш результатов `Email/query` и `Email/get` (PERF-02: p95 311 мс при пороге 200 мс — на каждый запрос
//! загружались все письма аккаунта с метаданными).
//!
//! Ключ записи — разобранные аргументы запроса (фильтр, сортировка; окно не входит: страница берётся
//! из полного списка). Инвалидация — токен версий папок: изменение письма (приём, флаги, перенос,
//! удаление) меняет версию его папки ([`Token`]), поэтому совпадение токена гарантирует тот же набор
//! писем и те же метаданные (конверт и ключ цепочки неизменяемы после приёма). Записи `Email/query`
//! при изменениях обновляются инкрементально по журналу (см. `email_query::try_patch`), записи
//! `Email/get` пересобираются. `ttl` — страховка от изменений вне журнала.
//!
//! Бюджеты ([`QueryCacheConfig`]) ограничивают память: вытесняется запись с самым давним обращением.
//! Кэш прозрачен для клиента: ответ совпадает с пересборкой (покрыто тестами крейта).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};
use tp_contracts::{AccountId, MailboxId, MessageId, ModSeq, TenantId};

use crate::core::config::QueryCacheConfig;

/// Версия каждой папки учётной записи (`highest_modseq`, по возрастанию id папки). Изменение любого
/// письма меняет версию его папки; создание и удаление папки меняет состав токена.
pub(crate) type Token = Vec<(MailboxId, ModSeq)>;

/// Список записи `Email/query`: идентификаторы в порядке сортировки, ключи сортировки (параллельно)
/// и папка письма (параллельно).
pub(crate) type QueryList = (Vec<MessageId>, Vec<Box<[i128]>>, Vec<MailboxId>);

/// Запись `Email/query`: идентификаторы в порядке сортировки, ключи сортировки и папки — параллельно.
pub(crate) struct QueryEntry {
    /// Версии папок на момент построения записи.
    pub(crate) token: Token,
    /// Состояние аккаунта на момент построения: точка отсчёта журнала для инкрементального обновления.
    pub(crate) state: ModSeq,
    /// Идентификаторы в порядке сортировки записи.
    pub(crate) ids: Vec<MessageId>,
    /// Ключи сортировки, параллельно `ids`: части уже ориентированы (меньше — раньше в списке),
    /// при равенстве всех частей раньше письмо с меньшим id.
    pub(crate) keys: Vec<Box<[i128]>>,
    /// Папка письма, параллельно `ids` (для пакетной выборки `Email/get`).
    pub(crate) boxes: Vec<MailboxId>,
    at: Instant,
}

/// Запись `Email/get`: ответ без поля `state` (оно вставляется свежим — текущее состояние аккаунта).
struct GetEntry {
    token: Token,
    value: Arc<Map<String, Value>>,
    at: Instant,
}

/// Оценка размера записи `Email/query`, байт на письмо: id, ключ сортировки (числа), папка, накладные.
const QUERY_BYTES_PER_ID: usize = 96;
/// Накладные расходы одной записи, байт.
const ENTRY_OVERHEAD: usize = 512;

fn json_bytes(v: &Value) -> usize {
    match v {
        Value::Null | Value::Bool(_) | Value::Number(_) => 16,
        Value::String(s) => s.len() + 24,
        Value::Array(a) => 24 + a.iter().map(json_bytes).sum::<usize>(),
        Value::Object(o) => {
            40 + o
                .iter()
                .map(|(k, v)| k.len() + 24 + json_bytes(v))
                .sum::<usize>()
        }
    }
}

/// Кэши `Email/query` и `Email/get` сервера. Методы без `await`: блокировка не удерживается
/// через точки ожидания, конкурентные обновления одной записи — «последний записавший» (см.
/// `email_query::try_patch` — каждый патч сворачивает журнал от своей базы, гонки безопасны).
pub(crate) struct Caches {
    cfg: QueryCacheConfig,
    queries: HashMap<(TenantId, AccountId), HashMap<String, QueryEntry>>,
    gets: HashMap<(TenantId, AccountId), HashMap<String, GetEntry>>,
    query_bytes: usize,
    get_bytes: usize,
}

impl Caches {
    pub(crate) fn new(cfg: QueryCacheConfig) -> Self {
        Self {
            queries: HashMap::new(),
            gets: HashMap::new(),
            query_bytes: 0,
            get_bytes: 0,
            cfg,
        }
    }

    fn expired(ttl: Duration, at: Instant) -> bool {
        at.elapsed() > ttl
    }

    /// Запись `Email/query` с совпавшим токеном версий папок: список идентификаторов в порядке записи.
    pub(crate) fn lookup_query(
        &mut self,
        scope: (TenantId, AccountId),
        key: &str,
        token: &Token,
    ) -> Option<Vec<MessageId>> {
        let entries = self.queries.get_mut(&scope)?;
        let e = entries.get_mut(key)?;
        if Self::expired(self.cfg.ttl, e.at) || e.token != *token {
            return None;
        }
        e.at = Instant::now();
        Some(e.ids.clone())
    }

    /// Запись `Email/query` независимо от токена — база для инкрементального обновления по журналу.
    pub(crate) fn stale_query(
        &mut self,
        scope: (TenantId, AccountId),
        key: &str,
    ) -> Option<(ModSeq, QueryList)> {
        let entries = self.queries.get_mut(&scope)?;
        let e = entries.get_mut(key)?;
        if Self::expired(self.cfg.ttl, e.at) {
            return None;
        }
        e.at = Instant::now();
        Some((e.state, (e.ids.clone(), e.keys.clone(), e.boxes.clone())))
    }

    /// Сохраняет запись `Email/query` (полная пересборка или результат инкрементального обновления).
    pub(crate) fn store_query(
        &mut self,
        scope: (TenantId, AccountId),
        key: &str,
        token: Token,
        state: ModSeq,
        list: QueryList,
    ) {
        if !self.enabled() {
            return;
        }
        let (ids, keys, boxes) = list;
        let entries = self.queries.entry(scope).or_default();
        if let Some(old) = entries.remove(key) {
            self.query_bytes = self
                .query_bytes
                .saturating_sub(ENTRY_OVERHEAD + old.ids.len() * QUERY_BYTES_PER_ID);
        }
        self.query_bytes += ENTRY_OVERHEAD + ids.len() * QUERY_BYTES_PER_ID;
        entries.insert(
            key.to_owned(),
            QueryEntry {
                token,
                state,
                ids,
                keys,
                boxes,
                at: Instant::now(),
            },
        );
        evict(
            entries,
            &mut self.query_bytes,
            self.cfg.max_bytes,
            self.cfg.max_entries,
            |e| ENTRY_OVERHEAD + e.ids.len() * QUERY_BYTES_PER_ID,
            |e| e.at,
        );
    }

    /// Ответ `Email/get` с совпавшим токеном версий папок.
    pub(crate) fn lookup_get(
        &mut self,
        scope: (TenantId, AccountId),
        key: &str,
        token: &Token,
    ) -> Option<Arc<Map<String, Value>>> {
        let entries = self.gets.get_mut(&scope)?;
        let e = entries.get_mut(key)?;
        if Self::expired(self.cfg.ttl, e.at) || e.token != *token {
            return None;
        }
        e.at = Instant::now();
        Some(e.value.clone())
    }

    /// Сохраняет ответ `Email/get` (без поля `state`).
    pub(crate) fn store_get(
        &mut self,
        scope: (TenantId, AccountId),
        key: &str,
        token: Token,
        value: Arc<Map<String, Value>>,
    ) {
        if !self.enabled_get() {
            return;
        }
        let bytes = |v: &GetEntry| ENTRY_OVERHEAD + json_bytes(&Value::Object((*v.value).clone()));
        let entry = GetEntry {
            token,
            value,
            at: Instant::now(),
        };
        let add = bytes(&entry);
        let entries = self.gets.entry(scope).or_default();
        if let Some(old) = entries.remove(key) {
            self.get_bytes = self.get_bytes.saturating_sub(bytes(&old));
        }
        self.get_bytes += add;
        entries.insert(key.to_owned(), entry);
        evict(
            entries,
            &mut self.get_bytes,
            self.cfg.get_max_bytes,
            self.cfg.max_entries,
            bytes,
            |e| e.at,
        );
    }

    /// Папки для `ids` из записи `Email/query` с текущим токеном: запись должна покрывать все
    /// идентификаторы (например, список пришёл из парного `Email/query` этого же кэша).
    /// Иначе — `None` (точные чтения по одному).
    pub(crate) fn covering(
        &mut self,
        scope: (TenantId, AccountId),
        ids: &[MessageId],
        token: &Token,
    ) -> Option<Vec<MailboxId>> {
        let entries = self.queries.get_mut(&scope)?;
        for e in entries.values_mut() {
            if Self::expired(self.cfg.ttl, e.at) || e.token != *token {
                continue;
            }
            let found: Vec<Option<MailboxId>> = ids
                .iter()
                .map(|id| e.ids.iter().position(|x| x == id).map(|p| e.boxes[p]))
                .collect();
            if found.iter().all(Option::is_some) {
                e.at = Instant::now();
                return Some(found.into_iter().map(Option::unwrap).collect());
            }
        }
        None
    }

    fn enabled(&self) -> bool {
        self.cfg.max_bytes > 0 && self.cfg.max_entries > 0
    }

    fn enabled_get(&self) -> bool {
        self.cfg.get_max_bytes > 0 && self.cfg.max_entries > 0
    }
}

/// Вытесняет записи с самым давним обращением, пока бюджет (байт и записей) не соблюдён.
fn evict<E, S, T>(
    entries: &mut HashMap<String, E>,
    bytes: &mut usize,
    cap: usize,
    max_entries: usize,
    size: S,
    stamp: T,
) where
    S: Fn(&E) -> usize,
    T: Fn(&E) -> Instant,
{
    while *bytes > cap || entries.len() > max_entries {
        let Some(oldest) = entries
            .iter()
            .min_by_key(|(_, e)| stamp(e))
            .map(|(k, _)| k.clone())
        else {
            return;
        };
        let Some(e) = entries.remove(&oldest) else {
            return;
        };
        *bytes = bytes.saturating_sub(size(&e));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scope() -> (TenantId, AccountId) {
        (TenantId::default(), AccountId::default())
    }

    fn token(v: u64) -> Token {
        vec![(MailboxId::default(), ModSeq(v))]
    }

    fn cfg(max_bytes: usize, get_max_bytes: usize, max_entries: usize) -> QueryCacheConfig {
        QueryCacheConfig {
            max_bytes,
            get_max_bytes,
            max_entries,
            ttl: Duration::from_secs(600),
            patch_max: 200,
            max_parallel_get: 8,
        }
    }

    fn entry(ids: usize) -> (Vec<MessageId>, Vec<Box<[i128]>>, Vec<MailboxId>) {
        (
            (0..ids).map(|_| MessageId::new()).collect(),
            (0..ids).map(|i| Box::from([i as i128])).collect(),
            (0..ids).map(|_| MailboxId::default()).collect(),
        )
    }

    #[test]
    fn query_lookup_needs_token() {
        let mut c = Caches::new(cfg(1 << 20, 0, 10));
        let s = scope();
        let (ids, keys, boxes) = entry(3);
        let t1 = token(1);
        c.store_query(
            s,
            "k",
            t1.clone(),
            ModSeq(1),
            (ids.clone(), keys.clone(), boxes.clone()),
        );
        assert!(c.lookup_query(s, "k", &t1).is_some());
        assert!(c.lookup_query(s, "k", &token(2)).is_none());
        assert!(c.stale_query(s, "k").is_some());
    }

    #[test]
    fn eviction_keeps_budget() {
        let cap = 2 * QUERY_BYTES_PER_ID + 2 * ENTRY_OVERHEAD;
        let mut c = Caches::new(cfg(cap, 0, 10));
        let s = scope();
        for i in 0..3 {
            let (ids, keys, boxes) = entry(2);
            c.store_query(s, &format!("k{i}"), token(1), ModSeq(1), (ids, keys, boxes));
        }
        let total: usize = c
            .queries
            .get(&s)
            .map(|m| m.values().map(|e| e.ids.len()).sum())
            .unwrap_or(0);
        assert!(total <= 4, "бюджет соблюдён: {total}");
    }

    #[test]
    fn get_store_lookup() {
        let mut c = Caches::new(cfg(0, 1 << 20, 10));
        let s = scope();
        let mut v = Map::new();
        v.insert("list".into(), json!([1, 2, 3]));
        let t1 = token(1);
        c.store_get(s, "k", t1.clone(), Arc::new(v.clone()));
        assert_eq!(c.lookup_get(s, "k", &t1), Some(Arc::new(v)));
        assert!(c.lookup_get(s, "k", &token(2)).is_none());
    }

    #[test]
    fn covering_requires_all_ids() {
        let mut c = Caches::new(cfg(1 << 20, 0, 10));
        let s = scope();
        let (ids, keys, boxes) = entry(2);
        let t1 = token(1);
        c.store_query(
            s,
            "k",
            t1.clone(),
            ModSeq(1),
            (ids.clone(), keys, boxes.clone()),
        );
        assert_eq!(c.covering(s, &ids, &t1), Some(boxes));
        let mut extra = ids.clone();
        extra.push(MessageId::new());
        assert_eq!(c.covering(s, &extra, &t1), None);
        assert_eq!(c.covering(s, &ids, &token(2)), None);
    }

    #[test]
    fn zero_budget_disables() {
        let mut c = Caches::new(cfg(0, 0, 10));
        let s = scope();
        let (ids, keys, boxes) = entry(2);
        c.store_query(s, "k", token(1), ModSeq(1), (ids, keys, boxes));
        let mut v = Map::new();
        v.insert("list".into(), json!([]));
        c.store_get(s, "g", token(1), Arc::new(v));
        assert!(c.queries.get(&s).map(|m| m.is_empty()).unwrap_or(true));
        assert!(c.gets.get(&s).map(|m| m.is_empty()).unwrap_or(true));
        assert!(c.stale_query(s, "k").is_none());
    }
}
