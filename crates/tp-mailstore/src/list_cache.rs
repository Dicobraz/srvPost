//! Кэш списка писем папки — прозрачный декоратор [`MessageStore`] (PERF-01: IMAP SELECT папки
//! 10 тыс. писем, p95 944 мс при пороге 100 мс).
//!
//! Путь SELECT: `list(All)` читает все строки папки с JSONB-метаданными и частями
//! (`message_parts` по всем письмам разом), счётчики (Exists, первое непрочитанное) протокол
//! считает из этого списка. Кэш хранит построенный список и обслуживает повторные чтения папки
//! без выгрузки: свежесть проверяется по журналу изменений ([`ChangeLog::message_changes`] от
//! базового `ModSeq` записи — записи журнала папки с `ModSeq` больше базового и есть изменения
//! «версии папки»; приём, флаги, перенос, корзина и окончательное удаление пишутся в журнал в
//! транзакции изменения). Без изменений список возвращается из кэша, при изменениях —
//! обновляется инкрементально по журналу (до [`ListCacheConfig::patch_max`]), иначе — полная
//! пересборка; `ttl` — страховка от изменений вне журнала. Образец подхода — кэш `Email/query`
//! tp-jmap (PERF-02): там версия — токен из статусов всех папок учётной записи, здесь база
//! записи проверяется журналом одной папки, поэтому проверка не дороже самой записи (чтение
//! журнала папки с лимитом `patch_max + 1`).
//!
//! База пересборки — `highest_modseq` папки, прочитанный **до** чтения списка: список строится
//! позже и отражает всё, что зафиксировано до базы, а изменения после базы переигрываются
//! журналом; обратный порядок мог бы пропустить изменение между чтением списка и версии.
//!
//! Кэш прозрачен: ответ совпадает с чтением внутреннего хранилища (покрыто тестами крейта).
//! Конкуренция — «последний записавший»: каждая запись согласована со своей базой (список
//! отражает все изменения с `ModSeq` не больше базы), проверка следующего чтения идёт от базы
//! сохранённой записи, поэтому перезапись конкурентной пересборкой лишь откатывает список к
//! согласованному состоянию. Бюджеты ([`ListCacheConfig`]) ограничивают память, вытесняется
//! самая давняя по обращению запись; `max_bytes = 0` выключает кэш.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::Deserialize;
use tp_contracts::config::duration;
use tp_contracts::meta::{
    AccountScope, ChangeLog, Changes, Flag, FlagOp, FlagsUpdate, Inserted, MailboxStore, Message,
    MessageChange, MessageMeta, MessageQuery, MessageStore, NewMessage,
};
use tp_contracts::{AccountId, MailboxId, MessageId, ModSeq, Result, TenantId};

/// Секция `mailstore.list_cache`: кэш списка писем папки (PERF-01).
///
/// ```yaml
/// list_cache:
///   max_bytes: 64MiB
///   patch_max: 200
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ListCacheConfig {
    /// Бюджет кэша, байт по всем записям (оценка содержимого записей); `0` — кэш выключен.
    pub max_bytes: usize,
    /// Записей (папок) не больше; при превышении вытесняется самая давняя по обращению.
    pub max_entries: usize,
    /// Сколько хранится запись; инвалидация по журналу — основная, это страховка.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub ttl: Duration,
    /// Изменений писем папки в журнале для инкрементального обновления; больше — полная пересборка.
    pub patch_max: usize,
}

impl Default for ListCacheConfig {
    fn default() -> Self {
        Self {
            max_bytes: 64 * 1024 * 1024,
            max_entries: 256,
            ttl: Duration::from_secs(600),
            patch_max: 200,
        }
    }
}

/// Показатели кэша (наблюдаемость и тесты): чтения из кэша, пересборки, патчи, вытеснения.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ListCacheStats {
    /// Список возвращён из кэша без изменений.
    pub hits: u64,
    /// Инкрементальных обновлений по журналу (тоже чтения из кэша).
    pub patches: u64,
    /// Полных пересборок из внутреннего хранилища.
    pub rebuilds: u64,
    /// Вытеснений записей (бюджет, срок).
    pub evictions: u64,
    /// Записей в кэше сейчас.
    pub entries: usize,
    /// Оценка занятой памяти, байт.
    pub bytes: usize,
}

/// Запись кэша: список писем одной папки (по возрастанию `Uid`), база журнала, окно построения.
struct Entry {
    /// Список отражает все изменения папки с `ModSeq` не больше базового; база — точка отсчёта
    /// проверки свежести по журналу.
    base: ModSeq,
    /// `limit`, с которым список построен: окно «первый `limit` по `Uid`».
    limit: usize,
    /// Список — вся папка (`len < limit`): годится для любого `limit`, обновляется по журналу.
    complete: bool,
    list: Arc<Vec<Message>>,
    at: Instant,
}

#[derive(Default)]
struct State {
    entries: HashMap<(TenantId, AccountId, MailboxId), Entry>,
    bytes: usize,
}

/// Кэш списков писем папок поверх [`MessageStore`] (сам [`MessageStore`]; остальные операции —
/// напрямую во внутреннее хранилище).
///
/// Хранилище писем, папки и журнал в приложении — одна реализация метаданных (`PgMeta`);
/// параметры раздельно — для тестов на реализациях `tp-testkit`.
pub struct CachedMessages {
    messages: Arc<dyn MessageStore>,
    mailboxes: Arc<dyn MailboxStore>,
    changes: Arc<dyn ChangeLog>,
    cfg: ListCacheConfig,
    state: Mutex<State>,
    stats: Mutex<ListCacheStats>,
}

impl fmt::Debug for CachedMessages {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedMessages")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl CachedMessages {
    /// Кэш поверх внутреннего хранилища писем, источника папок (существование папки, версия для
    /// базы пересборки) и журнала изменений (свежесть и инкрементальное обновление).
    pub fn new(
        messages: Arc<dyn MessageStore>,
        mailboxes: Arc<dyn MailboxStore>,
        changes: Arc<dyn ChangeLog>,
        cfg: ListCacheConfig,
    ) -> Self {
        Self {
            messages,
            mailboxes,
            changes,
            cfg,
            state: Mutex::default(),
            stats: Mutex::default(),
        }
    }

    /// Показатели кэша.
    pub fn stats(&self) -> ListCacheStats {
        *self.stats.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn count(&self, f: impl FnOnce(&mut ListCacheStats)) {
        f(&mut self.stats.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// Запись, пригодная выдать список для запроса с окном `limit`, не просроченная. Блокировка
    /// не удерживается через точки ожидания; обращение обновляет давность.
    fn servable(&self, key: &(TenantId, AccountId, MailboxId), limit: usize) -> Option<Entry> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let expired = st
            .entries
            .get(key)
            .is_some_and(|e| e.at.elapsed() > self.cfg.ttl);
        if expired {
            if let Some(e) = st.entries.remove(key) {
                st.bytes -= list_bytes(&e.list);
            }
            let (n, b) = (st.entries.len(), st.bytes);
            drop(st);
            self.count(|s| {
                s.evictions += 1;
                s.entries = n;
                s.bytes = b;
            });
            return None;
        }
        let e = st.entries.get_mut(key)?;
        if !(e.complete || limit <= e.limit) {
            return None;
        }
        e.at = Instant::now();
        Some(Entry {
            base: e.base,
            limit: e.limit,
            complete: e.complete,
            list: e.list.clone(),
            at: e.at,
        })
    }

    /// Сохраняет запись и вытесняет давние сверх бюджетов. Перезапись конкурентной записи
    /// безопасна: каждая согласована со своей базой (см. модуль).
    fn store(&self, key: (TenantId, AccountId, MailboxId), entry: Entry) {
        let mut evicted = 0;
        let (n, b) = {
            let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            let added = list_bytes(&entry.list);
            if let Some(old) = st.entries.insert(key, entry) {
                st.bytes -= list_bytes(&old.list);
            }
            st.bytes += added;
            while st.bytes > self.cfg.max_bytes
                || (self.cfg.max_entries > 0 && st.entries.len() > self.cfg.max_entries)
            {
                let Some(oldest) = st.entries.iter().min_by_key(|(_, e)| e.at).map(|(k, _)| *k)
                else {
                    break;
                };
                let e = st.entries.remove(&oldest).expect("запись есть");
                st.bytes -= list_bytes(&e.list);
                evicted += 1;
            }
            (st.entries.len(), st.bytes)
        };
        self.count(|s| {
            s.evictions += evicted;
            s.entries = n;
            s.bytes = b;
        });
    }

    /// Отбрасывает запись (папка исчезла).
    fn drop_entry(&self, key: &(TenantId, AccountId, MailboxId)) {
        let (n, b) = {
            let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(e) = st.entries.remove(key) {
                st.bytes -= list_bytes(&e.list);
            }
            (st.entries.len(), st.bytes)
        };
        self.count(|s| {
            s.entries = n;
            s.bytes = b;
        });
    }

    /// Фиксирует базу записи без пересборки: изменений папки в журнале нет. База двигается
    /// вперёд только у записи, от которой шла проверка (не заменённая конкурентной).
    fn advance(&self, key: &(TenantId, AccountId, MailboxId), from: ModSeq, to: ModSeq) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(e) = st.entries.get_mut(key)
            && e.base == from
        {
            e.base = to;
        }
    }

    /// Инкрементальное обновление списка по журналу; `None` — изменений слишком много, пересборка.
    ///
    /// «Удалённые» по журналу проверяются по фактическому существованию: журнал сворачивает
    /// «изменено, скрыто и восстановлено в интервале» в один `destroyed`, хотя письмо есть;
    /// созданные и изменённые перечитываются пачкой одним запросом, не найденные (перенос между
    /// чтением журнала и выборкой) — по одному.
    async fn patch(
        &self,
        scope: AccountScope,
        mailbox: MailboxId,
        mut list: Vec<Message>,
        c: &Changes<MessageChange>,
    ) -> Option<Vec<Message>> {
        for ch in &c.destroyed {
            match self.messages.get(scope, ch.id).await.ok().flatten() {
                // Восстановлено в ту же папку (скрытие с восстановлением свёрнуто в `destroyed`).
                Some(m) if m.mailbox == mailbox => upsert(&mut list, m),
                // Нет или живёт в другой папке — убрать.
                _ => remove(&mut list, ch.id),
            }
        }
        let mut fetch: Vec<MessageId> =
            c.created.iter().chain(&c.updated).map(|ch| ch.id).collect();
        fetch.sort_unstable();
        fetch.dedup();
        if !fetch.is_empty() {
            let n = fetch.len();
            let found = self
                .messages
                .list(scope, mailbox, MessageQuery::Ids(fetch.clone()), n)
                .await
                .ok()?;
            let got: HashSet<MessageId> = found.iter().map(|m| m.id).collect();
            for m in found {
                remove(&mut list, m.id);
                upsert(&mut list, m);
            }
            for id in fetch.iter().filter(|id| !got.contains(id)) {
                match self.messages.get(scope, *id).await.ok().flatten() {
                    Some(m) if m.mailbox == mailbox => {
                        remove(&mut list, m.id);
                        upsert(&mut list, m);
                    }
                    _ => remove(&mut list, *id),
                }
            }
        }
        Some(list)
    }

    /// Полная пересборка из внутреннего хранилища; база журнала — версия папки до чтения списка.
    async fn rebuild(
        &self,
        scope: AccountScope,
        mailbox: MailboxId,
        key: (TenantId, AccountId, MailboxId),
        limit: usize,
    ) -> Result<Vec<Message>> {
        let base = self.mailboxes.status(scope, mailbox).await?.highest_modseq;
        let list = self
            .messages
            .list(scope, mailbox, MessageQuery::All, limit)
            .await?;
        let complete = list.len() < limit;
        let bytes = list_bytes(&list);
        self.store(
            key,
            Entry {
                base,
                limit,
                complete,
                list: Arc::new(list.clone()),
                at: Instant::now(),
            },
        );
        self.count(|s| s.rebuilds += 1);
        tracing::debug!(
            account = %scope.account,
            mailbox = %mailbox,
            len = list.len(),
            bytes,
            "list_cache: список папки пересобран"
        );
        Ok(list)
    }
}

/// Вставляет письмо в список по месту по `Uid` (существующий с тем же идентификатором — заменить).
fn upsert(list: &mut Vec<Message>, m: Message) {
    if let Some(p) = list.iter().position(|x| x.id == m.id) {
        list.remove(p);
    }
    let pos = list.partition_point(|x| x.uid < m.uid);
    list.insert(pos, m);
}

/// Убирает письмо по идентификатору; нет — ничего.
fn remove(list: &mut Vec<Message>, id: MessageId) {
    if let Some(p) = list.iter().position(|x| x.id == id) {
        list.remove(p);
    }
}

/// Оценка содержимого списка, байт: поля письма, строки метаданных, флаги, части.
fn list_bytes(list: &[Message]) -> usize {
    list.iter().map(message_bytes).sum::<usize>() + 64
}

fn message_bytes(m: &Message) -> usize {
    128 + m.flags.iter().map(flag_bytes).sum::<usize>()
        + m.parts.len() * 64
        + m.parts.iter().map(|p| p.part.len()).sum::<usize>()
        + meta_bytes(&m.meta)
}

fn flag_bytes(f: &Flag) -> usize {
    match f {
        Flag::Seen | Flag::Answered | Flag::Flagged | Flag::Deleted | Flag::Draft => 24,
        Flag::Keyword(k) => 24 + k.len(),
    }
}

fn meta_bytes(m: &MessageMeta) -> usize {
    let e = &m.envelope;
    opt_bytes(&e.subject)
        + e.from
            .iter()
            .chain(&e.sender)
            .chain(&e.reply_to)
            .chain(&e.to)
            .chain(&e.cc)
            .chain(&e.bcc)
            .map(address_bytes)
            .sum::<usize>()
        + opt_bytes(&e.message_id)
        + opt_bytes(&e.in_reply_to)
        + 16
        + m.preview.len()
        + m.thread_key.len()
        + body_bytes(&m.body)
}

fn address_bytes(a: &tp_contracts::meta::Address) -> usize {
    48 + a.email.len() + a.name.as_ref().map_or(0, String::len)
}

fn opt_bytes(s: &Option<String>) -> usize {
    16 + s.as_ref().map_or(0, String::len)
}

fn body_bytes(b: &tp_contracts::meta::BodyPart) -> usize {
    96 + b.part.len()
        + b.media_type.len()
        + b.subtype.len()
        + b.content_id.as_ref().map_or(0, String::len)
        + b.description.as_ref().map_or(0, String::len)
        + b.encoding.as_ref().map_or(0, String::len)
        + b.location.as_ref().map_or(0, String::len)
        + b.language.iter().map(String::len).sum::<usize>()
        + b.params
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
        + b.disposition.as_ref().map_or(0, |(t, p)| {
            t.len() + p.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>()
        })
        + b.children.iter().map(body_bytes).sum::<usize>()
}

#[async_trait]
impl MessageStore for CachedMessages {
    async fn insert(
        &self,
        scope: AccountScope,
        mailbox: MailboxId,
        msg: NewMessage,
    ) -> Result<Inserted> {
        self.messages.insert(scope, mailbox, msg).await
    }

    async fn insert_batch(
        &self,
        tenant: TenantId,
        items: Vec<(AccountScope, MailboxId, NewMessage)>,
    ) -> Result<Vec<Inserted>> {
        self.messages.insert_batch(tenant, items).await
    }

    async fn get(&self, scope: AccountScope, id: MessageId) -> Result<Option<Message>> {
        self.messages.get(scope, id).await
    }

    /// Список писем папки: `MessageQuery::All` — из кэша (свежесть — по журналу папки),
    /// остальные выборки — во внутреннее хранилище.
    async fn list(
        &self,
        scope: AccountScope,
        mailbox: MailboxId,
        query: MessageQuery,
        limit: usize,
    ) -> Result<Vec<Message>> {
        let MessageQuery::All = query else {
            return self.messages.list(scope, mailbox, query, limit).await;
        };
        if self.cfg.max_bytes == 0 {
            return self.messages.list(scope, mailbox, query, limit).await;
        }
        let key = (scope.tenant, scope.account, mailbox);
        let Some(e) = self.servable(&key, limit) else {
            return self.rebuild(scope, mailbox, key, limit).await;
        };
        // Папка исчезла — запись отбросить, ответ — из внутреннего хранилища (в том числе ошибка).
        if self.mailboxes.get(scope, mailbox).await?.is_none() {
            self.drop_entry(&key);
            return self.messages.list(scope, mailbox, query, limit).await;
        }
        // Свежесть по журналу папки: изменений нет — из кэша; до `patch_max` — обновить;
        // больше, усечённый список или журнал недоступен — пересборка.
        let cap = self.cfg.patch_max.saturating_add(1);
        let fresh = match self
            .changes
            .message_changes(scope, Some(mailbox), e.base, cap)
            .await
        {
            Ok(c) if !c.has_more => Some(c),
            _ => None,
        };
        let Some(c) = fresh else {
            return self.rebuild(scope, mailbox, key, limit).await;
        };
        let changes = c.created.len() + c.updated.len() + c.destroyed.len();
        if changes == 0 {
            self.advance(&key, e.base, c.new_state);
            self.count(|s| s.hits += 1);
            return Ok(Self::serve(&e, limit));
        }
        if e.complete
            && changes <= self.cfg.patch_max
            && let Some(mut list) = self.patch(scope, mailbox, (*e.list).clone(), &c).await
        {
            list.truncate(e.limit);
            let complete = list.len() < e.limit;
            if complete || limit <= e.limit {
                let bytes = list_bytes(&list);
                self.store(
                    key,
                    Entry {
                        base: c.new_state,
                        limit: e.limit,
                        complete,
                        list: Arc::new(list.clone()),
                        at: Instant::now(),
                    },
                );
                self.count(|s| s.patches += 1);
                tracing::debug!(
                    account = %scope.account,
                    mailbox = %mailbox,
                    changes,
                    len = list.len(),
                    bytes,
                    "list_cache: список папки обновлён по журналу"
                );
                let n = limit.min(list.len());
                return Ok(list[..n].to_vec());
            }
        }
        self.rebuild(scope, mailbox, key, limit).await
    }

    async fn set_flags(
        &self,
        scope: AccountScope,
        ids: &[MessageId],
        op: FlagOp,
        unchanged_since: Option<ModSeq>,
    ) -> Result<FlagsUpdate> {
        self.messages
            .set_flags(scope, ids, op, unchanged_since)
            .await
    }

    async fn copy(
        &self,
        scope: AccountScope,
        ids: &[MessageId],
        to: MailboxId,
    ) -> Result<Vec<Inserted>> {
        self.messages.copy(scope, ids, to).await
    }

    async fn move_to(
        &self,
        scope: AccountScope,
        ids: &[MessageId],
        to: MailboxId,
    ) -> Result<Vec<Inserted>> {
        self.messages.move_to(scope, ids, to).await
    }

    async fn to_trash(&self, scope: AccountScope, ids: &[MessageId]) -> Result<ModSeq> {
        self.messages.to_trash(scope, ids).await
    }

    async fn restore(&self, scope: AccountScope, ids: &[MessageId]) -> Result<Vec<Inserted>> {
        self.messages.restore(scope, ids).await
    }

    async fn expunge_final(&self, scope: AccountScope, ids: &[MessageId]) -> Result<ModSeq> {
        self.messages.expunge_final(scope, ids).await
    }
}

impl CachedMessages {
    /// Список для выдачи: первые `limit` по `Uid` (список записи уже упорядочен).
    fn serve(e: &Entry, limit: usize) -> Vec<Message> {
        let n = limit.min(e.list.len());
        e.list[..n].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testenv::Env;
    use time::OffsetDateTime;
    use tp_contracts::Uid;
    use tp_contracts::mailstore::{Delivery, IngestRequest, MailStore};
    use tp_contracts::meta::{Flags, MailboxStore, NewMailbox, SpecialUse};

    /// Окружение: метаданные `tp-testkit` и кэш поверх них (хранилище, папки, журнал — одно).
    struct Fx {
        env: Env,
        scope: AccountScope,
        inbox: MailboxId,
        trash: MailboxId,
        cache: CachedMessages,
    }

    async fn fx_with(cfg: ListCacheConfig) -> Fx {
        let env = Env::new();
        let scope = env.meta.account("a@example.org").await.expect("acc");
        let inbox = env
            .meta
            .mailbox_by_role(scope, SpecialUse::Inbox)
            .expect("inbox");
        let trash = env
            .meta
            .mailbox_by_role(scope, SpecialUse::Trash)
            .expect("trash");
        let cache = CachedMessages::new(
            Arc::new(env.meta.clone()),
            Arc::new(env.meta.clone()),
            Arc::new(env.meta.clone()),
            cfg,
        );
        Fx {
            env,
            scope,
            inbox,
            trash,
            cache,
        }
    }

    async fn fx() -> Fx {
        fx_with(ListCacheConfig::default()).await
    }

    /// Доставляет письмо с темой `subject` во «Входящие».
    async fn deliver(f: &Fx, subject: &str) -> MessageId {
        let raw = format!(
            "From: s@example.org\r\nTo: a@example.org\r\nSubject: {subject}\r\n\r\nтело {subject}\r\n"
        );
        let done = f
            .env
            .store
            .ingest(IngestRequest {
                tenant: f.scope.tenant,
                mail_from: "s@example.org".into(),
                raw: crate::testenv::stream(raw.as_bytes(), 1024),
                deliveries: vec![Delivery {
                    account: f.scope.account,
                    mailbox: f.inbox,
                    extra_headers: vec![],
                    flags: Flags::new(),
                }],
                received_at: OffsetDateTime::now_utc(),
            })
            .await
            .expect("ingest");
        done.delivered[0].message
    }

    fn subjects(msgs: &[Message]) -> Vec<String> {
        msgs.iter()
            .map(|m| m.meta.envelope.subject.clone().unwrap_or_default())
            .collect()
    }

    /// Список кэша равен свежему чтению внутреннего хранилища.
    async fn assert_transparent(f: &Fx, limit: usize) {
        let cached = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, limit)
            .await
            .expect("cache list");
        let inner = MessageStore::list(&f.env.meta, f.scope, f.inbox, MessageQuery::All, limit)
            .await
            .expect("inner list");
        assert_eq!(cached, inner);
    }

    #[tokio::test]
    async fn repeat_select_served_from_cache() {
        let f = fx().await;
        for i in 0..3 {
            deliver(&f, &format!("m{i}")).await;
        }
        let first = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        assert_eq!(f.cache.stats().rebuilds, 1);
        let second = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        assert_eq!(first, second);
        let s = f.cache.stats();
        assert_eq!((s.rebuilds, s.hits, s.patches), (1, 1, 0));
    }

    #[tokio::test]
    async fn delivery_reflected_in_cache() {
        let f = fx().await;
        for i in 0..2 {
            deliver(&f, &format!("m{i}")).await;
        }
        MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        deliver(&f, "новое").await;
        let list = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        assert_eq!(subjects(&list), vec!["m0", "m1", "новое"]);
        assert_eq!(f.cache.stats().patches, 1);
        assert_transparent(&f, 100).await;
    }

    #[tokio::test]
    async fn flag_change_reflected_in_cache() {
        let f = fx().await;
        let ids = vec![deliver(&f, "m0").await, deliver(&f, "m1").await];
        MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        let seen: Flags = [Flag::Seen].into();
        f.env
            .store
            .set_flags(f.scope, &ids[..1], FlagOp::Add(seen), None)
            .await
            .expect("set_flags");
        let list = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        assert!(list[0].flags.contains(&Flag::Seen));
        assert!(!list[1].flags.contains(&Flag::Seen));
        assert_eq!(f.cache.stats().patches, 1);
        assert_transparent(&f, 100).await;
    }

    #[tokio::test]
    async fn move_between_folders_reflected_in_both_caches() {
        let f = fx().await;
        let ids = vec![deliver(&f, "m0").await, deliver(&f, "m1").await];
        let work = MailboxStore::create(
            &f.env.meta,
            f.scope,
            NewMailbox {
                parent: None,
                name: "Work".into(),
                role: None,
            },
        )
        .await
        .expect("create")
        .id;
        // Обе записи построены до переноса.
        MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("inbox");
        MessageStore::list(&f.cache, f.scope, work, MessageQuery::All, 100)
            .await
            .expect("work");
        f.env
            .store
            .move_to(f.scope, &ids[..1], work)
            .await
            .expect("move");
        let inbox_list = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("inbox");
        let work_list = MessageStore::list(&f.cache, f.scope, work, MessageQuery::All, 100)
            .await
            .expect("work");
        assert_eq!(subjects(&inbox_list), vec!["m1"]);
        assert_eq!(subjects(&work_list), vec!["m0"]);
        assert_eq!(f.cache.stats().patches, 2);
        let inner_work = MessageStore::list(&f.env.meta, f.scope, work, MessageQuery::All, 100)
            .await
            .expect("inner");
        assert_eq!(work_list, inner_work);
    }

    #[tokio::test]
    async fn trash_restore_expunge_reflected_in_cache() {
        let f = fx().await;
        let ids = vec![deliver(&f, "m0").await, deliver(&f, "m1").await];
        MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("inbox");
        MessageStore::list(&f.cache, f.scope, f.trash, MessageQuery::All, 100)
            .await
            .expect("trash");
        // В корзину: из «Входящих» исчезли, в корзине появились.
        f.env
            .store
            .delete_to_trash(f.scope, &ids)
            .await
            .expect("trash");
        let inbox_list = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("inbox");
        let trash_list = MessageStore::list(&f.cache, f.scope, f.trash, MessageQuery::All, 100)
            .await
            .expect("trash");
        assert!(inbox_list.is_empty());
        assert_eq!(trash_list.len(), 2);
        // Восстановление: вернулись во «Входящие».
        f.env.store.restore(f.scope, &ids).await.expect("restore");
        let inbox_list = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("inbox");
        assert_eq!(inbox_list.len(), 2);
        // В корзину и окончательное удаление: из корзины исчезли.
        f.env
            .store
            .delete_to_trash(f.scope, &ids)
            .await
            .expect("trash");
        MessageStore::expunge_final(&f.env.meta, f.scope, &ids)
            .await
            .expect("expunge");
        let trash_list = MessageStore::list(&f.cache, f.scope, f.trash, MessageQuery::All, 100)
            .await
            .expect("trash");
        assert!(trash_list.is_empty());
        assert!(f.cache.stats().patches >= 4);
        assert_transparent(&f, 100).await;
    }

    #[tokio::test]
    async fn limit_windows_sliced_and_rebuilt() {
        let f = fx().await;
        for i in 0..3 {
            deliver(&f, &format!("m{i}")).await;
        }
        let two = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 2)
            .await
            .expect("list");
        assert_eq!(two.len(), 2);
        assert_eq!(two[0].uid, Uid(1));
        // То же окно и меньшее — из кэша; большее (запись неполная) — пересборка.
        MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 2)
            .await
            .expect("list");
        let one = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 1)
            .await
            .expect("list");
        assert_eq!(one.len(), 1);
        let wide = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 5)
            .await
            .expect("list");
        assert_eq!(wide.len(), 3);
        let s = f.cache.stats();
        assert_eq!((s.rebuilds, s.hits), (2, 2));
        // Полная запись обслуживает меньшие окна.
        MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 5)
            .await
            .expect("list");
        let s = f.cache.stats();
        assert_eq!(s.hits, 3);
    }

    #[tokio::test]
    async fn truncated_list_is_not_patched() {
        let f = fx().await;
        for i in 0..3 {
            deliver(&f, &format!("m{i}")).await;
        }
        MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 2)
            .await
            .expect("list");
        deliver(&f, "ещё").await;
        let list = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 2)
            .await
            .expect("list");
        assert_eq!(subjects(&list), vec!["m0", "m1"]);
        let s = f.cache.stats();
        assert_eq!((s.rebuilds, s.patches), (2, 0));
    }

    #[tokio::test]
    async fn eviction_by_max_entries() {
        let f = fx_with(ListCacheConfig {
            max_entries: 1,
            ..ListCacheConfig::default()
        })
        .await;
        deliver(&f, "m0").await;
        let work = MailboxStore::create(
            &f.env.meta,
            f.scope,
            NewMailbox {
                parent: None,
                name: "Work".into(),
                role: None,
            },
        )
        .await
        .expect("create")
        .id;
        MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("inbox");
        MessageStore::list(&f.cache, f.scope, work, MessageQuery::All, 100)
            .await
            .expect("work");
        // «Входящие» вытеснены записью «Work» — пересборка; при сохранении снова вытеснен «Work».
        MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("inbox");
        let s = f.cache.stats();
        assert_eq!((s.rebuilds, s.evictions, s.entries), (3, 2, 1));
    }

    #[tokio::test]
    async fn byte_budget_evicts_entry() {
        // Запись не помещается в бюджет — кэш не удерживает её (учёт памяти работает).
        let f = fx_with(ListCacheConfig {
            max_bytes: 1000,
            ..ListCacheConfig::default()
        })
        .await;
        for i in 0..5 {
            deliver(&f, &format!("m{i}")).await;
        }
        let a = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        assert_eq!(f.cache.stats().entries, 0);
        let b = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        assert_eq!(a, b);
        let s = f.cache.stats();
        assert_eq!((s.rebuilds, s.hits, s.entries), (2, 0, 0));
    }

    #[tokio::test]
    async fn disabled_cache_is_pass_through() {
        let f = fx_with(ListCacheConfig {
            max_bytes: 0,
            ..ListCacheConfig::default()
        })
        .await;
        deliver(&f, "m0").await;
        let a = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        let b = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        assert_eq!(a, b);
        let s = f.cache.stats();
        assert_eq!((s.hits, s.rebuilds, s.patches, s.entries), (0, 0, 0, 0));
    }

    #[tokio::test]
    async fn deleted_mailbox_is_not_served_from_cache() {
        let f = fx().await;
        deliver(&f, "m0").await;
        let work = MailboxStore::create(
            &f.env.meta,
            f.scope,
            NewMailbox {
                parent: None,
                name: "Work".into(),
                role: None,
            },
        )
        .await
        .expect("create")
        .id;
        MessageStore::list(&f.cache, f.scope, work, MessageQuery::All, 100)
            .await
            .expect("work");
        MailboxStore::delete(&f.env.meta, f.scope, work, false)
            .await
            .expect("delete");
        let err = MessageStore::list(&f.cache, f.scope, work, MessageQuery::All, 100)
            .await
            .expect_err("удалённая папка");
        let inner = MessageStore::list(&f.env.meta, f.scope, work, MessageQuery::All, 100)
            .await
            .expect_err("удалённая папка");
        assert_eq!(err, inner);
    }

    #[tokio::test]
    async fn uid_order_kept_after_patches() {
        let f = fx().await;
        let mut ids = Vec::new();
        for i in 0..5 {
            ids.push(deliver(&f, &format!("m{i}")).await);
        }
        MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        let work = MailboxStore::create(
            &f.env.meta,
            f.scope,
            NewMailbox {
                parent: None,
                name: "Work".into(),
                role: None,
            },
        )
        .await
        .expect("create")
        .id;
        // Перенести каждый второй в «Work» и обратно — порядок UID в кэше сохраняется.
        for (i, id) in ids.iter().enumerate() {
            if i % 2 == 0 {
                f.env
                    .store
                    .move_to(f.scope, std::slice::from_ref(id), work)
                    .await
                    .expect("move");
                f.env
                    .store
                    .move_to(f.scope, std::slice::from_ref(id), f.inbox)
                    .await
                    .expect("back");
            }
        }
        assert_transparent(&f, 100).await;
        let list = MessageStore::list(&f.cache, f.scope, f.inbox, MessageQuery::All, 100)
            .await
            .expect("list");
        // Перенесённые письма вернулись с новыми UID (6–8), порядок списка — по возрастанию UID.
        let uids: Vec<u32> = list.iter().map(|m| m.uid.0).collect();
        assert!(
            uids.windows(2).all(|w| w[0] < w[1]),
            "UID по возрастанию: {uids:?}"
        );
        assert_eq!(subjects(&list), vec!["m1", "m3", "m0", "m2", "m4"]);
    }
}
