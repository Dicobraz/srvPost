//! Снимки папок для сеансов (PERF-03): список писем папки — один [`Arc`] на папку вместо копии
//! на соединение.
//!
//! `SELECT` строит снимок папки для номеров последовательности (состояние `selected` сессии).
//! Без общего кэша каждая сессия держала свою копию (`Vec<(Uid, MessageId)>`, 24 байта на письмо)
//! и каждый выбор выгружал список папки целиком с метаданными (`MessageStore::list` возвращает
//! принадлежащий `Vec<Message>` — конверт, дерево частей, превью) — на простаивающее соединение
//! приходились мегабайты (Д.7 №17: 981.6 KB на соединение, порог 64 KB).
//!
//! Кэш ([`Snapshots`]) при выдаче проверяет свежесть по журналу изменений папки
//! ([`ChangeLog::message_changes`] от базового `ModSeq` записи): изменений нет — тот же [`Arc`]
//! (копии на соединение нет вовсе), есть, журнал недоступен или старее базы — полная пересборка;
//! `ttl` — страховка от изменений вне журнала. Без инкрементальных патчей: `SELECT` читает папку
//! один раз за соединение, а свежесть — чтение журнала папки с лимитом 1. Сессия правит свой
//! снимок (`sync`, `EXPUNGE`) через `Arc::make_mut`: до первого изменения копии у сессии нет,
//! после — своя, как раньше. Образец подхода — кэши с инвалидацией по журналу: кэш списков папок
//! tp-mailstore (`CachedMessages`, PERF-01) и `Email/query` tp-jmap (PERF-02).
//!
//! Конкуренция — «последний записавший»: каждая запись согласована со своей базой (снимок
//! отражает все изменения с `ModSeq` не больше базы), проверка следующего чтения идёт от базы
//! сохранённой записи, перезапись конкурентной пересборкой лишь откатывает снимок к согласованному
//! состоянию. Существование папки к выдаче не проверяется: снимок запрашивается только после
//! разрешения папки деревом (`SELECT`), а исчезновение папки и её письма пишет в журнал — снимок
//! пересоберётся и вернёт ошибку хранилища вместе с `list`.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use tp_contracts::meta::{AccountScope, ChangeLog, Flag, MailboxStore, MessageQuery, MessageStore};
use tp_contracts::{AccountId, MailboxId, MessageId, ModSeq, Result, TenantId, Uid};

use crate::config::SnapshotsConfig;
use crate::session::Deps;

/// Строка снимка папки: UID, идентификатор письма, `\Seen` на момент снимка
/// (позиция первого непрочитанного — код `UNSEEN` при выборе).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Row {
    pub uid: Uid,
    pub id: MessageId,
    pub seen: bool,
}

/// Общий снимок папки: строки по возрастанию UID; номер последовательности — индекс + 1.
pub(crate) type Rows = Arc<Vec<Row>>;

/// Оценка записи, байт: строки снимка и накладные записи.
fn rows_bytes(rows: &[Row]) -> usize {
    rows.len() * std::mem::size_of::<Row>() + 64
}

/// Запись кэша: снимок одной папки, база журнала, окно построения.
struct Entry {
    /// Снимок отражает все изменения папки с `ModSeq` не больше базового; база — точка отсчёта
    /// проверки свежести по журналу.
    base: ModSeq,
    /// `limit`, с которым снимок построен: окно «первые `limit` по `Uid`».
    limit: usize,
    /// Снимок — вся папка (`len < limit`): годится для любого `limit`.
    complete: bool,
    rows: Rows,
    at: Instant,
}

#[derive(Default)]
struct State {
    entries: HashMap<(TenantId, AccountId, MailboxId), Entry>,
    bytes: usize,
}

/// Кэш снимков папок — общий для сеансов слушателя (`Server::serve`).
pub(crate) struct Snapshots {
    cfg: SnapshotsConfig,
    state: Mutex<State>,
}

impl fmt::Debug for Snapshots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Snapshots")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl Snapshots {
    /// Кэш с секцией `imap.snapshot` конфигурации.
    pub(crate) fn new(cfg: SnapshotsConfig) -> Self {
        Self {
            cfg,
            state: Mutex::default(),
        }
    }

    /// Записей в кэше сейчас (тесты).
    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .len()
    }

    /// Снимок папки по возрастанию UID в окне `limit`. Свежесть — по журналу папки:
    /// изменений нет — общий снимок из кэша (база двигается вперёд), есть, журнал недоступен
    /// или старее базы — пересборка.
    pub(crate) async fn serve(
        &self,
        deps: &Deps,
        scope: AccountScope,
        mailbox: MailboxId,
        limit: usize,
    ) -> Result<Rows> {
        // Кэш выключен: снимок строится для сессии, в кэше не хранится.
        if self.cfg.max_bytes == 0 {
            let (rows, _, _) = Self::build(deps, scope, mailbox, limit).await?;
            return Ok(rows);
        }
        let key = (scope.tenant, scope.account, mailbox);
        let Some(e) = self.servable(&key, limit) else {
            return self.rebuild(deps, scope, mailbox, Some(key), limit).await;
        };
        match deps
            .changes
            .message_changes(scope, Some(mailbox), e.base, 1)
            .await
        {
            // Изменений нет: общий снимок из кэша, база двигается к текущему состоянию журнала.
            Ok(c)
                if !c.has_more
                    && c.created.is_empty()
                    && c.updated.is_empty()
                    && c.destroyed.is_empty() =>
            {
                self.advance(&key, e.base, c.new_state);
                Ok(e.rows)
            }
            // Есть изменения или журнал недоступен — пересборка.
            _ => self.rebuild(deps, scope, mailbox, Some(key), limit).await,
        }
    }

    /// Запись, пригодная выдать снимок для запроса с окном `limit`, не просроченная. Блокировка
    /// не удерживается через точки ожидания; обращение обновляет давность.
    fn servable(&self, key: &(TenantId, AccountId, MailboxId), limit: usize) -> Option<Entry> {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let expired = st
            .entries
            .get(key)
            .is_some_and(|e| e.at.elapsed() > self.cfg.ttl);
        if expired {
            if let Some(e) = st.entries.remove(key) {
                st.bytes -= rows_bytes(&e.rows);
            }
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
            rows: e.rows.clone(),
            at: e.at,
        })
    }

    /// Двигает базу записи вперёд без пересборки (изменений папки в журнале нет). База двигается
    /// только у записи, от которой шла проверка, — не заменённая конкурентной пересборкой.
    fn advance(&self, key: &(TenantId, AccountId, MailboxId), from: ModSeq, to: ModSeq) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(e) = st.entries.get_mut(key)
            && e.base == from
        {
            e.base = to;
        }
    }

    /// Сохраняет запись и вытесняет давние сверх бюджетов. Перезапись конкурентной записи
    /// безопасна: каждая согласована со своей базой (см. модуль).
    fn store(&self, key: (TenantId, AccountId, MailboxId), entry: Entry) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let added = rows_bytes(&entry.rows);
        if let Some(old) = st.entries.insert(key, entry) {
            st.bytes -= rows_bytes(&old.rows);
        }
        st.bytes += added;
        while st.bytes > self.cfg.max_bytes
            || (self.cfg.max_entries > 0 && st.entries.len() > self.cfg.max_entries)
        {
            let Some(oldest) = st.entries.iter().min_by_key(|(_, e)| e.at).map(|(k, _)| *k) else {
                break;
            };
            let e = st.entries.remove(&oldest).expect("запись есть");
            st.bytes -= rows_bytes(&e.rows);
        }
    }

    /// Пересборка с сохранением в кэше (`Some(key)`); для выключенного кэша (`None`) — без записи.
    async fn rebuild(
        &self,
        deps: &Deps,
        scope: AccountScope,
        mailbox: MailboxId,
        key: Option<(TenantId, AccountId, MailboxId)>,
        limit: usize,
    ) -> Result<Rows> {
        let (rows, complete, base) = Self::build(deps, scope, mailbox, limit).await?;
        if let Some(key) = key {
            self.store(
                key,
                Entry {
                    base,
                    limit,
                    complete,
                    rows: rows.clone(),
                    at: Instant::now(),
                },
            );
        }
        Ok(rows)
    }

    /// Полная пересборка из хранилища; база журнала — версия папки до чтения списка: снимок
    /// отражает всё, что зафиксировано до базы, изменения после базы видит проверка свежести
    /// при следующей выдаче; обратный порядок мог бы пропустить изменение между чтением
    /// списка и версии.
    async fn build(
        deps: &Deps,
        scope: AccountScope,
        mailbox: MailboxId,
        limit: usize,
    ) -> Result<(Rows, bool, ModSeq)> {
        let base = deps.mailboxes.status(scope, mailbox).await?.highest_modseq;
        let list = deps
            .messages
            .list(scope, mailbox, MessageQuery::All, limit)
            .await?;
        let rows: Rows = Arc::new(
            list.iter()
                .map(|m| Row {
                    uid: m.uid,
                    id: m.id,
                    seen: m.flags.contains(&Flag::Seen),
                })
                .collect(),
        );
        let complete = list.len() < limit;
        tracing::debug!(
            account = %scope.account,
            mailbox = %mailbox,
            len = rows.len(),
            "imap: снимок папки пересобран"
        );
        Ok((rows, complete, base))
    }
}
