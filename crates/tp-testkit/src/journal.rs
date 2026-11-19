//! Журнал переписки в памяти ([`JournalStore`], CTR-97; CONTRACTS.md#Journal; SRS 4.9).
//!
//! Хеш цепочки — тестовый (SipHash из std с разным посевом на каждые 8 байт), не SHA-256: контракт
//! фиксирует образ входа ([`tp_contracts::journal::chain_input`]), алгоритм считают реализации
//! (`tp-meta`, полоса blob). «Хранилище записей» и «индекс» — одни данные; `drop_index` помечает индекс
//! потерянным до `restore_index` (для набора `suite::journal`).

use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use tp_contracts::ids::{BlobHash, JournalId, TenantId};
use tp_contracts::journal::{
    ChainReport, GENESIS_HASH, JournalAudit, JournalCursor, JournalEntry, JournalPage,
    JournalQuery, JournalRecord, JournalRule, JournalStore, chain_input, journal_eml,
};
use tp_contracts::{Error, Result};

use crate::infra::lock;

#[derive(Debug, Clone)]
struct Stored {
    id: JournalId,
    record: JournalRecord,
    message: Bytes,
    hash: [u8; 32],
}

#[derive(Debug, Default)]
struct JournalState {
    /// Записи в порядке добавления; цепочка — в пределах организации.
    entries: Vec<Stored>,
    /// Индекс потерян (до `restore_index`): поиск невозможен.
    index_dropped: bool,
}

/// [`JournalStore`] в памяти; клоны разделяют данные. Записи неизменяемы; методов удаления нет.
#[derive(Debug, Clone)]
pub struct MemJournal {
    state: Arc<Mutex<JournalState>>,
}

impl Default for MemJournal {
    fn default() -> Self {
        Self::new()
    }
}

impl MemJournal {
    /// Пустой журнал.
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(JournalState::default())),
        }
    }

    /// Тест набора `suite::journal`: подменяет запись `id` (отправителя) без пересчёта хеша цепочки.
    pub fn tamper(&self, id: JournalId) {
        let mut state = lock(&self.state);
        if let Some(entry) = state.entries.iter_mut().find(|e| e.id == id) {
            entry.record.sender = "tampered@example.invalid".to_owned();
        }
    }

    /// Тест набора `suite::journal`: теряет индекс, не трогая хранилище записей.
    pub fn drop_index(&self) {
        lock(&self.state).index_dropped = true;
    }
}

/// Хеш цепочки для тестов: детерминированный SipHash (посев — номер блока).
fn mem_hash(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h = DefaultHasher::new();
        h.write_u8(i as u8);
        h.write(input);
        chunk.copy_from_slice(&h.finish().to_be_bytes());
    }
    out
}

fn cursor(at: time::OffsetDateTime, id: JournalId) -> JournalCursor {
    JournalCursor(format!("{}|{id}", at.unix_timestamp_nanos()))
}

fn parse_cursor(c: &JournalCursor) -> Result<(i128, JournalId)> {
    let Some((nanos, id)) = c.0.split_once('|') else {
        return Err(Error::invalid("journal: bad cursor"));
    };
    Ok((
        nanos
            .parse()
            .map_err(|_| Error::invalid("journal: bad cursor"))?,
        id.parse()
            .map_err(|_| Error::invalid("journal: bad cursor"))?,
    ))
}

#[async_trait]
impl JournalStore for MemJournal {
    async fn append(
        &self,
        rule: &JournalRule,
        record: &JournalRecord,
        message: Bytes,
    ) -> Result<JournalId> {
        rule.validate()?;
        record.validate()?;
        if record.rule != rule.id {
            return Err(Error::invalid("journal: record rule does not match"));
        }
        if record.tenant != rule.tenant {
            return Err(Error::invalid("journal: record tenant does not match rule"));
        }
        if message.is_empty() {
            return Err(Error::invalid("journal: empty message"));
        }
        let mut state = lock(&self.state);
        let prev = state
            .entries
            .iter()
            .rev()
            .find(|e| e.record.tenant == rule.tenant)
            .map(|e| BlobHash(e.hash))
            .unwrap_or(GENESIS_HASH);
        let id = JournalId::new();
        let hash = mem_hash(&chain_input(&prev, record));
        state.entries.push(Stored {
            id,
            record: record.clone(),
            message,
            hash,
        });
        Ok(id)
    }

    async fn search(&self, _cap: &JournalAudit, query: &JournalQuery) -> Result<JournalPage> {
        query.validate()?;
        let state = lock(&self.state);
        if state.index_dropped {
            return Err(Error::internal("journal index is missing; run restore"));
        }
        let after = match &query.after {
            Some(c) => Some(parse_cursor(c)?),
            None => None,
        };
        let mut found: Vec<&Stored> = state
            .entries
            .iter()
            .filter(|e| e.record.tenant == query.tenant && query.matches(&e.record))
            .filter(|e| {
                // Строго после позиции `after`.
                after.is_none_or(|(nanos, id)| {
                    (e.record.at.unix_timestamp_nanos(), e.id) > (nanos, id)
                })
            })
            .collect();
        found.sort_by_key(|e| (e.record.at, e.id));
        let has_more = found.len() > query.limit;
        found.truncate(query.limit);
        let next = has_more.then(|| {
            found
                .last()
                .map(|e| cursor(e.record.at, e.id))
                .expect("full page")
        });
        Ok(JournalPage {
            entries: found
                .into_iter()
                .map(|e| JournalEntry {
                    id: e.id,
                    record: e.record.clone(),
                    hash: BlobHash(e.hash),
                })
                .collect(),
            next,
        })
    }

    async fn export(&self, _cap: &JournalAudit, tenant: TenantId, id: JournalId) -> Result<Bytes> {
        let state = lock(&self.state);
        let entry = state
            .entries
            .iter()
            .find(|e| e.id == id && e.record.tenant == tenant)
            .ok_or(Error::NotFound)?;
        journal_eml(&entry.record, &entry.message)
    }

    async fn verify_chain(&self, _cap: &JournalAudit, tenant: TenantId) -> Result<ChainReport> {
        let state = lock(&self.state);
        let mut prev = GENESIS_HASH;
        let mut report = ChainReport {
            records: 0,
            ok: true,
            broken_at: None,
        };
        for entry in state.entries.iter().filter(|e| e.record.tenant == tenant) {
            report.records += 1;
            let expected = mem_hash(&chain_input(&prev, &entry.record));
            if expected != entry.hash && report.ok {
                report.ok = false;
                report.broken_at = Some(entry.id);
            }
            prev = BlobHash(entry.hash);
        }
        Ok(report)
    }

    async fn restore_index(&self, tenant: TenantId) -> Result<u64> {
        let mut state = lock(&self.state);
        state.index_dropped = false;
        Ok(state
            .entries
            .iter()
            .filter(|e| e.record.tenant == tenant)
            .count() as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite;

    #[tokio::test]
    async fn suite_journal_store() {
        let journal = MemJournal::new();
        let tamper = {
            let journal = journal.clone();
            move |id: JournalId| journal.tamper(id)
        };
        let drop_index = {
            let journal = journal.clone();
            move || journal.drop_index()
        };
        suite::journal(&journal, &tamper, &drop_index).await;
    }
}
