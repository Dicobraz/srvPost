//! In-memory запись об отправленном ([`SentLog`], CTR-94; CONTRACTS.md#Reply): [`MemSentLog`] хранит записи
//! в порядке добавления; [`MemSentLog::records`] — для проверок в тестах полос.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use time::OffsetDateTime;
use tp_contracts::reply::{MessageIdHash, SentLog, SentRecord};
use tp_contracts::{Error, Result, TenantId};

use crate::infra::lock;

#[derive(Debug, Default)]
struct State {
    /// Записи в порядке добавления.
    records: Vec<SentRecord>,
}

/// Запись об отправленном в памяти; клоны разделяют данные. Повтор той же метки с тем же содержимым —
/// не ошибка (идемпотентность постановки в очередь), с другим — `Conflict` (метка уникальна).
#[derive(Debug, Clone, Default)]
pub struct MemSentLog {
    state: Arc<Mutex<State>>,
}

impl MemSentLog {
    /// Пустой журнал.
    pub fn new() -> Self {
        Self::default()
    }

    /// Все записи в порядке добавления (по всем организациям).
    pub fn records(&self) -> Vec<SentRecord> {
        lock(&self.state).records.clone()
    }
}

#[async_trait]
impl SentLog for MemSentLog {
    async fn record(&self, record: SentRecord) -> Result<()> {
        record.validate()?;
        let mut st = lock(&self.state);
        if let Some(prev) = st.records.iter().find(|r| r.tag == record.tag) {
            if prev == &record {
                return Ok(());
            }
            return Err(Error::Conflict);
        }
        st.records.push(record);
        Ok(())
    }

    async fn by_tag(&self, tenant: TenantId, tag: &[u8]) -> Result<Option<SentRecord>> {
        Ok(lock(&self.state)
            .records
            .iter()
            .find(|r| r.tenant == tenant && r.tag == tag)
            .cloned())
    }

    async fn by_message_id_hash(
        &self,
        tenant: TenantId,
        hash: &MessageIdHash,
    ) -> Result<Vec<SentRecord>> {
        let mut found: Vec<SentRecord> = lock(&self.state)
            .records
            .iter()
            .filter(|r| r.tenant == tenant && &r.message_id_hash == hash)
            .cloned()
            .collect();
        // Свежие первыми; при равенстве — более поздняя запись.
        found.reverse();
        Ok(found)
    }

    async fn purge_before(&self, before: OffsetDateTime) -> Result<usize> {
        let mut st = lock(&self.state);
        let before_len = st.records.len();
        st.records.retain(|r| r.sent_at >= before);
        Ok(before_len - st.records.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite;

    #[tokio::test]
    async fn suite_sent_log() {
        suite::reply(&MemSentLog::new(), TenantId::new(), TenantId::new()).await;
    }

    #[tokio::test]
    async fn records_are_shared_between_clones() {
        let log = MemSentLog::new();
        let clone = log.clone();
        let record = SentRecord {
            tenant: TenantId::DEFAULT,
            account: tp_contracts::AccountId::new(),
            tag: vec![7u8; 8],
            message_id_hash: tp_contracts::reply::MessageIdHash([1u8; 32]),
            recipients: vec!["bob@partner.example".into()],
            thread: None,
            sent_at: OffsetDateTime::UNIX_EPOCH,
        };
        log.record(record.clone()).await.expect("record");
        assert_eq!(clone.records().len(), 1);
        assert_eq!(log.records(), vec![record]);
    }
}
