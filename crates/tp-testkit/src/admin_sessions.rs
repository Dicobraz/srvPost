//! [`AdminSessions`] в памяти (CONTRACTS.md#Auth, CTR-61).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use time::OffsetDateTime;
use tp_contracts::admin_session::{AdminSession, AdminSessions};
use tp_contracts::{Error, Result};

use crate::infra::lock;

/// Сессии Admin API в памяти. Клоны разделяют данные.
#[derive(Debug, Clone, Default)]
pub struct MemAdminSessions {
    state: Arc<Mutex<Vec<AdminSession>>>,
}

impl MemAdminSessions {
    /// Пустое хранилище.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl AdminSessions for MemAdminSessions {
    async fn put(&self, session: AdminSession) -> Result<()> {
        session.validate()?;
        let mut st = lock(&self.state);
        if st.iter().any(|s| s.hash == session.hash) {
            return Err(Error::Conflict);
        }
        st.push(session);
        Ok(())
    }

    async fn get(&self, hash: &str) -> Result<Option<AdminSession>> {
        let now = OffsetDateTime::now_utc();
        Ok(lock(&self.state)
            .iter()
            .find(|s| s.hash == hash && now < s.expires_at)
            .cloned())
    }

    async fn delete(&self, hash: &str) -> Result<()> {
        lock(&self.state).retain(|s| s.hash != hash);
        Ok(())
    }

    async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64> {
        let mut st = lock(&self.state);
        let was = st.len();
        st.retain(|s| s.expires_at > now);
        Ok((was - st.len()) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite;

    #[tokio::test]
    async fn passes_contract_suite() {
        suite::admin_sessions(&MemAdminSessions::new()).await;
    }
}
