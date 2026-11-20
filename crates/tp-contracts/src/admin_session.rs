//! Сессии Admin API (CONTRACTS.md#Auth, CTR-61, решение 77 синка 12.11).
//!
//! Вход администратора (`POST /api/v1/session`: локальный токен `admin init`, пароль, OIDC) выдаёт сессию:
//! значение (`tps_…`) возвращается один раз, в хранилище — только хэш (hex SHA-256 значения, как у
//! [`crate::admin_token::LocalAdminToken`]). Хранилище — основная БД (решение 77, этап 3): сессия видна всем
//! узлам роли `admin` и переживает перезапуск узла. Реализация — `tp-meta` (META-64); in-memory — `tp-testkit`;
//! потребитель — `tp-admin` (ADM-28). Значение, хэш и выпуск ведёт `tp-admin`; хранилище — чтение, удаление
//! и очистка истёкших.

use std::fmt;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::admin_token::is_sha256_hex;
use crate::auth::Principal;
use crate::error::{Error, Result};

/// Сессия Admin API (без значения). `Debug` не показывает хэш.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminSession {
    /// Хэш значения сессии: hex SHA-256 в нижнем регистре (ключ хранилища).
    pub hash: String,
    /// Субъект сессии.
    pub principal: Principal,
    /// Роли Admin API (`installation_admin`, `organization_admin`, `operator`, `auditor`,
    /// `journal_auditor` — как в журнале аудита).
    pub roles: Vec<String>,
    /// Действует до (не включительно).
    pub expires_at: OffsetDateTime,
}

impl fmt::Debug for AdminSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AdminSession")
            .field("principal", &self.principal)
            .field("roles", &self.roles)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl AdminSession {
    /// Проверяет поля: хэш — 64 символа hex в нижнем регистре (SHA-256). Иначе — [`Error::Invalid`].
    pub fn validate(&self) -> Result<()> {
        if !is_sha256_hex(&self.hash) {
            return Err(Error::invalid("хэш сессии — не hex SHA-256"));
        }
        Ok(())
    }
}

/// Хранилище сессий Admin API (основная БД — решение 77). Реализация — `tp-meta`; in-memory — `tp-testkit`.
#[async_trait]
pub trait AdminSessions: Send + Sync + 'static {
    /// Сохраняет сессию. Недопустимый хэш ([`AdminSession::validate`]) — `Error::Invalid`; хэш занят —
    /// `Error::Conflict` (значение сессии случайно, повтор хэша — повтор значения). Истёкший `expires_at`
    /// не запрещён: чтение такую сессию не вернёт.
    async fn put(&self, session: AdminSession) -> Result<()>;

    /// Сессия с хэшем `hash`, если срок не истёк; истёкшая — как отсутствующая: `None` (срок знает только
    /// хранилище: истечение проверяется в момент чтения).
    async fn get(&self, hash: &str) -> Result<Option<AdminSession>>;

    /// Удаляет сессию (выход), в том числе истёкшую; нет — не ошибка (выход идемпотентен).
    async fn delete(&self, hash: &str) -> Result<()>;

    /// Удаляет сессии с `expires_at <= now`; возвращает число удалённых.
    async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64>;
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::*;
    use crate::ids::{AccountId, TenantId};

    fn session() -> AdminSession {
        AdminSession {
            hash: "a".repeat(64),
            principal: Principal {
                tenant: TenantId::DEFAULT,
                account: AccountId::new(),
                login: "admin@example.org".into(),
                groups: BTreeSet::new(),
                scopes: None,
            },
            roles: vec!["organization_admin".into()],
            expires_at: OffsetDateTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn object_safe() {
        fn _store(_: Arc<dyn AdminSessions>) {}
    }

    #[test]
    fn debug_hides_hash() {
        let s = session();
        let shown = format!("{s:?}");
        assert!(!shown.contains(&s.hash), "{shown}");
        assert!(shown.contains("admin@example.org"), "{shown}");
    }

    #[test]
    fn validate() {
        assert_eq!(session().validate(), Ok(()));
        for hash in [
            String::new(),
            "A".repeat(64),
            "a".repeat(63),
            "g".repeat(64),
        ] {
            let s = AdminSession { hash, ..session() };
            assert!(s.validate().is_err());
        }
    }

    #[test]
    fn serde_roundtrip() {
        let s = session();
        let back: AdminSession =
            serde_json::from_slice(&serde_json::to_vec(&s).expect("ser")).expect("de");
        assert_eq!(back, s);
    }
}
