//! Сессии Admin API на PostgreSQL (META-64; CTR-61, CONTRACTS.md#Auth, решение 77): таблица
//! `admin_sessions`, только хэши значений сессий.
//!
//! Выпуск — в транзакции организации субъекта (RLS). Чтение, удаление (выход) и очистка истёкших —
//! системной транзакцией: Bearer не несёт организацию, хэш уникален по инсталляции. Истёкшая сессия
//! остаётся в таблице (срок знает только хранилище), но чтение её не возвращает; очистка
//! (`purge_expired`) идёт порциями по индексу срока — короткие транзакции, долгих блокировок нет.

use std::collections::BTreeSet;

use async_trait::async_trait;
use sqlx::FromRow;
use sqlx::types::Json;
use time::OffsetDateTime;
use uuid::Uuid;

use tp_contracts::admin_session::{AdminSession, AdminSessions};
use tp_contracts::auth::Principal;
use tp_contracts::{AccountId, Result, TenantId};

use crate::PgMeta;
use crate::schema::{begin, begin_system, db_err};

/// Размер порции очистки (`purge_expired`): короткие транзакции, долгих блокировок нет.
const PURGE_PORTION: i64 = 10_000;

#[derive(FromRow)]
struct Row {
    hash: String,
    tenant_id: Uuid,
    account_id: Uuid,
    login: String,
    groups: Json<BTreeSet<String>>,
    scopes: Option<Json<BTreeSet<String>>>,
    roles: Json<Vec<String>>,
    expires_at: OffsetDateTime,
}

impl From<Row> for AdminSession {
    fn from(r: Row) -> Self {
        AdminSession {
            hash: r.hash,
            principal: Principal {
                tenant: TenantId::from_uuid(r.tenant_id),
                account: AccountId::from_uuid(r.account_id),
                login: r.login,
                groups: r.groups.0,
                scopes: r.scopes.map(|s| s.0),
            },
            roles: r.roles.0,
            expires_at: r.expires_at,
        }
    }
}

impl PgMeta {
    /// Удаляет сессии с `expires_at <= now` — очистка порциями ([`PURGE_PORTION`]) по индексу
    /// `admin_sessions_expires`; каждая порция — отдельная системная транзакция. Возвращает число
    /// удалённых.
    async fn purge_expired_portions(&self, now: OffsetDateTime) -> Result<u64> {
        let mut total: u64 = 0;
        loop {
            let deleted = sqlx::query(
                "DELETE FROM admin_sessions WHERE ctid IN (
                     SELECT ctid FROM admin_sessions WHERE expires_at <= $1 LIMIT $2)",
            )
            .bind(now)
            .bind(PURGE_PORTION)
            .execute(&mut *begin_system(&self.pool).await?)
            .await
            .map_err(db_err)?
            .rows_affected();
            total += deleted;
            if (deleted as i64) < PURGE_PORTION {
                return Ok(total);
            }
        }
    }
}

#[async_trait]
impl AdminSessions for PgMeta {
    async fn put(&self, session: AdminSession) -> Result<()> {
        session.validate()?;
        // Повтор применённой вставки ответил бы `Conflict` (хэш занят) — один раз.
        self.once(async move {
            let mut tx = begin(&self.pool, session.principal.tenant).await?;
            // Занятый хэш — нарушение уникальности (`Conflict`); RLS проверяет организацию субъекта.
            sqlx::query(
                "INSERT INTO admin_sessions (hash, tenant_id, account_id, login, groups, scopes, roles, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&session.hash)
            .bind(session.principal.tenant.as_uuid())
            .bind(session.principal.account.as_uuid())
            .bind(&session.principal.login)
            .bind(Json(&session.principal.groups))
            .bind(session.principal.scopes.as_ref().map(Json))
            .bind(Json(&session.roles))
            .bind(session.expires_at)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            crate::commits::commit(tx).await?;
            Ok(())
        })
        .await
    }

    async fn get(&self, hash: &str) -> Result<Option<AdminSession>> {
        // Истёкшая — как отсутствующая: срок проверяется в момент чтения.
        self.idempotent(|| async move {
            let mut tx = begin_system(&self.pool).await?;
            let row: Option<Row> = sqlx::query_as(
                "SELECT hash, tenant_id, account_id, login, groups, scopes, roles, expires_at
                 FROM admin_sessions WHERE hash = $1 AND expires_at > $2",
            )
            .bind(hash)
            .bind(OffsetDateTime::now_utc())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
            crate::commits::commit(tx).await?;
            Ok(row.map(AdminSession::from))
        })
        .await
    }

    async fn delete(&self, hash: &str) -> Result<()> {
        // Удаление по ключу без возврата удалённого: нет такой — не ошибка (выход идемпотентен).
        self.rewrite(|| async move {
            let mut tx = begin_system(&self.pool).await?;
            sqlx::query("DELETE FROM admin_sessions WHERE hash = $1")
                .bind(hash)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            crate::commits::commit(tx).await?;
            Ok(())
        })
        .await
    }

    async fn purge_expired(&self, now: OffsetDateTime) -> Result<u64> {
        // Число удалённых при повторе — только оставшиеся (META-40), как `purge_events`.
        self.rewrite(|| self.purge_expired_portions(now)).await
    }
}
