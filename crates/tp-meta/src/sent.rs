//! Запись об отправленном на PostgreSQL (META-86, CTR-94; CONTRACTS.md#Reply; решение 125 в).
//!
//! Таблица `sent_log` (миграция 0002): метка уникальна в инсталляции (`PRIMARY KEY (tag)`, повтор
//! постановки в очередь — та же запись), `message_id_hash` — SHA-256 канонического Message-ID клиента
//! (индекс по организации и хэшу, свежие первыми), адресаты — массив с индексом GIN, RLS по `tenant_id`.
//! Содержимого писем нет. Очистка [`SentLog::purge_before`] — порциями по индексу времени в системной
//! транзакции (`app.all_tenants`), по всем организациям — роль maintenance; срок задаёт вызывающий
//! (`smtp.reply.max_age` секции `smtp`, по умолчанию 30 суток). Момент отправки хранится с точностью
//! до микросекунды: повторная запись той же метки сравнивается с усечённым значением.

use async_trait::async_trait;
use sqlx::FromRow;
use time::OffsetDateTime;
use tp_contracts::reply::{MessageIdHash, SentLog, SentRecord};
use tp_contracts::{AccountId, Error, Result, TenantId, ThreadId};
use uuid::Uuid;

use crate::PgMeta;
use crate::pool::{with_system, with_tenant};
use crate::schema::db_err;

/// Размер порции очистки (`purge_before`): короткие транзакции, долгих блокировок нет.
const PURGE_PORTION: i64 = 10_000;

#[derive(FromRow)]
struct SentRow {
    tenant_id: Uuid,
    account_id: Uuid,
    tag: Vec<u8>,
    message_id_hash: Vec<u8>,
    recipients: Vec<String>,
    thread_id: Option<Uuid>,
    sent_at: OffsetDateTime,
}

impl SentRow {
    fn into_record(self) -> Result<SentRecord> {
        Ok(SentRecord {
            tenant: TenantId::from_uuid(self.tenant_id),
            account: AccountId::from_uuid(self.account_id),
            tag: self.tag,
            message_id_hash: MessageIdHash(
                self.message_id_hash
                    .try_into()
                    .map_err(|_| Error::internal("длина message_id_hash не 32 байта"))?,
            ),
            recipients: self.recipients,
            thread: self.thread_id.map(ThreadId::from_uuid),
            sent_at: self.sent_at,
        })
    }
}

/// Момент с точностью до микросекунды (хранение `timestamptz`): повторная запись сравнивается без
/// расхождений на наносекундах.
fn truncate_micros(at: OffsetDateTime) -> Result<OffsetDateTime> {
    let micros = at.nanosecond() / 1_000 * 1_000;
    at.replace_nanosecond(micros)
        .map_err(|_| Error::invalid("момент отправки вне диапазона"))
}

impl PgMeta {
    /// Удаляет записи старше `before` (по всем организациям) — очистка порциями ([`PURGE_PORTION`]) по
    /// индексу `sent_log_purge`; каждая порция — отдельная системная транзакция. Возвращает число удалённых.
    async fn purge_portions(&self, before: OffsetDateTime) -> Result<usize> {
        let mut total: usize = 0;
        loop {
            let deleted: u64 = with_system(&self.pool, move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "DELETE FROM sent_log WHERE ctid IN (
                             SELECT ctid FROM sent_log WHERE sent_at < $1 LIMIT $2)",
                    )
                    .bind(before)
                    .bind(PURGE_PORTION)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)
                    .map(|r| r.rows_affected())
                })
            })
            .await?;
            let deleted = usize::try_from(deleted).unwrap_or(0);
            total += deleted;
            if (deleted as i64) < PURGE_PORTION {
                return Ok(total);
            }
        }
    }
}

#[async_trait]
impl SentLog for PgMeta {
    async fn record(&self, record: SentRecord) -> Result<()> {
        record.validate()?;
        let record = SentRecord {
            sent_at: truncate_micros(record.sent_at)?,
            ..record
        };
        let tenant = record.tenant;
        // Метка уникальна, запись с ней идемпотентна: повтор над Failover — «идемпотентная по сути»
        // (META-40), как upsert по значению. Данные — владеемая копия на попытку (замыкания
        // `with_tenant` живут произвольно долго — HRTB по соединению).
        self.rewrite(move || {
            let record = record.clone();
            async move {
                with_tenant(&self.pool, tenant, move |tx| {
                    Box::pin(async move {
                        // RLS видит только записи своей организации; та же метка с тем же содержимым —
                        // повтор постановки в очередь.
                        let prev: Option<SentRow> = sqlx::query_as(
                            "SELECT tenant_id, account_id, tag, message_id_hash, recipients, thread_id, sent_at
                             FROM sent_log WHERE tag = $1",
                        )
                        .bind(&record.tag)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(db_err)?;
                        if let Some(prev) = prev {
                            return if prev.into_record()? == record {
                                Ok(())
                            } else {
                                Err(Error::Conflict)
                            };
                        }
                        // Метка другой организации ограничением уникальности не видна через RLS —
                        // конфликт обнаруживает INSERT (`ON CONFLICT (tag)`).
                        let inserted = sqlx::query(
                            "INSERT INTO sent_log (tenant_id, account_id, tag, message_id_hash, recipients,
                                                   thread_id, sent_at)
                             VALUES ($1, $2, $3, $4, $5, $6, $7)
                             ON CONFLICT (tag) DO NOTHING",
                        )
                        .bind(tenant.as_uuid())
                        .bind(record.account.as_uuid())
                        .bind(&record.tag)
                        .bind(&record.message_id_hash.0[..])
                        .bind(&record.recipients)
                        .bind(record.thread.map(|t| *t.as_uuid()))
                        .bind(record.sent_at)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?
                        .rows_affected();
                        if inserted == 0 {
                            return Err(Error::Conflict);
                        }
                        Ok(())
                    })
                })
                .await
            }
        })
        .await
    }

    async fn by_tag(&self, tenant: TenantId, tag: &[u8]) -> Result<Option<SentRecord>> {
        let tag = tag.to_vec();
        self.idempotent(move || {
            let tag = tag.clone();
            async move {
                let row: Option<SentRow> = with_tenant(&self.pool, tenant, move |tx| {
                    Box::pin(async move {
                        sqlx::query_as(
                            "SELECT tenant_id, account_id, tag, message_id_hash, recipients, thread_id, sent_at
                             FROM sent_log WHERE tenant_id = $1 AND tag = $2",
                        )
                        .bind(tenant.as_uuid())
                        .bind(&tag)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(db_err)
                    })
                })
                .await?;
                match row {
                    Some(row) => Ok(Some(row.into_record()?)),
                    None => Ok(None),
                }
            }
        })
        .await
    }

    async fn by_message_id_hash(
        &self,
        tenant: TenantId,
        hash: &MessageIdHash,
    ) -> Result<Vec<SentRecord>> {
        let hash = *hash;
        self.idempotent(move || async move {
            let rows: Vec<SentRow> = with_tenant(&self.pool, tenant, move |tx| {
                Box::pin(async move {
                    sqlx::query_as(
                        "SELECT tenant_id, account_id, tag, message_id_hash, recipients, thread_id, sent_at
                         FROM sent_log WHERE tenant_id = $1 AND message_id_hash = $2
                         ORDER BY sent_at DESC",
                    )
                    .bind(tenant.as_uuid())
                    .bind(&hash.0[..])
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(db_err)
                })
            })
            .await?;
            rows.into_iter().map(|r| r.into_record()).collect()
        })
        .await
    }

    async fn purge_before(&self, before: OffsetDateTime) -> Result<usize> {
        // Число удалённых при повторе — только оставшиеся (META-40), как `purge_events`.
        self.rewrite(|| self.purge_portions(before)).await
    }
}
