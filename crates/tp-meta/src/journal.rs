//! Индекс журнала переписки на PostgreSQL (META-88; CONTRACTS.md#Journal; SRS 4.9, CTR-97).
//!
//! Схема `journal` (базовая миграция): `entries` — конверты записей с хеш-цепочкой
//! `hash = sha256(prev_hash ‖ canonical)` — SHA-256 считает PostgreSQL (`sha256(bytea)`), образ входа
//! фиксирует контракт ([`tp_contracts::journal::chain_input`]); `canonical` хранится в строке, поэтому
//! цепочка проверяется чистым SQL (thepost doctor, внешний аудитор) вместе с согласованностью конверта
//! строки с её каноническим представлением (`journal.tp_consistent`) — подмена любого столбца записи
//! видна проверке. Таблица только на добавление (триггер
//! `tp_append_only`, как журнал аудита); очистка — только функцией `tp_journal_clear` при
//! восстановлении индекса. `rules` — правила журналирования организации.
//!
//! Письма целиком — в хранилище записей ([`JournalRecords`], полоса blob BLOB-18): `append`
//! двухфазный — сначала запись в бакет (идемпотентна, вне транзакции БД — обращения к BLOB в открытой
//! транзакции запрещены), затем строка индекса по ключу `JournalId` (повтор после обрыва во время
//! COMMIT — та же строка); при обрыве между фазами индекс чинит [`JournalStore::restore_index`].
//! Порядок цепочки — `seq` организации, добавления сериализует рекомендательная блокировка
//! организации. Поиск — порядок (`at`, `id`) по индексам; выгрузка — из хранилища записей по ссылке.
//! Доступ — токен [`JournalAudit`] (Admin API), транзакции организации (RLS); пользователи и
//! администраторы правил записи индекса не видят.

use std::sync::Arc;

use async_trait::async_trait;
use sqlx::PgConnection;
use time::OffsetDateTime;
use tp_contracts::Bytes;
use tp_contracts::ids::{BlobHash, JournalId, TenantId};
use tp_contracts::journal::{
    ChainReport, GENESIS_HASH, JournalAudit, JournalCursor, JournalDirection, JournalEntry,
    JournalPage, JournalQuery, JournalRecord, JournalRecords, JournalRule, JournalScope,
    JournalStore, journal_eml,
};
use tp_contracts::{Error, Result};
use uuid::Uuid;

use crate::PgMeta;
use crate::pool::{with_system, with_tenant};
use crate::schema::{db_err, to_u64};

/// Блокировка порядка цепочки организации до конца транзакции: `seq` и `prev_hash` выбираются под ней,
/// поэтому записи цепочки видны строго по порядку (как добавления журнала аудита).
const ORDER_LOCK: &str =
    "SELECT pg_advisory_xact_lock(hashtextextended('thepost:journal:' || $1, 0))";

/// Строка индекса для добавления: конверт, ключи поиска (нижний регистр ASCII), ссылка на запись
/// хранилища и каноническое представление записи (образ хеша).
struct EntryInsert {
    id: JournalId,
    sender: String,
    sender_key: String,
    recipients: Vec<String>,
    rcpt_keys: Vec<String>,
    message_id: Option<String>,
    at: OffsetDateTime,
    rule: String,
    storage: String,
    canonical: String,
}

impl EntryInsert {
    /// Строка добавления из записи; каноническое представление — UTF-8 (serde_json). Ключи поиска —
    /// адреса в нижнем регистре (как `delivery_log`: считает записывающий, не SQL).
    fn of(id: JournalId, record: &JournalRecord, storage: String) -> Result<Self> {
        Ok(EntryInsert {
            id,
            sender: record.sender.clone(),
            sender_key: record.sender.to_lowercase(),
            recipients: record.recipients.clone(),
            rcpt_keys: record.recipients.iter().map(|a| a.to_lowercase()).collect(),
            message_id: record.message_id.clone(),
            at: record.at,
            rule: record.rule.clone(),
            storage,
            canonical: String::from_utf8(record.canonical())
                .map_err(|_| Error::internal("journal: канонический JSON не utf-8"))?,
        })
    }
}

/// Строка индекса для чтения (поиск).
#[derive(sqlx::FromRow)]
struct EntryRow {
    id: Uuid,
    sender: String,
    recipients: Vec<String>,
    message_id: Option<String>,
    at: OffsetDateTime,
    rule: String,
    hash: Vec<u8>,
}

impl EntryRow {
    /// Запись индекса с хешем цепочки.
    fn entry(self, tenant: TenantId) -> Result<JournalEntry> {
        let hash: [u8; 32] = self
            .hash
            .try_into()
            .map_err(|_| Error::internal("journal.entries: хеш не 32 байта"))?;
        Ok(JournalEntry {
            id: JournalId::from_uuid(self.id),
            record: JournalRecord {
                tenant,
                sender: self.sender,
                recipients: self.recipients,
                message_id: self.message_id,
                at: self.at,
                rule: self.rule,
            },
            hash: BlobHash(hash),
        })
    }
}

/// Хеш из 32 байтов столбца.
fn hash32(v: Vec<u8>) -> Result<[u8; 32]> {
    v.try_into()
        .map_err(|_| Error::internal("journal.entries: хеш не 32 байта"))
}

/// Индекс журнала на PostgreSQL: [`JournalStore`] поверх схемы `journal` и хранилища записей
/// ([`JournalRecords`]). Клон разделяет пул (`PgMeta` клонируется дешево) и хранилище записей.
#[derive(Clone)]
pub struct PgJournal {
    meta: PgMeta,
    records: Arc<dyn JournalRecords>,
}

impl std::fmt::Debug for PgJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PgJournal").finish_non_exhaustive()
    }
}

impl PgJournal {
    /// Индекс над контуром метаданных с хранилищем записей журнала (бакет, BLOB-18).
    pub fn new(meta: PgMeta, records: Arc<dyn JournalRecords>) -> Self {
        Self { meta, records }
    }

    /// Число записей индекса организации (системная транзакция).
    async fn indexed(&self, tenant: TenantId) -> Result<u64> {
        self.meta
            .idempotent(|| {
                with_system(self.meta.pool(), move |tx| {
                    Box::pin(async move {
                        sqlx::query_scalar(
                            "SELECT count(*) FROM journal.entries WHERE tenant_id = $1",
                        )
                        .bind(*tenant.as_uuid())
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db_err)
                        .and_then(to_u64)
                    })
                })
            })
            .await
    }

    /// Правила журналирования организации (области, направления, состояние) по возрастанию
    /// идентификаторов; задаются [`Self::set_rule`].
    pub async fn rules(&self, tenant: TenantId) -> Result<Vec<JournalRule>> {
        let rows: Vec<RuleRow> = self
            .meta
            .idempotent(|| {
                with_tenant(self.meta.pool(), tenant, move |tx| {
                    Box::pin(async move {
                        sqlx::query_as(
                            "SELECT id, scope_kind, group_id, account_id, direction, enabled
                             FROM journal.rules WHERE tenant_id = $1 ORDER BY id COLLATE \"C\"",
                        )
                        .bind(*tenant.as_uuid())
                        .fetch_all(&mut *tx)
                        .await
                        .map_err(db_err)
                    })
                })
            })
            .await?;
        rows.into_iter().map(|r| r.rule(tenant)).collect()
    }

    /// Задаёт (или заменяет) правило журналирования организации: замена целиком по идентификатору —
    /// повтор после обрыва во время COMMIT даёт то же состояние.
    pub async fn set_rule(&self, rule: &JournalRule) -> Result<()> {
        rule.validate()?;
        let (scope_kind, group_id, account_id) = scope_parts(&rule.scope);
        let tenant = rule.tenant;
        let (id, direction, enabled) = (rule.id.clone(), rule.direction, rule.enabled);
        self.meta
            .rewrite(|| {
                with_tenant(self.meta.pool(), tenant, move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO journal.rules
                                 (tenant_id, id, scope_kind, group_id, account_id, direction, enabled)
                             VALUES ($1, $2, $3, $4, $5, $6, $7)
                             ON CONFLICT (tenant_id, id) DO UPDATE SET
                                 scope_kind = excluded.scope_kind, group_id = excluded.group_id,
                                 account_id = excluded.account_id, direction = excluded.direction,
                                 enabled = excluded.enabled, updated_at = now()",
                        )
                        .bind(*tenant.as_uuid())
                        .bind(&id)
                        .bind(scope_kind)
                        .bind(group_id)
                        .bind(account_id)
                        .bind(direction_str(direction))
                        .bind(enabled)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                        Ok(())
                    })
                })
            })
            .await
    }

    /// Удаляет правило (нет правила — не ошибка). Записи индекса правило не трогают: журнал
    /// неизменяем, изменение правила действует на будущие письма.
    pub async fn delete_rule(&self, tenant: TenantId, id: &str) -> Result<()> {
        let id = id.to_owned();
        self.meta
            .rewrite(|| {
                with_tenant(self.meta.pool(), tenant, move |tx| {
                    Box::pin(async move {
                        sqlx::query("DELETE FROM journal.rules WHERE tenant_id = $1 AND id = $2")
                            .bind(*tenant.as_uuid())
                            .bind(&id)
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                        Ok(())
                    })
                })
            })
            .await
    }
}

/// Столбцы правила в `journal.rules`.
#[derive(sqlx::FromRow)]
struct RuleRow {
    id: String,
    scope_kind: String,
    group_id: Option<Uuid>,
    account_id: Option<Uuid>,
    direction: String,
    enabled: bool,
}

impl RuleRow {
    /// Правило контракта; неизвестный вид области или направления — повреждение схемы (Internal).
    fn rule(self, tenant: TenantId) -> Result<JournalRule> {
        let scope = match (self.scope_kind.as_str(), self.group_id, self.account_id) {
            ("org", None, None) => JournalScope::Org,
            ("group", Some(g), None) => JournalScope::Group(tp_contracts::GroupId::from_uuid(g)),
            ("mailbox", None, Some(a)) => {
                JournalScope::Mailbox(tp_contracts::AccountId::from_uuid(a))
            }
            _ => return Err(Error::internal("journal.rules: повреждена область правила")),
        };
        Ok(JournalRule {
            id: self.id,
            tenant,
            scope,
            direction: direction_of(&self.direction)?,
            enabled: self.enabled,
        })
    }
}

/// Область правила → столбцы `journal.rules`.
fn scope_parts(scope: &JournalScope) -> (&'static str, Option<Uuid>, Option<Uuid>) {
    match scope {
        JournalScope::Org => ("org", None, None),
        JournalScope::Group(g) => ("group", Some(*g.as_uuid()), None),
        JournalScope::Mailbox(a) => ("mailbox", None, Some(*a.as_uuid())),
    }
}

fn direction_str(d: JournalDirection) -> &'static str {
    match d {
        JournalDirection::In => "in",
        JournalDirection::Out => "out",
        JournalDirection::Both => "both",
    }
}

fn direction_of(s: &str) -> Result<JournalDirection> {
    match s {
        "in" => Ok(JournalDirection::In),
        "out" => Ok(JournalDirection::Out),
        "both" => Ok(JournalDirection::Both),
        _ => Err(Error::internal(
            "journal.rules: повреждено направление правила",
        )),
    }
}

/// Позиция страницы поиска (как курсор in-memory хранилища: `<наносекунды>|<id>`); некорректная —
/// `Error::Invalid`.
fn cursor(at: OffsetDateTime, id: JournalId) -> JournalCursor {
    JournalCursor(format!("{}|{id}", at.unix_timestamp_nanos()))
}

fn parse_cursor(c: &JournalCursor) -> Result<(OffsetDateTime, JournalId)> {
    let bad = || Error::invalid("journal: bad cursor");
    let Some((nanos, id)) = c.0.split_once('|') else {
        return Err(bad());
    };
    let at = OffsetDateTime::from_unix_timestamp_nanos(nanos.parse().map_err(|_| bad())?)
        .map_err(|_| bad())?;
    Ok((at, id.parse().map_err(|_| bad())?))
}

/// Добавление строки индекса в открытой транзакции организации (под блокировкой порядка): `seq` —
/// следующий за последней записью, `prev_hash` — хеш последней записи (у первой — GENESIS), хеш —
/// SHA-256 в PostgreSQL от `chain_input`.
async fn insert_entry(tx: &mut PgConnection, tenant: TenantId, e: &EntryInsert) -> Result<()> {
    sqlx::query(ORDER_LOCK)
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO journal.entries
             (tenant_id, seq, id, sender, sender_key, recipients, rcpt_keys,
              message_id, at, rule, storage, canonical, prev_hash, hash)
         SELECT $1, p.seq, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, p.prev,
                sha256(p.prev || convert_to($12, 'UTF8'))
         FROM (SELECT coalesce((SELECT max(seq) FROM journal.entries WHERE tenant_id = $1), 0) + 1
                       AS seq,
                      coalesce((SELECT hash FROM journal.entries WHERE tenant_id = $1
                                ORDER BY seq DESC LIMIT 1), $13::bytea) AS prev) p",
    )
    .bind(*tenant.as_uuid())
    .bind(*e.id.as_uuid())
    .bind(&e.sender)
    .bind(&e.sender_key)
    .bind(&e.recipients)
    .bind(&e.rcpt_keys)
    .bind(&e.message_id)
    .bind(e.at)
    .bind(&e.rule)
    .bind(&e.storage)
    .bind(&e.canonical)
    .bind(e.canonical.as_str())
    .bind(GENESIS_HASH.as_bytes().to_vec())
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Строка уже в индексе (повтор добавления после обрыва во время COMMIT) — тот же идентификатор.
async fn committed_entry(
    tx: &mut PgConnection,
    tenant: TenantId,
    id: JournalId,
) -> Result<Option<JournalId>> {
    let present: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM journal.entries WHERE tenant_id = $1 AND id = $2")
            .bind(*tenant.as_uuid())
            .bind(*id.as_uuid())
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    Ok(present.map(|_| id))
}

/// Пересборка строк индекса из хранилища записей в системной транзакции (под блокировкой порядка):
/// по строке за раз — хеш цепочки считает SQL от хеша предыдущей строки; `start` — номер первой
/// вставляемой строки, `prev` — хеш предыдущей (GENESIS при полной пересборке).
async fn rebuild_entries(
    tx: &mut PgConnection,
    tenant: TenantId,
    rows: &[(JournalId, JournalRecord, String)],
    start: i64,
    prev: [u8; 32],
) -> Result<()> {
    let mut seq = start;
    let mut prev = prev.to_vec();
    for (id, record, storage) in rows {
        let canonical = String::from_utf8(record.canonical())
            .map_err(|_| Error::internal("journal: канонический JSON не utf-8"))?;
        let hash: Vec<u8> =
            sqlx::query_scalar("SELECT sha256($1::bytea || convert_to($2, 'UTF8'))")
                .bind(&prev)
                .bind(canonical.as_str())
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;
        sqlx::query(
            "INSERT INTO journal.entries
                 (tenant_id, seq, id, sender, sender_key, recipients, rcpt_keys, message_id, at,
                  rule, storage, canonical, prev_hash, hash)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(*tenant.as_uuid())
        .bind(seq)
        .bind(*id.as_uuid())
        .bind(&record.sender)
        .bind(record.sender.to_lowercase())
        .bind(&record.recipients)
        .bind(
            record
                .recipients
                .iter()
                .map(|a| a.to_lowercase())
                .collect::<Vec<_>>(),
        )
        .bind(&record.message_id)
        .bind(record.at)
        .bind(&record.rule)
        .bind(storage)
        .bind(&canonical)
        .bind(&prev)
        .bind(&hash)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
        prev = hash;
        seq += 1;
    }
    Ok(())
}

#[async_trait]
impl JournalStore for PgJournal {
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
        let id = JournalId::new();
        // Фаза 1 — запись в бакет хранилища записей: идемпотентна, вне транзакции БД.
        let storage = self.records.put(id, record, message).await?;
        let entry = EntryInsert::of(id, record, storage)?;
        // Фаза 2 — строка индекса по ключу id: повтор после обрыва во время COMMIT — та же строка.
        let tenant = record.tenant;
        self.meta
            .keyed(
                tenant,
                |tx| {
                    let entry = &entry;
                    Box::pin(async move {
                        insert_entry(tx, tenant, entry).await?;
                        Ok(id)
                    })
                },
                |tx| {
                    let id = id;
                    Box::pin(committed_entry(tx, tenant, id))
                },
            )
            .await?;
        Ok(id)
    }

    async fn search(&self, _cap: &JournalAudit, query: &JournalQuery) -> Result<JournalPage> {
        query.validate()?;
        let after = match &query.after {
            Some(c) => Some(parse_cursor(c)?),
            None => None,
        };
        let sender = query.sender.as_deref().map(|s| s.to_lowercase());
        let recipient = query.recipient.as_deref().map(|s| s.to_lowercase());
        let (message_id, rule, since, until) =
            (&query.message_id, &query.rule, query.since, query.until);
        let tenant = query.tenant;
        let limit = query.limit;
        let rows: Vec<EntryRow> = self
            .meta
            .idempotent(|| {
                let (sender, recipient) = (sender.clone(), recipient.clone());
                let (message_id, rule) = (message_id.clone(), rule.clone());
                with_tenant(self.meta.pool(), tenant, move |tx| {
                    Box::pin(async move {
                        sqlx::query_as(
                            "SELECT id, sender, recipients, message_id, at, rule, hash
                             FROM journal.entries
                             WHERE tenant_id = $1
                               AND ($2::text IS NULL OR sender_key = $2)
                               AND ($3::text IS NULL OR $3 = ANY(rcpt_keys))
                               AND ($4::text IS NULL OR message_id = $4)
                               AND ($5::text IS NULL OR rule = $5)
                               AND ($6::timestamptz IS NULL OR at >= $6)
                               AND ($7::timestamptz IS NULL OR at < $7)
                               AND ($8::timestamptz IS NULL OR (at, id) > ($8::timestamptz, $9::uuid))
                             ORDER BY at, id
                             LIMIT $10",
                        )
                        .bind(*tenant.as_uuid())
                        .bind(sender)
                        .bind(recipient)
                        .bind(message_id)
                        .bind(rule)
                        .bind(since)
                        .bind(until)
                        .bind(after.map(|(at, _)| at))
                        .bind(after.map(|(_, id)| *id.as_uuid()))
                        .bind(i64::try_from(limit).unwrap_or(i64::MAX).saturating_add(1))
                        .fetch_all(&mut *tx)
                        .await
                        .map_err(db_err)
                    })
                })
            })
            .await?;
        let has_more = rows.len() > limit;
        let entries: Vec<JournalEntry> = rows
            .into_iter()
            .take(limit)
            .map(|r| r.entry(tenant))
            .collect::<Result<_>>()?;
        let next = has_more.then(|| {
            entries
                .last()
                .map(|e| cursor(e.record.at, e.id))
                .expect("полная страница — с курсором")
        });
        Ok(JournalPage { entries, next })
    }

    async fn export(&self, _cap: &JournalAudit, tenant: TenantId, id: JournalId) -> Result<Bytes> {
        // Конверт и письмо — из хранилища записей по ссылке записи; чужой организации записи не видны.
        let (record, message) = self.records.read(id).await?;
        if record.tenant != tenant {
            return Err(Error::NotFound);
        }
        journal_eml(&record, &message)
    }

    async fn verify_chain(&self, _cap: &JournalAudit, tenant: TenantId) -> Result<ChainReport> {
        let (records, broken): (i64, Option<Uuid>) = self
            .meta
            .idempotent(|| {
                with_tenant(self.meta.pool(), tenant, move |tx| {
                    Box::pin(async move {
                        sqlx::query_as(
                            "WITH RECURSIVE walk AS (
                                 (SELECT e.seq, e.id, e.hash,
                                         (e.hash
                                              <> sha256($2::bytea || convert_to(e.canonical, 'UTF8'))
                                          OR e.prev_hash <> $2::bytea
                                          OR NOT journal.tp_consistent(e)) AS broken
                                  FROM journal.entries e
                                  WHERE e.tenant_id = $1 ORDER BY e.seq LIMIT 1)
                               UNION ALL
                                 (SELECT n.seq, n.id, n.hash,
                                         (n.hash
                                              <> sha256(w.hash || convert_to(n.canonical, 'UTF8'))
                                          OR n.prev_hash <> w.hash
                                          OR NOT journal.tp_consistent(n)) AS broken
                                  FROM walk w CROSS JOIN LATERAL
                                      (SELECT e.* FROM journal.entries e
                                       WHERE e.tenant_id = $1 AND e.seq > w.seq
                                       ORDER BY e.seq LIMIT 1) n)
                             )
                             SELECT count(*)::bigint AS records,
                                    (SELECT w.id FROM walk w WHERE w.broken
                                     ORDER BY w.seq LIMIT 1) AS broken
                             FROM walk",
                        )
                        .bind(*tenant.as_uuid())
                        .bind(GENESIS_HASH.as_bytes().to_vec())
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db_err)
                    })
                })
            })
            .await?;
        Ok(ChainReport {
            records: to_u64(records)?,
            ok: broken.is_none(),
            broken_at: broken.map(JournalId::from_uuid),
        })
    }

    async fn restore_index(&self, tenant: TenantId) -> Result<u64> {
        // Хранилище записей читается вне транзакции БД (обращения к BLOB в открытой транзакции
        // запрещены); пересборка идемпотентна — повтор после обрыва даёт то же состояние.
        let records = self.records.scan(tenant).await?;
        if records.is_empty() {
            // В хранилище записей организации ничего нет — восстанавливать нечего: индекс не трогаем
            // (записи неизменяемы; пустое хранилище при непустом индексе — расследование, не ремонт).
            return self.indexed(tenant).await;
        }
        self.meta
            .rewrite(|| {
                let records = records.clone();
                with_system(self.meta.pool(), move |tx| {
                    Box::pin(async move {
                        sqlx::query(ORDER_LOCK)
                            .bind(tenant.to_string())
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                        let existing: Vec<Uuid> = sqlx::query_scalar(
                            "SELECT id FROM journal.entries WHERE tenant_id = $1 ORDER BY seq",
                        )
                        .bind(*tenant.as_uuid())
                        .fetch_all(&mut *tx)
                        .await
                        .map_err(db_err)?;
                        // Индекс — префикс хранилища записей (обрыв между фазами записи)?
                        let prefix = existing.len() <= records.len()
                            && existing
                                .iter()
                                .zip(records.iter())
                                .all(|(have, (want, _, _))| *have == *want.as_uuid());
                        if prefix && existing.is_empty() {
                            // Индекс потерян целиком — пересборка с GENESIS (очистка не нужна).
                            rebuild_entries(tx, tenant, &records, 1, GENESIS_HASH.0).await?;
                        } else if prefix && existing.len() < records.len() {
                            // Добираем хвост, продолжая цепочку с хеша последней строки.
                            let prev: [u8; 32] = hash32(
                                sqlx::query_scalar(
                                    "SELECT hash FROM journal.entries WHERE tenant_id = $1
                                     ORDER BY seq DESC LIMIT 1",
                                )
                                .bind(*tenant.as_uuid())
                                .fetch_one(&mut *tx)
                                .await
                                .map_err(db_err)?,
                            )?;
                            let tail = records[existing.len()..].to_vec();
                            rebuild_entries(tx, tenant, &tail, existing.len() as i64 + 1, prev)
                                .await?;
                        } else if !prefix {
                            // Индекс расходится с хранилищем (потерян в середине) — пересборка:
                            // очистка tp_journal_clear, цепочка с GENESIS.
                            sqlx::query("SELECT public.tp_journal_clear($1)")
                                .bind(*tenant.as_uuid())
                                .execute(&mut *tx)
                                .await
                                .map_err(db_err)?;
                            rebuild_entries(tx, tenant, &records, 1, GENESIS_HASH.0).await?;
                        }
                        let count: i64 = sqlx::query_scalar(
                            "SELECT count(*) FROM journal.entries WHERE tenant_id = $1",
                        )
                        .bind(*tenant.as_uuid())
                        .fetch_one(&mut *tx)
                        .await
                        .map_err(db_err)?;
                        to_u64(count)
                    })
                })
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use tp_contracts::Error;
    use tp_contracts::ids::{AccountId, GroupId};
    use tp_contracts::journal::{JournalCursor, JournalDirection, JournalScope};

    #[test]
    fn cursor_roundtrip() {
        let at = time::OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time");
        let id = tp_contracts::JournalId::new();
        let (back_at, back_id) = super::parse_cursor(&super::cursor(at, id)).expect("курсор");
        assert_eq!((back_at, back_id), (at, id));
        for bad in ["мусор", "x|y", "1|2|3"] {
            assert!(matches!(
                super::parse_cursor(&JournalCursor(bad.to_owned())),
                Err(Error::Invalid(_))
            ));
        }
    }

    #[test]
    fn scope_direction_mapping() {
        let (group, mailbox) = (GroupId::new(), AccountId::new());
        assert_eq!(super::scope_parts(&JournalScope::Org), ("org", None, None));
        assert_eq!(
            super::scope_parts(&JournalScope::Group(group)),
            ("group", Some(*group.as_uuid()), None)
        );
        assert_eq!(
            super::scope_parts(&JournalScope::Mailbox(mailbox)),
            ("mailbox", None, Some(*mailbox.as_uuid()))
        );
        for d in [
            JournalDirection::In,
            JournalDirection::Out,
            JournalDirection::Both,
        ] {
            assert_eq!(super::direction_of(super::direction_str(d)).expect("d"), d);
        }
        assert!(super::direction_of("nope").is_err());
    }
}
