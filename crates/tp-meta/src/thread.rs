//! Беседы на PostgreSQL (META-86, CTR-94; CONTRACTS.md#Thread; решение 125 е–ж; RFC 8621 §3).
//!
//! Таблицы `threads`, `thread_messages`, `thread_keys`, `thread_holds`, `thread_rules` (миграция 0002) —
//! на шарде учётной записи, как письма. Беседы не пересекают учётные записи (одинаковые ключи в разных
//! учётных записях дают разные беседы); привязка письма неизменяема — `threadId` письма не меняется;
//! беседы задним числом не сливаются: письмо, ссылающееся на две, попадает в самую раннюю
//! (`threads.seq`, счётчик `thread_seq`), тем же счётчиком отмечен порядок привязки
//! (`thread_messages.ord`).
//!
//! # Транзакция приёма (MS-21)
//!
//! [`PgMeta::bind_tx`], [`PgMeta::remember_facts_tx`] и чтение применённых политик
//! ([`PgMeta::hold_tx`], [`PgMeta::rule_tx`]) выполняются в транзакции, которой пользуется
//! `MailStore::ingest` («письмо + беседа + применённые политики» — одна транзакция): сбой в середине
//! приёма откатывает и письмо, и привязку — привязка без письма и письмо без беседы не остаются.
//! Отдельного соединения методы не открывают. Изменения бесед учётной записи сериализует
//! рекомендательная блокировка транзакции (`pg_advisory_xact_lock` по учётной записи): условия
//! проверяются до записи, как in-memory (`tp-testkit::MemThreads`).
//!
//! Существующие письма (принятые до внедрения привязки) привязывает фоновая задача
//! [`PgMeta::bind_unthreaded_messages`] по `thread_key` `MessageMeta`, порциями, без простоя; уже
//! привязанное письмо она не переносит.

use async_trait::async_trait;
use sqlx::PgConnection;
use tp_contracts::meta::AccountScope;
use tp_contracts::thread::{
    ThreadFacts, ThreadHold, ThreadLimits, ThreadRule, ThreadStore, join_key,
};
use tp_contracts::{Error, MessageId, Result, ThreadId};
use uuid::Uuid;

use crate::PgMeta;
use crate::schema::{begin, db_err};

/// Наибольшая порция фоновой привязки (писем за одну транзакцию): короткие транзакции, приём писем
/// не блокируется.
const BIND_PORTION_MAX: usize = 500;

/// Сериализует изменения бесед учётной записи в транзакции: условия проверяются до записи
/// (повторная привязка, выбор самой ранней беседы, слияние памяти).
async fn lock_tx(tx: &mut PgConnection, scope: AccountScope) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(scope.account.as_uuid().to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// Привязка письма (по учётной записи); `None` — письма нет в привязках.
async fn thread_of_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    message: MessageId,
) -> Result<Option<ThreadId>> {
    let found: Option<Uuid> = sqlx::query_scalar(
        "SELECT thread_id FROM thread_messages
         WHERE tenant_id = $1 AND account_id = $2 AND message_id = $3",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(message.as_uuid())
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(found.map(ThreadId::from_uuid))
}

/// Самая ранняя из бесед, найденных по ключам присоединения (беседы не сливаются).
async fn earliest_thread_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    keys: &[String],
) -> Result<Option<ThreadId>> {
    if keys.is_empty() {
        return Ok(None);
    }
    let found: Option<Uuid> = sqlx::query_scalar(
        "SELECT tk.thread_id FROM thread_keys tk
         JOIN threads t ON t.tenant_id = tk.tenant_id AND t.account_id = tk.account_id
                       AND t.thread_id = tk.thread_id
         WHERE tk.tenant_id = $1 AND tk.account_id = $2 AND tk.key = ANY($3)
         ORDER BY t.seq, tk.thread_id LIMIT 1",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(keys.to_vec())
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(found.map(ThreadId::from_uuid))
}

/// Новая беседа: идентификатор и порядок создания (`thread_seq`).
async fn create_thread_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    thread: ThreadId,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO threads (tenant_id, account_id, thread_id, seq)
         VALUES ($1, $2, $3, nextval('thread_seq'))",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(thread.as_uuid())
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Привязывает письмо (порядок привязки — `thread_seq`).
async fn bind_message_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    message: MessageId,
    thread: ThreadId,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO thread_messages (tenant_id, account_id, message_id, thread_id, ord)
         VALUES ($1, $2, $3, $4, nextval('thread_seq'))",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(message.as_uuid())
    .bind(thread.as_uuid())
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Регистрирует ключи присоединения за беседой: первая привязка ключа не меняется.
async fn register_keys_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    keys: &[String],
    thread: ThreadId,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO thread_keys (tenant_id, account_id, key, thread_id)
         SELECT $1, $2, k, $4 FROM unnest($3::text[]) AS k
         ON CONFLICT (tenant_id, account_id, key) DO NOTHING",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(keys.to_vec())
    .bind(thread.as_uuid())
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Беседа существует (удержание и действие задают только существующей беседе).
async fn thread_exists_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    thread: ThreadId,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM threads
         WHERE tenant_id = $1 AND account_id = $2 AND thread_id = $3)",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(thread.as_uuid())
    .fetch_one(&mut *tx)
    .await
    .map_err(db_err)?)
}

/// Память беседы (`{}` — пустая память).
async fn read_facts_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    thread: ThreadId,
) -> Result<ThreadFacts> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT facts FROM threads WHERE tenant_id = $1 AND account_id = $2 AND thread_id = $3",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(thread.as_uuid())
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(value
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default())
}

/// Канонические ключи без пустых и повторов (как `MemThreads::bind`).
fn canonical_keys(keys: &[&str]) -> Vec<String> {
    let mut keys: Vec<String> = keys.iter().map(|k| join_key(k)).collect();
    keys.retain(|k| !k.is_empty());
    keys.sort_unstable();
    keys.dedup();
    keys
}

/// Привязка письма к беседе в открытой транзакции (RLS по организации): повторная привязка письма
/// возвращает прежнюю беседу и ничего не меняет; по ключам — самая ранняя из найденных, иначе новая
/// беседа; все ключи (включая собственный Message-ID) регистрируются за беседой.
async fn bind_in_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    message: MessageId,
    keys: &[String],
) -> Result<ThreadId> {
    lock_tx(tx, scope).await?;
    if let Some(thread) = thread_of_tx(tx, scope, message).await? {
        return Ok(thread);
    }
    let thread = match earliest_thread_tx(tx, scope, keys).await? {
        Some(thread) => thread,
        None => {
            let thread = ThreadId::new();
            create_thread_tx(tx, scope, thread).await?;
            thread
        }
    };
    bind_message_tx(tx, scope, message, thread).await?;
    register_keys_tx(tx, scope, keys, thread).await?;
    Ok(thread)
}

/// Дополняет память беседы в открытой транзакции: слияние без повторов, сверх пределов вытесняются
/// самые старые; беседы нет — `NotFound`.
async fn remember_facts_in_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    thread: ThreadId,
    facts: &ThreadFacts,
    limits: &ThreadLimits,
) -> Result<()> {
    lock_tx(tx, scope).await?;
    if !thread_exists_tx(tx, scope, thread).await? {
        return Err(Error::NotFound);
    }
    let merged = read_facts_tx(tx, scope, thread).await?.merge(facts, limits);
    let value = serde_json::to_value(&merged).map_err(|e| Error::internal(e.to_string()))?;
    sqlx::query(
        "UPDATE threads SET facts = $4 WHERE tenant_id = $1 AND account_id = $2 AND thread_id = $3",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(thread.as_uuid())
    .bind(value)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Удержание беседы в открытой транзакции; не установлено — `None`.
async fn read_hold_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    thread: ThreadId,
) -> Result<Option<ThreadHold>> {
    let row: Option<(String, time::OffsetDateTime, String)> = sqlx::query_as(
        "SELECT held_by, held_at, reason FROM thread_holds
         WHERE tenant_id = $1 AND account_id = $2 AND thread_id = $3",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(thread.as_uuid())
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(row.map(|(by, at, reason)| ThreadHold { by, at, reason }))
}

/// Действие по беседе в открытой транзакции; не задано — `None`.
async fn read_rule_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    thread: ThreadId,
) -> Result<Option<ThreadRule>> {
    let value: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT rule FROM thread_rules WHERE tenant_id = $1 AND account_id = $2 AND thread_id = $3",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(thread.as_uuid())
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    value
        .map(|v| serde_json::from_value(v).map_err(|e| Error::internal(e.to_string())))
        .transpose()
}

/// Письма учётной записи без привязки к беседе — кандидаты фоновой привязки (`thread_key` непуст),
/// в порядке приёма, до `limit`.
async fn unthreaded_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    limit: i64,
) -> Result<Vec<(MessageId, String)>> {
    let rows: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT m.message_id, m.thread_key FROM messages m
         WHERE m.tenant_id = $1 AND m.account_id = $2 AND m.thread_key <> ''
           AND NOT EXISTS (SELECT 1 FROM thread_messages tm
                           WHERE tm.tenant_id = m.tenant_id AND tm.account_id = m.account_id
                             AND tm.message_id = m.message_id)
         ORDER BY m.received_at, m.message_id LIMIT $3",
    )
    .bind(scope.tenant.as_uuid())
    .bind(scope.account.as_uuid())
    .bind(limit)
    .fetch_all(&mut *tx)
    .await
    .map_err(db_err)?;
    Ok(rows
        .into_iter()
        .map(|(id, key)| (MessageId::from_uuid(id), key))
        .collect())
}

/// Порция фоновой привязки в открытой транзакции: письма одной цепочки (`thread_key`) — в одну беседу,
/// в порядке приёма; уже привязанные письма не переносятся.
async fn bind_unthreaded_in_tx(
    tx: &mut PgConnection,
    scope: AccountScope,
    limit: usize,
) -> Result<usize> {
    lock_tx(tx, scope).await?;
    let candidates = unthreaded_tx(tx, scope, i64::try_from(limit).unwrap_or(i64::MAX - 1)).await?;
    // Кандидаты идут в порядке приёма: цепочки (равные thread_key) смежны.
    let mut chains: Vec<(String, Vec<MessageId>)> = Vec::new();
    for (message, key) in candidates {
        match chains.last_mut() {
            Some((k, list)) if *k == key => list.push(message),
            _ => chains.push((key, vec![message])),
        }
    }
    let mut bound: usize = 0;
    for (key, messages) in chains {
        let thread = match earliest_thread_tx(tx, scope, &[key.clone()]).await? {
            Some(thread) => thread,
            None => {
                let thread = ThreadId::new();
                create_thread_tx(tx, scope, thread).await?;
                register_keys_tx(tx, scope, &[key], thread).await?;
                thread
            }
        };
        for message in messages {
            bind_message_tx(tx, scope, message, thread).await?;
            bound += 1;
        }
    }
    Ok(bound)
}

impl PgMeta {
    /// Привязывает письмо к беседе в транзакции приёма (MS-21, META-86): работа идёт в открытой
    /// транзакции `tx` (`crate::schema::begin` — RLS по организации), отдельное соединение не
    /// открывается; сбой приёма откатывает и письмо, и привязку. Ключи канонизируются (`join_key`),
    /// пустые пропускаются. Повторная привязка письма возвращает прежнюю беседу и ничего не меняет.
    pub async fn bind_tx(
        &self,
        tx: &mut PgConnection,
        scope: AccountScope,
        message: MessageId,
        keys: &[&str],
    ) -> Result<ThreadId> {
        let keys = canonical_keys(keys);
        bind_in_tx(tx, scope, message, &keys).await
    }

    /// Дополняет память беседы для аномалий в транзакции приёма (MS-21): слияние без повторов, сверх
    /// пределов [`ThreadLimits`] вытесняются самые старые. Беседы нет — `NotFound`.
    pub async fn remember_facts_tx(
        &self,
        tx: &mut PgConnection,
        scope: AccountScope,
        thread: ThreadId,
        facts: &ThreadFacts,
    ) -> Result<()> {
        remember_facts_in_tx(tx, scope, thread, facts, &self.limits()).await
    }

    /// Удержание беседы в транзакции приёма (MS-21); не установлено — `None`.
    pub async fn hold_tx(
        &self,
        tx: &mut PgConnection,
        scope: AccountScope,
        thread: ThreadId,
    ) -> Result<Option<ThreadHold>> {
        read_hold_tx(tx, scope, thread).await
    }

    /// Действие по беседе в транзакции приёма (MS-21); не задано — `None`.
    pub async fn rule_tx(
        &self,
        tx: &mut PgConnection,
        scope: AccountScope,
        thread: ThreadId,
    ) -> Result<Option<ThreadRule>> {
        read_rule_tx(tx, scope, thread).await
    }

    /// Фоновая привязка существующих писем к беседам по `thread_key` `MessageMeta` (META-86): письма
    /// одной цепочки учётной записи попадают в одну беседу, в порядке приёма. Привязывает порцию до
    /// `limit` писем (не больше [`BIND_PORTION_MAX`]) за одну транзакцию и возвращает число привязанных;
    /// `0` — привязывать нечего. Роль фона повторяет вызовы до нуля — без простоя: приём писем и
    /// привязки других учётных записей не блокируются. Уже привязанное письмо не переносится
    /// (привязка неизменяема, RFC 8621 §3).
    pub async fn bind_unthreaded_messages(
        &self,
        scope: AccountScope,
        limit: usize,
    ) -> Result<usize> {
        if limit == 0 {
            return Err(Error::invalid("порция фоновой привязки: не меньше 1"));
        }
        // Порция по значению: повтор привязывает только ещё не привязанные письма (META-40).
        self.rewrite(|| async move {
            let mut tx = begin(&self.box_pool(scope).await?, scope.tenant).await?;
            let bound = bind_unthreaded_in_tx(&mut tx, scope, limit.min(BIND_PORTION_MAX)).await?;
            crate::commits::commit(tx).await?;
            Ok(bound)
        })
        .await
    }
}

#[async_trait]
impl ThreadStore for PgMeta {
    async fn bind(
        &self,
        scope: AccountScope,
        message: MessageId,
        keys: &[&str],
    ) -> Result<ThreadId> {
        let keys = canonical_keys(keys);
        // Привязка письма по его идентификатору: повтор даёт ту же беседу — запись с ключом (META-40).
        let db = self.box_db(scope).await?;
        self.keyed_at(
            &db,
            scope.tenant,
            move |tx| {
                let keys = keys.clone();
                Box::pin(async move { bind_in_tx(tx, scope, message, &keys).await })
            },
            move |tx| Box::pin(async move { thread_of_tx(tx, scope, message).await }),
        )
        .await
    }

    async fn thread_of(&self, scope: AccountScope, message: MessageId) -> Result<Option<ThreadId>> {
        self.idempotent(|| async move {
            let mut tx = begin(&self.box_pool(scope).await?, scope.tenant).await?;
            let found = thread_of_tx(&mut tx, scope, message).await?;
            crate::commits::commit(tx).await?;
            Ok(found)
        })
        .await
    }

    async fn messages(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        limit: usize,
    ) -> Result<Vec<MessageId>> {
        if limit == 0 {
            return Err(Error::invalid("limit беседы: не меньше 1"));
        }
        let n = i64::try_from(limit).unwrap_or(i64::MAX - 1);
        self.idempotent(|| async move {
            let mut tx = begin(&self.box_pool(scope).await?, scope.tenant).await?;
            let rows: Vec<Uuid> = sqlx::query_scalar(
                "SELECT message_id FROM thread_messages
                 WHERE tenant_id = $1 AND account_id = $2 AND thread_id = $3
                 ORDER BY ord LIMIT $4",
            )
            .bind(scope.tenant.as_uuid())
            .bind(scope.account.as_uuid())
            .bind(thread.as_uuid())
            .bind(n)
            .fetch_all(&mut *tx)
            .await
            .map_err(db_err)?;
            crate::commits::commit(tx).await?;
            Ok(rows.into_iter().map(MessageId::from_uuid).collect())
        })
        .await
    }

    async fn remember_facts(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        facts: &ThreadFacts,
    ) -> Result<()> {
        let limits = self.limits();
        // Слияние по значению: повтор добавляет только новое (META-40, «идемпотентные по сути»).
        self.rewrite(|| async move {
            let mut tx = begin(&self.box_pool(scope).await?, scope.tenant).await?;
            remember_facts_in_tx(&mut tx, scope, thread, facts, &limits).await?;
            crate::commits::commit(tx).await?;
            Ok(())
        })
        .await
    }

    async fn facts(&self, scope: AccountScope, thread: ThreadId) -> Result<ThreadFacts> {
        self.idempotent(|| async move {
            let mut tx = begin(&self.box_pool(scope).await?, scope.tenant).await?;
            let facts = read_facts_tx(&mut tx, scope, thread).await?;
            crate::commits::commit(tx).await?;
            Ok(facts)
        })
        .await
    }

    async fn hold(&self, scope: AccountScope, thread: ThreadId) -> Result<Option<ThreadHold>> {
        self.idempotent(|| async move {
            let mut tx = begin(&self.box_pool(scope).await?, scope.tenant).await?;
            let hold = read_hold_tx(&mut tx, scope, thread).await?;
            crate::commits::commit(tx).await?;
            Ok(hold)
        })
        .await
    }

    async fn set_hold(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        hold: Option<ThreadHold>,
    ) -> Result<()> {
        if let Some(hold) = &hold {
            hold.validate()?;
        }
        let hold = &hold;
        // Замена по значению (META-40): повторная установка даёт то же состояние.
        self.rewrite(|| async move {
            let mut tx = begin(&self.box_pool(scope).await?, scope.tenant).await?;
            if !thread_exists_tx(&mut tx, scope, thread).await? {
                return Err(Error::NotFound);
            }
            match hold {
                Some(hold) => {
                    sqlx::query(
                        "INSERT INTO thread_holds (tenant_id, account_id, thread_id, held_by, held_at, reason)
                         VALUES ($1, $2, $3, $4, $5, $6)
                         ON CONFLICT (tenant_id, account_id, thread_id) DO UPDATE
                         SET held_by = EXCLUDED.held_by, held_at = EXCLUDED.held_at,
                             reason = EXCLUDED.reason",
                    )
                    .bind(scope.tenant.as_uuid())
                    .bind(scope.account.as_uuid())
                    .bind(thread.as_uuid())
                    .bind(&hold.by)
                    .bind(hold.at)
                    .bind(&hold.reason)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                }
                None => {
                    sqlx::query(
                        "DELETE FROM thread_holds
                         WHERE tenant_id = $1 AND account_id = $2 AND thread_id = $3",
                    )
                    .bind(scope.tenant.as_uuid())
                    .bind(scope.account.as_uuid())
                    .bind(thread.as_uuid())
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                }
            }
            crate::commits::commit(tx).await?;
            Ok(())
        })
        .await
    }

    async fn rule(&self, scope: AccountScope, thread: ThreadId) -> Result<Option<ThreadRule>> {
        self.idempotent(|| async move {
            let mut tx = begin(&self.box_pool(scope).await?, scope.tenant).await?;
            let rule = read_rule_tx(&mut tx, scope, thread).await?;
            crate::commits::commit(tx).await?;
            Ok(rule)
        })
        .await
    }

    async fn set_rule(
        &self,
        scope: AccountScope,
        thread: ThreadId,
        rule: Option<ThreadRule>,
    ) -> Result<()> {
        let value = match &rule {
            Some(rule) => {
                rule.validate()?;
                Some(serde_json::to_value(rule).map_err(|e| Error::internal(e.to_string()))?)
            }
            None => None,
        };
        let value = &value;
        // Замена целиком по значению (META-40).
        self.rewrite(|| async move {
            let mut tx = begin(&self.box_pool(scope).await?, scope.tenant).await?;
            if !thread_exists_tx(&mut tx, scope, thread).await? {
                return Err(Error::NotFound);
            }
            match value {
                Some(value) => {
                    sqlx::query(
                        "INSERT INTO thread_rules (tenant_id, account_id, thread_id, rule)
                         VALUES ($1, $2, $3, $4)
                         ON CONFLICT (tenant_id, account_id, thread_id) DO UPDATE
                         SET rule = EXCLUDED.rule",
                    )
                    .bind(scope.tenant.as_uuid())
                    .bind(scope.account.as_uuid())
                    .bind(thread.as_uuid())
                    .bind(value)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                }
                None => {
                    sqlx::query(
                        "DELETE FROM thread_rules
                         WHERE tenant_id = $1 AND account_id = $2 AND thread_id = $3",
                    )
                    .bind(scope.tenant.as_uuid())
                    .bind(scope.account.as_uuid())
                    .bind(thread.as_uuid())
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                }
            }
            crate::commits::commit(tx).await?;
            Ok(())
        })
        .await
    }
}
