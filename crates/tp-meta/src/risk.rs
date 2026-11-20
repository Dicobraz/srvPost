//! Справочник аномалий и TI на PostgreSQL (META-87; CTR-95, CONTRACTS.md#Risk; решение 126).
//!
//! Пакеты поставщика — `risk_packages` (миграция 0003): строка на версию, номер только растёт
//! (ограничение-триггер `risk_packages_version_grows`), один действующий — частичный уникальный
//! индекс; очистка сверх [`RiskConfig::package_keep`] (`risk.package.keep`) прошлых — в той же
//! транзакции, что активация и откат. Политики уровней — `risk_policies`: строка на уровень
//! (установка — `tenant_id IS NULL`, организация — уникальный `tenant_id`), изменения и свои
//! признаки — jsonb по схеме контракта с номером версии схемы; RLS по `tenant_id`, строку установки
//! читают все (как политика доверия). Источники TI и версии списков — `ti_sources` и
//! `ti_list_versions` (уровень установки, без RLS): ключ — не секрет, а ссылка SecretRef; сами
//! записи списков — в BLOB, в строках только метаданные; текущая версия — последняя по `fetched_at`.
//! Учёт обращений MSSP — `ti_usage` (`record_usage` прибавляет `ON CONFLICT … DO UPDATE`, RLS),
//! журнал срабатываний — `risk_hits` (индекс `(tenant, at)`, RLS; удаление старше
//! `risk.hits.retention` — [`PgMeta::purge_risk_hits_before`], роль maintenance).
//!
//! Сведение уровней — функцией контракта [`Catalog::effective`], не SQL. Сигнал `risk_changed`
//! не публикует — его публикует узел после фиксации (как MemRisk в tp-testkit).

use std::time::Duration;

use async_trait::async_trait;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use sqlx::{FromRow, PgConnection, Postgres, Transaction};
use time::{Date, OffsetDateTime};
use tp_contracts::risk::{
    Catalog, DEFAULT_PACKAGE_KEEP, EffectiveCatalog, FeedFormat, HitRecord, HitsQuery, HttpAuth,
    License, ListVersion, Mode, PackageEntry, PackageManifest, PackageState, RiskLevel, RiskPolicy,
    RiskStore, Signal, SourceId, SourceKind, StaleAction, Tenants, TiOrigin, TiSource, Tier, Tlp,
    UsageEntry, Verdict,
};
use tp_contracts::{BlobHash, Error, Result, TenantId};
use uuid::Uuid;

use crate::PgMeta;
use crate::pool::{DbPool, with_system, with_tenant};
use crate::schema::{begin, begin_system, db_err, to_i64, to_u64};

/// Номер версии схемы политик в `risk_policies.schema_version` (как `trust_policies`): политика —
/// jsonb по схеме контракта, новое поле политики — не миграция схемы; несовместимое изменение —
/// новая версия, старая база читается узлом с ошибкой.
const POLICY_SCHEMA_VERSION: i32 = 1;

/// Размер порции очистки журнала срабатываний ([`PgMeta::purge_risk_hits_before`]): короткие
/// транзакции, долгих блокировок нет.
const PURGE_PORTION: i64 = 10_000;

/// Секция конфигурации `meta.risk` — хранение справочника аномалий (META-87).
///
/// ```yaml
/// meta:
///   risk:
///     package_keep: 5
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct RiskConfig {
    /// Сколько прошлых пакетов поставщика хранить для отката (секция `risk.package.keep` узла):
    /// лишние удаляют активация и откат в той же транзакции.
    pub package_keep: usize,
}

impl Default for RiskConfig {
    fn default() -> Self {
        RiskConfig {
            package_keep: DEFAULT_PACKAGE_KEEP,
        }
    }
}

// ---------- Строки ----------

/// Строка `risk_packages` для списка хранимых.
#[derive(FromRow)]
struct PackageRow {
    version: i64,
    state: String,
    report: Option<Json<String>>,
}

impl PackageRow {
    /// Запись списка пакетов; состояние строки — состояние контракта.
    fn into_entry(self) -> Result<PackageEntry> {
        let state = match self.state.as_str() {
            "active" => PackageState::Active,
            "previous" => PackageState::Previous,
            // Отказ проверки (подпись, lint, пробный прогон) — с отчётом; ставит узел (APP-78).
            "rejected" => PackageState::Rejected {
                report: self.report.map(|Json(report)| report).unwrap_or_default(),
            },
            other => {
                return Err(Error::internal(format!(
                    "risk_packages: неизвестное состояние {other:?}"
                )));
            }
        };
        Ok(PackageEntry {
            version: to_u64(self.version)?,
            state,
        })
    }
}

/// Строка `risk_policies`.
#[derive(FromRow)]
struct PolicyRow {
    policy: Json<RiskPolicy>,
    schema_version: i32,
}

impl PolicyRow {
    /// Политика с проверкой версии схемы.
    fn checked(self) -> Result<RiskPolicy> {
        if self.schema_version > POLICY_SCHEMA_VERSION {
            return Err(Error::internal(format!(
                "risk_policies: схема политики {} новее схемы узла ({POLICY_SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        Ok(self.policy.0)
    }
}

/// Строка `ti_sources`.
#[derive(FromRow)]
struct SourceRow {
    id: String,
    tier: String,
    kind: Json<SourceKind>,
    format: Json<FeedFormat>,
    ttl_seconds: i64,
    stale: Json<StaleAction>,
    license: Json<License>,
    tenants: Json<Tenants>,
    secret_ref: Option<String>,
    auth: Json<HttpAuth>,
    origin: String,
}

impl SourceRow {
    /// Источник контракта.
    fn into_source(self) -> Result<TiSource> {
        Ok(TiSource {
            id: id_of(&self.id)?,
            tier: tier_of(&self.tier)?,
            kind: self.kind.0,
            format: self.format.0,
            ttl: Duration::from_secs(u64::try_from(self.ttl_seconds).unwrap_or(u64::MAX)),
            stale: self.stale.0,
            license: self.license.0,
            tenants: self.tenants.0,
            key: self
                .secret_ref
                .map(|r| {
                    r.parse().map_err(|e| {
                        Error::internal(format!("ti_sources: плохая ссылка секрета: {e}"))
                    })
                })
                .transpose()?,
            auth: self.auth.0,
            origin: origin_of(&self.origin)?,
        })
    }
}

/// Строка `ti_list_versions`.
#[derive(FromRow)]
struct ListRow {
    list: String,
    source: String,
    sha256: Vec<u8>,
    blob: String,
    entries: i64,
    fetched_at: OffsetDateTime,
    tlp: Option<Json<Tlp>>,
}

impl ListRow {
    /// Версия списка контракта.
    fn into_version(self) -> Result<ListVersion> {
        Ok(ListVersion {
            list: id_of(&self.list)?,
            source: id_of(&self.source)?,
            sha256: BlobHash(
                self.sha256
                    .try_into()
                    .map_err(|_| Error::internal("ti_list_versions: длина sha256 не 32 байта"))?,
            ),
            blob: self.blob,
            entries: to_u64(self.entries)?,
            fetched_at: self.fetched_at,
            tlp: self.tlp.map(|Json(tlp)| tlp),
        })
    }
}

/// Строка `ti_usage`.
#[derive(FromRow)]
struct UsageRow {
    tenant_id: Uuid,
    day: Date,
    lookups: i64,
    hits: i64,
}

/// Строка `risk_hits`.
#[derive(FromRow)]
struct HitRow {
    message: Vec<u8>,
    signal: String,
    strength: i16,
    weight: i32,
    mode: String,
    at: OffsetDateTime,
}

impl HitRow {
    /// Запись журнала срабатываний организации `tenant`.
    fn into_record(self, tenant: TenantId) -> Result<HitRecord> {
        Ok(HitRecord {
            tenant,
            message: BlobHash(
                self.message
                    .try_into()
                    .map_err(|_| Error::internal("risk_hits: длина message не 32 байта"))?,
            ),
            signal: id_of(&self.signal)?,
            strength: u8::try_from(self.strength)
                .map_err(|_| Error::internal("risk_hits: сила вне u8"))?,
            weight: u16::try_from(self.weight)
                .map_err(|_| Error::internal("risk_hits: вес вне u16"))?,
            mode: mode_of(&self.mode)?,
            at: self.at,
        })
    }
}

// ---------- Значения перечислений в столбцах ----------

/// Идентификатор (признака, списка, источника) из столбца: строки пишет это хранилище после
/// проверки контракта, чужое значение — внутренняя ошибка.
fn id_of<T: std::str::FromStr<Err = Error>>(text: &str) -> Result<T> {
    text.parse()
        .map_err(|e| Error::internal(format!("риск: недопустимый идентификатор в строке: {e}")))
}

fn mode_text(mode: Mode) -> &'static str {
    match mode {
        Mode::Report => "report",
        Mode::Enforce => "enforce",
    }
}

fn mode_of(text: &str) -> Result<Mode> {
    match text {
        "report" => Ok(Mode::Report),
        "enforce" => Ok(Mode::Enforce),
        _ => Err(Error::internal(format!(
            "risk_hits: неизвестный режим {text:?}"
        ))),
    }
}

fn tier_text(tier: Tier) -> &'static str {
    match tier {
        Tier::Bundled => "bundled",
        Tier::CustomerKey => "customer_key",
        Tier::Import => "import",
    }
}

fn tier_of(text: &str) -> Result<Tier> {
    match text {
        "bundled" => Ok(Tier::Bundled),
        "customer_key" => Ok(Tier::CustomerKey),
        "import" => Ok(Tier::Import),
        _ => Err(Error::internal(format!(
            "ti_sources: неизвестный уровень {text:?}"
        ))),
    }
}

fn origin_text(origin: TiOrigin) -> &'static str {
    match origin {
        TiOrigin::Vendor => "vendor",
        TiOrigin::GosSopka => "gossopka",
        TiOrigin::FinCert => "fincert",
        TiOrigin::Own => "own",
    }
}

fn origin_of(text: &str) -> Result<TiOrigin> {
    match text {
        "vendor" => Ok(TiOrigin::Vendor),
        "gossopka" => Ok(TiOrigin::GosSopka),
        "fincert" => Ok(TiOrigin::FinCert),
        "own" => Ok(TiOrigin::Own),
        _ => Err(Error::internal(format!(
            "ti_sources: неизвестное происхождение {text:?}"
        ))),
    }
}

/// TTL источника в секундах для столбца `ttl_seconds`.
fn ttl_seconds(ttl: Duration) -> Result<i64> {
    i64::try_from(ttl.as_secs())
        .map_err(|_| Error::invalid(format!("risk: TTL источника вне bigint: {ttl:?}")))
}

// ---------- Чтения в открытой транзакции ----------

/// Признаки действующего пакета (нет пакета — пусто); таблица уровня установки, читается в любой
/// транзакции.
async fn active_signals(conn: &mut PgConnection) -> Result<Vec<Signal>> {
    let manifest: Option<(Json<PackageManifest>,)> =
        sqlx::query_as("SELECT manifest FROM risk_packages WHERE state = 'active'")
            .fetch_optional(conn)
            .await
            .map_err(db_err)?;
    Ok(manifest.map(|(Json(m),)| m.signals).unwrap_or_default())
}

/// Политика уровня в открытой транзакции; нет строки — `None`. Строку установки читает любая
/// организация (RLS `installation_read`), поэтому база проверки организации — в её же транзакции.
async fn policy_of(conn: &mut PgConnection, level: RiskLevel) -> Result<Option<RiskPolicy>> {
    let row: Option<PolicyRow> = match level {
        RiskLevel::Installation => sqlx::query_as(
            "SELECT policy, schema_version FROM risk_policies WHERE tenant_id IS NULL",
        )
        .fetch_optional(conn)
        .await
        .map_err(db_err)?,
        RiskLevel::Org(t) => {
            sqlx::query_as("SELECT policy, schema_version FROM risk_policies WHERE tenant_id = $1")
                .bind(*t.as_uuid())
                .fetch_optional(conn)
                .await
                .map_err(db_err)?
        }
    };
    row.map(PolicyRow::checked).transpose()
}

/// Транзакция уровня: организация — в контексте своей организации (RLS), установка — системная.
async fn begin_level(pool: &DbPool, level: RiskLevel) -> Result<Transaction<'static, Postgres>> {
    match level {
        RiskLevel::Installation => begin_system(pool).await,
        RiskLevel::Org(t) => begin(pool, t).await,
    }
}

/// Условие строки уровня в `risk_policies`.
fn level_filter(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Installation => "tenant_id IS NULL",
        RiskLevel::Org(_) => "tenant_id = $1",
    }
}

/// Цель `ON CONFLICT` записи уровня — частичный уникальный индекс уровня.
fn level_conflict(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Installation => "((tenant_id IS NULL)) WHERE tenant_id IS NULL",
        RiskLevel::Org(_) => "(tenant_id) WHERE tenant_id IS NOT NULL",
    }
}

/// Делает пакет `version` действующим и удаляет прошлые сверх `keep` — в той же транзакции (решение
/// 126 б). Строки пакета нет — `NotFound`.
async fn switch_active(conn: &mut PgConnection, version: i64, keep: i64) -> Result<()> {
    sqlx::query(
        "UPDATE risk_packages SET state = 'previous' WHERE state = 'active' AND version <> $1",
    )
    .bind(version)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    let switched = sqlx::query("UPDATE risk_packages SET state = 'active' WHERE version = $1")
        .bind(version)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?
        .rows_affected();
    if switched == 0 {
        return Err(Error::NotFound);
    }
    // Прошлые сверх keep: свежейшие остаются, остальные удаляются (в той же транзакции).
    sqlx::query(
        "DELETE FROM risk_packages WHERE state = 'previous' AND version NOT IN (
             SELECT version FROM risk_packages WHERE state = 'previous'
             ORDER BY version DESC LIMIT $1)",
    )
    .bind(keep)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Значение jsonb для записи (сериализация контракта — до транзакции, в ней ошибок разбора нет).
fn jsonb<T: Serialize>(value: &T) -> Result<serde_json::Value> {
    serde_json::to_value(value).map_err(|e| Error::internal(e.to_string()))
}

#[async_trait]
impl RiskStore for PgMeta {
    /// Одним запросом в транзакции организации: действующий пакет, политика установки (строку
    /// установки читают все — RLS `installation_read`) и политика организации; сведение —
    /// [`Catalog::effective`] контракта.
    async fn effective(&self, tenant: TenantId) -> Result<EffectiveCatalog> {
        self.idempotent(|| async move {
            let mut tx = begin(&self.pool, tenant).await?;
            let vendor = active_signals(&mut tx).await?;
            let installation = policy_of(&mut tx, RiskLevel::Installation).await?;
            let org = policy_of(&mut tx, RiskLevel::Org(tenant)).await?;
            crate::commits::commit(tx).await?;
            Ok(Catalog::effective(
                &vendor,
                installation.as_ref(),
                org.as_ref().map(|p| (RiskLevel::Org(tenant), p)),
            ))
        })
        .await
    }

    /// Запись проверенного пакета (ключ — номер версии: повтор над Failover после фиксации — уже
    /// записан): номер больше любого хранимого — иначе ошибка ограничения триггера (`Invalid`),
    /// манифест допустим. Пакет не действующий до [`RiskStore::activate`]; подпись и ссылку на
    /// архив записывает узел (APP-78).
    async fn put_package(&self, manifest: &PackageManifest) -> Result<()> {
        manifest.validate()?;
        let version = to_i64(manifest.version)?;
        let key_id = manifest.key_id.clone();
        let manifest = jsonb(manifest)?;
        self.keyed_system(
            |tx| {
                let manifest = manifest.clone();
                let key_id = key_id.clone();
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO risk_packages (version, manifest, key_id) VALUES ($1, $2, $3)",
                    )
                    .bind(version)
                    .bind(manifest)
                    .bind(key_id)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                    Ok(())
                })
            },
            |tx| {
                Box::pin(async move {
                    let present: Option<i32> =
                        sqlx::query_scalar("SELECT 1 FROM risk_packages WHERE version = $1")
                            .bind(version)
                            .fetch_optional(&mut *tx)
                            .await
                            .map_err(db_err)?;
                    Ok(present.map(|_| ()))
                })
            },
        )
        .await
    }

    /// Активация — запись состояния (не повторяется над Failover, как CAS по версии): номер строго
    /// больше действующего, нет пакета — `NotFound`; прошлые сверх `package_keep` удаляются в той же
    /// транзакции.
    async fn activate(&self, version: u64) -> Result<()> {
        let version = to_i64(version)?;
        let keep = keep_of(self);
        let pool = self.pool.clone();
        self.once(async move {
            with_system(&pool, move |tx| {
                Box::pin(async move {
                    let (target, active): (Option<String>, Option<i64>) = sqlx::query_as(
                        "SELECT (SELECT state FROM risk_packages WHERE version = $1),
                                (SELECT version FROM risk_packages WHERE state = 'active')",
                    )
                    .bind(version)
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(db_err)?;
                    if target.is_none() {
                        return Err(Error::NotFound);
                    }
                    if let Some(active) = active
                        && version <= active
                    {
                        return Err(Error::invalid(format!(
                            "risk: номер пакета {version} не растёт (действующий {active})"
                        )));
                    }
                    switch_active(&mut *tx, version, keep).await
                })
            })
            .await
        })
        .await
    }

    /// Откат на хранимую версию — та же транзакция переключения и очистки (повтор после обрыва во
    /// время COMMIT даёт то же состояние); нет — `NotFound`.
    async fn rollback(&self, version: u64) -> Result<()> {
        let version = to_i64(version)?;
        let keep = keep_of(self);
        self.rewrite(|| async move {
            with_system(&self.pool, move |tx| {
                Box::pin(async move { switch_active(&mut *tx, version, keep).await })
            })
            .await
        })
        .await
    }

    /// Хранимые пакеты по убыванию номера: действующий и не больше `package_keep` прошлых.
    async fn packages(&self) -> Result<Vec<PackageEntry>> {
        self.idempotent(|| async move {
            with_system(&self.pool, |tx| {
                Box::pin(async move {
                    let rows: Vec<PackageRow> = sqlx::query_as(
                        "SELECT version, state, report FROM risk_packages
                                        ORDER BY version DESC",
                    )
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(db_err)?;
                    rows.into_iter().map(PackageRow::into_entry).collect()
                })
            })
            .await
        })
        .await
    }

    /// Политика уровня; не задана — `None`. Чужой организации видна только своя политика (RLS).
    async fn policy(&self, level: RiskLevel) -> Result<Option<RiskPolicy>> {
        self.idempotent(|| async move {
            let mut tx = begin_level(&self.pool, level).await?;
            let out = policy_of(&mut tx, level).await?;
            crate::commits::commit(tx).await?;
            Ok(out)
        })
        .await
    }

    /// Запись уровня целиком (повтор после обрыва во время COMMIT даёт то же состояние): проверка по
    /// действующим значениям уровней ниже и запись — одна транзакция. Пустая политика удаляет уровень.
    async fn set_policy(&self, level: RiskLevel, policy: &RiskPolicy) -> Result<()> {
        let policy = policy.clone();
        self.rewrite(|| {
            let policy = policy.clone();
            async move {
                let mut tx = begin_level(&self.pool, level).await?;
                // База проверки: установка — действующий пакет, организация — с политикой установки
                // (строку установки читают все).
                let vendor = active_signals(&mut tx).await?;
                let base = match level {
                    RiskLevel::Installation => Catalog::effective(&vendor, None, None),
                    RiskLevel::Org(_) => {
                        let inst = policy_of(&mut tx, RiskLevel::Installation).await?;
                        Catalog::effective(&vendor, inst.as_ref(), None)
                    }
                };
                policy.validate(&base, level)?;
                if policy == RiskPolicy::default() {
                    let sql = format!("DELETE FROM risk_policies WHERE {}", level_filter(level));
                    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                    if let RiskLevel::Org(t) = level {
                        q = q.bind(*t.as_uuid());
                    }
                    q.execute(&mut *tx).await.map_err(db_err)?;
                } else {
                    let sql = format!(
                        "INSERT INTO risk_policies (tenant_id, policy, schema_version)
                         VALUES ($1, $2, $3)
                         ON CONFLICT {} DO UPDATE SET
                             policy = excluded.policy, schema_version = excluded.schema_version,
                             updated_at = now()",
                        level_conflict(level)
                    );
                    sqlx::query(sqlx::AssertSqlSafe(sql))
                        .bind(level.tenant().map(|t| *t.as_uuid()))
                        .bind(Json(&policy))
                        .bind(POLICY_SCHEMA_VERSION)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                }
                crate::commits::commit(tx).await?;
                Ok(())
            }
        })
        .await
    }

    /// Удаление уровня по ключу (нет строки — не ошибка): уровень выше и пакет продолжают действовать.
    async fn reset_policy(&self, level: RiskLevel) -> Result<()> {
        self.rewrite(|| async move {
            let mut tx = begin_level(&self.pool, level).await?;
            let sql = format!("DELETE FROM risk_policies WHERE {}", level_filter(level));
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            if let RiskLevel::Org(t) = level {
                q = q.bind(*t.as_uuid());
            }
            q.execute(&mut *tx).await.map_err(db_err)?;
            crate::commits::commit(tx).await?;
            Ok(())
        })
        .await
    }

    /// Источники TI по возрастанию идентификатора (таблица уровня установки).
    async fn sources(&self) -> Result<Vec<TiSource>> {
        self.idempotent(|| async move {
            with_system(&self.pool, |tx| {
                Box::pin(async move {
                    let rows: Vec<SourceRow> = sqlx::query_as(
                        "SELECT id, tier, kind, format, ttl_seconds, stale, license, tenants,
                                secret_ref, auth, origin
                         FROM ti_sources ORDER BY id",
                    )
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(db_err)?;
                    rows.into_iter().map(SourceRow::into_source).collect()
                })
            })
            .await
        })
        .await
    }

    /// Запись или замена источника целиком (повтор — то же состояние): [`TiSource::validate`] до
    /// записи.
    async fn put_source(&self, source: &TiSource) -> Result<()> {
        source.validate()?;
        let ttl = ttl_seconds(source.ttl)?;
        let (kind, format, stale, license, tenants, auth) = (
            jsonb(&source.kind)?,
            jsonb(&source.format)?,
            jsonb(&source.stale)?,
            jsonb(&source.license)?,
            jsonb(&source.tenants)?,
            jsonb(&source.auth)?,
        );
        let id = source.id.as_str().to_owned();
        let tier = tier_text(source.tier);
        let origin = origin_text(source.origin);
        let secret_ref = source.key.as_ref().map(ToString::to_string);
        self.rewrite(|| {
            let id = id.clone();
            let (kind, format, stale, license, tenants, auth) = (
                kind.clone(),
                format.clone(),
                stale.clone(),
                license.clone(),
                tenants.clone(),
                auth.clone(),
            );
            let secret_ref = secret_ref.clone();
            async move {
                with_system(&self.pool, move |tx| {
                    Box::pin(async move {
                        sqlx::query(
                            "INSERT INTO ti_sources (id, tier, kind, format, ttl_seconds, stale,
                                                     license, tenants, secret_ref, auth, origin)
                             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                             ON CONFLICT (id) DO UPDATE SET
                                 tier = excluded.tier, kind = excluded.kind,
                                 format = excluded.format, ttl_seconds = excluded.ttl_seconds,
                                 stale = excluded.stale, license = excluded.license,
                                 tenants = excluded.tenants, secret_ref = excluded.secret_ref,
                                 auth = excluded.auth, origin = excluded.origin",
                        )
                        .bind(id)
                        .bind(tier)
                        .bind(kind)
                        .bind(format)
                        .bind(ttl)
                        .bind(stale)
                        .bind(license)
                        .bind(tenants)
                        .bind(secret_ref)
                        .bind(auth)
                        .bind(origin)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                        Ok(())
                    })
                })
                .await
            }
        })
        .await
    }

    /// Удаление источника (нет — не ошибка); версии списков и учёт остаются (историю показывают).
    async fn delete_source(&self, id: &SourceId) -> Result<()> {
        let id = id.as_str().to_owned();
        self.rewrite(|| {
            let id = id.clone();
            async move {
                with_system(&self.pool, move |tx| {
                    Box::pin(async move {
                        sqlx::query("DELETE FROM ti_sources WHERE id = $1")
                            .bind(id)
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                        Ok(())
                    })
                })
                .await
            }
        })
        .await
    }

    /// Запись версии списка текущей (повтор с теми же значениями — не ошибка): источник должен быть
    /// известен, ссылка на содержимое непустая; `expires_at` — `fetched_at` + TTL источника.
    async fn put_list_version(&self, version: &ListVersion) -> Result<()> {
        if version.blob.is_empty() {
            return Err(Error::invalid("risk: пустая ссылка на содержимое списка"));
        }
        let list = version.list.as_str().to_owned();
        let source = version.source.as_str().to_owned();
        let sha256 = version.sha256.as_bytes().to_vec();
        let blob = version.blob.clone();
        let entries = to_i64(version.entries)?;
        let fetched_at = version.fetched_at;
        let tlp = version.tlp.map(|tlp| jsonb(&tlp)).transpose()?;
        self.rewrite(|| {
            let (list, source, sha256, blob, tlp) = (
                list.clone(),
                source.clone(),
                sha256.clone(),
                blob.clone(),
                tlp.clone(),
            );
            async move {
                with_system(&self.pool, move |tx| {
                    let tlp = tlp.clone();
                    Box::pin(async move {
                        let ttl: Option<i64> =
                            sqlx::query_scalar("SELECT ttl_seconds FROM ti_sources WHERE id = $1")
                                .bind(&source)
                                .fetch_optional(&mut *tx)
                                .await
                                .map_err(db_err)?;
                        let Some(ttl) = ttl else {
                            return Err(Error::invalid(format!(
                                "risk: источник {source} версии списка неизвестен"
                            )));
                        };
                        let expires_at = fetched_at + time::Duration::seconds(ttl);
                        sqlx::query(
                            "INSERT INTO ti_list_versions
                                 (list, source, sha256, blob, entries, fetched_at, expires_at, tlp)
                             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                             ON CONFLICT DO NOTHING",
                        )
                        .bind(list)
                        .bind(&source)
                        .bind(sha256)
                        .bind(blob)
                        .bind(entries)
                        .bind(fetched_at)
                        .bind(expires_at)
                        .bind(tlp)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                        Ok(())
                    })
                })
                .await
            }
        })
        .await
    }

    /// Текущая версия списка — последняя по `fetched_at` (при равенстве — большая `sha256`);
    /// нет — `None`.
    async fn list_current(&self, list: &tp_contracts::risk::ListId) -> Result<Option<ListVersion>> {
        let list = list.as_str().to_owned();
        self.idempotent(|| {
            let list = list.clone();
            async move {
                with_system(&self.pool, move |tx| {
                    Box::pin(async move {
                        let row: Option<ListRow> = sqlx::query_as(
                            "SELECT list, source, sha256, blob, entries, fetched_at, tlp
                             FROM ti_list_versions WHERE list = $1
                             ORDER BY fetched_at DESC, sha256 DESC LIMIT 1",
                        )
                        .bind(list)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(db_err)?;
                        row.map(ListRow::into_version).transpose()
                    })
                })
                .await
            }
        })
        .await
    }

    /// Учёт обращений за текущие сутки UTC организации `tenant` — прибавление (не повторяется над
    /// Failover: повтор после фиксации посчитал бы обращения дважды, как выдача UID).
    async fn record_usage(
        &self,
        source: &SourceId,
        tenant: TenantId,
        lookups: u64,
        hits: u64,
    ) -> Result<()> {
        let source = source.as_str().to_owned();
        let (lookups, hits) = (to_i64(lookups)?, to_i64(hits)?);
        self.once(async move {
            with_tenant(&self.pool, tenant, move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "INSERT INTO ti_usage (source, tenant_id, day, lookups, hits)
                         VALUES ($1, $2, (now() AT TIME ZONE 'UTC')::date, $3, $4)
                         ON CONFLICT (source, tenant_id, day) DO UPDATE
                         SET lookups = ti_usage.lookups + excluded.lookups,
                             hits = ti_usage.hits + excluded.hits",
                    )
                    .bind(source)
                    .bind(*tenant.as_uuid())
                    .bind(lookups)
                    .bind(hits)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                    Ok(())
                })
            })
            .await
        })
        .await
    }

    /// Учёт источника по суткам UTC от `since` включительно (свободное чтение MSSP по всем
    /// организациям — системная транзакция), по возрастанию суток и организаций.
    async fn usage(&self, source: &SourceId, since: OffsetDateTime) -> Result<Vec<UsageEntry>> {
        let source = source.clone();
        self.idempotent(|| {
            let source = source.clone();
            async move {
                with_system(&self.pool, move |tx| {
                    Box::pin(async move {
                        let rows: Vec<UsageRow> = sqlx::query_as(
                            "SELECT tenant_id, day, lookups, hits FROM ti_usage
                             WHERE source = $1 AND day >= ($2 AT TIME ZONE 'UTC')::date
                             ORDER BY day, tenant_id",
                        )
                        .bind(source.as_str())
                        .bind(since)
                        .fetch_all(&mut *tx)
                        .await
                        .map_err(db_err)?;
                        rows.into_iter()
                            .map(
                                |UsageRow {
                                     tenant_id,
                                     day,
                                     lookups,
                                     hits,
                                 }| {
                                    Ok(UsageEntry {
                                        source: source.clone(),
                                        tenant: TenantId::from_uuid(tenant_id),
                                        day: day.with_time(time::Time::MIDNIGHT).assume_utc(),
                                        lookups: to_u64(lookups)?,
                                        hits: to_u64(hits)?,
                                    })
                                },
                            )
                            .collect()
                    })
                })
                .await
            }
        })
        .await
    }

    /// Запись срабатываний вердикта в журнал организации (не повторяется над Failover: повтор
    /// записал бы срабатывания дважды — ключа у записей нет): применённые — `Enforce`, «только
    /// отчёт» — `Report`, момент — транзакции.
    async fn record_hits(
        &self,
        tenant: TenantId,
        message: BlobHash,
        verdict: &Verdict,
    ) -> Result<()> {
        // Порядок записей: применённые прежде «только отчёт» (порядок читает hits).
        let rows: Vec<(Vec<u8>, String, i16, i32, &'static str)> =
            [&verdict.hits, &verdict.report_only]
                .into_iter()
                .zip([mode_text(Mode::Enforce), mode_text(Mode::Report)])
                .flat_map(|(hits, mode)| {
                    hits.iter().map(move |h| {
                        (
                            message.0.to_vec(),
                            h.signal.as_str().to_owned(),
                            i16::from(h.strength),
                            i32::from(h.weight),
                            mode,
                        )
                    })
                })
                .collect();
        self.once(async move {
            with_tenant(&self.pool, tenant, move |tx| {
                Box::pin(async move {
                    for (message, signal, strength, weight, mode) in rows {
                        sqlx::query(
                            "INSERT INTO risk_hits (tenant_id, message, signal, strength, weight, mode)
                             VALUES ($1, $2, $3, $4, $5, $6)",
                        )
                        .bind(*tenant.as_uuid())
                        .bind(message)
                        .bind(signal)
                        .bind(strength)
                        .bind(weight)
                        .bind(mode)
                        .execute(&mut *tx)
                        .await
                        .map_err(db_err)?;
                    }
                    Ok(())
                })
            })
            .await
        })
        .await
    }

    /// Журнал срабатываний организации (свежие первыми, при равном моменте — порядок записи),
    /// не больше `filter.limit`; чужая организация срабатываний другой не видит (условие `tenant_id`
    /// в запросе и RLS).
    async fn hits(&self, tenant: TenantId, filter: &HitsQuery) -> Result<Vec<HitRecord>> {
        filter.validate()?;
        let (signal, message) = (
            filter.signal.as_ref().map(|s| s.as_str().to_owned()),
            filter.message.map(|m| m.0.to_vec()),
        );
        let (since, until) = (filter.since, filter.until);
        let limit = i64::try_from(filter.limit)
            .map_err(|_| Error::invalid("risk: лимит срабатываний вне bigint"))?;
        self.idempotent(|| {
            let signal = signal.clone();
            let message = message.clone();
            async move {
                with_tenant(&self.pool, tenant, move |tx| {
                    Box::pin(async move {
                        let rows: Vec<HitRow> = sqlx::query_as(
                            "SELECT message, signal, strength, weight, mode, at FROM risk_hits
                             WHERE tenant_id = $1
                               AND ($2::text IS NULL OR signal = $2)
                               AND ($3::bytea IS NULL OR message = $3)
                               AND ($4::timestamptz IS NULL OR at >= $4)
                               AND ($5::timestamptz IS NULL OR at < $5)
                             ORDER BY at DESC, ord ASC LIMIT $6",
                        )
                        .bind(*tenant.as_uuid())
                        .bind(signal)
                        .bind(message)
                        .bind(since)
                        .bind(until)
                        .bind(limit)
                        .fetch_all(&mut *tx)
                        .await
                        .map_err(db_err)?;
                        rows.into_iter().map(|r| r.into_record(tenant)).collect()
                    })
                })
                .await
            }
        })
        .await
    }
}

/// `keep` политики пакетов как предел SQL.
fn keep_of(meta: &PgMeta) -> i64 {
    i64::try_from(meta.cfg.risk.package_keep).unwrap_or(i64::MAX)
}

impl PgMeta {
    /// Удаляет срабатывания старше `before` (`risk.hits.retention`) по всем организациям — очистка
    /// порциями ([`PURGE_PORTION`]) по индексу `risk_hits_tenant_at`, задание роли maintenance.
    /// Возвращает число удалённых.
    pub async fn purge_risk_hits_before(&self, before: OffsetDateTime) -> Result<usize> {
        let mut total: usize = 0;
        loop {
            let deleted: u64 = with_system(&self.pool, move |tx| {
                Box::pin(async move {
                    sqlx::query(
                        "DELETE FROM risk_hits WHERE ctid IN (
                             SELECT ctid FROM risk_hits WHERE at < $1 LIMIT $2)",
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Секция `meta.risk` из yaml — значения и умолчания.
    #[test]
    fn risk_section_from_yaml() {
        let cfg: RiskConfig = serde_yaml_ng::from_str("package_keep: 3").expect("yaml");
        assert_eq!(cfg.package_keep, 3);
        assert_eq!(RiskConfig::default().package_keep, DEFAULT_PACKAGE_KEEP);
        assert!(serde_yaml_ng::from_str::<RiskConfig>("keep: 3").is_err());
    }
}
