//! Политика доверия на PostgreSQL (META-85; CTR-93, CONTRACTS.md#Trust; решение 124): таблица
//! `trust_policies` — по строке на уровень (установка — `tenant_id IS NULL` с частичным уникальным
//! индексом, организация — `group_id IS NULL` с уникальным `tenant_id`, группа — уникальная пара
//! `tenant_id` и `group_id`, каскадное удаление с группой), клетки — `cells` в jsonb по схеме контракта
//! с номером версии схемы; домены-партнёры и домены автопересылки организации — `trust_partner_domains`
//! и `trust_forward_domains` (первичный ключ — индекс `partner_of`).
//!
//! `effective_for` — один запрос в транзакции организации: установка (строку установки читают все
//! организации — RLS `installation_read`), своя организация и группы учётной записи через членство,
//! включая вложенные группы (рекурсивно); разбор и сведение — функцией контракта [`effective`], не SQL.
//! Запись уровня — в транзакции уровня (установка — системной), потолок записи и принятые домены
//! читаются в ней же. Сигнал `trust_changed` не публикует — его публикует узел после фиксации (как
//! `MemTrust`).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sqlx::types::Json;
use sqlx::{FromRow, PgConnection, Postgres, Transaction};
use tp_contracts::transport::normalize_domain;
use tp_contracts::trust::{
    Ceiling, Detail, Effective, GroupPost, InviteMode, PerPeer, Toggle, TrustLevel, TrustPolicy,
    TrustStore, effective,
};
use tp_contracts::{AccountId, Error, GroupId, Result, TenantId};
use uuid::Uuid;

use crate::PgMeta;
use crate::pool::DbPool;
use crate::schema::{begin, begin_system, db_err};

/// Номер версии схемы клеток в `trust_policies.schema_version`: клетки — jsonb по схеме контракта,
/// новое поле политики схемы клеток не меняет (читается как не заданное); несовместимое изменение —
/// новая версия, старая база читается узлом с ошибкой.
const CELLS_SCHEMA_VERSION: i32 = 1;

/// Клетки политики — столбец `cells` без доменных списков: `partners` и `auto_forward_domains` —
/// отдельные таблицы. Поля необязательные: новое поле контракта в старой базе — не задано.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Cells {
    #[serde(default)]
    invite_new: PerPeer<Option<InviteMode>>,
    #[serde(default)]
    itip_updates: PerPeer<Option<Toggle>>,
    #[serde(default)]
    auto_reply: PerPeer<Option<Toggle>>,
    #[serde(default)]
    mdn: PerPeer<Option<Toggle>>,
    #[serde(default)]
    auto_forward: PerPeer<Option<Toggle>>,
    #[serde(default)]
    freebusy: PerPeer<Option<Detail>>,
    #[serde(default)]
    sharing: PerPeer<Option<Detail>>,
    #[serde(default)]
    group_post: PerPeer<Option<GroupPost>>,
}

impl Cells {
    /// Клетки политики для записи.
    fn of(policy: &TrustPolicy) -> Self {
        Cells {
            invite_new: policy.invite_new,
            itip_updates: policy.itip_updates,
            auto_reply: policy.auto_reply,
            mdn: policy.mdn,
            auto_forward: policy.auto_forward,
            freebusy: policy.freebusy,
            sharing: policy.sharing,
            group_post: policy.group_post,
        }
    }

    /// Политика из клеток с доменными списками организации.
    fn into_policy(self, partners: Vec<String>, auto_forward_domains: Vec<String>) -> TrustPolicy {
        TrustPolicy {
            invite_new: self.invite_new,
            itip_updates: self.itip_updates,
            auto_reply: self.auto_reply,
            mdn: self.mdn,
            auto_forward: self.auto_forward,
            freebusy: self.freebusy,
            sharing: self.sharing,
            group_post: self.group_post,
            partners,
            auto_forward_domains,
        }
    }
}

/// Строка `trust_policies`; уровень — по паре `tenant_id`/`group_id`.
#[derive(FromRow)]
struct Row {
    tenant_id: Option<Uuid>,
    group_id: Option<Uuid>,
    cells: Json<Cells>,
    schema_version: i32,
}

impl Row {
    /// Клетки с проверкой версии схемы.
    fn checked(self) -> Result<Cells> {
        if self.schema_version > CELLS_SCHEMA_VERSION {
            return Err(Error::internal(format!(
                "trust_policies: схема клеток {} новее схемы узла ({CELLS_SCHEMA_VERSION})",
                self.schema_version
            )));
        }
        Ok(self.cells.0)
    }
}

/// Условие строки уровня в `trust_policies`.
fn level_filter(level: TrustLevel) -> &'static str {
    match level {
        TrustLevel::Installation => "tenant_id IS NULL",
        TrustLevel::Org(_) => "tenant_id = $1 AND group_id IS NULL",
        TrustLevel::Group(_, _) => "tenant_id = $1 AND group_id = $2",
    }
}

/// Параметры условия уровня (`$1`, `$2`).
fn level_args(level: TrustLevel) -> [Option<Uuid>; 2] {
    match level {
        TrustLevel::Installation => [None, None],
        TrustLevel::Org(t) => [Some(*t.as_uuid()), None],
        TrustLevel::Group(t, g) => [Some(*t.as_uuid()), Some(*g.as_uuid())],
    }
}

/// Цель `ON CONFLICT` записи уровня — частичный уникальный индекс уровня.
fn level_conflict(level: TrustLevel) -> &'static str {
    match level {
        TrustLevel::Installation => "((tenant_id IS NULL)) WHERE tenant_id IS NULL",
        TrustLevel::Org(_) => "(tenant_id) WHERE tenant_id IS NOT NULL AND group_id IS NULL",
        TrustLevel::Group(_, _) => "(tenant_id, group_id) WHERE group_id IS NOT NULL",
    }
}

/// Транзакция уровня: организация и группа — в контексте своей организации (RLS), установка — системная.
async fn begin_level(pool: &DbPool, level: TrustLevel) -> Result<Transaction<'static, Postgres>> {
    match level {
        TrustLevel::Installation => begin_system(pool).await,
        TrustLevel::Org(t) | TrustLevel::Group(t, _) => begin(pool, t).await,
    }
}

/// Клетки уровня в открытой транзакции; нет строки — `None`. Строку установки читает любая организация
/// (RLS `installation_read`), поэтому потолок для записи организации и группы — в их же транзакции.
async fn cells_of(conn: &mut PgConnection, level: TrustLevel) -> Result<Option<Cells>> {
    let sql = format!(
        "SELECT tenant_id, group_id, cells, schema_version FROM trust_policies WHERE {}",
        level_filter(level)
    );
    let mut q = sqlx::query_as::<_, Row>(sqlx::AssertSqlSafe(sql));
    for arg in level_args(level).into_iter().flatten() {
        q = q.bind(arg);
    }
    q.fetch_optional(conn)
        .await
        .map_err(db_err)?
        .map(Row::checked)
        .transpose()
}

/// Домены организации из таблицы `table` по возрастанию байтов (порядок детерминирован).
async fn domains_of(conn: &mut PgConnection, table: &str, tenant: TenantId) -> Result<Vec<String>> {
    let sql =
        format!(r#"SELECT domain FROM {table} WHERE tenant_id = $1 ORDER BY domain COLLATE "C""#);
    let out: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(*tenant.as_uuid())
        .fetch_all(conn)
        .await
        .map_err(db_err)?;
    Ok(out)
}

/// Заменяет домены организации в таблице `table` целиком (вместе с уровнем — одна транзакция).
async fn replace_domains(
    conn: &mut PgConnection,
    table: &str,
    tenant: TenantId,
    domains: &[String],
) -> Result<()> {
    let del = format!("DELETE FROM {table} WHERE tenant_id = $1");
    sqlx::query(sqlx::AssertSqlSafe(del))
        .bind(*tenant.as_uuid())
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    if !domains.is_empty() {
        let ins = format!(
            "INSERT INTO {table} (tenant_id, domain) SELECT $1, d FROM unnest($2::text[]) d"
        );
        sqlx::query(sqlx::AssertSqlSafe(ins))
            .bind(*tenant.as_uuid())
            .bind(domains.to_vec())
            .execute(&mut *conn)
            .await
            .map_err(db_err)?;
    }
    Ok(())
}

/// Действующий потолок записи уровня и принятые домены его организации (в открытой транзакции):
/// у установки — [`Ceiling::hard`] контракта, у организации — действующее значение установки, у группы —
/// организации (как `MemTrust::write_ceiling`). Принятые домены — из `domains`: свой домен в `partners`
/// не проходит проверку контракта.
async fn write_ceiling(
    conn: &mut PgConnection,
    level: TrustLevel,
) -> Result<(Ceiling, Vec<String>)> {
    match level {
        TrustLevel::Installation => Ok((Ceiling::hard(), Vec::new())),
        TrustLevel::Org(t) | TrustLevel::Group(t, _) => {
            let inst = cells_of(&mut *conn, TrustLevel::Installation)
                .await?
                .map(|c| c.into_policy(Vec::new(), Vec::new()));
            let org_level = TrustLevel::Org(t);
            let org = if level == org_level {
                None // потолок самой организации — установка, без её клеток
            } else {
                cells_of(&mut *conn, org_level)
                    .await?
                    .map(|c| c.into_policy(Vec::new(), Vec::new()))
            };
            let ceiling =
                effective(inst.as_ref(), org.as_ref().map(|p| (org_level, p)), &[]).ceiling;
            let accepted: Vec<String> =
                sqlx::query_scalar("SELECT lower(name) FROM domains WHERE tenant_id = $1")
                    .bind(*t.as_uuid())
                    .fetch_all(&mut *conn)
                    .await
                    .map_err(db_err)?;
            Ok((ceiling, accepted))
        }
    }
}

#[async_trait]
impl TrustStore for PgMeta {
    async fn policy(&self, level: TrustLevel) -> Result<Option<TrustPolicy>> {
        self.idempotent(|| async move {
            let mut tx = begin_level(&self.pool, level).await?;
            let out = match cells_of(&mut tx, level).await? {
                Some(cells) => {
                    let (partners, auto_forward) = match level {
                        TrustLevel::Org(t) => (
                            domains_of(&mut tx, "trust_partner_domains", t).await?,
                            domains_of(&mut tx, "trust_forward_domains", t).await?,
                        ),
                        _ => (Vec::new(), Vec::new()),
                    };
                    Some(cells.into_policy(partners, auto_forward))
                }
                None => None,
            };
            crate::commits::commit(tx).await?;
            Ok(out)
        })
        .await
    }

    /// Запись уровня целиком (повтор после обрыва во время COMMIT даёт то же состояние): проверка по
    /// действующему потолку и запись — одна транзакция. Пустая политика (все клетки `None`, списки
    /// пусты) удаляет уровень — как `MemTrust`.
    async fn set_policy(&self, level: TrustLevel, policy: &TrustPolicy) -> Result<()> {
        if !matches!(level, TrustLevel::Org(_))
            && (!policy.partners.is_empty() || !policy.auto_forward_domains.is_empty())
        {
            return Err(Error::invalid(
                "partners и auto_forward_domains задаёт только организация",
            ));
        }
        let cells = Json(Cells::of(policy));
        let cells = &cells;
        self.rewrite(|| async move {
            let mut tx = begin_level(&self.pool, level).await?;
            let (ceiling, accepted) = write_ceiling(&mut tx, level).await?;
            policy.validate(&ceiling, &accepted)?;
            let args = level_args(level);
            if *policy == TrustPolicy::default() {
                let sql = format!("DELETE FROM trust_policies WHERE {}", level_filter(level));
                let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
                for arg in args.into_iter().flatten() {
                    q = q.bind(arg);
                }
                q.execute(&mut *tx).await.map_err(db_err)?;
            } else {
                let sql = format!(
                    "INSERT INTO trust_policies (tenant_id, group_id, cells, schema_version)
                     VALUES ($1, $2, $3, $4)
                     ON CONFLICT {} DO UPDATE SET
                         cells = excluded.cells, schema_version = excluded.schema_version,
                         updated_at = now()",
                    level_conflict(level)
                );
                sqlx::query(sqlx::AssertSqlSafe(sql))
                    .bind(args[0])
                    .bind(args[1])
                    .bind(cells)
                    .bind(CELLS_SCHEMA_VERSION)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
            }
            if let TrustLevel::Org(t) = level {
                replace_domains(&mut tx, "trust_partner_domains", t, &policy.partners).await?;
                replace_domains(
                    &mut tx,
                    "trust_forward_domains",
                    t,
                    &policy.auto_forward_domains,
                )
                .await?;
            }
            crate::commits::commit(tx).await?;
            Ok(())
        })
        .await
    }

    /// Удаление уровня по ключу (нет строки — не ошибка): уровень выше и умолчания продолжают действовать.
    async fn reset_policy(&self, level: TrustLevel) -> Result<()> {
        self.rewrite(|| async move {
            let mut tx = begin_level(&self.pool, level).await?;
            let args = level_args(level);
            let sql = format!("DELETE FROM trust_policies WHERE {}", level_filter(level));
            let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
            for arg in args.into_iter().flatten() {
                q = q.bind(arg);
            }
            q.execute(&mut *tx).await.map_err(db_err)?;
            if let TrustLevel::Org(t) = level {
                replace_domains(&mut tx, "trust_partner_domains", t, &[]).await?;
                replace_domains(&mut tx, "trust_forward_domains", t, &[]).await?;
            }
            crate::commits::commit(tx).await?;
            Ok(())
        })
        .await
    }

    /// Одним запросом в транзакции организации: строка установки (RLS показывает её всем), своя
    /// организация и группы учётной записи — через прямое и вложенное членство; сведение — [`effective`].
    async fn effective_for(&self, tenant: TenantId, account: AccountId) -> Result<Effective> {
        self.idempotent(|| async move {
            let mut tx = begin(&self.pool, tenant).await?;
            let rows: Vec<Row> = sqlx::query_as(
                "WITH RECURSIVE mg(g) AS (
                     SELECT m.group_id FROM group_members m
                     WHERE m.tenant_id = $1 AND m.account_id = $2
                     UNION
                     SELECT m.group_id FROM group_members m
                     JOIN mg ON m.tenant_id = $1 AND m.member_group_id = mg.g)
                 SELECT tp.tenant_id, tp.group_id, tp.cells, tp.schema_version FROM trust_policies tp
                 WHERE tp.tenant_id IS NULL
                    OR (tp.tenant_id = $1 AND (tp.group_id IS NULL OR tp.group_id IN (SELECT g FROM mg)))",
            )
            .bind(*tenant.as_uuid())
            .bind(*account.as_uuid())
            .fetch_all(&mut *tx)
            .await
            .map_err(db_err)?;
            crate::commits::commit(tx).await?;
            let me = *tenant.as_uuid();
            let mut installation = None;
            let mut org = None;
            let mut groups = Vec::new();
            for row in rows {
                let (tenant_id, group_id) = (row.tenant_id, row.group_id);
                let cells = row.checked()?;
                match (tenant_id, group_id) {
                    (None, None) => installation = Some(cells.into_policy(Vec::new(), Vec::new())),
                    (Some(t), None) if t == me => org = Some(cells.into_policy(Vec::new(), Vec::new())),
                    (Some(t), Some(g)) if t == me => groups.push((
                        TrustLevel::Group(tenant, GroupId::from_uuid(g)),
                        cells.into_policy(Vec::new(), Vec::new()),
                    )),
                    _ => {
                        return Err(Error::internal(
                            "trust_policies: строка уровня вне организации запроса",
                        ));
                    }
                }
            }
            let group_refs: Vec<(TrustLevel, &TrustPolicy)> =
                groups.iter().map(|(level, p)| (*level, p)).collect();
            Ok(effective(
                installation.as_ref(),
                org.as_ref().map(|p| (TrustLevel::Org(tenant), p)),
                &group_refs,
            ))
        })
        .await
    }

    /// По индексу домена (первичный ключ `trust_partner_domains`); домен канонизируется — недопустимый
    /// `Invalid`.
    async fn partner_of(&self, tenant: TenantId, domain: &str) -> Result<bool> {
        self.idempotent(|| async move {
            let domain = normalize_domain(domain)?;
            let mut tx = begin(&self.pool, tenant).await?;
            let partner: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM trust_partner_domains WHERE tenant_id = $1 AND domain = $2)",
            )
            .bind(*tenant.as_uuid())
            .bind(&domain)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
            crate::commits::commit(tx).await?;
            Ok(partner)
        })
        .await
    }
}
