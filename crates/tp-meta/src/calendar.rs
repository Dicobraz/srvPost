//! Публикации календарей и шаблоны занятости доменов-партнёров на PostgreSQL (META-34; CTR-36,
//! CONTRACTS.md#Calendar; SRS 4.4, решение 2026-11-04-calendar-external-api).
//!
//! Ссылки публикации — таблица каталога `calendar_publications`, одна строка на ссылку: токен в
//! открытом виде не хранится — только хэш SHA-256, отзыв удаляет запись, истёкшие удаляет
//! обслуживание хранилища ([`PgMeta::expire_publications`]). Выдачу и отзыв ссылки в журнал аудита
//! записывает вызывающий (SRS 4.4), как и проверку существования календаря (CTR-36). Потолок
//! детализации ([`CalendarPublications::ceiling`]) — клетка `sharing` интернета действующей матрицы
//! доверия ([`publication_ceiling`] по [`TrustStore::effective_for`]); ужесточение политики
//! существующие ссылки не отзывает — отдачу по ссылке ограничивает отдающий.
//!
//! Ссылку по токену без входа (DAV-20) ищет [`PgMeta::publication_by_token`] — системной
//! транзакцией, как `local_admin_tokens`: токен не несёт организацию; отозванной и истёкшей ссылки
//! он не отвечает. Шаблоны ссылок занятости доменов-партнёров (источник `partner` для
//! `Availability/get`, JMAP-19) — политика организации, таблица `partner_availability`: домен —
//! партнёр организации (`trust_partner_domains`, [`TrustStore`]), шаблон — `https://` с `{user}`
//! и необязательным `{domain}`; сборку адреса и выборку делает узел (SSRF-правила отдающего).

use async_trait::async_trait;
use rand::RngExt;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tp_contracts::calendar::{CalendarPublication, CalendarPublications, publication_ceiling};
use tp_contracts::dav::CollectionId;
use tp_contracts::meta::AccountScope;
use tp_contracts::transport::normalize_domain;
use tp_contracts::trust::{Detail, TrustStore};
use tp_contracts::{AccountId, Error, PublicationId, Result, TenantId};
use uuid::Uuid;

use crate::PgMeta;
use crate::schema::{begin, begin_system, db_err};

/// Срок ссылки с точностью до микросекунды (хранение `timestamptz`): в хранилище пишется усечённый
/// срок, в ответе [`CalendarPublications::create`] — как запросили (для вызова срок и так один).
fn truncate_micros(at: OffsetDateTime) -> Result<OffsetDateTime> {
    let micros = at.nanosecond() / 1_000 * 1_000;
    at.replace_nanosecond(micros)
        .map_err(|_| Error::invalid("срок ссылки вне диапазона"))
}

/// Токен ссылки: `cal-` и 64 hex (32 случайных байта) — адрес ссылки собирает вызывающий,
/// токен отдаётся один раз ([`CalendarPublications::create`]).
fn new_token() -> String {
    let mut rng = rand::rng();
    let mut out = String::with_capacity(68);
    out.push_str("cal-");
    for _ in 0..4 {
        out.push_str(&format!("{:016x}", rng.random::<u64>()));
    }
    out
}

/// Хэш токена: hex SHA-256 в нижнем регистре (`calendar_publications.token_hash`).
fn token_hash(token: &str) -> String {
    let digest = Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn detail_str(detail: Detail) -> &'static str {
    match detail {
        Detail::None => "none",
        Detail::FreeBusy => "free_busy",
        Detail::Limited => "limited",
        Detail::Details => "details",
        Detail::All => "all",
    }
}

/// Уровень детализации из строки `calendar_publications.detail`; в хранилище попадают только уровни
/// выпуска (не `none`, не выше закреплённого потолка интернета) — прочее значение — ошибка схемы.
fn detail_of(s: &str) -> Result<Detail> {
    match s {
        "none" => Ok(Detail::None),
        "free_busy" => Ok(Detail::FreeBusy),
        "limited" => Ok(Detail::Limited),
        "details" => Ok(Detail::Details),
        "all" => Ok(Detail::All),
        other => Err(Error::internal(format!(
            "calendar_publications.detail: {other}"
        ))),
    }
}

/// Строка `calendar_publications` без хэша токена (в ответе токена нет).
#[derive(sqlx::FromRow)]
struct Row {
    tenant_id: Uuid,
    account_id: Uuid,
    publication_id: Uuid,
    calendar_id: Uuid,
    detail: String,
    expires_at: Option<OffsetDateTime>,
}

impl Row {
    /// Ссылка; токен всегда `None`.
    fn into_publication(self) -> Result<CalendarPublication> {
        Ok(CalendarPublication {
            id: PublicationId::from_uuid(self.publication_id),
            scope: AccountScope {
                tenant: TenantId::from_uuid(self.tenant_id),
                account: AccountId::from_uuid(self.account_id),
            },
            calendar: CollectionId::from_uuid(self.calendar_id),
            detail: detail_of(&self.detail)?,
            expires: self.expires_at,
            token: None,
        })
    }
}

#[async_trait]
impl CalendarPublications for PgMeta {
    async fn ceiling(&self, scope: AccountScope) -> Result<Detail> {
        let effective = self.effective_for(scope.tenant, scope.account).await?;
        Ok(publication_ceiling(&effective))
    }

    /// Выдача идентификаторов внутри операции — не повторяется (META-40).
    async fn create(
        &self,
        scope: AccountScope,
        calendar: CollectionId,
        detail: Detail,
        expires: Option<OffsetDateTime>,
    ) -> Result<CalendarPublication> {
        let ceiling = self.ceiling(scope).await?;
        if detail == Detail::None {
            return Err(Error::invalid("публикация без уровня детализации"));
        }
        if detail > ceiling {
            return Err(Error::Forbidden);
        }
        if expires.is_some_and(|e| e <= OffsetDateTime::now_utc()) {
            return Err(Error::invalid("срок ссылки не позже текущего момента"));
        }
        let stored = expires.map(truncate_micros).transpose()?;
        let id = PublicationId::new();
        let token = new_token();
        self.once(async move {
            let mut tx = begin(&self.pool, scope.tenant).await?;
            sqlx::query(
                "INSERT INTO calendar_publications
                     (tenant_id, account_id, publication_id, calendar_id, detail, token_hash, expires_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
            )
            .bind(scope.tenant.as_uuid())
            .bind(scope.account.as_uuid())
            .bind(id.as_uuid())
            .bind(calendar.as_uuid())
            .bind(detail_str(detail))
            .bind(token_hash(&token))
            .bind(stored)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            crate::commits::commit(tx).await?;
            Ok(CalendarPublication {
                id,
                scope,
                calendar,
                detail,
                expires,
                token: Some(token),
            })
        })
        .await
    }

    async fn list(&self, scope: AccountScope) -> Result<Vec<CalendarPublication>> {
        self.idempotent(|| async move {
            let mut tx = begin(&self.pool, scope.tenant).await?;
            let rows: Vec<Row> = sqlx::query_as(
                "SELECT tenant_id, account_id, publication_id, calendar_id, detail, expires_at
                 FROM calendar_publications
                 WHERE tenant_id = $1 AND account_id = $2
                 ORDER BY publication_id",
            )
            .bind(scope.tenant.as_uuid())
            .bind(scope.account.as_uuid())
            .fetch_all(&mut *tx)
            .await
            .map_err(db_err)?;
            crate::commits::commit(tx).await?;
            rows.into_iter().map(Row::into_publication).collect()
        })
        .await
    }

    /// Отзыв — удаление записи; нет или чужой учётной записи — `NotFound`. Удаление с ответом
    /// `NotFound` об отсутствии — один раз (META-40).
    async fn revoke(&self, scope: AccountScope, id: PublicationId) -> Result<()> {
        self.once(async move {
            let mut tx = begin(&self.pool, scope.tenant).await?;
            let deleted = sqlx::query(
                "DELETE FROM calendar_publications
                 WHERE tenant_id = $1 AND account_id = $2 AND publication_id = $3",
            )
            .bind(scope.tenant.as_uuid())
            .bind(scope.account.as_uuid())
            .bind(id.as_uuid())
            .execute(&mut *tx)
            .await
            .map_err(db_err)?
            .rows_affected();
            crate::commits::commit(tx).await?;
            if deleted == 0 {
                return Err(Error::NotFound);
            }
            Ok(())
        })
        .await
    }
}

impl PgMeta {
    /// Ссылка по токену в открытом виде (DAV-20: входа нет, токен не несёт организацию) — поиск
    /// по хэшу системной транзакцией, как `local_admin_tokens`. Нет, отозвана или истекла — `None`;
    /// уровень детализации отдачи ограничивает отдающий. Токен в ответе не возвращается.
    pub async fn publication_by_token(&self, token: &str) -> Result<Option<CalendarPublication>> {
        let hash = token_hash(token);
        let hash = &hash;
        self.idempotent(|| async move {
            let mut tx = begin_system(&self.pool).await?;
            let row: Option<Row> = sqlx::query_as(
                "SELECT tenant_id, account_id, publication_id, calendar_id, detail, expires_at
                 FROM calendar_publications
                 WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > now())",
            )
            .bind(hash)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
            crate::commits::commit(tx).await?;
            row.map(Row::into_publication).transpose()
        })
        .await
    }

    /// Удаляет истёкшие ссылки (`expires_at` не позже `before`) по всем организациям — обслуживание
    /// хранилища. Повтор удаляет оставшиеся (число — только их), как `LocalAdminTokens::prune`.
    pub async fn expire_publications(&self, before: OffsetDateTime) -> Result<u64> {
        self.rewrite(|| async move {
            let mut tx = begin_system(&self.pool).await?;
            let removed = sqlx::query(
                "DELETE FROM calendar_publications
                 WHERE expires_at IS NOT NULL AND expires_at <= $1",
            )
            .bind(before)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?
            .rows_affected();
            crate::commits::commit(tx).await?;
            Ok(removed)
        })
        .await
    }
}

// ---------- Шаблоны занятости доменов-партнёров (политика организации) ----------

/// Шаблон ссылки занятости домена-партнёра (источник `partner` для `Availability/get`, JMAP-19):
/// `{user}` — локальная часть адреса, `{domain}` — домен; сборку адреса и выборку делает узел
/// (только HTTPS, SSRF-правила отдающего).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartnerAvailability {
    /// Домен-партнёр (каноническая форма).
    pub domain: String,
    /// Шаблон `https://` с `{user}` и необязательным `{domain}`.
    pub template: String,
}

/// Проверка шаблона: только `https://`, есть `{user}` (иначе адрес занятости не собрать),
/// без управляющих символов и не длиннее 1024 байт (как в `partner_availability`).
fn validate_template(template: &str) -> Result<()> {
    let bad = |what: &str| Error::invalid(format!("шаблон занятости партнёра: {what}"));
    if !template.starts_with("https://") {
        return Err(bad("только https://"));
    }
    if !template.contains("{user}") {
        return Err(bad("нет {user}"));
    }
    if template.len() > 1024 || template.chars().any(char::is_control) {
        return Err(bad("управляющие символы или длиннее 1024"));
    }
    Ok(())
}

/// Строка `partner_availability`.
type TemplateRow = (String,);

impl PgMeta {
    /// Шаблоны занятости доменов-партнёров организации, по возрастанию домена (байтов).
    pub async fn partner_availability(&self, tenant: TenantId) -> Result<Vec<PartnerAvailability>> {
        self.idempotent(|| async move {
            let mut tx = begin(&self.pool, tenant).await?;
            let rows: Vec<(String, String)> = sqlx::query_as(
                r#"SELECT domain, template FROM partner_availability
                   WHERE tenant_id = $1 ORDER BY domain COLLATE "C""#,
            )
            .bind(tenant.as_uuid())
            .fetch_all(&mut *tx)
            .await
            .map_err(db_err)?;
            crate::commits::commit(tx).await?;
            Ok(rows
                .into_iter()
                .map(|(domain, template)| PartnerAvailability { domain, template })
                .collect())
        })
        .await
    }

    /// Шаблон домена `domain` (домен канонизируется); не задан — `None`.
    pub async fn partner_availability_template(
        &self,
        tenant: TenantId,
        domain: &str,
    ) -> Result<Option<String>> {
        let domain = normalize_domain(domain)?;
        let domain = &domain;
        self.idempotent(|| async move {
            let mut tx = begin(&self.pool, tenant).await?;
            let row: Option<TemplateRow> = sqlx::query_as(
                "SELECT template FROM partner_availability WHERE tenant_id = $1 AND domain = $2",
            )
            .bind(tenant.as_uuid())
            .bind(domain)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
            crate::commits::commit(tx).await?;
            Ok(row.map(|(t,)| t))
        })
        .await
    }

    /// Задаёт или убирает (`None`) шаблон домена-партнёра организации (политика организации).
    /// Домен не партнёр организации (`trust_partner_domains`) — `Invalid`; недопустимый шаблон —
    /// `Invalid`. Запись уровня политики доверия списки шаблонов не меняет.
    pub async fn set_partner_availability_template(
        &self,
        tenant: TenantId,
        domain: &str,
        template: Option<String>,
    ) -> Result<()> {
        let domain = normalize_domain(domain)?;
        if let Some(t) = &template {
            validate_template(t)?;
        }
        let (domain, template) = (&domain, &template);
        self.rewrite(|| async move {
            let mut tx = begin(&self.pool, tenant).await?;
            let partner: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM trust_partner_domains WHERE tenant_id = $1 AND domain = $2)",
            )
            .bind(tenant.as_uuid())
            .bind(domain)
            .fetch_one(&mut *tx)
            .await
            .map_err(db_err)?;
            if !partner {
                return Err(Error::invalid("домен не партнёр организации"));
            }
            match template.as_deref() {
                Some(t) => {
                    sqlx::query(
                        "INSERT INTO partner_availability (tenant_id, domain, template)
                         VALUES ($1, $2, $3)
                         ON CONFLICT (tenant_id, domain)
                         DO UPDATE SET template = EXCLUDED.template, updated_at = now()",
                    )
                    .bind(tenant.as_uuid())
                    .bind(domain)
                    .bind(t)
                    .execute(&mut *tx)
                    .await
                    .map_err(db_err)?;
                }
                None => {
                    sqlx::query(
                        "DELETE FROM partner_availability WHERE tenant_id = $1 AND domain = $2",
                    )
                    .bind(tenant.as_uuid())
                    .bind(domain)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn t(seconds: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(seconds)
    }

    /// Срок усекается до точности хранилища (микросекунды `timestamptz`).
    #[test]
    fn expires_truncated_to_micros() {
        let at = t(1_000_000) + time::Duration::nanoseconds(123_456_789);
        assert_eq!(truncate_micros(at).expect("в диапазоне"), t(1_000_123));
    }

    /// Токен узнаваем и хэш — 64 hex нижнего регистра; разным токенам отвечают разные хэши.
    #[test]
    fn tokens_and_hashes() {
        let token = new_token();
        assert!(token.starts_with("cal-"));
        assert_eq!(token.len(), 68);
        assert!(!token[4..].chars().any(|c| !c.is_ascii_hexdigit()));
        let hash = token_hash(&token);
        assert_eq!(hash.len(), 64);
        assert!(
            hash.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        assert_ne!(hash, token_hash(&new_token()));
        assert_eq!(token_hash("x"), token_hash("x"));
    }

    /// Проверка шаблона: https, `{user}`, пределы.
    #[test]
    fn template_validation() {
        let ok = "https://{domain}/fb?u={user}";
        assert_eq!(validate_template(ok), Ok(()));
        assert!(validate_template("http://{user}").is_err());
        assert!(validate_template("https://fb.example/?u=user").is_err());
        let long = format!("https://x/{}", "a".repeat(1024));
        assert!(validate_template(&long).is_err());
        assert!(validate_template("https://a\u{7}{user}").is_err());
    }

    /// Отображение уровня детализации: туда и обратно; неизвестная строка — ошибка схемы.
    #[test]
    fn detail_roundtrip() {
        for d in [
            Detail::None,
            Detail::FreeBusy,
            Detail::Limited,
            Detail::Details,
            Detail::All,
        ] {
            assert_eq!(detail_of(detail_str(d)), Ok(d));
        }
        assert!(detail_of("many").is_err());
    }
}
