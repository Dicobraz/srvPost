//! Схема БД: миграции ядра, транзакции в контексте организации (RLS), ошибки sqlx (SRS 3.1, 3.6, 3.8).
//!
//! Миграции встроены в бинарный файл (`migrations/*.sql`) и применяются `sqlx::migrate::Migrator`
//! под рекомендательной блокировкой: параллельный старт узлов безопасен, повторное применение — пустая операция.
//! Перед выпуском 1.0 миграции 0001…0044 свернуты в одну базовую схему (META-71, решение 106): версия 1 —
//! базовая схема 1.0, изменения после 1.0 — версиями 2 и дальше. Журнал миграций установки, обновлявшейся
//! по одной миграции до свёртывания (beta.2), сворачивается при старте в одну свернувшую запись базовой
//! схемы ([`fold_old_chain`], META-89) — обновление узла между релизами без пересоздания базы.

use std::borrow::Cow;

use sqlx::migrate::{Migrate, MigrateError, Migration, MigrationType, Migrator};
use sqlx::postgres::PgConnection;
use sqlx::{AssertSqlSafe, Connection, Postgres, SqlSafeStr, Transaction};
use tp_contracts::{Error, Result, TenantId};

use crate::pool::DbPool;

/// Миграции ядра: (версия, описание, SQL). Версии только добавляются; применённые не меняются.
const MIGRATIONS: &[(i64, &str, &str)] = &[(
    1,
    "base schema 1.0",
    include_str!("../migrations/0001_base.sql"),
)];

/// Последняя версия свёрнутой цепочки миграций (META-71: `0001…0044` свернуты в базовую схему —
/// версию 1). У установки, обновлявшейся миграциями по одной (beta.2), в журнале записаны все эти
/// версии. Послевыпусковые версии (`2` и дальше) не пересекаются с ней у баз новой схемы: их записи
/// стоят в журнале рядом с базовой схемой с её контрольной суммой — признак, по которому их цепочка
/// отличима от свёрнутой ([`fold_old_chain`]).
pub const FOLDED_LAST_VERSION: i64 = 44;

/// Таблица журнала миграций — имя по умолчанию у мигратора sqlx.
const MIGRATION_JOURNAL: &str = "_sqlx_migrations";

/// Описание свернувшей записи журнала: базовая схема с пометкой «свёрнута» (META-89).
const FOLDED_DESCRIPTION: &str = "base schema 1.0 — свёрнута цепочка 0001…0044";

/// Список миграций резолвера; контрольная сумма — по тексту без `\r\n`, как у мигратора.
fn resolved_migrations() -> Vec<Migration> {
    MIGRATIONS
        .iter()
        .map(|(version, desc, sql)| {
            Migration::new(
                *version,
                Cow::Borrowed(*desc),
                MigrationType::Simple,
                // Контрольная сумма не зависит от окончаний строк в рабочей копии.
                AssertSqlSafe(sql.replace("\r\n", "\n")).into_sql_str(),
                false,
            )
        })
        .collect()
}

/// Мигратор схемы ядра.
pub fn migrator() -> Migrator {
    Migrator::with_migrations(resolved_migrations())
}

/// Ошибка мигратора sqlx → ошибка границы крейта: обрыв и отказ СУБД — [`crate::schema::db_err`].
fn migrate_err(e: MigrateError) -> Error {
    match e {
        MigrateError::Execute(e) | MigrateError::ExecuteMigration(e, _) => db_err(e),
        e => {
            tracing::error!(error = %e, "миграция схемы");
            Error::internal(e.to_string())
        }
    }
}

/// Применяет недостающие миграции ядра; перед этим сворачивает журнал старой цепочки миграций
/// ([`fold_old_chain`], META-89).
/// Соединение — из пула `pool` через его наблюдателя.
pub async fn migrate(pool: &DbPool) -> Result<()> {
    let mut conn = pool.acquire().await?;
    fold_old_chain(&mut *conn).await?;
    migrator()
        .run_direct(None, &mut *conn, false)
        .await
        .map_err(migrate_err)
}

/// Свёртывание журнала миграций старой цепочки (META-89). Установка, обновлённая до beta.2 по одной
/// миграции, хранит в журнале записи версий `2…{FOLDED_LAST_VERSION}`, которых нет в резолвере, —
/// мигратор sqlx отвечает «migration 2 was previously applied but is missing in the resolved
/// migrations», и узел не стартует. Журнал — ровно вся старая цепочка `1…{FOLDED_LAST_VERSION}` с
/// контрольной суммой первой записи не от базовой схемы (признак базы до свёртывания) — заменяется
/// одной свернувшей записью базовой схемы с пометкой «свёрнута»: состояние базы после полной цепочки
/// `0001…0044` побайтово равно базовой схеме (META-71), поэтому данные не трогаются.
///
/// Иначе журнал не меняется: чистая и «грязная» базы — на разбор мигратору; неполная старая цепочка
/// (её схема не равна базовой — обновление беты, пересоздание базы) и база новой схемы без
/// послевыпусковой версии в бинарнике («база новее бинарника») остаются ошибками мигратора.
///
/// Под рекомендательной блокировкой — как сам мигратор: параллельный старт узлов безопасен.
async fn fold_old_chain(conn: &mut PgConnection) -> Result<()> {
    conn.lock().await.map_err(migrate_err)?;
    let folded = fold_old_chain_locked(conn).await;
    conn.unlock().await.map_err(migrate_err)?;
    folded
}

/// Тело [`fold_old_chain`] под блокировкой.
async fn fold_old_chain_locked(conn: &mut PgConnection) -> Result<()> {
    let Some(base) = resolved_migrations().into_iter().next() else {
        return Ok(());
    };
    // Чистая база: таблицы журнала ещё нет — создать, как это делает мигратор.
    conn.ensure_migrations_table(MIGRATION_JOURNAL)
        .await
        .map_err(migrate_err)?;
    let applied: Vec<(i64, bool, Vec<u8>)> =
        sqlx::query_as("SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&mut *conn)
            .await
            .map_err(db_err)?;
    if applied.is_empty() || applied.iter().any(|&(_, success, _)| !success) {
        // Чистая база либо «грязная» (прерванная миграция) — свёртывание не нужно, разбор у мигратора.
        return Ok(());
    }

    let versions: Vec<i64> = applied.iter().map(|(version, _, _)| *version).collect();
    let old_chain: Vec<i64> = (1..=FOLDED_LAST_VERSION).collect();
    let first_checksum = &applied[0].2;
    if versions != old_chain || first_checksum.as_slice() == base.checksum.as_ref() {
        // Не вся старая цепочка либо база новой схемы (рядом с базовой схемой — послевыпусковые
        // версии): отсутствие версии в бинарнике — ошибка мигратора.
        return Ok(());
    }

    // Одна свернувшая запись — в одной транзакции: прерванное свёртывание не оставляет следа.
    let mut tx = conn.begin().await.map_err(db_err)?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM {MIGRATION_JOURNAL}"
    )))
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO {MIGRATION_JOURNAL} (version, description, success, checksum, execution_time) \
         VALUES ($1, $2, TRUE, $3, -1)"
    )))
    .bind(base.version)
    .bind(FOLDED_DESCRIPTION)
    .bind(base.checksum.as_ref())
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)?;
    tracing::warn!(
        versions = versions.len(),
        "записи свёрнутой цепочки миграций заменены одной свернувшей записью базовой схемы 1.0"
    );
    Ok(())
}

/// Транзакция в контексте организации: `app.tenant_id` (SET LOCAL) — RLS видит только её строки.
pub async fn begin(pool: &DbPool, tenant: TenantId) -> Result<Transaction<'static, Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('app.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    Ok(tx)
}

/// Системная транзакция по всем организациям (GC BLOB, журнал событий): `app.all_tenants` (SET LOCAL).
pub async fn begin_system(pool: &DbPool) -> Result<Transaction<'static, Postgres>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT set_config('app.all_tenants', 'on', true)")
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    Ok(tx)
}

/// Ошибка sqlx → ошибка границы крейта. Обрыв, `25006` (сервер только для чтения — бывший primary) и
/// `57P01` (остановка сервера) — `Unavailable`: признаки переключения СУБД ([`crate::failover`]).
pub fn db_err(e: sqlx::Error) -> Error {
    match &e {
        sqlx::Error::RowNotFound => Error::NotFound,
        sqlx::Error::Database(d) => match d.code().as_deref() {
            Some("23505") => Error::Conflict,
            Some("23502" | "23503" | "23514" | "22003" | "22P02") => {
                Error::Invalid(d.message().to_owned())
            }
            Some("42501") => Error::Forbidden,
            Some(c)
                if c.starts_with("08")
                    || matches!(
                        c,
                        "25006"
                            | "40001"
                            | "40P01"
                            | "53300"
                            | "55P03"
                            | "57P01"
                            | "57P02"
                            | "57P03"
                    ) =>
            {
                Error::UNAVAILABLE
            }
            code => {
                tracing::error!(code, error = %e, "ошибка СУБД");
                Error::internal(e.to_string())
            }
        },
        sqlx::Error::Tls(t) => tls_err(t.as_ref()),
        sqlx::Error::Io(_)
        | sqlx::Error::PoolTimedOut
        | sqlx::Error::PoolClosed
        | sqlx::Error::WorkerCrashed
        | sqlx::Error::BeginFailed => Error::UNAVAILABLE,
        _ => {
            tracing::error!(error = %e, "ошибка sqlx");
            Error::internal(e.to_string())
        }
    }
}

/// Ошибка TLS канала до СУБД (META-56): причина — в журнал (значения ключа в ней нет). Ключ клиентского
/// сертификата не подходит к сертификату — `Invalid` с понятным текстом: rustls сверяет открытый ключ сертификата
/// с закрытым при сборке параметров TLS (`CertifiedKey::from_der`, текст «keys may not be consistent:
/// KeyMismatch»), до обмена с сервером. Остальное — `Unavailable` (повтор после исправления поможет).
fn tls_err(e: &(dyn std::error::Error + Send + Sync)) -> Error {
    let text = e.to_string();
    if text.contains("KeyMismatch") {
        tracing::error!(error = %text, "СУБД: ключ клиентского сертификата не подходит к сертификату");
        return Error::invalid(
            "database.tls: ключ клиентского сертификата (tls.key или tls.key_file) не подходит к сертификату \
             tls.cert_file",
        );
    }
    tracing::warn!(error = %text, "СУБД: ошибка TLS канала");
    Error::UNAVAILABLE
}

/// Значение столбца `bigint` → `u32` (UID, UIDVALIDITY, поколение).
pub(crate) fn to_u32(v: i64) -> Result<u32> {
    u32::try_from(v).map_err(|_| Error::internal(format!("значение вне u32: {v}")))
}

/// Значение столбца `bigint` → `u64` (размеры, ModSeq).
pub(crate) fn to_u64(v: i64) -> Result<u64> {
    u64::try_from(v).map_err(|_| Error::internal(format!("отрицательное значение: {v}")))
}

/// `u64` → `bigint`.
pub(crate) fn to_i64(v: u64) -> Result<i64> {
    i64::try_from(v).map_err(|_| Error::invalid(format!("значение вне bigint: {v}")))
}

#[cfg(test)]
mod tests {
    use super::MIGRATIONS;

    /// Версии в списке идут подряд с 1; каждому номеру соответствует ровно один файл
    /// `migrations/NNNN_*.sql` с тем же содержимым; лишних файлов в каталоге нет.
    #[test]
    fn migration_numbers_are_sequential_and_match_files() {
        for (i, (version, _, _)) in MIGRATIONS.iter().enumerate() {
            assert_eq!(
                *version,
                i64::try_from(i).expect("индекс") + 1,
                "версии миграций должны идти подряд с 1 (позиция {i})"
            );
        }

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
        let mut files: Vec<(i64, String)> = Vec::new();
        for entry in std::fs::read_dir(&dir).expect("каталог migrations") {
            let name = entry
                .expect("запись каталога")
                .file_name()
                .to_string_lossy()
                .into_owned();
            let (num, rest) = name.split_once('_').unwrap_or((&name, ""));
            let num: i64 = num
                .parse()
                .unwrap_or_else(|_| panic!("имя файла миграции без номера: {name}"));
            assert!(
                num.to_string().len() <= 4 && name.len() > 5 && rest.ends_with(".sql"),
                "имя файла миграции не вида NNNN_*.sql: {name}"
            );
            files.push((num, name));
        }
        files.sort();

        for pair in files.windows(2) {
            assert_ne!(
                pair[0].0, pair[1].0,
                "два файла с одним номером миграции: {} и {}",
                pair[0].1, pair[1].1
            );
        }
        let nums: Vec<i64> = files.iter().map(|(n, _)| *n).collect();
        let versions: Vec<i64> = MIGRATIONS.iter().map(|(v, _, _)| *v).collect();
        assert_eq!(
            nums, versions,
            "файлы в migrations/ и список MIGRATIONS расходятся"
        );

        for ((version, _, sql), (_, name)) in MIGRATIONS.iter().zip(&files) {
            assert!(
                name.starts_with(&format!("{version:04}_")),
                "номер в имени {name} не совпадает с версией {version}"
            );
            let on_disk = std::fs::read_to_string(dir.join(name)).expect("файл миграции");
            assert_eq!(&on_disk, sql, "файл {name} не тот, что подключён в списке");
        }
    }
}
