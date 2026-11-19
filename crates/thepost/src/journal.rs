//! Журналирование переписки в узле (APP-84, SRS 4.9; CTR-97): подключение этапа конвейера доставки
//! (`Delivery::with_journal`, SMTP-53) к инфраструктуре узла. Источник правил — порт tp-smtp
//! `JournalRules` над `PgJournal::rules` (META-88, `journal.rules`): чтение на каждое письмо,
//! изменения через Admin API действуют сразу, без перезапуска. Хранилище записей — `PgJournal`
//! (трейт `JournalStore`): индекс PostgreSQL (схема `journal`) поверх отдельного от BLOB ящиков
//! бакета/каталога секции `journal` (APP-83) через порт `JournalRecords` — полную проводку
//! put/read/scan даёт [`NodeRecords`] (адаптер проверок doctor из APP-82 проводит только `scan`).
//! Запись двухфазная, как в контракте: сначала бакет (идемпотентна, вне транзакции БД), затем строка
//! индекса; обрыв между фазами лечит `JournalStore::restore_index`. То же хранилище читает Admin API
//! (ADM-52: роль «аудитор журнала», [`NodeJournal::store`]). Секция `journal` выключена —
//! [`NodeJournal::open`] возвращает `None`, этап конвейера не ставится: поведение узла прежнее.
//!
//! Модульные этапы конвейера (`Delivery::with_stage`, точка расширения SRS 4.10) узел не подключает:
//! задел под будущие модули «Правил потока почты»; ядро конвейера (SMTP-54) в этапе не нуждается.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tp_contracts::Error;
use tp_contracts::Result;
use tp_contracts::ids::{JournalId, TenantId};
use tp_contracts::journal::{
    GENESIS_HASH, JournalRecord, JournalRecords, JournalRule, JournalStore,
};
use tp_contracts::secrets::SecretStore;
use tp_meta::PgMeta;
use tp_meta::journal::PgJournal;
use tp_meta::pool::DbPool;
use tp_meta::schema::db_err;
use tp_platform::Config;
use tp_smtp::deliver::journal::{JournalRules, Journaling};

use crate::infra;
use crate::sections::{JOURNAL, JournalSection};

/// Блокировка писателя хранилища записей организации (CTR-97): фаза бакета двухфазной записи
/// сериализуется между процессами — узлы кластера одной организации журналируют параллельно, а
/// развилка цепочки хранилища (BLOB-18: два писателя с одной предыдущей записью) — нарушение,
/// которое видит `thepost doctor journal chain`. Сессионная (не транзакционная): бакет пишется вне
/// транзакции БД. Ключ отличен от блокировки порядка индекса (`thepost:journal:`) — фазы не мешают
/// друг другу; соединение закрывается — сервер снимает блокировку сам.
const PUT_LOCK: &str = "SELECT pg_advisory_lock(hashtextextended('thepost:journal-put:' || $1, 0))";
const PUT_UNLOCK: &str =
    "SELECT pg_advisory_unlock(hashtextextended('thepost:journal-put:' || $1, 0))";

/// Порт хранилища записей журнала (CTR-97, META-88) над реализацией tp-blob (BLOB-18) — полная
/// проводка для конвейера и выгрузки (адаптер doctor из APP-82 проверяет только `scan`): `put` —
/// запись в бакет с продолжением цепочки хранилища (писатель один на организацию — блокировка
/// [`PUT_LOCK`]), `read` — конверт и письмо по глобально уникальному идентификатору, `scan` — конверты
/// организации в порядке цепочки (порядке добавления) со ссылкой — путём объекта записи.
pub struct NodeRecords {
    /// Хранилище записей над отдельным бакетом/каталогом журнала (BLOB-18).
    records: Arc<tp_blob::JournalRecords>,
    /// Пул узла: сессионная блокировка писателя организации.
    pool: DbPool,
}

impl NodeRecords {
    /// Порт над хранилищем записей `records` (BLOB-18, бакет/каталог секции `journal`) с блокировкой
    /// писателя на пуле `pool`.
    pub fn new(records: Arc<tp_blob::JournalRecords>, pool: DbPool) -> Self {
        Self { records, pool }
    }

    /// Фаза бакета под блокировкой писателя: `prev` — хеш последней записи цепочки хранилища
    /// организации (у первой — GENESIS), повторная запись того же идентификатора — та же ссылка
    /// (идемпотентность порта). Возвращает ссылку — путь объекта записи.
    async fn put_serialized(
        &self,
        id: JournalId,
        record: &JournalRecord,
        message: Bytes,
    ) -> Result<String> {
        let tenant = record.tenant;
        if self.records.stored(tenant, id).await.is_ok() {
            return Ok(self.records.record_path(tenant, record.at, id));
        }
        let prev = self
            .records
            .chain(tenant)
            .await?
            .last()
            .map_or(GENESIS_HASH, |s| s.hash);
        self.records.put(id, prev, record, message).await?;
        Ok(self.records.record_path(tenant, record.at, id))
    }
}

#[async_trait]
impl JournalRecords for NodeRecords {
    async fn put(&self, id: JournalId, record: &JournalRecord, message: Bytes) -> Result<String> {
        record.validate()?;
        if message.is_empty() {
            return Err(Error::invalid("journal: empty message"));
        }
        let tenant = record.tenant;
        let mut conn = self.pool.acquire().await?;
        sqlx::query(PUT_LOCK)
            .bind(tenant.to_string())
            .execute(&mut *conn)
            .await
            .map_err(db_err)?;
        let out = self.put_serialized(id, record, message).await;
        if let Err(e) = sqlx::query(PUT_UNLOCK)
            .bind(tenant.to_string())
            .execute(&mut *conn)
            .await
        {
            // Соединение отказало — блокировку снимет сервер, закрыв сессию (соединение с ошибкой
            // пул не переиспользует); запись уже решена `out`.
            tracing::warn!(%tenant, error = %e, "journal: блокировка записи журнала не снята");
        }
        out
    }

    async fn read(&self, id: JournalId) -> Result<(JournalRecord, Bytes)> {
        self.records.read_any(id).await
    }

    async fn scan(&self, tenant: TenantId) -> Result<Vec<(JournalId, JournalRecord, String)>> {
        let records = self.records.clone();
        Ok(records
            .chain(tenant)
            .await?
            .into_iter()
            .map(|s| {
                let storage = records.record_path(tenant, s.record.at, s.id);
                (s.id, s.record, storage)
            })
            .collect())
    }
}

/// Правила журналирования организации (SMTP-53): порт tp-smtp над `PgJournal::rules` (META-88) —
/// чтение на каждое письмо, изменения через Admin API действуют сразу (SRS 2.8). Образец подключения
/// приложения — `Delivery::with_messages` (#155).
struct NodeRules(PgJournal);

#[async_trait]
impl JournalRules for NodeRules {
    async fn rules(&self, tenant: TenantId) -> Result<Vec<JournalRule>> {
        self.0.rules(tenant).await
    }
}

/// Журналирование узла (APP-84): источник правил и хранилище записей с индексом для этапа конвейера
/// доставки (`Delivery::with_journal`, SMTP-53). Индекс — `PgJournal` (META-88) над портом
/// [`NodeRecords`] (бакет BLOB-18); этап ставится только при включённой секции `journal`
/// ([`NodeJournal::open`]).
pub struct NodeJournal {
    /// Правила организации над `PgJournal::rules`.
    rules: Arc<NodeRules>,
    /// Индекс и хранилище записей (двухфазная запись).
    store: Arc<PgJournal>,
}

impl NodeJournal {
    /// Открытие по секции `journal` (APP-83): выключена (или не задана — умолчание) — `None`, этап
    /// конвейера не ставится, поведение узла прежнее; включена — хранилище записей (отдельный от BLOB
    /// ящиков бакет/каталог, [`infra::open_journal_records`]) и индекс `PgJournal` на пуле `meta`.
    /// Ключи S3 — из хранилища секретов `secrets`.
    pub async fn open(
        cfg: &Config,
        meta: &PgMeta,
        secrets: Option<&Arc<dyn SecretStore>>,
    ) -> Result<Option<Self>> {
        let section = cfg.section::<JournalSection>(JOURNAL)?;
        if !section.enabled() {
            return Ok(None);
        }
        let records = infra::open_journal_records(cfg, &section, secrets).await?;
        let port = Arc::new(NodeRecords::new(records, meta.pool().clone()));
        let store = Arc::new(PgJournal::new(meta.clone(), port));
        Ok(Some(Self {
            rules: Arc::new(NodeRules((*store).clone())),
            store,
        }))
    }

    /// Этап журналирования для `Delivery::with_journal` (SMTP-53): правила организации и хранилище
    /// записей; запись — до Sieve ящика, конверт — полный (скрытые получатели, раскрытые группы).
    pub fn journaling(&self) -> Journaling {
        Journaling::new(self.rules.clone(), self.store.clone())
    }

    /// Хранилище записей с индексом для Admin API (ADM-52: поиск, просмотр, выгрузка `.eml`, проверка
    /// цепочки — роль «аудитор журнала») и выгрузки во внешний архив; то же хранилище, что пишет этап
    /// конвейера.
    pub fn store(&self) -> Arc<dyn JournalStore> {
        self.store.clone()
    }
}
