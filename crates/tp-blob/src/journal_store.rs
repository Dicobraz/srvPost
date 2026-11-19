//! Хранилище записей журнала переписки поверх инфраструктуры tp-blob (BLOB-18; CONTRACTS.md#Journal;
//! SRS 4.9, 5.2; CTR-97).
//!
//! Отдельное от BLOB ящиков хранилище: экземпляр [`JournalRecords`] открывается поверх собственного
//! каталога/бакета (`LocalStore`/`S3Store` с отдельным корнем — конфигурация секции журнала),
//! внутри — собственный префикс (по умолчанию `journal`). Удаление письма пользователем журнал не
//! затрагивает, GC и «сироты» BLOB ящиков работают по своему корню и объектов журнала не видят;
//! методов удаления у хранилища нет — записи только добавляются (SRS 4.9).
//!
//! Макет объектов (пути `put_raw` внутри корня журнала):
//! - запись `{prefix}/t/{tenant}/{YYMMDD}/{JournalId}` — JSON [`StoredRecord`]: конверт письма
//!   (метаданные), манифест частей, хеш цепочки со ссылкой на предыдущую запись, блокировка;
//! - часть `{prefix}/p/{tenant}/{hash[0..2]}/{hash}` — содержимое части по хешу SHA-256
//!   (дедупликация внутри организации; с BLOB ящиками части не разделяются).
//!
//! Дедупликация (SRS 4.9): письмо режется на части по содержимому (content-defined chunking: окно
//! 48 байт, порог из конфигурации) — границы частей зависят только от самих байтов, поэтому
//! одинаковое содержимое разных писем (вложения, пересылки) даёт одинаковые части и хранится один
//! раз. «Тело, вложения» как у Exchange single-instance storage, но без разбора MIME: часть —
//! сегмент содержимого, экономия достигается при любом расположении повтора.
//!
//! Срок блокировки (SRS 4.9; решение #113): tp-blob сам пишет режим (`compliance`/`governance`,
//! задаёт заказчик) и срок `retain_until = время записи + retention` в каждый объект при записи —
//! `x-amz-meta-thepost-lock-mode`/`-until` на S3 ([`lock_attributes`]), в объекте записи — и в
//! JSON ([`StoredRecord::retention`]). Метаданные объекта — источник истины по сроку: у старого
//! бакета дефолтный срок Object Lock может быть короче нужного, на него нельзя полагаться;
//! бакетный Object Lock — только уровень исполнения (сервер реально запретит удаление). Дефолт
//! бакета клиент `object_store` не читает, рассинхрон проверяет thepost doctor (APP-82); срок
//! короче суток в конфигурации — предупреждение в журнал узла ([`JournalRecords::new`]).
//! Срок объекта части — наибольший из ссылающихся записей ([`JournalRecords::part_retention`]):
//! новая ссылка перезаписывает метаданные части на больший срок, уменьшить нельзя — записи
//! неизменяемы; локальный бэкенд метаданных объектов не хранит — срок части выводится из записей
//! организации (защита от администратора ОС и не требуется: профиль SMB — warning doctor).
//!
//! Хеш-цепочка (CTR-97): каждая запись хранит `hash = SHA-256(chain_input(prev, record))` и `prev`
//! — хеш предыдущей записи организации (у первой [`GENESIS_HASH`]). Порядок цепи восстанавливается
//! по ссылкам без внешнего состояния: [`JournalRecords::chain`] собирает записи в порядке
//! добавления, [`JournalRecords::verify`] пересчитывает SHA-256 и ловит подмену конверта, потерю и
//! развилку. Индекс для поиска (PostgreSQL, схема journal) — META-88: пишет через
//! [`JournalRecords::put`], передавая `prev` из своей транзакции, и восстанавливается
//! [`JournalRecords::chain`]. Эта реализация [`JournalStore`] держит индекс в памяти (небольшие
//! установки и тесты), лениво собирая его из хранилища; потерянный индекс восстанавливает
//! [`JournalStore::restore_index`].
//!
//! Писатель — один процесс на организацию (роль transport; производство сериализует записи
//! транзакцией индекса). Конкурентные записи из разных процессов дают развилку цепи — её видит
//! [`JournalRecords::verify`].

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::TryStreamExt;
use object_store::{Attribute, AttributeValue, Attributes};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use time::{OffsetDateTime, PrimitiveDateTime};
use tokio::sync::Mutex as AsyncMutex;
use tp_contracts::blob::BlobStore;
use tp_contracts::config::duration;
use tp_contracts::ids::{BlobHash, JournalId, TenantId};
use tp_contracts::journal::{
    ChainReport, GENESIS_HASH, JournalAudit, JournalCursor, JournalEntry, JournalPage,
    JournalQuery, JournalRecord, JournalRule, JournalStore, chain_input, journal_eml,
};
use tp_contracts::{Error, Result};

use crate::{BlobHasher, LocalStore, Now, S3Store};

/// Размер окна разреза частей, байт: границы зависят от содержимого окна, а не позиции.
const CHUNK_WINDOW: usize = 48;

/// 2^48 — вес уходящего байта окна при обновлении gear-хеша.
const WINDOW_SCALE: u64 = 1u64 << CHUNK_WINDOW;

/// Таблица gear-хеша: детерминированные псевдослучайные значения SplitMix64 (без зависимости rand).
static GEAR: [u64; 256] = gear_table();

/// Таблица gear-хеша: поток SplitMix64 от фиксированного посева (const — один и тот же везде).
const fn gear_table() -> [u64; 256] {
    let mut table = [0u64; 256];
    let mut state = 0x0123_4567_89ab_cdefu64;
    let mut i = 0;
    while i < 256 {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        table[i] = z ^ (z >> 31);
        i += 1;
    }
    table
}

/// Режим блокировки объектов журнала (S3 Object Lock; SRS 4.9) — задаёт заказчик.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LockMode {
    /// Удаление только ролью с правом обхода блокировки, с записью в журнал аудита.
    #[default]
    Governance,
    /// Объект не удаляет никто до окончания срока, включая администратора хранилища.
    Compliance,
}

impl LockMode {
    /// Строка в метаданных объекта и config.yaml (`governance`, `compliance`).
    pub const fn as_str(self) -> &'static str {
        match self {
            LockMode::Governance => "governance",
            LockMode::Compliance => "compliance",
        }
    }

    /// Разбор строки метаданных; иное — `None`.
    fn parse(s: &str) -> Option<Self> {
        match s {
            "governance" => Some(LockMode::Governance),
            "compliance" => Some(LockMode::Compliance),
            _ => None,
        }
    }
}

/// Ключи метаданных блокировки объекта журнала (`x-amz-meta-thepost-lock-*` на S3; решение #113:
/// tp-blob сам пишет режим и срок при записи — источник истины по сроку, бакетный Object Lock
/// только исполняет запрет удаления: у старого бакета дефолтный срок может быть короче).
const LOCK_MODE_KEY: &str = "thepost-lock-mode";
const LOCK_UNTIL_KEY: &str = "thepost-lock-until";

/// Метаданные блокировки `retention` как атрибуты объекта.
fn lock_attributes(retention: &Retention) -> Attributes {
    let mut attrs = Attributes::new();
    attrs.insert(
        Attribute::Metadata(LOCK_MODE_KEY.into()),
        AttributeValue::from(retention.mode.as_str()),
    );
    attrs.insert(
        Attribute::Metadata(LOCK_UNTIL_KEY.into()),
        AttributeValue::from(retention.until.unix_timestamp().to_string()),
    );
    attrs
}

/// Блокировка из атрибутов объекта; метаданных нет или не разбираются — `None`.
fn lock_from_attributes(attrs: &Attributes) -> Option<Retention> {
    let mode = attrs
        .get(&Attribute::Metadata(LOCK_MODE_KEY.into()))
        .and_then(|v| LockMode::parse(v.as_ref()))?;
    let until = attrs
        .get(&Attribute::Metadata(LOCK_UNTIL_KEY.into()))
        .and_then(|v| v.as_ref().parse::<i64>().ok())
        .and_then(|t| OffsetDateTime::from_unix_timestamp(t).ok())?;
    Some(Retention { mode, until })
}

/// Блокировка объекта: режим и срок (SRS 4.9). Срок продлевается только.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retention {
    /// Режим из конфигурации установки.
    pub mode: LockMode,
    /// Действует до этого момента (UTC).
    pub until: OffsetDateTime,
}

/// Конфигурация хранилища записей журнала (секция рядом с `blob`; SRS 5.5). Отдельный бакет или
/// каталог задаётся бэкендом журнала (его `s3`/`local` подсекция), здесь — параметры записей.
///
/// ```yaml
/// prefix: journal
/// lock_mode: governance
/// retention: 730d
/// chunk_min_bytes: 65536
/// chunk_avg_bytes: 524288
/// chunk_max_bytes: 2097152
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct JournalConfig {
    /// Префикс объектов журнала внутри корня/бакета; сегменты через `/`, без пустых.
    pub prefix: String,
    /// Режим блокировки объектов (S3 Object Lock); по умолчанию `governance`, `compliance` — явно.
    pub lock_mode: LockMode,
    /// Срок хранения при записи (`retention: 730d`); продлевается только.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub retention: Duration,
    /// Минимальный размер части, байт: ближе точки сливаются.
    pub chunk_min_bytes: usize,
    /// Средний размер части, байт: задаёт порог разреза (степень двойки рядом).
    pub chunk_avg_bytes: usize,
    /// Максимальный размер части, байт: режется принудительно.
    pub chunk_max_bytes: usize,
}

impl Default for JournalConfig {
    fn default() -> Self {
        Self {
            prefix: "journal".to_owned(),
            lock_mode: LockMode::default(),
            retention: Duration::from_secs(730 * 24 * 3600),
            chunk_min_bytes: 64 << 10,
            chunk_avg_bytes: 512 << 10,
            chunk_max_bytes: 2 << 20,
        }
    }
}

impl JournalConfig {
    /// Проверка (запуск и `thepost config check`): префикс из сегментов без пустых и ведущих точек,
    /// срок положителен, размеры частей `0 < min ≤ avg ≤ max`.
    pub fn validate(&self) -> Result<()> {
        let bad_prefix = self.prefix.is_empty()
            || self.prefix.contains(['\\', '\0'])
            || self.prefix.ends_with('/')
            || self
                .prefix
                .split('/')
                .any(|s| s.is_empty() || s.starts_with('.'));
        if bad_prefix {
            return Err(Error::invalid(format!(
                "journal: bad prefix {:?}",
                self.prefix
            )));
        }
        if self.retention.is_zero() {
            return Err(Error::invalid("journal: retention must be positive"));
        }
        if self.chunk_min_bytes == 0
            || self.chunk_min_bytes > self.chunk_avg_bytes
            || self.chunk_avg_bytes > self.chunk_max_bytes
        {
            return Err(Error::invalid(
                "journal: chunk sizes must satisfy 0 < min <= avg <= max",
            ));
        }
        Ok(())
    }

    /// Маска порога разреза: средний размер `avg` → порог `2^-⌈log2 avg⌉` на байт (части ~avg).
    fn chunk_mask(&self) -> u64 {
        let avg = self.chunk_avg_bytes.clamp(2, 1 << 31) as u64;
        let bits = u64::BITS - (avg - 1).leading_zeros();
        (1u64 << bits) - 1
    }
}

/// Запись журнала в хранилище: конверт письма (метаданные), манифест частей и связь цепочки.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRecord {
    /// Идентификатор записи (повторяет имя объекта).
    pub id: JournalId,
    /// Конверт письма.
    pub record: JournalRecord,
    /// Части письма по порядку; содержимое — объекты по хешу.
    pub parts: Vec<BlobHash>,
    /// Хеш цепочки: `SHA-256(chain_input(prev, record))`.
    pub hash: BlobHash,
    /// Хеш предыдущей записи организации; у первой — [`GENESIS_HASH`].
    pub prev: BlobHash,
    /// Блокировка при записи; срок части — наибольший из ссылающихся записей.
    pub retention: Retention,
}

/// Бэкенд записей журнала: хранилище объектов с записью метаданных блокировки (SRS 4.9; решение
/// #113 — режим и срок в каждый объект пишет tp-blob при записи, бакетный дефолт в срок не
/// входит). Реализации крейта: [`S3Store`] (`x-amz-meta-thepost-lock-*`) и [`LocalStore`]
/// (локальный диск метаданных объектов не хранит — срок живёт в объекте записи).
#[async_trait]
pub trait JournalBackend: BlobStore {
    /// Записывает объект `path` с содержимым `data` и метаданными блокировки `lock`
    /// (существующий объект заменяется — срок метаданных только продлевается).
    async fn put_raw_locked(&self, path: &str, data: Bytes, lock: &Retention) -> Result<()>;

    /// Метаданные блокировки объекта `path`. Нет объекта — `NotFound`; бэкенд без метаданных
    /// объектов — `None`.
    async fn raw_lock(&self, path: &str) -> Result<Option<Retention>>;
}

#[async_trait]
impl JournalBackend for S3Store {
    async fn put_raw_locked(&self, path: &str, data: Bytes, lock: &Retention) -> Result<()> {
        self.put_raw_with_attributes(path, data, lock_attributes(lock))
            .await
    }

    async fn raw_lock(&self, path: &str) -> Result<Option<Retention>> {
        Ok(lock_from_attributes(&self.raw_attributes(path).await?))
    }
}

#[async_trait]
impl JournalBackend for LocalStore {
    async fn put_raw_locked(&self, path: &str, data: Bytes, _lock: &Retention) -> Result<()> {
        self.put_raw_with_attributes(path, data, Attributes::new())
            .await
    }

    async fn raw_lock(&self, _path: &str) -> Result<Option<Retention>> {
        // Локальный бэкенд метаданных не хранит: срок части выводится из записей организации,
        // срок записи — в её объекте ([`StoredRecord::retention`]).
        Ok(None)
    }
}

/// Хранилище записей журнала (SRS 4.9) поверх отдельного от BLOB ящиков бэкенда
/// ([`JournalBackend`]). Реализует [`JournalStore`] с индексом в памяти; полные установки
/// используют индекс PostgreSQL (META-88) поверх [`JournalRecords::put`]/[`JournalRecords::chain`].
pub struct JournalRecords {
    backend: Arc<dyn JournalBackend>,
    cfg: JournalConfig,
    now: Now,
    /// Индексы организаций; карта — на короткой блокировке без await.
    index: Mutex<HashMap<TenantId, Arc<AsyncMutex<TenantIndex>>>>,
    /// Поколение индекса: `drop_index` увеличивает — загруженные индексы считаются потерянными.
    epoch: AtomicU64,
}

/// Индекс организации в памяти: записи в порядке цепи.
#[derive(Default)]
struct TenantIndex {
    entries: Vec<JournalEntry>,
    /// Индекс загружен из хранилища (лениво при первом обращении).
    loaded: bool,
    /// Поколение, в котором загрузился индекс; меньше текущего — потерян (`drop_index`).
    epoch: u64,
}

impl std::fmt::Debug for JournalRecords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournalRecords")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl JournalRecords {
    /// Хранилище над `backend` — отдельным от BLOB ящиков корнем/бакетом — с конфигурацией `cfg`
    /// и часами `now` ([`crate::system_now`]). Конфигурация проверяется, ошибка — `Invalid`.
    /// Срок блокировки короче суток — предупреждение в журнал узла (решение #113: бакетный
    /// дефолт в срок не входит, короткий срок — почти всегда ошибка конфигурации).
    pub fn new(backend: Arc<dyn JournalBackend>, cfg: JournalConfig, now: Now) -> Result<Self> {
        cfg.validate()?;
        if cfg.retention < Duration::from_secs(24 * 3600) {
            tracing::warn!(
                retention = ?cfg.retention,
                "journal: срок блокировки меньше суток — проверьте секцию журнала и Object Lock \
                 бакета (дефолт бакета клиент не читает, срок гарантируют метаданные объектов)"
            );
        }
        Ok(Self {
            backend,
            cfg,
            now,
            index: Mutex::new(HashMap::new()),
            epoch: AtomicU64::new(0),
        })
    }

    /// Конфигурация хранилища.
    pub fn config(&self) -> &JournalConfig {
        &self.cfg
    }

    /// Путь объекта записи: `{prefix}/t/{tenant}/{YYMMDD}/{id}` (день — момент письма).
    fn record_path(&self, tenant: TenantId, at: OffsetDateTime, id: JournalId) -> String {
        format!(
            "{}/t/{}/{:02}{:02}{:02}/{}",
            self.cfg.prefix,
            tenant,
            at.year().rem_euclid(100),
            u8::from(at.month()),
            at.day(),
            id
        )
    }

    /// Путь объекта части: `{prefix}/p/{tenant}/{hash[0..2]}/{hash}` — дедупликация внутри
    /// организации: сроки блокировки разных организаций не смешиваются.
    fn part_path(&self, tenant: TenantId, hash: &BlobHash) -> String {
        let hex = hash.to_string();
        format!("{}/p/{}/{}/{}", self.cfg.prefix, tenant, &hex[..2], hex)
    }

    /// Записывает письмо частями (дедупликация) и объект записи; возвращает хеш цепочки записи.
    /// `prev` — хеш предыдущей записи организации (у первой [`GENESIS_HASH`]); порядок записей и
    /// единственность писателя обеспечивает вызывающий: транзакция индекса (META-88) или блокировка
    /// индекса этого экземпляра ([`JournalStore::append`]). Пустое письмо — `Invalid`.
    ///
    /// Блокировка (SRS 4.9, решение #113): режим и срок (`время записи + retention` из
    /// конфигурации) tp-blob пишет в каждый объект сам — метаданные объекта, не бакетный дефолт.
    /// Срок части — наибольший из ссылающихся записей: новая ссылка продлевает метаданные объекта
    /// части на больший срок (уменьшить нельзя — записи неизменяемы); содержимое существующих
    /// частей не меняется.
    pub async fn put(
        &self,
        id: JournalId,
        prev: BlobHash,
        record: &JournalRecord,
        message: Bytes,
    ) -> Result<BlobHash> {
        record.validate()?;
        if message.is_empty() {
            return Err(Error::invalid("journal: empty message"));
        }
        let parts = self.split_parts(message).await?;
        let retention = Retention {
            mode: self.cfg.lock_mode,
            until: after((self.now)(), self.cfg.retention),
        };
        // Наибольший срок каждой существующей части организации: сканирование записей раз на запись
        // (часть может быть старше новой записи и держать больший срок).
        let mut referenced: HashMap<BlobHash, Retention> = HashMap::new();
        for stored in self.load_records(record.tenant).await? {
            for hash in &stored.parts {
                match referenced.entry(*hash) {
                    Entry::Occupied(mut slot) if slot.get().until < stored.retention.until => {
                        slot.insert(stored.retention);
                    }
                    Entry::Vacant(slot) => {
                        slot.insert(stored.retention);
                    }
                    _ => {}
                }
            }
        }
        for (hash, chunk) in parts.iter() {
            let path = self.part_path(record.tenant, hash);
            let target = match referenced.get(hash) {
                Some(existing) if existing.until > retention.until => *existing,
                _ => retention,
            };
            match self.backend.get_raw(&path, Some(0..0)).await {
                Ok(_) => {
                    // Содержимое части неизменяемо; новая ссылка продлевает срок метаданными.
                    let extended = referenced
                        .get(hash)
                        .is_none_or(|existing| target.until > existing.until);
                    if extended {
                        self.backend
                            .put_raw_locked(&path, chunk.clone(), &target)
                            .await?;
                    }
                }
                Err(Error::NotFound) => {
                    self.backend
                        .put_raw_locked(&path, chunk.clone(), &target)
                        .await?;
                }
                Err(e) => return Err(e),
            }
        }
        let hash = BlobHasher::digest(&chain_input(&prev, record));
        let stored = StoredRecord {
            id,
            record: record.clone(),
            parts: parts.iter().map(|(h, _)| *h).collect(),
            hash,
            prev,
            retention,
        };
        let body = serde_json::to_vec(&stored)
            .map_err(|e| Error::internal(format!("journal: encode record: {e}")))?;
        let path = self.record_path(record.tenant, record.at, id);
        self.backend
            .put_raw_locked(&path, Bytes::from(body), &retention)
            .await?;
        tracing::debug!(
            tenant = %record.tenant, %id, parts = stored.parts.len(),
            "journal: record stored"
        );
        Ok(hash)
    }

    /// Объект записи (конверт, манифест, цепочка, блокировка). Нет записи или запись чужой
    /// организации — `NotFound`; повреждённый объект — `Internal`.
    pub async fn stored(&self, tenant: TenantId, id: JournalId) -> Result<StoredRecord> {
        let path = self.find_record_path(tenant, id).await?;
        let stored = self.read_record(&path).await?;
        if stored.id != id || stored.record.tenant != tenant {
            return Err(Error::NotFound);
        }
        Ok(stored)
    }

    /// Письмо записи: части по манифесту, хеш каждой части проверяется при чтении (подмена
    /// содержимого ловится). Нет записи — `NotFound`.
    pub async fn message(&self, tenant: TenantId, id: JournalId) -> Result<Bytes> {
        let stored = self.stored(tenant, id).await?;
        self.assemble(&stored).await
    }

    /// Записи организации в порядке цепи — порядке добавления: порядок восстанавливается по
    /// ссылкам `prev` от [`GENESIS_HASH`]. Развилка или потерянная запись обрывают цепь: её
    /// обходная часть — до разрыва; недостижимые записи сюда не попадают, их видит [`Self::verify`].
    /// Этим методом восстанавливается индекс (META-88).
    pub async fn chain(&self, tenant: TenantId) -> Result<Vec<StoredRecord>> {
        let (chain, _) = self.walk(tenant).await?;
        Ok(chain)
    }

    /// Проверка хеш-цепочки организации (SHA-256, CTR-97) по хранилищу записей: подмена конверта,
    /// развилка и потеря записи — `ok = false` с первой такой записью; `records` — просмотренные
    /// записи цепи. Используют `thepost doctor` (APP-82) и Admin API.
    pub async fn verify(&self, tenant: TenantId) -> Result<ChainReport> {
        let (chain, broken) = self.walk(tenant).await?;
        // Пересчёт от генезиса: подмененный конверт даёт другой SHA-256 при том же сохранённом хеше.
        let mut prev = GENESIS_HASH;
        let mut mismatch: Option<JournalId> = None;
        for stored in &chain {
            if mismatch.is_none() {
                let expected = BlobHasher::digest(&chain_input(&prev, &stored.record));
                if expected != stored.hash {
                    mismatch = Some(stored.id);
                }
            }
            prev = stored.hash;
        }
        Ok(ChainReport {
            records: chain.len() as u64,
            ok: broken.is_empty() && mismatch.is_none(),
            broken_at: mismatch.or_else(|| broken.first().copied()),
        })
    }

    /// Действующая блокировка части: режим и наибольший срок из ссылающихся записей организации
    /// (SRS 4.9: новая ссылка продлевает срок части до наибольшего из ссылающихся; уменьшить
    /// нельзя — записи неизменяемы). Источник истины — записи (решение #113); метаданные объекта
    /// части поддерживаются в том же значении при записи ([`JournalRecords::put`], S3
    /// `x-amz-meta-thepost-lock-*`). Нет ссылок — `None`.
    pub async fn part_retention(
        &self,
        tenant: TenantId,
        hash: &BlobHash,
    ) -> Result<Option<Retention>> {
        let mut best: Option<Retention> = None;
        for stored in self.load_records(tenant).await? {
            if stored.parts.contains(hash) && best.is_none_or(|r| stored.retention.until > r.until)
            {
                best = Some(stored.retention);
            }
        }
        Ok(best)
    }

    /// Сборка письма из частей записи с проверкой хешей.
    async fn assemble(&self, stored: &StoredRecord) -> Result<Bytes> {
        let mut out = Vec::new();
        for hash in &stored.parts {
            let body = self
                .read_object(&self.part_path(stored.record.tenant, hash))
                .await?;
            if BlobHasher::digest(&body) != *hash {
                return Err(Error::internal(format!(
                    "journal: part {hash} of record {} is corrupt",
                    stored.id
                )));
            }
            out.extend_from_slice(&body);
        }
        Ok(Bytes::from(out))
    }

    /// Обход цепи: записи в порядке добавления и идентификаторы записей с нарушением
    /// (дубликат хеша, развилка). Потерянная запись видна как недостижимость остатка.
    async fn walk(&self, tenant: TenantId) -> Result<(Vec<StoredRecord>, Vec<JournalId>)> {
        let records = self.load_records(tenant).await?;
        let mut broken: Vec<JournalId> = Vec::new();
        let mut by_prev: HashMap<BlobHash, Vec<&StoredRecord>> = HashMap::new();
        for stored in &records {
            let slot = by_prev.entry(stored.prev).or_default();
            slot.push(stored);
            if slot.len() > 1 {
                // Развилка: продолжает цепь запись раньше по (at, id), прочие — нарушение.
                let mut fork: Vec<&StoredRecord> = slot.to_vec();
                fork.sort_by_key(|s| (s.record.at, s.id));
                broken.extend(fork[1..].iter().map(|s| s.id));
            }
        }
        let mut chain = Vec::with_capacity(records.len());
        let mut cursor = GENESIS_HASH;
        // Шагов не больше записей: защита от цикла (криптографически невозможен, но не вечный цикл).
        let mut steps = records.len();
        while steps > 0
            && let Some(next) = by_prev.get(&cursor)
        {
            steps -= 1;
            let mut candidates: Vec<&StoredRecord> = next.to_vec();
            candidates.sort_by_key(|s| (s.record.at, s.id));
            let stored = candidates[0];
            chain.push(stored.clone());
            cursor = stored.hash;
        }
        // Недостижимые записи (потеряна предыдущая — цепь оборвалась) — тоже нарушение.
        let chained: HashSet<JournalId> = chain.iter().map(|s| s.id).collect();
        broken.extend(
            records
                .iter()
                .filter(|s| !chained.contains(&s.id))
                .map(|s| s.id),
        );
        broken.sort();
        broken.dedup();
        Ok((chain, broken))
    }

    /// Все разобранные записи организации в порядке (`at`, `id`). Повреждённый объект записи —
    /// `Internal` с именем записи (доктор показывает, где именно).
    async fn load_records(&self, tenant: TenantId) -> Result<Vec<StoredRecord>> {
        let prefix = format!("{}/t/{}/", self.cfg.prefix, tenant);
        let mut paths: Vec<String> = self
            .backend
            .list(&prefix, far_future())
            .map_ok(|entry| entry.path)
            .try_collect()
            .await?;
        paths.sort();
        let mut out = Vec::with_capacity(paths.len());
        for path in paths {
            // Имя объекта — идентификатор записи; прочие файлы (будущие служебные) пропускаем.
            let name = path.rsplit('/').next().unwrap_or_default();
            if name.parse::<JournalId>().is_err() {
                continue;
            }
            out.push(self.read_record(&path).await?);
        }
        out.sort_by_key(|s| (s.record.at, s.id));
        Ok(out)
    }

    /// Чтение и разбор объекта записи.
    async fn read_record(&self, path: &str) -> Result<StoredRecord> {
        let body = self.read_object(path).await?;
        serde_json::from_slice(&body).map_err(|e| {
            let name = path.rsplit('/').next().unwrap_or_default();
            Error::internal(format!("journal: record {name} is corrupt: {e}"))
        })
    }

    /// Путь объекта записи по идентификатору: день каталога неизвестен — поиском по объектам
    /// организации. Нет — `NotFound`.
    async fn find_record_path(&self, tenant: TenantId, id: JournalId) -> Result<String> {
        let prefix = format!("{}/t/{}/", self.cfg.prefix, tenant);
        self.find_under(&prefix, id).await
    }

    /// Поиск объекта записи по всему журналу (организация неизвестна): идентификатор записи —
    /// UUID, глобально уникален. Нет — `NotFound`.
    async fn find_record_path_any(&self, id: JournalId) -> Result<String> {
        let prefix = format!("{}/t/", self.cfg.prefix);
        self.find_under(&prefix, id).await
    }

    /// Объекты под `prefix`, чей путь заканчивается именем записи `id`.
    async fn find_under(&self, prefix: &str, id: JournalId) -> Result<String> {
        let suffix = format!("/{id}");
        let mut paths: Vec<String> = self
            .backend
            .list(prefix, far_future())
            .map_ok(|entry| entry.path)
            .try_collect()
            .await?;
        paths.sort();
        paths
            .into_iter()
            .find(|p| p.ends_with(&suffix))
            .ok_or(Error::NotFound)
    }

    /// Чтение объекта целиком.
    async fn read_object(&self, path: &str) -> Result<Bytes> {
        let chunks: Vec<Bytes> = self
            .backend
            .get_raw(path, None)
            .await?
            .try_collect()
            .await?;
        Ok(Bytes::from(chunks.concat()))
    }

    /// Разрез письма на части с хешами SHA-256; разрез и хеши — CPU, в `spawn_blocking`.
    async fn split_parts(&self, message: Bytes) -> Result<Vec<(BlobHash, Bytes)>> {
        let (min, mask, max) = (
            self.cfg.chunk_min_bytes,
            self.cfg.chunk_mask(),
            self.cfg.chunk_max_bytes,
        );
        tokio::task::spawn_blocking(move || {
            chunk_ranges(&message, min, mask, max)
                .into_iter()
                .map(|range| {
                    let chunk = message.slice(range);
                    (BlobHasher::digest(&chunk), chunk)
                })
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|e| Error::internal(format!("journal: chunking: {e}")))
    }

    /// Блокировка индекса организации (запись создаётся при первом обращении).
    fn tenant_lock(&self, tenant: TenantId) -> Result<Arc<AsyncMutex<TenantIndex>>> {
        let mut index = self
            .index
            .lock()
            .map_err(|_| Error::internal("journal: index lock poisoned"))?;
        Ok(index.entry(tenant).or_default().clone())
    }

    /// Индекс организации: при первом обращении или после потери загружается из хранилища.
    /// Потерянный индекс (`drop_index`) — `Internal` с подсказкой восстановить.
    async fn ensure_index(&self, tenant: TenantId) -> Result<Vec<JournalEntry>> {
        let lock = self.tenant_lock(tenant)?;
        let mut index = lock.lock().await;
        let stale = index.loaded && index.epoch != self.epoch.load(Ordering::Acquire);
        if stale {
            return Err(Error::internal("journal index is missing; run restore"));
        }
        if !index.loaded {
            index.reload(
                self.chain(tenant).await?,
                self.epoch.load(Ordering::Acquire),
            );
        }
        Ok(index.entries.clone())
    }

    /// Тест набора `suite::journal` (и doctor): подменяет конверт записи `id` в хранилище без
    /// пересчёта цепочки — выявляется [`Self::verify`] и [`JournalStore::verify_chain`].
    /// Организация не нужна: идентификатор записи глобально уникален.
    pub async fn tamper(&self, id: JournalId) -> Result<()> {
        let path = self.find_record_path_any(id).await?;
        let mut stored = self.read_record(&path).await?;
        if stored.id != id {
            return Err(Error::NotFound);
        }
        stored.record.sender = "tampered@example.invalid".to_owned();
        let body = serde_json::to_vec(&stored)
            .map_err(|e| Error::internal(format!("journal: encode record: {e}")))?;
        self.backend.put_raw(&path, Bytes::from(body)).await
    }

    /// Тест набора `suite::journal`: теряет индекс в памяти, не трогая хранилище записей;
    /// восстановление — [`JournalStore::restore_index`].
    pub fn drop_index(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }
}

impl TenantIndex {
    /// Пересобирает индекс из записей хранилища в порядке цепи.
    fn reload(&mut self, chain: Vec<StoredRecord>, epoch: u64) {
        self.entries = chain
            .into_iter()
            .map(|stored| JournalEntry {
                id: stored.id,
                record: stored.record,
                hash: stored.hash,
            })
            .collect();
        self.loaded = true;
        self.epoch = epoch;
    }
}

/// Разрез содержимого на части. Точки разреза — чистая функция содержимого: gear-хеш окна
/// [`CHUNK_WINDOW`] байт под порогом `mask` (средний размер части — `avg ≈ 2^⌈log2 mask⌉`); точки
/// ближе `min` сливаются; промежутки длиннее `max` режутся принудительно. Одинаковое содержимое в
/// разных письмах даёт одинаковые части — дедупликация внутри журнала (SRS 4.9).
fn chunk_ranges(data: &[u8], min: usize, mask: u64, max: usize) -> Vec<Range<usize>> {
    // Скользящий gear-хеш: добавляется входящий байт, вычитается ушедший с весом 2^48.
    let mut points: Vec<usize> = Vec::new();
    if data.len() >= CHUNK_WINDOW {
        let mut h: u64 = 0;
        for (i, &byte) in data.iter().enumerate() {
            h = h.wrapping_shl(1).wrapping_add(GEAR[usize::from(byte)]);
            if i >= CHUNK_WINDOW {
                let left = GEAR[usize::from(data[i - CHUNK_WINDOW])];
                h = h.wrapping_sub(left.wrapping_mul(WINDOW_SCALE));
            }
            if i + 1 >= CHUNK_WINDOW && (h & mask) == 0 {
                points.push(i + 1);
            }
        }
    }
    // Слияние: точка живёт, если дальше `min` от предыдущей живой.
    let mut kept: Vec<usize> = Vec::new();
    let mut last = 0usize;
    for point in points {
        if point - last >= min {
            kept.push(point);
            last = point;
        }
    }
    let mut ranges = Vec::new();
    let mut start = 0usize;
    let cut = |ranges: &mut Vec<Range<usize>>, start: &mut usize, end: usize| {
        while end - *start > max {
            ranges.push(*start..*start + max);
            *start += max;
        }
        ranges.push(*start..end);
        *start = end;
    };
    for point in kept {
        cut(&mut ranges, &mut start, point);
    }
    if start < data.len() {
        cut(&mut ranges, &mut start, data.len());
    }
    ranges
}

/// Момент позже любого срока: листинг всех объектов хранилища, предел сроков блокировки.
fn far_future() -> OffsetDateTime {
    PrimitiveDateTime::MAX.assume_utc()
}

/// `t + d`; вне диапазона — максимум времени (срок блокировки не уменьшается).
fn after(t: OffsetDateTime, d: Duration) -> OffsetDateTime {
    time::Duration::try_from(d)
        .ok()
        .and_then(|d| t.checked_add(d))
        .unwrap_or_else(far_future)
}

#[async_trait]
impl JournalStore for JournalRecords {
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
        let lock = self.tenant_lock(rule.tenant)?;
        let mut index = lock.lock().await;
        // Запись никогда не строит цепь от устаревшего индекса (потерян/другой процесс):
        // перезагружает его из хранилища — развилка исключена.
        let current = self.epoch.load(Ordering::Acquire);
        if !index.loaded || index.epoch != current {
            index.reload(self.chain(rule.tenant).await?, current);
        }
        let prev = index.entries.last().map_or(GENESIS_HASH, |e| e.hash);
        let id = JournalId::new();
        let hash = self.put(id, prev, record, message).await?;
        index.entries.push(JournalEntry {
            id,
            record: record.clone(),
            hash,
        });
        Ok(id)
    }

    async fn search(&self, _cap: &JournalAudit, query: &JournalQuery) -> Result<JournalPage> {
        query.validate()?;
        let entries = self.ensure_index(query.tenant).await?;
        let after = match &query.after {
            Some(c) => Some(parse_cursor(c)?),
            None => None,
        };
        let mut found: Vec<&JournalEntry> = entries
            .iter()
            .filter(|e| query.matches(&e.record))
            .filter(|e| {
                after.is_none_or(|(nanos, id)| {
                    (e.record.at.unix_timestamp_nanos(), e.id) > (nanos, id)
                })
            })
            .collect();
        found.sort_by_key(|e| (e.record.at, e.id));
        let has_more = found.len() > query.limit;
        found.truncate(query.limit);
        let next = has_more
            .then(|| found.last().map(|e| cursor(e.record.at, e.id)))
            .flatten();
        Ok(JournalPage {
            entries: found.into_iter().cloned().collect(),
            next,
        })
    }

    async fn export(&self, _cap: &JournalAudit, tenant: TenantId, id: JournalId) -> Result<Bytes> {
        let stored = self.stored(tenant, id).await?;
        let message = self.assemble(&stored).await?;
        journal_eml(&stored.record, &message)
    }

    async fn verify_chain(&self, _cap: &JournalAudit, tenant: TenantId) -> Result<ChainReport> {
        self.verify(tenant).await
    }

    async fn restore_index(&self, tenant: TenantId) -> Result<u64> {
        let lock = self.tenant_lock(tenant)?;
        let mut index = lock.lock().await;
        let chain = self.chain(tenant).await?;
        let restored = chain.len() as u64;
        index.reload(chain, self.epoch.load(Ordering::Acquire));
        Ok(restored)
    }
}

/// Позиция страницы поиска: `{наносекунды момента}|{id}` (образ `MemJournal`).
fn cursor(at: OffsetDateTime, id: JournalId) -> JournalCursor {
    JournalCursor(format!("{}|{id}", at.unix_timestamp_nanos()))
}

fn parse_cursor(c: &JournalCursor) -> Result<(i128, JournalId)> {
    let Some((nanos, id)) = c.0.split_once('|') else {
        return Err(Error::invalid("journal: bad cursor"));
    };
    Ok((
        nanos
            .parse()
            .map_err(|_| Error::invalid("journal: bad cursor"))?,
        id.parse()
            .map_err(|_| Error::invalid("journal: bad cursor"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use tp_contracts::blob::{Acquire, BlobIndex, Commit, ObjectEntry};
    use tp_contracts::journal::{JournalDirection, JournalScope};
    use tp_contracts::{BlobKey, Gen};

    use crate::{LocalConfig, LocalStore, OrphanConfig, OrphanSweeper, S3Config, S3Store};
    use tp_testkit::{ManualClock, MemBlobIndex, suite};

    /// Часы под управлением теста как [`Now`].
    fn test_clock(at: OffsetDateTime) -> (ManualClock, Now) {
        let clock = ManualClock::new(at);
        let shared = clock.shared();
        (clock, Arc::new(move || shared.now()))
    }

    /// S3-бэкенд поверх InMemory object_store (как s3-тесты blob; InMemory хранит атрибуты
    /// объектов — roundtrip метаданных блокировки проверяется без сети).
    fn backend_memory() -> Arc<S3Store> {
        Arc::new(S3Store::with_object_store(
            Arc::new(InMemory::new()),
            S3Config::default(),
        ))
    }

    /// Локальный бэкенд (профиль SMB) во временном каталоге.
    async fn backend_local(dir: &std::path::Path) -> Arc<LocalStore> {
        Arc::new(
            LocalStore::open(LocalConfig {
                root: dir.to_path_buf(),
                ..LocalConfig::default()
            })
            .await
            .expect("local open"),
        )
    }

    /// Параметры частей для тестов: маленькие части — дедуп виден на коротких письмах.
    fn cfg() -> JournalConfig {
        JournalConfig {
            chunk_min_bytes: 16,
            chunk_avg_bytes: 32,
            chunk_max_bytes: 64,
            ..JournalConfig::default()
        }
    }

    fn rule(tenant: TenantId) -> JournalRule {
        JournalRule {
            id: "r-0042".to_owned(),
            tenant,
            scope: JournalScope::Org,
            direction: JournalDirection::Both,
            enabled: true,
        }
    }

    fn record(tenant: TenantId, secs: i64, mid: &str) -> JournalRecord {
        JournalRecord {
            tenant,
            sender: "sender@external.example".to_owned(),
            recipients: vec!["anna@internal.example".to_owned()],
            message_id: Some(mid.to_owned()),
            at: OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time")
                + time::Duration::seconds(secs),
            rule: "r-0042".to_owned(),
        }
    }

    /// Псевдослучайное содержимое (xorshift): точки разреза есть, части не вырождаются.
    fn random_bytes(seed: u8, size: usize) -> Bytes {
        let mut out = Vec::with_capacity(size);
        let mut x = u64::from(seed) | 1;
        for _ in 0..size {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            out.push(x as u8);
        }
        Bytes::from(out)
    }

    /// Письмо с вложением `attach` между текстами `head`/`tail`.
    fn letter(head: &str, attach: &[u8], tail: &str) -> Bytes {
        let mut out = Vec::new();
        out.extend_from_slice(head.as_bytes());
        out.extend_from_slice(attach);
        out.extend_from_slice(tail.as_bytes());
        Bytes::from(out)
    }

    async fn part_count(store: &dyn BlobStore, cfg: &JournalConfig, tenant: TenantId) -> usize {
        store
            .list(&format!("{}/p/{tenant}/", cfg.prefix), far_future())
            .map_ok(|e: ObjectEntry| e.path)
            .try_collect::<Vec<_>>()
            .await
            .expect("part list")
            .len()
    }

    fn chunk_hashes(message: &Bytes, cfg: &JournalConfig) -> Vec<BlobHash> {
        chunk_ranges(
            message,
            cfg.chunk_min_bytes,
            cfg.chunk_mask(),
            cfg.chunk_max_bytes,
        )
        .into_iter()
        .map(|r| BlobHasher::digest(&message.slice(r)))
        .collect()
    }

    /// Замыкание `corrupt` набора `suite::journal`: подмена записи в отдельном потоке со своим
    /// маленьким рантаймом (замыкание синхронное, из задачи его не вызвать). Организация записи
    /// неизвестна вызывающему — подмена ищет запись по глобально уникальному идентификатору.
    fn corrupt_hook(journal: Arc<JournalRecords>) -> impl Fn(JournalId) + Send + Sync {
        move |id: JournalId| {
            let journal = journal.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("journal tamper runtime");
                rt.block_on(journal.tamper(id)).expect("journal tamper");
            })
            .join()
            .expect("journal tamper thread");
        }
    }

    #[tokio::test]
    async fn suite_journal_on_local_backend() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = backend_local(dir.path()).await;
        let (_, now) = test_clock(OffsetDateTime::UNIX_EPOCH);
        let journal = Arc::new(JournalRecords::new(backend, cfg(), now).expect("journal"));
        let corrupt = corrupt_hook(journal.clone());
        let drop_idx = {
            let journal = journal.clone();
            move || journal.drop_index()
        };
        suite::journal(journal.as_ref(), &corrupt, &drop_idx).await;
    }

    #[tokio::test]
    async fn suite_journal_on_s3_memory_backend() {
        let (_, now) = test_clock(OffsetDateTime::UNIX_EPOCH);
        let journal = Arc::new(JournalRecords::new(backend_memory(), cfg(), now).expect("journal"));
        let corrupt = corrupt_hook(journal.clone());
        let drop_idx = {
            let journal = journal.clone();
            move || journal.drop_index()
        };
        suite::journal(journal.as_ref(), &corrupt, &drop_idx).await;
    }

    #[tokio::test]
    async fn write_and_read_back() {
        let start = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("t");
        let (_, now) = test_clock(start);
        let backend = backend_memory();
        let journal = JournalRecords::new(backend.clone(), cfg(), now).expect("journal");
        let tenant = TenantId::DEFAULT;
        let message = random_bytes(1, 500);
        let id = journal
            .append(&rule(tenant), &record(tenant, 0, "m1@x"), message.clone())
            .await
            .expect("append");

        // Письмо читается байт в байт; export — .eml с конвертом.
        assert_eq!(journal.message(tenant, id).await.expect("message"), message);
        let eml = journal
            .export(&JournalAudit::grant(), tenant, id)
            .await
            .expect("export");
        assert_eq!(
            eml,
            journal_eml(&record(tenant, 0, "m1@x"), &message).expect("eml")
        );
        assert!(eml.starts_with(b"X-ThePost-Journal-Sender: sender@external.example\r\n"));
        assert!(eml.ends_with(&message[message.len() - 8..]));

        // Объект записи — по пути {prefix}/t/{tenant}/{YYMMDD}/{id}, с конвертом и цепочкой;
        // срок блокировки — время записи + retention из конфигурации.
        let at = record(tenant, 0, "m1@x").at;
        assert_eq!(
            journal.record_path(tenant, at, id),
            format!(
                "journal/t/{tenant}/{:02}{:02}{:02}/{id}",
                at.year() % 100,
                u8::from(at.month()),
                at.day()
            )
        );
        let stored = journal.stored(tenant, id).await.expect("stored");
        assert_eq!(stored.record, record(tenant, 0, "m1@x"));
        assert_eq!(stored.prev, GENESIS_HASH);
        assert_eq!(
            stored.hash,
            BlobHasher::digest(&chain_input(&GENESIS_HASH, &stored.record))
        );
        assert_eq!(stored.retention.mode, LockMode::default());
        assert_eq!(
            stored.retention.until,
            start + time::Duration::seconds(730 * 24 * 3600)
        );

        // Новый экземпляр над тем же корнем читает то же (индекс собирается из хранилища).
        let (_, now2) = test_clock(start);
        let second = JournalRecords::new(backend, cfg(), now2).expect("journal");
        assert_eq!(second.message(tenant, id).await.expect("again"), message);
        assert_eq!(
            second
                .search(&JournalAudit::grant(), &JournalQuery::all(tenant, 10))
                .await
                .expect("search")
                .entries
                .len(),
            1
        );
        // Чужая организация записи не видит.
        assert!(second.stored(TenantId::new(), id).await.is_err());
    }

    #[tokio::test]
    async fn dedup_same_attachment_single_part_objects() {
        let (_, now) = test_clock(OffsetDateTime::UNIX_EPOCH);
        let backend = backend_memory();
        let journal = JournalRecords::new(backend.clone(), cfg(), now).expect("journal");
        let tenant = TenantId::DEFAULT;

        let attach = random_bytes(7, 4096);
        let first = letter("Subject: one\r\n\r\n", &attach, "\r\n.");
        let second = letter("Subject: two, reply\r\n\r\nmore text\r\n", &attach, "\r\n.");
        journal
            .append(&rule(tenant), &record(tenant, 0, "m1@x"), first.clone())
            .await
            .expect("first append");
        let parts1 = part_count(backend.as_ref(), &cfg(), tenant).await;
        assert!(parts1 > 1, "вложение режется на части: {parts1}");

        journal
            .append(&rule(tenant), &record(tenant, 10, "m2@x"), second.clone())
            .await
            .expect("second append");
        let parts2 = part_count(backend.as_ref(), &cfg(), tenant).await;

        // Дедуп: объекты частей = уникальные части писем; второе письмо добавило только свои,
        // общее вложение двух писем хранится один раз.
        let unique: HashSet<BlobHash> = chunk_hashes(&first, &cfg())
            .into_iter()
            .chain(chunk_hashes(&second, &cfg()))
            .collect();
        let first_unique: HashSet<BlobHash> = chunk_hashes(&first, &cfg()).into_iter().collect();
        let second_unique: HashSet<BlobHash> = chunk_hashes(&second, &cfg()).into_iter().collect();
        let shared = first_unique.intersection(&second_unique).count();
        assert_eq!(parts1, first_unique.len(), "первое письмо — свои части");
        assert_eq!(
            parts2,
            unique.len(),
            "дублирующееся вложение хранится один раз"
        );
        assert!(parts2 > parts1, "второе письмо добавило свои части");
        assert!(
            shared > first_unique.len() / 2,
            "части общего вложения совпадают: {shared} из {}",
            first_unique.len()
        );

        // Оба письма собираются из частей байт в байт.
        let page = journal
            .search(&JournalAudit::grant(), &JournalQuery::all(tenant, 10))
            .await
            .expect("search");
        assert_eq!(page.entries.len(), 2);
        for entry in &page.entries {
            let message = journal.message(tenant, entry.id).await.expect("message");
            assert!(
                message == first || message == second,
                "собрано исходное письмо"
            );
        }
    }

    #[tokio::test]
    async fn retention_extends_on_second_reference() {
        let start = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("t");
        let (clock, now) = test_clock(start);
        let backend = backend_memory();
        let mut cfg = cfg();
        cfg.retention = Duration::from_secs(3600);
        let journal = JournalRecords::new(backend.clone(), cfg, now).expect("journal");
        let tenant = TenantId::DEFAULT;

        let attach = random_bytes(9, 2048);
        let first = letter("Subject: one\r\n\r\n", &attach, "");
        let second = letter("Subject: two\r\n\r\n", &attach, "");
        journal
            .append(&rule(tenant), &record(tenant, 0, "m1@x"), first)
            .await
            .expect("first");
        // Средняя часть вложения: обе записи на неё ссылаются (граничные части различаются).
        let part = journal
            .chain(tenant)
            .await
            .expect("chain")
            .first()
            .map(|stored| stored.parts[stored.parts.len() / 2])
            .expect("part");
        let before = journal
            .part_retention(tenant, &part)
            .await
            .expect("retention")
            .expect("referenced");
        assert_eq!(before.mode, LockMode::Governance);
        assert_eq!(before.until, start + time::Duration::hours(1));

        // Вторая ссылка позже: срок части — наибольший из ссылающихся записей, только растёт.
        clock.advance(Duration::from_secs(1800));
        journal
            .append(&rule(tenant), &record(tenant, 10, "m2@x"), second)
            .await
            .expect("second");
        let extended = journal
            .part_retention(tenant, &part)
            .await
            .expect("retention")
            .expect("referenced");
        assert_eq!(
            extended.until,
            start + time::Duration::hours(1) + time::Duration::seconds(1800)
        );
        assert!(
            extended.until > before.until,
            "срок блокировки только растёт"
        );

        // Метаданные объекта части продлены новой ссылкой (решение #113: срок пишет tp-blob,
        // x-amz-meta-thepost-lock-* на S3, бакетный дефолт в срок не входит).
        let lock = backend
            .raw_lock(&journal.part_path(tenant, &part))
            .await
            .expect("raw lock")
            .expect("part metadata");
        assert_eq!(lock, extended);

        // Часть без ссылок (не из манифеста) — None.
        let stray = BlobHasher::digest(b"no such part");
        assert_eq!(
            journal.part_retention(tenant, &stray).await.expect("scan"),
            None
        );
    }

    /// Метаданные блокировки пишет tp-blob и читает обратно (решение #113): режим и срок из
    /// конфигурации — в объекте записи и в каждом объекте части; без бакетного дефолта
    /// (compliance + 2 суток из секции конфигурации). Локальный бэкенд метаданных объектов
    /// не хранит — срок живёт в объекте записи, письмо собирается как прежде.
    #[tokio::test]
    async fn lock_metadata_written_and_read_back() {
        let start = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("t");
        let (_, now) = test_clock(start);
        let mut cfg = cfg();
        cfg.lock_mode = LockMode::Compliance;
        cfg.retention = Duration::from_secs(2 * 24 * 3600);

        let backend = backend_memory();
        let journal = JournalRecords::new(backend.clone(), cfg.clone(), now).expect("journal");
        let tenant = TenantId::DEFAULT;
        let message = random_bytes(2, 400);
        let id = journal
            .append(&rule(tenant), &record(tenant, 0, "m1@x"), message.clone())
            .await
            .expect("append");
        let stored = journal.stored(tenant, id).await.expect("stored");
        let expected = Retention {
            mode: LockMode::Compliance,
            until: start + time::Duration::days(2),
        };
        assert_eq!(
            stored.retention, expected,
            "срок из конфигурации, не бакета"
        );

        // Объект записи: x-amz-meta-thepost-lock-mode/-until читаются обратно.
        let record_path = journal.record_path(tenant, stored.record.at, id);
        assert_eq!(
            backend.raw_lock(&record_path).await.expect("record lock"),
            Some(expected)
        );

        // Каждый объект части: те же режим и срок.
        for hash in &stored.parts {
            let lock = backend
                .raw_lock(&journal.part_path(tenant, hash))
                .await
                .expect("part lock")
                .expect("part metadata");
            assert_eq!(lock, expected, "часть {hash}");
        }

        // Локальный бэкенд (SMB): метаданных объектов нет, срок — в объекте записи.
        let dir = tempfile::tempdir().expect("tempdir");
        let local = backend_local(dir.path()).await;
        let journal_local = JournalRecords::new(local.clone(), cfg.clone(), now).expect("journal");
        let id_local = journal_local
            .append(&rule(tenant), &record(tenant, 0, "m2@x"), message)
            .await
            .expect("append local");
        let stored_local = journal_local
            .stored(tenant, id_local)
            .await
            .expect("stored");
        assert_eq!(stored_local.retention, expected);
        for hash in &stored_local.parts {
            assert_eq!(
                local
                    .raw_lock(&journal_local.part_path(tenant, hash))
                    .await
                    .expect("local lock"),
                None,
                "часть {hash}: локальный бэкенд без метаданных"
            );
        }
    }

    #[tokio::test]
    async fn local_backend_append_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let backend = backend_local(dir.path()).await;
        let (_, now) = test_clock(OffsetDateTime::UNIX_EPOCH);
        let journal = JournalRecords::new(backend.clone(), cfg(), now).expect("journal");
        let tenant = TenantId::DEFAULT;
        let id = journal
            .append(
                &rule(tenant),
                &record(tenant, 0, "m1@x"),
                random_bytes(3, 300),
            )
            .await
            .expect("append");

        // Append-only: объекты только добавляются, методов удаления нет.
        let before: Vec<String> = backend
            .list("journal/", far_future())
            .map_ok(|e: ObjectEntry| e.path)
            .try_collect()
            .await
            .expect("list");
        assert!(!before.is_empty());
        journal
            .append(
                &rule(tenant),
                &record(tenant, 5, "m2@x"),
                random_bytes(4, 300),
            )
            .await
            .expect("append");
        let after: Vec<String> = backend
            .list("journal/", far_future())
            .map_ok(|e: ObjectEntry| e.path)
            .try_collect()
            .await
            .expect("list");
        assert!(after.len() > before.len(), "запись добавила объекты");
        for path in &before {
            assert!(after.contains(path), "объект {path} не удалён и не изменён");
        }

        // Защита от изменений локального файла — цепочка: перезапись записи ловится проверкой.
        journal.tamper(id).await.expect("tamper");
        let report = journal.verify(tenant).await.expect("verify");
        assert!(!report.ok, "подмена локального объекта ловится цепью");
        // (от администратора ОС локальный диск не защищает — предупреждение doctor, APP-82;
        // для требований неизменяемости — S3 с Object Lock, SRS 4.9)
    }

    #[tokio::test]
    async fn isolation_from_blob_mailbox_gc() {
        let blob_dir = tempfile::tempdir().expect("blob dir");
        let journal_dir = tempfile::tempdir().expect("journal dir");
        let blob = backend_local(blob_dir.path()).await;
        let journal_backend = backend_local(journal_dir.path()).await;

        // Живой объект BLOB ящика (с учётом) и «сирота» в корне BLOB.
        let body = random_bytes(5, 256);
        let hash = BlobHasher::digest(&body);
        let clock = ManualClock::default().shared();
        let index = Arc::new(MemBlobIndex::new(clock.clone()));
        let Acquire::Absent { generation } = index
            .acquire(TenantId::DEFAULT, None, &hash, 1)
            .await
            .expect("absent")
        else {
            panic!("объект уже учтён");
        };
        let key = BlobKey {
            tenant: TenantId::DEFAULT,
            hash,
            generation,
        };
        blob.put(&key, body.clone()).await.expect("blob put");
        match index
            .commit_new(TenantId::DEFAULT, &hash, generation, body.len() as u64, 1)
            .await
            .expect("commit")
        {
            Commit::Done { .. } => {}
            other => panic!("commit done: {other:?}"),
        }
        let orphan = BlobKey {
            tenant: TenantId::new(),
            hash: BlobHasher::digest(&random_bytes(6, 64)),
            generation: Gen(1),
        };
        blob.put(&orphan, random_bytes(6, 64))
            .await
            .expect("orphan put");

        // Записи журнала — в своём корне.
        let (_, now) = test_clock(OffsetDateTime::UNIX_EPOCH);
        let journal = JournalRecords::new(journal_backend.clone(), cfg(), now).expect("journal");
        let tenant = TenantId::DEFAULT;
        journal
            .append(
                &rule(tenant),
                &record(tenant, 0, "m1@x"),
                random_bytes(8, 512),
            )
            .await
            .expect("append");
        let journal_objects: Vec<String> = journal_backend
            .list("journal/", far_future())
            .map_ok(|e: ObjectEntry| e.path)
            .try_collect()
            .await
            .expect("journal list");

        // Проход «сирот» по корню BLOB (grace 0, часы будущего — видит всё): удаляет только сироту.
        let sweeper = OrphanSweeper::new(
            index.clone(),
            blob.clone(),
            OrphanConfig {
                grace: Duration::ZERO,
                ..OrphanConfig::default()
            },
            Arc::new(|| OffsetDateTime::now_utc() + time::Duration::hours(1)),
        );
        let pass = sweeper.run_once().await.expect("sweep");
        assert_eq!(pass.deleted, 1, "удалена только сирота: {pass:?}");
        assert_eq!(
            blob.head(&key).await,
            Ok(Some(body.len() as u64)),
            "живой объект цел"
        );

        // И наоборот: журнал не создаёт и не удаляет ничего в корне BLOB.
        let blob_before: Vec<String> = blob
            .list("", far_future())
            .map_ok(|e: ObjectEntry| e.path)
            .try_collect()
            .await
            .expect("blob list");
        journal
            .append(
                &rule(tenant),
                &record(tenant, 3, "m2@x"),
                random_bytes(2, 512),
            )
            .await
            .expect("append");
        journal.restore_index(tenant).await.expect("restore");
        journal.verify(tenant).await.expect("verify");
        let blob_after: Vec<String> = blob
            .list("", far_future())
            .map_ok(|e: ObjectEntry| e.path)
            .try_collect()
            .await
            .expect("blob list");
        assert_eq!(
            blob_before, blob_after,
            "журнал не трогает хранилище ящиков"
        );

        // Записи журнала целы после прохода GC.
        let journal_after: Vec<String> = journal_backend
            .list("journal/", far_future())
            .map_ok(|e: ObjectEntry| e.path)
            .try_collect()
            .await
            .expect("journal list");
        assert!(
            journal_after.len() > journal_objects.len(),
            "записи добавились"
        );
        for path in &journal_objects {
            assert!(journal_after.contains(path), "объект журнала {path} цел");
        }
    }

    #[tokio::test]
    async fn chain_detects_fork_and_gap() {
        let (_, now) = test_clock(OffsetDateTime::UNIX_EPOCH);
        let journal = JournalRecords::new(backend_memory(), cfg(), now).expect("journal");
        let tenant = TenantId::DEFAULT;
        // Развилка: две записи с одной предыдущей (обе — напрямую, минуя индекс, как два писателя).
        let first = journal
            .append(
                &rule(tenant),
                &record(tenant, 0, "m1@x"),
                random_bytes(1, 100),
            )
            .await
            .expect("first");
        let prev = journal.stored(tenant, first).await.expect("stored").hash;
        journal
            .put(
                JournalId::new(),
                prev,
                &record(tenant, 50, "m9@x"),
                random_bytes(2, 100),
            )
            .await
            .expect("fork a");
        journal
            .put(
                JournalId::new(),
                prev,
                &record(tenant, 51, "m8@x"),
                random_bytes(3, 100),
            )
            .await
            .expect("fork b");
        let report = journal.verify(tenant).await.expect("verify");
        assert!(!report.ok, "развилка ловится");

        // Потеря записи: объект в середине удалён напрямую из бэкенда.
        let dir = tempfile::tempdir().expect("dir");
        let backend = backend_local(dir.path()).await;
        let (_, now) = test_clock(OffsetDateTime::UNIX_EPOCH);
        let journal = JournalRecords::new(backend.clone(), cfg(), now).expect("journal");
        journal
            .append(
                &rule(tenant),
                &record(tenant, 0, "m1@x"),
                random_bytes(1, 100),
            )
            .await
            .expect("a");
        let b = journal
            .append(
                &rule(tenant),
                &record(tenant, 1, "m2@x"),
                random_bytes(2, 100),
            )
            .await
            .expect("b");
        journal
            .append(
                &rule(tenant),
                &record(tenant, 2, "m3@x"),
                random_bytes(3, 100),
            )
            .await
            .expect("c");
        let path = journal.record_path(tenant, record(tenant, 1, "m2@x").at, b);
        backend.delete_raw(&path).await.expect("delete middle");
        let report = journal.verify(tenant).await.expect("verify");
        assert!(!report.ok, "потеря записи ловится");
        // Цепь обрывается на первой записи: недостижимый остаток в chain не попадает.
        assert_eq!(journal.chain(tenant).await.expect("chain").len(), 1);
    }

    #[tokio::test]
    async fn index_dropped_until_restore() {
        let (_, now) = test_clock(OffsetDateTime::UNIX_EPOCH);
        let journal = JournalRecords::new(backend_memory(), cfg(), now).expect("journal");
        let tenant = TenantId::DEFAULT;
        journal
            .append(
                &rule(tenant),
                &record(tenant, 0, "m1@x"),
                random_bytes(1, 100),
            )
            .await
            .expect("append");
        journal.drop_index();
        let err = journal
            .search(&JournalAudit::grant(), &JournalQuery::all(tenant, 10))
            .await
            .expect_err("index lost");
        assert!(matches!(err, Error::Internal(_)), "{err:?}");
        // Восстановление из хранилища возвращает поиск; записи на месте.
        assert_eq!(journal.restore_index(tenant).await.expect("restore"), 1);
        let page = journal
            .search(&JournalAudit::grant(), &JournalQuery::all(tenant, 10))
            .await
            .expect("search");
        assert_eq!(page.entries.len(), 1);
    }

    #[test]
    fn chunker_properties() {
        let cfg = cfg();
        // Части покрывают всё содержимое без пропусков и перекрытий, в границах max.
        let data = random_bytes(11, 10_000);
        let ranges = chunk_ranges(
            &data,
            cfg.chunk_min_bytes,
            cfg.chunk_mask(),
            cfg.chunk_max_bytes,
        );
        let mut covered = 0usize;
        for r in &ranges {
            assert!(r.start < r.end, "часть не пуста");
            assert_eq!(r.start, covered, "без пропусков и наложений");
            assert!(r.len() <= cfg.chunk_max_bytes);
            covered = r.end;
        }
        assert_eq!(covered, data.len(), "полное покрытие");
        assert!(ranges.len() > 1, "содержимое режется");

        // Независимость от позиции: общий блок в разных письмах даёт те же части.
        let shared = random_bytes(12, 8192);
        let one = letter("A", &shared, "X");
        let two = letter("BBBB", &shared, "YYYYYY");
        let set_one: HashSet<_> = chunk_hashes(&one, &cfg).into_iter().collect();
        let set_two: HashSet<_> = chunk_hashes(&two, &cfg).into_iter().collect();
        let common = set_one.intersection(&set_two).count();
        assert!(
            common > set_one.len() / 2,
            "большая часть частей общего блока совпадает: {common} из {}",
            set_one.len()
        );

        // Маленькое письмо — одна часть; min уважается после слияния.
        assert_eq!(chunk_ranges(b"short", 16, cfg.chunk_mask(), 64), vec![0..5]);
        let sparse = chunk_ranges(&data, 4000, cfg.chunk_mask(), 8192);
        assert!(
            sparse.len() > 1,
            "большой min всё равно режет: {}",
            sparse.len()
        );
    }

    #[test]
    fn config_validated() {
        assert_eq!(JournalConfig::default().validate(), Ok(()));
        assert_eq!(cfg().validate(), Ok(()));
        for bad in [
            JournalConfig {
                prefix: "journal/".into(),
                ..cfg()
            },
            JournalConfig {
                prefix: "../x".into(),
                ..cfg()
            },
            JournalConfig {
                prefix: String::new(),
                ..cfg()
            },
            JournalConfig {
                retention: Duration::ZERO,
                ..cfg()
            },
            JournalConfig {
                chunk_min_bytes: 0,
                ..cfg()
            },
            JournalConfig {
                chunk_min_bytes: 64,
                chunk_avg_bytes: 32,
                chunk_max_bytes: 64,
                ..cfg()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    /// Интеграционный: SeaweedFS из compose (`TEST_S3_URL`, ключи — в окружении; как s3-тесты
    /// blob). Бакет `TEST_S3_JOURNAL_BUCKET` (по умолчанию `thepost-journal-test`) должен существовать.
    #[tokio::test]
    async fn seaweedfs() {
        let Ok(endpoint) = std::env::var("TEST_S3_URL") else {
            return;
        };
        let bucket = std::env::var("TEST_S3_JOURNAL_BUCKET")
            .unwrap_or_else(|_| "thepost-journal-test".into());
        let client = object_store::aws::AmazonS3Builder::from_env()
            .with_bucket_name(&bucket)
            .with_endpoint(endpoint)
            .with_allow_http(true)
            .with_virtual_hosted_style_request(false)
            .build()
            .expect("s3 client");
        let backend = Arc::new(S3Store::with_object_store(
            Arc::new(client),
            S3Config::default(),
        ));
        let (_, now) = test_clock(OffsetDateTime::UNIX_EPOCH);
        let journal =
            JournalRecords::new(backend.clone(), cfg(), now).expect("journal over seaweedfs");
        let tenant = TenantId::DEFAULT;

        // Запись, чтение обратно, дедуп одного вложения в двух письмах, метаданные блокировки.
        let attach = random_bytes(21, 8192);
        let first = letter("Subject: one\r\n\r\n", &attach, "");
        let second = letter("Subject: two\r\n\r\n", &attach, "");
        let id1 = journal
            .append(&rule(tenant), &record(tenant, 0, "m1@x"), first.clone())
            .await
            .expect("append 1");
        journal
            .append(&rule(tenant), &record(tenant, 1, "m2@x"), second)
            .await
            .expect("append 2");
        let stored = journal.stored(tenant, id1).await.expect("stored");
        assert_eq!(stored.retention.mode, LockMode::default());
        assert!(stored.parts.len() > 1, "части записаны");

        // Метаданные блокировки в объектах S3 (x-amz-meta-thepost-lock-*; решение #113).
        let record_lock = backend
            .raw_lock(&journal.record_path(tenant, stored.record.at, id1))
            .await
            .expect("record lock")
            .expect("record metadata");
        assert_eq!(record_lock, stored.retention);
        let part_lock = backend
            .raw_lock(&journal.part_path(tenant, &stored.parts[0]))
            .await
            .expect("part lock")
            .expect("part metadata");
        assert_eq!(part_lock.mode, stored.retention.mode);

        let eml = journal
            .export(&JournalAudit::grant(), tenant, id1)
            .await
            .expect("export");
        assert_eq!(
            eml,
            journal_eml(&record(tenant, 0, "m1@x"), &first).expect("eml")
        );
        let report = journal.verify(tenant).await.expect("verify");
        assert!(report.ok && report.records == 2, "{report:?}");
    }
}
