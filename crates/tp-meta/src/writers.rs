//! Писатели приёма: сериализация записей писем учётной записи в приложении (PERF-09, решение 19.11).
//!
//! Письма учётной записи (`MessageStore::insert`, `insert_batch` — приём SMTP и IMAP APPEND идут
//! через одни методы) пишутся одним писателем учётной записи: письма, пришедшие за окно батча
//! ([`IngestConfig::batch_window`]), — одна транзакция, один замок строки `mailbox_state` на пачку
//! вместо одного на письмо. Очередь приёма уходит из блокировок PostgreSQL: пул перестаёт насыщаться,
//! клиентские операции (`set_flags`, чтения) перестают ждать за хвостом приёма. Порядок `ModSeq` (по
//! фиксациям) держит единственный писатель учётной записи; клиентские операции по-прежнему берут
//! строку напрямую — коротко, без очереди. Идемпотентность по ключу письма (META-40) сохранена:
//! ключи выдаются до отправки писателю, запись — [`PgMeta::keyed_at`] (исход обрыва во время COMMIT —
//! по записям `created` журнала изменений).
//!
//! Доставки одного приёма нескольких учётных записей делятся по шардам, как в `insert_batch`
//! (решение 2026-10-31-atomic-delivery): письма шарда — одно задание, одна транзакция («вставлены все
//! или ни одного» в пределах шарда); задание ведёт писатель первой (в порядке блокировки строк)
//! учётной записи группы. Писатель стартует лениво, на первого отправителя;
//! [`IngestConfig::writer_idle`] без заданий — задача завершается: канал закрывается (новые
//! отправители пересоздают писателя), буфер сливается одной записью — задание в закрытый канал не
//! попадает. Переполнение очереди ([`IngestConfig::queue_cap`]) — `Unavailable`, явная ошибка
//! перегрузки приёма учётной записи.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tp_contracts::config::duration;
use tp_contracts::meta::{AccountScope, Inserted, NewMessage};
use tp_contracts::{AccountId, Error, MailboxId, MessageId, Result};

use crate::messages::{insert_one, inserted_by_id};
use crate::{BoxDb, PgMeta};

/// Писатели приёма: секция `meta.ingest` (PERF-09).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct IngestConfig {
    /// Окно накопления пачки писателя учётной записи: письма окна — одна транзакция.
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub batch_window: Duration,
    /// Наибольшее число писем одной пачки писателя (задание крупнее пачки — целиком).
    pub batch_cap: usize,
    /// Ёмкость очереди писателя учётной записи; переполнение — `Unavailable` (перегрузка приёма).
    pub queue_cap: usize,
    /// Простой писателя учётной записи до завершения задачи (буфер сливается одной записью).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub writer_idle: Duration,
}

impl Default for IngestConfig {
    fn default() -> Self {
        Self {
            batch_window: Duration::from_millis(5),
            batch_cap: 64,
            queue_cap: 1024,
            writer_idle: Duration::from_secs(30),
        }
    }
}

/// Письмо задания: учётная запись, папка, ключ (выдан до транзакции, META-40) и письмо.
type Item = (AccountScope, MailboxId, MessageId, NewMessage);

/// Задание писателя: письма одного вызова в пределах шарда и канал ответа.
struct Job {
    /// Письма задания в порядке блокировки строк (учётная запись, папка).
    items: Vec<Item>,
    /// Ответ вызову: `Inserted` в порядке `items`.
    reply: oneshot::Sender<Result<Vec<Inserted>>>,
}

/// Карта «учётная запись → писатель приёма»; общая для клонов [`PgMeta`].
pub(crate) struct Writers {
    /// Живые писатели и счётчик поколений — идентификатор задачи писателя (гонка с завершением).
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    map: HashMap<AccountScope, Entry>,
    generation: u64,
}

/// Живой писатель учётной записи.
#[derive(Clone)]
struct Entry {
    tx: mpsc::Sender<Job>,
    generation: u64,
}

impl std::fmt::Debug for Writers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Writers(..)")
    }
}

impl Default for Writers {
    fn default() -> Self {
        Self::new()
    }
}

impl Writers {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
        }
    }

    /// Пишет письма `items` (один шард, в порядке блокировки строк) через писателя `key`; ответ —
    /// в порядке `items`. Очередь писателя переполнена — `Unavailable` (перегрузка приёма).
    pub(crate) async fn write(
        writers: &Arc<Self>,
        meta: &PgMeta,
        key: AccountScope,
        items: Vec<Item>,
    ) -> Result<Vec<Inserted>> {
        let (reply, rx) = oneshot::channel();
        let mut job = Job { items, reply };
        let mut recreated = false;
        loop {
            let entry = Self::entry(writers, meta, key);
            match entry.tx.try_send(job) {
                Ok(()) => {
                    return match rx.await {
                        Ok(answer) => answer,
                        // Писатель завершился вместе с заданием (паника задачи): исход записи
                        // неизвестен — повтор невозможен без риска продублировать письма.
                        Err(_) => Err(Error::internal("писатель приёма завершён с заданием")),
                    };
                }
                Err(TrySendError::Full(_)) => {
                    return Err(Error::Unavailable {
                        retry_after: Some(Duration::from_millis(50)),
                    });
                }
                Err(TrySendError::Closed(closed)) => {
                    // Писатель завершился после простоя, задание в закрытый канал не прошло:
                    // запись карты убрать (если ещё его) и пересоздать писателя.
                    job = closed;
                    writers.retire(key, entry.generation);
                    if recreated {
                        return Err(Error::internal(
                            "писатель приёма завершён сразу после пересоздания",
                        ));
                    }
                    recreated = true;
                }
            }
        }
    }

    /// Писатель учётной записи: живой из карты или лениво созданный (задача приёма писем).
    fn entry(writers: &Arc<Self>, meta: &PgMeta, key: AccountScope) -> Entry {
        let mut state = writers.state.lock().expect("lock");
        if let Some(e) = state.map.get(&key) {
            return e.clone();
        }
        let (tx, rx) = mpsc::channel(meta.cfg.ingest.queue_cap);
        state.generation += 1;
        let generation = state.generation;
        state.map.insert(
            key,
            Entry {
                tx: tx.clone(),
                generation,
            },
        );
        drop(state);
        tokio::spawn(run(meta.clone(), rx, Arc::clone(writers), key, generation));
        Entry { tx, generation }
    }

    /// Удаляет запись писателя `generation`, если карта ещё держит его (задача завершилась после простоя;
    /// её место мог занять писатель, пересозданный отправителем из закрытого канала).
    fn retire(&self, key: AccountScope, generation: u64) {
        let mut state = self.state.lock().expect("lock");
        if state
            .map
            .get(&key)
            .is_some_and(|e| e.generation == generation)
        {
            state.map.remove(&key);
        }
    }
}

/// Задача писателя учётной записи: копит письма окна и пишет их одной транзакцией; `writer_idle`
/// без заданий — завершение (буфер канала сливается одной записью).
async fn run(
    meta: PgMeta,
    mut rx: mpsc::Receiver<Job>,
    writers: Arc<Writers>,
    key: AccountScope,
    generation: u64,
) {
    let (window, cap, idle) = {
        let ingest = &meta.cfg.ingest;
        (ingest.batch_window, ingest.batch_cap, ingest.writer_idle)
    };
    let mut jobs: Vec<Job> = Vec::new();
    loop {
        // Первое задание (после создания писателя) или следующее (после записи пачки); тише `idle` —
        // к завершению.
        match tokio::time::timeout(idle, rx.recv()).await {
            Ok(Some(job)) => jobs.push(job),
            Ok(None) | Err(_) => break,
        }
        // Окно батча: письма, пришедшие за `window`, — одна транзакция, не более `cap` писем.
        let deadline = tokio::time::Instant::now() + window;
        while queued(&jobs) < cap {
            let Some(left) = deadline.checked_duration_since(tokio::time::Instant::now()) else {
                break;
            };
            match tokio::time::timeout(left, rx.recv()).await {
                Ok(Some(job)) => jobs.push(job),
                Ok(None) | Err(_) => break,
            }
        }
        execute(&meta, std::mem::take(&mut jobs)).await;
    }
    // Простой: канал закрыт — новые отправители пересоздают писателя; буфер слить одной записью.
    rx.close();
    while let Some(job) = rx.recv().await {
        jobs.push(job);
    }
    if !jobs.is_empty() {
        execute(&meta, jobs).await;
    }
    writers.retire(key, generation);
}

/// Число писем в накопленных заданиях.
fn queued(jobs: &[Job]) -> usize {
    jobs.iter().map(|j| j.items.len()).sum()
}

/// Пишет письма заданий одной транзакцией ([`PgMeta::keyed_at`], ключи писем — META-40); строки
/// учётных записей и папок уже в порядке блокировки — встречные записи не ждут друг друга по кругу.
/// Сбой пачки — повтор по заданиям: одно «отравленное» письмо не валило пачку окна, ошибки —
/// персонально. Сигнал `LogAppended` — после фиксации, до ответов вызовам.
async fn execute(meta: &PgMeta, jobs: Vec<Job>) {
    let accounts: HashSet<AccountId> = jobs
        .iter()
        .flat_map(|j| j.items.iter())
        .map(|(scope, ..)| scope.account)
        .collect();
    let (tenant, lead) = (jobs[0].items[0].0.tenant, jobs[0].items[0].0);
    let partitions = meta.cfg.event_partitions;
    let db = match meta.box_db(lead).await {
        Ok(db) => db,
        Err(e) => {
            // Шард учётной записи не найден или недоступен: повтор по заданию не поможет.
            fail(jobs, e);
            return;
        }
    };
    let inserted = {
        // Письма всех заданий и их ключи — клоны на время транзакции (повтор keyed_at получает свой).
        let items: Vec<Item> = jobs.iter().flat_map(|j| j.items.clone()).collect();
        let keys: Vec<(AccountId, MessageId)> = items
            .iter()
            .map(|(scope, _, id, _)| (scope.account, *id))
            .collect();
        meta.keyed_at(
            &db,
            tenant,
            |tx| {
                let items = items.clone();
                Box::pin(async move {
                    let mut out = Vec::with_capacity(items.len());
                    for (scope, mailbox, id, msg) in items {
                        out.push(insert_one(tx, partitions, scope, mailbox, id, msg).await?);
                    }
                    Ok(out)
                })
            },
            |tx| {
                let keys = keys.clone();
                Box::pin(async move { inserted_by_id(tx, tenant, &keys).await })
            },
        )
        .await
    };
    match inserted {
        Ok(batch) => {
            meta.signal_log(accounts).await;
            // Каждому вызову — его `Inserted` в порядке его `items`.
            let mut by_id: HashMap<MessageId, Inserted> =
                batch.into_iter().map(|i| (i.id, i)).collect();
            for job in jobs {
                let mut out = Vec::with_capacity(job.items.len());
                for (_, _, id, _) in &job.items {
                    let ins = by_id.remove(id).expect("письмо записанной пачки");
                    out.push(ins);
                }
                let _ = job.reply.send(Ok(out));
            }
        }
        Err(e) => {
            if e.is_retryable() {
                // Временный отказ (пул, обрыв, переключение СУБД): повторы по заданиям ждут того же —
                // ошибка каждому вызову, вызывающий повторит задание целиком.
                fail(jobs, e);
                return;
            }
            retry_jobs(meta, &db, partitions, jobs).await;
        }
    }
}

/// Сбой пачки не из-за доступности СУБД — повтор по заданиям: каждое задание своей транзакцией
/// (те же ключи, META-40), исход — персонально. Два одинаковых сбоя подряд — отказ не отдельного
/// задания (например, отключённая учётная запись): остальным тот же ответ без попыток.
async fn retry_jobs(meta: &PgMeta, db: &BoxDb, partitions: u32, jobs: Vec<Job>) {
    let mut outcomes: Vec<Option<Result<Vec<Inserted>>>> = jobs.iter().map(|_| None).collect();
    let mut repeated: Option<Error> = None;
    let mut failures = 0;
    for (pos, job) in jobs.iter().enumerate() {
        if let Some(e) = &repeated {
            outcomes[pos] = Some(Err(e.clone()));
            continue;
        }
        let tenant = job.items[0].0.tenant;
        let keys: Vec<(AccountId, MessageId)> = job
            .items
            .iter()
            .map(|(scope, _, id, _)| (scope.account, *id))
            .collect();
        let outcome = meta
            .keyed_at(
                db,
                tenant,
                |tx| {
                    let items = job.items.clone();
                    Box::pin(async move {
                        let mut out = Vec::with_capacity(items.len());
                        for (scope, mailbox, id, msg) in items {
                            out.push(insert_one(tx, partitions, scope, mailbox, id, msg).await?);
                        }
                        Ok(out)
                    })
                },
                |tx| {
                    let keys = keys.clone();
                    Box::pin(async move { inserted_by_id(tx, tenant, &keys).await })
                },
            )
            .await;
        match &outcome {
            Err(e) => {
                failures += 1;
                if failures >= 2 {
                    repeated = Some(e.clone());
                }
            }
            Ok(_) => failures = 0,
        }
        outcomes[pos] = Some(outcome);
    }
    if outcomes.iter().any(|o| matches!(o, Some(Ok(_)))) {
        let accounts: HashSet<AccountId> = jobs
            .iter()
            .flat_map(|j| j.items.iter())
            .map(|(scope, ..)| scope.account)
            .collect();
        meta.signal_log(accounts).await;
    }
    // Исход — персонально; ответы в отброшенные каналы не доставляются.
    for (job, outcome) in jobs.into_iter().zip(outcomes) {
        let _ = job.reply.send(outcome.expect("исход задания"));
    }
}

/// Ошибка `e` каждому заданию целиком.
fn fail(jobs: Vec<Job>, e: Error) {
    for job in jobs {
        let _ = job.reply.send(Err(e.clone()));
    }
}
