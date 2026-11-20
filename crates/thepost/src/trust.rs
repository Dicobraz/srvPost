//! Политика доверия узла (APP-76, решение 124): хранилище `TrustStore` (`PgMeta`, META-85) с кэшем на узле —
//! действующая матрица учётной записи ([`TrustStore::effective_for`]), политики уровней и домены-партнёры.
//! Срок и размер кэша — секция `trust` (SRS 5.5), применяется без перезапуска; сброс — по событию
//! `trust_changed` шины (CTR-93) и по `Resync` ([`TrustCache::watch`], запуск — `serve`, как `Routes::watch`).
//!
//! Ошибка чтения политики — закрытая матрица ([`TrustMatrix::closed`]) и метрика `tp_trust_closed_total`
//! ([`crate::metrics::register_trust`]): чужим — самое узкое значение, почта при этом доставляется (решение
//! 124 б). Домен-партнёр при ошибке — не партнёр (тот же принцип «закрыто»).
//!
//! Запись политики ([`TrustStore::set_policy`], [`TrustStore::reset_policy`]) после фиксации публикует
//! `trust_changed` уровня — хранилище сигнал не публикует, его публикует узел (`tp-meta`); свой кэш узел
//! сбрасывает сразу, не дожидаясь сигнала.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::StreamExt;
use tp_contracts::Result;
use tp_contracts::bus::{EventBus, EventKind};
use tp_contracts::ids::{AccountId, TenantId};
use tp_contracts::role::CancellationToken;
use tp_contracts::trust::{
    Effective, TrustLevel, TrustMatrix, TrustPolicy, TrustStore, effective, trust_changed,
};

use crate::sections::TrustSection;

/// Запись кэша: значение, момент записи и поколение кэша (записи прежнего поколения — устаревшие).
struct Slot<T> {
    value: T,
    at: Instant,
    generation: u64,
}

/// Кладёт запись в кэш `map` (`cap` записей, давняя вытесняется; `0` — кэш выключен).
fn put<K: Clone + Eq + Hash, T>(
    map: &mut HashMap<K, Slot<T>>,
    cap: usize,
    generation: u64,
    key: K,
    value: T,
) {
    if cap == 0 {
        return;
    }
    while map.len() >= cap && !map.contains_key(&key) {
        let Some(oldest) = map.iter().min_by_key(|(_, v)| v.at).map(|(k, _)| k.clone()) else {
            break;
        };
        map.remove(&oldest);
    }
    map.insert(
        key,
        Slot {
            value,
            at: Instant::now(),
            generation,
        },
    );
}

/// Свежая запись кэша (поколение текущее и срок не вышел).
fn fresh<'a, K: Eq + Hash, T>(
    st: &State,
    map: &'a HashMap<K, Slot<T>>,
    key: &K,
    ttl: Duration,
) -> Option<&'a T> {
    let slot = map.get(key)?;
    (slot.generation == st.generation && slot.at.elapsed() < ttl).then_some(&slot.value)
}

/// Кэш узла: по учётной записи, домену-партнёру и уровню политики.
#[derive(Default)]
struct State {
    /// Растёт при каждом сбросе: записи с прежним поколением не выдаются.
    generation: u64,
    /// Действующая матрица учётной записи ([`TrustStore::effective_for`]).
    effective: HashMap<(TenantId, AccountId), Slot<Arc<Effective>>>,
    /// Домен-партнёр организации ([`TrustStore::partner_of`]).
    partners: HashMap<(TenantId, String), Slot<bool>>,
    /// Политика уровня ([`TrustStore::policy`]).
    policies: HashMap<TrustLevel, Slot<Option<TrustPolicy>>>,
}

/// Кэш политики доверия поверх [`TrustStore`] — [`TrustStore`] для сервисов узла: доставка SMTP, приём iTIP,
/// DAV, JMAP, Sieve (через доставку) и Admin API получают один и тот же [`Arc`].
pub struct TrustCache {
    /// Хранилище политик (`PgMeta`).
    inner: Arc<dyn TrustStore>,
    /// Шина узла: публикация `trust_changed` после записи; `None` — без публикации (тесты).
    bus: Option<Arc<dyn EventBus>>,
    /// Срок и размер кэша (секция `trust`, применяется без перезапуска — [`TrustCache::update`]).
    settings: Mutex<TrustSection>,
    /// Кэш и поколение сброса.
    state: Mutex<State>,
    /// Чтения, отвеченные закрытой матрицей (или «не партнёр») из-за ошибки хранилища — метрика узла.
    closed: AtomicU64,
}

impl std::fmt::Debug for TrustCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustCache")
            .field("bus", &self.bus.is_some())
            .finish_non_exhaustive()
    }
}

impl TrustCache {
    /// Кэш над хранилищем `inner` с шиной `bus` (публикация `trust_changed`) и секцией `trust`.
    pub fn new(
        inner: Arc<dyn TrustStore>,
        bus: Option<Arc<dyn EventBus>>,
        section: TrustSection,
    ) -> Self {
        Self {
            inner,
            bus,
            settings: Mutex::new(section),
            state: Mutex::default(),
            closed: AtomicU64::new(0),
        }
    }

    /// Новый срок и размер кэша (перечитанная секция `trust`, `serve` — без перезапуска).
    pub fn update(&self, section: TrustSection) {
        *self.settings.lock().expect("lock") = section;
    }

    /// Чтения политики, отвеченные закрытой матрицей («не партнёр») из-за недоступного хранилища — метрика
    /// `tp_trust_closed_total`.
    pub fn closed_total(&self) -> u64 {
        self.closed.load(Ordering::Relaxed)
    }

    /// Сброс кэша: записи прежнего поколения не выдаются.
    fn invalidate(&self) {
        let mut st = self.state.lock().expect("lock");
        st.generation += 1;
        let generation = st.generation;
        st.effective.retain(|_, v| v.generation == generation);
        st.partners.retain(|_, v| v.generation == generation);
        st.policies.retain(|_, v| v.generation == generation);
    }

    /// Публикует `trust_changed` уровня (после фиксации записи политики); ошибка — в журнал узла: политика
    /// записана, кэши других узлов перечитаются по сроку.
    async fn publish(&self, level: TrustLevel) {
        let Some(bus) = &self.bus else {
            return;
        };
        if let Err(e) = bus.publish(trust_changed(level)).await {
            tracing::warn!(
                level = %level,
                error = %e,
                "trust: сигнал trust_changed не опубликован — кэши узлов перечитаются по сроку"
            );
        }
    }

    /// Следит за сигналами шины до `shutdown`: сброс кэша по `trust_changed` (любой уровень) и `Resync`
    /// (потеря сигналов — сверка с хранилищем). Поток завершился или подписка не удалась — повтор через
    /// `retry` со сбросом.
    pub async fn watch(
        self: Arc<Self>,
        bus: Arc<dyn EventBus>,
        shutdown: CancellationToken,
        retry: Duration,
    ) {
        while !shutdown.is_cancelled() {
            match bus.subscribe_system().await {
                Ok(mut events) => {
                    // Сигналы до подписки могли потеряться.
                    self.invalidate();
                    loop {
                        let ev = tokio::select! {
                            () = shutdown.cancelled() => return,
                            ev = events.next() => ev,
                        };
                        match ev.map(|e| e.kind) {
                            Some(EventKind::TrustChanged { .. }) | Some(EventKind::Resync) => {
                                self.invalidate();
                            }
                            Some(_) => {}
                            None => break,
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "trust: подписка на сигналы политики не удалась");
                }
            }
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(retry) => {}
            }
        }
    }
}

#[async_trait]
impl TrustStore for TrustCache {
    /// Политика уровня из кэша; не задана — `None`. Ошибка хранилища — вызывающему (Admin API — 500,
    /// доставка — обработка своей ошибки).
    async fn policy(&self, level: TrustLevel) -> Result<Option<TrustPolicy>> {
        let ttl = self.settings.lock().expect("lock").cache_ttl;
        let hit = {
            let st = self.state.lock().expect("lock");
            fresh(&st, &st.policies, &level, ttl).cloned()
        };
        if let Some(policy) = hit {
            return Ok(policy);
        }
        let policy = self.inner.policy(level).await?;
        let cap = self.settings.lock().expect("lock").cache_entries;
        let mut st = self.state.lock().expect("lock");
        let generation = st.generation;
        put(&mut st.policies, cap, generation, level, policy.clone());
        Ok(policy)
    }

    /// Запись уровня в хранилище; после фиксации — сброс кэша узла и сигнал `trust_changed` другим узлам.
    async fn set_policy(&self, level: TrustLevel, policy: &TrustPolicy) -> Result<()> {
        self.inner.set_policy(level, policy).await?;
        self.invalidate();
        self.publish(level).await;
        Ok(())
    }

    /// Сброс уровня в хранилище; после фиксации — сброс кэша узла и сигнал `trust_changed`.
    async fn reset_policy(&self, level: TrustLevel) -> Result<()> {
        self.inner.reset_policy(level).await?;
        self.invalidate();
        self.publish(level).await;
        Ok(())
    }

    /// Действующая матрица учётной записи из кэша; ошибка хранилища — закрытая матрица и метрика: чужим —
    /// самое узкое значение, почта доставляется (решение 124 б). Закрытая матрица в кэш не кладётся.
    async fn effective_for(&self, tenant: TenantId, account: AccountId) -> Result<Effective> {
        let ttl = self.settings.lock().expect("lock").cache_ttl;
        let key = (tenant, account);
        let hit = {
            let st = self.state.lock().expect("lock");
            fresh(&st, &st.effective, &key, ttl).cloned()
        };
        if let Some(e) = hit {
            return Ok((*e).clone());
        }
        match self.inner.effective_for(tenant, account).await {
            Ok(e) => {
                let e = Arc::new(e);
                let cap = self.settings.lock().expect("lock").cache_entries;
                let mut st = self.state.lock().expect("lock");
                let generation = st.generation;
                put(&mut st.effective, cap, generation, key, e.clone());
                Ok((*e).clone())
            }
            Err(e) => {
                self.closed.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    tenant = %tenant,
                    account = %account,
                    error = %e,
                    "trust: политика доверия не прочитана — закрытая матрица, почта доставляется"
                );
                Ok(Effective {
                    matrix: TrustMatrix::closed(),
                    ..effective(None, None, &[])
                })
            }
        }
    }

    /// Домен-партнёр организации из кэша; ошибка хранилища — не партнёр (закрыто) и метрика.
    async fn partner_of(&self, tenant: TenantId, domain: &str) -> Result<bool> {
        let ttl = self.settings.lock().expect("lock").cache_ttl;
        let key = (tenant, domain.to_owned());
        let hit = {
            let st = self.state.lock().expect("lock");
            fresh(&st, &st.partners, &key, ttl).copied()
        };
        if let Some(partner) = hit {
            return Ok(partner);
        }
        match self.inner.partner_of(tenant, domain).await {
            Ok(partner) => {
                let cap = self.settings.lock().expect("lock").cache_entries;
                let mut st = self.state.lock().expect("lock");
                let generation = st.generation;
                put(&mut st.partners, cap, generation, key, partner);
                Ok(partner)
            }
            Err(e) => {
                self.closed.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    tenant = %tenant,
                    domain = %domain,
                    error = %e,
                    "trust: домены-партнёры не прочитаны — партнёром не считается"
                );
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use tp_contracts::trust::{InviteMode, PeerKind, Toggle, TrustLevel};
    use tp_testkit::{MemEventBus, MemTrust};

    use super::*;

    /// Хранилище с имитацией ошибки ([`TrustStore`]): при `fail_next` следующее чтение — `Unavailable`.
    #[derive(Clone)]
    struct Flaky {
        inner: MemTrust,
        fail: Arc<AtomicUsize>,
        reads: Arc<AtomicUsize>,
    }

    impl Flaky {
        fn new() -> Self {
            Self {
                inner: MemTrust::new(),
                fail: Arc::new(AtomicUsize::new(0)),
                reads: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn fail_next(&self) {
            self.fail.fetch_add(1, Ordering::Relaxed);
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::Relaxed)
        }

        /// Чтение: счётчик, ошибка при `fail` (один накопленный сбой — одна ошибка).
        fn step(&self) -> Result<()> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            if self
                .fail
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(tp_contracts::Error::UNAVAILABLE);
            }
            Ok(())
        }
    }

    #[async_trait]
    impl TrustStore for Flaky {
        async fn policy(&self, level: TrustLevel) -> Result<Option<TrustPolicy>> {
            self.step()?;
            self.inner.policy(level).await
        }

        async fn set_policy(&self, level: TrustLevel, policy: &TrustPolicy) -> Result<()> {
            self.inner.set_policy(level, policy).await
        }

        async fn reset_policy(&self, level: TrustLevel) -> Result<()> {
            self.inner.reset_policy(level).await
        }

        async fn effective_for(&self, tenant: TenantId, account: AccountId) -> Result<Effective> {
            self.step()?;
            self.inner.effective_for(tenant, account).await
        }

        async fn partner_of(&self, tenant: TenantId, domain: &str) -> Result<bool> {
            self.step()?;
            self.inner.partner_of(tenant, domain).await
        }
    }

    /// Политика организации: партнёрам автодобавление приглашений.
    fn org_auto() -> TrustPolicy {
        let mut p = TrustPolicy::default();
        p.invite_new.partner = Some(InviteMode::Auto);
        p
    }

    #[tokio::test]
    async fn cache_reads_once_and_resets_on_write() {
        let flaky = Flaky::new();
        let trust = Arc::new(TrustCache::new(
            Arc::new(flaky.clone()),
            None,
            TrustSection::default(),
        ));
        let tenant = TenantId::DEFAULT;
        let account = AccountId::new();
        let first = trust
            .effective_for(tenant, account)
            .await
            .expect("effective");
        assert_eq!(first.matrix, TrustMatrix::default());
        // Второй раз — из кэша.
        assert_eq!(
            trust
                .effective_for(tenant, account)
                .await
                .expect("effective"),
            first
        );
        assert_eq!(flaky.reads(), 1);

        // Запись политики: кэш сброшен, сигнал опубликован, новое значение видно сразу.
        let bus = MemEventBus::default();
        let mut events = bus.subscribe_system().await.expect("subscribe");
        let trust = Arc::new(TrustCache::new(
            Arc::new(MemTrust::new()),
            Some(Arc::new(bus.clone()) as Arc<dyn EventBus>),
            TrustSection::default(),
        ));
        // Матрица в кэше — умолчания (кнопка партнёру).
        let e = trust
            .effective_for(tenant, account)
            .await
            .expect("effective");
        assert_eq!(e.matrix.invite_new.partner, InviteMode::Button);
        trust
            .set_policy(TrustLevel::Org(tenant), &org_auto())
            .await
            .expect("set");
        let e = trust
            .effective_for(tenant, account)
            .await
            .expect("effective");
        assert_eq!(e.matrix.invite_new.partner, InviteMode::Auto, "сброс кэша");
        // Сигнал уровня в шине.
        let ev = tokio::time::timeout(Duration::from_secs(2), events.next())
            .await
            .expect("сигнал")
            .expect("поток");
        assert_eq!(
            ev.kind,
            EventKind::TrustChanged {
                level: TrustLevel::Org(tenant)
            }
        );

        // Сброс уровня — тоже сигнал.
        trust
            .reset_policy(TrustLevel::Org(tenant))
            .await
            .expect("reset");
        let ev = tokio::time::timeout(Duration::from_secs(2), events.next())
            .await
            .expect("сигнал")
            .expect("поток");
        assert_eq!(
            ev.kind,
            EventKind::TrustChanged {
                level: TrustLevel::Org(tenant)
            }
        );
    }

    /// Сигнал `trust_changed` шины сбрасывает кэш ([`TrustCache::watch`]): действующая матрица меняется,
    /// не дожидаясь срока кэша (изменение политики через Admin API действует без перезапуска).
    #[tokio::test]
    async fn watch_invalidates_on_trust_changed() {
        let mem = MemEventBus::default();
        let bus: Arc<dyn EventBus> = Arc::new(mem.clone());
        // Читающий и пишущий узлы — над одним хранилищем (как PgMeta у узлов одной базы).
        let shared = MemTrust::new();
        let trust = Arc::new(TrustCache::new(
            Arc::new(shared.clone()),
            Some(bus.clone()),
            TrustSection {
                cache_ttl: Duration::from_secs(3600),
                ..TrustSection::default()
            },
        ));
        let stop = CancellationToken::new();
        let guard = stop.clone().drop_guard();
        tokio::spawn(
            trust
                .clone()
                .watch(bus.clone(), stop.clone(), Duration::from_millis(20)),
        );
        // Сигналы at-most-once: публикация до подписки подписчику не достанется — ждём подписки `watch`.
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        while mem.subscribers() == 0 {
            assert!(
                tokio::time::Instant::now() < until,
                "watch не подписался на шину"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let tenant = TenantId::DEFAULT;
        let account = AccountId::new();
        // Матрица в кэше (TTL час).
        let e = trust
            .effective_for(tenant, account)
            .await
            .expect("effective");
        assert_eq!(e.matrix.invite_new.partner, InviteMode::Button);
        // Другой узел пишет политику и публикует сигнал.
        let writer = TrustCache::new(Arc::new(shared), Some(bus.clone()), TrustSection::default());
        writer
            .set_policy(TrustLevel::Org(tenant), &org_auto())
            .await
            .expect("set");
        // Подписчик `watch` сбросил кэш — новое значение без перезапуска.
        let until = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let e = trust
                .effective_for(tenant, account)
                .await
                .expect("effective");
            if e.matrix.invite_new.partner == InviteMode::Auto {
                break;
            }
            assert!(
                tokio::time::Instant::now() < until,
                "сигнал trust_changed не сбросил кэш"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(guard);
    }

    /// Ошибка хранилища — закрытая матрица («не партнёр») и метрика; хранилище живо — прежние значения.
    /// Кэш выключен (`cache_ttl: 0s`): каждое чтение — в хранилище, иначе прежняя запись скрыла бы сбой.
    #[tokio::test]
    async fn store_error_closed_matrix_and_metric() {
        let flaky = Flaky::new();
        let trust = Arc::new(TrustCache::new(
            Arc::new(flaky.clone()),
            None,
            TrustSection {
                cache_ttl: Duration::ZERO,
                cache_entries: 10,
            },
        ));
        let tenant = TenantId::DEFAULT;
        let account = AccountId::new();
        assert_eq!(trust.partner_of(tenant, "partner.example").await, Ok(false));
        flaky
            .inner
            .set_policy(
                TrustLevel::Org(tenant),
                &TrustPolicy {
                    partners: vec!["partner.example".into()],
                    ..TrustPolicy::default()
                },
            )
            .await
            .expect("policy");
        assert_eq!(trust.partner_of(tenant, "partner.example").await, Ok(true));
        assert_eq!(trust.closed_total(), 0);

        // Хранилище недоступно: матрица закрытая, партнёр — не партнёр, метрика растёт.
        flaky.fail_next();
        flaky.fail_next();
        let e = trust.effective_for(tenant, account).await.expect("closed");
        assert_eq!(e.matrix, TrustMatrix::closed(), "{e:?}");
        assert_eq!(trust.partner_of(tenant, "partner.example").await, Ok(false));
        assert_eq!(trust.closed_total(), 2, "метрика закрытых чтений");
        // Чужим — самое узкое значение: приём iTIP только письмом.
        for peer in [PeerKind::Partner, PeerKind::Neighbor, PeerKind::External] {
            assert_eq!(e.matrix.itip_updates.get(peer), Toggle::Off);
        }
    }

    /// Срок кэша: по истечении TTL чтение идёт в хранилище; `0s` — кэш выключен.
    #[tokio::test]
    async fn ttl_expires_entry() {
        let flaky = Flaky::new();
        let section = TrustSection {
            cache_ttl: Duration::from_millis(60),
            cache_entries: 10,
        };
        let trust = Arc::new(TrustCache::new(Arc::new(flaky.clone()), None, section));
        let tenant = TenantId::DEFAULT;
        let account = AccountId::new();
        trust
            .effective_for(tenant, account)
            .await
            .expect("effective");
        trust
            .effective_for(tenant, account)
            .await
            .expect("effective");
        assert_eq!(flaky.reads(), 1, "второе чтение из кэша");
        tokio::time::sleep(Duration::from_millis(120)).await;
        trust
            .effective_for(tenant, account)
            .await
            .expect("effective");
        assert_eq!(flaky.reads(), 2, "TTL вышел — чтение из хранилища");

        // Без кэша — каждое чтение в хранилище.
        let trust = Arc::new(TrustCache::new(
            Arc::new(flaky.clone()),
            None,
            TrustSection {
                cache_ttl: Duration::ZERO,
                cache_entries: 10,
            },
        ));
        trust.partner_of(tenant, "a.example").await.expect("p");
        trust.partner_of(tenant, "a.example").await.expect("p");
        assert_eq!(flaky.reads(), 4, "cache_ttl: 0s — кэш выключен");
    }

    /// `cache_entries` вытесняет давние записи.
    #[tokio::test]
    async fn cap_evicts_oldest() {
        let flaky = Flaky::new();
        let trust = Arc::new(TrustCache::new(
            Arc::new(flaky.clone()),
            None,
            TrustSection {
                cache_ttl: Duration::from_secs(60),
                cache_entries: 1,
            },
        ));
        let tenant = TenantId::DEFAULT;
        let (a, b) = (AccountId::new(), AccountId::new());
        trust.effective_for(tenant, a).await.expect("a");
        trust.effective_for(tenant, b).await.expect("b");
        trust.effective_for(tenant, a).await.expect("a again");
        assert_eq!(flaky.reads(), 3, "запись a вытеснена записью b");
        // Политики и партнёры считаются вместе.
        trust
            .policy(TrustLevel::Installation)
            .await
            .expect("policy");
        trust.partner_of(tenant, "d.example").await.expect("p");
        trust.policy(TrustLevel::Installation).await.expect("again");
        assert_eq!(flaky.reads(), 5, "политика вытеснена партнёром");
    }
}
