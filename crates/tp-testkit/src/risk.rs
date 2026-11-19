//! Справочник аномалий и TI в памяти ([`RiskStore`], CTR-95; CONTRACTS.md#Risk; решение 126): пакеты
//! поставщика с ростом номера и откатом, политики уровней, источники TI, версии списков, учёт обращений
//! по суткам и журнал срабатываний. Сигнал `risk_changed` не публикует — его публикует узел после
//! фиксации.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use time::OffsetDateTime;
use tp_contracts::ids::{BlobHash, TenantId};
use tp_contracts::risk::{
    Catalog, DEFAULT_PACKAGE_KEEP, EffectiveCatalog, HitRecord, HitsQuery, ListVersion, Mode,
    PackageEntry, PackageManifest, PackageState, RiskLevel, RiskPolicy, RiskStore, SourceId,
    TiSource, UsageEntry, Verdict,
};
use tp_contracts::{Error, Result};

use crate::infra::{Clock, lock};

#[derive(Debug, Default)]
struct RiskState {
    /// Хранимые пакеты по номеру версии.
    packages: BTreeMap<u64, PackageManifest>,
    /// Действующий пакет.
    active: Option<u64>,
    /// Политики уровней.
    policies: HashMap<RiskLevel, RiskPolicy>,
    /// Источники TI.
    sources: BTreeMap<SourceId, TiSource>,
    /// Текущие версии списков.
    lists: HashMap<tp_contracts::risk::ListId, ListVersion>,
    /// Учёт обращений: (источник, организация, сутки) → (обращения, совпадения).
    usage: BTreeMap<(SourceId, TenantId, i64), (u64, u64)>,
    /// Журнал срабатываний в порядке записи.
    hits: Vec<HitRecord>,
}

/// [`RiskStore`] в памяти; клоны разделяют данные, время — из `clock`. Политики пустых уровней не
/// хранятся; пустая политика (без изменений и признаков) при записи удаляет уровень. Пакеты сверх
/// `keep` прошлых (по умолчанию [`DEFAULT_PACKAGE_KEEP`]) удаляются при активации и откате.
#[derive(Clone)]
pub struct MemRisk {
    state: Arc<Mutex<RiskState>>,
    clock: Arc<dyn Clock>,
    keep: usize,
}

impl fmt::Debug for MemRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemRisk")
            .field("state", &self.state)
            .field("keep", &self.keep)
            .finish()
    }
}

impl MemRisk {
    /// Пустой справочник с часами `clock`.
    pub fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            state: Arc::default(),
            clock,
            keep: DEFAULT_PACKAGE_KEEP,
        }
    }

    /// Сколько прошлых пакетов хранить (секция `risk.package.keep`).
    pub fn with_keep(mut self, keep: usize) -> Self {
        self.keep = keep;
        self
    }

    /// Признаки активного пакета (пустой — нет пакета).
    fn vendor(&self, state: &RiskState) -> Vec<tp_contracts::risk::Signal> {
        state
            .active
            .and_then(|v| state.packages.get(&v))
            .map(|m| m.signals.clone())
            .unwrap_or_default()
    }

    /// Действующие значения уровней ниже `level` — база проверки [`RiskPolicy::validate`].
    fn base(&self, state: &RiskState, level: RiskLevel) -> EffectiveCatalog {
        let vendor = self.vendor(state);
        match level {
            RiskLevel::Installation => Catalog::effective(&vendor, None, None),
            RiskLevel::Org(_) => {
                let inst = state.policies.get(&RiskLevel::Installation);
                Catalog::effective(&vendor, inst, None)
            }
        }
    }

    /// Хранимые пакеты, кроме действующего, по убыванию номера; лишние (сверх `keep`) удаляет.
    fn prune(&self, state: &mut RiskState) {
        let mut previous: Vec<u64> = state
            .packages
            .keys()
            .copied()
            .filter(|v| Some(*v) != state.active)
            .collect();
        previous.reverse();
        for v in previous.into_iter().skip(self.keep) {
            state.packages.remove(&v);
        }
    }
}

#[async_trait]
impl RiskStore for MemRisk {
    async fn effective(&self, tenant: TenantId) -> Result<EffectiveCatalog> {
        let state = lock(&self.state);
        let vendor = self.vendor(&state);
        let inst = state.policies.get(&RiskLevel::Installation);
        let org = state.policies.get(&RiskLevel::Org(tenant));
        Ok(Catalog::effective(
            &vendor,
            inst,
            org.map(|p| (RiskLevel::Org(tenant), p)),
        ))
    }

    async fn put_package(&self, manifest: &PackageManifest) -> Result<()> {
        manifest.validate()?;
        let mut state = lock(&self.state);
        if let Some(max) = state.packages.keys().next_back()
            && manifest.version <= *max
        {
            return Err(Error::invalid(format!(
                "risk: номер пакета {} не растёт (максимальный хранимый {max})",
                manifest.version
            )));
        }
        state.packages.insert(manifest.version, manifest.clone());
        Ok(())
    }

    async fn activate(&self, version: u64) -> Result<()> {
        let mut state = lock(&self.state);
        if !state.packages.contains_key(&version) {
            return Err(Error::NotFound);
        }
        if let Some(active) = state.active
            && version <= active
        {
            return Err(Error::invalid(format!(
                "risk: номер пакета {version} не растёт (действующий {active})"
            )));
        }
        state.active = Some(version);
        self.prune(&mut state);
        Ok(())
    }

    async fn rollback(&self, version: u64) -> Result<()> {
        let mut state = lock(&self.state);
        if !state.packages.contains_key(&version) {
            return Err(Error::NotFound);
        }
        state.active = Some(version);
        self.prune(&mut state);
        Ok(())
    }

    async fn packages(&self) -> Result<Vec<PackageEntry>> {
        let state = lock(&self.state);
        let mut versions: Vec<u64> = state.packages.keys().copied().collect();
        versions.reverse();
        Ok(versions
            .into_iter()
            .map(|version| PackageEntry {
                version,
                state: if Some(version) == state.active {
                    PackageState::Active
                } else {
                    PackageState::Previous
                },
            })
            .collect())
    }

    async fn policy(&self, level: RiskLevel) -> Result<Option<RiskPolicy>> {
        Ok(lock(&self.state).policies.get(&level).cloned())
    }

    async fn set_policy(&self, level: RiskLevel, policy: &RiskPolicy) -> Result<()> {
        let mut state = lock(&self.state);
        policy.validate(&self.base(&state, level), level)?;
        if *policy == RiskPolicy::default() {
            state.policies.remove(&level);
        } else {
            state.policies.insert(level, policy.clone());
        }
        Ok(())
    }

    async fn reset_policy(&self, level: RiskLevel) -> Result<()> {
        lock(&self.state).policies.remove(&level);
        Ok(())
    }

    async fn sources(&self) -> Result<Vec<TiSource>> {
        Ok(lock(&self.state).sources.values().cloned().collect())
    }

    async fn put_source(&self, source: &TiSource) -> Result<()> {
        source.validate()?;
        lock(&self.state)
            .sources
            .insert(source.id.clone(), source.clone());
        Ok(())
    }

    async fn delete_source(&self, id: &SourceId) -> Result<()> {
        lock(&self.state).sources.remove(id);
        Ok(())
    }

    async fn put_list_version(&self, version: &ListVersion) -> Result<()> {
        let mut state = lock(&self.state);
        if !state.sources.contains_key(&version.source) {
            return Err(Error::invalid(format!(
                "risk: источник {} версии списка неизвестен",
                version.source
            )));
        }
        if version.blob.is_empty() {
            return Err(Error::invalid("risk: пустая ссылка на содержимое списка"));
        }
        state.lists.insert(version.list.clone(), version.clone());
        Ok(())
    }

    async fn list_current(&self, list: &tp_contracts::risk::ListId) -> Result<Option<ListVersion>> {
        Ok(lock(&self.state).lists.get(list).cloned())
    }

    async fn record_usage(
        &self,
        source: &SourceId,
        tenant: TenantId,
        lookups: u64,
        hits: u64,
    ) -> Result<()> {
        let day = day_start(self.clock.now());
        let mut state = lock(&self.state);
        let entry = state
            .usage
            .entry((source.clone(), tenant, day))
            .or_insert((0, 0));
        entry.0 += lookups;
        entry.1 += hits;
        Ok(())
    }

    async fn usage(&self, source: &SourceId, since: OffsetDateTime) -> Result<Vec<UsageEntry>> {
        let since_day = day_start(since);
        let state = lock(&self.state);
        let mut out: Vec<UsageEntry> = state
            .usage
            .iter()
            .filter(|((s, _, day), _)| s == source && *day >= since_day)
            .map(|((s, tenant, day), (lookups, hits))| UsageEntry {
                source: s.clone(),
                tenant: *tenant,
                day: OffsetDateTime::from_unix_timestamp(*day).expect("сутки"),
                lookups: *lookups,
                hits: *hits,
            })
            .collect();
        out.sort_by_key(|e| (e.day, e.tenant));
        Ok(out)
    }

    async fn record_hits(
        &self,
        tenant: TenantId,
        message: BlobHash,
        verdict: &Verdict,
    ) -> Result<()> {
        let at = self.clock.now();
        let mut state = lock(&self.state);
        for (hits, mode) in [
            (&verdict.hits, Mode::Enforce),
            (&verdict.report_only, Mode::Report),
        ] {
            for h in hits {
                state.hits.push(HitRecord {
                    tenant,
                    message,
                    signal: h.signal.clone(),
                    strength: h.strength,
                    weight: h.weight,
                    mode,
                    at,
                });
            }
        }
        Ok(())
    }

    async fn hits(&self, tenant: TenantId, filter: &HitsQuery) -> Result<Vec<HitRecord>> {
        filter.validate()?;
        let state = lock(&self.state);
        // Свежие первыми; при равном моменте — порядок записи (применённые прежде «только отчёт»).
        let mut out: Vec<(OffsetDateTime, usize, HitRecord)> = state
            .hits
            .iter()
            .enumerate()
            .filter(|(_, r)| r.tenant == tenant && filter.matches(r))
            .map(|(i, r)| (r.at, i, r.clone()))
            .collect();
        out.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        Ok(out
            .into_iter()
            .take(filter.limit)
            .map(|(_, _, r)| r)
            .collect())
    }
}

/// Начало суток UTC (unix-секунды).
fn day_start(at: OffsetDateTime) -> i64 {
    at.to_offset(time::UtcOffset::UTC)
        .date()
        .with_time(time::Time::MIDNIGHT)
        .assume_utc()
        .unix_timestamp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use tp_contracts::risk::{
        Detector, Hit, HitSource, ListId, Origin,
        PackageState::{Active, Previous},
        RiskAction, Semver, Signal, SignalId, SourceKind, Tier,
    };
    use tp_testkit::ManualClock;

    use crate::suite;

    fn signal(id: &str, weight: u16) -> Signal {
        Signal {
            id: SignalId::new(id).expect("id"),
            detector: Detector::EncryptedArchive,
            weight,
            threshold: 0,
            action: RiskAction::None,
            mode: Mode::Enforce,
            origin: Origin::Vendor,
            since: OffsetDateTime::UNIX_EPOCH,
        }
    }

    fn manifest(version: u64, weight: u16) -> PackageManifest {
        PackageManifest {
            format: tp_contracts::risk::PACKAGE_FORMAT,
            version,
            created: OffsetDateTime::UNIX_EPOCH,
            min_node: Semver::new(0, 1, 0),
            key_id: "suite".to_owned(),
            signals: vec![signal("tp.suite", weight)],
            lists: Vec::new(),
            samples: Vec::new(),
        }
    }

    fn verdict() -> Verdict {
        Verdict {
            score: 6,
            hits: vec![Hit {
                signal: SignalId::new("tp.suite").expect("id"),
                strength: 100,
                weight: 6,
                source: HitSource::Detector,
            }],
            report_only: vec![Hit {
                signal: SignalId::new("tp.report").expect("id"),
                strength: 90,
                weight: 4,
                source: HitSource::Sieve,
            }],
            action: RiskAction::Junk,
            drops_reply: false,
        }
    }

    #[tokio::test]
    async fn suite_risk_store() {
        let clock = ManualClock::default();
        let store = MemRisk::new(clock.shared()).with_keep(1);
        suite::risk(&store, 1).await;
    }

    #[tokio::test]
    async fn usage_by_day() {
        let clock = ManualClock::default();
        let store = MemRisk::new(clock.shared());
        let (source, tenant) = (SourceId::new("feodo").expect("source"), TenantId::new());
        // Обращения одного дня складываются.
        store
            .record_usage(&source, tenant, 10, 1)
            .await
            .expect("usage");
        store
            .record_usage(&source, tenant, 5, 2)
            .await
            .expect("usage");
        let now = clock.now();
        let usage = store.usage(&source, now).await.expect("usage");
        assert_eq!(usage.len(), 1);
        assert_eq!(
            (usage[0].lookups, usage[0].hits),
            (15, 3),
            "сутки суммируются"
        );
        // Другой источник и чужая организация не видны.
        let other = SourceId::new("other").expect("source");
        assert!(store.usage(&other, now).await.expect("usage").is_empty());
        assert!(
            store
                .usage(&source, now + Duration::from_secs(3 * 24 * 3600))
                .await
                .expect("usage")
                .is_empty(),
            "с завтра не видно сегодня"
        );
        // Следующие сутки — отдельная запись.
        clock.advance(Duration::from_secs(24 * 3600));
        store
            .record_usage(&source, tenant, 1, 1)
            .await
            .expect("usage");
        let usage = store.usage(&source, now).await.expect("usage");
        assert_eq!(usage.len(), 2, "по суткам");
        assert!(usage[0].day < usage[1].day);
        assert_eq!(
            (usage[1].lookups, usage[1].hits),
            (1, 1),
            "новые сутки — новые счётчики"
        );
    }

    #[tokio::test]
    async fn lists_and_sources() {
        let clock = ManualClock::default();
        let store = MemRisk::new(clock.shared());
        let feodo = TiSource {
            id: SourceId::new("feodo").expect("source"),
            tier: Tier::Bundled,
            kind: SourceKind::Http {
                url: "https://feodo.tracker.abuse.ch/downloads/ipblocklist.json".to_owned(),
            },
            format: tp_contracts::risk::FeedFormat::Txt,
            ttl: Duration::from_secs(3600),
            stale: Default::default(),
            license: tp_contracts::risk::License {
                terms_url: "https://abuse.ch/terms".to_owned(),
                attribution: None,
                commercial: true,
            },
            tenants: tp_contracts::risk::Tenants::All,
            key: None,
            auth: tp_contracts::risk::HttpAuth::None,
            origin: tp_contracts::risk::TiOrigin::Vendor,
        };
        store.put_source(&feodo).await.expect("put source");
        assert_eq!(store.sources().await.expect("sources"), vec![feodo.clone()]);
        let list = ListId::new("feodo-ip").expect("list");
        let version = |fetched_at| ListVersion {
            list: list.clone(),
            source: feodo.id.clone(),
            sha256: BlobHash([1u8; 32]),
            blob: format!("mem/{list}"),
            entries: 1200,
            fetched_at,
            tlp: None,
        };
        store
            .put_list_version(&version(OffsetDateTime::UNIX_EPOCH))
            .await
            .expect("put list");
        // Новая версия списка становится текущей.
        let fresh = version(OffsetDateTime::UNIX_EPOCH + time::Duration::days(1));
        store.put_list_version(&fresh).await.expect("put again");
        assert_eq!(
            store.list_current(&list).await.expect("current"),
            Some(fresh.clone())
        );
        // Неизвестный источник и пустая ссылка — Invalid.
        let mut bad = fresh.clone();
        bad.source = SourceId::new("unknown").expect("source");
        assert!(matches!(
            store.put_list_version(&bad).await,
            Err(Error::Invalid(_))
        ));
        let mut bad = fresh;
        bad.blob = String::new();
        assert!(matches!(
            store.put_list_version(&bad).await,
            Err(Error::Invalid(_))
        ));
        // Запрещённый к поставке источник — Invalid; удаление — идемпотентно.
        let mut forbidden = feodo.clone();
        forbidden.kind = SourceKind::Http {
            url: "https://api.rstcloud.net/v1/ip".to_owned(),
        };
        assert!(matches!(
            store.put_source(&forbidden).await,
            Err(Error::Invalid(_))
        ));
        store
            .delete_source(&SourceId::new("none").expect("source"))
            .await
            .expect("delete absent");
        store.delete_source(&feodo.id).await.expect("delete");
        assert!(store.sources().await.expect("sources").is_empty());
    }

    #[tokio::test]
    async fn hits_filter_and_limit() {
        let clock = ManualClock::default();
        let store = MemRisk::new(clock.shared());
        let tenant = TenantId::new();
        store
            .record_hits(tenant, BlobHash([1u8; 32]), &verdict())
            .await
            .expect("record");
        clock.advance(Duration::from_secs(1));
        store
            .record_hits(tenant, BlobHash([2u8; 32]), &verdict())
            .await
            .expect("record");
        let all = store.hits(tenant, &HitsQuery::all(10)).await.expect("hits");
        assert_eq!(all.len(), 4, "два вердикта по две записи");
        // Свежие первыми; при равном моменте применённые прежде «только отчёт».
        assert_eq!(all[0].message, BlobHash([2u8; 32]));
        assert_eq!(all[0].mode, Mode::Enforce);
        assert_eq!(all[3].mode, Mode::Report);
        // Фильтры: признак, письмо, интервал; лимит; некорректный запрос.
        let mut q = HitsQuery::all(10);
        q.signal = Some(SignalId::new("tp.report").expect("id"));
        assert_eq!(store.hits(tenant, &q).await.expect("hits").len(), 2);
        let mut q = HitsQuery::all(10);
        q.message = Some(BlobHash([1u8; 32]));
        assert_eq!(store.hits(tenant, &q).await.expect("hits").len(), 2);
        let mut q = HitsQuery::all(10);
        q.until = Some(all[0].at);
        assert_eq!(
            store.hits(tenant, &q).await.expect("hits").len(),
            2,
            "раньше"
        );
        assert_eq!(
            store
                .hits(tenant, &HitsQuery::all(1))
                .await
                .expect("hits")
                .len(),
            1,
            "лимит"
        );
        assert!(matches!(
            store.hits(tenant, &HitsQuery::all(0)).await,
            Err(Error::Invalid(_))
        ));
        // Чужая организация не видит срабатываний.
        assert!(
            store
                .hits(TenantId::new(), &HitsQuery::all(10))
                .await
                .expect("hits")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn packages_keep_and_states() {
        let clock = ManualClock::default();
        let store = MemRisk::new(clock.shared()).with_keep(2);
        for v in 1..=4u64 {
            store
                .put_package(&manifest(v, u16::try_from(v).expect("weight")))
                .await
                .expect("put");
            store.activate(v).await.expect("activate");
        }
        let packages = store.packages().await.expect("packages");
        assert_eq!(
            packages,
            vec![
                PackageEntry {
                    version: 4,
                    state: Active
                },
                PackageEntry {
                    version: 3,
                    state: Previous
                },
                PackageEntry {
                    version: 2,
                    state: Previous
                },
            ],
            "активный и 2 прошлых по убыванию"
        );
        // Сверх keep откат невозможен.
        assert_eq!(store.rollback(1).await, Err(Error::NotFound));
        // Повторная активация того же номера — не растёт.
        assert!(matches!(store.activate(3).await, Err(Error::Invalid(_))));
        // Откат меняет действующий каталог.
        store.rollback(2).await.expect("rollback");
        let catalog = store.effective(TenantId::new()).await.expect("effective");
        assert_eq!(
            catalog
                .get(&SignalId::new("tp.suite").expect("id"))
                .expect("signal")
                .signal
                .weight,
            2
        );
    }

    #[test]
    fn day_boundaries() {
        let at = OffsetDateTime::from_unix_timestamp(1_800_000_017).expect("time");
        let start = OffsetDateTime::from_unix_timestamp(day_start(at)).expect("time");
        assert_eq!(start.time(), time::Time::MIDNIGHT);
        assert!(start <= at && at - start < time::Duration::hours(24));
    }
}
