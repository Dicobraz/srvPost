//! In-memory политика доверия ([`TrustStore`], CTR-93; CONTRACTS.md#Trust; решение 124): уровни, потолки,
//! домены-партнёры. Группы учётной записи — через членство [`GroupStore`] (`with_groups`).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tp_contracts::groups::GroupStore;
use tp_contracts::transport::normalize_domain;
use tp_contracts::trust::{Ceiling, Effective, TrustLevel, TrustPolicy, TrustStore, effective};
use tp_contracts::{AccountId, Error, Result, TenantId};

use crate::infra::lock;

#[derive(Debug, Default)]
struct TrustState {
    levels: HashMap<TrustLevel, TrustPolicy>,
    accepted: HashMap<TenantId, Vec<String>>,
}

/// [`TrustStore`] в памяти; клоны разделяют данные. Политики пустых уровней не хранятся; пустая политика
/// (все клетки `None`, списки пусты) при записи удаляет уровень. Сигнал `trust_changed` не публикует — его
/// публикует узел после фиксации.
#[derive(Clone)]
pub struct MemTrust {
    state: Arc<Mutex<TrustState>>,
    groups: Option<Arc<dyn GroupStore>>,
}

impl fmt::Debug for MemTrust {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemTrust")
            .field("state", &self.state)
            .field("groups", &self.groups.is_some())
            .finish()
    }
}

impl MemTrust {
    /// Пустое хранилище без групп: `effective_for` не учитывает уровни групп.
    pub fn new() -> Self {
        Self {
            state: Arc::default(),
            groups: None,
        }
    }

    /// Группы учётной записи — членство в `groups` ([`GroupStore::list`] и [`GroupStore::expand`]).
    pub fn with_groups(mut self, groups: Arc<dyn GroupStore>) -> Self {
        self.groups = Some(groups);
        self
    }

    /// Принятые домены организации `tenant`: свой домен в `partners` — `Invalid` ([`TrustPolicy::validate`]).
    pub fn with_accepted(self, tenant: TenantId, domains: &[String]) -> Self {
        lock(&self.state).accepted.insert(tenant, domains.to_vec());
        self
    }

    /// Политика уровня, если задана.
    fn policy_of(&self, level: TrustLevel) -> Option<TrustPolicy> {
        lock(&self.state).levels.get(&level).cloned()
    }

    /// Действующий потолок записи уровня `level` и принятые домены его организации: у установки —
    /// [`Ceiling::hard`] (потолок контракта), у организации — явные клетки установки, у группы — организации
    /// ([`effective`] по уровням выше).
    fn write_ceiling(&self, level: TrustLevel) -> (Ceiling, Vec<String>) {
        let inst = self.policy_of(TrustLevel::Installation);
        let accepted_of = |t: TenantId| {
            lock(&self.state)
                .accepted
                .get(&t)
                .cloned()
                .unwrap_or_default()
        };
        match level {
            TrustLevel::Installation => (Ceiling::hard(), Vec::new()),
            TrustLevel::Org(t) => (effective(inst.as_ref(), None, &[]).ceiling, accepted_of(t)),
            TrustLevel::Group(t, _) => {
                let org = self.policy_of(TrustLevel::Org(t));
                let ceiling = effective(
                    inst.as_ref(),
                    org.as_ref().map(|p| (TrustLevel::Org(t), p)),
                    &[],
                )
                .ceiling;
                (ceiling, accepted_of(t))
            }
        }
    }
}

impl Default for MemTrust {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TrustStore for MemTrust {
    async fn policy(&self, level: TrustLevel) -> Result<Option<TrustPolicy>> {
        Ok(self.policy_of(level))
    }

    async fn set_policy(&self, level: TrustLevel, policy: &TrustPolicy) -> Result<()> {
        if !matches!(level, TrustLevel::Org(_))
            && (!policy.partners.is_empty() || !policy.auto_forward_domains.is_empty())
        {
            return Err(Error::invalid(
                "partners и auto_forward_domains задаёт только организация",
            ));
        }
        let (ceiling, accepted) = self.write_ceiling(level);
        policy.validate(&ceiling, &accepted)?;
        let mut st = lock(&self.state);
        if *policy == TrustPolicy::default() {
            st.levels.remove(&level);
        } else {
            st.levels.insert(level, policy.clone());
        }
        Ok(())
    }

    async fn reset_policy(&self, level: TrustLevel) -> Result<()> {
        lock(&self.state).levels.remove(&level);
        Ok(())
    }

    async fn effective_for(&self, tenant: TenantId, account: AccountId) -> Result<Effective> {
        let mut group_policies = Vec::new();
        if let Some(groups) = &self.groups {
            for g in groups.list(tenant).await? {
                if groups.expand(tenant, g.id).await?.contains(&account)
                    && let Some(p) = self.policy_of(TrustLevel::Group(tenant, g.id))
                {
                    group_policies.push((TrustLevel::Group(tenant, g.id), p));
                }
            }
        }
        let groups: Vec<(TrustLevel, &TrustPolicy)> = group_policies
            .iter()
            .map(|(level, p)| (*level, p))
            .collect();
        let inst = self.policy_of(TrustLevel::Installation);
        let org = self.policy_of(TrustLevel::Org(tenant));
        Ok(effective(
            inst.as_ref(),
            org.as_ref().map(|p| (TrustLevel::Org(tenant), p)),
            &groups,
        ))
    }

    async fn partner_of(&self, tenant: TenantId, domain: &str) -> Result<bool> {
        let domain = normalize_domain(domain)?;
        Ok(self
            .policy_of(TrustLevel::Org(tenant))
            .is_some_and(|p| p.partners.iter().any(|d| d == &domain)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tp_contracts::trust::{Detail, InviteMode, Toggle, TrustMatrix, TrustSources};

    use crate::MemGroups;
    use crate::suite;

    fn org_policy(t: TenantId) -> TrustLevel {
        TrustLevel::Org(t)
    }

    /// Организация поднимает новое приглашение партнёру до «авто» и включает MDN партнёру.
    fn raise() -> TrustPolicy {
        let mut p = TrustPolicy::default();
        p.invite_new.partner = Some(InviteMode::Auto);
        p.mdn.partner = Some(Toggle::On);
        p
    }

    #[tokio::test]
    async fn suite_trust_store() {
        let groups = MemGroups::new();
        let store = MemTrust::new().with_groups(Arc::new(groups.clone()));
        suite::trust(
            &store,
            &groups,
            TenantId::new(),
            TenantId::new(),
            AccountId::new(),
        )
        .await;
    }

    #[tokio::test]
    async fn ceiling_follows_levels_and_accepted_domains() {
        let tenant = TenantId::new();
        let store = MemTrust::new().with_accepted(tenant, &["example.com".to_owned()]);
        // Свои домены в partners не проходят, чужие — да.
        let own = TrustPolicy {
            partners: vec!["example.com".into()],
            ..TrustPolicy::default()
        };
        assert!(matches!(
            store.set_policy(org_policy(tenant), &own).await,
            Err(Error::Invalid(_))
        ));
        let p = TrustPolicy {
            partners: vec!["partner.example".into()],
            ..TrustPolicy::default()
        };
        store.set_policy(org_policy(tenant), &p).await.expect("set");
        assert_eq!(
            store.partner_of(tenant, "PARTNER.example").await,
            Ok(true),
            "домен канонизируется"
        );

        // Организация включает MDN партнёру — действует.
        store
            .set_policy(org_policy(tenant), &raise())
            .await
            .expect("raise");
        assert_eq!(
            store
                .effective_for(tenant, AccountId::new())
                .await
                .expect("eff")
                .matrix
                .mdn
                .partner,
            Toggle::On
        );

        // Установка снижает потолок — организация шире не пишет.
        let mut inst = TrustPolicy::default();
        inst.mdn.partner = Some(Toggle::Off);
        store
            .set_policy(TrustLevel::Installation, &inst)
            .await
            .expect("install");
        let mut wide = TrustPolicy::default();
        wide.mdn.partner = Some(Toggle::On);
        assert!(matches!(
            store.set_policy(org_policy(tenant), &wide).await,
            Err(Error::Invalid(_))
        ));
        // Действующая матрица организации обрезана до потолка, клетка помечена.
        let e = store
            .effective_for(tenant, AccountId::new())
            .await
            .expect("eff");
        assert_eq!(e.matrix.mdn.partner, Toggle::Off);
        assert_eq!(e.over_ceiling.len(), 1, "{:?}", e.over_ceiling);
        assert_eq!(e.source.mdn.partner, Some(TrustLevel::Installation));

        // Пустая политика удаляет уровень, сброс — тоже.
        store
            .set_policy(org_policy(tenant), &TrustPolicy::default())
            .await
            .expect("set empty");
        assert_eq!(store.policy(org_policy(tenant)).await, Ok(None));
        assert_eq!(
            store
                .effective_for(tenant, AccountId::new())
                .await
                .map(|e| e.matrix),
            Ok(TrustMatrix::default())
        );
    }

    #[tokio::test]
    async fn groups_through_membership() {
        let tenant = TenantId::new();
        let (account, outsider) = (AccountId::new(), AccountId::new());
        let groups = MemGroups::new();
        let store = MemTrust::new().with_groups(Arc::new(groups.clone()));
        store
            .set_policy(org_policy(tenant), &raise())
            .await
            .expect("org");
        let g = suite::member_group(tenant, tp_contracts::GroupId::new(), account);
        let g_level = TrustLevel::Group(tenant, g.id);
        groups.put(g).await.expect("put");
        let mut narrow = TrustPolicy::default();
        narrow.invite_new.partner = Some(InviteMode::Button);
        store.set_policy(g_level, &narrow).await.expect("group");
        // Участник — самое узкое из организации и группы.
        let e = store.effective_for(tenant, account).await.expect("eff");
        assert_eq!(e.matrix.invite_new.partner, InviteMode::Button);
        assert_eq!(e.matrix.mdn.partner, Toggle::On);
        assert_eq!(e.source.invite_new.partner, Some(g_level));
        // Не участник — только организация.
        let e = store.effective_for(tenant, outsider).await.expect("eff");
        assert_eq!(e.matrix.invite_new.partner, InviteMode::Auto);
        assert_eq!(e.source.invite_new.partner, Some(org_policy(tenant)));
        // Без групп — уровни групп не учитываются.
        let bare = MemTrust::new();
        bare.set_policy(org_policy(tenant), &raise())
            .await
            .expect("org");
        let e = bare.effective_for(tenant, account).await.expect("eff");
        assert_eq!(e.matrix.invite_new.partner, InviteMode::Auto);
        assert_eq!(e.source, {
            let mut src = TrustSources::default();
            src.invite_new.partner = Some(org_policy(tenant));
            src.mdn.partner = Some(org_policy(tenant));
            src
        });
    }

    #[tokio::test]
    async fn partners_only_at_org_and_domain_checks() {
        let tenant = TenantId::new();
        let store = MemTrust::new();
        let p = TrustPolicy {
            auto_forward_domains: vec!["example.net".into()],
            ..TrustPolicy::default()
        };
        for level in [
            TrustLevel::Installation,
            TrustLevel::Group(tenant, tp_contracts::GroupId::new()),
        ] {
            assert!(
                matches!(store.set_policy(level, &p).await, Err(Error::Invalid(_))),
                "{level}"
            );
        }
        store.set_policy(org_policy(tenant), &p).await.expect("org");
        assert_eq!(store.partner_of(tenant, "example.net").await, Ok(false));
        assert_eq!(
            store.partner_of(TenantId::new(), "example.net").await,
            Ok(false),
            "чужая организация"
        );
        assert!(matches!(
            store.partner_of(tenant, "не домен").await,
            Err(Error::Invalid(_))
        ));
        assert_eq!(
            store.effective_for(TenantId::new(), AccountId::new()).await,
            Ok(effective(None, None, &[])),
            "чужая организация — умолчания"
        );
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(
            MemTrust::default().policy_of(TrustLevel::Installation),
            None
        );
    }

    #[test]
    fn over_ceiling_detail_kept() {
        // Потолок вычислен по уровням выше: группа видит организацию (функция чистая, без хранилища).
        let (ceiling, _) = MemTrust::new().write_ceiling(TrustLevel::Installation);
        assert_eq!(ceiling.matrix.freebusy.partner, Detail::Limited);
    }
}
