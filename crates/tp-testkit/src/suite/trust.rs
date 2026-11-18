//! Набор проверок [`TrustStore`] (CTR-93, CONTRACTS.md#Trust; решение 124): in-memory `MemTrust` и `PgMeta`
//! (META-85) проходят одни и те же проверки.

use tp_contracts::groups::{DistributionGroup, GroupMember, GroupStore, SenderRestriction};
use tp_contracts::trust::{
    CellValue, Detail, HARD_CEILING, InviteMode, PeerKind, Toggle, TrustFunction, TrustLevel,
    TrustMatrix, TrustPolicy, TrustSources, TrustStore,
};
use tp_contracts::{AccountId, Error, GroupId, TenantId};

/// Группа рассылки `id` организации `tenant` с единственным участником `account` — уровень группы в наборе
/// [`trust`](super::trust()) действует на участников через членство.
pub fn member_group(tenant: TenantId, id: GroupId, account: AccountId) -> DistributionGroup {
    DistributionGroup {
        id,
        tenant,
        name: format!("trust-{id}"),
        address: Some(format!("trust-{id}@suite.example")),
        external_id: None,
        members: vec![GroupMember::Account(account)],
        senders: SenderRestriction::default(),
        moderators: Vec::new(),
        hidden_from_gal: false,
    }
}

/// Организация поднимает новое приглашение партнёру до «авто» и включает MDN партнёру (в пределах потолка
/// контракта).
fn raise() -> TrustPolicy {
    let mut p = TrustPolicy::default();
    p.invite_new.partner = Some(InviteMode::Auto);
    p.mdn.partner = Some(Toggle::On);
    p
}

/// Набор проверок [`TrustStore`] (решение 124). Хранилище в начале пустое; `tenant` и `foreign` — разные
/// организации, `account` — учётная запись `tenant` (для уровней групп — участник групп из `groups`).
///
/// Без политик — умолчания контракта и потолок [`HARD_CEILING`]; уровни пишутся и читаются; выше потолка —
/// `Invalid` без изменений уровня; `partners` и `auto_forward_domains` задаёт только организация; установка
/// снижает потолок — клетки организации шире потолка обрезаны и помечены `over_ceiling`, шире потолка организация
/// больше не пишет; группы учётной записи (через членство) дают самое узкое по каждой клетке, шире организации
/// группа не пишет; сброс возвращает уровень выше и умолчания; чужая организация своей политики не видит;
/// `partner_of` — домены-партнёры своей организации.
pub async fn trust(
    store: &dyn TrustStore,
    groups: &dyn GroupStore,
    tenant: TenantId,
    foreign: TenantId,
    account: AccountId,
) {
    let (org_level, inst_level) = (TrustLevel::Org(tenant), TrustLevel::Installation);

    // Без политик — умолчания контракта и потолок установки; сброс пустого уровня — не ошибка.
    assert_eq!(store.policy(inst_level).await, Ok(None));
    assert_eq!(store.policy(org_level).await, Ok(None));
    let e = store
        .effective_for(tenant, account)
        .await
        .expect("effective");
    assert_eq!(e.matrix, TrustMatrix::default());
    assert_eq!(e.ceiling.matrix, HARD_CEILING);
    assert_eq!(e.source, TrustSources::default());
    assert!(e.over_ceiling.is_empty());
    assert_eq!(store.reset_policy(org_level).await, Ok(()));

    // Уровень организации: пишется, читается, действует с источником; потолок организации — её явные клетки.
    let org = raise();
    store.set_policy(org_level, &org).await.expect("org set");
    assert_eq!(store.policy(org_level).await, Ok(Some(org.clone())));
    let e = store
        .effective_for(tenant, account)
        .await
        .expect("effective");
    assert_eq!(e.matrix.invite_new.partner, InviteMode::Auto);
    assert_eq!(e.matrix.mdn.partner, Toggle::On);
    assert_eq!(e.source.invite_new.partner, Some(org_level));
    assert_eq!(e.source.mdn.partner, Some(org_level));
    assert_eq!(e.ceiling.matrix.invite_new.partner, InviteMode::Auto);

    // Чужая организация своей политики не видит: уровни и действующая матрица — как без политик.
    assert_eq!(store.policy(TrustLevel::Org(foreign)).await, Ok(None));
    let e = store
        .effective_for(foreign, account)
        .await
        .expect("foreign effective");
    assert_eq!(e.matrix, TrustMatrix::default());
    assert_eq!(e.source, TrustSources::default());

    // Выше потолка контракта — Invalid без изменений уровня (закреплённые клетки).
    let mut bad = TrustPolicy::default();
    bad.freebusy.external = Some(Detail::FreeBusy);
    assert!(
        matches!(
            store.set_policy(org_level, &bad).await,
            Err(Error::Invalid(_))
        ),
        "freebusy.external"
    );
    let mut bad = TrustPolicy::default();
    bad.invite_new.neighbor = Some(InviteMode::Auto);
    assert!(
        matches!(
            store.set_policy(org_level, &bad).await,
            Err(Error::Invalid(_))
        ),
        "invite_new.neighbor"
    );
    assert_eq!(store.policy(org_level).await, Ok(Some(org.clone())));

    // Установка снижает потолок: организация шире не пишет, действующая клетка обрезана и помечена, источник
    // обрезанной клетки — уровень потолка.
    let mut cap = TrustPolicy::default();
    cap.mdn.partner = Some(Toggle::Off);
    store
        .set_policy(inst_level, &cap)
        .await
        .expect("install set");
    assert!(
        matches!(
            store.set_policy(org_level, &raise()).await,
            Err(Error::Invalid(_))
        ),
        "шире потолка установки"
    );
    let e = store
        .effective_for(tenant, account)
        .await
        .expect("effective");
    assert_eq!(e.matrix.mdn.partner, Toggle::Off, "обрезана");
    assert_eq!(
        e.matrix.invite_new.partner,
        InviteMode::Auto,
        "прочие клетки действуют"
    );
    assert_eq!(e.over_ceiling.len(), 1, "{:?}", e.over_ceiling);
    let cell = &e.over_ceiling[0];
    assert_eq!(
        (cell.function, cell.peer, cell.value, cell.ceiling),
        (
            TrustFunction::Mdn,
            PeerKind::Partner,
            CellValue::Toggle(Toggle::On),
            CellValue::Toggle(Toggle::Off)
        )
    );
    assert_eq!(cell.level, Some(inst_level));
    assert_eq!(e.source.mdn.partner, Some(inst_level));
    // Сброс установки — потолок контракта, организация действует снова.
    store.reset_policy(inst_level).await.expect("install reset");
    let e = store
        .effective_for(tenant, account)
        .await
        .expect("effective");
    assert_eq!(e.matrix.mdn.partner, Toggle::On);
    assert!(e.over_ceiling.is_empty());

    // Домены-партнёры и автопересылки задаёт только организация.
    let lists = TrustPolicy {
        partners: vec!["partner.example".into()],
        ..TrustPolicy::default()
    };
    for level in [inst_level, TrustLevel::Group(tenant, GroupId::new())] {
        assert!(
            matches!(
                store.set_policy(level, &lists).await,
                Err(Error::Invalid(_))
            ),
            "partners не у организации: {level}"
        );
    }
    let mut with_partners = org.clone();
    with_partners.partners = vec!["partner.example".into()];
    with_partners.auto_forward_domains = vec!["forward.example".into()];
    store
        .set_policy(org_level, &with_partners)
        .await
        .expect("partners set");

    // partner_of: домены-партнёры своей организации; чужая организация их не видит; длина и вид домена — Invalid.
    assert_eq!(store.partner_of(tenant, "partner.example").await, Ok(true));
    assert_eq!(store.partner_of(tenant, "PARTNER.example").await, Ok(true));
    assert_eq!(store.partner_of(tenant, "forward.example").await, Ok(false));
    assert_eq!(
        store.partner_of(foreign, "partner.example").await,
        Ok(false),
        "чужая организация"
    );
    assert!(matches!(
        store.partner_of(tenant, "не-домен").await,
        Err(Error::Invalid(_))
    ));

    // Группы учётной записи — через членство: каждая сужает свою клетку, действует самое узкое с источником
    // группы; не участник — только организация.
    let (g1, g2) = (GroupId::new(), GroupId::new());
    groups
        .put(member_group(tenant, g1, account))
        .await
        .expect("g1 put");
    groups
        .put(member_group(tenant, g2, account))
        .await
        .expect("g2 put");
    // Организация сузила общий доступ партнёру — группа шире организации не пишет.
    let mut narrow = with_partners.clone();
    narrow.sharing.partner = Some(Detail::None);
    store
        .set_policy(org_level, &narrow)
        .await
        .expect("narrow set");
    let mut wide = TrustPolicy::default();
    wide.sharing.partner = Some(Detail::Limited);
    assert!(
        matches!(
            store.set_policy(TrustLevel::Group(tenant, g1), &wide).await,
            Err(Error::Invalid(_))
        ),
        "группа шире организации"
    );
    let mut a = TrustPolicy::default();
    a.invite_new.partner = Some(InviteMode::Button);
    let mut b = TrustPolicy::default();
    b.mdn.partner = Some(Toggle::Off);
    store
        .set_policy(TrustLevel::Group(tenant, g1), &a)
        .await
        .expect("g1 set");
    store
        .set_policy(TrustLevel::Group(tenant, g2), &b)
        .await
        .expect("g2 set");
    let e = store
        .effective_for(tenant, account)
        .await
        .expect("effective");
    assert_eq!(
        e.matrix.invite_new.partner,
        InviteMode::Button,
        "сужена группой g1"
    );
    assert_eq!(e.matrix.mdn.partner, Toggle::Off, "сужена группой g2");
    assert_eq!(
        e.source.invite_new.partner,
        Some(TrustLevel::Group(tenant, g1))
    );
    assert_eq!(e.source.mdn.partner, Some(TrustLevel::Group(tenant, g2)));
    let outsider = AccountId::new();
    let e = store
        .effective_for(tenant, outsider)
        .await
        .expect("effective");
    assert_eq!(e.matrix.invite_new.partner, InviteMode::Auto);
    assert_eq!(e.matrix.mdn.partner, Toggle::On);

    // Сброс: группа — действует организация, организация — умолчания; домены-партнёры сброшены.
    store
        .reset_policy(TrustLevel::Group(tenant, g1))
        .await
        .expect("g1 reset");
    let e = store
        .effective_for(tenant, account)
        .await
        .expect("effective");
    assert_eq!(e.matrix.invite_new.partner, InviteMode::Auto, "организация");
    assert_eq!(e.matrix.mdn.partner, Toggle::Off, "группа g2 действует");
    store
        .reset_policy(TrustLevel::Group(tenant, g2))
        .await
        .expect("g2 reset");
    store.reset_policy(org_level).await.expect("org reset");
    assert_eq!(store.policy(org_level).await, Ok(None));
    let e = store
        .effective_for(tenant, account)
        .await
        .expect("effective");
    assert_eq!(e.matrix, TrustMatrix::default());
    assert_eq!(store.partner_of(tenant, "partner.example").await, Ok(false));
    assert_eq!(
        store.reset_policy(TrustLevel::Org(foreign)).await,
        Ok(()),
        "сброс пустого — не ошибка"
    );
}
