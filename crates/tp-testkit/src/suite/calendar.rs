//! Набор проверок публикаций календарей ([`CalendarPublications`], CTR-36): in-memory
//! `MemCalendarPublications` и PostgreSQL (`tp-meta`, META-34) проходят одни и те же проверки.
//! Потолок детализации набор поднимает политикой доверия ([`TrustStore`]) — реализация
//! [`CalendarPublications::ceiling`] считается по тому же хранилищу политики.

use time::{Duration, OffsetDateTime};
use tp_contracts::calendar::{CalendarPublication, CalendarPublications};
use tp_contracts::dav::CollectionId;
use tp_contracts::meta::AccountScope;
use tp_contracts::trust::{Detail, TrustLevel, TrustPolicy, TrustStore};
use tp_contracts::{AccountId, Error, PublicationId, TenantId};

/// Учётные записи для [`calendar_publications`]; организации — новые (без политик доверия и ссылок).
#[derive(Debug, Clone, Copy)]
pub struct PublicationsFixture {
    /// Владелец календаря.
    pub owner: AccountScope,
    /// Другая учётная запись той же организации.
    pub peer: AccountScope,
    /// Учётная запись другой организации.
    pub foreign: AccountScope,
}

impl PublicationsFixture {
    /// Учётные записи двух новых организаций: `owner` и `peer` — одной, `foreign` — другой.
    pub fn new() -> Self {
        let scope = |tenant| AccountScope {
            tenant,
            account: AccountId::new(),
        };
        let tenant = TenantId::new();
        PublicationsFixture {
            owner: scope(tenant),
            peer: scope(tenant),
            foreign: scope(TenantId::new()),
        }
    }
}

impl Default for PublicationsFixture {
    fn default() -> Self {
        Self::new()
    }
}

/// Набор проверок [`CalendarPublications`]: запрет выпуска без политики (потолок — `none`), потолок по
/// клетке `sharing` интернета политики доверия, уровни выше потолка — `Forbidden`, `none` и срок в прошлом —
/// `Invalid`, токен — только в результате `create`, список по возрастанию `id` без чужих ссылок, отзыв и
/// изоляция организаций. `publ` и `trust` — одно хранилище (реализация `ceiling` — по своему `TrustStore`).
pub async fn calendar_publications(
    publ: &dyn CalendarPublications,
    trust: &dyn TrustStore,
    fx: &PublicationsFixture,
) {
    let (owner, peer, foreign) = (fx.owner, fx.peer, fx.foreign);
    let calendar = CollectionId::new();
    let now = OffsetDateTime::now_utc();

    // Политики публикации нет: клетка `sharing` интернету — none, выпуск запрещён.
    assert_eq!(publ.ceiling(owner).await.expect("ceiling"), Detail::None);
    assert_eq!(
        publ.create(owner, calendar, Detail::FreeBusy, None).await,
        Err(Error::Forbidden)
    );

    // Организация разрешает «занят/свободен»: выпуск и список; токен — только в результате create.
    let mut policy = TrustPolicy::default();
    policy.sharing.external = Some(Detail::FreeBusy);
    trust
        .set_policy(TrustLevel::Org(owner.tenant), &policy)
        .await
        .expect("set policy");
    assert_eq!(
        publ.ceiling(owner).await.expect("ceiling"),
        Detail::FreeBusy
    );
    assert_eq!(
        publ.ceiling(peer).await.expect("ceiling peer"),
        Detail::FreeBusy,
        "та же организация"
    );

    let a = publ
        .create(owner, calendar, Detail::FreeBusy, None)
        .await
        .expect("create a");
    assert_eq!(
        (a.scope, a.calendar, a.detail, a.expires),
        (owner, calendar, Detail::FreeBusy, None)
    );
    let token = a.token.as_deref().expect("токен выдаётся один раз");
    assert!(
        !token.is_empty() && !token.chars().any(char::is_control),
        "{token}"
    );
    let listed = publ.list(owner).await.expect("list");
    assert_eq!(
        listed,
        vec![CalendarPublication {
            token: None,
            ..a.clone()
        }],
        "в списке токена нет"
    );

    // Уровень выше потолка — Forbidden; «нет уровня» и срок в прошлом — Invalid.
    assert_eq!(
        publ.create(owner, calendar, Detail::Limited, None).await,
        Err(Error::Forbidden)
    );
    assert!(matches!(
        publ.create(owner, calendar, Detail::None, None).await,
        Err(Error::Invalid(_))
    ));
    let past = now - Duration::minutes(5);
    let late = publ.create(owner, calendar, Detail::FreeBusy, Some(past));
    assert!(matches!(late.await, Err(Error::Invalid(_))));

    // Срок в будущем сохраняется; токены ссылок не повторяются.
    let b = publ
        .create(
            owner,
            calendar,
            Detail::FreeBusy,
            Some(now + Duration::hours(1)),
        )
        .await
        .expect("create b");
    assert_ne!(
        a.token.as_deref(),
        b.token.as_deref(),
        "токены не повторяются"
    );
    assert_ne!(a.id, b.id, "идентификаторы не повторяются");
    assert_eq!(b.expires, Some(now + Duration::hours(1)));

    // Подъём политики до «полностью»: limited проходит, all — выше закреплённого потолка интернета.
    policy.sharing.external = Some(Detail::Details);
    trust
        .set_policy(TrustLevel::Org(owner.tenant), &policy)
        .await
        .expect("raise policy");
    assert_eq!(
        publ.ceiling(owner).await.expect("ceiling details"),
        Detail::Details
    );
    let c = publ
        .create(owner, calendar, Detail::Limited, None)
        .await
        .expect("create limited");
    assert_eq!(c.detail, Detail::Limited);
    assert_eq!(
        publ.create(owner, calendar, Detail::All, None).await,
        Err(Error::Forbidden)
    );

    // Изоляция: чужая учётная запись не видит ссылок и не отзывает; чужая организация — без политики.
    assert!(publ.list(peer).await.expect("peer list").is_empty());
    assert_eq!(publ.revoke(peer, c.id).await, Err(Error::NotFound));
    assert_eq!(
        publ.ceiling(foreign).await.expect("foreign ceiling"),
        Detail::None,
        "политики организации foreign нет"
    );
    assert_eq!(
        publ.create(foreign, calendar, Detail::FreeBusy, None).await,
        Err(Error::Forbidden)
    );
    assert!(publ.list(foreign).await.expect("foreign list").is_empty());
    assert_eq!(publ.revoke(foreign, a.id).await, Err(Error::NotFound));

    // Отзыв: ссылка исчезает из списка, повторный отзыв и несуществующая — NotFound.
    assert_eq!(publ.revoke(owner, b.id).await, Ok(()));
    assert_eq!(publ.revoke(owner, b.id).await, Err(Error::NotFound));
    let left = publ.list(owner).await.expect("list after revoke");
    let ids: Vec<PublicationId> = left.iter().map(|l| l.id).collect();
    assert_eq!(ids.len(), 2, "остались a и c: {ids:?}");
    assert!(
        ids.windows(2).all(|w| w[0] < w[1]),
        "по возрастанию id: {ids:?}"
    );
    assert_eq!(left, vec![a, c], "отозванной нет");
}
