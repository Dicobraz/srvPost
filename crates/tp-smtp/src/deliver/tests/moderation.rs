//! FIX-01: решения модератора (`impl Moderation for Delivery`, CTR-31, CTR-43) — одобренное письмо участникам группы
//! ровно один раз, письмо правила потока — исходным получателям, отказ — уведомление отправителю через очередь.
//! SMTP-30: исход `Moderate` правил потока — постановка в очередь модерации и уведомление модератору.

use tp_contracts::groups::{
    DistributionGroup, GroupMember, GroupStore, HeldMessage, HoldSource, Moderation, Moderator,
    SenderRestriction,
};
use tp_contracts::transport::{FlowInput, FlowOutcome, FlowVerdict, MailFlow};
use tp_contracts::{Error, GroupId, HeldId, TenantId};
use tp_testkit::suite::{self, ModerationFixture};

use super::*;
use crate::groups::Groups;

const T: TenantId = TenantId::DEFAULT;

impl Env {
    fn moderating(&self, outbound: bool) -> Delivery {
        self.delivery(outbound).with_groups(Groups::new(
            Arc::new(self.groups.clone()),
            Arc::new(self.blobs.clone()),
            Arc::new(self.index.clone()),
        ))
    }

    /// Группа `address` с участниками `members` и модератором carol.
    async fn moderated(&self, address: &str, members: Vec<GroupMember>) -> DistributionGroup {
        let g = DistributionGroup {
            id: GroupId::new(),
            tenant: T,
            name: address.into(),
            address: Some(address.into()),
            external_id: None,
            members,
            senders: SenderRestriction::Anyone,
            moderators: vec![self.scope("carol@example.org").await.account],
            hidden_from_gal: false,
        };
        self.groups.put(g.clone()).await.expect("put group");
        g
    }

    async fn member(&self, login: &str) -> GroupMember {
        GroupMember::Account(self.scope(login).await.account)
    }

    /// Письмо внешнего отправителя в группу через smtp-in: ждёт модератора; возвращает его, забранное из очереди
    /// (`GroupStore::take_held`, как Admin API).
    async fn take(&self, d: &Delivery, group: &DistributionGroup, tag: &str) -> HeldMessage {
        let address = group.address.clone().expect("address");
        let e = envelope(Mode::Inbound, &[address.as_str()]);
        let raw = format!(
            "From: sender@example.net\r\nTo: {address}\r\nSubject: {tag}\r\nMessage-ID: <{tag}@example.net>\r\n\r\nbody\r\n"
        );
        assert_eq!(d.data(&e, Bytes::from(raw)).await.code, 250);
        let held = self
            .groups
            .held(T, Some(group.id), None, 100)
            .await
            .expect("held")
            .into_iter()
            .find(|h| h.message_id.as_deref() == Some(format!("{tag}@example.net").as_str()))
            .expect("письмо в очереди модерации");
        self.groups.take_held(T, held.id).await.expect("take")
    }

    fn refs(&self, h: &HeldMessage) -> u32 {
        self.index.row(T, &h.blob.hash).map_or(0, |r| r.refcnt)
    }

    fn queued(&self) -> Vec<(String, Vec<String>, Bytes)> {
        self.queue.0.lock().expect("lock").clone()
    }
}

/// Одобрено: каждый участник (с вложенной группой, в которой часть участников повторяется) получает письмо один раз,
/// без повторной модерации; повторное решение по тому же письму — `NotFound` очереди.
#[tokio::test]
async fn approved_message_delivered_to_each_member_once() {
    let env = Env::new(DecisionHooks::default()).await;
    let d = env.moderating(true);
    let team = DistributionGroup {
        id: GroupId::new(),
        tenant: T,
        name: "team".into(),
        address: None,
        external_id: None,
        members: vec![
            env.member("alice@example.org").await,
            env.member("carol@example.org").await,
        ],
        senders: SenderRestriction::Anyone,
        moderators: Vec::new(),
        hidden_from_gal: false,
    };
    env.groups.put(team.clone()).await.expect("team");
    let g = env
        .moderated(
            "news@example.org",
            vec![
                env.member("alice@example.org").await,
                env.member("bob@example.org").await,
                GroupMember::Group(team.id),
            ],
        )
        .await;
    let h = env.take(&d, &g, "approve-1").await;
    for login in ["alice@example.org", "bob@example.org", "carol@example.org"] {
        assert!(env.inbox(login).await.is_empty(), "{login}: до решения");
    }

    d.deliver(T, Some(&g), &h).await.expect("deliver");
    for login in ["alice@example.org", "bob@example.org", "carol@example.org"] {
        let inbox = env.inbox(login).await;
        assert_eq!(inbox.len(), 1, "{login}: {inbox:?}");
        assert!(inbox[0].contains("Subject: approve-1"), "{}", inbox[0]);
    }
    // Ничего наружу и ни одного уведомления отправителю.
    assert!(env.queued().is_empty(), "{:?}", env.queued());
    assert!(
        env.groups
            .held(T, Some(g.id), None, 100)
            .await
            .expect("held")
            .is_empty()
    );
    assert_eq!(env.groups.take_held(T, h.id).await, Err(Error::NotFound));
}

/// Отклонено: отправителю — DSN (RFC 3464) с причиной модератора и адресом группы через очередь, участникам ничего;
/// ссылка письма очереди на объект снята.
#[tokio::test]
async fn rejected_message_bounces_to_sender() {
    let env = Env::new(DecisionHooks::default()).await;
    let d = env.moderating(true);
    let g = env
        .moderated(
            "news@example.org",
            vec![env.member("alice@example.org").await],
        )
        .await;
    let h = env.take(&d, &g, "reject-1").await;
    assert_eq!(env.refs(&h), 1);

    for bad in ["", "a\nb"] {
        assert!(matches!(d.reject(T, &h, bad).await, Err(Error::Invalid(_))));
    }
    assert!(env.queued().is_empty());
    d.reject(T, &h, "off-topic").await.expect("reject");
    let queued = env.queued();
    assert_eq!(queued.len(), 1, "{queued:?}");
    let (from, rcpts, raw) = &queued[0];
    assert_eq!(from, "");
    assert_eq!(rcpts, &vec!["sender@example.net".to_owned()]);
    let dsn = String::from_utf8_lossy(raw);
    assert!(dsn.contains("multipart/report"), "{dsn}");
    assert!(
        dsn.contains("Final-Recipient: rfc822; news@example.org"),
        "{dsn}"
    );
    assert!(dsn.contains("Status: 5.7.1"), "{dsn}");
    assert!(dsn.contains("off-topic"), "{dsn}");
    assert!(dsn.contains("Subject: reject-1"), "{dsn}");
    assert!(env.inbox("alice@example.org").await.is_empty());
    assert_eq!(env.refs(&h), 0);
    assert_eq!(env.groups.take_held(T, h.id).await, Err(Error::NotFound));
}

/// Общий набор `Moderation` tp-testkit на реальных письмах очереди.
#[tokio::test]
async fn moderation_suite() {
    let env = Env::new(DecisionHooks::default()).await;
    let d = env.moderating(true);
    let g = env
        .moderated(
            "news@example.org",
            vec![env.member("bob@example.org").await],
        )
        .await;
    let fx = ModerationFixture {
        tenant: T,
        group: g.clone(),
        approve: env.take(&d, &g, "suite-a").await,
        decline: env.take(&d, &g, "suite-d").await,
    };
    suite::moderation(&d, &fx).await;
    assert_eq!(env.inbox("bob@example.org").await.len(), 1);
    // Решение по письму другой организации — `Invalid`.
    assert!(matches!(
        d.reject(TenantId::new(), &fx.decline, "off-topic").await,
        Err(Error::Invalid(_))
    ));
}

/// Письмо правила потока `n` (объект — в хранилище, одна ссылка): bob и внешний получатель, модератор carol.
async fn rule_held(env: &Env, raw: &Bytes, n: u8) -> HeldMessage {
    let blob = crate::queue::store_blob(&env.blobs, &env.index, T, None, raw.clone())
        .await
        .expect("blob");
    HeldMessage {
        id: HeldId::new(),
        group: None,
        source: HoldSource::FlowRule {
            rule: "Внешним — с одобрения".into(),
        },
        moderators: vec![Moderator::Account(
            env.scope("carol@example.org").await.account,
        )],
        recipients: vec!["bob@example.org".into(), "x@remote.example".into()],
        sender: "s@example.net".into(),
        sender_account: None,
        message_id: Some(format!("rule-{n}@example.net")),
        blob,
        size: raw.len() as u64,
        held_at: OffsetDateTime::now_utc(),
    }
}

/// Письмо правила потока (CTR-43, без группы): одобрено — локальному получателю в ящик, внешнему — в очередь
/// от исходного отправителя; отказ — DSN с исходными получателями.
#[tokio::test]
async fn flow_rule_message_delivered_to_original_recipients() {
    let env = Env::new(DecisionHooks::default()).await;
    let d = env.moderating(true);
    let raw = Bytes::from_static(b"From: s@example.net\r\nSubject: rule\r\n\r\nbody\r\n");
    let approve = rule_held(&env, &raw, 1).await;
    env.groups.hold(T, approve.clone()).await.expect("hold");
    let approve = env.groups.take_held(T, approve.id).await.expect("take");
    d.deliver(T, None, &approve).await.expect("deliver");
    assert_eq!(env.inbox("bob@example.org").await.len(), 1);
    let queued = env.queued();
    assert_eq!(queued.len(), 1, "{queued:?}");
    assert_eq!(queued[0].0, "s@example.net");
    assert_eq!(queued[0].1, vec!["x@remote.example".to_owned()]);
    assert_eq!(&queued[0].2[..], &raw[..]);

    let decline = rule_held(&env, &raw, 2).await;
    d.reject(T, &decline, "not allowed").await.expect("reject");
    let queued = env.queued();
    assert_eq!(queued.len(), 2, "{queued:?}");
    let dsn = String::from_utf8_lossy(&queued[1].2);
    assert_eq!(queued[1].1, vec!["s@example.net".to_owned()]);
    assert!(
        dsn.contains("Final-Recipient: rfc822; bob@example.org"),
        "{dsn}"
    );
    assert!(
        dsn.contains("Final-Recipient: rfc822; x@remote.example"),
        "{dsn}"
    );
    assert_eq!(env.inbox("bob@example.org").await.len(), 1);
}

// ---------- SMTP-30: исход Moderate правил потока — очередь модерации ----------

/// Заглушка `MailFlow`: отвечает заданным исходом, сработавшее правило — по имени (тело не читает).
struct RuleFlow {
    verdict: FlowVerdict,
    matched: Vec<String>,
}

#[async_trait]
impl MailFlow for RuleFlow {
    async fn apply(&self, input: &FlowInput) -> Result<FlowOutcome> {
        let mut out = FlowOutcome::unchanged(input);
        out.verdict = self.verdict.clone();
        out.matched = self.matched.clone();
        Ok(out)
    }
}

/// Письмо с темой `subject` и `Message-ID` от `from` (для очереди модерации по `message_id`).
fn letter(tag: &str, from: &str) -> Bytes {
    Bytes::from(format!(
        "From: {from}\r\nTo: bob@example.org\r\nSubject: {tag}\r\nMessage-ID: <{tag}@example.net>\r\n\r\nbody\r\n"
    ))
}

impl Env {
    /// Доставка с группами (очередь модерации) и правилом потока `flow`.
    fn flow_moderating(&self, flow: Arc<RuleFlow>) -> Delivery {
        self.moderating(true).with_mail_flow(
            flow,
            Arc::new(self.blobs.clone()),
            Arc::new(self.index.clone()),
        )
    }

    /// Запись очереди модерации письма правила (без группы) по `Message-ID`.
    async fn rule_message(&self, message_id: &str) -> HeldMessage {
        self.groups
            .held(T, None, None, 100)
            .await
            .expect("held")
            .into_iter()
            .find(|h| h.message_id.as_deref() == Some(message_id))
            .expect("письмо правила в очереди модерации")
    }
}

/// Правило с исходом Moderate (приём): отправителю — 250, письмо — в очереди модерации с исходными
/// получателями и модераторами, ссылка на объект — у очереди; модератору — уведомление с исходным письмом
/// во вложении. Одобрение доставляет письмо исходным получателям, отказ — DSN отправителю.
#[tokio::test]
async fn flow_rule_moderation_holds_then_approve_or_reject() {
    let env = Env::new(DecisionHooks::default()).await;
    let moderator = env.scope("carol@example.org").await.account;
    let flow = Arc::new(RuleFlow {
        verdict: FlowVerdict::Moderate {
            moderators: vec![moderator],
        },
        matched: vec!["Внешним — с одобрения".into()],
    });
    let d = env.flow_moderating(flow);
    let e = envelope(Mode::Inbound, &["bob@example.org"]);
    assert_eq!(
        d.data(&e, letter("smtp30-a", "sender@example.net"))
            .await
            .code,
        250
    );
    assert!(env.inbox("bob@example.org").await.is_empty(), "до решения");
    let notice = env.inbox("carol@example.org").await;
    assert_eq!(notice.len(), 1, "уведомление модератору: {notice:?}");
    let msg = mail_parser::MessageParser::new()
        .parse(notice[0].as_bytes())
        .expect("parse notice");
    assert_eq!(
        msg.subject(),
        Some("Moderation Request: Внешним — с одобрения")
    );
    assert!(
        notice[0].contains("Auto-Submitted: auto-replied"),
        "{}",
        notice[0]
    );
    assert!(notice[0].contains("message/rfc822"), "{}", notice[0]);
    assert!(notice[0].contains("Subject: smtp30-a"), "{}", notice[0]);
    let held = env.rule_message("smtp30-a@example.net").await;
    assert_eq!(held.group, None);
    assert_eq!(
        held.source,
        HoldSource::FlowRule {
            rule: "Внешним — с одобрения".into(),
        }
    );
    assert_eq!(held.moderators, vec![Moderator::Account(moderator)]);
    assert_eq!(held.recipients, ["bob@example.org"]);
    assert_eq!(
        (held.sender.as_str(), held.sender_account),
        ("sender@example.net", None)
    );
    assert_eq!(env.refs(&held), 1, "ссылка на объект — у очереди");

    // Одобрение (Admin API: take_held + Moderation::deliver без группы) — исходным получателям.
    let held = env.groups.take_held(T, held.id).await.expect("take");
    d.deliver(T, None, &held).await.expect("deliver");
    let bob = env.inbox("bob@example.org").await;
    assert_eq!(bob.len(), 1, "{bob:?}");
    assert!(bob[0].contains("Subject: smtp30-a"), "{}", bob[0]);
    assert!(
        env.queued().is_empty(),
        "без уведомлений: {:?}",
        env.queued()
    );
    assert_eq!(env.refs(&held), 0);

    // Отказ — DSN отправителю с причиной модератора; получателям ничего.
    assert_eq!(
        d.data(&e, letter("smtp30-r", "sender@example.net"))
            .await
            .code,
        250
    );
    assert_eq!(
        env.inbox("carol@example.org").await.len(),
        2,
        "второе уведомление"
    );
    let held = env.rule_message("smtp30-r@example.net").await;
    let held = env.groups.take_held(T, held.id).await.expect("take");
    d.reject(T, &held, "не для внешней рассылки")
        .await
        .expect("reject");
    let queued = env.queued();
    assert_eq!(queued.len(), 1, "{queued:?}");
    assert_eq!(queued[0].1, ["sender@example.net"]);
    let dsn = String::from_utf8_lossy(&queued[0].2);
    assert!(dsn.contains("Status: 5.7.1"), "{dsn}");
    assert!(dsn.contains("не для внешней рассылки"), "{dsn}");
    assert_eq!(env.inbox("bob@example.org").await.len(), 1, "после отказа");
}

/// Submission вошедшего пользователя: у записи очереди — учётная запись отправителя; отправка вне сессии
/// (JMAP, [`Delivery::submit`]) — `Queued` всем получателям.
#[tokio::test]
async fn flow_rule_moderation_submission_and_submit() {
    let env = Env::new(DecisionHooks::default()).await;
    let moderator = env.scope("carol@example.org").await.account;
    let alice = env.scope("alice@example.org").await.account;
    let flow = Arc::new(RuleFlow {
        verdict: FlowVerdict::Moderate {
            moderators: vec![moderator],
        },
        matched: vec!["Проверка отправки".into()],
    });
    let d = env.flow_moderating(flow);
    let mut e = envelope(Mode::Submission, &["bob@example.org", "x@remote.example"]);
    let mut principal = tp_testkit::principal(T, "alice@example.org");
    principal.account = alice;
    e.principal = Some(principal);
    e.mail_from = "alice@example.org".into();
    let raw = letter("smtp30-s", "alice@example.org");
    assert_eq!(d.data(&e, raw).await.code, 250);
    assert!(env.inbox("bob@example.org").await.is_empty());
    assert!(env.queue.0.lock().expect("lock").is_empty());
    let held = env.rule_message("smtp30-s@example.net").await;
    assert_eq!(held.sender, "alice@example.org");
    assert_eq!(held.sender_account, Some(alice));
    assert_eq!(held.recipients, ["bob@example.org", "x@remote.example"]);
    assert_eq!(env.inbox("carol@example.org").await.len(), 1);

    // Отправка вне сессии SMTP: письмо — в очереди модерации, всем получателям — `Queued`.
    let out = d
        .submit(
            T,
            None,
            "alice@example.org",
            &rcpts(&["bob@example.org"]),
            letter("smtp30-j", "alice@example.org"),
        )
        .await
        .expect("submit");
    assert_eq!(
        out.rcpts,
        [("bob@example.org".to_owned(), SubmitStatus::Queued)],
        "{out:?}"
    );
    assert!(env.inbox("bob@example.org").await.is_empty());
    let held = env.rule_message("smtp30-j@example.net").await;
    assert_eq!(held.sender_account, Some(alice));
    assert_eq!(
        env.inbox("carol@example.org").await.len(),
        2,
        "второе уведомление"
    );
}

/// Ставить некуда (нет хранилища очереди или модераторов) — временный отказ: письмо не теряется.
/// Имя правила — из сработавших, с запасным именем и обрезкой до 255 символов.
#[tokio::test]
async fn flow_rule_moderation_fallback_and_rule_name() {
    let env = Env::new(DecisionHooks::default()).await;
    let moderator = env.scope("carol@example.org").await.account;
    let e = envelope(Mode::Inbound, &["bob@example.org"]);
    // Хранилище очереди модерации не подключено.
    let flow = Arc::new(RuleFlow {
        verdict: FlowVerdict::Moderate {
            moderators: vec![moderator],
        },
        matched: vec!["R".into()],
    });
    let no_groups = env.delivery(true).with_mail_flow(
        flow,
        Arc::new(env.blobs.clone()),
        Arc::new(env.index.clone()),
    );
    assert_eq!(no_groups.data(&e, Bytes::from_static(MAIL)).await.code, 451);
    // Вердикт без модераторов — уведомлять некого.
    let flow = Arc::new(RuleFlow {
        verdict: FlowVerdict::Moderate {
            moderators: Vec::new(),
        },
        matched: vec!["R".into()],
    });
    let nobody = env.flow_moderating(flow);
    assert_eq!(nobody.data(&e, Bytes::from_static(MAIL)).await.code, 451);
    assert!(env.inbox("carol@example.org").await.is_empty());
    assert!(
        env.groups
            .held(T, None, None, 10)
            .await
            .expect("held")
            .is_empty(),
        "ничего не поставлено"
    );

    // Имя правила: первое сработавшее, запасное имя, обрезка до предела контракта.
    assert_eq!(rule_name(&["Первое".into(), "Второе".into()]), "Первое");
    assert_eq!(rule_name(&[]), "mail flow rule");
    assert_eq!(rule_name(&["  ".into()]), "mail flow rule");
    assert_eq!(rule_name(&["a\nb".into()]), "a b");
    assert_eq!(rule_name(&["д".repeat(300)]), "д".repeat(255));
    let flow = Arc::new(RuleFlow {
        verdict: FlowVerdict::Moderate {
            moderators: vec![moderator],
        },
        matched: Vec::new(),
    });
    let d = env.flow_moderating(flow);
    assert_eq!(d.data(&e, Bytes::from_static(MAIL)).await.code, 250);
    let held = env
        .groups
        .held(T, None, None, 10)
        .await
        .expect("held")
        .into_iter()
        .find(|h| h.group.is_none())
        .expect("запись правила");
    assert_eq!(
        held.source,
        HoldSource::FlowRule {
            rule: "mail flow rule".into(),
        }
    );
}
