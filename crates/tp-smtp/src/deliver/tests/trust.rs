//! Волна smtp-30: матрица доверия в SMTP (SMTP-50, решение 124) — тип абонента каждого письма, автоответ, MDN,
//! DSN, группы рассылки, автопересылка, сбой скрипта организации.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use tp_contracts::TenantId;
use tp_contracts::groups::GroupStore;
use tp_contracts::membership::NodeId;
use tp_contracts::queue::SubmitStatus;
use tp_contracts::sieve::{DeliveryRules, ReplyBody, RulesInput, RulesOutcome};
use tp_contracts::trust::{
    GroupPost, PeerKind, PerPeer, Toggle, TrustLevel, TrustMatrix, TrustPolicy,
};
use tp_testkit::{MemDeliveryLog, MemTrust};

use super::*;
use crate::authcheck::tests as fx;
use crate::groups::Groups;
use crate::tracking::Tracking;

/// Вызов правил: получатель и тип абонента с матрицей (без письма).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RuleCall {
    recipient: String,
    peer: PeerKind,
    matrix: TrustMatrix,
}

/// Правила, запоминающие контекст (тип абонента, матрица — SMTP-50) и отвечающие заданным итогом по получателю.
#[derive(Clone, Default)]
struct RecordingRules {
    state: Arc<Mutex<RulesState>>,
}

#[derive(Default)]
struct RulesState {
    calls: Vec<RuleCall>,
    outcomes: Vec<(String, RulesOutcome)>,
}

impl RecordingRules {
    fn new() -> Self {
        Self::default()
    }

    /// Итог `outcome` для получателя `recipient` (как [`RulesInput::recipient`]).
    fn set(&self, recipient: &str, outcome: RulesOutcome) {
        self.state
            .lock()
            .expect("lock")
            .outcomes
            .push((recipient.into(), outcome));
    }

    /// Вызовы по порядку.
    fn calls(&self) -> Vec<RuleCall> {
        self.state.lock().expect("lock").calls.clone()
    }
}

#[async_trait]
impl DeliveryRules for RecordingRules {
    async fn evaluate(&self, input: &RulesInput) -> Result<RulesOutcome> {
        let mut st = self.state.lock().expect("lock");
        st.calls.push(RuleCall {
            recipient: input.recipient.clone(),
            peer: input.peer,
            matrix: input.matrix,
        });
        Ok(st
            .outcomes
            .iter()
            .rev()
            .find(|(r, _)| r == &input.recipient)
            .map(|(_, o)| o.clone())
            .unwrap_or_else(RulesOutcome::implicit_keep))
    }
}

/// Доставка с правилами [`RecordingRules`] и журналом доставки.
async fn ruled(outbound: bool) -> (Env, RecordingRules, MemDeliveryLog, Delivery) {
    let env = Env::new(DecisionHooks::default()).await;
    let rules = RecordingRules::new();
    let log = MemDeliveryLog::new();
    let d = env
        .delivery(outbound)
        .with_rules(Arc::new(rules.clone()))
        .with_tracking(Tracking::new(
            Arc::new(log.clone()),
            NodeId::new("node-1").expect("node"),
        ));
    (env, rules, log, d)
}

/// Причины событий журнала доставки.
fn reasons(log: &MemDeliveryLog) -> Vec<String> {
    log.events().into_iter().filter_map(|e| e.reason).collect()
}

/// Политика организации с выключенным автоответом чужим.
async fn no_auto_reply() -> MemTrust {
    let trust = MemTrust::new().with_accepted(TenantId::DEFAULT, &["example.org".to_owned()]);
    let mut org = TrustPolicy::default();
    org.auto_reply.external = Some(Toggle::Off);
    org.auto_reply.partner = Some(Toggle::Off);
    org.auto_reply.neighbor = Some(Toggle::Off);
    org.group_post.external = Some(GroupPost::Open);
    trust
        .set_policy(TrustLevel::Org(TenantId::DEFAULT), &org)
        .await
        .expect("policy");
    trust
}

/// Отчёт о прочтении (RFC 8098 §3.1) от `from` с получателем `rcpt` в `Disposition-Notification-To`.
fn mdn(from: &str, rcpt: &str) -> Bytes {
    Bytes::from(format!(
        "From: {from}\r\nTo: {rcpt}\r\nSubject: Read: hello\r\n\
         Disposition-Notification-To: <{rcpt}>\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/report; report-type=disposition-notification; boundary=b\r\n\r\n\
         --b\r\nContent-Type: text/plain\r\n\r\nread\r\n\
         --b\r\nContent-Type: message/disposition-notification\r\n\r\n\
         Reporting-UA: mail.example\r\nFinal-Recipient: rfc822; {rcpt}\r\n\r\n--b--\r\n"
    ))
}

// ---------- Тип абонента каждого письма ----------

/// smtp-in: домен партнёра без DMARC — внешний; свой домен — внешний; чужие `Authentication-Results` тип не
/// меняют; submission — свой (приёмка SMTP-50).
#[tokio::test]
async fn smtp_in_peer_by_from_domain_and_dmarc() {
    let (env, rules, _log, mut d) = ruled(false).await;
    let check = fx::checker();
    fx::publish_sender(check.cache(), "none");
    d.deps.authcheck = Some(Arc::new(check));
    d = d.with_trust(Arc::new(
        trust(&["example.com"], GroupPost::Open, &[]).await,
    ));

    // Партнёр с пройденным DMARC (адрес в SPF домена) — партнёр.
    let partner = b"From: sender@example.com\r\nSubject: hi\r\n\r\nx\r\n";
    let mut e = fx::envelope("192.0.2.10:1000");
    e.rcpts = vec!["bob@example.org".into()];
    assert_eq!(d.data(&e, Bytes::from_static(partner)).await.code, 250);
    // Тот же домен без DMARC (адрес вне SPF) — внешний; подделка `Authentication-Results` чужого сервера
    // типа не меняет (RFC 8601 §5).
    let forged = b"From: sender@example.com\r\nSubject: hi\r\n\
         Authentication-Results: evil.net; dmarc=pass header.from=example.com\r\n\r\nx\r\n";
    let mut e = fx::envelope("203.0.113.5:1000");
    e.rcpts = vec!["bob@example.org".into()];
    assert_eq!(d.data(&e, Bytes::from_static(forged)).await.code, 250);
    // Свой домен письмом снаружи — внешний.
    let own = b"From: alice@example.org\r\nSubject: hi\r\n\r\nx\r\n";
    let mut e = fx::envelope("203.0.113.5:1000");
    e.rcpts = vec!["bob@example.org".into()];
    assert_eq!(d.data(&e, Bytes::from_static(own)).await.code, 250);
    // Submission со входом — свой.
    let mut e = envelope(Mode::Submission, &["bob@example.org"]);
    e.mail_from = "alice@example.org".into();
    e.principal = Some(tp_testkit::principal(
        TenantId::DEFAULT,
        "alice@example.org",
    ));
    assert_eq!(d.data(&e, Bytes::from_static(own)).await.code, 250);

    let peers: Vec<PeerKind> = rules.calls().into_iter().map(|c| c.peer).collect();
    assert_eq!(
        peers,
        [
            PeerKind::Partner,
            PeerKind::External,
            PeerKind::External,
            PeerKind::Own
        ]
    );
    // Матрица получателя — действующая: умолчания контракта с политикой организации (группы открыты,
    // без политик учётной записи).
    let mut matrix = TrustMatrix::default();
    matrix.group_post = PerPeer {
        own: GroupPost::Open,
        partner: GroupPost::Open,
        neighbor: GroupPost::Open,
        external: GroupPost::Open,
    };
    assert_eq!(rules.calls()[0].matrix, matrix);
    assert_eq!(env.inbox("bob@example.org").await.len(), 4);
}

// ---------- Автоответ ----------

fn vacation(to: &str) -> RulesOutcome {
    RulesOutcome {
        vacation: Some(AutoReply {
            to: to.into(),
            from: "bob@example.org".into(),
            subject: "Автоответ: hello".into(),
            body: ReplyBody::Text("В отпуске".into()),
            in_reply_to: None,
            references: Vec::new(),
        }),
        ..RulesOutcome::implicit_keep()
    }
}

/// Автоответ чужим — только при включённой клетке `auto_reply`; письмо в группу — без ответа участников
/// (приёмка SMTP-50, RFC 3834).
#[tokio::test]
async fn auto_reply_by_policy_and_mailing_group() {
    // Выключено политикой: ответа нет, событие журнала.
    let (env, rules, log, d) = ruled(true).await;
    let d = d.with_trust(Arc::new(no_auto_reply().await));
    rules.set("bob@example.org", vacation("sender@example.net"));
    let e = envelope(Mode::Inbound, &["bob@example.org"]);
    assert_eq!(d.data(&e, Bytes::from_static(MAIL)).await.code, 250);
    assert!(env.queue.0.lock().expect("lock").is_empty());
    assert!(
        reasons(&log)
            .iter()
            .any(|r| r == "sieve: auto-reply skipped: policy"),
        "{:?}",
        reasons(&log)
    );

    // Включено (умолчание) — ответ уходит; письмо в группу (группы открыты) — участники не отвечают.
    let (env, rules, log, d) = ruled(true).await;
    let d = d.with_trust(Arc::new(trust(&[], GroupPost::Open, &[]).await));
    rules.set("bob@example.org", vacation("sender@example.net"));
    rules.set("team@example.org", vacation("sender@example.net"));
    let e = envelope(Mode::Inbound, &["bob@example.org"]);
    assert_eq!(d.data(&e, Bytes::from_static(MAIL)).await.code, 250);
    let e = envelope(Mode::Inbound, &["team@example.org"]);
    assert_eq!(d.data(&e, Bytes::from_static(MAIL)).await.code, 250);
    let queued = env.queue.0.lock().expect("lock").clone();
    assert_eq!(queued.len(), 1, "{queued:?}");
    assert_eq!(queued[0].1, ["sender@example.net"]);
    // RFC 3834: конверт пустой, автоответ помечен.
    assert_eq!(queued[0].0, "");
    let reply = String::from_utf8_lossy(&queued[0].2);
    assert!(reply.contains("Auto-Submitted: auto-replied"), "{reply}");
    let why = reasons(&log);
    assert!(
        why.iter()
            .any(|r| r == "sieve: auto-reply skipped: mailing group"),
        "{why:?}"
    );
    // Группа раскрылась, все получили письмо (bob — и напрямую, и через группу).
    assert_eq!(env.inbox("alice@example.org").await.len(), 1);
    assert_eq!(env.inbox("bob@example.org").await.len(), 2);
    assert_eq!(env.inbox("carol@example.org").await.len(), 1);
}

// ---------- MDN ----------

/// Отчёт о прочтении из submission получателю с `mdn = Off` не отправляется: `250` клиенту, письмо в очередь не
/// попадает, событие журнала; своему — доставлен (приёмка SMTP-50, RFC 8098).
#[tokio::test]
async fn mdn_not_sent_where_policy_off() {
    let (env, _rules, log, d) = ruled(true).await;
    let mut e = envelope(Mode::Submission, &["bob@example.org", "x@example.net"]);
    e.mail_from = "alice@example.org".into();
    e.principal = Some(tp_testkit::principal(
        TenantId::DEFAULT,
        "alice@example.org",
    ));
    assert_eq!(
        d.data(&e, mdn("alice@example.org", "x@example.net"))
            .await
            .code,
        250
    );
    assert_eq!(env.inbox("bob@example.org").await.len(), 1);
    assert!(env.queue.0.lock().expect("lock").is_empty());
    assert!(
        reasons(&log)
            .iter()
            .any(|r| r == "MDN не отправлен: политика"),
        "{:?}",
        reasons(&log)
    );

    // Отправка вне сессии — то же: внешнему не в очереди, своему доставлен.
    let out = d
        .submit(
            TenantId::DEFAULT,
            None,
            None,
            "alice@example.org",
            &rcpts(&["bob@example.org", "y@example.net"]),
            mdn("alice@example.org", "y@example.net"),
        )
        .await
        .expect("submit");
    assert_eq!(
        out.rcpts,
        [
            ("bob@example.org".to_owned(), SubmitStatus::Delivered),
            ("y@example.net".to_owned(), SubmitStatus::Delivered),
        ]
    );
    assert_eq!(env.inbox("bob@example.org").await.len(), 2);
    assert!(env.queue.0.lock().expect("lock").is_empty());
}

// ---------- Группы рассылки ----------

/// Группа закрыта чужим по умолчанию (`550 5.7.1` на `RCPT`), своему — доставлено; `Moderated` — в очереди
/// модерации (приёмка SMTP-50).
#[tokio::test]
async fn group_post_closed_moderated_open() {
    let env = Env::new(DecisionHooks::default()).await;
    // Каталожная группа `team@example.org` — без записи GroupStore: действует умолчание матрицы.
    let closed = env.delivery(false);
    let e = envelope(Mode::Inbound, &[]);
    let r = closed.rcpt(&e, "team@example.org").await;
    assert_eq!((r.code, r.esc), (550, [5, 7, 1]), "чужим закрыто");

    // Своему (submission со входом, `From` вошедшего) — доставлено.
    let mut own_mail = envelope(Mode::Submission, &["team@example.org"]);
    own_mail.mail_from = "alice@example.org".into();
    own_mail.principal = Some(tp_testkit::principal(
        TenantId::DEFAULT,
        "alice@example.org",
    ));
    assert_eq!(
        closed.data(&own_mail, own("alice@example.org")).await.code,
        250
    );
    for login in ["alice@example.org", "bob@example.org", "carol@example.org"] {
        assert_eq!(env.inbox(login).await.len(), 1, "{login}");
    }

    // `Moderated` (группа с модератором) — письмо в очереди модерации.
    let moderated = env
        .delivery(false)
        .with_trust(Arc::new(trust(&[], GroupPost::Moderated, &[]).await))
        .with_groups(Groups::new(
            Arc::new(env.groups.clone()),
            Arc::new(env.blobs.clone()),
            Arc::new(env.index.clone()),
        ));
    let group = DistributionGroup {
        id: tp_contracts::GroupId::new(),
        tenant: TenantId::DEFAULT,
        name: "news".into(),
        address: Some("news@example.org".into()),
        external_id: None,
        members: vec![tp_contracts::groups::GroupMember::Account(
            env.scope("bob@example.org").await.account,
        )],
        senders: tp_contracts::groups::SenderRestriction::Anyone,
        moderators: vec![env.scope("carol@example.org").await.account],
        hidden_from_gal: false,
    };
    env.groups.put(group.clone()).await.expect("group");
    let e = envelope(Mode::Inbound, &[]);
    assert_eq!(moderated.rcpt(&e, "news@example.org").await.code, 250);
    let held = envelope(Mode::Inbound, &["news@example.org"]);
    assert_eq!(
        moderated.data(&held, Bytes::from_static(MAIL)).await.code,
        250
    );
    let queued = env
        .groups
        .held(TenantId::DEFAULT, Some(group.id), None, 10)
        .await
        .expect("held");
    assert_eq!(queued.len(), 1, "письмо ждёт модератора");
    // Модерация ничего не доставила: у bob только письмо своего отправителя из начала теста.
    assert_eq!(env.inbox("bob@example.org").await.len(), 1);

    // Открытая группа — как сейчас (каталожная группа раскрыта, письмо доставлено).
    let open = env
        .delivery(false)
        .with_trust(Arc::new(trust(&[], GroupPost::Open, &[]).await));
    let e = envelope(Mode::Inbound, &["team@example.org"]);
    assert_eq!(open.data(&e, Bytes::from_static(MAIL)).await.code, 250);
    assert_eq!(env.inbox("bob@example.org").await.len(), 2);
}

// ---------- DSN ----------

/// DSN внешнему отправителю — с общей диагностикой (код и общий текст, без причины узла); письмо в «Спаме» —
/// без DSN (приёмка SMTP-50, RFC 3464 §4.2, RFC 5321 §6.2).
#[tokio::test]
async fn dsn_plain_for_foreign_and_silent_for_junk() {
    let env = Env::new(DecisionHooks::default()).await;
    let d = env.delivery(true);
    let bob = env.scope("bob@example.org").await;
    // Ящик заполняется: следующее письмо — принятое и недоставленное, отправителю — уведомление на конверт.
    let fill = envelope(Mode::Inbound, &["bob@example.org"]);
    assert_eq!(d.data(&fill, Bytes::from_static(MAIL)).await.code, 250);
    // Лимит исчерпан (квота — в байтах): приём не отменяется — carol доставлено, bob — уведомление.
    env.quota.set_limit(bob, Some(0));
    let e = envelope(Mode::Inbound, &["bob@example.org", "carol@example.org"]);
    assert_eq!(d.data(&e, Bytes::from_static(MAIL)).await.code, 250);
    let queued = env.queue.0.lock().expect("lock").clone();
    assert_eq!(queued.len(), 1, "принятое и недоставленное — уведомление");
    let dsn = String::from_utf8_lossy(&queued[0].2).into_owned();
    assert!(dsn.contains("Status: 5.2.2"), "{dsn}");
    assert!(dsn.contains("delivery failed"), "{dsn}");
    assert!(
        !dsn.contains("mailbox full"),
        "общий текст без причины узла: {dsn}"
    );

    // Письмо в «Спаме» (DMARC reject не пройден) — уведомления нет (backscatter): недоставленное переполненным
    // ящиком письмо в карантине не уведомляется, доставленное — лежит в «Спаме».
    let check = fx::checker();
    fx::publish_sender(check.cache(), "reject");
    let mut d = env.delivery(true);
    d.deps.authcheck = Some(Arc::new(check));
    let spam = b"From: sender@example.com\r\nSubject: hello\r\n\r\nbody\r\n";
    let mut junk = fx::envelope("203.0.113.5:1000");
    junk.rcpts = vec!["bob@example.org".into(), "carol@example.org".into()];
    assert_eq!(d.data(&junk, Bytes::from_static(spam)).await.code, 250);
    let queued = env.queue.0.lock().expect("lock").clone();
    assert_eq!(queued.len(), 1, "письмо в карантине не уведомляется");
    assert_eq!(env.junk("carol@example.org").await, 1);
}

// ---------- Автопересылка ----------

/// `redirect` наружу при выключенной автопересылке — не в очереди, письмо в ящике; домен из
/// `auto_forward_domains` — в очереди (приёмка SMTP-50).
#[tokio::test]
async fn redirect_abroad_only_when_allowed() {
    // Закрыто (умолчание, хранилища нет): перенаправление не выполняется, письмо остаётся в ящике.
    let (env, rules, log, d) = ruled(true).await;
    rules.set(
        "bob@example.org",
        RulesOutcome {
            redirect: vec!["x@example.net".into()],
            ..RulesOutcome::default()
        },
    );
    let e = envelope(Mode::Inbound, &["bob@example.org"]);
    assert_eq!(d.data(&e, Bytes::from_static(MAIL)).await.code, 250);
    assert!(env.queue.0.lock().expect("lock").is_empty());
    assert_eq!(
        env.inbox("bob@example.org").await.len(),
        1,
        "письмо в ящике"
    );
    assert!(
        reasons(&log)
            .iter()
            .any(|r| r == "sieve: redirect skipped by policy: x@example.net"),
        "{:?}",
        reasons(&log)
    );

    // Домен из `auto_forward_domains` — в очереди.
    let (env, rules, _log, d) = ruled(true).await;
    let d = d.with_trust(Arc::new(
        trust(&[], GroupPost::Closed, &["forward.example"]).await,
    ));
    rules.set(
        "bob@example.org",
        RulesOutcome {
            redirect: vec!["x@forward.example".into()],
            ..RulesOutcome::default()
        },
    );
    let e = envelope(Mode::Inbound, &["bob@example.org"]);
    assert_eq!(d.data(&e, Bytes::from_static(MAIL)).await.code, 250);
    let queued = env.queue.0.lock().expect("lock").clone();
    assert_eq!(queued.len(), 1, "{queued:?}");
    assert_eq!(queued[0].1, ["x@forward.example"]);
    assert!(env.inbox("bob@example.org").await.is_empty(), "без копии");
}

// ---------- Сбой скрипта организации ----------

/// Сбой скрипта организации (SIEVE-14): smtp-in — `451 4.3.0`, письмо не доставляется; [`Delivery::submit`] —
/// `SubmitStatus::Failed` с тем же кодом; сбой скрипта пользователя — во «Входящие» (приёмка SMTP-50).
#[tokio::test]
async fn org_script_failure_is_temporary_refusal() {
    let (env, rules, _log, d) = ruled(false).await;
    rules.set(
        "bob@example.org",
        RulesOutcome::failed("скрипт организации: line 3: limit exceeded"),
    );
    let e = envelope(Mode::Inbound, &["bob@example.org"]);
    let r = d.data(&e, Bytes::from_static(MAIL)).await;
    assert_eq!((r.code, r.esc), (451, [4, 3, 0]), "{r:?}");
    assert!(env.inbox("bob@example.org").await.is_empty());

    // Отправка вне сессии — статус Failed с тем же кодом, без уведомления.
    let d = env.delivery(true).with_rules(Arc::new(rules.clone()));
    let out = d
        .submit(
            TenantId::DEFAULT,
            None,
            None,
            "alice@example.org",
            &rcpts(&["bob@example.org"]),
            Bytes::from_static(OWN),
        )
        .await
        .expect("submit");
    assert_eq!(
        out.rcpts,
        [(
            "bob@example.org".to_owned(),
            SubmitStatus::Failed("451 4.3.0 sieve organization script failed".into())
        )]
    );
    assert!(env.inbox("bob@example.org").await.is_empty());
    assert!(env.queue.0.lock().expect("lock").is_empty());

    // Сбой скрипта пользователя — как сейчас: во «Входящие» с записью в журнал.
    rules.set(
        "bob@example.org",
        RulesOutcome::failed("скрипт пользователя: line 1: unknown command"),
    );
    let e = envelope(Mode::Inbound, &["bob@example.org"]);
    assert_eq!(d.data(&e, Bytes::from_static(MAIL)).await.code, 250);
    assert_eq!(env.inbox("bob@example.org").await.len(), 1);
}
