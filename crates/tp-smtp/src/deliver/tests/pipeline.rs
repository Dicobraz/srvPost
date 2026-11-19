//! Волна smtp-33: реестр этапов конвейера в доставке и итоговый контроль действий (SMTP-54, CTR-96) —
//! порядок этапов ядра по контракту, отказ модульного этапа на `RCPT TO` — одному получателю, на `DATA` —
//! всему письму, этапы модулей до и после Sieve ящика, `forbid_external_forward` перехватывает `redirect`
//! из скрипта ящика и пересылку копии наружу, без политики поведение прежнее.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tp_contracts::membership::NodeId;
use tp_contracts::pipeline::{
    OrgPolicy, PipelinePoint, Stage, StageInput, StageKind, StageVerdict, core_stage,
};
use tp_contracts::sieve::RulesOutcome;
use tp_contracts::trust::GroupPost;
use tp_testkit::{FakeRules, MemDeliveryLog, RecordingDecisionHook};

use super::*;
use crate::tracking::Tracking;

/// Этап-зонд: фиксирует вызовы (получатель или `-`), возвращает заданный вердикт.
struct Probe {
    id: String,
    point: PipelinePoint,
    verdict: StageVerdict,
    calls: Mutex<Vec<String>>,
    /// Итоговые действия вызовов с точек после Sieve: получатель и адреса перенаправлений.
    actions: Mutex<Vec<(String, Vec<String>)>>,
}

impl Probe {
    fn allow(id: &str, point: PipelinePoint) -> Arc<Self> {
        Arc::new(Self {
            id: id.into(),
            point,
            verdict: StageVerdict::Allow,
            calls: Mutex::new(Vec::new()),
            actions: Mutex::new(Vec::new()),
        })
    }

    fn reject(id: &str, point: PipelinePoint, reason: &str) -> Arc<Self> {
        Arc::new(Self {
            id: id.into(),
            point,
            verdict: StageVerdict::Reject(reason.into()),
            calls: Mutex::new(Vec::new()),
            actions: Mutex::new(Vec::new()),
        })
    }

    fn reject_recipient(id: &str, rcpt: &str) -> Arc<Self> {
        Arc::new(Self {
            id: id.into(),
            point: PipelinePoint::RcptTo,
            verdict: StageVerdict::RejectRecipient {
                rcpt: rcpt.into(),
                reason: "suite".into(),
            },
            calls: Mutex::new(Vec::new()),
            actions: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("lock").clone()
    }

    /// Итоговые действия по получателям (вызовы с итоговым набором действий).
    fn actions(&self) -> Vec<(String, Vec<String>)> {
        self.actions.lock().expect("lock").clone()
    }
}

#[async_trait]
impl Stage for Probe {
    fn id(&self) -> &str {
        &self.id
    }

    fn point(&self) -> PipelinePoint {
        self.point
    }

    fn order(&self) -> i32 {
        0
    }

    fn kind(&self) -> StageKind {
        StageKind::Rules
    }

    async fn run(&self, input: &StageInput) -> tp_contracts::Result<StageVerdict> {
        self.calls
            .lock()
            .expect("lock")
            .push(input.rcpt.clone().unwrap_or_else(|| "-".into()));
        if let (Some(rcpt), Some(a)) = (&input.rcpt, &input.actions) {
            self.actions
                .lock()
                .expect("lock")
                .push((rcpt.clone(), a.redirect.clone()));
        }
        match &self.verdict {
            StageVerdict::RejectRecipient { rcpt, .. } if input.rcpt.as_deref() != Some(rcpt) => {
                Ok(StageVerdict::Allow)
            }
            v => Ok(v.clone()),
        }
    }
}

/// Письмо с темой `tag`.
fn letter(tag: &str) -> Bytes {
    Bytes::from(format!(
        "From: sender@example.net\r\nTo: alice@example.org\r\nSubject: {tag}\r\nMessage-ID: <{tag}@example.net>\r\n\r\nbody\r\n"
    ))
}

/// Доставка с правилами Sieve `rules`, перенаправление наружу разрешено матрицей доверия
/// (`auto_forward_domains`: `external.example`), журнал доставки `log`.
async fn forwarding(
    env: &Env,
    rules: &FakeRules,
    log: &MemDeliveryLog,
    policy: Option<OrgPolicy>,
) -> Delivery {
    let mut d = env
        .delivery(true)
        .with_rules(Arc::new(rules.clone()))
        .with_trust(Arc::new(
            trust(&[], GroupPost::Open, &["external.example"]).await,
        ))
        .with_tracking(Tracking::new(
            Arc::new(log.clone()),
            NodeId::new("node-1").expect("node"),
        ));
    if let Some(p) = policy {
        d = d.with_org_policy(p);
    }
    d
}

/// Скрипт ящика alice: перенаправление на `to` без копии в ящике.
fn redirect_rule(rules: &FakeRules, to: &str) {
    rules.set(
        "alice@example.org",
        RulesOutcome {
            redirect: vec![to.to_owned()],
            ..RulesOutcome::default()
        },
    );
}

/// Причины событий журнала доставки.
fn reasons(log: &MemDeliveryLog) -> Vec<String> {
    log.events().into_iter().filter_map(|e| e.reason).collect()
}

/// Этапы ядра — в порядке точек контракта CTR-96 (SRS 4.9): проверки сессии, Milter, журналирование
/// (до Sieve), Sieve ящика (последний этап точки), итоговый контроль.
#[tokio::test]
async fn core_stages_in_contract_order() {
    let env = Env::new(DecisionHooks::default()).await;
    let d = env.delivery(false);
    let stages = d.pipeline().stages();
    let ids: Vec<(PipelinePoint, &str)> = stages.iter().map(|s| (s.point(), s.id())).collect();
    assert_eq!(
        ids,
        vec![
            (PipelinePoint::MailFrom, core_stage::SESSION_MAIL_FROM),
            (PipelinePoint::RcptTo, core_stage::SESSION_RCPT),
            (PipelinePoint::Data, core_stage::MILTER),
            (PipelinePoint::BeforeMailboxSieve, core_stage::JOURNAL),
            (PipelinePoint::BeforeMailboxSieve, core_stage::SIEVE),
            (PipelinePoint::FinalActionCheck, core_stage::FINAL),
        ],
        "этапы ядра в порядке контракта"
    );
    // Модульный этап встаёт между журналированием и Sieve (точка расширения SRS 2.5, SRS 4.10).
    let d = d.with_stage(
        PipelinePoint::BeforeMailboxSieve,
        Probe::allow("mod.pre", PipelinePoint::BeforeMailboxSieve),
    );
    let at = |d: &Delivery, p: PipelinePoint| {
        d.pipeline()
            .stages_at(p)
            .into_iter()
            .map(|s| s.id().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        at(&d, PipelinePoint::BeforeMailboxSieve),
        vec![core_stage::JOURNAL, "mod.pre", core_stage::SIEVE]
    );
}

/// Отказ модульного этапа на `RCPT TO` относится к одному получателю; проверки ядра не задеты.
#[tokio::test]
async fn rcpt_stage_refuses_single_recipient() {
    let env = Env::new(DecisionHooks::default()).await;
    let deny = Probe::reject_recipient("mod.rcpt-deny", "bob@example.org");
    let d = env
        .delivery(true)
        .with_stage(PipelinePoint::RcptTo, deny.clone());
    let e = envelope(Mode::Inbound, &[]);
    assert_eq!(d.rcpt(&e, "bob@example.org").await.code, 550);
    assert_eq!(d.rcpt(&e, "alice@example.org").await.code, 250);
    // Неизвестный адрес по-прежнему отклоняется ядром (SRS 4.1), этап не вызван.
    assert_eq!(d.rcpt(&e, "nobody@example.org").await.code, 550);
    assert_eq!(deny.calls(), vec!["bob@example.org", "alice@example.org"]);
}

/// Отказ модульного этапа на `MAIL FROM` и `DATA` — всему письму, синхронно в сессии (SRS 2.6).
#[tokio::test]
async fn mail_from_and_data_stages_reject_message() {
    let env = Env::new(DecisionHooks::default()).await;
    let d = env
        .delivery(true)
        .with_stage(
            PipelinePoint::MailFrom,
            Probe::reject("mod.from", PipelinePoint::MailFrom, "bad sender"),
        )
        .with_stage(
            PipelinePoint::Data,
            Probe::reject("mod.data", PipelinePoint::Data, "bad content"),
        );
    let e = envelope(Mode::Inbound, &["alice@example.org"]);
    let r = d.sender(&e).await.expect("отказ на MAIL FROM");
    assert_eq!((r.code, r.esc), (550, [5, 7, 1]));
    assert!(r.message.contains("bad sender"));
    // Без этапа на MAIL FROM письмо доходит до точки Data и отклоняется там.
    let d2 = env.delivery(true).with_stage(
        PipelinePoint::Data,
        Probe::reject("mod.data", PipelinePoint::Data, "bad content"),
    );
    let e = envelope(Mode::Inbound, &["alice@example.org"]);
    let r = d2.data(&e, letter("m1")).await;
    assert_eq!(r.code, 550);
    assert!(r.message.contains("bad content"));
    assert!(env.inbox("alice@example.org").await.is_empty());
}

/// Модульные этапы до и после Sieve ящика вызываются по каждому локальному получателю; после Sieve видят
/// итоговый набор действий — адреса `redirect` из скрипта ящика.
#[tokio::test]
async fn module_stages_run_around_mailbox_sieve() {
    let env = Env::new(DecisionHooks::default()).await;
    let rules = FakeRules::new();
    redirect_rule(&rules, "keeper@example.org");
    let log = MemDeliveryLog::new();
    let before = Probe::allow("mod.pre", PipelinePoint::BeforeMailboxSieve);
    let after = Probe::allow("mod.post", PipelinePoint::AfterMailboxSieve);
    let d = forwarding(&env, &rules, &log, None)
        .await
        .with_stage(PipelinePoint::BeforeMailboxSieve, before.clone())
        .with_stage(PipelinePoint::AfterMailboxSieve, after.clone());
    let e = envelope(Mode::Inbound, &["alice@example.org", "bob@example.org"]);
    assert_eq!(d.data(&e, letter("m1")).await.code, 250);
    assert_eq!(before.calls(), vec!["alice@example.org", "bob@example.org"]);
    assert_eq!(after.calls(), vec!["alice@example.org", "bob@example.org"]);
    assert!(after.actions().contains(&(
        "alice@example.org".to_owned(),
        vec!["keeper@example.org".to_owned()]
    )));
    assert!(
        after
            .actions()
            .contains(&("bob@example.org".to_owned(), Vec::new()))
    );
}

/// `forbid_external_forward`: `redirect` из скрипта ящика наружу (разрешён матрицей автопересылки) —
/// отказ письму в сессии, ничего не доставлено и не поставлено в очередь, причина — в журнале доставки.
#[tokio::test]
async fn forbid_external_forward_rejects_sieve_redirect() {
    let env = Env::new(DecisionHooks::default()).await;
    let rules = FakeRules::new();
    redirect_rule(&rules, "evil@external.example");
    let log = MemDeliveryLog::new();
    let d = forwarding(
        &env,
        &rules,
        &log,
        Some(OrgPolicy {
            forbid_external_forward: true,
        }),
    )
    .await;
    let e = envelope(Mode::Inbound, &["alice@example.org"]);
    let r = d.data(&e, letter("m1")).await;
    assert_eq!(r.code, 550, "перенаправление наружу при запрете — отказ");
    assert!(r.message.contains("evil@external.example"), "{}", r.message);
    assert!(env.inbox("alice@example.org").await.is_empty());
    assert!(
        env.queue.0.lock().expect("lock").is_empty(),
        "в очередь ничего не попало"
    );
    assert!(
        reasons(&log)
            .iter()
            .any(|x| x.contains("external forwarding is forbidden: evil@external.example")),
        "причина — в журнале доставки: {:?}",
        reasons(&log)
    );

    // Отправка вне сессии (JMAP EmailSubmission): скрипт получателя перенаправляет наружу — все
    // получатели Failed с той же причиной, письмо не доставлено.
    rules.set(
        "bob@example.org",
        RulesOutcome {
            redirect: vec!["evil@external.example".to_owned()],
            ..RulesOutcome::default()
        },
    );
    let out = d
        .submit(
            TenantId::DEFAULT,
            None,
            None,
            "alice@example.org",
            &["bob@example.org".into()],
            letter("m2"),
        )
        .await
        .expect("submit");
    assert!(out.rcpts.iter().all(|(_, s)| matches!(
        s,
        SubmitStatus::Failed(line) if line.contains("evil@external.example")
    )));
    assert!(env.inbox("bob@example.org").await.is_empty());
}

/// Тот же запрет перехватывает пересылку копии наружу (точка принятия решений submission,
/// `CopyTo::Address`): письмо отклонено на `DATA`, ничего не доставлено и не поставлено в очередь.
#[tokio::test]
async fn forbid_external_forward_rejects_module_copy() {
    let hook = RecordingDecisionHook::new("copy");
    hook.set_submission(Decision::Augment(Augment {
        headers: Vec::new(),
        copies: vec![CopyTo::Address("evil@external.example".into())],
    }));
    let env = Env::new(DecisionHooks::default()).await;
    let log = MemDeliveryLog::new();
    let mut d = forwarding(
        &env,
        &FakeRules::new(),
        &log,
        Some(OrgPolicy {
            forbid_external_forward: true,
        }),
    )
    .await;
    d.deps.hooks = DecisionHooks::new(vec![Arc::new(hook)]);
    let mut e = envelope(Mode::Submission, &["bob@example.org"]);
    e.mail_from = "alice@example.org".into();
    e.principal = Some(tp_testkit::principal(
        TenantId::DEFAULT,
        "alice@example.org",
    ));
    let raw = Bytes::from(
        "From: alice@example.org\r\nTo: bob@example.org\r\nSubject: copy\r\n\r\nbody\r\n",
    );
    let r = d.data(&e, raw).await;
    assert_eq!(r.code, 550, "копия наружу при запрете — отказ");
    assert!(r.message.contains("evil@external.example"), "{}", r.message);
    assert!(env.inbox("bob@example.org").await.is_empty());
    assert!(env.queue.0.lock().expect("lock").is_empty());
}

/// Без политики поведение прежнее: перенаправление наружу (разрешённое матрицей) выполняется, копия на
/// внешний адрес уходит в очередь, письмо доставляется.
#[tokio::test]
async fn without_policy_redirect_and_copy_pass() {
    let env = Env::new(DecisionHooks::default()).await;
    let rules = FakeRules::new();
    redirect_rule(&rules, "keeper@external.example");
    let log = MemDeliveryLog::new();
    let d = forwarding(&env, &rules, &log, None).await;
    let e = envelope(Mode::Inbound, &["alice@example.org"]);
    assert_eq!(d.data(&e, letter("m1")).await.code, 250);
    let queued = env.queue.0.lock().expect("lock").clone();
    assert!(
        queued
            .iter()
            .any(|(_, rcpts, _)| rcpts.iter().any(|r| r == "keeper@external.example")),
        "перенаправление наружу — в очередь: {queued:?}"
    );
    // Внутреннее перенаправление при включённом запрете — не нарушение (домен организации).
    let rules = FakeRules::new();
    redirect_rule(&rules, "bob@example.org");
    let d = forwarding(
        &env,
        &rules,
        &log,
        Some(OrgPolicy {
            forbid_external_forward: true,
        }),
    )
    .await;
    let e = envelope(Mode::Inbound, &["alice@example.org"]);
    assert_eq!(d.data(&e, letter("m2")).await.code, 250);
    assert_eq!(env.inbox("bob@example.org").await.len(), 1);
}
