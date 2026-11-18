//! Набор проверок конвейера обработки (CTR-96; CONTRACTS.md#Pipeline; SRS 4.9).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tp_contracts::Error;
use tp_contracts::ids::TenantId;
use tp_contracts::pipeline::{
    ActionSet, OrgPolicy, PipelinePoint, Stage, StageInput, StageKind, StageRegistry, StageVerdict,
    SystemMessage, core_stage,
};
use tp_contracts::transport::FlowDirection;

use crate::infra::lock;

/// Этап-зонд: фиксирует вызовы (получатель или `""`), возвращает заданный вердикт.
struct Probe {
    id: String,
    point: PipelinePoint,
    order: i32,
    kind: StageKind,
    verdict: StageVerdict,
    calls: Mutex<Vec<String>>,
}

impl Probe {
    fn new(
        id: &str,
        point: PipelinePoint,
        order: i32,
        kind: StageKind,
        verdict: StageVerdict,
    ) -> Arc<Self> {
        Arc::new(Probe {
            id: id.to_owned(),
            point,
            order,
            kind,
            verdict,
            calls: Mutex::new(Vec::new()),
        })
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
        self.order
    }

    fn kind(&self) -> StageKind {
        self.kind
    }

    async fn run(&self, input: &StageInput) -> tp_contracts::Result<StageVerdict> {
        lock(&self.calls).push(input.rcpt.clone().unwrap_or_else(|| "-".to_owned()));
        Ok(self.verdict.clone())
    }
}

/// Итоговый контроль действий: этап ядра точки `FinalActionCheck` — применяет [`OrgPolicy`] к
/// [`ActionSet`] из скрипта ящика.
struct FinalCheck {
    policy: OrgPolicy,
    org_domains: Vec<String>,
}

#[async_trait]
impl Stage for FinalCheck {
    fn id(&self) -> &str {
        core_stage::FINAL
    }

    fn point(&self) -> PipelinePoint {
        PipelinePoint::FinalActionCheck
    }

    fn order(&self) -> i32 {
        0
    }

    fn kind(&self) -> StageKind {
        StageKind::Rules
    }

    async fn run(&self, input: &StageInput) -> tp_contracts::Result<StageVerdict> {
        let Some(actions) = &input.actions else {
            return Ok(StageVerdict::Allow);
        };
        let denied = self.policy.check(actions, &self.org_domains);
        if denied.is_empty() {
            Ok(StageVerdict::Allow)
        } else {
            Ok(StageVerdict::Reject(format!(
                "external forwarding is forbidden: {}",
                denied.join(", ")
            )))
        }
    }
}

/// Набор проверок конвейера обработки (CTR-96): этапы в порядке точек; модульный этап — до и после Sieve;
/// этап ядра нельзя удалить или переставить; отказ на `RcptTo` относится к одному получателю;
/// `FinalActionCheck` видит `redirect` из скрипта ящика и применяет `forbid_external_forward`;
/// служебное письмо (`SystemMessage`) не проходит этапы правил.
pub async fn pipeline() {
    let tenant = TenantId::new();
    let mut reg = StageRegistry::default();

    // Ядро: проверки сессии, Milter, журналирование (до Sieve и модулей), Sieve, итоговый контроль.
    let session_from = Probe::new(
        core_stage::SESSION_MAIL_FROM,
        PipelinePoint::MailFrom,
        0,
        StageKind::Check,
        StageVerdict::Allow,
    );
    reg.register_core(session_from).expect("core mail-from");
    let session = Probe::new(
        core_stage::SESSION_RCPT,
        PipelinePoint::RcptTo,
        0,
        StageKind::Check,
        StageVerdict::Allow,
    );
    let journal = Probe::new(
        core_stage::JOURNAL,
        PipelinePoint::BeforeMailboxSieve,
        tp_contracts::pipeline::ORDER_FIRST,
        StageKind::Rules,
        StageVerdict::Allow,
    );
    reg.register_core(session.clone()).expect("core session");
    reg.register_core(journal.clone()).expect("core journal");
    reg.register_core(Probe::new(
        core_stage::SIEVE,
        PipelinePoint::BeforeMailboxSieve,
        tp_contracts::pipeline::ORDER_LAST,
        StageKind::Rules,
        StageVerdict::Allow,
    ))
    .expect("core sieve");
    reg.register_core(Probe::new(
        core_stage::MILTER,
        PipelinePoint::Data,
        0,
        StageKind::Check,
        StageVerdict::Allow,
    ))
    .expect("core milter");
    let policy = OrgPolicy {
        forbid_external_forward: true,
    };
    reg.register_core(Arc::new(FinalCheck {
        policy,
        org_domains: vec!["internal.example".to_owned()],
    }))
    .expect("core final");

    // Модульные этапы до и после Sieve; порядок точек — по PipelinePoint::ALL.
    let before_sieve = Probe::new(
        "mod.pre",
        PipelinePoint::BeforeMailboxSieve,
        0,
        StageKind::Rules,
        StageVerdict::Allow,
    );
    let after_sieve = Probe::new(
        "mod.post",
        PipelinePoint::AfterMailboxSieve,
        0,
        StageKind::Rules,
        StageVerdict::Allow,
    );
    reg.register(PipelinePoint::BeforeMailboxSieve, before_sieve.clone())
        .expect("module before");
    reg.register(PipelinePoint::AfterMailboxSieve, after_sieve.clone())
        .expect("module after");
    let ids = |reg: &StageRegistry, p: PipelinePoint| {
        reg.stages_at(p)
            .into_iter()
            .map(|s| s.id().to_owned())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ids(&reg, PipelinePoint::BeforeMailboxSieve),
        vec![core_stage::JOURNAL, "mod.pre", core_stage::SIEVE],
        "журналирование до модульных этапов и Sieve"
    );
    assert_eq!(
        ids(&reg, PipelinePoint::AfterMailboxSieve),
        vec!["mod.post"]
    );
    let points = |reg: &StageRegistry| -> Vec<PipelinePoint> {
        reg.stages().iter().map(|s| s.point()).collect()
    };
    assert!(
        points(&reg).windows(2).all(|w| w[0] <= w[1]),
        "этапы в порядке точек: {:?}",
        points(&reg)
    );
    for point in PipelinePoint::ALL {
        assert!(points(&reg).contains(&point), "точка {point:?} без этапов");
    }

    // Этап ядра нельзя удалить или переставить; модульный — можно.
    assert!(matches!(
        reg.remove(core_stage::SIEVE),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        reg.set_order(core_stage::JOURNAL, 7),
        Err(Error::Invalid(_))
    ));
    assert_eq!(reg.remove("absent"), Err(Error::NotFound));
    assert_eq!(reg.stage("absent"), None);
    reg.set_order("mod.pre", 100).expect("свой порядок");
    assert_eq!(
        ids(&reg, PipelinePoint::BeforeMailboxSieve),
        vec![core_stage::JOURNAL, core_stage::SIEVE, "mod.pre"],
        "порядок модульного этапа изменился, ядро на месте"
    );
    reg.set_order("mod.pre", 0).expect("вернуть порядок");

    // Отказ на RcptTo относится к одному получателю.
    let rcpt_input = |rcpt: &str| {
        StageInput::envelope(
            tenant,
            FlowDirection::Inbound,
            "a@ext.example",
            Some(rcpt),
            None,
        )
    };
    assert_eq!(
        reg.run(PipelinePoint::RcptTo, &rcpt_input("anna@internal.example"))
            .await
            .expect("rcpt anna"),
        StageVerdict::Allow
    );
    let deny = Arc::new(Probe::new(
        "mod.rcpt-deny",
        PipelinePoint::RcptTo,
        0,
        StageKind::Rules,
        StageVerdict::RejectRecipient {
            rcpt: "bob@internal.example".to_owned(),
            reason: "suite".to_owned(),
        },
    ));
    reg.register(PipelinePoint::RcptTo, deny.clone())
        .expect("deny");
    assert_eq!(
        reg.run(PipelinePoint::RcptTo, &rcpt_input("bob@internal.example"))
            .await
            .expect("rcpt bob"),
        StageVerdict::RejectRecipient {
            rcpt: "bob@internal.example".to_owned(),
            reason: "suite".to_owned()
        },
        "отказ — одному получателю"
    );
    assert_eq!(
        reg.run(PipelinePoint::RcptTo, &rcpt_input("anna@internal.example"))
            .await
            .expect("rcpt anna again"),
        StageVerdict::Allow,
        "другого получателя отказ не задел"
    );
    assert_eq!(
        lock(&deny.calls).len(),
        2,
        "этап вызван для каждого получателя"
    );
    // Отказ получателю вне RcptTo недопустим.
    let data_rcpt = Arc::new(Probe::new(
        "mod.rcpt-at-data",
        PipelinePoint::Data,
        0,
        StageKind::Rules,
        StageVerdict::RejectRecipient {
            rcpt: "bob@internal.example".to_owned(),
            reason: "suite".to_owned(),
        },
    ));
    reg.register(PipelinePoint::Data, data_rcpt)
        .expect("rcpt@data");
    assert!(matches!(
        reg.run(
            PipelinePoint::Data,
            &StageInput::envelope(tenant, FlowDirection::Inbound, "a@ext.example", None, None)
        )
        .await,
        Err(Error::Invalid(_))
    ));
    reg.remove("mod.rcpt-at-data").expect("убрали этап");
    // Отказ всему письму в той же SMTP-сессии.
    let reject = Arc::new(Probe::new(
        "mod.reject",
        PipelinePoint::Data,
        0,
        StageKind::Rules,
        StageVerdict::Reject("suite: content".to_owned()),
    ));
    reg.register(PipelinePoint::Data, reject).expect("reject");
    assert_eq!(
        reg.run(
            PipelinePoint::Data,
            &StageInput::envelope(tenant, FlowDirection::Inbound, "a@ext.example", None, None)
        )
        .await
        .expect("data"),
        StageVerdict::Reject("suite: content".to_owned())
    );

    // FinalActionCheck видит redirect из скрипта ящика и применяет forbid_external_forward.
    let actions = |redirect: &[&str]| StageInput {
        tenant,
        flow: FlowDirection::Inbound,
        mail_from: "a@ext.example".to_owned(),
        rcpt: Some("anna@internal.example".to_owned()),
        message: Some(bytes::Bytes::from_static(
            b"From: a@ext.example\r\n\r\nbody",
        )),
        actions: Some(ActionSet {
            redirect: redirect.iter().map(|s| s.to_string()).collect(),
            copies: Vec::new(),
            recipients: vec!["anna@internal.example".to_owned()],
        }),
        system: None,
    };
    assert_eq!(
        reg.run(
            PipelinePoint::FinalActionCheck,
            &actions(&["evil@ext.example"])
        )
        .await
        .expect("final deny"),
        StageVerdict::Reject("external forwarding is forbidden: evil@ext.example".to_owned()),
        "redirect из скрипта ящика перехвачен"
    );
    assert_eq!(
        reg.run(
            PipelinePoint::FinalActionCheck,
            &actions(&["keeper@internal.example"])
        )
        .await
        .expect("final allow"),
        StageVerdict::Allow
    );

    // Служебные письма (в том числе копия журнала) не проходят этапы правил.
    lock(&journal.calls).clear();
    lock(&before_sieve.calls).clear();
    lock(&after_sieve.calls).clear();
    for system in [SystemMessage::Dsn, SystemMessage::JournalCopy] {
        let mut input = actions(&["evil@ext.example"]);
        input.system = Some(system);
        assert_eq!(
            reg.run(PipelinePoint::BeforeMailboxSieve, &input)
                .await
                .expect("before sieve"),
            StageVerdict::Allow
        );
        assert_eq!(
            reg.run(PipelinePoint::AfterMailboxSieve, &input)
                .await
                .expect("after sieve"),
            StageVerdict::Allow
        );
        // Итоговый контроль для служебного письма не блокирует доставку (внешние адресы DSN легальны).
        assert_eq!(
            reg.run(PipelinePoint::FinalActionCheck, &input)
                .await
                .expect("final"),
            StageVerdict::Allow,
            "служебное письмо минует этапы правил"
        );
    }
    assert!(
        lock(&journal.calls).is_empty() && lock(&before_sieve.calls).is_empty(),
        "копия журнала повторно не журналируется"
    );
    assert!(
        lock(&after_sieve.calls).is_empty(),
        "этапы правил после Sieve тоже пропущены"
    );
    // Этапы проверок (Check) для служебных писем выполняются.
    lock(&session.calls).clear();
    let mut input = actions(&[]);
    input.system = Some(SystemMessage::Dsn);
    assert_eq!(
        reg.run(PipelinePoint::RcptTo, &input).await.expect("rcpt"),
        StageVerdict::Allow
    );
    assert_eq!(lock(&session.calls).len(), 1, "проверки сессии — всегда");
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn suite_pipeline() {
        super::pipeline().await;
    }
}
