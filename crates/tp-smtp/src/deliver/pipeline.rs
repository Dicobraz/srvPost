//! Конвейер обработки в доставке — реестр этапов CTR-96 (SMTP-54; CONTRACTS.md#Pipeline; SRS 4.9, 2.5).
//!
//! Приём извне (smtp-in), отправка клиентом (submission, JMAP EmailSubmission —
//! [`super::Delivery::submit`]) и доставка в ящик проходят одни упорядоченные этапы: проверки сессии
//! (`MAIL`, `RCPT`), Milter (`DATA`), журналирование (SMTP-53), Sieve ящика, итоговый контроль
//! действий, доставка или постановка в очередь. [`StageRegistry`] фиксирует точки и порядок
//! контракта: этапы ядра — якоря (регистрирует [`super::Delivery::new`]), работу в фиксированной
//! точке выполняет сама доставка; модульные этапы добавляются [`super::Delivery::with_stage`] —
//! точка расширения SRS 2.5, задел под модуль «Правила потока почты» (SRS 4.10): этапы до и после
//! Sieve ящика. Отказ на `MailFrom`/`RcptTo` — по конверту (на `RcptTo` — отдельному получателю),
//! на `Data` — по содержимому, всему письму; входящая почта проходит точки до доставки в ящик,
//! исходящая — до постановки в очередь, синхронно в той же SMTP-сессии (edge передаёт насквозь,
//! SRS 2.6).
//!
//! Итоговый контроль действий ([`PipelinePoint::FinalActionCheck`], после Sieve и этапов модулей):
//! [`ActionSet`] — перенаправления из скрипта ящика, копии и итоговые адресаты — проверяется по
//! [`OrgPolicy::forbid_external_forward`] (запрет перенаправления и пересылки на внешние адреса,
//! по умолчанию выключен; перехватывает `redirect` из скрипта ящика): нарушение — отказ письму с
//! понятной причиной в журнале доставки. Служебные письма продукта ([`SystemMessage`]: DSN,
//! отбивки, копии журнала) этапы правил минуют — петли исключены (CTR-96).

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tp_contracts::Result;
use tp_contracts::pipeline::{
    ActionSet, ORDER_FIRST, ORDER_LAST, OrgPolicy, PipelinePoint, Stage, StageInput, StageKind,
    StageRegistry, StageVerdict, SystemMessage, core_stage,
};
use tp_contracts::transport::FlowDirection;

use super::{Delivery, clean, temporary};
use crate::server::{Envelope, Mode, Reply, is_positive, reply};

/// Якорь этапа ядра (SMTP-54): работу в фиксированной точке выполняет сама доставка — проверки сессии
/// ([`crate::server::Session`]), Milter, журналирование (SMTP-53), Sieve ящика, итоговый контроль
/// действий; якорь фиксирует идентификатор, точку, порядок и вид этапа контракта CTR-96 — модульный
/// этап не встаёт раньше журналирования и позже Sieve, этап ядра нельзя удалить или переставить.
struct Anchor {
    id: &'static str,
    point: PipelinePoint,
    order: i32,
    kind: StageKind,
}

#[async_trait]
impl Stage for Anchor {
    fn id(&self) -> &str {
        self.id
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

    async fn run(&self, _: &StageInput) -> Result<StageVerdict> {
        Ok(StageVerdict::Allow)
    }
}

/// Этапы ядра конвейера в порядке контракта (CTR-96): проверки сессии на `MAIL FROM` и `RCPT TO`,
/// Milter на `DATA`, журналирование (первый этап точки `BeforeMailboxSieve`, SMTP-53), Sieve ящика
/// (последний этап точки), итоговый контроль действий.
pub(super) fn core_registry() -> StageRegistry {
    let mut reg = StageRegistry::default();
    let anchor = |id, point, order, kind| {
        Arc::new(Anchor {
            id,
            point,
            order,
            kind,
        })
    };
    reg.register_core(anchor(
        core_stage::SESSION_MAIL_FROM,
        PipelinePoint::MailFrom,
        0,
        StageKind::Check,
    ))
    .expect("core stage ids are unique");
    reg.register_core(anchor(
        core_stage::SESSION_RCPT,
        PipelinePoint::RcptTo,
        0,
        StageKind::Check,
    ))
    .expect("core stage ids are unique");
    reg.register_core(anchor(
        core_stage::MILTER,
        PipelinePoint::Data,
        0,
        StageKind::Check,
    ))
    .expect("core stage ids are unique");
    reg.register_core(anchor(
        core_stage::JOURNAL,
        PipelinePoint::BeforeMailboxSieve,
        ORDER_FIRST,
        StageKind::Rules,
    ))
    .expect("core stage ids are unique");
    reg.register_core(anchor(
        core_stage::SIEVE,
        PipelinePoint::BeforeMailboxSieve,
        ORDER_LAST,
        StageKind::Rules,
    ))
    .expect("core stage ids are unique");
    reg.register_core(anchor(
        core_stage::FINAL,
        PipelinePoint::FinalActionCheck,
        0,
        StageKind::Rules,
    ))
    .expect("core stage ids are unique");
    reg
}

/// Как письмо вошло в конвейер.
pub(super) fn flow_of(mode: Mode) -> FlowDirection {
    match mode {
        Mode::Inbound => FlowDirection::Inbound,
        Mode::Submission => FlowDirection::Submission,
    }
}

/// Служебное письмо продукта в конверте (CTR-96, SMTP-53): пустой отправитель — уведомление о
/// доставке (DSN); отчёт о прочтении (MDN, RFC 8098) — уведомление. Этапы правил его минуют.
pub(super) fn system_message(mail_from: &str, mdn: bool) -> Option<SystemMessage> {
    if mail_from.is_empty() {
        Some(SystemMessage::Dsn)
    } else if mdn {
        Some(SystemMessage::Notification)
    } else {
        None
    }
}

impl Delivery {
    /// Модульный этап конвейера обработки (SMTP-54, SRS 2.5): точка расширения для модулей — задел под
    /// «Правила потока почты» (SRS 4.10) с этапами до и после Sieve ящика. Порядок и защита этапов
    /// ядра — контракт CTR-96 ([`StageRegistry::register`]); конфликт идентификаторов или чужая точка —
    /// этап не регистрируется (запись в журнал узла).
    pub fn with_stage(mut self, point: PipelinePoint, stage: Arc<dyn Stage>) -> Self {
        if let Err(e) = self.pipeline.register(point, stage.clone()) {
            tracing::warn!(
                stage = stage.id(),
                ?point,
                error = %e,
                "smtp: модульный этап конвейера не зарегистрирован"
            );
        }
        self
    }

    /// Политика организации для итогового контроля действий (SMTP-54, точка `FinalActionCheck`):
    /// `forbid_external_forward` — запрет перенаправления и пересылки на внешние адреса, перехватывает
    /// `redirect` из скрипта ящика и пересылку копий наружу. По умолчанию выключен; хранение и
    /// Admin API — волны полос (задел под SRS 4.10 `block_external_forward`).
    pub fn with_org_policy(mut self, policy: OrgPolicy) -> Self {
        self.org_policy = policy;
        self
    }

    /// Реестр этапов конвейера (SMTP-54): этапы ядра в порядке контракта и модульные этапы.
    pub fn pipeline(&self) -> &StageRegistry {
        &self.pipeline
    }

    /// Точки конвейера по конверту (`MailFrom`, `RcptTo`; SMTP-54): модульные этапы задают условия по
    /// конверту; отказ — всему письму, на `RcptTo` — отдельному получателю (проверки сессии ядра уже
    /// отработали). Ошибка этапа — временный отказ.
    pub(super) async fn envelope_point(
        &self,
        point: PipelinePoint,
        env: &Envelope,
        rcpt: Option<&str>,
    ) -> Option<Reply> {
        let input = StageInput::envelope(
            self.deps.tenant,
            flow_of(env.mode),
            &env.mail_from,
            rcpt,
            system_message(&env.mail_from, false),
        );
        match self.pipeline.run(point, &input).await {
            Ok(StageVerdict::Reject(reason)) | Ok(StageVerdict::RejectRecipient { reason, .. }) => {
                Some(reply(550, [5, 7, 1], clean(&reason)))
            }
            Ok(StageVerdict::Allow) => None,
            Err(e) => Some(temporary(&e)),
        }
    }

    /// Точка `Data` (SMTP-54): модульные этапы задают условия по содержимому — отказ всему письму
    /// (Milter ядра уже отработал). Возвращает причину отказа.
    pub(super) async fn data_point(
        &self,
        flow: FlowDirection,
        mail_from: &str,
        message: &Bytes,
        system: Option<SystemMessage>,
    ) -> Result<Option<String>> {
        let input = StageInput {
            tenant: self.deps.tenant,
            flow,
            mail_from: mail_from.to_owned(),
            rcpt: None,
            message: Some(message.clone()),
            actions: None,
            system,
        };
        // `RejectRecipient` вне `RcptTo` — ошибка реестра (контракт), сюда не доходит.
        Ok(
            match self.pipeline.run(PipelinePoint::Data, &input).await? {
                StageVerdict::Reject(reason) | StageVerdict::RejectRecipient { reason, .. } => {
                    Some(reason)
                }
                StageVerdict::Allow => None,
            },
        )
    }

    /// Точки доставки по получателю (`BeforeMailboxSieve`, `AfterMailboxSieve`, `FinalActionCheck`;
    /// SMTP-54): модульные этапы видят письмо, после Sieve — и итоговый набор действий
    /// ([`StageInput::actions`]); отказ — всему письму, причина — для журнала доставки и ответа.
    /// Служебные письма этапы правил минуют ([`system`]).
    #[allow(clippy::too_many_arguments)] // конвенция репо (как у `forward` и `apply_rules`)
    pub(super) async fn delivery_point(
        &self,
        point: PipelinePoint,
        flow: FlowDirection,
        mail_from: &str,
        rcpt: &str,
        message: &Bytes,
        actions: Option<ActionSet>,
        system: Option<SystemMessage>,
    ) -> Result<Option<String>> {
        let input = StageInput {
            tenant: self.deps.tenant,
            flow,
            mail_from: mail_from.to_owned(),
            rcpt: Some(rcpt.to_owned()),
            message: Some(message.clone()),
            actions,
            system,
        };
        Ok(match self.pipeline.run(point, &input).await? {
            StageVerdict::Reject(reason) | StageVerdict::RejectRecipient { reason, .. } => {
                Some(reason)
            }
            StageVerdict::Allow => None,
        })
    }

    /// Итоговый контроль действий (SMTP-54, ядро точки `FinalActionCheck`): [`ActionSet`] по
    /// [`OrgPolicy`] — запрет внешней пересылки перехватывает `redirect` из скрипта ящика и пересылку
    /// копий наружу (домены организации — принятые домены организации узла). Нарушение — причина
    /// отказа (журнал доставки, SMTP-ответ); пусто — контроля пройден.
    pub(super) async fn final_action_check(&self, actions: &ActionSet) -> Result<Option<String>> {
        let denied = self.org_policy.check(actions, &self.org_domains().await?);
        Ok((!denied.is_empty())
            .then(|| format!("external forwarding is forbidden: {}", denied.join(", "))))
    }

    /// Домены организации узла (итоговый контроль, SMTP-54): принятые домены организации из снимка
    /// транспорта; без снимков — пусто (при включённом запрете внешним считается любой адрес).
    async fn org_domains(&self) -> Result<Vec<String>> {
        let Some(routes) = &self.transport else {
            return Ok(Vec::new());
        };
        Ok(routes
            .cluster()
            .await?
            .domains
            .iter()
            .filter(|d| d.tenant == self.deps.tenant)
            .map(|d| d.name.clone())
            .collect())
    }

    /// Точка `RcptTo` после проверок ядра (SMTP-54): модульные этапы по конверту; положительный ответ
    /// `core` остаётся, отказ этапа — получателю.
    pub(super) async fn rcpt_point(&self, env: &Envelope, rcpt: &str, core: Reply) -> Reply {
        if !is_positive(&core) {
            return core;
        }
        self.envelope_point(PipelinePoint::RcptTo, env, Some(rcpt))
            .await
            .unwrap_or(core)
    }
}
