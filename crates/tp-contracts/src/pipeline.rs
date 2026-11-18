//! Конвейер обработки письма (CONTRACTS.md#Pipeline; SRS 4.9, 2.5, 2.6; CTR-96).
//!
//! Каждое письмо проходит упорядоченные этапы, общие для приёма извне (smtp-in), отправки клиентом
//! (submission, JMAP EmailSubmission) и доставки в ящик. Конвейер выполняется ролью transport; узел edge
//! передаёт сессию насквозь (SRS 2.6), поэтому отказ возвращается отправителю синхронно в той же SMTP-сессии.
//! Ядро регистрирует собственные этапы ([`StageRegistry::register_core`]: проверки сессии, Milter,
//! журналирование, Sieve ящика, итоговый контроль), модули — через точку расширения
//! ([`crate::ext::Registry::add_stage`] → [`StageRegistry::register`]); этап ядра нельзя удалить или
//! переставить. Входящая почта проходит конвейер до доставки в ящик, исходящая — до постановки в очередь.
//!
//! Служебные письма продукта и копии журнала ([`SystemMessage`]) минуют этапы правил ([`StageKind::Rules`]) —
//! петли исключены, копия журнала повторно не журналируется.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::valid_address;
use crate::ids::TenantId;
use crate::transport::{FlowDirection, normalize_domain};

/// Наибольшая длина идентификатора этапа, байт.
pub const MAX_STAGE_ID_LEN: usize = 64;

/// Порядок этапа ядра, который выполняется в точке первым (журналирование — до Sieve ящика и этапов
/// модулей, SRS 4.9): модульный этап с меньшим порядком задать нельзя.
pub const ORDER_FIRST: i32 = i32::MIN;

/// Порядок этапа ядра, который выполняется в точке последним (Sieve ящика — последний этап точки
/// [`PipelinePoint::BeforeMailboxSieve`], всё в этой точке — «до Sieve»).
pub const ORDER_LAST: i32 = i32::MAX;

/// Точка конвейера обработки (SRS 4.9). Порядок вариантов — порядок выполнения.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipelinePoint {
    /// `MAIL FROM` / отправитель конверта: условия по конверту, отказ — всему письму.
    MailFrom,
    /// `RCPT TO` / получатель конверта: условия по конверту, отказ — отдельному получателю.
    RcptTo,
    /// `DATA` / письмо целиком: условия по содержимому, отказ — всему письму.
    Data,
    /// До скрипта ящика (Sieve) и этапов модулей; последним этапом точки — Sieve ящика.
    BeforeMailboxSieve,
    /// После скрипта ящика: этапы видят итог Sieve ([`StageInput::actions`]).
    AfterMailboxSieve,
    /// Итоговый контроль действий ([`ActionSet`] по [`OrgPolicy`]) — после всех остальных этапов.
    FinalActionCheck,
}

impl PipelinePoint {
    /// Все точки по порядку выполнения.
    pub const ALL: [PipelinePoint; 6] = [
        PipelinePoint::MailFrom,
        PipelinePoint::RcptTo,
        PipelinePoint::Data,
        PipelinePoint::BeforeMailboxSieve,
        PipelinePoint::AfterMailboxSieve,
        PipelinePoint::FinalActionCheck,
    ];
}

/// Идентификаторы этапов ядра (регистрирует приложение при сборке через [`StageRegistry::register_core`]).
pub mod core_stage {
    /// Проверки сессии на `MAIL FROM` ([`super::PipelinePoint::MailFrom`]).
    pub const SESSION_MAIL_FROM: &str = "session-mail-from";
    /// Проверки сессии на `RCPT TO` ([`super::PipelinePoint::RcptTo`]).
    pub const SESSION_RCPT: &str = "session-rcpt";
    /// Milter на `DATA` ([`super::PipelinePoint::Data`]).
    pub const MILTER: &str = "milter";
    /// Журналирование ([`super::PipelinePoint::BeforeMailboxSieve`], [`super::ORDER_FIRST`]; CTR-97).
    pub const JOURNAL: &str = "journal";
    /// Sieve ящика ([`super::PipelinePoint::BeforeMailboxSieve`], [`super::ORDER_LAST`]).
    pub const SIEVE: &str = "sieve";
    /// Итоговый контроль действий ([`super::PipelinePoint::FinalActionCheck`]).
    pub const FINAL: &str = "final";
}

/// Проверяет идентификатор этапа: `[a-z0-9._-]`, не пусто, не длиннее [`MAX_STAGE_ID_LEN`].
pub fn valid_stage_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_STAGE_ID_LEN
        && id.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_' || b == b'-'
        })
}

/// Вид этапа: служебные письма продукта ([`SystemMessage`]) минуют этапы правил (SRS 4.9) — петли исключены.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageKind {
    /// Проверка ядра (проверки сессии, Milter): выполняется и для служебных писем.
    Check,
    /// Этап правил (журналирование, Sieve ящика, этапы модулей, итоговый контроль): служебные письма
    /// продукта его минуют.
    Rules,
}

/// Служебное письмо продукта (SRS 4.9): проходит конвейер без этапов правил ([`StageKind::Rules`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemMessage {
    /// Уведомление о доставке (DSN, RFC 3464) и отбивки.
    Dsn,
    /// Уведомление (карантин, сводка, администратору).
    Notification,
    /// Копия журнала (CTR-97): повторно не журналируется.
    JournalCopy,
}

/// Что известно этапу в точке конвейера. Заполняет вызывающий (роль transport): на `MailFrom`/`RcptTo` —
/// конверт, с `Data` — письмо, с `AfterMailboxSieve` — итоговый набор действий.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageInput {
    /// Организация.
    pub tenant: TenantId,
    /// Как письмо вошло в конвейер (приём извне или отправка клиентом).
    pub flow: FlowDirection,
    /// Отправитель конверта (`MAIL FROM`); пустой — уведомление о доставке.
    pub mail_from: String,
    /// Получатель, к которому относится вызов (`RcptTo` и точки доставки: Sieve, итоговый контроль);
    /// `None` — вызов на письмо в целом.
    pub rcpt: Option<String>,
    /// Письмо целиком (RFC 5322) с точки `Data`; `None` раньше.
    pub message: Option<Bytes>,
    /// Итоговый набор действий по получателю с точки `AfterMailboxSieve`; `None` раньше.
    pub actions: Option<ActionSet>,
    /// Служебное письмо продукта: этапы правил ([`StageKind::Rules`]) пропускаются.
    pub system: Option<SystemMessage>,
}

impl StageInput {
    /// Конверт точки `MailFrom`/`RcptTo`/`Data` (письма ещё нет): этапы правил для служебных писем
    /// пропускаются так же, как с письмом.
    pub fn envelope(
        tenant: TenantId,
        flow: FlowDirection,
        mail_from: &str,
        rcpt: Option<&str>,
        system: Option<SystemMessage>,
    ) -> Self {
        StageInput {
            tenant,
            flow,
            mail_from: mail_from.to_owned(),
            rcpt: rcpt.map(str::to_owned),
            message: None,
            actions: None,
            system,
        }
    }
}

/// Итог этапа в точке конвейера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StageVerdict {
    /// Пропустить письмо (этапу) дальше.
    Allow,
    /// Отказ всему письму: SMTP 5xx в той же сессии (edge передаёт насквозь, SRS 2.6); JMAP EmailSubmission —
    /// `forbiddenToSend` (RFC 8621). Причина — для журнала и ответа.
    Reject(String),
    /// Отказ одному получателю — только в точке [`PipelinePoint::RcptTo`]: его копия не доставляется,
    /// остальное письмо идёт дальше.
    RejectRecipient {
        /// Получатель из конверта.
        rcpt: String,
        /// Причина (журнал, ответ).
        reason: String,
    },
}

/// Этап конвейера (SRS 4.9, 2.5). Ядро регистрирует собственные этапы, модули — через точку расширения;
/// порядок — точка, затем `order`, затем порядок регистрации.
#[async_trait]
pub trait Stage: Send + Sync + 'static {
    /// Идентификатор (журнал, диагностика): [`valid_stage_id`], уникален в конвейере.
    fn id(&self) -> &str;

    /// Точка конвейера.
    fn point(&self) -> PipelinePoint;

    /// Порядок внутри точки; у этапов ядра — фиксированный ([`ORDER_FIRST`], [`ORDER_LAST`]).
    fn order(&self) -> i32;

    /// Вид этапа: для служебных писем этапы правил не выполняются.
    fn kind(&self) -> StageKind;

    /// Проверяет письмо в точке. Ошибка этапа — ошибка операции (временный отказ повторяется вызывающим).
    async fn run(&self, input: &StageInput) -> Result<StageVerdict>;
}

/// Итоговый набор действий по письму и получателю (SRS 4.9): строится после Sieve ящика и этапов модулей,
/// проверяется этапом [`PipelinePoint::FinalActionCheck`] по [`OrgPolicy`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSet {
    /// Перенаправления (`redirect` из скрипта ящика и правил потока): копия письма уходит по адресу.
    pub redirect: Vec<String>,
    /// Копии по адресам (пересылка копии; копии в ящики организации — доставка, не пересылка).
    pub copies: Vec<String>,
    /// Итоговые адресаты письма (включая раскрытых из групп; после перенаправлений и копий).
    pub recipients: Vec<String>,
}

impl ActionSet {
    /// Проверяет адреса ([`valid_address`], без угловых скобок); иначе — `Error::Invalid`.
    pub fn validate(&self) -> Result<()> {
        for list in [&self.redirect, &self.copies, &self.recipients] {
            for a in list {
                if !valid_address(a) {
                    return Err(Error::invalid(format!(
                        "pipeline: bad action address {a:?}"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Политика организации для итогового контроля действий (SRS 4.9; задел под модуль «Правила потока почты»,
/// SRS 4.10 — действие `block_external_forward`). Хранение и Admin API — волны полос.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgPolicy {
    /// Запрет перенаправления и пересылки на внешние адреса: адреса [`ActionSet::redirect`] и
    /// [`ActionSet::copies`] вне доменов организации. Перехватывает `redirect` из скрипта ящика.
    /// По умолчанию выключен.
    pub forbid_external_forward: bool,
}

impl OrgPolicy {
    /// Адреса перенаправлений и копий, запрещённые [`OrgPolicy::forbid_external_forward`]: вне доменов
    /// организации `org_domains` (сравнение по [`normalize_domain`], без учёта регистра). Пусто — нарушений
    /// нет (запрет выключен или все адреса внутренние). Итоговые адресаты доставки (`recipients`) не
    /// проверяются: запрет — на перенаправление и пересылку. Этап `FinalActionCheck` возвращает письмо с
    /// непустым списком как [`StageVerdict::Reject`].
    pub fn check(&self, actions: &ActionSet, org_domains: &[String]) -> Vec<String> {
        if !self.forbid_external_forward {
            return Vec::new();
        }
        let internal = |domain: &str| {
            normalize_domain(domain)
                .map(|d| org_domains.iter().any(|x| x.eq_ignore_ascii_case(&d)))
                .unwrap_or(false)
        };
        let mut seen = std::collections::BTreeSet::new();
        actions
            .redirect
            .iter()
            .chain(&actions.copies)
            .filter(|a| match a.rsplit_once('@') {
                Some((_, domain)) => !internal(domain),
                None => true,
            })
            .filter(|a| seen.insert((*a).clone()))
            .cloned()
            .collect()
    }
}

#[derive(Clone)]
struct Entry {
    stage: Arc<dyn Stage>,
    core: bool,
    seq: u32,
}

/// Реестр этапов конвейера. Ядро регистрирует собственные этапы ([`StageRegistry::register_core`]) при
/// сборке узла, модульные этапы переносит из [`crate::ext::Registry`] ([`StageRegistry::register`]).
/// Этап ядра нельзя удалить ([`StageRegistry::remove`] — `Error::Invalid`) или переставить
/// ([`StageRegistry::set_order`] — `Error::Invalid`).
#[derive(Clone, Default)]
pub struct StageRegistry {
    entries: Vec<Entry>,
    seq: u32,
}

impl fmt::Debug for StageRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list()
            .entries(
                self.sorted()
                    .iter()
                    .map(|e| format!("{}@{:?}", e.stage.id(), e.stage.point())),
            )
            .finish()
    }
}

impl StageRegistry {
    /// Этап ядра (проверки сессии, Milter, журналирование, Sieve ящика, итоговый контроль; идентификаторы —
    /// [`core_stage`]). Повтор идентификатора — `Error::Conflict`.
    pub fn register_core(&mut self, stage: Arc<dyn Stage>) -> Result<()> {
        self.push(stage, true)
    }

    /// Модульный этап в точке `point` (через [`crate::ext::Registry::add_stage`], SRS 2.5):
    /// `stage.point() ≠ point` — `Error::Invalid`, повтор идентификатора — `Error::Conflict`.
    pub fn register(&mut self, point: PipelinePoint, stage: Arc<dyn Stage>) -> Result<()> {
        if stage.point() != point {
            return Err(Error::invalid(format!(
                "pipeline: stage {} registered at {:?}, not at {point:?}",
                stage.id(),
                stage.point()
            )));
        }
        self.push(stage, false)
    }

    fn push(&mut self, stage: Arc<dyn Stage>, core: bool) -> Result<()> {
        let id = stage.id();
        if !valid_stage_id(id) {
            return Err(Error::invalid(format!("pipeline: bad stage id {id:?}")));
        }
        if self.entries.iter().any(|e| e.stage.id() == id) {
            return Err(Error::Conflict);
        }
        self.entries.push(Entry {
            stage,
            core,
            seq: self.seq,
        });
        self.seq += 1;
        Ok(())
    }

    /// Удаляет модульный этап. Этап ядра удалить нельзя — `Error::Invalid`; нет — `Error::NotFound`.
    pub fn remove(&mut self, id: &str) -> Result<()> {
        let Some(entry) = self.entries.iter().find(|e| e.stage.id() == id) else {
            return Err(Error::NotFound);
        };
        if entry.core {
            return Err(Error::invalid(format!(
                "pipeline: core stage {id} cannot be removed"
            )));
        }
        self.entries.retain(|e| e.stage.id() != id);
        Ok(())
    }

    /// Меняет порядок модульного этапа. Порядок этапа ядра фиксирован — `Error::Invalid`;
    /// нет этапа — `Error::NotFound`.
    pub fn set_order(&mut self, id: &str, order: i32) -> Result<()> {
        let Some(entry) = self.entries.iter_mut().find(|e| e.stage.id() == id) else {
            return Err(Error::NotFound);
        };
        if entry.core {
            return Err(Error::invalid(format!(
                "pipeline: core stage {id} cannot be reordered"
            )));
        }
        // Порядок хранит этап; обёртка заменяется копией с новым `order`.
        entry.stage = Arc::new(Reordered {
            stage: entry.stage.clone(),
            order,
        });
        Ok(())
    }

    /// Этап по идентификатору.
    pub fn stage(&self, id: &str) -> Option<Arc<dyn Stage>> {
        self.entries
            .iter()
            .find(|e| e.stage.id() == id)
            .map(|e| e.stage.clone())
    }

    /// Все этапы в порядке выполнения: точка, затем `order`, затем порядок регистрации.
    pub fn stages(&self) -> Vec<Arc<dyn Stage>> {
        self.sorted().into_iter().map(|e| e.stage).collect()
    }

    /// Этапы точки в порядке выполнения.
    pub fn stages_at(&self, point: PipelinePoint) -> Vec<Arc<dyn Stage>> {
        self.sorted()
            .into_iter()
            .filter(|e| e.stage.point() == point)
            .map(|e| e.stage)
            .collect()
    }

    fn sorted(&self) -> Vec<Entry> {
        let mut entries = self.entries.clone();
        entries.sort_by_key(|e| (e.stage.point(), e.stage.order(), e.seq));
        entries
    }

    /// Выполняет этапы точки по порядку (роль transport; входящая почта — до доставки в ящик, исходящая —
    /// до постановки в очередь). Этапы правил ([`StageKind::Rules`]) для служебных писем
    /// ([`StageInput::system`]) пропускаются. Первый отказ — итог: [`StageVerdict::Reject`] прекращает
    /// конвейер, [`StageVerdict::RejectRecipient`] допустим только в [`PipelinePoint::RcptTo`] (иначе —
    /// `Error::Invalid`); ошибка этапа — ошибка операции.
    pub async fn run(&self, point: PipelinePoint, input: &StageInput) -> Result<StageVerdict> {
        for stage in self.stages_at(point) {
            if input.system.is_some() && stage.kind() == StageKind::Rules {
                continue;
            }
            match stage.run(input).await? {
                StageVerdict::Allow => {}
                v @ (StageVerdict::Reject(_) | StageVerdict::RejectRecipient { .. }) => {
                    if matches!(v, StageVerdict::RejectRecipient { .. })
                        && point != PipelinePoint::RcptTo
                    {
                        return Err(Error::invalid(
                            "pipeline: per-recipient refusal is only valid at RcptTo",
                        ));
                    }
                    return Ok(v);
                }
            }
        }
        Ok(StageVerdict::Allow)
    }
}

/// Обёртка [`StageRegistry::set_order`]: тот же этап с новым порядком.
struct Reordered {
    stage: Arc<dyn Stage>,
    order: i32,
}

#[async_trait]
impl Stage for Reordered {
    fn id(&self) -> &str {
        self.stage.id()
    }

    fn point(&self) -> PipelinePoint {
        self.stage.point()
    }

    fn order(&self) -> i32 {
        self.order
    }

    fn kind(&self) -> StageKind {
        self.stage.kind()
    }

    async fn run(&self, input: &StageInput) -> Result<StageVerdict> {
        self.stage.run(input).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_stage(id: &str, point: PipelinePoint, order: i32) -> Arc<dyn Stage> {
        Arc::new(Fixed {
            id: id.to_owned(),
            point,
            order,
            kind: StageKind::Rules,
        })
    }

    struct Fixed {
        id: String,
        point: PipelinePoint,
        order: i32,
        kind: StageKind,
    }

    #[async_trait]
    impl Stage for Fixed {
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

        async fn run(&self, _: &StageInput) -> Result<StageVerdict> {
            Ok(StageVerdict::Allow)
        }
    }

    #[test]
    fn stage_ids_and_points() {
        for good in ["session", "core.milter", "x_1", &"a".repeat(64)] {
            assert!(valid_stage_id(good), "{good}");
        }
        for bad in ["", "Session", "a b", "a/b", &"a".repeat(65)] {
            assert!(!valid_stage_id(bad), "{bad}");
        }
        assert_eq!(
            PipelinePoint::ALL,
            [
                PipelinePoint::MailFrom,
                PipelinePoint::RcptTo,
                PipelinePoint::Data,
                PipelinePoint::BeforeMailboxSieve,
                PipelinePoint::AfterMailboxSieve,
                PipelinePoint::FinalActionCheck,
            ]
        );
        assert!(PipelinePoint::MailFrom < PipelinePoint::FinalActionCheck);
    }

    #[test]
    fn registry_order_and_protection() {
        let mut reg = StageRegistry::default();
        reg.register_core(rule_stage(
            core_stage::SESSION_RCPT,
            PipelinePoint::RcptTo,
            0,
        ))
        .expect("core session");
        reg.register_core(rule_stage(
            core_stage::JOURNAL,
            PipelinePoint::BeforeMailboxSieve,
            ORDER_FIRST,
        ))
        .expect("core journal");
        reg.register_core(rule_stage(
            core_stage::SIEVE,
            PipelinePoint::BeforeMailboxSieve,
            ORDER_LAST,
        ))
        .expect("core sieve");
        // Модульный этап между журналированием и Sieve.
        reg.register(
            PipelinePoint::BeforeMailboxSieve,
            rule_stage("mod.pre", PipelinePoint::BeforeMailboxSieve, 0),
        )
        .expect("module");
        // Точка не совпадает — Invalid; повтор идентификатора — Conflict.
        assert!(matches!(
            reg.register(
                PipelinePoint::AfterMailboxSieve,
                rule_stage("mod.post", PipelinePoint::BeforeMailboxSieve, 0)
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            reg.register(
                PipelinePoint::AfterMailboxSieve,
                rule_stage("mod.pre", PipelinePoint::AfterMailboxSieve, 0),
            ),
            Err(Error::Conflict)
        ));
        let ids = |p: PipelinePoint| {
            reg.stages_at(p)
                .into_iter()
                .map(|s| s.id().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids(PipelinePoint::BeforeMailboxSieve),
            vec![core_stage::JOURNAL, "mod.pre", core_stage::SIEVE],
            "журналирование до модулей и Sieve"
        );
        // Этап ядра нельзя удалить или переставить; модульный — можно.
        assert!(matches!(
            reg.remove(core_stage::JOURNAL),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            reg.set_order(core_stage::SIEVE, 5),
            Err(Error::Invalid(_))
        ));
        assert_eq!(reg.remove("nope"), Err(Error::NotFound));
        reg.set_order("mod.pre", 10).expect("reorder module");
        reg.remove("mod.pre").expect("remove module");
        assert_eq!(
            ids(PipelinePoint::BeforeMailboxSieve),
            vec![core_stage::JOURNAL, core_stage::SIEVE]
        );
        assert!(format!("{reg:?}").contains(core_stage::JOURNAL));
    }

    #[test]
    fn forbid_external_forward() {
        let actions = ActionSet {
            redirect: vec![
                "ally@internal.example".into(),
                "evil@external.example".into(),
            ],
            copies: vec!["copy@Ext.NET".into()],
            recipients: vec!["user@internal.example".into()],
        };
        actions.validate().expect("addresses");
        assert!(matches!(
            ActionSet {
                redirect: vec!["<evil@external.example>".into()],
                ..actions.clone()
            }
            .validate(),
            Err(Error::Invalid(_))
        ));

        let policy = OrgPolicy {
            forbid_external_forward: true,
        };
        let org = ["internal.example".to_owned()];
        assert_eq!(
            policy.check(&actions, &org),
            vec!["evil@external.example".to_owned(), "copy@Ext.NET".into()],
            "внешние перенаправление и копия, без повторов"
        );
        // Выключен — нарушений нет; адрес без домена — внешний.
        assert_eq!(
            OrgPolicy::default().check(&actions, &org),
            Vec::<String>::new()
        );
        let no_domain = ActionSet {
            redirect: vec!["not-an-address".into()],
            ..actions.clone()
        };
        assert_eq!(policy.check(&no_domain, &org).len(), 2);
    }
}
