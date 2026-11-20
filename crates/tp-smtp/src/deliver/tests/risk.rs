//! Волна smtp-32: каталог признаков на smtp-in (SMTP-52, приёмка карточки) — детектор беседы снимает
//! признак ответа и ставит `X-ThePost-Risk`; карантин по баллу, отказ в сессии, «только отчёт»;
//! сочетание с Rspamd; пришедший извне заголовок балла удаляется.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use time::OffsetDateTime;
use tp_contracts::delivery::{DeliveryDecision, DeliveryEventKind};
use tp_contracts::ids::{AccountId, TenantId};
use tp_contracts::membership::NodeId;
use tp_contracts::risk::{
    Detector, ListId, Mode, Origin, PACKAGE_FORMAT, PackageManifest, RiskAction, RiskStore, Semver,
    Signal, SignalId,
};
use tp_contracts::secrets::SecretRef;
use tp_contracts::sieve::{RulesInput, RulesOutcome};
use tp_contracts::thread::ThreadFacts;
use tp_testkit::{MemDeliveryLog, MemRisk, MemSecretStore, MemSentLog, SystemClock};

use super::*;
use crate::authcheck::tests as fx;
use crate::config::{ReplyConfig, ReplyKeyConfig, RiskConfig};
use crate::milter::proto::{self, Packet};
use crate::milter::tests as mt;
use crate::reply::ReplyMarks;
use crate::risk::{ListValue, Risk, RiskEnviron};

const PARTNER: &str = "partner.example";
const CLIENT_OK: &str = "192.0.2.10:1000";

/// Признак каталога `id` с детектором `detector` (пакет поставщика, порог силы 0).
fn signal(id: &str, detector: Detector, weight: u16, mode: Mode) -> Signal {
    Signal {
        id: SignalId::new(id).expect("id"),
        detector,
        weight,
        threshold: 0,
        action: RiskAction::None,
        mode,
        origin: Origin::Vendor,
        since: OffsetDateTime::UNIX_EPOCH,
    }
}

/// Каталог в `MemRisk`: пакет 1 с признаками `signals` активен.
async fn store_of(signals: Vec<Signal>) -> Arc<MemRisk> {
    let store = Arc::new(MemRisk::new(Arc::new(SystemClock)));
    store
        .put_package(&PackageManifest {
            format: PACKAGE_FORMAT,
            version: 1,
            created: OffsetDateTime::UNIX_EPOCH,
            min_node: Semver::new(0, 1, 0),
            key_id: "k1".into(),
            signals,
            lists: vec![],
            samples: vec![],
        })
        .await
        .expect("package");
    store.activate(1).await.expect("activate");
    store
}

/// Данные узла для детекторов: память бесед по учётным записям (списки TI и PSL — без совпадений).
#[derive(Default)]
struct Stub {
    facts: Mutex<HashMap<AccountId, ThreadFacts>>,
}

impl Stub {
    fn with_facts(self, account: AccountId, facts: ThreadFacts) -> Self {
        self.facts.lock().expect("lock").insert(account, facts);
        self
    }
}

#[async_trait]
impl RiskEnviron for Stub {
    async fn thread_facts(
        &self,
        _tenant: TenantId,
        account: AccountId,
        _keys: &[String],
    ) -> Result<ThreadFacts> {
        Ok(self
            .facts
            .lock()
            .expect("lock")
            .get(&account)
            .cloned()
            .unwrap_or_default())
    }

    async fn list_contains(
        &self,
        _tenant: TenantId,
        _list: &ListId,
        _value: ListValue<'_>,
    ) -> Result<bool> {
        Ok(false)
    }

    async fn psl(&self) -> Result<Option<Arc<publicsuffix::List>>> {
        Ok(None)
    }
}

/// Проверка каталога: включена, каталог `store`, память бесед — `stub`.
fn risk_of(store: Arc<MemRisk>, stub: Stub) -> Arc<Risk> {
    Arc::new(Risk::new(
        RiskConfig {
            enabled: true,
            ..RiskConfig::default()
        },
        store,
        Arc::new(stub),
        None,
    ))
}

/// Проверки отправителя: домен партнёра `partner.example` (SPF — `192.0.2.0/24`, DMARC `p=none`).
fn partner_check() -> AuthCheck {
    let check = fx::checker();
    fx::publish_sender_domain(check.cache(), PARTNER, "none");
    check
}

/// Метка ответа (ключ `k1`) и запись об отправленном — как в волне smtp-31.
async fn reply_marks() -> (Arc<ReplyMarks>, Arc<MemSentLog>) {
    let store = MemSecretStore::new(Arc::new(SystemClock));
    store.set(
        &SecretRef::new("thepost/reply", "k1").expect("ref"),
        "a".repeat(32),
    );
    let marks = Arc::new(ReplyMarks::new(
        Arc::new(store),
        ReplyConfig {
            keys: vec![ReplyKeyConfig {
                id: "k1".into(),
                secret: SecretRef::new("thepost/reply", "k1").expect("ref"),
                active: true,
            }],
            ..ReplyConfig::default()
        },
    ));
    (marks, Arc::new(MemSentLog::new()))
}

/// Запись об отправленном нами письме адресату `recipient` (`age` назад); возвращает метку
/// Message-ID — ответ на неё ссылается `In-Reply-To`.
async fn sent_marked(
    marks: &ReplyMarks,
    sent: &MemSentLog,
    recipient: &str,
    age: time::Duration,
) -> String {
    use tp_contracts::reply::{SentRecord, normalize_recipient};
    let (mid, tag) = marks
        .message_id("example.org", OffsetDateTime::now_utc() - age)
        .await
        .expect("mark")
        .expect("active key");
    sent.record(SentRecord {
        tenant: TenantId::DEFAULT,
        account: AccountId::new(),
        tag,
        message_id_hash: ReplyMarks::hash_of(&mid),
        recipients: vec![normalize_recipient(recipient).expect("rcpt")],
        thread: None,
        sent_at: OffsetDateTime::now_utc() - age,
    })
    .await
    .expect("record");
    mid
}

/// Входящий конверт с клиента `ip` и отправителем конверта `mail_from`.
fn inbound(ip: &str, mail_from: &str, rcpt: &str) -> Envelope {
    let mut e = fx::envelope(ip);
    e.mail_from = mail_from.into();
    e.rcpts = vec![rcpt.into()];
    e
}

/// Ответ `from` с вложением (MIME, base64) и ссылкой на письмо `references`.
fn reply_letter(from: &str, references: &str, attachment: &[u8]) -> Bytes {
    use base64::Engine;
    Bytes::from(format!(
        "From: {from}\r\nTo: alice@example.org\r\nSubject: Re: hi\r\n{references}\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=\"b\"\r\n\r\n\
         --b\r\n\
         Content-Type: application/octet-stream; name=\"doc.pdf\"\r\n\
         Content-Disposition: attachment; filename=\"doc.pdf\"\r\n\
         Content-Transfer-Encoding: base64\r\n\r\n{}\r\n\
         --b--\r\n",
        base64::engine::general_purpose::STANDARD.encode(attachment)
    ))
}

/// ISO 9660 в памяти теста: `CD001` в первичном дескрипторе тома.
fn iso_bytes() -> Vec<u8> {
    let mut iso = vec![0u8; 0x8018];
    iso[0x8001..0x8006].copy_from_slice(b"CD001");
    iso
}

/// Правила, запоминающие признак ответа и доверенность беседы по получателю.
#[derive(Default)]
struct RuleFacts(Mutex<Vec<(String, bool, bool)>>);

impl RuleFacts {
    fn calls(&self) -> Vec<(String, bool, bool)> {
        self.0.lock().expect("lock").clone()
    }
}

#[async_trait]
impl DeliveryRules for RuleFacts {
    async fn evaluate(&self, input: &RulesInput) -> Result<RulesOutcome> {
        self.0.lock().expect("lock").push((
            input.recipient.clone(),
            input.peer.reply,
            input.thread_trusted,
        ));
        Ok(RulesOutcome::implicit_keep())
    }
}

/// Приёмка: ответ в доверенной беседе с ISO — признак ответа снят, `X-ThePost-Risk` с
/// `tp.attach.disk_image_or_shortcut`; правилам видны доверенная беседа, вердикт каталога и
/// снятый признак ответа.
#[tokio::test]
async fn reply_with_iso_drops_reply_and_tags() {
    let env = Env::new(DecisionHooks::default()).await;
    let (marks, sent) = reply_marks().await;
    let mid = sent_marked(
        &marks,
        &sent,
        "bob@partner.example",
        time::Duration::minutes(5),
    )
    .await;
    let store = store_of(vec![signal(
        "tp.attach.disk_image_or_shortcut",
        Detector::DiskImageOrShortcut,
        3,
        Mode::Enforce,
    )])
    .await;
    let alice = env.scope("alice@example.org").await.account;
    let stub = Stub::default().with_facts(
        alice,
        ThreadFacts {
            // Беседа доверенная: в памяти есть переписка (тип вложения).
            attachments: vec!["application/pdf".into()],
            ..ThreadFacts::new()
        },
    );
    let rules = Arc::new(RuleFacts::default());
    let mut d = env
        .delivery(false)
        .with_reply_marks(marks)
        .with_sent_log(sent)
        .with_risk(risk_of(store, stub))
        .with_rules(rules.clone());
    d.deps.authcheck = Some(Arc::new(partner_check()));
    let raw = reply_letter(
        "bob@partner.example",
        &format!("In-Reply-To: <{mid}>\r\n"),
        &iso_bytes(),
    );
    assert_eq!(
        d.data(
            &inbound(CLIENT_OK, "bob@partner.example", "alice@example.org"),
            raw
        )
        .await
        .code,
        250
    );
    let got = env.inbox("alice@example.org").await;
    assert_eq!(
        got.len(),
        1,
        "{}",
        got.first().map(String::as_str).unwrap_or("")
    );
    // Признак ответа снят детектором беседы; балл каталога — заголовком.
    assert!(!got[0].contains("X-ThePost-Reply: yes"), "{}", got[0]);
    assert!(
        got[0].contains("X-ThePost-Risk: score=3; signals=tp.attach.disk_image_or_shortcut"),
        "{}",
        got[0]
    );
    // Правилам — снятый признак ответа и доверенная беседа (CTR-95), вердикт — в контексте правил.
    assert_eq!(
        rules.calls(),
        vec![("alice@example.org".into(), false, true)]
    );
}

/// Приёмка: балл ≥ порога `quarantine` — карантин узла («Спам», событие приёма `Quarantine`);
/// событие журнала доставки с баллом, признаками и действием (`thepost admin delivery show`).
#[tokio::test]
async fn quarantine_score_goes_to_junk_folder() {
    let env = Env::new(DecisionHooks::default()).await;
    let store = store_of(vec![signal(
        "tp.attach.disk_image_or_shortcut",
        Detector::DiskImageOrShortcut,
        10,
        Mode::Enforce,
    )])
    .await;
    let log = MemDeliveryLog::new();
    let d = env
        .delivery(false)
        .with_risk(risk_of(store, Stub::default()))
        .with_tracking(Tracking::new(
            Arc::new(log.clone()),
            NodeId::new("mx1").expect("node"),
        ));
    let raw = reply_letter("bob@partner.example", "", &iso_bytes());
    assert_eq!(
        d.data(
            &inbound(CLIENT_OK, "bob@partner.example", "alice@example.org"),
            raw
        )
        .await
        .code,
        250
    );
    assert_eq!(
        env.junk("alice@example.org").await,
        1,
        "карантин — «Спам» узла"
    );
    // Заголовок при действии `quarantine` тоже ставится (балл и признаки письма).
    let got = env.junk_mail("alice@example.org").await;
    assert_eq!(got.len(), 1);
    assert!(
        got[0].contains("X-ThePost-Risk: score=10; signals=tp.attach.disk_image_or_shortcut"),
        "{}",
        got[0]
    );
    // Событие журнала доставки — балл, признаки и действие.
    let events = log.events();
    let risk_event = events
        .iter()
        .find(|e| e.reason.as_deref().is_some_and(|r| r.starts_with("risk:")))
        .expect("risk event");
    assert_eq!(risk_event.kind, DeliveryEventKind::Receive);
    assert_eq!(
        risk_event.reason.as_deref(),
        Some("risk: score=10; signals=tp.attach.disk_image_or_shortcut, action=quarantine")
    );
    assert!(
        events
            .iter()
            .any(|e| e.decision == DeliveryDecision::Quarantine)
    );
}

/// Приёмка: признак в режиме «только отчёт» — балл не изменился, письмо во «Входящих» без
/// заголовка, срабатывание записано в журнал каталога.
#[tokio::test]
async fn report_mode_records_only() {
    let env = Env::new(DecisionHooks::default()).await;
    let store = store_of(vec![signal(
        "tp.attach.disk_image_or_shortcut",
        Detector::DiskImageOrShortcut,
        100,
        Mode::Report,
    )])
    .await;
    let d = env
        .delivery(false)
        .with_risk(risk_of(store.clone(), Stub::default()));
    let raw = reply_letter("bob@partner.example", "", &iso_bytes());
    assert_eq!(
        d.data(
            &inbound(CLIENT_OK, "bob@partner.example", "alice@example.org"),
            raw
        )
        .await
        .code,
        250
    );
    let got = env.inbox("alice@example.org").await;
    assert_eq!(got.len(), 1, "«только отчёт» — во «Входящих»");
    assert!(!got[0].contains("X-ThePost-Risk"), "{}", got[0]);
    let hits = store
        .hits(TenantId::DEFAULT, &tp_contracts::risk::HitsQuery::all(10))
        .await
        .expect("hits");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].mode, Mode::Report);
}

/// Приёмка: балл ≥ порога `reject` — отказ `550 5.7.1` в сессии, письма нет; сработавшие — в
/// журнале каталога до отказа.
#[tokio::test]
async fn reject_score_refuses_in_session() {
    let env = Env::new(DecisionHooks::default()).await;
    let store = store_of(vec![signal(
        "tp.attach.disk_image_or_shortcut",
        Detector::DiskImageOrShortcut,
        20,
        Mode::Enforce,
    )])
    .await;
    let d = env
        .delivery(false)
        .with_risk(risk_of(store.clone(), Stub::default()));
    let raw = reply_letter("bob@partner.example", "", &iso_bytes());
    let r = d
        .data(
            &inbound(CLIENT_OK, "bob@partner.example", "alice@example.org"),
            raw,
        )
        .await;
    assert_eq!(r.code, 550);
    assert_eq!(r.esc, [5, 7, 1]);
    assert!(env.inbox("alice@example.org").await.is_empty());
    let hits = store
        .hits(TenantId::DEFAULT, &tp_contracts::risk::HitsQuery::all(10))
        .await
        .expect("hits");
    assert!(!hits.is_empty());
}

/// Приёмка: Rspamd (Milter) с карантином при малом балле каталога — карантин (самое строгое из
/// действий, [`tp_contracts::risk::Verdict::combine`]); отказ Rspamd — отказ в сессии.
#[tokio::test]
async fn rspamd_verdict_combines_with_catalog() {
    let env = Env::new(DecisionHooks::default()).await;
    let quarantine = mt::Mock::start(
        0,
        mt::on_eob(vec![
            Packet::strings(proto::R_QUARANTINE, &[b"rspamd: spam"]),
            mt::reply_of(proto::R_CONTINUE),
        ]),
    )
    .await;
    let store = store_of(vec![signal(
        "tp.attach.disk_image_or_shortcut",
        Detector::DiskImageOrShortcut,
        3,
        Mode::Enforce,
    )])
    .await;
    let mut d = env
        .delivery(false)
        .with_risk(risk_of(store, Stub::default()));
    d.deps.milter = Some(Arc::new(Milters::new(
        crate::config::MilterConfig {
            filters: vec![quarantine.filter("rspamd")],
            ..crate::config::MilterConfig::default()
        },
        "mx.example.org",
    )));
    let raw = reply_letter("bob@partner.example", "", &iso_bytes());
    assert_eq!(
        d.data(
            &inbound(CLIENT_OK, "bob@partner.example", "alice@example.org"),
            raw
        )
        .await
        .code,
        250
    );
    // Малый балл каталога (3 — tag) и карантин Rspamd — итог карантин («Спам» узла).
    assert_eq!(env.junk("alice@example.org").await, 1);

    // Отказ Rspamd при малом балле — отказ в сессии (самое строгое).
    let reject = mt::Mock::start(0, mt::on_eob(vec![mt::reply_of(proto::R_REJECT)])).await;
    let store = store_of(vec![signal(
        "tp.attach.disk_image_or_shortcut",
        Detector::DiskImageOrShortcut,
        3,
        Mode::Enforce,
    )])
    .await;
    let mut d = env
        .delivery(false)
        .with_risk(risk_of(store, Stub::default()));
    d.deps.milter = Some(Arc::new(Milters::new(
        crate::config::MilterConfig {
            filters: vec![reject.filter("rspamd")],
            ..crate::config::MilterConfig::default()
        },
        "mx.example.org",
    )));
    let raw = reply_letter("bob@partner.example", "", &iso_bytes());
    let r = d
        .data(
            &inbound(CLIENT_OK, "bob@partner.example", "alice@example.org"),
            raw,
        )
        .await;
    assert_eq!(
        r.code, 550,
        "Rspamd reject — отказ при любом балле каталога"
    );
    assert!(env.inbox("alice@example.org").await.is_empty());
}

/// Приёмка: пришедший извне `X-ThePost-Risk` удаляется до проверок (свой ставит только узел).
#[tokio::test]
async fn inbound_risk_header_is_stripped() {
    let env = Env::new(DecisionHooks::default()).await;
    // Каталог без пакета — балла нет, свой заголовок узел не ставит: входящий должен исчезнуть.
    let store = Arc::new(MemRisk::new(Arc::new(SystemClock)));
    let d = env
        .delivery(false)
        .with_risk(risk_of(store, Stub::default()));
    let raw = Bytes::from_static(
        b"From: bob@partner.example\r\nX-ThePost-Risk: score=99; signals=tp.fake\r\n\r\nhello\r\n",
    );
    assert_eq!(
        d.data(
            &inbound(CLIENT_OK, "bob@partner.example", "alice@example.org"),
            raw
        )
        .await
        .code,
        250
    );
    let got = env.inbox("alice@example.org").await;
    assert_eq!(got.len(), 1);
    assert!(!got[0].contains("X-ThePost-Risk"), "{}", got[0]);
}
