//! Волна smtp-31: признак «ответ на наше письмо» (SMTP-51, решение 125 а) — по метке Message-ID и записи
//! об отправленном; BATV bounce-адреса (`prvs=…`); память беседы; признак ничего не пропускает.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tp_contracts::reply::{SentRecord, normalize_recipient};
use tp_contracts::secrets::SecretRef;
use tp_contracts::sieve::{RulesInput, RulesOutcome};
use tp_testkit::{MemSecretStore, MemSentLog, MemThreads, SystemClock};

use super::*;
use crate::authcheck::tests as fx;
use crate::config::{BatvConfig, BatvMode, ReplyConfig, ReplyKeyConfig};
use crate::milter::proto::{self, Packet};
use crate::milter::tests as mt;
use crate::reply::ReplyMarks;

const PARTNER: &str = "partner.example";

/// Правила, запоминающие признак «ответ на наше письмо» ([`PeerContext::reply`]) по получателю.
#[derive(Default)]
struct ReplyRules(Mutex<Vec<(String, bool)>>);

#[async_trait]
impl DeliveryRules for ReplyRules {
    async fn evaluate(&self, input: &RulesInput) -> Result<RulesOutcome> {
        self.0
            .lock()
            .expect("lock")
            .push((input.recipient.clone(), input.peer.reply));
        Ok(RulesOutcome::implicit_keep())
    }
}

impl ReplyRules {
    fn calls(&self) -> Vec<(String, bool)> {
        self.0.lock().expect("lock").clone()
    }
}

/// Стоматометка: ключ `k1`, BATV в режиме `mode` (exempt — реальный адрес `bob@example.org`).
async fn rig(mode: BatvMode) -> (Env, Arc<ReplyMarks>, Arc<MemSentLog>, MemThreads) {
    let env = Env::new(DecisionHooks::default()).await;
    let store = MemSecretStore::new(Arc::new(SystemClock));
    store.set(
        &SecretRef::new("thepost/reply", "k1").expect("ref"),
        "a".repeat(32),
    );
    let marks = Arc::new(
        ReplyMarks::new(
            Arc::new(store),
            ReplyConfig {
                keys: vec![ReplyKeyConfig {
                    id: "k1".into(),
                    secret: SecretRef::new("thepost/reply", "k1").expect("ref"),
                    active: true,
                }],
                ..ReplyConfig::default()
            },
        )
        .with_batv(&BatvConfig {
            mode,
            exempt: vec!["bob@example.org".into()],
            ..BatvConfig::default()
        }),
    );
    (env, marks, Arc::new(MemSentLog::new()), MemThreads::new())
}

/// Проверки отправителя: домен партнёра `partner.example` (SPF — `192.0.2.0/24`, DMARC `p=none`).
fn partner_check() -> AuthCheck {
    let check = fx::checker();
    fx::publish_sender_domain(check.cache(), PARTNER, "none");
    check
}

/// Доставка с меткой, записью об отправленном, беседами и проверками отправителя.
async fn delivery(
    env: &Env,
    marks: &Arc<ReplyMarks>,
    sent: &Arc<MemSentLog>,
    threads: &MemThreads,
) -> Delivery {
    let mut d = env
        .delivery(false)
        .with_reply_marks(marks.clone())
        .with_sent_log(sent.clone())
        .with_threads(Arc::new(threads.clone()));
    d.deps.authcheck = Some(Arc::new(partner_check()));
    d
}

/// Запись об отправленном нами письме: Message-ID — метка узла, адресат — `recipient`; `age` назад.
async fn sent_marked(
    marks: &ReplyMarks,
    sent: &MemSentLog,
    recipient: &str,
    age: time::Duration,
) -> String {
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

/// Запись письма клиента (Message-ID без метки узла) — поиск ответа по хэшу.
async fn sent_client_id(sent: &MemSentLog, message_id: &str, recipient: &str, age: time::Duration) {
    sent.record(SentRecord {
        tenant: TenantId::DEFAULT,
        account: AccountId::new(),
        tag: vec![1u8; 16],
        message_id_hash: ReplyMarks::hash_of(message_id),
        recipients: vec![normalize_recipient(recipient).expect("rcpt")],
        thread: None,
        sent_at: OffsetDateTime::now_utc() - age,
    })
    .await
    .expect("record");
}

/// Ответ `from` на письмо `references` (значение заголовка целиком или пусто).
fn reply_letter(from: &str, references: &str) -> Bytes {
    Bytes::from(format!(
        "From: {from}\r\nTo: alice@example.org\r\nSubject: Re: hi\r\n{references}\r\n\r\nanswer\r\n"
    ))
}

/// Входящий конверт с клиента `ip` и отправителем конверта `mail_from`.
fn inbound(ip: &str, mail_from: &str, rcpt: &str) -> Envelope {
    let mut e = fx::envelope(ip);
    e.mail_from = mail_from.into();
    e.rcpts = vec![rcpt.into()];
    e
}

const CLIENT_OK: &str = "192.0.2.10:1000";
const CLIENT_BAD: &str = "203.0.113.5:1000";

// ---------- Признак «ответ на наше письмо» ----------

/// Ответ внешнего адресата на наше письмо (метка в `In-Reply-To`) с пройденным DMARC — признак есть.
#[tokio::test]
async fn reply_from_recipient_is_flagged() {
    let (env, marks, sent, threads) = rig(BatvMode::Log).await;
    let mid = sent_marked(
        &marks,
        &sent,
        "bob@partner.example",
        time::Duration::minutes(5),
    )
    .await;
    let rules = Arc::new(ReplyRules::default());
    let d = delivery(&env, &marks, &sent, &threads)
        .await
        .with_rules(rules.clone());
    let raw = reply_letter("bob@partner.example", &format!("In-Reply-To: <{mid}>\r\n"));
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
    assert!(got[0].contains("X-ThePost-Reply: yes"), "{}", got[0]);
    // Признак видят правила ([`PeerContext::reply`], CTR-94).
    assert_eq!(rules.calls(), vec![("alice@example.org".into(), true)]);
}

/// Условия признака все сразу: не-адресат записи, DMARC fail, старше `max_age`, чужой ключ и подделанная
/// метка — признака нет.
#[tokio::test]
async fn reply_flag_needs_every_condition() {
    let (env, marks, sent, threads) = rig(BatvMode::Log).await;

    // Не адресат записи (письмо ушли carol, отвечает bob).
    let mid = sent_marked(
        &marks,
        &sent,
        "carol@partner.example",
        time::Duration::minutes(5),
    )
    .await;
    let d = delivery(&env, &marks, &sent, &threads).await;
    let raw = reply_letter("bob@partner.example", &format!("In-Reply-To: <{mid}>\r\n"));
    assert_eq!(
        d.data(
            &inbound(CLIENT_OK, "bob@partner.example", "alice@example.org"),
            raw
        )
        .await
        .code,
        250
    );

    // DMARC не пройден (клиент вне SPF домена отправителя) — метка и запись в порядке, всё решает DMARC.
    let mid = sent_marked(
        &marks,
        &sent,
        "bob@partner.example",
        time::Duration::minutes(5),
    )
    .await;
    let raw = reply_letter("bob@partner.example", &format!("In-Reply-To: <{mid}>\r\n"));
    assert_eq!(
        d.data(
            &inbound(CLIENT_BAD, "bob@partner.example", "alice@example.org"),
            raw
        )
        .await
        .code,
        250
    );

    // Исходное письмо старше `smtp.reply.max_age` (30 дней).
    let mid = sent_marked(
        &marks,
        &sent,
        "bob@partner.example",
        time::Duration::days(31),
    )
    .await;
    let raw = reply_letter("bob@partner.example", &format!("In-Reply-To: <{mid}>\r\n"));
    assert_eq!(
        d.data(
            &inbound(CLIENT_OK, "bob@partner.example", "alice@example.org"),
            raw
        )
        .await
        .code,
        250
    );

    // Чужой ключ (id вне набора) и подделанная метка (испорчен payload).
    let raw = reply_letter(
        "bob@partner.example",
        "In-Reply-To: <tp1.k2.ABCDEFGH@example.org>\r\n",
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
    let (valid, _) = marks
        .message_id("example.org", OffsetDateTime::now_utc())
        .await
        .expect("mark")
        .expect("mark");
    let (local, domain) = valid.split_once('@').expect("split");
    let mut broken = local.to_owned();
    let last = broken.pop().expect("non-empty");
    broken.push(if last == 'A' { 'B' } else { 'A' });
    let raw = reply_letter(
        "bob@partner.example",
        &format!("In-Reply-To: <{broken}@{domain}>\r\n"),
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

    // Ни одного письма: пять доставок без признака.
    let got = env.inbox("alice@example.org").await;
    assert_eq!(got.len(), 5);
    for raw in &got {
        assert!(!raw.contains("X-ThePost-Reply"), "{}", raw);
    }
}

/// Ответ на письмо с Message-ID клиента — признак по хэшу в записи об отправленном.
#[tokio::test]
async fn reply_to_client_message_id_by_hash() {
    let (env, marks, sent, threads) = rig(BatvMode::Log).await;
    sent_client_id(
        &sent,
        "client-1@mail.example.net",
        "bob@partner.example",
        time::Duration::minutes(5),
    )
    .await;
    let d = delivery(&env, &marks, &sent, &threads).await;
    // Хэш ищется без учёта регистра и скобок (каноническая форма).
    let raw = reply_letter(
        "bob@partner.example",
        "In-Reply-To: <CLIENT-1@Mail.Example.Net>\r\n",
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
    // `References` тоже проверяется, если `In-Reply-To` не подтвердился.
    let raw = reply_letter(
        "bob@partner.example",
        "In-Reply-To: <unknown@mail.example.net>\r\nReferences: <client-1@mail.example.net>\r\n",
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
    // От не-адресата записи — нет.
    let raw = reply_letter(
        "eve@partner.example",
        "In-Reply-To: <client-1@mail.example.net>\r\n",
    );
    assert_eq!(
        d.data(
            &inbound(CLIENT_OK, "eve@partner.example", "alice@example.org"),
            raw
        )
        .await
        .code,
        250
    );
    let got = env.inbox("alice@example.org").await;
    assert_eq!(got.len(), 3);
    assert!(got[0].contains("X-ThePost-Reply: yes"), "{}", got[0]);
    assert!(got[1].contains("X-ThePost-Reply: yes"), "{}", got[1]);
    assert!(!got[2].contains("X-ThePost-Reply"), "{}", got[2]);
}

/// Пришедший извне `X-ThePost-Reply` удаляется до проверок — признак ставит только узел.
#[tokio::test]
async fn inbound_reply_header_is_removed() {
    let (env, marks, sent, threads) = rig(BatvMode::Log).await;
    let d = delivery(&env, &marks, &sent, &threads).await;
    let raw = Bytes::from(
        "X-ThePost-Reply: yes\r\nFrom: bob@partner.example\r\nTo: alice@example.org\r\n\
         Subject: hi\r\n\r\nno reply here\r\n",
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
    assert!(!got[0].contains("X-ThePost-Reply"), "{}", got[0]);
}

/// Ответ с карантином фильтра (антивирус) — в «Спам» при любом признаке ответа.
#[tokio::test]
async fn reply_with_virus_is_junk_despite_flag() {
    let (env, marks, sent, threads) = rig(BatvMode::Log).await;
    let mid = sent_marked(
        &marks,
        &sent,
        "bob@partner.example",
        time::Duration::minutes(5),
    )
    .await;
    let virus = mt::Mock::start(
        0,
        mt::on_eob(vec![Packet::strings(
            proto::R_QUARANTINE,
            &[b"virus found"],
        )]),
    )
    .await;
    let mut d = delivery(&env, &marks, &sent, &threads).await;
    d.deps.milter = Some(Arc::new(Milters::new(
        crate::config::MilterConfig {
            filters: vec![virus.filter("av")],
            ..crate::config::MilterConfig::default()
        },
        "mx.example.org",
    )));
    let raw = reply_letter("bob@partner.example", &format!("In-Reply-To: <{mid}>\r\n"));
    assert_eq!(
        d.data(
            &inbound(CLIENT_OK, "bob@partner.example", "alice@example.org"),
            raw
        )
        .await
        .code,
        250
    );
    assert!(env.inbox("alice@example.org").await.is_empty());
    assert_eq!(env.junk("alice@example.org").await, 1);
}

// ---------- BATV ----------

/// Bounce (`MAIL FROM: <>`) на локальный адрес без метки: `550 5.7.1` в `enforce`, доставка в `log`;
/// адрес из `smtp.batv.exempt` метки не требует.
#[tokio::test]
async fn batv_bounce_rejected_in_enforce_only() {
    let (env, marks, sent, threads) = rig(BatvMode::Enforce).await;
    let d = delivery(&env, &marks, &sent, &threads).await;
    let e = inbound(CLIENT_OK, "", "alice@example.org");
    assert_eq!(
        d.rcpt(&e, "alice@example.org").await.code,
        550,
        "нет метки в enforce"
    );
    assert_eq!(
        d.rcpt(&e, "prvs=9ABC123XYZ=alice@example.org").await.code,
        550,
        "чужой ключ"
    );
    // exempt: метка не требуется (в наборе — реальный адрес учётной записи).
    assert_eq!(d.rcpt(&e, "bob@example.org").await.code, 250);

    // Тот же bounce в `log` — доставляется (только журнал и метрика).
    let (env, marks, sent, threads) = rig(BatvMode::Log).await;
    let d = delivery(&env, &marks, &sent, &threads).await;
    let e = inbound(CLIENT_OK, "", "alice@example.org");
    assert_eq!(d.rcpt(&e, "alice@example.org").await.code, 250);
}

/// Bounce на адрес с валидной меткой: доставлен, адрес — без метки; тот же bounce на адрес без метки
/// отклоняется.
#[tokio::test]
async fn batv_valid_mark_is_stripped_and_delivered() {
    let (env, marks, sent, threads) = rig(BatvMode::Enforce).await;
    let batv = marks.batv().expect("batv");
    let tagged = batv
        .sign("alice@example.org", OffsetDateTime::now_utc())
        .await
        .expect("sign")
        .expect("tagged");
    let d = delivery(&env, &marks, &sent, &threads).await;
    // RCPT: валидная метка снимается — bounce принят.
    let e = inbound(CLIENT_OK, "", "alice@example.org");
    assert_eq!(d.rcpt(&e, &tagged).await.code, 250);
    assert_eq!(
        d.rcpt(&e, "alice@example.org").await.code,
        550,
        "тот же адрес без метки — отказ"
    );
    // Доставка bounce по адресу с меткой — письмо у alice (приёмка сняла метку).
    let raw = Bytes::from_static(
        b"From: MAILER-DAEMON@example.net\r\nSubject: Undelivered\r\n\r\nbounce\r\n",
    );
    let data_env = inbound(CLIENT_OK, "", tagged.as_str());
    assert_eq!(d.data(&data_env, raw).await.code, 250);
    let got = env.inbox("alice@example.org").await;
    assert_eq!(got.len(), 1);
}

/// Метка BATV одна и та же в повторах одного письма: подпись детерминирована (тот же отправитель и момент).
#[tokio::test]
async fn batv_mark_is_stable_for_the_same_letter() {
    let (_env, marks, _sent, _threads) = rig(BatvMode::Log).await;
    let batv = marks.batv().expect("batv");
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000).expect("time");
    let first = batv
        .sign("alice@example.org", now)
        .await
        .expect("sign")
        .expect("tagged");
    for _ in 0..3 {
        assert_eq!(
            batv.sign("alice@example.org", now).await.expect("sign"),
            Some(first.clone()),
            "повтор и greylisting видят ту же метку"
        );
    }
}

// ---------- Память беседы ----------

/// Письмо с вложением, ссылкой и `Reply-To` — память беседы получателя получает все три.
#[tokio::test]
async fn thread_memory_after_reply() {
    let (env, marks, sent, threads) = rig(BatvMode::Log).await;
    let mid = sent_marked(
        &marks,
        &sent,
        "bob@partner.example",
        time::Duration::minutes(5),
    )
    .await;
    let d = delivery(&env, &marks, &sent, &threads).await;
    let raw = Bytes::from(format!(
        "From: bob@{PARTNER}\r\nTo: alice@example.org\r\nSubject: Re: docs\r\n\
         In-Reply-To: <{mid}>\r\nReply-To: news@example.net\r\nMIME-Version: 1.0\r\n\
         Content-Type: multipart/mixed; boundary=m\r\n\r\n\
         --m\r\nContent-Type: text/plain\r\n\r\nsee https://links.example.net/page\r\n\
         --m\r\nContent-Type: text/html\r\n\r\n\
         <html><body><a href=\"https://links.example.net/page\">link</a>\
         <a href=\"http://OTHER.Example.Net/\">x</a></body></html>\r\n\
         --m\r\nContent-Type: application/pdf; name=\"doc.pdf\"\r\n\
         Content-Disposition: attachment; filename=\"doc.pdf\"\r\n\r\nMIMEDOC\r\n\
         --m--\r\n"
    ));
    assert_eq!(
        d.data(
            &inbound(CLIENT_OK, "bob@partner.example", "alice@example.org"),
            raw
        )
        .await
        .code,
        250
    );
    // Письмо привязано к беседе alice, память беседы — вложения, домены ссылок, `Reply-To`.
    let scope = env.scope("alice@example.org").await;
    let inbox = env
        .meta
        .mailbox_by_role(scope, SpecialUse::Inbox)
        .expect("inbox");
    let messages = MessageStore::list(&env.meta, scope, inbox, MessageQuery::All, 10)
        .await
        .expect("list");
    assert_eq!(messages.len(), 1);
    let thread = threads
        .thread_of(scope, messages[0].id)
        .await
        .expect("thread_of")
        .expect("bound");
    let facts = threads.facts(scope, thread).await.expect("facts");
    assert_eq!(facts.attachments, vec!["application/pdf"]);
    assert_eq!(
        facts.link_domains,
        vec![
            "links.example.net".to_owned(),
            "other.example.net".to_owned()
        ],
        "канонические имена, нижний регистр"
    );
    assert_eq!(facts.reply_to, vec!["news@example.net".to_owned()]);
}
