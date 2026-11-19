//! Волна smtp-35: спам — максимально рано мимо всех автоматических механизмов и без ручного iTIP (SMTP-55,
//! решение #112): письмо со спам-вердиктом лежит в «Спаме», и больше с ним ничего не происходит; ручной
//! accept/tentative/decline/counter (REPLY или `COUNTER` письма клиента) в ответ на письмо из «Спама» сервер
//! отклоняет — после переноса письма из «Спама» всё работает.

use std::collections::BTreeSet;

use tp_contracts::MessageId;
use tp_contracts::meta::{Flag, Flags};
use tp_contracts::senders::{SenderList, SenderLists};
use tp_contracts::sieve::{
    AutoReply, KeepTo, MailboxRef, ProcessCalendar, ReplyBody, RulesOutcome,
};
use tp_testkit::{FakeItip, FakeRules, MemSenderLists};

use super::*;

const ALICE: &str = "alice@example.org";
const BOB: &str = "bob@example.org";

/// Списки отправителей ящика `login`: `blocked` — адреса заблокированных (письмо от них — спам).
async fn blocked(env: &Env, login: &str, blocked: &[&str]) -> Arc<MemSenderLists> {
    let lists = Arc::new(MemSenderLists::new());
    SenderLists::put_sender_list(
        lists.as_ref(),
        env.scope(login).await,
        SenderList {
            safe: Vec::new(),
            blocked: blocked.iter().map(|a| (*a).to_owned()).collect(),
        },
    )
    .await
    .expect("put");
    lists
}

/// Приглашение alice участнику bob (`Message-ID` — для `In-Reply-To` ответа).
fn invite() -> String {
    format!(
        "From: Alice <{ALICE}>\r\nTo: {BOB}\r\nSubject: Приглашение\r\nMessage-ID: <invite-1@example.org>\r\n\
         MIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\n\
         Content-Type: text/plain\r\n\r\nmeeting\r\n--b\r\n\
         Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\nBEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:u1\r\nDTSTAMP:20261112T100000Z\r\n\
         DTSTART:20261113T100000Z\r\nORGANIZER:mailto:{ALICE}\r\nATTENDEE:mailto:{BOB}\r\nEND:VEVENT\r\n\
         END:VCALENDAR\r\n--b--\r\n"
    )
}

/// Ответ bob организатору alice (`In-Reply-To` — приглашение): accept (`REPLY`, `PARTSTAT=ACCEPTED`).
fn accept() -> String {
    format!(
        "From: Bob <{BOB}>\r\nTo: {ALICE}\r\nSubject: Принято: Приглашение\r\n\
         In-Reply-To: <invite-1@example.org>\r\nMIME-Version: 1.0\r\n\
         Content-Type: text/calendar; method=REPLY; charset=utf-8\r\n\r\nBEGIN:VCALENDAR\r\n\
         VERSION:2.0\r\nMETHOD:REPLY\r\nBEGIN:VEVENT\r\nUID:u1\r\nDTSTAMP:20261112T100000Z\r\n\
         DTSTART:20261113T100000Z\r\nORGANIZER:mailto:{ALICE}\r\n\
         ATTENDEE;PARTSTAT=ACCEPTED:mailto:{BOB}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

/// Вошедший пользователь `login` (submission, `Delivery::submit`).
async fn user(env: &Env, login: &str) -> Principal {
    let scope = env.scope(login).await;
    Principal {
        tenant: scope.tenant,
        account: scope.account,
        login: login.to_owned(),
        groups: BTreeSet::new(),
        scopes: None,
    }
}

/// Доставка приглашения alice участнику bob через smtp-in.
async fn deliver_invite(d: &Delivery) {
    let mut e = envelope(Mode::Inbound, &[BOB]);
    e.mail_from = ALICE.into();
    assert_eq!(d.data(&e, Bytes::from(invite())).await.code, 250);
}

/// Переносит все письма папки «Спам» учётной записи `login` во «Входящие» (ручной перенос пользователя).
async fn move_out_of_junk(env: &Env, login: &str) {
    let scope = env.scope(login).await;
    let inbox = env
        .meta
        .mailbox_by_role(scope, SpecialUse::Inbox)
        .expect("inbox");
    let junk = env
        .meta
        .mailbox_by_role(scope, SpecialUse::Junk)
        .expect("junk");
    let ids: Vec<MessageId> = MessageStore::list(&env.meta, scope, junk, MessageQuery::All, 100)
        .await
        .expect("list")
        .into_iter()
        .map(|m| m.id)
        .collect();
    MessageStore::move_to(&env.meta, scope, &ids, inbox)
        .await
        .expect("move");
}

/// Приёмка: письмо со спам-вердиктом — автоответ не генерируется, Sieve-действия (включая `processcalendar`)
/// не применяются, перенаправления и DSN нет, приём iTIP не вызывается; письмо — в «Спаме», и только.
/// Соседнему получателю без вердикта те же правила применяются.
#[tokio::test]
async fn junk_mail_bypasses_all_automatic_mechanisms() {
    let env = Env::new(DecisionHooks::default()).await;
    let lists = blocked(&env, BOB, &[ALICE]).await;
    let rules = FakeRules::new();
    rules.set(
        BOB,
        RulesOutcome {
            keep: vec![KeepTo {
                mailbox: MailboxRef::Name {
                    name: "Work".into(),
                    create: true,
                },
                flags: [Flag::Flagged].into_iter().collect(),
            }],
            redirect: vec!["carol@partner.example".into()],
            vacation: Some(AutoReply {
                to: ALICE.into(),
                from: BOB.into(),
                subject: "Автоответ".into(),
                body: ReplyBody::Text("Я в отпуске".into()),
                in_reply_to: Some("<invite-1@example.org>".into()),
                references: vec!["<invite-1@example.org>".into()],
            }),
            calendar: Some(ProcessCalendar::default()),
            ..RulesOutcome::default()
        },
    );
    rules.set(
        "carol@example.org",
        RulesOutcome {
            keep: vec![KeepTo {
                mailbox: MailboxRef::Name {
                    name: "Work".into(),
                    create: true,
                },
                flags: Flags::new(),
            }],
            ..RulesOutcome::default()
        },
    );
    let itip = FakeItip::new();
    let d = env
        .delivery(true)
        .with_sender_lists(lists)
        .with_rules(Arc::new(rules.clone()))
        .with_itip(Arc::new(itip.clone()))
        .with_trust(Arc::new(
            trust(
                &[],
                tp_contracts::trust::GroupPost::Open,
                &["partner.example"],
            )
            .await,
        ));
    deliver_invite(&d).await;

    // Письмо — в «Спаме», и только: ни `fileinto`, ни перенаправления, ни автоответа, ни приёма iTIP.
    assert_eq!(env.junk(BOB).await, 1);
    assert!(env.inbox(BOB).await.is_empty());
    assert!(
        rules.calls().iter().all(|c| c.recipient != BOB),
        "{:?}",
        rules.calls()
    );
    assert!(env.queue.0.lock().expect("lock").is_empty());
    assert!(itip.calls().is_empty());

    // Тот же вердикт не действует на получателя без спама: его правила применяются.
    let mut e = envelope(Mode::Inbound, &["carol@example.org"]);
    e.mail_from = ALICE.into();
    assert_eq!(d.data(&e, Bytes::from(invite())).await.code, 250);
    assert!(
        rules
            .calls()
            .iter()
            .any(|c| c.recipient == "carol@example.org"),
        "{:?}",
        rules.calls()
    );
    assert_eq!(env.junk("carol@example.org").await, 0);
}

/// Приёмка: iTIP-обработка (accept) письма из «Спам» отклоняется сервером — приглашение не вносится, клиент
/// получает отказ (submission `550`); то же письмо после переноса из «Спама» — обрабатывается. Вердикт виден и
/// на приёме: письмо со спам-вердиктом приём iTIP не вызывается.
#[tokio::test]
async fn manual_itip_accept_refused_while_invitation_in_junk() {
    let env = Env::new(DecisionHooks::default()).await;
    let lists = blocked(&env, BOB, &[ALICE]).await;
    let itip = FakeItip::new();
    let d = env
        .delivery(false)
        .with_sender_lists(lists)
        .with_itip(Arc::new(itip.clone()))
        .with_messages(Arc::new(env.meta.clone()));

    // Приглашение — в «Спаме» (вердикт): приём iTIP не вызывается.
    deliver_invite(&d).await;
    assert_eq!(env.junk(BOB).await, 1);
    assert!(itip.calls().is_empty());

    // Ответ клиента (accept) через submission — отказ: приглашение из «Спама» руками не принять.
    let mut e = envelope(Mode::Submission, &[ALICE]);
    e.mail_from = BOB.into();
    e.principal = Some(user(&env, BOB).await);
    let r = d.data(&e, Bytes::from(accept())).await;
    assert_eq!((r.code, r.esc), (550, [5, 7, 1]), "{r:?}");
    assert!(itip.calls().is_empty());

    // То же письмо после переноса из «Спама» — обрабатывается.
    move_out_of_junk(&env, BOB).await;
    let mut e = envelope(Mode::Submission, &[ALICE]);
    e.mail_from = BOB.into();
    e.principal = Some(user(&env, BOB).await);
    let r = d.data(&e, Bytes::from(accept())).await;
    assert_eq!(r.code, 250, "{r:?}");
    let calls = itip.calls();
    assert_eq!(calls.len(), 1, "{calls:?}");
    assert_eq!(calls[0].method, ItipMethod::Reply);
    assert_eq!(calls[0].to, ALICE);
    assert_eq!(calls[0].from, BOB);
}

/// Приёмка: отправка вне сессии SMTP (JMAP `EmailSubmission`) — тот же отказ ручного iTIP из «Спама»:
/// `SubmitStatus::Failed` с `550 5.7.1`; после переноса письма из «Спама» — доставлено, приём вызван.
#[tokio::test]
async fn manual_itip_submit_refused_while_invitation_in_junk() {
    let env = Env::new(DecisionHooks::default()).await;
    let lists = blocked(&env, BOB, &[ALICE]).await;
    let itip = FakeItip::new();
    let d = env
        .delivery(false)
        .with_sender_lists(lists)
        .with_itip(Arc::new(itip.clone()))
        .with_messages(Arc::new(env.meta.clone()));
    deliver_invite(&d).await;

    let bob = user(&env, BOB).await;
    let sent = d
        .submit(
            TenantId::DEFAULT,
            None,
            Some(&bob),
            BOB,
            &rcpts(&[ALICE]),
            Bytes::from(accept()),
        )
        .await
        .expect("submit");
    assert_eq!(
        sent.rcpts,
        [(
            ALICE.to_owned(),
            SubmitStatus::Failed(
                "550 5.7.1 Scheduling response refused: invitation is in the Junk folder".into()
            )
        )],
        "{:?}",
        sent.rcpts
    );
    assert!(itip.calls().is_empty());

    move_out_of_junk(&env, BOB).await;
    let sent = d
        .submit(
            TenantId::DEFAULT,
            None,
            Some(&bob),
            BOB,
            &rcpts(&[ALICE]),
            Bytes::from(accept()),
        )
        .await
        .expect("submit");
    assert_eq!(sent.rcpts, [(ALICE.to_owned(), SubmitStatus::Delivered)]);
    assert_eq!(itip.calls().len(), 1);
}
