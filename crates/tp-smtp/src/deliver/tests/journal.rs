//! Волна smtp-33: этап журналирования конвейера (SMTP-53) — правила организации, группы и ящики, оба
//! направления, полный конверт записи (скрытые получатели, раскрытые группы), `discard` скрипта ящика
//! запись не отменяет, служебные письма повторно не журналируются.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tp_contracts::groups::{DistributionGroup, GroupMember, GroupStore, SenderRestriction};
use tp_contracts::journal::{
    JournalAudit, JournalDirection, JournalEntry, JournalQuery, JournalRule, JournalScope,
};
use tp_contracts::sieve::{AutoReply, ReplyBody, RulesOutcome};
use tp_contracts::{GroupId, Result, TenantId};
use tp_testkit::{FakeRules, MemJournal};

use super::*;
use crate::deliver::journal::{JournalRules, Journaling};
use crate::groups::Groups;

/// Правила журналирования в памяти: правила организации, меняются без перезапуска (SRS 2.8).
#[derive(Default)]
struct MemRules(Mutex<Vec<JournalRule>>);

impl MemRules {
    fn set(&self, rule: JournalRule) {
        self.0.lock().expect("lock").push(rule);
    }
}

#[async_trait]
impl JournalRules for MemRules {
    async fn rules(&self, _: TenantId) -> Result<Vec<JournalRule>> {
        Ok(self.0.lock().expect("lock").clone())
    }
}

/// Правило журналирования организации узла.
fn rule(id: &str, scope: JournalScope, direction: JournalDirection, enabled: bool) -> JournalRule {
    JournalRule {
        id: id.into(),
        tenant: TenantId::DEFAULT,
        scope,
        direction,
        enabled,
    }
}

/// Доставка с этапом журналирования (SMTP-53) и журналом `journal`.
fn journaled(env: &Env, rules: &MemRules, journal: &MemJournal) -> Delivery {
    env.delivery(true).with_journal(Journaling::new(
        Arc::new(MemRules(rules.0.lock().expect("lock").clone())),
        Arc::new(journal.clone()),
    ))
}

/// Записи журнала в порядке добавления.
async fn entries(journal: &MemJournal) -> Vec<JournalEntry> {
    journal
        .search(
            &JournalAudit::grant(),
            &JournalQuery::all(TenantId::DEFAULT, 100),
        )
        .await
        .expect("search")
        .entries
}

/// Письмо с получателем `to` в заголовке (скрытые получатели — только в конверте).
fn letter(tag: &str, to: &str) -> Bytes {
    Bytes::from(format!(
        "From: sender@example.net\r\nTo: {to}\r\nSubject: {tag}\r\nMessage-ID: <{tag}@example.net>\r\n\r\nbody\r\n"
    ))
}

/// Правило организации Both: входящее письмо — запись In с полным конвертом (скрытый получатель конверта —
/// в записи), отправка клиентом — запись Out; одно правило — по одной записи на письмо.
#[tokio::test]
async fn org_rule_journals_both_directions_with_full_envelope() {
    let env = Env::new(DecisionHooks::default()).await;
    let rules = MemRules::default();
    rules.set(rule(
        "r-0042",
        JournalScope::Org,
        JournalDirection::Both,
        true,
    ));
    let journal = MemJournal::new();
    let d = journaled(&env, &rules, &journal);

    // Входящее: carol — скрытый получатель (Bcc): в конверте, не в заголовках.
    let e = envelope(Mode::Inbound, &["alice@example.org", "carol@example.org"]);
    assert_eq!(
        d.data(&e, letter("m1", "alice@example.org")).await.code,
        250
    );
    // Исходящее (JMAP EmailSubmission — `Delivery::submit`).
    d.submit(
        TenantId::DEFAULT,
        None,
        None,
        "alice@example.org",
        &["bob@example.org".into()],
        letter("m2", "bob@example.org"),
    )
    .await
    .expect("submit");

    let rs = entries(&journal).await;
    assert_eq!(rs.len(), 2, "по одной записи на письмо");
    assert_eq!(rs[0].record.sender, "sender@example.net");
    assert_eq!(
        rs[0].record.recipients,
        vec!["alice@example.org", "carol@example.org"],
        "скрытый получатель конверта — в записи"
    );
    assert_eq!(rs[0].record.message_id.as_deref(), Some("m1@example.net"));
    assert_eq!(rs[0].record.rule, "r-0042");
    assert_eq!(rs[1].record.sender, "alice@example.org");
    assert_eq!(rs[1].record.recipients, vec!["bob@example.org"]);
    // Письмо целиком — в записи (выгрузка .eml с конвертом).
    let eml = journal
        .export(&JournalAudit::grant(), TenantId::DEFAULT, rs[0].id)
        .await
        .expect("export");
    let text = String::from_utf8_lossy(&eml);
    assert!(text.contains("X-ThePost-Journal-Rule: r-0042"));
    assert!(text.contains("Subject: m1"));
}

/// Правило на ящик: журналируются письма ящика (отправитель или получатель), чужие — нет; выключенное
/// правило и правило другого направления не срабатывают.
#[tokio::test]
async fn mailbox_rule_covers_sender_or_recipient() {
    let env = Env::new(DecisionHooks::default()).await;
    let alice = env.scope("alice@example.org").await.account;
    let rules = MemRules::default();
    rules.set(rule(
        "r-mailbox",
        JournalScope::Mailbox(alice),
        JournalDirection::Both,
        true,
    ));
    rules.set(rule(
        "r-off",
        JournalScope::Org,
        JournalDirection::Both,
        false,
    ));
    let journal = MemJournal::new();
    let d = journaled(&env, &rules, &journal);

    // Письмо bob — мимо правила; правило r-off выключено.
    let e = envelope(Mode::Inbound, &["bob@example.org"]);
    assert_eq!(d.data(&e, letter("m1", "bob@example.org")).await.code, 250);
    assert!(entries(&journal).await.is_empty());

    // Получатель alice — запись.
    let e = envelope(Mode::Inbound, &["alice@example.org"]);
    assert_eq!(
        d.data(&e, letter("m2", "alice@example.org")).await.code,
        250
    );
    assert_eq!(entries(&journal).await.len(), 1);

    // Направление: правило In не журналирует отправку клиентом.
    let rules_in = MemRules::default();
    rules_in.set(rule(
        "r-in",
        JournalScope::Mailbox(alice),
        JournalDirection::In,
        true,
    ));
    let journal_in = MemJournal::new();
    let d = journaled(&env, &rules_in, &journal_in);
    d.submit(
        TenantId::DEFAULT,
        None,
        None,
        "alice@example.org",
        &["bob@example.org".into()],
        letter("m3", "bob@example.org"),
    )
    .await
    .expect("submit");
    assert!(
        entries(&journal_in).await.is_empty(),
        "исходящее — мимо правила In"
    );
}

/// Группа в получателях раскрыта в записи (учётные записи членов, включая вложенную группу); правило на
/// группу срабатывает по членству отправителя или получателя.
#[tokio::test]
async fn group_recipients_expanded_and_group_rule() {
    let env = Env::new(DecisionHooks::default()).await;
    let alice = env.scope("alice@example.org").await.account;
    // Группа Groups с участником alice — область правила.
    let group = DistributionGroup {
        id: GroupId::new(),
        tenant: TenantId::DEFAULT,
        name: "team".into(),
        address: Some("team@example.org".into()),
        external_id: None,
        members: vec![GroupMember::Account(alice)],
        senders: SenderRestriction::Anyone,
        moderators: Vec::new(),
        hidden_from_gal: false,
    };
    env.groups.put(group.clone()).await.expect("put group");
    let rules = MemRules::default();
    rules.set(rule(
        "r-group",
        JournalScope::Group(group.id),
        JournalDirection::Both,
        true,
    ));
    let journal = MemJournal::new();
    let d = journaled(&env, &rules, &journal).with_groups(Groups::new(
        Arc::new(env.groups.clone()),
        Arc::new(env.blobs.clone()),
        Arc::new(env.index.clone()),
    ));

    // Письмо внешнего отправителя в группу каталога `all@example.org` (alice, bob — члены g-team, carol —
    // g-all): члены раскрыты в записи, адрес группы — тоже.
    let e = envelope(Mode::Inbound, &["all@example.org"]);
    assert_eq!(d.data(&e, letter("m1", "all@example.org")).await.code, 250);
    let rs = entries(&journal).await;
    assert_eq!(
        rs.len(),
        1,
        "получатель-член группы (alice) — правило сработало"
    );
    for address in [
        "all@example.org",
        "alice@example.org",
        "bob@example.org",
        "carol@example.org",
    ] {
        assert!(
            rs[0]
                .record
                .recipients
                .iter()
                .any(|r| r.eq_ignore_ascii_case(address)),
            "{address} раскрыт в записи: {:?}",
            rs[0].record.recipients
        );
    }

    // Чужое письмо (никто из конверта — не член группы) — мимо правила.
    let e = envelope(Mode::Inbound, &["bob@example.org"]);
    assert_eq!(d.data(&e, letter("m2", "bob@example.org")).await.code, 250);
    assert_eq!(entries(&journal).await.len(), 1);
}

/// `discard` в скрипте ящика не отменяет запись: письмо журналируется до Sieve (CTR-96: этап ядра —
/// первый в точке BeforeMailboxSieve); копия письма остаётся в записи.
#[tokio::test]
async fn sieve_discard_does_not_cancel_record() {
    let env = Env::new(DecisionHooks::default()).await;
    let rules = MemRules::default();
    rules.set(rule(
        "r-0042",
        JournalScope::Org,
        JournalDirection::In,
        true,
    ));
    let journal = MemJournal::new();
    let sieve = FakeRules::new();
    sieve.set(
        "alice@example.org",
        RulesOutcome {
            discard: true,
            ..RulesOutcome::default()
        },
    );
    let d = journaled(&env, &rules, &journal).with_rules(Arc::new(sieve));

    let e = envelope(Mode::Inbound, &["alice@example.org"]);
    assert_eq!(
        d.data(&e, letter("m1", "alice@example.org")).await.code,
        250
    );
    assert!(
        env.inbox("alice@example.org").await.is_empty(),
        "письмо отброшено скриптом"
    );
    let rs = entries(&journal).await;
    assert_eq!(rs.len(), 1, "запись не отменена скриптом ящика");
    let eml = journal
        .export(&JournalAudit::grant(), TenantId::DEFAULT, rs[0].id)
        .await
        .expect("export");
    assert!(String::from_utf8_lossy(&eml).contains("Subject: m1"));
}

/// Служебные письма продукта повторно не журналируются: автоответ правил (отбивка) не даёт записи;
/// письмо без правил журнала — тоже.
#[tokio::test]
async fn system_messages_are_not_journaled_again() {
    let env = Env::new(DecisionHooks::default()).await;
    let rules = MemRules::default();
    rules.set(rule(
        "r-0042",
        JournalScope::Org,
        JournalDirection::Both,
        true,
    ));
    let journal = MemJournal::new();
    let sieve = FakeRules::new();
    sieve.set(
        "alice@example.org",
        RulesOutcome {
            vacation: Some(AutoReply {
                to: "sender@example.net".into(),
                from: "alice@example.org".into(),
                subject: "away".into(),
                body: ReplyBody::Text("out of office".into()),
                in_reply_to: None,
                references: Vec::new(),
            }),
            ..RulesOutcome::implicit_keep()
        },
    );
    let d = journaled(&env, &rules, &journal).with_rules(Arc::new(sieve));

    let e = envelope(Mode::Inbound, &["alice@example.org"]);
    assert_eq!(
        d.data(&e, letter("m1", "alice@example.org")).await.code,
        250
    );
    assert_eq!(
        env.queue.0.lock().expect("lock").len(),
        1,
        "автоответ ушёл в очередь"
    );
    assert_eq!(
        entries(&journal).await.len(),
        1,
        "автоответ — служебное письмо, повторной записи нет"
    );

    // Без правил этап не пишет ничего (правил нет — даже с подключённым журналом).
    let none = MemRules::default();
    let bare = MemJournal::new();
    let d = journaled(&env, &none, &bare);
    let e = envelope(Mode::Inbound, &["alice@example.org"]);
    assert_eq!(
        d.data(&e, letter("m2", "alice@example.org")).await.code,
        250
    );
    assert!(entries(&bare).await.is_empty());
}
