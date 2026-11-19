//! Беседа и политики беседы в приёме письма (MS-21, решение 125 е; CONTRACTS.md#Thread).
//!
//! После вставки писем одной транзакцией (`MessageStore::insert_batch`) приём привязывает каждое
//! письмо к беседе (`ThreadStore::bind`: `Message-ID`/`In-Reply-To`/`References` среди писем учётной
//! записи), пополняет память беседы для аномалий и применяет политики беседы (как EWS
//! `ApplyConversationAction`): удержание беседы накрывает новое письмо привязкой (окончательное
//! удаление запретит `ThreadHoldHook`, CTR-94), `AlwaysMove` переносит письмо в заданную папку
//! вместо выбранной правилами, `Ignore` — в корзину (окончательное удаление — по сроку корзины),
//! `AlwaysKeyword` ставит ключевое слово.
//!
//! Сбой привязки или политики откатывает приём целиком: письма удаляются компенсацией
//! (`to_trash` + `expunge_final`; счётчики объектов снимает удаление, `Store::release` не нужен).
//! В PostgreSQL «письмо + беседа + политики» — одна транзакция приёма, сбой откатывает её (META-86).

use tp_contracts::mailstore::Delivery;
use tp_contracts::meta::{AccountScope, Flag, FlagOp, Flags, Inserted, MessageStore};
use tp_contracts::thread::{ThreadRule, ThreadStore};
use tp_contracts::{Error, MailboxId, ModSeq, Result, TenantId, Uid};

use crate::meta::ThreadInput;

/// Итог политик беседы одной доставки: неизменён — [`Outcome::default`].
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Outcome {
    /// Конечная папка, UID и `ModSeq` письма, если политики их изменили (`AlwaysMove`, `Ignore`).
    pub placed: Option<(MailboxId, Uid, ModSeq)>,
    /// Папка, из которой письмо перенесено (уведомляется наравне с конечной).
    pub moved_from: Option<MailboxId>,
}

/// Привязывает письма доставок к беседам и применяет политики беседы (в порядке доставок).
/// Ошибка любой привязки, политики или переноса — ошибка приёма (вызывающий откатывает письма).
pub(crate) async fn bind_and_apply(
    threads: &dyn ThreadStore,
    messages: &dyn MessageStore,
    tenant: TenantId,
    deliveries: &[Delivery],
    inserted: &[Inserted],
    input: &ThreadInput,
) -> Result<Vec<Outcome>> {
    let keys: Vec<&str> = input.keys.iter().map(String::as_str).collect();
    let mut out = Vec::with_capacity(deliveries.len());
    for (d, ins) in deliveries.iter().zip(inserted) {
        let scope = AccountScope {
            tenant,
            account: d.account,
        };
        // Привязка (CTR-94): письмо — в беседу по ключам среди писем учётной записи, иначе новая
        // беседа; повторная привязка возвращает прежнюю. Удержание беседы накрывает новое письмо
        // привязкой: окончательное удаление запретит хук удержания.
        let thread = threads.bind(scope, ins.id, &keys).await?;
        // Память беседы для аномалий (решение 125 д) — тем же шагом приёма.
        threads.remember_facts(scope, thread, &input.facts).await?;
        let mut outcome = Outcome::default();
        match threads.rule(scope, thread).await? {
            // Папка вместо выбранной правилами; папки уже нет — правило пропускается: письмо доходит.
            Some(ThreadRule::AlwaysMove(to)) if to != d.mailbox => {
                match messages.move_to(scope, &[ins.id], to).await {
                    Ok(moved) => {
                        if let Some(m) = moved.first() {
                            outcome.placed = Some((to, m.uid, m.modseq));
                            outcome.moved_from = Some(d.mailbox);
                        }
                    }
                    Err(Error::NotFound) => {
                        tracing::warn!(account = %d.account, mailbox = %to, "mailstore: беседа переносится в удалённую папку, политика пропущена");
                    }
                    Err(e) => return Err(e),
                }
            }
            // «Игнорировать»: письмо — в корзину (окончательное удаление — по сроку корзины).
            Some(ThreadRule::Ignore) => {
                messages.to_trash(scope, &[ins.id]).await?;
                outcome.moved_from = Some(d.mailbox);
                outcome.placed = messages
                    .get(scope, ins.id)
                    .await?
                    .map(|m| (m.mailbox, m.uid, m.modseq));
            }
            // Ключевое слово (JMAP keyword, IMAP флаг) на письмо беседы.
            Some(ThreadRule::AlwaysKeyword(keyword)) => {
                let flags: Flags = [Flag::Keyword(keyword)].into();
                messages
                    .set_flags(scope, &[ins.id], FlagOp::Add(flags), None)
                    .await?;
            }
            _ => {}
        }
        out.push(outcome);
    }
    Ok(out)
}

/// Откат приёма (сбой беседы или её политик): вставленные письма — в корзину и окончательно
/// удаляются, счётчики объектов снимает удаление. Сбой отката — в журнал: письмо останется
/// до сверки (в PostgreSQL откатывает транзакция приёма, META-86).
pub(crate) async fn rollback(
    messages: &dyn MessageStore,
    tenant: TenantId,
    deliveries: &[Delivery],
    inserted: &[Inserted],
) {
    for (d, ins) in deliveries.iter().zip(inserted) {
        let scope = AccountScope {
            tenant,
            account: d.account,
        };
        let undone = async {
            messages.to_trash(scope, &[ins.id]).await?;
            messages.expunge_final(scope, &[ins.id]).await
        }
        .await;
        if let Err(e) = undone {
            tracing::error!(error = %e, message = %ins.id, "mailstore: сбой отката письма при сбое беседы");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use async_trait::async_trait;
    use time::OffsetDateTime;
    use tp_contracts::ext::DecisionHook;
    use tp_contracts::mailstore::{IngestRequest, MailStore};
    use tp_contracts::meta::{MailboxStore, MessageQuery, SpecialUse};
    use tp_contracts::thread::{ThreadFacts, ThreadHold, ThreadLimits};
    use tp_contracts::{AccountId, MessageId, TenantId, ThreadId};
    use tp_testkit::{Clock, MemThreads, SystemClock};

    use crate::testenv::{Env, stream};

    /// Письмо беседы: `mid` — собственный Message-ID, `parent` — In-Reply-To.
    fn letter(mid: &str, parent: Option<&str>) -> Vec<u8> {
        let mut head = format!("From: peer@example.net\r\nTo: u@example.org\r\nSubject: deal\r\n");
        head.push_str(&format!("Message-ID: <{mid}>\r\n"));
        if let Some(p) = parent {
            head.push_str(&format!("In-Reply-To: <{p}>\r\nReferences: <{p}>\r\n"));
        }
        head.push_str(
            "\r\nSee https://Vendor.Example/pricing and http://shop.example.net:8080/x.\r\n",
        );
        head.into_bytes()
    }

    async fn inbox_delivery(env: &Env, login: &str) -> Delivery {
        let scope = env.meta.account(login).await.expect("account");
        Delivery {
            account: scope.account,
            mailbox: env
                .meta
                .mailbox_by_role(scope, SpecialUse::Inbox)
                .expect("inbox"),
            extra_headers: vec![],
            flags: Default::default(),
        }
    }

    fn request(raw: &[u8], deliveries: Vec<Delivery>) -> IngestRequest {
        IngestRequest {
            tenant: TenantId::DEFAULT,
            mail_from: "peer@example.net".into(),
            raw: stream(raw, 1000),
            deliveries,
            received_at: SystemClock.now(),
        }
    }

    async fn thread_of(env: &Env, account: AccountId, message: MessageId) -> ThreadId {
        let scope = AccountScope {
            tenant: TenantId::DEFAULT,
            account,
        };
        env.threads
            .thread_of(scope, message)
            .await
            .expect("thread_of")
            .expect("bound")
    }

    /// Приёмка MS-21: ответ попадает в беседу исходного письма, память беседы пополняется
    /// (типы вложений, домены ссылок, `Reply-To`).
    #[tokio::test]
    async fn reply_joins_original_thread_with_facts() {
        let env = Env::new();
        let d = inbox_delivery(&env, "u@example.org").await;
        let first = env
            .store
            .ingest(request(&letter("a@example.net", None), vec![d.clone()]))
            .await
            .expect("ingest");
        let reply = env
            .store
            .ingest(request(
                &letter("b@example.net", Some("a@example.net")),
                vec![d.clone()],
            ))
            .await
            .expect("ingest reply");
        let (t1, t2) = (
            thread_of(&env, d.account, first.delivered[0].message).await,
            thread_of(&env, d.account, reply.delivered[0].message).await,
        );
        assert_eq!(t1, t2, "ответ — в беседе исходного письма");

        // Память беседы: домены ссылок — канонические; ключи привязки зарегистрированы обеих писем.
        let scope = AccountScope {
            tenant: TenantId::DEFAULT,
            account: d.account,
        };
        let facts = env.threads.facts(scope, t1).await.expect("facts");
        assert_eq!(
            facts.link_domains,
            ["vendor.example", "shop.example.net"],
            "домены ссылок — в канонической форме"
        );
        assert_eq!(
            env.threads.messages(scope, t1, 10).await.expect("messages"),
            [first.delivered[0].message, reply.delivered[0].message],
            "письма беседы — в порядке привязки"
        );
    }

    /// Приёмка MS-21: письмо беседы с `AlwaysMove` — в заданной папке (вместо выбранной правилами),
    /// `AlwaysKeyword` — с ключевым словом.
    #[tokio::test]
    async fn always_move_and_keyword_apply_to_new_letter() {
        let env = Env::new();
        let scope = env.meta.account("u@example.org").await.expect("account");
        let d = inbox_delivery(&env, "u@example.org").await;
        let first = env
            .store
            .ingest(request(&letter("a@example.net", None), vec![d.clone()]))
            .await
            .expect("ingest");
        let t = thread_of(&env, d.account, first.delivered[0].message).await;

        // Папка «Deals» и правило всегда перемещать в неё.
        let deals = MailboxStore::create(
            &env.meta,
            scope,
            tp_contracts::meta::NewMailbox {
                parent: None,
                name: "Deals".into(),
                role: None,
            },
        )
        .await
        .expect("mailbox")
        .id;
        env.threads
            .set_rule(scope, t, Some(ThreadRule::AlwaysMove(deals)))
            .await
            .expect("rule");

        let next = env
            .store
            .ingest(request(
                &letter("c@example.net", Some("a@example.net")),
                vec![d.clone()],
            ))
            .await
            .expect("ingest");
        let id = next.delivered[0].message;
        assert_eq!(
            next.delivered[0].mailbox, deals,
            "папка вместо выбранной правилами"
        );
        let msg = env.meta.get(scope, id).await.expect("get").expect("msg");
        assert_eq!(msg.mailbox, deals);
        assert_eq!(msg.uid, next.delivered[0].uid);
        assert_eq!(
            env.meta
                .list(scope, d.mailbox, MessageQuery::All, 10)
                .await
                .expect("list")
                .len(),
            1,
            "во «Входящих» — только первое письмо"
        );

        // Правило беседы одно (замена целиком): ключевое слово на следующие письма.
        env.threads
            .set_rule(scope, t, Some(ThreadRule::AlwaysKeyword("$deal".into())))
            .await
            .expect("keyword rule");
        let keyworded = env
            .store
            .ingest(request(
                &letter("f@example.net", Some("a@example.net")),
                vec![d.clone()],
            ))
            .await
            .expect("ingest");
        let msg = env
            .meta
            .get(scope, keyworded.delivered[0].message)
            .await
            .expect("get")
            .expect("msg");
        assert_eq!(
            msg.mailbox, d.mailbox,
            "без AlwaysMove — выбранная правилами папка"
        );
        assert!(
            msg.flags.contains(&Flag::Keyword("$deal".into())),
            "ключевое слово беседы"
        );
    }

    /// Приёмка MS-21: письмо удержанной беседы удержано (привязка накрывает новое письмо),
    /// `Ignore` кладёт письмо в корзину.
    #[tokio::test]
    async fn hold_and_ignore_cover_new_letter() {
        let env = Env::new();
        let scope = env.meta.account("u@example.org").await.expect("account");
        let d = inbox_delivery(&env, "u@example.org").await;
        let first = env
            .store
            .ingest(request(&letter("a@example.net", None), vec![d.clone()]))
            .await
            .expect("ingest");
        let t = thread_of(&env, d.account, first.delivered[0].message).await;
        env.threads
            .set_hold(
                scope,
                t,
                Some(ThreadHold {
                    by: "compliance".into(),
                    at: OffsetDateTime::UNIX_EPOCH,
                    reason: "case-42".into(),
                }),
            )
            .await
            .expect("hold");

        // Письмо после удержания — удержано: хук запрещает окончательное удаление.
        let held = env
            .store
            .ingest(request(
                &letter("d@example.net", Some("a@example.net")),
                vec![d.clone()],
            ))
            .await
            .expect("ingest");
        let hook = tp_contracts::thread::ThreadHoldHook::new(Arc::new(env.threads.clone()));
        let op = tp_contracts::ext::FinalDelete {
            scope,
            mailbox: d.mailbox,
            message: held.delivered[0].message,
            received_at: SystemClock.now(),
            thread: None,
        };
        assert_eq!(
            hook.before_final_delete(&op).await,
            Ok(tp_contracts::ext::Decision::Deny(
                "thread hold: case-42".into()
            )),
            "будущее письмо удержанной беседы удержано"
        );

        // «Игнорировать»: следующее письмо беседы — в корзине.
        env.threads
            .set_rule(scope, t, Some(ThreadRule::Ignore))
            .await
            .expect("ignore");
        let ignored = env
            .store
            .ingest(request(
                &letter("e@example.net", Some("a@example.net")),
                vec![d.clone()],
            ))
            .await
            .expect("ingest");
        let msg = env
            .meta
            .get(scope, ignored.delivered[0].message)
            .await
            .expect("get")
            .expect("msg");
        let trash = env
            .meta
            .mailbox_by_role(scope, SpecialUse::Trash)
            .expect("trash");
        assert_eq!(msg.mailbox, trash, "игнорируемая беседа — в корзине");
        assert_eq!(ignored.delivered[0].mailbox, trash);
    }

    /// Хранилище бесед, отказывающее в привязке: приём откатывается целиком.
    #[derive(Default)]
    struct FailingThreads {
        inner: MemThreads,
    }

    #[async_trait]
    impl ThreadStore for FailingThreads {
        fn limits(&self) -> ThreadLimits {
            self.inner.limits()
        }

        async fn bind(
            &self,
            _scope: AccountScope,
            _message: MessageId,
            _keys: &[&str],
        ) -> Result<ThreadId> {
            Err(Error::UNAVAILABLE)
        }

        async fn thread_of(
            &self,
            scope: AccountScope,
            message: MessageId,
        ) -> Result<Option<ThreadId>> {
            self.inner.thread_of(scope, message).await
        }

        async fn messages(
            &self,
            scope: AccountScope,
            thread: ThreadId,
            limit: usize,
        ) -> Result<Vec<MessageId>> {
            self.inner.messages(scope, thread, limit).await
        }

        async fn remember_facts(
            &self,
            scope: AccountScope,
            thread: ThreadId,
            facts: &ThreadFacts,
        ) -> Result<()> {
            self.inner.remember_facts(scope, thread, facts).await
        }

        async fn facts(&self, scope: AccountScope, thread: ThreadId) -> Result<ThreadFacts> {
            self.inner.facts(scope, thread).await
        }

        async fn hold(&self, scope: AccountScope, thread: ThreadId) -> Result<Option<ThreadHold>> {
            self.inner.hold(scope, thread).await
        }

        async fn set_hold(
            &self,
            scope: AccountScope,
            thread: ThreadId,
            hold: Option<ThreadHold>,
        ) -> Result<()> {
            self.inner.set_hold(scope, thread, hold).await
        }

        async fn rule(&self, scope: AccountScope, thread: ThreadId) -> Result<Option<ThreadRule>> {
            self.inner.rule(scope, thread).await
        }

        async fn set_rule(
            &self,
            scope: AccountScope,
            thread: ThreadId,
            rule: Option<ThreadRule>,
        ) -> Result<()> {
            self.inner.set_rule(scope, thread, rule).await
        }
    }

    /// Приёмка MS-21: сбой привязки откатывает письмо целиком — метаданных нет, счётчики объектов
    /// сняты удалением (компенсация, не `release` поверх).
    #[tokio::test]
    async fn bind_failure_rolls_back_letter() {
        let env = Env::new();
        let d = inbox_delivery(&env, "u@example.org").await;
        let store = crate::Store::new(crate::Deps {
            threads: Some(Arc::new(FailingThreads::default())),
            ..env.store.d.clone()
        });
        let raw = letter("a@example.net", None);
        let err = store.ingest(request(&raw, vec![d.clone()])).await;
        assert_eq!(
            err,
            Err(Error::UNAVAILABLE),
            "сбой привязки — ошибка приёма"
        );

        let scope = AccountScope {
            tenant: TenantId::DEFAULT,
            account: d.account,
        };
        assert_eq!(
            env.meta
                .list(scope, d.mailbox, MessageQuery::All, 10)
                .await
                .expect("list")
                .len(),
            0,
            "письма нет"
        );
        let trash = env
            .meta
            .mailbox_by_role(scope, SpecialUse::Trash)
            .expect("trash");
        assert!(
            env.meta
                .list(scope, trash, MessageQuery::All, 10)
                .await
                .expect("list")
                .is_empty(),
            "и в корзине нет"
        );
        // Счётчики объектов: ссылки сняты удалением, не «release» поверх.
        let split = crate::split::Split::new(bytes::Bytes::from(raw));
        let skeleton = crate::split::hash(&split.skeleton(b""));
        for h in split.cuts().iter().map(|c| c.hash).chain([skeleton]) {
            let row = env.index.row(TenantId::DEFAULT, &h).expect("row");
            assert_eq!(row.refcnt, 0, "ссылки сняты");
        }
    }
}
