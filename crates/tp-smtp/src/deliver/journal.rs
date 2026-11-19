//! Журналирование переписки — этап ядра конвейера до Sieve ящика (SMTP-53; CTR-97,
//! CONTRACTS.md#Journal; SRS 4.9).
//!
//! Письмо, подошедшее под правило журналирования организации ([`JournalRule`]: организация, группа
//! или ящик, направление In/Out/Both), копируется в журнал целиком с конвертом — до Sieve ящика и
//! этапов модулей (CTR-96: [`tp_contracts::pipeline::core_stage::JOURNAL`] — первый этап точки
//! `BeforeMailboxSieve`): `discard` и `stop` скрипта ящика запись не отменяют, письмо журналируется
//! независимо от ящика. Конверт записи — отправитель и все получатели на момент конвейера, до сжатия
//! списка доставкой: скрытые (Bcc) получатели конверта и члены групп рассылки, раскрытые при записи.
//! Одна запись на письмо на правило ([`JournalStore::append`]); сбой записи — ошибка операции
//! (временный отказ: журналирование обязательно, письмо доставляется повтором). Служебные письма
//! продукта (DSN, отбивки, копии самого журнала) конвейер правил не проходят (`SystemMessage`,
//! CTR-96) и повторно не журналируются: этап вызывается только приёмом smtp-in и отправкой клиентом
//! (submission, [`super::Delivery::submit`]).
//!
//! Правила — данные организации в PostgreSQL (таблица `journal.rules`, META-88), меняются через
//! Admin API; источник правил передаёт приложение ([`JournalRules`]), чтение — на каждое письмо,
//! изменения действуют сразу, без перезапуска (SRS 2.8). Без правил этап не пишет ничего.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use time::OffsetDateTime;
use tp_contracts::Result;
use tp_contracts::ids::{AccountId, GroupId, TenantId};
use tp_contracts::journal::{
    JournalDirection, JournalRecord, JournalRule, JournalScope, JournalStore,
};

use super::{Delivery, Resolved, push_unique};

/// Источник правил журналирования организации (SMTP-53): реализация приложения читает правила из
/// PostgreSQL (META-88, `PgJournal::rules`); in-memory — тесты `tp-smtp`.
#[async_trait]
pub trait JournalRules: Send + Sync + 'static {
    /// Правила журналирования организации `tenant`.
    async fn rules(&self, tenant: TenantId) -> Result<Vec<JournalRule>>;
}

/// Журналирование конвейера (SMTP-53): источник правил и хранилище записей с индексом
/// ([`JournalStore`]; реализация — `tp-meta` `PgJournal` поверх бакета записей BLOB-18, in-memory —
/// `tp-testkit::MemJournal`). Подключается [`Delivery::with_journal`]; без него этап не пишет ничего.
pub struct Journaling {
    rules: Arc<dyn JournalRules>,
    store: Arc<dyn JournalStore>,
}

impl Journaling {
    /// Журналирование с источником правил `rules` и хранилищем `store`.
    pub fn new(rules: Arc<dyn JournalRules>, store: Arc<dyn JournalStore>) -> Self {
        Self { rules, store }
    }
}

impl fmt::Debug for Journaling {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Journaling").finish_non_exhaustive()
    }
}

impl Delivery {
    /// Подключает этап журналирования конвейера (SMTP-53): копия письма и конверт — в отдельный бакет
    /// журнала по правилам организации, до Sieve ящика и независимо от него.
    pub fn with_journal(mut self, journal: Journaling) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Этап журналирования (SMTP-53): для письма, подошедшего под [`JournalRule`], собрать
    /// [`JournalRecord`] и передать [`JournalStore::append`] — по одной записи на правило. Получатели
    /// записи — конверт на момент конвейера: адреса конверта (включая скрытых, Bcc) и раскрытые из
    /// групп рассылки члены (учётные записи и почтовые контакты); правило области группы сверяется с
    /// её участниками ([`Groups::members`]). `direction` — `In` для приёма smtp-in, `Out` для
    /// отправки клиентом. Отправитель-учётная запись и учётные записи получателей (группы раскрыты) —
    /// для области правила ([`JournalRule::covers`]). Пустой отправитель конверта — уведомление о
    /// доставке, служебное письмо: не журналируется.
    pub(super) async fn journal_message(
        &self,
        id: &str,
        direction: JournalDirection,
        mail_from: &str,
        rcpts: &[String],
        raw: &Bytes,
        at: OffsetDateTime,
    ) -> Result<()> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        // Пустой отправитель — уведомление о доставке (DSN, SystemMessage): повторных записей нет.
        if mail_from.is_empty() || rcpts.is_empty() {
            return Ok(());
        }
        let tenant = self.deps.tenant;
        let rules: Vec<JournalRule> = journal
            .rules
            .rules(tenant)
            .await?
            .into_iter()
            .filter(|r| r.tenant == tenant && r.enabled)
            .collect();
        if rules.is_empty() {
            return Ok(());
        }
        // Учётные записи конверта (получатели — с раскрытием групп) и адреса записи: конверт как есть
        // плюс раскрытые члены групп рассылки.
        let sender = self.sender_by_address(mail_from).await?;
        let mut rcpt_accounts: Vec<AccountId> = Vec::new();
        let mut recipients: Vec<String> = Vec::new();
        for rcpt in rcpts {
            push_unique(&mut recipients, vec![rcpt.clone()]);
            let target = self.target(rcpt).await?;
            if let Resolved::Local(accounts) = &target.resolved {
                for acc in accounts {
                    rcpt_accounts.push(acc.id);
                    if target.group.is_some() || target.mailing {
                        push_unique(&mut recipients, vec![acc.login.clone()]);
                    }
                }
            }
            push_unique(&mut recipients, target.contacts.clone());
        }
        // Участники групп областей правил (CTR-97: раскрытие — вызывающий).
        let mut members: HashMap<GroupId, Vec<AccountId>> = HashMap::new();
        if let Some(groups) = &self.groups {
            for rule in &rules {
                if let JournalScope::Group(gid) = rule.scope
                    && !members.contains_key(&gid)
                {
                    let expanded = match groups.get(tenant, gid).await {
                        Ok(Some(g)) => groups.members(tenant, &g).await.map(|m| m.accounts),
                        Ok(None) => Ok(Vec::new()),
                        Err(e) => Err(e),
                    };
                    members.insert(gid, expanded.unwrap_or_else(|e| {
                        tracing::warn!(%id, group = %gid, error = %e, "smtp: группа правила журнала не раскрыта");
                        Vec::new()
                    }));
                }
            }
        }
        let message_id = crate::tracking::message_id(raw);
        for rule in &rules {
            let group_members = match rule.scope {
                JournalScope::Group(gid) => members.get(&gid).cloned().unwrap_or_default(),
                _ => Vec::new(),
            };
            if !rule.covers(direction, sender, &rcpt_accounts, &group_members) {
                continue;
            }
            let record = JournalRecord {
                tenant,
                sender: mail_from.to_owned(),
                recipients: recipients.clone(),
                message_id: message_id.clone(),
                at,
                rule: rule.id.clone(),
            };
            if let Err(e) = record.validate() {
                // Конверт не собирается в запись (непригодный адрес) — письмо не задерживаем.
                tracing::warn!(%id, rule = %rule.id, error = %e, "smtp: запись журнала не собрана");
                continue;
            }
            match journal.store.append(rule, &record, raw.clone()).await {
                Ok(entry) => {
                    tracing::info!(%id, journal = %entry, rule = %rule.id, "smtp: письмо записано в журнал")
                }
                // Сбой записи — ошибка этапа: письмо не проходит дальше без обязательной записи.
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}
