//! Принятие встречи из письма (JMAP-50, решение #134 — вариант 3): `Invitation/respond`,
//! capability `urn:thepost:params:jmap:itip`.
//!
//! Кнопка «Принять / Возможно / Отклонить» веб-почты вызывает метод: сервер сам читает письмо `emailId`,
//! проверяет папку и спам-вердикт и применяет приглашение — каноническая точка отказа ручного iTIP-принятия
//! из спам-письма, надёжнее сверки ссылки ответа (SMTP-55 — вариант 1, PR #135 — защищает submission-путь
//! внешних клиентов; варианты совместимы, то же хранилище писем). Так же работает EWS `AcceptItem` /
//! `TentativelyAcceptItem` / `DeclineItem` (Exchange): ответ по ссылке на письмо-приглашение.
//!
//! Отказ — структурированная ошибка (код + человекочитаемое сообщение), календарь не меняется:
//! - `invitationInJunk` — письмо в папке «Спам»: вердикты доставки (DMARC quarantine/reject, карантин Milter,
//!   списки отправителей) при доставке материализуются в папку «Спам» (SMTP-50/SMTP-55), поэтому папка —
//!   итоговый признак всех источников вердикта; после переноса письма (JMAP `Email/set`, перетаскивание)
//!   метод применяется;
//! - `senderBlocked` — отправитель в списке заблокированных ящика (списки меняются и после доставки,
//!   поэтому проверяются заново на каждый вызов);
//! - попытка из «Спама» или под вердиктом пишется в журнал аудита ящика (действие `Send` — попытка ответа
//!   на приглашение, пояснение — причина отказа; по политике ящика, как остальные действия владельца).
//!   Успешное принятие — штатно: рассылка ответа идёт приёмом JMAP-31, без отдельной записи.
//!
//! Применение — существующие приёмы, своего применения iTIP здесь нет:
//! 1. приглашение вносится приёмом iTIP (`ItipDelivery`; `ItipMessage::calendar` из contracts-68 — `None`:
//!    действие `processcalendar` правил не выполнялось, принятие ручное) в пределах матрицы доверия
//!    получателя — своей организации всегда, партнёру по клетке `invite_new`; отказ приёма (кнопка для
//!    чужих) — `applied = false` с причиной, веб-почта предлагает добавить событие клиентом;
//! 2. статус участия в копии пользователя меняется на выбранный, ответ `REPLY` уходит рассылкой JMAP-31
//!    ([`crate::scheduling::announce`] → `tp_dav::ScheduleDeps::dispatch`): организатору организации — приём
//!    iTIP (его календарь обновляется), внешнему — письмо iMIP. Повторный вызов идемпотентен: без изменения
//!    статуса новый `REPLY` не рассылается.
//!
//! Идентичность участника — адреса учётной записи (`accountId`) среди `ATTENDEE` письма. Письмо без части
//! `text/calendar; method=REQUEST`, отправитель не организатор или учётная запись не участник —
//! `notAnInvitation`.

use calcard::icalendar::{
    ICalendar, ICalendarComponentType, ICalendarParameter, ICalendarParameterName,
    ICalendarParticipationStatus, ICalendarProperty,
};
use mail_parser::MessageParser;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::str::FromStr;
use tp_contracts::MessageId;
use tp_contracts::audit::{AuditAction, AuditObject};
use tp_contracts::dav::{DavObject, Precondition, PutOutcome};
use tp_contracts::meta::{Message, SpecialUse};
use tp_contracts::schedule::{ItipMessage, ItipMethod, ItipOutcome};
use tp_contracts::senders::SenderVerdict;
use tp_contracts::trust::PeerKind;
use tp_dav::itip;

use crate::audit::{detail, owner};
use crate::calendar_event::calendar_ids;
use crate::core::Ctx;
use crate::core::error::{MethodError, MethodResult};
use crate::core::request::{object, parse_args};
use crate::email_get::collect;
use crate::scheduling::Written;

/// Ответ пользователя на приглашение.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PartStat {
    Accepted,
    Tentative,
    Declined,
}

impl PartStat {
    /// Значение аргумента `participationStatus`.
    fn parse(s: &str) -> Option<Self> {
        match s {
            "accepted" => Some(PartStat::Accepted),
            "tentative" => Some(PartStat::Tentative),
            "declined" => Some(PartStat::Declined),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            PartStat::Accepted => "accepted",
            PartStat::Tentative => "tentative",
            PartStat::Declined => "declined",
        }
    }

    fn ical(self) -> ICalendarParticipationStatus {
        match self {
            PartStat::Accepted => ICalendarParticipationStatus::Accepted,
            PartStat::Tentative => ICalendarParticipationStatus::Tentative,
            PartStat::Declined => ICalendarParticipationStatus::Declined,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RespondArgs {
    account_id: String,
    email_id: String,
    participation_status: String,
}

/// Приглашение из письма: отправитель (организатор), объект iCalendar и UID встречи.
struct Invitation {
    from: String,
    ics: String,
    uid: String,
}

/// Приглашение iTIP письма `raw`: часть `text/calendar` с параметром `method=REQUEST`, один адрес `From` —
/// организатор встречи; вместе со сведениями планирования (участники для идентичности пользователя).
/// `None`/`Err` — письмо не приглашение (причина — в описании ошибки).
fn extract(raw: &[u8]) -> Option<Result<(Invitation, itip::Meeting), String>> {
    let msg = MessageParser::new().parse(raw)?;
    let (method, ics) = msg.root().parts().find_map(|p| {
        let ct = p.content_type()?;
        let calendar = ct.ctype().eq_ignore_ascii_case("text")
            && ct
                .subtype()
                .is_some_and(|s| s.eq_ignore_ascii_case("calendar"));
        let method = ct
            .attribute("method")
            .filter(|_| calendar)?
            .trim()
            .to_owned();
        Some((method, String::from_utf8_lossy(p.decoded()).into_owned()))
    })?;
    Some((|| {
        let not = "письмо не приглашение: часть text/calendar без method=REQUEST";
        if !method.eq_ignore_ascii_case(ItipMethod::Request.as_str()) {
            return Err(format!("{not} (method={method})"));
        }
        // Один заголовок `From` и один адрес — как у приёма iMIP (SMTP-48): с несколькими не применять.
        if msg
            .headers()
            .all(mail_parser::HeaderName::From)
            .nth(1)
            .is_some()
        {
            return Err("письмо не приглашение: не один заголовок From".into());
        }
        let from = msg
            .from()
            .map(|a| a.mailboxes().filter_map(|x| x.address()).collect())
            .unwrap_or_else(Vec::new);
        let [from] = from.as_slice() else {
            return Err("письмо не приглашение: не один адрес From".into());
        };
        let from = itip::address(from);
        let ical = ICalendar::parse(&ics)
            .ok()
            .ok_or("письмо не приглашение: неразборчивый iCalendar")?;
        let meeting = itip::meeting(&ical).ok_or("письмо не приглашение: нет события с UID")?;
        if meeting.organizer.as_deref() != Some(from.as_str()) {
            return Err("письмо не приглашение: отправитель письма — не организатор".into());
        }
        let uid = meeting.uid.clone();
        Ok((Invitation { from, ics, uid }, meeting))
    })())
}

/// Тип отправителя приглашения относительно организации пользователя (решение 123 → 124): адрес организатора —
/// учётная запись организации → свой; домен из списка партнёров → партнёр (выравнивание DMARC проверено при
/// доставке: письмо, его не прошедшее, лежит в «Спаме» и уже отклонено); остальное — интернет (сосед без
/// списка доменов установки неотличим; значения клеток матрицы для них одинаковы).
async fn peer_kind(ctx: &Ctx<'_>, organizer: &str) -> PeerKind {
    if matches!(
        ctx.jmap
            .d
            .accounts
            .by_address(ctx.scope.tenant, organizer)
            .await,
        Ok(Some(tp_contracts::meta::AddressTarget::Account(_)))
    ) {
        return PeerKind::Own;
    }
    let Some((_, domain)) = organizer.rsplit_once('@') else {
        return PeerKind::External;
    };
    let partner = match &ctx.jmap.trust {
        Some(t) => t
            .partner_of(ctx.scope.tenant, &domain.to_lowercase())
            .await
            .unwrap_or(false),
        None => false,
    };
    if partner {
        PeerKind::Partner
    } else {
        PeerKind::External
    }
}

/// Отказ ручного принятия — событие журнала аудита ящика (JMAP-50): попытка ответа на приглашение
/// (`Send`, как отправка ответа клиентом) с пояснением-причиной и `Message-ID` письма; пишется по политике
/// ящика, как остальные действия владельца. Сбой журнала отказ не меняет.
async fn refused(ctx: &Ctx<'_>, message: &Message, why: &str) {
    let text = match message.meta.envelope.message_id.as_deref() {
        Some(mid) => format!("{mid}: {why}"),
        None => why.to_owned(),
    };
    owner(
        ctx,
        AuditAction::Send,
        AuditObject {
            mailbox: Some(message.mailbox),
            message: Some(message.id),
            detail: detail(&text),
        },
    )
    .await;
}

/// Меняет `PARTSTAT` участника `me` во всех компонентах планирования объекта и снимает его `RSVP`
/// (ответ дан, как у приёма `REPLY`); `false` — участника нет ни в одном компоненте.
fn set_partstat(ical: &mut ICalendar, me: &str, ps: ICalendarParticipationStatus) -> bool {
    let mut any = false;
    for c in ical.components.iter_mut() {
        if !matches!(
            c.component_type,
            ICalendarComponentType::VEvent | ICalendarComponentType::VTodo
        ) {
            continue;
        }
        for e in c.entries.iter_mut() {
            if e.name != ICalendarProperty::Attendee {
                continue;
            }
            if e.calendar_address().map(itip::address) == Some(me.to_owned()) {
                e.params.retain(|p| {
                    !matches!(
                        p.name,
                        ICalendarParameterName::Partstat | ICalendarParameterName::Rsvp
                    )
                });
                e.params.push(ICalendarParameter::partstat(ps.clone()));
                any = true;
            }
        }
    }
    any
}

/// `Invitation/respond`: ответ пользователя на приглашение из письма `emailId`.
pub(crate) async fn respond(
    ctx: &mut Ctx<'_>,
    args: Map<String, Value>,
) -> MethodResult<Map<String, Value>> {
    let a: RespondArgs = parse_args(args)?;
    ctx.check_account(&a.account_id)?;
    let Some(partstat) = PartStat::parse(&a.participation_status) else {
        return Err(MethodError::invalid(
            "participationStatus must be one of accepted, tentative, declined",
        ));
    };
    let Some(schedule) = ctx.jmap.schedule.as_ref() else {
        return Err(MethodError::new("unknownMethod"));
    };
    let id = MessageId::from_str(ctx.resolve_id(&a.email_id))
        .map_err(|_| MethodError::invalid("emailId is not a valid id"))?;
    let Some(message) = ctx.jmap.d.messages.get(ctx.scope, id).await? else {
        return Err(MethodError::with("notFound", "email not found"));
    };

    // Папка «Спам»: вердикты доставки материализуются в неё (SMTP-50/SMTP-55) — итоговый признак всех
    // источников спам-вердикта получателя.
    let mailbox = ctx.jmap.d.mailboxes.get(ctx.scope, message.mailbox).await?;
    if mailbox
        .as_ref()
        .and_then(|m| m.role)
        .is_some_and(|r| r == SpecialUse::Junk)
    {
        refused(
            ctx,
            &message,
            "ручной iTIP-ответ отклонён: приглашение в «Спаме»",
        )
        .await;
        return Err(MethodError::with(
            "invitationInJunk",
            "Приглашение лежит в папке «Спам». Сначала перенесите письмо в другую папку, затем примите или отклоните встречу.",
        ));
    }

    // Личные списки отправителей меняются и после доставки — вердикт проверяется заново.
    if let Some(lists) = ctx.jmap.sender_lists.as_ref()
        && let Some(from) = message
            .meta
            .envelope
            .from
            .first()
            .map(|a| a.email.to_ascii_lowercase())
    {
        let blocked = lists
            .sender_list(ctx.scope)
            .await?
            .verdict(&from)
            .is_some_and(|v| v == SenderVerdict::Blocked);
        if blocked {
            refused(
                ctx,
                &message,
                "ручной iTIP-ответ отклонён: отправитель приглашения в списке заблокированных",
            )
            .await;
            return Err(MethodError::with(
                "senderBlocked",
                "Отправитель приглашения — в списке заблокированных вашего ящика.",
            ));
        }
    }

    // Приглашение из письма и идентичность участника.
    let raw = collect(
        ctx.jmap
            .d
            .store
            .fetch_raw(ctx.scope, message.id, None)
            .await?,
    )
    .await?;
    let (invitation, meeting) = match extract(&raw) {
        Some(Ok(i)) => i,
        Some(Err(why)) => return Err(MethodError::with("notAnInvitation", why)),
        None => {
            return Err(MethodError::with(
                "notAnInvitation",
                "В письме нет приглашения (части text/calendar с параметром method=REQUEST).",
            ));
        }
    };
    let account = ctx
        .jmap
        .d
        .accounts
        .get(ctx.scope.tenant, ctx.scope.account)
        .await?;
    let me = account
        .map(|a| a.addresses())
        .unwrap_or_default()
        .into_iter()
        .map(|a| itip::address(&a))
        .find(|a| meeting.attendee(a).is_some())
        .ok_or_else(|| {
            MethodError::with(
                "notAnInvitation",
                "Учётная запись не участник встречи из письма.",
            )
        })?;

    // 1. Внесение приглашения приёмом iTIP (матрица доверия получателя; calendar = None — принятие ручное,
    //    действия правил не было). Идемпотентно: повторная доставка того же сообщения ничего не меняет.
    let request = ItipMessage {
        recipient: ctx.scope,
        to: me.clone(),
        from: invitation.from.clone(),
        method: ItipMethod::Request,
        ics: invitation.ics.clone(),
        sender: peer_kind(ctx, &invitation.from).await,
        calendar: None,
    };
    let mut reason = None;
    match schedule.delivery.deliver(&request).await {
        Ok(ItipOutcome::Applied) => {}
        Ok(ItipOutcome::Ignored(why)) => reason = Some(why),
        Err(e) => tracing::warn!(error = %e, "jmap: сбой приёма iTIP приглашения"),
    }

    // 2. Копия события у пользователя: статус участия и ответ организатору (рассылка JMAP-31).
    let store = ctx.jmap.dav_store()?.clone();
    let mut found: Option<DavObject> = None;
    for cal in calendar_ids(ctx).await? {
        if let Some(o) = store.object_by_uid(ctx.scope, cal, &invitation.uid).await? {
            found = Some(o);
            break;
        }
    }
    let Some(obj) = found else {
        // Приём не внёс (решение матрицы) и события нет — честный итог без ответа организатору.
        let reason = reason.unwrap_or_else(|| "событие не найдено в календарях".to_owned());
        return Ok(object(json!({
            "accountId": a.account_id,
            "participationStatus": partstat.as_str(),
            "applied": false,
            "reason": reason,
            "calendarEventId": null,
        })));
    };
    let Some(mut ical) = ICalendar::parse(&obj.body).ok() else {
        return Err(MethodError::server_fail("копия события не разбирается"));
    };
    if !set_partstat(&mut ical, &me, partstat.ical()) {
        return Err(MethodError::server_fail("копия события без участника"));
    }
    let body = ical.to_string();
    // Индекс без изменений: PARTSTAT и RSVP не входят в Schedule-Tag и занятость.
    let put = store
        .put_object(
            ctx.scope,
            obj.collection,
            &obj.name,
            body.clone(),
            obj.index.clone(),
            Precondition::IfMatch(obj.etag.clone()),
        )
        .await;
    let etag = match put {
        Ok(PutOutcome::Stored(p)) => p.etag,
        Ok(PutOutcome::PreconditionFailed) => {
            return Err(MethodError::server_fail(
                "the event was changed concurrently",
            ));
        }
        Ok(PutOutcome::UidConflict { .. }) => {
            return Err(MethodError::server_fail("uid is used by another event"));
        }
        Err(e) => return Err(e.into()),
    };
    crate::scheduling::announce(
        ctx,
        Some(&obj.body),
        Some(Written {
            collection: obj.collection,
            name: &obj.name,
            body: &body,
            index: obj.index.clone(),
            etag,
        }),
    )
    .await;
    Ok(object(json!({
        "accountId": a.account_id,
        "participationStatus": partstat.as_str(),
        "applied": true,
        "reason": null,
        "calendarEventId": obj.id.to_string(),
    })))
}

#[cfg(test)]
mod tests {
    use axum::body::Bytes;
    use serde_json::{Value, json};
    use time::OffsetDateTime;
    use tp_contracts::MessageId;
    use tp_contracts::audit::{AuditAction, AuditActorKind, AuditPolicy, MailboxAudit};
    use tp_contracts::auth::Principal;
    use tp_contracts::dav::{CollectionKind, DavObject, DavStore};
    use tp_contracts::mailstore::{Delivery, IngestRequest, MailStore};
    use tp_contracts::meta::{AccountScope, MessageStore, SpecialUse};
    use tp_contracts::senders::{SenderList, SenderLists};

    use crate::calendars::tests::{call, create_calendar};
    use crate::testenv::Env;

    const ORG: &str = "user@example.org";
    const BOB: &str = "bob@example.org";
    const CAP: &str = "urn:thepost:params:jmap:itip";
    const USING: &[&str] = &[
        "urn:ietf:params:jmap:core",
        "urn:ietf:params:jmap:calendars",
        CAP,
    ];

    fn scope(p: &Principal) -> AccountScope {
        AccountScope {
            tenant: p.tenant,
            account: p.account,
        }
    }

    /// Объект события `uid` в календарях учётной записи `scope` — то, что хранит CalDAV.
    async fn stored(env: &Env, scope: AccountScope, uid: &str) -> Option<DavObject> {
        let cals = env
            .dav
            .list_collections(scope, CollectionKind::Calendar)
            .await
            .expect("calendars");
        for c in cals {
            if let Some(o) = env.dav.object_by_uid(scope, c.id, uid).await.expect("uid") {
                return Some(o);
            }
        }
        None
    }

    /// Письмо-приглашение организатора `org` (`From` и `ORGANIZER`) участнику `to` с UID `u1`.
    fn invite(org: &str, to: &str) -> Vec<u8> {
        format!(
            "From: Организатор <{org}>\r\nTo: {to}\r\nSubject: Приглашение\r\n\
             Message-ID: <invite-1@example.org>\r\nMIME-Version: 1.0\r\n\
             Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\n\
             Content-Type: text/plain\r\n\r\nвстреча\r\n--b\r\n\
             Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\nBEGIN:VCALENDAR\r\n\
             VERSION:2.0\r\nPRODID:-//test//EN\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:u1\r\n\
             DTSTAMP:20261112T100000Z\r\nDTSTART:20261113T100000Z\r\nDTEND:20261113T110000Z\r\n\
             SUMMARY:Планёрка\r\nORGANIZER:mailto:{org}\r\nATTENDEE:mailto:{to}\r\nEND:VEVENT\r\n\
             END:VCALENDAR\r\n--b--\r\n"
        )
        .into_bytes()
    }

    /// Событие организатора с участником BOB (UID `u1`), без рассылки: календарь организатора ждёт `REPLY`,
    /// у участника события ещё нет — как при приглашении, прошедшем мимо приёма (спам).
    async fn organizers_event(env: &Env) {
        create_calendar(env, "Работа").await;
        let r = call(
            env,
            "CalendarEvent/set",
            json!({"accountId": env.account(), "create": {"e": {
                "uid": "u1", "title": "Планёрка", "start": "2026-11-13T10:00:00",
                "timeZone": "UTC", "duration": "PT1H",
                "organizerCalendarAddress": format!("mailto:{ORG}"),
                "participants": {
                    "o": {"@type": "Participant", "name": "Организатор",
                          "calendarAddress": format!("mailto:{ORG}"), "roles": {"owner": true}},
                    "b": {"@type": "Participant", "name": "Борис",
                          "calendarAddress": format!("mailto:{BOB}"), "roles": {"attendee": true},
                          "participationStatus": "needs-action", "expectReply": true},
                },
            }}}),
        )
        .await;
        assert!(r["created"]["e"]["id"].is_string(), "{r}");
    }

    /// Письмо `raw` в папку `role` ящика `login` (доставка без приёма iTIP — как спам-письмо).
    async fn deliver(env: &Env, login: &str, role: SpecialUse, raw: &[u8]) -> MessageId {
        let scope = env.meta.account(login).await.expect("account");
        let mailbox = env.meta.mailbox_by_role(scope, role).expect("mailbox");
        let chunks: Vec<tp_contracts::Result<Bytes>> = vec![Ok(Bytes::copy_from_slice(raw))];
        let got = env
            .store
            .ingest(IngestRequest {
                tenant: scope.tenant,
                mail_from: ORG.into(),
                raw: Box::pin(futures::stream::iter(chunks)),
                deliveries: vec![Delivery {
                    account: scope.account,
                    mailbox,
                    extra_headers: vec![],
                    flags: Default::default(),
                }],
                received_at: OffsetDateTime::now_utc(),
            })
            .await
            .expect("ingest");
        got.delivered[0].message
    }

    /// `Invitation/respond` от имени `who` — ответ метода целиком (`[имя, аргументы]`).
    async fn respond(env: &Env, who: &Principal, email: &str, status: &str) -> Value {
        let req = json!({"using": USING, "methodCalls": [["Invitation/respond", {
            "accountId": who.account.to_string(), "emailId": email,
            "participationStatus": status}, "c0"]]});
        let resp = match env.jmap.api(who, req.to_string().as_bytes()).await {
            Ok(r) => serde_json::to_value(r).expect("serialize"),
            Err(p) => p.to_json(),
        };
        resp["methodResponses"][0].clone()
    }

    /// Приёмка JMAP-50: приглашение в «Спаме» — метод отвечает ошибкой, календарь не меняется, отказ в аудите;
    /// то же письмо после переноса из «Спама» — метод применяет `REPLY`, календарь обновляется (у участника —
    /// событие с его статусом, у организатора — статус участника).
    #[tokio::test]
    async fn junk_refused_then_applies_after_move() {
        let env = Env::new().await;
        organizers_event(&env).await;
        let bob = env.user(BOB).await;
        let email = deliver(&env, BOB, SpecialUse::Junk, &invite(ORG, BOB)).await;
        env.audit
            .set_audit_policy(bob.tenant, Some(bob.account), Some(AuditPolicy::all()))
            .await
            .expect("policy");

        // Из «Спама» — структурированная ошибка; календарь не меняется.
        let r = respond(&env, &bob, &email.to_string(), "accepted").await;
        assert_eq!(r[0], "error", "{r}");
        assert_eq!(r[1]["type"], "invitationInJunk", "{r}");
        assert!(
            r[1]["description"]
                .as_str()
                .unwrap_or_default()
                .contains("Спам"),
            "{r}"
        );
        assert!(
            stored(&env, scope(&bob), "u1").await.is_none(),
            "календарь участника пуст"
        );
        let org = stored(&env, env.scope, "u1")
            .await
            .expect("событие организатора");
        assert!(org.body.contains("PARTSTAT=NEEDS-ACTION"), "{}", org.body);

        // Отказ — событие аудита ящика: попытка ответа (`Send`), письмо и папка в записи.
        let entries = env.audit.entries();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].action, AuditAction::Send);
        assert_eq!(entries[0].actor_kind, AuditActorKind::Owner);
        assert_eq!(entries[0].scope.account, bob.account);
        assert_eq!(entries[0].object.message, Some(email));
        let junk = env
            .meta
            .mailbox_by_role(scope(&bob), SpecialUse::Junk)
            .expect("junk");
        assert_eq!(entries[0].object.mailbox, Some(junk));
        assert!(
            entries[0]
                .object
                .detail
                .as_deref()
                .unwrap_or_default()
                .contains("<invite-1@example.org>"),
            "{entries:?}"
        );

        // После переноса из «Спама» — применяется: событие у участника с его статусом, у организатора — `REPLY`.
        let inbox = env
            .meta
            .mailbox_by_role(scope(&bob), SpecialUse::Inbox)
            .expect("inbox");
        MessageStore::move_to(&env.meta, scope(&bob), &[email], inbox)
            .await
            .expect("move");
        let r = respond(&env, &bob, &email.to_string(), "accepted").await;
        assert_eq!(r[0], "Invitation/respond", "{r}");
        assert_eq!(r[1]["applied"], true, "{r}");
        assert_eq!(r[1]["participationStatus"], "accepted", "{r}");
        assert!(r[1]["calendarEventId"].is_string(), "{r}");
        assert!(r[1]["reason"].is_null(), "{r}");
        let mine = stored(&env, scope(&bob), "u1")
            .await
            .expect("копия участника");
        assert!(mine.body.contains("PARTSTAT=ACCEPTED"), "{}", mine.body);
        let org = stored(&env, env.scope, "u1")
            .await
            .expect("событие организатора");
        assert!(org.body.contains("PARTSTAT=ACCEPTED"), "{}", org.body);
        assert!(org.body.contains("SCHEDULE-STATUS=2.0"), "{}", org.body);

        // Повторный вызов идемпотентен: тот же итог, статус не сломан, лишних записей аудита нет.
        let r = respond(&env, &bob, &email.to_string(), "accepted").await;
        assert_eq!(r[1]["applied"], true, "{r}");
        assert_eq!(env.audit.entries().len(), 1);
        let mine = stored(&env, scope(&bob), "u1")
            .await
            .expect("копия участника");
        assert!(mine.body.contains("PARTSTAT=ACCEPTED"), "{}", mine.body);
    }

    /// Приёмка JMAP-50: письмо без спам-вердикта во «Входящих» — метод работает напрямую; смена ответа
    /// обновляет статус у участника и организатора.
    #[tokio::test]
    async fn inbox_invitation_applies_directly() {
        let env = Env::new().await;
        organizers_event(&env).await;
        let bob = env.user(BOB).await;
        let email = deliver(&env, BOB, SpecialUse::Inbox, &invite(ORG, BOB)).await;

        let r = respond(&env, &bob, &email.to_string(), "declined").await;
        assert_eq!(r[0], "Invitation/respond", "{r}");
        assert_eq!(r[1]["applied"], true, "{r}");
        let mine = stored(&env, scope(&bob), "u1")
            .await
            .expect("копия участника");
        assert!(mine.body.contains("PARTSTAT=DECLINED"), "{}", mine.body);
        let org = stored(&env, env.scope, "u1")
            .await
            .expect("событие организатора");
        assert!(org.body.contains("PARTSTAT=DECLINED"), "{}", org.body);

        // Смена ответа — новый `REPLY`, статусы обновляются.
        let r = respond(&env, &bob, &email.to_string(), "tentative").await;
        assert_eq!(r[1]["applied"], true, "{r}");
        let mine = stored(&env, scope(&bob), "u1")
            .await
            .expect("копия участника");
        assert!(mine.body.contains("PARTSTAT=TENTATIVE"), "{}", mine.body);
        let org = stored(&env, env.scope, "u1")
            .await
            .expect("событие организатора");
        assert!(org.body.contains("PARTSTAT=TENTATIVE"), "{}", org.body);
    }

    /// Приёмка JMAP-50: спам-вердикт получателя (личные списки, могли измениться после доставки) — отказ
    /// без изменения календаря, отказ в аудите; после разблокировки — применяется.
    #[tokio::test]
    async fn blocked_sender_verdict_is_refused() {
        let env = Env::new().await;
        organizers_event(&env).await;
        let bob = env.user(BOB).await;
        let email = deliver(&env, BOB, SpecialUse::Inbox, &invite(ORG, BOB)).await;
        env.sender_lists
            .put_sender_list(
                scope(&bob),
                SenderList {
                    safe: Vec::new(),
                    blocked: vec![ORG.into()],
                },
            )
            .await
            .expect("list");
        env.audit
            .set_audit_policy(bob.tenant, Some(bob.account), Some(AuditPolicy::all()))
            .await
            .expect("policy");

        let r = respond(&env, &bob, &email.to_string(), "accepted").await;
        assert_eq!(r[0], "error", "{r}");
        assert_eq!(r[1]["type"], "senderBlocked", "{r}");
        assert!(stored(&env, scope(&bob), "u1").await.is_none());
        let org = stored(&env, env.scope, "u1")
            .await
            .expect("событие организатора");
        assert!(org.body.contains("PARTSTAT=NEEDS-ACTION"), "{}", org.body);
        let entries = env.audit.entries();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert_eq!(entries[0].action, AuditAction::Send);
        assert_eq!(entries[0].scope.account, bob.account);

        // Отправитель разблокирован — метод применяется.
        env.sender_lists
            .put_sender_list(
                scope(&bob),
                SenderList {
                    safe: Vec::new(),
                    blocked: Vec::new(),
                },
            )
            .await
            .expect("list");
        let r = respond(&env, &bob, &email.to_string(), "accepted").await;
        assert_eq!(r[1]["applied"], true, "{r}");
        let org = stored(&env, env.scope, "u1")
            .await
            .expect("событие организатора");
        assert!(org.body.contains("PARTSTAT=ACCEPTED"), "{}", org.body);
    }

    /// Чужое приглашение (интернет) при кнопке по умолчанию приёмом не вносится (решение 124): итог —
    /// `applied = false` с причиной, без события и без ответа организатору.
    #[tokio::test]
    async fn external_invite_reports_refusal_of_the_inbox() {
        let env = Env::new().await;
        let bob = env.user(BOB).await;
        let email = deliver(
            &env,
            BOB,
            SpecialUse::Inbox,
            &invite("boss@partner.example", BOB),
        )
        .await;

        let r = respond(&env, &bob, &email.to_string(), "accepted").await;
        assert_eq!(r[0], "Invitation/respond", "{r}");
        assert_eq!(r[1]["applied"], false, "{r}");
        assert!(
            r[1]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("разрешено"),
            "{r}"
        );
        assert!(stored(&env, scope(&bob), "u1").await.is_none());
        assert!(env.imip.sent().is_empty(), "ответ не отправляется");
    }

    /// Ошибки входа: неизвестное письмо, письмо без приглашения, недопустимый статус; без capability —
    /// `unknownMethod`; capability объявлена только при подключённом планировании.
    #[tokio::test]
    async fn rejects_bad_input_and_declares_capability() {
        let env = Env::new().await;
        let bob = env.user(BOB).await;

        // Неизвестное письмо — `notFound`, недопустимый идентификатор — `invalidArguments`.
        let r = respond(
            &env,
            &bob,
            "00000000-0000-0000-0000-000000000000",
            "accepted",
        )
        .await;
        assert_eq!(r[1]["type"], "notFound", "{r}");
        let r = respond(&env, &bob, "nope", "accepted").await;
        assert_eq!(r[1]["type"], "invalidArguments", "{r}");
        let plain = crate::testenv::mail("Отчёт", ORG, "", "текст");
        let plain = deliver(&env, BOB, SpecialUse::Inbox, &plain).await;
        let r = respond(&env, &bob, &plain.to_string(), "accepted").await;
        assert_eq!(r[1]["type"], "notAnInvitation", "{r}");
        let invite_id = deliver(&env, BOB, SpecialUse::Inbox, &invite(ORG, BOB)).await;
        let r = respond(&env, &bob, &invite_id.to_string(), "maybe").await;
        assert_eq!(r[1]["type"], "invalidArguments", "{r}");

        // Метод — только под своей capability.
        let req = json!({"using": ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"],
            "methodCalls": [["Invitation/respond", {
                "accountId": bob.account.to_string(), "emailId": invite_id.to_string(),
                "participationStatus": "accepted"}, "c0"]]});
        let resp = env
            .jmap
            .api(&bob, req.to_string().as_bytes())
            .await
            .expect("api");
        let resp = serde_json::to_value(resp).expect("serialize");
        assert_eq!(resp["methodResponses"][0][0], "error");
        assert_eq!(resp["methodResponses"][0][1]["type"], "unknownMethod");

        // Capability в сессии — с планированием; без планирования не объявляется.
        let s = env
            .jmap
            .session(&env.principal, "https://mail.example.org")
            .await;
        assert!(s["capabilities"][CAP].is_object(), "{s}");
        assert_eq!(s["primaryAccounts"][CAP], json!(env.account()));
        let bare = Env::unscheduled().await;
        let s = bare
            .jmap
            .session(&bare.principal, "https://mail.example.org")
            .await;
        assert!(s["capabilities"][CAP].is_null(), "{s}");
    }
}
