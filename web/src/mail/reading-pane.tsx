/*
  Чтение (WEB-03): письмо — панель по макету 01. Беседа: «N писем · участников · Развернуть все»;
  тело HTML — hostile input (sanitize.ts): sandboxed iframe без same-origin, внешние картинки —
  opt-in (баннер «Загрузить / Всегда для домена», решение в localStorage), подменённые ссылки —
  красная полоса безопасности; text/plain — <pre>-вью. Вложения — ссылки скачивания (blob).
  Карточка приглашения (.ics) — кнопки ответа живые (WEB-06, JMAP-50): метод веб-почты
  Invitation/respond; приглашение в «Спаме» — структурированная ошибка и перенос письма
  (invite-respond.ts). WEB-05 — поиск: клик-уточнения по отправителю и дате письма (чипы
  панели фильтров, click-refinements); подсветка совпадений F3/Shift+F3 — термы поиска
  передаются в srcdoc (highlight.ts), счётчик совпадений — рядом с темой.
*/
import { useEffect, useMemo, useRef, useState } from "react";

import {
  blobUrl,
  type EmailBodyPart,
  type EmailFull,
  type EmailSummary,
  type JmapSession,
} from "../api/jmap";
import { useJmap } from "./context";
import {
  buildBodyDoc,
  plainTextHtml,
  sanitizeEmailHtml,
} from "./sanitize";
import { dayRibbon, formatInvitationWhen, isInvitationPart, parseInvitation, type Invitation } from "./invite";
import {
  canRespondToInvitations,
  errorText,
  inboxOf,
  isJunkError,
  moveToInbox,
  respondToInvitation,
  type ParticipationStatus,
} from "./invite-respond";
import { useMailboxes } from "./queries";
import { Icon } from "./icons";
import { initials } from "./message-list";
import { useToast } from "./toast";
import { TAKE_LABELS, type TakeAct } from "./shared";

/** Панель параметров чтения письма: разрешение картинок на это письмо/домен. */
export interface ReadToggles {
  /** Картинки разрешены для этого письма (баннер «Загрузить»). */
  imagesThisEmail: boolean;
  /** Картинки всегда разрешены для домена отправителя (баннер «Всегда для домена»). */
  imagesForDomain: boolean;
  onAllowThisEmail(): void;
  onAllowDomain(): void;
}

/** Состояние подсветки письма (hl-state из srcdoc): совпадений и текущий номер. */
export interface MatchState {
  count: number;
  index: number;
}

/** Полоса «Взять в работу» (WEB-15): кто взял письмо общего ящика и что сделает кнопка. */
export interface TakeStrip {
  act: TakeAct;
  /** Имя взявшего (справочник) или адрес; null — «никто не взял». */
  who: string | null;
  /** Когда взял (метка времени ISO) — в полосе рядом с именем. */
  at: string | null;
  /** Запрос «взять/вернуть» идёт — кнопка ждёт. */
  busy: boolean;
}

interface ReadingPaneProps {
  summary: EmailSummary | null;
  /** Письма развёрнутой беседы (стопка) или только выбранное. */
  stack: EmailSummary[];
  stackFull: Record<string, EmailFull>;
  toggles: ReadToggles;
  onExpandAll(): void;
  collapsed: boolean;
  prevNext: { prev: string | null; next: string | null };
  onPrevNext(id: string): void;
  // --- WEB-05 ---
  /** Термы подсветки активного поиска (пусто — письмо открыто не из поиска, без подсветки). */
  highlightTerms: string[];
  /** Счётчик совпадений подсветки (hl-state из iframe). */
  matchState: MatchState | null;
  /** Регистрация iframe тела (для команд F3; последний смонтированный — активный). */
  onBodyFrame(frame: HTMLIFrameElement | null): void;
  /** Уточнения кликом (только в режиме поиска): отправитель и период. */
  onRefineSender(email: EmailSummary): void;
  onRefinePeriod(email: EmailSummary): void;
  // --- WEB-15: «Взять в работу» ---
  /** Полоса «Взято» письма общего ящика; null — письмо не из общего ящика, полосы нет. */
  take: TakeStrip | null;
  onTake(): void;
  // --- WEB-19: напоминания ---
  /** Текст напоминаний письма («До ср · Ждём ответа») или null — напоминаний нет. */
  reminder: string | null;
  /** Открыть пикер напоминания у кнопки вызова (координаты — в окне). */
  onRemind(x: number, y: number): void;
  /** Снять напоминание (все слова pm.due/pm.wait/pm.expire). */
  onReminderClear(): void;
}

/** Полоса напоминания письма (WEB-19): что стоит и когда — «Напомнить…» открывает inline-пикер,
 * «Снять» убирает слова pm.due/pm.wait/pm.expire (в полосе «Напоминания» письмо исчезнет сразу —
 * инвалидация по мутации). */
function ReminderBar({
  reminder,
  onRemind,
  onReminderClear,
}: {
  reminder: string | null;
  onRemind(x: number, y: number): void;
  onReminderClear(): void;
}) {
  const open = (e: React.MouseEvent<HTMLButtonElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    onRemind(Math.round(r.left), Math.round(r.bottom + 6));
  };
  return (
    <div className="strip remind">
      <Icon name="bell" size={16} />
      {reminder ? (
        <span>
          <b>Напоминание:</b> {reminder}
        </span>
      ) : (
        <span>Напоминания нет</span>
      )}
      <span className="sp" />
      {reminder && (
        <button type="button" className="lk" onClick={onReminderClear}>
          Снять
        </button>
      )}
      <button type="button" className="lk" onClick={open}>
        Напомнить…
      </button>
    </div>
  );
}

/** Полоса над письмом: никто не взял — «Взять в работу»; взял коллега — «Взято в работу: имя ·
 * время» и «Забрать себе»; взял я — «Вы взяли в работу · время» и «Вернуть в очередь» (как в
 * Postman, S5-28). */
function TakeBar({ take, onTake }: { take: TakeStrip; onTake(): void }) {
  const me = take.act === "release";
  return (
    <div className="strip taken" role="status">
      <Icon name="person" size={16} />
      {take.who && !me ? (
        <span>
          <b>Взято в работу:</b> {take.who}
          {take.at && <> · {new Date(take.at).toLocaleString("ru", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })}</>}
        </span>
      ) : me ? (
        <span>
          <b>Вы взяли в работу</b>
          {take.at && <> · {new Date(take.at).toLocaleString("ru", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })}</>}
        </span>
      ) : (
        <span>Никто не взял в работу</span>
      )}
      <span className="sp" />
      <button type="button" className="lk" disabled={take.busy} onClick={onTake}>
        {TAKE_LABELS[take.act]}
      </button>
    </div>
  );
}

/** Тип письма для вкладки/строки: конверт синий (макет). */
function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString("ru", {
    weekday: "short",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function senderOf(email: EmailSummary): { name: string; address: string } {
  const from = email.from?.[0];
  return { name: from?.name?.trim() || from?.email || "(неизвестный)", address: from?.email ?? "" };
}

function formatSize(size: number): string {
  if (size >= 1_048_576) return `${(size / 1_048_576).toFixed(1)} МБ`;
  if (size >= 1024) return `${Math.round(size / 1024)} КБ`;
  return `${size} Б`;
}

/** Тело письма: HTML — sanitized iframe; текст — <pre>; вложения и приглашение — из Email/get.
 * Термы поиска — в srcdoc (подсветка F3, WEB-05): iframe перерисовывается при смене термов. */
function EmailBody({
  summary,
  full,
  toggles,
  session,
  accountId,
  highlightTerms,
  onBodyFrame,
}: {
  summary: EmailSummary;
  full: EmailFull | null;
  toggles: ReadToggles;
  session: JmapSession;
  accountId: string;
  highlightTerms: string[];
  onBodyFrame(frame: HTMLIFrameElement | null): void;
}) {
  const senderDomain = senderOf(summary).address.split("@")[1] ?? "";
  const allowImages = toggles.imagesThisEmail || toggles.imagesForDomain;
  const frameRef = useRef<HTMLIFrameElement | null>(null);

  // Регистрация iframe тела: активный (последний смонтированный) получает команды F3.
  useEffect(() => {
    onBodyFrame(frameRef.current);
    return () => onBodyFrame(null);
  }, [onBodyFrame]);

  // Ключ memo — строка термов: смена поиска перерисовывает srcdoc с новым скриптом подсветки.
  const termsKey = highlightTerms.join("\u0001");

  const bodyHtml = useMemo(() => {
    if (!full) return null;
    const htmlPart = full.htmlBody?.[0];
    if (htmlPart?.partId) {
      const value = full.bodyValues[htmlPart.partId]?.value;
      if (value) return { html: value, plain: false };
    }
    const textPart = full.textBody?.[0];
    if (textPart?.partId) {
      const value = full.bodyValues[textPart.partId]?.value;
      if (value) return { html: plainTextHtml(value), plain: true };
    }
    return { html: "", plain: false };
  }, [full]);

  const terms = useMemo(() => termsKey.split("\u0001").filter(Boolean), [termsKey]);

  const sanitized = useMemo(() => {
    if (!bodyHtml || bodyHtml.plain) return null;
    return sanitizeEmailHtml(bodyHtml.html, { allowImages, highlight: terms });
  }, [bodyHtml, allowImages, terms]);

  const attachments = (full?.attachments ?? []).filter((p) => !isInvitationPart(p.type) && p.disposition !== "inline");
  const calendarPart = (full?.attachments ?? []).find((p) => isInvitationPart(p.type));
  const ics = calendarPart?.partId ? full?.bodyValues[calendarPart.partId]?.value ?? null : null;
  const invitation = useMemo(() => (ics ? parseInvitation(ics) : null), [ics]);

  const spoofed = sanitized?.spoofedLinks ?? [];
  const blocked = sanitized?.blockedImageHosts ?? [];

  return (
    <>
      {!allowImages && blocked.length > 0 && (
        <div className="strip img">
          <Icon name="imgoff" size={16} />
          <span>
            <b>Внешние картинки скрыты</b> · <span className="dom">{blocked.join(", ")}</span>
          </span>
          <span className="sp" />
          <button type="button" className="lk" onClick={toggles.onAllowThisEmail}>
            Загрузить картинки
          </button>
          <button type="button" className="lk" onClick={toggles.onAllowDomain}>
            Всегда для {senderDomain || "отправителя"}
          </button>
        </div>
      )}
      {spoofed.length > 0 && (
        <div className="strip threat">
          <Icon name="shield" size={16} />
          <span>
            <b>Ссылка не совпадает с адресом:</b> «{spoofed[0].text.slice(0, 40)}» ведёт на <b>{spoofed[0].domain}</b>
          </span>
          <span className="sp" />
          <details>
            <summary className="lk">Показать адрес</summary>
            {spoofed.map((l, i) => (
              <div key={i} className="addr">
                {l.href}
              </div>
            ))}
          </details>
        </div>
      )}

      {attachments.length > 0 && (
        <div className="atts">
          {attachments.map((p) => (
            <AttachmentChip key={p.partId ?? p.blobId} part={p} session={session} accountId={accountId} />
          ))}
        </div>
      )}

      {invitation && <InvitationCard invitation={invitation} emailId={summary.id} />}

      <div className="bodym">
        {bodyHtml === null ? (
          <p className="empty">Загружаем тело письма…</p>
        ) : sanitized ? (
          // HTML письма — srcdoc-документ санитайзера (CSP + click-guard внутри, CSS изолирован)
          <iframe
            ref={frameRef}
            title="Тело письма"
            sandbox="allow-popups allow-popups-to-escape-sandbox allow-scripts"
            srcDoc={sanitized.doc}
          />
        ) : (
          // text/plain — безопасный <pre> (plainTextHtml, без внешних адресов и картинок)
          <iframe
            ref={frameRef}
            title="Текст письма"
            sandbox="allow-popups allow-popups-to-escape-sandbox allow-scripts"
            srcDoc={buildBodyDoc(bodyHtml?.html ?? "", false, terms)}
          />
        )}
      </div>
    </>
  );
}

/** Вложение: имя, размер, скачивание (downloadUrl сессии; сохранение всех — WEB-16). */
function AttachmentChip({ part, session, accountId }: { part: EmailBodyPart; session: JmapSession; accountId: string }) {
  const name = part.name ?? "вложение";
  const url = part.blobId ? blobUrl(session, accountId, part.blobId, name) : null;
  return (
    <a className="att" href={url ?? undefined} download={name}>
      <Icon name="doc" size={16} />
      {name}
      <span className="sz">{formatSize(part.size)}</span>
    </a>
  );
}

/** Статус ответа карточки: подпись чипа в заголовке и подсказка строки. */
const ANSWER_LABELS: Record<ParticipationStatus, string> = {
  accepted: "Принято",
  tentative: "Под вопросом",
  declined: "Отклонено",
};

/** Карточка приглашения (WEB-06): детали, лента «Ваш день», ответ методом веб-почты
 * (JMAP-50). Приглашение в «Спаме» — структурированная ошибка `invitationInJunk`: inline
 * полоса «сначала перенесите письмо», кнопка переноса во «Входящие» и повтор ответа.
 * (Экспорт для тестов спам-сценария.) */
export function InvitationCard({
  invitation,
  emailId,
}: {
  invitation: Invitation;
  emailId: string;
}) {
  const env = useJmap();
  const toast = useToast();
  const mailboxes = useMailboxes();
  const canRespond = canRespondToInvitations(env);
  const [pending, setPending] = useState<ParticipationStatus | null>(null);
  const [answered, setAnswered] = useState<ParticipationStatus | null>(null);
  const [junkBlocked, setJunkBlocked] = useState(false);
  const [lastStatus, setLastStatus] = useState<ParticipationStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const respond = async (status: ParticipationStatus): Promise<void> => {
    setPending(status);
    setError(null);
    try {
      const outcome = await respondToInvitation(env, emailId, status);
      if (outcome.kind === "applied") {
        setAnswered(status);
        setJunkBlocked(false);
        toast.show(
          `Ответ отправлен: ${ANSWER_LABELS[status].toLowerCase()} — организатор получит обновление календаря`,
        );
      } else if (outcome.kind === "refused") {
        setError(outcome.reason);
      } else if (isJunkError(outcome)) {
        setLastStatus(status);
        setJunkBlocked(true);
      } else {
        setError(errorText(outcome));
      }
    } catch {
      setError("Сеть недоступна: ответ не отправлен.");
    } finally {
      setPending(null);
    }
  };

  const moveAndRespond = async (): Promise<void> => {
    const inbox = inboxOf(mailboxes);
    if (!inbox) {
      setError("Папка «Входящие» не найдена — перенесите письмо из «Спама» вручную.");
      return;
    }
    setPending(lastStatus ?? "accepted");
    try {
      const moved = await moveToInbox(env, emailId, inbox.id);
      if (!moved) {
        setError("Перенос не удался — попробуйте ещё раз.");
        return;
      }
      setJunkBlocked(false);
      toast.show("Письмо перенесено из «Спама» во «Входящие»");
      if (lastStatus) await respond(lastStatus);
    } catch {
      setError("Сеть недоступна: перенос не выполнен.");
    } finally {
      setPending(null);
    }
  };

  const now = new Date();
  const ribbon = invitation.start && invitation.end ? dayRibbon(invitation.start, invitation.end, now) : null;
  const hours = ribbon?.filter((r) => "hour" in r) as Array<{ hour: number; label: string }> | null;
  const invite = ribbon?.find((r) => "invite" in r) as { top: number; height: number; nowTop: number | null } | undefined;
  const busy = pending !== null;
  return (
    <div className="inv">
      <div className="ih">
        <span className="cal-glyph">
          <Icon name="cal" size={16} />
        </span>
        <span className="ttl">Приглашение: {invitation.summary || "(без названия)"}</span>
        <span className="chip">{answered ? ANSWER_LABELS[answered] : "Ждёт ответа"}</span>
      </div>
      <div className="det">
        <b>{formatInvitationWhen(invitation.start, invitation.end)}</b>
        {invitation.location && <> · {invitation.location}</>}
        {invitation.organizer && <> · организатор: {invitation.organizer}</>}
        {invitation.attendees > 0 && (
          <> · {invitation.accepted} из {invitation.attendees} приняли</>
        )}
      </div>
      {hours && invite && (
        <div className="day">
          <div className="lbl">
            <b>Ваш день</b>
            <br />
            {hours[0]?.label}–{hours[hours.length - 1]?.label}
          </div>
          <div className="hours">
            {hours.map((h) => (
              <div key={h.hour} className="hrow">
                <span className="hl">{h.label}</span>
              </div>
            ))}
            <div className="ev invite" style={{ top: invite.top, height: invite.height }}>
              {invitation.summary || "Встреча"}
            </div>
            {invite.nowTop !== null && <div className="nowline" data-now={now.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" })} style={{ top: invite.nowTop }} />}
          </div>
        </div>
      )}
      {junkBlocked && (
        <div className="inv-junk" role="alert">
          <span>
            <b>Приглашение лежит в «Спаме».</b> Сначала перенесите письмо, затем ответьте —
            сервер не применяет ответы из спама.
          </span>
          <button type="button" className="lk" disabled={busy} onClick={() => void moveAndRespond()}>
            Перенести из «Спама» и ответить
          </button>
        </div>
      )}
      {error && (
        <div className="inv-err" role="alert">
          ▲ {error}
        </div>
      )}
      <div className="invacts">
        <button
          type="button"
          className="ibtn acc"
          disabled={!canRespond || busy || answered !== null}
          title={canRespond ? undefined : "Ответы на встречи недоступны на этом узле"}
          onClick={() => void respond("accepted")}
        >
          ✓ Принять
        </button>
        <button
          type="button"
          className="ibtn tint"
          disabled={!canRespond || busy || answered !== null}
          title={canRespond ? undefined : "Ответы на встречи недоступны на этом узле"}
          onClick={() => void respond("tentative")}
        >
          ? Под вопросом
        </button>
        <button
          type="button"
          className="ibtn tint"
          disabled={!canRespond || busy || answered !== null}
          title={canRespond ? undefined : "Ответы на встречи недоступны на этом узле"}
          onClick={() => void respond("declined")}
        >
          ✕ Отклонить
        </button>
        <span className="invnote">
          {answered
            ? `Ответ «${ANSWER_LABELS[answered]}» ушёл через календарь сервера`
            : "Ответ уйдёт через календарь сервера"}
        </span>
      </div>
    </div>
  );
}

export function ReadingPane({
  summary,
  stack,
  stackFull,
  toggles,
  onExpandAll,
  collapsed,
  prevNext,
  onPrevNext,
  highlightTerms,
  matchState,
  onBodyFrame,
  onRefineSender,
  onRefinePeriod,
  take,
  onTake,
  reminder,
  onRemind,
  onReminderClear,
}: ReadingPaneProps) {
  const env = useJmap();
  const refinable = highlightTerms.length > 0; // уточнения кликом — только в режиме поиска (WEB-05)
  if (!summary) {
    return (
      <section className="read" aria-label="Чтение">
        <p className="empty">Выберите письмо — J/K по списку, Enter — открыть.</p>
      </section>
    );
  }
  const participants = new Set<string>();
  for (const m of stack) {
    const f = m.from?.[0];
    if (f) participants.add(f.name?.trim() || f.email);
  }
  return (
    <section className="read" aria-label="Чтение">
      <h3>
        {summary.subject ?? "(без темы)"}
        {matchState && matchState.count > 0 && (
          <span className="hlcnt" title="Совпадения поиска в письме (F3 — дальше, Shift+F3 — назад)">
            {matchState.index < 0 ? matchState.count : `${matchState.index + 1}/${matchState.count}`}
          </span>
        )}
      </h3>
      <ReminderBar reminder={reminder} onRemind={onRemind} onReminderClear={onReminderClear} />
      {take && <TakeBar take={take} onTake={onTake} />}
      {stack.length > 1 && (
        <div className="tbar">
          Беседа: {stack.length} писем · {participants.size} участник(ов)
          <button type="button" className="lk" onClick={onExpandAll}>
            {collapsed ? "Развернуть все" : "Свернуть"}
          </button>
          <span style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            <button type="button" className="lk" disabled={!prevNext.prev} onClick={() => prevNext.prev && onPrevNext(prevNext.prev)}>
              ‹ пред
            </button>
            <button type="button" className="lk" disabled={!prevNext.next} onClick={() => prevNext.next && onPrevNext(prevNext.next)}>
              след ›
            </button>
          </span>
        </div>
      )}
      {(collapsed ? stack.slice(-1) : stack).map((m) => (
        <div key={m.id} className="thread-message">
          <div className="mhead">
            <div className="ava">{initials(senderOf(m).name)}</div>
            <div className="who">
              <b
                className={refinable ? "rfx" : undefined}
                title={refinable ? "Уточнить: письма этого отправителя" : undefined}
                onClick={
                  refinable
                    ? () => onRefineSender(m)
                    : undefined
                }
              >
                {senderOf(m).name}
              </b>{" "}
              <span className="adr">&lt;{senderOf(m).address}&gt;</span>
              <div className="meta">
                <span
                  className={refinable ? "rfx" : undefined}
                  title={refinable ? "Уточнить: этот месяц" : undefined}
                  onClick={refinable ? () => onRefinePeriod(m) : undefined}
                >
                  {formatDate(m.receivedAt)}
                </span>
                {" · Кому: "}
                {(m.to ?? []).map((t) => t.name?.trim() || t.email).join(", ") || env.selfAddress}
              </div>
            </div>
            <div className="right" />
          </div>
          <EmailBody
            summary={m}
            full={stackFull[m.id] ?? null}
            toggles={toggles}
            session={env.session}
            accountId={env.accountId}
            highlightTerms={highlightTerms}
            onBodyFrame={onBodyFrame}
          />
        </div>
      ))}
    </section>
  );
}
