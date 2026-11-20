/*
  Чтение (WEB-03): письмо — панель по макету 01. Беседа: «N писем · участников · Развернуть все»;
  тело HTML — hostile input (sanitize.ts): sandboxed iframe без same-origin, внешние картинки —
  opt-in (баннер «Загрузить / Всегда для домена», решение в localStorage), подменённые ссылки —
  красная полоса безопасности; text/plain — <pre>-вью. Вложения — ссылки скачивания (blob).
  Карточка приглашения (.ics) — заглушка по макету: кнопки ответа disabled с подсказкой
  «в разработке» (ответы примет волна 6, JMAP-50).
*/
import { useMemo } from "react";

import { blobUrl, type EmailBodyPart, type EmailFull, type EmailSummary, type JmapSession } from "../api/jmap";
import { useJmap } from "./context";
import {
  areImagesAllowedFor,
  buildBodyDoc,
  plainTextHtml,
  sanitizeEmailHtml,
} from "./sanitize";
import { dayRibbon, formatInvitationWhen, isInvitationPart, parseInvitation } from "./invite";
import { Icon } from "./icons";
import { initials } from "./message-list";

/** Панель параметров чтения письма: разрешение картинок на это письмо/домен. */
export interface ReadToggles {
  /** Картинки разрешены для этого письма (баннер «Загрузить»). */
  imagesThisEmail: boolean;
  /** Картинки всегда разрешены для домена отправителя (баннер «Всегда для домена»). */
  imagesForDomain: boolean;
  onAllowThisEmail(): void;
  onAllowDomain(): void;
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

/** Тело письма: HTML — sanitized iframe; текст — <pre>; вложения и приглашение — из Email/get. */
function EmailBody({
  summary,
  full,
  toggles,
  session,
  accountId,
}: {
  summary: EmailSummary;
  full: EmailFull | null;
  toggles: ReadToggles;
  session: JmapSession;
  accountId: string;
}) {
  const senderDomain = senderOf(summary).address.split("@")[1] ?? "";
  const allowImages = toggles.imagesThisEmail || toggles.imagesForDomain;

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

  const sanitized = useMemo(() => {
    if (!bodyHtml || bodyHtml.plain) return null;
    return sanitizeEmailHtml(bodyHtml.html, { allowImages });
  }, [bodyHtml, allowImages]);

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

      {invitation && <InvitationCard invitation={invitation} />}

      <div className="bodym">
        {bodyHtml === null ? (
          <p className="empty">Загружаем тело письма…</p>
        ) : sanitized ? (
          // HTML письма — srcdoc-документ санитайзера (CSP + click-guard внутри, CSS изолирован)
          <iframe
            title="Тело письма"
            sandbox="allow-popups allow-popups-to-escape-sandbox allow-scripts"
            srcDoc={sanitized.doc}
          />
        ) : (
          // text/plain — безопасный <pre> (plainTextHtml, без внешних адресов и картинок)
          <iframe
            title="Текст письма"
            sandbox="allow-popups allow-popups-to-escape-sandbox allow-scripts"
            srcDoc={buildBodyDoc(bodyHtml?.html ?? "", false)}
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

/** Карточка приглашения (заглушка волны 3): детали, лента «Ваш день», кнопки disabled. */
function InvitationCard({ invitation }: { invitation: ReturnType<typeof parseInvitation> }) {
  if (!invitation) return null;
  const now = new Date();
  const ribbon = invitation.start && invitation.end ? dayRibbon(invitation.start, invitation.end, now) : null;
  const hours = ribbon?.filter((r) => "hour" in r) as Array<{ hour: number; label: string }> | null;
  const invite = ribbon?.find((r) => "invite" in r) as { top: number; height: number; nowTop: number | null } | undefined;
  return (
    <div className="inv">
      <div className="ih">
        <span className="cal-glyph">
          <Icon name="cal" size={16} />
        </span>
        <span className="ttl">Приглашение: {invitation.summary || "(без названия)"}</span>
        <span className="chip">Ждёт ответа</span>
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
      <div className="invacts">
        <button type="button" className="ibtn acc" disabled title="В разработке — ответы на встречи примет волна 6">
          ✓ Принять
        </button>
        <button type="button" className="ibtn tint" disabled title="В разработке — ответы на встречи примет волна 6">
          ? Под вопросом
        </button>
        <button type="button" className="ibtn tint" disabled title="В разработке — ответы на встречи примет волна 6">
          ✕ Отклонить
        </button>
        <span className="invnote">Ответ уйдёт через календарь сервера</span>
      </div>
    </div>
  );
}

export function ReadingPane({ summary, stack, stackFull, toggles, onExpandAll, collapsed, prevNext, onPrevNext }: ReadingPaneProps) {
  const env = useJmap();
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
      <h3>{summary.subject ?? "(без темы)"}</h3>
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
              <b>{senderOf(m).name}</b> <span className="adr">&lt;{senderOf(m).address}&gt;</span>
              <div className="meta">
                {formatDate(m.receivedAt)} · Кому: {(m.to ?? []).map((t) => t.name?.trim() || t.email).join(", ") || env.selfAddress}
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
          />
        </div>
      ))}
    </section>
  );
}
