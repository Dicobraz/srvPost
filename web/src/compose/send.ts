/*
  Отправка и undo-send (WEB-04): один запрос JMAP — Email/set создаёт письмо в «Отправленные»
  (create до destroy — черновик в том же вызове уничтожается) и EmailSubmission/set ставит
  отправку по ссылке `#<cid>` на созданное письмо (RFC 8621 §7.4; сервер принимает ссылку —
  `ctx.resolve_id` на созданное в этом же запросе). Отложенная отправка: sendAt = сейчас +
  UNDO_SEND_SECONDS (окно undo, решение карточки ~15 с) — до срока отправка `pending`,
  отмена — EmailSubmission/set update {undoStatus: "canceled"}; после выпуска сервер отвечает
  cannotUnsend — письмо реально ушло, тост честно сообщает (undo идемпотентен). Если сервер не
  даёт maxDelayedSend на окно undo — отправка немедленная, кнопки «Отменить» у тоста нет.
  Отправка офлайн — очередь WEB-09 (не здесь).
*/

import { jmapCall, submissionSet, type JmapSession } from "../api/jmap";
import type { JmapEnv } from "../mail/types";
import { attachmentParts, type ComposeSnapshot } from "./model";
import { rememberSent } from "./send-history";

/** Окно undo-send: как в карточке (~15 с) и Postman. */
export const UNDO_SEND_SECONDS = 15;

/** Право сервера на отложенную отправку не меньше окна undo (accountCapabilities.submission). */
export function supportsUndoSend(session: JmapSession, accountId: string, seconds = UNDO_SEND_SECONDS): boolean {
  const caps = session.accounts[accountId]?.accountCapabilities ?? {};
  const submission = caps["urn:ietf:params:jmap:submission"] as { maxDelayedSend?: number } | undefined;
  return typeof submission?.maxDelayedSend === "number" && submission.maxDelayedSend >= seconds;
}

/** Ошибка отправки с типом JMAP (forbiddenToSend и пр.) — честный текст в тост. */
export class SendError extends Error {
  constructor(
    public readonly type: string,
    message: string,
  ) {
    super(message);
    this.name = "SendError";
  }
}

/** Разбор set-ошибки одного объекта → SendError (или обычная — HTTP-сбой запроса). */
function setFailure(errors: Record<string, { type?: string; description?: string }>, cid: string): SendError | null {
  const err = errors[cid];
  if (!err?.type) return null;
  return new SendError(err.type, err.description || `Отправка не выполнена (${err.type}).`);
}

/** Объект Email/set create письма в «Отправленные» из снимка. */
export function sentEmailCreate(
  sentMailboxId: string,
  s: ComposeSnapshot,
  extra: { inReplyTo?: string[] | null; references?: string[] | null } = {},
): Record<string, unknown> {
  const email: Record<string, unknown> = {
    mailboxIds: { [sentMailboxId]: true },
    keywords: { $seen: true },
    ...(s.from ? { from: [{ name: s.from.name, email: s.from.email }] } : {}),
    ...(s.to.length > 0 ? { to: s.to.map((r) => ({ name: r.name, email: r.email })) } : {}),
    ...(s.cc.length > 0 ? { cc: s.cc.map((r) => ({ name: r.name, email: r.email })) } : {}),
    ...(s.bcc.length > 0 ? { bcc: s.bcc.map((r) => ({ name: r.name, email: r.email })) } : {}),
    subject: s.subject,
    htmlBody: [{ partId: "body", type: "text/html" }],
    bodyValues: { body: { value: s.bodyHtml, isEncodingProblem: false, isTruncated: false } },
    ...(extra.inReplyTo ? { inReplyTo: extra.inReplyTo } : {}),
    ...(extra.references ? { references: extra.references } : {}),
  };
  const parts = attachmentParts(s.attachments);
  if (parts.length > 0) email.attachments = parts;
  return email;
}

/** Результат успешной отправки: что отменить (undo) и кому ушло (история подсказок). */
export interface SendResult {
  /** EmailSubmission id — отменить до срока (undoStatus: canceled). */
  submissionId: string;
  /** Отложенная отправка есть — окно undo реально действует (иначе письмо уже ушло). */
  undoable: boolean;
  /** Все адресаты письма (Кому/Копия/Скрытая) — запись в историю отправок. */
  recipients: Array<{ name: string | null; email: string }>;
}

/** Все получатели снимка (учёт «Кому», «Копия», «Скрытая» — конверт строит сервер из заголовков). */
export function allRecipients(s: ComposeSnapshot): Array<{ name: string | null; email: string }> {
  return [...s.to, ...s.cc, ...s.bcc];
}

/**
 * Отправка письма: Email/set (письмо в «Отправленные», черновик — в destroy) + EmailSubmission/set
 * (sendAt на окно undo, если сервер поддерживает) одним запросом. Ответы передают In-Reply-To/
 * References оригинала (references).
 */
export async function sendMessage(
  env: JmapEnv,
  snapshot: ComposeSnapshot,
  options: {
    sentMailboxId: string;
    identityId: string;
    /** Черновик уничтожить в том же запросе (id из DraftSaver). */
    destroyDraftId?: string | null;
    /** Сервер поддерживает отложенную отправку на окно undo. */
    undoable: boolean;
    /** Цепочка ответа (RFC 8621 §4.1.2.7). */
    references?: { inReplyTo?: string[] | null; references?: string[] | null };
  },
): Promise<SendResult> {
  const cid = "e0";
  const sid = "s0";
  const sendAt = options.undoable
    ? new Date(Date.now() + UNDO_SEND_SECONDS * 1000).toISOString()
    : undefined;
  const methodCalls: Array<[string, Record<string, unknown>, string]> = [
    [
      "Email/set",
      {
        accountId: env.accountId,
        create: { [cid]: sentEmailCreate(options.sentMailboxId, snapshot, options.references ?? {}) },
        ...(options.destroyDraftId ? { destroy: [options.destroyDraftId] } : {}),
      },
      "e",
    ],
    [
      "EmailSubmission/set",
      {
        accountId: env.accountId,
        create: {
          [sid]: {
            identityId: options.identityId,
            emailId: `#${cid}`,
            ...(sendAt ? { sendAt } : {}),
          },
        },
      },
      "s",
    ],
  ];
  let body;
  try {
    body = await jmapCall(
      env.apiUrl,
      env.authorization,
      ["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail", "urn:ietf:params:jmap:submission"],
      methodCalls,
    );
  } catch (e) {
    throw e instanceof Error ? e : new SendError("network", "Сеть недоступна: письмо не отправлено.");
  }
  const responses = new Map(body.methodResponses.map(([name, args]) => [name, args]));
  const emailSet = (responses.get("Email/set") ?? {}) as Record<string, unknown>;
  const submissionSetResponse = (responses.get("EmailSubmission/set") ?? {}) as Record<string, unknown>;

  // Ошибка метода целиком (RFC 8620 §3.6.1) — не объекты notCreated, а верхнеуровневый отказ.
  for (const [name, res] of [["Email/set", emailSet], ["EmailSubmission/set", submissionSetResponse]] as const) {
    if ((res["@type"] as string | undefined) === "error") {
      const err = res as { type?: string; description?: string };
      throw new SendError(err.type ?? "error", err.description || `Отправка не выполнена (${name}).`);
    }
  }

  const emailError = setFailure(
    (emailSet.notCreated as Record<string, { type?: string; description?: string }> | undefined) ?? {},
    cid,
  );
  if (emailError) throw emailError;
  const submissionError = setFailure(
    (submissionSetResponse.notCreated as Record<string, { type?: string; description?: string }> | undefined) ?? {},
    sid,
  );
  if (submissionError) throw submissionError;

  const created = (submissionSetResponse.created as Record<string, { id?: string }> | undefined) ?? {};
  const submissionId = created[sid]?.id;
  if (!submissionId) throw new SendError("serverFail", "Узел не вернул идентификатор отправки.");

  const recipients = allRecipients(snapshot);
  rememberSent(recipients);
  return {
    submissionId,
    undoable: options.undoable,
    recipients,
  };
}

/**
 * Отмена отправки в окне undo: EmailSubmission/set update {undoStatus: "canceled"}. Сервер
 * снимает письмо с выпуска очереди; после срока — cannotUnsend (письмо ушло, тост честно
 * пропадает). Успех: true — черновик можно восстановить.
 */
export async function cancelSend(env: JmapEnv, submissionId: string): Promise<boolean> {
  const result = await submissionSet(env.apiUrl, env.authorization, env.accountId, {
    update: { [submissionId]: { undoStatus: "canceled" } },
  });
  return Object.keys(result.errors).length === 0;
}
