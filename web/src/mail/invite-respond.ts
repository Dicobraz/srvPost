/*
  Ответ на приглашение из письма (WEB-06, JMAP-50): кнопки карточки вызывают метод веб-почты
  `Invitation/respond` (капабилити `urn:thepost:params:jmap:itip`) — сервер сам читает письмо,
  проверяет папку и спам-вердикт, применяет iTIP и рассылает REPLY организатору. Отказ
  структурированный: `invitationInJunk` — приглашение в «Спаме» (сначала перенесите письмо),
  `senderBlocked` — отправитель в списке заблокированных; ошибки отдаются карточке как есть
  (человекочитаемое описание сервера). Идемпотентно: повторный ответ не рассылает лишний REPLY.
*/

import {
  isMethodError,
  emailSetUpdate,
  invitationRespond,
  CAP_ITIP,
  hasCapability,
  type InvitationResult,
  type Mailbox,
} from "../api/jmap";
import type { JmapEnv } from "./types";

/** Статусы ответа (аргумент participationStatus метода). */
export type ParticipationStatus = "accepted" | "tentative" | "declined";

/** Есть ли у учётной записи метод веб-почты (кнопки карточки активны только при ней). */
export function canRespondToInvitations(env: JmapEnv): boolean {
  return hasCapability(env.session, env.accountId, CAP_ITIP);
}

/** Итог ответа: применён сервером (applied=false — приём не внёс, причина) или ошибка метода. */
export type RespondOutcome =
  | { kind: "applied"; result: InvitationResult }
  | { kind: "refused"; reason: string }
  | { kind: "error"; type: string; description: string | null };

/** `Invitation/respond` от имени владельца ящика. */
export async function respondToInvitation(
  env: JmapEnv,
  emailId: string,
  status: ParticipationStatus,
): Promise<RespondOutcome> {
  const result = await invitationRespond(env.apiUrl, env.authorization, env.accountId, emailId, status);
  if (isMethodError(result)) {
    return { kind: "error", type: result.type, description: result.description };
  }
  return result.applied
    ? { kind: "applied", result }
    : { kind: "refused", reason: result.reason ?? "Приглашение не применено сервером." };
}

/** Ошибка «приглашение в „Спаме"» — карточка показывает перенос и повтор ответа. */
export function isJunkError(outcome: RespondOutcome): boolean {
  return outcome.kind === "error" && outcome.type === "invitationInJunk";
}

/** Человекочитаемый текст ошибки метода (описание сервера, как в RFC 8620 §3.6.1). */
export function errorText(outcome: Extract<RespondOutcome, { kind: "error" }>): string {
  return outcome.description ?? `Сервер ответил ошибкой ${outcome.type}.`;
}

/** Папка «Входящие» по роли (RFC 6154) — куда карточка переносит письмо из «Спама». */
export function inboxOf(mailboxes: Mailbox[] | undefined): Mailbox | null {
  return mailboxes?.find((m) => m.role === "inbox") ?? null;
}

/** Перенос письма в «Входящие» (Email/set: mailboxIds целиком — как перенос в списке). */
export async function moveToInbox(env: JmapEnv, emailId: string, inboxId: string): Promise<boolean> {
  const result = await emailSetUpdate(env.apiUrl, env.authorization, env.accountId, {
    [emailId]: { mailboxIds: { [inboxId]: true } },
  });
  // Успешный update — id в updated (значение может быть null: серверных полей у переноса нет).
  return emailId in result.updated && !result.notUpdated[emailId];
}
