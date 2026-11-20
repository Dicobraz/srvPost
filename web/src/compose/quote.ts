/*
  Ответ и пересылка (WEB-04): цитата под телом — как в Outlook/Postman: строка «Кто и когда
  писал(а)», затем тело письма (через санитайзер — чужой HTML не идёт в черновик сырым) в
  blockquote. Пересылка с вложением: оригинал письма прикладывается как .eml (blobId письма —
  блоб M<id>, сервер отдаёт его в Email/set attachments), вложения оригинала остаются внутри
  .eml (forward attached — как в Postman PARITY.md). Темы — Re:/Fwd: без накопления повторов.
*/

import { sanitizeComposeHtml } from "./word-paste";
import type { EmailBodyPart, EmailFull } from "../api/jmap";

/** Участники для поля Кому при ответе: отправитель оригинала. */
export function replyToOf(email: EmailFull): Array<{ name: string | null; email: string }> {
  const from = email.from?.[0];
  return from ? [{ name: from.name, email: from.email }] : [];
}

/**
 * Ответ всем: отправитель + Кому оригинала + Копия, без себя и без дублей (Outlook/Postman).
 * selfEmail — адрес входа; свой адрес в Кому не возвращаем (сам себе отвечать не надо).
 */
export function replyAllToOf(
  email: EmailFull,
  selfEmail: string,
): { to: Array<{ name: string | null; email: string }>; cc: Array<{ name: string | null; email: string }> } {
  const self = selfEmail.toLowerCase();
  const seen = new Set([self]);
  const push = (list: Array<{ name: string | null; email: string }>) => {
    const out: Array<{ name: string | null; email: string }> = [];
    for (const a of list) {
      const key = a.email.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ name: a.name, email: a.email });
    }
    return out;
  };
  const to = push(replyToOf(email));
  const cc = push([...(email.to ?? []), ...(email.cc ?? [])]);
  return { to, cc };
}

/** Тема ответа/пересылки: Re:/Fwd: без повторов («Re: Re: …» не копится). */
export function subjectFor(kind: "reply" | "forward", subject: string | null): string {
  const base = subject?.trim() || "";
  if (kind === "reply") return /^re:/i.test(base) ? base : base ? `Re: ${base}` : "Re:";
  return /^(fwd|fw):/i.test(base) ? base : base ? `Fwd: ${base}` : "Fwd:";
}

/** Формат строки цитаты: «В пятницу, 21.11.2026 09:41, Ольга Смирнова <o@v> писал(а):». */
function quoteHeader(email: EmailFull): string {
  const from = email.from?.[0];
  const who = from ? `${from.name?.trim() || from.email} <${from.email}>` : "(неизвестный отправитель)";
  const when = new Date(email.receivedAt).toLocaleString("ru", {
    weekday: "long",
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
  return `В ${when}, ${who} писал(а):`;
}

/** Тело оригинала: HTML-часть, если есть, иначе текст как абзацы. */
function originalBodyHtml(email: EmailFull): string {
  const htmlPart = email.htmlBody?.[0];
  if (htmlPart?.partId) {
    const value = email.bodyValues[htmlPart.partId]?.value;
    if (value) return sanitizeComposeHtml(value);
  }
  const textPart = email.textBody?.[0];
  if (textPart?.partId) {
    const value = email.bodyValues[textPart.partId]?.value ?? "";
    return value
      .split(/\n{2,}/)
      .map((p) => `<p>${p.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\n/g, "<br>")}</p>`)
      .join("");
  }
  return "";
}

/**
 * HTML цитаты: перенос строки, шапка («В …, … писал(а):») и blockquote с телом оригинала.
 * Тело проходит тот же санитайзер, что и вставка из Word (чужой HTML — после pastedown).
 */
export function quoteHtml(email: EmailFull): string {
  return (
    `<br><div class="tp-quote"><p>${quoteHeader(email)}</p>` +
    `<blockquote>${originalBodyHtml(email) || "<p>(без текста)</p>"}</blockquote></div>`
  );
}

/**
 * Цитата пересылки — блок «Пересланное сообщение» с шапкой письма (Outlook/Postman): от кого,
 * когда, кому, тема. Тело — как в ответе, через санитайзер.
 */
export function forwardQuoteHtml(email: EmailFull): string {
  const fmt = (iso: string) =>
    new Date(iso).toLocaleString("ru", {
      day: "2-digit",
      month: "2-digit",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  const addr = (list: Array<{ name?: string | null; email: string }>) =>
    list.map((a) => `${a.name?.trim() || a.email} <${a.email}>`).join(", ") || "(нет)";
  const rows = [
    ["От", addr(email.from ?? [])],
    ["Дата", fmt(email.receivedAt)],
    ["Кому", addr(email.to ?? [])],
    ...(email.cc && email.cc.length > 0 ? ([["Копия", addr(email.cc)]] as Array<[string, string]>) : []),
    ["Тема", email.subject?.trim() || "(без темы)"],
  ];
  const head = rows.map(([k, v]) => `<p><b>${k}:</b> ${v}</p>`).join("");
  return (
    `<br><div class="tp-quote"><p><b>---------- Пересланное сообщение ----------</b></p>` +
    `${head}<blockquote>${originalBodyHtml(email) || "<p>(без текста)</p>"}</blockquote></div>`
  );
}

/** Пересылка: цитата + вложение-оригинал (.eml по blobId письма) для Email/set create. */
export function forwardAttachments(email: EmailFull): EmailBodyPart[] {
  if (!email.blobId) return [];
  const name = `${(email.subject?.trim() || "Письмо").replace(/[\\/:*?"<>|]/g, "_")}.eml`;
  return [
    {
      partId: null,
      blobId: email.blobId,
      size: email.size,
      type: "message/rfc822",
      name,
      disposition: "attachment",
      charset: null,
    },
  ];
}

/** Заголовки ответа (RFC 8621 §4.1.2.7): In-Reply-To и References оригинала. */
export function replyReferences(email: EmailFull): { inReplyTo: string[] | null; references: string[] | null } {
  const msgId = email.messageId ?? [];
  const refs = [...(email.references ?? [])];
  return {
    inReplyTo: msgId.length > 0 ? msgId : null,
    references: [...refs, ...msgId].length > 0 ? [...refs, ...msgId] : null,
  };
}
