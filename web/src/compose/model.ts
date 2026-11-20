/*
  Модель письма (WEB-04): снимок композера — общий для черновиков, отправки и undo. Вложение —
  только загруженное (blobId из `uploadUrl`); незагруженные в черновик и письмо не попадают.
*/

import type { EmailBodyPart, Identity } from "../api/jmap";
import type { Recipient } from "./recipients";

/** Вложение письма: после загрузки — blobId; в состав Email/set идёт как EmailBodyPart. */
export interface Attachment {
  /** Локальный идентификатор строки (upload — по нему чип). */
  id: string;
  name: string;
  size: number;
  type: string;
  /** Загружено (blobId есть), идёт загрузка или ошибка. */
  status: "uploading" | "ready" | "error";
  /** Прогресс 0…1 — только для uploading. */
  progress: number;
  blobId?: string;
  /** Отмена загрузки (AbortController вложенного XHR). */
  abort?: () => void;
}

/** Снимок письма: всё, что черновик сохраняет и отправка берёт. */
export interface ComposeSnapshot {
  /** Адрес отправителя (identity email) и имя — From письма. */
  from: { name: string; email: string } | null;
  to: Recipient[];
  cc: Recipient[];
  bcc: Recipient[];
  subject: string;
  /** Тело — чистый HTML (после pastedown-санитайзера, word-paste.ts). */
  bodyHtml: string;
  attachments: Attachment[];
}

/** Пустой снимок от identity (адрес входа). */
export function emptySnapshot(identity: Identity | null): ComposeSnapshot {
  return {
    from: identity ? { name: identity.name || identity.email, email: identity.email } : null,
    to: [],
    cc: [],
    bcc: [],
    subject: "",
    bodyHtml: "",
    attachments: [],
  };
}

/** Вложения снимка → части Email/set (RFC 8621 §4.1.4): только загруженные (blobId). */
export function attachmentParts(attachments: Attachment[]): EmailBodyPart[] {
  return attachments
    .filter((a) => a.status === "ready" && a.blobId)
    .map((a) => ({
      partId: null,
      blobId: a.blobId ?? null,
      size: a.size,
      type: a.type || "application/octet-stream",
      name: a.name,
      disposition: "attachment",
      charset: null,
    }));
}

/** Считаем снимок непустым: есть получатели, тема или тело — черновик сохраняет такое. */
export function snapshotHasContent(s: ComposeSnapshot): boolean {
  return (
    s.to.length > 0 ||
    s.cc.length > 0 ||
    s.bcc.length > 0 ||
    s.subject.trim() !== "" ||
    s.bodyHtml.replace(/<[^>]*>/g, "").trim() !== "" ||
    s.attachments.length > 0
  );
}
