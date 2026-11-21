/*
  Вложения (WEB-04): drag-drop и пикер файлов → POST uploadUrl сессии (RFC 8620 §6.1). Тело —
  File (File API): браузер читает файл частями и не держит гигабайт в памяти вкладки; на сервере
  upload тоже стримится (карточка). Прогресс — XHR upload.onprogress, отмена — AbortController;
  лимит узла maxSizeUpload (сессия) — честная ошибка до запроса, превышение при загрузке — HTTP
  413 («Файл больше лимита узла»).
*/

import { uploadBlob, type JmapSession } from "../api/jmap";
import type { JmapEnv } from "../mail/types";
import type { Attachment } from "./model";

/** Лимит загрузки узла из сессии (capabilities ядра, байт); нет свойства — не проверяем заранее. */
export function maxSizeUpload(session: JmapSession): number | null {
  const core = session.capabilities["urn:ietf:params:jmap:core"] as { maxSizeUpload?: number } | undefined;
  return typeof core?.maxSizeUpload === "number" && core.maxSizeUpload > 0 ? core.maxSizeUpload : null;
}

/** Человекочитаемый размер (как в чипах макета: «22 КБ», «1,5 МБ»). */
export function formatSize(size: number): string {
  if (size >= 1_048_576) return `${(size / 1_048_576).toFixed(1).replace(".", ",")} МБ`;
  if (size >= 1024) return `${Math.round(size / 1024)} КБ`;
  return `${size} Б`;
}

/** Ошибка лимита: честный текст с числом (приёмка — не должно выедать память вкладки). */
export function tooLargeError(file: File, limit: number | null): string | null {
  if (limit === null || file.size <= limit) return null;
  return `«${file.name}» больше лимита узла (${formatSize(limit)}) — файл не загружен.`;
}

/** Ошибки файлов пачкой (drag-drop нескольких): одна на файл, чип с ошибкой остаётся в ряду. */
export function fileError(file: File, limit: number | null): string | null {
  return tooLargeError(file, limit);
}

/** Загрузить один файл в блоб: прогресс и отмена; вернёт готовое вложение (blobId). */
export function uploadAttachment(
  env: JmapEnv,
  file: File,
  id: string,
  callbacks: {
    onProgress?: (loaded: number) => void;
    onReady?: (a: Attachment) => void;
    /** Ошибка: сообщение, null — отмена пользователем (чип убирается). */
    onError?: (message: string | null) => void;
  },
): Attachment {
  const limit = maxSizeUpload(env.session);
  const oversize = tooLargeError(file, limit);
  const controller = new AbortController();
  const item: Attachment = {
    id,
    name: file.name,
    size: file.size,
    type: file.type || "application/octet-stream",
    status: oversize ? "error" : "uploading",
    progress: 0,
    abort: oversize ? undefined : () => controller.abort(),
  };
  if (oversize) {
    item.error = oversize;
    callbacks.onError?.(oversize);
    return item;
  }
  uploadBlob(env.session.uploadUrl, env.authorization, env.accountId, file, {
    onProgress: (loaded, total) => {
      item.progress = total > 0 ? loaded / total : 0;
      callbacks.onProgress?.(loaded);
    },
    signal: controller.signal,
  })
    .then((res) => {
      item.status = "ready";
      item.blobId = res.blobId;
      item.abort = undefined;
      callbacks.onReady?.(item);
    })
    .catch((e: unknown) => {
      item.status = "error";
      item.abort = undefined;
      if (e instanceof DOMException && e.name === "AbortError") {
        // Отмена пользователем: чип убирает сам компонент (сообщение — null).
        callbacks.onError?.(null);
      } else {
        item.error = e instanceof Error ? e.message : "Загрузка не выполнена.";
        callbacks.onError?.(item.error ?? "Загрузка не выполнена.");
      }
    });
  return item;
}
