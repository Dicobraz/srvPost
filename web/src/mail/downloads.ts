/*
  Выгрузка (WEB-16, PARITY attach.save_all, mail.export): сервер отдаёт блобы только по входу
  (`authenticate_session` в tp-jmap/src/blob.rs), поэтому прямая ссылка downloadUrl в <a download>
  без заголовка не работает — скачивание всегда через fetch с Authorization → Blob → object URL
  → клик по anchor с download. «Сохранить все» — серия с паузой: браузеры блокируют
  мульти-download подряд (Chrome спрашивает разрешение и отбрасывает слишком частые клики).
  «Скачать письмо» — raw blobId письма (RFC 8621 §4: блоб письма = исходные октеты) → .eml.
  Имена файлов — sanitizeFilename: путь и нелегальные символы Windows долой, кириллица остаётся
  (anchor download attribute — Content-Disposition не нужен).
  Выбор вьювера — viewerKind по MIME (изображение/PDF/видео/аудио/текст); текстовый файл
  больше TEXT_VIEW_LIMIT — просмотр недоступен, честный отказ с «Скачать».
*/
import { blobUrl, type EmailBodyPart, type EmailSummary } from "../api/jmap";
import { isInvitationPart } from "./invite";
import type { JmapEnv } from "./types";

/** Пауза между скачиваниями «Сохранить все» (мс) — мульти-download браузеры блокируют. */
export const SAVE_ALL_PAUSE_MS = 700;

/** Лимит текста во вьювере (~1 МБ): больше — честный отказ с «Скачать». */
export const TEXT_VIEW_LIMIT = 1_048_576;

// ---------- Имена файлов ----------

/** Человекочитаемый размер («22 КБ», «1,5 МБ») — как в чипах макета (композер, вьювер). */
export function formatSize(size: number): string {
  if (size >= 1_048_576) return `${(size / 1_048_576).toFixed(1).replace(".", ",")} МБ`;
  if (size >= 1024) return `${Math.round(size / 1024)} КБ`;
  return `${size} Б`;
}

/** Нелегальные в имени файла Windows: путь (/ \), служебные (< > : " | ? *) и управляющие. */
const ILLEGAL_NAME = /[/\\<>:"|?*\u0000-\u001f\u007f]/g;
/** Резервные имена Windows (без расширения) — к ним добавляется префикс. */
const RESERVED = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i;
/** Предел длины имени: запас до лимита файловой системы с путём пользователя. */
const MAX_NAME = 150;

/** Безопасное имя файла для anchor download: путь и нелегальные символы — в «_», хвостовые
 * точки/пробелы (Windows их теряет) долой, резервные имена Windows — с префиксом, длина — до
 * 150 знаков с сохранением расширения; кириллица и прочий Unicode остаются. Пустое — fallback. */
export function sanitizeFilename(raw: string, fallback = "вложение"): string {
  let name = raw.replace(ILLEGAL_NAME, "_").trim().replace(/[ .]+$/, "");
  const stem = name.includes(".") ? name.slice(0, name.indexOf(".")) : name;
  if (RESERVED.test(stem)) name = `_${name}`;
  const chars = Array.from(name); // по кодовым точкам: эмодзи и суррогаты не рвём
  if (chars.length > MAX_NAME) {
    const dot = name.lastIndexOf(".");
    const ext = Array.from(dot > 0 && dot > name.length - 12 ? name.slice(dot) : "");
    name = chars.slice(0, Math.max(1, MAX_NAME - ext.length)).join("") + ext.join("");
  }
  return name || fallback;
}

/** Имя файла письма EML: «<тема>.eml»; темы нет (или она пустая) — «письмо.eml». */
export function emlFilename(subject: string | null): string {
  return `${sanitizeFilename((subject ?? "").trim() || "письмо", "письмо")}.eml`;
}

// ---------- Скачивание ----------

/** Сохранить Blob на диск: object URL → anchor download → освободить URL (с запасом: мгновенный
 * revoke может отменить начавшееся скачивание). */
export function saveBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

/** Получить блоб по downloadUrl сессии с Authorization и типом как у вложения (сервер без
 * параметра accept отдаёт octet-stream — вьюверу и скачиванию нужен настоящий MIME). */
export async function fetchBlob(url: string, authorization: string | null, mime: string): Promise<Blob> {
  let res: Response;
  try {
    res = await fetch(url, { headers: authorization ? { Authorization: authorization } : {} });
  } catch {
    throw new Error("Сеть недоступна: файл не получен.");
  }
  if (!res.ok) {
    throw new Error(
      res.status === 401
        ? "Сессия истекла: войдите заново."
        : `Узел ответил ошибкой HTTP ${res.status} — файл не получен.`,
    );
  }
  const buf = await res.arrayBuffer();
  return new Blob([buf], { type: mime || "application/octet-stream" });
}

/** Blob → data: URL. CSP веб-клиента (tp-webmail) пускает `data:` в `img-src`, но не `blob:` —
 * поэтому изображения во вкладке просмотра открываются как data: URL и работают в собранном
 * приложении уже сейчас; для PDF/видео/аудио (iframe/media `blob:`) вопрос CSP — issue #310. */
export function blobToDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error("Вложение не получено."));
    reader.readAsDataURL(blob);
  });
}

/** Скачать одно вложение: блоб с Authorization, имя — sanitized (path traversal долой). */
export async function downloadAttachment(env: JmapEnv, accountId: string, part: EmailBodyPart): Promise<void> {
  if (!part.blobId) throw new Error("У вложения нет блоба — скачать не удалось.");
  const name = sanitizeFilename(part.name ?? "вложение");
  const blob = await fetchBlob(blobUrl(env.session, accountId, part.blobId, name), env.authorization, part.type);
  saveBlob(blob, name);
}

/** Скачать письмо в EML: raw blobId письма (RFC 8621 §4), имя «<тема>.eml». Возвращает имя файла. */
export async function downloadEmailEml(
  env: JmapEnv,
  email: Pick<EmailSummary, "blobId" | "subject">,
): Promise<string> {
  if (!email.blobId) throw new Error("У письма нет блоба — скачать не удалось.");
  const name = emlFilename(email.subject);
  const blob = await fetchBlob(
    blobUrl(env.session, env.accountId, email.blobId, name),
    env.authorization,
    "message/rfc822",
  );
  saveBlob(blob, name);
  return name;
}

/** Итог «Сохранить все»: сколько сошло на диск и сколько не скачалось (честный тост). */
export interface SaveAllOutcome {
  saved: number;
  failed: number;
}

/** «Сохранить все» (PARITY attach.save_all): по одному — fetch + клик по anchor с паузой
 * SAVE_ALL_PAUSE_MS: браузеры блокируют частый мульти-download. Ошибки одного файла остальные
 * не отменяют — итогом число неудач. */
export async function saveAllAttachments(
  env: JmapEnv,
  accountId: string,
  parts: EmailBodyPart[],
  options: { pauseMs?: number } = {},
): Promise<SaveAllOutcome> {
  const pauseMs = options.pauseMs ?? SAVE_ALL_PAUSE_MS;
  const sleep = (ms: number) => new Promise<void>((r) => window.setTimeout(r, ms));
  let saved = 0;
  let failed = 0;
  for (const [i, part] of parts.entries()) {
    if (i > 0 && pauseMs > 0) await sleep(pauseMs);
    try {
      await downloadAttachment(env, accountId, part);
      saved += 1;
    } catch {
      failed += 1;
    }
  }
  return { saved, failed };
}

// ---------- Вьювер по типу ----------

/** Вид встроенного просмотра (PARITY attach.preview): у браузера — изображения, PDF, видео,
 * аудио; любой text/* — <pre> до TEXT_VIEW_LIMIT (HTML — экранированным исходником: безопаснее
 * скачивания); остальное (Office, архивы) — отказ. */
export type ViewerKind = "image" | "pdf" | "video" | "audio" | "text" | "toolarge" | "none";

/** Выбор вьювера по MIME вложения и размеру (текст — до лимита; MIME сравнивается без регистра). */
export function viewerKind(type: string | null | undefined, size: number): ViewerKind {
  const mime = (type ?? "").trim().toLowerCase();
  if (mime.startsWith("image/")) return "image";
  if (mime === "application/pdf") return "pdf";
  if (mime.startsWith("video/")) return "video";
  if (mime.startsWith("audio/")) return "audio";
  if (mime.startsWith("text/")) return size <= TEXT_VIEW_LIMIT ? "text" : "toolarge";
  return "none";
}

/** Список вложений письма для просмотра и «Сохранить все»: без приглашения (.ics — своя
 * карточка) и inline-частей — как в полосе вложений чтения. */
export function attachmentParts(full: Pick<EmailSummary, "attachments">): EmailBodyPart[] {
  return (full.attachments ?? []).filter((p) => !isInvitationPart(p.type) && p.disposition !== "inline");
}

/** Навигация по вложениям письма (PARITY attach.next/prev): индекс текущего, счётчик и соседние
 * ключи (partId или blobId — тот же ключ, что в маршруте вкладки); не найдено — index −1. */
export interface AttachmentNav {
  index: number;
  count: number;
  prev: string | null;
  next: string | null;
}

export function attachmentNav(parts: EmailBodyPart[], partId: string): AttachmentNav {
  const key = (p: EmailBodyPart) => p.partId ?? p.blobId ?? "";
  const index = parts.findIndex((p) => key(p) === partId);
  if (index < 0) return { index: -1, count: parts.length, prev: null, next: null };
  return {
    index,
    count: parts.length,
    prev: index > 0 ? key(parts[index - 1]) : null,
    next: index < parts.length - 1 ? key(parts[index + 1]) : null,
  };
}

/** Декодировать текст вложения в его кодировке (charset части, RFC 8621 §4.1.4): windows-1251
 * и прочие метки TextDecoder; неизвестная метка — UTF-8 (без отказа). */
export async function decodeTextData(buf: BufferSource, charset: string | null): Promise<string> {
  const label = charset?.trim();
  if (label) {
    try {
      return new TextDecoder(label).decode(buf);
    } catch {
      // Метки нет в браузере — текст читаем как UTF-8.
    }
  }
  return new TextDecoder().decode(buf);
}
