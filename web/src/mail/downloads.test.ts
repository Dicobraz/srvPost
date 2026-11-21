// Выгрузка (WEB-16): имена файлов — sanitize (путь и нелегальные символы долой, кириллица
// остаётся), выбор вьювера по MIME, навигация attach.next/prev, «Сохранить все» — серия
// fetch+anchor с паузой (моки сети и anchor), EML письма — «<тема>.eml», декодирование текста
// в charset части (windows-1251 — частая у вложений).
import { afterEach, expect, test, vi } from "vitest";

import { blobUrl, type EmailBodyPart, type JmapSession } from "../api/jmap";
import {
  attachmentNav,
  attachmentParts,
  blobToDataUrl,
  decodeTextData,
  downloadAttachment,
  downloadEmailEml,
  emlFilename,
  fetchBlob,
  sanitizeFilename,
  saveAllAttachments,
  TEXT_VIEW_LIMIT,
  viewerKind,
} from "./downloads";
import type { JmapEnv } from "./types";

afterEach(() => {
  vi.restoreAllMocks();
});

const SESSION = {
  downloadUrl: "https://node.example/jmap/blob/{accountId}/{blobId}/{name}?accept={type}",
  accounts: {},
} as unknown as JmapSession;
const ENV: JmapEnv = {
  session: SESSION,
  apiUrl: "https://node.example/jmap/api",
  accountId: "acc1",
  authorization: "Bearer t",
  selfAddress: "user@example.org",
};

const part = (over: Partial<EmailBodyPart> = {}): EmailBodyPart => ({
  partId: "p1",
  blobId: "G1",
  size: 100,
  type: "application/octet-stream",
  name: "файл",
  disposition: "attachment",
  charset: null,
  ...over,
});

// ---------- Имена файлов ----------

test("sanitizeFilename: кириллица и точки в имени остаются", () => {
  expect(sanitizeFilename("Договор поставки №3.pdf")).toBe("Договор поставки №3.pdf");
  expect(sanitizeFilename("отчёт_2026.docx")).toBe("отчёт_2026.docx");
});

test("sanitizeFilename: путь и нелегальные символы — в «_», traversal не проходим", () => {
  expect(sanitizeFilename("../../etc/passwd")).toBe(".._.._etc_passwd");
  expect(sanitizeFilename("C:\\Users\\evil\\x.exe")).toBe("C__Users_evil_x.exe");
  expect(sanitizeFilename("a<b>c:d\"e|f?g*h")).toBe("a_b_c_d_e_f_g_h");
  expect(sanitizeFilename(" evil . . ")).toBe("evil");
});

test("sanitizeFilename: управляющие символы убраны, хвостовые точки Windows долой", () => {
  expect(sanitizeFilename("вкл\u0000\u001fюч")).toBe("вкл__юч");
  expect(sanitizeFilename("файл.")).toBe("файл");
  expect(sanitizeFilename("..")).toBe("вложение");
  expect(sanitizeFilename("")).toBe("вложение");
});

test("sanitizeFilename: резервные имена Windows — с префиксом", () => {
  expect(sanitizeFilename("CON")).toBe("_CON");
  expect(sanitizeFilename("com1.txt")).toBe("_com1.txt");
  expect(sanitizeFilename("LPT9")).toBe("_LPT9");
  expect(sanitizeFilename("своё.txt")).toBe("своё.txt");
});

test("sanitizeFilename: длинное имя — до 150 кодовых точек с расширением", () => {
  const long = `${"б".repeat(200)}.pdf`;
  const got = sanitizeFilename(long);
  expect(Array.from(got).length).toBe(150);
  expect(got.endsWith(".pdf")).toBe(true);
  // Расширения нет — просто предел; эмодзи (суррогатная пара) не рвётся.
  const emoji = `${"🏷️".repeat(120)}.txt`;
  expect(sanitizeFilename(emoji).endsWith(".txt")).toBe(true);
});

test("emlFilename: тема sanitized, нет темы — «письмо.eml»", () => {
  expect(emlFilename("Квартальный отчёт")).toBe("Квартальный отчёт.eml");
  expect(emlFilename("a/b\\c")).toBe("a_b_c.eml");
  expect(emlFilename(null)).toBe("письмо.eml");
  expect(emlFilename("   ")).toBe("письмо.eml");
});

// ---------- Вьювер по типу ----------

test("viewerKind: встроенные типы браузера и текст с лимитом", () => {
  expect(viewerKind("image/png", 10)).toBe("image");
  expect(viewerKind("Image/SVG+XML", 10)).toBe("image");
  expect(viewerKind("application/pdf", 10)).toBe("pdf");
  expect(viewerKind("video/mp4", 10)).toBe("video");
  expect(viewerKind("audio/ogg", 10)).toBe("audio");
  expect(viewerKind("text/plain", 10)).toBe("text");
  expect(viewerKind("text/plain", TEXT_VIEW_LIMIT + 1)).toBe("toolarge");
  // HTML вложение — как текст (исходник в <pre>, экранирован React'ом): безопаснее скачивания.
  expect(viewerKind("text/html", 10)).toBe("text");
  // Office/архивы и пустой тип — нет встроенного вьювера.
  expect(viewerKind("application/vnd.ms-excel", 10)).toBe("none");
  expect(viewerKind(null, 10)).toBe("none");
  expect(viewerKind("", 10)).toBe("none");
});

// ---------- Навигация attach.next/prev ----------

test("attachmentNav: счётчик и соседи; не найдено — index −1 и соседей нет", () => {
  const parts = [part({ partId: "a" }), part({ partId: "b" }), part({ partId: "c" })];
  expect(attachmentNav(parts, "b")).toEqual({ index: 1, count: 3, prev: "a", next: "c" });
  expect(attachmentNav(parts, "a")).toEqual({ index: 0, count: 3, prev: null, next: "b" });
  expect(attachmentNav(parts, "c")).toEqual({ index: 2, count: 3, prev: "b", next: null });
  expect(attachmentNav(parts, "x").index).toBe(-1);
  // Ключ без partId — blobId (в маршруте тот же ключ).
  expect(attachmentNav([part({ partId: null, blobId: "G9" })], "G9").index).toBe(0);
});

// ---------- Скачивание ----------

/** URL downloadUrl сессии подставляется по шаблону (как в чипах чтения). */
test("blobUrl сессии: accountId/blobId/name по шаблону", () => {
  expect(blobUrl(SESSION, "acc1", "G1", "файл.pdf")).toBe("https://node.example/jmap/blob/acc1/G1/%D1%84%D0%B0%D0%B9%D0%BB.pdf?accept=");
});

test("fetchBlob: Authorization и MIME как у вложения; 401 — честный текст", async () => {
  const headers: Record<string, string> = {};
  let status = 200;
  globalThis.fetch = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    for (const [k, v] of Object.entries(new Headers(init?.headers))) headers[k] = v;
    return new Response(new Uint8Array([1, 2, 3]), { status });
  }) as unknown as typeof fetch;
  const blob = await fetchBlob("https://node.example/blob", "Bearer t", "application/pdf");
  expect(headers.Authorization).toBe("Bearer t");
  expect(blob.type).toBe("application/pdf");
  expect(blob.size).toBe(3);
  status = 401;
  await expect(fetchBlob("https://node.example/blob", "Bearer t", "application/pdf")).rejects.toThrow(
    "Сессия истекла: войдите заново.",
  );
});

test("downloadAttachment: сохраняется под sanitized именем", async () => {
  const saved: string[] = [];
  globalThis.fetch = vi.fn(async () => new Response(new Uint8Array([1]), { status: 200 })) as unknown as typeof fetch;
  URL.createObjectURL = vi.fn(() => "blob:mock") as unknown as typeof URL.createObjectURL;
  URL.revokeObjectURL = vi.fn() as unknown as typeof URL.revokeObjectURL;
  vi.spyOn(HTMLElement.prototype, "click").mockImplementation(function (this: HTMLElement) {
    saved.push((this as HTMLAnchorElement).download);
  });
  await downloadAttachment(ENV, "acc1", part({ name: "../плохое<имя>.pdf" }));
  expect(saved).toEqual([".._плохое_имя.pdf"]);
});

test("downloadEmailEml: raw blobId письма под «<тема>.eml»", async () => {
  const urls: string[] = [];
  const saved: string[] = [];
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    urls.push(String(input));
    return new Response(new Uint8Array([7]), { status: 200 });
  }) as unknown as typeof fetch;
  URL.createObjectURL = vi.fn(() => "blob:mock") as unknown as typeof URL.createObjectURL;
  URL.revokeObjectURL = vi.fn() as unknown as typeof URL.revokeObjectURL;
  vi.spyOn(HTMLElement.prototype, "click").mockImplementation(function (this: HTMLElement) {
    saved.push((this as HTMLAnchorElement).download);
  });
  const name = await downloadEmailEml(ENV, { blobId: "Graw", subject: "Обсуждение контракта" });
  expect(name).toBe("Обсуждение контракта.eml");
  expect(saved).toEqual(["Обсуждение контракта.eml"]);
  expect(urls[0]).toContain("/acc1/Graw/");
});

// ---------- «Сохранить все»: серия с паузой ----------

test("saveAllAttachments: по одному с паузой, итог saved/failed; ошибки не отменяют остальные", async () => {
  const saved: string[] = [];
  const gaps: number[] = [];
  let last = performance.now();
  globalThis.fetch = vi.fn(async (input: RequestInfo | URL) => {
    const now = performance.now();
    if (saved.length > 0) gaps.push(now - last);
    last = now;
    if (String(input).includes("G2")) return new Response("упс", { status: 500 });
    return new Response(new Uint8Array([1]), { status: 200 });
  }) as unknown as typeof fetch;
  URL.createObjectURL = vi.fn(() => "blob:mock") as unknown as typeof URL.createObjectURL;
  URL.revokeObjectURL = vi.fn() as unknown as typeof URL.revokeObjectURL;
  vi.spyOn(HTMLElement.prototype, "click").mockImplementation(function (this: HTMLElement) {
    saved.push((this as HTMLAnchorElement).download);
  });
  const outcome = await saveAllAttachments(
    ENV,
    "acc1",
    [part({ blobId: "G1", name: "a.pdf" }), part({ blobId: "G2", name: "б.png" }), part({ blobId: "G3", name: "в.txt" })],
    { pauseMs: 5 },
  );
  expect(outcome).toEqual({ saved: 2, failed: 1 });
  expect(saved).toEqual(["a.pdf", "в.txt"]); // по одному, пауза между — иначе мульти-download блокируется
  expect(gaps.length).toBeGreaterThan(0);
});

// ---------- Изображение во вьювере: data: URL (CSP img-src data:, blob: — вопрос владельца) ----------

test("blobToDataUrl: data: URL с настоящим MIME вложения", async () => {
  const url = await blobToDataUrl(new Blob([new Uint8Array([1, 2, 3])], { type: "image/png" }));
  expect(url).toBe("data:image/png;base64,AQID");
});

// ---------- attachmentParts: список вложений без приглашения и inline ----------

test("attachmentParts: .ics и inline-части не считаются вложениями", () => {
  const full = {
    attachments: [
      part({ name: "a.pdf" }),
      part({ name: "invite.ics", type: "text/calendar" }),
      part({ name: "logo.png", disposition: "inline" }),
    ],
  };
  expect(attachmentParts(full).map((p) => p.name)).toEqual(["a.pdf"]);
});

// ---------- Текст в кодировке части ----------

test("decodeTextData: windows-1251 читается, неизвестная метка — UTF-8 без отказа", async () => {
  // «Привет» в windows-1251: CF F0 E8 E2 E5 F2.
  const cp1251 = new Uint8Array([0xcf, 0xf0, 0xe8, 0xe2, 0xe5, 0xf2]);
  expect(await decodeTextData(cp1251, "windows-1251")).toBe("Привет");
  const utf8 = new TextEncoder().encode("Привет");
  expect(await decodeTextData(utf8, "нет-такой-метки")).toBe("Привет");
  expect(await decodeTextData(utf8, null)).toBe("Привет");
});
