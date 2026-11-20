// Клиент JMAP (WEB-03): сессия (RFC 8620 §2), запросы API окнами, Mailbox/Email/Thread — get/query/
// set/changes; same-origin запросы с заголовком Authorization — `Bearer` (OIDC-токен SPA) или `Basic`
// (логин + пароль приложения); сервер проверяет оба (`tp-jmap/core/http.rs`). Проверка пароля
// приложения — `GET /jmap/session`: сессия JMAP и есть ответ сервера; 401 — неверная пара.
// Push (RFC 8620 §7, RFC 8887) — `mail/push.ts`; состояние — TanStack Query (`mail/queries.ts`).

import type { Session } from "../auth/store";

/** `/.well-known/jmap` — объект сессии JMAP; проверка пары «логин + пароль приложения». */
export const JMAP_SESSION = "/.well-known/jmap";

/** Капабилити ядра (RFC 8620 §2.5): лимиты запросов, ссылки push. */
export const CAP_CORE = "urn:ietf:params:jmap:core";
/** Капабилити почты (RFC 8621): Mailbox, Email, Thread, SearchSnippet. */
export const CAP_MAIL = "urn:ietf:params:jmap:mail";
/** Капабилити WebSocket (RFC 8887): адрес `/jmap/ws` и признак push. */
export const CAP_WEBSOCKET = "urn:ietf:params:jmap:websocket";

/** Учётная запись сессии: имя, личная ли, права; капабилити — по типам данных. */
export interface JmapAccount {
  name: string;
  isPersonal: boolean;
  isReadOnly: boolean;
  accountCapabilities: Record<string, unknown>;
}

/** Объект сессии JMAP (RFC 8620 §2): ссылки API и push, учётные записи, состояния. */
export interface JmapSession {
  capabilities: Record<string, Record<string, unknown>>;
  accounts: Record<string, JmapAccount>;
  primaryAccounts: Record<string, string>;
  username: string;
  apiUrl: string;
  downloadUrl: string;
  uploadUrl: string;
  eventSourceUrl: string;
  state: string;
}

/** Объект Mailbox (RFC 8621 §2): узел дерева папок с ролью и счётчиками. */
export interface Mailbox {
  id: string;
  name: string;
  parentId: string | null;
  /** Роль RFC 6154: inbox/archive/drafts/junk/sent/trash; null — обычная папка. */
  role: string | null;
  sortOrder: number;
  totalEmails: number;
  unreadEmails: number;
  totalThreads: number;
  unreadThreads: number;
  myRights: {
    mayReadItems: boolean;
    mayAddItems: boolean;
    mayRemoveItems: boolean;
    maySetSeen: boolean;
    maySetKeywords: boolean;
    mayCreateChild: boolean;
    mayRename: boolean;
    mayDelete: boolean;
    maySubmit: boolean;
  };
  isSubscribed: boolean;
}

/** Адрес письма: имя и почта могут отсутствовать (RFC 8621 §4.1.2.3). */
export interface EmailAddress {
  name: string | null;
  email: string;
}

/** Часть письма (RFC 8621 §4.1.4): вложение или тело с partId для `bodyValues`. */
export interface EmailBodyPart {
  partId: string | null;
  blobId: string | null;
  size: number;
  /** Тип MIME, например text/html. */
  type: string;
  name: string | null;
  disposition: string | null;
  charset: string | null;
  /** Только для вложений: language, location — не используются клиентом. */
}

/** Значение тела (RFC 8621 §4.1.4): текст части partId; `isTruncated` — сервер урезал. */
export interface EmailBodyValue {
  value: string;
  isEncodingProblem: boolean;
  isTruncated: boolean;
}

/** Ключевые слова письма (RFC 8621 §2.3): `$seen`, `$flagged`, `pm.*` — маски в `mail/keywords.ts`. */
export type Keywords = Record<string, boolean>;

/** Краткое письмо для списка (свойства без тел: детали — `Email/get` при открытии). */
export interface EmailSummary {
  id: string;
  blobId: string | null;
  threadId: string;
  mailboxIds: Record<string, boolean>;
  keywords: Keywords;
  receivedAt: string;
  size: number;
  from: EmailAddress[] | null;
  to: EmailAddress[] | null;
  subject: string | null;
  preview: string;
  hasAttachment: boolean;
}

/** Полное письмо для чтения: тела (htmlBody/textBody) и вложения. */
export interface EmailFull extends EmailSummary {
  textBody: EmailBodyPart[] | null;
  htmlBody: EmailBodyPart[] | null;
  attachments: EmailBodyPart[] | null;
  bodyValues: Record<string, EmailBodyValue>;
}

/** Объект Thread (RFC 8621 §3): письма беседы по возрастанию времени. */
export interface Thread {
  id: string;
  emailIds: string[];
}

/** Свойства краткого письма (окна списка) — без тел и вложений. */
export const SUMMARY_PROPERTIES = [
  "id",
  "blobId",
  "threadId",
  "mailboxIds",
  "keywords",
  "receivedAt",
  "size",
  "from",
  "to",
  "subject",
  "preview",
  "hasAttachment",
] as const;

/** Свойства полного письма: краткое плюс тела и вложения. */
export const FULL_PROPERTIES = [...SUMMARY_PROPERTIES, "textBody", "htmlBody", "attachments", "bodyValues"];

/** Состояние JMAP-ошибки метода (`error`-ответ, RFC 8620 §3.6.1) — показывается пользователю. */
export interface MethodError {
  "@type": "error";
  type: string;
  description: string | null;
}

/** Ответ одного вызова: данные метода или ошибка. */
export type MethodResponse = Record<string, unknown> | MethodError;

/** Ошибка запроса к узлу: HTTP-статус и человекочитаемый текст. */
export class JmapHttpError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "JmapHttpError";
  }
}

/** Является ли ответ ошибкой метода (ссылка `#error` по RFC 8620 §3.6.1). */
export function isMethodError(response: MethodResponse): response is MethodError {
  return (response as MethodError)["@type"] === "error";
}

/** base64 UTF-8 (`btoa` не берёт кириллицу — имя входа бывает русским). */
function base64Utf8(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Заголовок `Basic` из пары «логин + пароль приложения». */
export function basicCredentials(login: string, secret: string): string {
  return base64Utf8(`${login}:${secret}`);
}

/** Заголовок Authorization сессии: OIDC — Bearer, пароль приложения — Basic; нет сессии — null. */
export function authHeader(session: Session | null): string | null {
  if (!session) return null;
  return session.kind === "oidc"
    ? `Bearer ${session.accessToken}`
    : `Basic ${basicCredentials(session.login, session.secret)}`;
}

/** Запрос к JMAP того же узла с Authorization; ответ отдаётся как есть (401 обрабатывает вызывающий). */
export async function jmapFetch(
  path: string,
  init?: RequestInit,
  authorization?: string | null,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (authorization) headers.set("Authorization", authorization);
  return fetch(path, { ...init, headers });
}

export interface JmapError {
  /** HTTP-статус ответа. */
  status: number;
  /** Человекочитаемый текст для экрана входа. */
  message: string;
}

/** Проверка пары «логин + пароль приложения» на `/jmap/session`; ошибка — человекочитаемая. */
export async function verifyBasic(
  login: string,
  secret: string,
): Promise<JmapError | null> {
  let response: Response;
  try {
    response = await jmapFetch(JMAP_SESSION, undefined, basicCredentials(login, secret));
  } catch {
    return { status: 0, message: "Узел недоступен: проверьте соединение и попробуйте ещё раз." };
  }
  if (response.ok) return null;
  return {
    status: response.status,
    message:
      response.status === 401 || response.status === 403
        ? "Неверное имя входа или пароль приложения."
        : `Узел ответил ошибкой HTTP ${response.status}.`,
  };
}

/** Получение объекта сессии (RFC 8620 §2); не-JMAP ответ — понятная ошибка для экрана входа. */
export async function fetchSession(authorization: string): Promise<JmapSession> {
  let response: Response;
  try {
    response = await jmapFetch(JMAP_SESSION, undefined, authorization);
  } catch {
    throw new JmapHttpError(0, "Узел недоступен: проверьте соединение и попробуйте ещё раз.");
  }
  if (!response.ok) {
    throw new JmapHttpError(
      response.status,
      response.status === 401
        ? "Сессия истекла: войдите заново."
        : `Узел ответил ошибкой HTTP ${response.status}.`,
    );
  }
  const body = (await response.json()) as JmapSession;
  if (!body?.apiUrl || !body?.accounts || !body?.primaryAccounts?.[CAP_MAIL]) {
    throw new JmapHttpError(response.status, "Ответ узла — не объект сессии JMAP.");
  }
  return body;
}

/** Учётная запись почты сессии (primaryAccounts[mail]); нет — ошибка программирования. */
export function mailAccount(session: JmapSession): string {
  const account = session.primaryAccounts[CAP_MAIL];
  if (!account) throw new Error("В сессии нет почтовой учётной записи.");
  return account;
}

/** Адрес WebSocket push (RFC 8887) из капабилити сессии; нет капабилити — null. */
export function websocketUrl(session: JmapSession): string | null {
  const ws = session.capabilities?.[CAP_WEBSOCKET] as { url?: string } | undefined;
  return typeof ws?.url === "string" && ws.url ? ws.url : null;
}

/** Адрес скачивания блоба (вложение, файл письма) по шаблону сессии. */
export function blobUrl(session: JmapSession, accountId: string, blobId: string, name: string): string {
  return session.downloadUrl
    .replace("{accountId}", encodeURIComponent(accountId))
    .replace("{blobId}", encodeURIComponent(blobId))
    .replace("{name}", encodeURIComponent(name))
    .replace("{type}", "");
}

interface RequestBody {
  using: string[];
  methodCalls: Array<[string, Record<string, unknown>, string]>;
}

interface ResponseBody {
  methodResponses: Array<[string, Record<string, unknown>, string]>;
  sessionState: string;
}

/** Один вызов JMAP API (RFC 8620 §3.2): POST apiUrl; ответ — пары «метод, аргументы». */
export async function jmapCall(
  apiUrl: string,
  authorization: string | null,
  using: string[],
  methodCalls: Array<[string, Record<string, unknown>, string]>,
): Promise<ResponseBody> {
  const body: RequestBody = { using, methodCalls };
  let response: Response;
  try {
    response = await jmapFetch(apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    }, authorization);
  } catch {
    throw new JmapHttpError(0, "Сеть недоступна: изменение не выполнено.");
  }
  if (!response.ok) {
    throw new JmapHttpError(
      response.status,
      response.status === 401
        ? "Сессия истекла: войдите заново."
        : `Узел ответил ошибкой HTTP ${response.status}.`,
    );
  }
  return (await response.json()) as ResponseBody;
}

/** Парный вызов метода и разбор ответа: одна пара «запрос-ответ» с одним call id. */
export async function callMethod(
  apiUrl: string,
  authorization: string | null,
  method: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const using = method.startsWith("Mailbox") || method.startsWith("Email") || method.startsWith("Thread")
    ? [CAP_CORE, CAP_MAIL]
    : [CAP_CORE];
  const body = await jmapCall(apiUrl, authorization, using, [[method, args, "c0"]]);
  const [, result] = body.methodResponses[0];
  return result;
}

/** Общий разбор ответа get-методов: объекты и не найденные идентификаторы. */
function parseGet<T>(result: Record<string, unknown>): { list: T[]; notFound: string[] } {
  return {
    list: (result.list as T[] | undefined) ?? [],
    notFound: (result.notFound as string[] | undefined) ?? [],
  };
}

const MAILBOX_PROPERTIES = [
  "id", "name", "parentId", "role", "sortOrder", "totalEmails", "unreadEmails",
  "totalThreads", "unreadThreads", "myRights", "isSubscribed",
];

/** `Mailbox/get` без идентификаторов — все папки учётной записи (дерево строит клиент). */
export async function mailboxesGet(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
): Promise<{ list: Mailbox[]; state: string }> {
  const result = await callMethod(apiUrl, authorization, "Mailbox/get", {
    accountId,
    properties: MAILBOX_PROPERTIES,
  });
  return { list: parseGet<Mailbox>(result).list, state: (result.state as string) ?? "" };
}

/** Условие фильтра `Email/query` (RFC 8621 §4.4.1): маски и папки — `mail/keywords.ts`. */
export interface EmailQueryFilter {
  inMailbox?: string;
  inMailboxOtherThan?: string[];
  hasKeyword?: string;
  notKeyword?: string;
  someInThreadHaveKeyword?: string;
  hasAttachment?: boolean;
  text?: string;
  from?: string;
  to?: string;
  subject?: string;
  before?: string;
  after?: string;
  operator?: "AND" | "OR" | "NOT";
  conditions?: EmailQueryFilter[];
}

/** Сортировка `Email/query`: receivedAt/from/subject/size + hasKeyword. */
export interface EmailQuerySort {
  property: string;
  keyword?: string;
  isAscending?: boolean;
}

/** `Email/query` окном (позиция + лимит): идентификаторы писем/представителей потоков. */
export async function emailQuery(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  filter: EmailQueryFilter,
  sort: EmailQuerySort[],
  options: { position?: number; limit?: number; collapseThreads?: boolean; total?: boolean } = {},
): Promise<{ ids: string[]; total: number | null; state: string }> {
  const result = await callMethod(apiUrl, authorization, "Email/query", {
    accountId,
    filter,
    sort,
    position: options.position ?? 0,
    ...(options.limit !== undefined ? { limit: options.limit } : {}),
    collapseThreads: options.collapseThreads ?? false,
    calculateTotal: options.total ?? true,
  });
  return {
    ids: (result.ids as string[] | undefined) ?? [],
    total: (result.total as number | undefined) ?? null,
    state: (result.queryState as string) ?? "",
  };
}

/** `Email/get`: краткие письма (список) или полные (чтение) — свойства выбирает вызывающий. */
export async function emailGet<T extends EmailSummary | EmailFull>(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  ids: string[],
  properties: readonly string[],
): Promise<T[]> {
  if (ids.length === 0) return [];
  const result = await callMethod(apiUrl, authorization, "Email/get", {
    accountId,
    ids,
    properties,
  });
  return parseGet<T>(result).list;
}

/** `Email/changes` (RFC 8620 §5.2): delta-sync по state-строке — что обновилось и что пропало. */
export async function emailChanges(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  sinceState: string,
): Promise<{ newState: string; updated: string[]; destroyed: string[]; hasMore: boolean } | null> {
  const result = await callMethod(apiUrl, authorization, "Email/changes", {
    accountId,
    sinceState,
  });
  if (result.type === "cannotCalculateChanges" || result.type === "stateMismatch") return null;
  return {
    newState: (result.newState as string) ?? "",
    updated: (result.updated as string[] | undefined) ?? [],
    destroyed: (result.destroyed as string[] | undefined) ?? [],
    hasMore: Boolean(result.hasMoreChanges),
  };
}

/** `Thread/get`: письма бесед — для группировки потоков в списке. */
export async function threadGet(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  ids: string[],
): Promise<Thread[]> {
  if (ids.length === 0) return [];
  const result = await callMethod(apiUrl, authorization, "Thread/get", { accountId, ids });
  return parseGet<Thread>(result).list;
}

/** `Email/set` обновление (RFC 8621 §5): keywords / mailboxIds / ($seen патчем) по идентификатору. */
export async function emailSetUpdate(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  updates: Record<string, Record<string, unknown>>,
): Promise<{ updated: Record<string, unknown | null>; notUpdated: Record<string, unknown> }> {
  const result = await callMethod(apiUrl, authorization, "Email/set", {
    accountId,
    update: updates,
  });
  return {
    updated: (result.updated as Record<string, unknown | null> | undefined) ?? {},
    notUpdated: (result.notUpdated as Record<string, unknown> | undefined) ?? {},
  };
}

/** `Email/set` удаление (в корзину — переносом, иное — по myRights). */
export async function emailSetDestroy(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  ids: string[],
): Promise<{ destroyed: string[]; notDestroyed: Record<string, unknown> }> {
  const result = await callMethod(apiUrl, authorization, "Email/set", {
    accountId,
    destroy: ids,
  });
  return {
    destroyed: (result.destroyed as string[] | undefined) ?? [],
    notDestroyed: (result.notDestroyed as Record<string, unknown> | undefined) ?? {},
  };
}

/** `Mailbox/set` (RFC 8621 §2.4): создание, переименование, удаление папок. */
export async function mailboxSet(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  changes: {
    create?: Record<string, { name: string; parentId: string | null; role: string | null }>;
    update?: Record<string, Record<string, unknown>>;
    destroy?: string[];
    onDestroyRemoveEmails?: boolean;
  },
): Promise<{ created: Record<string, unknown> | null; destroyed: string[] | null; errors: Record<string, unknown> }> {
  const result = await callMethod(apiUrl, authorization, "Mailbox/set", {
    accountId,
    ...(changes.create && Object.keys(changes.create).length > 0 ? { create: changes.create } : {}),
    ...(changes.update && Object.keys(changes.update).length > 0 ? { update: changes.update } : {}),
    ...(changes.destroy && changes.destroy.length > 0 ? { destroy: changes.destroy } : {}),
    onDestroyRemoveEmails: changes.onDestroyRemoveEmails ?? false,
  });
  return {
    created: (result.created as Record<string, unknown> | null) ?? null,
    destroyed: (result.destroyed as string[] | null) ?? null,
    errors: (result.notCreated as Record<string, unknown> | undefined) ??
      (result.notUpdated as Record<string, unknown> | undefined) ??
      (result.notDestroyed as Record<string, unknown> | undefined) ?? {},
  };
}
