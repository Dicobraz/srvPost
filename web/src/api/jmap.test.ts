// Клиент JMAP (WEB-02): заголовок Authorization — Bearer (OIDC) или Basic (пароль приложения,
// base64 UTF-8 — имя входа бывает русским); запрос несёт заголовок, 401 отдаётся вызывающему.
import { afterEach, expect, test, vi } from "vitest";

import { authHeader, basicCredentials, jmapFetch, JMAP_SESSION, verifyBasic } from "./jmap";
import type { Session } from "../auth/store";

afterEach(() => {
  vi.unstubAllGlobals();
});

test("Basic — base64 UTF-8 пары логин:пароль (кириллица не теряется)", () => {
  const header = basicCredentials("user@example.org", "app-secret");
  expect(atob(header)).toBe("user@example.org:app-secret");
  // atob отдаёт байты как Latin-1 — кириллицу читаем декодером UTF-8.
  const russian = basicCredentials("юзер@пример.рф", "пароль");
  const decoded = new TextDecoder().decode(Uint8Array.from(atob(russian), (c) => c.charCodeAt(0)));
  expect(decoded).toBe("юзер@пример.рф:пароль");
});

test("authHeader: OIDC — Bearer, Basic-сессия — Basic, нет сессии — null", () => {
  const oidc: Session = { kind: "oidc", accessToken: "acc-1", expiresAt: 0, idToken: null };
  expect(authHeader(oidc)).toBe("Bearer acc-1");
  const basic: Session = { kind: "basic", login: "user@example.org", secret: "app-secret" };
  expect(authHeader(basic)).toBe(`Basic ${basicCredentials("user@example.org", "app-secret")}`);
  expect(authHeader(null)).toBeNull();
});

test("jmapFetch несёт Authorization поверх заголовков запроса", async () => {
  const seen: Array<{ authorization: string | null; accept: string | null }> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    void input;
    seen.push({ authorization: headers.get("Authorization"), accept: headers.get("Accept") });
    return new Response("{}", { status: 200 });
  });
  vi.stubGlobal("fetch", fetchMock);
  await jmapFetch(JMAP_SESSION, { headers: { Accept: "application/json" } }, "Bearer acc-1");
  expect(seen[0]).toEqual({ authorization: "Bearer acc-1", accept: "application/json" });
  await jmapFetch(JMAP_SESSION, undefined, null); // без сессии заголовка нет
  expect(seen[1]).toEqual({ authorization: null, accept: null });
});

test("verifyBasic: 200 — вход; 401 — понятная ошибка; сеть — тоже", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 200 })));
  expect(await verifyBasic("user@example.org", "app-secret")).toBeNull();

  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 401 })));
  const wrong = await verifyBasic("user@example.org", "неверный");
  expect(wrong?.message).toBe("Неверное имя входа или пароль приложения.");

  vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("network down")));
  const down = await verifyBasic("user@example.org", "app-secret");
  expect(down?.message).toContain("Узел недоступен");

  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 503 })));
  expect((await verifyBasic("user@example.org", "app-secret"))?.message).toContain("503");
});

// ---- WEB-03: сессия, запросы API, Mailbox/Email set ----

import {
  CAP_MAIL,
  CAP_WEBSOCKET,
  emailChanges,
  emailSetUpdate,
  fetchSession,
  isMethodError,
  jmapCall,
  mailboxSet,
  mailAccount,
  mailboxesGet,
  websocketUrl,
  JmapHttpError,
  type JmapSession,
} from "./jmap";

const SESSION_BODY: JmapSession = {
  capabilities: {
    "urn:ietf:params:jmap:core": { maxSizeRequest: 10_000_000 },
    [CAP_WEBSOCKET]: { url: "wss://node.example/jmap/ws", supportsPush: true },
  },
  accounts: { acc1: { name: "user@example.org", isPersonal: true, isReadOnly: false, accountCapabilities: {} } },
  primaryAccounts: { [CAP_MAIL]: "acc1" },
  username: "user@example.org",
  apiUrl: "https://node.example/jmap/api",
  downloadUrl: "https://node.example/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
  uploadUrl: "https://node.example/jmap/upload/{accountId}/",
  eventSourceUrl: "https://node.example/jmap/eventsource/?types={types}&closeafter={closeafter}&ping={ping}",
  state: "2c9f1",
};

/** fetch-обманка: тело POST /jmap/api записывается, ответ — methodResponses. */
function apiStub(responses: Array<[string, Record<string, unknown>]>, seen?: unknown[]): (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> {
  return async (input, init) => {
    if (seen) seen.push({ url: String(input), body: init?.body, headers: new Headers(init?.headers) });
    return new Response(JSON.stringify({ methodResponses: responses, sessionState: "2c9f1" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };
}

test("fetchSession: валидный объект — сессия; не-JMAP — понятная ошибка", async () => {
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
    new Response(JSON.stringify(SESSION_BODY), { status: 200, headers: { "Content-Type": "application/json" } }),
  ));
  const session = await fetchSession("Bearer acc-1");
  expect(mailAccount(session)).toBe("acc1");
  expect(websocketUrl(session)).toBe("wss://node.example/jmap/ws");

  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("{}", { status: 200 })));
  await expect(fetchSession("Bearer acc-1")).rejects.toThrow("не объект сессии JMAP");

  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response("", { status: 401 })));
  const error = await fetchSession("Bearer stale").catch((e: unknown) => e);
  expect(error).toBeInstanceOf(JmapHttpError);
  expect((error as JmapHttpError).message).toContain("Сессия истекла");
});

test("jmapCall: using по методу, Authorization, пары «метод-ответ»", async () => {
  const seen: unknown[] = [];
  vi.stubGlobal("fetch", apiStub([["Mailbox/get", { accountId: "acc1" }]], seen));
  const body = await jmapCall("https://node.example/jmap/api", "Bearer acc-1", ["urn:ietf:params:jmap:core", CAP_MAIL], [
    ["Mailbox/get", { accountId: "acc1" }, "c0"],
  ]);
  expect(body.methodResponses[0][0]).toBe("Mailbox/get");
  const request = JSON.parse((seen[0] as { body: string }).body) as { using: string[]; methodCalls: unknown[][] };
  expect(request.using).toEqual(["urn:ietf:params:jmap:core", CAP_MAIL]);
  expect((seen[0] as { headers: Headers }).headers.get("Authorization")).toBe("Bearer acc-1");
});

test("mailboxesGet: список и состояние; Email/changes — delta-sync по state-строке", async () => {
  vi.stubGlobal("fetch", apiStub([["Mailbox/get", { list: [{ id: "mb1", name: "Входящие", role: "inbox" }], state: "st-1" }]]));
  const mailboxes = await mailboxesGet("https://node.example/jmap/api", "Bearer acc-1", "acc1");
  expect(mailboxes.list[0]?.role).toBe("inbox");
  expect(mailboxes.state).toBe("st-1");

  vi.stubGlobal("fetch", apiStub([["Email/changes", { newState: "st-2", updated: ["e1"], destroyed: ["e2"] }]]));
  const changes = await emailChanges("https://node.example/jmap/api", "Bearer acc-1", "acc1", "st-1");
  expect(changes?.newState).toBe("st-2");
  expect(changes?.updated).toEqual(["e1"]);

  vi.stubGlobal("fetch", apiStub([["error", { type: "cannotCalculateChanges" }]]));
  expect(await emailChanges("https://node.example/jmap/api", "Bearer acc-1", "acc1", "st-9")).toBeNull();
});

test("Email/set: патчи keywords/mailboxIds уходят одним запросом", async () => {
  const seen: unknown[] = [];
  vi.stubGlobal("fetch", apiStub([["Email/set", { updated: { e1: null } }]], seen));
  const result = await emailSetUpdate("https://node.example/jmap/api", "Bearer acc-1", "acc1", {
    e1: { "keywords/$flagged": true },
    e2: { mailboxIds: { mb2: true } },
  });
  expect(result.updated.e1).toBeNull();
  const request = JSON.parse((seen[0] as { body: string }).body) as { methodCalls: Array<[string, Record<string, unknown>]> };
  expect(request.methodCalls[0][0]).toBe("Email/set");
  expect(request.methodCalls[0][1].update).toEqual({ e1: { "keywords/$flagged": true }, e2: { mailboxIds: { mb2: true } } });
});

test("Mailbox/set: создание/переименование/удаление; ошибка папки с письмами — наружу", async () => {
  const seen: unknown[] = [];
  vi.stubGlobal("fetch", apiStub([["Mailbox/set", { created: { c1: { id: "mb9" } } }]], seen));
  const created = await mailboxSet("https://node.example/jmap/api", "Bearer acc-1", "acc1", {
    create: { c1: { name: "Проекты", parentId: null, role: null } },
  });
  expect(created.created?.c1).toEqual({ id: "mb9" });
  const request = JSON.parse((seen[0] as { body: string }).body) as { methodCalls: Array<[string, Record<string, unknown>]> };
  expect(request.methodCalls[0][1].create).toEqual({ c1: { name: "Проекты", parentId: null, role: null } });

  vi.stubGlobal("fetch", apiStub([["Mailbox/set", { notDestroyed: { mb1: { type: "mailboxHasEmail" } } }]]));
  const denied = await mailboxSet("https://node.example/jmap/api", "Bearer acc-1", "acc1", { destroy: ["mb1"] });
  expect(denied.errors.mb1).toEqual({ type: "mailboxHasEmail" });
});

test("isMethodError: ответ error — тип и описание", () => {
  expect(isMethodError({ "@type": "error", type: "unknownMethod", description: null })).toBe(true);
  expect(isMethodError({ accountId: "acc1" })).toBe(false);
});
