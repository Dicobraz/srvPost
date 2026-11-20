// Обёртка oidc-client-ts (WEB-02): manager по конфигурации узла, маршруты через state, токены
// для store, тихий renew и выход «везде». oidc-client-ts мокается — сеть не нужна.
import { afterEach, beforeEach, expect, test, vi } from "vitest";

const ctorArgs = vi.fn();
const storeArgs = vi.fn();
const signinRedirect = vi.fn();
const signinRedirectCallback = vi.fn();
const signinSilent = vi.fn();
const signoutRedirect = vi.fn();

vi.mock("oidc-client-ts", () => {
  class UserManager {
    constructor(args: unknown) {
      ctorArgs(args);
    }
    signinRedirect = signinRedirect;
    signinRedirectCallback = signinRedirectCallback;
    signinSilent = signinSilent;
    signoutRedirect = signoutRedirect;
  }
  class WebStorageStateStore {
    constructor(args: unknown) {
      storeArgs(args);
    }
  }
  return { UserManager, WebStorageStateStore };
});

const { callbackUri, endSessionUrl, nameFromIdToken, signin, signinCallback, signinSilent: silent, signout, toTokens, userManager } = await import("./oidc");

const CONFIG = {
  issuer: "https://idp.example.org/realms/post",
  client_id: "thepost-webmail",
  scope: "openid profile email",
  end_session: "https://idp.example.org/realms/post/logout",
};

beforeEach(() => {
  ctorArgs.mockClear();
  storeArgs.mockClear();
  signinRedirect.mockReset();
  signinRedirectCallback.mockReset();
  signinSilent.mockReset();
  signoutRedirect.mockReset();
});

test("userManager: авторизация кодом с PKCE, state и токены в sessionStorage", () => {
  userManager(CONFIG);
  expect(ctorArgs).toHaveBeenCalledWith({
    authority: "https://idp.example.org/realms/post",
    client_id: "thepost-webmail",
    scope: "openid profile email",
    redirect_uri: callbackUri(),
    response_type: "code",
    userStore: expect.anything(),
  });
  expect(storeArgs).toHaveBeenCalledWith({ store: sessionStorage });
  // В сборке base = /mail/ (vite.config.ts), в тестах vitest отдаёт BASE_URL = "/" — состав тот же.
  expect(callbackUri()).toBe(`${location.origin}${import.meta.env.BASE_URL}callback`);
});

test("signin переносит маршрут возврата в state; callback возвращает токены и маршрут", async () => {
  const manager = userManager(CONFIG);
  signinRedirect.mockResolvedValue(undefined);
  await signin(manager, "/folder/INBOX?select=42");
  expect(signinRedirect).toHaveBeenCalledWith({ state: JSON.stringify({ route: "/folder/INBOX?select=42" }) });

  signinRedirectCallback.mockResolvedValue({
    access_token: "acc-1",
    expires_at: 1700,
    id_token: "hdr.sig",
    state: JSON.stringify({ route: "/folder/INBOX?select=42" }),
  });
  const { tokens, route } = await signinCallback(manager);
  expect(tokens).toEqual({ accessToken: "acc-1", expiresAt: 1_700_000, idToken: "hdr.sig" });
  expect(route).toBe("/folder/INBOX?select=42");

  // Чужой или битый state — возврат в начало, а не падение.
  signinRedirectCallback.mockResolvedValue({ access_token: "a", expires_at: 1, state: "мусор" });
  expect((await signinCallback(manager)).route).toBe("/");
  signinRedirectCallback.mockResolvedValue({ access_token: "a", expires_at: 1, state: 42 });
  expect((await signinCallback(manager)).route).toBe("/");
});

test("toTokens: конец жизни — мс; тихий renew отдаёт свежие токены", async () => {
  expect(toTokens({ access_token: "a", expires_at: 2, id_token: null } as never)).toEqual({
    accessToken: "a",
    expiresAt: 2000,
    idToken: null,
  });
  signinSilent.mockResolvedValue({ access_token: "acc-2", expires_at: 9, id_token: "id-2" });
  expect(await silent(userManager(CONFIG))).toEqual({
    accessToken: "acc-2",
    expiresAt: 9000,
    idToken: "id-2",
  });
  signinSilent.mockResolvedValue(undefined);
  await expect(silent(userManager(CONFIG))).rejects.toThrow();
});

test("имя пользователя из id_token: email → preferred_username → sub; битый — null", () => {
  const payload = (claims: unknown) =>
    `hdr.${btoa(JSON.stringify(claims)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "")}.sig`;
  expect(nameFromIdToken(payload({ email: "user@example.org" }))).toBe("user@example.org");
  expect(nameFromIdToken(payload({ preferred_username: "user" }))).toBe("user");
  expect(nameFromIdToken(payload({ sub: "1234" }))).toBe("1234");
  expect(nameFromIdToken("hdr.!!!.sig")).toBeNull();
  expect(nameFromIdToken(null)).toBeNull();
});

test("выход: end session из discovery; иначе — адрес из конфигурации с id_token_hint", async () => {
  const manager = userManager(CONFIG);
  const assigned: string[] = [];
  const navigate = (url: string) => assigned.push(url);
  // Discovery отдал end_session_endpoint: уводим со страницы, адреса из конфигурации не нужен.
  signoutRedirect.mockResolvedValue(undefined);
  await signout(manager, { accessToken: "a", expiresAt: 0, idToken: "id-1" }, CONFIG, navigate);
  expect(signoutRedirect).toHaveBeenCalledWith({
    id_token_hint: "id-1",
    post_logout_redirect_uri: `${location.origin}${import.meta.env.BASE_URL}`,
  });
  expect(assigned).toHaveLength(0);

  // Discovery не отдал (исключение) — запасной адрес end_session из секции webmail.
  signoutRedirect.mockRejectedValue(new Error("no end_session_endpoint"));
  await signout(manager, { accessToken: "a", expiresAt: 0, idToken: "id-1" }, CONFIG, navigate);
  expect(assigned).toHaveLength(1);
  const url = new URL(assigned[0]);
  expect(url.toString().startsWith(CONFIG.end_session)).toBe(true);
  expect(url.searchParams.get("id_token_hint")).toBe("id-1");
  expect(url.searchParams.get("post_logout_redirect_uri")).toBe(
    `${location.origin}${import.meta.env.BASE_URL}`,
  );

  // Ни discovery, ни конфигурация — просто локальный выход (никаких переходов).
  await signout(manager, { accessToken: "a", expiresAt: 0, idToken: null }, { ...CONFIG, end_session: null }, navigate);
  expect(assigned).toHaveLength(1);
  // Адрес выхода (тест чистой функции): hint и возврат — в запросе.
  const fallback = endSessionUrl(CONFIG, "id-9");
  expect(fallback.searchParams.get("id_token_hint")).toBe("id-9");
});

afterEach(() => {
  vi.restoreAllMocks();
});
