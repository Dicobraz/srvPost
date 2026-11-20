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
  const russian = basicCredentials("юзер@пример.рф", "пароль");
  expect(atob(russian)).toBe("юзер@пример.рф:пароль");
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
