import { cleanup, fireEvent, render, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./App";
import { storageKey } from "./auth/store";

// Вход (WEB-02) мокается на границе: конфигурация — fetch (/mail/config.json), oidc-client-ts —
// модуль (сеть не нужна). Запросы — по контейнеру своего рендера: автоочистки RTL без globals
// у vitest нет (как в консоли), cleanup — в afterEach.

const OIDC_CONFIG = {
  oidc: { issuer: "https://idp.example.org", client_id: "thepost-webmail", scope: "openid", end_session: null },
  basic: false,
};
const BASIC_CONFIG = { oidc: null, basic: true };

/** id_token с полезной нагрузкой (base64url) — для имени пользователя в шапке. */
function idToken(claims: object): string {
  const payload = btoa(JSON.stringify(claims)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  return `hdr.${payload}.sig`;
}

vi.mock("oidc-client-ts", () => {
  const recorded = { redirect: vi.fn() };
  class UserManager {
    signinRedirect = recorded.redirect;
    signinRedirectCallback = vi.fn();
    signinSilent = vi.fn();
    signoutRedirect = vi.fn();
  }
  class WebStorageStateStore {}
  return { UserManager, WebStorageStateStore, recorded };
});

const oidcMock = () =>
  vi.importMock<typeof import("oidc-client-ts") & { recorded: { redirect: ReturnType<typeof vi.fn> } }>(
    "oidc-client-ts",
  );

/** fetch: конфигурация входа по адресу, сессия JMAP — ответом jmapStatus. */
function stubFetch(config: unknown, jmapStatus = 200, configStatus = 200) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("config.json")) {
      return new Response(configStatus === 200 ? JSON.stringify(config) : "{}", {
        status: configStatus,
        headers: { "Content-Type": configStatus === 200 ? "application/json" : "text/html" },
      });
    }
    if (url.includes("jmap")) return new Response("{}", { status: jmapStatus });
    throw new Error(`неожиданный запрос в тесте: ${url}`);
  });
}

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

test("оболочка — только в состоянии входа: сессия восстановлена, навигация и заглушки на месте", async () => {
  sessionStorage.setItem(
    storageKey(),
    JSON.stringify({
      accessToken: "acc-1",
      expiresAt: Date.now() + 3_600_000,
      idToken: idToken({ email: "user@example.org" }),
    }),
  );
  vi.stubGlobal("fetch", stubFetch(BASIC_CONFIG));
  const page = within(render(
    <MemoryRouter initialEntries={["/"]}>
      <App />
    </MemoryRouter>,
  ).container);
  const nav = await page.findByRole("navigation", { name: "Разделы" });
  expect(within(nav).getByRole("link", { name: "Почта" }).getAttribute("href")).toBe("/");
  expect(within(nav).getByRole("link", { name: "Календарь" }).getAttribute("href")).toBe("/calendar");
  // Шов «Каналы» (решение 2026-11-17): место под будущий веб-чат, пункт отключён.
  const seam = within(nav).getByText("Каналы");
  expect(seam.getAttribute("aria-disabled")).toBe("true");
  expect(page.getByRole("heading", { name: "Почта" })).toBeTruthy();
  expect(page.getByText("Раздел в разработке.")).toBeTruthy();
  expect(page.getByText("user@example.org")).toBeTruthy(); // имя из id_token — не показываем мусор
  expect(page.getByRole("button", { name: "Выйти" })).toBeTruthy();
  expect(document.documentElement.dataset.theme).toBe("light");
  expect(document.getElementById("thepost-theme")?.textContent).toContain("--c-screen:");
});

test("тема применяется к документу даже без сессии — заставка входа по паролю приложения", async () => {
  vi.stubGlobal("fetch", stubFetch(BASIC_CONFIG));
  const page = within(render(
    <MemoryRouter initialEntries={["/"]}>
      <App />
    </MemoryRouter>,
  ).container);
  await page.findByRole("button", { name: "Войти" }); // нет сессии — форма, не оболочка
  expect(page.queryByRole("navigation")).toBeNull();
  expect(document.documentElement.dataset.theme).toBe("light");
  expect(document.getElementById("thepost-theme")?.textContent).toContain("--c-screen:");
});

test("вход по паролю приложения: неверная пара — ошибка inline; верная — оболочка", async () => {
  vi.stubGlobal("fetch", stubFetch(BASIC_CONFIG, 401));
  const page = within(render(
    <MemoryRouter initialEntries={["/"]}>
      <App />
    </MemoryRouter>,
  ).container);
  fireEvent.change(await page.findByLabelText("Имя входа"), { target: { value: "user@example.org" } });
  fireEvent.change(page.getByLabelText("Пароль приложения"), { target: { value: "неверный" } });
  fireEvent.click(page.getByRole("button", { name: "Войти" }));
  const alert = await page.findByRole("alert");
  expect(alert.textContent).toContain("Неверное имя входа или пароль приложения.");

  vi.stubGlobal("fetch", stubFetch(BASIC_CONFIG, 200));
  fireEvent.change(page.getByLabelText("Пароль приложения"), { target: { value: "app-secret" } });
  fireEvent.click(page.getByRole("button", { name: "Войти" }));
  const nav = await page.findByRole("navigation", { name: "Разделы" });
  expect(within(nav).getByRole("link", { name: "Почта" })).toBeTruthy();
});

test("выход: оболочка возвращается к форме входа, соседям сообщение по каналу не мешает", async () => {
  sessionStorage.setItem(
    storageKey(),
    JSON.stringify({ accessToken: "acc-1", expiresAt: Date.now() + 3_600_000, idToken: null }),
  );
  vi.stubGlobal("fetch", stubFetch(BASIC_CONFIG));
  const page = within(render(
    <MemoryRouter initialEntries={["/"]}>
      <App />
    </MemoryRouter>,
  ).container);
  fireEvent.click(await page.findByRole("button", { name: "Выйти" }));
  await page.findByRole("button", { name: "Войти" });
  expect(page.queryByRole("navigation")).toBeNull();
});

test("конфигурация входа не получилась — человекочитаемая ошибка, оболочки и формы нет", async () => {
  vi.stubGlobal("fetch", stubFetch(BASIC_CONFIG, 200, 404));
  const page = within(render(
    <MemoryRouter initialEntries={["/"]}>
      <App />
    </MemoryRouter>,
  ).container);
  const alert = await page.findByRole("alert");
  expect(alert.textContent).toContain("конфигурацию входа");
  expect(page.queryByRole("navigation")).toBeNull();
  expect(page.queryByLabelText("Имя входа")).toBeNull();
});

test("узел сообщил только OIDC: тихий перевход к поставщику с сохранением маршрута", async () => {
  const mock = await oidcMock();
  mock.recorded.redirect.mockResolvedValue(undefined);
  vi.stubGlobal("fetch", stubFetch(OIDC_CONFIG));
  const page = within(render(
    <MemoryRouter initialEntries={["/folder/INBOX?select=42"]}>
      <App />
    </MemoryRouter>,
  ).container);
  await page.findByText("Загружаем…");
  await vi.waitFor(() => expect(mock.recorded.redirect).toHaveBeenCalled());
  const args = mock.recorded.redirect.mock.calls[0][0] as { state: string };
  expect(JSON.parse(args.state)).toEqual({ route: "/folder/INBOX?select=42" });
  expect(page.queryByRole("navigation")).toBeNull(); // оболочки без сессии нет
});
