// Экран входа (WEB-02): форма «логин + пароль приложения» — проверка на `/jmap/session`, ошибка
// inline, без блокировки; OIDC-кнопка — когда узел сообщил поставщика. AuthProvider — настоящий
// (fetch подменяется), как у консоли.
import { fireEvent, render, cleanup, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { AuthProvider } from "../auth/session";
import { LoginPage } from "./login";

beforeEach(() => {
  sessionStorage.clear();
  localStorage.clear();
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const json = (body: unknown) =>
  new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });

/** fetch подменяется по адресу: конфиг входа и сессия JMAP; прочие — ошибка теста. */
function stubFetch(config: unknown, jmapStatus = 200) {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("config.json")) return json(config);
    if (url.includes("jmap")) return new Response("{}", { status: jmapStatus });
    throw new Error(`неожиданный запрос в тесте: ${url}`);
  });
}

async function loginPage(config: unknown, jmapStatus = 200) {
  vi.stubGlobal("fetch", stubFetch(config, jmapStatus));
  const page = render(
    <MemoryRouter initialEntries={["/login"]}>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<p>Почта открыта</p>} />
        </Routes>
      </AuthProvider>
    </MemoryRouter>,
  );
  return within(page.container);
}

test("вход по паролю приложения: верная пара — сессия и возврат в Почту; неверная — ошибка inline", async () => {
  let page = await loginPage({ oidc: null, basic: true });
  const login = await page.findByLabelText("Имя входа");
  const secret = page.getByLabelText("Пароль приложения");
  fireEvent.change(login, { target: { value: "user@example.org" } });
  fireEvent.change(secret, { target: { value: "app-secret" } });
  fireEvent.click(page.getByRole("button", { name: "Войти" }));
  await page.findByText("Почта открыта");

  // Заново: неверная пара — понятная ошибка рядом с формой, без модалки.
  cleanup();
  page = await loginPage({ oidc: null, basic: true }, 401);
  fireEvent.change(await page.findByLabelText("Имя входа"), { target: { value: "user@example.org" } });
  fireEvent.change(page.getByLabelText("Пароль приложения"), { target: { value: "неверный" } });
  fireEvent.click(page.getByRole("button", { name: "Войти" }));
  const alert = await page.findByRole("alert");
  expect(alert.textContent).toContain("Неверное имя входа или пароль приложения.");
  expect(page.queryByText("Почта открыта")).toBeNull();
});

test("узел сообщил поставщика OIDC — кнопка входа у поставщика рядом с формой fallback", async () => {
  const page = await loginPage({
    oidc: { issuer: "https://idp.example.org", client_id: "thepost-webmail", scope: "openid", end_session: null },
    basic: true,
  });
  expect(await page.findByRole("button", { name: "Войти через поставщика идентификации" })).toBeTruthy();
  expect(page.getByLabelText("Имя входа")).toBeTruthy();
});

test("конфигурация входа не получилась — человекочитаемая ошибка с повтором, формы нет", async () => {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) =>
      String(input).endsWith("config.json") ? new Response("{}", { status: 404 }) : new Response("{}", { status: 200 }),
    ),
  );
  const page = within(
    render(
      <MemoryRouter initialEntries={["/login"]}>
        <AuthProvider>
          <LoginPage />
        </AuthProvider>
      </MemoryRouter>,
    ).container,
  );
  const alert = await page.findByRole("alert");
  expect(alert.textContent).toContain("конфигурацию входа");
  expect(page.queryByLabelText("Имя входа")).toBeNull();
});
