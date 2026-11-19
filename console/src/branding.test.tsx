// Приёмка UI-22: страница входа перезапрашивает брендинг по домену имени входа (знак, название, заголовок
// вкладки); после входа — знак и название своей организации в шапке; в разделе «Брендинг» незаданная роль
// показывает действующий цвет уровня выше, ошибки контраста 422 — у поля роли из `errors`, сброс организации
// возвращает тему установки.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, expect, test } from "vitest";

import { App } from "./App";
import { ORG, stubApi } from "./test-api";
import { open } from "./test-app";

const BASE = `/api/v1/orgs/${ORG}`;
const empty = { archive_after: null, archive_quota_bytes: null, dkim_selector: null, max_recipients: null, milter_profile: null, quota_bytes: null, rcpts_per_hour: null, retention: null, send_per_hour: null, trash_purge: null, trash_retention: null };
const noPalette = { palette: { light: {}, dark: {}, cli: {} } };
const org = () => ({ id: ORG, default: true, policy: empty, effective: empty });
const levelForm = async (name: string) => await screen.findByRole("form", { name });

afterEach(() => {
  cleanup();
  sessionStorage.clear();
  localStorage.clear();
  document.title = "";
});

test("страница входа: брендинг по домену имени входа — знак и название вместо IT TASK, заголовок вкладки", async () => {
  const orgBranding = { product_name: "Кофе", logo: "/api/v1/public/branding/logo/ab", ...noPalette };
  const calls = stubApi({
    "GET /api/v1/session": { body: { oidc: null, password: true } },
    "GET /api/v1/public/branding": (c) => (c.path.includes("domain=example.org") ? { body: orgBranding } : { body: { product_name: null, logo: null, ...noPalette } }),
  });
  const { container } = render(
    <MemoryRouter initialEntries={["/login"]}>
      <App />
    </MemoryRouter>,
  );
  // Сперва брендинг установки: встроенный знак и название The Post.
  expect(await screen.findByText("The Post — вход")).toBeTruthy();
  // Домен из введённого имени входа (после @, с задержкой) — перезапрос брендинга организации.
  fireEvent.change(await screen.findByLabelText("Имя входа"), { target: { value: "admin@example.org" } });
  expect(await screen.findByText("Кофе — вход")).toBeTruthy();
  await waitFor(() => expect(document.title).toBe("Кофе"));
  expect(container.querySelector('img[src="/api/v1/public/branding/logo/ab"]')).toBeTruthy();
  expect(calls.some((c) => c.method === "GET" && c.path === "/api/v1/public/branding?domain=example.org")).toBe(true);
});

test("после входа: effective своей организации — знак и название в шапке", async () => {
  open(
    "/",
    {
      [`GET ${BASE}`]: { body: org() },
      [`GET ${BASE}/branding`]: {
        body: { own: null, effective: { product_name: "Школа №1", logo: { hash: "ff00", size: 100, width: 100, height: 50 }, ...noPalette } },
      },
    },
    ["organization_admin"],
  );
  expect(await screen.findAllByText("Школа №1")).not.toHaveLength(0); // шапка и заголовок боковой панели
  await waitFor(() => expect(document.querySelector('img[src="/api/v1/public/branding/logo/ff00"]')).toBeTruthy());
});

test("раздел «Брендинг»: незаданная роль — действующий цвет уровня выше; сброс организации возвращает тему установки", async () => {
  const installation = { own: { product_name: "Сервер", primary: null, logo: null, light: { sel: "#112233" }, dark: {}, cli: {} }, effective: { product_name: "Сервер", logo: null, palette: { light: { sel: "#112233" }, dark: {}, cli: {} } } };
  const afterReset = { own: null, effective: installation.effective };
  let reset = false;
  const calls = open("/", {
    [`GET ${BASE}`]: { body: org() },
    "GET /api/v1/branding": { body: installation },
    "GET /api/v1/public/branding": { body: { product_name: "Сервер", logo: null, ...noPalette } },
    [`GET ${BASE}/branding`]: () => ({
      body: reset
        ? afterReset
        : { own: { product_name: "Моя орг", primary: null, logo: null, light: { sel: "#445566" }, dark: {}, cli: {} }, effective: { product_name: "Моя орг", logo: null, palette: { light: { sel: "#445566", screen: "#ABCDEF" }, dark: {}, cli: {} } } },
    }),
    [`DELETE ${BASE}/branding`]: () => {
      reset = true;
      return { body: afterReset };
    },
  });
  // Вкладка организации: sel задана уровнем, screen — нет: действующий цвет — с уровня выше (установки).
  fireEvent.click(await screen.findByRole("tab", { name: "Организация" }));
  expect(await within(await levelForm("Брендинг организации")).findByText("#ABCDEF")).toBeTruthy();
  // Сброс с подтверждением: свой набор организации удаляется, действующие цвета — установки.
  fireEvent.click(within(await levelForm("Брендинг организации")).getByRole("button", { name: "Сбросить" }));
  fireEvent.click(await screen.findByRole("button", { name: "Да, сбросить" }));
  expect(await screen.findByText("Брендинг сброшен")).toBeTruthy();
  await within(await levelForm("Брендинг организации")).findByText("#112233"); // sel — снова цвет установки
  expect(calls.some((c) => c.method === "DELETE" && c.path === `${BASE}/branding`)).toBe(true);
});

test("раздел «Брендинг»: ошибка контраста 422 — у поля роли из errors, текст detail сервера", async () => {
  const detail = "тёмная тема: sel #F5E663 на панели panel #FFFFFF — 1,3:1, нужно 3:1";
  open("/", {
    [`GET ${BASE}`]: { body: org() },
    "GET /api/v1/branding": { body: { own: { product_name: "Сервер", primary: null, logo: null, light: {}, dark: {}, cli: {} }, effective: { product_name: "Сервер", logo: null, palette: { light: {}, dark: {}, cli: {} } } } },
    "PUT /api/v1/branding": { status: 422, body: { status: 422, title: "Unprocessable Entity", detail, errors: [{ field: "dark.sel", role: "sel", theme: "dark", bg: "panel", contrast: 1.3, min: 3 }] } },
  });
  const form = await levelForm("Брендинг установки");
  expect(await within(form).findByText(/Действует: Сервер/)).toBeTruthy();
  fireEvent.click(within(form).getByRole("button", { name: "Сохранить брендинг" }));
  // Ошибка — у поля роли (вкладка открывается на теме первой ошибки) с текстом detail сервера.
  const shown = await screen.findAllByText(detail);
  expect(shown.some((e) => e.closest(".ant-form-item-explain-error"))).toBeTruthy();
});

test("оператор: раздел «Брендинг» только для чтения — вкладки установки и кнопки изменения скрыты", async () => {
  const calls = open(
    "/",
    {
      [`GET ${BASE}`]: { body: org() },
      [`GET ${BASE}/branding`]: { body: { own: null, effective: { product_name: null, logo: null, ...noPalette } } },
    },
    ["operator"],
  );
  expect(await screen.findByText("Брендинг")).toBeTruthy();
  await levelForm("Брендинг организации");
  expect(screen.queryByRole("form", { name: "Брендинг установки" })).toBeNull();
  expect(screen.queryByRole("button", { name: "Сохранить брендинг" })).toBeNull();
  expect(calls.some((c) => c.path === "/api/v1/branding")).toBe(false);
});
