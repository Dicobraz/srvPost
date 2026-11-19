import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";

import type { Schemas } from "../api/client";
import { ORG } from "../test-api";
import { BASE, open, sent } from "../test-app";

const cells = <T,>(v: T) => ({ own: v, partner: v, neighbor: v, external: v });

const matrix = (invite: Schemas["InviteMode"]): Schemas["TrustMatrix"] => ({
  invite_new: cells(invite),
  itip_updates: cells("on"),
  auto_reply: cells("on"),
  mdn: cells("on"),
  auto_forward: cells("off"),
  freebusy: cells("free_busy"),
  sharing: cells("details"),
  group_post: cells("closed"),
});

const policy = (invite: Schemas["InviteMode"]): Schemas["TrustPolicy"] => ({ ...matrix(invite), partners: [], auto_forward_domains: [] });

const sources = (level: Schemas["TrustLevel"] | null): Schemas["TrustSources"] => ({
  invite_new: cells(level),
  itip_updates: cells(level),
  auto_reply: cells(level),
  mdn: cells(level),
  auto_forward: cells(level),
  freebusy: cells(level),
  sharing: cells(level),
  group_post: cells(level),
});

/** Вид уровня: свой ответ «письмо с кнопкой», закреплены клетки соседа и интернета у нового приглашения. */
const view = (over: Partial<Schemas["TrustView"]> = {}): Schemas["TrustView"] => ({
  own: policy("button"),
  fixed: {
    invite_new: { ...cells(false), neighbor: true, external: true },
    itip_updates: cells(false),
    auto_reply: cells(false),
    mdn: cells(false),
    auto_forward: cells(false),
    freebusy: cells(false),
    sharing: cells(false),
    group_post: cells(false),
  },
  effective: {
    matrix: matrix("button"),
    ceiling: { matrix: matrix("auto"), sources: sources("installation") },
    source: sources(null),
    over_ceiling: [],
  },
  ...over,
});

const empty = {
  archive_after: null,
  archive_quota_bytes: null,
  dkim_selector: null,
  max_recipients: null,
  milter_profile: null,
  quota_bytes: null,
  rcpts_per_hour: null,
  retention: null,
  send_per_hour: null,
  trash_purge: null,
  trash_retention: null,
};
const account = {
  id: "a1",
  login: "alice@example.org",
  domain: "d1",
  display_name: "Алиса",
  enabled: true,
  external_id: null,
  aliases: [],
  hidden_from_gal: false,
  quota: { used_bytes: 0, messages: 0, limit_bytes: null },
  policy: empty,
  effective: empty,
};

afterEach(() => {
  cleanup();
  sessionStorage.clear();
  localStorage.clear();
});

test("значения выше потолка недоступны с подсказкой; доступное значение выбирается и сохраняется", async () => {
  const v = view();
  // Потолок организации по партнёру — «письмо с кнопкой» с уровня установки; для остальных — «авто».
  v.effective.ceiling.matrix.invite_new = { ...cells("auto"), partner: "button" };
  v.effective.ceiling.sources.invite_new = { own: "installation", partner: "installation", neighbor: null, external: null };
  // Потолок занятости — «ограниченные подробности»: доступное, но не действующее значение.
  v.effective.ceiling.matrix.freebusy = cells("limited");
  const calls = open("/trust", {
    [`GET ${BASE}/trust`]: { body: v },
    [`PUT ${BASE}/trust`]: (c) => ({ body: c.body }),
  });
  const select = await screen.findByRole("combobox", { name: "Новое приглашение — Партнёр" });
  fireEvent.mouseDown(select);
  // Значение выше потолка видно, но недоступно, с подсказкой «потолок уровня …: …».
  const auto = await screen.findByTitle("потолок уровня установка: письмо с кнопкой");
  expect(auto.className).toContain("disabled");
  expect(auto.textContent).toContain("авто");

  fireEvent.mouseDown(screen.getByRole("combobox", { name: "Занятость — Партнёр" }));
  fireEvent.click(await screen.findByTitle("ограниченные подробности"));
  fireEvent.click(screen.getByRole("button", { name: "Сохранить политику" }));
  await waitFor(() =>
    expect(sent(calls, "PUT", `${BASE}/trust`)[0]?.body).toEqual({
      ...policy("button"),
      freebusy: { ...cells("free_busy"), partner: "limited" },
      partners: [],
      auto_forward_domains: [],
    }),
  );
  expect(await screen.findByText("Политика доверия сохранена")).toBeTruthy();
});

test("закреплённые клетки — текстом с замком, без выбора", async () => {
  open("/trust", { [`GET ${BASE}/trust`]: { body: view() } });
  expect(await screen.findByRole("combobox", { name: "Новое приглашение — Свои" })).toBeTruthy();
  expect(screen.queryByRole("combobox", { name: "Новое приглашение — Сосед по установке" })).toBeNull();
  expect(screen.queryByRole("combobox", { name: "Новое приглашение — Интернет" })).toBeNull();
  expect(screen.getAllByRole("img", { name: "закреплено" })).toHaveLength(2);
  expect(await screen.findAllByText("закреплено контрактом")).toHaveLength(2);
});

test("ответ 422 показывается у клетки с текстом detail сервера", async () => {
  const detail = "Новое приглашение, партнёр: «авто» выше потолка «письмо с кнопкой» (установка).";
  const calls = open("/trust", {
    [`GET ${BASE}/trust`]: { body: view() },
    [`PUT ${BASE}/trust`]: {
      status: 422,
      body: {
        status: 422,
        title: "Unprocessable Entity",
        detail,
        errors: [{ function: "invite_new", peer: "partner", value: { invite: "auto" }, ceiling: { invite: "button" }, level: "installation" }],
      },
    },
  });
  const select = await screen.findByRole("combobox", { name: "Новое приглашение — Партнёр" });
  fireEvent.mouseDown(select);
  fireEvent.click(await screen.findByTitle("авто"));
  fireEvent.click(screen.getByRole("button", { name: "Сохранить политику" }));
  expect(await screen.findByText(detail)).toBeTruthy();
  expect(sent(calls, "PUT", `${BASE}/trust`)).toHaveLength(1);
});

test("переключение уровня перечитывает матрицу: установка и группа", async () => {
  const calls = open("/trust", {
    [`GET ${BASE}/trust`]: { body: view() },
    [`GET /api/v1/trust`]: { body: view({ own: policy("auto") }) },
    [`GET ${BASE}/groups`]: { body: [{ id: "g1", name: "Руководство" }] },
    [`GET ${BASE}/groups/g1/trust`]: { body: view() },
  });
  expect(await screen.findByRole("combobox", { name: "Новое приглашение — Свои" })).toBeTruthy();
  expect(sent(calls, "GET", `${BASE}/trust`)).toBeTruthy();

  fireEvent.click(await screen.findByRole("radio", { name: "Установка" }));
  await waitFor(() => expect(sent(calls, "GET", "/api/v1/trust")).toHaveLength(1));

  fireEvent.click(screen.getByRole("radio", { name: "Группа" }));
  fireEvent.mouseDown(await screen.findByRole("combobox", { name: "Группа уровня" }));
  fireEvent.click(await screen.findByTitle("Руководство"));
  await waitFor(() => expect(sent(calls, "GET", `${BASE}/groups/g1/trust`)).toHaveLength(1));
  expect(await screen.findByRole("combobox", { name: "Новое приглашение — Свои" })).toBeTruthy();
});

test("партнёры и домены автопересылки — в теле PUT организации; сброс уровня — DELETE с подтверждением", async () => {
  const v = view();
  v.own = { ...policy("button"), partners: ["partner.example"], auto_forward_domains: ["mail.partner.example"] };
  const calls = open("/trust", {
    [`GET ${BASE}/trust`]: { body: v },
    [`PUT ${BASE}/trust`]: (c) => ({ body: c.body }),
    [`DELETE ${BASE}/trust`]: { body: v },
  });
  fireEvent.click(await screen.findByRole("tab", { name: "Партнёры" }));
  expect(screen.getByText("Домены-партнёры")).toBeTruthy();
  fireEvent.change(await screen.findByRole("combobox", { name: "Домены-партнёры" }), { target: { value: "other.example," } });
  fireEvent.click(screen.getByRole("button", { name: "Сохранить политику" }));
  await waitFor(() =>
    expect(sent(calls, "PUT", `${BASE}/trust`)[0]?.body).toEqual({
      ...v.own,
      partners: ["partner.example", "other.example"],
    }),
  );

  fireEvent.click(screen.getByRole("button", { name: "Сбросить уровень" }));
  const confirm = await screen.findByText("Сбросить уровень?");
  fireEvent.click(within(confirm.closest(".ant-popover") as HTMLElement).getByRole("button", { name: "Сбросить" }));
  await waitFor(() => expect(sent(calls, "DELETE", `${BASE}/trust`)).toHaveLength(1));
});

test("карточка учётной записи: действующая матрица с источником по клетке", async () => {
  const v = view();
  v.own = undefined;
  v.effective.matrix.invite_new = { ...cells("button"), partner: "auto" };
  v.effective.source.invite_new = { own: null, partner: { org: ORG }, neighbor: null, external: null };
  v.effective.over_ceiling = [{ function: "mdn", peer: "external", value: { toggle: "on" }, ceiling: { toggle: "off" }, level: "installation" }];
  open("/accounts/a1", {
    [`GET ${BASE}/accounts/a1`]: { body: account },
    [`GET ${BASE}/accounts/a1/app-passwords`]: { body: [] },
    [`GET ${BASE}/accounts/a1/delegates`]: { body: [] },
    [`GET ${BASE}/accounts/a1/collections`]: { body: [] },
    [`GET ${BASE}/accounts/a1/trust`]: { body: v },
  });
  expect(await screen.findByText("Доверие")).toBeTruthy();
  expect(await screen.findByText("авто")).toBeTruthy();
  expect(screen.getByText("источник: организация")).toBeTruthy();
  expect(screen.getByText("выше потолка")).toBeTruthy();
});
