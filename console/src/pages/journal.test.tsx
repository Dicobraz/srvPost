import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";

import type { Schemas } from "../api/client";
import { allowed } from "../providers/access";
import { ORG } from "../test-api";
import { BASE, buttons, open, sent } from "../test-app";

const ID1 = "00000000-0000-0000-0000-0000000000a1";
const ID2 = "00000000-0000-0000-0000-0000000000b2";

/** Запись журнала (ADM-52): конверт со скрытым получателем. */
const entry = (id: string): Schemas["JournalEntryView"] => ({
  id,
  record: {
    tenant: ORG,
    sender: "a@external.example",
    recipients: ["anna@example.org", "hidden@example.org"],
    message_id: "m1@external.example",
    at: "2026-11-01T10:00:00Z",
    rule: "org-all",
  },
  hash: "ab".repeat(32),
});

afterEach(() => {
  cleanup();
  sessionStorage.clear();
  localStorage.clear();
});

test("журнал переписки: поиск по отправителю, получателю, Message-ID и правилу, страницы по next", async () => {
  const calls = open(
    "/journal",
    {
      [`GET ${BASE}/journal`]: (c) =>
        c.path.includes("after=c2")
          ? { body: { entries: [entry(ID2)], next: null } }
          : c.path.includes("sender=a%40external.example")
            ? { body: { entries: [entry(ID1)], next: "c2" } }
            : { body: { entries: [entry(ID1), entry(ID2)], next: null } },
      [`GET ${BASE}/journal/verify`]: { body: { records: 2, ok: true, broken_at: null } },
    },
    ["journal_auditor"],
  );
  // Обе записи страницы — в таблице; целостность цепочки — индикатор в заголовке (число записей — в отчёте).
  expect(await screen.findAllByText("a@external.example")).toHaveLength(2);
  expect(await screen.findByText("цепочка цела")).toBeTruthy();

  fireEvent.change(screen.getByLabelText("Отправитель"), { target: { value: "a@external.example" } });
  fireEvent.change(screen.getByLabelText("Получатель"), { target: { value: "hidden@example.org" } });
  fireEvent.change(screen.getByLabelText("Message-ID"), { target: { value: "<m1@external.example>" } });
  fireEvent.change(screen.getByLabelText("Правило"), { target: { value: "org-all" } });
  fireEvent.click(screen.getByRole("button", { name: "Найти" }));
  const query = `${BASE}/journal?sender=a%40external.example&recipient=hidden%40example.org&message_id=m1%40external.example&rule=org-all`;
  await waitFor(() => expect(sent(calls, "GET", query)).toHaveLength(1));

  fireEvent.click((await buttons("Дальше"))[0]);
  await waitFor(() => expect(sent(calls, "GET", `${query}&after=c2`)).toHaveLength(1));
});

test("запись: конверт со скрытым получателем и хешем цепочки, выгрузка .eml — запросы к Admin API", async () => {
  const e = entry(ID1);
  const calls = open(
    "/journal",
    {
      [`GET ${BASE}/journal`]: { body: { entries: [e], next: null } },
      [`GET ${BASE}/journal/verify`]: { body: { records: 1, ok: true, broken_at: null } },
      [`GET ${BASE}/journal/${ID1}`]: { body: e },
      [`GET ${BASE}/journal/${ID1}/export`]: { body: "X-ThePost-Journal-Sender: a@external.example\r\n" },
    },
    ["journal_auditor"],
  );
  expect(await screen.findByText("a@external.example")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Открыть" }));
  // Просмотр конверта — отдельное обращение к журналу; хеш цепочки — только в конверте.
  expect(await screen.findByText(e.hash)).toBeTruthy();
  expect(sent(calls, "GET", `${BASE}/journal/${ID1}`)).toHaveLength(1);

  // Панель конверта в jsdom скрыта от accessibility-дерева (нет transition-событий antd) — кнопка с hidden.
  fireEvent.click(screen.getByRole("button", { name: /Выгрузить \.eml/, hidden: true }));
  const exported = await waitFor(() => sent(calls, "GET", `${BASE}/journal/${ID1}/export`));
  expect(exported).toHaveLength(1);
  expect(exported[0].auth).toBe("Bearer tps_test");
});

test("целостность: разрыв цепочки — индикатор и отчёт с числом записей и первой нарушенной", async () => {
  open(
    "/journal",
    {
      [`GET ${BASE}/journal`]: { body: { entries: [], next: null } },
      [`GET ${BASE}/journal/verify`]: { body: { records: 7, ok: false, broken_at: ID2 } },
    },
    ["journal_auditor"],
  );
  expect(await screen.findByText("разрыв цепочки")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Отчёт целостности" }));
  expect(await screen.findByText("Проверено записей")).toBeTruthy();
  expect(screen.getByText("7")).toBeTruthy();
  expect(await screen.findByText(ID2)).toBeTruthy();
});

test("аудитор журнала: консоль открывается на журнале переписки, других разделов не запрашивает", async () => {
  const calls = open(
    "/",
    {
      [`GET ${BASE}/journal`]: { body: { entries: [entry(ID1)], next: null } },
      [`GET ${BASE}/journal/verify`]: { body: { records: 1, ok: true, broken_at: null } },
    },
    ["journal_auditor"],
  );
  expect(await screen.findByText("a@external.example")).toBeTruthy();
  // Разделы администраторов (и список организаций) роли не запрашиваются: решает журнал и узел.
  expect(
    calls.map((c) => c.path).filter((p) => p !== "/api/v1/whoami" && p !== "/api/v1/public/branding" && !p.startsWith(`${BASE}/journal`)),
  ).toEqual([]);
});

test("прочие роли: журнала в меню нет, прямой адрес — «Нет доступа»", async () => {
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
  const calls = open(
    "/",
    { [`GET ${BASE}`]: { body: { id: ORG, default: true, policy: empty, effective: empty } } },
    ["organization_admin"],
  );
  await screen.findByText("Политика организации");
  fireEvent.click(screen.getByRole("button", { name: "bars" }));
  const items = (await screen.findAllByRole("menuitem")).map((m) => m.textContent);
  expect(items).toContain("Журнал аудита");
  expect(items).not.toContain("Журнал переписки");
  expect(calls.some((c) => c.path.startsWith(`${BASE}/journal`))).toBe(false);

  cleanup();
  open("/journal", { [`GET ${BASE}/journal`]: { body: { entries: [], next: null } } }, ["auditor"]);
  expect(await screen.findByText("Нет доступа")).toBeTruthy();
});

test("роли: журнал переписки — только аудитору журнала, ему недоступны прочие разделы", () => {
  expect(allowed(["journal_auditor"], "journal", "list")).toBe(true);
  for (const role of ["auditor", "operator", "organization_admin", "installation_admin"] as const) {
    expect(allowed([role], "journal", "list")).toBe(false);
  }
  expect(allowed(["journal_auditor"], "organization", "list")).toBe(false);
  expect(allowed(["journal_auditor"], "audit", "list")).toBe(false);
  expect(allowed(["journal_auditor"], "accounts", "list")).toBe(false);
});
