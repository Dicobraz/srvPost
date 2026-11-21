// Карточка приглашения (WEB-06, спам-сценарий JMAP-50): кнопки ответа вызывают метод веб-почты
// Invitation/respond; приглашение в «Спаме» — структурированная ошибка invitationInJunk →
// inline-полоса «Перенести из „Спама"» → Email/set во «Входящие» → повтор ответа → чип статуса.
// Провайдеры подменены (useJmap/useToast/useMailboxes) — карточка в изоляции, транспорт — мок fetch.
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";

import type { Mailbox } from "../api/jmap";
import { InvitationCard } from "./reading-pane";
import { parseInvitation } from "./invite";

vi.mock("./context", () => ({
  useJmap: () => ENV,
}));
vi.mock("./toast", () => ({
  useToast: () => ({ show: toastMock }),
}));
vi.mock("./queries", () => ({
  useMailboxes: () => mailboxes,
}));

const ENV = {
  apiUrl: "https://node.example/jmap/api",
  authorization: "Bearer acc-1",
  accountId: "acc-1",
  selfAddress: "ivan@example.org",
  session: {
    apiUrl: "https://node.example/jmap/api",
    accounts: { "acc-1": { accountCapabilities: {} } },
    capabilities: { "urn:thepost:params:jmap:itip": {} },
  },
};
const toastMock = vi.fn();

const mailboxes: Mailbox[] = [
  { id: "inbox-1", role: "inbox", name: "Входящие" } as unknown as Mailbox,
];

/** Мок JMAP API: очередь ответов по имени метода + записи запросов. */
function mockJmap(responses: Array<Record<string, Record<string, unknown>>>): Array<{ body: Record<string, unknown> }> {
  const calls: Array<{ body: Record<string, unknown> }> = [];
  let next = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ body: JSON.parse(String(init?.body)) });
      const response = responses[next++] ?? {};
      const [[name, args]] = Object.entries(response);
      return new Response(
        JSON.stringify({ sessionState: "s1", methodResponses: [[name, args, "c0"]] }),
        { status: 200 },
      );
    }),
  );
  return calls;
}

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  toastMock.mockClear();
});

const ICS = [
  "BEGIN:VCALENDAR",
  "VERSION:2.0",
  "PRODID:-//test//RU",
  "METHOD:REQUEST",
  "BEGIN:VEVENT",
  "UID:u1",
  "DTSTAMP:20261112T100000Z",
  "DTSTART:20261124T140000Z",
  "DTEND:20261124T150000Z",
  "SUMMARY:Планёрка",
  "ORGANIZER:mailto:olga@example.org",
  "ATTENDEE:mailto:ivan@example.org",
  "END:VEVENT",
  "END:VCALENDAR",
].join("\r\n");

function renderCard() {
  const invitation = parseInvitation(ICS);
  if (!invitation) throw new Error("приглашение не разобрано");
  return render(<InvitationCard invitation={invitation} emailId="m1" />);
}

test("ответ «Отклонить» — метод веб-почты, чип статуса и тост", async () => {
  const calls = mockJmap([
    {
      "Invitation/respond": {
        accountId: "acc-1",
        participationStatus: "declined",
        applied: true,
        reason: null,
        calendarEventId: "ev-9",
      },
    },
  ]);
  renderCard();
  fireEvent.click(screen.getByRole("button", { name: /Отклонить/ }));
  await waitFor(() => {
    expect(calls).toHaveLength(1);
  });
  expect(calls[0].body).toMatchObject({
    using: expect.arrayContaining(["urn:thepost:params:jmap:itip"]),
    methodCalls: [["Invitation/respond", { accountId: "acc-1", emailId: "m1", participationStatus: "declined" }, "c0"]],
  });
  await waitFor(() => {
    expect(screen.getByText("Отклонено")).toBeTruthy();
  });
  expect(toastMock).toHaveBeenCalledWith(expect.stringContaining("Ответ отправлен"));
  // Кнопки после ответа погашены.
  expect((screen.getByRole("button", { name: /Принять/ }) as HTMLButtonElement).disabled).toBe(true);
});

test("спам-сценарий: invitationInJunk → перенос письма (Email/set) → повтор ответа", async () => {
  const calls = mockJmap([
    {
      error: {
        "@type": "error",
        type: "invitationInJunk",
        description:
          "Приглашение лежит в папке «Спам». Сначала перенесите письмо в другую папку, затем примите или отклоните встречу.",
      },
    },
    { "Email/set": { updated: { m1: null } } },
    {
      "Invitation/respond": {
        accountId: "acc-1",
        participationStatus: "accepted",
        applied: true,
        reason: null,
        calendarEventId: "ev-9",
      },
    },
  ]);
  renderCard();
  fireEvent.click(screen.getByRole("button", { name: /Принять/ }));

  // Структурированная ошибка — inline-полоса с переносом, статус не ставится.
  await waitFor(() => {
    expect(screen.getByText(/Приглашение лежит в «Спаме»/)).toBeTruthy();
  });
  expect(calls[0].body.methodCalls).toEqual([
    ["Invitation/respond", { accountId: "acc-1", emailId: "m1", participationStatus: "accepted" }, "c0"],
  ]);
  expect(screen.queryByText("Принято")).toBeNull();

  // Перенос: Email/set заменяет mailboxIds папкой «Входящие» (роль inbox).
  fireEvent.click(screen.getByRole("button", { name: /Перенести из «Спама»/ }));
  await waitFor(() => {
    expect(calls).toHaveLength(3);
  });
  expect(calls[1].body.methodCalls).toEqual([
    ["Email/set", { accountId: "acc-1", update: { m1: { mailboxIds: { "inbox-1": true } } } }, "c0"],
  ]);
  // Повтор ответа тем же статусом — метод применён, чип статуса поставлен.
  expect(calls[2].body.methodCalls).toEqual([
    ["Invitation/respond", { accountId: "acc-1", emailId: "m1", participationStatus: "accepted" }, "c0"],
  ]);
  await waitFor(() => {
    expect(screen.getByText("Принято")).toBeTruthy();
  });
  expect(toastMock).toHaveBeenCalledWith(expect.stringContaining("перенесено"));
});

test("узел без метода веб-почты (нет капабилити itip) — кнопки погашены с подсказкой", () => {
  const withoutItip = { ...ENV, session: { ...ENV.session, capabilities: {} } };
  const original = { ...ENV };
  Object.assign(ENV, withoutItip);
  try {
    renderCard();
    for (const label of [/Принять/, /Под вопросом/, /Отклонить/]) {
      const button = screen.getByRole("button", { name: label }) as HTMLButtonElement;
      expect(button.disabled).toBe(true);
      expect(button.title).toContain("недоступны");
    }
  } finally {
    Object.assign(ENV, original);
  }
});
