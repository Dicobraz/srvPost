// Данные календаря (WEB-06): формы JMAP-запросов — CalendarEvent/query с развёрткой повторов
// (границы UTCDate, свойства с utcStart), CalendarEvent/set с sendSchedulingMessages, справочник
// Principal (типы location), занятость Principal/getAvailability со своей capability в `using`,
// метод веб-почты Invitation/respond (JMAP-50) — результат и структурированная ошибка, перенос
// письма из «Спама» Email/set. Транспорт — мок fetch: проверяем тело запроса и разбор ответа.
import { afterEach, expect, test, vi } from "vitest";

import {
  calendarEventSet,
  calendarEventsInRange,
  invitationRespond,
  principalAvailability,
  principalsByType,
  type JmapSession,
} from "../api/jmap";
import { moveToInbox } from "../mail/invite-respond";
import type { JmapEnv } from "../mail/types";

interface Call {
  url: string;
  authorization: string | null;
  body: { using: string[]; methodCalls: Array<[string, Record<string, unknown>, string]> };
}

const ENV: JmapEnv = {
  apiUrl: "https://node.example/.well-known/jmap/api",
  authorization: "Bearer acc-1",
  accountId: "acc-1",
  selfAddress: "ivan@example.org",
  // Сессия не читается функциями этого уровня — заглушка типов.
  session: {
    apiUrl: "https://node.example/.well-known/jmap/api",
    accounts: {},
    capabilities: {},
  } as unknown as JmapSession,
};

/** Мок JMAP API: очередь ответов «{ИмяМетода: аргументы}» и записи запросов для проверок. */
function mockJmap(responses: Array<Record<string, Record<string, unknown>>>): Call[] {
  const calls: Call[] = [];
  let next = 0;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const call: Call = {
        url: String(input),
        authorization: new Headers(init?.headers).get("Authorization"),
        body: JSON.parse(String(init?.body)),
      };
      calls.push(call);
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
  vi.unstubAllGlobals();
});

test("CalendarEvent/query с развёрткой повторов: границы UTCDate, капабилити календарей", async () => {
  const calls = mockJmap([
    { "CalendarEvent/query": { queryState: "q1", ids: [], limit: 1000 } },
  ]);
  const events = await calendarEventsInRange(
    ENV.apiUrl,
    ENV.authorization,
    ENV.accountId,
    "2026-11-23T00:00:00.000Z",
    "2026-11-30T00:00:00.000Z",
  );
  expect(events).toEqual([]);
  const [query] = calls;
  expect(query.url).toBe(ENV.apiUrl);
  expect(query.authorization).toBe("Bearer acc-1");
  // Капабилити календарей в `using` — методы Calendar* под ней.
  expect(query.body.using).toContain("urn:ietf:params:jmap:calendars");
  const [name, args] = query.body.methodCalls[0];
  expect(name).toBe("CalendarEvent/query");
  expect(args).toMatchObject({
    accountId: "acc-1",
    filter: { after: "2026-11-23T00:00:00.000Z", before: "2026-11-30T00:00:00.000Z" },
    expandRecurrences: true,
    sort: [{ property: "start" }],
    calculateTotal: false,
  });
});

test("CalendarEvent/get после запроса: идентификаторы и свойства с utcStart/utcEnd", async () => {
  const calls = mockJmap([
    { "CalendarEvent/query": { queryState: "q1", ids: ["e1", "e2", "e3"], limit: 1000 } },
    {
      "CalendarEvent/get": {
        state: "st1",
        list: [
          { id: "e1", uid: "u1", utcStart: "2026-11-23T10:00:00Z", utcEnd: "2026-11-23T11:00:00Z", calendarIds: { c1: true } },
          { id: "e2", uid: "u2", utcStart: "2026-11-24T10:00:00Z", utcEnd: "2026-11-24T11:00:00Z", calendarIds: { c1: true } },
          { id: "e3", uid: "u3", utcStart: "2026-11-25T10:00:00Z", utcEnd: "2026-11-25T11:00:00Z", calendarIds: { c2: true } },
        ],
        notFound: [],
      },
    },
  ]);
  const events = await calendarEventsInRange(
    ENV.apiUrl,
    ENV.authorization,
    ENV.accountId,
    "2026-11-23T00:00:00.000Z",
    "2026-11-30T00:00:00.000Z",
  );
  expect(events).toHaveLength(3);
  expect(events[0].utcStart).toBe("2026-11-23T10:00:00Z");
  const [, get] = calls;
  expect(get.body.methodCalls[0][0]).toBe("CalendarEvent/get");
  expect(get.body.methodCalls[0][1].ids).toEqual(["e1", "e2", "e3"]);
  const properties = get.body.methodCalls[0][1].properties as string[];
  expect(properties).toContain("utcStart");
  expect(properties).toContain("utcEnd");
  expect(properties).toContain("participants");
  expect(properties).toContain("isOrigin");
});

test("CalendarEvent/set: создание встречи с рассылкой приглашений (sendSchedulingMessages)", async () => {
  const calls = mockJmap([{ "CalendarEvent/set": { created: { m: { id: "ev-1" } } } }]);
  const result = await calendarEventSet(
    ENV.apiUrl,
    ENV.authorization,
    ENV.accountId,
    {
      create: {
        m: {
          title: "Планёрка",
          start: "2026-11-24T10:00:00",
          timeZone: "Europe/Moscow",
          duration: "PT1H",
          participants: {
            o: { "@type": "Participant", name: "Иван", calendarAddress: "mailto:ivan@example.org", roles: { owner: true } },
          },
        },
      },
    },
    true,
  );
  expect(result.created["m"]?.id).toBe("ev-1");
  const [name, args] = calls[0].body.methodCalls[0];
  expect(name).toBe("CalendarEvent/set");
  expect(args.sendSchedulingMessages).toBe(true);
  expect(calls[0].body.using).toContain("urn:ietf:params:jmap:calendars");
});

test("Справочник формы: Principal/query по типу (комнаты) + Principal/get", async () => {
  const calls = mockJmap([
    { "Principal/query": { queryState: "0", ids: ["r1"], canCalculateChanges: false } },
    {
      "Principal/get": {
        state: "0",
        list: [{ id: "r1", type: "location", name: "Переговорная 3", email: "room-3@example.org" }],
        notFound: [],
      },
    },
  ]);
  const rooms = await principalsByType(ENV.apiUrl, ENV.authorization, ENV.accountId, "location");
  expect(rooms).toHaveLength(1);
  expect(rooms[0].name).toBe("Переговорная 3");
  const [query, get] = calls;
  expect(query.body.methodCalls[0][0]).toBe("Principal/query");
  expect(query.body.methodCalls[0][1]).toMatchObject({ filter: { type: "location" } });
  expect(get.body.methodCalls[0][0]).toBe("Principal/get");
  expect(get.body.methodCalls[0][1]).toMatchObject({ ids: ["r1"] });
  // Capability участников организации — без занятости (узел без хранилища отклонил бы запрос).
  expect(query.body.using).toEqual(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:principals"]);
});

test("Занятость (principals:availability): capability в `using`, разбор периодов", async () => {
  const calls = mockJmap([
    {
      "Principal/getAvailability": {
        list: [
          { utcStart: "2026-11-23T09:00:00Z", utcEnd: "2026-11-23T10:00:00Z", busyStatus: "confirmed", event: null },
        ],
      },
    },
  ]);
  const busy = await principalAvailability(
    ENV.apiUrl,
    ENV.authorization,
    ENV.accountId,
    "acc-1",
    "2026-11-23T00:00:00Z",
    "2026-11-24T00:00:00Z",
  );
  expect(busy).toHaveLength(1);
  expect(busy[0].busyStatus).toBe("confirmed");
  const [name, args] = calls[0].body.methodCalls[0];
  expect(name).toBe("Principal/getAvailability");
  expect(args).toMatchObject({ accountId: "acc-1", id: "acc-1", utcStart: "2026-11-23T00:00:00Z" });
  expect(calls[0].body.using).toContain("urn:ietf:params:jmap:principals:availability");
});

test("Метод веб-почты (JMAP-50): ответ применяется; ошибка метода отдаётся как есть", async () => {
  const calls = mockJmap([
    {
      "Invitation/respond": {
        accountId: "acc-1",
        participationStatus: "accepted",
        applied: true,
        reason: null,
        calendarEventId: "ev-9",
      },
    },
    {
      error: {
        "@type": "error",
        type: "invitationInJunk",
        description: "Приглашение лежит в папке «Спам». Сначала перенесите письмо в другую папку, затем примите или отклоните встречу.",
      },
    },
  ]);
  const ok = await invitationRespond(ENV.apiUrl, ENV.authorization, ENV.accountId, "m1", "accepted");
  expect(ok).toMatchObject({ applied: true, calendarEventId: "ev-9" });
  expect(calls[0].body.methodCalls[0][0]).toBe("Invitation/respond");
  expect(calls[0].body.methodCalls[0][1]).toMatchObject({
    accountId: "acc-1",
    emailId: "m1",
    participationStatus: "accepted",
  });
  // Капабилити метода веб-почты The Post в `using`.
  expect(calls[0].body.using).toContain("urn:thepost:params:jmap:itip");

  const refused = await invitationRespond(ENV.apiUrl, ENV.authorization, ENV.accountId, "m1", "declined");
  expect(refused).toMatchObject({ "@type": "error", type: "invitationInJunk" });
  expect(calls[1].body.methodCalls[0][1]).toMatchObject({ participationStatus: "declined" });
});

test("Перенос письма из «Спама» во «Входящие» — Email/set заменой mailboxIds", async () => {
  const calls = mockJmap([
    { "Email/set": { updated: { m1: null } } },
    { "Email/set": { notUpdated: { m1: { type: "notFound" } } } },
  ]);
  const moved = await moveToInbox(ENV, "m1", "inbox-1");
  expect(moved).toBe(true);
  const [name, args] = calls[0].body.methodCalls[0];
  expect(name).toBe("Email/set");
  expect(args.update).toEqual({ m1: { mailboxIds: { "inbox-1": true } } });
  expect(calls[0].body.using).toEqual(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:mail"]);

  expect(await moveToInbox(ENV, "m1", "inbox-1")).toBe(false);
});
