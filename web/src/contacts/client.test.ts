/*
  Клиент контактов (WEB-07): формы запросов — AddressBook/get (книги с myRights, GAL read-only),
  ContactCard/query+get (снимок: окно, свойства, капабилити contacts в `using`), ContactCard/set
  (создание, правка, удаление, группы members) и разбор ответа (created/updated/destroyed,
  ошибки с текстом для человека). Транспорт — мок fetch: проверяем тело запроса и разбор ответа.
*/
import { afterEach, expect, test, vi } from "vitest";

import {
  addressBooksGet,
  contactCardGet,
  contactCardSearch,
  contactCardSet,
  contactCardSnapshot,
  setErrorText,
} from "./client";
import { cardFromForm } from "./model";
import type { JmapSession } from "../api/jmap";
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

test("AddressBook/get: книги с правами — GAL «Организация» только для чтения", async () => {
  const calls = mockJmap([
    {
      "AddressBook/get": {
        state: "5.2",
        list: [
          {
            id: "b1",
            name: "Личные",
            description: null,
            sortOrder: 0,
            isDefault: true,
            isSubscribed: true,
            myRights: { mayRead: true, mayWrite: true, mayShare: false, mayDelete: true },
          },
          {
            id: "gal",
            name: "Организация",
            description: "Справочник организации",
            sortOrder: 1,
            isDefault: false,
            isSubscribed: true,
            myRights: { mayRead: true, mayWrite: false, mayShare: false, mayDelete: false },
          },
        ],
        notFound: [],
      },
    },
  ]);
  const books = await addressBooksGet(ENV.apiUrl, ENV.authorization, ENV.accountId);
  expect(books).toHaveLength(2);
  const [name, args] = calls[0].body.methodCalls[0];
  expect(name).toBe("AddressBook/get");
  expect(args.accountId).toBe("acc-1");
  // Капабилити адресных книг (RFC 9610) — без неё сервер отклонил бы метод.
  expect(calls[0].body.using).toEqual(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"]);
  const gal = books.find((b) => b.name === "Организация");
  expect(gal?.myRights.mayWrite).toBe(false); // read-only: правка и удаление недоступны
});

test("ContactCard/query+get: снимок — сортировка по имени, свойства списка, get кусками", async () => {
  const calls = mockJmap([
    { "ContactCard/query": { queryState: "q1", ids: ["c1", "c2", "c3"], total: 3 } },
    {
      "ContactCard/get": {
        state: "5.2",
        list: [
          { id: "c1", uid: "u1", kind: "individual", name: { full: "Анна" }, emails: { e: { address: "a@x.example" } }, addressBookIds: { b1: true } },
          { id: "c2", uid: "u2", kind: "individual", name: { full: "Борис" }, emails: { e: { address: "b@x.example" } }, addressBookIds: { b1: true } },
          { id: "c3", uid: "u3", kind: "group", name: { full: "Команда" }, members: { u1: true }, addressBookIds: { b1: true } },
        ],
        notFound: [],
      },
    },
  ]);
  const cards = await contactCardSnapshot(ENV.apiUrl, ENV.authorization, ENV.accountId);
  expect(cards).toHaveLength(3);
  const [query, get] = calls;
  expect(query.body.methodCalls[0][0]).toBe("ContactCard/query");
  expect(query.body.methodCalls[0][1]).toMatchObject({
    accountId: "acc-1",
    sort: [{ property: "name/given" }],
    limit: 500,
  });
  expect(get.body.methodCalls[0][0]).toBe("ContactCard/get");
  expect(get.body.methodCalls[0][1].ids).toEqual(["c1", "c2", "c3"]);
  const properties = get.body.methodCalls[0][1].properties as string[];
  expect(properties).toContain("uid");
  expect(properties).toContain("addressBookIds");
  expect(properties).not.toContain("notes"); // снимок — без тяжёлых полей
  expect(calls[0].body.using).toContain("urn:ietf:params:jmap:contacts");
});

test("ContactCard/get по идентификаторам: не найденные не попадают в список", async () => {
  mockJmap([
    {
      "ContactCard/get": {
        state: "5.2",
        list: [{ id: "c1", uid: "u1", name: { full: "Анна" } }],
        notFound: ["zz"],
      },
    },
  ]);
  const cards = await contactCardGet(ENV.apiUrl, ENV.authorization, ENV.accountId, ["c1", "zz"]);
  expect(cards).toHaveLength(1);
  expect(cards[0].id).toBe("c1");
});

test("ContactCard/set round-trip: создание из формы, правка патчем, группа, ошибки — с текстом", async () => {
  const form = { name: "Анна Смирнова", emails: ["anna@vektor.example"], phones: [], organization: "АО Вектор", photoUrl: "", notes: "" };
  const card = cardFromForm(form, { b1: true });
  const calls = mockJmap([
    { "ContactCard/set": { created: { c: { id: "c9", uid: "urn:uuid:9" } } } },
    { "ContactCard/set": { updated: { c9: null } } },
    { "ContactCard/set": { updated: { g1: null } } },
    { "ContactCard/set": { destroyed: ["c9"] } },
    // Read-only книга (GAL): сервер ответил forbidden — клиент даёт человекочитаемый текст.
    { "ContactCard/set": { notCreated: { c: { type: "forbidden", description: "the address book is read-only" } } } },
  ]);
  const created = await contactCardSet(ENV.apiUrl, ENV.authorization, ENV.accountId, {
    create: { c: card },
  });
  expect(created.created.c?.id).toBe("c9");
  const [createCall] = calls;
  const createArgs = createCall.body.methodCalls[0][1];
  expect(createArgs.create).toEqual({ c: card });
  expect(createCall.body.using).toEqual(["urn:ietf:params:jmap:core", "urn:ietf:params:jmap:contacts"]);

  const updated = await contactCardSet(ENV.apiUrl, ENV.authorization, ENV.accountId, {
    update: { c9: { "name/full": "Анна Смирнова-Крылова", notes: null } },
  });
  expect(updated.updated.c9).toBeNull();
  expect(calls[1].body.methodCalls[0][1].update).toEqual({
    c9: { "name/full": "Анна Смирнова-Крылова", notes: null },
  });

  // Участник группы — патч JSON-указателем members/<uid>; убрать — null.
  const group = await contactCardSet(ENV.apiUrl, ENV.authorization, ENV.accountId, {
    update: { g1: { "members/urn:uuid:9": true } },
  });
  expect(group.updated.g1).toBeNull();
  expect(calls[2].body.methodCalls[0][1].update).toEqual({ g1: { "members/urn:uuid:9": true } });

  const destroyed = await contactCardSet(ENV.apiUrl, ENV.authorization, ENV.accountId, {
    destroy: ["c9"],
  });
  expect(destroyed.destroyed).toEqual(["c9"]);

  const refused = await contactCardSet(ENV.apiUrl, ENV.authorization, ENV.accountId, {
    create: { c: cardFromForm(form, { gal: true }) },
  });
  expect(setErrorText(refused.errors.c, "ошибка")).toContain("только для чтения");
});

test("ContactCard/query с фильтром поиска: OR вариантов раскладки в одном запросе", async () => {
  const calls = mockJmap([
    { "ContactCard/query": { queryState: "q2", ids: ["c1"], total: 1 } },
    { "ContactCard/get": { state: "5.2", list: [{ id: "c1", uid: "u1" }], notFound: [] } },
  ]);
  const found = await contactCardSearch(ENV.apiUrl, ENV.authorization, ENV.accountId, {
    operator: "OR",
    conditions: [{ text: "rdfhnfk" }, { text: "квартал" }],
  });
  expect(found).toHaveLength(1);
  expect(calls[0].body.methodCalls[0][1].filter).toEqual({
    operator: "OR",
    conditions: [{ text: "rdfhnfk" }, { text: "квартал" }],
  });
});

test("setErrorText: описание сервера, forbidden и книга с содержимым — человекочитаемые", () => {
  expect(setErrorText({ type: "forbidden" }, "падение")).toContain("только для чтения");
  expect(setErrorText({ type: "addressBookHasContents" }, "падение")).toContain("не пуста");
  expect(setErrorText({ type: "overQuota", description: "quota exceeded" }, "падение")).toBe(
    "quota exceeded",
  );
  expect(setErrorText(undefined, "падение")).toBe("падение");
});
