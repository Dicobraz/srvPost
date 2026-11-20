// Вложения (WEB-04): лимит узла maxSizeUpload — честная ошибка до запроса (приёмка: гигабайт
// не выедает память вкладки — File API стримит браузер, превышение отсекается сразу);
// формат размера — как в чипах макета; распознавание почты и имени в JSContact.
import { beforeEach, expect, test } from "vitest";
import type { JmapSession } from "../api/jmap";

import { fileError, formatSize, maxSizeUpload } from "./attachments";
import { domainsOf, hasContacts, loadContacts } from "./contacts";

beforeEach(() => {
  localStorage.clear();
});

const SESSION = (maxSize: unknown): JmapSession =>
  ({
    capabilities: { "urn:ietf:params:jmap:core": { maxSizeUpload: maxSize } },
    accounts: {},
  }) as unknown as JmapSession;

test("maxSizeUpload из сессии; нет свойства — null (не проверяем заранее)", () => {
  expect(maxSizeUpload(SESSION(25_000_000))).toBe(25_000_000);
  expect(maxSizeUpload(SESSION(undefined))).toBeNull();
});

test("файл больше лимита — честная ошибка с числом, не больше лимита — null", () => {
  const big = new File([new Uint8Array(30)], "большой.pdf");
  const small = new File([new Uint8Array(10)], "небольшой.pdf");
  const err = fileError(big, 20);
  expect(err).toContain("большой.pdf");
  expect(err).toContain("20 Б");
  expect(fileError(small, 20)).toBeNull();
  expect(fileError(big, null)).toBeNull();
});

test("формат размера — как в чипах макета", () => {
  expect(formatSize(1024)).toBe("1 КБ");
  expect(formatSize(22 * 1024)).toBe("22 КБ");
  expect(formatSize(1_572_864)).toBe("1,5 МБ");
  expect(formatSize(500)).toBe("500 Б");
});

const CONTACT_SESSION: JmapSession =
  ({
    accounts: { acc1: { accountCapabilities: { "urn:ietf:params:jmap:contacts": {} } } },
  }) as unknown as JmapSession;
const ENV = {
  session: CONTACT_SESSION,
  apiUrl: "https://node.example/jmap/api",
  accountId: "acc1",
  authorization: "Bearer t",
  selfAddress: "user@example.org",
};

test("hasContacts: капабилити contacts у учётной записи", () => {
  expect(hasContacts(CONTACT_SESSION, "acc1")).toBe(true);
  expect(hasContacts({ accounts: {} } as unknown as JmapSession, "acc1")).toBe(false);
});

test("loadContacts: JSContact → имя и первая почта (pref приоритетнее); нет капабилити — пусто без запроса", async () => {
  const cards = [
    {
      name: { full: "Мария Сидорова" },
      emails: {
        home: { address: "maria@home.example", pref: 1 },
        work: { address: "maria@vektor.example", pref: 3 },
      },
    },
    { name: { components: [{ value: "Олег" }, { value: "Лебедев" }] }, emails: { w: { address: "o.lebedev@thepost.example" } } },
    { name: { full: "Без почты" }, emails: {} },
  ];
  const calls: unknown[] = [];
  const fetchMock = vi_fetch(cards, calls);
  globalThis.fetch = fetchMock as typeof fetch;
  const got = await loadContacts(ENV);
  expect(got).toEqual([
    { recipient: { name: "Мария Сидорова", email: "maria@vektor.example" }, source: "Контакты" },
    { recipient: { name: "Олег Лебедев", email: "o.lebedev@thepost.example" }, source: "Контакты" },
  ]);
  expect(calls).toHaveLength(2); // ContactCard/query + ContactCard/get

  const noContacts = { ...ENV, session: { accounts: {} } as unknown as JmapSession };
  await expect(loadContacts(noContacts)).resolves.toEqual([]);
});

test("домены контактов — внешними не считаются", () => {
  const domains = domainsOf([
    { recipient: { name: null, email: "a@Partner.example" }, source: "Контакты" },
    { recipient: { name: null, email: "b@thepost.example" }, source: "Контакты" },
  ]);
  expect([...domains].sort()).toEqual(["partner.example", "thepost.example"]);
});

/** fetch подменяется: JMAP-ответы на два вызова ContactCard; прочие — ошибка теста. */
function vi_fetch(cards: Array<Record<string, unknown>>, calls: unknown[]): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push(input);
    const body = JSON.parse(String(init?.body)) as { methodCalls: Array<[string, unknown]> };
    const [method] = body.methodCalls[0];
    const result =
      method === "ContactCard/query"
        ? { ids: cards.map((_, i) => `c${i + 1}`), notFound: [] }
        : { list: cards, notFound: [] };
    return new Response(JSON.stringify({ methodResponses: [[method, result, "c0"]] }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }) as unknown as typeof fetch;
}
