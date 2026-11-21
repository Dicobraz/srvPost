// Поиск (WEB-05): парсер операторов, сборка фильтра Email/query (чипы области, уточнения,
// транслитерация OR), термы подсветки и экранирование сниппетов.
import { expect, test } from "vitest";

import {
  EMPTY_SEARCH,
  highlightTerms,
  isSearchActive,
  monthPeriod,
  parseQuery,
  recent30After,
  searchFilter,
  snippetHtml,
} from "./search";

test("parseQuery: операторы en/ru полями, кавычки собирают слова, остаток — свободный текст", () => {
  expect(parseQuery("квартальный отчёт")).toEqual({ freeText: "квартальный отчёт", fields: [] });
  expect(parseQuery("from:ivan@example.ru отчет")).toEqual({
    freeText: "отчет",
    fields: [{ field: "from", value: "ivan@example.ru" }],
  });
  expect(parseQuery("от:олга кому:petrov тема:\"квартальный отчёт\"")).toEqual({
    freeText: null,
    fields: [
      { field: "from", value: "олга" },
      { field: "to", value: "petrov" },
      { field: "subject", value: "квартальный отчёт" },
    ],
  });
  // Оператор без значения — не оператор.
  expect(parseQuery("тело:")).toEqual({ freeText: "тело:", fields: [] });
});

/** Аргументы сборки: по умолчанию — «Везде», без чипов, быстрых фильтров и уточнений. */
const ARGS = { ...EMPTY_SEARCH, scopeAll: true, mailboxId: null, flagged: false, quick: null, translit: false };

test("searchFilter: пустой запрос — null, одно условие — Cond, много — AND", () => {
  expect(searchFilter(ARGS)).toBeNull();
  const onlyText = searchFilter({ ...ARGS, text: "квартал" });
  expect(onlyText).toEqual({ text: "квартал" });
  const many = searchFilter({
    ...ARGS,
    text: "отчет",
    scopeAll: false,
    mailboxId: "mb1",
    unread: true,
    attachment: true,
    recent30: true,
  });
  expect(many).toEqual({
    operator: "AND",
    conditions: [
      { text: "отчет" },
      { inMailbox: "mb1" },
      { notKeyword: "$seen" },
      { hasAttachment: true },
      { after: recent30After() },
    ],
  });
});

test("searchFilter: быстрые фильтры и «Отмеченные» сочетаются с поиском (как в Postman)", () => {
  const f = searchFilter({ ...ARGS, text: "договор", quick: "due", flagged: true });
  expect(f).toEqual({
    operator: "AND",
    conditions: [
      { text: "договор" },
      { hasKeyword: "$flagged" },
      { hasKeyword: "pm.due" },
    ],
  });
});

test("searchFilter: «Везде» ищет без папки, «В папке» — только текущая", () => {
  const all = searchFilter({ ...ARGS, text: "договор", scopeAll: true, mailboxId: "mb1" });
  expect(JSON.stringify(all)).not.toContain("inMailbox");
  const folder = searchFilter({ ...ARGS, text: "договор", scopeAll: false, mailboxId: "mb1" });
  expect(folder).toEqual({ operator: "AND", conditions: [{ text: "договор" }, { inMailbox: "mb1" }] });
});

test("searchFilter: транслитерация раскладки — OR исходного и перевода (rdfhnfk → квартал)", () => {
  const f = searchFilter({ ...ARGS, text: "rdfhnfk", translit: true });
  expect(f).toEqual({ operator: "OR", conditions: [{ text: "rdfhnfk" }, { text: "квартал" }] });
  // Выключенная транслитерация — только исходный.
  expect(searchFilter({ ...ARGS, text: "rdfhnfk", translit: false })).toEqual({ text: "rdfhnfk" });
  // Кириллица — вариант не нужен.
  expect(searchFilter({ ...ARGS, text: "квартал", translit: true })).toEqual({ text: "квартал" });
  // Оператор тоже транслитерируется.
  const field = searchFilter({ ...ARGS, text: "from:Plhfdcndeq", translit: true });
  expect(field).toEqual({
    operator: "OR",
    conditions: [{ from: "Plhfdcndeq" }, { from: "Здравствуй" }],
  });
});

test("searchFilter: уточнения кликом — AND чипами (отправитель, папка, категория, период)", () => {
  const f = searchFilter({
    ...ARGS,
    refinements: [
      { kind: "from", value: "o@vektor.example", label: "От: Ольга" },
      { kind: "folder", value: "mb2", label: "Папка: Архив" },
      { kind: "category", value: "pm.cat.tenders", label: "Тендеры" },
      { kind: "period", value: "2026-11-01T00:00:00.000Z", before: "2026-12-01T00:00:00.000Z", label: "ноябрь 2026" },
    ],
  });
  expect(f).toEqual({
    operator: "AND",
    conditions: [
      { from: "o@vektor.example" },
      { inMailbox: "mb2" },
      { hasKeyword: "pm.cat.tenders" },
      { after: "2026-11-01T00:00:00.000Z", before: "2026-12-01T00:00:00.000Z" },
    ],
  });
});

test("highlightTerms: слова запроса и перевода раскладки, без односимвольных и дублей", () => {
  expect(highlightTerms("квартальный отчёт", false)).toEqual(["квартальный", "отчёт"]);
  expect(highlightTerms("rdfhnfk", true)).toEqual(["rdfhnfk", "квартал"]);
  // Сначала слова свободного текста, затем значения операторов; одиночные «и», «в» — мимо.
  expect(highlightTerms("от:олга про и в договор", false)).toEqual(["про", "договор", "олга"]);
  expect(highlightTerms("", false)).toEqual([]);
});

test("snippetHtml: экранирует всё, кроме пар <mark></mark> сервера", () => {
  expect(snippetHtml("a < b & <mark>отчёт</mark> 'q'")).toBe(
    "a &lt; b &amp; <mark>отчёт</mark> &#x27;q&#x27;",
  );
  // Подменённый тег остаётся экранированным.
  expect(snippetHtml("<mark><img src=x></mark>")).toBe("<mark>&lt;img src=x&gt;</mark>");
});

test("isSearchActive: текст или уточнения; чипы области сами поиск не включают", () => {
  expect(isSearchActive({ text: "", refinements: [] })).toBe(false);
  expect(isSearchActive({ text: "  ", refinements: [] })).toBe(false);
  expect(isSearchActive({ text: "квартал", refinements: [] })).toBe(true);
  expect(isSearchActive({ text: "", refinements: [{ kind: "from", value: "a@b.c", label: "От: a" }] })).toBe(true);
});

test("monthPeriod: границы месяца и подпись по-русски", () => {
  const p = monthPeriod("2026-11-21T10:00:00Z");
  expect(p.after).toBe(new Date(2026, 10, 1).toISOString());
  expect(p.before).toBe(new Date(2026, 11, 1).toISOString());
  expect(p.label).toBe("ноябрь 2026 г."); // ru-локаль добавляет «г.»
});
