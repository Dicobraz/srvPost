// Получатели (WEB-04): разбор ввода, чипы без дублей, автодополнение с источниками.
import { describe, expect, test } from "vitest";

import { chipLabel, initialsOf, isDuplicate, isValidEmail, parseRecipients, suggest } from "./recipients";

describe("parseRecipients", () => {
  test("адрес, «Имя <адрес>», несколько через запятую и точку с запятой", () => {
    expect(parseRecipients("o@vektor.example")).toEqual([{ name: null, email: "o@vektor.example" }]);
    expect(parseRecipients("Ольга Смирнова <o.smirnova@vektor.example>")).toEqual([
      { name: "Ольга Смирнова", email: "o.smirnova@vektor.example" },
    ]);
    expect(parseRecipients("a@b.example; c@d.example, e@f.example")).toHaveLength(3);
    expect(parseRecipients("  ")).toEqual([]);
  });
});

describe("чипы", () => {
  test("невалидный адрес не проходит", () => {
    expect(isValidEmail("без-собаки")).toBe(false);
    expect(isValidEmail("a b@example.org")).toBe(false);
    expect(isValidEmail("a@example.org")).toBe(true);
  });

  test("дубль не создаёт (без учёта регистра)", () => {
    const chips = [{ name: null, email: "A@Example.org" }];
    expect(isDuplicate(chips, "a@example.org")).toBe(true);
    expect(isDuplicate(chips, "b@example.org")).toBe(false);
  });

  test("метка чипа: имя, если есть, иначе адрес", () => {
    expect(chipLabel({ name: "Ольга Смирнова", email: "o@x" })).toBe("Ольга Смирнова");
    expect(chipLabel({ name: null, email: "o@x" })).toBe("o@x");
  });

  test("инициалы аватара", () => {
    expect(initialsOf({ name: "Ольга Смирнова", email: "o@x" })).toBe("ОС");
    expect(initialsOf({ name: null, email: "olga@x" })).toBe("OL");
  });
});

describe("автодополнение", () => {
  const CANDIDATES = [
    { recipient: { name: "Ольга Смирнова", email: "o.smirnova@vektor.example" }, source: "Контакты" },
    { recipient: { name: "Ольга Смирнова", email: "o.smirnova@thepost.example" }, source: "Контакты" },
    { recipient: { name: "Олег Лебедев", email: "o.lebedev@thepost.example" }, source: "История" },
  ];

  test("по подстроке имени и адреса, источник сохраняется", () => {
    const got = suggest(CANDIDATES, "ол", []);
    expect(got.map((s) => s.recipient.email)).toEqual([
      "o.smirnova@vektor.example",
      "o.smirnova@thepost.example",
      "o.lebedev@thepost.example",
    ]);
    expect(got[0].source).toBe("Контакты");
    expect(got[2].source).toBe("История");
  });

  test("по домену тоже ищет", () => {
    const got = suggest(CANDIDATES, "vektor", []);
    expect(got).toHaveLength(1);
  });

  test("выбранные не повторяются", () => {
    const got = suggest(CANDIDATES, "ол", [{ name: null, email: "o.smirnova@vektor.example" }]);
    expect(got.some((s) => s.recipient.email === "o.smirnova@vektor.example")).toBe(false);
  });

  test("пустой запрос — пустой список", () => {
    expect(suggest(CANDIDATES, "", [])).toEqual([]);
  });

  test("дубли кандидатов не повторяются", () => {
    const dup = [...CANDIDATES, CANDIDATES[0]];
    expect(suggest(dup, "vektor", [])).toHaveLength(1);
  });
});
