/*
  Поиск контактов (WEB-07): варианты запроса (раскладка qwerty→йцукен — второй вариант, как в
  поиске писем WEB-05), фильтр ContactCard/query (один вариант — text, два — OR), локальная
  проверка карточки снимка.
*/
import { expect, test } from "vitest";

import { cardMatches, contactSearchFilter, queryVariants } from "./search";

test("варианты запроса: исходный + перевод qwerty→йцукен; кириллица и смешанный ввод — без варианта", () => {
  expect(queryVariants("rdfhnfk", true)).toEqual(["rdfhnfk", "квартал"]);
  expect(queryVariants("Квартал", true)).toEqual(["квартал"]); // уже кириллица
  expect(queryVariants("иван q", true)).toEqual(["иван q"]); // смешанный ввод — вариант не строится
  expect(queryVariants("  ", true)).toEqual([]);
});

test("фильтр ContactCard/query: один вариант — text, два — OR в одном запросе", () => {
  expect(contactSearchFilter("анна", true)).toEqual({ text: "анна" });
  expect(contactSearchFilter("rdfhnfk", true)).toEqual({
    operator: "OR",
    conditions: [{ text: "rdfhnfk" }, { text: "квартал" }],
  });
  // Выключенная транслитерация — только исходный запрос.
  expect(contactSearchFilter("rdfhnfk", false)).toEqual({ text: "rdfhnfk" });
  expect(contactSearchFilter("", true)).toBeNull();
});

test("локальная проверка карточки: имя, адрес, организация, телефон; вариант раскладки тоже", () => {
  const card = {
    name: { full: "Анна Смирнова" },
    emails: { e: { address: "anna@vektor.example" } },
    organizations: { o: { name: "АО Вектор" } },
    phones: { p: { number: "+7 495 111-22-33" } },
  };
  expect(cardMatches(card, "анна", true)).toBe(true);
  expect(cardMatches(card, "vektor", true)).toBe(true); // домен адреса
  expect(cardMatches(card, "вектор", true)).toBe(true); // организация
  expect(cardMatches(card, "111-22", true)).toBe(true); // телефон
  // EN-раскладка: «anna» набрано как «fyyf» — второй вариант находит кириллицу.
  expect(cardMatches(card, "anna", true)).toBe(true);
  expect(cardMatches(card, "fyyf", true)).toBe(true);
  expect(cardMatches(card, "петров", true)).toBe(false);
});
