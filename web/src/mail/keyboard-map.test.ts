// Транслитерация раскладки (WEB-05): посимвольная карта qwerty→йцукен — практику Postman
// («rdfhnfk» → «квартал»); смешанный/кириллический ввод вариант не даёт.
import { expect, test } from "vitest";

import { layoutVariant, textVariants } from "./keyboard-map";

test("практику Postman: rdfhnfk → квартал (qwerty→йцукен посимвольно)", () => {
  expect(layoutVariant("rdfhnfk")).toBe("квартал");
});

test("нижний и верхний регистр, знаки цифрового ряда проходят как были", () => {
  expect(layoutVariant("Plhfdcndeq")).toBe("Здравствуй");
  expect(layoutVariant("ghbdtn12!")).toBe("привет12!");
  // Ё на той же клавише с `.
  expect(layoutVariant("`nfr")).toBe("ётак");
});

test("кириллица или смешанный ввод — варианта нет", () => {
  expect(layoutVariant("квартал")).toBeNull();
  expect(layoutVariant("квартал rdfhnfk")).toBeNull();
  expect(layoutVariant("квартал123")).toBeNull();
  // Буквы вне карты (немецкая ü, ß) — не переводим частично.
  expect(layoutVariant("fü")).toBeNull();
  expect(layoutVariant("straße")).toBeNull();
});

test("без букв — варианта нет (цифры и знаки остаются как были)", () => {
  expect(layoutVariant("123 !?")).toBeNull();
  expect(layoutVariant("")).toBeNull();
});

test("textVariants: включённая транслитерация даёт [исходный, перевод], выключенная — только исходный", () => {
  expect(textVariants("rdfhnfk", true)).toEqual(["rdfhnfk", "квартал"]);
  expect(textVariants("rdfhnfk", false)).toEqual(["rdfhnfk"]);
  expect(textVariants("квартал", true)).toEqual(["квартал"]);
  expect(textVariants("  ", true)).toEqual([]);
});
