// Настройки чтения (WEB-03): плотность — «обычная с превью» по умолчанию (решение 20.11),
// вид потока — «группировка»; выбор в localStorage.
import { afterEach, expect, test } from "vitest";

import { loadDensity, loadThreadView, saveDensity, saveThreadView } from "./settings";

afterEach(() => {
  localStorage.clear();
});

test("по умолчанию — обычная плотность и группировка (решения владельца 20.11)", () => {
  expect(loadDensity()).toBe("normal");
  expect(loadThreadView()).toBe("grouped");
});

test("выбор сохраняется и читается; мусор в хранилище — снова умолчание", () => {
  saveDensity("compact");
  saveThreadView("outlook");
  expect(loadDensity()).toBe("compact");
  expect(loadThreadView()).toBe("outlook");

  localStorage.setItem("thepost-webmail-density", "космос");
  expect(loadDensity()).toBe("normal");
});
