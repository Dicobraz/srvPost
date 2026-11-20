// Ключевые слова (WEB-03): категории pm.cat.*, сроки pm.due/pm.wait/pm.expire, угрозы pm.threat —
// конвенции Postman (S5-02/S5-04); маски фиксирует WEB-12, веб читает слова как есть.
import { expect, test } from "vitest";

import {
  CATEGORIES,
  categoryByNumber,
  categoryOf,
  categoriesOf,
  dueLabel,
  expireLabel,
  lifecycleOf,
  overdueDays,
  quickFilterFilters,
  waitLabel,
  QUICK_FILTERS,
} from "./keywords";

test("таблица категорий по умолчанию — как в макете: Клиенты, Команда, Тендеры (розовый), Сервисы", () => {
  expect(CATEGORIES.map((c) => c.id)).toEqual(["clients", "team", "tenders", "services"]);
  expect(CATEGORIES[2].keyword).toBe("pm.cat.tenders");
  // Клавиши 1–9: категория по номеру; за пределами таблицы — нет.
  expect(categoryByNumber(3)?.id).toBe("tenders");
  expect(categoryByNumber(9)).toBeNull();
  // Порядок быстрых фильтров по срочности (DESIGN.md).
  expect(QUICK_FILTERS.map((f) => f.kind)).toEqual(["threat", "due", "wait", "me", "expire"]);
});

test("категория письма — первая из найденных (полоса слева), список — все", () => {
  const keywords = { "pm.cat.team": true, "pm.cat.services": true };
  expect(categoriesOf(keywords).map((c) => c.id)).toEqual(["team", "services"]);
  expect(categoryOf(keywords)?.id).toBe("team");
  expect(categoryOf({})).toBeNull();
});

test("сроки: pm.due с датой и общее слово, просрочено — дни (S5-04)", () => {
  const lc = lifecycleOf({ "pm.due.2026-10-29t1500": true, "pm.due": true, "pm.threat": true });
  expect(lc.threat).toBe(true);
  expect(lc.due?.at).not.toBeNull();
  expect(lc.due?.general).toBe(true);
  expect(lc.wait).toBeNull();

  const now = new Date(2026, 10, 1, 12, 0); // 01.11.2026 — срок 29.10 просрочен на 3 дня
  expect(overdueDays(lc.due!.at!, now)).toBe(3);
  const label = dueLabel(lc, now);
  expect(label?.overdue).toBe(true);
  expect(label?.text).toContain("Просрочено 3 д");
});

test("ждём ответа и исчезнет: даты в слове, без даты — общие признаки", () => {
  const lc = lifecycleOf({ "pm.wait.2026-10-29": true, "pm.expire": true });
  expect(waitLabel(lc)).toContain("Ждём ответа");
  expect(expireLabel(lc, new Date())).toBe("Исчезнет");

  // Дата срока 04.11, «сейчас» 01.11 12:00 — позади больше трёх суток (конец дня) → «· 4 д».
  const dated = lifecycleOf({ "pm.wait.2026-11-04": true });
  expect(waitLabel(dated, new Date(2026, 10, 1, 12, 0))).toContain("Ждём ответа · 4 д");
});

test("метка срока вперёд — короткое имя дня недели («До ср»), как в макете", () => {
  // Среда 04.11.2026 — «До ср» 01.11 (воскресенье).
  const lc = lifecycleOf({ "pm.due.2026-11-04": true });
  const label = dueLabel(lc, new Date(2026, 10, 1, 12, 0));
  expect(label?.overdue).toBe(false);
  expect(label?.text).toMatch(/^До [а-я]+$/);
});

test("маски быстрых фильтров: слова целиком; «Мне» — адрес в «Кому»", () => {
  expect(quickFilterFilters("threat", null)).toEqual({ hasKeyword: "pm.threat" });
  expect(quickFilterFilters("due", null)).toEqual({ hasKeyword: "pm.due" });
  expect(quickFilterFilters("wait", null)).toEqual({ hasKeyword: "pm.wait" });
  expect(quickFilterFilters("expire", null)).toEqual({ hasKeyword: "pm.expire" });
  expect(quickFilterFilters("me", "user@example.org")).toEqual({ to: "user@example.org" });
  expect(quickFilterFilters("me", null)).toBeNull();
});
