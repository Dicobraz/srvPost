// Сохранённые фильтры (WEB-05, search.save_filter): сохранение/применение/удаление в localStorage,
// повреждённое хранилище — пустой список.
import { beforeEach, expect, test } from "vitest";

import { applySavedFilter, loadSavedFilters, removeSavedFilter, saveFilter } from "./saved-filters";
import { EMPTY_SEARCH } from "./search";

beforeEach(() => {
  localStorage.clear();
});

test("saveFilter: сохраняет запрос с чипами и уточнениями, loadSavedFilters читает обратно", () => {
  const list = saveFilter("Отчёты за месяц", {
    text: "отчет",
    scope: "folder",
    unread: true,
    attachment: false,
    recent30: true,
    refinements: [{ kind: "category", value: "pm.cat.tenders", label: "Тендеры" }],
  });
  expect(list).toHaveLength(1);
  expect(list[0].name).toBe("Отчёты за месяц");
  const loaded = loadSavedFilters();
  expect(loaded).toEqual(list);
});

test("saveFilter: пустое имя — по тексту запроса; примен возвращает состояние поиска", () => {
  const [saved] = saveFilter("   ", { ...EMPTY_SEARCH, text: "квартал", scope: "all", unread: false, attachment: true, recent30: false });
  expect(saved.name).toBe("квартал");
  const state = applySavedFilter(saved);
  expect(state).toMatchObject({ text: "квартал", attachment: true, scope: "all" });
});

test("removeSavedFilter: удаляет по идентификатору", () => {
  // saveFilter возвращает весь список — добавленный в фильтр последним.
  const a = saveFilter("Один", { ...EMPTY_SEARCH, text: "раз" }).at(-1)!;
  const b = saveFilter("Два", { ...EMPTY_SEARCH, text: "два" }).at(-1)!;
  const next = removeSavedFilter(a.id);
  expect(next.map((f) => f.id)).toEqual([b.id]);
});

test("повреждённый JSON и не-массив — пустой список (не исключение)", () => {
  localStorage.setItem("thepost-webmail-saved-filters", "{oops");
  expect(loadSavedFilters()).toEqual([]);
  localStorage.setItem("thepost-webmail-saved-filters", JSON.stringify({ nope: 1 }));
  expect(loadSavedFilters()).toEqual([]);
});
