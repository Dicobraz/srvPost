/*
  Сохранённые фильтры (WEB-05, search.save_filter): текущий запрос + чипы области + уточнения
  сохраняются в localStorage и показываются рядом быстрых фильтров (как в Postman). Клик —
  применить сохранённый поиск, крестик — удалить. Только клиентское состояние: у JMAP нет
  капабилити «сохранённых поисков», поэтому это личные данные вкладки (как тема и плотность).
*/
import { EMPTY_SEARCH, type SearchState } from "./search";

const KEY = "thepost-webmail-saved-filters";

/** Сохранённый фильтр: имя и состояние поиска (без уточнений-однодневок — см. ниже). */
export interface SavedFilter {
  id: string;
  name: string;
  /** Сохраняемый поиск: текст, область, чипы; уточнения кликом тоже сохраняются. */
  query: Pick<SearchState, "text" | "scope" | "unread" | "attachment" | "recent30" | "refinements">;
}

/** Список сохранённых фильтров; повреждённый/чужой JSON — пустой список (личные данные). */
export function loadSavedFilters(): SavedFilter[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as unknown;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(
      (f): f is SavedFilter =>
        typeof f === "object" && f !== null &&
        typeof (f as SavedFilter).id === "string" &&
        typeof (f as SavedFilter).name === "string" &&
        typeof (f as SavedFilter).query === "object" && (f as SavedFilter).query !== null,
    );
  } catch {
    return [];
  }
}

function store(filters: SavedFilter[]): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(filters));
  } catch {
    // Приватный режим без localStorage: список живёт до перезагрузки страницы.
  }
}

/** search.save_filter: добавить текущий поиск под именем; возвращает новый список. */
export function saveFilter(name: string, query: SavedFilter["query"]): SavedFilter[] {
  const filters = loadSavedFilters();
  const next: SavedFilter = {
    id: `sf-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name: name.trim() || query.text.trim() || "Поиск",
    query,
  };
  store([...filters, next]);
  return [...filters, next];
}

/** Удаление сохранённого фильтра (крестик на чипе); возвращает новый список. */
export function removeSavedFilter(id: string): SavedFilter[] {
  const next = loadSavedFilters().filter((f) => f.id !== id);
  store(next);
  return next;
}

/** Применение сохранённого фильтра: состояние поиска из записи (уточнения — копия списка). */
export function applySavedFilter(saved: SavedFilter): SearchState {
  return {
    ...EMPTY_SEARCH,
    ...saved.query,
    refinements: [...(saved.query.refinements ?? [])],
  };
}
