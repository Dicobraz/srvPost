/*
  Ключевые слова писем (WEB-03): категории `pm.cat.<id>`, сроки жизненного цикла `pm.due/pm.wait/
  pm.expire`, угрозы `pm.threat` — конвенции Postman (`postman/docs/specs/S5.md`, S5-02/S5-03/S5-04;
  `docs/design/webmail/PARITY.md`: маски сроков/категорий фиксирует WEB-12). Стандартных JMAP-ключей
  для категорий и сроков нет: сервер ставит их как обычные keywords, клиент только читает. Цвета
  категорий — таблица DESIGN.md, палитра макетов `docs/design/webmail/` (светлая/тёмная — 01/03).
*/

import type { EmailQueryFilter, Keywords } from "../api/jmap";

/** Категория письма: ключевое слово, имя, цвета чипа и полосы (из макета — один оттенок). */
export interface Category {
  id: string;
  /** Ключевое слово письма: `pm.cat.<id>`. */
  keyword: string;
  name: string;
  /** CSS-переменные палитры макета: полоса/точка и подложка/текст чипа. */
  barVar: string;
  chipBgVar: string;
  chipTxVar: string;
}

/**
 * Таблица категорий по умолчанию — как в макете (`01-mail-desktop.html`): Клиенты, Команда,
 * Тендеры, Сервисы, клавиши 1–4. Персональная таблица аккаунта (Postman держит её у себя) —
 * WEB-12/WEB-14: пока сервер не отдаёт её через JMAP, веб показывает этот список.
 */
export const CATEGORIES: Category[] = [
  { id: "clients", keyword: "pm.cat.clients", name: "Клиенты", barVar: "--cat-blue", chipBgVar: "--cat-blue-bg", chipTxVar: "--cat-blue-tx" },
  { id: "team", keyword: "pm.cat.team", name: "Команда", barVar: "--cat-green", chipBgVar: "--cat-green-bg", chipTxVar: "--cat-green-tx" },
  { id: "tenders", keyword: "pm.cat.tenders", name: "Тендеры", barVar: "--cat-pink", chipBgVar: "--cat-pink-bg", chipTxVar: "--cat-pink-tx" },
  { id: "services", keyword: "pm.cat.services", name: "Сервисы", barVar: "--cat-gray", chipBgVar: "--cat-gray-bg", chipTxVar: "--cat-gray-tx" },
];

/** Категория по клавише 1–9 (быстрое назначение выделенному письму). */
export function categoryByNumber(n: number): Category | null {
  return CATEGORIES[n - 1] ?? null;
}

/** Категории письма по ключевым словам: первая — категория полосы (DESIGN.md: категория первая). */
export function categoriesOf(keywords: Keywords): Category[] {
  return CATEGORIES.filter((c) => keywords[c.keyword]);
}

/** Категория письма (первая из найденных) — для полосы слева и чипа. */
export function categoryOf(keywords: Keywords): Category | null {
  return categoriesOf(keywords)[0] ?? null;
}

/** Сроки жизненного цикла письма: дата и время в слове (S5-04: `pm.due.2026-10-29t1500`). */
export interface Lifecycle {
  /** Угроза (`pm.threat`): подложка угрозы, красный — только безопасность. */
  threat: boolean;
  /** Срок `pm.due` с датой (или общее слово без даты — только признак). */
  due: { at: Date | null; general: boolean } | null;
  /** Ждём ответа `pm.wait` (серый нейтральный). */
  wait: { at: Date | null; general: boolean } | null;
  /** Исчезнет `pm.expire` (быстрый фильтр «Истекают»). */
  expire: { at: Date | null; general: boolean } | null;
}

/** Слово с датой и временем: `pm.due.2026-10-29t1500` → { date, time }. */
function parseDatedKeyword(keyword: string, prefix: string): { date: string; time: string | null } | null {
  if (!keyword.startsWith(prefix) || keyword.length === prefix.length) return null;
  const rest = keyword.slice(prefix.length);
  const m = /^(\d{4}-\d{2}-\d{2})(?:t(\d{2})(\d{2}))?$/.exec(rest);
  if (!m) return null;
  return { date: m[1], time: m[2] && m[3] ? `${m[2]}:${m[3]}` : null };
}

/** Дата слова без времени — конец дня по местному времени (Postman S5-04: дата — местная). */
function endOfDay(date: string): Date {
  const [y, mo, d] = date.split("-").map(Number);
  // Местный конец дня: сроки в Postman — местная дата («до среды»).
  return new Date(y, mo - 1, d, 23, 59, 59, 999);
}

/** Разбор сроков по ключевым словам письма; без слов — пустой набор. */
export function lifecycleOf(keywords: Keywords): Lifecycle {
  const out: Lifecycle = { threat: false, due: null, wait: null, expire: null };
  for (const word of Object.keys(keywords)) {
    if (!keywords[word]) continue;
    if (word === "pm.threat") out.threat = true;
    for (const [key, prefix] of [
      ["due", "pm.due."],
      ["wait", "pm.wait."],
      ["expire", "pm.expire."],
    ] as const) {
      const dated = parseDatedKeyword(word, prefix);
      const general = dated === null && word === prefix.slice(0, -1);
      // Сервер ставит рядом и слово с датой, и общее (S5-04): дата и признак сливаются,
      // а не перезаписывают друг друга.
      if (dated) {
        out[key] = { at: endOfDay(dated.date), general: out[key]?.general ?? false };
      } else if (general) {
        out[key] = { at: out[key]?.at ?? null, general: true };
      }
    }
  }
  return out;
}

/** Просрочено: срок раньше конца вчерашнего дня (метка «Просрочено N д» в макете). */
export function overdueDays(at: Date, now: Date): number | null {
  const ms = now.getTime() - at.getTime();
  if (ms <= 0) return null;
  return Math.floor(ms / 86_400_000) + 1;
}

/** Условие фильтра по слову с датой не выразить сервером (`hasKeyword` ищет слово целиком) —
 * маска по общему слову рядом: сервер ставит и дату, и общее слово (S5-04). */
export function quickFilterFilters(kind: QuickFilterKind, selfAddress: string | null): EmailQueryFilter | null {
  switch (kind) {
    case "threat":
      return { hasKeyword: "pm.threat" };
    case "due":
      return { hasKeyword: "pm.due" };
    case "wait":
      return { hasKeyword: "pm.wait" };
    case "expire":
      return { hasKeyword: "pm.expire" };
    case "me":
      // «Мне (я в «Кому»)» — S5-03; адрес входа — username сессии.
      return selfAddress ? { to: selfAddress } : null;
  }
}

/** Виды быстрых фильтров — порядок по срочности (DESIGN.md: Угрозы → Срок → Ждём → Мне → Истекают). */
export type QuickFilterKind = "threat" | "due" | "wait" | "me" | "expire";

/** Порядок и подписи быстрых фильтров (кадры 01/04 макета). */
export const QUICK_FILTERS: Array<{ kind: QuickFilterKind; label: string; iconVar: string }> = [
  { kind: "threat", label: "Угрозы", iconVar: "--i-red" },
  { kind: "due", label: "Срок", iconVar: "--i-amber" },
  { kind: "wait", label: "Ждём", iconVar: "--i-amber" },
  { kind: "me", label: "Мне", iconVar: "--i-blue" },
  { kind: "expire", label: "Истекают", iconVar: "--i-amber" },
];

/** Метка срока в строке письма: «До ср» — короткое имя дня недели, «Просрочено N д» — заливка. */
export function dueLabel(lifecycle: Lifecycle, now: Date): { text: string; overdue: boolean } | null {
  const due = lifecycle.due;
  if (!due) return null;
  const at = due.at;
  if (!at) return { text: "Срок", overdue: false }; // только общее слово — без даты
  const days = overdueDays(at, now);
  if (days !== null) return { text: `Просрочено ${days} д`, overdue: true };
  const daysLeft = Math.ceil((at.getTime() - now.getTime()) / 86_400_000);
  if (daysLeft <= 0) return { text: "Срок сегодня", overdue: false };
  const weekday = at.toLocaleDateString("ru", { weekday: "short" });
  return { text: `До ${weekday}`, overdue: false };
}

/** Метка «Ждём ответа» — нейтральный серый (макет: строка 4 списка); `now` — для тестов. */
export function waitLabel(lifecycle: Lifecycle, now: Date = new Date()): string | null {
  if (!lifecycle.wait) return null;
  const at = lifecycle.wait.at;
  if (!at) return "Ждём ответа";
  const days = Math.ceil((at.getTime() - now.getTime()) / 86_400_000);
  return days > 0 ? `Ждём ответа · ${days} д` : "Ждём ответа";
}

/** Метка «Исчезнет» — до срока исчезновения (быстрый фильтр «Истекают»). */
export function expireLabel(lifecycle: Lifecycle, now: Date): string | null {
  const expire = lifecycle.expire;
  if (!expire) return null;
  const at = expire.at;
  if (!at) return "Исчезнет";
  const days = Math.ceil((at.getTime() - now.getTime()) / 86_400_000);
  return days > 0 ? `Исчезнет через ${days} д` : "Исчезнет";
}
