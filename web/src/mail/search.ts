/*
  Поиск (WEB-05): модель поискового состояния и сборка фильтра Email/query. Текст запроса —
  свободные слова (морфология, «ё», стемминг ru/en — серверная, Tantivy) и явные операторы
  из:/кому:/тема:/тело: (поля from/to/subject/body RFC 8621 §4.4.1). Чипы области — как в
  реестре Postman (PARITY.md search.*): Везде/В папке, С вложениями, Непрочитанные, 30 дней.
  Уточнения (click-refinements) — чипы из клика по отправителю/категории/периоду/папке —
  сужают запрос через AND. Транслитерация раскладки — второй вариант текста через OR
  (keyboard-map.ts). Отсюда же — термы подсветки F3 в открытом письме (highlight.ts).
*/
import type { EmailQueryFilter } from "../api/jmap";
import { layoutVariant } from "./keyboard-map";
import { quickFilterFilters, type QuickFilterKind } from "./keywords";

/** Область поиска: «Везде» (все папки) или «В папке» (текущая). */
export type SearchScope = "all" | "folder";

/** Уточнение запроса кликом (чип в панели фильтров, снимается крестиком). */
export interface SearchRefinement {
  kind: "from" | "folder" | "period" | "category";
  /** from — адрес; folder — id папки; category — keyword (pm.cat.*); period — начало (after). */
  value: string;
  /** Текст чипа для человека: «От: Ольга», «Папка: Входящие», «Ноябрь 2026». */
  label: string;
  /** Только period: конец периода (before, ISO) — от value (after) до before. */
  before?: string;
}

/** Состояние поиска: текст + чипы области + уточнения. */
export interface SearchState {
  text: string;
  scope: SearchScope;
  unread: boolean;
  attachment: boolean;
  recent30: boolean;
  refinements: SearchRefinement[];
}

/** Пустое состояние (сброс — filters.reset). */
export const EMPTY_SEARCH: SearchState = {
  text: "",
  scope: "all",
  unread: false,
  attachment: false,
  recent30: false,
  refinements: [],
};

/** Режим поиска активен: есть текст или уточнения (чипы области без текста не ищут сами). */
export function isSearchActive(state: Pick<SearchState, "text" | "refinements">): boolean {
  return state.text.trim().length > 0 || state.refinements.length > 0;
}

/** Явные операторы запроса: поле → значение (from/to/subject/body RFC 8621 §4.4.1). */
export type QueryField = "from" | "to" | "subject" | "body";

/** Разбор запроса: операторы полями (from:ivan «тема:отчёт»), остальное — свободный текст. */
export interface ParsedQuery {
  freeText: string | null;
  fields: Array<{ field: QueryField; value: string }>;
}

const FIELD_RE = /^(from|to|subject|body|от|кому|тема|тело):(.*)$/i;

/** Соответствие русских операторов полям (равнозначны английским). */
const FIELD_ALIASES: Record<string, QueryField> = {
  from: "from", "от": "from",
  to: "to", "кому": "to",
  subject: "subject", "тема": "subject",
  body: "body", "тело": "body",
};

/** Значение оператора: в кавычках — до закрывающей (с пробелами), без — до конца токена. */
function fieldValue(rest: string, tokens: string[], index: number): { value: string; consumed: number } {
  const first = rest.trim();
  if (first.startsWith('"')) {
    const afterQuote = rest.slice(rest.indexOf('"') + 1);
    const end = afterQuote.indexOf('"');
    if (end >= 0) return { value: afterQuote.slice(0, end), consumed: index };
    // Кавычка не закрыта в этом токене — собираем до закрывающей в следующих.
    let value = afterQuote;
    let j = index + 1;
    while (j < tokens.length) {
      const close = tokens[j].indexOf('"');
      if (close >= 0) {
        value += (value.endsWith(" ") || value === "" ? "" : " ") + tokens[j].slice(0, close);
        return { value, consumed: j };
      }
      value += (value.endsWith(" ") || value === "" ? "" : " ") + tokens[j];
      j++;
    }
    return { value, consumed: tokens.length - 1 };
  }
  return { value: first, consumed: index };
}

/** Парсер строки поиска: операторы (en/ru) вынимаются в поля, остаток — свободный текст. */
export function parseQuery(text: string): ParsedQuery {
  const tokens = text.split(/\s+/).filter(Boolean);
  const fields: ParsedQuery["fields"] = [];
  const rest: string[] = [];
  let i = 0;
  while (i < tokens.length) {
    const m = FIELD_RE.exec(tokens[i]);
    if (m && m[2] !== "") {
      const field = FIELD_ALIASES[m[1].toLowerCase()];
      const { value, consumed } = fieldValue(m[2], tokens, i);
      if (value.trim()) fields.push({ field, value: value.trim() });
      i = consumed + 1;
      continue;
    }
    rest.push(tokens[i]);
    i++;
  }
  return { freeText: rest.length > 0 ? rest.join(" ") : null, fields };
}

/** ISO-дата 30 дней назад (чип «30 дней», search.recent). */
export function recent30After(now: Date = new Date()): string {
  return new Date(now.getTime() - 30 * 86_400_000).toISOString();
}

/** Варианты текста условия: исходный + перевод раскладки (когда включён) — OR на сервере. */
function variantsOf(text: string, translit: boolean): string[] {
  const trimmed = text.trim();
  if (!trimmed) return [];
  const variant = translit ? layoutVariant(trimmed) : null;
  return variant ? [trimmed, variant] : [trimmed];
}

/** Условие одного текста: один вариант — Cond, несколько — OR (раскладка). */
function textCond(text: string, translit: boolean, field?: QueryField): EmailQueryFilter | null {
  const variants = variantsOf(text, translit);
  if (variants.length === 0) return null;
  const conds: EmailQueryFilter[] = variants.map((v) =>
    field ? { [field]: v } as EmailQueryFilter : { text: v },
  );
  return conds.length === 1 ? conds[0] : { operator: "OR", conditions: conds };
}

/** Аргументы сборки фильтра — ровно то, что есть в WindowArgs (queries.ts). */
export interface SearchFilterArgs {
  text: string;
  scopeAll: boolean;
  unread: boolean;
  attachment: boolean;
  recent30: boolean;
  refinements: SearchRefinement[];
  /** Текущая папка (для «В папке»); null — виртуальная «Отмеченные»/все. */
  mailboxId: string | null;
  /** Виртуальная папка «Отмеченные» ($flagged) — сочетается с поиском, как в Postman. */
  flagged: boolean;
  /** Быстрый фильтр (Угрозы/Срок/…) — сочетается с поиском. */
  quick: QuickFilterKind | null;
  translit: boolean;
}

/**
 * Фильтр Email/query из состояния поиска: текст (операторы + транслитерация OR) AND чипы
 * области AND уточнения AND быстрые фильтры/флаг. Пустой запрос — null (вызывающий ведёт
 * себя как без поиска).
 */
export function searchFilter(args: SearchFilterArgs): EmailQueryFilter | null {
  const parts: EmailQueryFilter[] = [];
  if (args.text.trim()) {
    const parsed = parseQuery(args.text);
    const free = textCond(parsed.freeText ?? "", args.translit);
    if (free) parts.push(free);
    for (const f of parsed.fields) {
      const cond = textCond(f.value, args.translit, f.field);
      if (cond) parts.push(cond);
    }
  }
  // Чипы области (PARITY search.*): «В папке» — текущая папка; «Везде» — без папки.
  if (!args.scopeAll && args.mailboxId) parts.push({ inMailbox: args.mailboxId });
  if (args.unread) parts.push({ notKeyword: "$seen" });
  if (args.attachment) parts.push({ hasAttachment: true });
  if (args.recent30) parts.push({ after: recent30After() });
  if (args.flagged) parts.push({ hasKeyword: "$flagged" });
  if (args.quick) {
    const mask = quickFilterFilters(args.quick, null);
    if (mask) parts.push(mask);
  }
  // Уточнения кликом: каждое — своё условие (AND).
  for (const r of args.refinements) {
    switch (r.kind) {
      case "from":
        parts.push({ from: r.value });
        break;
      case "folder":
        parts.push({ inMailbox: r.value });
        break;
      case "category":
        parts.push({ hasKeyword: r.value });
        break;
      case "period":
        parts.push({ after: r.value, ...(r.before ? { before: r.before } : {}) });
        break;
    }
  }
  if (parts.length === 0) return null;
  if (parts.length === 1) return parts[0];
  return { operator: "AND", conditions: parts };
}

/**
 * Термы подсветки F3 (highlight.ts): слова запроса и его перевода раскладки. Короткие слова
 * (1 символ) не подсвечиваем — «и» замарает половину письма; операторные значения тоже.
 */
export function highlightTerms(text: string, translit: boolean): string[] {
  const parsed = parseQuery(text);
  const sources: string[] = [];
  if (parsed.freeText) sources.push(parsed.freeText);
  for (const f of parsed.fields) sources.push(f.value);
  const terms: string[] = [];
  for (const source of sources) {
    for (const variant of variantsOf(source, translit)) {
      for (const word of variant.split(/\s+/)) {
        const clean = word.replace(/^[^\p{L}\p{N}]+|[^\p{L}\p{N}]+$/gu, "");
        if (clean.length >= 2 && !terms.some((t) => t.toLowerCase() === clean.toLowerCase())) {
          terms.push(clean);
        }
      }
    }
  }
  return terms.slice(0, 8);
}

/**
 * HTML сниппета сервера (RFC 8621 §5): текст экранирован, кроме <mark></mark> подсветки.
 * Это единственная разрешённая разметка — остальное из ответа узла в DOM не попадает.
 */
export function snippetHtml(text: string): string {
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
  return escaped
    .replaceAll("&lt;mark&gt;", "<mark>")
    .replaceAll("&lt;/mark&gt;", "</mark>");
}

/** Период месяца для уточнения кликом по дате: [after, before) и подпись чипа. */
export function monthPeriod(iso: string): { after: string; before: string; label: string } {
  const d = new Date(iso);
  const from = new Date(d.getFullYear(), d.getMonth(), 1);
  const to = new Date(d.getFullYear(), d.getMonth() + 1, 1);
  const label = d.toLocaleDateString("ru", { month: "long", year: "numeric" });
  return { after: from.toISOString(), before: to.toISOString(), label };
}
