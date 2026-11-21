/*
  Получатели (WEB-04): чипы Кому/Копия/Скрытая по макету 02 — модель, разбор ввода и
  автодополнение. Источники подсказок (порядок как в Postman, WEB-07): личные адресные книги
  из JMAP ContactCard (JSContact, RFC 9553/9610), «Часто пишу» (верх истории отправок), GAL
  «Организация» («Справочник»), остальная история (localStorage) — слияние в
  contacts/autocomplete.ts. Подсказка честно подписана источником («Контакты»/«Справочник»/
  «Часто пишу»/«История»), поиск устойчив к раскладке (keyboard-map).
*/
import { layoutVariant } from "../mail/keyboard-map";

/** Участник письма: имя может отсутствовать (RFC 8621 §4.1.2.3 EmailAddress). */
export interface Recipient {
  name: string | null;
  email: string;
}

/** Строка «Имя <a@b>», «a@b» или несколько через запятую/точку с запятой — в список чипов. */
export function parseRecipients(input: string): Recipient[] {
  return input
    .split(/[,;]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const m = s.match(/^(.*?)\s*<([^<>]+)>$/);
      if (m) return { name: m[1].trim() || null, email: m[2].trim() };
      return { name: null, email: s };
    });
}

/** Почта синтаксически допустима (упрощение RFC 5322: local@domain без пробелов и угловых). */
export function isValidEmail(email: string): boolean {
  return /^[^\s@<>]+@[^\s@<>]+$/.test(email) && email.includes("@") && !/\s/.test(email);
}

/** Чип дубликат не создаёт (почта без учёта регистра). */
export function isDuplicate(recipients: Recipient[], email: string): boolean {
  const lower = email.toLowerCase();
  return recipients.some((r) => r.email.toLowerCase() === lower);
}

/** Кандидат подсказки: участник + источник (метка в списке, как в макете). */
export interface Suggestion {
  recipient: Recipient;
  /** «Контакты» (адресная книга JMAP) или «История» (локальные отправки). */
  source: string;
}

/** Подсказки по запросу: по подстроке имени или почты, без регистра, уже выбранные не повторяются.
 * Запрос устойчив к раскладке (WEB-07, как поиск писем WEB-05): напечатанное в EN-раскладке
 * пробуется вторым вариантом qwerty→йцукен — «rdfhnfk» находит «Квартал». */
export function suggest(
  candidates: Suggestion[],
  query: string,
  chosen: Recipient[],
  limit = 8,
): Suggestion[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  const variant = layoutVariant(q);
  const seen = new Set(chosen.map((r) => r.email.toLowerCase()));
  return candidates
    .filter((c) => {
      const email = c.recipient.email.toLowerCase();
      if (seen.has(email)) return false; // выбранные и дубли кандидатов не повторяются
      seen.add(email);
      const name = (c.recipient.name ?? "").toLowerCase();
      return email.includes(q) || name.includes(q) || (variant !== null && (email.includes(variant) || name.includes(variant)));
    })
    .slice(0, limit);
}

/** Формат чипа: имя, если есть, иначе почта (макет: «Ольга Смирнова»). */
export function chipLabel(r: Recipient): string {
  return r.name?.trim() || r.email;
}

/** Инициалы для круглого аватара подсказки (макет: «ОС»); без имени — начало почты. */
export function initialsOf(r: Recipient): string {
  const name = (r.name ?? "").trim();
  if (!name) return r.email.split("@")[0].slice(0, 2).toUpperCase();
  const parts = name.split(/\s+/).filter(Boolean);
  return ((parts[0]?.[0] ?? "") + (parts[1]?.[0] ?? "")).toUpperCase() || name.slice(0, 2).toUpperCase();
}
