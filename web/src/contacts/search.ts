/*
  Поиск контактов (WEB-07): по имени/адресу/организации — серверный фильтр ContactCard/query
  (`text` RFC 9610 §3.3.1 ищет по имени, псевдонимам, организациям, адресам, телефонам,
  сервисам, адресам и заметкам). Устойчивость к раскладке — как в поиске писем (WEB-05):
  запрос, набранный в EN-раскладке, пробуется вторым вариантом qwerty→йцукен (keyboard-map.ts),
  варианты объединяются OR в одном запросе. Локальная проверка — тот же принцип для снимка
  подсказок композера (без похода в сеть).
*/
import { layoutVariant } from "../mail/keyboard-map";
import { emailsOf, fullNameOf, organizationOf, phonesOf, type ContactCard } from "./model";

/** Варианты запроса: исходный + перевод раскладки (если перевод есть). */
export function queryVariants(query: string, translit: boolean): string[] {
  const trimmed = query.trim();
  if (!trimmed) return [];
  const variant = translit ? layoutVariant(trimmed) : null;
  return variant ? [trimmed.toLowerCase(), variant.toLowerCase()] : [trimmed.toLowerCase()];
}

/** Фильтр ContactCard/query: один вариант — `text`, два — OR (сервер ищет оба в одном запросе). */
export function contactSearchFilter(
  query: string,
  translit: boolean,
): Record<string, unknown> | null {
  const variants = queryVariants(query, translit);
  if (variants.length === 0) return null;
  const conds = variants.map((v) => ({ text: v }));
  return conds.length === 1 ? conds[0] : { operator: "OR", conditions: conds };
}

/** Совпадает ли карточка с запросом (локально, снимок): имя, адрес, организация, телефон. */
export function cardMatches(card: ContactCard, query: string, translit: boolean): boolean {
  const variants = queryVariants(query, translit);
  if (variants.length === 0) return true;
  const haystack = [
    fullNameOf(card),
    organizationOf(card) ?? "",
    ...emailsOf(card),
    ...phonesOf(card),
  ]
    .join("\n")
    .toLowerCase();
  return variants.some((v) => haystack.includes(v));
}
