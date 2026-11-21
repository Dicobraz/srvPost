/*
  Автодополнение получателей (WEB-07): слияние источников в порядке Postman — личные контакты
  («Контакты»), часто пишу (верх истории отправок), справочник организации («Справочник»),
  остальная история («История»). Повтор адреса отсекается первым источником: личный контакт
  перекрывает свою запись истории, GAL — тоже (адрес из организации с именем полнее). Пометки
  источников — как в макете 02 («Контакты»/«Справочник»).
*/
import type { HistoryEntry } from "../compose/send-history";
import type { Suggestion } from "../compose/recipients";

/** Сколько верхних записей истории считаются «Часто пишу». */
export const FREQUENT_HISTORY = 3;

/** Источник подсказки — пометка в списке (макет 02). */
export type SuggestionSource = "Контакты" | "Справочник" | "Часто пишу" | "История";

/** Карточки и история — в подсказки. Источник подписывается честно. */
export function mergeSuggestions(
  personal: Suggestion[],
  gal: Suggestion[],
  history: HistoryEntry[],
  frequent = FREQUENT_HISTORY,
): Suggestion[] {
  const frequentHistory: Suggestion[] = history
    .slice(0, frequent)
    .map((h) => ({ recipient: { name: h.name, email: h.email }, source: "Часто пишу" }));
  const restHistory: Suggestion[] = history
    .slice(frequent)
    .map((h) => ({ recipient: { name: h.name, email: h.email }, source: "История" }));
  const seen = new Set<string>();
  const take = (list: Suggestion[]): Suggestion[] =>
    list.filter((s) => {
      const key = s.recipient.email.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  return [
    ...take(personal),
    ...take(frequentHistory),
    ...take(gal),
    ...take(restHistory),
  ];
}
