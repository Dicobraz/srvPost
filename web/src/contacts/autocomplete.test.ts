/*
  Слияние источников автодополнения (WEB-07): порядок как в Postman — личные («Контакты»),
  «Часто пишу» (верх истории отправок), «Справочник» (GAL «Организация»), «История»; повтор
  адреса отсекается первым источником, пометка честная.
*/
import { expect, test } from "vitest";

import { FREQUENT_HISTORY, mergeSuggestions } from "./autocomplete";
import type { HistoryEntry } from "../compose/send-history";
import type { Suggestion } from "../compose/recipients";

const personal: Suggestion[] = [
  { recipient: { name: "Мария Сидорова", email: "maria@vektor.example" }, source: "Контакты" },
];
const gal: Suggestion[] = [
  { recipient: { name: "Олег Лебедев", email: "o.lebedev@thepost.example" }, source: "Справочник" },
];
const history: HistoryEntry[] = [
  { email: "boris@example.org", name: "Борис Крылов", at: "2026-11-20T10:00:00Z" },
  { email: "vera@example.org", name: "Вера Пак", at: "2026-11-19T10:00:00Z" },
  { email: "glav@example.org", name: null, at: "2026-11-18T10:00:00Z" },
  { email: "stary@example.org", name: "Старый адрес", at: "2026-11-01T10:00:00Z" },
];

test("порядок источников: личные, часто пишу, справочник, история; пометки — как в макете 02", () => {
  const got = mergeSuggestions(personal, gal, history);
  expect(got.map((s) => [s.source, s.recipient.email])).toEqual([
    ["Контакты", "maria@vektor.example"],
    ["Часто пишу", "boris@example.org"],
    ["Часто пишу", "vera@example.org"],
    ["Часто пишу", "glav@example.org"],
    ["Справочник", "o.lebedev@thepost.example"],
    ["История", "stary@example.org"],
  ]);
});

test("«Часто пишу» — верх истории (FREQUENT_HISTORY), остальное — «История»", () => {
  expect(FREQUENT_HISTORY).toBe(3);
  const got = mergeSuggestions([], [], history);
  expect(got.filter((s) => s.source === "Часто пишу")).toHaveLength(FREQUENT_HISTORY);
  expect(got.filter((s) => s.source === "История")).toHaveLength(history.length - FREQUENT_HISTORY);
});

test("повтор адреса отсекается первым источником: личный контакт перекрывает историю и GAL", () => {
  const dupHistory: HistoryEntry[] = [
    { email: "maria@vektor.example", name: "Мария из истории", at: "2026-11-20T10:00:00Z" },
  ];
  const dupGal: Suggestion[] = [
    { recipient: { name: "Мария Сидорова", email: "maria@vektor.example" }, source: "Справочник" },
  ];
  const got = mergeSuggestions(personal, dupGal, dupHistory);
  expect(got).toHaveLength(1);
  expect(got[0].source).toBe("Контакты");
});

test("регистр адреса не важен для повтора; пустые источники — пустой список", () => {
  const galUpper: Suggestion[] = [
    { recipient: { name: "Мария Сидорова", email: "MARIA@vektor.example" }, source: "Справочник" },
  ];
  expect(mergeSuggestions(personal, galUpper, [])).toHaveLength(1);
  expect(mergeSuggestions([], [], [])).toEqual([]);
});
