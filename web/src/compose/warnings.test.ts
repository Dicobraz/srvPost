// Предупреждения (WEB-04, приёмка карточки): «прилагаю» без вложений срабатывает, без слов о
// вложении — нет; внешние получатели — чужой домен, контакты не считаются внешними; тема пуста.
import { describe, expect, test } from "vitest";

import { composeWarnings, externalDomains } from "./warnings";

const BASE = {
  subject: "Договор поставки",
  bodyHtml: "",
  to: [{ name: null, email: "o@vektor.example" }],
  cc: [],
  bcc: [],
  attachmentCount: 0,
  ownDomain: "thepost.example",
  knownDomains: new Set<string>(),
};

function warnings(patch: Partial<typeof BASE>) {
  return composeWarnings({ ...BASE, ...patch });
}

describe("забытая вложенность", () => {
  test("«прилагаю» без вложений — предупреждение есть", () => {
    const got = warnings({ bodyHtml: "<p>Прилагаю смету и спецификацию.</p>" });
    expect(got.some((w) => w.kind === "attachment")).toBe(true);
  });

  test("«вложение» в теме — тоже", () => {
    const got = warnings({ subject: "Файл во вложении" });
    expect(got.some((w) => w.kind === "attachment")).toBe(true);
  });

  test("без слов о вложении — предупреждения нет", () => {
    const got = warnings({ bodyHtml: "<p>Согласовали условия, отправляем документы курьером.</p>" });
    expect(got.some((w) => w.kind === "attachment")).toBe(false);
  });

  test("с вложениями — предупреждения нет даже со словом «прилагаю»", () => {
    const got = warnings({ bodyHtml: "<p>Прилагаю смету.</p>", attachmentCount: 1 });
    expect(got.some((w) => w.kind === "attachment")).toBe(false);
  });
});

describe("внешние получатели", () => {
  test("чужой домен — предупреждение с доменом", () => {
    const got = warnings({ to: [{ name: null, email: "x@outside.example" }] });
    const ext = got.find((w) => w.kind === "external");
    expect(ext?.text).toContain("outside.example");
  });

  test("свой домен и домены контактов — не внешние", () => {
    const got = warnings({
      to: [{ name: null, email: "a@thepost.example" }, { name: null, email: "b@partner.example" }],
      knownDomains: new Set(["partner.example"]),
    });
    expect(got.some((w) => w.kind === "external")).toBe(false);
  });

  test("поддомен своего домена — свой", () => {
    expect(externalDomains([{ name: null, email: "a@sub.thepost.example" }], "thepost.example", new Set())).toEqual([]);
  });
});

test("пустая тема — предупреждение; непустая — нет", () => {
  expect(warnings({ subject: "" }).some((w) => w.kind === "subject")).toBe(true);
  expect(warnings({ subject: "  " }).some((w) => w.kind === "subject")).toBe(true);
  expect(warnings({ subject: "Счёт № 419" }).some((w) => w.kind === "subject")).toBe(false);
});
