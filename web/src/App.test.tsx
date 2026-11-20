import { render, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { expect, test } from "vitest";

import { App } from "./App";

// Smoke-тест каркаса (WEB-01): оболочка с разделами, шов «Каналы» отключён, разделы — заглушки.
// Запросы — по контейнеру своего рендера: автоочистки RTL без globals у vitest нет (как в консоли).
test("оболочка: навигация разделов и заглушка Почты", () => {
  const page = within(render(
    <MemoryRouter initialEntries={["/"]}>
      <App />
    </MemoryRouter>,
  ).container);
  const nav = within(page.getByRole("navigation", { name: "Разделы" }));
  expect(nav.getByRole("link", { name: "Почта" }).getAttribute("href")).toBe("/");
  expect(nav.getByRole("link", { name: "Календарь" }).getAttribute("href")).toBe("/calendar");
  expect(nav.getByRole("link", { name: "Контакты" }).getAttribute("href")).toBe("/contacts");
  // Шов «Каналы» (решение 2026-11-17): место под будущий веб-чат, пункт отключён.
  const seam = nav.getByText("Каналы");
  expect(seam.getAttribute("aria-disabled")).toBe("true");
  expect(page.getByRole("heading", { name: "Почта" })).toBeTruthy();
  expect(page.getByText("Раздел в разработке.")).toBeTruthy();
});

test("разделы — заглушки «в разработке»", () => {
  for (const [path, section] of [
    ["/calendar", "Календарь"],
    ["/contacts", "Контакты"],
  ] as const) {
    const page = within(render(
      <MemoryRouter initialEntries={[path]}>
        <App />
      </MemoryRouter>,
    ).container);
    expect(page.getByRole("heading", { name: section })).toBeTruthy();
    expect(page.getByText("Раздел в разработке.")).toBeTruthy();
  }
});

test("тема применяется к документу (по умолчанию — системная, в jsdom светлая)", () => {
  render(
    <MemoryRouter initialEntries={["/"]}>
      <App />
    </MemoryRouter>,
  );
  expect(document.documentElement.dataset.theme).toBe("light");
  expect(document.getElementById("thepost-theme")?.textContent).toContain("--c-screen:");
});
