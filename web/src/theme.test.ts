import { expect, test } from "vitest";

import {
  applyTheme,
  cssVariables,
  resolveDark,
  saveTheme,
  storedTheme,
  systemDark,
  tokens,
} from "./theme";

// Тема из design/tokens.toml (решение 119): своих цветов в коде клиента нет — только роли токенов.
test("токены содержат оба режима и бренд", () => {
  expect(tokens.schema).toBe(1);
  expect(tokens.brand.pink).toMatch(/^#[0-9A-F]{6}$/);
  for (const mode of [tokens.mode.dark, tokens.mode.light]) {
    for (const role of Object.values(mode)) {
      expect(role).toMatch(/^#[0-9A-F]{6}$/);
    }
  }
});

test("CSS-переменные различают режимы", () => {
  const dark = cssVariables(true);
  const light = cssVariables(false);
  expect(dark).toContain(`--c-screen:${tokens.mode.dark.screen};`);
  expect(light).toContain(`--c-screen:${tokens.mode.light.screen};`);
  expect(dark).not.toBe(light);
});

test("выбор темы хранится, «системная» — по prefers-color-scheme", () => {
  expect(storedTheme()).toBe("system");
  saveTheme("dark");
  expect(storedTheme()).toBe("dark");
  saveTheme("light");
  expect(storedTheme()).toBe("light");
  // jsdom: matchMedia подменён в test-setup.ts (matches: false) — системная тема светлая.
  expect(systemDark()).toBe(false);
  expect(resolveDark("system")).toBe(false);
  expect(resolveDark("dark")).toBe(true);
  expect(resolveDark("light")).toBe(false);
});

test("applyTheme ставит переменные и data-theme", () => {
  applyTheme("dark");
  expect(document.documentElement.dataset.theme).toBe("dark");
  expect(document.getElementById("thepost-theme")?.textContent).toContain(
    `--c-screen:${tokens.mode.dark.screen};`,
  );
  applyTheme("system");
  expect(document.documentElement.dataset.theme).toBe("light");
});
