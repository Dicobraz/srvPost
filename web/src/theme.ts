// Тема веб-клиента из токенов фирменного стиля (UI-19, решение 119): design/tokens.toml читается при
// сборке (`?raw` + smol-toml) — своих цветов в коде клиента нет, как в веб-консоли. Роли — как у
// текстового интерфейса (TUI-06): screen/panel — фоны, text/muted — текст, frame/frameA — рамки,
// sel/titleA — акценты, ok/warn/err — состояния (знаки из [signs]: смысл статуса не держится на цвете).
// Переключение тем (WEB-01): «системная» (prefers-color-scheme), светлая, тёмная; выбор хранится
// в localStorage и применяется атрибутом data-theme на <html> с CSS-переменными из токенов.
import { useEffect, useState } from "react";
import { parse } from "smol-toml";

import raw from "../../design/tokens.toml?raw";

/** Цветовые роли одного режима — раздел [mode.dark] или [mode.light] файла токенов. */
export interface ModeColors {
  screen: string;
  panel: string;
  text: string;
  muted: string;
  frame: string;
  frameA: string;
  titleA: string;
  sel: string;
  selFg: string;
  ok: string;
  warn: string;
  err: string;
}

/** Файл токенов (цвета, шрифты, знаки состояний); клиенту нужны только эти разделы. */
export interface Tokens {
  schema: number;
  brand: { pink: string; blue: string; light: string };
  fonts: {
    heading: { family: string; weights: number[]; style: string };
    text: { family: string; weights: number[]; style: string };
  };
  signs: { ok: string; warn: string; err: string };
  roles: Record<string, string>;
  mode: { dark: ModeColors; light: ModeColors };
}

export const tokens = parse(raw) as unknown as Tokens;

/** Знаки состояний (● ▲ ×) — из [signs] файла токенов. */
export const signs = tokens.signs;

const fallback = "system-ui, sans-serif";
/** Стеки шрифтов из [fonts]: шрифт заголовков с fallback на текстовый (в Bebas Neue нет кириллицы).
 * Файлы шрифтов вшьёт карточка WEB-03 (CSP разрешает только свои ресурсы, CDN нет). */
export const fonts = {
  text: `"${tokens.fonts.text.family}", ${fallback}`,
  heading: `"${tokens.fonts.heading.family}", "${tokens.fonts.text.family}", ${fallback}`,
};

/** Выбор темы: как у системы, светлая или тёмная. */
export type ThemeChoice = "system" | "light" | "dark";

export const THEME_KEY = "thepost-webmail-theme";
const CHOICES: ThemeChoice[] = ["system", "light", "dark"];

/** Сохранённый выбор темы; пусто или неизвестное значение — «системная». */
export function storedTheme(): ThemeChoice {
  try {
    const value = localStorage.getItem(THEME_KEY);
    return CHOICES.includes(value as ThemeChoice) ? (value as ThemeChoice) : "system";
  } catch {
    return "system";
  }
}

export function saveTheme(choice: ThemeChoice): void {
  try {
    localStorage.setItem(THEME_KEY, choice);
  } catch {
    // Приватный режим без localStorage: выбор живёт до перезагрузки страницы.
  }
}

/** Тёмная ли тема у системы (jsdom отвечает «нет»: matchMedia подменяется в test-setup.ts). */
export function systemDark(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-color-scheme: dark)").matches;
}

/** Действующий режим: у «системной» — по prefers-color-scheme. */
export function resolveDark(choice: ThemeChoice): boolean {
  return choice === "system" ? systemDark() : choice === "dark";
}

/** Цвета действующего режима. */
export function modeColors(dark: boolean): ModeColors {
  return dark ? tokens.mode.dark : tokens.mode.light;
}

/** CSS-переменные темы из ролей токенов: `--c-screen` и т. д. */
export function cssVariables(dark: boolean): string {
  const colors = modeColors(dark);
  return Object.entries(colors)
    .map(([role, value]) => `--c-${role}:${value};`)
    .join("");
}

const STYLE_ID = "thepost-theme";

/** Применяет тему: переменные токенов в <style> и признак режима на <html> (data-theme). */
export function applyTheme(choice: ThemeChoice): void {
  const dark = resolveDark(choice);
  let style = document.getElementById(STYLE_ID) as HTMLStyleElement | null;
  if (!style) {
    style = document.createElement("style");
    style.id = STYLE_ID;
    document.head.append(style);
  }
  style.textContent = `:root{${cssVariables(dark)}--font-text:${fonts.text};--font-heading:${fonts.heading};}`;
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

/** Тема как состояние компонента: выбор хранится в localStorage, «системная» следит за prefers-color-scheme. */
export function useTheme(): [ThemeChoice, (choice: ThemeChoice) => void] {
  const [choice, setChoice] = useState<ThemeChoice>(storedTheme);
  useEffect(() => {
    applyTheme(choice);
    if (choice !== "system") return;
    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const follow = () => applyTheme("system");
    media.addEventListener("change", follow);
    return () => media.removeEventListener("change", follow);
  }, [choice]);
  return [
    choice,
    (next: ThemeChoice) => {
      setChoice(next);
      saveTheme(next);
    },
  ];
}
