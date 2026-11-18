// Тема консоли из токенов фирменного стиля (UI-19, решение 119): design/tokens.toml читается при сборке
// (`?raw` + smol-toml) и остаётся единственным источником цветов консоли — своих цветов в коде нет.
// Роли — как у текстового интерфейса (TUI-06): sel — акцент (главное действие, выделение меню), frameA —
// основной синий (сведения, активные элементы), titleA — акцент текста (ссылки), screen/panel — фоны,
// text/muted — текст, selI — подложка шапок таблиц и выделенной строки, ok/warn/err — состояния.
import { createContext, useContext, useEffect, useState } from "react";
import { theme as antdTheme, type ThemeConfig } from "antd";
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
  head: string;
  sel: string;
  selFg: string;
  selI: string;
  selIFg: string;
  fkBg: string;
  fkFg: string;
  ok: string;
  warn: string;
  err: string;
}

/** Файл токенов (цвета, шрифты, знаки состояний); в консоли используются только эти разделы. */
export interface Tokens {
  schema: number;
  brand: { pink: string; blue: string; light: string };
  fonts: {
    heading: { family: string; weights: number[]; style: string };
    text: { family: string; weights: number[]; style: string };
  };
  signs: { ok: string; warn: string; err: string };
  mode: { dark: ModeColors; light: ModeColors };
}

export const tokens = parse(raw) as unknown as Tokens;

/** Цвета текущей темы: тёмная (prefers-color-scheme) или светлая. */
export function modeColors(dark: boolean): ModeColors {
  return dark ? tokens.mode.dark : tokens.mode.light;
}

const fallback = "system-ui, sans-serif";
/** Стеки шрифтов из [fonts]: шрифт заголовков с fallback на текстовый (в Bebas Neue нет кириллицы). */
export const fonts = {
  text: `"${tokens.fonts.text.family}", ${fallback}`,
  heading: `"${tokens.fonts.heading.family}", "${tokens.fonts.text.family}", ${fallback}`,
};

/** Тема antd из токенов: светлая и тёмная строятся одними ролями, отличаясь значениями режима. */
export function brandTheme(dark: boolean): ThemeConfig {
  const c = modeColors(dark);
  return {
    algorithm: dark ? antdTheme.darkAlgorithm : antdTheme.defaultAlgorithm,
    token: {
      colorPrimary: c.sel,
      colorInfo: c.frameA,
      colorLink: c.titleA,
      colorSuccess: c.ok,
      colorWarning: c.warn,
      colorError: c.err,
      colorTextBase: c.text,
      colorText: c.text,
      colorTextSecondary: c.muted,
      colorTextTertiary: c.muted,
      colorTextQuaternary: c.muted,
      colorBgLayout: c.screen,
      colorBgContainer: c.panel,
      colorBgElevated: c.panel,
      colorBorder: c.frame,
      colorBorderSecondary: c.frame,
      fontFamily: fonts.text,
    },
    components: {
      Layout: { headerBg: "transparent", siderBg: c.panel, bodyBg: c.screen },
      Menu: { itemSelectedBg: c.sel, itemSelectedColor: c.selFg },
      Table: { headerBg: c.selI, headerColor: c.head, rowSelectedBg: c.selI, rowSelectedColor: c.selIFg },
    },
  };
}

const DarkContext = createContext(false);

/** Тема интерфейса для компонентов под ConfigProvider: знак и статусы знают, светлая тема или тёмная. */
export const DarkProvider = DarkContext.Provider;

export function useDark(): boolean {
  return useContext(DarkContext);
}

/** Тема — по системе (prefers-color-scheme), как у почтовых клиентов: светлая и тёмная без переключателя. */
export function useSystemDark(): boolean {
  const [dark, setDark] = useState(() => window.matchMedia?.("(prefers-color-scheme: dark)").matches ?? false);
  useEffect(() => {
    const query = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = (e: MediaQueryListEvent) => setDark(e.matches);
    query.addEventListener("change", onChange);
    return () => query.removeEventListener("change", onChange);
  }, []);
  return dark;
}
