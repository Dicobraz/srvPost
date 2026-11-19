// Тема консоли из токенов фирменного стиля (UI-19, решение 119): design/tokens.toml читается при сборке
// (`?raw` + smol-toml) — своих цветов в коде консоли нет. Действующий брендинг заказчика (UI-22, решение 122)
// заменяет одноимённые роли токенов значениями из ответа сервера; нет брендинга — тема IT TASK, как здесь.
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

/**
 * Действующий брендинг заказчика (UI-22, решение 122): название и знак (`null` — встроенные) и цвета ролей,
 * заменяющие токены. Ответ сервера (`effective`/публичный маршрут) уже выведен и проверен на контраст — консоль
 * только подставляет значения, своих расчётов цветов нет.
 */
export interface Branding {
  name: string | null;
  /** Знак заказчика: адрес открытого маршрута; `null` — встроенный знак IT TASK. */
  logo: { url: string } | null;
  light: Partial<ModeColors>;
  dark: Partial<ModeColors>;
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
  /** Смысл ролей — подписи в таблице брендинга (UI-22). */
  roles: Record<string, string>;
  mode: { dark: ModeColors; light: ModeColors };
  cli: { roles: Record<string, { ansi: string; brand: string; attrs: string[] }> };
}

export const tokens = parse(raw) as unknown as Tokens;

/** Знаки состояний (● ▲ ×) — из [signs] файла токенов: смысл статуса не держится на одном цвете. */
export const signs = tokens.signs;

/** Роли темы в порядке файла токенов (таблица ролей брендинга строится по нему). */
export const roleNames = Object.keys(tokens.mode.light) as (keyof ModeColors)[];

/** Роли CLI из [cli.roles] — порядок файла токенов. */
export const cliRoleNames = Object.keys(tokens.cli.roles);

/** Значения только известных ролей: карта ролей из ответа сервера — к Partial<ModeColors>. */
export function roleOverlay(map: Record<string, string> | undefined): Partial<ModeColors> {
  const known = Object.entries(map ?? {}).filter(([role]) => roleNames.includes(role as keyof ModeColors));
  return Object.fromEntries(known) as Partial<ModeColors>;
}

/**
 * Цвета текущей темы: тёмная (prefers-color-scheme) или светлая. Брендинг заказчика заменяет одноимённые роли
 * токенов (UI-22); нет его или ответа — тема IT TASK из `design/tokens.toml`, как раньше (UI-19).
 */
export function modeColors(dark: boolean, branding?: Branding | null): ModeColors {
  const over = branding ? roleOverlay(dark ? branding.dark : branding.light) : {};
  return { ...(dark ? tokens.mode.dark : tokens.mode.light), ...over };
}

const fallback = "system-ui, sans-serif";
/** Стеки шрифтов из [fonts]: шрифт заголовков с fallback на текстовый (в Bebas Neue нет кириллицы). */
export const fonts = {
  text: `"${tokens.fonts.text.family}", ${fallback}`,
  heading: `"${tokens.fonts.heading.family}", "${tokens.fonts.text.family}", ${fallback}`,
};

/** Тема antd из токенов и действующего брендинга: светлая и тёмная строятся одними ролями, отличаясь значениями режима. */
export function brandTheme(dark: boolean, branding?: Branding | null): ThemeConfig {
  const c = modeColors(dark, branding);
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
      Table: { headerBg: c.selI, headerColor: c.head, rowSelectedBg: c.selI },
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
