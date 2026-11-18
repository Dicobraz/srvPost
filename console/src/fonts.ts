// Шрифты в статике (UI-19, решение 119): без CDN и внешних адресов, консоль работает без интернета.
// Файлы woff2 идут через сборку Vite: Bebas Neue — пакет @fontsource (сборочный актив, файлы шрифта
// копируются в dist), Evolventa — src/fonts/evolventa с лицензиями рядом. Объявления @font-face —
// из design/tokens.toml (семейства, веса, начертание); ставятся одним <style> при запуске консоли.
import bebasLatin from "@fontsource/bebas-neue/files/bebas-neue-latin-400-normal.woff2";
import bebasLatinExt from "@fontsource/bebas-neue/files/bebas-neue-latin-ext-400-normal.woff2";
import bebasRanges from "@fontsource/bebas-neue/unicode.json";
import evolventaRegular from "./fonts/evolventa/Evolventa-Regular.woff2";
import evolventaBold from "./fonts/evolventa/Evolventa-Bold.woff2";

import { fonts, tokens } from "./theme";

// Bebas Neue — единственное начертание (Bold по брендбуку; в Google Fonts и @fontsource идёт как 400).
// Объявляем файл на вес из токенов (700), чтобы браузер не синтезировал жирный; unicode-range — из
// данных пакета (кириллицы в Bebas Neue нет — её берёт fallback на текстовый шрифт).
const subsets = bebasRanges as Record<string, string>;
const bebasFiles = { latin: bebasLatin, "latin-ext": bebasLatinExt } as const;
const headingFaces = (Object.keys(bebasFiles) as (keyof typeof bebasFiles)[])
  .map(
    (subset) =>
      `@font-face{font-family:"${tokens.fonts.heading.family}";font-style:${tokens.fonts.heading.style};` +
      `font-weight:${tokens.fonts.heading.weights[0]};src:url(${bebasFiles[subset]}) format("woff2");` +
      `unicode-range:${subsets[subset]};}`,
  )
  .join("");

// Evolventa: веса [fonts.text] по порядку — файлы Regular и Bold из src/fonts/evolventa.
const textFiles = [evolventaRegular, evolventaBold];
const textFaces = tokens.fonts.text.weights
  .map(
    (weight, i) =>
      `@font-face{font-family:"${tokens.fonts.text.family}";font-style:${tokens.fonts.text.style};` +
      `font-weight:${weight};src:url(${textFiles[i]}) format("woff2");}`,
  )
  .join("");

// Заголовки (Typography.Title, шапки карточек и окон) — шрифт заголовков из токенов.
const headings = `h1.ant-typography,h2.ant-typography,h3.ant-typography,h4.ant-typography,h5.ant-typography,` +
  `.ant-card-head-title,.ant-modal-title{font-family:${fonts.heading};font-weight:${tokens.fonts.heading.weights[0]};}`;

let installed = false;

/** Ставит @font-face и шрифт заголовков одним <style>; вызывается один раз при запуске консоли. */
export function installFonts(): void {
  if (installed || typeof document === "undefined") return;
  installed = true;
  const style = document.createElement("style");
  style.id = "thepost-fonts";
  style.textContent = headingFaces + textFaces + headings;
  document.head.append(style);
}
