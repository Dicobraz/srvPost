// Приёмка UI-19: тема строится из design/tokens.toml (своих цветов в коде нет), знаки состояний (● ▲ ×)
// стоят рядом с цветом статуса, шрифты объявляются из токенов и без внешних адресов.
import { render } from "@testing-library/react";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";

import { StatusTag } from "./components/status";
import { installFonts } from "./fonts";
import { brandTheme, fonts, modeColors, signs, tokens, type Branding } from "./theme";

test("тема antd строится из design/tokens.toml: роли режима — значения файла", () => {
  for (const dark of [false, true]) {
    const token = brandTheme(dark).token ?? {};
    const c = dark ? tokens.mode.dark : tokens.mode.light;
    // Акцент (sel), основной (frameA), текст-акцент (titleA), состояния, фоны и текст.
    expect(token.colorPrimary).toBe(c.sel);
    expect(token.colorInfo).toBe(c.frameA);
    expect(token.colorLink).toBe(c.titleA);
    expect(token.colorSuccess).toBe(c.ok);
    expect(token.colorWarning).toBe(c.warn);
    expect(token.colorError).toBe(c.err);
    expect(token.colorText).toBe(c.text);
    expect(token.colorTextSecondary).toBe(c.muted);
    expect(token.colorBgLayout).toBe(c.screen);
    expect(token.colorBgContainer).toBe(c.panel);
    expect(token.colorBorder).toBe(c.frame);
    expect(token.fontFamily).toContain(tokens.fonts.text.family);
  }
  // Светлая и тёмная темы различаются фоном и текстом, шрифт заголовков — из [fonts.heading].
  expect(brandTheme(true).token?.colorBgLayout).not.toBe(brandTheme(false).token?.colorBgLayout);
  expect(fonts.heading).toContain(tokens.fonts.heading.family);
});

test("тема из действующего брендинга сервера: заданные роли заменяют токены, незаданные и без брендинга — токены (UI-22)", () => {
  const branding: Branding = {
    name: "Кофе",
    logo: { url: "/api/v1/public/branding/logo/ab" },
    light: { sel: "#123456", text: "#234567" },
    dark: { sel: "#345678" },
  };
  const light = brandTheme(false, branding).token ?? {};
  expect(light.colorPrimary).toBe("#123456"); // sel — главная кнопка, выделение
  expect(light.colorText).toBe("#234567");
  expect((brandTheme(true, branding).token ?? {}).colorPrimary).toBe("#345678");
  // Незаданные роли остаются от токенов; бренда нет — тема целиком из токенов (UI-19).
  expect(light.colorBgLayout).toBe(tokens.mode.light.screen);
  expect(brandTheme(false).token?.colorPrimary).toBe(tokens.mode.light.sel);
  expect(modeColors(true, branding).sel).toBe("#345678");
});

test("знаки состояний из [signs]: у нормы, внимания и ошибки разные непустые знаки", () => {
  const values = Object.values(signs);
  expect(values.every((s) => s.length > 0)).toBe(true);
  expect(new Set(values).size).toBe(values.length);
});

test("статус: знак роли рядом с текстом, цвет — роль светлой темы", () => {
  const labels = { ok: "норма", warn: "внимание", err: "ошибка" } as const;
  const { container } = render(
    <>
      {(Object.keys(labels) as (keyof typeof labels)[]).map((role) => (
        <StatusTag key={role} role={role}>
          {labels[role]}
        </StatusTag>
      ))}
    </>,
  );
  const tags = [...container.querySelectorAll(".ant-tag")];
  expect(tags.map((t) => t.textContent)).toEqual(
    (Object.keys(labels) as (keyof typeof labels)[]).map((role) => `${signs[role]} ${labels[role]}`),
  );
  // Цвет — роль светлой темы из токенов (jsdom может отдать как hex или rgb — принимаем оба).
  const rgb = (hex: string) =>
    `rgb(${Number.parseInt(hex.slice(1, 3), 16)}, ${Number.parseInt(hex.slice(3, 5), 16)}, ${Number.parseInt(hex.slice(5, 7), 16)})`;
  for (const [i, role] of (Object.keys(labels) as (keyof typeof labels)[]).entries())
    expect([tokens.mode.light[role], rgb(tokens.mode.light[role])]).toContain((tags[i] as HTMLElement).style.color);
});

test("в коде консоли нет своих цветов: шестнадцатеричные литералы — только в design/tokens.toml", () => {
  const src = dirname(fileURLToPath(import.meta.url));
  const hex = /#[0-9a-fA-F]{6}\b/;
  const check = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name);
      if (statSync(path).isDirectory()) check(path);
      else if (/\.(ts|tsx)$/.test(name) && !/\.test\./.test(name) && name !== "schema.d.ts")
        expect(readFileSync(path, "utf8").match(hex), `${path}: цвет вне design/tokens.toml`).toBeNull();
    }
  };
  check(src);
});

test("шрифты: @font-face из токенов, файлы сборки — без внешних адресов", () => {
  installFonts();
  const css = document.getElementById("thepost-fonts")?.textContent ?? "";
  expect(css).toContain(`font-family:"${tokens.fonts.heading.family}"`);
  expect(css).toContain(`font-family:"${tokens.fonts.text.family}"`);
  expect(css).toContain(`font-weight:${tokens.fonts.heading.weights[0]}`);
  expect(css.match(/format\("woff2"\)/g)).toHaveLength(4); // Bebas Neue latin + latin-ext, Evolventa 400 и 700.
  expect(css).not.toMatch(/https?:\/\//); // файлы из сборки, CDN не используется (решение 119)
  expect(css).not.toMatch(/url\((?:https?:)?\/\//);
  expect(css).toContain(`font-family:${fonts.heading}`); // заголовки — шрифтом заголовков
});
