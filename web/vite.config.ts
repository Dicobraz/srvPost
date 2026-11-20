import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

// Веб-клиент раздаётся слушателем JMAP под /mail/ (WEB-01, решение 2026-11-20); узел разработчика —
// docs/DEV.md, адрес — THEPOST_JMAP. JMAP — same-origin: клиент и API за одним портом узла.
// Фирменный стиль (решение 119) читается из ../design при сборке и в тестах, как в веб-консоли:
//   - design/tokens.toml — прямым импортом `?raw` (server.fs.allow пускает файлы вне корня клиента);
//   - design/*.svg — виртуальным модулем `design/<файл>` (содержимое файла строкой): прямой импорт .svg
//     вне корня маршрутизация активов не разрешает в тестах.
const repo = resolve(fileURLToPath(new URL("..", import.meta.url)));
const VIRTUAL = "\0thepost-design/";

/** Виртуальные модули `design/<имя>` — содержимое файла из ../design строкой (знак IT TASK, UI-19). */
function designAssets(): Plugin {
  return {
    name: "thepost-design-assets",
    resolveId(source) {
      if (source.startsWith("design/")) return VIRTUAL + source.slice("design/".length);
    },
    load(id) {
      if (id.startsWith(VIRTUAL))
        return `export default ${JSON.stringify(readFileSync(resolve(repo, "design", id.slice(VIRTUAL.length)), "utf8"))}`;
    },
  };
}

export default defineConfig({
  base: "/mail/",
  plugins: [designAssets(), react()],
  build: { outDir: "dist", sourcemap: false },
  server: {
    fs: { allow: [repo] },
    proxy: {
      // Конфигурация входа (WEB-02) — от узла, как и JMAP: у разработчика SPA один источник.
      "/mail/config.json": { target: process.env.THEPOST_JMAP ?? "https://127.0.0.1:443", secure: true },
      "/jmap": { target: process.env.THEPOST_JMAP ?? "https://127.0.0.1:443", secure: true },
      "/.well-known/jmap": { target: process.env.THEPOST_JMAP ?? "https://127.0.0.1:443", secure: true },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["src/test-setup.ts"],
    testTimeout: 20000,
  },
});
