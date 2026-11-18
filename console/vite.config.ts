import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

// Консоль раздаётся ролью admin под /console/ (ADM-15); узел разработчика — docs/DEV.md, адрес — THEPOST_ADMIN.
// Admin API слушает только TLS: сертификат узла проверяется, его CA — в NODE_EXTRA_CA_CERTS (README).
// Фирменный стиль (UI-19) читается из ../design при сборке и в тестах:
//   - design/tokens.toml — прямым импортом `?raw` (server.fs.allow пускает файлы вне корня консоли);
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
  base: "/console/",
  plugins: [designAssets(), react()],
  build: { outDir: "dist", sourcemap: false },
  server: {
    fs: { allow: [repo] },
    proxy: { "/api": { target: process.env.THEPOST_ADMIN ?? "https://127.0.0.1:8443", secure: true } },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["src/test-setup.ts"],
    testTimeout: 20000,
    // Один экземпляр react-router у теста и у привязок Refine.
    server: { deps: { inline: [/@refinedev/] } },
  },
});
