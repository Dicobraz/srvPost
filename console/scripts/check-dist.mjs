// Проверка собранной консоли (UI-19, приёмка): в console/dist нет ссылок на внешние адреса — консоль
// работает без интернета (решение 119: шрифты и прочие ресурсы вшиты, CDN не используется нигде).
// Ищем http(s):// и протокольно-относительные адреса в текстовых файлах dist. Разрешены только
// строки, которые браузер не загружает: пространства имён XML (w3.org) и подсказки в сообщениях
// библиотек — ссылки на документацию и исходники (react.dev, react-router, refine, rolldown,
// github.com, fb.me, MDN), петлевой адрес — база разбора URL в oidc-client-ts — и адрес телеметрии
// refine (сама телеметрия выключена: disableTelemetry: true в App.tsx, строка остаётся в сборке).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dist = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");
const INERT = [
  /^https?:\/\/(www\.)?w3\.org\//, // пространства имён XML/SVG
  /^https?:\/\/developer\.mozilla\.org\//, // MDN в подсказках сообщений
  /^https?:\/\/react\.dev\//, // документация React в сообщениях об ошибках
  /^https?:\/\/rolldown\.rs\//, // документация bundler-а в сообщении CJS-обёртки
  /^https?:\/\/reactrouter\.com\//, // документация react-router в сообщениях
  /^https?:\/\/refine\.dev\/docs\//, // документация refine в сообщениях об ошибках
  /^https?:\/\/telemetry\.refine\.dev\//, // телеметрия refine выключена (App.tsx), строка не выполняется
  /^https?:\/\/(www\.)?github\.com\//, // ссылки на исходники и полифилы в сообщениях (react-router, react-markdown)
  /^https?:\/\/fb\.me\//, // подсказки prop-types в предупреждениях
  /^https?:\/\/(?:127\.0\.0\.1|localhost)(?::\d+)?(?:[/?#]|$)/, // петлевой адрес — база `new URL(url, "http://127.0.0.1")` в oidc-client-ts
];
const TEXT = /\.(html|js|mjs|css|svg|txt|json|webmanifest)$/;

const files = [];
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path);
    else if (TEXT.test(name)) files.push(path);
  }
};

walk(dist);
const bad = [];
for (const file of files) {
  // Комментарии (в т.ч. лицензии библиотек с адресами) — не выполняются, вырезаем.
  const text = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\//g, "");
  for (const match of text.matchAll(/(?:https?:)?\/\/[^\s"'`<>()]+/g)) {
    const url = match[0];
    // `//` из кода (деление, пустая строка пути) адресом не считаем: нужен вид домена.
    if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+(:\d+)?([/?#]|$)/i.test(url.replace(/^(https?:)?\/\//, ""))) continue;
    if (INERT.some((re) => re.test(url))) continue;
    bad.push(`${file.slice(dist.length + 1)}: ${url}`);
  }
}

if (bad.length > 0) {
  console.error(`Внешние адреса в сборке консоли (должна работать без интернета):\n${bad.join("\n")}`);
  process.exit(1);
}
console.log(`Внешних адресов в dist нет (просмотрено файлов: ${files.length}).`);
