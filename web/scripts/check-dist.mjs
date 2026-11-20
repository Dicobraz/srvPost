// Проверка собранного веб-клиента (приёмка WEB-01): в web/dist нет ссылок на внешние адреса — клиент
// работает без интернета (решение 119: ресурсы вшиты, CDN не используется нигде). Ищем http(s):// и
// протокольно-относительные адреса в текстовых файлах dist. Разрешены только строки, которые браузер
// не загружает: пространства имён XML и подсказки в сообщениях библиотек — ссылки на документацию и
// исходники (react.dev, react-router, rolldown, github.com, fb.me, MDN).
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
  /^https?:\/\/(www\.)?github\.com\//, // ссылки на исходники и полифилы в сообщениях (react-router, react-markdown)
  /^https?:\/\/fb\.me\//, // подсказки prop-types в предупреждениях
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
  console.error(`Внешние адреса в сборке веб-клиента (должен работать без интернета):\n${bad.join("\n")}`);
  process.exit(1);
}
console.log(`Внешних адресов в dist нет (просмотрено файлов: ${files.length}).`);
