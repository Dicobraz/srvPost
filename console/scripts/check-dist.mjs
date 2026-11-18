// Проверка собранной консоли (UI-19, приёмка): в console/dist нет ссылок на внешние адреса — консоль
// работает без интернета (решение 119: шрифты и прочие ресурсы вшиты, CDN не используется нигде).
// Ищем http(s):// и протокольно-относительные адреса в текстовых файлах dist. Разрешены только
// строки, которые браузер не загружает: пространства имён XML (w3.org) и ссылки на документацию
// в сообщениях библиотек (например, подсказка antd про CSS Logical Properties).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dist = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");
const INERT = [/^https?:\/\/(www\.)?w3\.org\//, /^https?:\/\/developer\.mozilla\.org\//];
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
