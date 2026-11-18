# Evolventa — текстовый шрифт консоли

Шрифт текста веб-консоли (UI-19, решение 119): `Evolventa` Regular (400) и Bold (700), формат `woff2`.
Геометрический гротеск с кириллицей на основе URW Gothic L.

- Источник: https://github.com/evolventa/evolventa (файлы `ttf/Evolventa-Regular.ttf`,
  `ttf/Evolventa-Bold.ttf`, копия от 2026-11; конвертация в `woff2` — fontTools, без изменений глифов).
- Лицензия — двойная, по выбору: GPL 2.0 (`LICENSE-GPL-2.0.txt`) или LPPL 1.3c+
  (`LICENSE-LPPL-1.3c.txt`); уведомление об авторских правах — в таблице имён самого файла шрифта.
- Копия в `woff2` пересобирается при смене версии: `python -m fontTools.ttLib.woff2 compress <ttf>`.
