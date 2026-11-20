// Вставка из Word (WEB-04): pastedown — мусор Office вычищен, структура сохранена (приёмка
// карточки: «письмо с таблицей из Word читается в Postman и Outlook без развала вёрстки»).
import { describe, expect, test } from "vitest";

import { htmlToText, looksLikeWordHtml, sanitizeComposeHtml } from "./word-paste";

/** Кусок HTML, как его кладёт в буфер Word (упрощённо, с mso-стилями и списками-абзацами). */
const WORD_HTML = `<!--[if gte mso 9]><xml><w:WordDocument></w:WordDocument></xml><![endif]-->
<html xmlns:o="urn:schemas-microsoft-com:office:office">
<body>
<!--StartFragment-->
<p class="MsoNormal" style="margin:0cm;mso-line-height-alt:10.0pt"><span style='font-size:11.0pt;font-family:"Calibri",sans-serif;mso-fareast-font-family:Calibri'>Добрый день, Ольга!</span></p>
<p class="MsoNormal" style="margin:0cm;mso-spacerun:yes">&nbsp;</p>
<p class="MsoListParagraph" style="text-indent:-18.0pt;mso-list:l0 level1 lfo1"><span style="font-family:Symbol">·</span>срок поставки — <b>не позднее 15.12.2026</b></p>
<p class="MsoListParagraph" style="text-indent:-18.0pt;mso-list:l0 level1 lfo1"><span style="font-family:Symbol">·</span>штраф 0,1 % за день просрочки</p>
<table class="MsoTableGrid" border="1" cellspacing="0" cellpadding="0" style="border-collapse:collapse">
 <tr><td width="301" valign="top" style="width:150.0pt;border:solid #BAC1C6 1.0pt;padding:0cm 5.4pt">Позиция</td><td width="301" valign="top" style="border:solid #BAC1C6 1.0pt">Сумма, ₽</td></tr>
 <tr><td colspan="2" style="border:solid #BAC1C6 1.0pt">Кабель ВВГнг 3×2,5 — <b>115 680,00</b></td></tr>
</table>
<p class="MsoNormal"><o:p>&nbsp;</o:p></p>
<!--EndFragment-->
</body></html>`;

test("Word распознаётся по приметам Office", () => {
  expect(looksLikeWordHtml(WORD_HTML)).toBe(true);
  expect(looksLikeWordHtml("<p>Обычный текст</p>")).toBe(false);
});

test("мусор Office вычищен: mso-стили, классы, conditional comments, o:p", () => {
  const clean = sanitizeComposeHtml(WORD_HTML, { word: true });
  expect(clean).not.toContain("mso-");
  expect(clean).not.toContain("MsoNormal");
  expect(clean).not.toContain("urn:schemas-microsoft-com");
  expect(clean).not.toContain("<o:p");
  expect(clean).not.toContain("<!--[if");
  expect(clean).not.toContain("font-family");
  expect(clean).not.toContain("style=");
});

test("структура сохранена: жирность, таблица, colspan", () => {
  const clean = sanitizeComposeHtml(WORD_HTML, { word: true });
  expect(clean).toContain("<b>не позднее 15.12.2026</b>");
  expect(clean).toContain("<table");
  expect(clean).toContain("<tr>");
  expect(clean).toContain('colspan="2"');
  expect(clean).toContain("Кабель ВВГнг 3×2,5");
});

test("списки Word (MsoListParagraph с буллетами) становятся ul/li", () => {
  const clean = sanitizeComposeHtml(WORD_HTML, { word: true });
  expect(clean).toContain("<ul>");
  expect(clean).toContain("<li>срок поставки — <b>не позднее 15.12.2026</b></li>");
  expect(clean).toContain("<li>штраф 0,1 % за день просрочки</li>");
  // Абзацы-списки разобраны: их больше нет.
  expect(clean).not.toContain("MsoListParagraph");
});

test("пустые абзацы-разделители Word убраны, свои пустые абзацы обычного HTML остаются", () => {
  const word = sanitizeComposeHtml(WORD_HTML, { word: true });
  expect(word).not.toContain("mso-spacerun");
  const own = sanitizeComposeHtml("<p>Строка</p><p></p><p>Ещё</p>");
  expect(own).toContain("<p>Строка</p>");
  expect(own).toContain("<p>Ещё</p>");
});

test("скрипты и обработчики вставки снимаются всегда", () => {
  const clean = sanitizeComposeHtml('<p onclick="evil()">текст<script>alert(1)</script></p><a href="javascript:alert(1)">ссылка</a>');
  expect(clean).not.toContain("script");
  expect(clean).not.toContain("onclick");
  expect(clean).not.toContain("javascript:");
});

test("нумерованные списки Word с цифрами становятся ol/li", () => {
  const numbered = `<p class="MsoListParagraph" style="mso-list:l1 level1">1. Первое</p><p class="MsoListParagraph" style="mso-list:l1 level1">2. Второе</p>`;
  const clean = sanitizeComposeHtml(numbered, { word: true });
  expect(clean).toContain("<ol>");
  expect(clean).toContain("<li>Первое</li>");
  expect(clean).toContain("<li>Второе</li>");
});

test("htmlToText: текст без разметки, одним пробелом", () => {
  expect(htmlToText("<p>Привет</p><p>мир</p>")).toBe("Привет мир");
});
