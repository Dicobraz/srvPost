/*
  Вставка из Word и чужого HTML (WEB-04): pastedown через DOMPurify — мусор Office вычищается,
  структура сохраняется. Word кладёт в буфер HTML с mso-стилями, conditional comments
  (<![if !vml]>), списками из <p class="MsoListParagraph"> и таблицами с <o:p> — в письме от
  этого разваливается вёрстка (приёмка карточки: «письмо с таблицей из Word читается в Postman
  и Outlook без развала вёрстки»). Подход — cleanWordPastedHTML как у CKEditor/TinyMCE, но на
  DOMPurify (уже в клиенте, WEB-03): 1) вырезать conditional comments и пустые абзацы-разделители,
  2) DOMPurify с разрешённым набором тегов (таблицы, списки, начертания, ссылки, картинки),
  3) снять style/class/width-мусор, оставив осмысленное (colspan/rowspan, выравнивание),
  4) абзацы-списки Word (MsoListParagraph с символом-буллетом) — в настоящие ul/ol/li.
  Этот же пайплайн идёт телом письма при отправке — наружу уходит чистый HTML.
*/
import DOMPurify from "dompurify";

/** Признаки Word/Office HTML: пространства имён, классы, фрагментный комментарий. */
export function looksLikeWordHtml(html: string): boolean {
  return /urn:schemas-microsoft-com:office|MsoNormal|<!--StartFragment-->|class="Mso/i.test(html);
}

/**
 * Теги, допустимые в письме: структура (абзацы, заголовки, таблицы, списки), начертания,
 * ссылки и картинки (data: — логотипы подписи), цитата и разделитель. Цвета/шрифты письма
 * не переносим (mso-мусор, тёмная тема получателя читает структуру, не оформление).
 */
const ALLOWED_TAGS = [
  "p", "br", "div", "span", "h1", "h2", "h3", "h4", "h5", "h6",
  "b", "strong", "i", "em", "u", "s", "sub", "sup", "code", "pre",
  "ul", "ol", "li",
  "table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "colgroup", "col",
  "a", "img", "blockquote", "hr",
];

/** Атрибуты: структура таблиц и ссылки; выравнивание оставляем (осмысленное из Word). */
const ALLOWED_ATTR = ["href", "title", "alt", "src", "colspan", "rowspan", "start", "type", "align", "dir"];

/** Убрать conditional comments Word (<![if !vml]> … <![endif]>) — DOMPurify их выносит как текст. */
function stripConditionalComments(html: string): string {
  return html.replace(/<!--\[if[\s\S]*?<!\[endif\]-->/gi, "").replace(/<!--\[if[\s\S]*?\]>/gi, "");
}


/** Маркер списка в начале текста абзаца: буллет-символ Word или нумерация «1.». */
function listMarkerOf(text: string): "ul" | "ol" | null {
  const t = text.replace(/^[\s\u00a0]+/, "");
  if (/^[·•▪◦‣●∙◦○]/u.test(t)) return "ul";
  // Нумерация Word: «1.», «2)»; буквы «o)» и «a)» — вложенный уровень ol тоже годится.
  if (/^[a-z1-9][.)]\s+/i.test(t)) return "ol";
  return null;
}

/**
 * Содержимое пункта списка без маркера: маркер-спан Word (Symbol, ≤2 символов) убирается
 * целиком, нумерация в тексте — срезается; начертания (<b>) сохраняются.
 */
function listItemContent(p: Element): DocumentFragment {
  const frag = document.createDocumentFragment();
  let stripped = false;
  for (const node of [...p.childNodes]) {
    if (!stripped && node.nodeType === Node.ELEMENT_NODE) {
      const el = node as Element;
      const t = (el.textContent ?? "").trim();
      if (t.length <= 2 && /^[·•▪◦‣●∙◦○o]$|^[a-z1-9][.)]$/i.test(t)) continue; // маркер-спан целиком
      stripped = true;
      frag.append(el.cloneNode(true));
      continue;
    }
    if (!stripped && node.nodeType === Node.TEXT_NODE) {
      const raw = node.textContent ?? "";
      const text = raw.replace(/^[\s\u00a0]*(?:[·•▪◦‣●∙◦○]|[a-z1-9][.)]\s?)/u, "");
      if (text !== raw) stripped = true;
      if (text) frag.append(document.createTextNode(text));
      continue;
    }
    frag.append(node.cloneNode(true));
  }
  return frag;
}

/**
 * Списки Word: абзацы с символом-буллетом в тексте — в настоящие ul/ol на том же месте
 * документа (иначе получатель видит «плоские» абзацы вместо списка). Стиль/класс к этому
 * моменту уже сняты санитайзером — распознаём по маркеру в тексте.
 */
function rebuildWordLists(root: Element): void {
  const paragraphs = [...root.querySelectorAll("p")].filter(
    (p) => listMarkerOf(p.textContent ?? "") !== null,
  );
  for (let i = 0; i < paragraphs.length; ) {
    const tag = listMarkerOf(paragraphs[i].textContent ?? "");
    if (!tag) {
      i += 1;
      continue;
    }
    const list = document.createElement(tag);
    let j = i;
    while (j < paragraphs.length && listMarkerOf(paragraphs[j].textContent ?? "") === tag) {
      const li = document.createElement("li");
      li.append(listItemContent(paragraphs[j]));
      list.append(li);
      j += 1;
    }
    // Список встаёт на место первого абзаца группы, остальные убираются.
    paragraphs[i].replaceWith(list);
    for (let k = i + 1; k < j; k += 1) paragraphs[k].remove();
    i = j;
  }
}

/** Пустые абзацы Word-разделители (mso-spacerun, только &nbsp;) — между блоками вставляет пустоту. */
function isSpacerParagraph(p: Element): boolean {
  const style = p.getAttribute("style") ?? "";
  if (!/mso-spacerun\s*:\s*yes/i.test(style)) return false;
  return /^[ \u00a0]*$/.test(p.textContent ?? "");
}

/** Чистка DOM после санитайзера: пустые ссылки Word, разделители-спейсеры (только в Word-вставке). */
function cleanDom(root: Element, word: boolean): string {
  for (const el of [...root.querySelectorAll("*")]) {
    // Пустые ссылки Word ставит вокруг каждого фрагмента — снимаем, текст остаётся.
    if (el.tagName === "A" && !el.getAttribute("href")) el.replaceWith(...el.childNodes);
    if (word) {
      if (isSpacerParagraph(el)) {
        el.remove();
        continue;
      }
      // Абзац Word-разделитель страниц: пустой, без картинок и переносов.
      if (
        (el.tagName === "P" || el.tagName === "DIV") &&
        /^[ \u00a0]*$/.test(el.textContent ?? "") &&
        !el.querySelector("img,br")
      ) {
        el.remove();
      }
    }
  }
  return root.innerHTML;
}

/** Санитайзер тела письма и вставки (pastedown): DOMPurify + снятие Office-мусора. */
export function sanitizeComposeHtml(html: string, options: { word?: boolean } = {}): string {
  let source = stripConditionalComments(html);
  const word = options.word || looksLikeWordHtml(source);

  if (word) {
    // Полный документ Word (StartFragment/EndFragment) — берём тело фрагмента.
    const fragment = source.match(/<!--StartFragment-->([\s\S]*?)<!--EndFragment-->/i);
    if (fragment) source = fragment[1];
    source = source.replace(/<o:p[\s\S]*?<\/o:p>/gi, "").replace(/<w:[^>]*>|<\/w:[^>]*>/gi, "");
  }

  const clean = DOMPurify.sanitize(source, {
    ALLOWED_TAGS,
    ALLOWED_ATTR,
    ALLOW_DATA_ATTR: false,
    KEEP_CONTENT: true,
    WHOLE_DOCUMENT: false,
  });

  const root = document.createElement("div");
  root.innerHTML = clean;
  if (word) rebuildWordLists(root);
  return cleanDom(root, word);
}

/** Текст из HTML (для предупреждения «прилагаю» и поиска по черновику): блоки — с переносом. */
export function htmlToText(html: string): string {
  const root = document.createElement("div");
  root.innerHTML = html;
  // Абзацы и строки таблиц в textContent идут вплотную — разделяем переносом.
  for (const el of [...root.querySelectorAll("p, div, li, tr, h1, h2, h3, h4, h5, h6, blockquote")]) {
    el.before(document.createTextNode("\n"));
  }
  return (root.textContent ?? "").replace(/\s+/g, " ").trim();
}
