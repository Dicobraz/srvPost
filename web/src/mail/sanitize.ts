/*
  Чтение чужого HTML (WEB-03, hostile input): DOMPurify + sandboxed iframe — письмо рендерится
  srcdoc-документом с `sandbox="allow-scripts allow-popups"` БЕЗ allow-same-origin: скриптов письма
  нет (DOMPurify снимает теги script и обработчики), свой мини-скрипт показывает предупреждение
  о подменённой ссылке при клике, CSS изолирован, сетевых запросов нет (CSP srcdoc-документа).
  Внешние картинки по умолчанию выключены — баннер «Внешние картинки скрыты · Загрузить /
  Всегда для домена» (opt-in на письмо/на домен отправителя — решение в localStorage).
  Spoofed-link: текст ссылки не совпадает с адресом — клик показывает адрес (target=_blank noopener).
*/
import DOMPurify from "dompurify";

/** Результат подготовки HTML письма: чистый srcdoc и сведения для полос над телом. */
export interface SanitizedHtml {
  /** Документ для `srcdoc` sandboxed iframe (со своим CSP и мини-скриптом кликов). */
  doc: string;
  /** Домены внешних картинок, скрытые баннером opt-in. */
  blockedImageHosts: string[];
  /** Подменённые ссылки: «текст ссылки» → настоящий адрес (полоса угрозы). */
  spoofedLinks: Array<{ text: string; href: string; domain: string }>;
}

/** Опции: разрешены ли внешние картинки (баннер — opt-in на письмо и на домен отправителя). */
export interface SanitizeOptions {
  allowImages: boolean;
}

/** Мини-скрипт srcdoc-документа: клик по подменённой ссылке — баннер с адресом (внутри iframe). */
const CLICK_GUARD = `
document.addEventListener("click", function (e) {
  var a = e.target.closest("a[data-spoofed]");
  if (!a) return;
  e.preventDefault();
  var bar = document.getElementById("__spoofbar");
  if (!bar) {
    bar = document.createElement("div");
    bar.id = "__spoofbar";
    bar.setAttribute("style", "position:sticky;top:0;z-index:9;background:#FFE6E3;color:#7A3430;padding:8px 12px;font:13px sans-serif;border-bottom:1px solid #C62828");
    document.body.insertBefore(bar, document.body.firstChild);
  }
  bar.textContent = "";
  var b = document.createElement("b");
  b.textContent = "Ссылка не совпадает с адресом: \\u00AB" + a.textContent + "\\u00BB ведёт на " + a.getAttribute("data-domain");
  bar.appendChild(b);
  var real = document.createElement("a");
  real.textContent = "Показать адрес";
  real.href = a.getAttribute("data-href");
  real.target = "_blank";
  real.rel = "noopener noreferrer";
  real.setAttribute("style", "margin-left:12px;color:#7A3430;font-weight:600");
  bar.appendChild(real);
}, true);
`;

/** Свой CSP srcdoc-документа: сети нет (кроме картинок по разрешению), стили — inline письма. */
function csp(allowImages: boolean): string {
  const img = allowImages ? "https: data: http:" : "data:";
  return [
    "default-src 'none'",
    `img-src ${img}`,
    "style-src 'unsafe-inline'",
    "script-src 'unsafe-inline'",
    "font-src data:",
    "form-action 'none'",
    "frame-src 'none'",
  ].join("; ");
}

/** Собрать srcdoc-документ письма: чистый HTML, CSP, подложка ссылок. */
function buildDoc(bodyHtml: string, allowImages: boolean): string {
  return `<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp(allowImages)}">
<meta name="color-scheme" content="light dark">
<style>
  body{margin:0;padding:0;font:14px/1.5 system-ui,sans-serif;color:#161616;background:transparent}
  a[data-spoofed]{outline:1px dashed #C62828;background:#FFE6E3;color:#7A3430}
  table{max-width:100%}
  img{max-width:100%}
</style>
<script>${CLICK_GUARD}</script></head><body>${bodyHtml}</body></html>`;
}

/** Домен адреса ссылки; отностительный/битый — null. База — origin приложения (same-origin),
 * чтобы в сборке не появлялось выдуманных внешних адресов (check-dist). */
function domainOf(href: string): string | null {
  try {
    return new URL(href, window.location.origin).hostname || null;
  } catch {
    return null;
  }
}

/** Несовпадение «текста и адреса» (spoofed-link): в тексте другой домен, чем в href. */
function isSpoofed(text: string, href: string): boolean {
  const domain = domainOf(href);
  if (!domain || !/^https?:/i.test(href)) return false;
  // Домены в тексте ссылки (клик-приманки: «открыть счёт» ведёт на чужой сайт).
  const found = text.match(/(?:[a-z0-9-]+\.)+[a-z]{2,}/gi);
  if (!found) return false;
  const target = domain.toLowerCase();
  return !found.some((f) => {
    const host = f.toLowerCase().replace(/^www\./, "");
    const real = target.replace(/^www\./, "");
    return host === real || host.endsWith("." + real) || real.endsWith("." + host);
  });
}

/** DOMPurify конфигурация: письмо — документ для чтения, не интерактивный (формы/скрипты — долой). */
const PURIFY_CONFIG: Parameters<typeof DOMPurify.sanitize>[1] = {
  FORBID_TAGS: ["script", "style", "link", "meta", "iframe", "object", "embed", "form", "input", "button", "base"],
  FORBID_ATTR: ["srcset"],
  ADD_ATTR: ["target", "rel"],
  ALLOW_DATA_ATTR: false,
  WHOLE_DOCUMENT: false,
};

/** Подготовка HTML письма: санитайзер → картинки (opt-in) → ссылки (spoofed) → srcdoc. */
export function sanitizeEmailHtml(html: string, options: SanitizeOptions): SanitizedHtml {
  const clean = DOMPurify.sanitize(html, PURIFY_CONFIG);
  // Контейнер — обычный div: разметка уже прошла санитайзер (скриптов нет), innerHTML не исполняет.
  const root = document.createElement("div");
  root.innerHTML = clean;

  const blockedImageHosts = new Set<string>();
  if (!options.allowImages) {
    // Внешние картинки скрыты: адресные — прочь (banнер — opt-in), inline data: — можно.
    for (const img of [...root.querySelectorAll("img")]) {
      const src = img.getAttribute("src") ?? "";
      // startsWith вместо regex с экранированным слешем: в сборке не появляется «//i.test»,
      // которое check-dist принимает за протокол-относительный адрес.
      if (src.toLowerCase().startsWith("data:image/")) continue;
      try {
        const url = new URL(src, window.location.origin);
        if (/^https?:$/i.test(url.protocol)) {
          blockedImageHosts.add(url.hostname);
          const placeholder = document.createElement("span");
          placeholder.setAttribute("data-img-blocked", url.hostname);
          placeholder.setAttribute(
            "style",
            "display:inline-block;min-width:120px;min-height:32px;border:1px solid #BAC1C6;border-radius:4px;color:#5F6B78;font:12px sans-serif;padding:8px 10px;vertical-align:middle",
          );
          placeholder.textContent = `[Картинка скрыта: ${url.hostname}]`;
          img.replaceWith(placeholder);
        }
      } catch {
        img.remove();
      }
    }
  }

  // Ссылки: внешний адрес — target=_blank + noopener; несовпадение текста — предупреждение при клике.
  const spoofedLinks: Array<{ text: string; href: string; domain: string }> = [];
  for (const a of [...root.querySelectorAll("a[href]")]) {
    const href = a.getAttribute("href") ?? "";
    if (/^javascript:/i.test(href)) {
      a.removeAttribute("href");
      continue;
    }
    if (!/^https?:/i.test(href)) continue; // mailto: и якоря — без изменений
    a.setAttribute("target", "_blank");
    a.setAttribute("rel", "noopener noreferrer");
    const text = (a.textContent ?? "").trim();
    if (isSpoofed(text, href)) {
      const domain = domainOf(href) ?? "";
      a.setAttribute("data-spoofed", "1");
      a.setAttribute("data-href", href);
      a.setAttribute("data-domain", domain);
      // Обычный href снимаем: пока пользователь не уточнил адрес, перехода нет.
      a.removeAttribute("href");
      spoofedLinks.push({ text, href, domain });
    }
  }

  return {
    doc: buildDoc(root.innerHTML, options.allowImages),
    blockedImageHosts: [...blockedImageHosts],
    spoofedLinks,
  };
}

/** Тело text/plain — безопасный <pre> (fallback и текстовые письма). */
export function plainTextHtml(text: string): string {
  const pre = document.createElement("pre");
  pre.textContent = text;
  pre.setAttribute("style", "white-space:pre-wrap;word-break:break-word;font:14px/1.5 ui-monospace,monospace;margin:0");
  return pre.outerHTML;
}

/** srcdoc для простого тела (текст или уже sanitized html) — общий вход чтения. */
export function buildBodyDoc(bodyHtml: string, allowImages: boolean): string {
  return buildDoc(bodyHtml, allowImages);
}

/** Домены, для которых пользователь разрешил картинки («Всегда для домена», localStorage). */
const IMAGES_KEY = "thepost-webmail-images";

export function allowedImageDomains(): string[] {
  try {
    const raw = localStorage.getItem(IMAGES_KEY);
    const list = raw ? (JSON.parse(raw) as unknown) : [];
    return Array.isArray(list) ? list.filter((x): x is string => typeof x === "string") : [];
  } catch {
    return [];
  }
}

export function allowImagesForDomain(domain: string): void {
  try {
    const list = allowedImageDomains();
    if (!list.includes(domain)) list.push(domain);
    localStorage.setItem(IMAGES_KEY, JSON.stringify(list));
  } catch {
    // Приватный режим без localStorage: разрешение живёт до перезагрузки.
  }
}

export function areImagesAllowedFor(senderDomain: string): boolean {
  return allowedImageDomains().includes(senderDomain);
}
