// Санитайзер (WEB-03): чужой HTML — hostile input. DOMPurify + sandboxed iframe; скрипты и
// обработчики долой, внешние картинки — opt-in, подменённые ссылки — предупреждение.
import { afterEach, expect, test } from "vitest";

import {
  allowImagesForDomain,
  allowedImageDomains,
  areImagesAllowedFor,
  buildBodyDoc,
  plainTextHtml,
  sanitizeEmailHtml,
} from "./sanitize";

afterEach(() => {
  localStorage.clear();
});

test("скрипт и обработчики снимаются, разметка сохраняется", () => {
  const { doc } = sanitizeEmailHtml(
    `<p onclick="steal()">Привет</p><script>steal()</script><table><tr><td>1</td></tr></table>`,
    { allowImages: false },
  );
  expect(doc).toContain("<p>Привет</p>");
  expect(doc).not.toContain("steal"); // чужой скрипт и обработчик долой
  expect(doc).toContain("<table>");
  // Свой CSP внутри srcdoc-документа: сети нет, формы нет.
  expect(doc).toContain("default-src 'none'");
});

test("внешние картинки скрыты (opt-in): адрес заменён заглушкой, домены — для баннера", () => {
  const { doc, blockedImageHosts } = sanitizeEmailHtml(
    `<img src="https://track.example/pixel.gif"><img src="data:image/png;base64,AAA">`,
    { allowImages: false },
  );
  expect(doc).not.toContain("https://track.example/pixel.gif");
  expect(blockedImageHosts).toEqual(["track.example"]);
  expect(doc).toContain("data:image/png;base64"); // inline — можно
  expect(doc).toContain("Картинка скрыта");

  const allowed = sanitizeEmailHtml(`<img src="https://cdn.example/a.png">`, { allowImages: true });
  expect(allowed.doc).toContain("https://cdn.example/a.png");
  expect(allowed.blockedImageHosts).toEqual([]);
});

test("spoofed-link: текст не совпадает с адресом — href снят, адрес для полосы угрозы", () => {
  const { doc, spoofedLinks } = sanitizeEmailHtml(
    `<a href="https://vektor-pay.example/steal">открыть счёт на vektor.example</a>
     <a href="https://vektor.example/ok">vektor.example</a>
     <a href="mailto:a@x.test">письмо</a>`,
    { allowImages: false },
  );
  expect(spoofedLinks).toHaveLength(1);
  expect(spoofedLinks[0].domain).toBe("vektor-pay.example");
  expect(doc).toContain("data-spoofed");
  // Честные ссылки — target=_blank + noopener.
  expect(doc).toContain('target="_blank"');
  expect(doc).toContain('rel="noopener noreferrer"');
});

test("javascript: — прочь; srcdoc собирается с мини-скриптом кликов", () => {
  const { doc } = sanitizeEmailHtml(`<a href="javascript:steal()">x</a>`, { allowImages: false });
  expect(doc).not.toContain("javascript:");
  const full = buildBodyDoc("<p>текст</p>", false);
  expect(full).toContain("__spoofbar"); // click-guard внутри песочницы
  expect(full).toContain("Content-Security-Policy");
});

test("text/plain — безопасный <pre> с переносами", () => {
  const html = plainTextHtml("Привет\r\nВторая строка <b>не разметка</b>");
  expect(html).toContain("<pre");
  expect(html).toContain("&lt;b&gt;не разметка&lt;/b&gt;");
});

test("«Всегда для домена» — решение в localStorage", () => {
  expect(areImagesAllowedFor("vektor.example")).toBe(false);
  allowImagesForDomain("vektor.example");
  expect(allowedImageDomains()).toEqual(["vektor.example"]);
  expect(areImagesAllowedFor("vektor.example")).toBe(true);
});
