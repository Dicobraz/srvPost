// Подсветка совпадений в письме (WEB-05, F3): скрипт валиден как JS, встраивается в srcdoc
// только с терма́ми поиска, состояние и команды — постмессаджами (iframe без same-origin).
import { expect, test } from "vitest";

import { highlightScript, isHlState, sendHlCommand } from "./highlight";
import { buildBodyDoc, sanitizeEmailHtml } from "./sanitize";

test("highlightScript: генерирует синтаксически валидный JS с терма́ми как данными", () => {
  const script = highlightScript(["квартал", "rdfhnfk", "a+b"]);
  // Компиляция без исполнения (document внутри — только при запуске в iframe).
  expect(() => new Function(script)).not.toThrow();
  expect(script.includes('"квартал"')).toBe(true);
  expect(script.includes('"a+b"')).toBe(true); // спецсимволы — данные (JSON), не разбор скрипта
  expect(script.includes("hl-next")).toBe(true);
});

test("srcdoc: термы поиска — скрипт и стиль подсветки внутри; без термов — нет", () => {
  const withHl = sanitizeEmailHtml("<p>Отчёт готов</p>", { allowImages: false, highlight: ["отчёт"] });
  expect(withHl.doc).toContain("search-hit");
  expect(withHl.doc).toContain('"отчёт"');
  const withoutHl = sanitizeEmailHtml("<p>Отчёт готов</p>", { allowImages: false });
  expect(withoutHl.doc).not.toContain("search-hit");
  // Текстовый путь (buildBodyDoc) — тот же скрипт для <pre>-писем.
  const plain = buildBodyDoc("<pre>квартал</pre>", false, ["квартал"]);
  expect(plain).toContain("hl-next");
});

test("isHlState и sendHlCommand: только сообщения hl-state, команда — в contentWindow", () => {
  expect(isHlState({ type: "hl-state", count: 3, index: 1 })).toBe(true);
  expect(isHlState({ type: "hl-next" })).toBe(false);
  expect(isHlState(null)).toBe(false);
  let posted: unknown = null;
  const frame = { contentWindow: { postMessage: (data: unknown) => (posted = data) } } as unknown as HTMLIFrameElement;
  sendHlCommand(frame, "hl-prev");
  expect(posted).toEqual({ type: "hl-prev" });
  sendHlCommand(null, "hl-next"); // нет iframe — не падает
});
