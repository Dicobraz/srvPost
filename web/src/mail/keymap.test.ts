// Хоткеи (WEB-03): one-modifier схема из DESIGN.md Postman — Ctrl+буква/цифра = команда, голые —
// навигация; клавиши физические (event.code) — раскладка RU/EN не мешает; в поле ввода буквы остаются вводу.
import { expect, test } from "vitest";

import { handleMailKeydown, KEYMAP_HINTS, type MailHotkeyActions } from "./keymap";

/** Записывающие действия: какие команды вызывались. */
function actions(): { act: MailHotkeyActions; calls: string[] } {
  const calls: string[] = [];
  const act: MailHotkeyActions = {
    nextMessage: () => calls.push("next"),
    prevMessage: () => calls.push("prev"),
    openSelected: () => calls.push("open"),
    categorize: (n) => calls.push(`cat${n}`),
    markRead: () => calls.push("read"),
    markUnread: () => calls.push("unread"),
    deleteSelected: () => calls.push("delete"),
    archiveSelected: () => calls.push("archive"),
    reply: () => calls.push("reply"),
    replyAll: () => calls.push("replyAll"),
    forward: () => calls.push("forward"),
    compose: () => calls.push("compose"),
    focusNextPanel: (backward) => calls.push(backward ? "focusPrev" : "focusNext"),
    focusFolders: () => calls.push("focusFolders"),
    escape: () => calls.push("escape"),
    openPalette: () => calls.push("palette"),
    findNext: () => calls.push("findNext"),
    findPrev: () => calls.push("findPrev"),
    takeSelected: () => calls.push("take"),
    remindSelected: () => calls.push("remind"),
  };
  return { act, calls };
}

/** Клавиатурное событие по физическому коду (как в браузере: RU/EN — один code). */
function key(code: string, mods: { ctrl?: boolean; shift?: boolean } = {}, target?: EventTarget): KeyboardEvent {
  const event = new KeyboardEvent("keydown", {
    code,
    ctrlKey: mods.ctrl ?? false,
    shiftKey: mods.shift ?? false,
    bubbles: true,
    cancelable: true,
  });
  Object.defineProperty(event, "target", { value: target ?? document.body });
  return event;
}

test("ответы и команды — Ctrl+буква (заглушки страницы), без Shift — ответ, с Shift — всем", () => {
  const { act, calls } = actions();
  expect(handleMailKeydown(key("KeyR", { ctrl: true }), act)).toBe(true);
  expect(handleMailKeydown(key("KeyR", { ctrl: true, shift: true }), act)).toBe(true);
  expect(handleMailKeydown(key("KeyF", { ctrl: true }), act)).toBe(true);
  expect(handleMailKeydown(key("KeyQ", { ctrl: true }), act)).toBe(true);
  expect(handleMailKeydown(key("KeyU", { ctrl: true }), act)).toBe(true);
  expect(handleMailKeydown(key("KeyN", { ctrl: true }), act)).toBe(true);
  expect(calls).toEqual(["reply", "replyAll", "forward", "read", "unread", "compose"]);
});

test("Ctrl+1..3 — разделы приложения (не категория); категории — голые 1–9", () => {
  const { act, calls } = actions();
  expect(handleMailKeydown(key("Digit1", { ctrl: true }), act)).toBe(false);
  expect(calls).toEqual([]);
  expect(handleMailKeydown(key("Digit3"), act)).toBe(true);
  expect(handleMailKeydown(key("Digit9"), act)).toBe(true);
  expect(calls).toEqual(["cat3", "cat9"]);
});

test("навигация голыми клавишами: J/K и стрелки, Enter, Del, Backspace, F6, Esc", () => {
  const { act, calls } = actions();
  expect(handleMailKeydown(key("KeyJ"), act)).toBe(true);
  expect(handleMailKeydown(key("KeyK"), act)).toBe(true);
  expect(handleMailKeydown(key("ArrowDown"), act)).toBe(true);
  expect(handleMailKeydown(key("ArrowUp"), act)).toBe(true);
  expect(handleMailKeydown(key("Enter"), act)).toBe(true);
  expect(handleMailKeydown(key("Delete"), act)).toBe(true);
  expect(handleMailKeydown(key("Backspace"), act)).toBe(true);
  expect(handleMailKeydown(key("F6", { shift: true }), act)).toBe(true);
  expect(handleMailKeydown(key("Escape"), act)).toBe(true);
  expect(calls).toEqual(["next", "prev", "next", "prev", "open", "delete", "archive", "focusPrev", "escape"]);
});

test("в поле ввода голые клавиши остаются вводу; Ctrl-команды действуют и там", () => {
  const { act, calls } = actions();
  const input = document.createElement("input");
  expect(handleMailKeydown(key("KeyJ", {}, input), act)).toBe(false);
  expect(handleMailKeydown(key("Enter", {}, input), act)).toBe(false);
  expect(handleMailKeydown(key("KeyR", { ctrl: true }, input), act)).toBe(true);
  expect(calls).toEqual(["reply"]);
});

test("Alt в схеме не используется; таблица клавиш для подсказок — из PARITY", () => {
  const { act, calls } = actions();
  expect(handleMailKeydown(key("KeyJ", {}, document.body), act)).toBe(true);
  void calls;
  const altEvent = key("KeyR", { ctrl: true });
  void altEvent;
  // Alt-схемы нет: с Alt обработчик не трогает команды (в keymap — ранний выход).
  const withAlt = new KeyboardEvent("keydown", { code: "KeyR", ctrlKey: false, altKey: true, cancelable: true });
  expect(handleMailKeydown(withAlt, act)).toBe(false);
  expect(KEYMAP_HINTS.some((h) => h.keys === "1–9" && h.action === "Категория")).toBe(true);
});

test("WEB-05: Ctrl+K — палитра команд; F3/Shift+F3 — совпадения в письме", () => {
  const { act, calls } = actions();
  expect(handleMailKeydown(key("KeyK", { ctrl: true }), act)).toBe(true);
  expect(handleMailKeydown(key("F3"), act)).toBe(true);
  expect(handleMailKeydown(key("F3", { shift: true }), act)).toBe(true);
  expect(calls).toEqual(["palette", "findNext", "findPrev"]);
});

test("WEB-15: Ctrl+J — «Взять в работу», голая J — навигация по списку", () => {
  const { act, calls } = actions();
  expect(handleMailKeydown(key("KeyJ", { ctrl: true }), act)).toBe(true);
  expect(handleMailKeydown(key("KeyJ"), act)).toBe(true);
  expect(KEYMAP_HINTS.some((h) => h.keys === "Ctrl+J" && h.action === "Взять в работу")).toBe(true);
  expect(calls).toEqual(["take", "next"]);
});

test("WEB-19: Ctrl+. — «Напомнить…» (пикер напоминания), подсказка в таблице клавиш", () => {
  const { act, calls } = actions();
  expect(handleMailKeydown(key("Period", { ctrl: true }), act)).toBe(true);
  expect(KEYMAP_HINTS.some((h) => h.keys === "Ctrl+." && h.action === "Напомнить…")).toBe(true);
  expect(calls).toEqual(["remind"]);
});

test("WEB-05: F3 работает и в поле ввода (поиск не мешает навигации по совпадениям)", () => {
  const { act, calls } = actions();
  const input = document.createElement("input");
  expect(handleMailKeydown(key("F3", {}, input), act)).toBe(true);
  expect(handleMailKeydown(key("KeyJ", {}, input), act)).toBe(false);
  expect(calls).toEqual(["findNext"]);
  expect(KEYMAP_HINTS.some((h) => h.keys === "Ctrl+K" && h.action === "Палитра команд")).toBe(true);
  expect(KEYMAP_HINTS.some((h) => h.keys === "F3 / Shift+F3")).toBe(true);
});
