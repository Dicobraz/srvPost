// Напоминания (WEB-19): слова pm.due/pm.wait/pm.expire — как в Postman (S5-04: рядом общее слово
// и слово с датой и временем); группировка полосы и границы «сейчас» — на фиксированных часах
// (now = 20.11.2026, пятница, 10:00). Round-trip: патч → слова → тот же момент.
import { expect, test } from "vitest";

import {
  clearReminderKindPatch,
  clearRemindersPatch,
  fromInputDateTime,
  groupReminders,
  hasReminderWords,
  presetInWeek,
  presetTomorrow9,
  reminderDueText,
  reminderKindOf,
  reminderMomentsOf,
  reminderTextOf,
  reminderWord,
  remindersTotal,
  sendReminderNavigation,
  setReminderGeneralPatch,
  setReminderPatch,
  takeReminderNavigation,
  toInputDate,
  toInputTime,
  type ReminderItem,
} from "./reminders";

/** Момент «сейчас» в тестах: 20.11.2026 (пятница) 10:00, местное время. */
const NOW = new Date(2026, 10, 20, 10, 0, 0, 0);
const END_OF_TODAY = new Date(2026, 10, 20, 23, 59, 59, 999);

function apply(keywords: Record<string, boolean>, patch: Record<string, unknown>): Record<string, boolean> {
  const out = { ...keywords };
  for (const [key, value] of Object.entries(patch)) out[key.slice("keywords/".length)] = value as boolean;
  return out;
}

const item = (id: string, keywords: Record<string, boolean>): ReminderItem => ({
  id,
  subject: `Письмо ${id}`,
  keywords,
});

test("слова: время местное в слове, дата без времени — просто дата", () => {
  expect(reminderWord("due", new Date(2026, 10, 25, 9, 5), true)).toBe("pm.due.2026-11-25t0905");
  expect(reminderWord("wait", new Date(2026, 10, 30), false)).toBe("pm.wait.2026-11-30");
  expect(reminderWord("expire", new Date(2026, 11, 1, 14, 30), true)).toBe("pm.expire.2026-12-01t1430");
});

test("разбор моментов: с временем, конец дня, общее слово; выключенные слова — мимо", () => {
  const timed = reminderMomentsOf({ "pm.due.2026-11-25t0900": true });
  expect(timed.due?.timed).toBe(true);
  expect(timed.due?.at?.getTime()).toBe(new Date(2026, 10, 25, 9, 0).getTime());

  const dateOnly = reminderMomentsOf({ "pm.wait.2026-11-30": true });
  expect(dateOnly.wait?.timed).toBe(false);
  expect(dateOnly.wait?.at?.getTime()).toBe(new Date(2026, 10, 30, 23, 59, 59, 999).getTime());

  expect(reminderMomentsOf({ "pm.expire": true }).expire).toEqual({ at: null, timed: false });
  expect(reminderMomentsOf({ "pm.due.2026-11-25t0900": false }).due).toBeNull();
  expect(reminderMomentsOf({}).due).toBeNull();

  // Чужие слова и мусор — не напоминания.
  expect(reminderKindOf("pm.cat.team")).toBeNull();
  expect(reminderKindOf("pm.due.xxx")).toBeNull();
  expect(reminderKindOf("pm.due")).toBe("due");
  expect(reminderKindOf("pm.expire.2026-12-01t1430")).toBe("expire");

  // Несколько дат одного вида — ранняя (срочнее), порядок слов не важен.
  const two = reminderMomentsOf({ "pm.due.2026-11-25t0900": true, "pm.due.2026-11-23t0800": true });
  expect(two.due?.at?.getTime()).toBe(new Date(2026, 10, 23, 8, 0).getTime());
});

test("round-trip установки: прежняя дата снята, общее слово и новое слово рядом (S5-04)", () => {
  const k0 = { "pm.due.2026-11-01t1000": true, "pm.due": true, $seen: true };
  const patch = setReminderPatch(k0, "due", new Date(2026, 10, 25, 9, 0), true);
  expect(patch).toEqual({
    "keywords/pm.due.2026-11-01t1000": false,
    "keywords/pm.due": true,
    "keywords/pm.due.2026-11-25t0900": true,
  });
  const moments = reminderMomentsOf(apply(k0, patch));
  expect(moments.due?.at?.getTime()).toBe(new Date(2026, 10, 25, 9, 0).getTime());
  expect(moments.due?.timed).toBe(true);
  expect(hasReminderWords(apply(k0, patch))).toBe(true);
});

test("«Ждать ответа» без даты: общее слово, прежние даты вида сняты", () => {
  const patch = setReminderGeneralPatch({ "pm.wait.2026-11-10t1200": true }, "wait");
  expect(patch).toEqual({ "keywords/pm.wait.2026-11-10t1200": false, "keywords/pm.wait": true });
  const moments = reminderMomentsOf(apply({ "pm.wait.2026-11-10t1200": true }, patch));
  expect(moments.wait).toEqual({ at: null, timed: false });
});

test("снятие: один вид — только свои слова, все — включая общие; после «всех» напоминаний нет", () => {
  const k = { "pm.due.2026-11-25t0900": true, "pm.due": true, "pm.wait": true, $seen: true };
  const due = clearReminderKindPatch(k, "due");
  expect(due["keywords/pm.due.2026-11-25t0900"]).toBe(false);
  expect(due["keywords/pm.due"]).toBe(false);
  expect(due["keywords/pm.wait"]).toBeUndefined();

  const all = clearRemindersPatch(k);
  const after = apply(k, all);
  expect(after["pm.due.2026-11-25t0900"]).toBe(false);
  expect(after["pm.due"]).toBe(false);
  expect(after["pm.wait"]).toBe(false);
  expect(hasReminderWords(after)).toBe(false);
});

test("группировка: Просрочено ≤ сейчас, Сегодня — до конца дня, Далее — 7 дней, потом счётчик", () => {
  const groups = groupReminders(
    [
      item("a", { "pm.due.2026-11-18t0900": true }), // просрочено, старше всех — сверху
      item("b", { "pm.due.2026-11-19t0900": true }), // просрочено
      item("c", { "pm.due.2026-11-20t1500": true }), // сегодня позже «сейчас»
      item("d", { "pm.due.2026-11-20": true }), // дата без времени — конец дня → сегодня
      item("e", { "pm.due.2026-11-21t0900": true }), // далее
      item("f", { "pm.due.2026-11-27t1200": true }), // далее (горизонт: конец 27.11)
      item("g", { "pm.due.2026-11-28t0900": true }), // дальше горизонта — счётчик
      item("h", { "pm.wait": true }), // ждём ответа без даты
      item("i", { "pm.wait.2026-11-18": true }), // просроченное ожидание
      item("j", { "pm.wait.2026-11-22": true, "pm.due.2026-11-25t0900": true }), // срок → «Далее»
      item("k", { "pm.expire.2026-12-01": true }), // только «Исчезнет» — в полосе не показываем
    ],
    NOW,
  );
  expect(groups.overdue.map((i) => i.id)).toEqual(["a", "b"]);
  expect(groups.today.map((i) => i.id)).toEqual(["c", "d"]);
  expect(groups.next.map((i) => i.id)).toEqual(["e", "f", "j"]);
  expect(groups.later).toBe(1);
  expect(groups.wait.map((i) => i.id)).toEqual(["i", "h"]); // дольше ждём — выше, без даты — в конце
  expect(remindersTotal(groups)).toBe(10);
});

test("границы суток: полночь — вчерашний вечер уже просрочен, сегодняшний день ещё «Сегодня»", () => {
  const midnight = new Date(2026, 10, 20, 0, 0, 0, 0);
  const groups = groupReminders(
    [
      item("y", { "pm.due.2026-11-19t2359": true }), // вчера 23:59 ≤ 00:00 → просрочено
      item("t", { "pm.due.2026-11-20": true }), // конец сегодняшнего дня → сегодня
      item("x", { "pm.due.2026-11-19": true }), // вчера концом дня → просрочено
    ],
    midnight,
  );
  expect(groups.overdue.map((i) => i.id)).toEqual(["y", "x"]); // ранний срок — сверху
  expect(groups.today.map((i) => i.id)).toEqual(["t"]);
});

test("подписи: с временем — «Сегодня/Завтра/дата ЧЧ:ММ», без — как чипы списка («До пт»)", () => {
  expect(reminderDueText({ at: new Date(2026, 10, 20, 14, 30), timed: true }, NOW)).toBe("Сегодня 14:30");
  expect(reminderDueText({ at: new Date(2026, 10, 21, 9, 0), timed: true }, NOW)).toBe("Завтра 09:00");
  expect(reminderDueText({ at: new Date(2026, 10, 25, 9, 0), timed: true }, NOW)).toBe("25.11 09:00");
  expect(reminderDueText({ at: new Date(2026, 10, 20, 9, 0), timed: true }, NOW)).toBe("Просрочено сегодня 09:00");
  expect(reminderDueText({ at: new Date(2026, 10, 18, 9, 0), timed: true }, NOW)).toBe("Просрочено 3 д");
  expect(reminderDueText({ at: new Date(2026, 10, 27, 23, 59, 59, 999), timed: false }, NOW)).toBe("До пт");
  expect(reminderDueText({ at: END_OF_TODAY, timed: false }, NOW)).toBe("До пт");
  expect(reminderDueText({ at: new Date(2026, 10, 18, 23, 59, 59, 999), timed: false }, NOW)).toBe("Просрочено 2 д");
  expect(reminderDueText({ at: null, timed: false }, NOW)).toBeNull();
  expect(reminderDueText(null, NOW)).toBeNull();
});

test("текст письма для панели чтения: срок и ожидание рядом, без слов — null", () => {
  expect(reminderTextOf({ "pm.due.2026-11-25t0900": true, "pm.wait": true }, NOW)).toBe("25.11 09:00 · Ждём ответа");
  expect(reminderTextOf({ "pm.due.2026-11-20": true }, NOW)).toBe("До пт");
  expect(reminderTextOf({ "pm.wait.2026-11-18": true }, NOW)).toBe("Ждём ответа");
  expect(reminderTextOf({ "pm.expire.2026-12-01": true }, NOW)).toBe("Исчезнет: 01.12");
  expect(reminderTextOf({}, NOW)).toBeNull();
});

test("пресеты пикера: «Завтра 9:00» и «Через неделю» — 9:00 местного", () => {
  const now = new Date(2026, 10, 20, 15, 40);
  expect(presetTomorrow9(now).getTime()).toBe(new Date(2026, 10, 21, 9, 0).getTime());
  expect(presetInWeek(now).getTime()).toBe(new Date(2026, 10, 27, 9, 0).getTime());
});

test("поля пикера: дата/время — туда и обратно; дата без времени — конец дня; мусор — null", () => {
  expect(toInputDate(new Date(2026, 10, 5, 9, 7))).toBe("2026-11-05");
  expect(toInputTime(new Date(2026, 10, 5, 9, 7))).toBe("09:07");
  expect(fromInputDateTime("2026-11-25", "09:30")?.getTime()).toBe(new Date(2026, 10, 25, 9, 30).getTime());
  expect(fromInputDateTime("2026-11-25", null)?.getTime()).toBe(new Date(2026, 10, 25, 23, 59, 59, 999).getTime());
  expect(fromInputDateTime("не дата", "09:30")).toBeNull();
  expect(fromInputDateTime("2026-11-25", "25:99")).toBeNull();
});

test("шина переходов полосы: послано — забрано один раз, новое затирает прежнее", () => {
  expect(takeReminderNavigation()).toBeNull();
  sendReminderNavigation({ quick: "wait" });
  sendReminderNavigation({ open: "e1" });
  expect(takeReminderNavigation()).toEqual({ open: "e1" });
  expect(takeReminderNavigation()).toBeNull();
});
