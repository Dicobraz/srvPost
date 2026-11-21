/*
  Модель календаря (WEB-06): виды день / рабочая неделя / неделя / месяц, периоды навигации
  («Сегодня», ←/→), планировочная сетка (колонки дней, часы, «сейчас») и раскладка чипов
  событий по цвету календаря. Русские подписи дат — Intl («ru»), не свои строки — календарь
  не заводит слов вне макета. Чистые функции без React — тесты правды видов и разметки.
  Время вхождений — UTCDate сервера (utcStart/utcEnd); подписи — местное время браузера.
*/

import type { CalendarEventObject } from "../api/jmap";

/** Вид календаря (макет 01, PARITY calendar.*): день / рабочая неделя / неделя / месяц. */
export type CalendarViewKind = "day" | "workweek" | "week" | "month";

/** Названия видов для переключателя (макет 01). */
export const VIEW_LABELS: Record<CalendarViewKind, string> = {
  day: "День",
  workweek: "Рабочая неделя",
  week: "Неделя",
  month: "Месяц",
};

/** Число дней вида (месяц — по дате, см. periodDays). */
export function daysIn(kind: Exclude<CalendarViewKind, "month">): number {
  switch (kind) {
    case "day":
      return 1;
    case "workweek":
      return 5;
    case "week":
      return 7;
  }
}

/** Начало суток (без времени). */
export function startOfDay(d: Date): Date {
  const out = new Date(d);
  out.setHours(0, 0, 0, 0);
  return out;
}

/** Понедельник недели даты (неделя с понедельника — макет и Postman). */
export function startOfWeek(d: Date): Date {
  const out = startOfDay(d);
  const shift = (out.getDay() + 6) % 7; // вс=0 → 6
  out.setDate(out.getDate() - shift);
  return out;
}

/** Сетка месяца: с понедельника недели первого числа, полными неделями до конца месяца. */
export function startOfMonthGrid(d: Date): Date {
  return startOfWeek(new Date(d.getFullYear(), d.getMonth(), 1));
}

/** Число суток периода вида (месяц — по дате: полные недели, 5 или 6 рядов). */
export function periodDays(kind: CalendarViewKind, anchor: Date): number {
  if (kind !== "month") return daysIn(kind);
  const first = new Date(anchor.getFullYear(), anchor.getMonth(), 1);
  const last = new Date(first.getFullYear(), first.getMonth() + 1, 0).getDate();
  return Math.ceil((((first.getDay() + 6) % 7) + last) / 7) * 7;
}

/** Начало периода вида по опорной дате (день — сама дата, месяц — сетка месяца). */
export function periodStart(kind: CalendarViewKind, anchor: Date): Date {
  if (kind === "month") return startOfMonthGrid(anchor);
  if (kind === "week" || kind === "workweek") return startOfWeek(anchor);
  return startOfDay(anchor);
}

/** Опорная дата внутри периода — для заголовка и «Сегодня»-подсветки. */
export function periodAnchor(kind: CalendarViewKind, anchor: Date): Date {
  return kind === "month" ? new Date(anchor.getFullYear(), anchor.getMonth(), 1) : anchor;
}

/** Сдвиг периода на шаг назад/вперёд (←/→): день ±1, неделя ±7, месяц ±1 (без переполнения). */
export function shiftAnchor(kind: CalendarViewKind, anchor: Date, dir: -1 | 1): Date {
  if (kind === "month") {
    return new Date(anchor.getFullYear(), anchor.getMonth() + dir, 1);
  }
  const step = kind === "day" ? 1 : 7;
  const out = new Date(anchor);
  out.setDate(out.getDate() + dir * step);
  return out;
}

/** Дни периода по порядку (начало сетки и число дней). */
export function periodDayList(kind: CalendarViewKind, anchor: Date): Date[] {
  const start = periodStart(kind, anchor);
  const total = periodDays(kind, anchor);
  return Array.from({ length: total }, (_, i) => {
    const d = new Date(start);
    d.setDate(d.getDate() + i);
    return d;
  });
}

// ---------- Подписи (Intl, «ru») ----------

const WEEKDAY_SHORT = (d: Date) => d.toLocaleDateString("ru", { weekday: "short" });
const DAY_MONTH = (d: Date) => d.toLocaleDateString("ru", { day: "numeric", month: "long" });
const DAY_MONTH_YEAR = (d: Date) =>
  d.toLocaleDateString("ru", { day: "numeric", month: "long", year: "numeric" });

/** Месяц и год в родительном падеже («ноября 2026 г.») — из полной даты без числа. */
function monthYearGenitive(d: Date): string {
  return DAY_MONTH_YEAR(d).replace(/^\d+\s+/, "");
}

/** Заголовок периода: «воскресенье, 23 ноября 2026» / «23–29 ноября 2026» / «Ноябрь 2026». */
export function periodTitle(kind: CalendarViewKind, anchor: Date): string {
  const days = periodDayList(kind, anchor);
  if (kind === "day") {
    const d = days[0];
    const weekday = d.toLocaleDateString("ru", { weekday: "long" });
    return `${weekday.charAt(0).toUpperCase()}${weekday.slice(1)}, ${DAY_MONTH_YEAR(d)}`;
  }
  if (kind === "month") {
    const title = days[Math.floor(days.length / 2)].toLocaleDateString("ru", { month: "long", year: "numeric" });
    return `${title.charAt(0).toUpperCase()}${title.slice(1)}`;
  }
  const a = days[0];
  const b = days[days.length - 1];
  if (a.getMonth() === b.getMonth() && a.getFullYear() === b.getFullYear()) {
    return `${a.getDate()}–${b.getDate()} ${monthYearGenitive(a)}`;
  }
  return `${DAY_MONTH(a)} – ${DAY_MONTH(b)} ${b.getFullYear()}`;
}

/** Заголовок колонки дня: «пн 23.11» (макет 01: короткий день и дата). */
export function dayColumnTitle(d: Date, today: Date): { weekday: string; date: string; isToday: boolean } {
  return {
    weekday: WEEKDAY_SHORT(d),
    date: d.toLocaleDateString("ru", { day: "2-digit", month: "2-digit" }),
    isToday: startOfDay(d).getTime() === startOfDay(today).getTime(),
  };
}

/** Метка часа сетки: «09:00» (первые два часа — ночь, метки всех часов, как в макете). */
export function hourLabel(hour: number): string {
  return `${String(hour).padStart(2, "0")}:00`;
}

/** Время события по-русски: «14:00–15:00» (местное время браузера). */
export function eventTimeLabel(start: Date | null, end: Date | null): string {
  const fmt = (d: Date) => d.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" });
  if (!start) return "";
  return end ? `${fmt(start)}–${fmt(end)}` : fmt(start);
}

// ---------- Вхождения и чипы ----------

/** Событие вхождения на экране: абсолютное время из utcStart/utcEnd (нечто у сервера всегда есть
 * для вхождений развёртки; событие без них — не показывается в сетке). */
export interface Occurrence {
  event: CalendarEventObject;
  start: Date;
  end: Date;
  allDay: boolean;
  /** Цвет календаря подставляет страница (по calendarIds). */
  color: string;
}

/** Вхождение «весь день» (showWithoutTime) или длительностью более суток. */
function isAllDay(event: CalendarEventObject, start: Date, end: Date): boolean {
  return Boolean(event.showWithoutTime) || end.getTime() - start.getTime() >= 24 * 3_600_000;
}

/** Вхождения из ответа сервера: время — utcStart/utcEnd; нечитаемое время пропускается. */
export function toOccurrences(
  events: CalendarEventObject[],
  colorOf: (event: CalendarEventObject) => string,
): Occurrence[] {
  const out: Occurrence[] = [];
  for (const event of events) {
    if (!event.utcStart) continue;
    const start = new Date(event.utcStart);
    const end = event.utcEnd ? new Date(event.utcEnd) : start;
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) continue;
    out.push({ event, start, end: end > start ? end : new Date(start.getTime() + 1), allDay: isAllDay(event, start, end), color: colorOf(event) });
  }
  return out;
}

/** Вхождения суток: пересекаются с [день 00:00, +1 сутки) — «пересекает интервал» сервера. */
export function occurrencesOfDay(all: Occurrence[], day: Date): Occurrence[] {
  const from = startOfDay(day).getTime();
  const to = from + 24 * 3_600_000;
  return all.filter((o) => o.start.getTime() < to && o.end.getTime() > from);
}

/** Разметка чипа в колонке дня: сверху — доля суток (CSS top/height в %), полосы — наложение
 * (жадная упаковка «дорожек», как в Outlook): пересекающиеся события — рядом, не поверх. */
export interface TimedChip {
  occurrence: Occurrence;
  /** Позиция внутри колонки, проценты от высоты суток. */
  top: number;
  height: number;
  /** Дорожка наложений и их число (ширина чипа). */
  lane: number;
  lanes: number;
}

export function layoutTimed(occurrences: Occurrence[], day: Date): TimedChip[] {
  const from = startOfDay(day).getTime();
  const DAY = 24 * 3_600_000;
  const timed = occurrences
    .filter((o) => !o.allDay)
    .map((o) => ({
      occurrence: o,
      s: Math.max(o.start.getTime(), from),
      e: Math.min(o.end.getTime(), from + DAY),
    }))
    .filter((o) => o.e > o.s)
    .sort((a, b) => a.s - b.s || a.occurrence.end.getTime() - b.occurrence.end.getTime());
  const chips: TimedChip[] = timed.map((o) => ({
    occurrence: o.occurrence,
    top: ((o.s - from) / DAY) * 100,
    height: Math.max(0, ((o.e - o.s) / DAY) * 100),
    lane: 0,
    lanes: 1,
  }));
  // Дорожки: событие занимает первую свободную среди пересекающихся активных.
  const lanes: Array<number | null> = []; // конец занятости дорожки
  for (const chip of chips) {
    const s = from + (chip.top / 100) * DAY;
    let lane = lanes.findIndex((end) => end === null || end <= s);
    if (lane === -1) {
      lane = lanes.length;
      lanes.push(null);
    }
    lanes[lane] = from + ((chip.top + chip.height) / 100) * DAY;
    chip.lane = lane;
  }
  // Число дорожек: максимальное число одновременно пересекающихся (на каждое событие).
  for (const chip of chips) {
    const s = from + (chip.top / 100) * DAY;
    const e = from + ((chip.top + chip.height) / 100) * DAY;
    chip.lanes = chips.filter((c) => {
      const cs = from + (c.top / 100) * DAY;
      const ce = from + ((c.top + c.height) / 100) * DAY;
      return cs < e && ce > s;
    }).length;
  }
  return chips;
}

/** Метка дня месяца: число; 1-е — «1 ноября» (макет месяца Outlook; месяц — родительный). */
export function monthDayLabel(d: Date): string {
  return d.getDate() === 1 ? DAY_MONTH(d) : String(d.getDate());
}

/** Форма встречи (макет полей композера): значения полей формы. */
export interface MeetingDraft {
  title: string;
  /** Дата «YYYY-MM-DD». */
  date: string;
  /** Время «HH:MM». */
  start: string;
  end: string;
  description: string;
}

/** Длительность формы в минутах (конец — на следующие сутки, если «конец» раньше «начала»). */
export function draftDurationMinutes(draft: { start: string; end: string }): number {
  const at = (t: string) => {
    const [h, m] = t.split(":").map(Number);
    return (h || 0) * 60 + (m || 0);
  };
  const diff = at(draft.end) - at(draft.start);
  return diff > 0 ? diff : diff + 24 * 60;
}

/** ISO 8601 duration из минут: PT45M / PT1H30M. */
export function minutesToDuration(minutes: number): string {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (h === 0) return `PT${m}M`;
  if (m === 0) return `PT${h}H`;
  return `PT${h}H${m}M`;
}

/** Дата формы «YYYY-MM-DD» из Date (местное время). */
export function dateInputValue(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}

/** Время формы «HH:MM» из Date. */
export function timeInputValue(d: Date): string {
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

/** Date из «YYYY-MM-DD» + «HH:MM» (местное время). */
export function fromDateTime(date: string, time: string): Date {
  const [y, mo, d] = date.split("-").map(Number);
  const [h, mi] = time.split(":").map(Number);
  return new Date(y, (mo || 1) - 1, d || 1, h || 0, mi || 0);
}

/** Часовой пояс браузера для событий без пояса (IANA-имя, TZID). */
export function localTimeZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

/** Пересекается ли встреча с занятым слотом занятости (read-only free/busy). */
export function overlapsBusy(start: Date, end: Date, busy: Array<{ utcStart: string; utcEnd: string }>): boolean {
  return busy.some((b) => new Date(b.utcStart).getTime() < end.getTime() && new Date(b.utcEnd).getTime() > start.getTime());
}
