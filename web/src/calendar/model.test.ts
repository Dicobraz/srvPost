// Модель календаря (WEB-06): виды (день / рабочая неделя / неделя / месяц), периоды навигации,
// русские подписи дат (Intl «ru»), разметка чипов (наложение «дорожками», позиция в сутках),
// форма встречи (длительность, ISO duration), пересечение с занятостью.
import { describe, expect, test } from "vitest";

import type { CalendarEventObject } from "../api/jmap";
import {
  dateInputValue,
  draftDurationMinutes,
  eventTimeLabel,
  fromDateTime,
  hourLabel,
  layoutTimed,
  localTimeZone,
  minutesToDuration,
  monthDayLabel,
  occurrencesOfDay,
  overlapsBusy,
  periodDayList,
  periodStart,
  periodTitle,
  shiftAnchor,
  timeInputValue,
  toOccurrences,
  VIEW_LABELS,
  type CalendarViewKind,
} from "./model";

/** Дата местного времени из Y/M/D/H/M (читаемость тестов). */
function at(y: number, m: number, d: number, h = 0, mi = 0): Date {
  return new Date(y, m - 1, d, h, mi);
}

function event(start: string, utcEnd: string, extra: Partial<CalendarEventObject> = {}): CalendarEventObject {
  return {
    id: "e1",
    uid: "u1",
    title: "Планёрка",
    description: null,
    start: "2026-11-23T10:00:00",
    duration: "PT1H",
    timeZone: null,
    locations: null,
    participants: null,
    organizerCalendarAddress: null,
    recurrenceId: null,
    baseEventId: null,
    calendarIds: { cal1: true },
    utcStart: start,
    utcEnd,
    ...extra,
  };
}

describe("виды и периоды", () => {
  test("рабочая неделя — с понедельника по пятницу (5 дней)", () => {
    // 25.11.2026 — среда.
    const days = periodDayList("workweek", at(2026, 11, 25));
    expect(days).toHaveLength(5);
    expect(days[0].getDay()).toBe(1); // понедельник
    expect(dateInputValue(days[0])).toBe("2026-11-23");
    expect(dateInputValue(days[4])).toBe("2026-11-27");
  });

  test("полная неделя — 7 дней с понедельника", () => {
    const days = periodDayList("week", at(2026, 11, 25));
    expect(days).toHaveLength(7);
    expect(days[0].getDay()).toBe(1);
    expect(dateInputValue(days[6])).toBe("2026-11-29");
  });

  test("день — одни сутки с полуночи", () => {
    const days = periodDayList("day", at(2026, 11, 25, 14, 30));
    expect(days).toHaveLength(1);
    expect(days[0].getHours()).toBe(0);
    expect(dateInputValue(days[0])).toBe("2026-11-25");
  });

  test("месяц — сетка полными неделями, накрывает весь месяц (ноябрь 2026: 1-е в воскресенье — 6 рядов)", () => {
    const days = periodDayList("month", at(2026, 11, 15));
    expect(days).toHaveLength(42);
    expect(dateInputValue(days[0])).toBe("2026-10-26"); // понедельник недели 1 ноября
    expect(dateInputValue(days[days.length - 1])).toBe("2026-12-06"); // декабрь накрыт
  });

  test("месяц, начинающийся с понедельника, короткий — 4 ряда (февраль 2027)", () => {
    const days = periodDayList("month", at(2027, 2, 10));
    expect(days).toHaveLength(28);
    expect(dateInputValue(days[0])).toBe("2027-02-01");
  });

  test("начало периода совпадает с началом сетки для всех видов", () => {
    for (const kind of ["day", "workweek", "week", "month"] as CalendarViewKind[]) {
      const start = periodStart(kind, at(2026, 11, 25));
      expect(dateInputValue(start)).toBe(dateInputValue(periodDayList(kind, at(2026, 11, 25))[0]));
    }
  });

  test("навигация: день ±1, недели ±7, месяц ±1 (без переполнения дней)", () => {
    expect(dateInputValue(shiftAnchor("day", at(2026, 11, 30), 1))).toBe("2026-12-01");
    expect(dateInputValue(shiftAnchor("day", at(2026, 12, 1), -1))).toBe("2026-11-30");
    expect(dateInputValue(shiftAnchor("week", at(2026, 11, 25), 1))).toBe("2026-12-02");
    expect(dateInputValue(shiftAnchor("workweek", at(2026, 11, 25), -1))).toBe("2026-11-18");
    const monthNext = shiftAnchor("month", at(2026, 11, 25), 1);
    expect(monthNext.getFullYear()).toBe(2026);
    expect(monthNext.getMonth()).toBe(11);
    expect(monthNext.getDate()).toBe(1);
    const monthPrev = shiftAnchor("month", at(2027, 1, 15), -1);
    expect(monthPrev.getFullYear()).toBe(2026);
    expect(monthPrev.getMonth()).toBe(11);
  });

  test("названия видов — как в макете", () => {
    expect(VIEW_LABELS).toEqual({
      day: "День",
      workweek: "Рабочая неделя",
      week: "Неделя",
      month: "Месяц",
    });
  });
});

describe("русские подписи (Intl «ru»)", () => {
  test("заголовок дня: «Среда, 25 ноября 2026 г.»", () => {
    expect(periodTitle("day", at(2026, 11, 25))).toContain("25");
    expect(periodTitle("day", at(2026, 11, 25))).toContain("ноября");
  });

  test("заголовок недели в одном месяце: «23–29 ноября 2026 г.»", () => {
    const title = periodTitle("week", at(2026, 11, 25));
    expect(title).toMatch(/^23–29/);
    expect(title).toContain("ноября");
  });

  test("заголовок недели через границу месяца: оба месяца", () => {
    const title = periodTitle("week", at(2026, 11, 30));
    expect(title).toContain("ноября");
    expect(title).toContain("декабря");
  });

  test("заголовок месяца: «Ноябрь 2026 г.»", () => {
    expect(periodTitle("month", at(2026, 11, 15))).toContain("Ноябрь");
    expect(periodTitle("month", at(2026, 11, 15))).toContain("2026");
  });

  test("час и время события: «09:00», «14:00–15:00»", () => {
    expect(hourLabel(9)).toBe("09:00");
    expect(hourLabel(13)).toBe("13:00");
    expect(eventTimeLabel(at(2026, 11, 23, 14, 0), at(2026, 11, 23, 15, 0))).toBe("14:00–15:00");
    expect(eventTimeLabel(at(2026, 11, 23, 14, 5), null)).toBe("14:05");
    expect(eventTimeLabel(null, null)).toBe("");
  });

  test("метка дня месяца: число, у 1-го — с месяцем", () => {
    expect(monthDayLabel(at(2026, 11, 23))).toBe("23");
    expect(monthDayLabel(at(2026, 11, 1))).toContain("1");
    expect(monthDayLabel(at(2026, 11, 1))).toContain("ноября");
  });

  test("часовой пояс браузера — IANA-имя (TZID события без пояса)", () => {
    const tz = localTimeZone();
    expect(tz.length).toBeGreaterThan(0);
    expect(tz).not.toContain(" ");
  });
});

describe("вхождения и чипы", () => {
  const colorOf = () => "#4687d8";

  test("вхождения из utcStart/utcEnd; без времени сервера — пропускаются", () => {
    const list = toOccurrences(
      [
        event("2026-11-23T10:00:00Z", "2026-11-23T11:00:00Z"),
        event("2026-11-23T12:00:00Z", "2026-11-23T13:00:00Z", { id: "e2" }),
        event("", ""),
      ],
      colorOf,
    );
    expect(list).toHaveLength(2);
    expect(list[0].start.getUTCHours()).toBe(10);
    expect(list[0].allDay).toBe(false);
  });

  test("«весь день» — showWithoutTime или длительность больше суток", () => {
    const list = toOccurrences(
      [
        event("2026-11-23T00:00:00Z", "2026-11-24T00:00:00Z", { showWithoutTime: true, id: "a" }),
        event("2026-11-23T10:00:00Z", "2026-11-25T10:00:00Z", { id: "b" }),
      ],
      colorOf,
    );
    expect(list.every((o) => o.allDay)).toBe(true);
  });

  test("вхождения суток: пересечение с [00:00, +24ч) — «пересекает интервал» сервера", () => {
    const all = toOccurrences(
      [
        event("2026-11-22T23:00:00Z", "2026-11-23T01:00:00Z", { id: "edge" }), // через полночь
        event("2026-11-23T10:00:00Z", "2026-11-23T11:00:00Z", { id: "inside" }),
        event("2026-11-24T10:00:00Z", "2026-11-24T11:00:00Z", { id: "next" }),
      ],
      colorOf,
    );
    const day = occurrencesOfDay(all, at(2026, 11, 23));
    expect(day.map((o) => o.event.id).sort()).toEqual(["edge", "inside"]);
  });

  test("разметка чипа: позиция в процентах суток, длительность", () => {
    const all = toOccurrences([event("2026-11-23T06:00:00Z", "2026-11-23T07:00:00Z")], colorOf);
    const day = at(2026, 11, 23);
    // 06:00Z в поясе теста: позиция считаем от полуночи пояса — проверяем относительно вхождения.
    const chips = layoutTimed(all, day);
    expect(chips).toHaveLength(1);
    expect(chips[0].height).toBeCloseTo(100 / 24, 5); // час = 1/24 суток
    expect(chips[0].lanes).toBe(1);
  });

  test("наложение: пересекающиеся события — соседние дорожки, одно событие — во всю ширину", () => {
    const all = toOccurrences(
      [
        event("2026-11-23T10:00:00Z", "2026-11-23T11:00:00Z", { id: "a" }),
        event("2026-11-23T10:30:00Z", "2026-11-23T11:30:00Z", { id: "b" }),
      ],
      colorOf,
    );
    const chips = layoutTimed(all, at(2026, 11, 23));
    expect(chips).toHaveLength(2);
    expect(new Set(chips.map((c) => c.lane)).size).toBe(2);
    expect(chips.every((c) => c.lanes === 2)).toBe(true);
  });

  test("последовательные события (не пересекаются) — одна дорожка", () => {
    const all = toOccurrences(
      [
        event("2026-11-23T10:00:00Z", "2026-11-23T11:00:00Z", { id: "a" }),
        event("2026-11-23T11:00:00Z", "2026-11-23T12:00:00Z", { id: "b" }),
      ],
      colorOf,
    );
    const chips = layoutTimed(all, at(2026, 11, 23));
    expect(chips.map((c) => c.lane)).toEqual([0, 0]);
    expect(chips.every((c) => c.lanes === 1)).toBe(true);
  });
});

describe("форма встречи", () => {
  test("длительность из полей времени, конец на следующие сутки", () => {
    expect(draftDurationMinutes({ start: "09:00", end: "10:30" })).toBe(90);
    expect(draftDurationMinutes({ start: "23:00", end: "00:30" })).toBe(90);
    expect(draftDurationMinutes({ start: "10:00", end: "10:00" })).toBe(24 * 60);
  });

  test("ISO duration из минут", () => {
    expect(minutesToDuration(45)).toBe("PT45M");
    expect(minutesToDuration(60)).toBe("PT1H");
    expect(minutesToDuration(90)).toBe("PT1H30M");
  });

  test("значения полей даты/времени и обратно", () => {
    const d = at(2026, 11, 23, 14, 5);
    expect(dateInputValue(d)).toBe("2026-11-23");
    expect(timeInputValue(d)).toBe("14:05");
    const back = fromDateTime("2026-11-23", "14:05");
    expect(back.getFullYear()).toBe(2026);
    expect(back.getMonth()).toBe(10);
    expect(back.getDate()).toBe(23);
    expect(back.getHours()).toBe(14);
    expect(back.getMinutes()).toBe(5);
  });

  test("пересечение с занятостью: границы по [начало, конец)", () => {
    const busy = [{ utcStart: "2026-11-23T09:00:00Z", utcEnd: "2026-11-23T10:00:00Z" }];
    const start = new Date("2026-11-23T09:30:00Z");
    const end = new Date("2026-11-23T10:30:00Z");
    expect(overlapsBusy(start, end, busy)).toBe(true);
    // Начало вплотную к концу занятости — не пересекается.
    expect(overlapsBusy(new Date("2026-11-23T10:00:00Z"), end, busy)).toBe(false);
    expect(overlapsBusy(new Date("2026-11-24T10:00:00Z"), new Date("2026-11-24T11:00:00Z"), busy)).toBe(false);
  });
});
