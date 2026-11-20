// Карточка приглашения (WEB-03): .ics в письме — чтение VEVENT (RFC 5545), заглушка по макету
// (кнопки ответа примет волна 6 — JMAP-50).
import { expect, test } from "vitest";

import { dayRibbon, formatInvitationWhen, isInvitationPart, parseInvitation } from "./invite";

const ICS = [
  "BEGIN:VCALENDAR",
  "PRODID:-//Test//RU",
  "VERSION:2.0",
  "METHOD:REQUEST",
  "BEGIN:VEVENT",
  "UID:1234@x.test",
  "SUMMARY:Согласование договора поставки",
  "DTSTART;TZID=Europe/Moscow:20261124T140000",
  "DTEND;TZID=Europe/Moscow:20261124T150000",
  "LOCATION:Переговорная 4",
  "ORGANIZER;CN=Ольга Смирнова:mailto:o.smirnova@vektor.example",
  "ATTENDEE;PARTSTAT=ACCEPTED;CN=Анна:mailto:a@x.test",
  "ATTENDEE;PARTSTAT=NEEDS-ACTION;CN=Борис:mailto:b@x.test",
  "DESCRIPTION:Просьба согласить\\, до среды",
  "END:VEVENT",
  "END:VCALENDAR",
].join("\r\n");

test("VEVENT: тема, время, место, организатор, счётчик участников", () => {
  const inv = parseInvitation(ICS);
  expect(inv).not.toBeNull();
  expect(inv!.summary).toBe("Согласование договора поставки");
  expect(inv!.location).toBe("Переговорная 4");
  expect(inv!.organizer).toBe("Ольга Смирнова <o.smirnova@vektor.example>");
  expect(inv!.attendees).toBe(2);
  expect(inv!.accepted).toBe(1);
  // TZID без Z — местное время 14:00.
  expect(inv!.start?.getHours()).toBe(14);
  expect(inv!.start?.getMinutes()).toBe(0);
});

test("не iCalendar и не VEVENT — null; part text/calendar — приглашение", () => {
  expect(parseInvitation("BEGIN:VCALENDAR\r\nEND:VCALENDAR")).toBeNull();
  expect(isInvitationPart("text/calendar; method=REQUEST")).toBe(true);
  expect(isInvitationPart("application/pdf")).toBe(false);
});

test("свёртка строк RFC 5545 §3.1: unfolding убирает CRLF и ведущий пробел", () => {
  const folded = "BEGIN:VEVENT\r\nSUMMARY:Длинная тема\r\n продолжение\r\nEND:VEVENT";
  expect(parseInvitation(folded)?.summary).toBe("Длинная темапродолжение");
});

test("подпись «вт 24.11.2026 14:00–15:00» — как в карточке макета", () => {
  const inv = parseInvitation(ICS)!;
  const when = formatInvitationWhen(inv.start, inv.end);
  expect(when).toMatch(/14:00–15:00/);
  expect(when).toMatch(/2026/);
});

test("лента «Ваш день»: часы по 24 px, приглашение — полосой, «сейчас» — линией", () => {
  const start = new Date(2026, 10, 24, 14, 0);
  const end = new Date(2026, 10, 24, 15, 0);
  const ribbon = dayRibbon(start, end, new Date(2026, 10, 24, 13, 20));
  const hours = ribbon.filter((r) => "hour" in r) as Array<{ hour: number; label: string }>;
  expect(hours.map((h) => h.label)).toEqual(["13:00", "14:00", "15:00"]);
  const invite = ribbon.find((r) => "invite" in r) as { top: number; height: number; nowTop: number | null };
  expect(invite.top).toBeCloseTo(24); // 14:00 — через час от 13:00
  expect(invite.height).toBeCloseTo(24); // час встречи
  expect(invite.nowTop).not.toBeNull();
});
