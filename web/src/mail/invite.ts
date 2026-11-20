/*
  Карточка приглашения (WEB-03): .ics в письме (text/calendar, iTIP REQUEST) — покадровая заглушка
  по макету `01-mail-desktop.html`: детали встречи, лента «Ваш день» с приглашением и линией
  «сейчас», кнопки «Принять / Под вопросом / Отклонить» — disabled с подсказкой «в разработке»
  (ответы примет волна 6 — метод веб-почты JMAP-50). Синтаксис iCalendar — RFC 5545 §3.1
  (свёртка строк), поля — RFC 5545 §3.8.
*/

/** Детали приглашения, которые читаются из VEVENT. */
export interface Invitation {
  summary: string;
  start: Date | null;
  end: Date | null;
  location: string | null;
  organizer: string | null;
  /** Согласие участников «2 из 5 приняли» — по STATUS/присутствию PARTSTAT; грубая оценка. */
  attendees: number;
  accepted: number;
}

/** Развёртка строк iCalendar (RFC 5545 §3.1): продолжение строки начинается с пробела. */
function unfold(text: string): string[] {
  const lines: string[] = [];
  for (const raw of text.split(/\r?\n/)) {
    if ((raw.startsWith(" ") || raw.startsWith("\t")) && lines.length > 0) {
      lines[lines.length - 1] += raw.slice(1);
    } else {
      lines.push(raw);
    }
  }
  return lines;
}

/** Значение и параметры строки: `DTSTART;TZID=Europe/Moscow:20261124T140000`. */
function parseLine(line: string): { name: string; params: Record<string, string>; value: string } | null {
  const colon = line.indexOf(":");
  if (colon <= 0) return null;
  const left = line.slice(0, colon);
  const value = line.slice(colon + 1);
  const [name, ...params] = left.split(";");
  const out: Record<string, string> = {};
  for (const p of params) {
    const eq = p.indexOf("=");
    if (eq > 0) out[p.slice(0, eq).toUpperCase()] = p.slice(eq + 1);
  }
  return { name: name.toUpperCase(), params: out, value };
}

/** Дата-время iCalendar → Date: с Z — UTC, с TZID/без — местное время (уточнение — волна 6). */
function parseDateTime(value: string, params: Record<string, string>): Date | null {
  const m = /^(\d{4})(\d{2})(\d{2})(?:T(\d{2})(\d{2})(\d{2})?)?$/.exec(value.trim());
  if (!m) return null;
  const [, y, mo, d, h = "0", mi = "0", s = "0"] = m;
  if (params.VALUE === "DATE" || !h) {
    return new Date(Number(y), Number(mo) - 1, Number(d));
  }
  if (value.endsWith("Z")) {
    return new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)));
  }
  return new Date(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s));
}

/** Имя и адрес из `ORGANIZER;CN=Имя:mailto:a@x.test`. */
function parsePerson(value: string, params: Record<string, string>): string | null {
  const email = value.replace(/^mailto:/i, "");
  if (!email) return null;
  const name = params.CN;
  return name ? `${name} <${email}>` : email;
}

/** Чтение VEVENT из текста .ics; не приглашение (нет VEVENT) — null. */
export function parseInvitation(ics: string): Invitation | null {
  const lines = unfold(ics);
  let event: Invitation | null = null;
  let organizer: { name: string | null; email: string | null } | null = null;
  for (const line of lines) {
    const parsed = parseLine(line);
    if (!parsed) continue;
    if (parsed.name === "BEGIN" && parsed.value === "VEVENT") {
      event = { summary: "", start: null, end: null, location: null, organizer: null, attendees: 0, accepted: 0 };
      organizer = null;
    } else if (parsed.name === "END" && parsed.value === "VEVENT") {
      if (event) {
        if (organizer?.email) {
          event.organizer = organizer.name ? `${organizer.name} <${organizer.email}>` : organizer.email;
        }
        return event;
      }
    } else if (event) {
      switch (parsed.name) {
        case "SUMMARY":
          event.summary = parsed.value;
          break;
        case "DTSTART":
          event.start = parseDateTime(parsed.value, parsed.params);
          break;
        case "DTEND":
          event.end = parseDateTime(parsed.value, parsed.params);
          break;
        case "LOCATION":
          event.location = parsed.value;
          break;
        case "ORGANIZER":
          organizer = { name: parsed.params.CN ?? null, email: parsed.value.replace(/^mailto:/i, "") || null };
          break;
        case "ATTENDEE": {
          event.attendees += 1;
          // PARTSTAT=ACCEPTED — согласился (RFC 5545 §3.2.12); без статуса — не считаем.
          if (parsed.params.PARTSTAT === "ACCEPTED") event.accepted += 1;
          break;
        }
      }
    }
  }
  return null;
}

/** Приглашение есть в письме: часть text/calendar с методом REQUEST. */
export function isInvitationPart(type: string): boolean {
  return type.toLowerCase().startsWith("text/calendar");
}

/** Дата-время встречи по-русски: «вт 24.11.2026 14:00–15:00» (макет карточки). */
export function formatInvitationWhen(start: Date | null, end: Date | null): string {
  if (!start) return "время уточняется";
  const day = start.toLocaleDateString("ru", { weekday: "short", day: "2-digit", month: "2-digit", year: "numeric" });
  const from = start.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" });
  if (!end) return `${day} ${from}`;
  const to = end.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" });
  const sameDay = start.toDateString() === end.toDateString();
  return sameDay ? `${day} ${from}–${to}` : `${day} ${from} — ${end.toLocaleDateString("ru")}${" "}${to}`;
}

/** Вертикальная лента «Ваш день» карточки: часы от встречи и «сейчас», приглашение — полосой. */
export function dayRibbon(
  start: Date,
  end: Date,
  now: Date,
): Array<{ hour: number; label: string } | { invite: true; top: number; height: number; nowTop: number | null }> {
  const hourMs = 3_600_000;
  // Лента покрывает встречу и «сейчас»: линия времени видна рядом с приглашением (макет 01).
  const firstHour = new Date(Math.min(start.getTime(), now.getTime()));
  firstHour.setMinutes(0, 0, 0);
  const lastHour = new Date(Math.max(end.getTime(), now.getTime()));
  lastHour.setHours(lastHour.getHours() + 1, 0, 0, 0);
  const hours: Array<{ hour: number; label: string }> = [];
  for (let t = firstHour.getTime(); t < lastHour.getTime(); t += hourMs) {
    const d = new Date(t);
    hours.push({ hour: d.getHours(), label: `${String(d.getHours()).padStart(2, "0")}:00` });
  }
  const top = ((start.getTime() - firstHour.getTime()) / hourMs) * 24;
  const height = Math.max(24, ((end.getTime() - start.getTime()) / hourMs) * 24);
  const nowTop = now >= firstHour && now <= lastHour ? ((now.getTime() - firstHour.getTime()) / hourMs) * 24 : null;
  return [...hours, { invite: true, top, height, nowTop }];
}
