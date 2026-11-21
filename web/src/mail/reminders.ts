/*
  Напоминания «всегда перед глазами» (WEB-19, решение владельца 21.11 — issue #303): слова сроков
  письма `pm.due`/`pm.wait`/`pm.expire` (CONTRACTS.md «Mail keywords», маски WEB-12) собираются в
  постоянную полосу оболочки. Веб ставит слова как Postman (S5-04): рядом общее слово и слово с
  датой и временем `pm.due.<ГГГГ-ММ-ДД>t<ЧЧММ>` (дата и время — местные); сервер `hasKeyword`
  ищет слово целиком, поэтому запрос полосы — по общему слову. Группировка полосы: «Просрочено»
  (момент срока ≤ сейчас), «Сегодня», «Далее» (ближайшие 7 дней, дальше — счётчик), «Ждём ответа»
  (`pm.wait` без срока или с прошедшей датой ожидания). Несколько дат одного вида — ранняя
  (срочнее), порядок слов в объекте не важен. Подписи сроков — те же, что у чипов списка
  (keywords.ts): «До ср», «Просрочено N д».
*/
import type { Keywords } from "../api/jmap";
import { dueLabel, lifecycleOf, overdueDays, waitLabel, type Lifecycle } from "./keywords";

/** Вид напоминания: срок (`pm.due`), ждём ответа (`pm.wait`), исчезнет (`pm.expire`). */
export type ReminderKind = "due" | "wait" | "expire";

const GENERAL: Record<ReminderKind, string> = { due: "pm.due", wait: "pm.wait", expire: "pm.expire" };
const PREFIX: Record<ReminderKind, string> = { due: "pm.due.", wait: "pm.wait.", expire: "pm.expire." };
const KINDS: ReminderKind[] = ["due", "wait", "expire"];

/** Момент напоминания: время в слове (`tЧЧММ`) — местное; дата без времени — конец дня (S5-04). */
export interface ReminderMoment {
  at: Date | null;
  timed: boolean;
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/** Слово с датой или датой-временем: `pm.due.2026-11-25t0900` / `pm.wait.2026-11-30`. */
export function reminderWord(kind: ReminderKind, at: Date, timed: boolean): string {
  const date = `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`;
  return timed ? `${PREFIX[kind]}${date}t${pad(at.getHours())}${pad(at.getMinutes())}` : `${PREFIX[kind]}${date}`;
}

function parseMoment(word: string, kind: ReminderKind): ReminderMoment | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:t(\d{2})(\d{2}))?$/.exec(word.slice(PREFIX[kind].length));
  if (!m) return null;
  const at = m[4] && m[5]
    ? new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]))
    : new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 23, 59, 59, 999);
  if (Number.isNaN(at.getTime())) return null;
  return { at, timed: Boolean(m[4] && m[5]) };
}

/** Какому виду принадлежит слово (общее или с датой); не напоминание — null. */
export function reminderKindOf(word: string): ReminderKind | null {
  for (const kind of KINDS) {
    if (word === GENERAL[kind]) return kind;
    if (word.startsWith(PREFIX[kind]) && parseMoment(word, kind)) return kind;
  }
  return null;
}

/** Моменты напоминаний письма по словам: слова нет — null; общее слово — { at: null }. */
export function reminderMomentsOf(keywords: Keywords): Record<ReminderKind, ReminderMoment | null> {
  const out: Record<ReminderKind, ReminderMoment | null> = { due: null, wait: null, expire: null };
  for (const [word, on] of Object.entries(keywords)) {
    if (!on) continue;
    const kind = reminderKindOf(word);
    if (!kind) continue;
    if (word === GENERAL[kind]) {
      out[kind] = out[kind] ?? { at: null, timed: false };
      continue;
    }
    const m = parseMoment(word, kind);
    if (!m) continue;
    const prev = out[kind];
    if (!prev?.at || (m.at && m.at.getTime() < prev.at.getTime())) out[kind] = m;
  }
  return out;
}

/** Есть ли на письме слова напоминаний (любого вида, включая общие). */
export function hasReminderWords(keywords: Keywords): boolean {
  return Object.keys(keywords).some((w) => keywords[w] && reminderKindOf(w) !== null);
}

// ---------- Патчи Email/set (порядок слов — как в Postman: общее слово + слово с датой) ----------

/** «Поставить/переставить» напоминание вида kind: прежние даты вида снимаются, общее слово и
 * слово с датой ставятся рядом (S5-04). */
export function setReminderPatch(keywords: Keywords, kind: ReminderKind, at: Date, timed: boolean): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  for (const word of Object.keys(keywords)) {
    if (reminderKindOf(word) === kind && word !== GENERAL[kind]) patch[`keywords/${word}`] = false;
  }
  patch[`keywords/${GENERAL[kind]}`] = true;
  patch[`keywords/${reminderWord(kind, at, timed)}`] = true;
  return patch;
}

/** Напоминание вида kind без даты («Ждать ответа»): общее слово, прежние даты вида снимаются. */
export function setReminderGeneralPatch(keywords: Keywords, kind: ReminderKind): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  for (const word of Object.keys(keywords)) {
    if (reminderKindOf(word) === kind && word !== GENERAL[kind]) patch[`keywords/${word}`] = false;
  }
  patch[`keywords/${GENERAL[kind]}`] = true;
  return patch;
}

/** «Снять» напоминание вида kind: все слова вида — false (общее — тоже: другой клиент мог
 * оставить его на письме). */
export function clearReminderKindPatch(keywords: Keywords, kind: ReminderKind): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  for (const word of Object.keys(keywords)) {
    if (reminderKindOf(word) === kind) patch[`keywords/${word}`] = false;
  }
  patch[`keywords/${GENERAL[kind]}`] = false;
  return patch;
}

/** «Снять напоминание»: слова всех видов — false. */
export function clearRemindersPatch(keywords: Keywords): Record<string, unknown> {
  const patch: Record<string, unknown> = {};
  for (const kind of KINDS) Object.assign(patch, clearReminderKindPatch(keywords, kind));
  return patch;
}

// ---------- Группировка полосы ----------

/** Пункт полосы: письмо (моменты считаются из слов на месте — кэш писем уже нормализован по id). */
export interface ReminderItem {
  id: string;
  subject: string | null;
  keywords: Keywords;
}

/** Секции полосы: «Просрочено» (янтарным), «Сегодня», «Далее» (7 дней), «Ждём ответа». */
export interface ReminderGroups {
  overdue: ReminderItem[];
  today: ReminderItem[];
  next: ReminderItem[];
  /** Сроки дальше 7 дней — счётчиком («Ещё N позже»). */
  later: number;
  wait: ReminderItem[];
}

const NEXT_DAYS = 7;

export function groupReminders(items: ReminderItem[], now: Date): ReminderGroups {
  const endOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate(), 23, 59, 59, 999);
  const horizon = endOfToday.getTime() + NEXT_DAYS * 86_400_000;
  const groups: ReminderGroups = { overdue: [], today: [], next: [], later: 0, wait: [] };
  for (const item of items) {
    const m = reminderMomentsOf(item.keywords);
    // «Ждём ответа»: pm.wait без срока или просроченное ожидание (дата ожидания прошла).
    if (m.wait && (!m.wait.at || m.wait.at.getTime() <= now.getTime())) {
      groups.wait.push(item);
      continue;
    }
    // Только «Исчезнет» (без срока и ожидания) в полосе не показываем — фильтр «Истекают» в списке.
    if (!m.due?.at) continue;
    const at = m.due.at.getTime();
    if (at <= now.getTime()) groups.overdue.push(item);
    else if (at <= endOfToday.getTime()) groups.today.push(item);
    else if (at <= horizon) groups.next.push(item);
    else groups.later += 1;
  }
  const byDue = (a: ReminderItem, b: ReminderItem): number =>
    (reminderMomentsOf(a.keywords).due?.at?.getTime() ?? 0) - (reminderMomentsOf(b.keywords).due?.at?.getTime() ?? 0);
  groups.overdue.sort(byDue); // самый старый срок — сверху
  groups.today.sort(byDue);
  groups.next.sort(byDue);
  groups.wait.sort((a, b) => {
    const aa = reminderMomentsOf(a.keywords).wait?.at?.getTime() ?? Number.POSITIVE_INFINITY;
    const bb = reminderMomentsOf(b.keywords).wait?.at?.getTime() ?? Number.POSITIVE_INFINITY;
    return aa - bb; // дольше ждём — выше; без даты ожидания — в конце
  });
  return groups;
}

/** Всего напоминаний в полосе (счётчик свёрнутого вида). */
export function remindersTotal(groups: ReminderGroups): number {
  return groups.overdue.length + groups.today.length + groups.next.length + groups.later + groups.wait.length;
}

/** Секции полосы в порядке срочности; `quick` — быстрый фильтр «Почты» по клику на секцию. */
export const REMINDER_SECTIONS = [
  { id: "overdue", label: "Просрочено", quick: "due" },
  { id: "today", label: "Сегодня", quick: "due" },
  { id: "next", label: "Далее", quick: "due" },
  { id: "wait", label: "Ждём ответа", quick: "wait" },
] as const;

export type ReminderSectionId = (typeof REMINDER_SECTIONS)[number]["id"];

// ---------- Подписи (как чипы списка) ----------

function timeOf(at: Date): string {
  return at.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" });
}

/** Подпись срока: с временем из слова — «Сегодня 14:30», «Завтра 09:00», «Просрочено сегодня 09:00»;
 * дата без времени — как чип списка («До ср», «Просрочено N д»). Момента нет — null. */
export function reminderDueText(m: ReminderMoment | null, now: Date): string | null {
  const at = m?.at;
  if (!at) return null;
  if (at.getTime() <= now.getTime()) {
    if (m?.timed) {
      return at.toDateString() === now.toDateString()
        ? `Просрочено сегодня ${timeOf(at)}`
        : `Просрочено ${overdueDays(at, now) ?? 1} д`;
    }
    const days = overdueDays(at, now);
    return days !== null ? `Просрочено ${days} д` : "Срок сегодня";
  }
  if (!m?.timed) {
    // Дата без времени — конец дня: подпись как у чипа списка (dueLabel).
    const lc: Lifecycle = { threat: false, due: { at, general: true }, wait: null, expire: null };
    return dueLabel(lc, now)?.text ?? null;
  }
  const time = timeOf(at);
  if (at.toDateString() === now.toDateString()) return `Сегодня ${time}`;
  const tomorrow = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
  if (at.toDateString() === tomorrow.toDateString()) return `Завтра ${time}`;
  return `${at.toLocaleDateString("ru", { day: "2-digit", month: "2-digit" })} ${time}`;
}

/** Текст напоминаний письма (панель чтения): «До ср · Ждём ответа» или null — напоминаний нет. */
export function reminderTextOf(keywords: Keywords, now: Date): string | null {
  const lc = lifecycleOf(keywords);
  const m = reminderMomentsOf(keywords);
  const parts: string[] = [];
  if (lc.due) {
    const due = m.due?.at && m.due.timed ? reminderDueText(m.due, now) : (dueLabel(lc, now)?.text ?? null);
    if (due) parts.push(due);
  }
  const wait = waitLabel(lc, now);
  if (wait) parts.push(wait);
  if (m.expire?.at) {
    const when = m.expire.timed
      ? reminderDueText(m.expire, now)
      : m.expire.at.toLocaleDateString("ru", { day: "2-digit", month: "2-digit" });
    parts.push(`Исчезнет: ${when}`);
  }
  return parts.length > 0 ? parts.join(" · ") : null;
}

// ---------- Навигация полосы → раздел «Почта» (WEB-19) ----------

/** Переход от полосы: быстрый фильтр «Почты» (клик по секции) или письмо открыть (клик по пункту). */
export interface ReminderNavigation {
  quick?: "due" | "wait";
  open?: string;
}

/** Событие окна: «Почта» смонтирована и применит переход сразу (setState в колбэке события). */
export const REMINDER_NAV_EVENT = "thepost-reminders-nav";

let pendingNavigation: ReminderNavigation | null = null;

/** Клик полосы: полоса живёт над роутом — переход применит «Почта», и событием, если она уже
 * смонтирована, или «с руки» при монтировании (клик из Календаря/Контактов). */
export function sendReminderNavigation(nav: ReminderNavigation): void {
  pendingNavigation = nav;
  window.dispatchEvent(new CustomEvent(REMINDER_NAV_EVENT));
}

/** Забрать переход (один раз): при монтировании «Почты» и в обработчике события. */
export function takeReminderNavigation(): ReminderNavigation | null {
  const nav = pendingNavigation;
  pendingNavigation = null;
  return nav;
}

// ---------- Пресеты пикера и поля ввода ----------

/** Пресет «Завтра 9:00» (местное время). */
export function presetTomorrow9(now: Date): Date {
  const d = new Date(now);
  d.setDate(d.getDate() + 1);
  d.setHours(9, 0, 0, 0);
  return d;
}

/** Пресет «Через неделю» (местное время, 9:00). */
export function presetInWeek(now: Date): Date {
  const d = new Date(now);
  d.setDate(d.getDate() + 7);
  d.setHours(9, 0, 0, 0);
  return d;
}

/** Значение для `<input type="date">`: ГГГГ-ММ-ДД (местное). */
export function toInputDate(at: Date): string {
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`;
}

/** Значение для `<input type="time">`: ЧЧ:ММ. */
export function toInputTime(at: Date): string {
  return `${pad(at.getHours())}:${pad(at.getMinutes())}`;
}

/** Дата из полей пикера: с временем — местный момент, без — конец дня (дата — местная, S5-04);
 * поля не разобрались или время вне суток — null (Date иначе тихо переводит переполнение). */
export function fromInputDateTime(date: string, time: string | null): Date | null {
  const d = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  if (!d) return null;
  const [y, mo, day] = [Number(d[1]), Number(d[2]), Number(d[3])];
  if (mo < 1 || mo > 12 || day < 1 || day > 31) return null;
  const timed = time !== null && time !== "";
  let hh = 23;
  let mm = 59;
  if (timed) {
    const t = /^(\d{2}):(\d{2})$/.exec(time as string);
    if (!t) return null;
    hh = Number(t[1]);
    mm = Number(t[2]);
    if (hh > 23 || mm > 59) return null;
  }
  const at = timed ? new Date(y, mo - 1, day, hh, mm, 0, 0) : new Date(y, mo - 1, day, 23, 59, 59, 999);
  return Number.isNaN(at.getTime()) ? null : at;
}
