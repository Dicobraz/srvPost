/*
  Общие ящики и «Взять в работу» (WEB-15): формат слова «взял» — как в Postman (`postman_core::marks`,
  S5-28), чтобы состояние было общим между клиентами: общее слово `pm.taken` + слово с тем, кто взял и
  когда — `pm.taken.<ГГГГ-ММ-ДД>t<ЧЧММ>z.<адрес>` (например `pm.taken.2026-10-22t1042z.p.koval@corp.example`).
  «Взять» ставит оба слова и снимает прежние «взял»; «Вернуть» снимает все слова «взял» (PATCH
  `keywords/<слово>` в Email/set). Кто держит письмо — из слов «взял» позднее (при равном времени —
  меньший адрес, одинаково у всех клиентов). Общие ящики (JMAP-49, делегированный доступ): чужие
  учётные записи сессии — `isPersonal: false` с capability почты; папки чужого аккаунта Mailbox/get
  делегату не отдаёт, поэтому в дереве секция «Общие» — по строке на общий ящик, письма — Email/query
  с его accountId.
*/
import { CAP_MAIL, type EmailSummary, type JmapSession, type Keywords } from "../api/jmap";

/** Общее слово «Взято в работу»: по нему сервер и клиенты находят взятые письма. */
export const TAKEN = "pm.taken";

const TAKEN_PREFIX = "pm.taken.";

/** Кто взял письмо общего ящика в работу и когда. */
export interface Taken {
  /** Адрес взявшего (нижний регистр). */
  who: string;
  at: Date;
}

/** Взял `me` (адрес сравнивается без регистра). */
export function takenBy(t: Taken, me: string): boolean {
  return t.who.toLowerCase() === me.trim().toLowerCase();
}

/** Допустимое ключевое слово JMAP: 1–255 знаков %x21-7E без `( ) { ] % * " \`, без заглавных
 * (RFC 8621 §4.1.1; как `labels::valid_keyword` Postman). */
export function validKeyword(k: string): boolean {
  if (k.length < 1 || k.length > 255) return false;
  for (const byte of new TextEncoder().encode(k)) {
    if (byte < 0x21 || byte > 0x7e) return false;
    if ("(){]%*\"\\".includes(String.fromCharCode(byte))) return false;
    if (byte >= 0x41 && byte <= 0x5a) return false;
  }
  return true;
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : String(n);
}

/** Слово «взял `who` в `at`»: `pm.taken.2026-10-22t1042z.p.koval@corp.example`. Адрес, который не
 * годится в ключевое слово JMAP (пробел, кавычка, скобка…), — null. */
export function takenKeyword(who: string, at: Date): string | null {
  const w = who.trim().toLowerCase();
  if (!w) return null;
  const stamp = `${at.getUTCFullYear()}-${pad(at.getUTCMonth() + 1)}-${pad(at.getUTCDate())}t${pad(at.getUTCHours())}${pad(at.getUTCMinutes())}`;
  const k = `${TAKEN_PREFIX}${stamp}z.${w}`;
  return validKeyword(k) ? k : null;
}

/** Разбор слова «взял»: `pm.taken.<ГГГГ-ММ-ДД>t<ЧЧММ>z.<адрес>`; чужой формат — null (как
 * `parse_taken` Postman: 15 знаков штампа, `z.`, адрес с `@`). */
export function parseTaken(keyword: string): Taken | null {
  if (!keyword.slice(0, TAKEN_PREFIX.length).toLowerCase().startsWith(TAKEN_PREFIX)) return null;
  const rest = keyword.slice(TAKEN_PREFIX.length);
  if (rest.length < 18) return null;
  if (rest.slice(15, 17).toLowerCase() !== "z.") return null;
  const stamp = rest.slice(0, 15);
  const who = rest.slice(17);
  if (!who || !who.includes("@")) return null;
  const m = /^(\d{4}-\d{2}-\d{2})t(\d{2})(\d{2})$/.exec(stamp);
  if (!m) return null;
  const at = new Date(`${m[1]}T${m[2]}:${m[3]}:00Z`);
  if (Number.isNaN(at.getTime())) return null;
  return { who: who.toLowerCase(), at };
}

/** Слово относится к «Взять в работу»: общее или со временем и адресом (в том числе неразобранное). */
export function isTakenWord(keyword: string): boolean {
  const head = keyword.slice(0, TAKEN.length).toLowerCase();
  if (head !== TAKEN) return false;
  return keyword.length === TAKEN.length || keyword[TAKEN.length] === ".";
}

/** Кто держит письмо: из слов «взял» — позднее (при равном времени — меньший адрес, одинаково у
 * всех). Нет слова — никто, даже если общее слово осталось (другой клиент снял не всё). */
export function takenOf(keywords: Keywords): Taken | null {
  let best: Taken | null = null;
  for (const [word, on] of Object.entries(keywords)) {
    if (!on) continue;
    const t = parseTaken(word);
    if (!t) continue;
    if (!best || t.at > best.at || (t.at.getTime() === best.at.getTime() && t.who < best.who)) best = t;
  }
  return best;
}

/** Что поставит «Взять в работу»: слова к включению (`pm.taken` + своё) и к снятию (прежние «взял»).
 * Адрес не годится в ключевое слово — null (Postman `marks::taking`). */
export function takeKeywordChanges(
  keywords: Keywords,
  me: string,
  at: Date,
): { add: string[]; remove: string[] } | null {
  const add = takenKeyword(me, at);
  if (!add) return null;
  const remove: string[] = [];
  for (const word of Object.keys(keywords)) {
    if (!isTakenWord(word) || word.toLowerCase() === TAKEN || word.toLowerCase() === add.toLowerCase()) continue;
    if (!remove.includes(word)) remove.push(word);
  }
  return { add: [TAKEN, add], remove };
}

/** Что снимет «Вернуть в очередь»: все слова «взял» (общее — тоже, даже если его уже нет на письме). */
export function releaseKeywordChanges(keywords: Keywords): string[] {
  const out = Object.keys(keywords).filter((w) => isTakenWord(w) && keywords[w]);
  if (!out.some((w) => w.toLowerCase() === TAKEN)) out.push(TAKEN);
  return out;
}

/** Что сделает «Взять в работу» с письмом (кнопка и Ctrl+J): взять, забрать у коллеги или вернуть своё. */
export type TakeAct = "take" | "steal" | "release";

export function takeActOf(keywords: Keywords, me: string): TakeAct {
  const t = takenOf(keywords);
  if (!t) return "take";
  return takenBy(t, me) ? "release" : "steal";
}

/** Подпись действия (как в Postman: «Взять в работу» / «Забрать себе» / «Вернуть в очередь»). */
export const TAKE_LABELS: Record<TakeAct, string> = {
  take: "Взять в работу",
  steal: "Забрать себе",
  release: "Вернуть в очередь",
};

/** Время «взял»: сегодня — «10:42», раньше — «22.10, 16:30» (как в строках списка). */
export function takenWhen(at: Date, now: Date = new Date()): string {
  const time = at.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" });
  if (at.toDateString() === now.toDateString()) return time;
  return `${at.toLocaleDateString("ru", { day: "2-digit", month: "2-digit" })}, ${time}`;
}

// ---------- Общие ящики сессии (JMAP-49) ----------

/** Общий ящик сессии: чужая учётная запись с capability почты. */
export interface SharedMailAccount {
  id: string;
  /** Имя аккаунта (имя входа владельца — оно же адрес общего ящика). */
  name: string;
  /** Ни на одну общую папку нет права записи (сессия, `isReadOnly`). */
  readOnly: boolean;
}

/** Чужие учётные записи почты сессии: `isPersonal: false` + capability почты (JMAP-49). */
export function sharedMailAccounts(session: JmapSession): SharedMailAccount[] {
  const out: SharedMailAccount[] = [];
  for (const [id, account] of Object.entries(session.accounts)) {
    if (account.isPersonal) continue;
    if (!account.accountCapabilities?.[CAP_MAIL]) continue;
    out.push({ id, name: account.name, readOnly: Boolean(account.isReadOnly) });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name, "ru"));
}

/** Ключ выбора дерева для общего ящика (свои папки — id папки, «Отмеченные» — flagged). */
export const SHARED_PREFIX = "shared:";

export function sharedFolderKey(id: string): string {
  return `${SHARED_PREFIX}${id}`;
}

export function isSharedFolderKey(key: string | null): boolean {
  return typeof key === "string" && key.startsWith(SHARED_PREFIX);
}

export function sharedAccountId(key: string | null): string | null {
  return isSharedFolderKey(key) ? (key as string).slice(SHARED_PREFIX.length) : null;
}

// ---------- Патчи «Взять/Вернуть» для Email/set ----------

/** Патч письма для Email/set update: слова «взял» — включить/выключить. Адрес не годится в слово —
 * null (нечего ставить). */
export function takePatchOf(email: EmailSummary, me: string, at: Date): Record<string, unknown> | null {
  const act = takeActOf(email.keywords, me);
  if (act === "release") {
    const patch: Record<string, unknown> = {};
    for (const w of releaseKeywordChanges(email.keywords)) patch[`keywords/${w}`] = false;
    return patch;
  }
  const changes = takeKeywordChanges(email.keywords, me, at);
  if (!changes) return null;
  const patch: Record<string, unknown> = {};
  for (const w of changes.remove) patch[`keywords/${w}`] = false;
  for (const w of changes.add) patch[`keywords/${w}`] = true;
  return patch;
}
