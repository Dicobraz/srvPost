/*
  Контакты для автодополнения (WEB-04): адресная книга из JMAP ContactCard (JSContact, RFC 9553),
  если в сессии есть капабилити contacts (учётная запись с адресной книгой, `tp-dav`). Нет
  капабилити — пусто (остаётся история отправок, send-history.ts). Поиск пока локальный: снимок
  карточек — ContactCard/query окном + ContactCard/get; серверный поиск по тексту (text-needle)
  подставит WEB-05/07. GAL в вебе появится с контактами (WEB-07, пометка в PR).
*/

import { callMethod, type JmapSession } from "../api/jmap";
import type { JmapEnv } from "../mail/types";
import type { Suggestion } from "./recipients";

/** Капабилити адресной книги (RFC 9610): ContactCard, AddressBook. */
export const CAP_CONTACTS = "urn:ietf:params:jmap:contacts";

/** Есть ли у почтовой учётной записи адресная книга (по сессии, без запроса). */
export function hasContacts(session: JmapSession, accountId: string): boolean {
  const caps = session.accounts[accountId]?.accountCapabilities ?? {};
  return Boolean(caps[CAP_CONTACTS]);
}

/** Первая почта карточки JSContact: emails — карта «ключ → {address, pref?}». */
function firstEmail(emails: unknown): string | null {
  if (typeof emails !== "object" || emails === null) return null;
  const entries = Object.values(emails as Record<string, { address?: unknown; pref?: unknown }>);
  const sorted = [...entries].sort((a, b) => Number(b?.pref ?? 0) - Number(a?.pref ?? 0));
  for (const e of sorted) {
    if (typeof e?.address === "string" && e.address.includes("@")) return e.address;
  }
  return null;
}

/** Полное имя карточки JSContact: name.full или компоненты. */
function fullName(name: unknown): string | null {
  if (typeof name === "object" && name !== null) {
    const full = (name as { full?: unknown }).full;
    if (typeof full === "string" && full.trim()) return full.trim();
    const components = (name as { components?: Array<{ value?: unknown }> }).components;
    const joined = (components ?? [])
      .map((c) => (typeof c.value === "string" ? c.value : ""))
      .join(" ")
      .trim();
    if (joined) return joined;
  }
  return null;
}

/**
 * Снимок контактов для подсказок: все карточки учётной записи (лимит 500) — имя и почта.
 * Нет капабилити или запрос не удался (чужая книга, нет прав) — пусто без ошибки: подсказки
 * необязательны, ввод адреса работает всегда.
 */
export async function loadContacts(env: JmapEnv): Promise<Suggestion[]> {
  if (!hasContacts(env.session, env.accountId)) return [];
  try {
    const query = await callMethod(env.apiUrl, env.authorization, "ContactCard/query", {
      accountId: env.accountId,
      position: 0,
      limit: 500,
    });
    const ids = (query.ids as string[] | undefined) ?? [];
    if (ids.length === 0) return [];
    const get = await callMethod(env.apiUrl, env.authorization, "ContactCard/get", {
      accountId: env.accountId,
      ids,
      properties: ["name", "emails"],
    });
    const list = ((get.list as Array<{ name?: unknown; emails?: unknown }> | undefined) ?? []).flatMap(
      (card) => {
        const email = firstEmail(card.emails);
        if (!email) return [];
        return [{ recipient: { name: fullName(card.name), email }, source: "Контакты" }];
      },
    );
    return list;
  } catch {
    return [];
  }
}

/** Домены контактов — внешними получателями не считаются (warnings.ts). */
export function domainsOf(suggestions: Suggestion[]): Set<string> {
  const out = new Set<string>();
  for (const s of suggestions) {
    const domain = s.recipient.email.split("@")[1]?.toLowerCase();
    if (domain) out.add(domain);
  }
  return out;
}
