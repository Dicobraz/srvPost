/*
  Контакты для автодополнения (WEB-07, дооснащение WEB-04): личные книги и книга «Организация»
  (GAL) из JMAP ContactCard (JSContact, RFC 9553/9610) + локальная история отправок сливаются
  в порядке Postman (contacts/autocomplete.ts). Разделение источников — по книгам: AddressBook/get
  даёт myRights, книга без права записи (GAL «Организация» из LDAP/PostgreSQL) подписывается
  «Справочник», свои — «Контакты» (макет 02). Нет капабилити contacts — пусто без запроса
  (ввод адреса руками работает всегда). Поиск подсказок — локальный по снимку, раскладко-
  устойчивый (recipients.ts/suggest: вариант qwerty→йцукен).
*/

import type { JmapSession } from "../api/jmap";
import type { JmapEnv } from "../mail/types";
import { addressBooksGet, contactCardSnapshot } from "../contacts/client";
import { emailsOf, fullNameOf, isGroupCard, type AddressBookObject, type ContactCard } from "../contacts/model";
import type { Suggestion } from "./recipients";

/** Капабилити адресной книги (RFC 9610): ContactCard, AddressBook. */
export const CAP_CONTACTS = "urn:ietf:params:jmap:contacts";

/** Есть ли у почтовой учётной записи адресная книга (по сессии, без запроса). */
export function hasContacts(session: JmapSession, accountId: string): boolean {
  const caps = session.accounts[accountId]?.accountCapabilities ?? {};
  return Boolean(caps[CAP_CONTACTS]);
}

/** Карточка → подсказка: полное имя и первый (предпочтительный) адрес; без адреса карточка
 * в подсказки не попадает. */
function suggestionOf(card: ContactCard, source: string): Suggestion | null {
  const email = emailsOf(card)[0];
  if (!email) return null;
  return { recipient: { name: fullNameOf(card) || null, email }, source };
}

/** Снимок источников подсказок: личные («Контакты») и справочник («Справочник»). Группы
 * (kind=group) и карточки без адреса не участвуют. Ошибка запроса — пусто без ошибки:
 * подсказки необязательны. */
export async function loadContactSources(env: JmapEnv): Promise<{ personal: Suggestion[]; gal: Suggestion[] }> {
  if (!hasContacts(env.session, env.accountId)) return { personal: [], gal: [] };
  try {
    let books: AddressBookObject[] = [];
    try {
      books = await addressBooksGet(env.apiUrl, env.authorization, env.accountId);
    } catch {
      // Нет книг (или метод не отвечает) — карточки всё равно читаются ниже.
    }
    // Книга без права записи — read-only справочник (GAL «Организация», чужая общая книга).
    const galBooks = new Set(books.filter((b) => !b.myRights?.mayWrite).map((b) => b.id));
    const cards = await contactCardSnapshot(env.apiUrl, env.authorization, env.accountId);
    const personal: Suggestion[] = [];
    const gal: Suggestion[] = [];
    for (const card of cards) {
      if (isGroupCard(card)) continue;
      const s = suggestionOf(card, "Контакты");
      if (!s) continue;
      const inGal = Object.keys(card.addressBookIds as Record<string, boolean> ?? {}).some((id) => galBooks.has(id));
      (inGal ? gal : personal).push(inGal ? { ...s, source: "Справочник" } : s);
    }
    return { personal, gal };
  } catch {
    return { personal: [], gal: [] };
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
