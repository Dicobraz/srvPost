/*
  Модель карточки контакта (WEB-07): JSContact (RFC 9553) — то, что сервер хранит в vCard и
  отдаёт ContactCard/get (tp-jmap contact_card.rs). Помощники читают поля карточки (имя,
  адреса, телефоны, организация, фото, заметки, группа), сборщики — готовят объекты /set
  (создание и патчи правки). Группа рассылки (RFC 9610) — та же карточка с kind=group и
  members по uid участников; сервер ищет её фильтром kind/hasMember.
*/

/** Сырая карточка JSContact + свойства JMAP (RFC 9610 §3): то, что приходит от ContactCard/get. */
export type ContactCard = Record<string, unknown>;

/** Книга адресов (RFC 9610 §2): AddressBook/get, книга GAL — read-only по myRights. */
export interface AddressBookObject {
  id: string;
  name: string;
  description: string | null;
  sortOrder: number;
  isDefault: boolean;
  isSubscribed: boolean;
  myRights: {
    mayRead: boolean;
    mayWrite: boolean;
    mayShare: boolean;
    mayDelete: boolean;
  };
}

/** Права на книгу: писать можно в свою с mayWrite; книга «Организация» (GAL) — только чтение. */
export function bookWritable(book: AddressBookObject | null): boolean {
  return Boolean(book?.myRights?.mayWrite);
}

/** Полное имя карточки: name.full, иначе — компоненты через пробел (выгрузки без full). */
export function fullNameOf(card: ContactCard): string {
  const name = card.name as { full?: unknown; components?: Array<{ value?: unknown }> } | undefined;
  if (name && typeof name.full === "string" && name.full.trim()) return name.full.trim();
  const joined = (name?.components ?? [])
    .map((c) => (typeof c.value === "string" ? c.value.trim() : ""))
    .filter(Boolean)
    .join(" ")
    .trim();
  return joined;
}

/** Адреса e-mail карточки (по pref, как в vCard); адрес без «@» не адрес. */
export function emailsOf(card: ContactCard): string[] {
  const emails = card.emails as Record<string, { address?: unknown; pref?: unknown }> | undefined;
  if (!emails) return [];
  return Object.values(emails)
    .sort((a, b) => Number(b?.pref ?? 0) - Number(a?.pref ?? 0))
    .map((e) => (typeof e?.address === "string" ? e.address.trim() : ""))
    .filter((a) => a.includes("@"));
}

/** Первый (предпочтительный) адрес карточки. */
export function primaryEmailOf(card: ContactCard): string | null {
  return emailsOf(card)[0] ?? null;
}

/** Телефоны карточки (по pref). */
export function phonesOf(card: ContactCard): string[] {
  const phones = card.phones as Record<string, { number?: unknown; pref?: unknown }> | undefined;
  if (!phones) return [];
  return Object.values(phones)
    .sort((a, b) => Number(b?.pref ?? 0) - Number(a?.pref ?? 0))
    .map((p) => (typeof p?.number === "string" ? p.number.trim() : ""))
    .filter(Boolean);
}

/** Организация: имя первой организации (подразделения не показываем). */
export function organizationOf(card: ContactCard): string | null {
  const orgs = card.organizations as Record<string, { name?: unknown }> | undefined;
  const name = Object.values(orgs ?? {})[0]?.name;
  return typeof name === "string" && name.trim() ? name.trim() : null;
}

/** Должность (titles, kind=title). */
export function titleOf(card: ContactCard): string | null {
  const titles = card.titles as Record<string, { name?: unknown }> | undefined;
  const name = Object.values(titles ?? {})[0]?.name;
  return typeof name === "string" && name.trim() ? name.trim() : null;
}

/** Фото карточки: URL первой фотографии (макет — круглый аватар). */
export function photoUrlOf(card: ContactCard): string | null {
  const photos = card.photos as Record<string, { url?: unknown }> | undefined;
  const url = Object.values(photos ?? {})[0]?.url;
  return typeof url === "string" && url.trim() ? url.trim() : null;
}

/** Заметки карточки: текст первой заметки. */
export function notesOf(card: ContactCard): string | null {
  const notes = card.notes as Record<string, { note?: unknown }> | undefined;
  const note = Object.values(notes ?? {})[0]?.note;
  return typeof note === "string" && note.trim() ? note.trim() : null;
}

/** Карточка — группа рассылки (kind=group, RFC 9610 §1.6.2). */
export function isGroupCard(card: ContactCard): boolean {
  return card.kind === "group";
}

/** Инициалы для круглого аватара (макет 02): первые буквы имени, без имени — начало адреса. */
export function initials(name: string, email: string | null): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length > 0) {
    return ((parts[0]?.[0] ?? "") + (parts[1]?.[0] ?? "")).toUpperCase() ||
      name.slice(0, 2).toUpperCase();
  }
  return (email?.split("@")[0] ?? "?").slice(0, 2).toUpperCase();
}

/** uid участников группы: members — карта «uid → true». */
export function memberUidsOf(card: ContactCard): string[] {
  const members = card.members as Record<string, unknown> | undefined;
  return Object.entries(members ?? {})
    .filter(([, on]) => on === true)
    .map(([uid]) => uid);
}

/** Книга карточки: единственный ключ addressBookIds (сервер: maxAddressBooksPerCard=1). */
export function bookIdOf(card: ContactCard): string | null {
  const books = card.addressBookIds as Record<string, unknown> | undefined;
  const on = Object.entries(books ?? {}).filter(([, v]) => v === true);
  return on.length === 1 ? on[0][0] : null;
}

/** Компоненты имени из строки: первое слово — given, последнее — surname (для сортировки
 * name/given на сервере; одно слово — только given). */
export function nameComponents(full: string): Array<{ kind: string; value: string }> {
  const words = full.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return [];
  if (words.length === 1) return [{ kind: "given", value: words[0] }];
  return [
    { kind: "given", value: words[0] },
    { kind: "surname", value: words[words.length - 1] },
  ];
}

/** Данные формы контакта — то, что редактирует CardEditor. */
export interface ContactForm {
  name: string;
  emails: string[];
  phones: string[];
  organization: string;
  photoUrl: string;
  notes: string;
}

/** Форма из карточки (правка). */
export function formOf(card: ContactCard): ContactForm {
  return {
    name: fullNameOf(card),
    emails: emailsOf(card),
    phones: phonesOf(card),
    organization: organizationOf(card) ?? "",
    photoUrl: photoUrlOf(card) ?? "",
    notes: notesOf(card) ?? "",
  };
}

/** Объект создания (ContactCard/set create) из формы: книга обязательна (GAL — forbidden). */
export function cardFromForm(form: ContactForm, addressBookIds: Record<string, boolean>): ContactCard {
  const card: ContactCard = {
    "@type": "Card",
    version: "1.0",
    addressBookIds,
    name: { full: form.name.trim(), components: nameComponents(form.name) },
  };
  fillForm(card, form);
  return card;
}

/** Записывает редактируемые поля формы в карточку (патч правки: поля целиком). */
export function fillForm(card: ContactCard, form: ContactForm): void {
  const emails: ContactCard = {};
  form.emails
    .map((e) => e.trim())
    .filter(Boolean)
    .forEach((address, i) => {
      emails[`e${i}`] = { address, ...(i === 0 ? { pref: 1 } : {}) };
    });
  if (Object.keys(emails).length > 0) card.emails = emails;
  else card.emails = null;
  const phones: ContactCard = {};
  form.phones
    .map((p) => p.trim())
    .filter(Boolean)
    .forEach((number, i) => {
      phones[`p${i}`] = { number };
    });
  if (Object.keys(phones).length > 0) card.phones = phones;
  else card.phones = null;
  const org = form.organization.trim();
  card.organizations = org ? { o: { name: org } } : null;
  const photo = form.photoUrl.trim();
  card.photos = photo ? { p: { url: photo } } : null;
  const notes = form.notes.trim();
  card.notes = notes ? { n: { note: notes } } : null;
  const full = form.name.trim();
  card.name = { full, components: nameComponents(full) };
}
