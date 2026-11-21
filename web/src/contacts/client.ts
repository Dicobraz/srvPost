/*
  Клиент контактов (WEB-07): AddressBook/get (книги, книга GAL — read-only по myRights),
  ContactCard/query+get (карточки JSContact) и ContactCard/set (создание, правка, удаление,
  группы members). Капабилити `urn:ietf:params:jmap:contacts` (RFC 9610) — сервер отклоняет
  методы без неё, callMethod ведёт их под ней (api/jmap.ts). Снимок для автодополнения —
  окно query без фильтра (свойства: имя, адреса, организация, kind) + get кусками.
*/
import { callMethod } from "../api/jmap";
import type { AddressBookObject, ContactCard } from "./model";

/** Свойства карточки для списков и подсказок: без заметок, адресов и телефонов — легче. */
export const CARD_LIST_PROPERTIES = [
  "uid",
  "kind",
  "name",
  "emails",
  "organizations",
  "addressBookIds",
];

/** Свойства карточки карточки контакта (все поля раздела). */
export const CARD_FULL_PROPERTIES = [
  "uid",
  "kind",
  "name",
  "emails",
  "phones",
  "organizations",
  "titles",
  "photos",
  "addresses",
  "notes",
  "members",
  "addressBookIds",
  "updated",
];

/** `AddressBook/get` без идентификаторов — книги учётной записи, включая книгу GAL. */
export async function addressBooksGet(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
): Promise<AddressBookObject[]> {
  const result = await callMethod(apiUrl, authorization, "AddressBook/get", { accountId });
  return ((result.list as AddressBookObject[] | undefined) ?? []).filter(
    (b): b is AddressBookObject => typeof b?.id === "string",
  );
}

/** Страница запроса карточек: идентификаторы и итог выборки (окно — вызывающий). */
export async function contactCardQuery(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  filter: Record<string, unknown> | null,
  options: { position?: number; limit?: number } = {},
): Promise<{ ids: string[]; total: number | null }> {
  const result = await callMethod(apiUrl, authorization, "ContactCard/query", {
    accountId,
    filter: filter ?? undefined,
    sort: [{ property: "name/given" }],
    position: options.position ?? 0,
    ...(options.limit !== undefined ? { limit: options.limit } : {}),
    calculateTotal: options.limit === undefined ? true : false,
  });
  return {
    ids: (result.ids as string[] | undefined) ?? [],
    total: (result.total as number | undefined) ?? null,
  };
}

/** `ContactCard/get` по идентификаторам (кусок не больше maxObjectsInGet — вызывающий делит). */
export async function contactCardGet(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  ids: string[],
  properties: string[] = CARD_FULL_PROPERTIES,
): Promise<ContactCard[]> {
  if (ids.length === 0) return [];
  const result = await callMethod(apiUrl, authorization, "ContactCard/get", {
    accountId,
    ids,
    properties,
  });
  return ((result.list as ContactCard[] | undefined) ?? []).filter(
    (c): c is ContactCard => typeof c?.id === "string",
  );
}

/** Ошибка операции /set для человека: известные типы — по-русски, иначе описание сервера. */
export function setErrorText(
  error: { type?: string; description?: string } | undefined,
  fallback: string,
): string {
  if (!error) return fallback;
  // Известные типы — человекочитаемо (даже с английским описанием сервера).
  if (error.type === "forbidden") return "Книга только для чтения — правка недоступна.";
  if (error.type === "addressBookHasContents") return "Книга не пуста — удалите её карточки.";
  if (error.description) return error.description;
  return error.type ?? fallback;
}

/** Ответ ContactCard/set: интересующие части — созданное, изменённое, удалённое, ошибки. */
export interface CardSetResult {
  created: Record<string, { id?: string } & Record<string, unknown>>;
  updated: Record<string, unknown | null>;
  destroyed: string[];
  errors: Record<string, { type?: string; description?: string }>;
}

/** `ContactCard/set`: создание (объект целиком), правка (патч: поля целиком), удаление. */
export async function contactCardSet(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  changes: {
    create?: Record<string, ContactCard>;
    update?: Record<string, ContactCard>;
    destroy?: string[];
  },
): Promise<CardSetResult> {
  const result = await callMethod(apiUrl, authorization, "ContactCard/set", {
    accountId,
    ...(changes.create && Object.keys(changes.create).length > 0 ? { create: changes.create } : {}),
    ...(changes.update && Object.keys(changes.update).length > 0 ? { update: changes.update } : {}),
    ...(changes.destroy && changes.destroy.length > 0 ? { destroy: changes.destroy } : {}),
  });
  return {
    created: (result.created as CardSetResult["created"] | null) ?? {},
    updated: (result.updated as CardSetResult["updated"] | null) ?? {},
    destroyed: (result.destroyed as string[] | null) ?? [],
    errors: (result.notCreated as CardSetResult["errors"] | undefined) ??
      (result.notUpdated as CardSetResult["errors"] | undefined) ??
      (result.notDestroyed as CardSetResult["errors"] | undefined) ?? {},
  };
}

/** Снимок карточек для подсказок и списка: query окном (лимит узла больше не режет — 500),
 * затем get свойств списка кусками. Возвращаются карточки с адресом e-mail. */
export async function contactCardSnapshot(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  limit = 500,
): Promise<ContactCard[]> {
  const page = await contactCardQuery(apiUrl, authorization, accountId, null, { limit });
  const out: ContactCard[] = [];
  for (let i = 0; i < page.ids.length; i += 200) {
    const cards = await contactCardGet(
      apiUrl,
      authorization,
      accountId,
      page.ids.slice(i, i + 200),
      CARD_LIST_PROPERTIES,
    );
    out.push(...cards);
  }
  return out;
}

/** Поиск карточек сервером (фильтр — search.ts, раскладка OR) + get свойств списка. */
export async function contactCardSearch(
  apiUrl: string,
  authorization: string | null,
  accountId: string,
  filter: Record<string, unknown>,
  limit = 500,
): Promise<ContactCard[]> {
  const page = await contactCardQuery(apiUrl, authorization, accountId, filter, { limit });
  const out: ContactCard[] = [];
  for (let i = 0; i < page.ids.length; i += 200) {
    const cards = await contactCardGet(
      apiUrl,
      authorization,
      accountId,
      page.ids.slice(i, i + 200),
      CARD_LIST_PROPERTIES,
    );
    out.push(...cards);
  }
  return out;
}
