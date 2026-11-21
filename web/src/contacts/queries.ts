/*
  Запросы контактов (WEB-07): TanStack Query поверх JMAP — книги (AddressBook/get), снимок
  карточек для списка и подсказок (ContactCard/query окном + ContactCard/get кусками),
  серверный поиск (фильтр с OR вариантов раскладки — search.ts) и карточка по идентификатору.
  Мутации — ContactCard/set: создание и правка карточки, удаление, группы (карточки kind=group
  с members по uid: создать, переименовать, добавить/убрать участника, удалить). Ключи — в
  mail/client.ts, инвалидация — contacts/sync.ts (push) и после мутаций.
*/
import { useMutation, useQuery } from "@tanstack/react-query";

import { hasCapability } from "../api/jmap";
import { keys, queryClient } from "../mail/client";
import { useJmap } from "../mail/context";
import type { JmapEnv } from "../mail/types";
import { CAP_CONTACTS } from "../api/jmap";
import {
  addressBooksGet,
  contactCardGet,
  contactCardSearch,
  contactCardSet,
  contactCardSnapshot,
  setErrorText,
} from "./client";
import {
  cardFromForm,
  fillForm,
  nameComponents,
  type AddressBookObject,
  type ContactCard,
  type ContactForm,
} from "./model";
import { contactSearchFilter } from "./search";

/** Есть ли адресные книги у почтовой учётной записи (по сессии, без запроса). */
export function hasContactsCapability(env: JmapEnv): boolean {
  return hasCapability(env.session, env.accountId, CAP_CONTACTS);
}

/** Инвалидация всех ключей контактов (после мутаций и по push — contacts/sync.ts). */
export function invalidateContacts(): void {
  void queryClient.invalidateQueries({ queryKey: ["address-books"] });
  void queryClient.invalidateQueries({ queryKey: ["contact-snapshot"] });
  void queryClient.invalidateQueries({ queryKey: ["contact-search"] });
  void queryClient.invalidateQueries({ queryKey: ["contact-card"] });
}

/** Книги учётной записи, включая «Организация» (GAL, read-only по myRights). */
export function useAddressBooks(): AddressBookObject[] {
  const env = useJmap();
  const enabled = hasContactsCapability(env);
  const query = useQuery<AddressBookObject[]>({
    queryKey: keys.addressBooks(),
    queryFn: () => addressBooksGet(env.apiUrl, env.authorization, env.accountId),
    enabled,
  });
  return enabled ? query.data ?? [] : [];
}

/** Снимок карточек учётной записи (список раздела без поиска, подсказки, участники групп). */
export function useContactSnapshot(): ContactCard[] {
  const env = useJmap();
  const enabled = hasContactsCapability(env);
  const query = useQuery<ContactCard[]>({
    queryKey: keys.contactSnapshot(),
    queryFn: () => contactCardSnapshot(env.apiUrl, env.authorization, env.accountId),
    enabled,
  });
  return enabled ? query.data ?? [] : [];
}

/** Аргументы серверного поиска карточек: запрос и перевод раскладки в фильтре. */
export interface ContactSearchArgs {
  query: string;
  translit: boolean;
}

/** Аргументы запроса в ключе кэша (фильтр с OR вариантов раскладки). */
export function contactSearchArgs(args: ContactSearchArgs): Record<string, unknown> {
  return { query: args.query.trim().toLowerCase(), translit: args.translit };
}

/** Серверный поиск карточек: имя/адрес/организация/телефон, устойчив к раскладке. */
export function useContactSearch(args: ContactSearchArgs): ContactCard[] | null {
  const env = useJmap();
  const enabled = hasContactsCapability(env) && args.query.trim() !== "";
  const query = useQuery<ContactCard[]>({
    queryKey: keys.contactSearch(contactSearchArgs(args)),
    queryFn: async () => {
      const filter = contactSearchFilter(args.query, args.translit);
      if (!filter) return [];
      return contactCardSearch(env.apiUrl, env.authorization, env.accountId, filter);
    },
    enabled,
  });
  return enabled ? query.data ?? null : null;
}

/** Карточка по идентификатору (маршрут /contacts/:id). */
export function useContactCard(id: string): ContactCard | null {
  const env = useJmap();
  const enabled = hasContactsCapability(env) && id !== "";
  const query = useQuery<ContactCard[]>({
    queryKey: keys.contactCard(id),
    queryFn: () => contactCardGet(env.apiUrl, env.authorization, env.accountId, [id]),
    enabled,
  });
  return enabled ? query.data?.[0] ?? null : null;
}

/** Книга для карточки контакта: id книги из карточки (иначе — null). */
export function useBookById(): (id: string | null) => AddressBookObject | null {
  const books = useAddressBooks();
  return (id) => (id ? books.find((b) => b.id === id) ?? null : null);
}

function setFailure(result: { errors: Record<string, { type?: string; description?: string }> }, key: string, fallback: string): Error {
  return new Error(setErrorText(result.errors[key], fallback));
}

/** Создание карточки в личной книге (GAL — сервер ответит forbidden; UI его не предлагает). */
export function useContactCreate() {
  const env = useJmap();
  return useMutation({
    mutationFn: async ({ form, bookId }: { form: ContactForm; bookId: string }) => {
      const result = await contactCardSet(env.apiUrl, env.authorization, env.accountId, {
        create: { c: cardFromForm(form, { [bookId]: true }) },
      });
      const id = result.created["c"]?.id;
      if (!id) throw setFailure(result, "c", "Сервер не сохранил контакт.");
      return id;
    },
    onSettled: () => invalidateContacts(),
  });
}

/** Правка карточки: поля формы целиком (патч), книга не меняется. */
export function useContactUpdate() {
  const env = useJmap();
  return useMutation({
    mutationFn: async ({ id, form }: { id: string; form: ContactForm }) => {
      const patch: ContactCard = {};
      fillForm(patch, form);
      const result = await contactCardSet(env.apiUrl, env.authorization, env.accountId, {
        update: { [id]: patch },
      });
      if (!result.updated[id] && result.errors[id]) {
        throw setFailure(result, id, "Сервер не сохранил контакт.");
      }
      return id;
    },
    onSettled: () => invalidateContacts(),
  });
}

/** Удаление карточки (контакта или группы). */
export function useContactDelete() {
  const env = useJmap();
  return useMutation({
    mutationFn: async (id: string) => {
      const result = await contactCardSet(env.apiUrl, env.authorization, env.accountId, {
        destroy: [id],
      });
      if (!result.destroyed.includes(id)) {
        throw setFailure(result, id, "Сервер не удалил карточку.");
      }
      return id;
    },
    onSettled: () => invalidateContacts(),
  });
}

/** Карточка группы: kind=group, имя, пустой набор участников, книга (свои — правится). */
function groupCard(name: string, bookId: string): ContactCard {
  return {
    "@type": "Card",
    version: "1.0",
    kind: "group",
    name: { full: name },
    members: {},
    addressBookIds: { [bookId]: true },
  };
}

/** Создание группы рассылки (в личной книге; RFC 9610 — группа та же карточка). */
export function useGroupCreate() {
  const env = useJmap();
  return useMutation({
    mutationFn: async ({ name, bookId }: { name: string; bookId: string }) => {
      const result = await contactCardSet(env.apiUrl, env.authorization, env.accountId, {
        create: { g: groupCard(name, bookId) },
      });
      const id = result.created["g"]?.id;
      if (!id) throw setFailure(result, "g", "Сервер не создал группу.");
      return id;
    },
    onSettled: () => invalidateContacts(),
  });
}

/** Переименование группы. */
export function useGroupRename() {
  const env = useJmap();
  return useMutation({
    mutationFn: async ({ id, name }: { id: string; name: string }) => {
      const result = await contactCardSet(env.apiUrl, env.authorization, env.accountId, {
        update: { [id]: { name: { full: name, components: nameComponents(name) } } },
      });
      if (!result.updated[id] && result.errors[id]) {
        throw setFailure(result, id, "Сервер не переименовал группу.");
      }
      return id;
    },
    onSettled: () => invalidateContacts(),
  });
}

/** Участник группы: патч JSON-указателем members/<uid> (true — добавить, null — убрать). */
function memberPatch(uid: string, add: boolean): ContactCard {
  return { [`members/${uid}`]: add ? true : null };
}

export function useGroupMemberMutation() {
  const env = useJmap();
  return useMutation({
    mutationFn: async ({ groupId, uid, add }: { groupId: string; uid: string; add: boolean }) => {
      const result = await contactCardSet(env.apiUrl, env.authorization, env.accountId, {
        update: { [groupId]: memberPatch(uid, add) },
      });
      if (!result.updated[groupId] && result.errors[groupId]) {
        throw setFailure(result, groupId, "Сервер не обновил группу.");
      }
      return groupId;
    },
    onSettled: () => invalidateContacts(),
  });
}
