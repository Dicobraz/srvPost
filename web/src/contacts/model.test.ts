/*
  Модель карточки JSContact (WEB-07): чтение полей (имя, адреса по pref, телефоны, организация,
  фото, заметки, группа и участники), сборка объектов ContactCard/set (создание и правка).
*/
import { expect, test } from "vitest";

import {
  bookIdOf,
  bookWritable,
  cardFromForm,
  emailsOf,
  fillForm,
  formOf,
  fullNameOf,
  initials,
  isGroupCard,
  memberUidsOf,
  nameComponents,
  organizationOf,
  photoUrlOf,
  phonesOf,
  primaryEmailOf,
  type AddressBookObject,
  type ContactCard,
} from "./model";

const CARD = {
  "@type": "Card",
  uid: "urn:uuid:1111",
  id: "c1",
  kind: "individual",
  name: {
    full: "Мария Сидорова",
    components: [
      { kind: "given", value: "Мария" },
      { kind: "surname", value: "Сидорова" },
    ],
  },
  emails: {
    home: { address: "maria@home.example", pref: 1 },
    work: { address: "maria@vektor.example", pref: 3 },
  },
  phones: {
    m: { number: "+7 911 000-11-22" },
  },
  organizations: { o: { name: "АО Вектор", units: [{ name: "Бухгалтерия" }] } },
  titles: { t: { name: "Главный бухгалтер" } },
  photos: { p: { url: "https://example.org/maria.jpg" } },
  notes: { n: { note: "Звонить после 10" } },
  addressBookIds: { book1: true },
};

test("чтение полей: имя, адреса по pref, телефон, организация, фото, заметки, книга", () => {
  expect(fullNameOf(CARD)).toBe("Мария Сидорова");
  // pref 3 выше pref 1 — рабочий адрес первый.
  expect(emailsOf(CARD)).toEqual(["maria@vektor.example", "maria@home.example"]);
  expect(primaryEmailOf(CARD)).toBe("maria@vektor.example");
  expect(phonesOf(CARD)).toEqual(["+7 911 000-11-22"]);
  expect(organizationOf(CARD)).toBe("АО Вектор");
  expect(photoUrlOf(CARD)).toBe("https://example.org/maria.jpg");
  expect(bookIdOf(CARD)).toBe("book1");
  expect(isGroupCard(CARD)).toBe(false);
});

test("имя без full собирается из компонентов; без имени — пусто", () => {
  expect(fullNameOf({ name: { components: [{ value: "Олег" }, { value: "Лебедев" }] } })).toBe(
    "Олег Лебедев",
  );
  expect(fullNameOf({})).toBe("");
});

test("группа: kind=group, участники по uid", () => {
  const group = { kind: "group", name: { full: "Команда" }, members: { "urn:uuid:1": true, "urn:uuid:2": true, dead: false } };
  expect(isGroupCard(group)).toBe(true);
  expect(memberUidsOf(group)).toEqual(["urn:uuid:1", "urn:uuid:2"]);
});

test("книга read-only: GAL — myRights.mayWrite=false, правка недоступна; своя — доступна", () => {
  const gal: AddressBookObject = {
    id: "gal",
    name: "Организация",
    description: null,
    sortOrder: 0,
    isDefault: false,
    isSubscribed: true,
    myRights: { mayRead: true, mayWrite: false, mayShare: false, mayDelete: false },
  };
  const own: AddressBookObject = { ...gal, id: "own", name: "Личные", myRights: { ...gal.myRights, mayWrite: true } };
  expect(bookWritable(gal)).toBe(false);
  expect(bookWritable(own)).toBe(true);
  expect(bookWritable(null)).toBe(false);
});

test("компоненты имени: первое слово — given, последнее — surname; одно слово — given", () => {
  expect(nameComponents("Анна Смирнова")).toEqual([
    { kind: "given", value: "Анна" },
    { kind: "surname", value: "Смирнова" },
  ]);
  expect(nameComponents("Анна")).toEqual([{ kind: "given", value: "Анна" }]);
});

test("сборка создания: адреса/телефоны/организация/фото/заметки + книга; форма туда и обратно", () => {
  const form = {
    name: "Ольга Петрова",
    emails: ["olga@vektor.example", "olga@home.example"],
    phones: ["+7 495 111-22-33"],
    organization: "АО Вектор",
    photoUrl: "https://example.org/o.jpg",
    notes: "Бухгалтер",
  };
  const card = cardFromForm(form, { book1: true });
  expect(card.name).toEqual({
    full: "Ольга Петрова",
    components: [
      { kind: "given", value: "Ольга" },
      { kind: "surname", value: "Петрова" },
    ],
  });
  expect(card.emails).toEqual({
    e0: { address: "olga@vektor.example", pref: 1 },
    e1: { address: "olga@home.example" },
  });
  expect(card.phones).toEqual({ p0: { number: "+7 495 111-22-33" } });
  expect(card.organizations).toEqual({ o: { name: "АО Вектор" } });
  expect(card.photos).toEqual({ p: { url: "https://example.org/o.jpg" } });
  expect(card.notes).toEqual({ n: { note: "Бухгалтер" } });
  expect(card.addressBookIds).toEqual({ book1: true });

  // Чтение той же карточки — та же форма (round-trip).
  expect(formOf(card)).toEqual(form);
});

test("правка: пустые поля записи стираются (null в патче)", () => {
  const patch: ContactCard = {};
  fillForm(patch, { name: "Только имя", emails: [], phones: [], organization: "", photoUrl: "", notes: "" });
  expect(patch.name).toEqual({ full: "Только имя", components: [{ kind: "given", value: "Только" }, { kind: "surname", value: "имя" }] });
  expect(patch.emails).toBeNull();
  expect(patch.phones).toBeNull();
  expect(patch.organizations).toBeNull();
  expect(patch.photos).toBeNull();
  expect(patch.notes).toBeNull();
});

test("инициалы: первые буквы имени, без имени — начало адреса", () => {
  expect(initials("Мария Сидорова", "m@x.example")).toBe("МС");
  expect(initials("Мария", "m@x.example")).toBe("М");
  expect(initials("", "olga@vektor.example")).toBe("OL");
});
