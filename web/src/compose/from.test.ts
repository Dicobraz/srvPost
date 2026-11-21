// Выбор «От» композера (WEB-15): свои identity (Send As) плюс адреса общих ящиков сессии;
// дубликаты своего адреса — прочь; порядок — свои, затем общие по имени.
import { describe, expect, test } from "vitest";

import { CAP_MAIL, type Identity, type JmapSession } from "../api/jmap";
import { fromOptions } from "./model";

const IDENTITY: Identity = {
  id: "I1",
  name: "Пётр Ковалёв",
  email: "p.koval@example.org",
  replyTo: null,
  bcc: null,
  textSignature: "",
  htmlSignature: "",
  mayDelete: false,
};

const SESSION: JmapSession = {
  capabilities: {},
  accounts: {
    acc1: { name: "p.koval@example.org", isPersonal: true, isReadOnly: false, accountCapabilities: { [CAP_MAIL]: {} } },
    acc2: { name: "sales@example.org", isPersonal: false, isReadOnly: false, accountCapabilities: { [CAP_MAIL]: {} } },
    acc3: { name: "info@example.org", isPersonal: false, isReadOnly: true, accountCapabilities: { [CAP_MAIL]: {} } },
    acc4: { name: "books@example.org", isPersonal: false, isReadOnly: true, accountCapabilities: {} },
  },
  primaryAccounts: { [CAP_MAIL]: "acc1" },
  username: "p.koval@example.org",
  apiUrl: "https://node.example/jmap/api",
  downloadUrl: "",
  uploadUrl: "",
  eventSourceUrl: "",
  state: "s",
};

describe("варианты «От»", () => {
  test("свой адрес — не общий, общие ящики — после него (по имени), книги без почты — прочь", () => {
    expect(fromOptions(IDENTITY, [IDENTITY], SESSION)).toEqual([
      { email: "p.koval@example.org", name: "Пётр Ковалёв", shared: false },
      { email: "info@example.org", name: "info@example.org", shared: true },
      { email: "sales@example.org", name: "sales@example.org", shared: true },
    ]);
  });

  test("второй свой identity (Send As) идёт в список; дубликат своего адреса среди общих — прочь", () => {
    const second: Identity = { ...IDENTITY, id: "I2", name: "", email: "peter@personal.example" };
    const duplicateSession: JmapSession = {
      ...SESSION,
      accounts: {
        ...SESSION.accounts,
        acc2: { name: "peter@personal.example", isPersonal: false, isReadOnly: false, accountCapabilities: { [CAP_MAIL]: {} } },
      },
    };
    const options = fromOptions(IDENTITY, [IDENTITY, second], duplicateSession);
    expect(options.filter((c) => c.email === "peter@personal.example")).toHaveLength(1);
    expect(options[0]).toEqual({ email: "p.koval@example.org", name: "Пётр Ковалёв", shared: false });
    expect(options[1]).toEqual({ email: "peter@personal.example", name: "peter@personal.example", shared: false });
  });

  test("имя варианта — имя identity, пустое имя — сам адрес", () => {
    const anonymous: Identity = { ...IDENTITY, name: "" };
    const options = fromOptions(anonymous, [anonymous], SESSION);
    expect(options[0]).toEqual({ email: "p.koval@example.org", name: "p.koval@example.org", shared: false });
  });
});
