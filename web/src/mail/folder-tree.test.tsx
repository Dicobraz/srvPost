// Дерево папок — секция «Общие» (WEB-15): заголовок группы, строки общих ящиков сессии,
// выбор (ключ shared:<accountId>), счётчики непрочитанных, сворачивание; свои папки как были.
import { cleanup, fireEvent, render, within } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import type { Mailbox } from "../api/jmap";
import { FolderTree } from "./folder-tree";
import { sharedFolderKey, type SharedMailAccount } from "./shared";

function mailbox(id: string, name: string, role: string | null = null): Mailbox {
  return {
    id,
    name,
    parentId: null,
    role,
    sortOrder: 0,
    totalEmails: 0,
    unreadEmails: 0,
    totalThreads: 0,
    unreadThreads: 0,
    myRights: {
      mayReadItems: true,
      mayAddItems: true,
      mayRemoveItems: true,
      maySetSeen: true,
      maySetKeywords: true,
      mayCreateChild: true,
      mayRename: true,
      mayDelete: role === null,
      maySubmit: true,
    },
    isSubscribed: true,
  };
}

const SHARED: SharedMailAccount[] = [
  { id: "acc2", name: "sales@example.org", readOnly: false },
  { id: "acc4", name: "info@example.org", readOnly: true },
];

const noop = vi.fn();

function tree(overrides: Partial<Parameters<typeof FolderTree>[0]> = {}) {
  return render(
    <FolderTree
      mailboxes={[mailbox("mb-inbox", "Входящие", "inbox"), mailbox("mb-work", "Работа")]}
      flaggedUnread={0}
      selected={null}
      onSelect={noop}
      onDropTo={noop}
      onFolderMenu={noop}
      onCreateFolder={noop}
      renameRow={null}
      onRenameDraft={noop}
      onRename={noop}
      onCancelRename={noop}
      {...overrides}
    />,
  );
}

afterEach(cleanup);

describe("секция «Общие»", () => {
  test("общие ящики сессии — строки после своих папок, с именем и подсказкой доступа", () => {
    const page = within(tree({ shared: SHARED }).container);
    expect(page.getByRole("button", { name: "Общие" })).toBeTruthy();
    const sales = page.getByRole("button", { name: /sales@example\.org/ });
    expect(sales.getAttribute("title")).toContain("общий ящик");
    expect(sales.getAttribute("title")).not.toContain("только чтение");
    const info = page.getByRole("button", { name: /info@example\.org/ });
    expect(info.getAttribute("title")).toContain("только чтение");
  });

  test("секции нет, если общих ящиков в сессии нет", () => {
    const page = within(tree().container);
    expect(page.queryByRole("button", { name: "Общие" })).toBeNull();
    expect(page.queryByRole("button", { name: /sales@example\.org/ })).toBeNull();
  });

  test("выбор общего ящика отдаёт ключ shared:<accountId>; выбор своей папки — её id", () => {
    const onSelect = vi.fn();
    const page = within(tree({ shared: SHARED, onSelect }).container);
    fireEvent.click(page.getByRole("button", { name: /sales@example\.org/ }));
    expect(onSelect).toHaveBeenCalledWith(sharedFolderKey("acc2"));
    fireEvent.click(page.getByRole("button", { name: "Работа" }));
    expect(onSelect).toHaveBeenCalledWith("mb-work");
  });

  test("выбранная строка общих ящиков помечена; счётчик непрочитанных показывается", () => {
    const page = within(tree({ shared: SHARED, sharedUnread: { acc2: 7 }, selected: sharedFolderKey("acc2") }).container);
    const sales = page.getByRole("button", { name: /sales@example\.org/ });
    expect(sales.className).toContain("on");
    expect(within(sales).getByText("7")).toBeTruthy();
  });

  test("сворачивание секции прячет строки, выбор и счётчики сохраняются в разгорнутом виде", () => {
    const page = within(tree({ shared: SHARED }).container);
    fireEvent.click(page.getByRole("button", { name: "Общие" }));
    expect(page.queryByRole("button", { name: /sales@example\.org/ })).toBeNull();
    fireEvent.click(page.getByRole("button", { name: "Общие" }));
    expect(page.getByRole("button", { name: /sales@example\.org/ })).toBeTruthy();
  });

  test("свои папки и «Отмеченные» на месте при наличии общих", () => {
    const page = within(tree({ shared: SHARED }).container);
    expect(page.getByRole("button", { name: "Входящие" })).toBeTruthy();
    expect(page.getByRole("button", { name: "Отмеченные" })).toBeTruthy();
    expect(page.getByRole("button", { name: "Новая папка" })).toBeTruthy();
  });
});
