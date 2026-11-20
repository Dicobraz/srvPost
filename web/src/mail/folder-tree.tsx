/*
  Дерево папок (WEB-03): роли RFC 6154 (inbox/drafts/sent/junk/archive/trash) — системные строки
  по макету 01 (Входящие, Отмеченные — виртуальная, Черновики, Отправленные, Спам, Архив),
  остальные папки — по имени с отступом родителя. Счётчики непрочитанных; перетаскивание письма
  (drop — перенос, решение #134: «Спам» — обычный перенос); inline-создание папки; контекстное
  меню — переименование/удаление (удаление с письмами — inline-подтверждение).
*/
import { useState } from "react";

import type { Mailbox } from "../api/jmap";
import { Icon, type IconName } from "./icons";

/** Виртуальная папка «Отмеченные» ($flagged — письма из всех папок). */
export const FLAGGED_FOLDER = "flagged";

/** Значки ролей (макет 01). */
const ROLE_ICONS: Record<string, IconName> = {
  inbox: "inbox",
  drafts: "draft",
  sent: "sent",
  junk: "ban",
  archive: "arch",
  trash: "trash",
};

/** Порядок системных папок в дереве. */
const ROLE_ORDER = ["inbox", "drafts", "sent", "junk", "archive", "trash"];

/** Строки дерева: системные по ролям, «Отмеченные» виртуальная, свои — по имени. */
export interface TreeRow {
  key: string;
  id: string | null; // null — виртуальная «Отмеченные»
  name: string;
  icon: IconName;
  unread: number;
  child: boolean;
  mailbox: Mailbox | null;
}

/** Дерево из Mailbox/get: системные роли сверху, свои папки — после (children — отступ). */
export function buildTree(mailboxes: Mailbox[], flaggedUnread: number): TreeRow[] {
  const byId = new Map(mailboxes.map((m) => [m.id, m]));
  const rows: TreeRow[] = [];
  for (const role of ROLE_ORDER) {
    const mb = mailboxes.find((m) => m.role === role);
    if (!mb) continue;
    rows.push({ key: mb.id, id: mb.id, name: mb.name, icon: ROLE_ICONS[role] ?? "folder", unread: mb.unreadEmails, child: false, mailbox: mb });
  }
  rows.push({ key: FLAGGED_FOLDER, id: null, name: "Отмеченные", icon: "flag", unread: flaggedUnread, child: false, mailbox: null });
  const custom = mailboxes.filter((m) => !m.role).sort((a, b) => a.name.localeCompare(b.name, "ru"));
  for (const mb of custom) {
    const parent = mb.parentId ? byId.get(mb.parentId) : undefined;
    rows.push({
      key: mb.id,
      id: mb.id,
      name: mb.name,
      icon: "folder",
      unread: mb.unreadEmails,
      child: Boolean(parent && !parent.role),
      mailbox: mb,
    });
  }
  return rows;
}

interface FolderTreeProps {
  mailboxes: Mailbox[];
  flaggedUnread: number;
  selected: string | null; // id папки или FLAGGED_FOLDER
  onSelect(id: string | null): void;
  /** Письмо перетащили на папку (перенос, Email/set mailboxIds). */
  onDropTo(mailboxId: string): void;
  /** Inline-меню папки: переименование, удаление (страница решает подтверждение). */
  onFolderMenu(mailbox: Mailbox, x: number, y: number): void;
  onCreateFolder(name: string, parentId: string | null): void;
  /** Inline-переименование (из контекстного меню): строка-редактор в дереве. */
  renameRow: { id: string; name: string } | null;
  /** Черновик имени при наборе. */
  onRenameDraft(id: string, name: string): void;
  onRename(id: string, name: string): void;
  onCancelRename(): void;
}

export function FolderTree({
  mailboxes,
  flaggedUnread,
  selected,
  onSelect,
  onDropTo,
  onFolderMenu,
  onCreateFolder,
  renameRow,
  onRenameDraft,
  onRename,
  onCancelRename,
}: FolderTreeProps) {
  const rows = buildTree(mailboxes, flaggedUnread);
  const [dropId, setDropId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");

  return (
    <nav className="tree" aria-label="Папки">
      {rows.map((row) => {
        const editing = renameRow?.id === row.id;
        return editing ? (
          <form
            key={`rename-${row.key}`}
            className="fold"
            onSubmit={(e) => {
              e.preventDefault();
              const trimmed = (renameRow?.name ?? "").trim();
              if (trimmed && trimmed !== row.name) onRename(row.mailbox?.id ?? "", trimmed);
              else onCancelRename();
            }}
          >
            <input
              className="newfolder"
              value={renameRow?.name ?? ""}
              autoFocus
              aria-label="Новое имя папки"
              onChange={(e) => onRenameDraft(row.mailbox?.id ?? "", e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Escape") onCancelRename();
              }}
              onBlur={onCancelRename}
            />
          </form>
        ) : (
          <button
            key={row.key}
            type="button"
            className={[
              "fold",
              row.child ? "child" : "",
              selected === (row.key === FLAGGED_FOLDER ? FLAGGED_FOLDER : row.id) ? "on" : "",
              dropId === row.key ? "drop" : "",
            ]
              .join(" ")
              .trim()}
            onClick={() => onSelect(row.key === FLAGGED_FOLDER ? FLAGGED_FOLDER : row.id)}
            onContextMenu={(e) => {
              if (!row.mailbox) return;
              e.preventDefault();
              onFolderMenu(row.mailbox, e.clientX, e.clientY);
            }}
            onDragOver={(e) => {
              if (!row.mailbox) return;
              e.preventDefault();
              setDropId(row.key);
            }}
            onDragLeave={() => setDropId(null)}
            onDrop={(e) => {
              if (!row.mailbox) return;
              e.preventDefault();
              setDropId(null);
              onDropTo(row.mailbox.id);
            }}
            title={row.name}
          >
            <Icon name={row.icon} size={16} />
            <span className="name">{row.name}</span>
            {row.unread > 0 && <span className="n">{row.unread}</span>}
          </button>
        );
      })}
      {creating ? (
        <form
          className="fold"
          onSubmit={(e) => {
            e.preventDefault();
            const trimmed = name.trim();
            if (trimmed) onCreateFolder(trimmed, null);
            setName("");
            setCreating(false);
          }}
        >
          <input
            className="newfolder"
            value={name}
            autoFocus
            placeholder="Новая папка"
            aria-label="Имя новой папки"
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                setCreating(false);
                setName("");
              }
            }}
            onBlur={() => {
              setCreating(false);
              setName("");
            }}
          />
        </form>
      ) : (
        <button type="button" className="fold" onClick={() => setCreating(true)}>
          <Icon name="folder" size={16} />
          <span className="name">Новая папка</span>
        </button>
      )}
    </nav>
  );
}
