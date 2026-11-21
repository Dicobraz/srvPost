/*
  Раздел «Почта» (WEB-03/04) — ядро веб-почты: три-панель по макету docs/design/webmail/01
  (папки | список | чтение), потоки (группировка — по умолчанию), быстрые фильтры, перетаскивание,
  контекстные меню (без модалок — inline-подтверждения), тосты с Undo (undo-send — WEB-04),
  one-modifier хоткеи (keymap.ts). Данные — JMAP через mail/queries.ts; push — mail/push.ts
  (одно соединение на пользователя, лидер вкладок). Композер — вкладка /compose (WEB-04, макет 02):
  новое письмо, ответ/ответ всем/пересылка, черновик — «Изменить черновик» в контекст-меню.
*/
import { useEffect, useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";

import { mailboxSet, type EmailSummary, type Mailbox } from "../api/jmap";
import { useJmap, useJmapReady, usePushHub } from "../mail/context";
import { keys, queryClient } from "../mail/client";
import {
  keywordPatch,
  movePatch,
  undoEntries,
  useEmailsFull,
  useEmailUpdateMutation,
  useEmailDestroyMutation,
  useFlaggedCount,
  useMailWindow,
  useMailboxes,
  type UndoEntry,
  type WindowArgs,
} from "../mail/queries";
import { CATEGORIES, categoryByNumber, categoriesOf, type QuickFilterKind } from "../mail/keywords";
import { handleMailKeydown, KEYMAP_HINTS, type MailHotkeyActions } from "../mail/keymap";
import { FLAGGED_FOLDER, FolderTree } from "../mail/folder-tree";
import { MessageList, useQuickCounts, type ListRow } from "../mail/message-list";
import { ReadingPane } from "../mail/reading-pane";
import { ContextMenu, type MenuState, type MenuItem } from "../mail/context-menu";
import { Icon } from "../mail/icons";
import { useToast } from "../mail/toast";
import { loadDensity, loadThreadView, saveDensity, saveThreadView, type Density, type ThreadView } from "../mail/settings";
import { allowImagesForDomain, areImagesAllowedFor } from "../mail/sanitize";

/** Раздел «Почта»: заставка/ошибка сессии, затем приложение. */
export function MailPage() {
  const ready = useJmapReady();
  if (ready.state === "loading") {
    return (
      <section className="stub" aria-busy="true">
        <h1>Почта</h1>
        <p>Загружаем ящик…</p>
      </section>
    );
  }
  if (ready.state === "error") {
    return (
      <section className="stub">
        <h1>Почта</h1>
        <p className="alert">{ready.message}</p>
      </section>
    );
  }
  return <MailApp />;
}

/** Патчи обновления по письмам: только те, что уже в кэше (нормализация id). */
function updateFor(ids: string[], patch: (email: EmailSummary) => Record<string, unknown>): Record<string, Record<string, unknown>> {
  const out: Record<string, Record<string, unknown>> = {};
  for (const id of ids) {
    const cached = queryClient.getQueryData<EmailSummary>(keys.email(id));
    if (cached) out[id] = patch(cached);
  }
  return out;
}

function MailApp() {
  const env = useJmap();
  const hub = usePushHub();
  const toast = useToast();
  const navigate = useNavigate();
  const mailboxes = useMailboxes();
  const flaggedCount = useFlaggedCount();
  const quickCounts = useQuickCounts(null);
  const updateMut = useEmailUpdateMutation();
  const destroyMut = useEmailDestroyMutation();
  const qc = useQueryClient();

  // Панели и окно списка.
  const [folderRaw, setFolder] = useState<string | null>(null);
  const [quick, setQuick] = useState<QuickFilterKind | null>(null);
  const [filters, setFilters] = useState({ unread: false, attachment: false });
  const [sort, setSort] = useState<WindowArgs["sort"]>("date-desc");
  const [search, setSearch] = useState("");
  const [density, setDensityState] = useState<Density>(loadDensity);
  const [threadView, setThreadViewState] = useState<ThreadView>(loadThreadView);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [collapsedReading, setCollapsedReading] = useState(true);
  const [menu, setMenu] = useState<MenuState | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [imagesForEmail, setImagesForEmail] = useState<Record<string, boolean>>({});
  const [renameRow, setRenameRow] = useState<{ id: string; name: string } | null>(null);
  const [lastSync, setLastSync] = useState<Date | null>(null);

  const dragRef = useRef<EmailSummary[]>([]);
  const treeRef = useRef<HTMLDivElement | null>(null);
  const listRef = useRef<HTMLDivElement | null>(null);
  const readRef = useRef<HTMLDivElement | null>(null);
  const focusOrder = [treeRef, listRef, readRef];
  const focusIndex = useRef(0);

  // Папка по умолчанию — «Входящие» (роль inbox), пока пользователь не выбрал: вывод из списка
  // папок, без setState в эффекте (каскадный рендер недопустим).
  const inboxFallback = mailboxes?.find((m) => m.role === "inbox")?.id ?? mailboxes?.[0]?.id ?? null;
  const folder = folderRaw ?? inboxFallback;

  // Синхронизация: тик push/таймера — время в строке состояния.
  useEffect(() => {
    if (!hub) return;
    return hub.subscribe(() => setLastSync(new Date()));
  }, [hub]);

  const mailboxId = folder && folder !== FLAGGED_FOLDER ? folder : null;
  const flagged = folder === FLAGGED_FOLDER;
  const args: WindowArgs = useMemo(
    () => ({
      mailboxId,
      quick,
      flagged,
      unread: filters.unread,
      attachment: filters.attachment,
      sort,
      grouped: threadView === "grouped",
      search: search.trim() ? search.trim() : null,
    }),
    [mailboxId, quick, flagged, filters, sort, threadView, search],
  );
  const windowQuery = useMailWindow(args);
  const junkId = mailboxes?.find((m) => m.role === "junk")?.id ?? null;
  const archiveId = mailboxes?.find((m) => m.role === "archive")?.id ?? null;
  const inboxId = mailboxes?.find((m) => m.role === "inbox")?.id ?? null;
  const trashId = mailboxes?.find((m) => m.role === "trash")?.id ?? null;

  // Строки списка: представители потоков из окна, письма потоков — из кэша (нормализация id).
  const flatIds = useMemo(() => windowQuery.data?.pages.flatMap((p) => p.ids) ?? [], [windowQuery.data]);
  const rows = useMemo<ListRow[]>(() => {
    const out: ListRow[] = [];
    for (const id of flatIds) {
      const email = queryClient.getQueryData<EmailSummary>(keys.email(id));
      if (!email) continue;
      if (!args.grouped) {
        out.push({ email, threadCount: 1, threadUnread: email.keywords.$seen ? 0 : 1, threadExpanded: false, threadChild: false });
        continue;
      }
      const thread = queryClient.getQueryData<{ emailIds: string[] }>(keys.thread(email.threadId));
      const threadEmails = (thread?.emailIds ?? [email.id])
        .map((e) => queryClient.getQueryData<EmailSummary>(keys.email(e)))
        .filter((e): e is EmailSummary => Boolean(e))
        .sort((a, b) => a.receivedAt.localeCompare(b.receivedAt));
      const threadUnread = threadEmails.filter((e) => !e.keywords.$seen).length;
      if (expanded.has(email.threadId)) {
        for (const m of threadEmails) {
          out.push({ email: m, threadCount: threadEmails.length, threadUnread, threadExpanded: true, threadChild: true });
        }
      } else {
        out.push({ email, threadCount: threadEmails.length || 1, threadUnread, threadExpanded: false, threadChild: false });
      }
    }
    return out;
  }, [flatIds, expanded, args.grouped]);

  const unreadCount = useMemo(() => {
    const mb = mailboxes?.find((m) => m.id === mailboxId);
    if (mb) return mb.unreadEmails;
    return rows.filter((r) => !r.email.keywords.$seen).length;
  }, [mailboxes, mailboxId, rows]);

  // Чтение: выбранные письма (стек беседы при группировке), полные тела — одним запросом.
  const selected = selectedId ? (queryClient.getQueryData<EmailSummary>(keys.email(selectedId)) ?? null) : null;
  const selectedThread = selected ? (queryClient.getQueryData<{ emailIds: string[] }>(keys.thread(selected.threadId)) ?? null) : null;
  const stackIds = useMemo(() => {
    if (!selected) return [];
    if (args.grouped && selectedThread) {
      return [...selectedThread.emailIds].sort((a, b) => {
        const sa = queryClient.getQueryData<EmailSummary>(keys.email(a));
        const sb = queryClient.getQueryData<EmailSummary>(keys.email(b));
        return (sa?.receivedAt ?? "").localeCompare(sb?.receivedAt ?? "");
      });
    }
    return [selected.id];
  }, [selected, selectedThread, args.grouped]);
  const stackFull = useEmailsFull(stackIds);

  // ---------- Действия ----------

  const applyUpdate = async (updates: Record<string, Record<string, unknown>>, label: string) => {
    try {
      const snapshot = (await updateMut.mutateAsync(updates)) as UndoEntry[];
      const undo = () => {
        void updateMut
          .mutateAsync(undoEntries(snapshot))
          .then(() => toast.show("Возвращено как было"));
      };
      toast.show(label, undo);
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Изменение не выполнено.");
    }
  };

  const setSeen = (emails: EmailSummary[], seen: boolean) => {
    const updates = updateFor(
      emails.map((e) => e.id),
      () => keywordPatch("$seen", seen),
    );
    void applyUpdate(updates, seen ? "Отмечено прочитанным" : "Отмечено непрочитанным");
  };

  const setFlagged = (emails: EmailSummary[], on: boolean) => {
    const updates = updateFor(
      emails.map((e) => e.id),
      () => keywordPatch("$flagged", on),
    );
    void applyUpdate(updates, on ? "Помечено флагом" : "Флаг снят");
  };

  const categorize = (emails: EmailSummary[], categoryIndex: number) => {
    if (emails.length === 0) return;
    const category = categoryByNumber(categoryIndex);
    // Категория одна (как Postman mail.categorize): прежние pm.cat.* снимаются.
    const updates: Record<string, Record<string, unknown>> = {};
    for (const email of emails) {
      const patch: Record<string, unknown> = {};
      for (const c of categoriesOf(email.keywords)) patch[`keywords/${c.keyword}`] = false;
      if (category) patch[`keywords/${category.keyword}`] = true;
      updates[email.id] = patch;
    }
    void applyUpdate(updates, category ? `Категория: ${category.name}` : "Категория снята");
  };

  const moveTo = (emails: EmailSummary[], target: string, label: string) => {
    const updates = updateFor(
      emails.map((e) => e.id),
      (cached) => movePatch(cached, target),
    );
    void applyUpdate(updates, label);
  };

  const deleteEmails = (emails: EmailSummary[]) => {
    if (emails.length === 0) return;
    destroyMut
      .mutateAsync(emails.map((e) => e.id))
      .then((snapshot) => {
        const undo = () => {
          const reverse: Record<string, Record<string, unknown>> = {};
          for (const entry of snapshot as UndoEntry[]) {
            if (entry.mailboxIds) reverse[entry.emailId] = { mailboxIds: entry.mailboxIds };
          }
          void updateMut.mutateAsync(reverse).then(() => toast.show("Возвращено из корзины"));
        };
        toast.show(emails.length > 1 ? `Удалено писем: ${emails.length}` : "Письмо удалено", undo);
        if (selectedId && emails.some((e) => e.id === selectedId)) setSelectedId(null);
      })
      .catch((e: unknown) => toast.show(e instanceof Error ? e.message : "Удалить не удалось."));
  };

  // Композер — вкладка /compose (WEB-04): новое письмо, ответы и пересылка, черновик.
  const openCompose = (query: string = "") => navigate(`/compose${query}`);
  const replyTo = (email: EmailSummary, kind: "reply" | "reply-all" | "forward") =>
    navigate(`/compose?kind=${kind}&email=${encodeURIComponent(email.id)}`);

  // ---------- Контекстные меню (без модалок) ----------

  const emailMenu = (email: EmailSummary): MenuItem[] => {
    const inTrash = Boolean(trashId && email.mailboxIds[trashId]);
    const inJunk = Boolean(junkId && email.mailboxIds[junkId]);
    const items: MenuItem[] = [
      { label: "Ответить", onSelect: () => replyTo(email, "reply") },
      { label: "Ответить всем", onSelect: () => replyTo(email, "reply-all") },
      { label: "Переслать", onSelect: () => replyTo(email, "forward") },
      ...(email.keywords.$draft
        ? [{ label: "Изменить черновик", onSelect: () => openCompose(`?draft=${encodeURIComponent(email.id)}`) }]
        : []),
      { label: "", separator: true },
      email.keywords.$seen
        ? { label: "Отметить непрочитанным", onSelect: () => setSeen([email], false) }
        : { label: "Отметить прочитанным", onSelect: () => setSeen([email], true) },
      {
        label: email.keywords.$flagged ? "Снять флаг" : "Поставить флаг",
        onSelect: () => setFlagged([email], !email.keywords.$flagged),
      },
      { label: "", separator: true },
    ];
    for (const c of CATEGORIES) {
      const active = categoriesOf(email.keywords).some((x) => x.keyword === c.keyword);
      items.push({
        label: active ? `${c.name} (снять)` : `Категория: ${c.name}`,
        onSelect: () => categorize([email], CATEGORIES.indexOf(c) + 1),
      });
    }
    items.push(
      { label: "", separator: true },
      {
        label: "В архив",
        disabled: !archiveId,
        onSelect: () => archiveId && moveTo([email], archiveId, "В архив"),
      },
      inJunk
        ? {
            label: "Не спам (перенести во «Входящие»)",
            disabled: !inboxId,
            onSelect: () => inboxId && moveTo([email], inboxId, "Не спам"),
          }
        : {
            label: "Пожаловаться (в «Спам»)",
            disabled: !junkId,
            onSelect: () => junkId && moveTo([email], junkId, "Помечено как спам"),
          },
      {
        label: inTrash ? "Удалить навсегда" : "Удалить",
        danger: inTrash,
        onSelect: () => deleteEmails([email]),
      },
    );
    return items;
  };

  const folderMenu = (mailbox: Mailbox, x: number, y: number) => {
    setMenu({
      x,
      y,
      items: [
        {
          label: `Переименовать «${mailbox.name}»`,
          onSelect: () => setRenameRow({ id: mailbox.id, name: mailbox.name }),
          disabled: !mailbox.myRights.mayRename,
        },
        {
          label: "Удалить папку",
          danger: true,
          disabled: !mailbox.myRights.mayDelete,
          onSelect: () => void deleteFolder(mailbox),
        },
      ],
    });
  };

  const deleteFolder = async (mailbox: Mailbox, withEmails = false) => {
    try {
      const result = await mailboxSet(env.apiUrl, env.authorization, env.accountId, {
        destroy: [mailbox.id],
        onDestroyRemoveEmails: withEmails,
      });
      const error = result.errors[mailbox.id] as { type?: string } | undefined;
      if (error?.type === "mailboxHasEmail") {
        // Inline-подтверждение вместо модалки: пункт «удалить вместе с письмами».
        setMenu({
          x: 240,
          y: 180,
          items: [
            {
              label: `В папке есть письма — удалить «${mailbox.name}» вместе с письмами?`,
              confirm: true,
              onSelect: () => void deleteFolder(mailbox, true),
            },
            { label: "Отмена" },
          ],
        });
        return;
      }
      void qc.invalidateQueries({ queryKey: ["mailboxes"] });
      toast.show(`Папка «${mailbox.name}» удалена`);
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Папку удалить не удалось.");
    }
  };

  const createFolder = (name: string, parentId: string | null) => {
    mailboxSet(env.apiUrl, env.authorization, env.accountId, {
      create: { [`c-${Date.now()}`]: { name, parentId, role: null } },
    })
      .then(() => {
        void qc.invalidateQueries({ queryKey: ["mailboxes"] });
        toast.show(`Папка «${name}» создана`);
      })
      .catch((e: unknown) => toast.show(e instanceof Error ? e.message : "Папку создать не удалось."));
  };

  const renameFolder = (id: string, name: string) => {
    mailboxSet(env.apiUrl, env.authorization, env.accountId, { update: { [id]: { name } } })
      .then(() => {
        void qc.invalidateQueries({ queryKey: ["mailboxes"] });
        toast.show(`Папка переименована в «${name}»`);
      })
      .catch((e: unknown) => toast.show(e instanceof Error ? e.message : "Переименовать не удалось."));
  };

  // ---------- Хоткеи (one-modifier схема; RU/EN не мешает — event.code) ----------

  const toggleThread = (email: EmailSummary) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(email.threadId)) next.delete(email.threadId);
      else next.add(email.threadId);
      return next;
    });
  };

  const selectNeighbor = (offset: 1 | -1) => {
    const index = rows.findIndex((r) => r.email.id === selectedId);
    const next = index + offset;
    if (next >= 0 && next < rows.length) {
      const email = rows[next].email;
      setSelectedId(email.id);
      if (!email.keywords.$seen) setSeen([email], true);
    }
  };

  const escapeAction = () => {
    const row = rows.find((r) => r.email.id === selectedId);
    if (row && row.threadCount > 1 && expanded.has(row.email.threadId)) {
      setExpanded((prev) => {
        const next = new Set(prev);
        next.delete(row.email.threadId);
        return next;
      });
    }
  };

  const actions = useMemo<MailHotkeyActions>(
    () => ({
      nextMessage: () => selectNeighbor(1),
      prevMessage: () => selectNeighbor(-1),
      openSelected: () => {
        const row = rows.find((r) => r.email.id === selectedId);
        if (row && row.threadCount > 1) toggleThread(row.email);
      },
      categorize: (n: number) => {
        if (selected) categorize([selected], n);
      },
      markRead: () => {
        if (selected) setSeen([selected], true);
      },
      markUnread: () => {
        if (selected) setSeen([selected], false);
      },
      deleteSelected: () => {
        if (selected) deleteEmails([selected]);
      },
      archiveSelected: () => {
        if (selected && archiveId) moveTo([selected], archiveId, "В архив");
      },
      reply: () => {
        if (selected) replyTo(selected, "reply");
        else openCompose();
      },
      replyAll: () => {
        if (selected) replyTo(selected, "reply-all");
        else openCompose();
      },
      forward: () => {
        if (selected) replyTo(selected, "forward");
        else openCompose();
      },
      compose: () => openCompose(),
      focusNextPanel: (backward?: boolean) => {
        focusIndex.current = (focusIndex.current + (backward ? focusOrder.length - 1 : 1)) % focusOrder.length;
        focusOrder[focusIndex.current]?.current?.focus();
      },
      focusFolders: () => {
        focusIndex.current = 0;
        treeRef.current?.focus();
      },
      escape: escapeAction,
    }),
    [rows, selectedId, selected, archiveId, expanded],
  );
  const actionsRef = useRef<MailHotkeyActions>(actions);
  useEffect(() => {
    actionsRef.current = actions; // свежие замыкания на каждый рендер (не во время рендера)
  });

  useEffect(() => {
    const handler = (e: KeyboardEvent) => handleMailKeydown(e, actionsRef.current);
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // ---------- Рендер ----------

  const folderTitle = flagged ? "Отмеченные" : (mailboxes?.find((m) => m.id === folder)?.name ?? "Почта");
  const pushLabel = hub
    ? hub.pushStatus === "live"
      ? "Живая синхронизация"
      : hub.pushStatus === "poll"
        ? "Таймер (push недоступен)"
        : "Соединение…"
    : "";
  const neighborIds = {
    prev: flatIds.indexOf(selectedId ?? "") > 0 ? (flatIds[flatIds.indexOf(selectedId ?? "") - 1] ?? null) : null,
    next:
      flatIds.indexOf(selectedId ?? "") >= 0 && flatIds.indexOf(selectedId ?? "") < flatIds.length - 1
        ? (flatIds[flatIds.indexOf(selectedId ?? "") + 1] ?? null)
        : null,
  };

  return (
    <div className={`mail${selectedId ? " reading" : ""}`} data-density={density}>
      {/* Командная строка: одна акцентная кнопка + тихие команды + поиск (макет 01) */}
      <div className="cmd">
        <button type="button" className="btn-acc" onClick={() => openCompose()} title="Новое письмо (Ctrl+N)">
          <Icon name="pen" size={16} />
          Новое письмо
        </button>
        <button type="button" className="btn-q" onClick={() => selected && replyTo(selected, "reply")} disabled={!selected} title="Ответить (Ctrl+R)">
          <Icon name="reply" size={16} />
          Ответить
        </button>
        <button type="button" className="btn-q" onClick={() => selected && replyTo(selected, "forward")} disabled={!selected} title="Переслать (Ctrl+F)">
          <Icon name="fwd" size={16} />
          Переслать
        </button>
        <button type="button" className="btn-q" onClick={() => selected && deleteEmails([selected])} disabled={!selected} title="Удалить (Del)">
          <Icon name="trash" size={16} />
          Удалить
        </button>
        <input
          className="search"
          type="search"
          placeholder="Поиск (FTS сервера — развёрнуто в WEB-05)"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <span className="settings">
          <button
            type="button"
            className="gear"
            aria-label="Настройки чтения"
            aria-expanded={settingsOpen}
            onClick={() => setSettingsOpen((v) => !v)}
          >
            ⚙
          </button>
          {settingsOpen && (
            <div className="settings-pop">
              <label>
                Плотность списка
                <select
                  value={density}
                  onChange={(e) => {
                    const next = e.target.value as Density;
                    setDensityState(next);
                    saveDensity(next);
                  }}
                >
                  <option value="normal">Обычная с превью</option>
                  <option value="compact">Компактная</option>
                </select>
              </label>
              <label>
                Вид потока
                <select
                  value={threadView}
                  onChange={(e) => {
                    const next = e.target.value as ThreadView;
                    setThreadViewState(next);
                    saveThreadView(next);
                  }}
                >
                  <option value="grouped">Группировка</option>
                  <option value="outlook">Как в Outlook</option>
                </select>
              </label>
              <div className="cap">
                {KEYMAP_HINTS.map((h) => (
                  <div key={h.keys}>
                    <b>{h.keys}</b> — {h.action}
                  </div>
                ))}
              </div>
            </div>
          )}
        </span>
      </div>

      <div className="main">
        {/* Дерево папок: выбор, drag-drop, контекстное меню (переименование/удаление) */}
        <div ref={treeRef} tabIndex={-1} style={{ display: "contents" }}>
          <FolderTree
          mailboxes={mailboxes ?? []}
          flaggedUnread={flaggedCount ?? 0}
          selected={folder}
          onSelect={(id) => {
            setFolder(id);
            setSelectedId(null);
            setExpanded(new Set());
          }}
          onDropTo={(target) => {
            const dragged = dragRef.current;
            if (dragged.length > 0) moveTo(dragged, target, "Письмо перемещено");
            dragRef.current = [];
          }}
          onFolderMenu={folderMenu}
          onCreateFolder={createFolder}
          renameRow={renameRow}
          onRename={(id, name) => {
            setRenameRow(null);
            renameFolder(id, name);
          }}
          onRenameDraft={(id, name) => setRenameRow({ id, name })}
          onCancelRename={() => setRenameRow(null)}
          />
        </div>

        <div ref={listRef} tabIndex={-1} style={{ display: "contents" }}>
          <MessageList
            title={folderTitle}
            rows={rows}
            total={windowQuery.data?.pages[0]?.total ?? null}
            unreadCount={unreadCount}
            density={density}
            selectedId={selectedId}
            onSelect={(email) => {
              setSelectedId(email.id);
              setCollapsedReading(true);
              if (!email.keywords.$seen) setSeen([email], true);
            }}
            onToggleThread={toggleThread}
            onRowMenu={(email, x, y) => setMenu({ x, y, items: emailMenu(email) })}
            onDragStartEmail={(email) => {
              dragRef.current = [email];
            }}
            quick={quick}
            counts={quickCounts}
            onQuick={setQuick}
            filters={filters}
            onFilters={setFilters}
            fetchNextPage={() => void windowQuery.fetchNextPage()}
            isFetchingNext={windowQuery.isFetchingNextPage}
            sort={sort}
            onSort={() => setSort((s) => (s === "date-desc" ? "date-asc" : s === "date-asc" ? "from" : "date-desc"))}
          />
        </div>

        <div ref={readRef} tabIndex={-1} style={{ display: "contents" }}>
          <ReadingPane
            summary={selected}
            stack={stackIds
              .map((id) => queryClient.getQueryData<EmailSummary>(keys.email(id)))
              .filter((e): e is EmailSummary => Boolean(e))}
            stackFull={stackFull}
            toggles={{
              imagesThisEmail: Boolean(selectedId && imagesForEmail[selectedId]),
              imagesForDomain: selected ? areImagesAllowedFor(selected.from?.[0]?.email.split("@")[1] ?? "") : false,
              onAllowThisEmail: () => {
                if (selectedId) {
                  setImagesForEmail((prev) => ({ ...prev, [selectedId]: true }));
                  toast.show("Картинки письма показаны");
                }
              },
              onAllowDomain: () => {
                if (selected) {
                  const domain = selected.from?.[0]?.email.split("@")[1];
                  if (domain) {
                    allowImagesForDomain(domain);
                    toast.show(`Картинки от ${domain} показываются всегда`);
                  }
                }
              },
            }}
            onExpandAll={() => setCollapsedReading((v) => !v)}
            collapsed={collapsedReading}
            prevNext={neighborIds}
            onPrevNext={(id) => {
              setSelectedId(id);
              setCollapsedReading(true);
            }}
          />
        </div>
      </div>

      {/* Строка состояния: синхронизация и состояние push (макет: «Синхронизировано · HH:MM») */}
      <div className="status">
        <span className="it">
          <Icon name="sync" size={14} />
          {lastSync
            ? `Синхронизировано · ${lastSync.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" })}`
            : "Синхронизируем…"}
          {pushLabel && ` · ${pushLabel}`}
        </span>
        <span className="sp" />
        <span className="it">J/K — по списку · F6 — панели · Ctrl — клавиши</span>
      </div>

      {menu && <ContextMenu menu={menu} onClose={() => setMenu(null)} />}
    </div>
  );
}
