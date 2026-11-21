/*
  Раздел «Почта» (WEB-03/04/05) — ядро веб-почты: три-панель по макету docs/design/webmail/01
  (папки | список | чтение), потоки (группировка — по умолчанию), быстрые фильтры, перетаскивание,
  контекстные меню (без модалок — inline-подтверждения), тосты с Undo (undo-send — WEB-04),
  one-modifier хоткеи (keymap.ts). Данные — JMAP через mail/queries.ts; push — mail/push.ts
  (одно соединение на пользователя, лидер вкладок). Композер — вкладка /compose (WEB-04, макет 02):
  новое письмо, ответ/ответ всем/пересылка, черновик — «Изменить черновик» в контекст-меню.
  WEB-05 — поиск: строка в шапке с debounce 300 мс (FTS сервера: морфология, «ё», поля
  from:/кому:/тема:/тело:, транслитерация раскладки — keyboard-map.ts), чипы области над
  результатами (PARITY search.*), уточнения кликом (отправитель/папка/период/категория),
  сниппеты совпадений (SearchSnippet/get), сохранённые фильтры (search.save_filter) рядом
  под быстрыми, F3/Shift+F3 — совпадения в открытом письме (highlight.ts), палитра команд
  Ctrl+K (palette.tsx) — команды и письма одним вводом.
  WEB-15 — общие ящики и «Взять в работу»: секция «Общие» в дереве (строка на общий ящик сессии,
  письма — Email/query по его accountId), «Взять/Забрать себе/Вернуть» (Ctrl+J, слова `pm.taken…`
  как в Postman), метка «Назначено: …» в строке и полоса «Взято в работу» в чтении (имена — из
  справочника контактов); ответ из общего ящика — «От» его адрес (право проверяет сервер).
*/
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router";

import { mailboxSet, type EmailSummary, type Mailbox, type SearchSnippet } from "../api/jmap";
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
  useSharedUnreads,
  type UndoEntry,
  type WindowArgs,
} from "../mail/queries";
import { CATEGORIES, categoryByNumber, categoriesOf, type QuickFilterKind } from "../mail/keywords";
import { handleMailKeydown, KEYMAP_HINTS, type MailHotkeyActions } from "../mail/keymap";
import { FLAGGED_FOLDER, FolderTree } from "../mail/folder-tree";
import { MessageList, useQuickCounts, type ListRow } from "../mail/message-list";
import { ReadingPane, type MatchState, type TakeStrip } from "../mail/reading-pane";
import {
  sharedAccountId,
  sharedMailAccounts,
  TAKE_LABELS,
  takeActOf,
  takenBy,
  takenOf,
  takePatchOf,
} from "../mail/shared";
import { useContactSnapshot } from "../contacts/queries";
import { emailsOf, fullNameOf } from "../contacts/model";
import { ContextMenu, type MenuState, type MenuItem } from "../mail/context-menu";
import { CommandPalette, type PaletteCommand } from "../mail/palette";
import { isHlState, sendHlCommand } from "../mail/highlight";
import {
  EMPTY_SEARCH,
  highlightTerms,
  isSearchActive,
  monthPeriod,
  type SearchRefinement,
  type SearchScope,
} from "../mail/search";
import {
  applySavedFilter,
  loadSavedFilters,
  removeSavedFilter,
  saveFilter,
  type SavedFilter,
} from "../mail/saved-filters";
import { Icon } from "../mail/icons";
import { useToast } from "../mail/toast";
import {
  loadDensity,
  loadThreadView,
  loadTranslit,
  saveDensity,
  saveThreadView,
  saveTranslit,
  type Density,
  type ThreadView,
} from "../mail/settings";
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
  const updateMut = useEmailUpdateMutation();
  const destroyMut = useEmailDestroyMutation();
  const qc = useQueryClient();
  // Общие ящики сессии (WEB-15, JMAP-49) и их счётчики; имена коллег — из справочника (контакты
  // и GAL своей учётной записи), нет карточки — адрес как есть.
  const sharedAccounts = useMemo(() => sharedMailAccounts(env.session), [env.session]);
  const sharedUnread = useSharedUnreads(sharedAccounts.map((a) => a.id));
  const contacts = useContactSnapshot();
  const takenNames = useMemo(() => {
    const map = new Map<string, string>();
    for (const card of contacts) {
      const name = fullNameOf(card);
      if (!name) continue;
      for (const email of emailsOf(card)) map.set(email.toLowerCase(), name);
    }
    return map;
  }, [contacts]);
  const nameOf = useCallback(
    (who: string) => takenNames.get(who.toLowerCase()) ?? who,
    [takenNames],
  );

  // Панели и окно списка.
  const [folderRaw, setFolder] = useState<string | null>(null);
  const [quick, setQuick] = useState<QuickFilterKind | null>(null);
  const [filters, setFilters] = useState({ unread: false, attachment: false });
  const [sort, setSort] = useState<WindowArgs["sort"]>("date-desc");
  // Поиск (WEB-05): ввод в поле — сразу, запрос — после debounce 300 мс; чипы области,
  // уточнения кликом и сохранённые фильтры — как в Postman (PARITY search.*).
  const [searchInput, setSearchInput] = useState("");
  const [searchText, setSearchText] = useState("");
  const [scope, setScope] = useState<SearchScope>("all");
  const [recent30, setRecent30] = useState(false);
  const [refinements, setRefinements] = useState<SearchRefinement[]>([]);
  const [savedFilters, setSavedFilters] = useState<SavedFilter[]>(loadSavedFilters);
  const [savingName, setSavingName] = useState<string | null>(null);
  const [translit, setTranslit] = useState<boolean>(loadTranslit);
  const [paletteOpen, setPaletteOpen] = useState(false);
  // Подсветка письма (hl-state из iframe) — привязана к письму: смена выделения сама
  // убирает счётчик прошлой подсветки (без setState в эффекте).
  const [hl, setHl] = useState<{ emailId: string; count: number; index: number } | null>(null);
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

  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const bodyFrameRef = useRef<HTMLIFrameElement | null>(null);

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
  // Контекст окна (WEB-15): общий ящик — выбор «shared:<accountId>»; запросы письма — с его
  // accountId, потоки и сниппеты делегату сервер не отдаёт — плоский список без них.
  const sharedId = sharedAccountId(folder);
  const sharedCtx = sharedAccounts.find((a) => a.id === sharedId) ?? null;
  const windowAccountId = sharedCtx?.id ?? env.accountId;
  const quickCounts = useQuickCounts(null, sharedCtx?.id);

  // Синхронизация: тик push/таймера — время в строке состояния.
  useEffect(() => {
    if (!hub) return;
    return hub.subscribe(() => setLastSync(new Date()));
  }, [hub]);

  const mailboxId = !sharedCtx && folder && folder !== FLAGGED_FOLDER ? folder : null;
  const flagged = folder === FLAGGED_FOLDER;
  // Debounce поиска 300 мс (как в Postman): ввод живёт в поле, запрос — после тишины.
  // Пустой ввод сбрасывает запрос сразу (таймер 0), непустой — после 300 мс.
  useEffect(() => {
    const timer = window.setTimeout(
      () => setSearchText(searchInput.trim()),
      searchInput.trim() ? 300 : 0,
    );
    return () => window.clearTimeout(timer);
  }, [searchInput]);

  const searchActive = isSearchActive({ text: searchText, refinements });
  const args: WindowArgs = useMemo(
    () => ({
      accountId: windowAccountId,
      mailboxId,
      quick,
      flagged,
      unread: filters.unread,
      attachment: filters.attachment,
      sort,
      grouped: !sharedCtx && threadView === "grouped",
      search: searchText.trim() ? searchText.trim() : null,
      scopeAll: scope === "all",
      recent30,
      refinements,
      translit,
    }),
    [windowAccountId, mailboxId, quick, flagged, filters, sort, threadView, searchText, scope, recent30, refinements, translit, sharedCtx],
  );
  const windowQuery = useMailWindow(args);
  // Сниппеты совпадений всех загруженных страниц (SearchSnippet/get) — строка списка их рендерит.
  const snippets = useMemo<Record<string, SearchSnippet>>(
    () => Object.assign({}, ...(windowQuery.data?.pages.map((p) => p.snippets) ?? [])),
    [windowQuery.data],
  );
  const junkId = mailboxes?.find((m) => m.role === "junk")?.id ?? null;
  const archiveId = mailboxes?.find((m) => m.role === "archive")?.id ?? null;
  const inboxId = mailboxes?.find((m) => m.role === "inbox")?.id ?? null;
  const trashId = mailboxes?.find((m) => m.role === "trash")?.id ?? null;

  // Строки списка: представители потоков из окна, письма потоков — из кэша (нормализация id).
  // Общий ящик (WEB-15): у взятых писем метка «Назначено: …» (имя — из справочника).
  const flatIds = useMemo(() => windowQuery.data?.pages.flatMap((p) => p.ids) ?? [], [windowQuery.data]);
  const takenLabelOf = useCallback(
    (email: EmailSummary): string | null => {
      if (!sharedCtx) return null;
      const t = takenOf(email.keywords);
      if (!t) return null;
      return `Назначено: ${takenBy(t, env.selfAddress) ? "вы" : nameOf(t.who)}`;
    },
    [sharedCtx, env.selfAddress, nameOf],
  );
  const rows = useMemo<ListRow[]>(() => {
    const out: ListRow[] = [];
    for (const id of flatIds) {
      const email = queryClient.getQueryData<EmailSummary>(keys.email(id));
      if (!email) continue;
      const takenLabel = takenLabelOf(email);
      if (!args.grouped) {
        out.push({ email, threadCount: 1, threadUnread: email.keywords.$seen ? 0 : 1, threadExpanded: false, threadChild: false, takenLabel });
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
          out.push({ email: m, threadCount: threadEmails.length, threadUnread, threadExpanded: true, threadChild: true, takenLabel: takenLabelOf(m) });
        }
      } else {
        out.push({ email, threadCount: threadEmails.length || 1, threadUnread, threadExpanded: false, threadChild: false, takenLabel });
      }
    }
    return out;
  }, [flatIds, expanded, args.grouped, takenLabelOf]);

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
  const stackFull = useEmailsFull(stackIds, sharedCtx?.id);

  // WEB-05: термы подсветки F3 — из активного поиска (текст без уточнений); письмо открыто
  // не из результатов (пустой поиск) — подсветки нет. iframe тела регистрируется страницей.
  const hlTerms = useMemo(
    () => (searchActive ? highlightTerms(searchText, translit) : []),
    [searchActive, searchText, translit],
  );
  const selectedRef = useRef<string | null>(null);
  useEffect(() => {
    selectedRef.current = selectedId; // свежее выделение для обработчика сообщений iframe
  });
  const onBodyFrame = useCallback((frame: HTMLIFrameElement | null) => {
    bodyFrameRef.current = frame;
    if (!frame) setHl(null);
  }, []);

  // Состояние подсветки (hl-state) — сообщения из srcdoc активного письма.
  const matchState: MatchState | null =
    hl && hl.emailId === selectedId ? { count: hl.count, index: hl.index } : null;
  useEffect(() => {
    const handler = (e: MessageEvent) => {
      if (e.source === bodyFrameRef.current?.contentWindow && isHlState(e.data)) {
        setHl({ emailId: selectedRef.current ?? "", count: e.data.count, index: e.data.index });
      }
    };
    window.addEventListener("message", handler);
    return () => window.removeEventListener("message", handler);
  }, []);

  // ---------- Поиск (WEB-05): чипы, уточнения, сохранённые фильтры ----------

  const clearSearch = useCallback(() => {
    setSearchInput("");
    setSearchText("");
    setHl(null);
  }, []);

  /** filters.reset: сброс запроса, чипов области и уточнений. */
  const resetFilters = () => {
    clearSearch();
    setScope(EMPTY_SEARCH.scope);
    setRecent30(false);
    setRefinements([]);
    setFilters({ unread: false, attachment: false });
  };

  /** Уточнение запроса кликом: чип добавляется один раз (повторный клик — ничего). */
  const addRefinement = (chip: SearchRefinement) => {
    setRefinements((prev) =>
      prev.some((r) => r.kind === chip.kind && r.value === chip.value) ? prev : [...prev, chip],
    );
  };
  const refineSender = (email: EmailSummary) => {
    const from = email.from?.[0];
    if (!from) return;
    addRefinement({ kind: "from", value: from.email, label: `От: ${from.name?.trim() || from.email}` });
  };
  const refinePeriod = (email: EmailSummary) => {
    const period = monthPeriod(email.receivedAt);
    addRefinement({ kind: "period", value: period.after, before: period.before, label: period.label });
  };
  const refineCategory = (category: { keyword: string; name: string }) => {
    addRefinement({ kind: "category", value: category.keyword, label: category.name });
  };
  const refineFolder = (id: string, name: string) => {
    addRefinement({ kind: "folder", value: id, label: `Папка: ${name}` });
  };
  const removeRefinement = (chip: SearchRefinement) => {
    setRefinements((prev) => prev.filter((r) => !(r.kind === chip.kind && r.value === chip.value)));
  };

  /** Имя папки письма для чипа в строке (режим «Везде» — как в Postman). */
  const folderNameOf = useCallback(
    (email: EmailSummary): string | null => {
      const id = Object.keys(email.mailboxIds)[0];
      return (id && mailboxes?.find((m) => m.id === id)?.name) ?? null;
    },
    [mailboxes],
  );

  const applySaved = (saved: SavedFilter) => {
    const state = applySavedFilter(saved);
    setSearchInput(state.text);
    setSearchText(state.text);
    setScope(state.scope);
    setRecent30(state.recent30);
    setFilters({ unread: state.unread, attachment: state.attachment });
    setRefinements(state.refinements);
    toast.show(`Фильтр «${saved.name}» применён`);
  };
  const deleteSaved = (id: string) => setSavedFilters(removeSavedFilter(id));
  const confirmSave = () => {
    const query = {
      text: searchText,
      scope,
      unread: filters.unread,
      attachment: filters.attachment,
      recent30,
      refinements,
    };
    const name = (savingName ?? "").trim();
    if (!searchActive && !name) {
      setSavingName(null);
      return;
    }
    setSavedFilters(saveFilter(name || searchText, query));
    setSavingName(null);
    toast.show("Поиск сохранён рядом с быстрыми фильтрами");
  };

  const openFromList = (email: EmailSummary) => {
    setSelectedId(email.id);
    setCollapsedReading(true);
    if (!email.keywords.$seen) setSeen([email], true);
  };

  // ---------- Действия ----------

  const applyUpdate = async (
    updates: Record<string, Record<string, unknown>>,
    label: string,
    accountId?: string,
  ) => {
    try {
      const snapshot = (await updateMut.mutateAsync({ updates, accountId })) as UndoEntry[];
      const undo = () => {
        void updateMut
          .mutateAsync({ updates: undoEntries(snapshot), accountId })
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
          void updateMut.mutateAsync({ updates: reverse }).then(() => toast.show("Возвращено из корзины"));
        };
        toast.show(emails.length > 1 ? `Удалено писем: ${emails.length}` : "Письмо удалено", undo);
        if (selectedId && emails.some((e) => e.id === selectedId)) setSelectedId(null);
      })
      .catch((e: unknown) => toast.show(e instanceof Error ? e.message : "Удалить не удалось."));
  };

  // ---------- «Взять в работу» (WEB-15, mail.take Postman): слова pm.taken… ----------

  /** Полоса чтения и кнопка действия по письму общего ящика; вне общего ящика — null (Postman:
   * «взять» — только там). */
  const takeStrip: TakeStrip | null = useMemo(() => {
    if (!selected || !sharedCtx) return null;
    const t = takenOf(selected.keywords);
    return {
      act: takeActOf(selected.keywords, env.selfAddress),
      who: t && !takenBy(t, env.selfAddress) ? nameOf(t.who) : null,
      at: t ? t.at.toISOString() : null,
      busy: updateMut.isPending,
    };
  }, [selected, sharedCtx, env.selfAddress, nameOf, updateMut.isPending]);

  /** Действие «взять/забрать/вернуть» по письму общего ящика (строка списка или выделенное). */
  const takeEmail = useCallback(
    (email: EmailSummary) => {
      const act = takeActOf(email.keywords, env.selfAddress);
      if (!sharedCtx) {
        toast.show("«Взять в работу» — для писем общих ящиков.");
        return;
      }
      const patch = takePatchOf(email, env.selfAddress, new Date());
      if (!patch) {
        toast.show("Адрес учётной записи не годится для пометки — взять не удалось.");
        return;
      }
      void updateMut
        .mutateAsync({ updates: { [email.id]: patch }, accountId: sharedCtx.id })
        .then(() => {
          const was = takenOf(email.keywords);
          toast.show(
            act === "release"
              ? "Письмо вернулось в очередь"
              : act === "steal" && was
                ? `Письмо забрано себе (было у: ${nameOf(was.who)}). Коллеги видят «Назначено: вы»`
                : "Письмо в работе у вас. Коллеги видят «Назначено: вы»",
          );
        })
        .catch((e: unknown) =>
          toast.show(e instanceof Error ? e.message : "Взять в работу не удалось."),
        );
    },
    [sharedCtx, env.selfAddress, updateMut, toast, nameOf],
  );

  const takeSelected = useCallback(() => {
    if (selected) takeEmail(selected);
  }, [selected, takeEmail]);

  // Композер — вкладка /compose (WEB-04): новое письмо, ответы и пересылка, черновик.
  // Ответ письму общего ящика (WEB-15): источник — по accountId владельца («От» — общий адрес).
  const openCompose = (query: string = "") => navigate(`/compose${query}`);
  const replyTo = (email: EmailSummary, kind: "reply" | "reply-all" | "forward") =>
    navigate(
      `/compose?kind=${kind}&email=${encodeURIComponent(email.id)}${sharedCtx ? `&account=${encodeURIComponent(sharedCtx.id)}` : ""}`,
    );

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
      // «Взять в работу» (WEB-15) — письмо общего ящика: действие по состоянию слов pm.taken.
      ...(sharedCtx
        ? [{ label: TAKE_LABELS[takeActOf(email.keywords, env.selfAddress)], onSelect: () => takeEmail(email) }]
        : []),
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
      openPalette: () => setPaletteOpen(true),
      findNext: () => sendHlCommand(bodyFrameRef.current, "hl-next"),
      findPrev: () => sendHlCommand(bodyFrameRef.current, "hl-prev"),
      takeSelected,
    }),
    [rows, selectedId, selected, archiveId, expanded, takeSelected],
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

  // ---------- Палитра команд (Ctrl+K, WEB-05): реестр — из хоткеев keymap.ts ----------

  const commands = useMemo<PaletteCommand[]>(() => [
    { id: "compose", label: "Новое письмо", hint: "Ctrl+N", icon: "pen", run: () => openCompose() },
    { id: "reply", label: "Ответить", hint: "Ctrl+R", icon: "reply", run: () => selected && replyTo(selected, "reply") },
    { id: "reply-all", label: "Ответить всем", hint: "Ctrl+Shift+R", icon: "reply", run: () => selected && replyTo(selected, "reply-all") },
    { id: "forward", label: "Переслать", hint: "Ctrl+F", icon: "fwd", run: () => selected && replyTo(selected, "forward") },
    { id: "take", label: selected ? TAKE_LABELS[takeActOf(selected.keywords, env.selfAddress)] : TAKE_LABELS.take, hint: "Ctrl+J", icon: "person", run: () => takeSelected() },
    { id: "read", label: "Отметить прочитанным", hint: "Ctrl+Q", icon: "check", run: () => selected && setSeen([selected], true) },
    { id: "unread", label: "Отметить непрочитанным", hint: "Ctrl+U", icon: "mail", run: () => selected && setSeen([selected], false) },
    { id: "flag", label: selected?.keywords.$flagged ? "Снять флаг" : "Поставить флаг", icon: "flag", run: () => selected && setFlagged([selected], !selected.keywords.$flagged) },
    { id: "delete", label: "Удалить", hint: "Del", icon: "trash", run: () => selected && deleteEmails([selected]) },
    { id: "archive", label: "В архив", hint: "Backspace", icon: "arch", run: () => selected && archiveId && moveTo([selected], archiveId, "В архив") },
    ...CATEGORIES.map((c, i) => ({
      id: `cat-${c.id}`,
      label: `Категория: ${c.name}`,
      hint: String(i + 1),
      icon: "list" as const,
      run: () => selected && categorize([selected], i + 1),
    })),
    { id: "find", label: "Найти в письмах", hint: "Поиск", icon: "search", run: () => searchInputRef.current?.focus() },
    { id: "reset-search", label: "Сбросить поиск и фильтры", icon: "x", run: resetFilters },
    { id: "save-search", label: "Сохранить текущий поиск", icon: "check", run: () => setSavingName(searchText) },
    { id: "density", label: density === "normal" ? "Плотность: компактная" : "Плотность: обычная", icon: "list", run: () => { const next = density === "normal" ? "compact" : "normal"; setDensityState(next); saveDensity(next); } },
    { id: "threads", label: threadView === "grouped" ? "Потоки: как в Outlook" : "Потоки: группировка", icon: "thread", run: () => { const next = threadView === "grouped" ? "outlook" : "grouped"; setThreadViewState(next); saveThreadView(next); } },
    { id: "folders", label: "К дереву папок", hint: "Ctrl+Y", icon: "folder", run: () => { focusIndex.current = 0; treeRef.current?.focus(); } },
    { id: "panels", label: "Между панелями", hint: "F6", icon: "list", run: () => { focusIndex.current = (focusIndex.current + 1) % focusOrder.length; focusOrder[focusIndex.current]?.current?.focus(); } },
  ], [selected, archiveId, density, threadView, searchText, env.selfAddress, takeSelected]);

  // ---------- Рендер ----------

  const folderTitle = sharedCtx
    ? sharedCtx.name
    : flagged
      ? "Отмеченные"
      : (mailboxes?.find((m) => m.id === folder)?.name ?? "Почта");
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
        <div className="searchbar">
          <Icon name="search" size={16} />
          <input
            ref={searchInputRef}
            className="search"
            type="text"
            placeholder="Поиск · from: кому: тема: тело:"
            aria-label="Поиск по письмам"
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            onKeyDown={(e) => {
              // Сброс поиска Escape (WEB-05): запрос и подсветка — прочь, чипы — отдельной кнопкой.
              if (e.key === "Escape") {
                e.preventDefault();
                e.stopPropagation();
                clearSearch();
                (e.target as HTMLInputElement).blur();
              }
            }}
          />
          {searchInput && (
            <button type="button" className="clr" aria-label="Очистить поиск" onClick={clearSearch}>
              <Icon name="x" size={12} />
            </button>
          )}
        </div>
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
              <label>
                Транслитерация раскладки
                <input
                  type="checkbox"
                  checked={translit}
                  onChange={(e) => {
                    setTranslit(e.target.checked);
                    saveTranslit(e.target.checked);
                  }}
                  title="Запрос в чужой раскладке пробуется и как qwerty→йцукен (rdfhnfk → квартал)"
                />
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
          shared={sharedAccounts}
          sharedUnread={sharedUnread}
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
            searchActive={searchActive}
            scope={scope}
            onScope={setScope}
            recent30={recent30}
            onRecent30={setRecent30}
            snippets={snippets}
            refinements={refinements}
            onRemoveRefinement={removeRefinement}
            onRefineSender={refineSender}
            onRefineCategory={refineCategory}
            onRefinePeriod={refinePeriod}
            onRefineFolder={refineFolder}
            folderNameOf={folderNameOf}
            onResetFilters={resetFilters}
            savedFilters={savedFilters}
            onApplySaved={applySaved}
            onDeleteSaved={deleteSaved}
            savingName={savingName}
            onSavingName={setSavingName}
            onSaveConfirm={confirmSave}
            onSaveCancel={() => setSavingName(null)}
            onSaveStart={() => setSavingName(searchText)}
          />
        </div>

        <div ref={readRef} tabIndex={-1} style={{ display: "contents" }}>
          <ReadingPane
            summary={selected}
            stack={stackIds
              .map((id) => queryClient.getQueryData<EmailSummary>(keys.email(id)))
              .filter((e): e is EmailSummary => Boolean(e))}
            stackFull={stackFull}
            highlightTerms={hlTerms}
            matchState={matchState}
            onBodyFrame={onBodyFrame}
            onRefineSender={refineSender}
            onRefinePeriod={refinePeriod}
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
            take={takeStrip}
            onTake={takeSelected}
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

      {/* Палитра команд и писем (Ctrl+K, WEB-05): ввод фильтрует команды + письма (FTS top-5). */}
      <CommandPalette
        open={paletteOpen}
        commands={commands}
        onClose={() => setPaletteOpen(false)}
        onOpenEmail={openFromList}
        translit={translit}
      />
    </div>
  );
}
