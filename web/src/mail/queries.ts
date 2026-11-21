/*
  Запросы почты (WEB-03): TanStack Query поверх JMAP — окна Email/query с дозагрузкой при скролле
  (useInfiniteQuery), письма нормализованы по идентификатору в кэше (список и чтение берут одно и
  то же), потоки — Thread/get для группировки. Мутации — Email/set: keywords патчем, перенос —
  замена mailboxIds, удаление — destroy (сервер переносит в корзину сам, решение #134 — спам тоже
  перенос); оптимистично правят кэш, откат — обратный патч (Undo тоста).
  Папки: Mailbox/get; счётчик виртуальной папки «Отмеченные» — Email/query с пустой страницей.
*/
import { useInfiniteQuery, useMutation, useQuery } from "@tanstack/react-query";

import {
  FULL_PROPERTIES,
  SUMMARY_PROPERTIES,
  emailGet,
  emailQuery,
  emailSetDestroy,
  emailSetUpdate,
  mailboxesGet,
  searchSnippetsGet,
  threadGet,
  type EmailFull,
  type EmailQueryFilter,
  type EmailQuerySort,
  type EmailSummary,
  type Mailbox,
  type SearchSnippet,
  type Thread,
} from "../api/jmap";
import { quickFilterFilters, type QuickFilterKind } from "./keywords";
import { isSearchActive, searchFilter } from "./search";
import type { SearchRefinement } from "./search";
import { keys, queryClient } from "./client";
import { rememberSyncState } from "./sync";
import { useJmap } from "./context";
import type { JmapEnv } from "./types";

/** Аргументы окна списка: папка, быстрые фильтры, сортировка, вид потоков. */
export interface WindowArgs {
  /** Папка; null — все папки (виртуальная «Отмеченные» и фильтры по словам). */
  mailboxId: string | null;
  /** Быстрый фильтр (Угрозы/Срок/Ждём/Мне/Истекают) или null. */
  quick: QuickFilterKind | null;
  /** Только отмеченные ($flagged) — виртуальная папка. */
  flagged: boolean;
  /** Только непрочитанные ($seen нет) — вне поиска фильтр списка, в поиске чип search.unread. */
  unread: boolean;
  /** Только с вложениями (вне поиска фильтр, в поиске чип search.attachments). */
  attachment: boolean;
  /** Сортировка: сначала новые/старые/по отправителю. */
  sort: "date-desc" | "date-asc" | "from";
  /** Вид потока: группировка (collapseThreads) или плоский список («как в Outlook»). */
  grouped: boolean;
  /** Поиск по тексту (FTS сервера; операторы и транслитерация — search.ts). */
  search: string | null;
  // --- WEB-05: поиск и фильтры ---
  /** Область поиска: true — «Везде» (без папки), false — «В папке» (текущая). */
  scopeAll: boolean;
  /** Чип «30 дней» (search.recent): письма за последние 30 дней. */
  recent30: boolean;
  /** Уточнения кликом (отправитель/папка/период/категория) — чипы панели фильтров. */
  refinements: SearchRefinement[];
  /** Транслитерация раскладки (настройка): запрос пробуется и как qwerty→йцукен. */
  translit: boolean;
}

/** Страница окна (дозагрузка при скролле): идентификаторы строк списка. */
export interface WindowPage {
  /** Представители потоков (группировка) или письма (плоский список). */
  ids: string[];
  /** Всего в выборке — только на первой странице. */
  total: number | null;
  /** Сниппеты совпадений (режим поиска, SearchSnippet/get); нет сниппета — превью как было. */
  snippets: Record<string, SearchSnippet>;
}

/** Страница окна (дозагрузка при скролле) и кусок Email/get — не выше типового maxObjectsInGet. */
const PAGE = 100;
const CHUNK = 64;

/** Условие фильтра окна: в режиме поиска — сборка search.ts (чипы, уточнения, транслитерация),
 * вне поиска — папка + маски фильтров (keywords.ts). */
function filterFor(args: WindowArgs): EmailQueryFilter {
  if (isSearchActive({ text: args.search ?? "", refinements: args.refinements })) {
    const built = searchFilter({
      text: args.search ?? "",
      scopeAll: args.scopeAll,
      unread: args.unread,
      attachment: args.attachment,
      recent30: args.recent30,
      refinements: args.refinements,
      mailboxId: args.mailboxId,
      flagged: args.flagged,
      quick: args.quick,
      translit: args.translit,
    });
    if (built) return built;
  }
  const parts: EmailQueryFilter[] = [];
  if (args.flagged) parts.push({ hasKeyword: "$flagged" });
  if (args.unread) parts.push({ notKeyword: "$seen" });
  if (args.attachment) parts.push({ hasAttachment: true });
  if (args.quick) {
    const mask = quickFilterFilters(args.quick, null);
    if (mask) parts.push(mask);
  }
  if (args.mailboxId) parts.push({ inMailbox: args.mailboxId });
  if (args.search) parts.push({ text: args.search });
  if (parts.length === 1) return parts[0];
  return { operator: "AND", conditions: parts };
}

/** Сортировка окна: сначала новые — receivedAt по убыванию (макет: «Сначала новые»). */
function sortFor(sort: WindowArgs["sort"]): EmailQuerySort[] {
  switch (sort) {
    case "date-asc":
      return [{ property: "receivedAt", isAscending: true }];
    case "from":
      return [{ property: "from" }];
    case "date-desc":
    default:
      return [{ property: "receivedAt", isAscending: false }];
  }
}

/** Нормализация: письма кладутся в кэш по id — список и чтение читают одно и то же.
 * (Экспорт для палитры команд WEB-05: письма из поиска палитры открываются панелью чтения.) */
export function cacheEmails(summaries: EmailSummary[]): void {
  for (const s of summaries) queryClient.setQueryData(keys.email(s.id), s);
}

function cacheThreads(threads: Thread[]): void {
  for (const t of threads) queryClient.setQueryData(keys.thread(t.id), t);
}

/** Email/get кусками — идентификаторов бывает больше лимита объектов одного запроса. */
async function fetchChunked<T extends EmailSummary>(
  env: JmapEnv,
  ids: string[],
  properties: readonly string[],
): Promise<T[]> {
  const out: T[] = [];
  for (let i = 0; i < ids.length; i += CHUNK) {
    out.push(
      ...(await emailGet<T>(env.apiUrl, env.authorization, env.accountId, ids.slice(i, i + CHUNK), properties)),
    );
  }
  return out;
}

/** Окно списка с дозагрузкой: первая страница — по открытии папки, дальше — fetchNextPage. */
export function useMailWindow(args: WindowArgs) {
  const env = useJmap();
  return useInfiniteQuery<WindowPage, Error>({
    queryKey: keys.window(args),
    queryFn: async ({ pageParam }) => {
      const position = pageParam as number;
      const query = await emailQuery(
        env.apiUrl,
        env.authorization,
        env.accountId,
        filterFor(args),
        sortFor(args.sort),
        { position, limit: PAGE, collapseThreads: args.grouped, total: position === 0 },
      );
      const summaries = await fetchChunked<EmailSummary>(env, query.ids, SUMMARY_PROPERTIES);
      cacheEmails(summaries);
      // Сниппеты совпадений (WEB-05): SearchSnippet/get с тем же фильтром — на каждую страницу
      // окна. Сервер без сниппетов или без совпадений в тексте — превью как было (fallback UI).
      const snippets: Record<string, SearchSnippet> = {};
      if (args.search) {
        try {
          for (let i = 0; i < query.ids.length; i += CHUNK) {
            const list = await searchSnippetsGet(
              env.apiUrl,
              env.authorization,
              env.accountId,
              filterFor(args),
              query.ids.slice(i, i + CHUNK),
            );
            for (const s of list) snippets[s.emailId] = s;
          }
        } catch {
          // Сниппеты — усиление, не требование: без них список показывает обычное превью.
        }
      }
      if (args.grouped) {
        // Потоки: счётчик «N писем» и участники — по Thread/get; письма потока тоже в кэше
        // (разворот потока не ходит в сеть, если его письма уже загружены).
        const tids = [...new Set(summaries.map((s) => s.threadId))];
        const threads = await threadGet(env.apiUrl, env.authorization, env.accountId, tids);
        const threadEmails = [...new Set(threads.flatMap((t) => t.emailIds))];
        const missing = threadEmails.filter(
          (id) => !summaries.some((s) => s.id === id) && !queryClient.getQueryData(keys.email(id)),
        );
        if (missing.length > 0) {
          cacheEmails(await fetchChunked<EmailSummary>(env, missing, SUMMARY_PROPERTIES));
        }
        cacheThreads(threads);
      }
      return { ids: query.ids, total: position === 0 ? query.total : null, snippets };
    },
    initialPageParam: 0,
    getNextPageParam: (_lastPage, pages, lastPageParam) => {
      const total = pages[0]?.total;
      if (total === null || total === undefined) return undefined;
      const next = (lastPageParam as number) + PAGE;
      return next < total ? next : undefined;
    },
    // Окно смены фильтров показывает прежний список, пока грузится новый (без мигания).
    placeholderData: (previous) => previous,
  });
}

/** Полные письма беседы (стопка чтения): один запрос на все письма стека. */
export function useEmailsFull(ids: string[]): Record<string, EmailFull> {
  const env = useJmap();
  const stableKey = [...ids].sort().join(",");
  const query = useQuery<Record<string, EmailFull>>({
    queryKey: ["full-batch", stableKey],
    queryFn: async () => {
      const list = await fetchChunked<EmailFull>(env, ids, FULL_PROPERTIES);
      return Object.fromEntries(list.map((e) => [e.id, e]));
    },
    enabled: ids.length > 0,
    staleTime: 60_000,
  });
  return query.data ?? {};
}

/** Все папки учётной записи (дерево строит клиент). */
export function useMailboxes(): Mailbox[] | undefined {
  const env = useJmap();
  return useQuery<Mailbox[]>({
    queryKey: keys.mailboxes(),
    queryFn: async () => {
      const { list, state } = await mailboxesGet(env.apiUrl, env.authorization, env.accountId);
      rememberSyncState(state); // точка отсчёта delta-sync по состоянию почты
      return list;
    },
  }).data;
}

/** Счётчик виртуальной папки «Отмеченные» — Email/query с пустой страницей и total. */
export function useFlaggedCount(): number | undefined {
  const env = useJmap();
  const query = useQuery<number>({
    queryKey: keys.flaggedCount(),
    queryFn: async () => {
      const q = await emailQuery(
        env.apiUrl,
        env.authorization,
        env.accountId,
        { hasKeyword: "$flagged" },
        [{ property: "receivedAt", isAscending: false }],
        { limit: 0, total: true },
      );
      return q.total ?? 0;
    },
    staleTime: 30_000,
  });
  return query.data;
}

// ---------- Мутации (Email/set): оптимистичный кэш, Undo — обратный патч ----------

/** Ключевые слова письма (патч keywords — Map слово → true/false). */
export type Keywords = Record<string, boolean>;

/** Снимок письма до мутации — для Undo тоста и отката ошибки. */
export interface UndoEntry {
  emailId: string;
  keywords: Keywords | null;
  mailboxIds: Record<string, boolean> | null;
}

/** Оптимистичное применение патчей к кэшу писем; снимок — для Undo. */
function applyOptimistic(updates: Record<string, Record<string, unknown>>): UndoEntry[] {
  const snapshot: UndoEntry[] = [];
  for (const [emailId, patch] of Object.entries(updates)) {
    const cached = queryClient.getQueryData<EmailSummary>(keys.email(emailId));
    snapshot.push({
      emailId,
      keywords: cached ? { ...cached.keywords } : null,
      mailboxIds: cached ? { ...cached.mailboxIds } : null,
    });
    if (cached) queryClient.setQueryData(keys.email(emailId), { ...cached, ...patch });
  }
  return snapshot;
}

/** Возвращение прежних keywords/mailboxIds (Undo тоста или откат ошибки). */
export function undoEntries(snapshot: UndoEntry[]): Record<string, Record<string, unknown>> {
  const reverse: Record<string, Record<string, unknown>> = {};
  for (const entry of snapshot) {
    const patch: Record<string, unknown> = {};
    if (entry.keywords) patch.keywords = entry.keywords;
    if (entry.mailboxIds) patch.mailboxIds = entry.mailboxIds;
    if (Object.keys(patch).length > 0) reverse[entry.emailId] = patch;
    const cached = queryClient.getQueryData<EmailSummary>(keys.email(entry.emailId));
    if (cached) queryClient.setQueryData(keys.email(entry.emailId), { ...cached, ...patch });
  }
  return reverse;
}

function invalidateAfterChange(): void {
  // Списки (окна) и счётчики папок перечитываются; письма остаются в кэше по id.
  void queryClient.invalidateQueries({ queryKey: ["window"] });
  void queryClient.invalidateQueries({ queryKey: ["mailboxes"] });
  void queryClient.invalidateQueries({ queryKey: ["count"] });
}

/** Мутация Email/set update: патчи keywords/mailboxIds по письмам; снимок — для Undo. */
export function useEmailUpdateMutation() {
  const env = useJmap();
  return useMutation({
    mutationFn: async (updates: Record<string, Record<string, unknown>>) => {
      const snapshot = applyOptimistic(updates);
      await emailSetUpdate(env.apiUrl, env.authorization, env.accountId, updates);
      return snapshot;
    },
    onSettled: () => invalidateAfterChange(),
    onError: (_error, _updates, snapshot) => {
      if (Array.isArray(snapshot)) undoEntries(snapshot as UndoEntry[]);
    },
  });
}

/** Патч переноса: письмо целиком в одну папку (замена mailboxIds — как Postman move). */
export function movePatch(_summary: EmailSummary, target: string): Record<string, unknown> {
  return { mailboxIds: { [target]: true } };
}

/** Мутация удаления (destroy): сервер переносит в корзину; повтор — «очистить корзину». */
export function useEmailDestroyMutation() {
  const env = useJmap();
  return useMutation({
    mutationFn: async (ids: string[]) => {
      const snapshot: UndoEntry[] = [];
      for (const id of ids) {
        const cached = queryClient.getQueryData<EmailSummary>(keys.email(id));
        if (cached) snapshot.push({ emailId: id, keywords: null, mailboxIds: { ...cached.mailboxIds } });
      }
      await emailSetDestroy(env.apiUrl, env.authorization, env.accountId, ids);
      return snapshot;
    },
    onSettled: () => invalidateAfterChange(),
  });
}

/** Патч ключевых слов: одно слово включить/выключить, остальные не трогать (Postman SetKeywords). */
export function keywordPatch(word: string, on: boolean): Record<string, unknown> {
  return { [`keywords/${word}`]: on };
}
