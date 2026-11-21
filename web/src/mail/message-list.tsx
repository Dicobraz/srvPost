/*
  Список писем (WEB-03): TanStack Virtual — цель 50 тыс. строк без лагов (строки фиксированной
  высоты, окно Email/query дозагружается при скролле); потоки — группировка по умолчанию
  (решение 20.11): свёрнутый поток — бейдж «N писем» + последнее сообщение, разворот — по клику
  (двойной) ; «как в Outlook» — плоский список (переключатель в настройках). Строка — как в
  макете 01: отправитель/тема/превью/время, чипы категорий (палитра макета), флаг, срок янтарным,
  «Просрочено N д» заливкой, «Ждём ответа» серым, вложение, бейдж непрочитанности потока.
  Быстрые фильтры — закладками поверх нижнего края (Угрозы/Срок/Ждём/Мне/Истекают), счётчики —
  Email/query с пустой страницей и total (как в Postman S5-02).
  WEB-05 — поиск: чипы области над результатами (PARITY search.all/folder/attachments/unread/
  recent) вместо строки простых фильтров, уточнения кликом (отправитель/категория/период/папка —
  чипы с крестиком), сниппеты совпадений сервера (SearchSnippet/get, <mark>) третьей строкой,
  сохранённые фильтры (search.save_filter) — рядом под быстрыми фильтрами.
*/
import { useEffect, useMemo, useRef, type CSSProperties } from "react";
import { useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";

import { emailQuery, type EmailSummary, type SearchSnippet } from "../api/jmap";
import { useJmap } from "./context";
import {
  categoryOf,
  dueLabel,
  expireLabel,
  lifecycleOf,
  QUICK_FILTERS,
  waitLabel,
  type Category,
  type QuickFilterKind,
} from "./keywords";
import { snippetHtml, type SearchRefinement, type SearchScope } from "./search";
import type { SavedFilter } from "./saved-filters";
import { Icon } from "./icons";

/** Строка списка: письмо (свёрнутый поток — представитель) или раскрытое письмо потока. */
export interface ListRow {
  email: EmailSummary;
  /** Поток: количество писем (>1 — значок беседы), непрочитанные, раскрыт ли. */
  threadCount: number;
  threadUnread: number;
  threadExpanded: boolean;
  /** Письмо внутри развёрнутого потока — с отступом темы. */
  threadChild: boolean;
  /** «Назначено: …» — письмо общего ящика взято в работу (WEB-15); null — метки нет. */
  takenLabel?: string | null;
}

/** Чип уточнения (панель фильтров) для рендера с крестиком. */
function RefinementChip({ chip, onRemove }: { chip: SearchRefinement; onRemove(): void }) {
  return (
    <span className="rf">
      {chip.label}
      <button type="button" className="x" aria-label={`Снять уточнение ${chip.label}`} onClick={onRemove}>
        ×
      </button>
    </span>
  );
}

interface MessageListProps {
  title: string;
  rows: ListRow[];
  total: number | null;
  unreadCount: number;
  density: "normal" | "compact";
  selectedId: string | null;
  onSelect(email: EmailSummary): void;
  onToggleThread(email: EmailSummary): void;
  onRowMenu(email: EmailSummary, x: number, y: number): void;
  onDragStartEmail(email: EmailSummary): void;
  /** Быстрые фильтры: текущий, счётчики, клик. */
  quick: QuickFilterKind | null;
  counts: Partial<Record<QuickFilterKind, number>>;
  onQuick(kind: QuickFilterKind | null): void;
  filters: { unread: boolean; attachment: boolean };
  onFilters(next: { unread: boolean; attachment: boolean }): void;
  fetchNextPage(): void;
  isFetchingNext: boolean;
  sort: "date-desc" | "date-asc" | "from";
  onSort(): void;
  // --- WEB-05: поиск ---
  /** Режим поиска: есть текст запроса или уточнения. */
  searchActive: boolean;
  /** Область поиска: «Везде»/«В папке» (search.all/search.folder). */
  scope: SearchScope;
  onScope(scope: SearchScope): void;
  /** Чип «30 дней» (search.recent). */
  recent30: boolean;
  onRecent30(on: boolean): void;
  /** Сниппеты совпадений страницы (SearchSnippet/get); нет записи — превью как было. */
  snippets: Record<string, SearchSnippet>;
  /** Уточнения кликом и снятие чипа. */
  refinements: SearchRefinement[];
  onRemoveRefinement(chip: SearchRefinement): void;
  /** Click-refinements: отправитель/категория/период/папка из строки списка. */
  onRefineSender(email: EmailSummary): void;
  onRefineCategory(category: Category, email: EmailSummary): void;
  onRefinePeriod(email: EmailSummary): void;
  onRefineFolder(mailboxId: string, label: string): void;
  /** Имя папки письма (для чипа «Везде» — как в Postman). */
  folderNameOf(email: EmailSummary): string | null;
  /** Сброс поиска и чипов (filters.reset). */
  onResetFilters(): void;
  /** Сохранённые фильтры (search.save_filter): список, применение, удаление, сохранение. */
  savedFilters: SavedFilter[];
  onApplySaved(saved: SavedFilter): void;
  onDeleteSaved(id: string): void;
  /** Инлайн-ввод имени сохраняемого поиска: null — закрыт, иначе текущее значение. */
  savingName: string | null;
  onSavingName(name: string): void;
  onSaveConfirm(): void;
  onSaveCancel(): void;
  onSaveStart(): void;
}

/** Счётчики быстрых фильтров окна (кэш TanStack, ключ — папка); общий ящик — по его accountId
 * (WEB-15). */
export function useQuickCounts(mailboxId: string | null, accountId?: string): Partial<Record<QuickFilterKind, number>> {
  const env = useJmap();
  const base: Record<string, unknown> = mailboxId ? { inMailbox: mailboxId } : {};
  return (
    useQuery<Partial<Record<QuickFilterKind, number>>>({
      queryKey: ["quick-counts", accountId ?? env.accountId, mailboxId],
      queryFn: async () => {
        const masks: Array<[QuickFilterKind, Record<string, unknown>]> = [
          ["threat", { hasKeyword: "pm.threat" }],
          ["due", { hasKeyword: "pm.due" }],
          ["wait", { hasKeyword: "pm.wait" }],
          ["me", { to: env.selfAddress }],
          ["expire", { hasKeyword: "pm.expire" }],
        ];
        const out: Partial<Record<QuickFilterKind, number>> = {};
        for (const [kind, mask] of masks) {
          const q = await emailQuery(
            env.apiUrl,
            env.authorization,
            accountId ?? env.accountId,
            { operator: "AND", conditions: [base, mask] },
            [{ property: "receivedAt", isAscending: false }],
            { limit: 0, total: true },
          );
          out[kind] = q.total ?? 0;
        }
        return out;
      },
      staleTime: 20_000,
    }).data ?? {}
  );
}

/** Время в строке: сегодня — часы, вчера — «Вчера», в этом году — день недели, старше — дата. */
function rowTime(receivedAt: string, now: Date): string {
  const d = new Date(receivedAt);
  if (d.toDateString() === now.toDateString()) {
    return d.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" });
  }
  const yesterday = new Date(now);
  yesterday.setDate(now.getDate() - 1);
  if (d.toDateString() === yesterday.toDateString()) return "Вчера";
  if (d.getFullYear() === now.getFullYear()) {
    return d.toLocaleDateString("ru", { weekday: "short" });
  }
  return d.toLocaleDateString("ru", { day: "2-digit", month: "2-digit", year: "2-digit" });
}

/** Имя отправителя строки (макет: «Иван Петров»; источник — первое поле From).
 * Экспорт для палитры команд (подсказка письма — отправитель). */
export function senderName(email: EmailSummary): string {
  const from = email.from?.[0];
  if (!from) return "(неизвестный отправитель)";
  return from.name?.trim() || from.email;
}

/** Инициалы для аватара чтения. */
export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).slice(0, 2);
  return parts.map((p) => [...p][0]?.toUpperCase() ?? "").join("") || "?";
}

export function MessageList({
  title,
  rows,
  total,
  unreadCount,
  density,
  selectedId,
  onSelect,
  onToggleThread,
  onRowMenu,
  onDragStartEmail,
  quick,
  counts,
  onQuick,
  filters,
  onFilters,
  fetchNextPage,
  isFetchingNext,
  sort,
  onSort,
  searchActive,
  scope,
  onScope,
  recent30,
  onRecent30,
  snippets,
  refinements,
  onRemoveRefinement,
  onRefineSender,
  onRefineCategory,
  onRefinePeriod,
  onRefineFolder,
  folderNameOf,
  onResetFilters,
  savedFilters,
  onApplySaved,
  onDeleteSaved,
  savingName,
  onSavingName,
  onSaveConfirm,
  onSaveCancel,
  onSaveStart,
}: MessageListProps) {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const now = useMemo(() => new Date(), []);

  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => (searchActive && density === "normal" ? 72 : density === "compact" ? 36 : 52),
    overscan: 12,
  });

  // Высота строки меняется с режимом поиска (третья строка — сниппет): пересчёт размеров.
  useEffect(() => {
    virtual.measure();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchActive, density]);

  // Дозагрузка окна при скролле до конца (окна Email/query, useInfiniteQuery).
  useEffect(() => {
    const el = scrollRef.current;
    if (!el || isFetchingNext || rows.length === 0) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 400) fetchNextPage();
  }, [rows.length, fetchNextPage, isFetchingNext]);

  const savedRowVisible = savedFilters.length > 0 || savingName !== null;
  const refinementChips =
    refinements.length > 0 || filters.unread || filters.attachment || recent30 ? (
      refinements.map((chip) => (
        <RefinementChip key={`${chip.kind}:${chip.value}`} chip={chip} onRemove={() => onRemoveRefinement(chip)} />
      ))
    ) : null;

  return (
    <section className="list" aria-label="Список писем">
      <div className="lhead">
        {title}
        <span className="sec">{total === null ? "" : `${total} писем · ${unreadCount} непрочитанных`}</span>
        <button type="button" className="sort" onClick={onSort}>
          {sort === "from" ? "По отправителю" : sort === "date-asc" ? "Сначала старые" : "Сначала новые"}
        </button>
      </div>
      {searchActive ? (
        // Чипы области поиска (PARITY search.*): Везде/В папке — переключатель, остальные — чипы;
        // рядом — уточнения кликом, сброс (filters.reset) и сохранение текущего поиска.
        <div className="filters scopes">
          <button type="button" className={scope === "all" ? "f on" : "f"} onClick={() => onScope("all")} title="Искать во всех папках (search.all)">
            Везде
          </button>
          <button type="button" className={scope === "folder" ? "f on" : "f"} onClick={() => onScope("folder")} title="Искать только в этой папке (search.folder)">
            В папке
          </button>
          <span className="sep" />
          <button
            type="button"
            className={filters.attachment ? "f on" : "f"}
            onClick={() => onFilters({ ...filters, attachment: !filters.attachment })}
            title="Только письма с вложениями (search.attachments)"
          >
            С вложениями
          </button>
          <button
            type="button"
            className={filters.unread ? "f on" : "f"}
            onClick={() => onFilters({ ...filters, unread: !filters.unread })}
            title="Только непрочитанные (search.unread)"
          >
            Непрочитанные
          </button>
          <button
            type="button"
            className={recent30 ? "f on" : "f"}
            onClick={() => onRecent30(!recent30)}
            title="За последние 30 дней (search.recent)"
          >
            30 дней
          </button>
          {refinementChips}
          <span className="sp" />
          <button type="button" className="f act" onClick={onSaveStart} title="Сохранить текущий поиск (search.save_filter)">
            Сохранить
          </button>
          <button type="button" className="f act" onClick={onResetFilters} title="Сбросить поиск и чипы (filters.reset)">
            Сбросить
          </button>
        </div>
      ) : (
        <div className="filters">
          <button type="button" className={filters.unread ? "f on" : "f"} onClick={() => onFilters({ ...filters, unread: !filters.unread })}>
            Непрочитанные
          </button>
          <button
            type="button"
            className={filters.attachment ? "f on" : "f"}
            onClick={() => onFilters({ ...filters, attachment: !filters.attachment })}
          >
            С вложениями
          </button>
        </div>
      )}
      <div className="rows" ref={scrollRef} style={{ paddingBottom: savedRowVisible ? 72 : 34 }}>
        <div style={{ height: virtual.getTotalSize(), position: "relative" }}>
          {virtual.getVirtualItems().map((item) => {
            const row = rows[item.index];
            const email = row.email;
            const category = categoryOf(email.keywords);
            const lifecycle = lifecycleOf(email.keywords);
            const due = dueLabel(lifecycle, now);
            const wait = waitLabel(lifecycle);
            const expire = expireLabel(lifecycle, now);
            const unread = !email.keywords.$seen;
            const flagged = Boolean(email.keywords.$flagged);
            const isGroup = row.threadCount > 1 && !row.threadChild;
            const snippet = snippets[email.id];
            const folderChip = searchActive && scope === "all" ? folderNameOf(email) : null;
            const rowStyle: CSSProperties = {
              position: "absolute",
              top: 0,
              left: 0,
              width: "100%",
              height: item.size,
              transform: `translateY(${item.start}px)`,
              ...(category && !row.threadChild ? { ["--catcol" as string]: `var(${category.barVar})` } : {}),
            };
            return (
              <div key={item.key} style={rowStyle}>
                <div
                  className={[
                    "msg",
                    unread ? "unread" : "",
                    selectedId === email.id ? "sel" : "",
                    category && !row.threadChild ? "catbar" : "",
                  ]
                    .join(" ")
                    .trim()}
                  onClick={() => onSelect(email)}
                  onDoubleClick={() => onToggleThread(email)}
                  onContextMenu={(e) => {
                    e.preventDefault();
                    onRowMenu(email, e.clientX, e.clientY);
                  }}
                  draggable
                  onDragStart={() => onDragStartEmail(email)}
                  data-email-id={email.id}
                >
                  <div className="l1">
                    {isGroup && <Icon name="thread" size={14} />}
                    <span
                      className={searchActive ? "from rfx" : "from"}
                      title={searchActive ? "Уточнить: письма этого отправителя" : undefined}
                      onClick={
                        searchActive
                          ? (e) => {
                              e.stopPropagation();
                              onRefineSender(email);
                            }
                          : undefined
                      }
                    >
                      {senderName(email)}
                    </span>
                    {flagged && <Icon name="flag" size={14} />}
                    {row.threadUnread > 0 && <span className="unread-badge">{row.threadUnread}</span>}
                    {isGroup && <span className="st">{row.threadCount} писем</span>}
                    {due && (
                      <span className={due.overdue ? "duelbl over" : "duelbl"}>
                        <Icon name="clock" size={14} />
                        {due.text}
                      </span>
                    )}
                    {wait && !due && <span className="st">{wait}</span>}
                    {expire && !due && !wait && <span className="st">{expire}</span>}
                    {row.takenLabel && (
                      <span className="st taken" title="Письмо общего ящика взято в работу">
                        <Icon name="person" size={14} />
                        {row.takenLabel}
                      </span>
                    )}
                    <span
                      className={searchActive ? "time rfx" : "time"}
                      title={searchActive ? "Уточнить: этот месяц" : undefined}
                      onClick={
                        searchActive
                          ? (e) => {
                              e.stopPropagation();
                              onRefinePeriod(email);
                            }
                          : undefined
                      }
                    >
                      {rowTime(email.receivedAt, now)}
                    </span>
                  </div>
                  <div className="l2">
                    {snippet?.subject ? (
                      <span className="subj" dangerouslySetInnerHTML={{ __html: snippetHtml(snippet.subject) }} />
                    ) : (
                      <span className="subj">{email.subject ?? "(без темы)"}</span>
                    )}
                    {category && (
                      <span
                        className={searchActive ? "chip rfx" : "chip"}
                        style={{ background: `var(${category.chipBgVar})`, color: `var(${category.chipTxVar})` }}
                        title={searchActive ? "Уточнить: эта категория" : undefined}
                        onClick={
                          searchActive
                            ? (e) => {
                                e.stopPropagation();
                                onRefineCategory(category, email);
                              }
                            : undefined
                        }
                      >
                        {category.name}
                      </span>
                    )}
                    {folderChip && (
                      <span
                        className="fchip"
                        title="Уточнить: эта папка"
                        onClick={(e) => {
                          e.stopPropagation();
                          const id = Object.keys(email.mailboxIds)[0];
                          if (id) onRefineFolder(id, folderChip);
                        }}
                      >
                        <Icon name="folder" size={12} />
                        {folderChip}
                      </span>
                    )}
                    {email.hasAttachment && <Icon name="clip" size={14} />}
                  </div>
                  {searchActive && density === "normal" && (
                    <div className="l3">
                      {snippet?.preview ? (
                        <span dangerouslySetInnerHTML={{ __html: snippetHtml(snippet.preview) }} />
                      ) : (
                        <span>{email.preview}</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
        {rows.length === 0 && <div className="empty-list">Писем нет.</div>}
      </div>
      <div className="qfwrap">
        <div className="qf">
          {QUICK_FILTERS.map((f) => (
            <button
              key={f.kind}
              type="button"
              className={quick === f.kind ? "f on" : "f"}
              data-icon={f.iconVar === "--i-red" ? "red" : f.iconVar === "--i-amber" ? "amber" : "blue"}
              onClick={() => onQuick(quick === f.kind ? null : f.kind)}
            >
              <Icon name={f.kind === "threat" ? "shield" : f.kind === "me" ? "person" : "clock"} size={14} />
              {f.label}
              <span className="cnt">{counts[f.kind] ?? ""}</span>
            </button>
          ))}
        </div>
        {savedRowVisible && (
          // Сохранённые фильтры (search.save_filter): ряд под быстрыми фильтрами — как в Postman.
          <div className="saved">
            {savedFilters.map((f) => (
              <span key={f.id} className="sfchip">
                <button type="button" className="nm" title="Применить сохранённый поиск" onClick={() => onApplySaved(f)}>
                  {f.name}
                </button>
                <button type="button" className="x" aria-label={`Удалить фильтр ${f.name}`} onClick={() => onDeleteSaved(f.id)}>
                  ×
                </button>
              </span>
            ))}
            {savingName !== null && (
              <form
                className="sfform"
                onSubmit={(e) => {
                  e.preventDefault();
                  onSaveConfirm();
                }}
              >
                <input
                  autoFocus
                  value={savingName}
                  placeholder="Имя поиска"
                  aria-label="Имя сохраняемого поиска"
                  onChange={(e) => onSavingName(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Escape") onSaveCancel();
                  }}
                  onBlur={onSaveCancel}
                />
              </form>
            )}
          </div>
        )}
      </div>
    </section>
  );
}
