/*
  Список писем (WEB-03): TanStack Virtual — цель 50 тыс. строк без лагов (строки фиксированной
  высоты, окно Email/query дозагружается при скролле); потоки — группировка по умолчанию
  (решение 20.11): свёрнутый поток — бейдж «N писем» + последнее сообщение, разворот — по клику
  (двойной) ; «как в Outlook» — плоский список (переключатель в настройках). Строка — как в
  макете 01: отправитель/тема/превью/время, чипы категорий (палитра макета), флаг, срок янтарным,
  «Просрочено N д» заливкой, «Ждём ответа» серым, вложение, бейдж непрочитанности потока.
  Быстрые фильтры — закладками поверх нижнего края (Угрозы/Срок/Ждём/Мне/Истекают), счётчики —
  Email/query с пустой страницей и total (как в Postman S5-02).
*/
import { useEffect, useMemo, useRef, type CSSProperties } from "react";
import { useQuery } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";

import { emailQuery, type EmailSummary } from "../api/jmap";
import { useJmap } from "./context";
import {
  categoryOf,
  dueLabel,
  expireLabel,
  lifecycleOf,
  QUICK_FILTERS,
  waitLabel,
  type QuickFilterKind,
} from "./keywords";
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
}

/** Счётчики быстрых фильтров окна (кэш TanStack, ключ — папка). */
export function useQuickCounts(mailboxId: string | null): Partial<Record<QuickFilterKind, number>> {
  const env = useJmap();
  const base: Record<string, unknown> = mailboxId ? { inMailbox: mailboxId } : {};
  return (
    useQuery<Partial<Record<QuickFilterKind, number>>>({
      queryKey: ["quick-counts", mailboxId],
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
            env.accountId,
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

/** Имя отправителя строки (макет: «Иван Петров»; источник — первое поле From). */
function senderName(email: EmailSummary): string {
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
}: MessageListProps) {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const now = useMemo(() => new Date(), []);

  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => (density === "compact" ? 36 : 52),
    overscan: 12,
  });

  // Дозагрузка окна при скролле до конца (окна Email/query, useInfiniteQuery).
  useEffect(() => {
    const el = scrollRef.current;
    if (!el || isFetchingNext || rows.length === 0) return;
    if (el.scrollTop + el.clientHeight >= el.scrollHeight - 400) fetchNextPage();
  }, [rows.length, fetchNextPage, isFetchingNext]);

  return (
    <section className="list" aria-label="Список писем">
      <div className="lhead">
        {title}
        <span className="sec">{total === null ? "" : `${total} писем · ${unreadCount} непрочитанных`}</span>
        <button type="button" className="sort" onClick={onSort}>
          {sort === "from" ? "По отправителю" : sort === "date-asc" ? "Сначала старые" : "Сначала новые"}
        </button>
      </div>
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
      <div className="rows" ref={scrollRef} style={{ paddingBottom: 34 }}>
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
                    <span className="from">{senderName(email)}</span>
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
                    <span className="time">{rowTime(email.receivedAt, now)}</span>
                  </div>
                  <div className="l2">
                    <span className="subj">{email.subject ?? "(без темы)"}</span>
                    {category && (
                      <span
                        className="chip"
                        style={{ background: `var(${category.chipBgVar})`, color: `var(${category.chipTxVar})` }}
                      >
                        {category.name}
                      </span>
                    )}
                    {email.hasAttachment && <Icon name="clip" size={14} />}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
        {rows.length === 0 && <div className="empty-list">Писем нет.</div>}
      </div>
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
    </section>
  );
}
