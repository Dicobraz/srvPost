/*
  Палитра команд (WEB-05, palette.*): Ctrl+K — overlay по принципу макета 01 (токены почты,
  без новых зависимостей). Ввод фильтрует команды (реестр из хоткеев keymap.ts) и письма —
  текущий запрос FTS сервера (морфология + транслитерация раскладки, top-5). Навигация —
  ↓/↑, Enter — выполнить/открыть, Escape — закрыть; как в Postman.
*/
import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { emailGet, emailQuery, SUMMARY_PROPERTIES, type EmailSummary } from "../api/jmap";
import { useJmap } from "./context";
import { cacheEmails } from "./queries";
import { searchFilter } from "./search";
import { senderName } from "./message-list";
import { Icon, type IconName } from "./icons";

/** Команда палитры: подпись, подсказка клавиш и действие (реестр — из keymap.ts страницы). */
export interface PaletteCommand {
  id: string;
  label: string;
  /** Подсказка клавиш справа (например, «Ctrl+N»). */
  hint?: string;
  /** Значок строки (те же глифы, что в списках). */
  icon?: IconName;
  run(): void;
}

/** Строка палитры: команда или письмо. */
interface PaletteItem {
  key: string;
  kind: "command" | "email";
  label: string;
  hint?: string;
  icon: IconName | null;
  email?: EmailSummary;
  run(): void;
}

/** Фильтрация команд по вводу (без регистра; подсказка клавиш тоже ищется). Экспорт для теста. */
export function filterCommands(commands: PaletteCommand[], query: string): PaletteCommand[] {
  const q = query.trim().toLowerCase();
  if (!q) return commands;
  return commands.filter(
    (c) => c.label.toLowerCase().includes(q) || (c.hint ?? "").toLowerCase().includes(q),
  );
}

interface PaletteProps {
  open: boolean;
  commands: PaletteCommand[];
  onClose(): void;
  /** Открыть письмо из результатов поиска палитры. */
  onOpenEmail(email: EmailSummary): void;
  /** Транслитерация раскладки (настройка) — второй вариант запроса FTS. */
  translit: boolean;
}

/** Палитра команд и писем (Ctrl+K). Рендерится поверх страницы почты; open=false — ничего. */
export function CommandPalette({ open, commands, onClose, onOpenEmail, translit }: PaletteProps) {
  // Состояние (ввод, выбор) живёт в панели: закрытие размонтирует её, открытие — свежая.
  if (!open) return null;
  return <PalettePanel commands={commands} onClose={onClose} onOpenEmail={onOpenEmail} translit={translit} />;
}

function PalettePanel({ commands, onClose, onOpenEmail, translit }: Omit<PaletteProps, "open">) {
  const env = useJmap();
  const [query, setQuery] = useState("");
  const [index, setIndex] = useState(0);

  // Письма по текущему вводу (FTS сервера, top-5): письма кладутся в общий кэш по id —
  // открытие из палитры работает так же, как из списка.
  const trimmed = query.trim();
  const mailQuery = useQuery<EmailSummary[]>({
    queryKey: ["palette-mail", trimmed, translit],
    queryFn: async () => {
      const filter = searchFilter({
        text: trimmed,
        scopeAll: true,
        unread: false,
        attachment: false,
        recent30: false,
        refinements: [],
        mailboxId: null,
        flagged: false,
        quick: null,
        translit,
      });
      if (!filter) return [];
      const q = await emailQuery(env.apiUrl, env.authorization, env.accountId, filter, [
        { property: "receivedAt", isAscending: false },
      ], { limit: 5, collapseThreads: false, total: false });
      const summaries = await emailGet<EmailSummary>(
        env.apiUrl,
        env.authorization,
        env.accountId,
        q.ids,
        SUMMARY_PROPERTIES,
      );
      cacheEmails(summaries);
      return summaries;
    },
    enabled: trimmed.length >= 2,
    staleTime: 15_000,
  });

  const items = useMemo<PaletteItem[]>(() => {
    const cmdItems: PaletteItem[] = filterCommands(commands, query)
      .slice(0, 8)
      .map((c) => ({
        key: `cmd-${c.id}`,
        kind: "command",
        label: c.label,
        hint: c.hint,
        icon: c.icon ?? null,
        run: c.run,
      }));
    const mailItems: PaletteItem[] = (mailQuery.data ?? []).map((e) => ({
      key: `mail-${e.id}`,
      kind: "email",
      label: e.subject ?? "(без темы)",
      hint: senderName(e),
      icon: "mail" as IconName,
      email: e,
      run: () => onOpenEmail(e),
    }));
    return [...cmdItems, ...mailItems];
  }, [commands, query, mailQuery.data, onOpenEmail]);

  // Выбор не выйдет за пределы списка (список сжался — индекс поджимается).
  const safeIndex = Math.min(index, Math.max(0, items.length - 1));

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      onClose();
      return;
    }
    if (e.key === "ArrowDown" || (e.key === "Tab" && !e.shiftKey)) {
      e.preventDefault();
      setIndex(items.length === 0 ? 0 : Math.min(safeIndex + 1, items.length - 1));
      return;
    }
    if (e.key === "ArrowUp" || (e.key === "Tab" && e.shiftKey)) {
      e.preventDefault();
      setIndex(Math.max(0, safeIndex - 1));
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      const item = items[safeIndex];
      if (item) {
        onClose();
        item.run();
      }
    }
  };

  return (
    // Клик по подложке закрывает (как у Postman); клик по панели — нет.
    <div className="palbg" onMouseDown={onClose}>
      <div className="pal" role="dialog" aria-label="Палитра команд" onMouseDown={(e) => e.stopPropagation()}>
        <div className="pin">
          <Icon name="search" size={16} />
          <input
            autoFocus
            value={query}
            placeholder="Команда или поиск по письмам…"
            aria-label="Поиск команды или письма"
            onChange={(e) => {
              setQuery(e.target.value);
              setIndex(0); // новый ввод — выбор с начала списка
            }}
            onKeyDown={onKeyDown}
          />
          <span className="esc">Esc</span>
        </div>
        <div className="pitems">
          {items.length === 0 && <div className="pempty">Ничего не найдено.</div>}
          {items.map((item, i) => (
            <button
              key={item.key}
              type="button"
              className={i === safeIndex ? "pi on" : "pi"}
              onMouseEnter={() => setIndex(i)}
              onClick={() => {
                onClose();
                item.run();
              }}
            >
              {item.icon ? <Icon name={item.icon} size={14} /> : <span className="pic" />}
              <span className="lbl">{item.label}</span>
              <span className={item.kind === "email" ? "hint mail" : "hint"}>{item.hint ?? ""}</span>
            </button>
          ))}
        </div>
        <div className="pfoot">↓↑ — выбор · Enter — выполнить · Esc — закрыть</div>
      </div>
    </div>
  );
}
