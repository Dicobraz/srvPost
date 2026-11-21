/*
  Полоса «Напоминания» (WEB-19, решение владельца 21.11 — «напоминания должны появляться и висеть
  фоном, чтобы были всегда перед глазами»): постоянная полоса оболочки над разделами — живёт в
  App.tsx над роутом, поэтому видна на Почте, Календаре и Контактах. Данные — useReminders
  (Email/query по маскам слов pm.due/pm.wait/pm.expire); живое обновление — инвалидация по
  StateChange (push и delta-sync, sync.ts) и мутациям слов; границы «сейчас» (Просрочено/Сегодня)
  двигает минутный тик. Группировка и подписи — reminders.ts. Клик по секции — раздел «Почта» с
  быстрым фильтром (?quick=due|wait, механика wave 3), клик по письму — открыть (?open=<id>).
  Свёрнутый вид — счётчик; свёрнутость — localStorage. Нет напоминаний — полосы нет.
*/
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router";

import type { EmailSummary } from "../api/jmap";
import { lifecycleOf, waitLabel } from "./keywords";
import { Icon } from "./icons";
import { useReminders } from "./queries";
import {
  groupReminders,
  reminderDueText,
  reminderMomentsOf,
  REMINDER_SECTIONS,
  remindersTotal,
  type ReminderGroups,
  type ReminderItem,
  type ReminderSectionId,
} from "./reminders";

const OPEN_KEY = "thepost-webmail-reminders";
/** Ближайшие темы в секции (остальные — счётчиком «Ещё N»): полоса не должна съедать экран. */
const MAX_ITEMS = 5;

function loadOpen(): boolean {
  try {
    return localStorage.getItem(OPEN_KEY) !== "closed";
  } catch {
    return true;
  }
}

function saveOpen(open: boolean): void {
  try {
    localStorage.setItem(OPEN_KEY, open ? "open" : "closed");
  } catch {
    // Приватный режим без localStorage: свёрнутость живёт до перезагрузки страницы.
  }
}

/** Секция для рендера: пункты, подпись счётчика «Ещё N». */
interface ReminderSectionView {
  id: ReminderSectionId;
  label: string;
  quick: "due" | "wait";
  items: ReminderItem[];
  more: number;
  overdue: boolean;
}

function sectionsOf(groups: ReminderGroups): ReminderSectionView[] {
  const cap = (items: ReminderItem[]): { items: ReminderItem[]; more: number } => ({
    items: items.slice(0, MAX_ITEMS),
    more: Math.max(0, items.length - MAX_ITEMS),
  });
  const next = cap(groups.next);
  const byId: Record<ReminderSectionId, { items: ReminderItem[]; more: number }> = {
    overdue: cap(groups.overdue),
    today: cap(groups.today),
    next: { items: next.items, more: next.more + groups.later }, // сроки дальше 7 дней — счётчиком
    wait: cap(groups.wait),
  };
  return REMINDER_SECTIONS.map((s) => ({
    id: s.id,
    label: s.label,
    quick: s.quick,
    items: byId[s.id].items,
    more: byId[s.id].more,
    overdue: s.id === "overdue",
  }));
}

export function RemindersBar() {
  const navigate = useNavigate();
  const emails = useReminders();
  const [open, setOpen] = useState(loadOpen);
  // Границы «сейчас» (Просрочено → Сегодня → Далее) двигает минутный тик; данные приходят
  // по push/инвалидации (sync.ts, queries.ts) — без перезагрузки страницы.
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = window.setInterval(() => setNow(new Date()), 60_000);
    return () => window.clearInterval(timer);
  }, []);

  const groups = useMemo(
    () =>
      groupReminders(
        emails.map((e: EmailSummary) => ({ id: e.id, subject: e.subject, keywords: e.keywords })),
        now,
      ),
    [emails, now],
  );
  const total = remindersTotal(groups);
  if (total === 0) return null; // напоминаний нет — полоса не занимает место
  const overdueCount = groups.overdue.length;

  const openEmail = (id: string) => navigate(`/?open=${encodeURIComponent(id)}`);
  const openSection = (quick: string) => navigate(`/?quick=${quick}`);

  return (
    <div className="rembar" role="region" aria-label="Напоминания">
      <button
        type="button"
        className="rem-toggle"
        aria-expanded={open}
        title="Напоминания — всегда перед глазами (WEB-19): клик сворачивает полосу"
        onClick={() => {
          const next = !open;
          setOpen(next);
          saveOpen(next);
        }}
      >
        <Icon name="bell" size={16} />
        <span>Напоминания</span>
        <span className={overdueCount > 0 ? "rem-count over" : "rem-count"}>{total}</span>
        {overdueCount > 0 && <span className="rem-sub">просрочено: {overdueCount}</span>}
        <span className="rem-chev" aria-hidden="true">
          {open ? "▾" : "▸"}
        </span>
      </button>
      {open && (
        <div className="rem-sections">
          {sectionsOf(groups)
            .filter((s) => s.items.length > 0 || s.more > 0)
            .map((s) => (
              <div key={s.id} className={s.overdue ? "rem-sec overdue" : "rem-sec"}>
                <button type="button" className="rem-sec-head" onClick={() => openSection(s.quick)}>
                  {s.label}
                  <span className="rem-badge">{s.items.length + s.more}</span>
                </button>
                {s.items.map((item) => {
                  const m = reminderMomentsOf(item.keywords);
                  const when =
                    s.id === "wait"
                      ? (waitLabel(lifecycleOf(item.keywords), now) ?? "Ждём ответа")
                      : (reminderDueText(m.due, now) ?? "Срок");
                  return (
                    <button key={item.id} type="button" className="rem-item" onClick={() => openEmail(item.id)}>
                      <span className="subj">{item.subject ?? "(без темы)"}</span>
                      <span className={s.overdue ? "when over" : "when"}>{when}</span>
                    </button>
                  );
                })}
                {s.more > 0 && <div className="rem-later">Ещё {s.more}…</div>}
              </div>
            ))}
        </div>
      )}
    </div>
  );
}
