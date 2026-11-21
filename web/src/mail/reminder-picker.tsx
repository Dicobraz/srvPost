/*
  Inline-пикер напоминания (WEB-19): без модалок — панель у точки вызова (как контекстное меню и
  настройки чтения). «Напомнить…» — дата и время с пресетами («Завтра 9:00», «Через неделю»);
  «Ждать ответа…» — дата по желанию (без даты — общее слово pm.wait); «Исчезнет…» — дата и время.
  Слова ставятся как в Postman (S5-04): рядом общее слово и слово с датой — reminders.ts.
  Закрытие — клик мимо, Esc, действие. Дата и время — местные.
*/
import { useEffect, useRef, useState } from "react";

import type { EmailSummary } from "../api/jmap";
import {
  fromInputDateTime,
  presetInWeek,
  presetTomorrow9,
  reminderDueText,
  reminderMomentsOf,
  toInputDate,
  toInputTime,
  type ReminderKind,
} from "./reminders";

/** Что и где редактируется: письмо, вид напоминания, координаты вызова. */
export interface ReminderPickerState {
  email: EmailSummary;
  kind: ReminderKind;
  x: number;
  y: number;
}

interface ReminderPickerProps {
  state: ReminderPickerState;
  /** Поставить: момент (местный) или null — без даты (только «Ждать ответа»). */
  onApply(at: Date | null): void;
  /** Снять этот вид напоминания. */
  onClear(): void;
  onClose(): void;
}

const TITLES: Record<ReminderKind, string> = { due: "Напомнить", wait: "Ждать ответа", expire: "Исчезнет" };

export function ReminderPicker({ state, onApply, onClear, onClose }: ReminderPickerProps) {
  const ref = useRef<HTMLDivElement | null>(null);
  const current = reminderMomentsOf(state.email.keywords)[state.kind];
  const [date, setDate] = useState(() => (current?.at ? toInputDate(current.at) : toInputDate(presetTomorrow9(new Date()))));
  const [time, setTime] = useState(() => toInputTime(current?.at && current.timed ? current.at : presetTomorrow9(new Date())));
  const dated = state.kind !== "wait" || date.trim() !== "";

  useEffect(() => {
    const outside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    };
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("mousedown", outside);
    window.addEventListener("keydown", key);
    window.addEventListener("resize", onClose);
    return () => {
      window.removeEventListener("mousedown", outside);
      window.removeEventListener("keydown", key);
      window.removeEventListener("resize", onClose);
    };
  }, [onClose]);

  const apply = () => {
    if (!dated) {
      // «Ждать ответа» без даты — общее слово pm.wait.
      onApply(null);
      return;
    }
    const at = fromInputDateTime(date, state.kind === "wait" ? null : time);
    // Срок/исчезновение без даты или времени не ставим (поля не заполнены).
    if (state.kind !== "wait" && !at) return;
    onApply(at);
  };

  return (
    <div
      className="rem-pick"
      role="dialog"
      aria-label={TITLES[state.kind]}
      style={{ left: Math.min(state.x, window.innerWidth - 300), top: Math.min(state.y, window.innerHeight - 260) }}
      ref={ref}
    >
      <span className="cap">{TITLES[state.kind]}</span>
      {current && (
        <span className="cur">
          Стоит: {reminderDueText(current, new Date()) ?? "да (без даты)"} — новое заменит прежнее
        </span>
      )}
      {state.kind === "due" && (
        <span className="presets">
          <button
            type="button"
            onClick={() => {
              const at = presetTomorrow9(new Date());
              setDate(toInputDate(at));
              setTime(toInputTime(at));
            }}
          >
            Завтра 9:00
          </button>
          <button
            type="button"
            onClick={() => {
              const at = presetInWeek(new Date());
              setDate(toInputDate(at));
              setTime(toInputTime(at));
            }}
          >
            Через неделю
          </button>
        </span>
      )}
      <span className="row">
        <label>
          Дата
          <input type="date" value={date} onChange={(e) => setDate(e.target.value)} autoFocus={state.kind !== "due"} />
        </label>
        {state.kind !== "wait" && (
          <label>
            Время
            <input type="time" value={time} onChange={(e) => setTime(e.target.value)} />
          </label>
        )}
      </span>
      {state.kind === "wait" && <span className="cur">Дата не обязательна: без неё — просто «Ждём ответа».</span>}
      <span className="acts">
        <button type="button" className="lk" disabled={!current} onClick={onClear}>
          Снять
        </button>
        <span className="sp" />
        <button type="button" className="lk" onClick={onClose}>
          Отмена
        </button>
        <button type="button" className="ok" disabled={state.kind !== "wait" && !date} onClick={apply}>
          Поставить
        </button>
      </span>
    </div>
  );
}
