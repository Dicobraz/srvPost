/*
  Поле получателей (WEB-04) — по макету 02: подпись слева (Кому/Копия/Скрытая), чипы, ввод
  после чипов, автодополнение списком (аватар с инициалами, имя, адрес, метка источника —
  «Контакты»/«История»), пикер «Кому…» (адресная книга + история). Модальных окон нет:
  список — выпадающая панель под строкой, закрытие — Esc, клик мимо, выбор.
*/
import { useEffect, useRef, useState, type KeyboardEvent } from "react";

import { chipLabel, initialsOf, isDuplicate, isValidEmail, parseRecipients, suggest, type Recipient, type Suggestion } from "./recipients";
import { Icon } from "../mail/icons";

export interface RecipientsFieldProps {
  label: string;
  recipients: Recipient[];
  /** Кандидаты подсказок (контакты + история) — фильтрует suggest(). */
  candidates: Suggestion[];
  onChange(recipients: Recipient[]): void;
  /** Показывать пикер «Кому…» (первое поле — макет). */
  withPicker?: boolean;
  placeholder?: string;
}

/** Поле с чипами получателей и автодополнением. */
export function RecipientsField({ label, recipients, candidates, onChange, withPicker, placeholder }: RecipientsFieldProps) {
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [highlight, setHighlight] = useState(0);
  const [pickerOpen, setPickerOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);

  const items = pickerOpen ? candidates.slice(0, 20) : suggest(candidates, draft, recipients);

  // Клик мимо закрывает и подсказку, и пикер (модальных окон нет — выпадающие панели).
  useEffect(() => {
    const outside = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
        setPickerOpen(false);
      }
    };
    window.addEventListener("mousedown", outside);
    return () => window.removeEventListener("mousedown", outside);
  }, []);

  const add = (raw: string): boolean => {
    const parsed = parseRecipients(raw);
    if (parsed.length === 0) return false;
    let added = 0;
    let invalid: string | null = null;
    const next = [...recipients];
    for (const r of parsed) {
      if (!isValidEmail(r.email)) {
        invalid = r.email;
        continue;
      }
      if (isDuplicate(next, r.email)) continue;
      next.push(r);
      added += 1;
    }
    if (invalid) setError(`«${invalid}» — не похоже на адрес: имя@домен`);
    else setError(null);
    if (added > 0) onChange(next);
    return added > 0;
  };

  const commitDraft = () => {
    if (draft.trim() === "") return;
    if (add(draft)) setDraft("");
  };

  const pick = (s: Suggestion) => {
    if (!isDuplicate(recipients, s.recipient.email)) onChange([...recipients, s.recipient]);
    setDraft("");
    setOpen(false);
    setPickerOpen(false);
    setError(null);
    inputRef.current?.focus();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (open && items.length > 0) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setHighlight((h) => (h + 1) % items.length);
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setHighlight((h) => (h - 1 + items.length) % items.length);
        return;
      }
    }
    switch (e.key) {
      case "Enter":
        e.preventDefault();
        if (open && items.length > 0 && highlight < items.length && draft.trim() !== "") {
          pick(items[highlight]);
        } else {
          commitDraft();
          setOpen(false);
        }
        break;
      case ",":
      case ";":
        e.preventDefault();
        commitDraft();
        setOpen(false);
        break;
      case "Tab":
        if (draft.trim() !== "") {
          e.preventDefault();
          commitDraft();
        }
        break;
      case "Backspace":
        if (draft === "" && recipients.length > 0) {
          onChange(recipients.slice(0, -1));
        }
        break;
      case "Escape":
        setOpen(false);
        setPickerOpen(false);
        break;
      default:
        break;
    }
  };

  return (
    <div className="frow" ref={rootRef}>
      <span className="lbl">{label}</span>
      <div className="finput chips" onClick={() => inputRef.current?.focus()}>
        {recipients.map((r) => (
          <span className="chip" key={r.email.toLowerCase()}>
            <span className="chip-label">{chipLabel(r)}</span>
            <button
              type="button"
              className="x"
              aria-label={`Убрать ${chipLabel(r)}`}
              onClick={(e) => {
                e.stopPropagation();
                onChange(recipients.filter((x) => x.email.toLowerCase() !== r.email.toLowerCase()));
              }}
            >
              <Icon name="x" size={14} />
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          className="fentry"
          value={draft}
          placeholder={recipients.length === 0 ? (placeholder ?? "имя или адрес") : ""}
          onChange={(e) => {
            setDraft(e.target.value);
            setOpen(true);
            setPickerOpen(false);
            setHighlight(0);
            setError(null);
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={onKeyDown}
          onBlur={commitDraft}
          aria-label={`${label}: адрес получателя`}
        />
        {withPicker && (
          <button
            type="button"
            className="picker"
            aria-label="Выбрать из адресной книги"
            aria-expanded={pickerOpen}
            onClick={(e) => {
              e.stopPropagation();
              setOpen(false);
              setPickerOpen((v) => !v);
            }}
          >
            <Icon name="person" size={16} />
            Кому…
          </button>
        )}
      </div>
      {error && <span className="ferr" role="alert">{error}</span>}
      {pickerOpen && items.length > 0 && (
        <div className="ac" role="listbox" aria-label="Адресная книга и история">
          <div className="grp">Контакты и история</div>
          {items.map((s, i) => (
            <button
              type="button"
              key={s.recipient.email.toLowerCase()}
              role="option"
              aria-selected={i === highlight}
              className={`mi${i === highlight ? " on" : ""}`}
              onClick={() => pick(s)}
              onMouseDown={(e) => e.preventDefault()} // фокус остаётся во вводе — blur не коммитит
              onMouseEnter={() => setHighlight(i)}
            >
              <span className="ava">{initialsOf(s.recipient)}</span>
              <span className="nm">{chipLabel(s.recipient)}</span>
              <span className="adr">{s.recipient.email}</span>
              <span className="src">{s.source}</span>
            </button>
          ))}
        </div>
      )}
      {open && !pickerOpen && draft.trim() !== "" && items.length > 0 && (
        <div className="ac" role="listbox" aria-label="Подсказки адресов">
          <div className="grp">Справочник и контакты</div>
          {items.map((s, i) => (
            <button
              type="button"
              key={s.recipient.email.toLowerCase()}
              role="option"
              aria-selected={i === highlight}
              className={`mi${i === highlight ? " on" : ""}`}
              onClick={() => pick(s)}
              onMouseDown={(e) => e.preventDefault()} // фокус остаётся во вводе — blur не коммитит
              onMouseEnter={() => setHighlight(i)}
            >
              <span className="ava">{initialsOf(s.recipient)}</span>
              <span className="nm">{chipLabel(s.recipient)}</span>
              <span className="adr">{s.recipient.email}</span>
              <span className="src">{s.source}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
