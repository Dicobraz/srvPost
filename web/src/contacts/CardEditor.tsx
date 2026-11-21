/*
  Форма карточки контакта (WEB-07): панель inline (не модалка, как в DESIGN.md) — имя, адреса
  и телефоны списками строк (добавить/убрать), организация, фото-URL, заметки. Создание — в
  выбранную личную книгу (GAL read-only в выбор не попадает), правка — патч полей целиком.
*/
import { useState } from "react";

import { Icon } from "../mail/icons";
import { type ContactForm } from "./model";

export interface CardEditorProps {
  /** Черновик формы: для правки — текущие поля, для создания — пустые. */
  initial: ContactForm;
  title: string;
  saving: boolean;
  onSave(form: ContactForm): void;
  onClose(): void;
}

/** Панель формы поверх страницы: поля списка строк — ввод адреса/телефона, «добавить». */
export function CardEditor({ initial, title, saving, onSave, onClose }: CardEditorProps) {
  const [form, setForm] = useState<ContactForm>(initial);
  const [error, setError] = useState<string | null>(null);
  const set = (patch: Partial<ContactForm>) => setForm((f) => ({ ...f, ...patch }));

  const submit = () => {
    if (!form.name.trim()) {
      setError("У контакта должно быть имя.");
      return;
    }
    const email = form.emails.find((e) => e.trim() !== "");
    if (email !== undefined && !email.includes("@")) {
      setError(`«${email.trim()}» — не похоже на адрес: имя@домен`);
      return;
    }
    setError(null);
    const clean: ContactForm = {
      ...form,
      emails: form.emails.map((e) => e.trim()).filter(Boolean),
      phones: form.phones.map((p) => p.trim()).filter(Boolean),
    };
    onSave(clean);
  };

  return (
    <aside className="cal-panel" aria-label={title}>
      <div className="cal-panel-head">
        <b>{title}</b>
        <button type="button" className="cal-x" aria-label="Закрыть форму" onClick={onClose}>
          <Icon name="x" size={16} />
        </button>
      </div>
      <div className="cal-panel-body">
        <label className="cal-field">
          <span>Имя</span>
          <input value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="Имя Фамилия" autoFocus />
        </label>
        <div className="cal-field">
          <span>Адреса</span>
          {form.emails.map((email, i) => (
            <span className="ct-row" key={i}>
              <input
                value={email}
                onChange={(e) => set({ emails: form.emails.map((x, j) => (j === i ? e.target.value : x)) })}
                placeholder="имя@домен"
                aria-label={`Адрес ${i + 1}`}
              />
              <button
                type="button"
                className="cal-x"
                aria-label={`Убрать адрес ${i + 1}`}
                onClick={() => set({ emails: form.emails.filter((_, j) => j !== i) })}
              >
                <Icon name="x" size={14} />
              </button>
            </span>
          ))}
          <button type="button" className="button" onClick={() => set({ emails: [...form.emails, ""] })}>
            Добавить адрес
          </button>
        </div>
        <div className="cal-field">
          <span>Телефоны</span>
          {form.phones.map((phone, i) => (
            <span className="ct-row" key={i}>
              <input
                value={phone}
                onChange={(e) => set({ phones: form.phones.map((x, j) => (j === i ? e.target.value : x)) })}
                placeholder="+7 …"
                aria-label={`Телефон ${i + 1}`}
              />
              <button
                type="button"
                className="cal-x"
                aria-label={`Убрать телефон ${i + 1}`}
                onClick={() => set({ phones: form.phones.filter((_, j) => j !== i) })}
              >
                <Icon name="x" size={14} />
              </button>
            </span>
          ))}
          <button type="button" className="button" onClick={() => set({ phones: [...form.phones, ""] })}>
            Добавить телефон
          </button>
        </div>
        <label className="cal-field">
          <span>Организация</span>
          <input value={form.organization} onChange={(e) => set({ organization: e.target.value })} placeholder="Организация" />
        </label>
        <label className="cal-field">
          <span>Фото (ссылка)</span>
          <input value={form.photoUrl} onChange={(e) => set({ photoUrl: e.target.value })} placeholder="https://…" />
        </label>
        <label className="cal-field">
          <span>Заметки</span>
          <textarea value={form.notes} onChange={(e) => set({ notes: e.target.value })} rows={3} placeholder="Заметки о контакте" />
        </label>
        {error && (
          <div className="cal-warn" role="alert">
            ▲ {error}
          </div>
        )}
      </div>
      <div className="cal-panel-foot">
        <span className="cal-note">Поля записываются целиком; адрес без «@» не сохранится.</span>
        <span className="sp" />
        <button type="button" className="button" onClick={onClose}>
          Отмена
        </button>
        <button type="button" className="button button-primary" disabled={saving} onClick={submit}>
          {saving ? "Сохраняем…" : "Сохранить"}
        </button>
      </div>
    </aside>
  );
}

/** Пустая форма создания: один пустой адрес. */
export function emptyForm(): ContactForm {
  return { name: "", emails: [""], phones: [], organization: "", photoUrl: "", notes: "" };
}

/** Форма правки — поля карточки (обратная запись тем же fillForm). */
export { formOf } from "./model";
