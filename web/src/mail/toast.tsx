/*
  Тосты с Undo (WEB-03, земля для волны 4): inline-карточки в стопке внизу справа (макет 02 —
  «Отправлено · Отменить»), модальных окон нет. Undo — действие обратного патча (Email/set),
  сроки показа: обычный тост 6 с, с Undo — 10 с (успеть подумать).
*/
import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";

/** Тост: текст, действие Undo и срок. */
interface Toast {
  id: number;
  label: string;
  undo: (() => void) | null;
}

interface ToastContextValue {
  /** Показать тост; `undo` — «Отменить» (откат оптимистичной мутации). */
  show(label: string, undo?: () => void): void;
}

const ToastContext = createContext<ToastContextValue | null>(null);

/** Доступ к тостам; вне ToastProvider — ошибка программирования. */
export function useToast(): ToastContextValue {
  const value = useContext(ToastContext);
  if (!value) throw new Error("useToast вне ToastProvider");
  return value;
}

const TOAST_MS = 6_000;
const TOAST_UNDO_MS = 10_000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((t) => t.id !== id));
  }, []);

  const show = useCallback(
    (label: string, undo?: () => void) => {
      const id = nextId.current++;
      setToasts((current) => [...current.slice(-3), { id, label, undo: undo ?? null }]);
      window.setTimeout(() => dismiss(id), undo ? TOAST_UNDO_MS : TOAST_MS);
    },
    [dismiss],
  );

  return (
    <ToastContext.Provider value={{ show }}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className="toast">
            <span className="toast-label">{t.label}</span>
            {t.undo && (
              <button
                type="button"
                className="toast-undo"
                onClick={() => {
                  t.undo?.();
                  dismiss(t.id);
                }}
              >
                Отменить
              </button>
            )}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
