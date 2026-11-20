/*
  Контекстное меню (WEB-03): пункт 4 карточки — перенос drag-drop + контекстное меню + клавиши;
  модальных окон нет — inline-меню и inline-подтверждение (пункт «Удалить папку с письмами?»).
  Закрытие — клик мимо, Esc, выбор пункта.
*/
import { useEffect, useRef } from "react";

export interface MenuItem {
  label: string;
  onSelect?: () => void;
  /** Недоступен (например, ответить — до композера в меню списка остаётся тостом). */
  disabled?: boolean;
  /** Пункт-подтверждение (красная подложка — только безопасность/удаление с потерей). */
  danger?: boolean;
  confirm?: boolean;
  separator?: boolean;
}

export interface MenuState {
  x: number;
  y: number;
  items: MenuItem[];
}

/** Меню по координатам (контекстное); рендерится в корне mail-страницы. */
export function ContextMenu({ menu, onClose }: { menu: MenuState; onClose: () => void }) {
  const ref = useRef<HTMLDivElement | null>(null);

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

  const style = {
    left: Math.min(menu.x, window.innerWidth - 240),
    top: Math.min(menu.y, window.innerHeight - 40 - menu.items.length * 30),
  };

  return (
    <div className="menu" role="menu" style={style} ref={ref}>
      {menu.items.map((item, i) =>
        item.separator ? (
          <div key={i} role="separator" style={{ borderTop: "1px solid var(--m-div)", margin: "4px 0" }} />
        ) : (
          <button
            key={i}
            type="button"
            role="menuitem"
            className={[item.danger ? "danger" : "", item.confirm ? "confirm" : ""].join(" ").trim() || undefined}
            disabled={item.disabled}
            onClick={() => {
              item.onSelect?.();
              onClose();
            }}
          >
            {item.label}
          </button>
        ),
      )}
    </div>
  );
}
