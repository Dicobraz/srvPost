// Статус со знаком (UI-19, решение 119): у нормы, внимания и ошибки свой знак (● ▲ ×) — смысл состояния
// не держится на одном цвете (WCAG 1.4.1 Use of Color). Цвет — роль текущей темы из design/tokens.toml
// (или действующего брендинга заказчика, UI-22), а не пресет antd: контраст ролей проверяет сервер (DES-01).
import { Tag } from "antd";
import type { ReactNode } from "react";

import { useBranding } from "../providers/branding";
import { modeColors, signs, useDark } from "../theme";

/** Роль статуса: ok — норма ●, warn — внимание ▲, err — ошибка ×, info — сведения (синий, без знака). */
export type StatusRole = "ok" | "warn" | "err" | "info";

/** Цвет роли статуса в текущей теме (для точек таймлайна и прочего цветового акцента). */
export function useStatusColor(role: StatusRole): string {
  const c = modeColors(useDark(), useBranding());
  return role === "info" ? c.frameA : c[role];
}

/** Метка статуса: знак роли рядом с текстом; фон прозрачный, цвет роли — текст и рамка. */
export function StatusTag({ role, children }: { role: StatusRole; children: ReactNode }) {
  const color = useStatusColor(role);
  return (
    <Tag style={{ background: "transparent", borderColor: color, color }}>
      {/* Знак дублирует цвет: статус читается и без различения цветов; скринридеру достаточно текста. */}
      {role !== "info" && <span aria-hidden="true">{signs[role]}</span>} {children}
    </Tag>
  );
}
