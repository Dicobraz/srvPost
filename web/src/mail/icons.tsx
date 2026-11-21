/*
  Значки — Fluent-подобные контурные SVG из макетов docs/design/webmail (символы 01/03):
  функциональные глифы синие (--m-i-blue), календарный — розовый icon.pink по DESIGN.md,
  красный — только значок безопасности. Цвет — currentColor (размер задаёт CSS).
*/
import type { JSX } from "react";

const PATHS: Record<string, JSX.Element> = {
  mail: (
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="M3.5 7.5l8.5 6 8.5-6" />
    </>
  ),
  inbox: (
    <>
      <path d="M4 13.5V18a2 2 0 002 2h12a2 2 0 002-2v-4.5" />
      <path d="M4 13.5h4.5l1.5 2.5h4l1.5-2.5H20" />
      <path d="M12 3.5v7M9.5 8L12 10.5 14.5 8" />
    </>
  ),
  flag: (
    <>
      <path d="M6 3.5v17" />
      <path d="M6 4.5c4-2 8 2 12 0v8c-4 2-8-2-12 0" />
    </>
  ),
  draft: (
    <>
      <path d="M12 3.5H6a2 2 0 00-2 2v13a2 2 0 002 2h12a2 2 0 002-2v-6" />
      <path d="M18.5 3.5l2 2L12 14l-3 .8.8-3 8.7-8.3z" />
    </>
  ),
  sent: (
    <>
      <path d="M20.5 3.5L3.5 10.5l6 2.5 2.5 6 8.5-15.5z" />
      <path d="M9.5 13l11-9.5" />
    </>
  ),
  ban: (
    <>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M6.5 6.5l11 11" />
    </>
  ),
  arch: (
    <>
      <rect x="3.5" y="4.5" width="17" height="5" rx="1" />
      <path d="M5.5 9.5V19a1 1 0 001 1h11a1 1 0 001-1V9.5M9.5 13h5" />
    </>
  ),
  thread: (
    <>
      <rect x="4.5" y="4.5" width="12" height="12" rx="1.5" />
      <path d="M8.5 7.5h9A1.5 1.5 0 0119 9v8" />
      <path d="M8.5 11.5h9" />
    </>
  ),
  clip: <path d="M17.5 11.5l-6 6a4 4 0 01-5.7-5.7l7.3-7.3a2.7 2.7 0 013.8 3.8l-7.3 7.3a1.4 1.4 0 01-2-2l6.4-6.4" />,
  clock: (
    <>
      <circle cx="12" cy="12" r="8" />
      <path d="M12 7.5V12l3 2" />
    </>
  ),
  shield: (
    <>
      <path d="M12 3.5l7 2.5v5c0 4.5-3 8-7 9.5-4-1.5-7-5-7-9.5V6l7-2.5z" />
      <path d="M12 8v4" />
      <circle cx="12" cy="15.3" r="0.4" fill="currentColor" />
    </>
  ),
  person: (
    <>
      <circle cx="12" cy="8.5" r="3.4" />
      <path d="M5.5 19.5c.7-3.5 3.3-5.4 6.5-5.4s5.8 1.9 6.5 5.4" />
    </>
  ),
  search: (
    <>
      <circle cx="11" cy="11" r="6" />
      <path d="M15.5 15.5L20 20" />
    </>
  ),
  pen: (
    <>
      <path d="M14.5 5.5l4 4" />
      <path d="M4 20l1-4L16.5 4.5a2.05 2.05 0 013 3L8 19l-4 1z" />
    </>
  ),
  reply: (
    <>
      <path d="M9 7l-4.5 4.5L9 16" />
      <path d="M4.5 11.5H14a5.5 5.5 0 015.5 5.5v1" />
    </>
  ),
  fwd: (
    <>
      <path d="M15 7l4.5 4.5L15 16" />
      <path d="M19.5 11.5H10a5.5 5.5 0 00-5.5 5.5v1" />
    </>
  ),
  trash: (
    <>
      <path d="M5 7h14M9.5 7V5h5v2M7 7l1 13h8l1-13" />
      <path d="M10.5 10.5v6M13.5 10.5v6" />
    </>
  ),
  imgoff: (
    <>
      <rect x="4" y="5.5" width="16" height="13" rx="2" />
      <path d="M4.5 15.5l4-3.5 4 3.5 3-2.5 4 3" />
      <circle cx="9.3" cy="9.5" r="1.3" />
      <path d="M4.5 4.5l15 15" />
    </>
  ),
  cal: (
    <>
      <rect x="3.5" y="5" width="17" height="15.5" rx="2" />
      <path d="M3.5 9.5h17M8 3v4M16 3v4" />
    </>
  ),
  sync: <path d="M19 12a7 7 0 01-12 4.9M5 12a7 7 0 0112-4.9M17 4.5v3h-3M7 19.5v-3h3" />,
  doc: (
    <>
      <path d="M6.5 3.5h7L18 8v12.5H6.5z" />
      <path d="M13.5 3.5V8H18" />
      <path d="M9 12h6M9 15h6" />
    </>
  ),
  folder: <path d="M3.5 6.5a2 2 0 012-2h4l2 2.5h7a2 2 0 012 2v9a2 2 0 01-2 2h-13a2 2 0 01-2-2v-11.5z" />,
  // WEB-04 (композер) — значки макета 02: чипы, форматирование, таблицы, undo-send.
  x: <path d="M6.5 6.5l11 11M17.5 6.5l-11 11" />,
  table: (
    <>
      <rect x="4" y="5" width="16" height="14" rx="1.5" />
      <path d="M4 10h16M10.5 10v9" />
    </>
  ),
  list: (
    <>
      <path d="M9 6.5h11M9 12h11M9 17.5h11" />
      <circle cx="5.2" cy="6.5" r="1.1" fill="currentColor" stroke="none" />
      <circle cx="5.2" cy="12" r="1.1" fill="currentColor" stroke="none" />
      <circle cx="5.2" cy="17.5" r="1.1" fill="currentColor" stroke="none" />
    </>
  ),
  quote: (
    <>
      <path d="M6.5 9.5h4v4h-2.5l-1 3.5" />
      <path d="M14.5 9.5h4v4h-2.5l-1 3.5" />
    </>
  ),
  link: (
    <>
      <path d="M9.5 14.5l5-5" />
      <path d="M8.5 11.5L6 14a3.5 3.5 0 005 5l2.5-2.5" />
      <path d="M15.5 12.5L18 10a3.5 3.5 0 00-5-5l-2.5 2.5" />
    </>
  ),
  undo: (
    <>
      <path d="M8 6L4 10l4 4" />
      <path d="M4 10h9.5a6 6 0 016 6v1" />
    </>
  ),
  check: <path d="M5 12.5l4.5 4.5L19 7.5" />,
  // WEB-19: колокольчик напоминаний (полоса «Напоминания», пикер).
  bell: (
    <>
      <path d="M6.5 10.5a5.5 5.5 0 0111 0c0 4 1.5 5.5 1.5 5.5h-14s1.5-1.5 1.5-5.5z" />
      <path d="M10 19.5a2.2 2.2 0 004 0" />
    </>
  ),
};

export type IconName = keyof typeof PATHS | string;

/** Контурный значок макета; `size` — px (20 — строка, 14/16 — в строке письма). */
export function Icon({ name, size = 20, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {PATHS[name] ?? PATHS.mail}
    </svg>
  );
}
