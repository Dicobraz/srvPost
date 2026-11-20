import { NavLink, Navigate, Route, Routes } from "react-router";

import { CalendarPage } from "./pages/calendar";
import { ContactsPage } from "./pages/contacts";
import { MailPage } from "./pages/mail";
import { useTheme, type ThemeChoice } from "./theme";

// Оболочка веб-клиента (WEB-01): разделы Почта / Календарь / Контакты и шов «Каналы» — место под будущий
// веб-чат (решение 2026-11-17: свой брендированный чат после запуска, сейчас не реализуется). На узких
// экранах навигация уходит вниз (паттерн mobile Outlook, ADR 2026-11-20). Данные — через JMAP того же
// узла (same-origin); вход и ящики — карточки WEB-02/03, разделы пока заглушки.
const SECTIONS = [
  { to: "/", label: "Почта", end: true },
  { to: "/calendar", label: "Календарь", end: false },
  { to: "/contacts", label: "Контакты", end: false },
];

/** Шов «Каналы»: отключённый пункт навигации, чтобы вписать чат потом без переделки оболочки. */
function ChannelsSeam() {
  return (
    <span
      className="nav-item nav-seam"
      aria-disabled="true"
      title="Появится позже: веб-чат (решение 2026-11-17)"
    >
      Каналы
    </span>
  );
}

function Nav() {
  return (
    <nav className="nav" aria-label="Разделы">
      {SECTIONS.map((s) => (
        <NavLink key={s.to} to={s.to} end={s.end} className="nav-item">
          {s.label}
        </NavLink>
      ))}
      <ChannelsSeam />
    </nav>
  );
}

const THEME_LABELS: Record<ThemeChoice, string> = {
  system: "Системная",
  light: "Светлая",
  dark: "Тёмная",
};
const THEME_ORDER: ThemeChoice[] = ["system", "light", "dark"];

function ThemeButton() {
  const [theme, setTheme] = useTheme();
  const next = () => setTheme(THEME_ORDER[(THEME_ORDER.indexOf(theme) + 1) % THEME_ORDER.length]);
  return (
    <button type="button" className="theme-button" onClick={next} title="Сменить тему">
      {THEME_LABELS[theme]}
    </button>
  );
}

export function App() {
  useTheme();
  return (
    <div className="shell">
      <header className="header">
        <span className="product">The Post</span>
        <ThemeButton />
      </header>
      <Nav />
      <main className="content">
        <Routes>
          <Route path="/" element={<MailPage />} />
          <Route path="/calendar" element={<CalendarPage />} />
          <Route path="/contacts" element={<ContactsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  );
}
