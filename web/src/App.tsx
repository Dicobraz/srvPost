import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router";

import { CalendarPage } from "./pages/calendar";
import { ContactsPage } from "./pages/contacts";
import { MailPage } from "./pages/mail";
import { LoginPage } from "./pages/login";
import { CallbackPage } from "./pages/callback";
import { AuthProvider, useAuth } from "./auth/session";
import { useTheme, type ThemeChoice } from "./theme";

// Оболочка веб-клиента (WEB-01/02): вход — карточка WEB-02 (OIDC PKCE из SPA или пароль приложения;
// решение 2026-11-20 — без новой серверной точки), разделы Почта / Календарь / Контакты и шов
// «Каналы» — место под будущий веб-чат (решение 2026-11-17). На узких экранах навигация уходит вниз
// (паттерн mobile Outlook, ADR 2026-11-20). Данные — через JMAP того же узла (same-origin); ящики —
// карточка WEB-03, разделы пока заглушки.
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

function Account() {
  const { session, userName, logout } = useAuth();
  if (!session) return null;
  return (
    <span className="account">
      {userName && <span className="account-name">{userName}</span>}
      <button
        type="button"
        className="theme-button"
        onClick={() => {
          void logout();
        }}
        title="Выйти (вход по OIDC — и на других устройствах, если поставщик даёт end session)"
      >
        Выйти
      </button>
    </span>
  );
}

function Shell() {
  return (
    <div className="shell">
      <header className="header">
        <span className="product">The Post</span>
        <span className="header-actions">
          <Account />
          <ThemeButton />
        </span>
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

/** Заставка, пока конфигурация входа и сессия не готовы (мигание оболочки недопустимо). */
function Splash() {
  return (
    <section className="login" aria-busy="true">
      <h1>The Post</h1>
      <p>Загружаем…</p>
    </section>
  );
}

/** Оболочка — только в состоянии входа. Нет сессии: OIDC — тихий перевход к поставщику (маршрут
 * сохраняется в state), пароль приложения — форма входа; route не теряется. */
function Protected({ children }: { children: ReactNode }) {
  const { ready, session, config, loginOidc } = useAuth();
  const location = useLocation();
  const [kickFailed, setKickFailed] = useState(false);
  const route = location.pathname + location.search;

  useEffect(() => {
    if (!ready || session || !config?.oidc) return;
    // Неудача перевхода (поставщик недоступен) — вернёмся к форме входа ниже.
    loginOidc(route).catch(() => setKickFailed(true));
  }, [ready, session, config, loginOidc, route]);

  if (!ready) return <Splash />;
  if (!session) {
    // Перевход начат — ждём поставщика; нет OIDC или он отказал — форма входа с возвратом.
    if (config?.oidc && !kickFailed) return <Splash />;
    return <Navigate to={`/login?next=${encodeURIComponent(route)}`} replace />;
  }
  return children;
}

export function App() {
  useTheme();
  return (
    <AuthProvider>
      <Routes>
        <Route path="/callback" element={<CallbackPage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="*"
          element={
            <Protected>
              <Shell />
            </Protected>
          }
        />
      </Routes>
    </AuthProvider>
  );
}
