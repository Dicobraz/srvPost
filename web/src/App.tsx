import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Navigate, Route, Routes, useLocation } from "react-router";
import { QueryClientProvider } from "@tanstack/react-query";

import { CalendarPage } from "./pages/calendar";
import { ContactsPage } from "./pages/contacts";
import { MailPage } from "./pages/mail";
import { LoginPage } from "./pages/login";
import { CallbackPage } from "./pages/callback";
import { ComposerPage } from "./compose/Composer";
import { AuthProvider, useAuth } from "./auth/session";
import { JmapProvider } from "./mail/context";
import { ToastProvider } from "./mail/toast";
import { queryClient } from "./mail/client";
import { useTheme, type ThemeChoice } from "./theme";

// Оболочка веб-клиента (WEB-01/02/03/04): разделы Почта / Календарь / Контакты, композер —
// вкладкой /compose (макет 02). Шов «Каналы» скрыт до запуска чата (решение 20.11): видимой
// навигации нет — маршрут /channels зарезервирован (страница-заглушка не рендерится
// пользователю), чтобы вписать веб-чат без переделки маршрутов. Данные почты — JMAP того же
// узла (WEB-03): JmapProvider — сессия и push, ToastProvider — тосты с Undo (undo-send ~15 с,
// WEB-04), QueryClientProvider — кэш TanStack Query.
const SECTIONS = [
  { to: "/", label: "Почта", end: true },
  { to: "/calendar", label: "Календарь", end: false },
  { to: "/contacts", label: "Контакты", end: false },
];

function Nav() {
  return (
    <nav className="nav" aria-label="Разделы">
      {SECTIONS.map((s) => (
        <NavLink key={s.to} to={s.to} end={s.end} className="nav-item">
          {s.label}
        </NavLink>
      ))}
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
          {/* Композер — вкладкой приложения (WEB-04, макет 02), не модалка; письмо — её источник. */}
          <Route path="/compose" element={<ComposerPage />} />
          <Route path="/calendar" element={<CalendarPage />} />
          <Route path="/contacts" element={<ContactsPage />} />
          {/* Шов «Каналы»: маршрут зарезервирован (решение 2026-11-17), в навигации скрыт. */}
          <Route path="/channels" element={<Navigate to="/" replace />} />
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
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Routes>
          <Route path="/callback" element={<CallbackPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route
            path="*"
            element={
              <Protected>
                {/* Почта живёт на сессии JMAP: сессия и push — JmapProvider (WEB-03). */}
                <JmapProvider>
                  <ToastProvider>
                    <Shell />
                  </ToastProvider>
                </JmapProvider>
              </Protected>
            }
          />
        </Routes>
      </AuthProvider>
    </QueryClientProvider>
  );
}
