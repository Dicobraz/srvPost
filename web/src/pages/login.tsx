// Экран входа (WEB-02, по DESIGN.md Postman — без модалок, ошибки inline): OIDC с PKCE, если узел
// сообщил поставщика, и/или форма «логин + пароль приложения». Вход с OIDC без формы — тихий
// перевод к поставщику делает Protected (перевход без потери маршрута); здесь — явный вход.
import { useState, type FormEvent } from "react";
import { useLocation, useNavigate } from "react-router";

import { humanError } from "../config";
import { useAuth } from "../auth/session";

/** Маршрут возврата после входа: state следующего location (перевход без потери черновика — WEB-04).
 * Только свой путь: `//узел` — чужой сайт, `next` со стороны не поверим. */
export function nextRoute(search: string): string {
  const next = new URLSearchParams(search).get("next");
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/";
}

export function LoginPage() {
  const { config, configError, loginBasic, loginOidc } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [login, setLogin] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    loginBasic(login, secret)
      .then(() => navigate(nextRoute(location.search), { replace: true }))
      .catch((e: unknown) => {
        setError(humanError(e));
        setBusy(false);
      });
  };

  const oidc = config?.oidc;
  const basic = config?.basic ?? false;

  return (
    <section className="login">
      <h1>The Post — вход</h1>
      {configError && (
        <p className="alert" role="alert">
          {configError}{" "}
          <a
            href=""
            onClick={(e) => {
              e.preventDefault();
              window.location.reload();
            }}
          >
            Повторить
          </a>
        </p>
      )}
      {!configError && oidc && (
        <>
          <button
            type="button"
            className="button button-primary"
            disabled={busy}
            onClick={() => {
              setBusy(true);
              setError(null);
              loginOidc(nextRoute(location.search)).catch((e: unknown) => {
                setError(humanError(e));
                setBusy(false);
              });
            }}
          >
            Войти через поставщика идентификации
          </button>
          {basic && <p className="login-or">или</p>}
        </>
      )}
      {!configError && basic && (
        <form onSubmit={submit}>
          <label>
            Имя входа
            <input
              name="login"
              autoComplete="username"
              value={login}
              onChange={(e) => setLogin(e.target.value)}
              required
            />
          </label>
          <label>
            Пароль приложения
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              value={secret}
              onChange={(e) => setSecret(e.target.value)}
              required
            />
          </label>
          <p className="hint">Пароль приложения — из настроек почты; обычный пароль не подойдёт.</p>
          {error && (
            <p className="alert" role="alert">
              {error}
            </p>
          )}
          <button type="submit" className="button button-primary" disabled={busy}>
            Войти
          </button>
        </form>
      )}
    </section>
  );
}
