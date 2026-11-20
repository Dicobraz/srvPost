// Callback OIDC (WEB-02): поставщик вернул код — обмениваем на токены, подхватываем маршрут
// возврата из state и возвращаемся туда, откуда уходили на вход. Ошибка — человекочитаемая inline
// (без модалок, DESIGN.md Postman), без блокировки: можно начать вход заново.
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router";

import { humanError } from "../config";
import { useAuth } from "../auth/session";

export function CallbackPage() {
  const { finishOidc } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (started.current) return; // StrictMode дважды вызывает эффекты: обмен кода — один раз
    started.current = true;
    finishOidc()
      .then((route) => navigate(route, { replace: true }))
      .catch((e: unknown) => setError(humanError(e)));
  }, [finishOidc, navigate]);

  if (error) {
    return (
      <section className="login">
        <h1>Вход не завершён</h1>
        <p className="alert" role="alert">
          {error}
        </p>
        <Link className="button" to="/login">
          Войти заново
        </Link>
      </section>
    );
  }
  return (
    <section className="login">
      <h1>Завершаем вход…</h1>
    </section>
  );
}
