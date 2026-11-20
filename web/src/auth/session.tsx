// Жизнь сессии (WEB-02): конфигурация входа (`config.json`), сессия вкладки (`auth/store`),
// вход OIDC (`auth/oidc`) и тихий renew между вкладками — обновляющий (старейшая вкладка с
// OIDC-сессией) продлевает токен, остальные подхватывают по каналу; 401 от JMAP — тихий renew.
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import type { UserManager } from "oidc-client-ts";

import { humanError, loadMailConfig, type MailConfig } from "../config";
import { authHeader, verifyBasic } from "../api/jmap";
import { HEARTBEAT_MS, RENEW_BEFORE_MS, AuthStore, type Session } from "./store";
import { nameFromIdToken, signin, signinCallback, signinSilent, signout, userManager } from "./oidc";

interface AuthContextValue {
  /** Конфигурация и восстановление сессии завершены — можно решать, что показывать. */
  ready: boolean;
  /** Сессия вкладки или нет (вход по паролю приложения живёт в памяти вкладки). */
  session: Session | null;
  /** Конфигурация входа; null — получить не удалось (см. configError). */
  config: MailConfig | null;
  /** Человекочитаемая ошибка конфигурации входа. */
  configError: string | null;
  /** Имя пользователя для шапки (email из id_token или логин входа). */
  userName: string | null;
  /** Вход по паролю приложения: проверка на `/jmap/session`, ошибка — человекочитаемая. */
  loginBasic(login: string, secret: string): Promise<void>;
  /** Вход OIDC: редирект к поставщику, `route` — куда вернуться после callback. */
  loginOidc(route: string): Promise<void>;
  /** Завершение входа OIDC (callback-страница): токены + маршрут возврата. */
  finishOidc(): Promise<string>;
  /** Выход: вкладкам — по каналу; у OIDC ещё и end session поставщика, если он известен. */
  logout(): Promise<void>;
  /** Истёкший токен (401 от JMAP): тихий renew; неудача — сброс сессии (перевход без потери route). */
  renew(): Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/** Доступ к состоянию входа; вне AuthProvider — ошибка программирования. */
export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth вне AuthProvider");
  return value;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<MailConfig | null>(null);
  const [configError, setConfigError] = useState<string | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);
  const storeRef = useRef<AuthStore | null>(null);
  const managerRef = useRef<UserManager | null>(null);
  const renewingRef = useRef(false);

  // Конфигурация для эффектов и logout: после загрузки не меняется, UserManager создаётся один раз.
  const configRef = useRef<MailConfig | null>(null);

  /** Тихий renew (refresh-токеном); неудача — сброс сессии у всех вкладок, дальше перевход. */
  const renew = async (s: AuthStore): Promise<void> => {
    const current = s.get();
    const oidc = configRef.current?.oidc;
    if (current?.kind !== "oidc" || !oidc) return;
    try {
      const m = (managerRef.current ??= userManager(oidc));
      s.loginOidc(await signinSilent(m));
    } catch {
      s.clear(true); // соседям тоже; Protected отправит на перевход, маршрут сохранится
    }
  };

  useEffect(() => {
    const s = new AuthStore();
    storeRef.current = s;
    // Сессия попадает в состояние через подписку: store сам уведомляет (и restore, и канал).
    const unsubscribe = s.subscribe(() => setSession(s.get()));
    s.restore();
    loadMailConfig()
      .then((loaded) => {
        configRef.current = loaded;
        setConfig(loaded);
        setReady(true);
      })
      .catch((e: unknown) => {
        setConfigError(humanError(e));
        setReady(true);
      });
    // Новая вкладка просит соседей поделиться сессией OIDC (пароль приложения — не общее имущество).
    s.requestSession();

    // Жизнь вкладок и тихий renew: обновляющий (старейшая вкладка с OIDC-сессией) продлевает
    // токен за минуту до конца его жизни, остальные подхватывают по каналу (auth/store).
    const timer = window.setInterval(() => {
      const current = s.get();
      const due = current?.kind === "oidc" && Date.now() >= current.expiresAt - RENEW_BEFORE_MS;
      if (s.tick(Date.now()) && due && !renewingRef.current) {
        renewingRef.current = true;
        renew(s)
          .catch((e: unknown) => console.error("renew:", e))
          .finally(() => {
            renewingRef.current = false;
          });
      }
    }, HEARTBEAT_MS);
    return () => {
      window.clearInterval(timer);
      unsubscribe();
      s.close();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- эффект один на жизнь провайдера; renew работает с ref-ами
  }, []);

  /** UserManager по конфигурации; без OIDC — null (вход только по паролю приложения). */
  const manager = (): UserManager | null => {
    const oidc = configRef.current?.oidc;
    if (!oidc) return null;
    return (managerRef.current ??= userManager(oidc));
  };

  /** Store появляется в первом эффекте; действия входа до этого недостижимы (экран — заставка). */
  const requireStore = (): AuthStore => {
    const s = storeRef.current;
    if (!s) throw new Error("Сессия ещё не готова — обновите страницу.");
    return s;
  };

  const value: AuthContextValue = {
    ready,
    session,
    config,
    configError,
    userName:
      session?.kind === "basic"
        ? session.login
        : session?.kind === "oidc"
          ? nameFromIdToken(session.idToken)
          : null,
    loginBasic: async (login, secret) => {
      const name = login.trim();
      const failure = await verifyBasic(name, secret);
      if (failure) throw new Error(failure.message);
      requireStore().loginBasic(name, secret);
    },
    loginOidc: async (route) => {
      const m = manager();
      if (!m) throw new Error("Поставщик OIDC не настроен на узле.");
      await signin(m, route);
    },
    finishOidc: async () => {
      const m = manager();
      if (!m) throw new Error("Поставщик OIDC не настроен на узле.");
      const { tokens, route } = await signinCallback(m);
      requireStore().loginOidc(tokens);
      return route;
    },
    logout: async () => {
      const s = requireStore();
      const current = s.get();
      const oidc = configRef.current?.oidc;
      s.clear(true); // вкладкам — сразу; выход «везде» — ниже, у поставщика
      if (current?.kind === "oidc" && oidc) {
        const m = manager();
        if (m) await signout(m, current, oidc);
      }
    },
    renew: () => {
      const s = storeRef.current;
      return s ? renew(s) : Promise.resolve();
    },
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

/** Заголовок Authorization текущей сессии — для JMAP-запросов (волны 3+). */
export function useAuthHeader(): string | null {
  return authHeader(useContext(AuthContext)?.session ?? null);
}
