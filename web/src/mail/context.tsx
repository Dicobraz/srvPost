/*
  Провайдер JMAP-сессии (WEB-03): объект сессии из `/.well-known/jmap` (RFC 8620 §2) для вошедшей
  вкладки; хаб push (mail/push.ts — одно соединение на пользователя, лидер вкладок) получает свежие
  адреса и токен из сессии OIDC; события push и таймера — в delta-sync (mail/sync.ts). Смена сессии
  (renew OIDC меняет только заголовок; выход — сессия пуста) видна провайдеру через useAuth.
*/
import { createContext, useContext, useEffect, useMemo, type ReactNode } from "react";
import { useQuery } from "@tanstack/react-query";

import { authHeader, fetchSession, websocketUrl, type JmapSession } from "../api/jmap";
import { useAuth } from "../auth/session";
import { queryClient, keys } from "./client";
import { envFromSession, handleSyncEvent, resetSyncState } from "./sync";
import { PushHub, type PushSource } from "./push";
import type { JmapEnv } from "./types";

const JmapContext = createContext<JmapEnv | null>(null);

/** Среда запросов; вне JmapProvider — ошибка программирования. */
export function useJmap(): JmapEnv {
  const value = useContext(JmapContext);
  if (!value) throw new Error("useJmap вне JmapProvider");
  return value;
}

/** Состояние сессии для страницы почты: загрузка, ошибка сети/входа, готово. */
export type JmapReady =
  | { state: "loading" }
  | { state: "error"; message: string }
  | { state: "ready"; session: JmapSession };

const ReadyContext = createContext<JmapReady>({ state: "loading" });

/** Состояние сессии JMAP — заставка/ошибка страницы почты. */
export function useJmapReady(): JmapReady {
  return useContext(ReadyContext);
}

const PushContext = createContext<PushHub | null>(null);

/** Хаб push вкладки — индикация соединения в строке состояния. */
export function usePushHub(): PushHub | null {
  return useContext(PushContext);
}

interface JmapProviderProps {
  children: ReactNode;
  /** Хаб push (подменяется в тестах; по умолчанию — новый). */
  hub?: PushHub;
}

export function JmapProvider({ children, hub }: JmapProviderProps) {
  const { session: login } = useAuth();
  const authorization = authHeader(login);
  const pushHub = useMemo(() => hub ?? new PushHub(), [hub]);

  // Сессия JMAP: один раз на сессию входа (узел один; renew OIDC меняет токен, но не сессию).
  const sessionQuery = useQuery<JmapSession>({
    queryKey: keys.session(authorization),
    queryFn: () => fetchSession(authorization as string),
    enabled: Boolean(authorization),
    retry: false,
    staleTime: Infinity,
  });

  const session = sessionQuery.data ?? null;
  const env = useMemo<JmapEnv | null>(
    () => (session ? envFromSession(session, authorization) : null),
    [session, authorization],
  );

  // Выход: delta-sync с чистой точки, кэш почты не нужен (следующий вход перечитает).
  useEffect(() => {
    if (!login) {
      resetSyncState();
      void queryClient.removeQueries({ queryKey: ["mailboxes"] });
      void queryClient.removeQueries({ queryKey: ["window"] });
      void queryClient.removeQueries({ queryKey: ["count"] });
    }
  }, [login]);

  // Push: один транспорт на пользователя (лидер вкладок); события — в delta-sync. Источник читает
  // свежий токен OIDC на каждое (пере)подключение — renew не обрывает соединение искусственно.
  useEffect(() => {
    if (!env) return;
    const source = (): PushSource => ({
      wsUrl: websocketUrl(env.session),
      eventSourceUrl: env.session.eventSourceUrl,
      accessToken: env.authorization?.startsWith("Bearer ")
        ? env.authorization.slice("Bearer ".length)
        : null,
    });
    const unsubscribe = pushHub.subscribe(() => void handleSyncEvent(env));
    pushHub.start(source);
    return () => {
      unsubscribe();
      pushHub.stop();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- env пересоздаётся со сменой сессии
  }, [pushHub, env]);

  const ready: JmapReady = sessionQuery.isError
    ? { state: "error", message: sessionQuery.error.message }
    : session
      ? { state: "ready", session }
      : { state: "loading" };

  return (
    <JmapContext.Provider value={env}>
      <ReadyContext.Provider value={ready}>
        <PushContext.Provider value={pushHub}>{children}</PushContext.Provider>
      </ReadyContext.Provider>
    </JmapContext.Provider>
  );
}
