/*
  Экземпляр TanStack Query (WEB-03): один на приложение (App.tsx) — окна, письма по id, папки и
  потоки живут в одном кэше; delta-sync (mail/sync.ts) правит его же. Повторы — сеть, не логика;
  письма в кэше «бесконечно» свежи — их правят мутации и delta-sync.
*/
import { QueryClient } from "@tanstack/react-query";

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      staleTime: 30_000,
    },
  },
});

/** Ключи кэша: окна — по аргументам, письма и потоки — по идентификаторам (нормализация id). */
export const keys = {
  session: (authorization: string | null) => ["jmap-session", authorization] as const,
  mailboxes: () => ["mailboxes"] as const,
  flaggedCount: () => ["count", "flagged"] as const,
  window: (args: unknown) => ["window", args] as const,
  email: (id: string) => ["email", id] as const,
  thread: (id: string) => ["thread", id] as const,
  full: (id: string) => ["full", id] as const,
};
