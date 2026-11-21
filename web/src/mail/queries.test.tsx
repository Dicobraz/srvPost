// Запросы и мутации (WEB-03): нормализация по id, Undo — обратный патч; формы патчей Email/set.
import { renderHook } from "@testing-library/react";
import { QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, expect, test } from "vitest";
import type { ReactNode } from "react";

import { CAP_MAIL, CAP_WEBSOCKET, type EmailSummary, type JmapSession } from "../api/jmap";
import { keys, queryClient } from "./client";
import { keywordPatch, movePatch, undoEntries, useFlaggedCount, useReminders } from "./queries";
import { envFromSession } from "./sync";

beforeEach(() => {
  queryClient.clear();
});

/** Объект сессии, как его отдаёт узел (RFC 8620 §2) — учётная запись почты acc1. */
const SESSION: JmapSession = {
  capabilities: {
    "urn:ietf:params:jmap:core": { maxSizeRequest: 10_000_000 },
    [CAP_WEBSOCKET]: { url: "wss://node.example/jmap/ws", supportsPush: true },
  },
  accounts: { acc1: { name: "user@example.org", isPersonal: true, isReadOnly: false, accountCapabilities: {} } },
  primaryAccounts: { [CAP_MAIL]: "acc1" },
  username: "user@example.org",
  apiUrl: "https://node.example/jmap/api",
  downloadUrl: "https://node.example/jmap/download/{accountId}/{blobId}/{name}?accept={type}",
  uploadUrl: "https://node.example/jmap/upload/{accountId}/",
  eventSourceUrl: "https://node.example/jmap/eventsource/?types={types}&closeafter={closeafter}&ping={ping}",
  state: "2c9f1",
};

const SUMMARY: EmailSummary = {
  id: "e1",
  blobId: "b1",
  threadId: "t1",
  mailboxIds: { mb1: true },
  keywords: { $seen: true, "pm.cat.clients": true },
  receivedAt: "2026-11-20T10:00:00Z",
  size: 100,
  from: [{ name: "Ольга", email: "o@vektor.example" }],
  to: [{ name: null, email: "user@example.org" }],
  subject: "Договор поставки",
  preview: "Направляю третью редакцию",
  hasAttachment: false,
};

test("Undo: обратный патч возвращает прежние keywords и mailboxIds", () => {
  queryClient.setQueryData(keys.email("e1"), SUMMARY);
  const snapshot = [{ emailId: "e1", keywords: { ...SUMMARY.keywords }, mailboxIds: { ...SUMMARY.mailboxIds } }];
  const reverse = undoEntries(snapshot);
  expect(reverse.e1).toEqual({ keywords: SUMMARY.keywords, mailboxIds: { mb1: true } });
  // Кэш тоже откатывается (оптимистичный патч снят).
  const restored = queryClient.getQueryData<EmailSummary>(keys.email("e1"));
  expect(restored?.keywords).toEqual(SUMMARY.keywords);
});

test("формы патчей Email/set: слово целиком и замена mailboxIds", () => {
  expect(keywordPatch("$flagged", true)).toEqual({ "keywords/$flagged": true });
  expect(keywordPatch("pm.cat.clients", false)).toEqual({ "keywords/pm.cat.clients": false });
  expect(movePatch(SUMMARY, "mb2")).toEqual({ mailboxIds: { mb2: true } });
});

test("envFromSession: учётная запись почты и адрес входа", () => {
  const env = envFromSession(SESSION, "Bearer acc-1");
  expect(env.accountId).toBe("acc1");
  expect(env.selfAddress).toBe("user@example.org");
  expect(env.authorization).toBe("Bearer acc-1");
});

test("useFlaggedCount без провайдера — ошибка программирования (useJmap вне JmapProvider)", () => {
  expect(() => {
    renderHook(() => useFlaggedCount(), {
      wrapper: ({ children }: { children: ReactNode }) => (
        <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
      ),
    });
  }).toThrow("useJmap вне JmapProvider");
});

test("useReminders (WEB-19) без сессии JMAP — пусто и без запроса: полоса живёт во всей оболочке", () => {
  const { result } = renderHook(() => useReminders(), {
    wrapper: ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    ),
  });
  expect(result.current).toEqual([]);
});
