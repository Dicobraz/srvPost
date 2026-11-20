/*
  Delta-sync (WEB-03): по событиям push (mail/push.ts — StateChange или синтетический тик таймера)
  состояние почты сверяется `Email/changes` по state-строкам: изменённые письма перечитываются
  точечно в кэш по id, уничтоженные — удаляются из кэша, окна и счётчики папок пересчитываются
  query-строкой (ids дёшево, тела уже в кэше — «delta-sync не перечитывает всё окно»).
*/
import { queryClient, keys } from "./client";
import { emailChanges, type JmapSession } from "../api/jmap";
import type { JmapEnv } from "./types";

/** Состояние почты, с которого идёт delta-sync (строка из Mailbox/get state). */
let syncState: string | null = null;

/** Запомнить состояние почты из Mailbox/get — точка отсчёта delta-sync (первый раз). */
export function rememberSyncState(state: string): void {
  if (state && !syncState) syncState = state;
}

/** Сброс delta-sync: смена сессии/учётной записи. */
export function resetSyncState(): void {
  syncState = null;
}

/** Событие push/таймера: окна и счётчики — сразу; письма — по `/changes`, если есть точка отсчёта. */
export async function handleSyncEvent(env: JmapEnv): Promise<void> {
  void queryClient.invalidateQueries({ queryKey: ["mailboxes"] });
  void queryClient.invalidateQueries({ queryKey: ["count"] });
  void queryClient.invalidateQueries({ queryKey: ["window"] });
  if (!syncState) return;
  let state = syncState;
  for (let round = 0; round < 8; round += 1) {
    const changes = await emailChanges(env.apiUrl, env.authorization, env.accountId, state);
    if (!changes) {
      // Сервер не считает изменения (потеря журнала) — правки окон уже перечитаны выше.
      return;
    }
    for (const id of changes.updated) {
      void queryClient.invalidateQueries({ queryKey: keys.email(id) });
    }
    for (const id of changes.destroyed) {
      queryClient.removeQueries({ queryKey: keys.email(id) });
      queryClient.removeQueries({ queryKey: keys.full(id) });
    }
    state = changes.newState;
    if (!changes.hasMore) break;
  }
  syncState = state;
}

/** Из сессии JMAP — среда запросов (адрес API, учётная запись почты, адрес входа). */
export function envFromSession(session: JmapSession, authorization: string | null): JmapEnv {
  const accountId = session.primaryAccounts["urn:ietf:params:jmap:mail"];
  if (!accountId) throw new Error("В сессии нет почтовой учётной записи.");
  return {
    session,
    apiUrl: session.apiUrl,
    accountId,
    authorization,
    selfAddress: session.username,
  };
}
