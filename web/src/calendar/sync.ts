/*
  Push календаря (WEB-06): канал уже открыт — WS-лидер вкладок (mail/push.ts); типы Calendar,
  CalendarEvent (и CalendarEventNotification) включены в WebSocketPushEnable/{types}, события
  StateChange приходят вместе с почтовыми. Для вида «минимум» delta-sync — перечитывание
  видимого периода: query+get двух запросов, точечная сверка /changes не даёт выгоды (ids
  дёшевы, тела уже в кэше, период короткий) — окна календаря и занятости инвалидируются,
  TanStack Query сам обновит смонтированные запросы. Тик таймера (нет push) — тот же путь.
*/
import { CAP_CALENDARS, hasCapability } from "../api/jmap";
import { queryClient } from "../mail/client";
import type { JmapEnv } from "../mail/types";

/** Событие push/таймера: календари узла с капабилити перечитывают видимый период. */
export function handleCalendarSyncEvent(env: JmapEnv): void {
  if (!hasCapability(env.session, env.accountId, CAP_CALENDARS)) return;
  void queryClient.invalidateQueries({ queryKey: ["calendar-events"] });
  void queryClient.invalidateQueries({ queryKey: ["busy"] });
  void queryClient.invalidateQueries({ queryKey: ["calendars"] });
}
