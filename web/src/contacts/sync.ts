/*
  Push контактов (WEB-07): канал уже открыт — WS-лидер вкладок (mail/push.ts); типы AddressBook
  и ContactCard включены в WebSocketPushEnable/{types}, события StateChange приходят вместе с
  почтовыми и календарными. Изменения GAL сервер сообщает после своего sync-интервала
  (thepost/gal.rs) — новая книга и её карточки появляются в вебе живо: снимок подсказок,
  поиск и открытая карточка перечитываются инвалидацией TanStack Query (delta-сверка /changes
  не даёт выгоды: карточки немного, тела кэшированы). Тик таймера (нет push) — тот же путь.
*/
import { CAP_CONTACTS, hasCapability } from "../api/jmap";
import { queryClient } from "../mail/client";
import type { JmapEnv } from "../mail/types";

/** Событие push/таймера: узел с адресными книгами перечитывает книги и карточки. */
export function handleContactsSyncEvent(env: JmapEnv): void {
  if (!hasCapability(env.session, env.accountId, CAP_CONTACTS)) return;
  void queryClient.invalidateQueries({ queryKey: ["address-books"] });
  void queryClient.invalidateQueries({ queryKey: ["contact-snapshot"] });
  void queryClient.invalidateQueries({ queryKey: ["contact-search"] });
  void queryClient.invalidateQueries({ queryKey: ["contact-card"] });
}
