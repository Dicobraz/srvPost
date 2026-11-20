// Типы, общие для синхронизации и запросов: среда JMAP-запросов (без импортов React — чтобы
// mail/sync.ts и mail/queries.ts не зацикливались на провайдере).
import type { JmapSession } from "../api/jmap";

/** Среда запросов: сессия JMAP, почтовая учётная запись и свежий заголовок входа. */
export interface JmapEnv {
  session: JmapSession;
  accountId: string;
  authorization: string | null;
  /** Адрес входа — для быстрого фильтра «Мне» (я в «Кому»). */
  selfAddress: string;
}
