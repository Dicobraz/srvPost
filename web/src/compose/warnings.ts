/*
  Предупреждения перед отправкой (WEB-04, как в Postman): inline-полоса в карточке композера,
  не модалка (макет 01 — inline-подтверждения). Три проверки карточки:
  - «прилагаю»/«вложение» без вложений — регэксп по теме и тексту тела (приёмка: срабатывает на
    «прилагаю», не срабатывает без слов о вложении);
  - внешние получатели — домен не свой (домен адреса входа) и не из известных контактов;
  - пустая тема.
  Смысл не держится на цвете: знак ▲ из токенов ([signs] warn) рядом с текстом.
*/

import { htmlToText } from "./word-paste";
import type { Recipient } from "./recipients";

/** Активные предупреждения одним списком — полоса рисует по строке на предупреждение. */
export interface Warning {
  kind: "attachment" | "external" | "subject";
  text: string;
}

/**
 * Слова о вложенности (русский и английский): «прилагаю», «вложение», «скрепка», «attach»,
 * «в файле» не считаем — ложных срабатываний много (приёмка карточки: без слов о вложении
 * предупреждения нет).
 */
const ATTACH_WORDS = /прилага\w*|вложени\w*|скрепк\w*|attach\w*|enclos\w*/i;

/** Домены внешних получателей: не свой домен и не домены известных контактов. */
export function externalDomains(
  recipients: Recipient[],
  ownDomain: string,
  knownDomains: Set<string>,
): string[] {
  const own = ownDomain.toLowerCase();
  const domains = new Set<string>();
  for (const r of recipients) {
    const domain = r.email.split("@")[1]?.toLowerCase();
    if (!domain) continue;
    if (domain === own || domain.endsWith(`.${own}`)) continue;
    if (knownDomains.has(domain)) continue;
    domains.add(domain);
  }
  return [...domains];
}

/** Все предупреждения текущего состояния письма (порядок: вложения → внешние → тема). */
export function composeWarnings(state: {
  subject: string;
  bodyHtml: string;
  to: Recipient[];
  cc: Recipient[];
  bcc: Recipient[];
  attachmentCount: number;
  /** Домен адреса входа (свой — внешним не считается). */
  ownDomain: string;
  /** Домены адресатов из адресной книги (подсказки контактов) — внешними не считаются. */
  knownDomains: Set<string>;
}): Warning[] {
  const out: Warning[] = [];
  const text = `${state.subject} ${htmlToText(state.bodyHtml)}`;
  if (state.attachmentCount === 0 && ATTACH_WORDS.test(text)) {
    out.push({
      kind: "attachment",
      text: "В тексте есть слова о вложении, а вложений нет — добавить файл или отправить так?",
    });
  }
  const external = externalDomains([...state.to, ...state.cc, ...state.bcc], state.ownDomain, state.knownDomains);
  if (external.length > 0) {
    out.push({
      kind: "external",
      text: `Письмо уйдёт вне организации: ${external.join(", ")}`,
    });
  }
  if (state.subject.trim() === "") {
    out.push({ kind: "subject", text: "Тема не указана — отправить без темы?" });
  }
  return out;
}
