/*
  Черновики (WEB-04): автосохранение Email/set в папку Drafts с задержкой (debounce 1,5 с) и
  сразу — по команде «Сохранить черновик» и перед отправкой. Источник истины — черновик сервера
  (приёмка карточки: «черновик сохранён при падении вкладки — открывается из Drafts»). Тело
  Email/set не меняется (сервер правит только keywords/mailboxIds), поэтому каждое сохранение —
  новое письмо + уничтожение предыдущего одним запросом: сервер исполняет create до destroy,
  падение создания не теряет прежний черновик. Сохранитель — обычный объект (useState), никаких
  ref: правила react-hooks (React Compiler) запрещают доступ к ref во время рендера.
*/

import { emailSetCreate, emailSetDestroy } from "../api/jmap";
import type { JmapEnv } from "../mail/types";
import { attachmentParts, snapshotHasContent, type ComposeSnapshot } from "./model";
import type { Recipient } from "./recipients";

/** Ключевые слова черновика: $draft + $seen (письмо своё, непрочитанным его не считают). */
const DRAFT_KEYWORDS = { $draft: true, $seen: true } as const;

/** Объект Email/set create черновика из снимка (адреса, тема, тело, вложения). */
export function draftCreate(draftsMailboxId: string, s: ComposeSnapshot): Record<string, unknown> {
  const email: Record<string, unknown> = {
    mailboxIds: { [draftsMailboxId]: true },
    keywords: { ...DRAFT_KEYWORDS },
    ...(s.from ? { from: [{ name: s.from.name, email: s.from.email }] } : {}),
    ...(s.to.length > 0 ? { to: s.to.map(toJmapAddress) } : {}),
    ...(s.cc.length > 0 ? { cc: s.cc.map(toJmapAddress) } : {}),
    ...(s.bcc.length > 0 ? { bcc: s.bcc.map(toJmapAddress) } : {}),
    subject: s.subject,
    htmlBody: [{ partId: "body", type: "text/html" }],
    bodyValues: { body: { value: s.bodyHtml, isEncodingProblem: false, isTruncated: false } },
  };
  const parts = attachmentParts(s.attachments);
  if (parts.length > 0) email.attachments = parts;
  return email;
}

/** JMAP EmailAddress: имя может отсутствовать. */
function toJmapAddress(r: Recipient): { name: string | null; email: string } {
  return { name: r.name, email: r.email };
}

/** Задержка автосохранения: быстро после правки, но не на каждое нажатие. */
export const DRAFT_DEBOUNCE_MS = 1_500;

/**
 * Сохранитель черновика: schedule(state) — отложенно, flush() — сейчас, destroyCurrent() —
 * удалить. Папку Drafts композер вписывает в draftsMailboxId, когда загрузятся папки; без неё
 * сохранение честно пишет ошибку.
 */
export class DraftSaver {
  private timer: number | null = null;
  private pending: ComposeSnapshot | null = null;
  private saving: Promise<string | null> | null = null;
  /** Ошибка последнего сохранения — композер покажет её в строке «Черновик сохраняется…». */
  error: string | null = null;
  /** Текущий id черновика сервера (пересоздаётся на каждое сохранение). */
  draftId: string | null = null;
  /** Папка Drafts учётной записи (роль drafts); появляется с загрузкой папок. */
  draftsMailboxId: string | null = null;

  constructor(
    private readonly env: JmapEnv,
    /** Пробуждение после каждой операции (перерисовать «сохранён HH:MM» / ошибку). */
    private readonly onSaved?: (saver: DraftSaver) => void,
  ) {}

  /** Запланировать автосохранение снимка (перезапускает таймер — пользователь печатает дальше). */
  schedule(state: ComposeSnapshot): void {
    this.pending = state;
    if (this.timer !== null) window.clearTimeout(this.timer);
    this.timer = window.setTimeout(() => {
      this.timer = null;
      void this.flush();
    }, DRAFT_DEBOUNCE_MS);
  }

  /** Есть не сохранённый снимок (принять правку сейчас — «Сохранить черновик»). */
  hasPending(): boolean {
    return this.pending !== null;
  }

  /**
   * Сохранить немедленно: нет накопленного снимка — ничего (черновик не трогаем, закрытие
   * вкладки без правок ничего не удаляет); пустой снимок — черновик уничтожается (пользователь
   * всё вычистил); непустой — create нового + destroy предыдущего.
   */
  async flush(): Promise<string | null> {
    if (this.timer !== null) {
      window.clearTimeout(this.timer);
      this.timer = null;
    }
    const state = this.pending;
    this.pending = null;
    if (!state) return this.draftId;
    if (!snapshotHasContent(state)) {
      await this.destroyCurrent();
      return this.draftId;
    }
    if (this.saving) await this.saving.catch(() => undefined);
    this.saving = this.saveNow(state);
    const id = await this.saving;
    this.saving = null;
    return id;
  }

  /** Уничтожить черновик сервера («Удалить черновик», отправка — черновик больше не нужен). */
  async destroyCurrent(): Promise<void> {
    const id = this.draftId;
    this.draftId = null;
    this.pending = null;
    if (!id) return;
    if (!this.draftsMailboxId) {
      this.error = "Папка «Черновики» недоступна.";
      this.onSaved?.(this);
      return;
    }
    try {
      const result = await emailSetDestroy(this.env.apiUrl, this.env.authorization, this.env.accountId, [id]);
      if (Object.keys(result.notDestroyed).length > 0) this.error = "Удалить черновик не удалось.";
    } catch {
      this.error = "Удалить черновик не удалось.";
    }
    this.onSaved?.(this);
  }

  private async saveNow(state: ComposeSnapshot): Promise<string | null> {
    const cid = "d0";
    const previous = this.draftId;
    if (!this.draftsMailboxId) {
      this.error = "Папка «Черновики» недоступна — черновик не сохранён.";
      this.onSaved?.(this);
      return this.draftId;
    }
    try {
      const result = await emailSetCreate(this.env.apiUrl, this.env.authorization, this.env.accountId, {
        [cid]: draftCreate(this.draftsMailboxId, state),
      });
      const created = result.created[cid];
      if (!created?.id) {
        const err = result.errors[cid];
        this.error = err?.description ? `Черновик не сохранён: ${err.description}` : "Черновик не сохранён.";
        return this.draftId;
      }
      this.error = null;
      this.draftId = created.id;
      // Прежний черновик уничтожаем только после успешного создания нового (сервер исполняет
      // create до destroy, но здесь отдельные запросы — порядок важен вдвойне).
      if (previous) {
        void emailSetDestroy(this.env.apiUrl, this.env.authorization, this.env.accountId, [previous]).catch(
          () => undefined,
        );
      }
      this.onSaved?.(this);
      return this.draftId;
    } catch (e) {
      this.error = e instanceof Error ? e.message : "Черновик не сохранён.";
      this.onSaved?.(this);
      return this.draftId;
    }
  }
}

/** Разовое сохранение черновика (undo-send возвращает письмо в Drafts; без состояния debounce). */
export async function saveDraftOnce(env: JmapEnv, draftsMailboxId: string, state: ComposeSnapshot): Promise<string | null> {
  const result = await emailSetCreate(env.apiUrl, env.authorization, env.accountId, {
    d0: draftCreate(draftsMailboxId, state),
  });
  return result.created.d0?.id ?? null;
}
