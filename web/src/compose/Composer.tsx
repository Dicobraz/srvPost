/*
  Композер (WEB-04) — вкладкой приложения (маршрут /compose, макет 02), не модалка: строка
  команд (Отправить / Сохранить черновик / Вложить / Удалить черновик), карточка с полями
  (От — identity, Кому/Копия/Скрытая — чипы с автодополнением, Тема), TipTap-редактор,
  чипы вложений, строка «Черновик сохраняется автоматически · сохранён HH:MM». Предупреждения
  перед отправкой — inline-полоса (не модалка): слова о вложении без вложений, внешние
  получатели, пустая тема. Отправка — Email/set + EmailSubmission/set (send.ts), окно undo ~15 с
  с тостом «Отменить» (undo возвращает письмо в черновики; после срока — cannotUnsend, тост
  честно сообщает). Ответы/пересылка — из письма (цитата, forward attached .eml).
*/
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useSearchParams } from "react-router";

import { emailGet, identitiesGet, FULL_PROPERTIES, type EmailFull, type Identity } from "../api/jmap";
import { useJmap } from "../mail/context";
import { queryClient } from "../mail/client";
import { useMailboxes } from "../mail/queries";
import { Icon } from "../mail/icons";
import { useToast } from "../mail/toast";
import { sanitizeComposeHtml } from "./word-paste";
import { RecipientsField } from "./RecipientsField";
import { ComposeEditor } from "./Editor";
import { DraftSaver, saveDraftOnce } from "./drafts";
import { formatSize, uploadAttachment } from "./attachments";
import { loadContacts, domainsOf } from "./contacts";
import { loadSendHistory } from "./send-history";
import { composeWarnings, type Warning } from "./warnings";
import { snapshotHasContent, type Attachment, type ComposeSnapshot } from "./model";
import {
  forwardQuoteHtml,
  forwardAttachments,
  quoteHtml,
  replyAllToOf,
  replyReferences,
  replyToOf,
  subjectFor,
} from "./quote";
import { UNDO_SEND_SECONDS, sendMessage, cancelSend, supportsUndoSend } from "./send";
import type { Recipient } from "./recipients";

/** Ключ локальной подписи (настройки — WEB-14; пока localStorage, пометка в PR). */
const SIGNATURE_KEY = "thepost-webmail-signature";

function localSignature(): string {
  try {
    return localStorage.getItem(SIGNATURE_KEY) ?? "";
  } catch {
    return "";
  }
}

/** Черновик сервера (EmailFull) → снимок композера (сервер — источник истины). */
function snapshotFromDraft(email: EmailFull, identity: Identity | null): ComposeSnapshot {
  const htmlPart = email.htmlBody?.[0];
  const bodyHtml = htmlPart?.partId ? (email.bodyValues[htmlPart.partId]?.value ?? "") : "";
  const attachments = (email.attachments ?? [])
    .filter((p) => p.disposition !== "inline" && p.blobId)
    .map((p, i) => ({
      id: `d${i}`,
      name: p.name ?? "вложение",
      size: p.size,
      type: p.type,
      status: "ready" as const,
      progress: 1,
      blobId: p.blobId ?? undefined,
    }));
  return {
    from: identity ? { name: identity.name || identity.email, email: identity.email } : null,
    to: (email.to ?? []).map((a) => ({ name: a.name, email: a.email })),
    cc: (email.cc ?? []).map((a) => ({ name: a.name, email: a.email })),
    bcc: (email.bcc ?? []).map((a) => ({ name: a.name, email: a.email })),
    subject: email.subject ?? "",
    bodyHtml: sanitizeComposeHtml(bodyHtml),
    attachments,
  };
}

/** Причина открытия композера — параметры маршрута /compose. */
export type ComposeKind = "new" | "reply" | "reply-all" | "forward";

/** Страница композера: сессия, identity и письмо-источник, затем карточка. */
export function ComposerPage() {
  const env = useJmap();
  const [params] = useSearchParams();
  const kindParam = params.get("kind");
  const kind: ComposeKind =
    kindParam === "reply" || kindParam === "reply-all" || kindParam === "forward" ? kindParam : "new";
  const sourceId = params.get("email");
  const draftId = params.get("draft");

  // Identity отправителя (Send As — из JMAP Identity/get; право проверяет сервер — честная ошибка).
  const identities = useQuery<Identity[]>({
    queryKey: ["identities", env.accountId],
    queryFn: () => identitiesGet(env.apiUrl, env.authorization, env.accountId),
    staleTime: 5 * 60_000,
  });
  const identity = identities.data?.[0] ?? null;

  // Источник ответа/пересылки или восстанавливаемый черновик.
  const source = useQuery<EmailFull | null>({
    queryKey: ["compose-source", sourceId ?? draftId ?? ""],
    queryFn: async () => {
      const list = await emailGet<EmailFull>(
        env.apiUrl,
        env.authorization,
        env.accountId,
        [sourceId ?? draftId ?? ""],
        FULL_PROPERTIES,
      );
      return list[0] ?? null;
    },
    enabled: Boolean(sourceId || draftId),
    retry: false,
  });

  if (identities.isPending) {
    return (
      <section className="stub" aria-busy="true">
        <h1>Новое письмо</h1>
        <p>Загружаем…</p>
      </section>
    );
  }
  if (identities.isError || !identity) {
    return (
      <section className="stub">
        <h1>Новое письмо</h1>
        <p className="alert">
          Адрес отправителя недоступен: {identities.error?.message ?? "нет Identity в сессии."}
        </p>
      </section>
    );
  }
  if ((sourceId || draftId) && source.isPending) {
    return (
      <section className="stub" aria-busy="true">
        <h1>Новое письмо</h1>
        <p>Загружаем письмо…</p>
      </section>
    );
  }
  if ((sourceId || draftId) && source.isError) {
    return (
      <section className="stub">
        <h1>Новое письмо</h1>
        <p className="alert">Письмо недоступно: {source.error?.message}</p>
      </section>
    );
  }
  if ((sourceId || draftId) && !source.data) {
    return (
      <section className="stub">
        <h1>Новое письмо</h1>
        <p className="alert">Письмо не найдено — возможно, удалено.</p>
      </section>
    );
  }

  // Ключ — источник письма: смена параметров маршрута пересоздаёт композер (новая вкладка),
  // иначе начальное содержимое осталось бы от прежнего письма.
  return (
    <Composer
      key={sourceId ?? draftId ?? kind}
      identity={identity}
      identities={identities.data ?? []}
      kind={kind}
      source={sourceId ? (source.data ?? null) : null}
      draft={draftId ? (source.data ?? null) : null}
    />
  );
}

interface ComposerProps {
  identity: Identity;
  identities: Identity[];
  kind: ComposeKind;
  /** Письмо-источник для ответа/пересылки (цитата + вложение .eml). */
  source: EmailFull | null;
  /** Черновик сервера для восстановления. */
  draft: EmailFull | null;
}

function Composer({ identity, identities, kind, source, draft }: ComposerProps) {
  const env = useJmap();
  const toast = useToast();
  const navigate = useNavigate();
  const counter = useRef(1);
  const fileInput = useRef<HTMLInputElement | null>(null);

  // Папки Drafts/Sent (роли RFC 6154) — кэш TanStack, общий со списком почты.
  const mailboxes = useMailboxes();
  const draftsMailboxId = mailboxes?.find((m) => m.role === "drafts")?.id ?? null;
  const sentMailboxId = mailboxes?.find((m) => m.role === "sent")?.id ?? null;

  // Подсказки: адресная книга (капабилити contacts есть) + локальная история отправок.
  const contacts = useQuery({
    queryKey: ["contacts", env.accountId],
    queryFn: () => loadContacts(env),
    staleTime: 60_000,
  });
  const candidates = useMemo(
    () => [
      ...(contacts.data ?? []),
      ...loadSendHistory().map((h) => ({ recipient: { name: h.name, email: h.email }, source: "История" })),
    ],
    [contacts.data],
  );
  const knownDomains = useMemo(() => domainsOf(contacts.data ?? []), [contacts.data]);

  // Состояние письма: поля и тело отдельно (редактор даёт HTML по onUpdate).
  const [fromId, setFromId] = useState(identity.id);
  const from = identities.find((i) => i.id === fromId) ?? identity;
  const [to, setTo] = useState<Recipient[]>([]);
  const [cc, setCc] = useState<Recipient[]>([]);
  const [bcc, setBcc] = useState<Recipient[]>([]);
  const [subject, setSubject] = useState("");
  const [bodyHtml, setBodyHtml] = useState("");
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [confirmSend, setConfirmSend] = useState(false);
  const [sending, setSending] = useState(false);
  const [dropHot, setDropHot] = useState(false);
  const [savedAt, setSavedAt] = useState<Date | null>(null);
  const [draftError, setDraftError] = useState<string | null>(null);
  const [initialHtml, setInitialHtml] = useState<string | null>(null);

  const snapshotWith = useCallback(
    (patch: Partial<ComposeSnapshot>): ComposeSnapshot => ({
      from: { name: from.name || from.email, email: from.email },
      to,
      cc,
      bcc,
      subject,
      bodyHtml,
      attachments,
      ...patch,
    }),
    [from, to, cc, bcc, subject, bodyHtml, attachments],
  );

  // Сохранитель черновика — обычный объект в состоянии (никаких ref: правила react-hooks
  // запрещают доступ к ref во время рендера); восстановленный черновик сервера — его же id.
  const [saver] = useState(
    () =>
      new DraftSaver(env, (s) => {
        setSavedAt(s.draftId ? new Date() : null);
        setDraftError(s.error ?? null);
      }),
  );
  useEffect(() => {
    saver.draftsMailboxId = draftsMailboxId;
  }, [saver, draftsMailboxId]);

  const scheduleDraft = useCallback(
    (snap: ComposeSnapshot) => {
      if (draftsMailboxId && snapshotHasContent(snap)) saver.schedule(snap);
    },
    [saver, draftsMailboxId],
  );

  // Начальное содержимое — один раз: черновик сервера (источник истины) или ответ/пересылка
  // с цитатой и подписью (identity → каталог; пусто — подпись из localStorage, настройки WEB-14).
  useEffect(() => {
    if (initialHtml !== null) return;
    const signatureHtml = from.htmlSignature?.trim()
      ? sanitizeComposeHtml(from.htmlSignature)
      : sanitizeComposeHtml(localSignature());
    const signature = signatureHtml ? `<div class="tp-sig">${signatureHtml}</div>` : "";
    if (draft) {
      const snap = snapshotFromDraft(draft, from);
      setTo(snap.to);
      setCc(snap.cc);
      setBcc(snap.bcc);
      setSubject(snap.subject);
      setBodyHtml(snap.bodyHtml);
      setAttachments(snap.attachments);
      setInitialHtml(snap.bodyHtml);
      return;
    }
    if (source) {
      const quote = kind === "forward" ? forwardQuoteHtml(source) : quoteHtml(source);
      if (kind === "reply-all") {
        const all = replyAllToOf(source, env.selfAddress);
        setTo(all.to);
        setCc(all.cc);
      } else {
        setTo(replyToOf(source));
      }
      setSubject(subjectFor(kind === "forward" ? "forward" : "reply", source.subject));
      // Пересылка с вложением: оригинал — как .eml (forward attached, PARITY.md).
      if (kind === "forward") setAttachments(forwardParts(source));
      const html = `${quote}${signature}`;
      setBodyHtml(html);
      setInitialHtml(html);
      return;
    }
    setBodyHtml(signature);
    setInitialHtml(signature);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- сборка начального письма один раз на вкладку
  }, [initialHtml]);

  // Уход со вкладки (Закрыть, смена раздела) — непустые правки идут в черновики; нет
  // накопленного снимка — черновик сервера не трогается (закрытие без правок ничего не удаляет).
  useEffect(() => {
    return () => {
      void saver.flush().catch(() => undefined);
    };
  }, [saver]);

  // ---------- Вложения: пикер, drag-drop, прогресс, отмена ----------

  const addFiles = useCallback(
    (files: File[]) => {
      for (const file of files) {
        const id = `a${counter.current++}`;
        const item = uploadAttachment(env, file, id, {
          onProgress: () => setAttachments((list) => [...list]),
          onReady: () => {
            setAttachments((list) => [...list]);
            scheduleDraft(snapshotWith({ attachments: [...attachments, item] }));
          },
          onError: (message) => {
            setAttachments((list) =>
              message === null ? list.filter((a) => a.id !== id) : [...list],
            );
            if (message !== null) toast.show(message);
          },
        });
        setAttachments((list) => [...list, item]);
      }
    },
    [env, scheduleDraft, snapshotWith, toast, attachments],
  );

  const removeAttachment = (id: string) => {
    setAttachments((list) => {
      const item = list.find((a) => a.id === id);
      item?.abort?.();
      return list.filter((a) => a.id !== id);
    });
    scheduleDraft(snapshotWith({ attachments: attachments.filter((a) => a.id !== id) }));
  };

  // ---------- Предупреждения (inline) и отправка ----------

  const warnings: Warning[] = useMemo(
    () =>
      composeWarnings({
        subject,
        bodyHtml,
        to,
        cc,
        bcc,
        attachmentCount: attachments.filter((a) => a.status === "ready").length,
        ownDomain: from.email.split("@")[1] ?? "",
        knownDomains,
      }),
    [subject, bodyHtml, to, cc, bcc, attachments, from, knownDomains],
  );

  const send = async () => {
    if (!sentMailboxId || !draftsMailboxId) {
      toast.show("Папки «Отправленные» и «Черновики» недоступны — отправка не выполнена.");
      return;
    }
    if (attachments.some((a) => a.status === "uploading")) {
      toast.show("Дождитесь загрузки вложений или отмените их.");
      return;
    }
    if (warnings.length > 0 && !confirmSend) {
      setConfirmSend(true); // inline-подтверждение вместо модалки
      return;
    }
    setSending(true);
    try {
      await saver.flush();
      const snapshot = snapshotWith({});
      const result = await sendMessage(env, snapshot, {
        sentMailboxId,
        identityId: from.id,
        destroyDraftId: saver.draftId ?? null,
        undoable: supportsUndoSend(env.session, env.accountId),
        references: source && kind !== "forward" ? replyReferences(source) : undefined,
      });
      void queryClient.invalidateQueries({ queryKey: ["window"] });
      void queryClient.invalidateQueries({ queryKey: ["mailboxes"] });
      void queryClient.invalidateQueries({ queryKey: ["count"] });
      const label = `Письмо отправлено: ${subject.trim() || "(без темы)"}`;
      const undo = result.undoable
        ? () => {
            void cancelSend(env, result.submissionId)
              .then((ok) => {
                if (!ok) throw new Error("cannotUnsend");
                return saveDraftOnce(env, draftsMailboxId, snapshot);
              })
              .then((id) => {
                toast.show("Отправка отменена — письмо вернулось в черновики");
                void queryClient.invalidateQueries({ queryKey: ["window"] });
                void queryClient.invalidateQueries({ queryKey: ["mailboxes"] });
                if (id) navigate(`/compose?draft=${encodeURIComponent(id)}`);
              })
              .catch(() => {
                // Письмо уже выпущено из очереди (cannotUnsend) — undo невозможен, тост честный.
                toast.show("Письмо уже ушло — отменить не удалось.");
              });
          }
        : undefined;
      toast.show(label, undo, undo ? UNDO_SEND_SECONDS * 1000 : undefined);
      saver.draftId = null;
      navigate("/");
    } catch (e) {
      // Честная ошибка сервера (forbiddenToSend и пр.) — текст в тост, письмо остаётся открытым.
      toast.show(e instanceof Error ? e.message : "Отправка не выполнена.");
      saver.schedule(snapshotWith({}));
    } finally {
      setSending(false);
    }
  };

  const saveDraftNow = async () => {
    saver.schedule(snapshotWith({}));
    await saver.flush();
    if (saver.error) toast.show(saver.error);
    else toast.show("Черновик сохранён");
    void queryClient.invalidateQueries({ queryKey: ["window"] });
  };

  const deleteDraft = async () => {
    await saver.destroyCurrent();
    void queryClient.invalidateQueries({ queryKey: ["window"] });
    toast.show("Черновик удалён");
    navigate("/");
  };

  // ---------- Рендер ----------

  if (initialHtml === null) {
    return (
      <section className="stub" aria-busy="true">
        <h1>Новое письмо</h1>
        <p>Готовим письмо…</p>
      </section>
    );
  }

  return (
    <div
      className="compose"
      onDragOver={(e) => {
        e.preventDefault();
        setDropHot(true);
      }}
      onDragLeave={() => setDropHot(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDropHot(false);
        addFiles([...(e.dataTransfer?.files ?? [])]);
      }}
    >
      {/* Командная строка композера (макет 02): одна акцентная + тихие команды. */}
      <div className="cmd">
        <button type="button" className="btn-acc" onClick={() => void send()} disabled={sending}>
          <Icon name="sent" size={16} />
          Отправить
        </button>
        <button type="button" className="btn-t" onClick={() => void saveDraftNow()} disabled={sending}>
          <Icon name="draft" size={16} />
          Сохранить черновик
        </button>
        <button type="button" className="btn-q" onClick={() => fileInput.current?.click()}>
          <Icon name="clip" size={16} />
          Вложить
        </button>
        <button
          type="button"
          className="btn-q"
          onClick={() => void deleteDraft()}
          disabled={!saver.draftId && !draft}
          title="Черновик сервера удаляется, вкладка закрывается"
        >
          <Icon name="trash" size={16} />
          Удалить черновик
        </button>
        <span className="sp" />
        <button type="button" className="btn-q" onClick={() => navigate("/")}>
          <Icon name="x" size={16} />
          Закрыть
        </button>
      </div>

      <div className="main">
        <div className={`card${dropHot ? " drop" : ""}`}>
          <div className="frow">
            <span className="lbl">От</span>
            {identities.length > 1 ? (
              <select
                className="fromsel"
                value={fromId}
                onChange={(e) => setFromId(e.target.value)}
                aria-label="Адрес отправителя (Send As)"
              >
                {identities.map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.name || i.email} &lt;{i.email}&gt;
                  </option>
                ))}
              </select>
            ) : (
              <span className="finput">
                {from.name || from.email} &lt;{from.email}&gt;
              </span>
            )}
          </div>
          <RecipientsField
            label="Кому"
            recipients={to}
            candidates={candidates}
            onChange={(r) => {
              setTo(r);
              scheduleDraft(snapshotWith({ to: r }));
            }}
            withPicker
          />
          <RecipientsField
            label="Копия"
            recipients={cc}
            candidates={candidates}
            onChange={(r) => {
              setCc(r);
              scheduleDraft(snapshotWith({ cc: r }));
            }}
          />
          <RecipientsField
            label="Скрытая"
            recipients={bcc}
            candidates={candidates}
            onChange={(r) => {
              setBcc(r);
              scheduleDraft(snapshotWith({ bcc: r }));
            }}
          />
          <div className="frow">
            <label className="lbl" htmlFor="compose-subject">
              Тема
            </label>
            <input
              id="compose-subject"
              className="finput subject"
              value={subject}
              onChange={(e) => {
                setSubject(e.target.value);
                scheduleDraft(snapshotWith({ subject: e.target.value }));
              }}
            />
          </div>
          <div className="fsep" />

          {/* Предупреждения перед отправкой — inline-полоса, не модалка (как в Postman). */}
          {confirmSend && warnings.length > 0 && (
            <div className="strip warn" role="alert">
              <div className="warnlines">
                {warnings.map((w) => (
                  <div key={w.kind}>
                    <b aria-hidden="true">▲</b> {w.text}
                  </div>
                ))}
              </div>
              <span className="sp" />
              {warnings.some((w) => w.kind === "attachment") && (
                <button type="button" className="lk" onClick={() => fileInput.current?.click()}>
                  Добавить вложение
                </button>
              )}
              <button type="button" className="lk" onClick={() => void send()}>
                Отправить всё равно
              </button>
              <button type="button" className="lk" onClick={() => setConfirmSend(false)}>
                Вернуться
              </button>
            </div>
          )}

          <ComposeEditor
            initialHtml={initialHtml}
            onChange={(html) => {
              setBodyHtml(html);
              scheduleDraft(snapshotWith({ bodyHtml: html }));
            }}
            onFiles={addFiles}
            onPickFiles={() => fileInput.current?.click()}
          />

          {/* Вложения: чипы с прогрессом и отменой (макет 02) + пикер файлов. */}
          <input
            ref={fileInput}
            type="file"
            multiple
            hidden
            onChange={(e) => {
              addFiles([...(e.target.files ?? [])]);
              e.target.value = ""; // повторный выбор того же файла работает
            }}
          />
          {attachments.length > 0 && (
            <div className="atts">
              {attachments.map((a) => (
                <span className="att" key={a.id} data-status={a.status}>
                  <Icon name={a.status === "error" ? "ban" : "doc"} size={16} />
                  {a.name}
                  <span className="sz">
                    {a.status === "uploading"
                      ? `${Math.round(a.progress * 100)} %`
                      : a.status === "error"
                        ? (a.error ?? "ошибка")
                        : formatSize(a.size)}
                  </span>
                  {a.status === "uploading" && (
                    <span className="attbar" aria-hidden="true">
                      <span style={{ width: `${Math.round(a.progress * 100)}%` }} />
                    </span>
                  )}
                  <button
                    type="button"
                    className="x"
                    aria-label={a.status === "uploading" ? `Отменить загрузку ${a.name}` : `Убрать ${a.name}`}
                    onClick={() => removeAttachment(a.id)}
                  >
                    <Icon name="x" size={14} />
                  </button>
                </span>
              ))}
              <button type="button" className="addf" onClick={() => fileInput.current?.click()}>
                <Icon name="clip" size={16} />
                Добавить вложение
              </button>
            </div>
          )}
          <div className="flexspace" />
          <div className="cardfoot">
            <span className="sp" />
            <span>
              {savedAt
                ? `Черновик сохраняется автоматически · сохранён ${savedAt.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" })}`
                : "Черновик сохраняется автоматически"}
              {draftError && <b className="draft-err"> · {draftError}</b>}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

/** Вложения пересылки: .eml оригинала + его файлы — в снимок при создании письма. */
export function forwardParts(source: EmailFull): Attachment[] {
  return forwardAttachments(source).map((p, i) => ({
    id: `f${i}`,
    name: p.name ?? "Письмо.eml",
    size: p.size,
    type: p.type,
    status: "ready" as const,
    progress: 1,
    blobId: p.blobId ?? undefined,
  }));
}
