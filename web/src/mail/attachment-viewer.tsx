/*
  Вкладка просмотра вложения (WEB-16, PARITY attach.preview/next/prev) — вкладка приложения по
  маршруту /mail/:id/attach/:partId (стиль вкладки композера: в приложении, не модалка).

  Выбор вьювера — viewerKind (downloads.ts): изображение — <img> по data: URL (CSP приложения
  пускает data: в img-src и не пускает blob: — работает в собранном приложении уже сейчас),
  PDF — <iframe>, видео/аудио — <video>/<audio> по blob: (CSP в части media/frame blob: —
  вопрос владельца, issue #310; в dev без CSP работает), текст — <pre> в кодировке части
  (до ~1 МБ), остальное — честный отказ с «Скачать». Блоб — fetch с Authorization (сервер
  отдаёт блоб только по входу) → data:/object URL; object URL освобождается при уходе или
  смене вложения.

  Решение по sandbox (зафиксировано в PR): атрибут sandbox iframe отключает плагины, а
  встроенный PDF-просмотрщик Chrome — плагин, поэтому PDF в sandbox-iframe (даже с
  allow-scripts) не рендерится (whatwg/html#3958; MDN: «sandbox can prevent the built-in PDF
  viewer from loading»). Приёмка карты требует рендер PDF без скачивания, значит iframe PDF —
  без sandbox-атрибута; риск разумен, потому что (1) MIME жёстко задаётся Blob'ом
  (application/pdf из типа части) — документ HTML в кадр не попадает и подменить тип нельзя
  (блоб создаём сами из полученных октетов), (2) скрипты PDF-вьювера исполняются в
  привилегированном контексте браузера, а не в origin приложения, (3) HTML-вложение во вьювере
  не рендерится как HTML вовсе — text/* показывается экранированным исходником в <pre>.
  Same-origin кадра с приложением остаётся теоретическим риском бага браузера; WASM-вьювер
  (pdf.js) его снимает — отдельное решение владельца (карточка WEB-16). Изображения и текст
  iframe не используют. Навигация ←/→ между вложениями письма, счётчик «2/5», Escape —
  закрыть вкладку.
*/
import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate, useParams, useSearchParams } from "react-router";

import { blobUrl, emailGet, type EmailBodyPart, type EmailFull } from "../api/jmap";
import { useJmap } from "./context";
import { Icon } from "./icons";
import {
  attachmentNav,
  attachmentParts,
  blobToDataUrl,
  decodeTextData,
  downloadAttachment,
  fetchBlob,
  formatSize,
  sanitizeFilename,
  viewerKind,
} from "./downloads";
import { sharedMailAccounts } from "./shared";
import type { JmapEnv } from "./types";
import { useToast } from "./toast";

/** Свойства письма для вкладки: вложения и тема (тела не нужны). */
const ATTACH_PROPERTIES = ["id", "subject", "attachments"];

export function AttachmentViewerPage() {
  const env = useJmap();
  const toast = useToast();
  const navigate = useNavigate();
  const { id: emailId = "", partId = "" } = useParams();
  const [params] = useSearchParams();
  // Письмо общего ящика (WEB-15): источник — по accountId владельца (как композер, ?account=).
  const sharedAccounts = useMemo(() => sharedMailAccounts(env.session), [env.session]);
  const accountParam = params.get("account");
  const accountId = sharedAccounts.find((a) => a.id === accountParam)?.id ?? env.accountId;

  const full = useQuery<EmailFull | null>({
    queryKey: ["attach-view", accountId, emailId],
    queryFn: async () => {
      const list = await emailGet<EmailFull>(env.apiUrl, env.authorization, accountId, [emailId], ATTACH_PROPERTIES);
      return list[0] ?? null;
    },
    enabled: Boolean(emailId),
    retry: false,
  });

  const parts = useMemo(() => (full.data ? attachmentParts(full.data) : []), [full.data]);
  const nav = useMemo(() => attachmentNav(parts, partId), [parts, partId]);
  const current = nav.index >= 0 ? parts[nav.index] : null;

  /** Переход к соседнему вложению (attach.next/prev): тот же маршрут, другой ключ части. */
  const go = (key: string | null) => {
    if (!key) return;
    navigate(
      `/mail/${encodeURIComponent(emailId)}/attach/${encodeURIComponent(key)}${accountParam ? `?account=${encodeURIComponent(accountParam)}` : ""}`,
    );
  };

  // ←/→ — между вложениями письма (PARITY attach.next/prev), Escape — закрыть вкладку.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.ctrlKey || e.altKey || e.metaKey) return;
      if (e.code === "ArrowLeft") {
        e.preventDefault();
        go(nav.prev);
      } else if (e.code === "ArrowRight") {
        e.preventDefault();
        go(nav.next);
      } else if (e.code === "Escape") {
        e.preventDefault();
        navigate("/");
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const back = () => navigate("/");

  return (
    <div className="attachview">
      <div className="cmd">
        <button type="button" className="btn-acc" disabled={!current} onClick={() => void downloadCurrent()}>
          <Icon name="download" size={16} />
          Скачать
        </button>
        <button type="button" className="btn-q" disabled={!nav.prev} onClick={() => go(nav.prev)} title="Предыдущее вложение (←)">
          ‹ пред
        </button>
        <button type="button" className="btn-q" disabled={!nav.next} onClick={() => go(nav.next)} title="Следующее вложение (→)">
          след ›
        </button>
        <span className="attachview-spread" />
        <button type="button" className="btn-q" onClick={back} title="Закрыть просмотр (Esc)">
          <Icon name="x" size={16} />
          Закрыть
        </button>
      </div>
      <div className="main">
        <div className="card">
          {full.isPending ? (
            <p className="empty" aria-busy="true">
              Загружаем письмо…
            </p>
          ) : full.isError ? (
            <p className="empty">Письмо недоступно: {full.error.message}</p>
          ) : nav.count === 0 ? (
            <p className="empty">У письма нет вложений.</p>
          ) : !current ? (
            <p className="empty">Вложение не найдено — возможно, письмо изменилось.</p>
          ) : (
            <>
              <div className="avhead">
                <Icon name="doc" size={16} />
                <span className="ttl">{sanitizeFilename(current.name ?? "вложение")}</span>
                <span className="sz">{formatSize(current.size)}</span>
                <span className="cnt" title="Номер вложения в письме">
                  {nav.index + 1}/{nav.count}
                </span>
              </div>
              <AttachmentContent key={partId} env={env} accountId={accountId} part={current} onDownload={() => void downloadCurrent()} />
            </>
          )}
        </div>
      </div>
    </div>
  );

  /** Скачивание текущего вложения с честным тостом (кнопка в командной строке вкладки). */
  async function downloadCurrent(): Promise<void> {
    if (!current) return;
    try {
      await downloadAttachment(env, accountId, current);
      toast.show(`Скачано: ${sanitizeFilename(current.name ?? "вложение")}`);
    } catch (e) {
      toast.show(e instanceof Error ? e.message : "Скачать не удалось.");
    }
  }
}

/** Содержимое вкладки: блоб по типу (image/pdf/video/audio/text) или честный отказ со «Скачать».
 * Пересоздаётся сменой ключа части (key у родителя) — object URL прошлой части освобождается,
 * начальное состояние считается заново без setState в эффекте. */
function AttachmentContent({
  env,
  accountId,
  part,
  onDownload,
}: {
  env: JmapEnv;
  accountId: string;
  part: EmailBodyPart;
  onDownload(): void;
}) {
  const kind = viewerKind(part.type, part.size);
  const name = sanitizeFilename(part.name ?? "вложение");
  const [state, setState] = useState<
    { kind: "loading" } | { kind: "error"; message: string } | { kind: "url"; url: string } | { kind: "text"; text: string }
  >(() => {
    // Отказы известны до запроса блоба: тип не вьюверится, текст больше лимита (~1 МБ) или у
    // части нет блоба. setState в эффекте остаётся только в асинхронных колбэках.
    if (kind === "none") {
      return {
        kind: "error",
        message: `Нет встроенного просмотра для «${part.type || "неизвестного типа"}» — скачайте файл на диск.`,
      };
    }
    if (kind === "toolarge") {
      return { kind: "error", message: `Текстовый файл больше 1 МБ — просмотр недоступен, скачайте файл на диск.` };
    }
    if (!part.blobId) {
      return { kind: "error", message: "У вложения нет блоба — просмотр недоступен, скачайте файл на диск." };
    }
    return { kind: "loading" };
  });

  // Блоб текущей части: fetch с Authorization → data: URL (изображение — CSP img-src data:),
  // object URL (PDF/видео/аудио — CSP blob: в media/frame — issue #310) или текст (charset части).
  useEffect(() => {
    if (kind === "none" || kind === "toolarge" || !part.blobId) return; // отказ — уже в начальном состоянии
    let alive = true;
    let objectUrl: string | null = null;
    (async () => {
      try {
        const blob = await fetchBlob(blobUrl(env.session, accountId, part.blobId as string, name), env.authorization, part.type);
        if (!alive) return;
        if (kind === "text") {
          const text = await decodeTextData(await blob.arrayBuffer(), part.charset);
          if (!alive) return;
          setState({ kind: "text", text });
        } else if (kind === "image") {
          const dataUrl = await blobToDataUrl(blob);
          if (!alive) return;
          setState({ kind: "url", url: dataUrl });
        } else {
          objectUrl = URL.createObjectURL(blob);
          setState({ kind: "url", url: objectUrl });
        }
      } catch (e) {
        if (alive) setState({ kind: "error", message: e instanceof Error ? e.message : "Вложение не получено." });
      }
    })();
    return () => {
      alive = false;
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [env, accountId, part, kind, name]);

  if (state.kind === "loading") {
    return (
      <div className="avbody">
        <p className="empty" aria-busy="true">
          Загружаем вложение…
        </p>
      </div>
    );
  }
  if (state.kind === "error") {
    return (
      <div className="avbody">
        <div className="avnone" role="alert">
          <Icon name="ban" size={28} />
          <p>{state.message}</p>
          <button type="button" className="btn-acc" onClick={onDownload}>
            <Icon name="download" size={16} />
            Скачать {name}
          </button>
        </div>
      </div>
    );
  }
  if (state.kind === "text") {
    return (
      <div className="avbody">
        {/* Текст вложения — React-экранированный <pre> (без iframe и HTML). */}
        <pre className="avpre">{state.text}</pre>
      </div>
    );
  }
  return (
    <div className="avbody">
      {kind === "image" ? (
        <img className="avmedia" src={state.url} alt={name} />
      ) : kind === "pdf" ? (
        // PDF — нативный вьювер браузера в iframe без sandbox (решение по sandbox — в шапке файла).
        <iframe className="avframe" title={name} src={state.url} />
      ) : kind === "video" ? (
        <video className="avmedia" src={state.url} controls />
      ) : (
        <audio className="avaudio" src={state.url} controls />
      )}
    </div>
  );
}
