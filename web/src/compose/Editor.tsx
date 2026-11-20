/*
  Редактор письма (WEB-04) — TipTap (@tiptap/react): начертания (Ctrl+B/I/U), списки, цитата,
  ссылка (inline-поповер вместо window.prompt — модальных окон нет), таблицы (создание кнопкой,
  правка через контекст-меню) и вставка из Word — pastedown через DOMPurify-пайплайн
  (word-paste.ts: мусор mso вычищен, списки/таблицы/жирность сохраняются). Ctrl+Z — цепочка
  редактора (UndoRedo из StarterKit v3). Обработчики — через ref: замыкание editorProps живёт
  на создании редактора, свежие пропсы читает handlers.current.
*/
import { useEffect, useRef, useState, type ReactNode } from "react";
import { EditorContent, useEditor, type Editor } from "@tiptap/react";
import StarterKit from "@tiptap/starter-kit";
import Link from "@tiptap/extension-link";
import { TableKit } from "@tiptap/extension-table";

import { Icon } from "../mail/icons";
import { ContextMenu, type MenuState } from "../mail/context-menu";
import { looksLikeWordHtml, sanitizeComposeHtml } from "./word-paste";

export interface EditorProps {
  /** Начальный HTML (черновик или ответ с цитатой); меняется только извне при смене письма. */
  initialHtml: string;
  /** Тело изменилось (значение берут editor.getHTML() по требованию). */
  onChange(html: string): void;
  /** Файлы брошены в редактор — во вложения (drag-drop карточки композера). */
  onFiles(files: File[]): void;
  /** Пикер файлов (кнопка «Вложить») — открывает выбор файла композер. */
  onPickFiles(): void;
}

/** Меню правки таблицы (контекст-меню по правому клику в таблице). */
function tableMenu(editor: Editor, x: number, y: number): MenuState {
  const cmd = (run: () => unknown): (() => void) => () => run();
  const chain = () => editor.chain().focus();
  return {
    x,
    y,
    items: [
      { label: "Добавить строку выше", onSelect: cmd(() => chain().addRowBefore().run()) },
      { label: "Добавить строку ниже", onSelect: cmd(() => chain().addRowAfter().run()) },
      { label: "Добавить столбец слева", onSelect: cmd(() => chain().addColumnBefore().run()) },
      { label: "Добавить столбец справа", onSelect: cmd(() => chain().addColumnAfter().run()) },
      { label: "", separator: true },
      { label: "Строка заголовков (вкл/выкл)", onSelect: cmd(() => chain().toggleHeaderRow().run()) },
      { label: "", separator: true },
      { label: "Удалить строку", onSelect: cmd(() => chain().deleteRow().run()) },
      { label: "Удалить столбец", onSelect: cmd(() => chain().deleteColumn().run()) },
      { label: "Удалить таблицу", danger: true, onSelect: cmd(() => chain().deleteTable().run()) },
    ],
  };
}

/** Тело письма: панель форматирования + TipTap + контекст-меню таблиц. */
export function ComposeEditor({ initialHtml, onChange, onFiles, onPickFiles }: EditorProps) {
  const [menu, setMenu] = useState<MenuState | null>(null);
  const [linkOpen, setLinkOpen] = useState(false);
  const [linkUrl, setLinkUrl] = useState("");
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const editorRef = useRef<Editor | null>(null);
  // Свежие колбэки для замыканий, живущих на создании редактора (editorProps, onUpdate).
  const handlers = useRef({ onChange, onFiles, onPickFiles });
  useEffect(() => {
    handlers.current = { onChange, onFiles, onPickFiles };
  });

  const editor = useEditor({
    extensions: [
      // Link/Underline входят в StarterKit v3; свой Link — с openOnClick: false (правка, не переход),
      // встроенный отключаем (дубликат имени расширения недопустим).
      StarterKit.configure({ link: false }),
      Link.configure({ openOnClick: false, autolink: true }),
      TableKit.configure({ table: { resizable: false } }),
    ],
    content: initialHtml,
    editorProps: {
      attributes: { class: "compose-body", "aria-label": "Текст письма" },
      // Вставка (в т.ч. из Word) — через pastedown-санитайзер: mso-мусор долой, структура остаётся.
      handlePaste: (_view, event) => {
        const html = event.clipboardData?.getData("text/html");
        if (!html) return false;
        const e = editorRef.current;
        if (!e) return false;
        e.commands.insertContent(sanitizeComposeHtml(html, { word: looksLikeWordHtml(html) }));
        return true;
      },
      // Файлы, брошенные прямо в текст — во вложения письма.
      handleDrop: (_view, event) => {
        const files = [...(event.dataTransfer?.files ?? [])];
        if (files.length === 0) return false;
        event.preventDefault();
        handlers.current.onFiles(files);
        return true;
      },
    },
    onUpdate: ({ editor: e }) => handlers.current.onChange(e.getHTML()),
  });
  editorRef.current = editor;

  useEffect(() => {
    // Контекст-меню таблиц: правый клик внутри таблицы — операции строк/столбцов.
    const node = bodyRef.current;
    if (!node) return;
    const onContext = (e: MouseEvent) => {
      if (!editor?.isActive("table")) return;
      e.preventDefault();
      setMenu(tableMenu(editor, e.clientX, e.clientY));
    };
    node.addEventListener("contextmenu", onContext);
    return () => node.removeEventListener("contextmenu", onContext);
  }, [editor]);

  const btn = (title: string, active: boolean, run: () => unknown, content: ReactNode) => (
    <button
      type="button"
      className="fb"
      title={title}
      aria-label={title}
      aria-pressed={active}
      onMouseDown={(e) => e.preventDefault()} // фокус остаётся в редакторе — выделение не теряется
      onClick={run}
      style={active ? { background: "var(--m-tint)" } : undefined}
    >
      {content}
    </button>
  );

  if (!editor) return <div className="bodyc" ref={bodyRef} />;

  const applyLink = () => {
    const url = linkUrl.trim();
    setLinkOpen(false);
    if (!url) return;
    const href = /^https?:\/\//i.test(url) || url.includes("@") ? url : `https://${url}`;
    const safe = href.replace(/"/g, "%22");
    if (editor.state.selection.empty) {
      editor.chain().focus().insertContent(`<a href="${safe}">${safe}</a>`).run();
    } else {
      editor.chain().focus().setLink({ href }).run();
    }
    setLinkUrl("");
  };

  return (
    <>
      <div className="fmt" role="toolbar" aria-label="Форматирование">
        {btn("Жирный (Ctrl+B)", editor.isActive("bold"), () => editor.chain().focus().toggleBold().run(), <b>Ж</b>)}
        {btn("Курсив (Ctrl+I)", editor.isActive("italic"), () => editor.chain().focus().toggleItalic().run(), <i>К</i>)}
        {btn("Подчёркнутый (Ctrl+U)", editor.isActive("underline"), () => editor.chain().focus().toggleUnderline().run(), <u>Ч</u>)}
        <span className="fs" />
        {btn("Маркированный список", editor.isActive("bulletList"), () => editor.chain().focus().toggleBulletList().run(), <Icon name="list" size={16} />)}
        {btn("Цитата", editor.isActive("blockquote"), () => editor.chain().focus().toggleBlockquote().run(), <Icon name="quote" size={16} />)}
        {btn("Таблица 2×3", editor.isActive("table"), () => editor.chain().focus().insertTable({ rows: 3, cols: 2, withHeaderRow: true }).run(), <Icon name="table" size={16} />)}
        <span className="fbwrap">
          {btn("Ссылка", editor.isActive("link"), () => {
            setLinkUrl((editor.getAttributes("link").href as string) ?? "");
            setLinkOpen((v) => !v);
          }, <Icon name="link" size={16} />)}
          {linkOpen && (
            <span className="linkpop">
              <input
                autoFocus
                className="linkinput"
                placeholder="Адрес ссылки"
                value={linkUrl}
                onChange={(e) => setLinkUrl(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") applyLink();
                  if (e.key === "Escape") setLinkOpen(false);
                }}
              />
              <button type="button" className="lk" onClick={applyLink}>
                ОК
              </button>
              {editor.isActive("link") && (
                <button
                  type="button"
                  className="lk"
                  onClick={() => {
                    editor.chain().focus().unsetLink().run();
                    setLinkOpen(false);
                  }}
                >
                  Убрать
                </button>
              )}
            </span>
          )}
        </span>
        <span className="fs" />
        {btn("Вложить файл", false, () => handlers.current.onPickFiles(), <Icon name="clip" size={16} />)}
      </div>
      <div className="bodyc" ref={bodyRef}>
        <EditorContent editor={editor} className="compose-editor" />
      </div>
      {menu && <ContextMenu menu={menu} onClose={() => setMenu(null)} />}
    </>
  );
}
