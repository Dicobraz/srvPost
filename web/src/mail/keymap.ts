/*
  Хоткеи почты (WEB-03): one-modifier схема из DESIGN.md Postman — Ctrl + буква/цифра = команда,
  без модификатора — навигация и действие над выделенным; таблица клавиш — реестр PARITY.md
  (Postman): Ctrl+R/Ctrl+Shift+R/Ctrl+F — ответы (в вебе — заглушки до композера, волна 4),
  Ctrl+Q/U — прочитано/непрочитано, Del — удалить, Backspace — архив, 1–9 — категория выделенного.
  Клавиши — по event.code: физические, раскладка RU/EN не мешает (буквы — Key*).
  Голые j/k — навигация (схема «Одиночные клавиши» Postman, удобнее на ноутбуке).
  F6 — фокус-роум по трём панелям (дерево → список → чтение).
  WEB-05: Ctrl+K — палитра команд (palette.*), F3/Shift+F3 — совпадения поиска в открытом письме
  (работают и в полях ввода — как в Postman).
  WEB-15: Ctrl+J — «Взять в работу» письма общего ящика (mail.take Postman).
  WEB-19: Ctrl+. — «Напомнить…» (слот PARITY свободен) — пикер напоминания выделенному письму.
*/

/** Действия почты, привязанные к клавишам (страница передаёт замыкания). */
export interface MailHotkeyActions {
  nextMessage(): void;
  prevMessage(): void;
  openSelected(): void;
  /** Категория по клавише 1–9 (категория или null — снятие). */
  categorize(n: number): void;
  markRead(): void;
  markUnread(): void;
  deleteSelected(): void;
  archiveSelected(): void;
  /** Ответы — заглушки до композера (тост). */
  reply(): void;
  replyAll(): void;
  forward(): void;
  /** Новое письмо — заглушка (композер — волна 4). */
  compose(): void;
  /** Фокус-роум: следующая/предыдущая панель. */
  focusNextPanel(backward?: boolean): void;
  /** Фокус на дерево папок (Ctrl+Y — «перейти к папке» из Postman). */
  focusFolders(): void;
  /** Закрыть чтение/свернуть поток (Esc). */
  escape(): void;
  /** Палитра команд и писем (Ctrl+K, WEB-05). */
  openPalette(): void;
  /** Совпадения поиска в открытом письме: следующее/предыдущее (F3/Shift+F3, WEB-05). */
  findNext(): void;
  findPrev(): void;
  /** «Взять в работу»/«Вернуть» — письмо общего ящика (Ctrl+J, WEB-15). */
  takeSelected(): void;
  /** «Напомнить…» — пикер напоминания для выделенного письма (Ctrl+., WEB-19). */
  remindSelected(): void;
}

/** Поле ввода: буквы и цифры там остаются вводу (Ctrl-команды действуют и там). */
function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable) return true;
  return target.matches("input, textarea, select");
}

/** Обработка клавиатуры почты; `true` — клавиша обработана (вызову не нужен). */
export function handleMailKeydown(event: KeyboardEvent, actions: MailHotkeyActions): boolean {
  const code = event.code;
  const ctrl = event.ctrlKey || event.metaKey;
  const alt = event.altKey;

  // Один модификатор: Ctrl (Alt в схеме не используется).
  if (ctrl && !alt) {
    switch (code) {
      case "KeyR":
        event.preventDefault();
        if (event.shiftKey) actions.replyAll();
        else actions.reply();
        return true;
      case "KeyF":
        event.preventDefault();
        actions.forward();
        return true;
      case "KeyQ":
        event.preventDefault();
        actions.markRead();
        return true;
      case "KeyU":
        event.preventDefault();
        actions.markUnread();
        return true;
      case "KeyN":
        event.preventDefault();
        actions.compose();
        return true;
      case "KeyJ":
        // «Взять в работу» письма общего ящика (WEB-15, как mail.take Postman).
        event.preventDefault();
        actions.takeSelected();
        return true;
      case "Period":
        // «Напомнить…» (WEB-19): слот PARITY свободен — пикер срока выделенному письму.
        event.preventDefault();
        actions.remindSelected();
        return true;
      case "KeyK":
        event.preventDefault();
        actions.openPalette();
        return true;
      case "KeyY":
        event.preventDefault();
        actions.focusFolders();
        return true;
      case "Digit1":
      case "Digit2":
      case "Digit3":
      case "Digit4":
      case "Digit5":
      case "Digit6":
      case "Digit7":
      case "Digit8":
      case "Digit9":
        // Ctrl+цифра — разделы (Почта/Календарь/Контакты): навигация приложения, не категория.
        return false;
      default:
        return false;
    }
  }
  if (alt) return false;

  // F3/Shift+F3 — совпадения в открытом письме: и в поле ввода тоже (поиск в Postman работает,
  // пока пользователь не снял фокус с поля). Остальные голые клавиши в поле остаются вводу.
  if (code === "F3") {
    event.preventDefault();
    if (event.shiftKey) actions.findPrev();
    else actions.findNext();
    return true;
  }

  // В поле ввода голые клавиши остаются вводу.
  if (isTypingTarget(event.target)) return false;

  switch (code) {
    case "KeyJ":
    case "ArrowDown":
      event.preventDefault();
      actions.nextMessage();
      return true;
    case "KeyK":
    case "ArrowUp":
      event.preventDefault();
      actions.prevMessage();
      return true;
    case "Enter":
      event.preventDefault();
      actions.openSelected();
      return true;
    case "Delete":
      event.preventDefault();
      actions.deleteSelected();
      return true;
    case "Backspace":
      event.preventDefault();
      actions.archiveSelected();
      return true;
    case "F6":
      event.preventDefault();
      actions.focusNextPanel(event.shiftKey);
      return true;
    case "Escape":
      event.preventDefault();
      actions.escape();
      return true;
    case "Digit1":
    case "Digit2":
    case "Digit3":
    case "Digit4":
    case "Digit5":
    case "Digit6":
    case "Digit7":
    case "Digit8":
    case "Digit9":
      event.preventDefault();
      actions.categorize(Number(code.slice("Digit".length)));
      return true;
    default:
      return false;
  }
}

/** Подсказка клавиш для строки состояния и подсказок (таблица PARITY.md). */
export const KEYMAP_HINTS: Array<{ keys: string; action: string }> = [
  { keys: "Ctrl+N", action: "Новое письмо" },
  { keys: "Ctrl+K", action: "Палитра команд" },
  { keys: "Ctrl+J", action: "Взять в работу" },
  { keys: "Ctrl+.", action: "Напомнить…" },
  { keys: "Ctrl+R / Ctrl+Shift+R", action: "Ответить / всем" },
  { keys: "Ctrl+F", action: "Переслать" },
  { keys: "Ctrl+Q / Ctrl+U", action: "Прочитано / непрочитано" },
  { keys: "Del / Backspace", action: "Удалить / в архив" },
  { keys: "1–9", action: "Категория" },
  { keys: "J / K или ↓ / ↑", action: "По списку" },
  { keys: "Enter", action: "Открыть письмо" },
  { keys: "F3 / Shift+F3", action: "Совпадения в письме" },
  { keys: "F6", action: "Между панелями" },
  { keys: "Ctrl+Y", action: "К дереву папок" },
  { keys: "Esc", action: "Свернуть / закрыть" },
];
