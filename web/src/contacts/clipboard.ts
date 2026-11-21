/*
  Буфер обмена (WEB-07, PARITY contacts.copy_address): копирование адреса из карточки и
  контекстного меню списка — тост подтверждает. Clipboard API требует защищённый контекст и
  права; fallback — скрытая textarea и execCommand (старые браузеры, http-узлы).
*/

/** Скопировать текст; true — получилось (тост успеха), false — нет (тост с извинением). */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Права или незащищённый контекст — fallback ниже.
  }
  try {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    area.remove();
    return ok;
  } catch {
    return false;
  }
}
