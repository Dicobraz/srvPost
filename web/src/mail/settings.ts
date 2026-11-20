/*
  Настройки чтения (WEB-03, минимум до WEB-14): плотность списка — «обычная с превью» по умолчанию
  (решение владельца 20.11), «компактная» — переключается; вид потока — «группировка» по умолчанию
  (решение владельца), «в списке, как в Outlook» и «стопка в панели чтения» — останутся в настройках.
  Выбор — localStorage (тема — theme.ts, WEB-01; раскладка RU/EN не мешает хоткеям — keymap.ts).
*/

/** Плотность списка. */
export type Density = "normal" | "compact";

/** Вид списка: группировка потоков или плоский список («как в Outlook»). */
export type ThreadView = "grouped" | "outlook";

const DENSITY_KEY = "thepost-webmail-density";
const VIEW_KEY = "thepost-webmail-threads";

function load<T extends string>(key: string, allowed: T[], fallback: T): T {
  try {
    const value = localStorage.getItem(key);
    return allowed.includes(value as T) ? (value as T) : fallback;
  } catch {
    return fallback;
  }
}

function save(key: string, value: string): void {
  try {
    localStorage.setItem(key, value);
  } catch {
    // Приватный режим без localStorage: выбор живёт до перезагрузки страницы.
  }
}

/** Плотность списка: по умолчанию обычная с превью (решение владельца 20.11). */
export function loadDensity(): Density {
  return load(DENSITY_KEY, ["normal", "compact"], "normal");
}

export function saveDensity(density: Density): void {
  save(DENSITY_KEY, density);
}

/** Вид потока: по умолчанию группировка (решение владельца 20.11). */
export function loadThreadView(): ThreadView {
  return load(VIEW_KEY, ["grouped", "outlook"], "grouped");
}

export function saveThreadView(view: ThreadView): void {
  save(VIEW_KEY, view);
}
