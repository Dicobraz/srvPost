/*
  История отправок (WEB-04): источник автодополнения получателей до WEB-07 (контакты и GAL
  придут с адресной книгой в вебе; в WebView история локальная — по отправленным, как в
  карточке WEB-04). Хранилище — localStorage (как выбор темы и плотности), запись — при
  успешной отправке: адрес и имя из полей Кому/Копия/Скрытая, 200 свежих.
*/

const HISTORY_KEY = "thepost-webmail-recipients";
const LIMIT = 200;

/** Запись истории: последний раз отправляли этому адресату. */
export interface HistoryEntry {
  email: string;
  name: string | null;
  at: string;
}

/** История отправок, свежие первыми; битые записи пропускаются. */
export function loadSendHistory(): HistoryEntry[] {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const list = raw ? (JSON.parse(raw) as unknown) : [];
    if (!Array.isArray(list)) return [];
    return list.filter(
      (x): x is HistoryEntry =>
        typeof x === "object" && x !== null &&
        typeof (x as HistoryEntry).email === "string" && (x as HistoryEntry).email.includes("@"),
    );
  } catch {
    return [];
  }
}

/** Запомнить получателей удачной отправки (без дублей, свежие в начало, LIMIT свежих). */
export function rememberSent(recipients: Array<{ name: string | null; email: string }>): void {
  if (recipients.length === 0) return;
  const now = new Date().toISOString();
  const seen = new Set<string>();
  const fresh = recipients
    .filter((r) => r.email.includes("@"))
    .map((r) => ({ email: r.email, name: r.name, at: now }))
    .filter((r) => {
      const key = r.email.toLowerCase();
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  const old = loadSendHistory().filter((h) => !seen.has(h.email.toLowerCase()));
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify([...fresh, ...old].slice(0, LIMIT)));
  } catch {
    // Приватный режим без localStorage: история живёт до перезагрузки страницы.
  }
}
