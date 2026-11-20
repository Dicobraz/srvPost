// Клиент JMAP (WEB-02 — заготовка на волны 3+): same-origin запросы с заголовком Authorization —
// `Bearer` (OIDC-токен SPA) или `Basic` (логин + пароль приложения); сервер проверяет оба
// (`tp-jmap/core/http.rs`). Проверка пароля приложения — `GET /jmap/session`: сессия JMAP и есть
// ответ сервера; 401 — неверная пара. Расширяют карточки WEB-03+ (запросы API, блобы, push).

import type { Session } from "../auth/store";

/** `/.well-known/jmap` — объект сессии JMAP; проверка пары «логин + пароль приложения». */
export const JMAP_SESSION = "/.well-known/jmap";

/** base64 UTF-8 (`btoa` не берёт кириллицу — имя входа бывает русским). */
function base64Utf8(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

/** Заголовок `Basic` из пары «логин + пароль приложения». */
export function basicCredentials(login: string, secret: string): string {
  return base64Utf8(`${login}:${secret}`);
}

/** Заголовок Authorization сессии: OIDC — Bearer, пароль приложения — Basic; нет сессии — null. */
export function authHeader(session: Session | null): string | null {
  if (!session) return null;
  return session.kind === "oidc"
    ? `Bearer ${session.accessToken}`
    : `Basic ${basicCredentials(session.login, session.secret)}`;
}

/** Запрос к JMAP того же узла с Authorization; ответ отдаётся как есть (401 обрабатывает вызывающий). */
export async function jmapFetch(
  path: string,
  init?: RequestInit,
  authorization?: string | null,
): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (authorization) headers.set("Authorization", authorization);
  return fetch(path, { ...init, headers });
}

export interface JmapError {
  /** HTTP-статус ответа. */
  status: number;
  /** Человекочитаемый текст для экрана входа. */
  message: string;
}

/** Проверка пары «логин + пароль приложения» на `/jmap/session`; ошибка — человекочитаемая. */
export async function verifyBasic(
  login: string,
  secret: string,
): Promise<JmapError | null> {
  let response: Response;
  try {
    response = await jmapFetch(JMAP_SESSION, undefined, basicCredentials(login, secret));
  } catch {
    return { status: 0, message: "Узел недоступен: проверьте соединение и попробуйте ещё раз." };
  }
  if (response.ok) return null;
  return {
    status: response.status,
    message:
      response.status === 401 || response.status === 403
        ? "Неверное имя входа или пароль приложения."
        : `Узел ответил ошибкой HTTP ${response.status}.`,
  };
}
