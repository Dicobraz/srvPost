// Вход OIDC (WEB-02, решение 2026-11-20): authorization code + PKCE из SPA — как в веб-консоли
// (`console/src/providers/auth.ts`), но сессию держит сама вкладка: токены не обмениваются на
// серверную сессию, JMAP принимает Bearer напрямую. Тихий renew — refresh-токеном (скрытый iframe
// не нужен: CSP `frame-src` не расширяется); state с маршрутом — возврат на ту же страницу после
// редиректа поставщика (перевход без потери route).
import { UserManager, WebStorageStateStore, type User } from "oidc-client-ts";

import type { OidcConfig } from "../config";
import type { OidcTokens } from "./store";

/** Маршрут в state редиректа: после callback возвращаемся туда, откуда ушли на вход. */
interface RedirectState {
  route: string;
}

/** Маршрут callback-страницы (у поставщика — redirect_uri). */
export function callbackUri(): string {
  return `${location.origin}${import.meta.env.BASE_URL}callback`;
}

/** UserManager по конфигурации узла: state и user — в sessionStorage (перезагрузка не разлогинивает,
 * localStorage не используется). */
export function userManager(config: OidcConfig): UserManager {
  return new UserManager({
    authority: config.issuer,
    client_id: config.client_id,
    scope: config.scope,
    redirect_uri: callbackUri(),
    response_type: "code", // authorization code + PKCE
    userStore: new WebStorageStateStore({ store: sessionStorage }),
  });
}

/** Токены пользователя для store: конец жизни — мс от эпохи (у oidc-client-ts — секунды). */
export function toTokens(user: User): OidcTokens {
  return {
    accessToken: user.access_token,
    expiresAt: (user.expires_at ?? 0) * 1000,
    idToken: user.id_token ?? null,
  };
}

/** Вход: редирект на поставщика с маршрутом возврата в state. */
export async function signin(manager: UserManager, route: string): Promise<void> {
  const state: RedirectState = { route };
  await manager.signinRedirect({ state: JSON.stringify(state) });
}

/** Завершение входа (callback): токены + маршрут возврата из state. */
export async function signinCallback(manager: UserManager): Promise<{ tokens: OidcTokens; route: string }> {
  const user = await manager.signinRedirectCallback();
  let route = "/";
  try {
    const state = JSON.parse(String(user.state)) as Partial<RedirectState>;
    if (typeof state.route === "string" && state.route.startsWith("/")) route = state.route;
  } catch {
    // state не наш (не строка с маршрутом) — вернёмся в начало.
  }
  return { tokens: toTokens(user), route };
}

/** Тихий renew по refresh-токену (если поставщик его выдал); иначе ошибка — дальше перевход. */
export async function signinSilent(manager: UserManager): Promise<OidcTokens> {
  const user = await manager.signinSilent();
  if (!user) throw new Error("Тихий продление сессии не вернул токен.");
  return toTokens(user);
}

/** Маршрут из id_token (email / preferred_username / sub) — только для показа имени в шапке. */
export function nameFromIdToken(idToken: string | null): string | null {
  if (!idToken) return null;
  const payload = idToken.split(".")[1];
  if (!payload) return null;
  try {
    // base64url → обычный base64 (запас), байты → текст; только чтение для имени.
    const bytes = Uint8Array.from(atob(payload.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
    const claims = JSON.parse(new TextDecoder().decode(bytes)) as {
      email?: string;
      preferred_username?: string;
      sub?: string;
    };
    return claims.email ?? claims.preferred_username ?? claims.sub ?? null;
  } catch {
    return null;
  }
}

/** Адрес выхода «везде» из конфигурации узла: end_session + id_token_hint + возврат на клиента. */
export function endSessionUrl(config: OidcConfig, idToken: string | null): URL {
  const url = new URL(config.end_session ?? "");
  if (idToken) url.searchParams.set("id_token_hint", idToken);
  url.searchParams.set("post_logout_redirect_uri", `${location.origin}${import.meta.env.BASE_URL}`);
  return url;
}

/** Выход «везде»: end session поставщика (id_token_hint), с возвратом на страницу клиента. */
export async function signout(
  manager: UserManager,
  tokens: OidcTokens,
  config: OidcConfig,
  navigate: (url: string) => void = (url) => location.assign(url),
): Promise<void> {
  try {
    // Адрес выхода из discovery поставщика; без него — исключение, ниже запасной адрес конфигурации.
    await manager.signoutRedirect({
      id_token_hint: tokens.idToken ?? undefined,
      post_logout_redirect_uri: `${location.origin}${import.meta.env.BASE_URL}`,
    });
    return;
  } catch {
    // Discovery не отдал end_session_endpoint.
  }
  if (config.end_session) navigate(endSessionUrl(config, tokens.idToken).toString());
}
