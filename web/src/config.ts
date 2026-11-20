// Конфигурация входа (WEB-02): `/mail/config.json` отдаёт узел (`crates/tp-webmail`) из секции
// `modules.webmail` — только публичные сведения (issuer/client_id/scope поставщика OIDC, флаг
// входа по паролю приложения); секретов в конфигурации нет и быть не может: страница публичная.
export interface OidcConfig {
  /** Адрес поставщика (discovery issuer). */
  issuer: string;
  /** Идентификатор публичного клиента (PKCE — без секрета). */
  client_id: string;
  /** Запрашиваемые области. */
  scope: string;
  /** Адрес выхода «везде», если discovery поставщика его не отдаёт. */
  end_session: string | null;
}

export interface MailConfig {
  /** Поставщик OIDC; нет — вход только по паролю приложения. */
  oidc: OidcConfig | null;
  /** Форма «логин + пароль приложения» (без OIDC — всегда). */
  basic: boolean;
}

/** Конфигурация рядом со страницей: каталог сборки (`base` Vite; в тестах — корень). */
export function configUrl(): string {
  return `${import.meta.env.BASE_URL}config.json`;
}

/** Человекочитаемое сообщение об ошибке входа: подробности в консоль, текст — пользователю. */
export function humanError(e: unknown): string {
  if (e instanceof Error && e.message) return e.message;
  return "Вход не выполнен: неизвестная ошибка (подробности в консоли браузера).";
}

/** Загружает конфигурацию входа; ошибка — человекочитаемая (экран входа покажет её inline). */
export async function loadMailConfig(): Promise<MailConfig> {
  let response: Response;
  try {
    response = await fetch(configUrl(), { headers: { Accept: "application/json" } });
  } catch {
    throw new Error("Узел недоступен: не удалось получить конфигурацию входа.");
  }
  if (!response.ok) {
    throw new Error(
      response.status === 404
        ? "Узел не отдал конфигурацию входа (/mail/config.json) — веб-клиент выключен?"
        : `Конфигурация входа не получена: HTTP ${response.status}.`,
    );
  }
  const type = response.headers.get("Content-Type") ?? "";
  if (!type.includes("json")) {
    throw new Error(`Конфигурация входа: ожидается JSON, получено ${type || "без типа"}.`);
  }
  const body = (await response.json()) as MailConfig;
  if (body.oidc && (!body.oidc.issuer || !body.oidc.client_id)) {
    throw new Error("Конфигурация входа: в поставщике OIDC нет issuer или client_id.");
  }
  if (!body.oidc && !body.basic) {
    throw new Error("Конфигурация входа: ни OIDC, ни вход по паролю приложения не включены.");
  }
  return body;
}
