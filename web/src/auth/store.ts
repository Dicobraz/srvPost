// Состояние входа веб-клиента (WEB-02) — маленький store поверх BroadcastChannel: одна вкладка
// renew'ит токен OIDC (выбор — старейшая живая вкладка с OIDC-сессией), остальные подхватывают
// (земля для «один WebSocket на пользователя», WEB-03). Пароль приложения живёт только в памяти
// вкладки: ни sessionStorage, ни BroadcastChannel его не покидают; токены OIDC — в sessionStorage
// (перезагрузка страницы не разлогинивает) и рассылаются вкладкам.

/** Канал вкладок одного клиента (same-origin). */
export const CHANNEL = "thepost-webmail";

/** Токены OIDC: access — JMAP-запросы, id — выход «везде» (end session), expiresAt — мс от эпохи. */
export interface OidcTokens {
  accessToken: string;
  expiresAt: number;
  idToken: string | null;
}

/** Сессия вкладки: OIDC (общая между вкладками) или пара «логин + пароль приложения» (только здесь). */
export type Session = ({ kind: "oidc" } & OidcTokens) | { kind: "basic"; login: string; secret: string };

/** Сообщения канала: рассылка токенов, выход, запрос сессии новой вкладкой, жизнь вкладок. */
export type AuthMessage =
  | { type: "session"; from: string; tokens: OidcTokens }
  | { type: "logout"; from: string }
  | { type: "request"; from: string }
  | { type: "heartbeat"; from: string; holds: string | null }
  | { type: "bye"; from: string };

/** Канал (подменяется в тестах; без BroadcastChannel клиент живёт одной вкладкой). */
export interface Channel {
  postMessage(message: AuthMessage): void;
  close(): void;
  onmessage: ((event: { data: AuthMessage }) => void) | null;
}

/** Тихий renew — за минуту до конца жизни токена. */
export const RENEW_BEFORE_MS = 60_000;
/** Вкладка молчит дольше — считается закрытой. */
export const PEER_TIMEOUT_MS = 15_000;
/** Частота сигналов жизни вкладок. */
export const HEARTBEAT_MS = 5_000;

/** Момент тихого renew: за RENEW_BEFORE_MS до конца жизни, но не в прошлом. */
export function renewAt(expiresAt: number, now: number): number {
  return Math.max(now, expiresAt - RENEW_BEFORE_MS);
}

/** Обновляющий: старейший из живых держателей OIDC-сессии (стабильный порядок — меньше гонок). */
export function leaderOf(
  peers: Map<string, { seen: number; holds: string | null }>,
  now: number,
): string | null {
  const alive = [...peers.entries()]
    .filter(([, p]) => p.holds === "oidc" && now - p.seen <= PEER_TIMEOUT_MS)
    .map(([id]) => id)
    .sort();
  return alive[0] ?? null;
}

function makeChannel(): Channel | null {
  try {
    return new BroadcastChannel(CHANNEL) as Channel;
  } catch {
    return null; // Нет BroadcastChannel (старый браузер): сессия живёт одной вкладкой.
  }
}

/** Состояние входа вкладки: сессия, подписки, соседи; канал — наружу и от соседей. */
export class AuthStore {
  /** Идентификатор вкладки: время старта (старейший — обновляющий) + случайная добавка;
   * тестам передаётся явный, чтобы порядок «старейшин» не зависел от совпадения миллисекунд. */
  readonly id: string;

  private session: Session | null = null;
  private readonly peers = new Map<string, { seen: number; holds: string | null }>();
  private readonly listeners = new Set<() => void>();
  private readonly channel: Channel | null;

  constructor(channel: Channel | null = makeChannel(), id?: string) {
    this.id = id ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    this.channel = channel;
    if (channel) {
      channel.onmessage = (event) => this.receive(event.data);
    }
  }

  /** Текущая сессия или null. */
  get(): Session | null {
    return this.session;
  }

  /** Подписка на смену сессии; возвращает отписку. */
  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Сессия OIDC: память, sessionStorage (перезагрузка), рассылка вкладкам. */
  loginOidc(tokens: OidcTokens): void {
    this.setOidc(tokens);
    this.send({ type: "session", from: this.id, tokens });
  }

  /** Подхват сессии от соседа (по каналу): без повторной рассылки — иначе эхо между вкладками. */
  adoptOidc(tokens: OidcTokens): void {
    this.setOidc(tokens);
  }

  private setOidc(tokens: OidcTokens): void {
    this.session = { kind: "oidc", ...tokens };
    this.save();
    this.notify();
  }

  /** Вход по паролю приложения: только память вкладки — пароль никуда не покидает её. */
  loginBasic(login: string, secret: string): void {
    this.session = { kind: "basic", login, secret };
    this.notify();
  }

  /** Восстановление после перезагрузки: токены OIDC из sessionStorage (пароль приложения — нет). */
  restore(): Session | null {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEY);
      if (!raw) return null;
      const tokens = JSON.parse(raw) as Partial<OidcTokens>;
      if (
        typeof tokens.accessToken !== "string" ||
        typeof tokens.expiresAt !== "number" ||
        !(tokens.idToken === null || typeof tokens.idToken === "string")
      ) {
        sessionStorage.removeItem(STORAGE_KEY);
        return null;
      }
      this.session = {
        kind: "oidc",
        accessToken: tokens.accessToken,
        expiresAt: tokens.expiresAt,
        idToken: tokens.idToken,
      };
      this.notify();
      return this.session;
    } catch {
      sessionStorage.removeItem(STORAGE_KEY);
      return null;
    }
  }

  /** Выход: память и sessionStorage; `broadcast` — вкладкам (выход «везде» — ниже, у поставщика). */
  clear(broadcast = false): void {
    this.session = null;
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      // Приватный режим без sessionStorage: выходить не из чего.
    }
    this.notify();
    if (broadcast) this.send({ type: "logout", from: this.id });
  }

  /** Новая вкладка просит соседей поделиться сессией OIDC (пароль приложения — не общее имущество). */
  requestSession(): void {
    this.send({ type: "request", from: this.id });
  }

  /** Сигнал жизни + сбор мусора по соседям; заодно решает, эта ли вкладка обновляет токен. */
  tick(now: number): boolean {
    this.peers.set(this.id, { seen: now, holds: this.session?.kind ?? null });
    for (const [id, peer] of this.peers) {
      if (id !== this.id && now - peer.seen > PEER_TIMEOUT_MS) this.peers.delete(id);
    }
    this.send({ type: "heartbeat", from: this.id, holds: this.session?.kind ?? null });
    return this.session?.kind === "oidc" && leaderOf(this.peers, now) === this.id;
  }

  /** Обновляющий ли эта вкладка (для тестов и решении renew по 401). */
  isRenewer(now: number): boolean {
    return this.session?.kind === "oidc" && leaderOf(this.peers, now) === this.id;
  }

  /** Канал закрыт (вкладка уходит): соседи узнают сразу, не дожидаясь тишины. */
  close(): void {
    this.send({ type: "bye", from: this.id });
    this.channel?.close();
    this.listeners.clear();
  }

  private save(): void {
    if (this.session?.kind !== "oidc") return;
    try {
      const { accessToken, expiresAt, idToken } = this.session;
      sessionStorage.setItem(STORAGE_KEY, JSON.stringify({ accessToken, expiresAt, idToken }));
    } catch {
      // Приватный режим без sessionStorage: сессия живёт до перезагрузки страницы.
    }
  }

  private notify(): void {
    for (const listener of this.listeners) listener();
  }

  private send(message: AuthMessage): void {
    try {
      this.channel?.postMessage(message);
    } catch {
      // Канал уже закрыт: сообщения больше не нужны.
    }
  }

  private receive(message: AuthMessage): void {
    if (message.from === this.id) return;
    const seen = Date.now();
    if (message.type === "bye") {
      this.peers.delete(message.from);
      return;
    }
    // Состояние соседа по типу сообщения: session — у него теперь OIDC, logout — сессии нет.
    const holds =
      message.type === "heartbeat"
        ? message.holds
        : message.type === "session"
          ? "oidc"
          : message.type === "logout"
            ? null
            : this.peers.get(message.from)?.holds ?? null;
    this.peers.set(message.from, { seen, holds });
    switch (message.type) {
      case "session":
        this.adoptOidc(message.tokens);
        break;
      case "logout":
        this.clear();
        break;
      case "request":
        // Своя сессия OIDC — делимся (пароль приложения чужой вкладке не передаётся никогда).
        if (this.session?.kind === "oidc") {
          const { accessToken, expiresAt, idToken } = this.session;
          this.send({ type: "session", from: this.id, tokens: { accessToken, expiresAt, idToken } });
        }
        break;
      case "heartbeat":
        break;
    }
  }
}

const STORAGE_KEY = "thepost-webmail-oidc";

/** Ключ sessionStorage с токенами OIDC (перезагрузка страницы; пароль приложения сюда не пишется). */
export function storageKey(): string {
  return STORAGE_KEY;
}
