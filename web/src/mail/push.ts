/*
  Push на пользователя, не на вкладку (WEB-03): вкладки одного клиента выбирают лидера (BroadcastChannel,
  земля auth/store — решение 2026-11-20 §1.2); WebSocket RFC 8887 (`/jmap/ws` из капабилити сессии,
  подпротокол jmap) открыт только у лидера, события `StateChange` тиражируются вкладкам по каналу.
  Fallback: EventSource (`eventSourceUrl` сессии) у лидера; если push недоступен вовсе — таймер
  delta-sync (вкладки перечитывают `/changes` — живое состояние с задержкой).

  Аутентификация push из браузера: браузер не ставит заголовки на WebSocket и EventSource, а сервер
  проверяет только Authorization (`tp-jmap/core/http.rs`). Клиент передаёт токен OIDC параметром
  `access_token` (обычная практика браузерных SSE/WS); пока сервер его не принимает, соединение
  получит отказ и клиент уйдёт в таймер — вопрос серверу (cookie или параметр) оформлен issue.
  Пароль приложения в query не передаётся — для Basic-сессий push не стартует, только таймер.

  Переподключения — с экспоненциальной паузой (предел 60 с); после неудач — EventSource, затем
  таймер; попытки push повторяются раз в 5 минут (сервер мог включить поддержку).
*/

/** Типовое сообщение канала вкладок push (отдельный канал — не мешает сессии auth/store). */
export type PushMessage =
  | { type: "hello"; from: string }
  | { type: "alive"; from: string }
  | { type: "bye"; from: string }
  | { type: "state"; from: string; change: StateChange }
  | { type: "poll"; from: string };

/** Канал (подменяется в тестах; без BroadcastChannel клиент живёт одной вкладкой). */
export interface PushChannel {
  postMessage(message: PushMessage): void;
  close(): void;
  onmessage: ((event: { data: PushMessage }) => void) | null;
}

/** `StateChange` (RFC 8620 §7.1): состояния типов по учётным записям. */
export interface StateChange {
  "@type": string;
  changed: Record<string, Record<string, string | null>>;
}

/** Событие подписчику: изменение от push или синтетический тик таймера (delta-sync — в queries). */
export type PushEvent = { kind: "state"; change: StateChange } | { kind: "poll" };

/** Данные транспорта на момент (пере)подключения: свежая сессия и токен. */
export interface PushSource {
  /** Адрес WS из капабилити `urn:ietf:params:jmap:websocket`; null — нет. */
  wsUrl: string | null;
  /** `eventSourceUrl` сессии (шаблон RFC 8620 §7.3); null — нет. */
  eventSourceUrl: string | null;
  /** Свежий токен OIDC для `?access_token=`; null (Basic) — push из браузера недоступен. */
  accessToken: string | null;
}

/** Состояние соединения — для строки состояния и отладки. */
export type PushStatus = "off" | "connecting" | "live" | "poll";

/** Экспоненциальная пауза переподключения: 1, 2, 4 … с, предел. */
const BACKOFF_BASE_MS = 1_000;
const BACKOFF_MAX_MS = 60_000;
/** Повтор попыток push после перехода на таймер. */
const RETRY_PUSH_MS = 5 * 60_000;

function makeChannel(name: string): PushChannel | null {
  try {
    return new BroadcastChannel(name) as PushChannel;
  } catch {
    return null; // Нет BroadcastChannel (старый браузер): вкладка одна и всегда лидер.
  }
}

/** Хаб push вкладки: выбор лидера, один транспорт, тиражирование `StateChange` вкладкам. */
export class PushHub {
  /** Идентификатор вкладки: время старта (старейший — лидер) + случайная добавка; подменяется в тестах. */
  readonly id: string;

  private readonly channel: PushChannel | null;
  private readonly heartbeatMs: number;
  private readonly peerTimeoutMs: number;
  private readonly pollMs: number;
  private readonly peers = new Map<string, { seen: number }>();
  private readonly listeners = new Set<(event: PushEvent) => void>();
  private readonly timers: number[] = [];

  private getSource: (() => PushSource) | null = null;
  private ws: WebSocket | null = null;
  private source: EventSource | null = null;
  /** Какой транспорт сейчас подключается — для счётчика отказов. */
  private transport: "ws" | "es" | null = null;
  private status: PushStatus = "off";
  private backoffMs = BACKOFF_BASE_MS;
  private wsFailures = 0;
  private esFailures = 0;
  private lastChange: StateChange | null = null;

  constructor(
    options: { id?: string; channel?: PushChannel | null; heartbeatMs?: number; peerTimeoutMs?: number; pollMs?: number } = {},
  ) {
    this.id = options.id ?? `push-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    this.channel = options.channel ?? makeChannel("thepost-webmail-push");
    this.heartbeatMs = options.heartbeatMs ?? 5_000;
    this.peerTimeoutMs = options.peerTimeoutMs ?? 15_000;
    this.pollMs = options.pollMs ?? 30_000;
    if (this.channel) {
      this.channel.onmessage = (event) => this.receive(event.data);
    }
  }

  /** Подписка на события push; возвращает отписку. */
  subscribe(listener: (event: PushEvent) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  /** Последний полученный `StateChange` — для отладки и первичной сверке вкладок. */
  get lastState(): StateChange | null {
    return this.lastChange;
  }

  /** Состояние соединения вкладки: лидер с живым push — live, без — poll. */
  get pushStatus(): PushStatus {
    return this.status;
  }

  /** Запуск: жизнь вкладок, выбор лидера, транспорт у лидера. */
  start(getSource: () => PushSource): void {
    this.getSource = getSource;
    this.send({ type: "hello", from: this.id });
    this.tick();
    this.timers.push(
      window.setInterval(() => this.tick(), this.heartbeatMs),
      // Синтетический тик у всех вкладок: delta-sync и без push (живая почта с задержкой).
      window.setInterval(() => this.emit({ kind: "poll" }), this.pollMs),
    );
  }

  /** Остановка: транспорт, таймеры, канал. */
  stop(): void {
    this.send({ type: "bye", from: this.id });
    for (const t of this.timers) window.clearInterval(t);
    this.timers.length = 0;
    this.closeTransport();
    this.status = "off";
    this.channel?.close();
    this.listeners.clear();
  }

  /** Сигнал жизни: мусор по соседям, смена лидера, транспорт — у лидера. */
  private tick(): void {
    const now = Date.now();
    this.peers.set(this.id, { seen: now });
    for (const [id, peer] of this.peers) {
      if (id !== this.id && now - peer.seen > this.peerTimeoutMs) this.peers.delete(id);
    }
    this.send({ type: "alive", from: this.id });
    const isLeader = this.leaderId() === this.id;
    if (isLeader && this.status === "off") {
      this.connectPush();
    } else if (!isLeader && this.status !== "off") {
      this.closeTransport();
      this.status = "off";
    }
  }

  /** Лидер — старейшая живая вкладка (стабильный порядок id, как в auth/store). */
  private leaderId(): string {
    const now = Date.now();
    const ids = [...this.peers.entries()]
      .filter(([, p]) => now - p.seen <= this.peerTimeoutMs)
      .map(([id]) => id)
      .sort();
    return ids[0] ?? this.id;
  }

  /** Подключение push: WebSocket → EventSource → таймер; каждая ступень — с одной попыткой,
   * отказ — экспоненциальная пауза и следующая ступень. */
  private connectPush(): void {
    const src = this.getSource?.();
    if (!src) return;
    this.status = "connecting";
    if (src.wsUrl && src.accessToken && this.wsFailures === 0) {
      this.transport = "ws";
      this.openWebSocket(src.wsUrl, src.accessToken);
      return;
    }
    if (src.eventSourceUrl && src.accessToken && this.esFailures === 0) {
      this.transport = "es";
      this.openEventSource(src.eventSourceUrl, src.accessToken);
      return;
    }
    this.status = "poll";
    // Раз в RETRY_PUSH_MS — снова попытка push (сервер мог включить поддержку access_token).
    this.timers.push(
      window.setTimeout(() => {
        this.wsFailures = 0;
        this.esFailures = 0;
        this.backoffMs = BACKOFF_BASE_MS;
        if (this.leaderId() === this.id) this.connectPush();
      }, RETRY_PUSH_MS),
    );
  }

  private openWebSocket(wsUrl: string, accessToken: string): void {
    const url = `${wsUrl}${wsUrl.includes("?") ? "&" : "?"}access_token=${encodeURIComponent(accessToken)}`;
    let ws: WebSocket;
    try {
      ws = new WebSocket(url, ["jmap"]);
    } catch {
      this.failTransport();
      return;
    }
    this.ws = ws;
    ws.onopen = () => {
      // RFC 8887 §2: включение push — не Request, отдельный тип сообщения.
      ws.send(JSON.stringify({ "@type": "WebSocketPushEnable", dataTypes: ["Email", "Thread", "Mailbox"] }));
      this.transport = null;
      this.status = "live";
      this.backoffMs = BACKOFF_BASE_MS;
    };
    ws.onmessage = (event) => this.handlePushPayload(event.data as string);
    ws.onclose = () => {
      if (this.ws === ws) {
        this.ws = null;
        this.failTransport();
      }
    };
    ws.onerror = () => {
      // Отказ аутентификации/сети: закрытие вызовет failTransport.
    };
  }

  private openEventSource(eventSourceUrl: string, accessToken: string): void {
    // Шаблон eventSourceUrl (RFC 8620 §7.3): типы почты, поток держим открытым, ping раз в 4 минуты.
    const url = eventSourceUrl
      .replace("{types}", "Email,Thread,Mailbox")
      .replace("{closeafter}", "no")
      .replace("{ping}", "240");
    const full = `${url}${url.includes("?") ? "&" : "?"}access_token=${encodeURIComponent(accessToken)}`;
    let source: EventSource;
    try {
      source = new EventSource(full);
    } catch {
      this.failTransport();
      return;
    }
    this.source = source;
    source.addEventListener("state", (event) => this.handlePushPayload((event as MessageEvent).data as string));
    source.onerror = () => {
      // Отказ (аутентификация/сеть): дальше — своя экспоненциальная пауза, не автоповтор браузера.
      if (this.source === source) {
        this.source = null;
        this.failTransport();
      }
    };
    source.onopen = () => {
      this.transport = null;
      this.status = "live";
      this.backoffMs = BACKOFF_BASE_MS;
    };
  }

  private handlePushPayload(text: string): void {
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      return;
    }
    const change = value as StateChange;
    if (change["@type"] !== "StateChange") return; // Response/RequestError — не события изменений.
    this.lastChange = change;
    this.emit({ kind: "state", change });
    this.send({ type: "state", from: this.id, change });
  }

  /** Неудача транспорта: счётчик отказов, пауза и следующая ступень (WS → EventSource → таймер). */
  private failTransport(): void {
    if (this.transport === "ws") this.wsFailures += 1;
    if (this.transport === "es") this.esFailures += 1;
    this.transport = null;
    this.closeTransport();
    this.status = "off";
    this.timers.push(
      window.setTimeout(() => {
        if (this.leaderId() === this.id) this.connectPush();
      }, this.backoffMs),
    );
    this.backoffMs = Math.min(this.backoffMs * 2, BACKOFF_MAX_MS);
  }

  private closeTransport(): void {
    const ws = this.ws;
    this.ws = null;
    if (ws) {
      ws.onclose = null;
      ws.onerror = null;
      ws.onmessage = null;
      try {
        ws.close();
      } catch {
        // Уже закрыт.
      }
    }
    const source = this.source;
    this.source = null;
    if (source) {
      source.onopen = null;
      source.onerror = null;
      source.close();
    }
  }

  /** Событие подписчикам вкладки (и от транспорта лидера, и от канала). */
  private emit(event: PushEvent): void {
    for (const listener of this.listeners) listener(event);
  }

  private send(message: PushMessage): void {
    try {
      this.channel?.postMessage(message);
    } catch {
      // Канал уже закрыт: сообщения больше не нужны.
    }
  }

  private receive(message: PushMessage): void {
    if (message.from === this.id) return;
    this.peers.set(message.from, { seen: Date.now() });
    switch (message.type) {
      case "state":
        this.lastChange = message.change;
        this.emit({ kind: "state", change: message.change });
        break;
      case "bye":
        this.peers.delete(message.from);
        break;
      case "hello":
      case "alive":
      case "poll":
        break;
    }
  }
}
