// Store сессии (WEB-02): токены OIDC — между вкладками и в sessionStorage, пароль приложения —
// только в памяти вкладки; обновляющий (тихий renew) — старейшая живая вкладка с OIDC-сессией.
import { beforeEach, expect, test } from "vitest";

import {
  PEER_TIMEOUT_MS,
  RENEW_BEFORE_MS,
  AuthStore,
  leaderOf,
  renewAt,
  storageKey,
  type AuthMessage,
  type Channel,
  type OidcTokens,
} from "./store";

const TOKENS: OidcTokens = { accessToken: "acc-1", expiresAt: 5_000, idToken: "id-1" };

/** Фейковый канал с личным реестром: доставка подписчикам напрямую, себе — нет. */
class FakeChannel implements Channel {
  static readonly hub = new Set<FakeChannel>();
  readonly sent: AuthMessage[] = [];
  onmessage: ((event: { data: AuthMessage }) => void) | null = null;
  closed = false;
  constructor() {
    FakeChannel.hub.add(this);
  }
  postMessage(message: AuthMessage): void {
    this.sent.push(message);
    for (const peer of FakeChannel.hub) {
      if (peer !== this && !peer.closed) peer.onmessage?.({ data: structuredClone(message) });
    }
  }
  close(): void {
    this.closed = true;
    FakeChannel.hub.delete(this);
  }
}

beforeEach(() => {
  FakeChannel.hub.clear();
  sessionStorage.clear();
});

test("renewAt — за минуту до конца жизни, но не в прошлом", () => {
  expect(renewAt(1_500_000, 1_000_000)).toBe(1_500_000 - RENEW_BEFORE_MS);
  expect(renewAt(1_500_000, 1_490_000)).toBe(1_490_000);
});

test("leaderOf — старейший из живых держателей OIDC", () => {
  const peers = new Map([
    ["b", { seen: 0, holds: "oidc" }],
    ["a", { seen: 0, holds: "oidc" }],
    ["c", { seen: 0, holds: "oidc", }], // выходит из игры ниже
    ["d", { seen: 0, holds: "basic" }], // пароль приложения — не общий, renew не его забота
  ]);
  expect(leaderOf(peers, PEER_TIMEOUT_MS)).toBe("a");
  peers.delete("a");
  expect(leaderOf(peers, PEER_TIMEOUT_MS)).toBe("b");
  // Вкладка молчала дольше срока — не живая, лидера среди OIDC не осталось.
  peers.set("c", { seen: 0, holds: "oidc" });
  expect(leaderOf(peers, PEER_TIMEOUT_MS + 1)).toBeNull();
  const none = new Map([["x", { seen: 0, holds: null }]]);
  expect(leaderOf(none, 0)).toBeNull();
});

test("loginOidc: сессия, sessionStorage и рассылка соседям; loginBasic — только память вкладки", () => {
  const channel = new FakeChannel();
  const store = new AuthStore(channel);
  let notified = 0;
  store.subscribe(() => {
    notified += 1;
  });

  store.loginBasic("user@example.org", "app-secret");
  expect(store.get()).toEqual({ kind: "basic", login: "user@example.org", secret: "app-secret" });
  expect(notified).toBe(1);
  expect(channel.sent).toHaveLength(0); // пароль приложения не покидает вкладку
  expect(sessionStorage.getItem(storageKey())).toBeNull();

  store.loginOidc(TOKENS);
  expect(store.get()).toEqual({ kind: "oidc", ...TOKENS });
  expect(notified).toBe(2);
  expect(JSON.parse(sessionStorage.getItem(storageKey()) ?? "")).toEqual(TOKENS);
  // Соседям — только токены OIDC, без паролей: канал видел одну сессию.
  const messages = channel.sent.map((m) => m.type);
  expect(messages).toEqual(["session"]);
});

test("restore: перезагрузка подхватывает токены OIDC из sessionStorage", () => {
  sessionStorage.setItem(storageKey(), JSON.stringify(TOKENS));
  const restored = new AuthStore(null).restore();
  expect(restored).toEqual({ kind: "oidc", ...TOKENS });

  sessionStorage.setItem(storageKey(), "{битый json");
  expect(new AuthStore(null).restore()).toBeNull();
  expect(sessionStorage.getItem(storageKey())).toBeNull(); // битое значение убрано

  sessionStorage.setItem(storageKey(), JSON.stringify({ accessToken: 42 }));
  expect(new AuthStore(null).restore()).toBeNull();

  sessionStorage.setItem(storageKey(), JSON.stringify({ kind: "basic", login: "x", secret: "y" }));
  expect(new AuthStore(null).restore()).toBeNull(); // пароль приложения в sessionStorage не живёт
});

test("clear: память и sessionStorage; broadcast — соседям тоже", () => {
  const channel = new FakeChannel();
  const store = new AuthStore(channel);
  store.loginOidc(TOKENS);
  new AuthStore(new FakeChannel()); // сосед с каналом того же реестра

  store.clear();
  expect(store.get()).toBeNull();
  expect(sessionStorage.getItem(storageKey())).toBeNull();
  expect(channel.sent.filter((m) => m.type === "logout")).toHaveLength(0);

  store.loginOidc(TOKENS);
  store.clear(true);
  const logout = channel.sent.find((m) => m.type === "logout");
  expect(logout).toBeTruthy();
});

test("вторая вкладка подхватывает сессию и узнаёт о выходе; пароль приложения не передаётся", () => {
  const first = new AuthStore(new FakeChannel(), "tab-1-first");
  const second = new AuthStore(new FakeChannel(), "tab-2-second");

  first.loginOidc(TOKENS);
  expect(second.get()).toEqual({ kind: "oidc", ...TOKENS });

  first.clear(true);
  expect(second.get()).toBeNull();

  first.loginBasic("user@example.org", "app-secret");
  expect(second.get()).toBeNull(); // Basic-сессия — частная собственность вкладки

  second.requestSession();
  expect(first.get()).toEqual({ kind: "basic", login: "user@example.org", secret: "app-secret" });
  expect(second.get()).toBeNull(); // сосед с Basic не делится
});

test("новая вкладка получает сессию по запросу — без эха по каналу", () => {
  const first = new AuthStore(new FakeChannel());
  first.loginOidc(TOKENS);
  const newTab = new AuthStore(new FakeChannel());
  // first ответил на request — newTab подхватил; повторной рассылки нет (эхо кончилось).
  newTab.requestSession();
  expect(newTab.get()).toEqual({ kind: "oidc", ...TOKENS });
  const broadcasts = [...FakeChannel.hub].flatMap((c) => c.sent).filter((m) => m.type === "session");
  expect(broadcasts).toHaveLength(2); // вход и ответ на запрос — подхват по каналу не рассылается
});

test("tick выбирает обновляющего — ровно одна вкладка с OIDC сессией", () => {
  const a = new AuthStore(new FakeChannel(), "tab-1-a");
  const b = new AuthStore(new FakeChannel(), "tab-2-b");
  a.loginOidc(TOKENS); // b подхватил по каналу

  const now = 1_000_000;
  const aRenews = a.tick(now);
  const bRenews = b.tick(now);
  expect(aRenews).not.toBe(bRenews);
  expect(a.isRenewer(now)).toBe(aRenews);

  // Вкладка с паролем приложения обновляющим не бывает, даже одна.
  b.clear();
  b.loginBasic("user@example.org", "app-secret");
  b.tick(now);
  expect(b.isRenewer(now)).toBe(false);
});

test("закрывшаяся вкладка выпадает из соседей — обновление переезжает", () => {
  // Сосед должен существовать к моменту входа: иначе подхвата сессии не будет.
  const b = new AuthStore(new FakeChannel(), "tab-2-b");
  const a = new AuthStore(new FakeChannel(), "tab-1-a");
  a.loginOidc(TOKENS); // b подхватил по каналу
  const now = 500_000;
  a.tick(now);
  b.tick(now);
  const aWasLeader = a.isRenewer(now);
  const later = now + PEER_TIMEOUT_MS;
  if (aWasLeader) {
    a.close(); // bye — соседи узнают сразу
    expect(b.isRenewer(later)).toBe(true);
  } else {
    b.close();
    expect(a.isRenewer(later)).toBe(true);
  }
});
