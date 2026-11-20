// Push на пользователя (WEB-03): лидер вкладок — один WebSocket RFC 8887 на пользователя, события
// тиражируются вкладкам по BroadcastChannel; отказ WS — EventSource, без push — таймер.
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { PushHub, type PushChannel, type PushEvent, type PushMessage, type PushSource } from "./push";

/** Подмены браузерных WebSocket и EventSource: соединения и их события — руками. */
class MockWebSocket {
  static instances: MockWebSocket[] = [];
  url: string;
  protocol: string | undefined;
  sent: string[] = [];
  opened = false;
  closed = false;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string, protocols?: string | string[]) {
    this.url = url;
    this.protocol = Array.isArray(protocols) ? protocols[0] : protocols;
    MockWebSocket.instances.push(this);
  }
  send(data: string): void {
    this.sent.push(data);
  }
  close(): void {
    this.closed = true;
    this.onclose?.();
  }
  open(): void {
    this.opened = true;
    this.onopen?.();
  }
}

class MockEventSource {
  static instances: MockEventSource[] = [];
  url: string;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  private listeners = new Map<string, Array<(event: { data: string }) => void>>();
  constructor(url: string) {
    this.url = url;
    MockEventSource.instances.push(this);
  }
  addEventListener(type: string, cb: (event: { data: string }) => void): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), cb]);
  }
  emit(type: string, data: string): void {
    for (const cb of this.listeners.get(type) ?? []) cb({ data });
  }
  close(): void {
    this.onopen = null;
    this.onerror = null;
  }
}

const SOURCE: PushSource = {
  wsUrl: "wss://node.example/jmap/ws",
  eventSourceUrl: "https://node.example/jmap/eventsource/?types={types}&closeafter={closeafter}&ping={ping}",
  accessToken: "acc-1",
};

const STATE_CHANGE = {
  "@type": "StateChange",
  changed: { acc1: { Email: "s1", Mailbox: "m1" } },
};

beforeEach(() => {
  MockWebSocket.instances = [];
  MockEventSource.instances = [];
  vi.useFakeTimers();
  vi.stubGlobal("WebSocket", MockWebSocket);
  vi.stubGlobal("EventSource", MockEventSource);
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

/** Связанные каналы вкладок одного клиента: сообщение получают все, кроме отправителя. */
function makeChannelPair(): PushChannel[] {
  const channels: Array<{
    onmessage: ((event: { data: PushMessage }) => void) | null;
  }> = [];
  const make = (): PushChannel => {
    const ch: PushChannel = {
      onmessage: null,
      postMessage: (message: PushMessage) => {
        for (const other of channels) {
          if (other !== ch) other.onmessage?.({ data: structuredClone(message) });
        }
      },
      close: () => {
        const index = channels.indexOf(ch);
        if (index >= 0) channels.splice(index, 1);
      },
    };
    channels.push(ch);
    return ch;
  };
  return [make(), make()];
}

/** Две связанные вкладки: лидер — старейшая (id по времени старта). */
function twoHubs(eventsLeader?: PushEvent[], eventsPeer?: PushEvent[]): [PushHub, PushHub] {
  const [channelA, channelB] = makeChannelPair();
  const leader = new PushHub({ id: "push-1-aaa", channel: channelA, heartbeatMs: 20, pollMs: 600_000 });
  const peer = new PushHub({ id: "push-2-bbb", channel: channelB, heartbeatMs: 20, pollMs: 600_000 });
  if (eventsLeader) leader.subscribe((e) => eventsLeader.push(e));
  if (eventsPeer) peer.subscribe((e) => eventsPeer.push(e));
  return [leader, peer];
}

function hubWith(events?: PushEvent[]): PushHub {
  return twoHubs(events)[0];
}

test("лидер вкладок открывает WebSocket RFC 8887 один на пользователя", () => {
  const hub = hubWith();
  hub.start(() => SOURCE);
  const ws = MockWebSocket.instances[0];
  expect(ws.url).toContain("wss://node.example/jmap/ws");
  expect(ws.url).toContain("access_token=acc-1");
  expect(ws.protocol).toBe("jmap");
  ws.open();
  // Включение push — WebSocketPushEnable с типами почты (RFC 8887 §2).
  expect(JSON.parse(ws.sent[0])).toEqual({
    "@type": "WebSocketPushEnable",
    dataTypes: ["Email", "Thread", "Mailbox"],
  });
  expect(hub.pushStatus).toBe("live");
  hub.stop();
});

test("StateChange от сервера: событие подписчику и тираж соседней вкладке без своего соединения", () => {
  const leaderEvents: PushEvent[] = [];
  const peerEvents: PushEvent[] = [];
  const [leader, peer] = twoHubs(leaderEvents, peerEvents);
  leader.start(() => SOURCE);
  peer.start(() => SOURCE);
  vi.advanceTimersByTime(30); // сигналы жизни: старейшая — лидер, сосед закрыл лишнюю попытку

  const ws = MockWebSocket.instances[0]; // соединение лидера
  ws.open();
  ws.onmessage!({ data: JSON.stringify(STATE_CHANGE) });
  expect(leaderEvents).toHaveLength(1);
  expect(peerEvents).toHaveLength(1);
  const received = peerEvents[0];
  expect(received?.kind).toBe("state");
  if (received?.kind === "state") {
    expect(received.change["@type"]).toBe("StateChange");
  }
  leader.stop();
  peer.stop();
});

test("отказ WS — EventSource с типами почты; событие state — подписчикам", () => {
  const events: PushEvent[] = [];
  const hub = hubWith(events);
  hub.start(() => SOURCE);
  MockWebSocket.instances[0].close(); // сервер закрыл WS
  vi.advanceTimersByTime(1_100); // экспоненциальная пауза — следующая ступень
  const es = MockEventSource.instances[0];
  expect(es.url).toContain("types=Email,Thread,Mailbox");
  expect(es.url).toContain("closeafter=no");
  es.onopen!();
  expect(hub.pushStatus).toBe("live");
  es.emit("state", JSON.stringify(STATE_CHANGE));
  expect(events).toHaveLength(1);
  hub.stop();
});

test("push недоступен вовсе (Basic-сессия) — таймер delta-sync", () => {
  const events: PushEvent[] = [];
  const hub = hubWith(events);
  hub.start(() => ({ wsUrl: null, eventSourceUrl: null, accessToken: null }));
  expect(hub.pushStatus).toBe("poll");
  vi.advanceTimersByTime(600_000);
  expect(events.some((e) => e.kind === "poll")).toBe(true);
  hub.stop();
});

test("лидер уходит — сосед сам открывает соединение", () => {
  const [leader, peer] = twoHubs();
  leader.start(() => SOURCE);
  peer.start(() => SOURCE);
  vi.advanceTimersByTime(30);
  const before = MockWebSocket.instances.length;

  leader.stop(); // соседи узнают сразу (bye)
  vi.advanceTimersByTime(30);
  expect(MockWebSocket.instances.length).toBe(before + 1); // бывший сосед стал лидером
  peer.stop();
});

test("не-JSON и не StateChange — подписчикам ничего", () => {
  const events: PushEvent[] = [];
  const hub = hubWith(events);
  hub.start(() => SOURCE);
  const ws = MockWebSocket.instances[0];
  ws.open();
  ws.onmessage!({ data: "не JSON" });
  ws.onmessage!({ data: JSON.stringify({ "@type": "Response" }) });
  expect(events).toHaveLength(0);
  hub.stop();
});
