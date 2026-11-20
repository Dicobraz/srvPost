// jsdom не реализует API, которые тема и React вызывают при отрисовке.
import { configure } from "@testing-library/dom";
import { vi } from "vitest";

configure({ asyncUtilTimeout: 10_000 });

if (typeof window !== "undefined") {
  window.matchMedia ??= (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    }) as unknown as MediaQueryList;
  globalThis.ResizeObserver ??= class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
  // BroadcastChannel (сессия между вкладками, WEB-02): jsdom не реализует — простой хаб в памяти,
  // себе не доставляет; close() убирает канал из хаба (изоляция тестов через cleanup RTL).
  if (typeof globalThis.BroadcastChannel === "undefined") {
    const channels = new Set<MockChannel>();
    class MockChannel {
      name: string;
      onmessage: ((event: { data: unknown }) => void) | null = null;
      constructor(name: string) {
        this.name = name;
        channels.add(this);
      }
      postMessage(data: unknown): void {
        for (const channel of channels) {
          if (channel !== this && channel.name === this.name) {
            channel.onmessage?.({ data: structuredClone(data) });
          }
        }
      }
      close(): void {
        channels.delete(this);
      }
    }
    globalThis.BroadcastChannel = MockChannel as unknown as typeof BroadcastChannel;
  }
}
