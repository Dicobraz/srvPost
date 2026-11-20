// Черновики (WEB-04): автосохранение с debounce — правки в окне перезапускают таймер,
// сохранение — Email/set create в Drafts, прежний черновик уничтожается после успешного
// создания; пустой снимок черновик уничтожает; ошибки — в строке состояния композера.
import { afterEach, beforeEach, describe, expect, test, vi } from "vitest";
import { emailSetCreate, emailSetDestroy } from "../api/jmap";
import type { JmapSession } from "../api/jmap";
import type { JmapEnv } from "../mail/types";
import { DRAFT_DEBOUNCE_MS, DraftSaver } from "./drafts";

vi.mock("../api/jmap", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/jmap")>();
  return { ...actual, emailSetCreate: vi.fn(), emailSetDestroy: vi.fn() };
});

const mockedCreate = vi.mocked(emailSetCreate);
const mockedDestroy = vi.mocked(emailSetDestroy);

const ENV: JmapEnv = {
  session: {} as JmapSession,
  apiUrl: "https://node.example/jmap/api",
  accountId: "acc1",
  authorization: "Bearer t",
  selfAddress: "user@example.org",
};

/** Сохранитель с папкой Drafts (в тестах папка известна сразу). */
function newSaver(): DraftSaver {
  const saver = new DraftSaver(ENV);
  saver.draftsMailboxId = "mb-drafts";
  return saver;
}

const SNAPSHOT = {
  from: { name: "Анна Антропова", email: "user@example.org" },
  to: [{ name: "Ольга", email: "o@vektor.example" }],
  cc: [],
  bcc: [],
  subject: "Договор поставки",
  bodyHtml: "<p>Вернули протокол разногласий.</p>",
  attachments: [],
};

beforeEach(() => {
  vi.useFakeTimers();
  mockedCreate.mockReset();
  mockedDestroy.mockReset();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("DraftSaver debounce", () => {
  test("правки в окне debounce перезапускают таймер — один запрос на паузу", async () => {
    mockedCreate.mockResolvedValue({ created: { d0: { id: "m1" } }, errors: {}, destroyed: [] });
    const saver = newSaver();
    saver.schedule(SNAPSHOT);
    vi.advanceTimersByTime(DRAFT_DEBOUNCE_MS - 200);
    saver.schedule({ ...SNAPSHOT, subject: "Договор поставки — протокол разногласий" });
    vi.advanceTimersByTime(DRAFT_DEBOUNCE_MS - 100);
    expect(mockedCreate).not.toHaveBeenCalled();
    vi.advanceTimersByTime(100);
    await vi.waitFor(() => expect(mockedCreate).toHaveBeenCalledTimes(1));
    const args = mockedCreate.mock.calls[0][3] as { create: Record<string, Record<string, unknown>> };
    expect(args.create.d0.subject).toBe("Договор поставки — протокол разногласий");
    expect(args.create.d0.mailboxIds).toEqual({ "mb-drafts": true });
    expect(args.create.d0.keywords).toEqual({ $draft: true, $seen: true });
    expect(args.create.d0.htmlBody).toEqual([{ partId: "body", type: "text/html" }]);
    expect(saver.draftId).toBe("m1");
  });

  test("второе сохранение создаёт новый черновик и уничтожает прежний", async () => {
    mockedCreate
      .mockResolvedValueOnce({ created: { d0: { id: "m1" } }, errors: {}, destroyed: [] })
      .mockResolvedValueOnce({ created: { d0: { id: "m2" } }, errors: {}, destroyed: [] });
    const saver = newSaver();
    saver.schedule(SNAPSHOT);
    await vi.advanceTimersByTimeAsync(DRAFT_DEBOUNCE_MS);
    saver.schedule({ ...SNAPSHOT, subject: "Уточнение" });
    await vi.advanceTimersByTimeAsync(DRAFT_DEBOUNCE_MS);
    await vi.waitFor(() => expect(mockedCreate).toHaveBeenCalledTimes(2));
    expect(mockedDestroy).toHaveBeenCalledWith(ENV.apiUrl, ENV.authorization, ENV.accountId, ["m1"]);
    expect(saver.draftId).toBe("m2");
  });

  test("падение создания — прежний черновик жив (destroy не вызван), ошибка в error", async () => {
    mockedCreate.mockResolvedValue({ created: {}, errors: { d0: { type: "invalidProperties" } }, destroyed: [] });
    const saver = newSaver();
    saver.schedule(SNAPSHOT);
    await vi.advanceTimersByTimeAsync(DRAFT_DEBOUNCE_MS);
    await vi.waitFor(() => expect(mockedCreate).toHaveBeenCalled());
    expect(saver.draftId).toBeNull();
    expect(saver.error).toContain("Черновик не сохранён");
    expect(mockedDestroy).not.toHaveBeenCalled();
  });

  test("пустой снимок (всё вычистено) — черновик уничтожается, новый не создаётся", async () => {
    mockedDestroy.mockResolvedValue({ destroyed: ["m1"], notDestroyed: {} });
    const saver = newSaver();
    saver.draftId = "m1";
    saver.schedule({ ...SNAPSHOT, to: [], subject: "", bodyHtml: "" });
    await vi.advanceTimersByTimeAsync(DRAFT_DEBOUNCE_MS);
    await vi.waitFor(() => expect(mockedDestroy).toHaveBeenCalledTimes(1));
    expect(mockedCreate).not.toHaveBeenCalled();
    expect(saver.draftId).toBeNull();
  });

  test("flush сохраняет сразу, без ожидания таймера («Сохранить черновик»)", async () => {
    mockedCreate.mockResolvedValue({ created: { d0: { id: "m9" } }, errors: {}, destroyed: [] });
    const saver = newSaver();
    saver.schedule(SNAPSHOT);
    await saver.flush();
    expect(mockedCreate).toHaveBeenCalledTimes(1);
    expect(saver.draftId).toBe("m9");
  });

  test("destroyCurrent: «Удалить черновик» — Email/set destroy", async () => {
    mockedDestroy.mockResolvedValue({ destroyed: ["m3"], notDestroyed: {} });
    const saver = newSaver();
    saver.draftId = "m3";
    await saver.destroyCurrent();
    expect(mockedDestroy).toHaveBeenCalledWith(ENV.apiUrl, ENV.authorization, ENV.accountId, ["m3"]);
    expect(saver.draftId).toBeNull();
  });
});
