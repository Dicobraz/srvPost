// Отправка и undo-send (WEB-04): один запрос Email/set + EmailSubmission/set (ссылка #e0),
// sendAt на окно undo при поддержке сервера, отмена update {undoStatus: canceled}, честные
// ошибки (forbiddenToSend, cannotUnsend — как SetError), запись истории получателей.
import { beforeEach, describe, expect, test, vi } from "vitest";
import { jmapCall, submissionSet } from "../api/jmap";
import type { SetResult } from "../api/jmap";
import type { JmapSession } from "../api/jmap";
import type { JmapEnv } from "../mail/types";
import type { ComposeSnapshot } from "./model";
import { UNDO_SEND_SECONDS, cancelSend, sendMessage, SendError, supportsUndoSend } from "./send";
import { rememberSent } from "./send-history";

vi.mock("../api/jmap", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../api/jmap")>();
  // jmapCall — запросы sendMessage; submissionSet — отмена отслеживает свой jmapCall изнутри
  // модуля (перепривязка экспортов его не меняет), поэтому мокается сам.
  return { ...actual, jmapCall: vi.fn(), submissionSet: vi.fn() };
});

const mocked = vi.mocked(jmapCall);
const mockedSubmissionSet = vi.mocked(submissionSet);

const ENV: JmapEnv = {
  session: {} as JmapSession,
  apiUrl: "https://node.example/jmap/api",
  accountId: "acc1",
  authorization: "Bearer t",
  selfAddress: "user@example.org",
};

const SNAPSHOT: ComposeSnapshot = {
  from: { name: "Анна Антропова", email: "user@example.org" },
  to: [{ name: "Ольга", email: "o@vektor.example" }],
  cc: [{ name: null, email: "k@thepost.example" }],
  bcc: [],
  subject: "Счёт № 419",
  bodyHtml: "<p>Счёт прилагаю.</p>",
  attachments: [
    { id: "a1", name: "счёт.pdf", size: 10, type: "application/pdf", status: "ready", progress: 1, blobId: "U123_1" },
    { id: "a2", name: "плохой.pdf", size: 10, type: "application/pdf", status: "error", progress: 0 },
  ],
};

type CreateObject = Record<string, Record<string, unknown>>;

/** Созданные объекты первого вызова Email/set и EmailSubmission/set запроса отправки. */
function createdOf(callIndex: number): { email: CreateObject; submission: CreateObject } {
  const methodCalls = mocked.mock.calls[callIndex][3] as Array<[string, Record<string, CreateObject>, string]>;
  return { email: methodCalls[0][1].create, submission: methodCalls[1][1].create };
}

function okResponses(submissionId = "s1") {
  return {
    methodResponses: [
      ["Email/set", { created: { e0: { id: "m1" } } }, "e"],
      ["EmailSubmission/set", { created: { s0: { id: submissionId } } }, "s"],
    ],
    sessionState: "1",
  } as unknown as Awaited<ReturnType<typeof jmapCall>>;
}

beforeEach(() => {
  mocked.mockReset();
  mockedSubmissionSet.mockReset();
  localStorage.clear();
});

describe("sendMessage", () => {
  test("создаёт письмо в «Отправленные» и отправку по ссылке #e0; с undo — sendAt на 15 с", async () => {
    mocked.mockResolvedValue(okResponses());
    const result = await sendMessage(ENV, SNAPSHOT, {
      sentMailboxId: "mb-sent",
      identityId: "I1",
      undoable: true,
    });
    expect(result).toMatchObject({ submissionId: "s1", undoable: true });
    expect(result.recipients.map((r) => r.email)).toEqual(["o@vektor.example", "k@thepost.example"]);

    const { email, submission } = createdOf(0);
    expect(email.e0.mailboxIds).toEqual({ "mb-sent": true });
    expect(email.e0.keywords).toEqual({ $seen: true });
    expect(email.e0.subject).toBe("Счёт № 419");
    expect(email.e0.from).toEqual([{ name: "Анна Антропова", email: "user@example.org" }]);
    expect(email.e0.to).toEqual([{ name: "Ольга", email: "o@vektor.example" }]);
    expect(email.e0.cc).toEqual([{ name: null, email: "k@thepost.example" }]);
    expect(email.e0.attachments).toHaveLength(1); // только загруженные
    expect((email.e0.attachments as Array<{ blobId?: string }>)[0]?.blobId).toBe("U123_1");

    expect(submission.s0.identityId).toBe("I1");
    expect(submission.s0.emailId).toBe("#e0");
    expect(new Date(submission.s0.sendAt as string).getTime() - Date.now()).toBeGreaterThan(
      (UNDO_SEND_SECONDS - 2) * 1000,
    );
    expect(mocked.mock.calls[0][2]).toEqual([
      "urn:ietf:params:jmap:core",
      "urn:ietf:params:jmap:mail",
      "urn:ietf:params:jmap:submission",
    ]);
  });

  test("без поддержки undo — немедленная отправка без sendAt; получатели — в историю", async () => {
    mocked.mockResolvedValue(okResponses());
    const result = await sendMessage(ENV, SNAPSHOT, {
      sentMailboxId: "mb-sent",
      identityId: "I1",
      undoable: false,
    });
    expect(result.undoable).toBe(false);
    const { submission } = createdOf(0);
    expect(submission.s0.sendAt).toBeUndefined();
    const history = JSON.parse(localStorage.getItem("thepost-webmail-recipients") ?? "[]") as Array<{ email: string }>;
    expect(history.map((h) => h.email)).toEqual(["o@vektor.example", "k@thepost.example"]);
  });

  test("ошибка Email/set → SendError с типом и текстом сервера", async () => {
    mocked.mockResolvedValue({
      methodResponses: [["Email/set", { notCreated: { e0: { type: "overQuota" } } }, "e"]],
      sessionState: "1",
    } as unknown as Awaited<ReturnType<typeof jmapCall>>);
    await expect(
      sendMessage(ENV, SNAPSHOT, { sentMailboxId: "mb", identityId: "I1", undoable: false }),
    ).rejects.toMatchObject({ type: "overQuota" });
  });

  test("отказ отправки (forbiddenToSend — Send As без права) — честная ошибка, письмо не теряется", async () => {
    mocked.mockResolvedValue({
      methodResponses: [
        ["Email/set", { created: { e0: { id: "m1" } } }, "e"],
        [
          "EmailSubmission/set",
          { notCreated: { s0: { type: "forbiddenToSend", description: "нет права Send As от этого адреса" } } },
          "s",
        ],
      ],
      sessionState: "1",
    } as unknown as Awaited<ReturnType<typeof jmapCall>>);
    await expect(
      sendMessage(ENV, SNAPSHOT, { sentMailboxId: "mb", identityId: "I9", undoable: false }),
    ).rejects.toSatisfy((e: unknown) => e instanceof SendError && e.message.includes("Send As"));
  });

  test("ошибка метода целиком (RFC 8620 §3.6.1) — тоже SendError", async () => {
    mocked.mockResolvedValue({
      methodResponses: [["EmailSubmission/set", { "@type": "error", type: "serverFail" }, "s"]],
      sessionState: "1",
    } as unknown as Awaited<ReturnType<typeof jmapCall>>);
    await expect(
      sendMessage(ENV, SNAPSHOT, { sentMailboxId: "mb", identityId: "I1", undoable: false }),
    ).rejects.toMatchObject({ type: "serverFail" });
  });
});

describe("undo-send", () => {
  test("supportsUndoSend: maxDelayedSend ≥ окна undo", () => {
    const session = (seconds: number): JmapSession =>
      ({
        accounts: { acc1: { accountCapabilities: { "urn:ietf:params:jmap:submission": { maxDelayedSend: seconds } } } },
      }) as unknown as JmapSession;
    expect(supportsUndoSend(session(60), "acc1")).toBe(true);
    expect(supportsUndoSend(session(UNDO_SEND_SECONDS), "acc1")).toBe(true);
    expect(supportsUndoSend(session(5), "acc1")).toBe(false);
    expect(supportsUndoSend({ accounts: {} } as unknown as JmapSession, "acc1")).toBe(false);
  });

  test("cancelSend: update undoStatus=canceled; успех — true, cannotUnsend — false", async () => {
    mockedSubmissionSet
      .mockResolvedValueOnce({ created: {}, errors: {}, destroyed: [] } satisfies SetResult)
      .mockResolvedValueOnce({
        created: {},
        errors: { s1: { type: "cannotUnsend", description: "письмо уже ушло" } },
        destroyed: [],
      } satisfies SetResult);
    await expect(cancelSend(ENV, "s1")).resolves.toBe(true);
    expect(mockedSubmissionSet.mock.calls[0][2]).toBe("EmailSubmission/set");
    expect(mockedSubmissionSet.mock.calls[0][3].update).toEqual({ s1: { undoStatus: "canceled" } });
    await expect(cancelSend(ENV, "s1")).resolves.toBe(false);
  });

  test("rememberSent: без дублей, свежие в начало", () => {
    rememberSent([{ name: "Ольга", email: "o@x" }]);
    rememberSent([{ name: "Ольга", email: "O@X" }, { name: null, email: "k@x" }]);
    const history = JSON.parse(localStorage.getItem("thepost-webmail-recipients") ?? "[]") as Array<{ email: string }>;
    expect(history.map((h) => h.email)).toEqual(["o@x", "k@x"]);
  });
});
