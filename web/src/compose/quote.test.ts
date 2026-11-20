// Ответ и пересылка (WEB-04): получатели ответа всем без себя и дублей, темы Re:/Fwd: без
// накопления, forward attached — .eml по blobId письма, In-Reply-To/References.
import { describe, expect, test } from "vitest";
import type { EmailFull } from "../api/jmap";
import { forwardAttachments, replyAllToOf, replyReferences, replyToOf, subjectFor } from "./quote";

const SOURCE: EmailFull = {
  id: "m1",
  blobId: "M1",
  threadId: "t1",
  mailboxIds: { mb1: true },
  keywords: { $seen: true },
  receivedAt: "2026-11-20T10:00:00Z",
  size: 100,
  from: [{ name: "Ольга Смирнова", email: "o@vektor.example" }],
  to: [{ name: null, email: "user@example.org" }, { name: "Ольга Смирнова", email: "o@vektor.example" }],
  cc: [{ name: null, email: "kim@example.org" }],
  bcc: [],
  subject: "Договор поставки",
  preview: "",
  hasAttachment: false,
  textBody: [{ partId: "p1", blobId: "M1_1", size: 10, type: "text/plain", name: null, disposition: null, charset: "utf-8" }],
  htmlBody: [{ partId: "p2", blobId: "M1_2", size: 10, type: "text/html", name: null, disposition: null, charset: null }],
  attachments: null,
  bodyValues: { p1: { value: "Привет", isEncodingProblem: false, isTruncated: false }, p2: { value: "<p>Привет</p>", isEncodingProblem: false, isTruncated: false } },
  messageId: ["msg-1@vektor.example"],
  references: ["msg-0@thepost.example"],
};

test("replyToOf: отправитель оригинала", () => {
  expect(replyToOf(SOURCE)).toEqual([{ name: "Ольга Смирнова", email: "o@vektor.example" }]);
});

test("replyAllToOf: отправитель + Кому + Копия, без себя и без дублей", () => {
  const all = replyAllToOf(SOURCE, "user@example.org");
  expect(all.to).toEqual([{ name: "Ольга Смирнова", email: "o@vektor.example" }]);
  expect(all.cc).toEqual([{ name: null, email: "kim@example.org" }]);
});

describe("subjectFor", () => {
  test("Re: и Fwd: не копятся, пустая тема не даёт пустого хвоста", () => {
    expect(subjectFor("reply", "Договор")).toBe("Re: Договор");
    expect(subjectFor("reply", "Re: Договор")).toBe("Re: Договор");
    expect(subjectFor("reply", null)).toBe("Re:");
    expect(subjectFor("forward", "Договор")).toBe("Fwd: Договор");
    expect(subjectFor("forward", "FW: Договор")).toBe("FW: Договор");
  });
});

test("forwardAttachments: оригинал — вложением .eml по blobId письма", () => {
  const parts = forwardAttachments(SOURCE);
  expect(parts).toHaveLength(1);
  expect(parts[0]).toMatchObject({ blobId: "M1", type: "message/rfc822", name: "Договор поставки.eml", disposition: "attachment" });
});

test("replyReferences: In-Reply-To = messageId оригинала, References — цепочка + messageId", () => {
  expect(replyReferences(SOURCE)).toEqual({
    inReplyTo: ["msg-1@vektor.example"],
    references: ["msg-0@thepost.example", "msg-1@vektor.example"],
  });
  expect(replyReferences({ ...SOURCE, messageId: null, references: null })).toEqual({
    inReplyTo: null,
    references: null,
  });
});
