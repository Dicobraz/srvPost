// «Взять в работу» и общие ящики (WEB-15): формат слов `pm.taken…` — как в Postman
// (`postman_core::marks`, S5-28) — round-trip, разбор, «кто взял», патчи Email/set; общие
// учётные записи сессии (JMAP-49) и ключи дерева.
import { describe, expect, test } from "vitest";

import { CAP_MAIL, type EmailSummary, type JmapSession } from "../api/jmap";
import {
  isTakenWord,
  parseTaken,
  releaseKeywordChanges,
  sharedAccountId,
  sharedFolderKey,
  sharedMailAccounts,
  TAKEN,
  takeActOf,
  takenKeyword,
  takenOf,
  takePatchOf,
  TAKE_LABELS,
  takeKeywordChanges,
  takenBy,
  takenWhen,
  validKeyword,
} from "./shared";

const AT = new Date("2026-10-22T10:42:00Z");

/** Письмо с ключевыми словами — для патчей. */
function emailWith(keywords: Record<string, boolean>): { id: string; keywords: Record<string, boolean> } & Partial<EmailSummary> {
  return { id: "e1", keywords };
}

describe("слово «взял» — формат Postman", () => {
  test("takenKeyword даёт слово вида pm.taken.ГГГГ-ММ-ДДtЧЧММz.адрес (пример из Postman)", () => {
    const k = takenKeyword("P.Koval@Corp.Example", AT);
    expect(k).toBe("pm.taken.2026-10-22t1042z.p.koval@corp.example");
    expect(validKeyword(k as string)).toBe(true);
  });

  test("round-trip: parseTaken возвращает взявшего и время, адрес в нижнем регистре", () => {
    const k = takenKeyword("p.koval@corp.example", AT) as string;
    const t = parseTaken(k);
    expect(t?.who).toBe("p.koval@corp.example");
    expect(t?.at.toISOString()).toBe(AT.toISOString());
    expect(takenBy(t as NonNullable<typeof t>, "P.Koval@Corp.Example")).toBe(true);
  });

  test("чужой формат слова не разбирается (как parse_taken Postman)", () => {
    expect(parseTaken("pm.taken")).toBeNull();
    expect(parseTaken("pm.taken.")).toBeNull();
    expect(parseTaken("pm.taken.2026-10-22t1042z.")).toBeNull();
    expect(parseTaken("pm.taken.2026-10-22t1042z.koval")).toBeNull(); // нет @
    expect(parseTaken("pm.taken.2026-10-22t1042.p.koval@x.org")).toBeNull(); // нет z.
    expect(parseTaken("pm.taken.xxxx-10-22t1042z.p@x.org")).toBeNull(); // штампа нет
    expect(parseTaken("$flagged")).toBeNull();
  });

  test("адрес, негодный в ключевое слово JMAP, — null", () => {
    expect(takenKeyword("", AT)).toBeNull();
    expect(takenKeyword("  ", AT)).toBeNull();
    expect(takenKeyword('p "quoted"@x.org', AT)).toBeNull();
    expect(takenKeyword("p(1)@x.org", AT)).toBeNull();
  });

  test("isTakenWord: общее слово, со временем и адресом, неразобранное — да; чужие — нет", () => {
    expect(isTakenWord("pm.taken")).toBe(true);
    expect(isTakenWord("pm.taken.2026-10-22t1042z.p.koval@corp.example")).toBe(true);
    expect(isTakenWord("pm.taken.slovo")).toBe(true);
    expect(isTakenWord("PM.Taken.2026-10-22T1042Z.P@X.ORG")).toBe(true);
    expect(isTakenWord("pm.taker")).toBe(false);
    expect(isTakenWord("pm.wait.2026-10-24")).toBe(false);
  });
});

describe("кто держит письмо — takenOf", () => {
  test("нет слов «взял» — никто, даже если общее слово осталось", () => {
    expect(takenOf({ [TAKEN]: true, $seen: true })).toBeNull();
  });

  test("из двух слов — позднее; при равном времени — меньший адрес (как в Postman)", () => {
    const later = parseTaken("pm.taken.2026-10-23t0900z.b@x.org") as NonNullable<ReturnType<typeof parseTaken>>;
    const earlier = parseTaken("pm.taken.2026-10-22t1042z.a@x.org") as NonNullable<ReturnType<typeof parseTaken>>;
    expect(takenOf({ "pm.taken.2026-10-22t1042z.a@x.org": true, "pm.taken.2026-10-23t0900z.b@x.org": true })).toEqual(later);
    expect(takenOf({ "pm.taken.2026-10-23t0900z.b@x.org": true, "pm.taken.2026-10-22t1042z.a@x.org": true })).toEqual(later);
    expect(takenOf({ "pm.taken.2026-10-23t0900z.b@x.org": true, "pm.taken.2026-10-23t0900z.a@x.org": true })).toEqual(
      parseTaken("pm.taken.2026-10-23t0900z.a@x.org"),
    );
    expect(later.at > earlier.at).toBe(true);
  });
});

describe("взять и вернуть — патчи слов", () => {
  test("взять: ставит общее слово и своё, снимает прежние «взял»", () => {
    const changes = takeKeywordChanges({ "pm.taken.2026-10-21t0900z.old@x.org": true, $seen: true }, "me@x.org", AT);
    expect(changes?.add).toEqual([TAKEN, "pm.taken.2026-10-22t1042z.me@x.org"]);
    expect(changes?.remove).toEqual(["pm.taken.2026-10-21t0900z.old@x.org"]);
  });

  test("вернуть: снимает все слова «взял» и общее слово", () => {
    const remove = releaseKeywordChanges({
      TAKEN: true,
      "pm.taken.2026-10-22t1042z.me@x.org": true,
      $seen: true,
    });
    expect(remove).toEqual([TAKEN, "pm.taken.2026-10-22t1042z.me@x.org"]);
    // Общее слово ставится к снятию, даже если его на письме нет (снимет другой клиент не всё).
    expect(releaseKeywordChanges({ "pm.taken.2026-10-22t1042z.me@x.org": true })).toEqual([
      "pm.taken.2026-10-22t1042z.me@x.org",
      TAKEN,
    ]);
  });

  test("патч письма для Email/set: слова со включением и снятием (взять и вернуть)", () => {
    const take = takePatchOf(emailWith({}) as EmailSummary, "me@x.org", AT);
    expect(take).toEqual({
      "keywords/pm.taken": true,
      "keywords/pm.taken.2026-10-22t1042z.me@x.org": true,
    });
    const steal = takePatchOf(
      emailWith({ "pm.taken.2026-10-21t0900z.old@x.org": true, "pm.taken": true }) as EmailSummary,
      "me@x.org",
      AT,
    );
    expect(steal).toEqual({
      "keywords/pm.taken.2026-10-21t0900z.old@x.org": false,
      "keywords/pm.taken": true,
      "keywords/pm.taken.2026-10-22t1042z.me@x.org": true,
    });
    const release = takePatchOf(
      emailWith({ "pm.taken": true, "pm.taken.2026-10-22t1042z.me@x.org": true }) as EmailSummary,
      "me@x.org",
      AT,
    );
    expect(release).toEqual({
      "keywords/pm.taken": false,
      "keywords/pm.taken.2026-10-22t1042z.me@x.org": false,
    });
  });
});

describe("действие по состоянию — takeActOf", () => {
  test("никто не взял — взять; взял коллега — забрать; взял я — вернуть", () => {
    expect(takeActOf({}, "me@x.org")).toBe("take");
    expect(takeActOf({ "pm.taken.2026-10-22t1042z.col@x.org": true }, "me@x.org")).toBe("steal");
    expect(takeActOf({ "pm.taken.2026-10-22t1042z.ME@X.ORG": true }, "Me@X.org")).toBe("release");
    expect(TAKE_LABELS.take).toBe("Взять в работу");
    expect(TAKE_LABELS.steal).toBe("Забрать себе");
    expect(TAKE_LABELS.release).toBe("Вернуть в очередь");
  });

  test("время «взял»: сегодня — часы, раньше — дата и часы (как в строках списка)", () => {
    const now = new Date("2026-10-22T12:00:00Z");
    expect(takenWhen(AT, now)).toBe(AT.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" }));
    const earlier = new Date("2026-10-20T16:30:00Z");
    expect(takenWhen(earlier, now)).toContain("20.10");
    expect(takenWhen(earlier, now)).toContain(earlier.toLocaleTimeString("ru", { hour: "2-digit", minute: "2-digit" }));
  });
});

describe("общие ящики сессии (JMAP-49)", () => {
  const SESSION: JmapSession = {
    capabilities: {},
    accounts: {
      acc1: { name: "user@example.org", isPersonal: true, isReadOnly: false, accountCapabilities: { [CAP_MAIL]: {} } },
      acc2: { name: "sales@example.org", isPersonal: false, isReadOnly: false, accountCapabilities: { [CAP_MAIL]: {} } },
      acc3: { name: "boss@example.org", isPersonal: false, isReadOnly: true, accountCapabilities: {} }, // без почты — книги
      acc4: { name: "info@example.org", isPersonal: false, isReadOnly: true, accountCapabilities: { [CAP_MAIL]: {} } },
    },
    primaryAccounts: { [CAP_MAIL]: "acc1" },
    username: "user@example.org",
    apiUrl: "https://node.example/jmap/api",
    downloadUrl: "",
    uploadUrl: "",
    eventSourceUrl: "",
    state: "s",
  };

  test("чужие учётные записи с capability почты; свои и книги — прочь", () => {
    expect(sharedMailAccounts(SESSION)).toEqual([
      { id: "acc4", name: "info@example.org", readOnly: true },
      { id: "acc2", name: "sales@example.org", readOnly: false },
    ]);
  });

  test("ключи дерева: shared:<accountId> туда и обратно", () => {
    expect(sharedFolderKey("acc2")).toBe("shared:acc2");
    expect(sharedAccountId("shared:acc2")).toBe("acc2");
    expect(sharedAccountId("mb1")).toBeNull();
    expect(sharedAccountId("flagged")).toBeNull();
    expect(sharedAccountId(null)).toBeNull();
  });
});
