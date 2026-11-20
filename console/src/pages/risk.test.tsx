import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";

import type { Schemas } from "../api/client";
import { ORG } from "../test-api";
import { BASE, open, sent } from "../test-app";

const ID = "tp.encrypted_archive";
const PUT_URL = `${BASE}/risk/signals/${ID}`;

/** Признак каталога: пакет поставщика без изменений уровня. */
const sig = (over: Partial<Schemas["SignalView"]> = {}): Schemas["SignalView"] => ({
  id: ID,
  origin: "vendor",
  detector: "encrypted_archive",
  weight: 8,
  threshold: 50,
  action: "junk",
  mode: "enforce",
  since: "2026-11-01T10:00:00Z",
  source: null,
  orphaned: false,
  ...over,
});

/** Источник TI: фид по HTTP с ключом-ссылкой. */
const src = (over: Partial<Schemas["TiSourceView"]> = {}): Schemas["TiSourceView"] => ({
  id: "feed-misp",
  tier: "customer_key",
  origin: "vendor",
  kind: { http: { url: "https://feeds.example/misp" } },
  format: "misp_feed",
  ttl: "30m",
  stale: "report",
  license: { terms_url: "https://feeds.example/terms", commercial: false, attribution: "feeds.example" },
  auth: { header: { name: "Auth-Key" } },
  key: { secret: "vault/feeds#api_key" },
  tenants: "all",
  ...over,
});

afterEach(() => {
  cleanup();
  sessionStorage.clear();
  localStorage.clear();
});

test("организация не может выбрать вес ниже установки (пол уровня установки)", async () => {
  const calls = open("/risk", {
    "GET /api/v1/risk/signals": { body: { signals: [sig()] } },
    [`GET ${BASE}/risk/signals`]: { body: { signals: [sig()] } },
    [`PUT ${PUT_URL}`]: (c) => ({ body: c.body }),
  });
  expect(await screen.findByText(ID)).toBeTruthy();
  fireEvent.click(await screen.findByRole("button", { name: "Изменить" }));
  const weight = await screen.findByRole("spinbutton", { name: `Вес ${ID}` });
  // Вес ниже уровня установки — подсказка у поля, кнопка сохранения недоступна, записи нет.
  fireEvent.change(weight, { target: { value: "3" } });
  expect(screen.getByText("не ниже уровня установки: 8")).toBeTruthy();
  expect((screen.getByRole("button", { name: "Сохранить" }) as HTMLButtonElement).disabled).toBe(true);
  expect(sent(calls, "PUT", PUT_URL)).toBeUndefined();

  // Строгое значение принимается: вес, действие и режим — уровнем выше текущего каталога.
  fireEvent.change(weight, { target: { value: "10" } });
  fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  await waitFor(() => expect(sent(calls, "PUT", PUT_URL)[0]?.body).toEqual({ weight: 10, action: "junk", mode: "enforce" }));
  expect(await screen.findByText("Признак сохранён")).toBeTruthy();
});

test("422 «мягче уровня установки» — у поля с текстом detail сервера", async () => {
  const detail = "Вес признака tp.encrypted_archive: 3 ниже уровня установки (8).";
  const calls = open(
    "/risk",
    {
      [`GET ${BASE}/risk/signals`]: { body: { signals: [sig()] } },
      [`PUT ${PUT_URL}`]: {
        status: 422,
        body: {
          status: 422,
          title: "Unprocessable Entity",
          detail,
          errors: [{ signal: ID, field: "weight", value: "3", base: "8" }],
        },
      },
    },
    ["organization_admin"],
  );
  expect(await screen.findByText(ID)).toBeTruthy();
  fireEvent.click(await screen.findByRole("button", { name: "Изменить" }));
  fireEvent.change(await screen.findByRole("spinbutton", { name: `Вес ${ID}` }), { target: { value: "3" } });
  fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));
  // Текст `detail` сервера — в той же клетке таблицы, где поле веса.
  expect(await screen.findByText(detail)).toBeTruthy();
  expect(screen.getByRole("spinbutton", { name: `Вес ${ID}` }).closest("td")?.textContent).toContain(detail);
  expect(sent(calls, "PUT", PUT_URL)).toHaveLength(1);
});

test("метка «только отчёт» — с датой; осиротевшие изменения — отдельным списком со сбросом", async () => {
  const calls = open(
    "/risk",
    {
      [`GET ${BASE}/risk/signals`]: {
        body: {
          signals: [
            sig({ mode: "report", since: "2026-11-05T10:00:00Z" }),
            sig({ id: "tp.gone", orphaned: true, detector: null, threshold: null, weight: 12, since: null, source: { org: ORG } }),
          ],
        },
      },
      [`DELETE ${BASE}/risk/signals/tp.gone`]: { body: sig({ id: "tp.gone" }) },
    },
    ["organization_admin"],
  );
  expect(await screen.findByText("только отчёт")).toBeTruthy();
  expect(screen.getByText(/с 05\.11\.2026/)).toBeTruthy();
  // Осиротевшее изменение — не в общей таблице, а отдельным списком с кнопкой сброса.
  expect(await screen.findByText("Осиротевшие изменения")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Сбросить" }));
  const confirm = await screen.findByText("Сбросить изменение tp.gone?");
  fireEvent.click(within(confirm.closest(".ant-popover") as HTMLElement).getByRole("button", { name: "Сбросить" }));
  await waitFor(() => expect(sent(calls, "DELETE", `${BASE}/risk/signals/tp.gone`)).toHaveLength(1));
});

test("свой признак org.* создаётся формой", async () => {
  const calls = open(
    "/risk",
    {
      [`GET ${BASE}/risk/signals`]: { body: { signals: [sig()] } },
      [`PUT ${BASE}/risk/signals/org.unusual_attachment`]: (c) => ({ body: c.body }),
    },
    ["organization_admin"],
  );
  expect(await screen.findByText(ID)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Добавить признак" }));
  fireEvent.change(await screen.findByLabelText("Идентификатор"), { target: { value: "org.unusual_attachment" } });
  fireEvent.mouseDown(screen.getByRole("combobox", { name: "Детектор" }));
  fireEvent.click(await screen.findByTitle("новый домен ссылки в переписке"));
  fireEvent.change(screen.getByRole("spinbutton", { name: "Вес нового признака" }), { target: { value: "5" } });
  fireEvent.change(screen.getByRole("spinbutton", { name: "Порог нового признака" }), { target: { value: "60" } });
  fireEvent.mouseDown(screen.getByRole("combobox", { name: "Действие нового признака" }));
  fireEvent.click(await screen.findByTitle("карантин"));
  fireEvent.click(screen.getByRole("button", { name: "Создать" }));
  await waitFor(() =>
    expect(sent(calls, "PUT", `${BASE}/risk/signals/org.unusual_attachment`)[0]?.body).toEqual({
      detector: "thread_new_link_domain",
      weight: 5,
      threshold: 60,
      action: "quarantine",
      mode: "report",
    }),
  );
  expect(await screen.findByText("Признак создан")).toBeTruthy();
});

test("пороги: четыре числа с подписями действий, «действует самое строгое», сохранение PUT", async () => {
  const calls = open("/risk", {
    "GET /api/v1/risk/thresholds": { body: { effective: { tag: 1, junk: 6, quarantine: 10, reject: 15 }, own: null, source: null } },
    "PUT /api/v1/risk/thresholds": (c) => ({ body: c.body }),
  });
  // Пороги уровня установки: переключение уровня — запрос уходит уже к установке.
  fireEvent.click(await screen.findByRole("radio", { name: "Установка" }));
  fireEvent.click(await screen.findByRole("tab", { name: "Пороги" }));
  await waitFor(() => expect(sent(calls, "GET", "/api/v1/risk/thresholds")).toHaveLength(1));
  expect(screen.getByText(/действует самое строгое/)).toBeTruthy();
  fireEvent.change(await screen.findByRole("spinbutton", { name: "Порог папки «Спам»" }), { target: { value: "7" } });
  fireEvent.click(screen.getByRole("button", { name: "Сохранить пороги" }));
  await waitFor(() =>
    expect(sent(calls, "PUT", "/api/v1/risk/thresholds")[0]?.body).toEqual({ tag: 1, junk: 7, quarantine: 10, reject: 15 }),
  );
  expect(await screen.findByText("Пороги сохранены")).toBeTruthy();
});

test("загрузка пакета показывает отчёт проверки и сама пакет не активирует", async () => {
  const report: Schemas["PackageReportView"] = {
    version: 6,
    key_id: "vendor-2026-11",
    samples: 512,
    signals: 40,
    update: { added: ["tp.new_link_domain"], changed: [ID], removed: ["tp.old_signal"], orphaned_overrides: [] },
  };
  const calls = open("/risk", {
    "GET /api/v1/risk/packages": { body: { packages: [{ version: 5, state: "active" }] } },
    "POST /api/v1/risk/packages": { status: 202, body: report },
    "POST /api/v1/risk/packages/6/activate": { body: { packages: [{ version: 6, state: "active" }, { version: 5, state: "previous" }] } },
  });
  fireEvent.click(await screen.findByRole("tab", { name: "Пакеты" }));
  const input = (await waitFor(() => {
    const el = document.querySelector('input[type="file"]') as HTMLInputElement | null;
    if (!el) throw new Error("нет поля файла");
    return el;
  })) as HTMLInputElement;
  fireEvent.change(input, { target: { files: [new File(["PKG"], "vendor-6.tpkg", { type: "application/octet-stream" })] } });
  await waitFor(() => expect(sent(calls, "POST", "/api/v1/risk/packages")).toHaveLength(1));
  // Отчёт проверки — до активации: подпись, пробный прогон, что изменится.
  expect(await screen.findByText(/Отчёт проверки пакета 6/)).toBeTruthy();
  expect(screen.getByText(/vendor-2026-11/)).toBeTruthy();
  expect(screen.getByText(/512 образцов/)).toBeTruthy();
  expect(screen.getByText("tp.new_link_domain")).toBeTruthy();
  expect(screen.getByText(ID)).toBeTruthy();
  // Автоактивации нет: активация — отдельным действием с подтверждением.
  expect(sent(calls, "POST", "/api/v1/risk/packages/6/activate")).toBeUndefined();
  fireEvent.click(screen.getByRole("button", { name: "Активировать" }));
  const confirm = await screen.findByText("Активировать пакет 6?");
  fireEvent.click(within(confirm.closest(".ant-popover") as HTMLElement).getByRole("button", { name: "Активировать" }));
  await waitFor(() => expect(sent(calls, "POST", "/api/v1/risk/packages/6/activate")).toHaveLength(1));
  expect(await screen.findByText("Пакет 6 активирован")).toBeTruthy();
});

test("ключ источника — только выбор SecretRef, значение узлу не вводится", async () => {
  const calls = open("/risk", {
    "GET /api/v1/risk/sources": { body: { sources: [src()] } },
    "POST /api/v1/risk/sources": (c) => ({ body: c.body }),
  });
  fireEvent.click(await screen.findByRole("tab", { name: "Источники TI" }));
  expect(await screen.findByText("feed-misp")).toBeTruthy();
  expect(screen.getByText("vault/feeds#api_key")).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Добавить источник" }));
  fireEvent.change(await screen.findByLabelText("Идентификатор"), { target: { value: "own-feed" } });
  fireEvent.change(await screen.findByLabelText("Адрес фида"), { target: { value: "https://feeds.example/own.txt" } });
  fireEvent.change(await screen.findByLabelText("Срок жизни данных (TTL)"), { target: { value: "1h" } });
  fireEvent.change(await screen.findByLabelText("Условия использования (лицензия)"), { target: { value: "https://feeds.example/terms" } });
  fireEvent.mouseDown(screen.getByRole("combobox", { name: "Авторизация" }));
  fireEvent.click(await screen.findByTitle("Bearer (ключ из секрета)"));
  const key = await screen.findByRole("combobox", { name: "Ключ (ссылка на секрет)" });
  fireEvent.change(key, { target: { value: "vault/feeds#own_key" } });
  fireEvent.click(screen.getByRole("button", { name: "Создать" }));
  await waitFor(() => expect(sent(calls, "POST", "/api/v1/risk/sources")).toHaveLength(1));
  expect(sent(calls, "POST", "/api/v1/risk/sources")[0]?.body).toEqual({
    id: "own-feed",
    tier: "customer_key",
    origin: "own",
    kind: { http: { url: "https://feeds.example/own.txt" } },
    format: "txt",
    ttl: "1h",
    stale: "report",
    license: { terms_url: "https://feeds.example/terms", commercial: false, attribution: null },
    auth: "bearer",
    key: { secret: "vault/feeds#own_key" },
    tenants: "all",
  });
});

test("устаревший источник помечен, импорт показывает число записей", async () => {
  const version: Schemas["ListVersionView"] = {
    list: "feed-misp",
    source: "feed-misp",
    blob: "b1",
    entries: 42,
    sha256: "abc",
    fetched_at: "2026-11-18T10:00:00Z",
    tlp: "amber",
  };
  const calls = open("/risk", {
    "GET /api/v1/risk/sources": { body: { sources: [src()] } },
    "POST /api/v1/risk/sources/feed-misp/import": { status: 200, body: version },
  });
  fireEvent.click(await screen.findByRole("tab", { name: "Источники TI" }));
  const row = ((await screen.findByText("feed-misp")).closest("tr") as HTMLElement);
  const input = row.querySelector('input[type="file"]') as HTMLInputElement;
  fireEvent.change(input, { target: { files: [new File(["1.2.3.4"], "list.txt", { type: "application/octet-stream" })] } });
  await waitFor(() => expect(sent(calls, "POST", "/api/v1/risk/sources/feed-misp/import")).toHaveLength(1));
  // Загрузка старше TTL (30m) — источник помечен как устаревший, рядом число записей.
  const updated = (await screen.findByText("feed-misp")).closest("tr") as HTMLElement;
  await waitFor(() => expect(updated.textContent).toContain("устарел"));
  expect(updated.textContent).toContain("42");
});

test("срабатывания: фильтры по признаку и режиму, ссылка на журнал доставки", async () => {
  const hits: Schemas["HitsView"] = {
    hits: [{ at: "2026-11-19T12:00:00Z", message: "a".repeat(64), signal: ID, mode: "enforce", strength: 72, weight: 8 }],
    next: null,
  };
  const calls = open("/risk", {
    [`GET ${BASE}/risk/signals`]: { body: { signals: [sig()] } },
    [`GET ${BASE}/risk/hits`]: { body: hits },
    [`GET ${BASE}/delivery`]: { body: { events: [], next: null } },
  });
  fireEvent.click(await screen.findByRole("tab", { name: "Срабатывания" }));
  expect(await screen.findByText(ID)).toBeTruthy();
  fireEvent.mouseDown(screen.getByRole("combobox", { name: "Режим срабатывания" }));
  fireEvent.click(await screen.findByTitle("применять"));
  fireEvent.click(screen.getByRole("button", { name: "Найти" }));
  await waitFor(() => expect(sent(calls, "GET", `${BASE}/risk/hits?mode=enforce`)).toHaveLength(1));
  // Ссылка из строки срабатывания открывает журнал доставки.
  fireEvent.click(screen.getByRole("button", { name: "Открыть журнал доставки" }));
  await waitFor(() => expect(sent(calls, "GET", `${BASE}/delivery`)).toBeTruthy());
});

test("раздел «Признаки риска» есть в меню", async () => {
  const empty = {
    archive_after: null,
    archive_quota_bytes: null,
    dkim_selector: null,
    max_recipients: null,
    milter_profile: null,
    quota_bytes: null,
    rcpts_per_hour: null,
    retention: null,
    send_per_hour: null,
    trash_purge: null,
    trash_retention: null,
  };
  open("/", { [`GET ${BASE}`]: { body: { id: ORG, default: true, policy: empty, effective: empty } } });
  await screen.findByText("Политика организации");
  fireEvent.click(screen.getByRole("button", { name: "bars" }));
  const items = (await screen.findAllByRole("menuitem")).map((m) => m.textContent);
  expect(items).toContain("Признаки риска");
});
