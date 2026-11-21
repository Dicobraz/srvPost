// Полоса «Напоминания» (WEB-19): секции и счётчики, клик-навигация (секция → фильтр «Почты»,
// письмо → открыть — через напоминания-шину reminders.ts), свёрнутость в localStorage. Данные
// (useReminders) подменяются на границе модуля queries — полоса тестируется как компонент
// оболочки, без JMAP и роутера.
import { cleanup, fireEvent, render, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import type { EmailSummary } from "../api/jmap";
import { queryClient } from "./client";
import { RemindersBar } from "./reminders-bar";
import { takeReminderNavigation } from "./reminders";

vi.mock("./queries", () => ({
  useReminders: vi.fn(),
}));

import { useReminders } from "./queries";

const mockedReminders = vi.mocked(useReminders);

function renderBar(): ReturnType<typeof within> {
  const view = render(<RemindersBar />);
  return within(view.container);
}

/** Полное краткое письмо: полоса берёт из него id, тему и слова. */
function item(id: string, subject: string, keywords: Record<string, boolean>): EmailSummary {
  return {
    id,
    blobId: null,
    threadId: `t-${id}`,
    mailboxIds: { inbox: true },
    keywords,
    receivedAt: "2026-11-20T10:00:00Z",
    size: 100,
    from: null,
    to: null,
    subject,
    preview: "",
    hasAttachment: false,
  };
}

/** Локальная дата в формате слова: сегодня + offset дней. */
function dayWord(offset: number): string {
  const now = new Date();
  const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() + offset);
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${d.getFullYear()}-${mm}-${dd}`;
}

beforeEach(() => {
  localStorage.clear();
  queryClient.clear();
  takeReminderNavigation(); // шина переходов между тестами пуста
  mockedReminders.mockReset();
});

afterEach(cleanup);

test("нет напоминаний — полосы нет: место не занимает", () => {
  mockedReminders.mockReturnValue([]);
  const page = renderBar();
  expect(page.queryByRole("region", { name: "Напоминания" })).toBeNull();
});

test("секции по срочности, счётчики и ближайшие темы со сроком в пункте", () => {
  mockedReminders.mockReturnValue([
    item("e1", "Счёт с истёкшим сроком", { "pm.due.2020-01-01t0900": true }),
    item("e2", "Отчёт к вечеру", { [`pm.due.${dayWord(0)}`]: true }),
    item("e3", "В пределах семи дней", { [`pm.due.${dayWord(3)}t1200`]: true }),
    item("e4", "Дальше горизонта", { [`pm.due.${dayWord(20)}`]: true }),
    item("e5", "Ответ коллеге", { "pm.wait": true }),
  ]);
  const page = renderBar();
  const bar = page.getByRole("region", { name: "Напоминания" });
  // Секции: «Просрочено», «Сегодня», «Далее» (горизонт 7 дней), «Ждём ответа».
  expect(within(bar).getByRole("button", { name: /^Просрочено/ })).toBeTruthy();
  expect(within(bar).getByRole("button", { name: /^Сегодня/ })).toBeTruthy();
  expect(within(bar).getByRole("button", { name: /^Далее/ })).toBeTruthy();
  expect(within(bar).getByRole("button", { name: /^Ждём ответа/ })).toBeTruthy();
  // Счётчик свёрнутого вида: всего пять; сроки дальше горизонта — счётчиком в «Далее».
  expect(within(bar).getByText("5")).toBeTruthy();
  expect(within(bar).getByText("Ещё 1…")).toBeTruthy();
  // Пункты — тема + срок (подписи как у чипов списка).
  expect(within(bar).getByText("Счёт с истёкшим сроком")).toBeTruthy();
  expect(within(bar).getByText(/Просрочено \d+ д/)).toBeTruthy();
  expect(within(bar).getByText("В пределах семи дней")).toBeTruthy();
  expect(within(bar).getByText("Ждём ответа")).toBeTruthy(); // подпись пункта ожидания
});

test("клик по секции — быстрый фильтр «Почты», клик по письму — открыть (шина переходов)", () => {
  mockedReminders.mockReturnValue([
    item("e1", "Счёт с истёкшим сроком", { "pm.due.2020-01-01t0900": true }),
    item("e5", "Ответ коллеге", { "pm.wait": true }),
  ]);
  const page = renderBar();
  const bar = page.getByRole("region", { name: "Напоминания" });
  fireEvent.click(within(bar).getByRole("button", { name: /^Ждём ответа/ }));
  expect(takeReminderNavigation()).toEqual({ quick: "wait" });
  fireEvent.click(within(bar).getByText("Счёт с истёкшим сроком"));
  expect(takeReminderNavigation()).toEqual({ open: "e1" });
  // Секция «Просрочено» — тот же фильтр «Срок» (маска pm.due).
  fireEvent.click(within(bar).getByRole("button", { name: /^Просрочено/ }));
  expect(takeReminderNavigation()).toEqual({ quick: "due" });
});

test("свёрнутость: счётчик остаётся, хранится в localStorage и переживает перезагрузку", () => {
  mockedReminders.mockReturnValue([item("e1", "Тема письма", { "pm.due.2020-01-01t0900": true })]);
  const page = renderBar();
  const bar = page.getByRole("region", { name: "Напоминания" });
  const toggle = within(bar).getByRole("button", { expanded: true });
  expect(within(bar).getByText("Тема письма")).toBeTruthy(); // по умолчанию развёрнута

  fireEvent.click(toggle);
  expect(within(bar).queryByText("Тема письма")).toBeNull(); // секции скрыты
  expect(within(bar).getByRole("button", { expanded: false })).toBeTruthy(); // счётчик на месте
  expect(localStorage.getItem("thepost-webmail-reminders")).toBe("closed");

  // «Перезагрузка»: новая полоса читает свёрнутость из localStorage.
  cleanup();
  mockedReminders.mockReturnValue([item("e1", "Тема письма", { "pm.due.2020-01-01t0900": true })]);
  const page2 = renderBar();
  const bar2 = page2.getByRole("region", { name: "Напоминания" });
  expect(within(bar2).queryByText("Тема письма")).toBeNull();
  expect(within(bar2).getByText("1")).toBeTruthy();
  fireEvent.click(within(bar2).getByRole("button", { expanded: false }));
  expect(within(bar2).getByText("Тема письма")).toBeTruthy();
});
