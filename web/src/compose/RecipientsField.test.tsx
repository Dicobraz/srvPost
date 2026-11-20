// Поле получателей (WEB-04): чипы — ввод Enter/запятая, дубли и невалидные не проходят
// (ошибка inline), Backspace убирает последний, автодополнение — список с источниками,
// пикер «Кому…» открывает адресную книгу; выбранное — не в подсказках.
import { fireEvent, render, cleanup, within } from "@testing-library/react";
import { afterEach, expect, test } from "vitest";
import { useState } from "react";

import { RecipientsField } from "./RecipientsField";
import type { Recipient } from "./recipients";

afterEach(cleanup);

const CANDIDATES = [
  { recipient: { name: "Ольга Смирнова", email: "o.smirnova@vektor.example" }, source: "Контакты" },
  { recipient: { name: "Ольга Смирнова", email: "o.smirnova@thepost.example" }, source: "Контакты" },
  { recipient: { name: "Олег Лебедев", email: "o.lebedev@thepost.example" }, source: "История" },
];

function Field({ onChange }: { onChange?: (r: Recipient[]) => void }) {
  const [recipients, setRecipients] = useState<Recipient[]>([]);
  return (
    <RecipientsField
      label="Кому"
      recipients={recipients}
      candidates={CANDIDATES}
      onChange={(r) => {
        setRecipients(r);
        onChange?.(r);
      }}
      withPicker
    />
  );
}

const field = () => within(render(<Field />).container);

test("Enter добавляет чип; невалидный адрес — inline-ошибка без чипа", async () => {
  const p = field();
  const input = p.getByLabelText("Кому: адрес получателя") as HTMLInputElement;
  fireEvent.change(input, { target: { value: "o@vektor.example" } });
  fireEvent.keyDown(input, { key: "Enter" });
  expect(p.getAllByText("o@vektor.example").length).toBeGreaterThan(0);

  fireEvent.change(input, { target: { value: "не адрес" } });
  fireEvent.keyDown(input, { key: "Enter" });
  const alert = await p.findByRole("alert");
  expect(alert.textContent).toContain("не похоже на адрес");
});

test("чипы без дублей: повтор не добавляется", () => {
  const p = field();
  const input = p.getByLabelText("Кому: адрес получателя") as HTMLInputElement;
  fireEvent.change(input, { target: { value: "o@vektor.example" } });
  fireEvent.keyDown(input, { key: "Enter" });
  fireEvent.change(input, { target: { value: "o@vektor.example" } });
  fireEvent.keyDown(input, { key: "Enter" });
  expect(p.getAllByText("o@vektor.example")).toHaveLength(1);
});

test("Backspace на пустом вводе убирает последний чип", () => {
  const p = field();
  const input = p.getByLabelText("Кому: адрес получателя") as HTMLInputElement;
  fireEvent.change(input, { target: { value: "a@b.example" } });
  fireEvent.keyDown(input, { key: "Enter" });
  expect(p.getAllByText("a@b.example").length).toBeGreaterThan(0);
  fireEvent.keyDown(input, { key: "Backspace" });
  expect(p.queryByText("a@b.example")).toBeNull();
});

test("× на чипе убирает получателя", () => {
  const p = field();
  const input = p.getByLabelText("Кому: адрес получателя") as HTMLInputElement;
  fireEvent.change(input, { target: { value: "a@b.example" } });
  fireEvent.keyDown(input, { key: "Enter" });
  fireEvent.click(p.getByLabelText("Убрать a@b.example"));
  expect(p.queryByText("a@b.example")).toBeNull();
});

test("автодополнение: подсказки по вводу, выбор — чип, источник в строке", async () => {
  const p = field();
  const input = p.getByLabelText("Кому: адрес получателя") as HTMLInputElement;
  fireEvent.change(input, { target: { value: "ол" } });
  const list = await p.findByRole("listbox", { name: "Подсказки адресов" });
  expect(within(list).getAllByRole("option")).toHaveLength(3);
  expect(within(list).getAllByText("Контакты").length).toBe(2);
  fireEvent.click(within(list).getAllByRole("option")[0]);
  expect(p.getByText("Ольга Смирнова")).toBeTruthy();
  // Выбранное в подсказках больше не появляется, остальное — остаётся.
  fireEvent.change(input, { target: { value: "ол" } });
  const next = p.getByRole("listbox", { name: "Подсказки адресов" });
  expect(within(next).getAllByRole("option")).toHaveLength(2);
});

test("пикер «Кому…» — вся книга без запроса", async () => {
  const p = field();
  fireEvent.click(p.getByLabelText("Выбрать из адресной книги"));
  const list = await p.findByRole("listbox", { name: "Адресная книга и история" });
  expect(within(list).getAllByRole("option")).toHaveLength(3);
});
