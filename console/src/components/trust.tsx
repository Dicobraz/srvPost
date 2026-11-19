// Матрица доверия (UI-23, решение 124): строки — функции, столбцы — типы абонентов. Подписи функций и
// значений — как в разделе «Кто с кем и что может» ADMIN-GUIDE. У клетки — источник действующего значения;
// значения выше потолка видны, но недоступны; закреплённые — текстом с замком и пояснением.
import { LockOutlined } from "@ant-design/icons";
import { Select, Table, Tag, Tooltip, Typography } from "antd";
import type { ReactNode } from "react";

import type { Schemas } from "../api/client";

type Peer = Schemas["PeerKind"];
type MatrixKey = keyof Schemas["TrustMatrix"];
type Row = { key: MatrixKey; label: string };

const PEERS: Peer[] = ["own", "partner", "neighbor", "external"];

const PEER_LABEL: Record<Peer, string> = { own: "Свои", partner: "Партнёр", neighbor: "Сосед по установке", external: "Интернет" };

const TOGGLE = [
  { value: "off", label: "нет" },
  { value: "on", label: "да" },
];
const DETAILS = [
  { value: "none", label: "нет" },
  { value: "free_busy", label: "свободен/занят" },
  { value: "limited", label: "ограниченные подробности" },
  { value: "details", label: "подробности" },
  { value: "all", label: "всё" },
];

/** Функции — строки матрицы; ключу `freebusy` схемы соответствует функция `free_busy` в ошибках узла. */
const ROWS: Row[] = [
  { key: "invite_new", label: "Новое приглашение" },
  { key: "itip_updates", label: "Ответ и отмена к нашим событиям" },
  { key: "freebusy", label: "Занятость" },
  { key: "sharing", label: "Общий доступ и публикация" },
  { key: "group_post", label: "Письма в группы рассылки" },
  { key: "auto_reply", label: "Автоответ" },
  { key: "mdn", label: "Уведомление о прочтении наружу" },
  { key: "auto_forward", label: "Автопересылка наружу" },
];

/** Значения от узкого к широкому. */
const VALUES: Record<MatrixKey, { value: string; label: string }[]> = {
  invite_new: [
    { value: "button", label: "письмо с кнопкой" },
    { value: "auto", label: "авто" },
  ],
  itip_updates: TOGGLE,
  freebusy: DETAILS,
  sharing: DETAILS,
  group_post: [
    { value: "closed", label: "закрыто" },
    { value: "moderated", label: "с модерацией" },
    { value: "open", label: "открыто" },
  ],
  auto_reply: TOGGLE,
  mdn: TOGGLE,
  auto_forward: TOGGLE,
};

/** Клетки в ошибках узла адресуются функцией (`TrustFunction`): `freebusy` → `free_busy`. */
const fnOf = (key: MatrixKey): Schemas["TrustFunction"] => (key === "freebusy" ? "free_busy" : key);

const valueLabel = (key: MatrixKey, value: string | undefined) => VALUES[key].find((v) => v.value === value)?.label ?? value ?? "—";

/** Уровень, давший значение или потолок; `null` — умолчание контракта. */
const levelLabel = (level: Schemas["TrustLevel"] | null): string =>
  level == null ? "умолчание" : level === "installation" ? "установка" : "org" in level ? "организация" : "группа";

type Cell = {
  fixed: boolean;
  value?: string;
  source: Schemas["TrustLevel"] | null;
  ceiling?: string;
  ceilingSource: Schemas["TrustLevel"] | null;
};

// Схема даёт литеральные типы клеток; для таблицы они читаются по строковым ключам.
const cellOf = (view: Schemas["TrustView"], key: MatrixKey, peer: Peer): Cell => {
  const at = <T,>(o: unknown) => o as Record<string, Record<string, T>>;
  return {
    fixed: !!at<boolean>(view.fixed)[key]?.[peer],
    value: at<string>(view.effective.matrix)[key]?.[peer],
    source: at<Schemas["TrustLevel"] | null>(view.effective.source)[key]?.[peer] ?? null,
    ceiling: at<string>(view.effective.ceiling.matrix)[key]?.[peer],
    ceilingSource: at<Schemas["TrustLevel"] | null>(view.effective.ceiling.sources)[key]?.[peer] ?? null,
  };
};

/** Клетки «выше потолка»: «функция:тип» из ответа узла. */
const overCells = (view: Schemas["TrustView"]) =>
  new Set((view.effective.over_ceiling ?? []).map((c) => `${c.function}:${c.peer}`));

function MatrixTable({ render }: { render: (key: MatrixKey, peer: Peer) => ReactNode }) {
  return (
    <Table<Row> size="middle" pagination={false} rowKey="key" dataSource={ROWS}>
      <Table.Column title="Функция" dataIndex="label" width={250} />
      {PEERS.map((peer) => (
        <Table.Column<Row> key={peer} title={PEER_LABEL[peer]} render={(_, row) => render(row.key, peer)} />
      ))}
    </Table>
  );
}

const FIXED_HINT = "Закреплено контрактом: клетку не меняет никто, потолок — само значение.";

function FixedCell({ label }: { label: string }) {
  return (
    <div>
      <Tooltip title={FIXED_HINT}>
        <LockOutlined aria-label="закреплено" />
      </Tooltip>{" "}
      {label}
      <div>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          закреплено контрактом
        </Typography.Text>
      </div>
    </div>
  );
}

/** Под клеткой: источник действующего значения, метка «выше потолка», текст отказа узла 422. */
function Note(p: { source: string; over: boolean; error?: string }) {
  return (
    <>
      <div>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>источник: {p.source}</Typography.Text>{" "}
        {p.over && <Tag color="warning" style={{ fontSize: 12 }}>выше потолка</Tag>}
      </div>
      {p.error && (
        <div>
          <Typography.Text type="danger" style={{ fontSize: 12 }}>{p.error}</Typography.Text>
        </div>
      )}
    </>
  );
}

/** Действующая матрица с источником по клетке — чтение (карточка учётной записи, роли без изменения). */
export function EffectiveMatrix({ view }: { view: Schemas["TrustView"] }) {
  const over = overCells(view);
  return (
    <MatrixTable
      render={(key, peer) => {
        const cell = cellOf(view, key, peer);
        return cell.fixed ? (
          <FixedCell label={valueLabel(key, cell.value)} />
        ) : (
          <div>
            {valueLabel(key, cell.value)}
            <Note source={levelLabel(cell.source)} over={over.has(`${fnOf(key)}:${peer}`)} />
          </div>
        );
      }}
    />
  );
}

/**
 * Редактируемая матрица уровня: в клетке — `Select` из значений не выше потолка (выше — недоступны с
 * подсказкой «потолок уровня …: …»), значение уровня; ошибки 422 — у клетки с текстом `detail` узла.
 */
export function TrustMatrix(p: {
  view: Schemas["TrustView"];
  value: Schemas["TrustBody"];
  errors: Record<string, string>;
  onChange: (key: string, peer: string, value: string) => void;
}) {
  const over = overCells(p.view);
  return (
    <MatrixTable
      render={(key, peer) => {
        const cell = cellOf(p.view, key, peer);
        const label = ROWS.find((r) => r.key === key)?.label ?? key;
        if (cell.fixed) return <FixedCell label={valueLabel(key, cell.value)} />;
        const values = VALUES[key];
        const at = values.findIndex((v) => v.value === cell.ceiling);
        const current = String(
          (p.value as unknown as Record<string, Record<string, string | null>>)[key]?.[peer] ?? cell.value ?? values[0].value,
        );
        const hint =
          cell.ceilingSource == null
            ? `потолок по умолчанию контракта: ${valueLabel(key, cell.ceiling)}`
            : `потолок уровня ${levelLabel(cell.ceilingSource)}: ${valueLabel(key, cell.ceiling)}`;
        return (
          <div>
            <Select
              aria-label={`${label} — ${PEER_LABEL[peer]}`}
              style={{ width: 220 }}
              value={current}
              onChange={(v) => p.onChange(key, peer, v)}
              options={values.map((v, i) => ({
                value: v.value,
                label: v.label,
                disabled: i > at,
                title: i > at ? hint : v.label,
              }))}
            />
            <Note source={levelLabel(cell.source)} over={over.has(`${fnOf(key)}:${peer}`)} error={p.errors[`${fnOf(key)}:${peer}`]} />
          </div>
        );
      }}
    />
  );
}
