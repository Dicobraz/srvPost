// Журнал переписки (SRS 4.9, 5.2; UI-25): конверты писем по правилам журналирования — раздел роли
// «аудитор журнала» (прочие роли его не видят, права проверяет узел). Поиск: отправитель, получатель
// (включая скрытых), Message-ID, интервал, правило; записи — страницами по `next`. Управление правилами
// журналирования — волна Admin API правил потока почты: экран придёт вместе с эндпоинтами.
import { List } from "@refinedev/antd";
import { useCustom } from "@refinedev/core";
import { Button, DatePicker, Descriptions, Drawer, Form, Input, Space, Table, Tag, Typography } from "antd";
import type { Dayjs } from "dayjs";
import { useState } from "react";

import { download, type Schemas } from "../api/client";
import { useCursorPages } from "../components/cursor-pages";
import { interval, moment } from "../components/format";
import { StatusTag } from "../components/status";

const URL = "/api/v1/orgs/{org}/journal";

type Entry = Schemas["JournalEntryView"];
type Filters = { sender?: string; recipient?: string; message_id?: string; rule?: string; range?: [Dayjs | null, Dayjs | null] | null };

const sender = (r: Schemas["JournalRecordView"]) => r.sender || "<> (уведомление о недоставке)";

/** Конверт записи: просмотр — отдельное обращение к журналу (фиксируется журналом аудита узла), рядом выгрузка `.eml`. */
function Envelope({ id }: { id: string }) {
  const { result, query } = useCustom<Entry>({ url: `${URL}/${id}`, method: "get" });
  // До ответа Refine отдаёт пустой объект — запись распознаётся по конверту.
  const e = result.data as Entry | undefined;
  const r = e?.record;
  return (
    <Space direction="vertical" size="middle">
      <Descriptions column={1} size="small">
        <Descriptions.Item label="Время">{r && moment(r.at)}</Descriptions.Item>
        <Descriptions.Item label="Отправитель">{r && sender(r)}</Descriptions.Item>
        <Descriptions.Item label="Получатели">{r ? r.recipients.join(", ") : ""}</Descriptions.Item>
        <Descriptions.Item label="Message-ID">{r ? (r.message_id ?? "—") : ""}</Descriptions.Item>
        <Descriptions.Item label="Правило">{r ? r.rule : ""}</Descriptions.Item>
        <Descriptions.Item label="Хеш цепочки">
          {e?.hash && (
            <Typography.Text code copyable={{ text: e.hash }}>
              {e.hash}
            </Typography.Text>
          )}
        </Descriptions.Item>
      </Descriptions>
      <Button loading={query.isLoading} onClick={() => void download(`${URL}/${id}/export`, `${id}.eml`)}>
        Выгрузить .eml
      </Button>
    </Space>
  );
}

/** Целостность хеш-цепочки индекса (`verify chain`): индикатор состояния — ссылка на отчёт о проверке. */
function Chain() {
  const [open, setOpen] = useState(false);
  const { result, query } = useCustom<Schemas["ChainReportView"]>({ url: `${URL}/verify`, method: "get" });
  // До ответа Refine отдаёт пустой объект — отчёт распознаётся по числу записей.
  const data = result.data as Schemas["ChainReportView"] | undefined;
  const r = typeof data?.records === "number" ? data : undefined;
  return (
    <Space>
      {r ? (
        r.ok ? (
          <StatusTag role="ok">цепочка цела</StatusTag>
        ) : (
          <StatusTag role="err">разрыв цепочки</StatusTag>
        )
      ) : (
        <Typography.Text type="secondary">Целостность цепочки: {query.isLoading ? "проверка…" : "нет отчёта"}</Typography.Text>
      )}
      <Button type="link" style={{ padding: 0 }} onClick={() => setOpen(true)}>
        Отчёт целостности
      </Button>
      <Drawer open={open} title="Отчёт целостности цепочки" width={480} onClose={() => setOpen(false)} destroyOnHidden>
        <Descriptions column={1} size="small">
          <Descriptions.Item label="Состояние">
            {r ? (
              r.ok ? (
                <StatusTag role="ok">цепочка целостна</StatusTag>
              ) : (
                <StatusTag role="err">разрыв цепочки</StatusTag>
              )
            ) : (
              "…"
            )}
          </Descriptions.Item>
          <Descriptions.Item label="Проверено записей">{r ? r.records : "…"}</Descriptions.Item>
          <Descriptions.Item label="Разрыв">{r ? (r.broken_at ?? "—") : "…"}</Descriptions.Item>
        </Descriptions>
      </Drawer>
    </Space>
  );
}

export function JournalPage() {
  const [filters, setFilters] = useState<Filters>({});
  const [entry, setEntry] = useState<string | null>(null);
  const { page, loading, pager } = useCursorPages<Schemas["JournalPageView"]>(URL, {
    sender: filters.sender?.trim(),
    recipient: filters.recipient?.trim(),
    message_id: filters.message_id?.trim().replace(/^<|>$/g, ""),
    rule: filters.rule?.trim(),
    ...interval(filters.range),
  });
  return (
    <List title="Журнал переписки" breadcrumb={false} headerButtons={() => <Chain />}>
      <Form<Filters> layout="inline" onFinish={setFilters} style={{ marginBottom: 16, rowGap: 8 }}>
        <Form.Item name="sender" label="Отправитель">
          <Input allowClear placeholder="точный адрес" />
        </Form.Item>
        <Form.Item name="recipient" label="Получатель">
          <Input allowClear placeholder="точный адрес, включая скрытых" />
        </Form.Item>
        <Form.Item name="message_id" label="Message-ID">
          <Input allowClear />
        </Form.Item>
        <Form.Item name="rule" label="Правило">
          <Input allowClear placeholder="идентификатор правила" />
        </Form.Item>
        <Form.Item name="range" label="Интервал">
          <DatePicker.RangePicker showTime allowEmpty={[true, true]} />
        </Form.Item>
        <Button type="primary" htmlType="submit">
          Найти
        </Button>
      </Form>
      <Table<Entry> dataSource={page?.entries} loading={loading} rowKey="id" pagination={false}>
        <Table.Column<Entry> title="Время" render={(_, e) => moment(e.record.at)} />
        <Table.Column<Entry> title="Отправитель" render={(_, e) => sender(e.record)} />
        <Table.Column<Entry> title="Получатели" render={(_, e) => e.record.recipients.join(", ")} />
        <Table.Column<Entry> title="Message-ID" render={(_, e) => e.record.message_id ?? "—"} />
        <Table.Column<Entry> title="Правило" render={(_, e) => <Tag>{e.record.rule}</Tag>} />
        <Table.Column<Entry> title="Конверт" render={(_, e) => (
          <Button type="link" size="small" style={{ padding: 0 }} onClick={() => setEntry(e.id)}>
            Открыть
          </Button>
        )} />
      </Table>
      {pager}
      <Drawer open={entry !== null} title="Конверт записи" width={640} onClose={() => setEntry(null)} destroyOnHidden>
        {entry !== null && <Envelope id={entry} />}
      </Drawer>
    </List>
  );
}
