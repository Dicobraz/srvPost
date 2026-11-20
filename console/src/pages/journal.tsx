// Журнал переписки (SRS 4.9, 5.2; UI-25): конверты писем по правилам журналирования — раздел роли
// «аудитор журнала» (прочие роли его не видят, права проверяет узел). Поиск: отправитель, получатель
// (включая скрытых), Message-ID, интервал, правило; записи — страницами по `next`. Правила
// журналирования — отдельный раздел администратора организации (UI-26): `JournalRulesPage` ниже.
import { List } from "@refinedev/antd";
import { type HttpError, useCustom, useCustomMutation, useList } from "@refinedev/core";
import {
  Alert,
  Button,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Radio,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Typography,
} from "antd";
import type { Dayjs } from "dayjs";
import { useState } from "react";

import { download, type Schemas } from "../api/client";
import { AccountPick } from "../components/account-select";
import { useCursorPages } from "../components/cursor-pages";
import { interval, moment } from "../components/format";
import { StatusTag } from "../components/status";
import { useReadOnly } from "../providers/access";

const URL = "/api/v1/orgs/{org}/journal";

type Entry = Schemas["JournalEntryView"];
type Filters = { sender?: string; recipient?: string; message_id?: string; rule?: string; range?: [Dayjs | null, Dayjs | null] | null };

const sender = (r: Schemas["JournalRecordView"]) => r.sender || "<> (уведомление о недоставке)";

/** Конверт записи: просмотр — отдельное обращение к журналу (фиксируется журналом аудита узла), рядом выгрузка `.eml`. */
function Envelope({ id }: { id: string }) {
  const { result } = useCustom<Entry>({ url: `${URL}/${id}`, method: "get" });
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
      <Button onClick={() => void download(`${URL}/${id}/export`, `${id}.eml`)}>Выгрузить .eml</Button>
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

// --- Правила журналирования (UI-26, решение #171) -------------------------------------------------------------

const RULES_URL = "/api/v1/orgs/{org}/journal/rules";

type Rule = Schemas["JournalRuleView"];
type Scope = Schemas["JournalScope"];

/** Направление правила (решение #171): In — доставляемое, Out — отправляемое, Both — оба. */
const DIRECTIONS: { value: Schemas["JournalDirection"]; label: string }[] = [
  { value: "in", label: "входящие (In)" },
  { value: "out", label: "исходящие (Out)" },
  { value: "both", label: "оба (Both)" },
];

/** Приоритет наследования ([`JournalScope::priority`]): ящик (0) > группа (1) > организация (2). */
const priority = (scope: Scope) => (scope === "org" ? 2 : "group" in scope ? 1 : 0);

/** Уровень — источник значения (UI-23): подпись области правила. */
const source = (scope: Scope) => (scope === "org" ? "организация" : "group" in scope ? "группа" : "ящик");

/** Имена целей: группы — по имени, ящики — по имени входа; нет в списках — идентификатор. */
type Names = { group: Record<string, string>; mailbox: Record<string, string> };

const scopeText = (scope: Scope, names: Names) =>
  scope === "org"
    ? "организация"
    : "group" in scope
      ? `группа ${names.group[scope.group] ?? scope.group}`
      : `ящик ${names.mailbox[scope.mailbox] ?? scope.mailbox}`;

/** Включённые правила с подходящим направлением, покрывающие цель: сама цель, содержащие её группы (у ящика) или организация. */
function covering(rules: Rule[], target: Scope, direction: Schemas["JournalDirection"], membersOf: (g: string) => string[] | undefined) {
  return rules.filter((r) => {
    if (!r.enabled || (r.direction !== "both" && r.direction !== direction)) return false;
    if (r.scope === "org") return true;
    // Цель-организация покрывают только правила организации (выше); правило группы не покрывает её.
    if (target === "org") return false;
    if ("group" in r.scope) {
      return "group" in target ? r.scope.group === target.group : (membersOf(r.scope.group) ?? []).includes(target.mailbox);
    }
    return "mailbox" in target && r.scope.mailbox === target.mailbox;
  });
}

/** Действующее правило для цели (решение #171): самое конкретное по наследованию, при равных — по идентификатору. */
function effective(rules: Rule[], target: Scope, direction: Schemas["JournalDirection"], membersOf: (g: string) => string[] | undefined) {
  return covering(rules, target, direction, membersOf).sort((a, b) => priority(a.scope) - priority(b.scope) || a.id.localeCompare(b.id))[0];
}

/** «Источник значения» у строки (UI-23): включённое правило — источник для своей цели; выключенное — что действует вместо. */
function EffectiveNote(p: { rules: Rule[]; rule: Rule; membersOf: (g: string) => string[] | undefined }) {
  const style = { fontSize: 12 };
  if (!p.rule.enabled) {
    const eff = effective(p.rules, p.rule.scope, p.rule.direction, p.membersOf);
    return (
      <Typography.Text type="secondary" style={style}>
        {eff ? `выключено — действует ${eff.id} (источник: ${source(eff.scope)})` : "выключено — цель не журналируется"}
      </Typography.Text>
    );
  }
  return (
    <Typography.Text type="secondary" style={style}>
      источник: {source(p.rule.scope)}
    </Typography.Text>
  );
}

/** Выбор группы — цель правила: список групп организации по имени. */
function GroupPick(p: { value?: string; onChange?: (v: string) => void }) {
  const { result, query } = useList<Schemas["GroupInfo"]>({ resource: "groups", pagination: { mode: "off" } });
  return (
    <Select
      aria-label="Группа цели"
      showSearch
      optionFilterProp="label"
      value={p.value}
      onChange={p.onChange}
      loading={query.isLoading}
      placeholder="Выберите группу"
      options={(result.data ?? []).map((g) => ({ value: g.id, label: g.name }))}
    />
  );
}

type RuleForm = {
  id: string;
  kind: "org" | "group" | "mailbox";
  group?: string;
  mailbox?: string;
  direction: Schemas["JournalDirection"];
  enabled: boolean;
};

/** Тело `PUT` из формы: область — `"org"`, `{"group"}` или `{"mailbox"}`. */
const ruleBody = (v: RuleForm): Schemas["JournalRuleBody"] => ({
  scope: v.kind === "org" ? "org" : v.kind === "group" ? { group: v.group ?? "" } : { mailbox: v.mailbox ?? "" },
  direction: v.direction,
  enabled: v.enabled,
});

/** Правило в форму: область — вид цели и выбор группы или ящика. */
const ruleForm = (r: Rule): RuleForm =>
  r.scope === "org"
    ? { id: r.id, kind: "org", direction: r.direction, enabled: r.enabled }
    : "group" in r.scope
      ? { id: r.id, kind: "group", group: r.scope.group, direction: r.direction, enabled: r.enabled }
      : { id: r.id, kind: "mailbox", mailbox: r.scope.mailbox, direction: r.direction, enabled: r.enabled };

/** Поля правила: идентификатор (в записях журнала — менять нельзя), цель, направление, включение. */
function RuleFields(p: { editing: boolean; names: Names }) {
  const kind = Form.useWatch("kind", Form.useFormInstance<RuleForm>()) ?? "org";
  return (
    <>
      <Form.Item
        name="id"
        label="Идентификатор правила"
        extra="До 64 символов без пробелов; попадает в записи журнала."
        rules={[
          { required: true, message: "Укажите идентификатор" },
          { pattern: /^\S{1,64}$/, message: "До 64 символов без пробелов" },
        ]}
      >
        <Input disabled={p.editing} placeholder="org-all" />
      </Form.Item>
      <Form.Item name="kind" label="Цель">
        <Radio.Group
          options={[
            { value: "org", label: "Организация" },
            { value: "group", label: "Группа рассылки" },
            { value: "mailbox", label: "Ящик" },
          ]}
        />
      </Form.Item>
      {kind === "group" && (
        <Form.Item name="group" label="Группа" rules={[{ required: true, message: "Выберите группу" }]}>
          <GroupPick />
        </Form.Item>
      )}
      {kind === "mailbox" && (
        <Form.Item name="mailbox" label="Ящик" rules={[{ required: true, message: "Выберите ящик" }]}>
          <AccountPick names={p.names.mailbox} />
        </Form.Item>
      )}
      <Form.Item name="direction" label="Направление" rules={[{ required: true, message: "Выберите направление" }]}>
        <Select aria-label="Направление" options={DIRECTIONS} />
      </Form.Item>
      <Form.Item
        name="enabled"
        label="Включено"
        valuePropName="checked"
        extra="Выключенное правило писем не касается — вместо него действует более широкое."
      >
        <Switch />
      </Form.Item>
    </>
  );
}

/** Окно правила: добавление и изменение — `PUT` целиком по идентификатору; отказ узла (RFC 9457) — у формы. */
function RuleModal(p: { open: { row?: Rule } | null; names: Names; onClose: () => void; onSaved: () => void }) {
  const [form] = Form.useForm<RuleForm>();
  const [error, setError] = useState<string>();
  const editing = Boolean(p.open?.row);
  const { mutate, mutation } = useCustomMutation<Schemas["JournalRuleView"], HttpError, Schemas["JournalRuleBody"]>();
  const close = () => {
    setError(undefined);
    p.onClose();
  };
  const save = (v: RuleForm) =>
    mutate(
      {
        url: `${RULES_URL}/${encodeURIComponent(v.id.trim())}`,
        method: "put",
        values: ruleBody(v),
        errorNotification: false,
        successNotification: {
          type: "success",
          message: editing ? "Правило журналирования сохранено" : "Правило журналирования создано",
        },
      },
      {
        onSuccess: () => {
          close();
          p.onSaved();
        },
        // Ошибка сервера (RFC 9457) — у формы: дубликат цели с направлением (409) с подсказкой узла,
        // несуществующие группа или ящик области (422), непригодный идентификатор (400).
        onError: (e) => setError(e.message),
      },
    );
  return (
    <Modal
      open={p.open !== null}
      title={p.open?.row ? `Изменить: ${p.open.row.id}` : "Добавить правило"}
      okText="Сохранить"
      confirmLoading={mutation.isPending}
      onOk={() => form.submit()}
      onCancel={close}
      destroyOnHidden
    >
      {error && <Alert type="error" showIcon style={{ marginBottom: 16 }} message={error} />}
      <Form
        form={form}
        layout="vertical"
        preserve={false}
        initialValues={p.open?.row ? ruleForm(p.open.row) : { kind: "org", direction: "both", enabled: true }}
        onFinish={save}
      >
        <RuleFields editing={editing} names={p.names} />
      </Form>
    </Modal>
  );
}

/**
 * Раздел «Правила журналирования» (UI-26, решение #171): ведёт администратор организации — аудитор
 * журнала правил не видит (развод ролей: записи журнала — его раздел «Журнал переписки», узел на
 * правила отвечает 403). Список в порядке наследования ящик > группа > организация; у строки —
 * «источник значения» (UI-23); добавление и изменение в окне, удаление с подтверждением. Изменение
 * действует на будущие письма без перезапуска узла (SMTP-53) — предупреждений в интерфейсе нет.
 */
export function JournalRulesPage() {
  const readOnly = useReadOnly("journal-rules");
  const { result, query } = useCustom<Schemas["JournalRulesView"]>({
    url: RULES_URL,
    method: "get",
    errorNotification: false,
    queryOptions: { retry: false },
  });
  const groups = useList<Schemas["GroupInfo"]>({ resource: "groups", pagination: { mode: "off" } });
  const accounts = useList<Schemas["AccountInfo"]>({ resource: "accounts", pagination: { mode: "off" } });
  const rules = query.isSuccess ? result.data.rules : undefined;
  const names: Names = {
    group: Object.fromEntries((groups.result.data ?? []).map((g) => [g.id, g.name])),
    mailbox: Object.fromEntries((accounts.result.data ?? []).map((a) => [a.id, a.login])),
  };
  const membersOf = (g: string) =>
    (groups.result.data ?? []).find((x) => x.id === g)?.members.flatMap((m) => ("account" in m ? [m.account] : []));
  const [open, setOpen] = useState<{ row?: Rule } | null>(null);
  const { mutate: remove } = useCustomMutation<Rule, HttpError, undefined>();
  const del = (r: Rule) =>
    remove(
      {
        url: `${RULES_URL}/${encodeURIComponent(r.id)}`,
        method: "delete",
        values: undefined,
        successNotification: { type: "success", message: `Правило ${r.id} удалено` },
      },
      { onSuccess: () => void query.refetch() },
    );
  return (
    <List title="Правила журналирования" breadcrumb={false} headerButtons={() => null}>
      <Typography.Paragraph type="secondary">
        {`Правило журналирует письма цели — организации, группы рассылки или ящика — по направлению In/Out/Both; в записях журнала — его идентификатор. Изменение действует на будущие письма, без перезапуска узла.`}
      </Typography.Paragraph>
      {query.isError && <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="Правила недоступны: узел ответил отказом." />}
      {!readOnly && (
        <Button type="primary" style={{ marginBottom: 16 }} onClick={() => setOpen({})}>
          Добавить правило
        </Button>
      )}
      <Table<Rule>
        dataSource={rules}
        loading={query.isLoading}
        rowKey="id"
        pagination={false}
        locale={{ emptyText: "Правил нет — переписка не журналируется" }}
      >
        <Table.Column<Rule> title="Правило" render={(_, r) => <Typography.Text code>{r.id}</Typography.Text>} />
        <Table.Column<Rule> title="Цель" render={(_, r) => scopeText(r.scope, names)} />
        <Table.Column<Rule> title="Направление" render={(_, r) => DIRECTIONS.find((d) => d.value === r.direction)?.label} />
        <Table.Column<Rule>
          title="Включено"
          render={(_, r) => (r.enabled ? <StatusTag role="ok">да</StatusTag> : <StatusTag role="info">нет</StatusTag>)}
        />
        <Table.Column<Rule>
          title="Наследование"
          render={(_, r) => <EffectiveNote rules={rules ?? []} rule={r} membersOf={membersOf} />}
        />
        {!readOnly && (
          <Table.Column<Rule>
            title="Действия"
            width={180}
            render={(_, r) => (
              <Space>
                <Button size="small" onClick={() => setOpen({ row: r })}>
                  Изменить
                </Button>
                <Popconfirm
                  title={`Удалить правило ${r.id}?`}
                  description="Записи журнала останутся."
                  okText="Удалить"
                  okButtonProps={{ danger: true }}
                  onConfirm={() => del(r)}
                >
                  <Button size="small" danger>
                    Удалить
                  </Button>
                </Popconfirm>
              </Space>
            )}
          />
        )}
      </Table>
      <RuleModal open={open} names={names} onClose={() => setOpen(null)} onSaved={() => void query.refetch()} />
    </List>
  );
}
