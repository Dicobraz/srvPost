// Раздел «Признаки риска» (UI-24, решение 126): каталог признаков (пакет поставщика с изменениями
// установки и организации), пороги действий, пакеты поставщика, источники TI и журнал срабатываний.
// Уровень «установка» — администратору установки (вкладки «Пакеты» и «Источники TI» — только ему),
// «организация» — администратору организации. Правка в строке — для организации не мягче уровня
// установки (базовые значения видит администратор установки, без них пол проверяет узел), отказ
// 422 — у поля с текстом `detail` сервера. Ключ фида — только ссылка на секрет (`SecretRef`),
// значение узлу не вводится; отчёт проверки пакета виден до активации, активация — отдельным действием.
import { Show } from "@refinedev/antd";
import { type HttpError, useCustom, useCustomMutation, usePermissions } from "@refinedev/core";
import {
  Alert,
  App as AntdApp,
  AutoComplete,
  Button,
  Card,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Radio,
  Select,
  Space,
  Switch,
  Table,
  Tabs,
  Tag,
  Typography,
  Upload,
} from "antd";
import type { Dayjs } from "dayjs";
import { type ReactNode, useState } from "react";
import { useNavigate } from "react-router";

import { request, type Schemas } from "../api/client";
import { useCursorPages } from "../components/cursor-pages";
import { interval, moment, when } from "../components/format";
import { orgName, useOrgs } from "../components/orgs";
import { StatusTag } from "../components/status";
import { useReadOnly } from "../providers/access";

const INST_SIGNALS = "/api/v1/risk/signals";
const ORG_SIGNALS = "/api/v1/orgs/{org}/risk/signals";
const INST_THRESHOLDS = "/api/v1/risk/thresholds";
const ORG_THRESHOLDS = "/api/v1/orgs/{org}/risk/thresholds";
const PACKAGES_URL = "/api/v1/risk/packages";
const SOURCES_URL = "/api/v1/risk/sources";
const HITS_URL = "/api/v1/orgs/{org}/risk/hits";

type Signal = Schemas["SignalView"];
type SignalDraft = { row: Signal; body: Schemas["SignalBody"] };
type RiskProblem = Partial<Schemas["RiskProblem"]>;

/** Действия от мягкого к строгому (контракт): порядок — для запрета «мягче уровня установки». */
const ACTIONS: { value: Schemas["RiskAction"]; label: string }[] = [
  { value: "none", label: "нет" },
  { value: "tag", label: "пометка" },
  { value: "junk", label: "«Спам»" },
  { value: "quarantine", label: "карантин" },
  { value: "reject", label: "отказ" },
];
const actionOrder = (a?: Schemas["RiskAction"] | null) => ACTIONS.findIndex((x) => x.value === a);
const actionLabel = (a?: Schemas["RiskAction"] | null) => (a ? (ACTIONS.find((x) => x.value === a)?.label ?? a) : "—");

const MODE_LABELS: Record<Schemas["Mode"], string> = { report: "только отчёт", enforce: "применять" };
const MODE_OPTIONS = (Object.keys(MODE_LABELS) as Schemas["Mode"][]).map((m) => ({ value: m, label: MODE_LABELS[m] }));

/** Встроенные детекторы (без детектора по списку TI) — значения контракта. */
type NamedDetector = Exclude<Schemas["Detector"], { list_match: { field: Schemas["Field"]; list: string } }>;
const NAMED_DETECTORS: { value: NamedDetector; label: string }[] = [
  { value: "thread_new_attachment_type", label: "новый тип вложения в переписке" },
  { value: "encrypted_archive", label: "шифрованный архив" },
  { value: "disk_image_or_shortcut", label: "образ диска или ярлык" },
  { value: "thread_new_link_domain", label: "новый домен ссылки в переписке" },
  { value: "reply_to_changed", label: "сменился Reply-To" },
];
const DETECTOR_LABELS: Record<string, string> = Object.fromEntries(NAMED_DETECTORS.map((d) => [d.value, d.label]));
const FIELD_LABELS: Record<string, string> = {
  sender_ip: "IP отправителя",
  link_domain: "домен ссылки",
  link_url: "адрес ссылки",
  from_domain: "домен отправителя",
  attachment_sha256: "SHA-256 вложения",
};

const detectorText = (d?: Signal["detector"]) =>
  !d ? "—" : typeof d === "string" ? (DETECTOR_LABELS[d] ?? d) : `список ${d.list_match.list} (${FIELD_LABELS[d.list_match.field] ?? d.list_match.field})`;

const originText = (o: Signal["origin"]) => (o === "vendor" ? "поставщик" : "администратор");
/** Уровень-источник действующего значения: нет отличия от пакета — пакет поставщика. */
const sourceText = (s?: Signal["source"]) => (s == null ? "пакет" : typeof s === "string" ? "установка" : "организация");

const DETECTORS_OF_FORM = NAMED_DETECTORS;
const FIELDS_OF_FORM = Object.entries(FIELD_LABELS).map(([value, label]) => ({ value: value as Schemas["Field"], label }));

/** Тело `PUT` из правки в строке: признак поставщика — вес, действие, режим; свой `org.*` — целиком. */
const signalBody = (d: SignalDraft): Schemas["SignalBody"] =>
  d.row.id.startsWith("org.")
    ? {
        detector: d.body.detector ?? d.row.detector ?? undefined,
        weight: d.body.weight ?? d.row.weight ?? undefined,
        threshold: d.body.threshold ?? d.row.threshold ?? undefined,
        action: d.body.action ?? d.row.action ?? undefined,
        mode: d.body.mode ?? d.row.mode ?? undefined,
      }
    : {
        weight: d.body.weight ?? d.row.weight ?? undefined,
        action: d.body.action ?? d.row.action ?? undefined,
        mode: d.body.mode ?? d.row.mode ?? undefined,
      };

type Floor = { weight?: number; action?: Schemas["RiskAction"]; mode?: Schemas["Mode"] };

/** Пол: организация не может выбрать значение мягче уровня установки (вес ниже, действие мягче, «только отчёт»). */
const softer = (d: SignalDraft, floor?: Floor) => {
  if (!floor) return false;
  const w = d.body.weight ?? d.row.weight;
  const a = d.body.action ?? d.row.action;
  const m = d.body.mode ?? d.row.mode;
  return (
    (w != null && floor.weight != null && w < floor.weight) ||
    (a != null && floor.action != null && actionOrder(a) < actionOrder(floor.action)) ||
    (m === "report" && floor.mode === "enforce")
  );
};

/** Каталог уровня установки — база «не мягче» при правке организации (кэш общего запроса). */
function useBaseSignals(enabled: boolean): Signal[] | undefined {
  const { result, query } = useCustom<Schemas["SignalsView"]>({
    url: INST_SIGNALS,
    method: "get",
    errorNotification: false,
    queryOptions: { enabled, retry: false },
  });
  const signals = query.isSuccess ? result.data.signals : undefined;
  return enabled && Array.isArray(signals) ? signals : undefined;
}

/** Текст ошибки 422 у поля правки: `detail` сервера. */
function FieldError(p: { text?: string }) {
  return p.text ? (
    <Typography.Text type="danger" style={{ display: "block", fontSize: 12 }}>
      {p.text}
    </Typography.Text>
  ) : null;
}

type NewSignalForm = {
  id?: string;
  detector_kind: "named" | "list";
  detector?: string;
  field?: Schemas["Field"];
  list?: string;
  weight?: number;
  threshold?: number;
  action?: Schemas["RiskAction"];
  mode: Schemas["Mode"];
};

/** Окно «свой признак `org.*`»: идентификатор, детектор (встроенный или по списку TI), вес, порог, действие, режим. */
function NewSignalModal(p: { open: boolean; url: string; onClose: () => void; onSaved: () => void }) {
  const [form] = Form.useForm<NewSignalForm>();
  const [error, setError] = useState<string>();
  const kind = Form.useWatch("detector_kind", form) ?? "named";
  const { mutate, mutation } = useCustomMutation<Schemas["SignalView"], HttpError, Schemas["SignalBody"]>();
  const close = () => {
    setError(undefined);
    p.onClose();
  };
  const save = (v: NewSignalForm) => {
    const detector: Schemas["Detector"] =
      v.detector_kind === "list"
        ? { list_match: { field: v.field ?? "from_domain", list: v.list ?? "" } }
        : (NAMED_DETECTORS.find((d) => d.value === v.detector)?.value ?? "reply_to_changed");
    mutate(
      {
        url: `${p.url}/${encodeURIComponent((v.id ?? "").trim())}`,
        method: "put",
        values: { detector, weight: v.weight, threshold: v.threshold, action: v.action, mode: v.mode },
        errorNotification: false,
        successNotification: { type: "success", message: "Признак создан" },
      },
      {
        onSuccess: () => {
          close();
          p.onSaved();
        },
        onError: (e) => setError((e.problem as RiskProblem)?.detail ?? e.message),
      },
    );
  };
  return (
    <Modal open={p.open} title="Свой признак" okText="Создать" confirmLoading={mutation.isPending} onOk={() => form.submit()} onCancel={close} destroyOnHidden>
      {error && <Alert type="error" showIcon style={{ marginBottom: 16 }} message={error} />}
      <Form form={form} layout="vertical" preserve={false} initialValues={{ detector_kind: "named", mode: "report" }} onFinish={save}>
        <Form.Item
          name="id"
          label="Идентификатор"
          extra="Свой признак начинается с org.; идентификатор попадает в журнал срабатываний."
          rules={[{ required: true, message: "Укажите идентификатор" }, { pattern: /^org\.[a-z0-9._-]+$/, message: "Вид org.<имя> из строчных букв, цифр, точки, подчёркивания и дефиса" }]}
        >
          <Input placeholder="org.unusual_attachment" maxLength={64} />
        </Form.Item>
        <Form.Item name="detector_kind" label="Детектор">
          <Radio.Group
            options={[
              { value: "named", label: "встроенный" },
              { value: "list", label: "по списку TI" },
            ]}
          />
        </Form.Item>
        {kind === "named" ? (
          <Form.Item name="detector" label="Детектор" rules={[{ required: true, message: "Выберите детектор" }]}>
            <Select aria-label="Детектор" options={DETECTORS_OF_FORM} />
          </Form.Item>
        ) : (
          <>
            <Form.Item name="field" label="Поле письма" rules={[{ required: true, message: "Выберите поле" }]}>
              <Select aria-label="Поле письма" options={FIELDS_OF_FORM} />
            </Form.Item>
            <Form.Item name="list" label="Список TI" rules={[{ required: true, message: "Укажите список" }]}>
              <Input placeholder="bad-domains" maxLength={64} />
            </Form.Item>
          </>
        )}
        <Form.Item name="weight" label="Вес, 0–100" rules={[{ required: true, message: "Укажите вес" }]}>
          <InputNumber aria-label="Вес нового признака" min={0} max={100} style={{ width: 120 }} />
        </Form.Item>
        <Form.Item name="threshold" label="Порог силы срабатывания, 0–100" rules={[{ required: true, message: "Укажите порог" }]}>
          <InputNumber aria-label="Порог нового признака" min={0} max={100} style={{ width: 120 }} />
        </Form.Item>
        <Form.Item name="action" label="Действие" rules={[{ required: true, message: "Выберите действие" }]}>
          <Select aria-label="Действие нового признака" options={ACTIONS} />
        </Form.Item>
        <Form.Item name="mode" label="Режим" extra="«Только отчёт» — признак пишется в журнал срабатываний, письмо не меняется.">
          <Select aria-label="Режим нового признака" options={MODE_OPTIONS} />
        </Form.Item>
      </Form>
    </Modal>
  );
}

/** Вкладка «Каталог»: таблица действующего каталога уровня с правкой в строке и осиротевшими изменениями. */
function CatalogTab(p: { level: "installation" | "org"; editable: boolean; instAdmin: boolean }) {
  const url = p.level === "installation" ? INST_SIGNALS : ORG_SIGNALS;
  const { result, query } = useCustom<Schemas["SignalsView"]>({
    url,
    method: "get",
    errorNotification: false,
    queryOptions: { retry: false },
  });
  const refetch = () => query.refetch();
  const base = useBaseSignals(p.level === "org" && p.instAdmin);
  const signals = query.isSuccess ? result.data.signals : undefined;
  const fresh = (signals ?? []).filter((s) => !s.orphaned);
  const orphaned = (signals ?? []).filter((s) => s.orphaned);

  const [draft, setDraft] = useState<SignalDraft | null>(null);
  const [rowErrors, setRowErrors] = useState<Record<string, string>>({});
  const [creating, setCreating] = useState(false);
  const { mutate, mutation } = useCustomMutation<Schemas["SignalView"], HttpError, Schemas["SignalBody"]>();
  const { mutate: reset, mutation: resetting } = useCustomMutation<Schemas["SignalView"], HttpError, undefined>();

  /** Пол уровня установки для признака: база «не мягче» (известна администратору установки). */
  const floorOf = (row: Signal): Floor | undefined => {
    const b = base?.find((x) => x.id === row.id);
    return b ? { weight: b.weight ?? undefined, action: b.action ?? undefined, mode: b.mode ?? undefined } : undefined;
  };
  /** Изменение этого уровня — можно сбросить (к значениям уровня выше или пакета). */
  const ownChange = (row: Signal) =>
    row.orphaned || (p.level === "installation" ? row.source === "installation" : typeof row.source === "object" && row.source != null);

  const save = () => {
    if (!draft) return;
    mutate(
      {
        url: `${url}/${encodeURIComponent(draft.row.id)}`,
        method: "put",
        values: signalBody(draft),
        errorNotification: false,
        successNotification: { type: "success", message: "Признак сохранён" },
      },
      {
        onSuccess: () => {
          setDraft(null);
          setRowErrors({});
          void refetch();
        },
        // 422 «мягче уровня установки» — у поля: поле из `errors` признака, текст — `detail` сервера.
        onError: (e) => {
          const problem = e.problem as RiskProblem;
          const fields: Record<string, string> = {};
          for (const v of problem?.errors ?? []) if (v.signal === draft.row.id) fields[v.field] = problem?.detail ?? e.message;
          setRowErrors(Object.keys(fields).length ? fields : { _all: problem?.detail ?? e.message });
        },
      },
    );
  };
  const doReset = (row: Signal) =>
    reset(
      {
        url: `${url}/${encodeURIComponent(row.id)}`,
        method: "delete",
        values: undefined,
        successNotification: { type: "success", message: `Изменение ${row.id} сброшено` },
      },
      { onSuccess: () => void refetch() },
    );

  const startEdit = (row: Signal) => {
    setRowErrors({});
    setDraft({
      row,
      body: {
        detector: row.detector ?? undefined,
        weight: row.weight ?? undefined,
        threshold: row.threshold ?? undefined,
        action: row.action ?? undefined,
        mode: row.mode ?? undefined,
      },
    });
  };

  const draftRow = draft?.row.id;
  const blocked = draft ? softer(draft, floorOf(draft.row)) : false;
  const generalError = rowErrors._all && Object.keys(rowErrors).length === 1 ? rowErrors._all : undefined;
  /** Содержимое ячейки правки; вне правки строки — null (колонка показывает значение). */
  const edit = (row: Signal, cell: (d: SignalDraft) => ReactNode): ReactNode => (draftRow === row.id && draft ? cell(draft) : null);

  return (
    <>
      <Space wrap style={{ marginBottom: 16 }}>
        <Typography.Text type="secondary">
          Действующий каталог: пакет поставщика с изменениями{p.level === "installation" ? " установки" : " установки и организации"}; у строки —
          источник значения.
        </Typography.Text>
        {p.editable && (
          <Button type="primary" onClick={() => setCreating(true)}>
            Добавить признак
          </Button>
        )}
      </Space>
      {generalError && <Alert type="error" showIcon style={{ marginBottom: 16 }} message={generalError} />}
      {query.isError && <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="Каталог недоступен: узел ответил отказом." />}
      <Table<Signal> dataSource={fresh} loading={query.isLoading} rowKey="id" pagination={false} size="small">
        <Table.Column<Signal> title="Признак" render={(_, r) => <Typography.Text code>{r.id}</Typography.Text>} />
        <Table.Column<Signal> title="Происхождение" render={(_, r) => originText(r.origin)} />
        <Table.Column<Signal> title="Детектор" render={(_, r) => detectorText(r.detector)} />
        <Table.Column<Signal>
          title="Вес"
          render={(_, r) =>
            edit(r, (d) => (
              <Space direction="vertical" size={0}>
                <InputNumber
                  aria-label={`Вес ${r.id}`}
                  min={0}
                  max={100}
                  value={d.body.weight}
                  onChange={(v) => setDraft({ ...d, body: { ...d.body, weight: v ?? undefined } })}
                />
                {(() => {
                  const floor = floorOf(r);
                  return floor?.weight != null && (d.body.weight ?? r.weight ?? 0) < floor.weight ? (
                    <Typography.Text type="danger" style={{ fontSize: 12 }}>
                      {`не ниже уровня установки: ${floor.weight}`}
                    </Typography.Text>
                  ) : null;
                })()}
                <FieldError text={rowErrors.weight} />
              </Space>
            )) ?? (r.weight ?? "—")
          }
        />
        <Table.Column<Signal>
          title="Порог"
          render={(_, r) =>
            r.id.startsWith("org.") ? (
              (edit(r, (d) => (
                <Space direction="vertical" size={0}>
                  <InputNumber
                    aria-label={`Порог ${r.id}`}
                    min={0}
                    max={100}
                    value={d.body.threshold}
                    onChange={(v) => setDraft({ ...d, body: { ...d.body, threshold: v ?? undefined } })}
                  />
                  <FieldError text={rowErrors.threshold} />
                </Space>
              )) ??
                (r.threshold ?? "—"))
            ) : (
              (r.threshold ?? "—")
            )
          }
        />
        <Table.Column<Signal>
          title="Действие"
          render={(_, r) =>
            edit(r, (d) => {
              const floor = floorOf(r);
              return (
                <Space direction="vertical" size={0}>
                  <Select
                    aria-label={`Действие ${r.id}`}
                    style={{ width: 150 }}
                    value={d.body.action}
                    onChange={(v) => setDraft({ ...d, body: { ...d.body, action: v } })}
                    options={ACTIONS.map((a) => {
                      const below = floor?.action != null && actionOrder(a.value) < actionOrder(floor.action);
                      return { ...a, disabled: below, title: below ? `не мягче уровня установки: ${actionLabel(floor.action)}` : a.label };
                    })}
                  />
                  <FieldError text={rowErrors.action} />
                </Space>
              );
            }) ?? actionLabel(r.action)
          }
        />
        <Table.Column<Signal>
          title="Режим"
          render={(_, r) =>
            edit(r, (d) => {
              const floor = floorOf(r);
              return (
                <Space direction="vertical" size={0}>
                  <Select
                    aria-label={`Режим ${r.id}`}
                    style={{ width: 150 }}
                    value={d.body.mode}
                    onChange={(v) => setDraft({ ...d, body: { ...d.body, mode: v } })}
                    options={MODE_OPTIONS.map((o) => {
                      const blockedReport = o.value === "report" && floor?.mode === "enforce";
                      return { ...o, disabled: blockedReport, title: blockedReport ? "не мягче уровня установки: применять" : o.label };
                    })}
                  />
                  <FieldError text={rowErrors.mode} />
                </Space>
              );
            }) ??
              (r.mode === "report" ? (
                <Space size={4}>
                  <StatusTag role="warn">только отчёт</StatusTag>
                  {r.since && <Typography.Text type="secondary">с {when(r.since)}</Typography.Text>}
                </Space>
              ) : (
                MODE_LABELS[r.mode ?? "enforce"]
              ))
          }
        />
        <Table.Column<Signal> title="Источник значения" render={(_, r) => sourceText(r.source)} />
        <Table.Column<Signal> title="Действует с" render={(_, r) => when(r.since)} />
        {p.editable && (
          <Table.Column<Signal>
            title="Действия"
            width={220}
            render={(_, r) =>
              draftRow === r.id ? (
                <Space>
                  <Button type="primary" size="small" disabled={blocked} title={blocked ? "не мягче уровня установки" : undefined} loading={mutation.isPending} onClick={save}>
                    Сохранить
                  </Button>
                  <Button size="small" onClick={() => setDraft(null)}>
                    Отмена
                  </Button>
                </Space>
              ) : (
                <Space>
                  <Button size="small" onClick={() => startEdit(r)}>
                    Изменить
                  </Button>
                  {ownChange(r) && (
                    <Popconfirm
                      title={`Сбросить изменение ${r.id}?`}
                      description={r.orphaned && r.id.startsWith("org.") ? "Свой признак будет удалён." : "Действовать будет уровень выше или пакет."}
                      okText="Сбросить"
                      okButtonProps={{ danger: true }}
                      onConfirm={() => doReset(r)}
                    >
                      <Button size="small" danger loading={resetting.isPending}>
                        Сбросить
                      </Button>
                    </Popconfirm>
                  )}
                </Space>
              )
            }
          />
        )}
      </Table>
      {orphaned.length > 0 && (
        <>
          <Typography.Title level={5} style={{ marginTop: 24 }}>
            Осиротевшие изменения
          </Typography.Title>
          <Typography.Paragraph type="secondary">
            Признака больше нет в действующем пакете поставщика, а изменение этого уровня осталось — известно только само изменение. Его можно сбросить.
          </Typography.Paragraph>
          <Table<Signal> dataSource={orphaned} rowKey="id" pagination={false} size="small">
            <Table.Column<Signal> title="Признак" render={(_, r) => <Typography.Text code>{r.id}</Typography.Text>} />
            <Table.Column<Signal> title="Вес" render={(_, r) => r.weight ?? "—"} />
            <Table.Column<Signal> title="Действие" render={(_, r) => actionLabel(r.action)} />
            <Table.Column<Signal> title="Режим" render={(_, r) => (r.mode ? MODE_LABELS[r.mode] : "—")} />
            {p.editable && (
              <Table.Column<Signal>
                title="Действия"
                render={(_, r) => (
                  <Popconfirm
                    title={`Сбросить изменение ${r.id}?`}
                    description={r.id.startsWith("org.") ? "Свой признак будет удалён." : "Действовать будет пакет поставщика."}
                    okText="Сбросить"
                    okButtonProps={{ danger: true }}
                    onConfirm={() => doReset(r)}
                  >
                    <Button size="small" danger>
                      Сбросить
                    </Button>
                  </Popconfirm>
                )}
              />
            )}
          </Table>
        </>
      )}
      <NewSignalModal open={creating} url={url} onClose={() => setCreating(false)} onSaved={() => void refetch()} />
    </>
  );
}

// --- Пороги ---------------------------------------------------------------------------------------------------------

const THRESHOLD_FIELDS: { key: keyof Schemas["Thresholds"]; label: string }[] = [
  { key: "tag", label: "Порог пометки письма" },
  { key: "junk", label: "Порог папки «Спам»" },
  { key: "quarantine", label: "Порог карантина" },
  { key: "reject", label: "Порог отказа" },
];

/** Вкладка «Пороги»: четыре числа с подписями действий; у организации — не выше уровня установки. */
function ThresholdsTab(p: { level: "installation" | "org"; editable: boolean; instAdmin: boolean }) {
  const url = p.level === "installation" ? INST_THRESHOLDS : ORG_THRESHOLDS;
  const { result, query } = useCustom<Schemas["ThresholdsView"]>({
    url,
    method: "get",
    errorNotification: false,
    queryOptions: { retry: false },
  });
  const baseQuery = useCustom<Schemas["ThresholdsView"]>({
    url: INST_THRESHOLDS,
    method: "get",
    errorNotification: false,
    queryOptions: { enabled: p.level === "org" && p.instAdmin, retry: false },
  });
  const refetch = () => query.refetch();
  const base =
    p.level === "org" && p.instAdmin && baseQuery.query.isSuccess ? baseQuery.result.data.effective : undefined;
  const view = query.isSuccess ? result.data : undefined;
  const [values, setValues] = useState<Schemas["Thresholds"] | null>(null);
  const [error, setError] = useState<string>();
  const { mutate, mutation } = useCustomMutation<Schemas["ThresholdsView"], HttpError, Schemas["ThresholdsBody"]>();

  const current = values ?? view?.own ?? view?.effective;
  const dirty = values != null && view != null && JSON.stringify(values) !== JSON.stringify(view.own ?? view.effective);
  const aboveBase = base != null && current != null && THRESHOLD_FIELDS.some(({ key }) => current[key] > base[key]);

  const save = () => {
    if (!current) return;
    mutate(
      {
        url,
        method: "put",
        values: { tag: current.tag, junk: current.junk, quarantine: current.quarantine, reject: current.reject },
        errorNotification: false,
        successNotification: { type: "success", message: "Пороги сохранены" },
      },
      {
        onSuccess: () => {
          setValues(null);
          setError(undefined);
          void refetch();
        },
        onError: (e) => setError((e.problem as RiskProblem)?.detail ?? e.message),
      },
    );
  };

  return (
    <>
      <Typography.Paragraph type="secondary">
        {`Порог — балл письма, с которого действует действие: пометка, папка «Спам», карантин, отказ (по возрастанию балла). Действует самое строгое: у каждого уровня свои пороги, но действие наступает по низшему.`}
      </Typography.Paragraph>
      {error && <Alert type="error" showIcon style={{ marginBottom: 16 }} message={error} />}
      {query.isError && <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="Пороги недоступны: узел ответил отказом." />}
      {view && current && (
        <>
          <Space wrap size="large" style={{ marginBottom: 16 }}>
            {THRESHOLD_FIELDS.map(({ key, label }) => (
              <Space key={key} direction="vertical" size={0}>
                <InputNumber
                  aria-label={label}
                  min={0}
                  max={1000}
                  disabled={!p.editable}
                  value={current[key]}
                  onChange={(v) =>
                    setValues({ ...(current ?? { tag: 0, junk: 0, quarantine: 0, reject: 0 }), [key]: v ?? 0 })
                  }
                />
                {base && current[key] > base[key] && (
                  <Typography.Text type="danger" style={{ fontSize: 12 }}>
                    {`не выше уровня установки: ${base[key]}`}
                  </Typography.Text>
                )}
              </Space>
            ))}
          </Space>
          <Typography.Paragraph type="secondary">
            {`Действует: пометка ${view.effective.tag}, «Спам» ${view.effective.junk}, карантин ${view.effective.quarantine}, отказ ${view.effective.reject} — источник: ${view.source == null ? "умолчание контракта" : typeof view.source === "string" ? "установка" : "организация"}.`}
          </Typography.Paragraph>
          {p.editable && (
            <Space>
              <Button type="primary" disabled={!dirty || aboveBase} loading={mutation.isPending} onClick={save}>
                Сохранить пороги
              </Button>
              {aboveBase && <Typography.Text type="danger">порог выше уровня установки — действие наступит позже</Typography.Text>}
            </Space>
          )}
        </>
      )}
    </>
  );
}

// --- Пакеты ---------------------------------------------------------------------------------------------------------

/** Подпись состояния пакета: активный, прошлый (поставлен и не активен), отклонённый с отчётом. */
const packageState = (s: Schemas["PackageState"]) =>
  s === "active" ? <StatusTag role="ok">активный</StatusTag> : s === "previous" ? <Tag>прошлый</Tag> : <StatusTag role="err">отклонён</StatusTag>;

/** Отчёт проверки пакета: подпись, lint и пробный прогон, что изменится — виден до активации. */
function PackageReport(p: { report: Schemas["PackageReportView"]; onClose: () => void; onActivated: () => void }) {
  const { mutate, mutation } = useCustomMutation<Schemas["PackagesView"], HttpError, undefined>();
  const activate = () =>
    mutate(
      {
        url: `${PACKAGES_URL}/${p.report.version}/activate`,
        method: "post",
        values: undefined,
        successNotification: { type: "success", message: `Пакет ${p.report.version} активирован` },
      },
      { onSuccess: p.onActivated },
    );
  const list = (title: string, items: string[], note?: string) => (
    <div>
      <Typography.Text strong>{title}</Typography.Text>{" "}
      {items.length ? (
        <>
          {items.map((s) => (
            <Tag key={s}>{s}</Tag>
          ))}
        </>
      ) : (
        <Typography.Text type="secondary">нет</Typography.Text>
      )}
      {note && <Typography.Text type="secondary"> — {note}</Typography.Text>}
    </div>
  );
  return (
    <Card
      style={{ marginBottom: 16 }}
      title={`Отчёт проверки пакета ${p.report.version} — пакет поставлен, но не активен`}
      extra={
        <Space>
          <Popconfirm
            title={`Активировать пакет ${p.report.version}?`}
            description="Каталог признаков будет заменён пакетом; новые признаки придут в режиме «только отчёт»."
            okText="Активировать"
            onConfirm={activate}
          >
            <Button type="primary" loading={mutation.isPending}>
              Активировать
            </Button>
          </Popconfirm>
          <Button onClick={p.onClose}>Скрыть</Button>
        </Space>
      }
    >
      <Descriptions column={1} size="small">
        <Descriptions.Item label="Подпись Ed25519">{`проверена узлом, ключ ${p.report.key_id}`}</Descriptions.Item>
        <Descriptions.Item label="Lint и пробный прогон">{`${p.report.signals} признаков, ${p.report.samples} образцов`}</Descriptions.Item>
      </Descriptions>
      <Typography.Title level={5}>Что изменится при активации</Typography.Title>
      {list("Новые", p.report.update.added, "придут в режиме «только отчёт»")}
      {list("Изменённые", p.report.update.changed)}
      {list("Удалённые", p.report.update.removed)}
      {list("Осиротевшие изменения администратора", p.report.update.orphaned_overrides, "признака в пакете больше нет")}
    </Card>
  );
}

/** Вкладка «Пакеты» (администратор установки): загрузка файла, отчёт до активации, активация и откат. */
function PackagesTab() {
  const { message } = AntdApp.useApp();
  const readOnly = useReadOnly("risk");
  const { result, query } = useCustom<Schemas["PackagesView"]>({
    url: PACKAGES_URL,
    method: "get",
    errorNotification: false,
    queryOptions: { retry: false },
  });
  const refetch = () => query.refetch();
  const [report, setReport] = useState<Schemas["PackageReportView"] | null>(null);
  const [error, setError] = useState<string>();
  const { mutate } = useCustomMutation<Schemas["PackagesView"], HttpError, undefined>();
  const packages = query.isSuccess ? result.data.packages : undefined;

  /** Загрузка файла пакета (закрытый контур): проверка узла, 202 — поставлен и не активен. */
  const upload = (file: File) =>
    request<Schemas["PackageReportView"]>(PACKAGES_URL, { method: "POST", file })
      .then((r) => {
        setError(undefined);
        setReport(r.data);
      })
      .catch((e: { message?: string }) => void message.error(e.message ?? "Пакет не принят"));

  const act = (version: number, what: "activate" | "rollback", title: string) =>
    mutate(
      {
        url: `${PACKAGES_URL}/${version}/${what}`,
        method: "post",
        values: undefined,
        successNotification: { type: "success", message: title },
      },
      {
        onSuccess: () => {
          setReport(null);
          void refetch();
        },
        onError: (e) => setError((e.problem as RiskProblem)?.detail ?? e.message),
      },
    );

  return (
    <>
      <Space wrap style={{ marginBottom: 16 }}>
        <Typography.Text type="secondary">Хранимые пакеты поставщика: активный и прошлые по убыванию номера.</Typography.Text>
        {!readOnly && (
          <Upload maxCount={1} showUploadList={false} customRequest={({ file }) => void upload(file as File)}>
            <Button>Загрузить пакет…</Button>
          </Upload>
        )}
      </Space>
      <Typography.Paragraph type="secondary">
        Пакет проверяется узлом (подпись Ed25519, lint, пробный прогон) и ставится без активации: отчёт проверки виден до включения, активация —
        отдельным действием.
      </Typography.Paragraph>
      {error && <Alert type="error" showIcon style={{ marginBottom: 16 }} message={error} />}
      {query.isError && <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="Пакеты недоступны: узел ответил отказом." />}
      {report && <PackageReport report={report} onClose={() => setReport(null)} onActivated={() => {
        setReport(null);
        void refetch();
      }} />}
      <Table<Schemas["PackageEntryView"]> dataSource={packages} loading={query.isLoading} rowKey="version" pagination={false} size="small">
        <Table.Column<Schemas["PackageEntryView"]> title="Версия" dataIndex="version" />
        <Table.Column<Schemas["PackageEntryView"]> title="Состояние" render={(_, r) => packageState(r.state)} />
        <Table.Column<Schemas["PackageEntryView"]> title="Отчёт проверки" render={(_, r) => (typeof r.state === "object" ? r.state.rejected.report : "—")} />
        {!readOnly && (
          <Table.Column<Schemas["PackageEntryView"]>
            title="Действия"
            width={220}
            render={(_, r) =>
              r.state === "previous" ? (
                <Space>
                  <Popconfirm title={`Активировать пакет ${r.version}?`} okText="Активировать" onConfirm={() => act(r.version, "activate", `Пакет ${r.version} активирован`)}>
                    <Button size="small" type="primary">
                      Активировать
                    </Button>
                  </Popconfirm>
                  <Popconfirm title={`Откатить к пакету ${r.version}?`} description="Действующим снова станет этот пакет." okText="Откатить" okButtonProps={{ danger: true }} onConfirm={() => act(r.version, "rollback", `Откат к пакету ${r.version}`)}>
                    <Button size="small" danger>
                      Откатить
                    </Button>
                  </Popconfirm>
                </Space>
              ) : null
            }
          />
        )}
      </Table>
    </>
  );
}

// --- Источники TI ---------------------------------------------------------------------------------------------------

const TIERS: { value: Exclude<Schemas["Tier"], "bundled">; label: string }[] = [
  { value: "customer_key", label: "ключ заказчика" },
  { value: "import", label: "импорт" },
];
const tierText = (t: Schemas["Tier"]) => (t === "bundled" ? "поставка" : (TIERS.find((x) => x.value === t)?.label ?? t));
const ORIGINS: { value: Schemas["TiOrigin"]; label: string }[] = [
  { value: "vendor", label: "поставщик" },
  { value: "gos_sopka", label: "ГОСТ СОПКА" },
  { value: "fin_cert", label: "ФИНСЕРТ" },
  { value: "own", label: "свой" },
];
const originOfTi = (o: Schemas["TiOrigin"]) => ORIGINS.find((x) => x.value === o)?.label ?? o;
const FORMATS: { value: "txt" | "csv" | "rpz" | "misp_feed" | "stix21"; label: string }[] = [
  { value: "txt", label: "текст (строка — индикатор)" },
  { value: "csv", label: "CSV" },
  { value: "rpz", label: "RPZ" },
  { value: "misp_feed", label: "MISP feed" },
  { value: "stix21", label: "STIX 2.1" },
];
const formatText = (f: Schemas["FeedFormat"]) =>
  typeof f === "string" ? (FORMATS.find((x) => x.value === f)?.label ?? f) : `CSV, колонка «${f.csv.column}»`;
const kindText = (k: Schemas["TiSourceKind"]) =>
  typeof k === "string" ? "файл" : "http" in k ? `фид: ${k.http.url}` : `TAXII: ${k.taxii.api_root} / ${k.taxii.collection}`;
const staleText = (s: Schemas["StaleAction"]) => (typeof s === "string" ? "только отчёт" : `снизить вес на ${s.reduce.percent}%`);
const authText = (a: Schemas["HttpAuth"]) =>
  a === "none"
    ? "без авторизации"
    : typeof a === "string"
      ? a === "bearer"
        ? "Bearer"
        : "клиентский сертификат"
      : "header" in a
        ? `заголовок ${a.header.name}`
        : `Basic (${a.basic.user})`;

type SourceForm = {
  id?: string;
  tier: Exclude<Schemas["Tier"], "bundled">;
  origin: Schemas["TiOrigin"];
  kind: "http" | "taxii" | "file";
  url?: string;
  api_root?: string;
  collection?: string;
  format: "txt" | "csv" | "rpz" | "misp_feed" | "stix21";
  column?: string;
  ttl?: string;
  stale: "report" | "reduce";
  percent?: number;
  terms_url?: string;
  commercial: boolean;
  attribution?: string;
  auth: "none" | "bearer" | "client_cert" | "header" | "basic";
  header_name?: string;
  basic_user?: string;
  key?: string;
  tenants: "all" | "only";
  only?: string[];
};

/** Тело источника (без идентификатора — он в пути `PUT` или добавляется при `POST`): ключ — только ссылка на секрет. */
const sourceBody = (v: SourceForm): Schemas["TiSourceBody"] => ({
  tier: v.tier,
  origin: v.origin,
  kind:
    v.kind === "http"
      ? { http: { url: v.url ?? "" } }
      : v.kind === "taxii"
        ? { taxii: { api_root: v.api_root ?? "", collection: v.collection ?? "" } }
        : "file",
  format: v.format === "csv" ? { csv: { column: v.column ?? "" } } : v.format,
  ttl: (v.ttl ?? "").trim(),
  stale: v.stale === "reduce" ? { reduce: { percent: v.percent ?? 0 } } : "report",
  license: { terms_url: (v.terms_url ?? "").trim(), commercial: v.commercial, attribution: v.attribution?.trim() || null },
  auth: v.auth === "header" ? { header: { name: v.header_name ?? "" } } : v.auth === "basic" ? { basic: { user: v.basic_user ?? "" } } : v.auth,
  key: v.key?.trim() ? { secret: v.key.trim() } : null,
  tenants: v.tenants === "only" ? { only: v.only ?? [] } : "all",
});

const sourceToForm = (s: Schemas["TiSourceView"]): SourceForm => ({
  tier: s.tier === "bundled" ? "customer_key" : s.tier,
  origin: s.origin,
  kind: typeof s.kind === "string" ? "file" : "http" in s.kind ? "http" : "taxii",
  url: typeof s.kind === "object" && "http" in s.kind ? s.kind.http.url : undefined,
  api_root: typeof s.kind === "object" && "taxii" in s.kind ? s.kind.taxii.api_root : undefined,
  collection: typeof s.kind === "object" && "taxii" in s.kind ? s.kind.taxii.collection : undefined,
  format: typeof s.format === "object" ? "csv" : s.format,
  column: typeof s.format === "object" ? s.format.csv.column : undefined,
  ttl: s.ttl,
  stale: typeof s.stale === "string" ? "report" : "reduce",
  percent: typeof s.stale === "object" ? s.stale.reduce.percent : undefined,
  terms_url: s.license.terms_url,
  commercial: s.license.commercial,
  attribution: s.license.attribution ?? undefined,
  auth: typeof s.auth === "string" ? s.auth : "header" in s.auth ? "header" : "basic",
  header_name: typeof s.auth === "object" && "header" in s.auth ? s.auth.header.name : undefined,
  basic_user: typeof s.auth === "object" && "basic" in s.auth ? s.auth.basic.user : undefined,
  key: s.key?.secret,
  tenants: s.tenants === "all" ? "all" : "only",
  only: s.tenants === "all" ? undefined : s.tenants.only,
});

const TTL_UNITS: Record<string, number> = { s: 1_000, m: 60_000, h: 3_600_000, d: 86_400_000 };
// Текущий момент — снимок при загрузке страницы (модуль один на сессию): сравнение чистое при отрисовке.
const NOW = Date.now();

/** Момент устаревания версии списка: загрузка + TTL (`30m`, `1h`, `12h`, `2d`); TTL не распознан — null. */
const staleAt = (version: Schemas["ListVersionView"], ttl: string): number | null => {
  const m = /^(\d+)([smhd])$/.exec(ttl.trim());
  const unit = m ? TTL_UNITS[m[2]] : undefined;
  return m && unit !== undefined ? Date.parse(version.fetched_at) + Number(m[1]) * unit : null;
};

/** Окно источника TI: добавление и изменение — ключ только выбором `SecretRef`, не значение. */
function SourceModal(p: { open: { row?: Schemas["TiSourceView"] } | null; refs: string[]; onClose: () => void; onSaved: () => void }) {
  const [form] = Form.useForm<SourceForm>();
  const [error, setError] = useState<string>();
  const editing = Boolean(p.open?.row);
  const values = Form.useWatch([], form) as SourceForm | undefined;
  const { orgs } = useOrgs();
  const { mutate, mutation } = useCustomMutation<Schemas["TiSourceView"], HttpError, Schemas["NewTiSourceBody"] | Schemas["TiSourceBody"]>();
  const close = () => {
    setError(undefined);
    p.onClose();
  };
  const save = (v: SourceForm) => {
    const id = (v.id ?? "").trim();
    mutate(
      {
        url: editing ? `${SOURCES_URL}/${encodeURIComponent(p.open?.row?.id ?? "")}` : SOURCES_URL,
        method: editing ? "put" : "post",
        values: editing ? sourceBody(v) : { ...sourceBody(v), id },
        errorNotification: false,
        successNotification: { type: "success", message: editing ? "Источник сохранён" : "Источник создан" },
      },
      {
        onSuccess: () => {
          close();
          p.onSaved();
        },
        onError: (e) => setError((e.problem as RiskProblem)?.detail ?? e.message),
      },
    );
  };
  const needsKey = values?.auth !== undefined && values.auth !== "none";
  return (
    <Modal
      open={p.open !== null}
      title={editing ? `Изменить источник: ${p.open?.row?.id}` : "Добавить источник TI"}
      okText={editing ? "Сохранить" : "Создать"}
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
        initialValues={
          p.open?.row
            ? sourceToForm(p.open.row)
            : { tier: "customer_key", origin: "own", kind: "http", format: "txt", stale: "report", auth: "none", commercial: false, tenants: "all" }
        }
        onFinish={save}
      >
        {!editing && (
          <Form.Item
            name="id"
            label="Идентификатор"
            extra="Строчные буквы, цифры, точка, подчёркивание и дефис, до 64 символов."
            rules={[{ required: true, message: "Укажите идентификатор" }, { pattern: /^[a-z0-9._-]{1,64}$/, message: "Не соответствует виду идентификатора" }]}
          >
            <Input placeholder="feed-misp" maxLength={64} />
          </Form.Item>
        )}
        <Form.Item name="tier" label="Уровень" extra="«В поставке» создаёт только пакет поставщика.">
          <Select aria-label="Уровень источника" options={TIERS} />
        </Form.Item>
        <Form.Item name="origin" label="Происхождение данных" extra="Для журнала и отчётов.">
          <Select aria-label="Происхождение данных" options={ORIGINS} />
        </Form.Item>
        <Form.Item name="kind" label="Доставка">
          <Radio.Group
            options={[
              { value: "http", label: "фид по HTTP(S)" },
              { value: "taxii", label: "TAXII 2.1" },
              { value: "file", label: "файл" },
            ]}
          />
        </Form.Item>
        {values?.kind === "http" && (
          <Form.Item name="url" label="Адрес фида" rules={[{ required: true, message: "Укажите адрес" }]}>
            <Input placeholder="feeds.example/list.txt" />
          </Form.Item>
        )}
        {values?.kind === "taxii" && (
          <>
            <Form.Item name="api_root" label="API root" rules={[{ required: true, message: "Укажите API root" }]}>
              <Input placeholder="taxii.example/api" />
            </Form.Item>
            <Form.Item name="collection" label="Коллекция" rules={[{ required: true, message: "Укажите коллекцию" }]}>
              <Input placeholder="discovery" />
            </Form.Item>
          </>
        )}
        <Form.Item name="format" label="Формат">
          <Select aria-label="Формат" options={FORMATS} />
        </Form.Item>
        {values?.format === "csv" && (
          <Form.Item name="column" label="Колонка с индикатором" rules={[{ required: true, message: "Укажите колонку" }]}>
            <Input placeholder="indicator" />
          </Form.Item>
        )}
        <Form.Item
          name="ttl"
          label="Срок жизни данных (TTL)"
          extra="Старее — источник считается устаревшим (`30m`, `1h`, `12h`)."
          rules={[{ required: true, message: "Укажите TTL" }, { pattern: /^\d+[smhd]$/, message: "Вид `30m`, `1h`, `12h`, `2d`" }]}
        >
          <Input placeholder="1h" maxLength={8} />
        </Form.Item>
        <Form.Item name="stale" label="Действие при устаревании" extra="«Отключить» нет: признаки источника не перестают работать из-за старой выгрузки.">
          <Select
            aria-label="Действие при устаревании"
            options={[
              { value: "report", label: "только отчёт" },
              { value: "reduce", label: "снизить вес признаков" },
            ]}
          />
        </Form.Item>
        {values?.stale === "reduce" && (
          <Form.Item name="percent" label="Снижение веса, %" rules={[{ required: true, message: "Укажите процент" }]}>
            <InputNumber min={0} max={100} style={{ width: 120 }} />
          </Form.Item>
        )}
        <Form.Item name="terms_url" label="Условия использования (лицензия)" rules={[{ required: true, message: "Укажите адрес условий" }]}>
          <Input placeholder="feeds.example/terms" />
        </Form.Item>
        <Form.Item name="commercial" label="Коммерческое использование разрешено" valuePropName="checked">
          <Switch />
        </Form.Item>
        <Form.Item name="attribution" label="Атрибуция (ссылка, дата, ©)">
          <Input placeholder="feeds.example/about" />
        </Form.Item>
        <Form.Item name="auth" label="Авторизация">
          <Select
            aria-label="Авторизация"
            options={[
              { value: "none", label: "без авторизации" },
              { value: "bearer", label: "Bearer (ключ из секрета)" },
              { value: "client_cert", label: "клиентский сертификат" },
              { value: "header", label: "свой заголовок" },
              { value: "basic", label: "Basic" },
            ]}
          />
        </Form.Item>
        {values?.auth === "header" && (
          <Form.Item name="header_name" label="Имя заголовка" rules={[{ required: true, message: "Укажите имя заголовка" }]}>
            <Input placeholder="X-Api-Key" />
          </Form.Item>
        )}
        {values?.auth === "basic" && (
          <Form.Item name="basic_user" label="Пользователь" rules={[{ required: true, message: "Укажите пользователя" }]}>
            <Input placeholder="taxii" />
          </Form.Item>
        )}
        {needsKey && (
          <Form.Item
            name="key"
            label="Ключ (ссылка на секрет)"
            extra="Выберите ссылку на поле хранилища секретов вида путь#поле — значение ключа узлу не вводится."
            rules={[{ required: true, message: "Выберите ссылку на секрет" }]}
          >
            <AutoComplete aria-label="Ключ (ссылка на секрет)" options={p.refs.map((r) => ({ value: r, title: r }))} placeholder="vault/feeds#api_key" />
          </Form.Item>
        )}
        <Form.Item name="tenants" label="Организации" extra="Учёт обращений ведётся по организациям (MSSP).">
          <Radio.Group
            options={[
              { value: "all", label: "все" },
              { value: "only", label: "только перечисленные" },
            ]}
          />
        </Form.Item>
        {values?.tenants === "only" && (
          <Form.Item name="only" label="Организации-получатели" rules={[{ required: true, message: "Выберите организации" }]}>
            <Select mode="multiple" placeholder="Организации" options={orgs.map((o) => ({ value: o.id, label: orgName(o) }))} />
          </Form.Item>
        )}
      </Form>
    </Modal>
  );
}

/** Учёт источника по организациям (MSSP): суммы обращений и совпадений с момента. */
function UsageDrawer(p: { source: string | null; onClose: () => void }) {
  const [since, setSince] = useState<Dayjs | null>(null);
  const { result, query } = useCustom<Schemas["UsageView"]>({
    url: `${SOURCES_URL}/${encodeURIComponent(p.source ?? "")}/usage`,
    method: "get",
    config: { query: { since: since?.toISOString() } },
    errorNotification: false,
    queryOptions: { enabled: p.source != null, retry: false },
  });
  const { orgs } = useOrgs();
  const usage = query.isSuccess ? result.data.usage : undefined;
  return (
    <Drawer open={p.source !== null} title={`Учёт источника: ${p.source ?? ""}`} width={560} onClose={p.onClose} destroyOnHidden>
      <Space wrap style={{ marginBottom: 16 }}>
        <Typography.Text type="secondary">С момента:</Typography.Text>
        <DatePicker showTime value={since} onChange={(v) => setSince(v)} allowClear />
      </Space>
      <Table<Schemas["UsageTotalView"]> dataSource={usage} loading={query.isLoading} rowKey="tenant" pagination={false} size="small">
        <Table.Column<Schemas["UsageTotalView"]>
          title="Организация"
          render={(_, u) => orgName(orgs.find((o) => o.id === u.tenant) ?? { id: u.tenant, default: false })}
        />
        <Table.Column<Schemas["UsageTotalView"]> title="Обращения" dataIndex="lookups" />
        <Table.Column<Schemas["UsageTotalView"]> title="Совпадения" dataIndex="hits" />
      </Table>
    </Drawer>
  );
}

/** Вкладка «Источники TI» (администратор установки): уровень, лицензия, свежесть, записи; импорт и обновление. */
function SourcesTab() {
  const { message } = AntdApp.useApp();
  const readOnly = useReadOnly("risk");
  const { result, query } = useCustom<Schemas["SourcesView"]>({
    url: SOURCES_URL,
    method: "get",
    errorNotification: false,
    queryOptions: { retry: false },
  });
  const refetch = () => query.refetch();
  const sources = query.isSuccess ? result.data.sources : undefined;
  // Версии списков — из ответов импорта и обновления: свежесть и число записей видны после загрузки.
  const [versions, setVersions] = useState<Record<string, Schemas["ListVersionView"]>>({});
  const [modal, setModal] = useState<{ row?: Schemas["TiSourceView"] } | null>(null);
  const [usage, setUsage] = useState<string | null>(null);
  const { mutate: remove, mutation: removing } = useCustomMutation<Schemas["TiSourceView"], HttpError, undefined>();

  const known = (id: string) => versions[id];
  const refs = [...new Set((sources ?? []).map((s) => s.key?.secret).filter((s): s is string => Boolean(s)))];

  const importFile = (id: string, file: File) =>
    request<Schemas["ListVersionView"]>(`${SOURCES_URL}/${encodeURIComponent(id)}/import`, { method: "POST", file })
      .then((r) => {
        setVersions((prev) => ({ ...prev, [id]: r.data }));
        void message.success(`Импортировано ${r.data.entries} записей (${moment(r.data.fetched_at)})`);
      })
      .catch((e: { message?: string }) => void message.error(e.message ?? "Импорт не выполнен"));

  const refresh = (id: string) =>
    request<Schemas["ListVersionView"]>(`${SOURCES_URL}/${encodeURIComponent(id)}/refresh`, { method: "POST" })
      .then((r) => {
        setVersions((prev) => ({ ...prev, [id]: r.data }));
        void message.success(`Обновлено: ${r.data.entries} записей (${moment(r.data.fetched_at)})`);
      })
      .catch((e: { message?: string }) => void message.error(e.message ?? "Обновление не выполнено"));

  const del = (s: Schemas["TiSourceView"]) =>
    remove(
      {
        url: `${SOURCES_URL}/${encodeURIComponent(s.id)}`,
        method: "delete",
        values: undefined,
        successNotification: { type: "success", message: `Источник ${s.id} удалён` },
      },
      { onSuccess: () => void refetch() },
    );

  return (
    <>
      <Space wrap style={{ marginBottom: 16 }}>
        <Typography.Text type="secondary">Фиды по уровню: в поставке (пакетом), ключ заказчика, импорт; ключи — ссылки на секреты.</Typography.Text>
        {!readOnly && (
          <Button type="primary" onClick={() => setModal({})}>
            Добавить источник
          </Button>
        )}
      </Space>
      {query.isError && <Alert type="warning" showIcon style={{ marginBottom: 16 }} message="Источники недоступны: узел ответил отказом." />}
      <Table<Schemas["TiSourceView"]> dataSource={sources} loading={query.isLoading} rowKey="id" pagination={false} size="small" scroll={{ x: 1080 }}>
        <Table.Column<Schemas["TiSourceView"]> title="Источник" fixed="left" render={(_, s) => <Typography.Text code>{s.id}</Typography.Text>} />
        <Table.Column<Schemas["TiSourceView"]> title="Уровень" render={(_, s) => tierText(s.tier)} />
        <Table.Column<Schemas["TiSourceView"]> title="Доставка" render={(_, s) => kindText(s.kind)} />
        <Table.Column<Schemas["TiSourceView"]> title="Формат" render={(_, s) => formatText(s.format)} />
        <Table.Column<Schemas["TiSourceView"]> title="TTL" dataIndex="ttl" />
        <Table.Column<Schemas["TiSourceView"]> title="Происхождение" render={(_, s) => originOfTi(s.origin)} />
        <Table.Column<Schemas["TiSourceView"]>
          title="Лицензия"
          render={(_, s) => (
            <Space direction="vertical" size={0}>
              <Typography.Text>{s.license.terms_url}</Typography.Text>
              <Typography.Text type="secondary">
                {`коммерческое: ${s.license.commercial ? "да" : "нет"}${s.license.attribution ? `, атрибуция: ${s.license.attribution}` : ""}`}
              </Typography.Text>
            </Space>
          )}
        />
        <Table.Column<Schemas["TiSourceView"]> title="При устаревании" render={(_, s) => staleText(s.stale)} />
        <Table.Column<Schemas["TiSourceView"]> title="Организации" render={(_, s) => (s.tenants === "all" ? "все" : `${s.tenants.only.length}`)} />
        <Table.Column<Schemas["TiSourceView"]> title="Авторизация" render={(_, s) => authText(s.auth)} />
        <Table.Column<Schemas["TiSourceView"]> title="Ключ" render={(_, s) => (s.key ? <Typography.Text code>{s.key.secret}</Typography.Text> : "—")} />
        <Table.Column<Schemas["TiSourceView"]>
          title="Свежесть"
          render={(_, s) => {
            const v = known(s.id);
            if (!v) return <Typography.Text type="secondary">—</Typography.Text>;
            const limit = staleAt(v, s.ttl);
            const stale = limit != null && limit < NOW;
            return <StatusTag role={stale ? "warn" : "ok"}>{`${stale ? "устарел" : "свежий"}: загружен ${when(v.fetched_at)}`}</StatusTag>;
          }}
        />
        <Table.Column<Schemas["TiSourceView"]> title="Записей" render={(_, s) => known(s.id)?.entries ?? "—"} />
        <Table.Column<Schemas["TiSourceView"]>
          title="Действия"
          width={360}
          render={(_, s) => (
            <Space wrap size={4}>
              {typeof s.kind !== "string" && (
                <Button size="small" onClick={() => void refresh(s.id)}>
                  Обновить сейчас
                </Button>
              )}
              <Upload maxCount={1} showUploadList={false} customRequest={({ file }) => void importFile(s.id, file as File)}>
                <Button size="small">Импорт файла…</Button>
              </Upload>
              <Button size="small" onClick={() => setUsage(s.id)}>
                Учёт
              </Button>
              {!readOnly && s.tier !== "bundled" && (
                <>
                  <Button size="small" onClick={() => setModal({ row: s })}>
                    Изменить
                  </Button>
                  <Popconfirm title={`Удалить источник ${s.id}?`} description="Версии списков и учёт останутся." okText="Удалить" okButtonProps={{ danger: true }} onConfirm={() => del(s)}>
                    <Button size="small" danger loading={removing.isPending}>
                      Удалить
                    </Button>
                  </Popconfirm>
                </>
              )}
            </Space>
          )}
        />
      </Table>
      <SourceModal open={modal} refs={refs} onClose={() => setModal(null)} onSaved={() => void refetch()} />
      <UsageDrawer source={usage} onClose={() => setUsage(null)} />
    </>
  );
}

// --- Срабатывания ---------------------------------------------------------------------------------------------------

type HitFilters = { signal?: string; mode?: Schemas["Mode"]; range?: [Dayjs | null, Dayjs | null] | null };

/** Вкладка «Срабатывания»: журнал организации с фильтрами по признаку, режиму и времени. */
function HitsTab() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState<HitFilters>({});
  const { result, query: catalog } = useCustom<Schemas["SignalsView"]>({
    url: ORG_SIGNALS,
    method: "get",
    errorNotification: false,
    queryOptions: { retry: false },
  });
  const options = (catalog.isSuccess ? result.data.signals : []).map((s) => ({ value: s.id, label: s.id }));
  // Продолжение страницы — её `next` в параметре `until` (он же конец интервала).
  const { page, loading, pager } = useCursorPages<Schemas["HitsView"]>(
    HITS_URL,
    {
      signal: filters.signal,
      mode: filters.mode,
      ...interval(filters.range),
    },
    "until",
  );
  return (
    <>
      <Form<HitFilters> layout="inline" onFinish={setFilters} style={{ marginBottom: 16, rowGap: 8 }}>
        <Form.Item name="signal" label="Признак">
          <Select aria-label="Признак срабатывания" allowClear showSearch optionFilterProp="label" style={{ minWidth: 220 }} options={options} placeholder="любой" />
        </Form.Item>
        <Form.Item name="mode" label="Режим">
          <Select aria-label="Режим срабатывания" allowClear style={{ minWidth: 160 }} options={MODE_OPTIONS} placeholder="любой" />
        </Form.Item>
        <Form.Item name="range" label="Интервал">
          <DatePicker.RangePicker showTime allowEmpty={[true, true]} />
        </Form.Item>
        <Button type="primary" htmlType="submit">
          Найти
        </Button>
      </Form>
      <Table<Schemas["HitView"]> dataSource={page?.hits} loading={loading} rowKey={(h) => `${h.at} ${h.signal} ${h.message}`} pagination={false} size="small">
        <Table.Column<Schemas["HitView"]> title="Время" render={(_, h) => moment(h.at)} />
        <Table.Column<Schemas["HitView"]> title="Признак" render={(_, h) => <Typography.Text code>{h.signal}</Typography.Text>} />
        <Table.Column<Schemas["HitView"]>
          title="Режим"
          render={(_, h) => (h.mode === "report" ? <StatusTag role="warn">только отчёт</StatusTag> : <Tag>применено</Tag>)}
        />
        <Table.Column<Schemas["HitView"]> title="Сила" dataIndex="strength" />
        <Table.Column<Schemas["HitView"]> title="Вес" dataIndex="weight" />
        <Table.Column<Schemas["HitView"]>
          title="Письмо"
          render={(_, h) => (
            <Button type="link" size="small" style={{ padding: 0 }} title={h.message} aria-label="Открыть журнал доставки" onClick={() => navigate("/delivery")}>
              {`${h.message.slice(0, 12)}…`}
            </Button>
          )}
        />
      </Table>
      {pager}
    </>
  );
}

/** Раздел «Признаки риска»: переключатель уровня (установка — администратору установки) и вкладки. */
export function RiskPage() {
  const { data: roles } = usePermissions<Schemas["AdminRole"][]>({});
  const instAdmin = roles?.includes("installation_admin") ?? false;
  const readOnly = useReadOnly("risk");
  // По умолчанию — уровень организации (как в «Доверии»); установку переключает администратор установки.
  const [level, setLevel] = useState<"installation" | "org">("org");
  return (
    <Show title="Признаки риска" goBack={false} breadcrumb={false} headerButtons={() => null}>
      {instAdmin && (
        <Space wrap style={{ marginBottom: 16 }}>
          <Typography.Text type="secondary">Уровень:</Typography.Text>
          <Radio.Group
            optionType="button"
            value={level}
            onChange={(e) => setLevel(e.target.value as "installation" | "org")}
            options={[
              { value: "installation", label: "Установка" },
              { value: "org", label: "Организация" },
            ]}
          />
        </Space>
      )}
      <Tabs
        destroyOnHidden
        items={[
          { key: "catalog", label: "Каталог", children: <CatalogTab key={level} level={level} editable={!readOnly} instAdmin={instAdmin} /> },
          { key: "thresholds", label: "Пороги", children: <ThresholdsTab key={level} level={level} editable={!readOnly} instAdmin={instAdmin} /> },
          ...(instAdmin ? [{ key: "packages", label: "Пакеты", children: <PackagesTab /> }] : []),
          ...(instAdmin ? [{ key: "sources", label: "Источники TI", children: <SourcesTab /> }] : []),
          { key: "hits", label: "Срабатывания", children: <HitsTab /> },
        ]}
      />
    </Show>
  );
}
