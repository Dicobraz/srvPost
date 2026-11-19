// Раздел «Брендинг» (UI-22, решение 122): уровень установки — администратору установки, организации — вкладка.
// Все поля необязательны: название, основной цвет, роли светлой и тёмной темы и CLI («как на уровне выше» —
// очистка поля), знак PNG. Контраст проверяет сервер (ADM-48): 422 problem+json кладёт `detail` к полю роли
// из `errors`. Своих расчётов цветов нет: действующие цвета и предпросмотр — подстановка ответа сервера.
import { type HttpError, useCustom, useCustomMutation, usePermissions } from "@refinedev/core";
import { App as AntdApp, Button, ColorPicker, Form, Input, Popconfirm, Space, Table, Tabs, Upload } from "antd";
import { useEffect, useState } from "react";

import { API, apiUrl, request, type Schemas } from "../api/client";
import { useReadOnly } from "../providers/access";
import { BUILTIN_PRODUCT, publicBranding } from "../providers/branding";
import { cliRoleNames, fonts, modeColors, roleNames, tokens, type Branding, type ModeColors } from "../theme";
import { ItTaskSign } from "./logo";

/** Пределы знака (контракт tp_contracts::branding): PNG до 256 КБ, до 1024×1024 — остальное проверяет сервер. */
const LOGO_MAX_BYTES = 256 * 1024;

/** Роли подсветки CLI — подписи (в design/tokens.toml описаний ролей CLI нет, только имена). */
const CLI_ROLE_LABELS: Record<string, string> = {
  head: "заголовки таблиц, разделы справки",
  accent: "акцент: метод и путь, флаги",
  ok: "успех, OK",
  warn: "внимание, WARN",
  err: "ошибка, FAIL",
  muted: "вторичный текст",
  json_key: "JSON: ключи",
  json_number: "JSON: числа",
  json_bool: "JSON: true и false",
};

/** Цвет из ColorPicker в `#RRGGBB` (верхний регистр, как в контракте); очистка — `null`, «как на уровне выше». */
const hexOf = (c: { toHexString: () => string } | null): string | null => (c ? c.toHexString().toUpperCase() : null);

type RoleMap = Record<string, string | null>;
type Values = { product_name?: string | null; primary?: string | null; light?: RoleMap; dark?: RoleMap; cli?: RoleMap };

/** Значения формы → тело `PUT`: пустое — `null`, очищенные роли не отправляются (берутся с уровня выше). */
function toBody(v: Values): Schemas["BrandingBody"] {
  const roles = (m?: RoleMap) => Object.fromEntries(Object.entries(m ?? {}).filter(([, c]) => c)) as Record<string, string>;
  return { product_name: v.product_name?.trim() || null, primary: v.primary ?? null, light: roles(v.light), dark: roles(v.dark), cli: roles(v.cli) };
}

/** Ошибки контраста 422 — к полям ролей из `errors` (роль, пара, тема), текст — `detail` сервера. */
function contrastFields(problem: unknown): { name: ["light", string]; errors: string[] }[] {
  const p = (problem ?? {}) as { detail?: string; errors?: { field?: string }[] };
  return (p.errors ?? []).flatMap((e) =>
    typeof e.field === "string" && e.field.includes(".")
      ? [{ name: e.field.split(".") as ["light", string], errors: [p.detail ?? "Контраст ниже порога"] }]
      : [],
  );
}

/** Тема первой ошибки контраста — вкладка ролей открывается на ней. */
function contrastTheme(problem: unknown): string | undefined {
  const p = (problem ?? {}) as { errors?: { field?: string }[] };
  const first = p.errors?.find((e) => typeof e.field === "string" && e.field.includes("."));
  return first?.field?.split(".")[0];
}

/** Предпросмотр одной темы: шапка, выделение и F-клавиши цветами действующего набора (с редактируемым). */
function ThemePreview({ title, colors, name }: { title: string; colors: ModeColors; name: string }) {
  return (
    <div aria-label={title} style={{ flex: 1, minWidth: 240, border: `1px solid ${colors.frame}`, borderRadius: 4, overflow: "hidden" }}>
      <div style={{ background: colors.panel, borderBottom: `2px solid ${colors.frameA}`, color: colors.head, fontFamily: fonts.heading, padding: "6px 10px", fontSize: 18 }}>
        {name}
      </div>
      <div style={{ background: colors.screen, padding: 6 }}>
        <div style={{ background: colors.panel, border: `1px solid ${colors.frame}`, borderRadius: 4 }}>
          <div style={{ background: colors.selI, color: colors.selIFg, padding: "4px 10px" }}>Строка списка</div>
          <div style={{ background: colors.sel, color: colors.selFg, padding: "4px 10px" }}>Выделенная строка</div>
        </div>
      </div>
      <div style={{ background: colors.fkBg, color: colors.fkFg, display: "flex", gap: 16, padding: "4px 10px", fontSize: 12 }}>
        <span>F1 Помощь</span>
        <span>F2 Сохранить</span>
        <span>F10 Выход</span>
      </div>
    </div>
  );
}

/** Форма одного уровня: установка или организация. */
function LevelForm({ level }: { level: "installation" | "org" }) {
  const readOnly = useReadOnly("organization");
  const { message } = AntdApp.useApp();
  const view = level === "installation" ? `${API}/branding` : `${API}/orgs/{org}/branding`;
  const logoUrl = level === "installation" ? `${API}/branding/logo` : `${API}/orgs/{org}/branding/logo`;
  const { result, query } = useCustom<Schemas["BrandingView"]>({ url: view, method: "get", errorNotification: false, queryOptions: { retry: false } });
  const { mutate, mutation } = useCustomMutation<Schemas["BrandingView"], HttpError, Schemas["BrandingBody"] | undefined>();
  const [form] = Form.useForm<Values>();
  const values = Form.useWatch([], form) as Values | undefined;
  // Вкладка ролей: открывается на теме первой ошибки контраста (поля всех тем смонтированы — forceRender).
  const [roleTab, setRoleTab] = useState<string>();
  // Уровень выше (для предпросмотра): организация — брендинг установки (открытый маршрут), установка — токены IT TASK.
  const [parent, setParent] = useState<Branding | null>(null);
  useEffect(() => {
    if (level !== "org") return;
    let cancelled = false;
    void publicBranding().then((b) => {
      if (!cancelled) setParent(b);
    });
    return () => {
      cancelled = true;
    };
  }, [level]);

  // До ответа и при отказе Refine отдаёт пустой объект: ждём `effective`.
  if (query.isLoading || !result.data?.effective) return null;
  const own = result.data.own ?? null;
  const effective = result.data.effective;
  const initial: Values = {
    product_name: own?.product_name ?? null,
    primary: own?.primary ?? null,
    light: { ...(own?.light ?? {}) },
    dark: { ...(own?.dark ?? {}) },
    cli: { ...(own?.cli ?? {}) },
  };
  const refetch = () => void query.refetch();

  // Роли одной темы: поле цвета («как на уровне выше» — очистка) и действующий цвет из `effective`.
  const roleTable = (theme: "light" | "dark" | "cli") => {
    const names = theme === "cli" ? cliRoleNames : roleNames;
    const label = (role: string) =>
      theme === "cli" ? CLI_ROLE_LABELS[role] ?? role : tokens.roles[role] ?? role;
    return (
      <Table
        rowKey="role"
        size="small"
        pagination={false}
        dataSource={names.map((role) => ({ role }))}
        columns={[
          {
            title: "Роль",
            dataIndex: "role",
            render: (role: string) => (
              <>
                <code>{role}</code> — {label(role)}
              </>
            ),
          },
          {
            title: "Цвет уровня (очистить — как на уровне выше)",
            dataIndex: "role",
            render: (role: string) => (
              // Без noStyle: ошибки контраста 422 (роль, пара, тема) показываются у поля роли.
              <Form.Item name={[theme, role]} getValueFromEvent={hexOf}>
                <ColorPicker allowClear format="hex" showText />
              </Form.Item>
            ),
          },
          {
            title: "Действующий",
            dataIndex: "role",
            render: (role: string) => {
              const color = effective.palette[theme][role];
              return color ? (
                <Space size={4}>
                  <span aria-label={`Действующий ${theme}.${role}`} style={{ background: color, border: `1px solid ${modeColors(false).frame}`, display: "inline-block", height: 14, width: 14, borderRadius: 2 }} />
                  <code>{color}</code>
                </Space>
              ) : null;
            },
          },
        ]}
      />
    );
  };

  // Предпросмотр: поля формы поверх уровня выше (установка — поверх токенов IT TASK); имя — из поля или действующее.
  const preview: Branding = {
    name: null,
    logo: null,
    light: { ...parent?.light, ...Object.fromEntries(Object.entries(values?.light ?? {}).filter(([, c]) => c)) },
    dark: { ...parent?.dark, ...Object.fromEntries(Object.entries(values?.dark ?? {}).filter(([, c]) => c)) },
  };
  const previewName = values?.product_name?.trim() || effective.product_name || BUILTIN_PRODUCT;

  return (
    <Form<Values>
      key={JSON.stringify(initial)}
      aria-label={level === "installation" ? "Брендинг установки" : "Брендинг организации"}
      form={form}
      layout="vertical"
      initialValues={initial}
      disabled={readOnly}
      onFinish={(v) =>
        mutate(
          { url: view, method: "put", values: toBody(v), successNotification: { type: "success", message: "Брендинг сохранён" } },
          {
            onSuccess: refetch,
            onError: (error) => {
              form.setFields(contrastFields(error?.problem));
              setRoleTab(contrastTheme(error?.problem));
            },
          },
        )
      }
    >
      <Form.Item
        name="product_name"
        label="Название продукта"
        extra={`Действует: ${effective.product_name ?? BUILTIN_PRODUCT} — шапка, экран входа и заголовок вкладки.`}
      >
        <Input allowClear placeholder={BUILTIN_PRODUCT} maxLength={64} />
      </Form.Item>
      <Form.Item
        name="primary"
        label="Основной цвет"
        getValueFromEvent={hexOf}
        extra="Источник незаданных ролей бренда этого уровня (рамки, F-клавиши, выделение, заголовки); без него — с уровня выше."
      >
        <ColorPicker allowClear format="hex" showText />
      </Form.Item>
      <Form.Item label="Знак (PNG)" extra="Действующий знак уровня; файл до 256 КБ и 1024×1024 — остальное проверит сервер.">
        <Space direction="vertical" size={8}>
          {effective.logo ? (
            <img alt="Действующий знак" src={apiUrl(`${API}/public/branding/logo/${effective.logo.hash}`)} style={{ height: 48, width: "auto" }} />
          ) : (
            <ItTaskSign height={34} />
          )}
          {!readOnly && (
            <Space>
              <Upload
                accept="image/png"
                maxCount={1}
                showUploadList={false}
                beforeUpload={(file) => {
                  // Проверка до отправки (карточка UI-22): не PNG или больше 256 КБ — файл не уходит на сервер.
                  if (file.type !== "image/png") {
                    void message.error("Знак — только PNG");
                    return Upload.LIST_IGNORE;
                  }
                  if (file.size > LOGO_MAX_BYTES) {
                    void message.error(`Знак — до ${LOGO_MAX_BYTES / 1024} КБ (файл ${Math.ceil(file.size / 1024)} КБ)`);
                    return Upload.LIST_IGNORE;
                  }
                  return true; // годный файл отправляет customRequest
                }}
                customRequest={({ file }) => {
                  request<Schemas["BrandingView"]>(logoUrl, { method: "PUT", file: file as File })
                    .then(() => {
                      void message.success("Знак загружен");
                      refetch();
                    })
                    .catch((e: { message?: string }) => void message.error(e.message ?? "Знак не загружен"));
                }}
              >
                <Button>Загрузить знак…</Button>
              </Upload>
              {own?.logo && (
                <Popconfirm
                  title="Вернуть знак с уровня выше?"
                  okText="Убрать знак"
                  onConfirm={() =>
                    mutate({ url: logoUrl, method: "delete", values: undefined, successNotification: { type: "success", message: "Знак убран" } }, { onSuccess: refetch })
                  }
                >
                  <Button danger>Убрать знак</Button>
                </Popconfirm>
              )}
            </Space>
          )}
        </Space>
      </Form.Item>
      <Tabs
        activeKey={roleTab}
        onChange={setRoleTab}
        items={[
          { key: "light", label: "Светлая тема", children: roleTable("light"), forceRender: true },
          { key: "dark", label: "Тёмная тема", children: roleTable("dark"), forceRender: true },
          { key: "cli", label: "CLI", children: roleTable("cli"), forceRender: true },
        ]}
      />
      <Form.Item label="Предпросмотр (шапка, выделение, F-клавиши — в обеих темах)">
        <div style={{ display: "flex", gap: 12 }}>
          <ThemePreview title="Предпросмотр: светлая тема" colors={modeColors(false, preview)} name={previewName} />
          <ThemePreview title="Предпросмотр: тёмная тема" colors={modeColors(true, preview)} name={previewName} />
        </div>
      </Form.Item>
      {!readOnly && (
        <Space>
          <Button type="primary" htmlType="submit" loading={mutation.isPending}>
            Сохранить брендинг
          </Button>
          {own && (
            <Popconfirm
              title="Сбросить брендинг — всё возьмётся с уровня выше?"
              okText="Да, сбросить"
              onConfirm={() =>
                mutate({ url: view, method: "delete", values: undefined, successNotification: { type: "success", message: "Брендинг сброшен" } }, { onSuccess: refetch })
              }
            >
              <Button danger loading={mutation.isPending}>
                Сбросить
              </Button>
            </Popconfirm>
          )}
        </Space>
      )}
    </Form>
  );
}

/** Раздел «Брендинг»: уровень установки (администратору установки) и вкладка организации. */
export function BrandingSection() {
  const { data: roles } = usePermissions<Schemas["AdminRole"][]>({});
  const installation = roles?.includes("installation_admin") ?? false;
  return (
    <Tabs
      items={
        installation
          ? [
              { key: "installation", label: "Установка", children: <LevelForm level="installation" /> },
              { key: "org", label: "Организация", children: <LevelForm level="org" /> },
            ]
          : [{ key: "org", label: "Организация", children: <LevelForm level="org" /> }]
      }
    />
  );
}
