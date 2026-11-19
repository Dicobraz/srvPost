// Раздел «Доверие» (UI-23, решение 124): матрица функций и типов абонентов на уровнях установка →
// организация → группа; у клетки — источник значения, «выше потолка» и текст отказа узла 422; у
// организации — вкладка «Партнёры» с доменами-партнёрами и доменами автопересылки; сброс уровня —
// к значениям уровня выше (с подтверждением).
import { Show } from "@refinedev/antd";
import { type HttpError, useCustom, useCustomMutation, useList, usePermissions } from "@refinedev/core";
import { Alert, Button, Popconfirm, Radio, Select, Space, Tabs, Tag, Typography } from "antd";
import { useState } from "react";

import type { Schemas } from "../api/client";
import { EffectiveMatrix, TrustMatrix } from "../components/trust";

const enc = encodeURIComponent;

type Level = "installation" | "org" | "group";
type DomainLists = "partners" | "auto_forward_domains";

/** Тело `PUT` из политики уровня: заданные клетки, у организации — списки доменов. */
const draftOf = (view: Schemas["TrustView"]): Schemas["TrustBody"] => ({
  invite_new: view.own?.invite_new,
  itip_updates: view.own?.itip_updates,
  auto_reply: view.own?.auto_reply,
  mdn: view.own?.mdn,
  auto_forward: view.own?.auto_forward,
  freebusy: view.own?.freebusy,
  sharing: view.own?.sharing,
  group_post: view.own?.group_post,
  partners: view.own?.partners ?? [],
  auto_forward_domains: view.own?.auto_forward_domains ?? [],
});

/** Отказ записи политики — клетки выше потолка (RFC 9457 с `errors`). */
const trustProblem = (e: HttpError): Partial<Schemas["TrustProblem"]> | undefined => e.problem as Partial<Schemas["TrustProblem"]> | undefined;

/** Выбор группы для уровня «группа». */
function GroupPick(p: { value?: string; onChange: (v: string) => void }) {
  const { result, query } = useList<Schemas["GroupInfo"]>({ resource: "groups", pagination: { mode: "off" } });
  return (
    <Select
      aria-label="Группа уровня"
      showSearch
      optionFilterProp="label"
      value={p.value}
      onChange={p.onChange}
      loading={query.isLoading}
      style={{ minWidth: 280 }}
      placeholder="Выберите группу"
      options={(result.data ?? []).map((g) => ({ value: g.id, label: g.name }))}
    />
  );
}

/** Списки доменов уровня организации: партнёры и автопересылка; читателям — тегами. */
function Partners(p: {
  body: Schemas["TrustBody"];
  editable: boolean;
  onChange: (key: DomainLists, domains: string[]) => void;
}) {
  const list = (key: DomainLists) => (Array.isArray(p.body[key]) ? (p.body[key] as string[]) : []);
  const tags = { mode: "tags" as const, tokenSeparators: [",", " "], open: false, style: { maxWidth: 640, width: "100%" } };
  const show = (key: DomainLists, empty: string) =>
    p.editable ? (
      <Select aria-label={key === "partners" ? "Домены-партнёры" : "Домены автопересылки"} {...tags} value={list(key)} onChange={(v) => p.onChange(key, v)} />
    ) : list(key).length ? (
      <div>
        {list(key).map((d) => (
          <Tag key={d}>{d}</Tag>
        ))}
      </div>
    ) : (
      <Typography.Text type="secondary">{empty}</Typography.Text>
    );
  return (
    <div style={{ maxWidth: 640 }}>
      <Typography.Title level={5}>Домены-партнёры</Typography.Title>
      <Typography.Paragraph type="secondary">
        Письма с этих доменов считаются письмами партнёров. Свой принятый домен партнёром быть не может — узел отклонит.
      </Typography.Paragraph>
      {show("partners", "доменов-партнёров нет")}
      <Typography.Title level={5} style={{ marginTop: 24 }}>
        Домены автопересылки
      </Typography.Title>
      <Typography.Paragraph type="secondary">
        Куда разрешена автопересылка наружу (правила `redirect` и пересылка ящика): не в списке — письма наружу не уйдут.
      </Typography.Paragraph>
      {show("auto_forward_domains", "доменов автопересылки нет")}
    </div>
  );
}

/** Редактор одного уровня: матрица, партнёры (у организации), сохранение и сброс. */
function LevelEditor(p: { url: string; view: Schemas["TrustView"]; editable: boolean; org: boolean; onChanged: () => void }) {
  const initial = draftOf(p.view);
  const [body, setBody] = useState<Schemas["TrustBody"]>(initial);
  const [cellErrors, setCellErrors] = useState<Record<string, string>>({});
  const [listError, setListError] = useState<string>();
  const dirty = JSON.stringify(body) !== JSON.stringify(initial);
  const { mutate, mutation } = useCustomMutation<Schemas["TrustView"], HttpError, Schemas["TrustBody"]>();
  // Списки доменов тело несёт только у организации: на других уровнях узел отклоняет их (422).
  const values = (): Schemas["TrustBody"] => ({
    invite_new: body.invite_new,
    itip_updates: body.itip_updates,
    auto_reply: body.auto_reply,
    mdn: body.mdn,
    auto_forward: body.auto_forward,
    freebusy: body.freebusy,
    sharing: body.sharing,
    group_post: body.group_post,
    ...(p.org ? { partners: body.partners ?? [], auto_forward_domains: body.auto_forward_domains ?? [] } : {}),
  });
  const save = () =>
    mutate(
      {
        url: p.url,
        method: "put",
        values: values(),
        // Текст отказа — у клетки или общим сообщением, без повторного уведомления.
        errorNotification: false,
        successNotification: { type: "success", message: "Политика доверия сохранена" },
      },
      {
        onSuccess: p.onChanged,
        onError: (e) => {
          // Текст `detail` узла — у клетки (по клеткам из `errors`); домены и прочее — отдельным сообщением.
          const problem = trustProblem(e);
          const errors: Record<string, string> = {};
          for (const c of problem?.errors ?? []) errors[`${c.function}:${c.peer}`] = problem?.detail ?? e.message;
          const other = Object.keys(errors).length === 0 ? (problem?.detail ?? e.message) : undefined;
          setCellErrors(errors);
          setListError(other);
        },
      },
    );
  const { mutate: reset, mutation: resetting } = useCustomMutation<Schemas["TrustView"], HttpError, undefined>();
  const changeCell = (key: string, peer: string, value: string) =>
    setBody({
      ...body,
      [key]: { ...((body as unknown as Record<string, Record<string, string | null>>)[key] ?? {}), [peer]: value },
    } as Schemas["TrustBody"]);
  const changeList = (key: DomainLists, domains: string[]) => setBody({ ...body, [key]: domains } as Schemas["TrustBody"]);
  return (
    <>
      {p.editable && (
        <Space wrap style={{ marginBottom: 16 }}>
          <Button type="primary" onClick={save} loading={mutation.isPending} disabled={!dirty}>
            Сохранить политику
          </Button>
          <Popconfirm
            title="Сбросить уровень?"
            description="Действующими станут значения уровня выше и умолчания контракта."
            okText="Сбросить"
            okButtonProps={{ danger: true }}
            onConfirm={() =>
              reset(
                { url: p.url, method: "delete", values: undefined, successNotification: { type: "success", message: "Политика уровня сброшена" } },
                { onSuccess: p.onChanged },
              )
            }
          >
            <Button danger loading={resetting.isPending}>
              Сбросить уровень
            </Button>
          </Popconfirm>
        </Space>
      )}
      {listError && (
        <Alert type="error" showIcon style={{ marginBottom: 16 }} message={listError} />
      )}
      <Tabs
        destroyOnHidden
        items={[
          {
            key: "matrix",
            label: "Матрица",
            children: p.editable ? (
              <TrustMatrix view={p.view} value={body} errors={cellErrors} onChange={changeCell} />
            ) : (
              <>
                <EffectiveMatrix view={p.view} />
                <Typography.Paragraph type="secondary" style={{ marginTop: 16 }}>
                  Изменение политики доверия — администратору установки или организации.
                </Typography.Paragraph>
              </>
            ),
          },
          ...(p.org ? [{ key: "partners", label: "Партнёры", children: <Partners body={body} editable={p.editable} onChange={changeList} /> }] : []),
        ]}
      />
    </>
  );
}

/** Раздел «Доверие»: переключатель уровня (установку видит администратор установки), организация, группа. */
export function TrustPage() {
  const { data: roles } = usePermissions<Schemas["AdminRole"][]>({});
  const all = roles ?? [];
  const editable = all.includes("installation_admin") || all.includes("organization_admin");
  const [level, setLevel] = useState<Level>("org");
  const [group, setGroup] = useState<string>();
  const ready = level !== "group" || Boolean(group);
  const url =
    level === "installation" ? "/api/v1/trust" : level === "org" ? "/api/v1/orgs/{org}/trust" : `/api/v1/orgs/{org}/groups/${enc(group ?? "")}/trust`;
  const { result, query } = useCustom<Schemas["TrustView"]>({
    url,
    method: "get",
    errorNotification: false,
    queryOptions: { enabled: ready, retry: false },
  });
  const view = query.isSuccess ? result.data : undefined;
  return (
    <Show title="Доверие" isLoading={ready && query.isLoading} goBack={false} breadcrumb={false} headerButtons={() => null}>
      <Space wrap style={{ marginBottom: 16 }}>
        <Radio.Group
          optionType="button"
          value={level}
          onChange={(e) => setLevel(e.target.value as Level)}
          options={[
            ...(all.includes("installation_admin") ? [{ value: "installation", label: "Установка" }] : []),
            { value: "org", label: "Организация" },
            { value: "group", label: "Группа" },
          ]}
        />
        {level === "group" && <GroupPick value={group} onChange={setGroup} />}
      </Space>
      {level === "group" && !group && <Typography.Text type="secondary">Выберите группу — матрица покажет её политику.</Typography.Text>}
      {query.isError && <Alert type="warning" showIcon message="Политика уровня недоступна: узел ответил отказом." />}
      {view && (
        // Смена уровня и перечитывание после записи — новый редактор с состояниями узла.
        <LevelEditor
          key={`${level}:${group ?? ""}:${query.dataUpdatedAt}`}
          url={url}
          view={view}
          editable={editable}
          org={level === "org"}
          onChanged={() => void query.refetch()}
        />
      )}
    </Show>
  );
}
