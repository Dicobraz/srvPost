import { useGetIdentity, usePermissions } from "@refinedev/core";
import { Layout, Space, Typography } from "antd";

import { getOrg, type Schemas } from "../api/client";
import { allowed } from "../providers/access";
import { Brand } from "./logo";
import { OrgSelect, useOrgs } from "./orgs";

/** Шапка: знак и название (брендинг заказчика, UI-22; нет — знак IT TASK из UI-19), кто вошёл, организация
 * (администратор инсталляции выбирает её из списка); выход — в меню. */
export function Header() {
  const { data: me } = useGetIdentity<Schemas["WhoAmI"]>();
  const { data: roles } = usePermissions<Schemas["AdminRole"][]>({});
  const { name } = useOrgs(Boolean(roles && allowed(roles, "organization", "list")));
  return (
    <Layout.Header
      style={{
        background: "transparent",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        padding: "0 24px",
      }}
    >
      <Brand height={20} />
      <Space size="middle">
        <Typography.Text type="secondary">Организация:</Typography.Text>
        {roles?.includes("installation_admin") ? <OrgSelect /> : <Typography.Text>{name(getOrg())}</Typography.Text>}
        <Typography.Text strong>{me?.login}</Typography.Text>
      </Space>
    </Layout.Header>
  );
}
