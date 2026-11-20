import { BgColorsOutlined, LogoutOutlined, UserOutlined } from "@ant-design/icons";
import { useGetIdentity, useLogout, usePermissions } from "@refinedev/core";
import { Avatar, Button, Drawer, Dropdown, Layout, Space, Typography } from "antd";
import type { MenuProps } from "antd";
import { useState } from "react";

import { getOrg, type Schemas } from "../api/client";
import { allowed } from "../providers/access";
import { BrandingSection } from "./branding";
import { Brand } from "./logo";
import { OrgSelect, useOrgs } from "./orgs";

/** Шапка: знак и название (брендинг заказчика, UI-22; нет — знак IT TASK из UI-19), кто вошёл, организация
 * (администратор инсталляции выбирает её из списка). Меню пользователя (FIX-24): настройки интерфейса —
 * не повседневные, им не место на видном месте, и выход. */
export function Header() {
  const { data: me } = useGetIdentity<Schemas["WhoAmI"]>();
  const { data: roles } = usePermissions<Schemas["AdminRole"][]>({});
  const { name } = useOrgs(Boolean(roles && allowed(roles, "organization", "list")));
  const { mutate: logout } = useLogout();
  const [settings, setSettings] = useState(false);
  const items: MenuProps["items"] = [
    { key: "settings", icon: <BgColorsOutlined />, label: "Настройки интерфейса", onClick: () => setSettings(true) },
    { type: "divider" },
    { key: "logout", icon: <LogoutOutlined />, label: "Выход", onClick: () => logout() },
  ];
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
        <Dropdown menu={{ items }} trigger={["click"]}>
          <Button type="text" shape="round" icon={<Avatar size="small" icon={<UserOutlined />} />} aria-label="Меню пользователя">
            {me?.login}
          </Button>
        </Dropdown>
      </Space>
      {/* Настройки интерфейса (брендинг, UI-22): вкладки «Установка»/«Организация» по роли. */}
      <Drawer title="Настройки интерфейса" open={settings} onClose={() => setSettings(false)} width={760} destroyOnHidden>
        <BrandingSection />
      </Drawer>
    </Layout.Header>
  );
}
