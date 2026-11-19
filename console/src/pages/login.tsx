import { useLogin } from "@refinedev/core";
import { Button, Card, Divider, Form, Input, Layout, Typography } from "antd";
import { useEffect, useState } from "react";

import type { Schemas } from "../api/client";
import { Brand } from "../components/logo";
import { BUILTIN_PRODUCT, useBranding, useBrandingDomain } from "../providers/branding";
import { type LoginParams, type SessionInfo, sessionInfo } from "../providers/auth";

/** Задержка перезапроса брендинга по домену имени входа: печатание не спрашивает сервер на каждый знак. */
const DOMAIN_DEBOUNCE_MS = 500;

/** Домен имени входа (после `@`): почтовые домены публичны через MX — по ним открытый маршрут отдаёт брендинг организации. */
function domainOf(login: string | undefined): string | undefined {
  const domain = (login?.split("@").pop() ?? "").trim().toLowerCase();
  // Домен в печати (без точки) не спрашиваем: ответ всё равно — брендинг установки.
  return /^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$/.test(domain) ? domain : undefined;
}

/**
 * Экран входа (решение 117): OIDC с PKCE, если узел сообщает поставщика; имя входа и пароль администратора, если вход
 * по паролю включён (`admin.password_login`); иначе — одноразовый токен `thepost admin init` (META-43). Знак,
 * название и тема — действующий брендинг (UI-22): сперва установки, по домену имени входа — организации.
 */
export function LoginPage() {
  const { mutate: login, isPending } = useLogin<LoginParams>();
  const [info, setInfo] = useState<SessionInfo | null>(null);
  const setDomain = useBrandingDomain();
  const [form] = Form.useForm<Schemas["PasswordLogin"]>();
  const typed = Form.useWatch("login", form) as string | undefined;
  useEffect(() => {
    // С задержкой: брендинг перезапрашивается, когда домен в имени входа напечатан.
    const t = setTimeout(() => setDomain(domainOf(typed)), DOMAIN_DEBOUNCE_MS);
    return () => clearTimeout(t);
  }, [typed, setDomain]);
  useEffect(() => {
    void sessionInfo().then((i) => {
      setInfo(i);
      // Возврат от поставщика OIDC: в адресе — код авторизации.
      const q = new URLSearchParams(location.search);
      if (i.oidc && q.has("code") && q.has("state")) login({ oidc: i.oidc, callback: true });
    });
  }, [login]);
  const oidc = info?.oidc;
  const submit = (
    <Button type={oidc ? "default" : "primary"} htmlType="submit" loading={isPending} block>
      Войти
    </Button>
  );
  const product = useBranding()?.name ?? BUILTIN_PRODUCT;
  return (
    <Layout style={{ minHeight: "100vh", justifyContent: "center", alignItems: "center" }}>
      <Card style={{ width: 400 }}>
        <Brand height={30} style={{ display: "flex", justifyContent: "center", margin: "8px auto 16px" }} />
        <Typography.Title level={3} style={{ textAlign: "center" }}>
          {product} — вход
        </Typography.Title>
        {oidc && (
          <>
            <Button type="primary" block loading={isPending} onClick={() => login({ oidc })}>
              Войти через OIDC
            </Button>
            <Divider plain>или</Divider>
          </>
        )}
        {info?.password && (
          <Form form={form} layout="vertical" onFinish={(v) => login(v)}>
            <Form.Item name="login" label="Имя входа" rules={[{ required: true, message: "Укажите имя входа" }]}>
              <Input autoComplete="username" />
            </Form.Item>
            <Form.Item
              name="password"
              label="Пароль"
              extra="Пароль администратора; первый — выдаёт thepost admin init."
              rules={[{ required: true, message: "Укажите пароль" }]}
            >
              <Input.Password autoComplete="current-password" />
            </Form.Item>
            {submit}
          </Form>
        )}
        {info && !info.password && (
          <Form layout="vertical" onFinish={(v: { token: string }) => login(v)}>
            <Form.Item
              name="token"
              label="Токен администратора"
              extra="Вход по паролю выключен. Токен выдаёт thepost admin init, действует один раз."
              rules={[{ required: true, message: "Укажите токен" }]}
            >
              <Input.Password autoComplete="off" />
            </Form.Item>
            {submit}
          </Form>
        )}
      </Card>
    </Layout>
  );
}
