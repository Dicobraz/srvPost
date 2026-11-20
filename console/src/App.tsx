import "@refinedev/antd/dist/reset.css";
import "dayjs/locale/ru";

// Иконки разделов панели (FIX-23): у свёрнутой панели подписей нет — у каждого раздела своя различимая иконка.
import {
  ApartmentOutlined,
  BankOutlined,
  BookOutlined,
  CalendarOutlined,
  ClockCircleOutlined,
  EyeOutlined,
  FileDoneOutlined,
  FileSearchOutlined,
  FilterOutlined,
  FolderOpenOutlined,
  InboxOutlined,
  MailOutlined,
  NodeIndexOutlined,
  SafetyCertificateOutlined,
  TeamOutlined,
  UserDeleteOutlined,
  UserOutlined,
  WarningOutlined,
} from "@ant-design/icons";
import { ErrorComponent, ThemedLayout, ThemedTitle, useNotificationProvider } from "@refinedev/antd";
import { Authenticated, CanAccess, Refine, usePermissions } from "@refinedev/core";
import routerProvider, { CatchAllNavigate, DocumentTitleHandler, NavigateToResource } from "@refinedev/react-router";
import { App as AntdApp, ConfigProvider } from "antd";
// ES-модуль: `antd/locale/ru_RU` (CommonJS) в сборке Vite приходит обёрткой без текстов — интерфейс остаётся английским.
import ruRU from "antd/es/locale/ru_RU";
import dayjs from "dayjs";
import { Outlet, Route, Routes, useLocation } from "react-router";

import { loadSession, type Schemas } from "./api/client";
import { Forbidden } from "./components/forbidden";
import { Header } from "./components/header";
import { i18nProvider } from "./i18n";
import { AccountCreate, AccountList, AccountShow } from "./pages/accounts";
import { AuditPage } from "./pages/audit";
import { ContactCreate, ContactEdit, ContactList } from "./pages/contacts";
import { DeliveryPage } from "./pages/delivery";
import { DisabledPage } from "./pages/disabled";
import { GroupCreate, GroupEdit, GroupList } from "./pages/groups";
import { JournalPage, JournalRulesPage } from "./pages/journal";
import { LoginPage } from "./pages/login";
import { MailboxAuditPage } from "./pages/mailbox-audit";
import { ModerationPage } from "./pages/moderation";
import { OrganizationPage } from "./pages/organization";
import { QueuePage } from "./pages/queue";
import { RiskPage } from "./pages/risk";
import { ResourceCreate, ResourceList, ResourceShow } from "./pages/resources";
import { AccountSieve, OrgSieve } from "./pages/sieve";
import { AccountTrash } from "./pages/trash";
import { TransportPage } from "./pages/transport";
import { TrustPage } from "./pages/trust";
import { UnitsPage } from "./pages/units";
import { accessControlProvider, allowed } from "./providers/access";
import { authProvider } from "./providers/auth";
import { BrandingProvider, useBranding, useBrandingState } from "./providers/branding";
import { dataProvider } from "./providers/data";
import { brandTheme, DarkProvider, useSystemDark } from "./theme";
import { installFonts } from "./fonts";

// Шрифты — одним <style> из файлов сборки (без внешних адресов), до первой отрисовки.
installFonts();

dayjs.locale("ru");

/** Название в заголовке боковой панели: брендинг заказчика, нет — The Post. */
const Title = (props: { collapsed: boolean }) => <ThemedTitle {...props} text={useBranding()?.name ?? "The Post"} />;

/** Первый раздел по роли: аудитору журнала — журнал переписки, аудитору — журнал аудита. */
function Home() {
  const { data: roles, isLoading } = usePermissions<Schemas["AdminRole"][]>({});
  if (isLoading) return null;
  const rs = roles ?? ["installation_admin"];
  const first = allowed(rs, "organization", "list") ? "organization" : allowed(rs, "audit", "list") ? "audit" : "journal";
  return <NavigateToResource resource={first} />;
}

export function App() {
  // Тема — светлая и тёмная, строится из design/tokens.toml и следует системной настройке (UI-19);
  // действующий брендинг заказчика заменяет роли токенов (UI-22).
  const dark = useSystemDark();
  // Вход и выход меняют адрес — сессия пересчитывается, брендинг перечитывается (effective после входа).
  useLocation();
  const token = loadSession()?.token ?? null;
  const branding = useBrandingState(token);
  return (
    <BrandingProvider value={branding}>
      <ConfigProvider locale={ruRU} theme={brandTheme(dark, branding.branding)}>
        <AntdApp>
          <DarkProvider value={dark}>
            <Refine
            routerProvider={routerProvider}
            dataProvider={dataProvider}
            authProvider={authProvider}
            accessControlProvider={accessControlProvider}
            i18nProvider={i18nProvider}
            notificationProvider={useNotificationProvider}
            // Порядок разделов — по предполагаемой частоте обращений (FIX-24): повседневные сверху,
            // настройка «раз при развёртывании» ниже, журналы аудитора внизу (для них это дом).
            resources={[
              {
                name: "accounts",
                list: "/accounts",
                create: "/accounts/create",
                show: "/accounts/:id",
                meta: { label: "Учётные записи", icon: <UserOutlined /> },
              },
              { name: "queue", list: "/queue", meta: { label: "Очередь", icon: <ClockCircleOutlined /> } },
              { name: "delivery", list: "/delivery", meta: { label: "Журнал доставки", icon: <MailOutlined /> } },
              { name: "moderation", list: "/moderation", meta: { label: "Модерация", icon: <EyeOutlined /> } },
              {
                name: "groups",
                list: "/groups",
                create: "/groups/create",
                edit: "/groups/:id",
                meta: { label: "Группы рассылки", icon: <TeamOutlined /> },
              },
              {
                name: "resources",
                list: "/resources",
                create: "/resources/create",
                show: "/resources/:id",
                meta: { label: "Ресурсы", icon: <CalendarOutlined /> },
              },
              {
                name: "contacts",
                list: "/contacts",
                create: "/contacts/create",
                edit: "/contacts/:id",
                meta: { label: "Адресная книга", icon: <BookOutlined /> },
              },
              { name: "units", list: "/units", meta: { label: "Оргструктура", icon: <ApartmentOutlined /> } },
              { name: "disabled-accounts", list: "/disabled-accounts", meta: { label: "Отключённые ящики", icon: <UserDeleteOutlined /> } },
              { name: "sieve", list: "/sieve", meta: { label: "Правила организации", icon: <FilterOutlined /> } },
              { name: "trust", list: "/trust", meta: { label: "Доверие", icon: <SafetyCertificateOutlined /> } },
              { name: "transport", list: "/transport", meta: { label: "Транспорт", icon: <NodeIndexOutlined /> } },
              // Признаки риска (UI-24): каталог, пороги, пакеты, источники TI — настройка поставщика
              // анти-спама; срабатывания — журнал организации.
              { name: "risk", list: "/risk", meta: { label: "Признаки риска", icon: <WarningOutlined /> } },
              // Правила журналирования (UI-26, решение #171): ведёт администратор организации —
              // аудитор журнала правил не видит (узел отвечает 403, раздел — другая роль).
              { name: "journal-rules", list: "/journal-rules", meta: { label: "Правила журналирования", icon: <FileDoneOutlined /> } },
              { name: "organization", list: "/organization", meta: { label: "Организация", icon: <BankOutlined /> } },
              // Отдельно от журналов доставки и аудита: содержимое писем — только аудитору журнала (UI-25).
              { name: "journal", list: "/journal", meta: { label: "Журнал переписки", icon: <InboxOutlined /> } },
              { name: "audit", list: "/audit", meta: { label: "Журнал аудита", icon: <FileSearchOutlined /> } },
              { name: "mailbox-audit", list: "/mailbox-audit", meta: { label: "Аудит ящиков", icon: <FolderOpenOutlined /> } },
            ]}
            // Без внешних обращений (SRS 5.2): телеметрия Refine выключена.
            options={{ disableTelemetry: true, syncWithLocation: true, warnWhenUnsavedChanges: true }}
          >
            <Routes>
              <Route
                element={
                  <Authenticated key="app" fallback={<CatchAllNavigate to="/login" />}>
                    <ThemedLayout Title={Title} Header={Header}>
                      {/* Раздел или действие по маршруту, недоступные роли, — «Нет доступа» вместо отказов узла в таблице. */}
                      <CanAccess fallback={<Forbidden />}>
                        <Outlet />
                      </CanAccess>
                    </ThemedLayout>
                  </Authenticated>
                }
              >
                <Route index element={<Home />} />
                <Route path="/organization" element={<OrganizationPage />} />
                <Route path="/accounts">
                  <Route index element={<AccountList />} />
                  <Route path="create" element={<AccountCreate />} />
                  <Route path=":id" element={<AccountShow />} />
                  <Route path=":id/trash" element={<AccountTrash />} />
                  <Route path=":id/sieve" element={<AccountSieve />} />
                </Route>
                <Route path="/resources">
                  <Route index element={<ResourceList />} />
                  <Route path="create" element={<ResourceCreate />} />
                  <Route path=":id" element={<ResourceShow />} />
                </Route>
                <Route path="/groups">
                  <Route index element={<GroupList />} />
                  <Route path="create" element={<GroupCreate />} />
                  <Route path=":id" element={<GroupEdit />} />
                </Route>
                <Route path="/disabled-accounts" element={<DisabledPage />} />
                <Route path="/contacts">
                  <Route index element={<ContactList />} />
                  <Route path="create" element={<ContactCreate />} />
                  <Route path=":id" element={<ContactEdit />} />
                </Route>
                <Route path="/units" element={<UnitsPage />} />
                <Route path="/moderation" element={<ModerationPage />} />
                <Route path="/queue" element={<QueuePage />} />
                <Route path="/sieve" element={<OrgSieve />} />
                <Route path="/trust" element={<TrustPage />} />
                <Route path="/transport" element={<TransportPage />} />
                <Route path="/risk" element={<RiskPage />} />
                <Route path="/delivery" element={<DeliveryPage />} />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="/journal" element={<JournalPage />} />
                <Route path="/journal-rules" element={<JournalRulesPage />} />
                <Route path="/mailbox-audit" element={<MailboxAuditPage />} />
                <Route path="*" element={<ErrorComponent />} />
              </Route>
              <Route
                path="/login"
                element={
                  <Authenticated key="login" fallback={<LoginPage />}>
                    <Home />
                  </Authenticated>
                }
              />
            </Routes>
            <DocumentTitleHandler />
          </Refine>
        </DarkProvider>
      </AntdApp>
      </ConfigProvider>
    </BrandingProvider>
  );
}
