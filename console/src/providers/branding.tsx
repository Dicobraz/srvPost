// Действующий брендинг заказчика (UI-22, решение 122): до входа — открытый маршрут (по домену имени входа),
// после — `effective` своей организации (администратор установки — уровня установки). Ответ заменяет роли темы
// токенов; своих расчётов цветов и контраста в консоли нет — сервер отдаёт уже выведенный и проверенный набор.
import { createContext, useContext, useEffect, useState } from "react";

import { API, apiUrl, request, whoami, type Schemas } from "../api/client";
import { roleOverlay, type Branding } from "../theme";

/** Встроенное название продукта (без брендинга): заголовок вкладки и страницы входа. */
export const BUILTIN_PRODUCT = "The Post";

let current: Branding | null = null;

/** Название продукта из действующего брендинга (`null` — встроенное): для заголовка вкладки (i18n). */
export const productName = () => current?.name ?? null;

/** Знак из `effective`: хэш — адрес открытого маршрута знака (без входа, immutable). */
function logoOf(logo: Schemas["BrandLogo"] | null | undefined): Branding["logo"] {
  return logo ? { url: apiUrl(`${API}/public/branding/logo/${logo.hash}`) } : null;
}

/** Открытый маршрут без входа: только название, цвета всех ролей и ссылка на знак — без сведений об организации. */
export async function publicBranding(domain?: string): Promise<Branding | null> {
  try {
    const { data } = await request<Schemas["PublicBranding"]>(`${API}/public/branding`, domain ? { query: { domain } } : {});
    return {
      name: data.product_name ?? null,
      logo: data.logo ? { url: apiUrl(data.logo) } : null,
      light: roleOverlay(data.palette.light),
      dark: roleOverlay(data.palette.dark),
    };
  } catch {
    return null; // узел недоступен — тема IT TASK из токенов
  }
}

/**
 * После входа — `effective` своей организации (администратор установки — уровня установки, решение 122):
 * организация поверх установки. Аудитору брендинг недоступен — открытый маршрут (уровень установки).
 */
async function effectiveBranding(): Promise<Branding | null> {
  try {
    const roles = (await whoami()).roles;
    const view = roles.includes("installation_admin")
      ? `${API}/branding`
      : roles.includes("organization_admin") || roles.includes("operator")
        ? `${API}/orgs/{org}/branding`
        : null;
    if (!view) return publicBranding();
    const { data } = await request<Schemas["BrandingView"]>(view);
    return { name: data.effective.product_name ?? null, logo: logoOf(data.effective.logo), ...paletteOf(data) };
  } catch {
    return null;
  }
}

const paletteOf = (data: Schemas["BrandingView"]) => ({
  light: roleOverlay(data.effective.palette.light),
  dark: roleOverlay(data.effective.palette.dark),
});

/** Брендинг для отрисовки (`null` — ещё нет ответа или узел недоступен) и домен имени входа экрана входа. */
export interface BrandingState {
  branding: Branding | null;
  /** Домен из введённого имени входа (после `@`): экран входа перезапрашивает брендинг организации. */
  setDomain: (domain: string | undefined) => void;
}

const BrandingContext = createContext<BrandingState>({ branding: null, setDomain: () => undefined });

export const useBranding = () => useContext(BrandingContext).branding;
export const useBrandingDomain = () => useContext(BrandingContext).setDomain;

/**
 * Загружает действующий брендинг: `token` — сессия (после входа `effective`, до входа — открытый маршрут по
 * `domain`). Пока ответа нет — `null`, тема строится из токенов; заголовок вкладки — название продукта.
 */
export function useBrandingState(token: string | null): BrandingState {
  const [branding, setBranding] = useState<Branding | null>(null);
  const [domain, setDomain] = useState<string | undefined>();

  useEffect(() => {
    let cancelled = false;
    const apply = (b: Branding | null) => {
      if (cancelled) return;
      current = b;
      setBranding(b);
    };
    if (token) void effectiveBranding().then(apply);
    else void publicBranding(domain).then(apply);
    return () => {
      cancelled = true;
    };
  }, [token, domain]);

  // Заголовок вкладки — название продукта (карточка UI-22); дальше его ведёт Refine с тем же названием (i18n).
  useEffect(() => {
    document.title = branding?.name ?? BUILTIN_PRODUCT;
  }, [branding?.name]);

  return { branding, setDomain };
}

export const BrandingProvider = BrandingContext.Provider;
