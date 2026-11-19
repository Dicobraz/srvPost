// Знак (UI-19, UI-22): по умолчанию — знак IT TASK (решение 119), design/logo.svg — куб и надпись; на тёмном
// фоне надпись белая (logo-white.svg). Файлы читаются из design/ виртуальным модулем Vite (vite.config.ts)
// и вшиваются адресом data: — без запросов наружу. Брендинг заказчика заменяет знак и название PNG-знаком
// из открытого маршрута узла; нет знака или он не загрузился — только название.
import { useState, type CSSProperties } from "react";

import logoRaw from "design/logo.svg";
import logoWhiteRaw from "design/logo-white.svg";

import { useBranding } from "../providers/branding";
import { fonts, useDark } from "../theme";

const src = (svg: string) => `data:image/svg+xml,${encodeURIComponent(svg)}`;

/** Встроенный знак IT TASK: чёрная надпись на светлом фоне, белая — на тёмном (решение 119). Пропорция 1327×521. */
export function ItTaskSign({ height = 24, style }: { height?: number; style?: CSSProperties }) {
  const dark = useDark();
  return (
    <img
      alt="IT TASK"
      height={height}
      src={src(dark ? logoWhiteRaw : logoRaw)}
      style={style}
      width={Math.round((height * 1327) / 521)}
    />
  );
}

/**
 * Знак и название: брендинг заказчика — PNG-знак (высота `height`, ширина по пропорции файла) и название
 * шрифтом заголовков; `null` в брендинге или нет ответа — встроенный знак IT TASK. Знак не загрузился —
 * только название (карточка UI-22).
 */
export function Brand({ height = 24, style }: { height?: number; style?: CSSProperties }) {
  const branding = useBranding();
  const [failedUrl, setFailedUrl] = useState<string | null>(null);
  const logo = branding?.logo;
  const name = branding?.name ?? null;
  if (!logo && !name) return <ItTaskSign height={height} style={style} />;
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 10, ...style }}>
      {logo && failedUrl !== logo.url && (
        <img
          alt=""
          height={height}
          onError={() => setFailedUrl(logo.url)}
          src={logo.url}
          style={{ width: "auto", maxWidth: height * 6, objectFit: "contain" }}
        />
      )}
      {name && (
        <span style={{ fontFamily: fonts.heading, fontSize: Math.round(height * 0.72), lineHeight: 1 }}>{name}</span>
      )}
    </span>
  );
}
