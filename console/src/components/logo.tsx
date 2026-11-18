// Знак IT TASK (решение 119): design/logo.svg — куб и надпись; на тёмном фоне надпись белая (logo-white.svg).
// Файл читается из design/ при сборке (`?raw`) и вшивается адресом data: — без запросов наружу.
import type { CSSProperties } from "react";

import logoRaw from "../../design/logo.svg?raw";
import logoWhiteRaw from "../../design/logo-white.svg?raw";

import { useDark } from "../theme";

const src = (svg: string) => `data:image/svg+xml,${encodeURIComponent(svg)}`;

/** Знак IT TASK: чёрная надпись на светлом фоне, белая — на тёмном (решение 119). Пропорция файла 1327×521. */
export function Brand({ height = 24, style }: { height?: number; style?: CSSProperties }) {
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
