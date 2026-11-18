// Знак IT TASK (решение 119): design/logo.svg — куб и надпись; на тёмном фоне надпись белая (logo-white.svg).
import type { CSSProperties } from "react";

import logo from "../../design/logo.svg";
import logoWhite from "../../design/logo-white.svg";

import { useDark } from "../theme";

/** Знак IT TASK: чёрная надпись на светлом фоне, белая — на тёмном (решение 119). Пропорция файла 1327×521. */
export function Brand({ height = 24, style }: { height?: number; style?: CSSProperties }) {
  const dark = useDark();
  return (
    <img alt="IT TASK" height={height} src={dark ? logoWhite : logo} style={style} width={Math.round((height * 1327) / 521)} />
  );
}
