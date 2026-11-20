# Веб-клиент The Post (полоса mod-webmail)

SPA поверх JMAP (SRS 1.3, решение 2026-11-20, `docs/decisions/2026-11-20-webmail.md`): React 19 +
TypeScript + Vite, та же цепочка, что у веб-консоли (`console/`). Каркас (WEB-01): оболочка с
разделами Почта / Календарь / Контакты, шов «Каналы» под будущий веб-чат (решение 2026-11-17),
темы из `design/tokens.toml`. Данные — JMAP того же узла (same-origin); вход (OIDC + PKCE,
`oidc-client-ts`) — WEB-02, ящики и письма — WEB-03.

## Сборка и проверка

```sh
npm ci
npm run typecheck   # tsc --noEmit
npm run lint        # eslint
npm test            # vitest
npm run build       # vite build -> dist/ + проверка внешних адресов (scripts/check-dist.mjs)
```

Локально по правилу 18.11 не собирать: проверки и сборку делает CI (`.github/actions/webmail`,
job `webmail` в `ci.yml`). Разработка: `npm run dev` против узла из `docs/DEV.md`
(`THEPOST_JMAP=https://узел` — прокси JMAP).

Сборка `dist/` вшивается в бинарный файл `thepost` (`rust-embed`, фича `webmail`) и раздаётся
слушателем JMAP под `/mail/` (`crates/tp-webmail`, wiring — `crates/thepost/src/webmail.rs`).
Выключается секцией `modules.webmail.enabled: false`.

## Темы

Единственный источник цветов — `design/tokens.toml` (решение 119), читается при сборке (`?raw` +
`smol-toml`) и в тестах; виртуальные модули `design/<файл>` — как в `console/vite.config.ts`.
Переключение: системная (prefers-color-scheme), светлая, тёмная (`web/src/theme.ts`); выбор — в
localStorage. Файлы шрифтов вшьёт карточка WEB-03 (CSP разрешает только свои ресурсы).
