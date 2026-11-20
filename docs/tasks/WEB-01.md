# WEB-01. Каркас: полоса mod-webmail, SPA встроен в бинарь

**Класс:** B · **Волна:** `mod-webmail-1` · **Ждёт:** — (старт модуля: решение 2026-11-20, `docs/decisions/2026-11-20-webmail.md`)

Веб-клиент — SPA поверх JMAP (SRS 1.3 «Веб-клиент»), без отдельного веб-сервиса. Каркас =
новая полоса + пустой shell, вшитый в бинарь как веб-консоль.

## Полоса

`lanes.toml` — `[lane.mod-webmail]` (правка lanes.toml — класс B): `web/*`,
`crates/tp-webmail/*`, `crates/thepost/src/webmail*.rs` (по образцу исключения admin
в lanes.toml: свой файл в thepost — чтобы PR не пересекался с полосой app).

## Что делает

1. `web/` — каркас Vite + React 19 + TypeScript по образцу `console/`: ESLint, vitest,
   бренд-токены из `design/tokens.toml` (virtual modules), base `/mail/`. Сборка — `web/dist`.
2. Пустой shell приложения: маршрутизация, оболочка с разделами Почта/Календарь/Контакты
   и **швом «Каналы»** (место под будущий веб-чат, решение 2026-11-17 — не реализуется),
   переключение тем по токенам.
3. Feature `webmail` в thepost: rust-embed `web/dist`, маршруты `/mail/*` на listener'е JMAP
   по образцу `tp-admin/src/console.rs`: SPA-fallback на index.html, строгий CSP
   (`default-src 'self'`), X-Frame-Options DENY; `modules.webmail.enabled=false` убирает
   маршруты. Код раздачи — `crates/tp-webmail`, wiring — `crates/thepost/src/webmail.rs`.
4. CI: композит-экшены для web-сборки по образцу `.github/actions/console` (setup-node,
   кэш по `web/package-lock.json`, typecheck/lint/vitest/npm audit, vite build) + проверка
   собранного образа: `GET /mail/` отдаёт shell (аналог console-check).

## Приёмка

- Собранный образ: `GET /mail/` и deep-link `/mail/folder/x` отдают SPA, ассеты не режутся CSP.
- `modules.webmail.enabled=false` — маршрутов нет; feature off — бинарник собирается без web/.
- CI: web-сборка зелёная; npm audit и лицензии в allow-list.
