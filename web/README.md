# Веб-клиент The Post (полоса mod-webmail)

SPA поверх JMAP (SRS 1.3, решение 2026-11-20, `docs/decisions/2026-11-20-webmail.md`): React 19 +
TypeScript + Vite, та же цепочка, что у веб-консоли (`console/`). Каркас (WEB-01): оболочка с
разделами Почта / Календарь / Контакты, шов «Каналы» под будущий веб-чат (решение 2026-11-17),
темы из `design/tokens.toml`. Вход (WEB-02): OIDC authorization code + PKCE из SPA
(`oidc-client-ts`, как в веб-консоли) с тихим renew между вкладками (BroadcastChannel) или
fallback — логин + пароль приложения (Basic); конфигурация входа — `/mail/config.json` от узла
(секция `modules.webmail`). Данные — JMAP того же узла (same-origin); ящики и письма — WEB-03;
композер — WEB-04.

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
(`THEPOST_JMAP=https://узел` — прокси JMAP и `/mail/config.json`).

Сборка `dist/` вшивается в бинарный файл `thepost` (`rust-embed`, фича `webmail`) и раздаётся
слушателем JMAP под `/mail/` (`crates/tp-webmail`, wiring — `crates/thepost/src/webmail.rs`).
Выключается секцией `modules.webmail.enabled: false`.

## Вход

- **OIDC (основной путь)**: `modules.webmail.oidc` — `issuer` (discovery), `client_id` (публичный
  клиент, PKCE), `scope`, опционально `end_session` (если discovery поставщика не отдаёт адрес
  выхода). Тихий renew — refresh-токеном (скрытый iframe не нужен, CSP не расширяется); при
  неудаче — тихий перевход к поставщику с сохранением маршрута.
- **Fallback — Basic**: `basic_login: true` при настроенном OIDC (без OIDC — вход и так только по
  паролю приложения). Пароль живёт только в памяти вкладки — ни sessionStorage, ни канал вкладок
  его не покидают.
- **Между вкладками**: одна (старейшая с OIDC-сессией) renew'ит токен, остальные подхватывают по
  `BroadcastChannel` (`web/src/auth/store.ts`) — земля для «один WebSocket на пользователя» (WEB-03).

## Темы

Единственный источник цветов — `design/tokens.toml` (решение 119), читается при сборке (`?raw` +
`smol-toml`) и в тестах; виртуальные модули `design/<файл>` — как в `console/vite.config.ts`.
Переключение: системная (prefers-color-scheme), светлая, тёмная (`web/src/theme.ts`); выбор — в
localStorage. Файлы шрифтов вшьёт карточка WEB-03 (CSP разрешает только свои ресурсы).

## Композер (WEB-04)

Композер — вкладка приложения (`/compose`), не модалка, по макету `docs/design/webmail/02`:
редактор TipTap (`@tiptap/react` v3 + StarterKit + Table + Link), чипы получателей
(Кому/Копия/Скрытая) с автодополнением и пикером «Кому…», таблицы (контекст-меню по правому
клику), чипы вложений, подпись под телом.

- **Вставка из Word**: pastedown через DOMPurify (`compose/word-paste.ts`) — мусор mso-стилей,
  conditional comments и `<o:p>` вычищен; списки Word (абзацы `MsoListParagraph`) разбираются в
  ul/ol, таблицы/жирность/colspan сохраняются. Тот же пайплайн идёт телом письма при отправке.
- **Автодополнение**: адресная книга из JMAP ContactCard — если у учётной записи есть капабилити
  `urn:ietf:params:jmap:contacts` (`compose/contacts.ts`); иначе и всегда — локальная история
  отправок (localStorage, `compose/send-history.ts`, до WEB-07 — там же появятся контакты и GAL
  в вебе). Подсказка честно подписана источником («Контакты» / «История»).
- **Вложения**: пикер и drag-drop → `POST uploadUrl` сессии (RFC 8620 §6.1) — тело File (File
  API): файл читается браузером частями, память вкладки не растёт с размером файла; прогресс и
  отмена — XHR + AbortController; `maxSizeUpload` сессии — честная ошибка до запроса и HTTP 413
  при превышении (`compose/attachments.ts`).
- **Черновики**: автосохранение Email/set в Drafts с debounce 1,5 с (`compose/drafts.ts`) —
  каждое сохранение создаёт новое письмо и уничтожает прежнее (тело Email/set сервер не правит);
  источник истины — черновик сервера: восстановление из Drafts («Изменить черновик» в
  контекст-меню списка), уход со вкладки сохраняет правки, Ctrl+Z — цепочка редактора.
- **Отправка + undo-send**: один запрос — Email/set (письмо в «Отправленные», черновик — в
  destroy) + EmailSubmission/set по ссылке `#<cid>` (`compose/send.ts`). Если сервер даёт
  `maxDelayedSend ≥ 15 с` — sendAt на окно ~15 с: «Отменить» в тосте меняет `undoStatus` на
  `canceled` (undo) и возвращает письмо в черновики; после выпуска сервер отвечает
  `cannotUnsend` — тост честно сообщает («Письмо уже ушло»). Без поддержки сервера — отправка
  немедленная, у тоста нет «Отменить». Отправка офлайн — очередь WEB-09.
- **Предупреждения** (`compose/warnings.ts`): inline-полоса, не модалка — «прилагаю» без
  вложений, внешние получатели (чужой домен, домены контактов не считаются внешними), пустая
  тема; «Отправить всё равно» — повторный клик.
- **Ответы/пересылка**: цитата («В …, … писал(а):» + blockquote; для пересылки — блок
  «Пересланное сообщение»), In-Reply-To/References, forward attached — оригинал вложением
  .eml по blobId письма (`compose/quote.ts`).
- **От**: адрес отправителя из JMAP Identity/get; больше одного — селектор Send As; без права
  сервер отвечает `forbiddenToSend` (честная ошибка в тосте). Подпись — `htmlSignature` identity
  (каталог), при пустом — localStorage `thepost-webmail-signature` (настройки UI — WEB-14,
  inline-картинки подписи — тоже после WEB-14).
