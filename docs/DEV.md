# Разработка The Post

## Окружение
- Linux x86_64 (на Windows — WSL2 Ubuntu, репозиторий — в файловой системе WSL). Rust stable
  (`rust-toolchain.toml`; не ниже 1.98 — `rust-version` в `Cargo.toml`), `cargo install cargo-nextest --locked`.
- Узел собирается только под Linux: `tp-sys` зависит от `landlock`, `seccompiler` и `nix`. На Windows без WSL не
  собираются `tp-sys` и всё, что от него зависит: `tp-platform`, `tp-search`, `tp-smtp`, `tp-sieve`, `tp-imap`,
  `tp-jmap`, `tp-dav`, `thepost`.
- Фичи крейта `thepost` (по умолчанию выключены; в выпуске и образе — обе): `gssapi` — вход по Kerberos (сборке —
  `libkrb5-dev` и `libclang-dev`, узлу — `libgssapi_krb5`), `console` — вшитая веб-консоль (до `cargo build` —
  Node 26, `npm ci && npm run build` в `console/`).
- Зависимости для интеграционных тестов: `docker compose -f deploy/compose/dev.yml --profile dev up -d --wait`
  (профиль по умолчанию — `tls`, только TLS; описание — [deploy/README.md](../deploy/README.md#зависимости)).
- Переменные: `TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres`, `TEST_S3_URL`,
  `TEST_OPENBAO_URL` с `TEST_OPENBAO_TOKEN`, `TEST_LDAP_URL` — тест без своей переменной пропускается
  (`tp_testkit::pg_url()`). Значения для профиля `dev` —
  [deploy/README.md](../deploy/README.md#интеграционные-тесты).

## Запуск
Узел — один бинарный файл: `thepost serve --config <config.yaml>` (по умолчанию — `THEPOST_CONFIG` или
`/etc/thepost/config.yaml`); другие команды — `config check`, `config schema`,
`doctor`, `verify`, `admin`. Готовый узел с зависимостями в контейнерах —
`docker compose -f deploy/compose/dev.yml --profile smb up -d --build`
([deploy/README.md](../deploy/README.md#эталон-smb-в-контейнерах-профиль-smb)). Установка на сервер —
[docs/INSTALL.md](INSTALL.md), стенд нагрузки — `deploy/stand/stand.yml`.

## Состав
| Путь | Что это | Полоса |
|---|---|---|
| `crates/tp-contracts` | межкрейтовые контракты (правка — класс B) | contracts |
| `crates/tp-testkit` | in-memory реализации контрактов и корпус писем для тестов полос | testkit |
| `crates/tp-sys`, `tp-platform` | системный слой Linux (seccomp, Landlock, сокеты); конфигурация, секреты, слушатели | sys, platform |
| `crates/tp-meta`, `tp-blob`, `tp-mailstore`, `tp-cluster`, `tp-search` | PostgreSQL, хранилище писем (диск и S3), почтовое хранилище, кластер, поиск | по имени крейта |
| `crates/tp-auth`, `tp-smtp`, `tp-sieve`, `tp-imap`, `tp-jmap`, `tp-dav` | доступ и протоколы (POP3 — в `tp-imap`) | по имени крейта |
| `crates/tp-admin` | Admin REST API; с фичей `console` вшивает `console/dist` | admin |
| `crates/tp-admin-client` | клиент Admin API — общий для CLI `thepost admin` и текстового интерфейса; подсветка вывода CLI | admin |
| `crates/tp-tui` | текстовый интерфейс `thepost admin tui` — тонкий клиент Admin API | tui |
| `crates/thepost` | бинарный файл: сборка ролей по `config.yaml`; `src/admin_cli.rs` — полоса admin | app |
| `console/` | веб-консоль (Refine, Ant Design); запуск — `console/README.md` | console |
| `design/` | фирменный стиль: `tokens.toml` и знак — единственный источник цветов консоли, `tp-tui` и CLI | design |
| `deploy/` | compose, Ansible, Helm, systemd, пресеты `config.yaml`; описание — `deploy/README.md` | deploy |

Токены `design/tokens.toml` вшиваются при сборке: консоль читает их в `npm run build`, `tp-tui` и
`tp-admin-client` — `include_str!`. Контраст ролей проверяет `python3 scripts/design_contrast.py design/tokens.toml`
(job `design`).

## Миграции схемы (META-92)
Схема — у ядра и у каждого модуля своя (`mod_<имя>`). Миграции вшиты в бинарник и применяются узлом при старте:
ядро — `crates/tp-meta/src/schema.rs` (список `MIGRATIONS`, `sqlx::Migrator`, рекомендательная блокировка —
параллельный старт узлов безопасен), модули — `tp_meta::modules::migrate_module` (одна транзакция на схему,
advisory lock, контрольные суммы применённых). Боевые правила (решение владельца 20.11):

- версии только добавляются, применённые не меняются (сверка checksum — «применённая миграция изменена» — отказ
  старта), и только вперёд: версия ниже уже применённых — отказ;
- срыв миграции откатывает транзакцию целиком — схема остаётся прежней, узел не стартует (тест
  `failed_migration_rolls_back`): «положить базу» миграцией нельзя, можно оставить узел не запущенным — это видно;
- **сильная смена схемы — расширение/сжатие, два релиза.** Релиз N добавляет новый формат рядом со старым
  (таблицы/колонки), пишет в оба, читает из старого, историю доливает порциями (батчами с чекпойнтом в схеме
  модуля — не «один UPDATE по всем строкам»: локи и место). Релиз N+1 сжимает — удаляет старый формат. Сжатие
  никогда не в том же релизе, что расширение: пока окно открыто, откат — поставить предыдущий релиз (он живёт
  на общей схеме); после сжатия вниз — только восстановление из копии (PITR pgBackRest,
  [deploy/README «Обновление»](../deploy/README.md#обновление-решение-владельца-2011-dep-60)).
  Пример: 0005 — `ADD COLUMN title_new`, порционный залив из кода модуля, чтение ещё из `title`; 0006 —
  `DROP COLUMN title` и переименование. 0005 откатывается предыдущим релизом, 0006 — нет;
- шаги вне транзакции (`CREATE INDEX CONCURRENTLY`) раннером не поддерживаются — держим таблицы, где обычный
  индекс в транзакции приемлем; появится большая боевая таблица — отдельная карточка на шаги вне транзакции,
  не обходными путями;
- **репетиция мажора:** перед боевым деплоем версии со сменой схемы — прогон на копии (pgBackRest →
  `restore.yml` на пустой ВМ), время и место — в заметки выпуска.

## Проверки (конец волны)
```
cargo fmt --all
cargo clippy -p <крейты> --all-targets -- -D warnings
cargo nextest run -p <крейты> --no-tests=pass
```
CI (`.github/workflows/ci.yml`) — обязательная проверка одна, `gate`: зелёная, если нужные задания прошли или пропущены.
PR только с `docs/`, `*.md` в корне и `*/README.md` идёт без сборки; только с `console/` — без Rust, с заданием `console`.

| Задание | Когда | Что делает |
|---|---|---|
| `changes` | всегда | изменённые файлы; на PR — `lane_check` (`.github/lane_check.py`) |
| `fmt` | изменён код | `cargo fmt --all --check` |
| `clippy` | изменён код | `cargo clippy --workspace --all-targets --locked --features thepost/gssapi`, `RUSTFLAGS=-D warnings` |
| `test` | изменён код | PostgreSQL 16; `cargo nextest run --workspace --locked --profile ci --no-tests=pass` (профиль — `.config/nextest.toml`), `cargo test --doc --workspace --locked`; при правке `crates/tp-admin/` — сверка схемы Admin API с `console/src/api/openapi.json` |
| `interp` | изменён код | поставка без интерпретаторов: базовый образ `deploy/docker/Dockerfile` |
| `deny` | изменены любой `Cargo.toml`, `Cargo.lock`, `deny.toml` | `cargo deny --locked check licenses bans sources`, `cargo audit` |
| `console` | изменены `console/`, `design/` | типы, линтер, vitest, `npm audit`, лицензии, `npm run build` |
| `design` | изменены `design/`, `scripts/design_contrast.py` | контраст ролей `design/tokens.toml` |
| `release` | только main, теги `v*` (бета, выпуск), ручной запуск | release-сборка и артефакт |

Бета и образ — `.github/workflows/beta.yml`, ночной фаззинг (`crates/*/fuzz`) — `fuzz.yml`.

## Полосы и очередь
- Полосы — `lanes.toml`: первое совпадение сверху вниз, `*` включает `/`. `[common]` (`docs/tasks/*`,
  `docs/manual-tests/*`, `docs/decisions/*`, `docs/metrics/*`) разрешён в любом PR.
- Одна волна = одна полоса = один PR, ветка `w/<полоса>-<NN>`. PR с файлами двух полос `lane_check` отклоняет;
  межполосный PR — ветка `x/<суть>`, класс B.
- Документы: `deploy/README.md` — полоса deploy, `console/README.md` — console, `docs/CONTRACTS.md` — contracts,
  `docs/*` и прочие `*.md` — docs. Корневые `Cargo.toml`, `Cargo.lock`, `deny.toml`, `rust-toolchain.toml`,
  `rustfmt.toml`, `clippy.toml` — deps; `.github/*`, `.config/*`, `scripts/*`, `lanes.toml` — ci.
- Класс B — пути из `.github/CODEOWNERS` (нужен approve владельца), остальное — класс A: `gh pr merge --auto`,
  очередь мержит merge-коммитом (решение 2026-10-31). Метка `owner-review` делает `gate` красным: PR ждёт владельца.

## Агенты
Все полосы собираются на Linux, поэтому основной режим — облачные агенты (Managed Agents).
```
python scripts/cloud_agent.py run ThePost <полоса> <NN> <ID> [<ID> ...] [--budget 10]
python scripts/cloud_agent.py wait <session>
python scripts/cloud_agent.py say <session> <текст>
gh pr create -R Dicobraz/srvPost --head w/<полоса>-<NN> --fill && gh pr merge -R Dicobraz/srvPost --auto w/<полоса>-<NN>
```
Нужны `ant` (`ant auth login`) и `gh` (`gh auth login`). Агент и окружение — те же, что у pets (`PETS_AGENT_ID`, `PETS_AGENT_ENV`).
Альтернатива — сессия Claude Code (claude.ai/code или локально в WSL2) с промптом `docs/process/agent-prompt.md`;
локально — отдельный worktree на полосу: `git worktree add ../ThePost-<полоса> origin/main`, свой `CARGO_TARGET_DIR`, общий `sccache`.
Локально — только `-p <крейты>` на хосте; сборка под Linux (крейты из раздела «Окружение») и тесты с PostgreSQL — CI
(без локальных контейнеров и томов).
В конце волны агент удаляет свой worktree и `CARGO_TARGET_DIR`.

## Карточки
Шаблон — поля `lane, deps, class, files, read, checks, manual` + разделы «Сделать», «Приёмка» (см. любую `docs/tasks/*.md`).
Ручная проверка — `docs/manual-tests/<ID>.md`. Решение владельца — `docs/decisions/<YYYY-MM-DD>-<slug>.md`.
План волн — `docs/PLAN.md`; сводку `docs/tasks/README.md` генерирует `python3 scripts/plan_index.py`.
