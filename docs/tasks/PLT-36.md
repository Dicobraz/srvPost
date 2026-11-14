# PLT-36: переменные THEPOST_* вне схемы не ломают проверку конфигурации

lane: platform
deps: []
class: A
files: [crates/tp-platform/src/config.rs]
read: [docs/decisions/2026-10-30-owner-answers.md#28, docs/ADMIN-GUIDE.md#переменные-окружения]
checks: [nextest]
manual: no

## Ошибка
- Стенд, бета `beta-20261114.3`: `thepost config check` — `rc=0`; с `THEPOST_ADMIN_URL=https://127.0.0.1:8443
  THEPOST_TUI_THEME=dark thepost config check` — `admin_url: unknown parameter`, `tui_theme: unknown parameter`, `rc=1`.
- Причина: `apply_env` применяет как параметр любую переменную с префиксом `THEPOST_`, кроме `THEPOST_CONFIG`.
  Переменные клиента (`THEPOST_ADMIN_URL`, `THEPOST_ADMIN_TOKEN`, `THEPOST_ADMIN_ORG`, `THEPOST_TUI_THEME`) становятся
  ключами верхнего уровня, строгая проверка считает их неизвестными параметрами.
- Следствия: в оболочке администратора, где эти переменные экспортированы (так советуют `docs/INSTALL.md` и
  `docs/ADMIN-GUIDE.md`), падает `thepost config check`; раздел «Конфигурация узла» в `thepost admin tui` не сохраняет
  правки (проверка перед записью — та же). Мягкий режим (запуск, перечитывание) пишет ложные предупреждения.

## Сделать
- `apply_env`: переменная `THEPOST_*` — переопределение, только если её первый ключ (до первого `__`, в нижнем
  регистре) — известный ключ верхнего уровня: параметр платформы (`domain`, `profile`, `roles`, `modules`), секция
  реестра или секция слоя данных (`database`, `blob`). Иначе переменная конфигурации не касается: не применяется,
  не ошибка и не предупреждение.
- Источник известных ключей один — `SectionRegistry::known_key`; им же пользуется проверка файла `unknown_params`
  (второго списка нет). Имён клиентских переменных в `tp-platform` нет.
- Отдельное исключение `THEPOST_CONFIG` из отбора убрать: ключа `config` в схеме нет, общее правило его покрывает.
  Константа `ENV_CONFIG_PATH` остаётся — её читает `crates/thepost/src/cli.rs`.
- Строгость к файлу и к полям известных секций не меняется: `smtpp: {}` в файле и `THEPOST_SMTP__LIMTS__X` в
  окружении — по-прежнему `unknown parameter`.

## Как делают другие
Общее правило у всех проверенных систем: окружение — общее пространство имён, незнакомая переменная своего префикса не
ошибка конфигурации; строгость, где она есть, относится к файлу.
- Spring Boot: при `ignoreUnknownFields = false` проверка непривязанных свойств не распространяется на источники
  `systemEnvironment` и `systemProperties` (`BENIGN_PROPERTY_SOURCE_NAMES`) —
  https://github.com/spring-projects/spring-boot/blob/3.5.x/spring-boot-project/spring-boot/src/main/java/org/springframework/boot/context/properties/source/UnboundElementsSourceFilter.java
- pydantic-settings, раздел «Unknown environment variables»: несовпавшие переменные игнорируются даже с `env_prefix`
  и `extra='forbid'`; лишний ключ в dotenv-файле при `extra='forbid'` — ошибка; неизвестный ключ внутри вложенной
  модели, чей префикс совпал, — тоже ошибка (как у нас опечатка внутри секции) —
  https://github.com/pydantic/pydantic-settings/blob/main/docs/index.md
- Grafana (`GF_<SECTION>_<KEY>`): до 12.x `applyEnvVariableOverrides` идёт по секциям и ключам ini-файла и для каждого
  спрашивает окружение; с 13.0 есть проход по `GF_*`, но переменная, не попавшая в известную секцию, пропускается
  молча; применённые переопределения пишутся в лог —
  https://github.com/grafana/grafana/blob/v12.3.0/pkg/setting/setting.go
- HashiCorp Vault: сервер читает `VAULT_*` поимённо, клиентские `VAULT_ADDR`, `VAULT_TOKEN` живут в том же префиксе;
  неизвестный ключ в файле — предупреждение — https://developer.hashicorp.com/vault/docs/configuration,
  https://github.com/hashicorp/vault/blob/main/internalshared/configutil/lint.go.
  Consul: неизвестный ключ в файле — ошибка загрузки, общего сбора `CONSUL_*` нет —
  https://github.com/hashicorp/consul/blob/main/agent/config/builder.go
- Rust: `config::Environment::with_prefix` собирает все переменные префикса без проверки —
  https://docs.rs/config/latest/config/struct.Environment.html; `figment::providers::Env` даёт явный отбор ключей
  (`only`, `ignore`, `filter`) — https://docs.rs/figment/latest/figment/providers/struct.Env.html
- GitLab Runner: каждая переменная привязана к своему ключу команды тегом `env:`, прочие не читаются —
  https://gitlab.com/gitlab-org/gitlab-runner/-/blob/main/common/config.go
- Twelve-Factor, III. Config: переменные окружения — независимые друг от друга точечные настройки —
  https://12factor.net/config
- Обратный пример — только по желанию: `envconfig.CheckDisallowed` возвращает ошибку на переменную префикса вне
  спецификации, но это отдельный вызов, не поведение по умолчанию —
  https://github.com/kelseyhightower/envconfig/blob/master/envconfig.go

Отличия по сути: отбор у нас — по первому ключу (секции), как в Grafana 13 и во вложенных моделях pydantic-settings;
внутри известной секции строгость сохраняется. Цена, которую признаёт и документация pydantic-settings: опечатка
в имени секции (`THEPOST_SMPT__…`) больше не даёт ошибки — переменная просто не применяется. Журнал применённых
переопределений (как у Grafana) — вне этой карточки.

## Приёмка
- Тест: `THEPOST_ADMIN_URL`, `THEPOST_ADMIN_TOKEN`, `THEPOST_ADMIN_ORG`, `THEPOST_TUI_THEME`, `THEPOST_CONFIG` при
  строгой проверке — ошибок нет, дерево не изменено; в мягком режиме нет предупреждений `unknown parameter`.
- Тест: `THEPOST_SMTP__LIMITS__MAX_SIZE` и скалярный `THEPOST_DOMAIN` применяются.
- Тест: `THEPOST_SMTP__LIMTS__MAX_SIZE` — `smtp.limts: unknown parameter` (ошибка строгого режима, предупреждение
  мягкого).
- Поставка: `deploy/compose/dev.yml` передаёт узлу `THEPOST_DOMAIN`, `THEPOST_DATABASE__URL`, `THEPOST_SMTP__HOSTNAME`,
  `THEPOST_SECRETS__*` — все начинаются с известного ключа; Helm и Ansible переменных `THEPOST_*` узлу не передают.
