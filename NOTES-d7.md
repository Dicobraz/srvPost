# Д.7 — диагностика на ноутбуке владельца (Docker, SSD), ветка w/laptop-d7

**Статус: диагностика, НЕ официальная приёмка.** Эталон — podium-dev (DEP-13, прогон 2026-11-20, beta.5).
Цель: A/B-проверка гипотезы «порог SMTP взят fsync WAL на совмещённом диске эталона».
(A) весь стек на SSD одним томом; (B) pg_wal на отдельном docker-томе (симлинк).
Машина: ноутбук владельца, Windows + Docker Desktop 29.9.3 (WSL2-бэкенд), C: — SSD.
Guard по диску: < 3 ГБ свободно на C: — СТОП. Фоновые агенты на машине — замеры с пометкой «фон».

## Чекпоинт 0 — подготовка (2026-11-20)
- Релиз `v0.2.1-beta.5` скачан из gh release: `thepost-v0.2.1-beta.5-x86_64-unknown-linux-gnu.tar.gz`
  (29 МБ) + sha256 OK. Консоль отдельно, стендом не ставится — не нужна.
- Стек повторяет механику dev.yml (профиль smb) + роль stand: postgres:16 (TLS, SCRAM), OpenBao 2.7.2
  (TLS, Raft), tls-init (CA SAN: localhost, thepost, mail.stand.test, postgres, openbao), app-role.sh
  (thepost_owner/thepost/thepost_readonly), узел — релизный бинарник в образе на базе python-slim
  (libgssapi-krb5 для gssapi-фичи), генератор — python-slim + postfix (smtp-source) + swaks;
  k6 — образ grafana/k6:1.0.0; imaptest — образ dovecot/imaptest (как stand_imaptest_image).
- Протокол Д.7 (DEP-13, 2026-11-20): users=50, 200 IDLE (hold 40 с), 3 × 5 мин, зонды раз в 1 с
  (probes.py, probe.js), нагрузка ×1 по модели Д.3 (вход 120/сут, исход 30/сут, поиск 10/сут,
  флаги 200/сут, imaptest clients=30, push 15), наполнение Д.12 (50 × 100 писем + big 10 000).
- Числа эталона для сравнения (beta.5, умолчания 5 мс/64): SMTP 250 p95 **1.76 с** (n=275), COMMIT
  p50 456–548 мс, хвост 3.3–5.3 с, WALWrite до 2.5 с, FOR UPDATE max **3.06 с**, JMAP query/get
  530/394 мс, SELECT 153 мс, доставка 1.67 с, индексация 18.0 с. Отказы/потери 0.
- Отличия от эталона (документирую честно): Postgres в контейнере с настройками по умолчанию
  (у эталона — systemd с дефолтами кластера Debian), Rspamd-milter не подключён (как dev.yml smb —
  узел без milter), WAL/блобы на одной физической SSD в обоих прогонах (B измеряет разделение
  томов/ФС, не физические устройства).

## Прогон A — SSD одним томом
(выполняется; ниже — подготовка и дымовой прогон)

### Подготовка прогонов (чекпоинт 2, 2026-11-20 ~09:20–10:45 UTC)
- Конфигурация узла с доверием генератору — `deploy/compose/d7/config-d7.yaml` (копия пресета all +
  `ratelimit.trusted: ["172.16.0.0/12"]`, `smtp.screen.exempt` — то же) и `smtp.queue.relay: "d7sink:2525"`
  (smtp-sink — контейнер d7gen с postfix'овским `smtp-sink`, файл письма — в томе d7stand `sink/`, счёт — сверке).
  Без этого SMTP-экран (умолчания: max_rate 60/мин на адрес) и ratelimit.ip (burst 60) блокируют генератор
  (200 IDLE + зонды раз в 1 с идут с одного адреса) — повтор DEP-13 2026-11-18 (421×267).
- Генератор: образ `d7gen:local` (python:3.12-slim + postfix (smtp-source) + swaks + curl + k6 v1.0.0 из
  образа grafana/k6 + docker CLI из docker:cli; обёртка `podman → docker` для imaptest (образ
  dovecot/imaptest:latest) — run-scenario.sh запускает его через сокет Docker, `--network host` переписывается
  в сеть compose `thepost_default`; том d7stand смонтирован по пути демона — пути -v совпадают).
  `stand.env` — `deploy/compose/d7/stand.env`: SMB_HOST=thepost, DOMAIN=example.test, USERS=50, 200 IDLE × 40 с,
  PROBE_INTERVAL=1, TAIL_MAX=300, профиль **speed** (рабочие пороги Д.7 — как в отчёте эталона beta.5;
  profile=thresholds — это пороги Д.5, строки скорости «справочно», для сравнения с beta.5 нужен speed).
- Provision ВНУТРИ узла (rootfs read-only → скрипт через `docker exec -i bash -s`, аргументы как в provision.yml):
  `provision-accounts.sh /tmp/d7state example.test user 50 probe1 probe2 probe3 big bruteforce` →
  **created=55 existing=0 issued=55 skipped=0 total=55**; accounts + ca.pem — в том d7stand (`etc/`).
- Наполнение Д.12: `make-corpus.py` (200 × 75 KB, вложения 20 % × 500 KB, дубли 30 % → 89 МБ), `fill.py`
  50 × 100 + big 10 000 → **planned=15000 delivered=15000 failed=0 retries=0 in 385s**, видимость ok (выборка 20
  ящиков + big 10 000); календари/контакты — `fill-dav.py` (Д.21): 15 000 событий + 5 000 карточек,
  **failed=0**, видимость ok. Состояние — fill-state.json / fill-dav-state.json в томе.
- Срезы узла: smb-sampler.py (из stand_generator/files) — в контейнере узла (`/tmp`), пишет раз в 5 с
  в том (метрики tp_db_pool_* у beta.5 есть: pool_max=33; tp_db_commit_*/notify/listeners в /metrics
  **нет** — строки 6/7/17 Д.7 будут «не измерялось», как и часть эталона). COMMIT-латентность — журнал
  PostgreSQL (`log_min_duration_statement=100ms`, `log_lock_waits=on` — ALTER SYSTEM + reload) + сэмплер
  pg_stat_activity с хоста раз в 1 с (активные операторы дольше 50 мс).
- Грабли (решены): (1) MSYS Git Bash переделывает аргументы `/stand/...` в Windows-пути — все docker-вызовы
  обёрнуты `MSYS_NO_PATHCONV=1`; (2) run-scenario.sh требует `/etc/thepost-stand/stand.env` — биндится из тома
  (путь демона); (3) `-I` у python3 убирает каталог скрипта из sys.path — fill-dav.py импортирует fill.py,
  запускать без `-I`; (4) Docker Desktop VM перезапустилась в 10:07 (все контейнеры Exited 255 разом) —
  стек поднят заново (тома целы), настройки PG сохранились.

### Дымовой прогон d7a1-0953 (конвейер проверен целиком; обрыв VM на финальной сверке)
Нагрузка 300 с прошла полностью: 200 IDLE × 40 с (IMAP + push), imaptest clients=30, k6 push 15 + dav.js,
зонды раз в 1 с, сверка: **принято 639 = ящики 568 + sink 71, потеряно 0**; DAV-зонды 6/0. Зонды (весь прогон,
без срезов узла — они погибли с VM): JMAP query/get p95 **146/340 мс**, SELECT 10k p95 **25 мс**, SMTP 250
p95 **3.01 с** (n=259), доставка p95 3.61 с (n=50, отказов 2), сигнал IMAP/push p99 377/668 мс (отказов 9/2),
FTS p95 352 мс, индексация p95 9.43 с (не найдено 1). Официальным прогоном A не считается (нет срезов узла
и criteria на момент обрыва); подготовка по нему доведена — см. прогоны A ниже.

**Журнал PostgreSQL дымового прогона** (срез docker logs с начала прогона; ALTER SYSTEM
log_min_duration_statement=100ms / log_lock_waits=on; файл — d7/work/pglog-d7a1-0953.log, локально):
- **COMMIT > 100 мс: 597** (эталон beta.5: 724), **p50 262 мс** (эталон 456–548), p95 522 мс, **max 2.12 с**
  (эталон — хвост 3.3–5.3 с). Распределение двугорбое: 565 из 597 — < 500 мс, 28 — 0.5–1 с, 4 — 1.5–2.5 с.
- **FOR UPDATE-стоек нет**: ни одного оператора `FOR UPDATE` > 100 мс и ни одной строки log_lock_waits
  (эталон: 21 оператор, max 3.06 с) — цена фиксации ниже, писатель держит строку ящика меньше.
- Сэмплер pg_stat_activity (частичный, ~последние 85 с нагрузки, 17 срезов): COMMIT в IO/WALSync
  (89–719 мс), COMMIT и INSERT в LWLock/WALWrite (~0.15–0.3 с) — ожидания WAL видны, до 1 с
  (эталон: WALWrite до 2.5 с); UPDATE leases с WALSync 719 мс.
- Прочее > 100 мс: 4×SELECT сообщений (max 2.7 с), 2×INSERT event_partitions (~0.3 с) — как на эталоне
  (log_lock_waits эталона: очереди на event_partitions).

## Остановка по guard — прогоны A/B не состоялись (2026-11-20 ~11:35 UTC)
- Диск C:: в 11:35 — **2.4 ГБ свободно** — ниже guard 3 ГБ → замеры остановлены (правило чекпоинта 0).
  Серия за день: 3.9 ГБ (утро) → 8.0 → 3.8 → 3.5 → **25 ГБ** (чужая сессия освободила target-каталоги) →
  2.4 ГБ — колебания целиком на стороне параллельной сессии компиляции, не диагностикой (стек занимает
  ~0.6 ГБ в томах).
- Docker Desktop падал дважды: 10:07:24 (все контейнеры Exited 255 разом — VM перезапустилась; стек поднят
  заново, тома целы) и ~11:05–11:35 («Docker Desktop is unable to start», не восстановился за 10 мин
  наблюдения). На ноутбуке параллельно идёт чужая локальная компиляция (cargo) — фон во время замеров.
- Состояние на момент остановки: контейнеры exited (Docker Desktop не работает); тома и данные целы
  (pgdata-tls c наполнением A, tpdata, d7stand с отчётами и корпусом). Подъём после возврата Docker Desktop:
  `THEPOST_IMAGE=thepost:beta5 docker compose -f deploy/compose/dev.yml -f deploy/compose/d7/dev-d7-node.yml --profile smb up -d`
  и `docker start d7sink`; прогоны — `d7/work/run-one.sh <RUN_ID>` (WORK=.../d7/work), pg_wal-том B —
  `deploy/compose/d7/dev-d7-b.yml` по NOTES выше. Прогон B перед запуском: новый pgdata (fill заново —
  протокол эталона), wipe tpdata + chown 65532, свежий provision (файл accounts в d7stand/etc заменить).
- Промежуточный вывод по гипотезе (один дымовой прогон, НЕ доказательство): COMMIT p50 на ноутбуке
  вдвое ниже эталона (262 против 456–548 мс), хвост 2.1 с против 3.3–5.3 с, FOR UPDATE-стоек нет —
  согласуется с «порог на эталоне берут дисковые фиксации», но A/B-разделение WAL не выполнено,
  а SMTP p95 приёма на ноутбуке хуже эталона (3.01 с против 1.76 с) при n=259 — среда шумнее
  (фон компиляции, контейнерный PG с умолчаниями, ноутбук против 4 vCPU ВМ). Вывод о переносе
  pg_wal (прогон B) не сделан.

## Прогон B — pg_wal на отдельном томе
**Не состоялся.** Инфраструктура подготовлена (`deploy/compose/d7/dev-d7-b.yml` + `wal-entrypoint.sh`:
новый том pgdata-b, том pgwal-b, initdb с `--waldir`, пересоздаётся только postgres-tls; роли на новом томе —
app-role с паролями из OpenBao KV: `db_secret` не переписывает существующие, pg-bootstrap-файлы применены и
удалены — брать `bao kv get -mount=thepost db` и передавать в TP_DB_PASSWORD/…). Запускам препятствовали
падение Docker Desktop и диск ниже guard (ниже).

## Чекпоинт 1 — стек поднят вручную (2026-11-20 ~09:00 UTC)
- Образ узла: `thepost:beta5` из бинарника релиза v0.2.1-beta.5 (python:3.12-slim-bookworm + libgssapi-krb5-2,
  USER 65532, ENTRYPOINT thepost, CMD serve) — в /tmp/d7-inbox/Dockerfile.node (вне репо).
- Стек: `THEPOST_IMAGE=thepost:beta5 docker compose -f deploy/compose/dev.yml --profile smb up -d`
  в worktree — TLS, OpenBao (Raft+AppRole), PostgreSQL 16 (SCRAM, учётки thepost_owner/thepost/thepost_readonly),
  Rspamd 3.11.1, узел — все роли стартовали (smtp-in/submission/smtp-out/imap/jmap/dav/admin/search/indexer/
  maintenance), HTTPS 443 отвечает.
- Грабли решённые: (1) CMD serve; (2) том thepost_tpdata создался от root — chown 65532:65532.
- Provision: запускать provision-accounts.sh ВНУТРИ контейнера узла (docker cp + docker exec; admin по локальному
  сокету, admin init/login/account create/app-password), состояние в /tmp узла, accounts file — docker cp наружу.
  Аргументы по provision.yml: <state> example.test user 50 probe1 probe2 probe3 big bruteforce (дефолты stand).
- Диск: 4.6 ГБ свободно (100%), идёт ЧУЖАЯ локальная компиляция (cargo ×2, nextest — параллельная сессия волн;
  кэши cargo-target в корне workspace ОТСУТСТВУЮТ). Не удалять чужие target-каталоги. Guard < 3 ГБ.
- Прогон A/B ещё не выполнялся. Генератор: собрать по stand_generator/files (run-scenario.sh требует
  /etc/thepost-stand/stand.env, smtp-source (postfix), swaks, imaptest, k6; образ grafana/k6:1.0.0 уже в docker).
