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
(пока не выполнен)

## Прогон B — pg_wal на отдельном томе
(пока не выполнен)

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
