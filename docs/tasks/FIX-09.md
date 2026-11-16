# FIX-09: systemd-юнит openbao не переживает нечистую остановку: drop-in в роли

lane: deploy
deps: []
class: A
files: [deploy/ansible/roles/openbao/**]
read: [docs/manual-tests/DEP-44.md]
checks: [none]
manual: DEP-44

**Срочно** — ошибка на живом узле (бета `beta-20261114.4`, стенд school-99, issue #4), этап 2. После жёсткого
рестарта контейнера/ВМ узел не поднимается без ручного вмешательства.

Дистрибутивный `/usr/lib/systemd/system/openbao.service`: `KillMode=process` — при остановке остаётся процесс `bao`,
он держит flock bolt-файла raft; каждый старт падает `failed to open bolt file: timeout`, после `StartLimitBurst=3`
за 60 с юнит уходит в `failed` → `thepost` (ждёт secret store) не стартует. Дополнительно `Type=notify` +
`TimeoutStartSec=90s`: под нагрузкой systemd объявляет старт таймаутом, хотя процесс становится готов.
Восстановление ручное: `kill -9 <leftover>; systemctl reset-failed openbao; systemctl start openbao`.

## Сделать
- Роль `openbao`: drop-in `/etc/systemd/system/openbao.service.d/override.conf` — `KillMode=control-group`,
  `TimeoutStartSec=5min`, `StartLimitIntervalSec=0`.
- Проверка роли: остановка юнита не оставляет процессов в контрольной группе (`systemd-cgls`).

## Приёмка
- На стенде (контейнер узла с systemd): жёсткий рестарт контейнера (`docker restart <узел>`) → узел поднимается
  сам, без ручных `kill`/`reset-failed`; `systemctl is-active thepost` — `active`.
