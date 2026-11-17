# FIX-15 — чистый деплой стенда: условие сбора фактов FIX-12 падает; каталог drop-in openbao не создаётся

Место: `deploy/stand/stand.yml` (FIX-12), `deploy/ansible/roles/openbao/tasks/main.yml` (FIX-09).
Найдено развёртыванием чистого перф-стенда на podium-dev (17.11, релиз v0.2.1-beta.1, без сборок).

## Что случилось (свежий хост, docker-инвентарь)

1. **FIX-12 «Gather generator facts»**: условие `hostvars[inventory_hostname].ansible_host is not match(...)`
   падает — `object of type 'HostVarsVars' has no attribute 'ansible_host'` (ansible при отсутствии
   атрибута кидает ошибку, а не False). Из-за этого факты генератора не собираются, адрес пустеет и
   (корректно) роняет плейбук assert — чистый стенд не разворачивается вовсе.
2. **FIX-09 drop-in**: `/etc/systemd/system/openbao.service.d` не существует — задача template падает
   «Destination directory does not exist». На стендах 16–17.11 каталог существовал (ставился руками);
   чистый деплой — нет. Тот же фикс, что в отклонённом fixup к PR #9.

## Сделать

- `stand.yml`: убрать условие по `hostvars[...].ansible_host` из «Gather generator facts» (факты
  docker-генератора собираются всегда — это дёшево; выбор ansible_host-IP/фактов остаётся в set_fact).
- `deploy/ansible/roles/openbao/tasks/main.yml`: задача `file: state=directory` для
  `/etc/systemd/system/{{ openbao_service }}.service.d` перед drop-in.

## Приёмка

- Чистый docker-стенд (podium): `--tags install,provision` проходит без ручных mkdir и правок роли.
