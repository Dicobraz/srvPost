# FIX-11 — генератор стенда: молча нерабочая запись /etc/hosts (имя вместо адреса)

Место: `deploy/stand/roles/stand_generator/tasks/main.yml` («Resolve SMB host name on generator»), дефолт
`stand_smb_address` в `defaults/main.yml`.

## Что случилось (стенд Д.7, 16–17.11)

Инвентарь стенда с `ansible_connection: community.docker.docker_api` без `ansible_host` → дефолт
`stand_smb_address: hostvars[...].ansible_host | default(stand_smb_host)` подставил ИМЯ узла инвентаря
(`thepost-d7-smb`) вместо адреса. Задача lineinfile записала в `/etc/hosts` генератора строку без IP:
`thepost-d7-smb mail.stand.test`. `getaddrinfo` такую строку игнорирует, имя уходит в docker-DNS (127.0.0.11),
тот — наружу; запрос висит десятки секунд. fill.py на каждый SMTP-коннект тратил ~40 c в `getaddrinfo`
(блокирующий вызов, таймауты smtplib не действуют) — 15 000 писем «ползли» бы ~60 часов; два прогона Д.7
потеряны (16.11 списали на rustc-сборки, 17.11 вскрыли).

## Сделать

- Роль падает сразу (assert до записи в `/etc/hosts`), если `stand_smb_address` — не IP-адрес и не
  резолвится с генератора: внятная ошибка «задайте ansible_host узла SMB в инвентаре», а не молчаливая
  мусорная строка.
- (На выбор агента) надёжнее: для docker_api выводить адрес контейнера автоматически
  (`docker inspect` / `hostvars[...].ansible_default_ipv4`), дефолт-имя оставить только как последний
  резерв с предупреждением.

## Приёмка

- Инвентарь docker_api без `ansible_host` и без резолва имени → роль падает на шаге генератора с ошибкой
  про адрес узла; `/etc/hosts` не тронут.
- Инвентарь с `ansible_host: <IP>` → запись `<IP> mail.stand.test`, `getent hosts mail.stand.test` на
  генераторе отвечает IP; fill.py стартует без задержек DNS (первый коннект < 1 c).
