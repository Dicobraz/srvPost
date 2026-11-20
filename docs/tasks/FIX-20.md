# FIX-20 — internal-сертификат узла: loopback SAN (admin login к 127.0.0.1 проходит проверку имени)

Место: `deploy/ansible/roles/thepost/tasks/tls-internal.yml`. Найдено на стенде beta.2
(test-post, 10.70.2.48), issue #196.

## Что случилось

HTTP-сертификат internal-режима выписывается только по доменам `thepost_tls_names`; loopback-имён
нет, поэтому `thepost admin login --ca-file … https://127.0.0.1:8443` падает по hostname
verification (работает только `--insecure`). Доки сами советуют этот вызов (ADMIN-GUIDE «Управление
узлом», INSTALL «tui»), а в compose/dev и у `thepost_pki_internal_names` (PG/OpenBao) SAN
`127.0.0.1` есть — непоследовательность только в выписке клиентского сертификата.

## Сделать

- В `tls-internal.yml` дополнить `thepost_pki_issue_names` санами `DNS:localhost`,
  `IP:127.0.0.1`, `IP:::1` (как у внутренних каналов). ACME-стенды не затронуты (доступ по имени).

## Приёмка

- Прогон роли на стенде: `thepost admin login/tui` к `https://127.0.0.1:8443` с `--ca-file`
  проходит без `--insecure`; SAN сертификата видны `openssl x509 -text`.
