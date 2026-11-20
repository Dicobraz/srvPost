# FIX-19 — doctor: плоский путь зонда blob (root-прогон не оставляет каталог root:root)

Место: `probe_blob` (`crates/thepost/src/doctor.rs`), `LocalStore` (`crates/tp-blob/src/local.rs`).
Найдено на стенде beta.2 (test-post, 10.70.2.48), issue #195.

## Что случилось

`thepost doctor` от root пишет пробный объект в `doctor/probe-…`; `LocalStore` создаёт каталог
`doctor/` от root и при удалении объекта удаляет только файл — каталог остаётся root:root.
Следующий прогон от `thepost` (как рекомендует ADMIN-GUIDE) падает на `blob.write`:
`Permission denied`. Каталог сам не восстановится.

## Сделать

- Путь зонда — плоский, без подкаталога: `probe-doctor-<pid>-<nanos>` (каталог вообще не создаётся).
- Существующие стенды лечится одноразово: `rm -rf /var/lib/thepost/blob/doctor` от root.

## Приёмка

- Тест `blob_probe_ok_and_failures` — путь зонда без `/`; прогон doctor от root на стенде не
  оставляет новых каталогов в BLOB.
