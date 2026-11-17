# PERF-06 — подключить CachedMessages (list_cache) в узел: IMAP и JMAP

Место: `crates/thepost/src/` (`Services::imap`, `Services::jmap`) + конфиг эталона. Ядро готово:
mailstore-16 (PR #51, `crates/tp-mailstore/src/list_cache.rs`) и jmap-32 (PR #50). Без подключения
эффекта на стенде нет — Д.7 №2 (SELECT 10k) продолжает идти по `list(All)`.

## Сделать

- Обернуть `MessageStore`, который получают IMAP- и JMAP-сервисы, в `CachedMessages`, когда
  `mailstore.list_cache` включён (конфиг из PR #51; в эталоне SMB — включить, max_bytes ≥ 64 МБ).
- Один общий кэш на процессы IMAP и JMAP (тот же MessageStore в Services) — иначе двойная память.
- Телеметрия: stats() кэша в /metrics (hits/misses/entries/bytes) — чтобы прогон Д.7 показывал работу.

## Приёмка

- Прогон Д.7 (эталон Д.2 или podium): №2 SELECT 10k p95 < 100 мс на повторных SELECT; №1 JMAP query
  p95 < 200 мс;(stats кэша видны); при приёме/удалении писем во время прогона — клиенты видят
  изменения (прозрачность кэша).
