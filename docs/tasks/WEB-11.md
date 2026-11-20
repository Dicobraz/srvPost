# WEB-11. Deploy: web/dist в образе, webmail-check образом, архив выпуска

**Класс:** B · **Волна:** `mod-webmail-11` · **Ждёт:** `mod-webmail-1` (WEB-01, PR #258)

Хвост WEB-01, не влезший в полосу mod-webmail (правки полосы deploy/ci — межполосный PR):

1. **Образ:** `deploy/docker/Dockerfile` собирает `web/dist` (stage с Node) и кладёт в
   бинарь с фичей `webmail` — образ соответствует бинарю (сейчас web/dist собирается
   только в CI-джобе, образ его не содержит).
2. **webmail-check образом** — полный аналог console-check: собранный образ отвечает
   `GET /mail/`, deep-link отдаёт SPA, 307 с `/mail`, CSP-заголовки, hashed-ассет.
   Подключить в beta build рядом с console-check.
3. **Архив выпуска `web/dist`** — по образцу архива консоли (CI-10): tarball в release
   с версией, reproducibility-проверка, подпись, запись в манифест выпуска.
4. Примеры конфига/доки развёртывания: `modules.webmail.enabled` (по умолчанию
   выключен — отличие от консоли осознанное, модуль = opt-in по SRS 1.3).

## Приёмка

- `docker build` собирает образ с webmail; контейнер отвечает `GET /mail/` (webmail-check).
- Release-артефакты содержат архив `web/dist`; повторная сборка — побайтово (repro).
- Бинарник без фичи `webmail` и образ без web/dist не регрессируют.
