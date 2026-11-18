# PLT-37: ACME — окно продления по доле срока сертификата

lane: platform
deps: []
class: A
files: [crates/tp-platform/src/acme.rs]
read: [docs/tasks/PLT-29.md (решение 100), docs/manual-tests/PLT-08.md, docs/spec/S6.md (п. 6.2)]
checks: [nextest]
manual: no

## Зачем
- `needs_renewal_at` сравнивает срок с фиксированным `renew_before` (по умолчанию 30 дней). Срок жизни публичных
  сертификатов сокращают по графику CA/Browser Forum (ballot SC-081v3, 2025): с 15.03.2026 — 200 дней,
  с 15.03.2027 — 100, с 15.03.2029 — 47; Let's Encrypt уже выпускает короткий профиль (6 дней).
  Фиксированное окно при коротком сроке — неверная пропорция: для 6-дневного сертификата продление «за 30 дней»
  наступает немедленно, узел перевыпускается на каждой проверке; для длинного — наоборот, редкий выход к серверу.
- Общее правило индустрии — продлевать, когда прошла ⅔ срока (запас — треть): certbot продлевает за 30 дней
  90-дневного сертификата (⅔), cert-manager по умолчанию — `renewBefore` = треть срока, Caddy — при ⅔ срока.

## Сделать
- `needs_renewal_at`: читать из сертификата и `notBefore` (сейчас парсится только `notAfter`); срок жизни
  `lifetime = not_after − not_before`; эффективное окно `min(renew_before, lifetime / 3)`.
- `renew_before` в конфиге остаётся «максимальным» окном (смысл секции не меняется); правило дроби — без настройки.
- Часы-цикл (`check_interval`, `retry_interval`, `order_timeout`) не меняются.

## Как делают другие
- Certbot: продление по умолчанию за 30 дней 90-дневного сертификата; с ARI — в подсказанном окне —
  https://certbot.eff.org/docs/using.html
- cert-manager: `renewBefore`, по умолчанию треть срока, минимум 5 минут —
  https://cert-manager.io/docs/usage/certificate/#renewal
- Caddy: продление при ⅔ срока — https://caddyserver.com/docs/automatic-https
- График сокращения срока: https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/
- Профиль коротких сертификатов Let's Encrypt (6 дней): https://letsencrypt.org/docs/profiles/

## Приёмка
- Тест: сертификат на 90 дней, `renew_before` 30 дней — продление за 30 (как сейчас, ⅔ > 30 − дробь не режет).
- Тест: сертификат на 47 дней — продление при остатке ≤ 15⅔ дня (⅔ срока прошли), не при 30.
- Тест: сертификат на 6 дней — продление при остатке ≤ 2 дня; до этого `needs_renewal_at` = false
  (сейчас — true на каждой проверке).
- Тест: сертификат без `notBefore` (разобрать не удалось) — работает по фиксированному `renew_before`, без паники.
