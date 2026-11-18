# PLT-39: ACME — окно продления от сервера (ARI, RFC 9773)

lane: platform
deps: [PLT-37]
class: A
files: [crates/tp-platform/src/acme.rs]
read: [docs/tasks/PLT-37.md, docs/tasks/PLT-29.md]
checks: [nextest]
manual: no

## Зачем
- Свой календарь продления (PLT-37) не знает планов сервера: массовый отзыв (как в 2021-м у Let's Encrypt),
  перевод сертификата в досрочный отзыв — сервер ждёт перевыпуска раньше срока, клиент об этом не догадывается.
- ARI (ACME Renewal Information, RFC 9773): сервер публикует для выпущенного сертификата подсказанное окно
  продления (`RenewalInfo.suggestedWindow`), в том числе «уже сейчас» — для заменяемых сертификатов.
  Крейт `instant-acme` 0.8 умеет: `CertificateIdentifier` (серийный номер + идентификатор ключа уполномоченного
  CA из цепочки), `RenewalInfo`, `SuggestedWindow` — https://docs.rs/instant-acme/0.8.5/instant_acme/

## Сделать
- После выпуска запоминать `CertificateIdentifier` выпущенной цепочки (разбор DER уже есть — `cert_not_after`).
- Перед решением о продлении: сервер каталога отдаёт `renewalInfo` (отдельный GET, поддержка видна в directory) —
  окно есть: продлевать, когда `now` внутри `[start, end)`; окна нет или запрос не удался — правило PLT-37
  (⅔ срока), ошибка ARI — предупреждение в журнал, не отказ продления. Сервер без ARI в directory — как сейчас.
- Выпуск не удался внутри окна — повтор по `retry_interval` до конца окна; за окном — снова свой календарь.
- Вне карточки: DNS-01 (wildcard), External Account Binding — по мере запроса, не заранее.

## Как делают другие
- Спецификация ARI и рекомендация «без окна — продлевать на случайной точке до ⅔ срока» — https://www.rfc-editor.org/info/rfc9773
- Let's Encrypt о публикации RFC: https://letsencrypt.org/2025/09/16/ari-rfc/
- Certbot: ARI учитывается в расписании продления — https://certbot.eff.org/docs/using.html
- Ansible community.crypto: модуль `acme_ari_info` —
  https://docs.ansible.com/ansible/latest/collections/community/crypto/acme_ari_info_module.html
- acme.sh: трекинг поддержки — https://github.com/acmesh-official/acme.sh/issues/4944

## Приёмка
- Тест (мок каталога): сервер отдаёт окно в будущем — продления нет, хотя до конца срока меньше `renew_before`.
- Тест: окно содержит `now` — выпуск; окно миновало без выпуска — возвращение к календарю PLT-37.
- Тест: сервер отдаёт «заменяющее» окно (сертификат отмечен к замене) — ранний перевыпуск действующего сертификата.
- Тест: endpoint ARI отвечает ошибкой/его нет в directory — продление по своему календарю, `warn` в журнал.
