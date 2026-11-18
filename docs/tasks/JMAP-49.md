# JMAP-49: доступ к чужим ящикам почты в JMAP — делегированные Email/query и Email/get по ACL

lane: jmap
deps: [JMAP-32, CTR-82]
class: A
files: [crates/tp-jmap/src/*]
read: [docs/decisions/2026-11-11-stage2-followups.md#114, docs/tasks/JMAP-43.md, docs/CONTRACTS.md#queue]
checks: [nextest]
manual: no

## Сделать
- `Email/query`, `Email/queryChanges`, `Email/get` по чужому `accountId` от контекста представителя:
  права — единый слой авторизации (`AclAuthorizer`, группы — CTR-82), видимость — только папки,
  предоставленные общим доступом (модель JMAP-32).
- Сессия подключённого ящика — `isPersonal: false`; чужой `accountId` без права — `noAccess`
  (не раскрывает существование ящика).
- Отправка от чужого имени — существующий путь `Outbound::submit` с вошедшим пользователем (CTR-82),
  в этой карточке не трогается.
- Аудит: ветка `Search` из JMAP-43 (влита, недостижима) становится достижимой — запись `Search`
  в журнал аудита чужого ящика при фильтре `text`/`body` от представителя (решение 114).
  Приёмка этой ветки закрывает issue #46.

## Как делают другие
- Делегирование почты: Gmail delegation — поиск, чтение, отправка от имени
  (https://support.google.com/a/answer/7272719).
- Exchange delegate access / shared mailboxes — права на папки, аудит доступа делегата
  (https://learn.microsoft.com/en-us/exchange/recipients/mailbox-delegates).
- RFC 8621: модель `accountId` и общий доступ без нарушения своего ящика
  (https://www.rfc-editor.org/rfc/rfc8621#section-2.2).
- Отличие: права через общий ACL-слой с группами, аудит поиска — по решению 114 (у Exchange —
  журнал действий делегата в едином аудите).

## Приёмка
- Тест от контекста представителя: `Email/query` с `text` в чужом ящике пишет запись `Search` в журнал
  аудита ящика до выдачи (ветка JMAP-43 достижима — issue #46 закрывается).
- `Email/get` читает только папки по ACL; без права — `noAccess`; сессия — `isPersonal: false`.
