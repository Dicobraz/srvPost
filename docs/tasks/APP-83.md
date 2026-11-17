# APP-83: конфигурация journal — секция config.yaml, пресеты профилей, JSON Schema

lane: app
deps: [CTR-97]
class: A
files: [crates/thepost/src/sections.rs, deploy/config/all.yaml, deploy/config/mailbox.yaml]
read: [docs/spec/S5.md (п. 5.5), docs/spec/S4.md (п. 4.9), docs/tasks/BLOB-18.md, crates/thepost/src/sections.rs]
checks: [nextest]
manual: no

## Сделать
- Секция `journal` приложения в реестре секций (SRS 5.5): `enabled` (по умолчанию false — журналирование включается явно), хранилище записей (`s3` с бакетом/режимом Object Lock и сроком по умолчанию, или `local` каталог для SMB), настройки выгрузки во внешний архив (адрес, формат .eml, повтор при сбое). Подсекции крейтов — как есть (по образцу `blob.local`/`blob.s3`).
- Пресеты: `deploy/config/all.yaml` (Enterprise) — S3 с Object Lock, режим governance по умолчанию (compliance — явно, риск 21); `deploy/config/mailbox.yaml` (SMB) — локальный каталог, предупреждение doctor (APP-82).
- JSON Schema секции и значения по умолчанию — в общем конструкторе конфигурации (`thepost config check` валидирует: режим compliance только с явным сроком; бакет отдельный от BLOB ящиков).
- Правила журналирования — НЕ в config.yaml (данные организации через Admin API); в конфиге только параметры узла/инсталляции.

## Как делают другие
- Exchange: JournalRule — данные организации (командлетами), не файл сервера — та же граница «конфиг узла / данные организации».

## Приёмка
- `thepost config check` принимает валидные пресеты и отвергает: journal.s3 с бакетом BLOB ящиков, compliance без срока, неизвестный режим; тесты секций как у прочих.
