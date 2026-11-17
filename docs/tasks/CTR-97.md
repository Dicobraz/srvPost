# CTR-97: журналирование — контракт записей, правил и хранилища журнала

lane: contracts
deps: [CTR-96]
class: B
files: [crates/tp-contracts/src/journal.rs, crates/tp-contracts/src/lib.rs, docs/CONTRACTS.md, crates/tp-testkit/*]
read: [docs/spec/S4.md (п. 4.9), docs/spec/S5.md (п. 5.2), docs/tasks/CTR-96.md, crates/tp-contracts/src/audit.rs]
checks: [nextest]
manual: no

## Сделать
- `journal.rs`. `JournalRule { scope: Org | Group | Mailbox, target, direction: In | Out | Both, enabled }` — правило журналирования задаётся на организацию, группу или ящик; выполняется этапом ядра до Sieve ящика и этапов модулей — скрипт ящика (`discard`, `stop`) и правила модулей его не отменяют.
- `JournalRecord`: письмо целиком + конверт — отправитель, все получатели (включая скрытых и раскрытых из групп), `Message-ID`, время, правило; одна запись на письмо. Копия в журнал — `SystemMessage` (CTR-96): без этапов правил.
- `JournalStore`: `append(rule, record, message) -> JournalId`; `search(JournalQuery)` — отправитель, получатель, Message-ID, интервал, правило; `export(id) -> eml с конвертом`; `verify_chain() -> ChainReport`; `restore_index()` — индекс восстанавливается из хранилища записей. Записи индекса связаны цепочкой хешей: `hash = H(prev_hash ‖ canonical(record))` — целостность проверяют thepost doctor и Admin API (SRS 4.9).
- Хранилище записей — отдельное от BLOB ящиков (SRS 4.9: дедупликация внутри журнала, блокировка не затрагивает хранилище ящиков); контракт не знает бэкенд — реализация `JournalStore` в полосе blob (BLOB-18), индекс — META-88.
- Доступ — только роль «аудитор журнала» (SRS 5.2): контракт `JournalAudit` capability; пользователи и администратор правил журнал не видят, через IMAP и JMAP не доступен.
- Описание — раздел «Journal» в `docs/CONTRACTS.md`, строка CHANGELOG. `tp-testkit`: `MemJournal` + `suite::journal`.

## Как делают другие
- Exchange Journaling: правило на организацию/группу/ящик, направление, одна запись на письмо с конвертом включая BCC (https://learn.microsoft.com/en-us/exchange/security-and-compliance/journaling/journaling).
- Exchange Journal report (envelope) — формат выгрузки .eml с конвертом.
- Отличие: индекс с хеш-цепочкой (доказательная целостность) и восстановление индекса из неизменяемого хранилища записей — у Exchange такого нет.

## Приёмка
- `suite::journal`: запись содержит скрытых и раскрытых из групп получателей; `discard` в скрипте ящика не отменяет запись; поиск по всем полям запроса; `export` возвращает .eml с конвертом; `verify_chain` ловит подмену записи; `restore_index` восстанавливает индекс из записей; копия журнала повторно не журналируется.
