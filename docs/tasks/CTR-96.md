# CTR-96: конвейер обработки — реестр этапов, итоговый набор действий, итоговый контроль

lane: contracts
deps: []
class: B
files: [crates/tp-contracts/src/pipeline.rs, crates/tp-contracts/src/lib.rs, docs/CONTRACTS.md, crates/tp-testkit/*]
read: [docs/spec/S4.md (п. 4.9), docs/spec/S2.md (п. 2.5), docs/tasks/CTR-43.md, crates/tp-contracts/src/delivery.rs]
checks: [nextest]
manual: no

## Сделать
- `pipeline.rs`. `PipelinePoint` — точка конвейера: `MailFrom`, `RcptTo`, `Data`, `BeforeMailboxSieve`, `AfterMailboxSieve`, `FinalActionCheck`. Конвейер общий для приёма извне (smtp-in), отправки клиентом (submission, JMAP EmailSubmission) и доставки в ящик; выполняется ролью transport, edge передаёт сессию насквозь (SRS 2.6) — отказ синхронный в той же SMTP-сессии.
- `Stage { id, point, order }` + `StageRegistry::register(point, stage)`: этапы регистрируют модули через точку расширения (SRS 2.5); ядро регистрирует собственные этапы (проверки сессии, Milter, журналирование, Sieve ящика, итоговый контроль); модуль не удаляет и не переставляет этапы ядра. На `MailFrom`/`RcptTo` — условия по конверту, отказ отдельному получателю; на `Data` — условия по содержимому, отказ всему письму; входящая почта — до доставки в ящик, исходящая — до постановки в очередь.
- `ActionSet` — итоговый набор действий по письму и получателю: перенаправления (`redirect` из Sieve и правил), копии, итоговые адресаты. `FinalActionCheck` — этап после всех остальных: проверка `ActionSet` по `OrgPolicy`; в базовой поставке — `forbid_external_forward` (запрет перенаправления и пересылки на внешние адреса; перехватывает redirect из скрипта ящика; по умолчанию выключен) — задел под модуль «Правила потока почты» (SRS 4.10, `block_external_forward`).
- Служебные письма продукта (DSN, отбивки, уведомления) и копии журнала — `SystemMessage`: конвейер без этапов правил, петли исключены.
- Описание — раздел «Pipeline» в `docs/CONTRACTS.md`, строка CHANGELOG. `tp-testkit`: `suite::pipeline` — порядок этапов по точкам, этап ядра нельзя удалить или переставить, отказ на `RcptTo` относится к одному получателю, `SystemMessage` минует этапы правил.

## Как делают другие
- Exchange: transport agents (классификация — до правил,_AGENT-этапы вокруг), audit agent на этапе классификации — журнал до правил ящика (https://learn.microsoft.com/en-us/exchange/mail-flow/transport-agents).
- Milter: этапы на соединении/письме, отказ получателю (`xxrcpt`) и письму — как стадии SRS 4.9 (https://ftp.sendmail.org/milter/engine.api.html).
- Отличие: этапы регистрируются в фиксированных точках ядра (модуль не переставляет ядро) — у Exchange порядок агентов настраивается произвольно.

## Приёмка
- `suite::pipeline`: этапы в порядке точек; регистрация модульного этапа до/после Sieve; попытка удалить/переставить этап ядра — ошибка; `FinalActionCheck` видит redirect из скрипта ящика и применяет `forbid_external_forward`; `SystemMessage` не проходит этапы правил.
