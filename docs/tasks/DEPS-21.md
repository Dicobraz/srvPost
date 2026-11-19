# DEPS-21: фича `time` у `instant-acme` — подсказка окна продления (ARI)

lane: deps
deps: [PLT-39]
class: B
files: [Cargo.toml, Cargo.lock]
read: [docs/tasks/PLT-39.md]
checks: [nextest]
manual: no

PLT-39 (окно продления от сервера, ARI RFC 9773): `Account::renewal_info`, `RenewalInfo`, `SuggestedWindow`
крейта `instant-acme` собраны за фичей `time` (окно — `time::OffsetDateTime`).

## Сделать
- Фича `time` у workspace-зависимости `instant-acme` (0.8.5); новых внешних пакетов нет — `time` 0.3 уже в
  дереве (через другие зависимости), в lock у `instant-acme` появляется запись `time`.

## Приёмка
- `cargo deny check` без новых записей; CI зелёный.
