# FIX-21 — doctor: проверки privileges_* по процессу службы, а не CLI

Место: `tp_platform::privileges::doctor` (`crates/tp-platform/src/privileges.rs`). Найдено на
стенде beta.2 (test-post, 10.70.2.48), issue #197.

## Что случилось

`doctor()` читает `/proc/self/status` — состояние собственного процесса CLI. Юнит при этом имеет
`NoNewPrivileges=yes` и пустой `CapabilityBoundingSet`, но doctor этого не видит: прогон от
`thepost` даёт `NoNewPrivs: 0` и требует «включите NoNewPrivileges=yes в службе» — ложный сигнал.

## Сделать

- Если служба запущена — `/proc/<MainPID>/status` процесса `thepost.service` (pid через
  `systemctl show thepost -p MainPID --value`), с пометкой «процесс службы (pid N)».
- Служба не найдена — прежнее поведение (свой процесс), но в сообщении прямо: проверен процесс
  doctor, состояние службы — `systemctl show thepost`.
- Сигнатура `doctor_with` не меняется: выбор источника и пометка — в `doctor()`.

## Приёмка

- На узле с работающей службой doctor показывает NoNewPrivs/seccomp процесса службы;
  на машине без systemd — прежние значения с пометкой в сообщении.
