# FIX-12 — stand.yml: адрес генератора в конфиге узла — ansible_host / факты / assert

Место: `deploy/stand/stand.yml` («Apply common stand parameters …»). Решение владельца — issue #22,
вариант 1 (2026-11-17).

## Что случилось

Адрес генератора подставляется в конфиг узла SMB выражением
`hostvars[generator].ansible_host | default(имя_узла)` — тем же классом бага, что FIX-11 (PR #21):
на docker-стенде без `ansible_host` у генератора в узел уходит имя вместо IP:
- `ratelimit.trusted` (vec CIDR, `crates/tp-platform/src/ratelimit.rs`) — имя не парсится, узел не
  стартует: падение громкое, но непонятное;
- `smtp.queue.relay` = «имя:2525» — узел может не зарезолвить relay, исходящая почта молча копится
  (тихая разновидность потери, как два потерянных прогона Д.7).

## Сделать (по образцу FIX-11 в роли stand_generator)

Адрес генератора: `ansible_host`, иначе IP из фактов генератора (`ansible_default_ipv4`),
иначе assert «задайте ansible_host генератора — IP» до применения конфига узла.

## Приёмка

- Инвентарь docker_api без `ansible_host` у генератора, факты недоступны → плейбук падает на шаге
  параметров с внятной ошибкой; конфиг узла не применяется.
- `ansible_host: <IP>` (или факты собраны) → в конфиге узла `ratelimit.trusted` — CIDR, `smtp.queue.relay` —
  «<IP>:2525»; узел стартует, исходящая почта уходит на генератор.
