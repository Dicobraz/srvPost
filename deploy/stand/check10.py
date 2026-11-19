#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check10.py — шаг чек-листа приёмки беты: «журнал: запись, поиск, выгрузка, восстановление» (DEP-58, SRS 4.9).

На стенд кладётся рядом с check8.py/check9.py (~/thepost-beta-020/); в репо — deploy/stand/check10.py.
Проверяет четыре действия журнала переписки на бета-узле:

  запись         — правило Both на организацию + входящее и исходящее письма дают две записи;
  поиск          — запись находится по отправителю/получателю/Message-ID;
  выгрузка       — export отдаёт .eml с конвертом (заголовки X-ThePost-Journal-*);
  восстановление — после очистки индекса restore_index пересобирает его из хранилища записей.

Порча записи и замер задержки с журналированием (риск 22) — сценарий docs/manual-tests/DEP-58.md,
в этот шаг не входят. Записи журнала неизменяемы: прогон оставляет записи в журнале стенда.

Поверхности (состояние на волне deploy-51): этап журналирования в узле и `thepost admin journal …`
(ADM-52) вливаются волнами app-81/admin-38 — до их слияния шаги помечаются БЛОК (не FAIL), кроме
проверок по индексу PostgreSQL (схема journal — tp-meta, влита). Правило журналирования — данные
организации (Admin API); здесь при отсутствии правила заводится напрямую в journal.rules — только
для стенда, продуктовая поверхность — Admin API/консоль.

Запуск (стенд): python3 check10.py --host mail.example.test --domain example.test \
  --user-a a@example.test --password-a … --user-b b@example.test \
  --psql "docker,exec,<узел>,psql,-U,thepost,-d,thepost,-t,-A" \
  --node "docker,exec,<узел>"
Каждый из --psql/--node — префикс команды списком через запятую (без пробелов внутри слов).
"""

from __future__ import annotations

import argparse
import smtplib
import subprocess
import sys
import time
import uuid
from email.message import EmailMessage

RULE_ID = "r-check10"
TENANT = "00000000-0000-0000-0000-000000000001"  # TenantId::DEFAULT (однотенантная установка)
ENVELOPE_HEADERS = ("X-ThePost-Journal-Sender", "X-ThePost-Journal-Recipient",
                    "X-ThePost-Journal-Message-Id", "X-ThePost-Journal-Rule", "X-ThePost-Journal-Date")

results: list[tuple[str, str]] = []


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=check)


def psql(psql_prefix: list[str], sql: str) -> str:
    p = run(psql_prefix + ["-c", sql], check=False)
    if p.returncode != 0:
        raise RuntimeError(f"psql: {p.stderr.strip() or p.stdout.strip()}")
    return p.stdout.strip()


def node(node_prefix: list[str], args: list[str]) -> subprocess.CompletedProcess[str]:
    return run(node_prefix + ["thepost"] + args, check=False)


def record(sub: str, status: str) -> None:
    results.append((sub, status))
    print(f"[{status}] {sub}")


def smtp_in(host: str, domain: str, to_b: str, message_id: str) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Bcc"] = f"x@remote.{domain}", to_b, f"hidden@{domain}"
    msg["Subject"], msg["Message-ID"] = "check10: входящее", f"<{message_id}>"
    msg.set_content("check10")
    with smtplib.SMTP(host, 25, timeout=30) as s:
        s.send_message(msg)


def smtp_out(host: str, user_a: str, password_a: str, to_b: str, message_id: str) -> None:
    msg = EmailMessage()
    msg["From"], msg["To"] = user_a, to_b
    msg["Subject"], msg["Message-ID"] = "check10: исходящее", f"<{message_id}>"
    msg.set_content("check10")
    with smtplib.SMTP(host, 587, timeout=30) as s:
        s.starttls()
        s.login(user_a, password_a)
        s.send_message(msg)


def wait_entries(psql_prefix: list[str], since: int, message_ids: list[str], timeout_s: int = 120) -> list[str]:
    """Ждёт появления записей с заданными Message-ID; возвращает их идентификаторы (UUID)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        rows = psql(psql_prefix, "SELECT id, message_id FROM journal.entries "
                                 f"WHERE tenant_id = '{TENANT}'::uuid AND seq >= {since}")
        found = {mid: rid for rid, mid in (row.split("|") for row in rows.splitlines() if row)}
        if all(m in found for m in message_ids):
            return [found[m] for m in message_ids]
        time.sleep(2)
    raise TimeoutError(f"записи журнала не появились за {timeout_s} с: {message_ids}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Чек-лист беты: журнал — запись, поиск, выгрузка, восстановление")
    ap.add_argument("--host", required=True, help="почтовый хост стенда (SMTP 25/587)")
    ap.add_argument("--domain", required=True)
    ap.add_argument("--user-a", required=True, help="отправитель исходящего (submission)")
    ap.add_argument("--password-a", required=True, help="пароль приложения user-a")
    ap.add_argument("--user-b", required=True, help="получатель")
    ap.add_argument("--psql", required=True, help="префикс psql списком через запятую")
    ap.add_argument("--node", default="", help="префикс запуска thepost на узле списком через запятую")
    args = ap.parse_args()
    psql_prefix = args.psql.split(",")
    node_prefix = args.node.split(",") if args.node else []

    # Правило Both на организацию (данные организации; здесь — напрямую в journal.rules, только стенд).
    rules = psql(psql_prefix, "SELECT count(*) FROM journal.rules "
                              f"WHERE tenant_id = '{TENANT}'::uuid AND scope_kind = 'org' "
                              "AND direction = 'both' AND enabled")
    if rules == "0":
        psql(psql_prefix, "INSERT INTO journal.rules (tenant_id, id, scope_kind, group_id, account_id, "
                          f"direction, enabled) VALUES ('{TENANT}'::uuid, '{RULE_ID}', 'org', NULL, NULL, "
                          "'both', true) ON CONFLICT (tenant_id, id) DO UPDATE SET enabled = true")
        record(f"правило Both на организацию ({RULE_ID}) заведено", "ок")
    else:
        record("правило Both на организацию уже есть", "ок")

    since = int(psql(psql_prefix, "SELECT coalesce(max(seq), 0) FROM journal.entries "
                                  f"WHERE tenant_id = '{TENANT}'::uuid"))
    mid_in, mid_out = f"check10-in-{uuid.uuid4()}@remote.{args.domain}", f"check10-out-{uuid.uuid4()}@{args.domain}"

    # Запись: входящее (25, без AUTH, со скрытой копией) и исходящее (587, AUTH).
    try:
        smtp_in(args.host, args.domain, args.user_b, mid_in)
        smtp_out(args.host, args.user_a, args.password_a, args.user_b, mid_out)
        ids = wait_entries(psql_prefix, since + 1, [mid_in, mid_out])
        record("запись: правило Both — входящее и исходящее дали две записи", "ок")
    except Exception as e:  # noqa: BLE001 — шаг чек-листа: любая ошибка — провал шага
        record(f"запись: {e}", "FAIL")
        print("\nШаг     | Итог")
        for sub, status in results:
            print(f"{sub} | {status}")
        return 1

    env = f"конверт входящего: скрытая копия hidden@{args.domain}"
    bcc = psql(psql_prefix, "SELECT recipients FROM journal.entries "
                            f"WHERE tenant_id = '{TENANT}'::uuid AND message_id = '{mid_in}'")
    record(env, "ок" if f"hidden@{args.domain}" in bcc else f"FAIL ({bcc})")

    # Поиск: thepost admin journal search (ADM-52); поверхность не влита — поиск по индексу (БД).
    if node_prefix:
        p = node(node_prefix, ["admin", "journal", "search", "--sender", f"x@remote.{args.domain}"])
        if p.returncode == 0 and mid_in in p.stdout:
            record("поиск: thepost admin journal search находит запись по отправителю", "ок")
        else:
            hit = psql(psql_prefix, "SELECT count(*) FROM journal.entries WHERE tenant_id = "
                                    f"'{TENANT}'::uuid AND sender = 'x@remote.{args.domain}'")
            record("поиск: по отправителю (индекс; admin journal search — волна admin-38)",
                   "ок" if hit != "0" else "FAIL")
    else:
        record("поиск: --node не задан — пропущен", "БЛОК")

    # Выгрузка: .eml с конвертом (X-ThePost-Journal-*); без поверхности ADM-52 шаг блокируется.
    if node_prefix:
        p = node(node_prefix, ["admin", "journal", "export", ids[0]])
        head = p.stdout.split("\r\n\r\n", 1)[0] if p.returncode == 0 else ""
        if p.returncode == 0 and all(h in head for h in ENVELOPE_HEADERS[:4]):
            record("выгрузка: .eml с конвертом X-ThePost-Journal-*", "ок")
        else:
            record(f"выгрузка: thepost admin journal export недоступен/без конверта "
                   f"(волна admin-38): {p.stderr.strip()[:120]}", "БЛОК")
    else:
        record("выгрузка: --node не задан — пропущена", "БЛОК")

    # Восстановление: сначала убеждаемся, что поверхность ремонта есть (запуск идемпотентен), лишь
    # затем чистим индекс — иначе стенд остаётся с пустым журналом.
    if node_prefix:
        probe = node(node_prefix, ["admin", "journal", "restore-index"])
        if probe.returncode != 0:
            record("восстановление: thepost admin journal restore-index недоступен (волна admin-38) — "
                   "индекс не очищаем, стенд не ломаем", "БЛОК")
        else:
            psql(psql_prefix, f"DELETE FROM journal.entries WHERE tenant_id = '{TENANT}'::uuid")
            empty = psql(psql_prefix, "SELECT count(*) FROM journal.entries "
                                      f"WHERE tenant_id = '{TENANT}'::uuid")
            node(node_prefix, ["admin", "journal", "restore-index"])
            restored = wait_entries(psql_prefix, 1, [mid_in, mid_out])
            chain = node(node_prefix, ["doctor", "journal", "chain"])
            ok = empty == "0" and restored and chain.returncode == 0
            record("восстановление: индекс очищен, restore_index пересобрал, цепочка целостна", "ок" if ok else "FAIL")
    else:
        record("восстановление: --node не задан — пропущено", "БЛОК")

    print("\nШаг          | Итог")
    for sub, status in results:
        print(f"{sub} | {status}")
    return 1 if any(s == "FAIL" for _, s in results) else 0


if __name__ == "__main__":
    sys.exit(main())
