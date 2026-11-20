#!/bin/bash
# Диагностика Д.7, прогон B (w/laptop-d7): обёртка docker-entrypoint.sh postgres:16 — pg_wal на отдельном томе.
# На пустом PGDATA initdb делается здесь (с --waldir=$D7_WALDIR; пароль суперпользователя — POSTGRES_PASSWORD
# через --pwfile), дальше — оригинальный docker-entrypoint.sh: он видит PG_VERSION и сразу запускает postgres
# с command из dev.yml (TLS, hba_file). На существующем кластере — просто пропуск.
set -Eeo pipefail

PGDATA="${PGDATA:-/var/lib/postgresql/data}"
if [ ! -s "$PGDATA/PG_VERSION" ]; then
  WALDIR="${D7_WALDIR:?D7_WALDIR не задан}"
  echo "d7-wal-entrypoint: initdb с --waldir=$WALDIR" >&2
  mkdir -p "$PGDATA" "$WALDIR"
  chown postgres:postgres "$PGDATA" "$WALDIR"
  chmod 700 "$PGDATA" "$WALDIR"
  pwfile=$(mktemp)
  printf %s "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD не задан}" >"$pwfile"
  chown postgres "$pwfile"
  # shellcheck disable=SC2086  # POSTGRES_INITDB_ARGS — набор слов, как в docker-entrypoint
  gosu postgres initdb -D "$PGDATA" --username="${POSTGRES_USER:-postgres}" --pwfile="$pwfile" \
    --waldir="$WALDIR" $POSTGRES_INITDB_ARGS
  rm -f "$pwfile"
fi
exec docker-entrypoint.sh "$@"
