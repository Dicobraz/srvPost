#!/bin/sh
# SeaweedFS в compose: сервер с S3 и бакеты для интеграционных тестов при старте.
# /tmp/ready — бакеты есть и S3 слушает порт (healthcheck); повторный старт бакеты не трогает.
# Бакет журнала (DEP-58, SRS 4.9) — с Object Lock, если образ поддерживает (SeaweedFS ≥ 4.x:
# s3.bucket.create -withLock); иначе — обычный бакет: тесты tp-blob пишут режим и срок метаданными
# объектов (x-amz-meta-thepost-lock-*), enforcement уровня сервера на старом образе нет.
set -eu

BUCKET=${TP_S3_BUCKET:-thepost-test}
JOURNAL_BUCKET=${TP_S3_JOURNAL_BUCKET:-thepost-journal-test}
rm -f /tmp/ready
weed -logtostderr=true "$@" &
pid=$!
trap 'kill -TERM "$pid"' TERM INT

shell() { echo "$1" | weed shell -master=127.0.0.1:9333 2>/dev/null; }
until shell s3.bucket.list | grep -qw "$BUCKET" || shell "s3.bucket.create -name $BUCKET" | grep -q created; do
  kill -0 "$pid"
  sleep 1
done
echo "seaweedfs: бакет $BUCKET есть"

# Бакет журнала: с Object Lock на образах ≥ 4.x (s3.bucket.create -withLock; включение необратимо,
# данные compose — том, down -v снимает). Образ 3.80 флага не знает — обычный бакет: тесты tp-blob
# пишут режим и срок метаданными объектов (x-amz-meta-thepost-lock-*), enforcement на нём нет.
# weed version → «version 30GB 4.49 linux amd64»: версия — первое поле вида X.Y (3-е), мажорная — до точки.
major=$(weed version 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+[.][0-9]+$/) {split($i, v, "."); print v[1]; exit}}')
if ! shell s3.bucket.list | grep -qw "$JOURNAL_BUCKET"; then
  if [ "${major:-0}" -ge 4 ]; then
    until shell "s3.bucket.create -name $JOURNAL_BUCKET -withLock" | grep -q created; do
      kill -0 "$pid"
      sleep 1
    done
  else
    echo "seaweedfs: образ без Object Lock (SeaweedFS < 4) — бакет $JOURNAL_BUCKET без блокировки"
    until shell "s3.bucket.create -name $JOURNAL_BUCKET" | grep -q created; do
      kill -0 "$pid"
      sleep 1
    done
  fi
fi
echo "seaweedfs: бакет $JOURNAL_BUCKET есть"
touch /tmp/ready

# Первый wait прерывает сигнал (trap), второй дожидается остановки сервера.
wait "$pid" || wait "$pid"
