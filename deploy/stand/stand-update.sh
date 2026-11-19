#!/bin/sh
# stand-update.sh — автообновление стенда из релизов GitHub (DEP-59).
#
# Стенд Д.2–Д.7 (stand.yml) живёт на хосте-управлителе: каталог стенда (инвентарь, repo/,
# rel/, inbox), ansible в контейнере, узел и генератор — контейнеры с systemd. Скрипт
# периодически (cron/timer) сверяет последнюю версию GitHub Releases с маркером
# installed-version и при новой версии делает чистую установку: скачать тарболл → сверить
# sha256 → распаковать в rel/ → пересоздать узел → install,provision → проверка md5 и
# служб. Обновление = новая установка (решение 2026-11-19: история миграций не хранится
# до релизов), поэтому данные узла не переносятся, fill-state.json сбрасывается.
#
# Использование: stand-update.sh [--check] [--tag <тег>]
#   (без аргументов)  обновить до последней версии, если есть; занято — пропустить
#   --check           только сообщить (exit 2 — есть новая версия, 0 — актуален)
#   --tag <тег>       установить указанный тег, не сверяясь с releases API
#
# Конфиг — update.conf рядом (пример: update.conf.example): каталоги inbox/rel, имена
# контейнеров узла/генератора, образы, аргументы запуска узла (сеть, --ip, hostname),
# теги установки, юниты проверки. Журнал — update.log (пишет вызывающий, cron).
# Повторный запуск поверх идущего — безопасен (lock-каталог); занятость стенда
# (ansible/прогон/fill) — пропуск до следующего вызова.
#
# Самопочинка: при сбое установки маркер не обновляется — следующий вызов повторит
# обновление с чистого узла. Старые тарболлы и rel/<версия> подчищаются (KEEP).
set -eu

DIR=$(cd "$(dirname "$0")" && pwd)
[ -f "$DIR/update.conf" ] && . "$DIR/update.conf"

REPO=${REPO:-Dicobraz/srvPost}
ASSET_ARCH=${ASSET_ARCH:-x86_64-unknown-linux-gnu}
INBOX=${INBOX:-$DIR/inbox}
REL=${REL:-$DIR/rel}
INVENTORY=${INVENTORY:-$DIR/inventory.yml}
NODE=${NODE:-thepost-stand-smb}
# Генератор стенда (если есть): его /var/lib/thepost-stand — внутренний слой контейнера,
# счётчики наполнения в нём переживают пересоздание узла (см. RESET_STAND_STATE ниже).
GEN=${GEN:-}
NODE_IMAGE=${NODE_IMAGE:-thepost-beta-020-smb:13}
# Аргументы запуска узла (сеть, --ip, hostname, privileged) — обязательны: без них
# пересозданный узел уплывёт по IP/сети (ловушка FIX-11: адрес узла в /etc/hosts
# генератора и stand_smb_address инвентаря должны оставаться валидными).
NODE_RUN_ARGS=${NODE_RUN_ARGS:-}
ANSIBLE_IMAGE=${ANSIBLE_IMAGE:-thepost-beta-020-ansible:1}
INSTALL_TAGS=${INSTALL_TAGS:-install,provision}
HEALTH_UNITS=${HEALTH_UNITS:-thepost openbao postgresql}
FILL_STATE=${FILL_STATE:-$DIR/fill-state.json}
KEEP=${KEEP:-2}
BUSY_PATTERNS=${BUSY_PATTERNS:-'[a]nsible-playbook|[r]un-perf|[r]un-only|[r]un-d7'}
# Гидратация свежего узла до ansible: образ узла голый (Debian+systemd), а become: true
# требует sudo — в прежних узлах он был установлен вручную в слой контейнера и терялся
# при пересоздании. Пустая строка — пропустить шаг.
PRE_INSTALL_CMD=${PRE_INSTALL_CMD:-'command -v sudo >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sudo >/dev/null; }'}
# Политика автообновления (решение владельца 19.11): не чаще UPDATE_EVERY_DAYS дней, только безопасно
# (простой стенда, sha256, чистая установка, приёмка md5+служб, откат на предыдущую версию при провале).
# По умолчанию ВЫКЛЮЧЕНО (AUTO_UPDATE=no) — в проде не включать; на тестовых/перф-стендах включают явно
# в update.conf (AUTO_UPDATE=yes). Ручные --check/--tag работают всегда.
AUTO_UPDATE=${AUTO_UPDATE:-no}
UPDATE_EVERY_DAYS=${UPDATE_EVERY_DAYS:-3}
LAST_UPDATE=${LAST_UPDATE:-$DIR/.last-update}

mode=update
if [ "$#" -ge 1 ]; then
  case "$1" in
    --check) mode=check ;;
    --tag) mode=force; tag_force=${2:?--tag требует тег} ;;
    *) echo "неизвестный аргумент: $1 (см. шапку)" >&2; exit 64 ;;
  esac
fi

# Lock: повторный вызов поверх идущего обновления — не входить (mkdir атомарен).
LOCK="$DIR/.update.lock"
mkdir "$LOCK" 2>/dev/null || { echo "$(date '+%F %T') обновление уже выполняется — пропуск"; exit 0; }
trap 'rmdir "$LOCK"' EXIT INT TERM

say() { echo "$(date '+%F %T') $*"; }

# Стенд занят (установка/прогон/наполнение) — обновление отложим до следующего вызова.
busy=$(pgrep -f "$BUSY_PATTERNS" 2>/dev/null || true)
for p in $busy; do
  [ "$p" != "$$" ] || continue
  say "стенд занят (pid $p) — пропуск"; exit 0
done

if [ "$mode" = update ]; then
  [ "$AUTO_UPDATE" = yes ] || { say "автообновление выключено (AUTO_UPDATE=no) — пропуск"; exit 0; }
  now=$(date +%s)
  last=$(cat "$LAST_UPDATE" 2>/dev/null || true)
  case "$last" in ''|*[!0-9]*) last=0;; esac
  age=$(( (now - last) / 86400 ))
  [ "$age" -ge "$UPDATE_EVERY_DAYS" ] || {
    say "с прошлого обновления ${age} дн. (< $UPDATE_EVERY_DAYS) — пропуск"; exit 0; }
fi

if [ "$mode" != force ]; then
  # Первая запись tag_name в выдаче /releases — самая свежая (включая pre-release).
  api=$(curl -fsSL --max-time 30 \
    "https://api.github.com/repos/$REPO/releases?per_page=10") || {
    say "ОШИБКА: releases API недоступен"; exit 1; }
  latest=$(printf '%s' "$api" | grep -m1 '"tag_name"' | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
  [ -n "$latest" ] || { say "ОШИБКА: пустой ответ releases API"; exit 1; }
else
  latest=$tag_force
fi

installed=$(cat "$DIR/installed-version" 2>/dev/null || true)
if [ "$mode" = check ]; then
  if [ "$latest" = "$installed" ]; then
    say "актуально: $installed"; exit 0
  fi
  say "доступна новая версия: $latest (установлена: ${installed:-нет})"; exit 2
fi
if [ "$mode" = update ] && [ "$latest" = "$installed" ]; then
  say "актуально: $installed"; exit 0
fi

pkg="thepost-$latest-$ASSET_ARCH"
asset="$pkg.tar.gz"
base="https://github.com/$REPO/releases/download/$latest"

say "обновление: ${installed:-нет} -> $latest: скачивание $asset"
mkdir -p "$INBOX" "$REL"
curl -fL --max-time 600 -o "$INBOX/$asset" "$base/$asset" || { say "ОШИБКА: тарболл не скачался"; exit 1; }
curl -fL --max-time 60 -o "$INBOX/$asset.sha256" "$base/$asset.sha256" || { say "ОШИБКА: sha256 не скачался"; exit 1; }
(cd "$INBOX" && sha256sum -c "$asset.sha256") || { say "ОШИБКА: sha256 не сошёлся"; exit 1; }

# Распаковка в rel/<pkg> (тарболл может содержать верхний каталог — срезать).
top=$(tar tzf "$INBOX/$asset" | head -1)
mkdir -p "$REL/$pkg"
case "$top" in */*) tar xzf "$INBOX/$asset" -C "$REL/$pkg" --strip-components=1 ;;
             *)  tar xzf "$INBOX/$asset" -C "$REL/$pkg" ;; esac
[ -x "$REL/$pkg/thepost" ] || { say "ОШИБКА: в тарболле нет исполняемого thepost"; exit 1; }

# Инвентарь на новый бинарник (роль install копирует его в узел).
sed -i "s#thepost_binary_src: .*#thepost_binary_src: /work/rel/$pkg/thepost#" "$INVENTORY"

# Чистая установка: пересоздать узел (данные не переносятся), сбросить state наполнения.
say "пересоздание узла $NODE"
docker rm -f "$NODE" >/dev/null
# shellcheck disable=SC2086 — NODE_RUN_ARGS разворачивается намеренно
docker run -d --name "$NODE" $NODE_RUN_ARGS "$NODE_IMAGE" /sbin/init >/dev/null
i=0; until docker exec "$NODE" true >/dev/null 2>&1; do
  i=$((i + 1)); [ "$i" -lt 60 ] || { say "ОШИБКА: узел не поднялся"; exit 1; }; sleep 1
done
if [ -n "$PRE_INSTALL_CMD" ]; then
  say "гидратация узла (PRE_INSTALL_CMD)"
  docker exec -u 0 "$NODE" sh -c "$PRE_INSTALL_CMD" || { say "ОШИБКА: гидратация не прошла"; exit 1; }
fi
rm -f "$FILL_STATE"
# Состояние наполнения генератора переживает пересоздание узла: fill-state.json (ящик → писем)
# и fill-dav-state.json живут во внутреннем слое контейнера генератора — без сброса fill считает
# «accepted total=15000» на пустом узле (planned=0, visible=0) и падает. Генератор не
# пересоздаётся — сбрасываем его стенд-состояние изнутри.
if [ -n "$GEN" ]; then
  docker exec "$GEN" sh -c 'rm -f /var/lib/thepost-stand/fill-state.json /var/lib/thepost-stand/fill-dav-state.json' || true
fi

# Установка версии из rel/<pkg> в пересозданный узел + приёмка (md5 бинарника = тарболлу, службы живы).
install_and_verify() { # $1 = каталог в rel/
  sed -i "s#thepost_binary_src: .*#thepost_binary_src: /work/rel/$1/thepost#" "$INVENTORY"
  docker run --rm -v "$DIR":/work -v /var/run/docker.sock:/var/run/docker.sock     "$ANSIBLE_IMAGE"     sh -c "cd /work && ansible-playbook -i inventory.yml repo/deploy/stand/stand.yml --tags $INSTALL_TAGS"     > "$DIR/install-last.log" 2>&1 || return 1
  want=$(md5sum "$REL/$1/thepost" | cut -d' ' -f1)
  got=$(docker exec "$NODE" md5sum /usr/local/bin/thepost | cut -d' ' -f1) || return 1
  [ "$want" = "$got" ] || return 1
  for u in $HEALTH_UNITS; do
    docker exec "$NODE" systemctl is-active --quiet "$u" || return 1
  done
  return 0
}

say "установка: ansible --tags $INSTALL_TAGS"
if install_and_verify "$pkg"; then
  echo "$latest" > "$DIR/installed-version"
  date +%s > "$LAST_UPDATE"
  say "готово: $latest установлена и проверена"
else
  say "ОШИБКА: установка/приёмка $latest не прошла (install-last.log)"
  if [ -n "$installed" ] && [ "$installed" != "$latest" ]      && [ -x "$REL/thepost-$installed-$ASSET_ARCH/thepost" ]; then
    say "безопасный откат на $installed"
    if install_and_verify "thepost-$installed-$ASSET_ARCH"; then
      say "откат выполнен: узел на $installed (маркер не менялся)"
    else
      say "ОШИБКА: откат не прошёл — узел требует ручного вмешательства (install-last.log)"
    fi
  fi
  exit 1
fi

# Подчистка: последние KEEP версий в rel/ и inbox.
ls -1dt "$REL"/thepost-* 2>/dev/null | tail -n +"$((KEEP + 1))" | while IFS= read -r d; do rm -rf "$d"; done
ls -1t "$INBOX"/thepost-v*.tar.gz 2>/dev/null | tail -n +"$((KEEP + 1))" | while IFS= read -r f; do rm -f "$f" "$f.sha256"; done
exit 0
