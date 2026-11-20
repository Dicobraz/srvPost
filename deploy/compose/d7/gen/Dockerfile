# Диагностика Д.7 на ноутбуке (w/laptop-d7): образ генератора нагрузки — состав как у stand_generator
# (smtp-source — postfix, swaks, curl, CA-сертификаты, python3), k6 v1.0.0 — из образа grafana/k6 (multi-stage,
# без скачивания с github), docker CLI — из docker:cli (imaptest запускается контейнером через сокет Docker).
# imaptest — не в образе: run-scenario.sh запускает его контейнером (образ dovecot/imaptest) через обёртку
# ./podman → docker (сокет Docker монтируется в контейнер).
FROM grafana/k6:1.0.0 AS k6
FROM docker:cli AS dockercli

FROM python:3.12-slim-bookworm
RUN apt-get update \
 && apt-get install -y --no-install-recommends postfix swaks libio-socket-ssl-perl curl ca-certificates procps \
 && rm -rf /var/lib/apt/lists/*
COPY --from=k6 /usr/bin/k6 /usr/local/bin/k6
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY podman /usr/local/bin/podman
ENTRYPOINT ["bash"]
