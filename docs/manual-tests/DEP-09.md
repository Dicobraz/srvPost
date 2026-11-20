# DEP-09: эталоны HA СУБД (pg_auto_failover, CloudNativePG) — ручная проверка

Команды — из корня репозитория. Приёмка: переключение primary на стенде — RTO ≤ 30 с, узлы thepost продолжают работу.
Нагрузка во время переключения — сценарий стенда (`deploy/stand`, Д.6) или цикл отправки писем через 587.

## Без стенда
1. YAML: `python3 -c 'import sys,yaml; [yaml.safe_load_all(open(f)) for f in sys.argv[1:]]' deploy/ansible/pg-ha.yml
   deploy/ansible/inventory-ha.example.yml deploy/config/mailbox.yaml` → без ошибок.
2. `ansible-playbook -i deploy/ansible/inventory-ha.example.yml deploy/ansible/pg-ha.yml --syntax-check` → без ошибок.
3. `helm template t deploy/helm/thepost --set cnpg.enabled=true | kubectl apply --dry-run=server -f -` (кластер с
   оператором CloudNativePG 1.26+) → Cluster `t-db`, Pooler `t-db-pooler-rw`; в ConfigMap `database.url` — Pooler,
   `pgbouncer: true`, `direct_url` — `t-db-rw`. С `--set cnpg.pooler.enabled=false` — `url` — `t-db-rw`, без `pgbouncer`.
4. `helm template t deploy/helm/thepost` (по умолчанию) → ресурсов CloudNativePG нет, `database.url` — из values.
5. Режим сохранности (решение #272): `helm template t deploy/helm/thepost --set cnpg.enabled=true` → в Cluster
   `synchronous.dataDurability: required`; с `--set cnpg.db_durability=preferred` → `preferred`; с
   `--set cnpg.db_durability=x` → ошибка «cnpg.db_durability: required или preferred».
6. Прямые адреса и фоновые чтения (DEP-30, 2026-11-20): `helm template t deploy/helm/thepost --set cnpg.enabled=true`
   → в ConfigMap `database.direct_url` — `t-db-rw` (мимо PgBouncer), `database.read_replica` — `t-db-ro`,
   `replica_max_lag: 30s`; с `--set cnpg.pooler.enabled=false` — `url` — `t-db-rw`, без `pgbouncer` и `direct_url`,
   `read_replica` — `t-db-ro`; с `--set cnpg.read_replica=false` — `read_replica` и `replica_max_lag` не задаются;
   с `--set cnpg.replica_max_lag=15s` — `15s`. kubeconform рендера — `Invalid: 0` (хук `openbao-bootstrap` — Job и
   ConfigMap политики; DEP-33).
7. Ansible (DEP-30): `ansible-playbook -i deploy/ansible/inventory-ha.example.yml deploy/ansible/pg-ha.yml
   --syntax-check` и `-i deploy/ansible/inventory-small.example.yml deploy/ansible/small-enterprise.yml
   --syntax-check` (ansible-core 2.18, community.postgresql 5.x) — без ошибок; шаблон `roles/thepost` с
   `thepost_db_direct_urls`, `thepost_db_read_replica`, `thepost_db_replica_max_lag` рендерится в config.yaml с
   секциями `database.direct_urls` / `read_replica` / `replica_max_lag`; пустые значения — секций нет.
   `python3 -c 'import yaml; …'` (safe_load) — `pg-ha.yml`, `small-enterprise.yml`, `config/mailbox.yaml` — без ошибок.

## Итог DEP-30/DEP-31 (2026-11-20, волна deploy-24)
- DEP-30: в эталонах описаны и подключены прямые адреса и реплика фоновых чтений — `config/mailbox.yaml`
  (комментарии: `direct_url` + `direct_urls` мимо PgBouncer для слушателя сигналов и миграций,
  `read_replica` + `replica_max_lag`), роль `thepost` (`thepost_db_direct_url`/`thepost_db_direct_urls`,
  `thepost_db_read_replica`, `thepost_db_replica_max_lag` → `database.*`), `small-enterprise.yml` задаёт узлам
  mailbox `read_replica` — второй узел данных (при установке standby; после переключения отставание ноль),
  чарт `helm/thepost` с `cnpg.enabled` задаёт `read_replica` — службу `-ro` (выключение — `cnpg.read_replica: false`),
  `deploy/README.md` — таблица «когда что задавать» в разделе «PostgreSQL: высокая доступность».
- DEP-31: `{{ ansible_managed }}` в `copy: content` («Write keepalived.conf», `small-enterprise.yml`) заменён
  текстом, как в роли `thepost` (DEP-15): `# Ansible: deploy/ansible/small-enterprise.yml — не править вручную.`
  Аудит параметров `community.postgresql` (5.x и 4.x: `login_db`/`login_port`, `no_password_changes`,
  `postgresql_alter_system`, пустой `query_result`) по `pg-ha.yml`, `small-enterprise.yml`, ролям
  `pg_auto_failover` и `postgresql` — расхождений с документацией коллекции нет; статические проверки выше
  выполнены, прогоны `pg-ha.yml` и `small-enterprise.yml` на стенде (community.postgresql 4.x и 5.x, повторный
  прогон без изменений) в этой волне не выполнялись — шаги разделов «Enterprise-ВМ» и «Малый Enterprise» выше
  не изменены и подлежат стендовому прогону без правок.

## Enterprise-ВМ: pg_auto_failover
1. Инвентарь по `deploy/ansible/inventory-ha.example.yml` (монитор, pg1–pg3, сертификаты с SAN — имя узла), пароли в
   vault. `ansible-playbook -i inventory-ha.yml deploy/ansible/pg-ha.yml --ask-vault-pass` → без ошибок; повторный
   прогон — `changed=0`, primary не перезапускался.
2. На мониторе: `sudo -u postgres /usr/lib/postgresql/16/bin/pg_autoctl show state --pgdata /var/lib/postgresql/16/pgaf`
   → один `primary`, два `secondary`, все `read-write`/`read-only` и `yes` в «Healthy».
   `... pg_autoctl show settings` → `number_sync_standbys 1`, `synchronous_standby_names` — `ANY 1 (…)`.
3. Без интерпретаторов: `systemctl show pgautofailover -p ExecStart` → `/usr/lib/postgresql/16/bin/pg_autoctl run`;
   `ps -o comm= --ppid $(systemctl show -p MainPID --value pgautofailover)` → только `postgres`, `pg_autoctl`;
   `pg_lsclusters` → кластеров Debian нет.
4. TLS: `psql "host=pg1.example.ru dbname=thepost user=thepost sslmode=disable"` → отказ (`pg_hba` reject);
   с `sslmode=verify-full sslrootcert=ca.pem` → вход.
5. Узлы thepost: `thepost_db_url` — pg1, `thepost_db_urls: [pg2, pg3]` (или `deploy/config/mailbox.yaml`) →
   `thepost config check`, `thepost doctor` без `Fail`; в `/metrics` — `tp_db_failover_primary 0`.
6. Переключение (отказ primary): под нагрузкой на primary `sudo systemctl kill -s SIGKILL pgautofailover` или
   выключение ВМ. Замер — от отказа до `tp_db_failover_switching 0` на узлах thepost:
   `tp_db_failover_last_switch_seconds` ≤ 30, `tp_db_failover_switches_total` +1, `tp_db_failover_primary` — номер
   нового primary; `pg_autoctl show state` — новый `primary`, прежний — после возврата `secondary`.
   Во время переключения — временные отказы (SMTP 4xx), после — отправка и IMAP/JMAP работают, писем не потеряно
   (число принятых 250 = число доставленных).
7. Изоляция прежнего primary (без второго primary): отключить сеть primary (`iptables -A INPUT -j DROP` кроме
   управления) → через ≈ 10 с прежний primary — только чтение (`SHOW transaction_read_only` → `on`), новый primary —
   на другом узле не раньше, чем через `primary_demote_timeout` (15 с).
8. Плановое переключение: `pg_autoctl perform switchover --pgdata …` на мониторе → узлы thepost продолжают работу.
9. Режим сохранности `required` (по умолчанию, решение #272): `pg_autoctl show settings` → `number_sync_standbys 1`
   у формации `default`, `0` у `shard2` (`db_durability: preferred`, один узел). Остановить одну реплику
   (`systemctl stop pgautofailover` на pg3) → запись идёт. Остановить вторую (pg2) → `pg_autoctl show state`: primary
   остаётся `primary` (не `wait_primary`), `SHOW synchronous_standby_names` на primary — не пусто;
   на primary `sudo -u postgres psql -c 'SELECT txid_current()'` висит на фиксации (Ctrl+C — «canceling wait for
   synchronous replication»), узлы thepost — SMTP 4xx на приём, IMAP/JMAP-чтение работает. Запустить pg2 →
   висящие фиксации завершаются, приём писем возобновляется, писем не потеряно.
10. Режим `preferred`: `db_durability: preferred` в инвентаре, повторный прогон `pg-ha.yml` → `number_sync_standbys 0`
    (`changed` только у задачи «Set number of synchronous standbys»). Остановить обе реплики → primary — `wait_primary`,
    `synchronous_standby_names` пуст, запись и приём писем продолжаются. Запустить реплики → после догоняния primary —
    `primary`, `synchronous_standby_names` — `ANY 1 (…)`. Вернуть `required`, прогон → `number_sync_standbys 1`.
11. Неверные значения: `db_durability: x` или `required` с `pgaf_number_sync_standbys: 0` → прогон останавливается на
    задаче «Check durability mode».

## Enterprise-K8s: CloudNativePG
1. Оператор (`helm install cnpg cnpg/cloudnative-pg …`), секреты `thepost-db-owner`, `thepost-db`,
   `thepost-db-readonly`, `helm install thepost deploy/helm/thepost --set cnpg.enabled=true …` →
   `kubectl cnpg status thepost-db` — 3 экземпляра, синхронная реплика `quorum`/`sync`; поды thepost — Ready.
2. `kubectl exec thepost-db-1 -- ps -eo comm` → только `postgres`, `manager` (без python, perl).
3. Переключение: `kubectl delete pod <primary> --grace-period=0 --force` под нагрузкой → новый primary,
   `tp_db_failover_last_switch_seconds` ≤ 30 (или время недоступности службы `thepost-db-rw`), узлы thepost
   продолжают работу, писем не потеряно.
4. Плановое: `kubectl cnpg promote thepost-db thepost-db-2` → то же.
5. Режим `required` (по умолчанию): `kubectl get cluster thepost-db -o jsonpath='{.spec.postgresql.synchronous}'` →
   `dataDurability: required`. Остановить обе реплики (`kubectl cnpg fencing on thepost-db thepost-db-2`, то же для
   `-3`) → фиксации на primary ждут (`SHOW synchronous_standby_names` не пусто), thepost — SMTP 4xx, чтение работает;
   `fencing off` → фиксации завершаются, писем не потеряно.
6. Режим `preferred`: `helm upgrade … --set cnpg.db_durability=preferred` → `dataDurability: preferred`; те же реплики
   под fencing → `synchronous_standby_names` пуст, запись и приём писем продолжаются; `fencing off` → снова
   `ANY 1 (…)`. Вернуть `required`.
7. Повтор записи за PgBouncer (META-62; Pooler `t-db-pooler-rw`, `pgbouncer: true`): под циклом отправки через 587
   и выпуском паролей приложения на primary раз в секунду в течение минуты
   `psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'thepost' AND state <> 'idle'"`
   → `tp_db_failover_retries_total` растёт, клиентам — успех или временный отказ (4xx); `SELECT count(*),
   count(DISTINCT queue_id) FROM queue` — числа равны; `SELECT password_id, count(*) FROM app_passwords GROUP BY 1
   HAVING count(*) > 1` — пусто; число принятых 250 = число доставленных.

## SMB: PostgreSQL без pg_ctlcluster
1. `ansible-playbook -i inventory.yml deploy/ansible/smb.yml` поверх существующей установки → PostgreSQL перезапущен
   один раз, повторный прогон — `changed=0`.
2. `systemctl show postgresql@16-main -p ExecStart` → `/usr/lib/postgresql/16/bin/postgres -D …`; `systemctl reload
   postgresql` перечитывает настройки; `thepost` — `/healthz/ready` 200.
