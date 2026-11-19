# Установка The Post

Для администратора: как поставить сервер, завести первого администратора и пользователей, подключить почтовые
клиенты. Подробности по каждому компоненту — [`deploy/README.md`](../deploy/README.md).

## Что понадобится

- **Linux** x86_64 с glibc 2.18 и новее. Для рабочего сервера — Debian 13 (основа) или 12, Ubuntu 26.04
  или 24.04, Astra Linux SE 1.8, РЕД ОС 8, AlmaLinux 10 или 9 (совместимость с RHEL 9 и 10), от 4 vCPU и 8 ГБ памяти
  (целевой размер для 1 000 пользователей), диск — под письма (или S3 —
  [где лежат письма](#где-лежат-письма-диск-или-s3)).
- **Имя сервера** (например, `mail.example.ru`) и **почтовый домен** (`example.ru`), доступ к их DNS.
- **Открытые порты**: 25 (приём почты), 465 и 587 (отправка), 993 и 143 (IMAP), 4190 (ManageSieve — правила
  фильтрации), 443 (JMAP, календари и контакты, автонастройка), 80 (только для выпуска сертификата Let's Encrypt).
- Все требования к окружению и тонкости настройки (кодировка базы UTF-8 и др.) — [PREREQUISITES.md](PREREQUISITES.md).

Все внутренние компоненты ставятся вместе с сервером: PostgreSQL (метаданные), OpenBao (секреты), Rspamd (антиспам).

## Попробовать: Docker Compose

Самый быстрый способ посмотреть — на любой машине с Docker Engine и Compose v2, от 4 ГБ памяти. Домен в этом
варианте тестовый — `example.test`, сертификаты выпускает свой тестовый центр.

```bash
git clone https://github.com/Dicobraz/srvPost && cd srvPost
docker compose -f deploy/compose/dev.yml --profile smb up -d --build
```

Первая сборка образа идёт 20–30 минут (Rust собирается внутри Docker, на машине его ставить не нужно). Без сборки —
готовый образ выпуска из ghcr.io. Образ закрытый: сначала войдите в реестр токеном GitHub с правом `read:packages`
(выдаёт владелец репозитория), `<версия>` — из выпуска (тег образа совпадает с `appVersion` чарта Helm):

```bash
docker login ghcr.io -u <логин GitHub>          # пароль — токен read:packages
THEPOST_IMAGE=ghcr.io/dicobraz421/thepost:<версия> docker compose -f deploy/compose/dev.yml --profile smb up -d
```

Когда все контейнеры запущены, проверьте окружение:

```bash
docker compose -f deploy/compose/dev.yml --profile smb run --rm --no-deps thepost doctor
```

В итоге не должно быть строк `FAIL`. Предупреждения `WARN` про DKIM и DNS для тестового домена — ожидаемы.

Дальше — [первый администратор](#первый-администратор). В этом варианте команды узла запускаются через
`docker compose -f deploy/compose/dev.yml --profile smb exec thepost thepost …`, а CA для клиентов —
`deploy/compose/tls/ca.pem`.

Остановить — `… --profile smb down`; данные остаются в томах Docker и вернутся при следующем `up`.

## Рабочий сервер: Ansible

Чистая ВМ (Debian 13 или 12, Ubuntu 26.04 или 24.04, Astra Linux SE 1.8, РЕД ОС 8, AlmaLinux 10 или 9) →
PostgreSQL 16, OpenBao, Rspamd (по желанию — антивирус ClamAV) и `thepost`
под systemd, одной командой с управляющей машины. Повторный запуск ничего не ломает — им же применяются изменения.

1. Скачайте выпуск и распакуйте бинарный файл:

   ```bash
   git clone https://github.com/Dicobraz/srvPost && cd srvPost
   V=v0.2.1-beta.1   # последний выпуск — на странице Releases
   curl -LO https://github.com/Dicobraz/srvPost/releases/download/$V/thepost-$V-x86_64-unknown-linux-gnu.tar.gz
   tar xzf thepost-$V-x86_64-unknown-linux-gnu.tar.gz
   ```

2. Опишите сервер:

   ```bash
   cp deploy/ansible/inventory.example.yml inventory.yml
   ```

   В `inventory.yml` — адрес ВМ и пользователь SSH, `thepost_domain` (почтовый домен), `thepost_hostname`
   (имя сервера), `thepost_tls_mode` и `thepost_acme_email`:

   | `thepost_tls_mode` | Сертификат |
   |---|---|
   | `acme` (по умолчанию) | Let's Encrypt встроенным клиентом The Post; порт 80 виден со всех адресов имени сервера (все A/AAAA-записи — эта ВМ, см. ниже); ключ — в OpenBao |
   | `files` | свои файлы PEM: `thepost_tls_cert_src` (цепочка), `thepost_tls_key_src` (ключ — плейбук загружает его в OpenBao) |
   | `internal` | внутренний центр сертификации — только для стенда |

   **`acme`: порт 80 виден со всех адресов имени.** Let's Encrypt проверяет владение доменом с нескольких независимых
   точек мира (multi-perspective validation), поэтому порт 80 должен отвечать с любого адреса интернета: все
   A/AAAA-записи имени сервера ведут на этот узел, без гео-блокировок и выборочных пробросов. Частичная видимость —
   «открыт только из нашей сети», гео-фильтр или часть адресов имени — означает отказ выпуска, и причина тогда на
   границе сети, а не в узле. Проверьте руками из внешней сети (не с самой ВМ и не из её сегмента):

   ```bash
   curl -i http://mail.example.ru/
   ```

   Ответ `404` — норма: у служебного HTTP открыт только маршрут `/.well-known/acme-challenge/*`, остальные пути — 404.
   Тайм-аут или недоступность — порт режет сеть, выпуск не пройдёт. При неудачном выпуске причину ищите в журнале узла
   (`journalctl -u thepost`): первый запуск без сертификата не стартует, а ошибка называет сервер ACME и адрес
   проверки HTTP-01.

   Закрытый ключ сертификата хранится только в OpenBao (секрет `thepost/tls`), на диске сервера его нет: плейбук
   кладёт его туда сам, при `acme` — сам узел. Сменить свой сертификат (`files`) — заменить файлы и повторить прогон.

3. Запустите:

   ```bash
   ansible-galaxy collection install -r deploy/ansible/requirements.yml
   ansible-playbook -i inventory.yml deploy/ansible/smb.yml \
     -e thepost_binary_src=$PWD/thepost-$V-x86_64-unknown-linux-gnu/thepost
   ```

   Плейбук сам дождётся готовности узла. Ключи восстановления OpenBao он кладёт в `/root/openbao-init.json` на ВМ —
   **перенесите их в надёжное место и удалите с сервера.**

4. Проверьте на ВМ: `sudo -u thepost thepost doctor` — без `FAIL`.

## Вручную под systemd

Если PostgreSQL и OpenBao уже есть или нужна своя схема — установка бинарного файла, юнита systemd и `config.yaml`
по шагам описана в [`deploy/README.md`](../deploy/README.md#установка-под-systemd-smb-enterprise-вм). Секреты (пароли
СУБД, ключи, в том числе ключ TLS — `tls.key: { secret: "thepost/tls#key" }`) в `config.yaml` не пишутся — только
ссылки на OpenBao. Порты ниже 1024 слушают сокеты systemd (`thepost-*.socket`): у процесса нет прав открыть их самому.
Сертификат — встроенный ACME (секция `acme`, порт 80 — `thepost-http.socket`) или свой: цепочка — файл
`tls.cert_file`, ключ — в OpenBao (`bao kv put -mount=thepost tls key=@privkey.pem`, затем удалите файл ключа с сервера).

## Где лежат письма: диск или S3

Тела писем и вложения хранятся отдельно от базы. Где — задаёт один параметр `config.yaml`, `blob.url` (читается при
запуске узла):

| `blob.url` | Хранилище | Где задано по умолчанию |
|---|---|---|
| `file:///var/lib/thepost/blob` | каталог на диске сервера | одна ВМ: `smb.yml`, Docker Compose (пресет `deploy/config/all.yaml`) |
| `s3://<бакет>[/<префикс>]` | объектное хранилище S3 (эталон — SeaweedFS) | несколько узлов: чарт Helm, пресет `deploy/config/mailbox.yaml`, `deploy/ansible/small-enterprise.yml` |

**На одной ВМ по умолчанию — диск**, настраивать нечего: каталог создаёт узел, копии снимает
[резервное копирование](#резервное-копирование-и-восстановление). Каталог вне `/var/lib/thepost` — ещё и
`ReadWritePaths=` юнита (`systemctl edit thepost`).

**S3** — когда узлов несколько или у узла нет своего диска (в Kubernetes том пода временный). Рядом с `blob.url` —
секция `blob.s3`:

```yaml
blob:
  url: s3://thepost-blob
  s3:
    endpoint: https://s3.example.ru:8333          # только https://; не задан — AWS по region
    path_style: true                              # по умолчанию; нужен SeaweedFS и MinIO
    credentials:
      access_key_id: { secret: "thepost/s3#access_key_id" }
      secret_access_key: { secret: "thepost/s3#secret_access_key" }
    tls: { ca_file: /etc/thepost/pki/ca.pem }     # свой CA; не задан — системные корневые сертификаты
```

- Бакет и префикс — только в `blob.url`; `blob.s3.bucket` и `blob.s3.prefix` — ошибка `thepost config check`.
- Ключи доступа — только в OpenBao, в `config.yaml` — ссылки: `bao kv put -mount=thepost s3 access_key_id=…
  secret_access_key=…` (`small-enterprise.yml` создаёт секрет сам). Нет секрета — узел не запускается.
- Канал — только HTTPS с проверкой сертификата; `http://` отклоняется (кроме профиля `dev`).
- Ansible — `thepost_config_extra: { blob: { url: …, s3: { … } } }`, Helm — `config.blob`.
- Проверка — `thepost doctor`: `blob.open`, `blob.write`, `blob.read`, `blob.delete`.

Выбирайте при установке: при смене `blob.url` уже записанные письма узел сам не переносит. Копии каталога на диске
делает эталон SMB; копии S3 — средствами самого хранилища. В 0.2.0 хранение в S3 на стенде не проверялось
([известные ограничения](releases/0.2.0.md#известные-ограничения)). Требования —
[PREREQUISITES.md](PREREQUISITES.md#хранилище-писем).

## Первый администратор

На сервере, от root или от учётной записи службы:

```bash
sudo thepost admin init --email admin@example.ru
```

Команда заводит администратора и принятый домен и один раз выводит:

- **пароль** администратора — им администратор входит в консоль и в `thepost admin`, а также в почту по IMAP, SMTP
  и JMAP;
- **одноразовый токен** Admin API (`tpa_…`), действует 10 минут, — для первого входа в консоль, если вход по паролю
  выключен (`admin.password_login: false` или настроен `admin.oidc`).

Сохраните пароль сразу: повторно он не показывается. `admin init` — не единственный способ получить сессию Admin API:
истёкшая сессия (8 часов) или перезапуск узла — это снова вход по паролю, а не `admin init`. Повторный запуск откажет
(`409`); `thepost admin init --force` нужен, только если пароль утрачен: прежний пароль `admin init` перестанет
действовать.

### Вход администратора по паролю: `admin.password_login`

Консоль и `thepost admin login` принимают имя входа и пароль администратора (`POST /api/v1/session`): пароль каталога
(`auth.ldap`) или пароль приложения, в том числе выданный `admin init`. Проверка — та же, что у входа в почту: после
`auth.abuse.ip_failures` неудач с одного адреса (и `account_failures` — под одной учётной записью) вход блокируется на
`auth.abuse.block_for`, и верный пароль до конца блокировки тоже отвергается. Каждый вход и каждая неудача — в журнале
аудита. Роли — по назначениям `admin.roles`; администратор, заведённый `admin init`, — администратор инсталляции; у
учётной записи без ролей вход отклоняется (`403`).

| Ключ | Умолчание | Что задаёт |
|---|---|---|
| `admin.password_login` | не задан — включён без `admin.oidc`, выключен с ним | `true`/`false` — включить или выключить вход по паролю явно; выключен — `POST /api/v1/session` с паролем отвечает `404`, консоль показывает вход через OIDC и форму токена `admin init` |

## Учётные записи

Пользователи заводятся командой `thepost admin` на самом сервере: Admin API слушает только локальный адрес
(`127.0.0.1:8443`), адрес команда берёт из `config.yaml`. Сначала войдите по паролю — сессия на 8 часов:

```bash
thepost admin login --user admin@example.ru --insecure     # пароль — из терминала без эха; выводит сессию tps_…
export THEPOST_ADMIN_TOKEN=tps_…
```

Пароль не передаётся аргументом (он виден в списке процессов): в сценариях — первой строкой stdin
(`--password-stdin`).

`--insecure` — только для этого локального адреса, если сертификат узла выпущен на имя сервера (иначе — `--ca-file`).
Дальше — пользователь и пароль для его почтового клиента:

```bash
thepost admin account create ivanov@example.ru --name "Иван Иванов" --insecure
thepost admin app-password create ivanov@example.ru --label Thunderbird --insecure   # пароль — один раз
thepost admin account get ivanov@example.ru --insecure
thepost admin transport domain list --insecure
```

У каждого клиента может быть свой пароль приложения: `app-password list` показывает их без значений,
`app-password revoke` отзывает один, не трогая остальные. Принятые домены организации —
`transport domain list|create|delete` (`create <домен> --relay host[:port]` — пересылка на другой узел вместо
собственного домена). Вывод — таблица или `--json`.

То же — в веб-консоли (`https://127.0.0.1:8443/console/`, с рабочего места — через SSH-туннель) и в текстовой
консоли `thepost admin tui` — [управление без веб-интерфейса](#управление-без-веб-интерфейса).

В Docker Compose те же команды выполняются в контейнере узла:

```bash
DC="docker compose -f deploy/compose/dev.yml --profile smb"
$DC exec -it thepost thepost admin login --user admin@example.test --insecure
$DC exec -e THEPOST_ADMIN_TOKEN=tps_… thepost thepost admin account create a@example.test --insecure
```

### Вход администратора через OIDC: секция `cli.oidc`

Вместо пароля администратор может войти у поставщика OpenID Connect из `auth.oidc` с устройства без
браузера (OAuth 2.0 Device Authorization Grant, RFC 8628): команда показывает адрес и код, администратор
подтверждает вход в браузере на другом устройстве, команда выводит токен доступа одной строкой в stdout.
Адрес и код команда пишет в stderr, а токен — в stdout, чтобы он не попал в историю оболочки:

```bash
export THEPOST_ADMIN_TOKEN="$(thepost admin login --oidc)"
thepost admin whoami --insecure
```

Токен OIDC подставляется в `THEPOST_ADMIN_TOKEN` вместо сессии `tps_…`: обмена на сессию нет, остальные команды
`thepost admin` — те же.

| Ключ | Умолчание | Что задаёт |
|---|---|---|
| `cli.oidc.client_id` | не задан — вход с устройства выключен | открытый клиент (public client) у поставщика с разрешённым Device Authorization Grant; его токен должен содержать получателя из `auth.oidc.audience` |
| `cli.oidc.scope` | `openid` | области доступа через пробел |
| `cli.oidc.poll_interval` | `5s` | пауза между опросами токена, если поставщик не прислал свой `interval` |
| `cli.oidc.slow_down_step` | `5s` | прибавка к паузе на каждый ответ поставщика `slow_down` |
| `cli.oidc.max_wait` | `15m` | наибольшее ожидание подтверждения, даже если код поставщика действует дольше |

Секцию читает сама команда при каждом запуске — перезапуск узла не нужен. Без `auth.oidc` или без `client_id`
команда завершается ошибкой; пустой `client_id` или `scope`, нулевые паузы — ошибка `thepost config check`.
Ansible — `thepost_cli_oidc` (например `{ client_id: thepost-cli }`), Helm — `config.cli.oidc`.

## Управление без веб-интерфейса

Когда браузера нет — медленный канал или консоль сервера по SSH, — те же действия выполняет текстовая консоль
`thepost admin tui`: двухпанельный интерфейс в стиле Midnight Commander. Как веб-консоль и CLI, она — тонкий клиент
Admin API: вход, права и записи в журнале аудита у всех трёх одинаковые, прямого доступа к базе нет. Полный
справочник экранов и разделов — [руководство администратора](ADMIN-GUIDE.md#текстовая-консоль-thepost-admin-tui).

```bash
thepost admin tui --url https://127.0.0.1:8443 --ca-file /etc/thepost/pki/ca.pem
```

- Ключи подключения — те же, что у остальных команд `thepost admin`: `--url` (`THEPOST_ADMIN_URL`), `--token`
  (`THEPOST_ADMIN_TOKEN`), `--ca-file`, `--insecure`, `--timeout`, `-c, --config`. Адрес Admin API из `config.yaml`
  подкоманда не берёт — укажите его ключом или впишите в форме входа; `--config` нужен только разделу
  «Конфигурация узла». Нужен терминал не меньше 80×24.
- Задан токен — вход сразу, без формы. Иначе — форма: адрес, способ входа (‹ пароль / токен ›, переключается ←→),
  имя входа, пароль; поля — ↑↓ или Tab, вход — Enter. Пароль — тот же, что у `thepost admin login` и веб-консоли.
  Токен OIDC из `thepost admin login --oidc` принимается как обычный токен, токен `tpa_…` из `admin init` — нет;
  входа через OIDC прямо в форме нет.
- Тема — `--theme auto|dark|light|256|16|mono` или `THEPOST_TUI_THEME` (ключ сильнее переменной). При `auto` режим
  выбирается по окружению: `NO_COLOR` — монохром, `COLORTERM=truecolor` или `24bit` — полноцветный тёмный, `TERM`
  с `256color` — 256 цветов, `TERM=dumb` — монохром, иначе — 16 цветов. У сообщений есть знак, а не только цвет:
  ● норма, ▲ внимание, × ошибка.
- Управление — только клавиатура (мыши нет). Выход — F10 или Ctrl+C.

| Клавиша | Действие |
| --- | --- |
| Tab / Shift+Tab | другая панель (активная — с двойной рамкой) |
| ↑↓ PgUp PgDn Home End | по строкам дерева и списка; ↓ в конце списка подгружает следующую страницу |
| Enter, F3 | открыть раздел или запись |
| Esc, Backspace, ← | назад |
| F1 | справка по клавишам |
| F2 | фильтр списка (параметры запроса); в конфигурации узла — перечитать файл |
| F4 | правка записи или значения |
| F5, F6 | действия раздела: у учётных записей F5 — запретить или разрешить вход, F6 — пароли приложений; в журналах F5 — сменить журнал аудита и доставки; в корзине F5 — восстановить письмо, F6 — скрытые письма. Полная таблица разделов — руководство администратора |
| F7 | создать |
| F8 | удалить: подтвердить — Enter / y / д, отменить — Esc / n / н |
| F9 | меню всех операций Admin API: раздел, метод и описание операции |
| F10, Ctrl+C | выход |

В формах: ↑↓ или Tab — поле, ←→ — выбор варианта, Enter — выполнить, Esc — отмена; ошибка узла показывается у
поля. Если операции нужна учётная запись, консоль спрашивает имя входа, а не идентификатор.

Внизу каждого экрана — связь с CLI: строка команды показывает то же действие командой `thepost admin …`, а для
операций без команды — «нет в CLI: МЕТОД путь». Строку можно скопировать в скрипт, когда действие, сделанное
вручную, надо повторять регулярно.

### Конфигурация узла

На самом узле консоль правит и `config.yaml` — строка «Конфигурация узла» в дереве слева. Раздел работает, когда
консоль видит файл (`--config`, `THEPOST_CONFIG` или `/etc/thepost/config.yaml`) и запущена с правом записи в него.

- Дерево секций строится по схеме `thepost config schema`: у каждого параметра — описание и значение по умолчанию.
  ← → — раскрыть и свернуть секцию, Enter или F4 — правка значения. Пустое значение убирает параметр из файла —
  действует умолчание; ← → — выбор из вариантов, для логических полей — «да»/«нет».
- Перед записью новое значение проходит `thepost config check`: ошибка показывается у поля, файл не меняется.
  Прежний файл остаётся рядом копией `config.yaml.bak`, новый записывается целиком, атомарно — сбой не оставляет
  наполовину переписанный файл. Если файл изменили после чтения, запись откажет: F2 перечитает его. Узел
  перечитывает `config.yaml` без перезапуска сам.
- Файл, которым управляет Ansible или Helm, помечен строкой `# thepost: managed-by=ansible` (или `=helm`) в начале
  — её пишут эталоны установки: консоль открывает такой файл только на чтение (в дереве — «R/O») и подсказывает
  править в инвентаре роли или в значениях чарта, иначе у файла два источника изменений. Только чтение и тогда,
  когда нет права на запись.
- Консоль запущена не на узле и файла нет — раздел поясняет, что `config.yaml` правят на узле, а проверяют командой
  `thepost config check`.

## Брендинг заказчика

Веб-консоль, текстовый интерфейс и подсветка вывода CLI по умолчанию оформлены в фирменном стиле IT TASK. Вместо
него ставится брендинг заказчика: название продукта, знак и цвета ролей — обе темы консоли и текстового
интерфейса, подсветка CLI. Меняется через Admin API без пересборки и перезапуска узла, каждое изменение — в
журнале аудита.

Уровни два: **установка** (задаёт администратор установки) и **организация** (администратор организации и
установки; оператору — только чтение). Все поля необязательны: незаданное берётся с уровня выше — организация →
установка → встроенный IT TASK. Заказчик сменил только название — название новое, знак и цвета остаются с уровня
выше. Если уровень задал основной цвет, незаданные роли бренда этого уровня (рамка активной панели, F-клавиши,
выделение, заголовки и текст на них) выводятся из него; фоны, текст и цвета состояний — с уровня выше. Уровень
без единого цвета берёт цвета уровня выше целиком.

```bash
thepost admin branding set --name "Почта Иванов и Ко" --primary "#177CAA" --insecure
thepost admin branding set --role light.sel="#E3107F" --role dark.text="#161616" --insecure
thepost admin branding logo set znak.png --insecure
thepost admin branding show --insecure           # свой набор уровня и действующий
thepost admin branding reset --insecure          # сброс набора — действует уровень выше
thepost admin branding logo reset --insecure     # убрать знак (название и цвета остаются)
```

`set` меняет только заданное — остальное набора сохраняется; уровень организации — ключ `--org <UUID>` (или
переменная `THEPOST_ADMIN_ORG`), без него — уровень установки. То же — в веб-консоли, раздел «Брендинг».

Требования: цвета — `#RRGGBB`; роли тем `light` и `dark` — `screen`, `panel`, `text`, …, подсветка CLI (`cli`) —
`head`, `accent`, `ok`, `warn`, `err`, `muted`, `json_*` (полный список — `design/tokens.toml`; вводятся как
`--role <тема>.<роль>=#RRGGBB`); название — до 64 символов; знак — PNG до 256 КБ и до 1024×1024, ставится и без
названия и цветов уровня (иной тип — 415, больше 256 КБ — 413, не PNG или битый файл — 422).

При сохранении действующий набор уровня проверяется по контрасту: текст — 4,5:1, рамки и заливки — 3:1, роли CLI
— 3:1 на светлом и тёмном фоне терминала. Не проходит — 422, ответ problem+json называет тему, роль, пару,
контраст и порог:

```
контраст ниже порога: светлая тема: выделение sel #F5E663 на панель panel #FFFFFF — 1,3 : 1, нужно 3 : 1
```

Подберите для роли цвет темнее или светлее — по контрасту из ответа, пока он не станет не ниже порога. Смена
набора установки отклоняется и тогда, когда она ломает действующую палитру хотя бы одной организации, — в ответе
эти организации и пары.

Текстовый интерфейс применяет цвета брендинга в режимах truecolor и 256 цветов; в 16 цветах и монохроме —
встроенные цвета, а знак показывается только там, где терминал поддерживает графику (иначе — одно название).
Экран входа консоли и текстового интерфейса показывает брендинг до входа: открытый маршрут
`GET /api/v1/public/branding?domain=<домен>` отдаёт только название, цвета и ссылку на знак; организация
определяется по принятому домену имени входа, а неизвестный домен и организация без своего набора дают один и
тот же ответ (брендинг установки) — наличие организации перебором не раскрывается.

## Обслуживание: секция `maintenance`

Роль `maintenance` (входит в пресеты) очищает данные по сроку, заполняет книгу «Организация» и проверяет
целостность хранилища писем. Все ключи читаются при запуске узла — после изменения нужен перезапуск. Ansible —
`thepost_maintenance` (например `{ verify: { at: "02:30" } }`), Helm — `config.maintenance`; полный перечень с
описаниями — `thepost config schema`.

| Ключ | Умолчание | Что задаёт |
|---|---|---|
| `maintenance.purge_interval` | `1h` | период очистки по сроку: надгробия DAV, журналы автоответов и доставки, завершённые отправки JMAP, аудит ящиков, токены `admin init`, применённые сообщения iTIP; первый проход — при запуске роли. Сами сроки — в `meta` (`meta.dav.tombstone_ttl`, `meta.sieve.vacation_log_ttl`, `meta.delivery.retention`, `meta.submissions.retention`, `meta.mailbox_audit.retention`) |
| `maintenance.admin_token_retention` | `30d` | сколько хранить токены `thepost admin init` после истечения (погашенные, отозванные, истёкшие — для аудита); `0s` — удалять сразу. Срок действия самого токена — `admin.init.token_ttl` (`10m`) |
| `maintenance.gal_interval` | `1m` | период заполнения книги «Организация» (GAL) из каталога: `auth.ldap`, без него — учётные записи и группы PostgreSQL; первый проход — при запуске роли, изменение каталога видно в CardDAV и JMAP не позже чем через период |
| `maintenance.verify.enabled` | `true` | проверка целостности BLOB по расписанию — `thepost verify` без `--fix`: ничего не удаляет, итог — в журнал узла и `/metrics` (`tp_blob_verify_*`); исправление — только вручную, `thepost verify --fix` |
| `maintenance.verify.at` | `"03:00"` | время прохода, UTC, `ЧЧ:ММ` |
| `maintenance.verify.interval` | `24h` | период проходов; не в целых сутках — сетка проходов отсчитывается от `at` после полуночи UTC 1970-01-01 |
| `maintenance.verify.lease_name` | `blob-verify` | имя лизы: в кластере проход выполняет один узел — её держатель |
| `maintenance.verify.lease_ttl` | `2m` | срок лизы; продлевается во время прохода и держится после него — должен покрывать расхождение часов узлов |

`thepost config check` отклоняет нулевые `purge_interval`, `gal_interval`, `verify.interval`, `verify.lease_ttl`,
пустой `verify.lease_name` и `verify.at` не в виде `ЧЧ:ММ`. Удалённые ключи `smtp.queue.poll_interval` и
`mailstore.disabled.max_wait` — в [несовместимых изменениях 0.2.0](releases/0.2.0.md#несовместимые-изменения-для-администратора).

## Календари и контакты: секция `dav`

Роль `dav` (входит в пресеты) отдаёт CalDAV и CardDAV на том же порту 443, что и JMAP (путь `/dav/`); отдельный
порт — `http.dav` (Ansible — `thepost_dav_listen`). Ключи секции читаются при запуске узла. Ansible — `thepost_dav`,
Helm — `config.dav`; остальные лимиты (размеры запросов и объектов, развёртка повторов) — `thepost config schema`.

| Ключ | Умолчание | Что задаёт |
|---|---|---|
| `dav.schedule_keep_processed` | `true` | хранить применённые сервером сообщения iTIP для ленты уведомлений JMAP (`CalendarEventNotification`); во входящих планирования CalDAV они не видны, их удаляет очистка по сроку (роль maintenance). `false` — не хранить, лента пуста |
| `dav.schedule_processed_ttl` | `30d` | срок хранения этих сообщений при `dav.schedule_keep_processed: true` |
| `dav.principal_search_scan` | `10000` | сколько учётных записей организации просматривает один поиск принципалов (`principal-property-search`, `calendarserver-principal-search`: выбор участников и переговорных в клиенте); остальные не ищутся. Целое число. Если в организации записей больше, часть сотрудников и переговорных не находится — увеличьте значение |
| `dav.principal_search_results` | `50` | сколько найденных принципалов отдаётся в одном ответе поиска. В `calendarserver-principal-search` клиент может запросить меньше (`cs:nresults`), больше этого значения — не получит; при превышении ответ содержит найденное и статус `507` (`number-of-matches-within-limits`). Целое число |

Общий доступ к календарям и адресным книгам, представители и ресурсы (переговорные, оборудование) ключей в
`config.yaml` не имеют. Права на свой календарь выдаёт владелец в клиенте; политику общего доступа организации,
представителей и ресурсы с правилами бронирования ведёт администратор — веб-консоль, текстовая консоль или Admin API
(`/api/v1/orgs/{org}/calendar-sharing`, `…/accounts/{account}/delegates`, `…/resources`). Переговорную клиент находит
поиском принципалов — его пределы в таблице выше.

## Настройка клиентов

| | Сервер | Порт | Защита |
|---|---|---|---|
| Входящая почта (IMAP) | `mail.example.ru` | 993 | SSL/TLS |
| | | 143 | STARTTLS |
| Исходящая почта (SMTP) | `mail.example.ru` | 465 | SSL/TLS |
| | | 587 | STARTTLS |
| Правила фильтрации (ManageSieve) | `mail.example.ru` | 4190 | STARTTLS |
| JMAP | `https://mail.example.ru/.well-known/jmap` | 443 | HTTPS |
| Календари и контакты (CalDAV, CardDAV) | `https://mail.example.ru/dav/` | 443 | HTTPS |

Имя входа — адрес целиком (`ivanov@example.ru`), пароль — пароль приложения. Подходит любой клиент IMAP и SMTP
(например, Thunderbird), правила фильтрации — клиент ManageSieve (дополнение Thunderbird Sieve, `sieve-connect`),
по JMAP — [Postman](https://github.com/Dicobraz421/Postman), календари и контакты — клиент CalDAV и CardDAV
(Thunderbird, iOS и macOS, DAVx5): адрес сервера он находит сам по `/.well-known/caldav` и `/.well-known/carddav`,
а по адресу почты — по записям SRV ([DNS домена](#dns-домена)). В тестовом варианте с `example.test` клиент
попросит принять сертификат: его выпустил тестовый центр (`deploy/compose/tls/ca.pem`).

Вход по Kerberos (SASL GSSAPI) вместо пароля — для SMTP, IMAP, POP3 и ManageSieve: keytab служб узла и секция
`auth.gssapi` (Ansible — `thepost_gssapi_keytab_src` и `thepost_gssapi`). Что завести в области Kerberos и как
проверить — [PREREQUISITES.md](PREREQUISITES.md#kerberos-gssapi).

## DNS домена

Чтобы почта приходила и не попадала в спам у получателей:

| Запись | Значение |
|---|---|
| `MX` домена | `10 mail.example.ru.` |
| `A` / `AAAA` сервера | адрес ВМ; обратная запись (PTR) адреса — `mail.example.ru` |
| `TXT` домена (SPF) | `v=spf1 mx -all` |
| `TXT _dmarc` | `v=DMARC1; p=quarantine; rua=mailto:postmaster@example.ru` |
| `TXT <селектор>._domainkey` (DKIM) | открытый ключ подписи, см. ниже |
| `SRV _caldavs._tcp`, `SRV _carddavs._tcp` домена | `0 1 443 mail.example.ru.` — клиент находит календари и контакты по адресу почты |
| `TXT _caldavs._tcp`, `TXT _carddavs._tcp` домена | `"path=/dav/"` |

**Подпись DKIM.** Закрытый ключ (PEM) хранится в OpenBao, в `config.yaml` — только ссылка на него:

```bash
openssl genrsa -out dkim.pem 2048
openssl rsa -in dkim.pem -pubout -outform DER | base64 -w0     # запись TXT: "v=DKIM1; k=rsa; p=<эта строка>"
bao kv put -mount=thepost dkim example.ru=@dkim.pem            # затем удалите dkim.pem с сервера
```

```yaml
smtp:
  dkim:
    domains:
      example.ru:
        keys:
          s2026: { algorithm: rsa-sha256, key: { secret: "thepost/dkim#example.ru" } }
```

Каким селектором подписывать, задаёт не `config.yaml`, а политика организации или домена (поле `dkim_selector`);
без неё письмо подписывается всеми ключами домена. Там же — лимиты отправки (`send_per_hour`, `rcpts_per_hour`,
`max_recipients`; без политики — 1000 писем и 2000 адресатов в час, 100 получателей в письме) и набор фильтров Milter
(`milter_profile`): `thepost admin policy set` — [руководство администратора](ADMIN-GUIDE.md#политики--policy). В
`config.yaml` остаются только ключи DKIM (`smtp.dkim.domains`) и адреса фильтров (`smtp.milter.filters`, наборы —
`smtp.milter.profiles`).

`thepost doctor` проверяет MX, SPF, DKIM, DMARC, MTA-STS, PTR и записи SRV календарей и контактов по публичному DNS
и подсказывает, чего не хватает.

### Входящая почта через шлюз

Если входящая почта приходит через доверенный шлюз с `authserv_id` и без XCLIENT/XFORWARD, The Post не проверяет письмо заново, а берёт результаты шлюза из `Authentication-Results` с этим authserv-id (иначе из ARC с печатью домена шлюза). Шлюз обязан выполнять RFC 8601 §5: удалять из входящих писем все `Authentication-Results` со своим authserv-id, которые поставил не он. Иначе отправитель впишет `dmarc=pass` сам, и приглашения iMIP от чужого имени будут приняты как подлинные. authserv-id должен быть доменом шлюза или его поддоменом, а печать ARC — ставиться ключом этого домена. Домен верхнего уровня не годится. Результаты `Authentication-Results` принимаются только с `header.from=` домена `From` письма.

Шлюз задаётся доверенным источником организации (Admin API `/api/v1/orgs/{org}/transport/sources`, поле `gateway.authserv_id`), в `config.yaml` его нет:

```bash
thepost admin transport source set gw --network 192.0.2.0/24 --authserv-id mx.example.ru --insecure
```

Без `--authserv-id` результатам шлюза не доверяют и письмо проверяется как от обычного клиента; `--xclient` включает передачу адреса исходного клиента (тогда проверки выполняются по нему).

## Kubernetes: Helm

Чарт — `deploy/helm/thepost`, до него — OpenBao и секрет TLS (порядок — в
[`deploy/README.md`](../deploy/README.md#kubernetes-helm)). Образ в ghcr.io закрытый: нужен секрет реестра с токеном
GitHub (`read:packages`), без `imagePullSecrets` чарт не устанавливается и подсказывает, что сделать:

```bash
kubectl -n thepost create secret docker-registry ghcr --docker-server=ghcr.io   --docker-username=<логин GitHub> --docker-password=<токен read:packages>
helm install thepost deploy/helm/thepost -n thepost --set 'imagePullSecrets[0].name=ghcr' -f <свои значения>
```

Тег образа по умолчанию — `appVersion` чарта: установка закреплена за выпуском. Другой тег — `--set image.tag=…`.

Письма в Kubernetes хранятся в S3: чарт задаёт `config.blob.url: s3://thepost-blob`, том пода — временный. В своих
значениях укажите `config.blob.s3` (адрес, ссылки на ключи, CA) и положите ключи в секрет `thepost/s3` —
[где лежат письма](#где-лежат-письма-диск-или-s3).

## Обновление

- **Ansible** — скачайте новый выпуск и повторите `ansible-playbook … -e thepost_binary_src=…`: узел перезапустится,
  миграции базы применятся сами.
- **Docker Compose** — `git pull` и `… --profile smb up -d --build` (с готовым образом — новая `<версия>` в
  `THEPOST_IMAGE` и `… up -d`).
- **Helm** — `git pull` и `helm upgrade thepost deploy/helm/thepost -n thepost --reuse-values`: тег образа — новый
  `appVersion` чарта.

Перед обновлением рабочего сервера сделайте внеочередную копию: `sudo systemctl start thepost-backup@full` (см. ниже).

## Резервное копирование и восстановление

Плейбук `smb.yml` сам включает резервное копирование (`thepost_backup: true`, отключить — `false`) готовыми
средствами по таймерам systemd:

- **база** (PostgreSQL) — [pgBackRest](https://pgbackrest.org/): журнал изменений (WAL) уходит в копию непрерывно,
  не реже раза в минуту; полная копия — в ночь на воскресенье, разностная — в остальные ночи. Восстановить можно
  состояние на любой момент за последние `thepost_backup_retention_days` суток (по умолчанию 7);
- **каталог писем** (`/var/lib/thepost/blob`, тела писем) — [restic](https://restic.net/) (по умолчанию: снимки,
  шифрование) или rsync (`thepost_backup_blob_tool: rsync`, зеркало): каждый час и после каждой копии базы.

Где лежат копии:

| Параметр инвентаря | По умолчанию | Что это |
|---|---|---|
| `thepost_backup_repo` | `posix` | `posix` — каталог на сервере, `s3` — объектное хранилище S3 (только HTTPS) |
| `thepost_backup_repo_path` | `/var/lib/pgbackrest` | каталог копий базы (или префикс в бакете S3) |
| `thepost_backup_s3_endpoint`, `thepost_backup_s3_bucket` | — | адрес S3 (`https://…`) и бакет |
| `thepost_backup_restic_repo` | `/var/backups/thepost/restic` | копии писем restic: каталог или `s3:https://<адрес>/<бакет>/<префикс>` |
| `thepost_backup_rsync_dest` | `/var/backups/thepost/blob-mirror` | зеркало rsync: каталог или `user@host:каталог` (SSH) |
| `thepost_backup_blob_schedule` | `hourly` | как часто копировать письма (пусто — только после копий базы) |

**Копия на том же диске не спасёт при отказе диска**: подключите к этим каталогам отдельный диск или сетевой том,
или храните копии в S3.

**Ключи.** Копии базы шифруются (AES-256), репозиторий restic — тоже. Ключ шифрования и пароль restic плейбук
создаёт в OpenBao при первом запуске (`thepost-backup/pgbackrest`, `thepost-backup/restic`; узлу The Post они
недоступны), на сервере они лежат только зашифрованными (`systemd-creds`). Ключи S3 положите в OpenBao сами — на
сервере, с токеном администратора OpenBao (root-токен — в `/root/openbao-init.json`, пока вы его не перенесли):

```bash
export BAO_ADDR=https://localhost:8200 BAO_CACERT=/etc/openbao/tls/ca.pem BAO_TOKEN=…
bao kv put -mount=thepost-backup s3 access_key_id=… secret_access_key=…
```

**Сохраните ключ шифрования и пароль restic вне сервера** (рядом с ключами восстановления OpenBao): если сервер
потерян целиком, без них копии не прочитать.

```bash
bao kv get -mount=thepost-backup -field=cipher_pass pgbackrest
bao kv get -mount=thepost-backup -field=password restic
```

Проверка на сервере (от root):

```bash
systemctl list-timers 'thepost-backup*'      # расписание
thepost-pgbackrest info                      # копии базы и архив WAL
thepost-restic snapshots                     # снимки каталога писем
journalctl -u 'thepost-backup*' --since today
systemctl start thepost-backup@full          # внеочередная полная копия (затем — копия писем)
```

### Восстановление

С управляющей машины — на момент `T` (время с часовым поясом; без `thepost_restore_target` — последнее состояние):

```bash
ansible-playbook -i inventory.yml deploy/ansible/restore.yml -e thepost_restore_confirm=true \
  -e "thepost_restore_target='2026-11-11 18:00:00+03'"
```

Плейбук останавливает узел и таймеры копий, возвращает базу на момент `T`, кладёт каталог писем из первой копии,
сделанной после `T` (без `T` — из последней; другой снимок — `-e thepost_restore_blob_snapshot=<ID>`), поверх
текущего, выставляет пароли учётных записей СУБД из OpenBao, запускает узел и проверяет `thepost verify`:
если у какого-то письма нет тела, плейбук остановится с ошибкой. Лишние тела (письма, пришедшие после `T`) удалит
`thepost verify --fix` в том же прогоне, если им больше суток, иначе — позже сам узел (поиск «сирот»). В конце —
новая полная копия.

Почему копия писем, сделанная после `T`, подходит: тело письма удаляется с диска не раньше окна W после удаления
последнего письма, которое на него ссылается (`blob.gc.window`, по умолчанию — глубина восстановления + 8 суток;
SRS 3.5). Поэтому потерять можно только письма, пришедшие после последней копии каталога писем (по умолчанию —
за последний час), и только при потере самого диска: `thepost verify` покажет их как повреждённые. Пустой или
пропавший каталог писем таймер не копирует. При потере диска указывайте `T` — момент перед потерей.

### Новый сервер вместо потерянного

Копия OpenBao (секреты узла, в том числе ключи DKIM) снимается вместе с копией базы — снимок Raft в то же
хранилище копий (`thepost_backup_openbao: true`, по умолчанию). Заранее храните **вне сервера**:
`/root/openbao-init.json`, `/etc/openbao/unseal.key` и пароль restic.

1. Установите новый сервер без копирования и без ожидания готовности узла:
   `ansible-playbook … deploy/ansible/smb.yml -e thepost_backup=false -e thepost_wait_ready=false`. Прогон завершится
   успешно с предупреждением «thepost не готов»: узел ждёт секретов прежнего сервера (ключ DKIM и другие), они
   вернутся из снимка OpenBao.
2. Верните копии по тем же путям и выполните `chown -R postgres:postgres /var/lib/pgbackrest`.
3. В новом OpenBao заведите только хранилище пароля копий:
   `bao secrets enable -path=thepost-backup -version=2 kv` и
   `bao kv put -mount=thepost-backup restic password=…` (для S3 — и его ключи). Ключ шифрования pgBackRest
   вернётся из снимка.
4. Восстановите: `ansible-playbook … deploy/ansible/restore.yml -e thepost_restore_confirm=true
   -e thepost_restore_openbao=true -e thepost_restore_openbao_init_src=<openbao-init.json>
   -e thepost_restore_openbao_static_key_src=<unseal.key>` (при распечатывании ключами Шамира —
   `thepost_restore_openbao_unseal_keys`). Снимок OpenBao ставится до восстановления базы.
5. Обычный прогон `smb.yml` — узел стартует, DKIM подписывает тем же ключом, `thepost verify` — без потерь; ключ TLS
   из снимка прогон сводит с сертификатом сервера (`internal` — новый сертификат к ключу, `files` — свой
   ключ новой версией секрета, `acme` — узел выпускает новый сам).

Без снимка OpenBao (`thepost_backup_openbao: false`) шаг 4 — без переменных `thepost_restore_openbao*`, а на шаге 3 в
новый OpenBao кладутся оба сохранённых ключа копий: `bao kv put -mount=thepost-backup pgbackrest cipher_pass=…` и
`bao kv put -mount=thepost-backup restic password=…`. Секреты узла (ключи DKIM и другие) при этом не возвращаются —
их заводят заново.

## Проверка подписи

Архивы, SBOM и образ подписаны [cosign](https://docs.sigstore.dev/) без ключей; рядом с каждым файлом лежит
`<файл>.sigstore.json`. Готовая команда проверки — в описании каждого выпуска, например:

```bash
f=thepost-$V-x86_64-unknown-linux-gnu.tar.gz
cosign verify-blob "$f" --bundle "$f.sigstore.json" \
  --certificate-identity 'https://github.com/Dicobraz/srvPost/.github/workflows/beta.yml@refs/heads/main' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

## Если что-то не так

- `thepost doctor` — первая проверка: что именно не так и как исправить.
- Журнал узла — `journalctl -u thepost` (в Docker — `docker compose … logs thepost`); пароли и токены в него не пишутся.
- Вопросы и ошибки — в [issues](https://github.com/Dicobraz/srvPost/issues).
