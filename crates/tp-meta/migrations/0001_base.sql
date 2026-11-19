-- Базовая схема метаданных 1.0 (META-71, решение 106 от 2026-11-12; SRS 3.1, 3.4, 3.6, 3.8).
-- Миграции 0001…0044 свернуты в одну базовую схему перед выпуском 1.0: новая база создаётся ею целиком,
-- обновление бета-установок — пересоздание базы, совместимость с прежними номерами миграций не нужна.
-- Изменения схемы после 1.0 — новыми миграциями с версией 2 и дальше; применённые версии не меняются.
--
-- Ключи таблиц ящика содержат tenant_id и account_id; внешних ключей между ящиками нет (шардирование, SRS 3.6).
-- RLS по tenant_id: транзакция начинается с set_config('app.tenant_id', $1, true) (= SET LOCAL, совместимо
-- с PgBouncer transaction); системные операции (GC BLOB, журнал событий) — set_config('app.all_tenants', 'on', true).
-- Владелец таблиц тоже подчиняется RLS (FORCE); суперпользователь и BYPASSRLS — нет (проверяет doctor).

CREATE FUNCTION tp_tenant_visible(t uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT t = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        OR coalesce(current_setting('app.all_tenants', true), '') = 'on'
$$;

-- ---------- Каталог (основная БД; на других шардах пуст) ----------

CREATE TABLE tenants (
    tenant_id  uuid PRIMARY KEY,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Организация по умолчанию (TenantId::DEFAULT).
INSERT INTO tenants (tenant_id, name) VALUES ('00000000-0000-0000-0000-000000000001', 'default');

-- Справочник шардов: в базовой поставке один шард — эта БД (dsn IS NULL). Учётные данные — из хранилища
-- секретов (CTR-15): адрес без пароля, пароль — ссылка `<путь>#<поле>` на секрет (SecretRef).
-- Площадка (геораспределение) и адрес реплики для фоновых чтений (ReadIntent::Stale, META-32).
CREATE TABLE shards (
    shard_id     integer PRIMARY KEY,
    name         text NOT NULL UNIQUE,
    dsn          text,
    accepts_new  boolean NOT NULL DEFAULT true,
    created_at   timestamptz NOT NULL DEFAULT now(),
    credentials  text
        CONSTRAINT shards_credentials_ref CHECK (
            credentials ~ '^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*#[A-Za-z0-9_.-]+$'
            AND credentials !~ '(^|/)\.{1,2}(/|#)'
            AND length(credentials) <= 512
        ),
    site         text CONSTRAINT shards_site_name CHECK (
        length(site) BETWEEN 1 AND 255 AND site !~ '[[:space:][:cntrl:]]'
    ),
    read_replica text CONSTRAINT shards_read_replica_without_password CHECK (
        read_replica !~ '^[A-Za-z][A-Za-z0-9+.-]*://[^/?#@]*:[^/?#@]*@'
        AND read_replica !~* '[?&]password='
    ),
    -- Пароль в адресе шарда (`user:password@` или параметр `password=`) запрещён: его отклоняет справочник.
    CONSTRAINT shards_dsn_without_password CHECK (
        dsn IS NULL OR (
            dsn !~ '^[A-Za-z][A-Za-z0-9+.-]*://[^/?#@]*:[^/?#@]*@'
            AND dsn !~* '[?&]password='
        )
    )
);

INSERT INTO shards (shard_id, name) VALUES (0, 'local');

CREATE TABLE domains (
    tenant_id  uuid NOT NULL REFERENCES tenants,
    domain_id  uuid NOT NULL,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    -- Вид принятого домена: полномочный или внутренняя ретрансляция (неизвестные адреса — на next_hop).
    kind       text NOT NULL DEFAULT 'authoritative' CHECK (kind IN ('authoritative', 'internal_relay')),
    next_hop   text CHECK (length(next_hop) BETWEEN 1 AND 255 AND next_hop !~ '[[:space:][:cntrl:]]'),
    PRIMARY KEY (tenant_id, domain_id),
    CONSTRAINT domains_next_hop CHECK ((kind = 'internal_relay') = (next_hop IS NOT NULL))
);

-- Имя домена уникально в инсталляции (маршрутизация входящей почты).
CREATE UNIQUE INDEX domains_name ON domains (lower(name));

-- Учётная запись. Счётчики ящика (ModSeq, нижняя граница журнала изменений, последний UIDVALIDITY) — в
-- mailbox_state на шарде ящика (триггер tp_mailbox_state_init создаёт строку в основной БД); внешних ключей
-- таблиц ящика к каталогу нет (учётные записи не удаляются, каскад не использовался).
CREATE TABLE accounts (
    tenant_id       uuid NOT NULL,
    account_id      uuid NOT NULL,
    domain_id       uuid NOT NULL,
    login           text NOT NULL,
    display_name    text NOT NULL DEFAULT '',
    external_id     text,
    enabled         boolean NOT NULL DEFAULT true,
    shard_id        integer NOT NULL DEFAULT 0 REFERENCES shards,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- Выбор пользователя trash.purge (PolicyResolver::set_user_trash_purge); действует только при
    -- user_can_choose правила администратора. NULL — не выбран.
    trash_purge     text CHECK (trash_purge IN ('hide', 'erase')),
    -- Состояние ящика (AccountStore::account_state): NULL — действует, иначе отключён до срока хранения.
    disabled_until  timestamptz,
    -- Псевдонимы каталога с целью — этой учётной записью: нижний регистр, без повторов, основного адреса и catch-all.
    aliases         text[] NOT NULL DEFAULT '{}',
    -- Вид учётной записи: пользователь или ресурс (переговорная, оборудование).
    kind            text NOT NULL DEFAULT 'user' CHECK (kind IN ('user', 'resource')),
    -- Окончательное удаление отключённого ящика начато (AccountStore::begin_removal): восстановление,
    -- подключение и перенос срока — Conflict. Только у отключённого (disabled_until задан).
    removing        boolean NOT NULL DEFAULT false,
    -- Признак «скрыта из книги «Организация»»: нет в GAL, вход и приём почты — как обычно.
    hidden_from_gal boolean NOT NULL DEFAULT false,
    -- Правила бронирования ресурса (BookingPolicy, JSON контракта) — только у вида `resource`; смена вида
    -- на пользователя снимает правила (триггер tp_booking_policy_kind).
    booking_policy  jsonb,
    -- Тип ресурса бронирования: помещение или оборудование; у пользователя — NULL.
    resource_type   text CHECK (resource_type IN ('room', 'equipment')),
    PRIMARY KEY (tenant_id, account_id),
    FOREIGN KEY (tenant_id, domain_id) REFERENCES domains,
    CONSTRAINT accounts_removing_disabled CHECK (NOT removing OR disabled_until IS NOT NULL),
    CONSTRAINT accounts_booking_policy_resource CHECK (booking_policy IS NULL OR kind = 'resource'),
    CONSTRAINT accounts_resource_type_kind CHECK ((kind = 'resource') = (resource_type IS NOT NULL))
);

CREATE UNIQUE INDEX accounts_login ON accounts (tenant_id, lower(login));
CREATE UNIQUE INDEX accounts_external ON accounts (tenant_id, external_id) WHERE external_id IS NOT NULL;
-- Побайтный порядок списка учётных записей (решение 21 2026-11-11-stage2-followups): AccountStore::list
-- упорядочивает имена входа в нижнем регистре по байтам (COLLATE "C"), как хранилище в памяти; курсор `after`
-- и префикс (диапазон) идут по этому индексу. Уникальность имён держит accounts_login (tenant_id, lower(login)).
CREATE INDEX accounts_login_c ON accounts (tenant_id, (lower(login) COLLATE "C"));
CREATE INDEX accounts_disabled ON accounts (disabled_until, account_id) WHERE disabled_until IS NOT NULL;

-- Членство узлов (CTR-14, META-16). Запись узла продлевает сам узел (Membership::heartbeat); живые —
-- с expires_at > now() по часам СУБД. Таблица без RLS: состав кластера общий для всех организаций.
-- Адрес служебного канала (`https://host:port`, пусто — запросов не принимает) и площадка (SiteId).
CREATE TABLE nodes (
    node_id    text PRIMARY KEY CHECK (length(node_id) BETWEEN 1 AND 255 AND node_id !~ '[[:space:][:cntrl:]]'),
    roles      text[] NOT NULL DEFAULT '{}',
    joined_at  timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    addr       text NOT NULL DEFAULT '' CHECK (length(addr) <= 2048 AND addr !~ '[[:space:][:cntrl:]]'),
    site       text NOT NULL DEFAULT 'default'
        CHECK (length(site) BETWEEN 1 AND 255 AND site !~ '[[:space:][:cntrl:]]')
);

CREATE INDEX nodes_expires_at ON nodes (expires_at);

-- Группы рассылки и очередь модерации (META-21; CONTRACTS.md#Groups; SRS 4.5).
-- Списки группы (участники, ограничение отправителей, модераторы) хранятся с позицией `pos`: группа читается
-- такой, какой записана (порядок и повторы). Вложенные группы и группы в списке отправителей — без внешнего
-- ключа: неизвестная группа (каталог ещё не синхронизирован, группа удалена) при раскрытии пропускается.
-- Учётные записи — без внешнего ключа: активность учётной записи проверяет вызывающий.
CREATE TABLE groups (
    tenant_id       uuid NOT NULL REFERENCES tenants,
    group_id        uuid NOT NULL,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 255 AND name !~ '[[:cntrl:]]'),
    address         text CHECK (octet_length(address) <= 320 AND position('@' IN address) > 0
                                AND address !~ '[[:space:][:cntrl:]]'),
    external_id     text CHECK (external_id <> '' AND octet_length(external_id) <= 255),
    senders         text NOT NULL DEFAULT 'anyone' CHECK (senders IN ('anyone', 'internal', 'only')),
    hidden_from_gal boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, group_id)
);

-- Адрес рассылки уникален в организации без учёта регистра; идентификатор каталога — уникален.
CREATE UNIQUE INDEX groups_address ON groups (tenant_id, lower(address)) WHERE address IS NOT NULL;
CREATE UNIQUE INDEX groups_external ON groups (tenant_id, external_id) WHERE external_id IS NOT NULL;

-- Участники: учётная запись или вложенная группа (ровно одно из двух).
CREATE TABLE group_members (
    tenant_id       uuid NOT NULL,
    group_id        uuid NOT NULL,
    pos             integer NOT NULL CHECK (pos >= 0),
    account_id      uuid,
    member_group_id uuid,
    CHECK ((account_id IS NULL) <> (member_group_id IS NULL)),
    PRIMARY KEY (tenant_id, group_id, pos),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups ON DELETE CASCADE
);

-- Ограничение `only`: разрешённые учётные записи и группы (участники — с раскрытием вложенных).
CREATE TABLE group_senders (
    tenant_id       uuid NOT NULL,
    group_id        uuid NOT NULL,
    pos             integer NOT NULL CHECK (pos >= 0),
    account_id      uuid,
    sender_group_id uuid,
    CHECK ((account_id IS NULL) <> (sender_group_id IS NULL)),
    PRIMARY KEY (tenant_id, group_id, pos),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups ON DELETE CASCADE
);

-- Модераторы: непусто — группа модерируемая.
CREATE TABLE group_moderators (
    tenant_id  uuid NOT NULL,
    group_id   uuid NOT NULL,
    pos        integer NOT NULL CHECK (pos >= 0),
    account_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, group_id, pos),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups ON DELETE CASCADE
);

-- Очередь модерации групп и правил потока почты (решение 9 2026-11-11-stage2-followups). Источник задержки —
-- ровно один: группа (group_id задан, `rule` пуст) или правило потока (group_id пуст, `rule` — имя правила).
-- Ссылку на объект письма учитывает вызывающий; удаление группы забирает её письма (`GroupStore::remove`
-- возвращает их вызывающему), поэтому внешний ключ — без каскада. Снимок модераторов письма (учётные записи
-- и группы, порядок как в письме) — `moderators`; исходные получатели конверта (адрес доставки одобренного
-- письма правила) — `recipients`.
CREATE TABLE group_held (
    tenant_id      uuid NOT NULL,
    held_id        uuid NOT NULL,
    group_id       uuid,
    sender         text NOT NULL,
    sender_account uuid,
    message_id     text,
    blob_hash      bytea NOT NULL CHECK (octet_length(blob_hash) = 32),
    blob_gen       bigint NOT NULL,
    size           bigint NOT NULL CHECK (size >= 0),
    held_at        timestamptz NOT NULL,
    rule           text
        CHECK (rule IS NULL OR (char_length(rule) BETWEEN 1 AND 255 AND rule !~ '[[:cntrl:]]')),
    moderators     jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(moderators) = 'array'),
    recipients     text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, held_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups,
    CONSTRAINT group_held_one_source CHECK ((group_id IS NULL) <> (rule IS NULL))
);

CREATE INDEX group_held_order ON group_held (tenant_id, held_at, held_id);
CREATE INDEX group_held_group ON group_held (tenant_id, group_id, held_at, held_id);

-- Роль администратора установки — явная запись (решение 117): её ставит `thepost admin init`
-- (`AccountStore::grant_installation_admin`), читает вход администратора по паролю
-- (`AccountStore::is_installation_admin`). Запись удаляется вместе с учётной записью.
CREATE TABLE installation_admins (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, account_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts ON DELETE CASCADE
);

-- Блокировки организации (AbuseBlocks). Субъект — ключ `subject`: `ip:<адрес>`, `net:<адрес>/<префикс>`,
-- `account:<uuid>`; адрес и подсеть — также `net` (cidr: адрес — /32 или /128) для поиска покрывающих подсетей.
-- Истёкшие строки не действуют; новая блокировка того же субъекта заменяет истёкшую. Срок — часы СУБД.
-- Без внешнего ключа на tenants: блокировки — служебные записи с ограниченным сроком.
CREATE TABLE abuse_blocks (
    tenant_id  uuid NOT NULL,
    subject    text NOT NULL CHECK (length(subject) BETWEEN 1 AND 128),
    kind       text NOT NULL CHECK (kind IN ('ip', 'net', 'account')),
    net        cidr,
    account_id uuid,
    until      timestamptz NOT NULL,
    reason     text NOT NULL CHECK (length(reason) <= 1024),
    blocked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject),
    CHECK ((kind = 'account') = (account_id IS NOT NULL) AND (kind = 'account') = (net IS NULL))
);

CREATE INDEX abuse_blocks_net ON abuse_blocks USING gist (net inet_ops) WHERE net IS NOT NULL;
CREATE INDEX abuse_blocks_until ON abuse_blocks (tenant_id, until);

-- Списки отправителей ящика (SenderLists): хранимый вид `SenderList::normalized`, `state` — JMAP state.
-- Учётную запись контракт не проверяет: внешнего ключа нет, строки удаляет tp-meta вместе с учётной записью.
CREATE TABLE sender_lists (
    tenant_id  uuid NOT NULL REFERENCES tenants,
    account_id uuid NOT NULL,
    state      bigint NOT NULL CHECK (state > 0),
    safe       text[] NOT NULL,
    blocked    text[] NOT NULL,
    PRIMARY KEY (tenant_id, account_id)
);

-- Почтовые контакты (ContactStore). Адрес уникален в организации без учёта регистра; `groups` — группы
-- рассылки по возрастанию без повторов (группы контракт не проверяет: состав задаёт каталог).
CREATE TABLE mail_contacts (
    tenant_id       uuid NOT NULL REFERENCES tenants,
    contact_id      uuid NOT NULL,
    display_name    text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 255),
    email           text NOT NULL CHECK (octet_length(email) <= 320),
    external_id     text CHECK (external_id <> ''),
    attributes      jsonb NOT NULL DEFAULT '{}',
    groups          uuid[] NOT NULL DEFAULT '{}',
    hidden_from_gal boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, contact_id)
);

CREATE UNIQUE INDEX mail_contacts_email ON mail_contacts (tenant_id, lower(email));
CREATE UNIQUE INDEX mail_contacts_external ON mail_contacts (tenant_id, external_id);
CREATE INDEX mail_contacts_groups ON mail_contacts USING gin (groups);

-- Подразделения (OrgStore): дерево, вышестоящее — в той же организации; удаление с вложенными запрещено.
CREATE TABLE org_units (
    tenant_id   uuid NOT NULL REFERENCES tenants,
    unit_id     uuid NOT NULL,
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    parent_id   uuid,
    external_id text CHECK (external_id <> ''),
    PRIMARY KEY (tenant_id, unit_id),
    FOREIGN KEY (tenant_id, parent_id) REFERENCES org_units
);

CREATE UNIQUE INDEX org_units_external ON org_units (tenant_id, external_id);

-- Оргатрибуты учётной записи; строка без заданных полей не хранится (`OrgAttributes::default()`).
CREATE TABLE org_attributes (
    tenant_id     uuid NOT NULL,
    account_id    uuid NOT NULL,
    department_id uuid,
    title         text CHECK (length(title) <= 255),
    manager_id    uuid,
    seniority     integer,
    attributes    jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, account_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, department_id) REFERENCES org_units ON DELETE SET NULL (department_id),
    FOREIGN KEY (tenant_id, manager_id) REFERENCES accounts ON DELETE SET NULL (manager_id),
    CHECK (manager_id IS DISTINCT FROM account_id)
);

CREATE INDEX org_attributes_department ON org_attributes (tenant_id, department_id);

-- Фильтры динамических групп (DynamicGroupStore): группа рассылки — в `groups`.
CREATE TABLE dynamic_groups (
    tenant_id uuid NOT NULL,
    group_id  uuid NOT NULL,
    filter    jsonb NOT NULL,
    contacts  boolean NOT NULL,
    PRIMARY KEY (tenant_id, group_id),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups ON DELETE CASCADE
);

-- Остановка синхронизации каталога при удалении больше порога учётных записей (SyncGate): одна запись на
-- организацию, её подтверждает администратор (Admin API), снимает синхронизация.
CREATE TABLE sync_holds (
    tenant_id   uuid PRIMARY KEY REFERENCES tenants,
    removed     bigint NOT NULL CHECK (removed >= 0),
    total       bigint NOT NULL CHECK (total >= 0),
    detected_at timestamptz NOT NULL,
    approved    boolean NOT NULL
);

-- Смена вида учётной записи на пользователя снимает правила бронирования.
CREATE FUNCTION tp_booking_policy_kind() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.booking_policy := NULL;
    RETURN NEW;
END
$$;

CREATE TRIGGER tp_booking_policy_kind BEFORE UPDATE OF kind ON accounts
    FOR EACH ROW WHEN (NEW.kind <> 'resource' AND NEW.booking_policy IS NOT NULL)
    EXECUTE FUNCTION tp_booking_policy_kind();

-- Представители учётной записи: доступ ко всем её календарям и планирование от её имени. Удаление любой из
-- учётных записей удаляет запись.
CREATE TABLE account_delegates (
    tenant_id          uuid NOT NULL,
    account_id         uuid NOT NULL,
    delegate_id        uuid NOT NULL,
    level              text NOT NULL CHECK (level IN ('read', 'write')),
    schedule_on_behalf boolean NOT NULL,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CHECK (delegate_id <> account_id),
    PRIMARY KEY (tenant_id, account_id, delegate_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, delegate_id) REFERENCES accounts ON DELETE CASCADE
);

-- Чьим представителем является учётная запись (`delegations`).
CREATE INDEX account_delegates_delegate ON account_delegates (tenant_id, delegate_id);

-- Политика общего доступа организации (SharingPolicy, JSON контракта); нет строки — политика по умолчанию.
CREATE TABLE sharing_policies (
    tenant_id  uuid PRIMARY KEY REFERENCES tenants,
    policy     jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Уведомления о доступе к коллекциям (JMAP `ShareNotification`, RFC 9670 §5): общие для узлов, видит только
-- получатель; удаление учётной записи-получателя удаляет её уведомления, состояние и журнал внешними ключами.

-- Состояние уведомлений получателя (JMAP `state`): растёт при каждой записи и удалении; нет строки — 0.
-- Изменения с `state <= floor` удалены из журнала: `since` ниже — `Conflict` (`cannotCalculateChanges`).
CREATE TABLE share_notification_state (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    state      bigint NOT NULL DEFAULT 0 CHECK (state >= 0),
    floor      bigint NOT NULL DEFAULT 0 CHECK (floor BETWEEN 0 AND state),
    PRIMARY KEY (tenant_id, account_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts ON DELETE CASCADE
);

-- Уведомление (не меняется: только запись и удаление). Права — как выданы, битовая маска: 1 — free_busy,
-- 2 — read, 4 — write, 8 — schedule, 16 — admin (0 — нет прав). Владелец и автор изменения — без внешних
-- ключей: уведомление переживает их удаление.
CREATE TABLE share_notifications (
    tenant_id          uuid NOT NULL,
    account_id         uuid NOT NULL,
    notification_id    uuid NOT NULL,
    created            timestamptz NOT NULL,
    changed_by_name    text NOT NULL,
    changed_by_email   text,
    changed_by_account uuid,
    object_type        text NOT NULL CHECK (object_type IN ('calendar', 'task_list', 'address_book')),
    owner_id           uuid NOT NULL,
    collection_id      uuid NOT NULL,
    old_rights         smallint NOT NULL CHECK (old_rights BETWEEN 0 AND 31),
    new_rights         smallint NOT NULL CHECK (new_rights BETWEEN 0 AND 31),
    name               text NOT NULL,
    CHECK (old_rights <> new_rights),
    PRIMARY KEY (tenant_id, account_id, notification_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES share_notification_state ON DELETE CASCADE
);

-- Срок хранения (`expire_notifications`): старшие первыми во всех организациях.
CREATE INDEX share_notifications_created ON share_notifications (created, notification_id);

-- Журнал состояний (`notification_changes`): запись (`created`) или удаление уведомления на шаге `state`.
-- `notice_created` — момент изменения прав уведомления: срок хранения убирает из журнала историю удалённых
-- уведомлений старше срока, поднимая `floor`.
CREATE TABLE share_notification_log (
    tenant_id       uuid NOT NULL,
    account_id      uuid NOT NULL,
    state           bigint NOT NULL CHECK (state > 0),
    notification_id uuid NOT NULL,
    created         boolean NOT NULL,
    notice_created  timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, account_id, state),
    FOREIGN KEY (tenant_id, account_id) REFERENCES share_notification_state ON DELETE CASCADE
);

CREATE INDEX share_notification_log_notice_created ON share_notification_log (notice_created);

-- Брендинг заказчика (решение 122): по строке на уровень — установка (`tenant_id IS NULL`, не больше одной
-- строки) и организация (`tenant_id` уникален). Все поля необязательны: незаданное берётся с уровня выше
-- (организация → установка → IT TASK, `BrandingLevels::effective`). Заданные роли — `roles`:
-- `{"light": {...}, "dark": {...}, "cli": {...}}`, имена ролей и цвета проверяет контракт. Байты знака —
-- в BLOB по пути `branding/<hash>.png` (`BrandLogo::path`), здесь — только описание; удаление организации
-- удаляет её набор.
CREATE TABLE branding (
    tenant_id     uuid UNIQUE REFERENCES tenants ON DELETE CASCADE,
    product_name  text CHECK (char_length(product_name) BETWEEN 1 AND 64),
    primary_color text CHECK (primary_color ~ '^#[0-9A-F]{6}$'),
    roles         jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(roles) = 'object'),
    logo_hash     bytea CHECK (octet_length(logo_hash) = 32),
    logo_size     bigint CHECK (logo_size BETWEEN 1 AND 262144),
    logo_width    integer CHECK (logo_width BETWEEN 1 AND 1024),
    logo_height   integer CHECK (logo_height BETWEEN 1 AND 1024),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    -- Знак задан целиком или не задан.
    CHECK ((logo_hash IS NULL) = (logo_size IS NULL)
       AND (logo_hash IS NULL) = (logo_width IS NULL)
       AND (logo_hash IS NULL) = (logo_height IS NULL))
);

-- Уровень установки — не больше одной строки (цель `ON CONFLICT` записи набора установки).
CREATE UNIQUE INDEX branding_installation ON branding ((tenant_id IS NULL)) WHERE tenant_id IS NULL;

-- `logo_in_use`: упомянут ли знак хоть одним уровнем.
CREATE INDEX branding_logo ON branding (logo_hash) WHERE logo_hash IS NOT NULL;

-- Политика доверия (решение 124; CTR-93, META-85): по строке на уровень — установка (tenant_id и group_id
-- NULL, не больше одной строки), организация (group_id IS NULL, уникальный tenant) и группа (уникальная
-- пара tenant и группа; удаление группы удаляет её политику). Клетки — cells в jsonb по схеме контракта
-- (TrustPolicy без доменных списков; новое поле политики — не миграция схемы клеток), схема клеток —
-- schema_version. Домены-партнёры и домены автопересылки — только у организации, отдельными таблицами.
-- RLS: строку установки читают все организации (installation_read), пишет её только системная транзакция.
CREATE TABLE trust_policies (
    tenant_id      uuid REFERENCES tenants ON DELETE CASCADE,
    group_id       uuid,
    cells          jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(cells) = 'object'),
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    -- Группа всегда с организацией: tenant_id IS NULL (установка) — только вместе с group_id IS NULL.
    CHECK (tenant_id IS NOT NULL OR group_id IS NULL),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, group_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX trust_policies_installation ON trust_policies ((tenant_id IS NULL)) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX trust_policies_org ON trust_policies (tenant_id) WHERE tenant_id IS NOT NULL AND group_id IS NULL;
CREATE UNIQUE INDEX trust_policies_group ON trust_policies (tenant_id, group_id) WHERE group_id IS NOT NULL;

-- Домены-партнёры организации (PeerKind::Partner): канонические имена (нижний регистр, A-label IDN —
-- проверяет контракт при записи, CHECK — страховка); partner_of — по первичному ключу.
CREATE TABLE trust_partner_domains (
    tenant_id  uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
    domain     text NOT NULL CHECK (domain = lower(domain)),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain)
);

-- Домены, куда разрешена автопересылка (при auto_forward = On); вид — как у партнёров.
CREATE TABLE trust_forward_domains (
    tenant_id  uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
    domain     text NOT NULL CHECK (domain = lower(domain)),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain)
);

-- ---------- Ящик: таблицы шарда ящика (без внешних ключей к каталогу) ----------

CREATE TABLE mailboxes (
    tenant_id      uuid NOT NULL,
    account_id     uuid NOT NULL,
    mailbox_id     uuid NOT NULL,
    parent_id      uuid,
    name           text NOT NULL,
    role           text CHECK (role IN ('inbox', 'archive', 'drafts', 'junk', 'sent', 'trash')),
    uid_validity   bigint NOT NULL CHECK (uid_validity BETWEEN 1 AND 4294967295),
    uid_next       bigint NOT NULL DEFAULT 1,
    highest_modseq bigint NOT NULL DEFAULT 0,
    subscribed     boolean NOT NULL DEFAULT true,
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, account_id, mailbox_id)
);

CREATE UNIQUE INDEX mailboxes_name ON mailboxes (tenant_id, account_id, parent_id, name) NULLS NOT DISTINCT;
CREATE UNIQUE INDEX mailboxes_role ON mailboxes (tenant_id, account_id, role) WHERE role IS NOT NULL;

-- Элемент корзины — письмо с trashed_at (перенос в корзину: исходная папка trashed_from, момент trashed_at).
-- Срок окончательного удаления фиксируется при переносе: изменение политики действует на элементы,
-- удалённые после него; TrashStore::defer переносит срок (Legal Hold).
-- Скрытое письмо (TrashStore::purge с hide; erase под Legal Hold): остаётся в корзине (mailbox_id, UID, срок
-- trash_expires_at), но не видно пользователю — его нет в MessageStore, в счётчиках папки и в квоте.
-- Видит и восстанавливает его администратор (TrashStore::list_hidden, restore); срок истекает как обычно.
CREATE TABLE messages (
    tenant_id       uuid NOT NULL,
    account_id      uuid NOT NULL,
    message_id      uuid NOT NULL,
    mailbox_id      uuid NOT NULL,
    uid             bigint NOT NULL,
    modseq          bigint NOT NULL,
    size            bigint NOT NULL,
    received_at     timestamptz NOT NULL,
    flags           text[] NOT NULL DEFAULT '{}',
    skeleton_hash   bytea NOT NULL,
    skeleton_gen    bigint NOT NULL,
    thread_key      text NOT NULL DEFAULT '',
    meta            jsonb NOT NULL,
    trashed_from    uuid,
    trashed_at      timestamptz,
    trash_expires_at timestamptz,
    hidden_at       timestamptz,
    PRIMARY KEY (tenant_id, account_id, message_id),
    CONSTRAINT messages_hidden_in_trash CHECK (hidden_at IS NULL OR trashed_at IS NOT NULL)
);

CREATE UNIQUE INDEX messages_uid ON messages (tenant_id, account_id, mailbox_id, uid);
CREATE INDEX messages_modseq ON messages (tenant_id, account_id, mailbox_id, modseq);
CREATE INDEX messages_thread ON messages (tenant_id, account_id, thread_key);
CREATE INDEX messages_trash_expires ON messages (trash_expires_at) WHERE trash_expires_at IS NOT NULL;
CREATE INDEX messages_trashed ON messages (tenant_id, account_id, trashed_at) WHERE trashed_at IS NOT NULL;
CREATE INDEX messages_hidden ON messages (tenant_id, account_id, trashed_at) WHERE hidden_at IS NOT NULL;

-- Объекты частей письма (модель «скелет + части»); объект принадлежит организации письма.
CREATE TABLE message_parts (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    message_id uuid NOT NULL,
    part       text NOT NULL,
    blob_hash  bytea NOT NULL,
    blob_gen   bigint NOT NULL,
    size       bigint NOT NULL,
    PRIMARY KEY (tenant_id, account_id, message_id, part),
    FOREIGN KEY (tenant_id, account_id, message_id) REFERENCES messages ON DELETE CASCADE
);

-- Журнал изменений (IMAP QRESYNC, JMAP /changes). object: 'message' | 'mailbox';
-- op 'moved' — письмо сменило папку с тем же message_id (корзина): из from_mailbox_id/from_uid в mailbox_id/uid.
CREATE TABLE changelog (
    tenant_id       uuid NOT NULL,
    account_id      uuid NOT NULL,
    modseq          bigint NOT NULL,
    object          text NOT NULL CHECK (object IN ('message', 'mailbox')),
    object_id       uuid NOT NULL,
    op              text NOT NULL CHECK (op IN ('created', 'updated', 'destroyed', 'moved')),
    mailbox_id      uuid,
    uid             bigint,
    from_mailbox_id uuid,
    from_uid        bigint,
    PRIMARY KEY (tenant_id, account_id, modseq, object, object_id, op)
);

-- Состояние ящика на его шарде: счётчики, границы журналов и состояния JMAP. Схема ядра применяется на
-- каждом шарде справочника; данные каталога — только в основной БД (шард 0). Транзакции ящика не обращаются
-- к каталогу. Строка счётчика блокируется до фиксации, поэтому номера изменений видны по порядку.
CREATE TABLE mailbox_state (
    tenant_id             uuid NOT NULL,
    account_id            uuid NOT NULL,
    -- Счётчик ModSeq учётной записи (CONTRACTS.md#Metadata), общий для писем, календарей и планирования.
    modseq                bigint NOT NULL DEFAULT 0,
    -- Изменения с modseq <= changelog_floor удалены из журнала: since ниже — Conflict.
    changelog_floor       bigint NOT NULL DEFAULT 0,
    -- Последний выданный UIDVALIDITY папок (строго растёт).
    uid_validity_last     bigint NOT NULL DEFAULT 0,
    -- Надгробия вида с modseq <= границы очищены: since ниже (кроме 0) — Conflict.
    dav_calendar_floor    bigint NOT NULL DEFAULT 0,
    dav_addressbook_floor bigint NOT NULL DEFAULT 0,
    -- Состояние вида (JMAP state): наибольший ModSeq изменений календарей и адресных книг.
    dav_calendar_state    bigint NOT NULL DEFAULT 0,
    dav_addressbook_state bigint NOT NULL DEFAULT 0,
    -- Состояние скриптов и автоответа (JMAP state, версия кэша программ tp-sieve): растёт при каждом изменении.
    sieve_state           bigint NOT NULL DEFAULT 0,
    -- ModSeq последнего изменения входящих планирования (запись или удаление); 0 — изменений не было.
    dav_inbox_state       bigint NOT NULL DEFAULT 0,
    -- Состояние отправок (JMAP state EmailSubmission): растёт при каждом изменении.
    submission_state      bigint NOT NULL DEFAULT 0,
    -- Надгробия с состоянием <= submission_floor удалены: изменения от более раннего состояния — Conflict.
    submission_floor      bigint NOT NULL DEFAULT 0,
    -- Надгробия входящих с modseq <= границы очищены: since ниже (кроме 0) — Conflict.
    dav_inbox_floor       bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, account_id)
);

-- Учётная запись основной БД получает состояние ящика при создании; на другом шарде его создаёт
-- tp-meta вместе с системными папками.
CREATE FUNCTION tp_mailbox_state_init() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO mailbox_state (tenant_id, account_id) VALUES (NEW.tenant_id, NEW.account_id)
    ON CONFLICT DO NOTHING;
    RETURN NULL;
END
$$;

CREATE TRIGGER tp_mailbox_state_init AFTER INSERT ON accounts
    FOR EACH ROW WHEN (NEW.shard_id = 0) EXECUTE FUNCTION tp_mailbox_state_init();

-- ACL папок (RFC 4314). Запись: идентификатор (имя входа, имя группы, `anyone`; с `-` в начале —
-- отрицательные права RFC 4314 §2) и права — строка `lrswipkxtea` в каноническом порядке. Пустые права
-- не хранятся. Связь только внутри учётной записи-владельца (папка удаляется — её ACL тоже).
CREATE TABLE mailbox_acl (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    mailbox_id uuid NOT NULL,
    identifier text NOT NULL CHECK (length(identifier) BETWEEN 1 AND 255
                                    AND identifier !~ '[[:space:][:cntrl:]]' AND identifier <> '-'),
    rights     text NOT NULL CHECK (rights ~ '^l?r?s?w?i?p?k?x?t?e?a?$' AND rights <> ''),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, account_id, mailbox_id, identifier),
    FOREIGN KEY (tenant_id, account_id, mailbox_id) REFERENCES mailboxes ON DELETE CASCADE
);

-- Общие папки субъекта: по идентификатору.
CREATE INDEX mailbox_acl_identifier ON mailbox_acl (tenant_id, identifier);

-- Делегирование отправки от адресов учётной записи-владельца: представитель (имя входа или группы) и вид права.
CREATE TABLE send_delegations (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    delegate   text NOT NULL CHECK (length(delegate) BETWEEN 1 AND 255
                                    AND delegate !~ '[[:space:][:cntrl:]]' AND left(delegate, 1) <> '-'),
    kind       text NOT NULL CHECK (kind IN ('send_as', 'send_on_behalf')),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, account_id, delegate)
);

CREATE INDEX send_delegations_delegate ON send_delegations (tenant_id, delegate);

-- Манифесты поисковых индексов (SRS 4.6). Одна строка на учётную запись: версия (CAS put_manifest; растёт
-- и при запросе перестройки), схема индекса, сегменты (jsonb: [{path, size, docs}]) и запрошенная перестройка.
-- Нет строки — индекса нет (версия 0).
CREATE TABLE index_manifests (
    tenant_id            uuid NOT NULL,
    account_id           uuid NOT NULL,
    version              bigint NOT NULL CHECK (version > 0),
    schema_version       bigint NOT NULL CHECK (schema_version BETWEEN 0 AND 4294967295),
    segments             jsonb NOT NULL DEFAULT '[]',
    rebuild_requested_at timestamptz,
    rebuild_reason       text CHECK (rebuild_reason IN ('admin', 'corrupt', 'restore')),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, account_id),
    CHECK ((rebuild_requested_at IS NULL) = (rebuild_reason IS NULL))
);

-- pending_rebuilds: запрошенные перестройки и индексы старой схемы (по всем организациям).
CREATE INDEX index_manifests_rebuild ON index_manifests (rebuild_requested_at) WHERE rebuild_requested_at IS NOT NULL;
CREATE INDEX index_manifests_schema ON index_manifests (schema_version);

-- Пароли приложений (SRS 5.1): хэш (argon2id, PHC-строка), значение не хранится. Отозванные пароли
-- остаются в списке (Admin API показывает историю); удаляются вместе с учётной записью.
CREATE TABLE app_passwords (
    tenant_id   uuid NOT NULL,
    account_id  uuid NOT NULL,
    password_id text NOT NULL CHECK (length(password_id) BETWEEN 1 AND 64
                                     AND password_id !~ '[[:space:][:cntrl:]]'),
    label       text NOT NULL CHECK (length(label) <= 255 AND label !~ '[[:cntrl:]]'),
    hash        text NOT NULL CHECK (hash <> ''),
    created_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    PRIMARY KEY (tenant_id, account_id, password_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts ON DELETE CASCADE
);

-- Календари и контакты (SRS 4.4; CONTRACTS.md#Dav): коллекции, объекты, надгробия. Тела объектов
-- (iCalendar, vCard) — в PostgreSQL, не в BLOB (SRS 3.1). Номер изменения — из счётчика
-- mailbox_state.modseq, общего с письмами.
--
-- Граница очищенных надгробий хранится по виду (учётная запись) и по коллекции: токен полной синхронизации
-- (состояние вида или коллекции) не ниже своей границы, поэтому очистка одного вида или одной коллекции не
-- делает устаревшими токены других.
CREATE TABLE dav_collections (
    tenant_id      uuid NOT NULL,
    account_id     uuid NOT NULL,
    collection_id  uuid NOT NULL,
    kind           text NOT NULL CHECK (kind IN ('calendar', 'address_book')),
    -- Сегмент URL; уникален среди коллекций вида учётной записи.
    name           text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 255),
    display_name   text NOT NULL,
    description    text,
    color          text,
    sort_order     bigint NOT NULL DEFAULT 0 CHECK (sort_order BETWEEN 0 AND 4294967295),
    timezone       text,
    -- Допустимые компоненты объектов: VEVENT, VTODO, VJOURNAL, VCARD.
    components     text[] NOT NULL CHECK (cardinality(components) > 0),
    -- ModSeq создания, последнего изменения свойств, последнего изменения коллекции или её объектов (CTag).
    created_modseq bigint NOT NULL,
    props_modseq   bigint NOT NULL,
    modseq         bigint NOT NULL,
    -- Число объектов (лимит meta.dav.max_objects без подсчёта строк).
    object_count   integer NOT NULL DEFAULT 0 CHECK (object_count >= 0),
    -- Надгробия объектов коллекции с modseq <= границы очищены: since ниже (кроме 0) — Conflict.
    tombstone_floor bigint NOT NULL DEFAULT 0,
    -- Календарь не влияет на занятость (RFC 6638 schedule-calendar-transp: transparent).
    transparent     boolean NOT NULL DEFAULT false,
    -- Коллекция по умолчанию своего вида: не больше одной на вид у учётной записи (индекс ниже).
    is_default      boolean NOT NULL DEFAULT false,
    -- Подписка и видимость (JMAP isSubscribed, isVisible).
    subscribed      boolean NOT NULL DEFAULT true,
    visible         boolean NOT NULL DEFAULT true,
    -- Оповещения по умолчанию календаря: текст JSON-объекта Id[Alert] JSCalendar; NULL — нет.
    alerts_with_time text CHECK (octet_length(alerts_with_time) <= 8192),
    alerts_without_time text CHECK (octet_length(alerts_without_time) <= 8192),
    PRIMARY KEY (tenant_id, account_id, collection_id)
);

CREATE UNIQUE INDEX dav_collections_name ON dav_collections (tenant_id, account_id, kind, name);
CREATE UNIQUE INDEX dav_collections_default ON dav_collections (tenant_id, account_id, kind) WHERE is_default;

CREATE TABLE dav_objects (
    tenant_id      uuid NOT NULL,
    account_id     uuid NOT NULL,
    object_id      uuid NOT NULL,
    collection_id  uuid NOT NULL,
    -- Имя ресурса — сегмент URL.
    name           text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 255),
    uid            text NOT NULL CHECK (octet_length(uid) BETWEEN 1 AND 1024),
    etag           text NOT NULL CHECK (octet_length(etag) BETWEEN 1 AND 64),
    component      text NOT NULL CHECK (component IN ('VEVENT', 'VTODO', 'VJOURNAL', 'VCARD')),
    -- Интервал с развёрнутыми повторами (UTC): span_start NULL — без дат, span_end NULL — бесконечный.
    span_start     timestamptz,
    span_end       timestamptz,
    body           text NOT NULL,
    created_modseq bigint NOT NULL,
    modseq         bigint NOT NULL,
    -- Schedule-Tag объекта планирования (RFC 6638 §3.2) без кавычек; NULL — объект без планирования.
    schedule_tag   text CHECK (octet_length(schedule_tag) BETWEEN 1 AND 64),
    -- Повторяющееся событие (в теле RRULE или RDATE): строк dav_busy нет, занятость разворачивается из тела
    -- при запросе (решение 59).
    recurring      boolean NOT NULL DEFAULT false
        CHECK (NOT recurring OR component = 'VEVENT'),
    -- Поисковые строки контакта (ObjectIndex::search): нижний регистр; у объектов календаря — пусто.
    -- Поиск — по вхождению подстроки среди объектов одной коллекции (без расширений СУБД, SRS 3.1).
    search         text[] NOT NULL DEFAULT '{}' CHECK (cardinality(search) <= 64),
    -- ModSeq появления в нынешней коллекции: создание или перенос (created_modseq перенос не меняет).
    placed_modseq  bigint NOT NULL,
    -- Признак «поисковые строки не посчитаны» (пересчёт — PgMeta::reindex_cards); значим только у VCARD.
    search_pending boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, account_id, object_id),
    FOREIGN KEY (tenant_id, account_id, collection_id) REFERENCES dav_collections ON DELETE CASCADE,
    CHECK (span_end IS NULL OR (span_start IS NOT NULL AND span_end >= span_start))
);

CREATE UNIQUE INDEX dav_objects_name ON dav_objects (tenant_id, account_id, collection_id, name);
CREATE UNIQUE INDEX dav_objects_uid ON dav_objects (tenant_id, account_id, collection_id, uid);
-- Запрос time-range: кандидаты по началу интервала (без расширений СУБД, SRS 3.1).
CREATE INDEX dav_objects_span ON dav_objects (tenant_id, account_id, collection_id, span_start, span_end);
-- Изменения коллекции (sync-collection) и учётной записи (JMAP /changes).
CREATE INDEX dav_objects_collection_modseq ON dav_objects (tenant_id, account_id, collection_id, modseq);
CREATE INDEX dav_objects_modseq ON dav_objects (tenant_id, account_id, modseq);
-- Запрос занятости: повторяющиеся события учётных записей (их мало — частичный индекс).
CREATE INDEX dav_objects_recurring ON dav_objects (tenant_id, account_id) WHERE recurring;
-- Непосчитанные карточки: после пересчёта индекс пуст, повторный запуск — один пустой просмотр на шард.
CREATE INDEX dav_objects_search_pending ON dav_objects (tenant_id, account_id, object_id)
    WHERE search_pending AND component = 'VCARD';

-- Надгробия удалённых объектов и коллекций — до очистки старше meta.dav.tombstone_ttl.
CREATE TABLE dav_tombstones (
    tenant_id     uuid NOT NULL,
    account_id    uuid NOT NULL,
    -- У каждого удаления свой ModSeq.
    modseq        bigint NOT NULL,
    kind          text NOT NULL CHECK (kind IN ('calendar', 'address_book')),
    collection_id uuid NOT NULL,
    -- Удалённый объект; NULL — надгробие самой коллекции.
    object_id     uuid,
    -- Имя ресурса или коллекции.
    name          text NOT NULL,
    deleted_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, account_id, modseq)
);

CREATE INDEX dav_tombstones_collection ON dav_tombstones (tenant_id, account_id, collection_id, modseq);
CREATE INDEX dav_tombstones_deleted ON dav_tombstones (deleted_at);

-- Индекс занятости объекта: вхождения неповторяющихся событий с развёрнутыми повторами (повторяющиеся
-- разворачиваются при запросе, строки в индексе — только у неповторяющихся; META-54, решение 59).
-- Строки заменяются целиком при записи объекта и уходят вместе с ним.
CREATE TABLE dav_busy (
    tenant_id     uuid NOT NULL,
    account_id    uuid NOT NULL,
    object_id     uuid NOT NULL,
    -- Порядок периода в индексе объекта: индекс читается как записан.
    ord           integer NOT NULL CHECK (ord >= 0),
    -- Коллекция объекта: прозрачность календаря — без обращения к dav_objects.
    collection_id uuid NOT NULL,
    -- Период [busy_start, busy_end) в UTC.
    busy_start    timestamptz NOT NULL,
    busy_end      timestamptz NOT NULL,
    kind          text NOT NULL CHECK (kind IN ('busy', 'tentative', 'unavailable')),
    PRIMARY KEY (tenant_id, account_id, object_id, ord),
    FOREIGN KEY (tenant_id, account_id, object_id) REFERENCES dav_objects ON DELETE CASCADE,
    CHECK (busy_end > busy_start)
);

-- Занятость учётных записей в интервале: кандидаты по концу периода (прошедшие отсекаются индексом).
CREATE INDEX dav_busy_range ON dav_busy (tenant_id, account_id, busy_end, busy_start);

-- Входящие планирования (schedule-inbox, RFC 6638 §2.2): сообщения iTIP учётной записи. UID не уникален
-- (REQUEST, затем CANCEL); в коллекции и их изменения не входят, надгробия — в dav_inbox_tombstones.
CREATE TABLE dav_inbox (
    tenant_id      uuid NOT NULL,
    account_id     uuid NOT NULL,
    item_id        uuid NOT NULL,
    -- Имя ресурса — сегмент URL.
    name           text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 255),
    -- Метод iTIP (RFC 5546): REQUEST, REPLY, CANCEL, ...
    method         text NOT NULL,
    uid            text NOT NULL CHECK (octet_length(uid) BETWEEN 1 AND 1024),
    -- Адрес отправителя без mailto:.
    sender         text NOT NULL CHECK (octet_length(sender) BETWEEN 1 AND 320),
    body           text NOT NULL,
    etag           text NOT NULL CHECK (octet_length(etag) BETWEEN 1 AND 64),
    -- ModSeq последней записи: порядок поступления.
    modseq         bigint NOT NULL,
    -- Время первой записи ресурса (InboxItem::received_at): перезапись его не меняет.
    received_at    timestamptz NOT NULL DEFAULT now(),
    -- ModSeq первой записи: created или updated в inbox_changes.
    created_modseq bigint NOT NULL,
    PRIMARY KEY (tenant_id, account_id, item_id)
);

CREATE UNIQUE INDEX dav_inbox_name ON dav_inbox (tenant_id, account_id, name);
CREATE INDEX dav_inbox_modseq ON dav_inbox (tenant_id, account_id, modseq);

-- Надгробия входящих планирования (JMAP CalendarEventNotification/changes): время поступления и ModSeq
-- создания ресурса. Номера — из счётчика mailbox_state.modseq; очистка старше meta.dav.tombstone_ttl
-- поднимает mailbox_state.dav_inbox_floor.
CREATE TABLE dav_inbox_tombstones (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    -- У каждого удаления свой ModSeq.
    modseq     bigint NOT NULL,
    item_id    uuid NOT NULL,
    deleted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, account_id, modseq)
);

CREATE INDEX dav_inbox_tombstones_deleted ON dav_inbox_tombstones (deleted_at);

-- Скрипты Sieve учётной записи: имя (RFC 5804 §1.6), до 128 символов. Текст хранилище не разбирает:
-- его проверяет tp-sieve до записи.
CREATE TABLE sieve_scripts (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    name       text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 128),
    script     text NOT NULL,
    active     boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, account_id, name)
);

-- Активный скрипт учётной записи — не больше одного.
CREATE UNIQUE INDEX sieve_scripts_active ON sieve_scripts (tenant_id, account_id) WHERE active;

-- Скрипт организации: выполняется до скрипта пользователя у всех учётных записей организации.
CREATE TABLE sieve_org_scripts (
    tenant_id  uuid PRIMARY KEY REFERENCES tenants ON DELETE CASCADE,
    script     text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Автоответ учётной записи (модель JMAP VacationResponse, RFC 8621 §8); нет строки — выключен. Внешний
-- текст (CTR-93, решение 124 г, RFC 3834): чужим (`PeerKind` не `Own`) ответ идёт только им и только если
-- задан; все внешние поля NULL — наружу ничего не уходит.
CREATE TABLE vacation (
    tenant_id          uuid NOT NULL,
    account_id         uuid NOT NULL,
    enabled            boolean NOT NULL,
    from_at            timestamptz,
    to_at              timestamptz,
    subject            text,
    text_body          text,
    html_body          text,
    external_subject   text,
    external_text_body text,
    external_html_body text,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, account_id),
    CHECK (from_at IS NULL OR to_at IS NULL OR from_at <= to_at)
);

-- Журнал отправленных автоответов (RFC 5230 `:days`, `:handle`). Ключ — SHA-256 от «отправитель NUL handle»:
-- адрес отправителя открытым текстом не хранится, длина ключа не зависит от длины `:handle`. Записи старше
-- meta.sieve.vacation_log_ttl удаляет роль maintenance.
CREATE TABLE vacation_log (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    digest     bytea NOT NULL CHECK (octet_length(digest) = 32),
    -- Время последнего отправленного автоответа этому отправителю по этому `:handle`.
    replied_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, account_id, digest)
);

CREATE INDEX vacation_log_replied ON vacation_log (replied_at);

-- Отправки JMAP (CONTRACTS.md#Identity и EmailSubmission): записи `email_submissions`, надгробия удалённых
-- `email_submission_tombstones` (для `EmailSubmission/changes`), состояние и нижняя граница истории — в
-- `mailbox_state`.
CREATE TABLE email_submissions (
    tenant_id     uuid NOT NULL,
    account_id    uuid NOT NULL,
    id            text NOT NULL CHECK (octet_length(id) BETWEEN 1 AND 64),
    identity      text NOT NULL CHECK (octet_length(identity) BETWEEN 1 AND 64),
    email_id      uuid NOT NULL,
    mail_from     text NOT NULL,
    rcpt_to       text[] NOT NULL,
    send_at       timestamptz NOT NULL,
    undo_status   text NOT NULL CHECK (undo_status IN ('pending', 'final', 'canceled')),
    -- Статусы получателей: массив пар [адрес, SubmitStatus] в порядке записи.
    delivery      jsonb NOT NULL DEFAULT '[]',
    queue_id      uuid,
    -- Состояние при создании и при последнем изменении.
    created_state bigint NOT NULL,
    changed_state bigint NOT NULL,
    PRIMARY KEY (tenant_id, account_id, id)
);

CREATE INDEX email_submissions_order ON email_submissions (tenant_id, account_id, send_at, id);
CREATE INDEX email_submissions_changed ON email_submissions (tenant_id, account_id, changed_state);
CREATE INDEX email_submissions_due ON email_submissions (send_at, id) WHERE undo_status = 'pending';
CREATE INDEX email_submissions_done ON email_submissions (send_at, id) WHERE undo_status <> 'pending';

CREATE TABLE email_submission_tombstones (
    tenant_id       uuid NOT NULL,
    account_id      uuid NOT NULL,
    id              text NOT NULL,
    created_state   bigint NOT NULL,
    destroyed_state bigint NOT NULL,
    destroyed_at    timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, account_id, id)
);

CREATE INDEX email_submission_tombstones_state
    ON email_submission_tombstones (tenant_id, account_id, destroyed_state);
CREATE INDEX email_submission_tombstones_at ON email_submission_tombstones (destroyed_at);

-- Права на коллекции учётной записи-владельца: субъект (имя входа, имя группы, `anyone`; отрицательных прав
-- нет) и права, как выданы, без включённых младших. Пустые права не хранятся. Лежит на шарде ящика рядом с
-- коллекцией: удаление коллекции удаляет записи.
CREATE TABLE collection_acl (
    tenant_id     uuid NOT NULL,
    account_id    uuid NOT NULL,
    collection_id uuid NOT NULL,
    identifier    text NOT NULL CHECK (length(identifier) BETWEEN 1 AND 255
                                       AND identifier !~ '[[:space:][:cntrl:]]' AND left(identifier, 1) <> '-'),
    free_busy     boolean NOT NULL,
    read          boolean NOT NULL,
    write         boolean NOT NULL,
    schedule      boolean NOT NULL,
    admin         boolean NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    CHECK (free_busy OR read OR write OR schedule OR admin),
    PRIMARY KEY (tenant_id, account_id, collection_id, identifier),
    FOREIGN KEY (tenant_id, account_id, collection_id) REFERENCES dav_collections ON DELETE CASCADE
);

-- Чужие коллекции субъекта (`shared_with`): по идентификатору.
CREATE INDEX collection_acl_identifier ON collection_acl (tenant_id, identifier);

-- ---------- BLOB (SRS 3.2, 3.4) ----------

-- Одна строка на хэш в организации. state 'deleted' — надгробие после finalize_delete: хранит поколение,
-- чтобы загрузка, начатая до удаления, получила Bumped; удаляется по истечении срока (BlobIndexConfig).
-- `thepost verify` отмечает запись `live`, у которой объекта нет в хранилище или размер не совпадает
-- (damaged_at); запись остаётся `live`, время первой пометки сохраняется.
-- compression: `none` — объект хранится как есть, `zstd` — кадр zstd исходного содержимого; хэш и размер
-- в учёте — от исходного содержимого.
CREATE TABLE blobs (
    tenant_id   uuid NOT NULL,
    hash        bytea NOT NULL CHECK (octet_length(hash) = 32),
    gen         bigint NOT NULL,
    refcnt      bigint NOT NULL CHECK (refcnt >= 0),
    state       text NOT NULL DEFAULT 'live' CHECK (state IN ('live', 'deleting', 'deleted')),
    size        bigint NOT NULL,
    zero_since  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now(),
    damaged_at  timestamptz,
    compression text NOT NULL DEFAULT 'none'
        CONSTRAINT blobs_compression CHECK (compression IN ('none', 'zstd')),
    PRIMARY KEY (tenant_id, hash)
);

CREATE INDEX blobs_gc ON blobs (zero_since) WHERE refcnt = 0;

-- ---------- Очередь исходящей почты (SRS 4.1) ----------

-- Запись — письмо (один объект BLOB) и его получатели. Захват записи узлом — лиза `lease_until` с номером
-- захвата `fencing`; время сравнивается с `now` вызывающего (тестовые часы), не с часами СУБД.
-- `next_attempt` записи — ближайший срок попытки незавершённых получателей (поддерживает реализация):
-- по нему claim выбирает записи по индексу. Запись, все получатели которой завершены, удаляется.
CREATE TABLE queue (
    tenant_id    uuid NOT NULL,
    queue_id     uuid PRIMARY KEY,
    blob_hash    bytea NOT NULL CHECK (octet_length(blob_hash) = 32),
    blob_gen     bigint NOT NULL,
    size         bigint NOT NULL CHECK (size >= 0),
    mail_from    text NOT NULL,
    envid        text,
    ret          text CHECK (ret IN ('full', 'hdrs')),
    queued_at    timestamptz NOT NULL,
    next_attempt timestamptz NOT NULL,
    fencing      bigint NOT NULL DEFAULT 0,
    lease_until  timestamptz
);

CREATE INDEX queue_next_attempt ON queue (next_attempt);

-- notify: NULL — не задан; иначе битовая маска 1 = SUCCESS, 2 = FAILURE, 4 = DELAY (0 — NEVER).
CREATE TABLE queue_rcpts (
    tenant_id    uuid NOT NULL,
    queue_id     uuid NOT NULL REFERENCES queue ON DELETE CASCADE,
    ord          integer NOT NULL,
    address      text NOT NULL,
    notify       smallint CHECK (notify BETWEEN 0 AND 7),
    orcpt        text,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'delivered', 'failed')),
    next_attempt timestamptz NOT NULL,
    attempts     integer NOT NULL DEFAULT 0,
    last_error   text,
    reply        text,
    PRIMARY KEY (queue_id, address)
);

CREATE INDEX queue_rcpts_pending ON queue_rcpts (queue_id, next_attempt) WHERE status = 'pending';

-- ---------- Политики ----------

-- Политики уровня цепочки организация → домен → ящик (учётная запись) → папка (PolicyResolver).
-- object_id: организация — tenant_id, иначе идентификатор домена, учётной записи или папки.
-- NULL — не задано на этом уровне. Длительности — микросекунды.
CREATE TABLE policies (
    tenant_id          uuid NOT NULL REFERENCES tenants,
    level              text NOT NULL CHECK (level IN ('tenant', 'domain', 'account', 'mailbox')),
    object_id          uuid NOT NULL,
    quota_bytes        bigint CHECK (quota_bytes >= 0),
    trash_retention_us bigint CHECK (trash_retention_us >= 0),
    retention_us       bigint CHECK (retention_us >= 0),
    send_per_hour      bigint CHECK (send_per_hour BETWEEN 0 AND 4294967295),
    max_recipients     bigint CHECK (max_recipients BETWEEN 0 AND 4294967295),
    dkim_selector      text,
    milter_profile     text,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    -- Правило администратора trash.purge: значение и разрешение выбора пользователю (задаются вместе).
    trash_purge        text CHECK (trash_purge IN ('hide', 'erase')),
    trash_purge_user_can_choose boolean,
    -- Лимит отправки «адресатов в час» (решение 113; SRS 6.3): сумма получателей писем учётной записи за
    -- скользящий час, как RecipientRateLimit в Exchange.
    rcpts_per_hour     bigint CHECK (rcpts_per_hour BETWEEN 0 AND 4294967295),
    -- Политика архива: возраст автопереноса (не больше 100 лет — срок письма received_at + возраст остаётся
    -- в диапазоне timestamptz) и квота архива.
    archive_after_us   bigint CHECK (archive_after_us BETWEEN 0 AND 3155760000000000),
    archive_quota_bytes bigint CHECK (archive_quota_bytes >= 0),
    PRIMARY KEY (tenant_id, level, object_id),
    CHECK (level <> 'tenant' OR object_id = tenant_id),
    CONSTRAINT policies_trash_purge_pair
        CHECK ((trash_purge IS NULL) = (trash_purge_user_can_choose IS NULL))
);

-- Срок корзины для письма учётной записи a из папки m: самый специфичный заданный уровень; NULL — не задан
-- (значение по умолчанию конфигурации). Вызывается при переносе в корзину; подчиняется RLS вызывающего.
CREATE FUNCTION tp_trash_retention_us(t uuid, a uuid, m uuid) RETURNS bigint
LANGUAGE sql STABLE AS $$
    SELECT p.trash_retention_us FROM policies p
    WHERE p.tenant_id = t AND p.trash_retention_us IS NOT NULL
      AND ((p.level = 'tenant' AND p.object_id = t)
        OR (p.level = 'domain'
            AND p.object_id = (SELECT domain_id FROM accounts WHERE tenant_id = t AND account_id = a))
        OR (p.level = 'account' AND p.object_id = a)
        OR (p.level = 'mailbox' AND p.object_id = m))
    ORDER BY CASE p.level WHEN 'mailbox' THEN 0 WHEN 'account' THEN 1 WHEN 'domain' THEN 2 ELSE 3 END
    LIMIT 1
$$;

-- ---------- Журналы доставки и аудита — только добавление (SRS 3.1, 5.2) ----------
--
-- Изменять и удалять записи нельзя никому, в том числе владельцу схемы: триггер `tp_append_only` отклоняет
-- UPDATE и DELETE (код 42501). Роли приложения выдаются только SELECT и INSERT.
-- Журналы секционированы по суткам (UTC); срок хранения — удаление секций целиком. Секции создаёт и удаляет
-- владелец схемы через функции SECURITY DEFINER `tp_log_partitions` и `tp_log_purge`: роль приложения
-- не выполняет DDL и не видит секции напрямую — только родительскую таблицу под RLS.

CREATE FUNCTION tp_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
    RAISE EXCEPTION 'таблица % только на добавление', TG_TABLE_NAME USING ERRCODE = 'insufficient_privilege';
END
$$;

-- ---------- Журнал доставки ----------

-- Порядок записи для равных моментов.
CREATE SEQUENCE delivery_log_seq;

-- sender_key, rcpt_keys — адреса в нижнем регистре ASCII для поиска; содержимое писем не хранится.
-- kind 'itip' — итог применения приглашения из письма iMIP (решение accept или discard, метод и причина —
-- в reason; содержимое не хранится).
CREATE TABLE delivery_log (
    tenant_id  uuid NOT NULL,
    at         timestamptz NOT NULL,
    seq        bigint NOT NULL DEFAULT nextval('delivery_log_seq'),
    node       text NOT NULL,
    kind       text NOT NULL CHECK (kind IN ('receive', 'reject', 'deliver', 'relay', 'dsn', 'itip')),
    sender     text NOT NULL,
    sender_key text NOT NULL,
    recipients text[] NOT NULL,
    rcpt_keys  text[] NOT NULL,
    message_id text,
    queue_id   uuid,
    decision   text NOT NULL
               CHECK (decision IN ('accept', 'reject', 'defer', 'quarantine', 'discard', 'hold')),
    reason     text
) PARTITION BY RANGE (at);

ALTER SEQUENCE delivery_log_seq OWNED BY delivery_log.seq;

CREATE INDEX delivery_log_time ON delivery_log (tenant_id, at, seq);
CREATE INDEX delivery_log_sender ON delivery_log (tenant_id, sender_key, at, seq);
CREATE INDEX delivery_log_message ON delivery_log (tenant_id, message_id) WHERE message_id IS NOT NULL;
CREATE INDEX delivery_log_rcpt ON delivery_log USING gin (rcpt_keys);
-- Статус доставки отправки JMAP: события записи очереди (`DeliveryLog::by_queue`).
CREATE INDEX delivery_log_queue ON delivery_log (tenant_id, queue_id, at, seq) WHERE queue_id IS NOT NULL;

CREATE TRIGGER tp_append_only BEFORE UPDATE OR DELETE ON delivery_log
    FOR EACH ROW EXECUTE FUNCTION tp_append_only();

-- ---------- Аудит ящика ----------

-- Порядок записи для равных моментов.
CREATE SEQUENCE mailbox_audit_seq;

-- actor_key — исполнитель в нижнем регистре ASCII для поиска; содержимое писем не хранится.
-- Действие `search` — поиск по тексту писем в чужом ящике; строка запроса — в detail, найденные письма
-- не хранятся (решение 114).
CREATE TABLE mailbox_audit (
    tenant_id     uuid NOT NULL,
    account_id    uuid NOT NULL,
    at            timestamptz NOT NULL,
    seq           bigint NOT NULL DEFAULT nextval('mailbox_audit_seq'),
    actor         text NOT NULL,
    actor_key     text NOT NULL,
    actor_account uuid,
    actor_kind    text NOT NULL CHECK (actor_kind IN ('owner', 'delegate', 'admin')),
    action        text NOT NULL CHECK (action IN ('login', 'read', 'search', 'move', 'delete', 'send',
                                                  'send_as', 'send_on_behalf', 'change_rights',
                                                  'change_rules', 'change_forwarding')),
    mailbox_id    uuid,
    message_id    uuid,
    detail        text,
    client        text
) PARTITION BY RANGE (at);

ALTER SEQUENCE mailbox_audit_seq OWNED BY mailbox_audit.seq;

CREATE INDEX mailbox_audit_time ON mailbox_audit (tenant_id, at, seq);
CREATE INDEX mailbox_audit_account ON mailbox_audit (tenant_id, account_id, at, seq);
CREATE INDEX mailbox_audit_actor ON mailbox_audit (tenant_id, actor_key, at, seq);

CREATE TRIGGER tp_append_only BEFORE UPDATE OR DELETE ON mailbox_audit
    FOR EACH ROW EXECUTE FUNCTION tp_append_only();

-- Политика аудита организации (account_id IS NULL) или ящика.
CREATE TABLE mailbox_audit_policies (
    tenant_id     uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
    account_id    uuid,
    non_owner     boolean NOT NULL,
    owner_actions text[] NOT NULL,
    UNIQUE NULLS NOT DISTINCT (tenant_id, account_id)
);

-- ---------- Журнал аудита ----------

-- Операции администраторов (SRS 5.2, ADM-01): организация операции (`NULL` — уровень инсталляции, видна только
-- системным транзакциям), администратор, запись целиком (`record`). Тело запроса и секреты не записываются.
CREATE TABLE audit_log (
    seq          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at           timestamptz NOT NULL,
    tenant_id    uuid,
    actor_tenant uuid NOT NULL,
    actor        uuid NOT NULL,
    record       jsonb NOT NULL
);

CREATE INDEX audit_log_tenant ON audit_log (tenant_id, at);

CREATE TRIGGER tp_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION tp_append_only();

-- Отметка доставки приёмника (`syslog`, `otlp`): номер последней доставленной записи `audit_log.seq`. Выгрузка
-- (роль maintenance под лизой) читает записи после отметки и сдвигает её после доставки; недоступный приёмник
-- догоняет пропущенное. Таблица уровня инсталляции, без организации: читает и пишет только системная транзакция.
CREATE TABLE audit_export (
    sink          text PRIMARY KEY CHECK (sink <> ''),
    delivered_seq bigint NOT NULL CHECK (delivered_seq >= 0),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Секции суток `days` (UTC) журнала `parent`, которых ещё нет: `<parent>_YYYYMMDD`. Параллельное создание той
-- же секции не ошибка.
CREATE FUNCTION tp_log_partitions(parent text, days date[]) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    d    date;
    part text;
BEGIN
    IF parent NOT IN ('delivery_log', 'mailbox_audit') THEN
        RAISE EXCEPTION 'журнал % не секционирован по суткам', parent USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOREACH d IN ARRAY days
    LOOP
        part := parent || '_' || to_char(d, 'YYYYMMDD');
        IF to_regclass(format('public.%I', part)) IS NULL THEN
            BEGIN
                EXECUTE format('CREATE TABLE public.%I PARTITION OF public.%I FOR VALUES FROM (%L) TO (%L)',
                               part, parent, d::timestamp AT TIME ZONE 'UTC', (d + 1)::timestamp AT TIME ZONE 'UTC');
            EXCEPTION WHEN duplicate_table OR unique_violation OR invalid_object_definition THEN
                NULL;
            END;
        END IF;
    END LOOP;
END
$$;

-- Удаляет секции журнала `parent`, сутки которых целиком раньше `before`; возвращает число удалённых.
CREATE FUNCTION tp_log_purge(parent text, before timestamptz) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
    part text;
    n    integer := 0;
BEGIN
    IF parent NOT IN ('delivery_log', 'mailbox_audit') THEN
        RAISE EXCEPTION 'журнал % не секционирован по суткам', parent USING ERRCODE = 'invalid_parameter_value';
    END IF;
    FOR part IN
        SELECT c.relname FROM pg_inherits i JOIN pg_class c ON c.oid = i.inhrelid
        WHERE i.inhparent = format('public.%I', parent)::regclass AND c.relname ~ ('^' || parent || '_[0-9]{8}$')
        ORDER BY c.relname
    LOOP
        IF (to_date(right(part, 8), 'YYYYMMDD') + 1)::timestamp AT TIME ZONE 'UTC' <= before THEN
            EXECUTE format('DROP TABLE public.%I', part);
            n := n + 1;
        END IF;
    END LOOP;
    RETURN n;
END
$$;

REVOKE ALL ON FUNCTION tp_log_partitions(text, date[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION tp_log_purge(text, timestamptz) FROM PUBLIC;

-- ---------- Журнал переписки (SRS 4.9; CTR-97, META-88) ----------
--
-- Индекс журнала — в схеме journal: конверт каждой записи для поиска (eDiscovery) и хеш-цепочка
-- доказательной целостности hash = sha256(prev_hash ‖ canonical) — SHA-256 считает PostgreSQL
-- (sha256(bytea); контракт фиксирует образ входа chain_input). Письма целиком — в отдельном бакете
-- журнала (полоса blob, BLOB-18): строка индекса хранит ссылку на запись (storage). Таблица только на
-- добавление, как журналы аудита: UPDATE и DELETE отклоняет триггер tp_append_only; очистка — только
-- функцией восстановления tp_journal_clear (maintenance, restore_index). Без внешнего ключа на tenants
-- — как у других журналов только на добавление.

CREATE SCHEMA journal;

-- Запись индекса: конверт (sender, recipients, message_id, at, rule) + цепочка. seq — порядок в цепочке
-- организации (присваивается под рекомендательной блокировкой), поиск — по (at, id).
-- sender_key и rcpt_keys — адреса в нижнем регистре ASCII для поиска без учёта регистра; canonical —
-- канонический JSON записи (образ хеша): индекс самодостаточен для проверки цепочки чистым SQL.
CREATE TABLE journal.entries (
    tenant_id  uuid NOT NULL,
    seq        bigint NOT NULL CHECK (seq > 0),
    id         uuid NOT NULL,
    sender     text NOT NULL,
    sender_key text NOT NULL,
    recipients text[] NOT NULL CHECK (cardinality(recipients) > 0),
    rcpt_keys  text[] NOT NULL,
    message_id text,
    at         timestamptz NOT NULL,
    rule       text NOT NULL,
    storage    text NOT NULL CHECK (storage <> ''),
    canonical  text NOT NULL CHECK (jsonb_typeof(canonical::jsonb) = 'object'),
    prev_hash  bytea NOT NULL CHECK (octet_length(prev_hash) = 32),
    hash       bytea NOT NULL CHECK (octet_length(hash) = 32),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, seq)
);

-- Согласованность конверта строки с её каноническим представлением: подмена любого столбца записи
-- (не только canonical) видна проверке цепочки. Время сравнивается в timestamptz (микросекунды)
-- с обеих сторон — наносекунды канонического JSON усекаются как в столбце.
CREATE FUNCTION journal.tp_consistent(e journal.entries) RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT (e.canonical::jsonb ->> 'tenant')::uuid IS NOT DISTINCT FROM e.tenant_id
       AND e.canonical::jsonb ->> 'sender' IS NOT DISTINCT FROM e.sender
       AND (SELECT array_agg(x ORDER BY ord)
            FROM jsonb_array_elements_text(e.canonical::jsonb -> 'recipients')
                 WITH ORDINALITY AS t(x, ord)) IS NOT DISTINCT FROM e.recipients
       AND e.canonical::jsonb ->> 'message_id' IS NOT DISTINCT FROM e.message_id
       AND (e.canonical::jsonb ->> 'at')::timestamptz IS NOT DISTINCT FROM e.at
       AND e.canonical::jsonb ->> 'rule' IS NOT DISTINCT FROM e.rule
$$;

CREATE INDEX journal_entries_time ON journal.entries (tenant_id, at, id);
CREATE INDEX journal_entries_sender ON journal.entries (tenant_id, sender_key, at, id);
CREATE INDEX journal_entries_rcpt ON journal.entries USING gin (rcpt_keys);
CREATE INDEX journal_entries_message ON journal.entries (tenant_id, message_id)
    WHERE message_id IS NOT NULL;
CREATE INDEX journal_entries_rule ON journal.entries (tenant_id, rule, at, id);

CREATE TRIGGER tp_append_only BEFORE UPDATE OR DELETE ON journal.entries
    FOR EACH ROW EXECUTE FUNCTION tp_append_only();

-- Очистка индекса организации — только восстановлением (restore_index пересобирает индекс из хранилища
-- записей). Триггер только на добавление отключается на время очистки и только этой функцией; записи
-- хранилища (бакет) она не трогает. Системная транзакция (app.all_tenants) — RLS.
CREATE FUNCTION tp_journal_clear(tenant uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = journal, public, pg_temp AS $$
BEGIN
    ALTER TABLE journal.entries DISABLE TRIGGER tp_append_only;
    DELETE FROM journal.entries WHERE tenant_id = tenant;
    ALTER TABLE journal.entries ENABLE TRIGGER tp_append_only;
END
$$;

REVOKE ALL ON FUNCTION tp_journal_clear(uuid) FROM PUBLIC;

-- Правила журналирования (CTR-97): организация, группа или ящик, направление, состояние; правило —
-- данные организации. Удаление группы или учётной записи удаляет их правила (каскад).
CREATE TABLE journal.rules (
    tenant_id  uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
    id         text NOT NULL CHECK (id <> ''),
    scope_kind text NOT NULL CHECK (scope_kind IN ('org', 'group', 'mailbox')),
    group_id   uuid,
    account_id uuid,
    direction  text NOT NULL CHECK (direction IN ('in', 'out', 'both')),
    enabled    boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    CHECK ((scope_kind = 'group') = (group_id IS NOT NULL)),
    CHECK ((scope_kind = 'mailbox') = (account_id IS NOT NULL)),
    FOREIGN KEY (tenant_id, group_id) REFERENCES groups (tenant_id, group_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts (tenant_id, account_id) ON DELETE CASCADE
);

-- ---------- Транспорт (SRS 4.1, 2.6; решение 2026-11-01-transport-scope-external-mta) ----------
-- Уровень кластера — принятые домены (таблица domains) и доверенные источники; версия снимка — одна строка
-- transport_cluster, запись блокирует её (FOR UPDATE), чтение снимка — FOR SHARE. Уровень организации —
-- политики доменов назначения и версия снимка организации (RLS).

-- Версия снимка уровня кластера (одна строка).
CREATE TABLE transport_cluster (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    version   bigint NOT NULL CHECK (version >= 0)
);

INSERT INTO transport_cluster (singleton, version) VALUES (true, 0);

-- Доверенные источники приёма: tenant_id IS NULL — источник кластера (общий шлюз), виден всем; источник
-- организации виден только ей; источник кластера пишет только системная транзакция (app.all_tenants).
CREATE TABLE transport_sources (
    name       text PRIMARY KEY CHECK (name ~ '^[a-z0-9._-]{1,64}$'),
    tenant_id  uuid REFERENCES tenants,
    matcher    jsonb NOT NULL,
    kind       jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX transport_sources_tenant ON transport_sources (tenant_id) WHERE tenant_id IS NOT NULL;

-- Версия снимка организации; нет строки — версия 0.
CREATE TABLE transport_versions (
    tenant_id uuid PRIMARY KEY REFERENCES tenants,
    version   bigint NOT NULL CHECK (version > 0)
);

-- Политики доменов назначения организации: шаблон — ключ (`example.org`, `*.example.org`, `*`).
CREATE TABLE transport_routes (
    tenant_id  uuid NOT NULL REFERENCES tenants,
    pattern    text NOT NULL CHECK (length(pattern) BETWEEN 1 AND 255),
    tls        jsonb NOT NULL,
    smart_host text CHECK (length(smart_host) BETWEEN 1 AND 255 AND smart_host !~ '[[:space:][:cntrl:]]'),
    egress_ip  inet,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, pattern)
);

-- Таблица переписывания адресов конверта организации (модель Postfix canonical_maps). Ключ — исходный шаблон
-- в канонической форме (`old@example.org`, `@old.example`); версия — общая с политиками доменов назначения
-- (transport_versions).
CREATE TABLE transport_rewrites (
    tenant_id   uuid NOT NULL REFERENCES tenants,
    from_addr   text NOT NULL CHECK (length(from_addr) BETWEEN 2 AND 320 AND from_addr ~ '@'),
    to_addr     text NOT NULL CHECK (length(to_addr) BETWEEN 2 AND 320 AND to_addr ~ '@'),
    sender      boolean NOT NULL,
    recipient   boolean NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, from_addr),
    CHECK (sender OR recipient),
    CHECK (from_addr <> to_addr)
);

-- Локальные одноразовые токены Admin API: `thepost admin init` выпускает токен администратору организации;
-- хранится только хэш значения (hex SHA-256), значение не хранится. Идентификатор и хэш уникальны по
-- инсталляции: Bearer не несёт организацию, погашение (`consume`), отзыв и очистка идут системной транзакцией
-- (app.all_tenants), выпуск и список — в транзакции организации (RLS). Без внешнего ключа на учётную запись:
-- токен — служебная запись с коротким сроком, удаляется очисткой (`prune`).
CREATE TABLE local_admin_tokens (
    token_id   text PRIMARY KEY CHECK (length(token_id) BETWEEN 1 AND 64
                                       AND token_id !~ '[[:space:][:cntrl:]]'),
    tenant_id  uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
    account_id uuid NOT NULL,
    hash       text NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    revoked_at timestamptz,
    CHECK (expires_at > created_at)
);

-- `consume` — по уникальному индексу хэша; `list` — организация по выпуску; `prune` — по сроку.
CREATE INDEX local_admin_tokens_tenant ON local_admin_tokens (tenant_id, created_at, token_id COLLATE "C");
CREATE INDEX local_admin_tokens_expires ON local_admin_tokens (expires_at);

-- ---------- Журнал событий ядра (SRS 2.5) ----------

-- Счётчик позиций раздела: строка блокируется до фиксации транзакции, поэтому позиции видны по порядку.
CREATE TABLE event_partitions (
    partition integer PRIMARY KEY,
    last_pos  bigint NOT NULL
);

CREATE TABLE events (
    partition  integer NOT NULL,
    pos        bigint NOT NULL,
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    mailbox_id uuid,
    kind       jsonb NOT NULL,
    at         timestamptz NOT NULL,
    PRIMARY KEY (partition, pos)
);

CREATE TABLE event_cursors (
    subscriber text NOT NULL,
    partition  integer NOT NULL,
    pos        bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (subscriber, partition)
);

-- ---------- Лизы ----------

CREATE TABLE leases (
    name       text PRIMARY KEY,
    holder     text NOT NULL,
    fencing    bigint NOT NULL,
    expires_at timestamptz NOT NULL
);

-- ---------- RLS ----------
-- Данные и запросы — в контексте организации; владелец таблиц тоже подчиняется RLS (FORCE).

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'tenants', 'domains', 'accounts', 'groups', 'group_members', 'group_senders', 'group_moderators',
        'group_held', 'installation_admins', 'abuse_blocks', 'sender_lists', 'mail_contacts', 'org_units',
        'org_attributes', 'dynamic_groups', 'sync_holds', 'account_delegates', 'sharing_policies',
        'share_notification_state', 'share_notifications', 'share_notification_log',
        'mailboxes', 'messages', 'message_parts', 'changelog', 'mailbox_state', 'mailbox_acl',
        'send_delegations', 'index_manifests', 'app_passwords', 'dav_collections', 'dav_objects',
        'dav_tombstones', 'dav_busy', 'dav_inbox', 'dav_inbox_tombstones', 'sieve_scripts',
        'sieve_org_scripts', 'vacation', 'vacation_log', 'email_submissions', 'email_submission_tombstones',
        'collection_acl', 'blobs', 'queue', 'queue_rcpts', 'policies', 'delivery_log', 'mailbox_audit',
        'mailbox_audit_policies', 'audit_log', 'transport_versions', 'transport_routes',
        'transport_rewrites', 'local_admin_tokens', 'events', 'trust_partner_domains',
        'trust_forward_domains']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tp_tenant_visible(tenant_id))'
                       ' WITH CHECK (tp_tenant_visible(tenant_id))', t);
    END LOOP;
END
$$;

-- Источник кластера (tenant_id IS NULL) виден всем, источник организации — только ей.
ALTER TABLE transport_sources ENABLE ROW LEVEL SECURITY;
ALTER TABLE transport_sources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON transport_sources
    USING (tenant_id IS NULL OR tp_tenant_visible(tenant_id))
    WITH CHECK (coalesce(tp_tenant_visible(tenant_id), false));

-- Набор организации видит и меняет только она; набор установки читают все (он публичен: экран входа без
-- входа), меняет — только системная транзакция (`app.all_tenants`): у `tenant_id IS NULL` проверка
-- `tp_tenant_visible` ложна.
ALTER TABLE branding ENABLE ROW LEVEL SECURITY;
ALTER TABLE branding FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON branding USING (tp_tenant_visible(tenant_id))
    WITH CHECK (tp_tenant_visible(tenant_id));
CREATE POLICY installation_read ON branding FOR SELECT USING (tenant_id IS NULL);

-- Политики доверия — как брендинг: уровни организации и группы видит и меняет только своя организация,
-- строку установки читают все (действующий потолок и effective_for в транзакции организации), меняет —
-- только системная транзакция (у tenant_id IS NULL проверка tp_tenant_visible ложна).
ALTER TABLE trust_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE trust_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON trust_policies USING (tp_tenant_visible(tenant_id))
    WITH CHECK (tp_tenant_visible(tenant_id));
CREATE POLICY installation_read ON trust_policies FOR SELECT USING (tenant_id IS NULL);

-- Журнал переписки: записи индекса и правила видит и меняет только своя организация (аудитора журнала
-- через токен JournalAudit пускает Admin API в транзакции организации); очистку индекса выполняет
-- только tp_journal_clear в системной транзакции.
ALTER TABLE journal.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE journal.entries FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON journal.entries USING (public.tp_tenant_visible(tenant_id))
    WITH CHECK (public.tp_tenant_visible(tenant_id));
ALTER TABLE journal.rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE journal.rules FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON journal.rules USING (public.tp_tenant_visible(tenant_id))
    WITH CHECK (public.tp_tenant_visible(tenant_id));

-- ---------- Роли PostgreSQL (SRS 2.7, 3.1; решение 2026-11-01-borrowings-security) ----------
--
-- Владелец схемы (роль, применяющая миграции) в работе узлов не используется. Узлы входят ролями с минимальными
-- правами — членами групповых ролей без входа:
--   thepost_app    — общая роль узлов: SELECT, INSERT, UPDATE, DELETE в таблицах ядра; в таблицах только
--                    на добавление (триггер tp_append_only: журналы доставки и аудита) — только SELECT и INSERT;
--   thepost_reader — только чтение метаданных для ролей search и indexer: SELECT, запись — только в служебные
--                    таблицы узла (членство, аренды, позиции подписчиков журнала событий, манифесты индексов).
-- Ни одна из ролей не владеет таблицами, не создаёт объекты в схеме и не имеет BYPASSRLS; таблица миграций им
-- недоступна. Учётные записи узлов создаёт администратор СУБД или database secrets engine, например:
--   CREATE ROLE thepost_node LOGIN PASSWORD '…' IN ROLE thepost_app;
-- Групповые роли общие для кластера СУБД: создаются, если их нет и у владельца схемы есть CREATEROLE, иначе —
-- предупреждение (их создаёт администратор СУБД, затем права выдаёт `SELECT tp_grant_roles()`).

DO $$
DECLARE
    r text;
BEGIN
    FOREACH r IN ARRAY ARRAY['thepost_app', 'thepost_reader']
    LOOP
        CONTINUE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r);
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = current_user AND (rolsuper OR rolcreaterole)) THEN
            BEGIN
                EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS', r);
            -- Роль создана параллельно (другая БД того же кластера).
            EXCEPTION WHEN duplicate_object OR unique_violation THEN
                NULL;
            END;
        ELSE
            RAISE WARNING 'роль % не создана: у % нет CREATEROLE; создайте её и выполните SELECT tp_grant_roles()',
                r, current_user;
        END IF;
    END LOOP;
END
$$;

-- Выдаёт права групповым ролям на таблицы схем public и journal (секции — только через родительскую
-- таблицу; служебные таблицы — как в комментарии выше).
CREATE FUNCTION tp_grant_roles() RETURNS void
LANGUAGE plpgsql SET search_path = public, journal, pg_temp AS $$
DECLARE
    t record;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'thepost_app') THEN
        GRANT USAGE ON SCHEMA public, journal TO thepost_app;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO thepost_app;
        GRANT EXECUTE ON FUNCTION tp_log_partitions(text, date[]), tp_log_purge(text, timestamptz),
            tp_journal_clear(uuid) TO thepost_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'thepost_reader') THEN
        GRANT USAGE ON SCHEMA public, journal TO thepost_reader;
    END IF;
    FOR t IN
        SELECT n.nspname AS schema, c.relname,
               EXISTS (SELECT 1 FROM pg_trigger g WHERE g.tgrelid = c.oid AND g.tgname = 'tp_append_only')
                   AS append_only
        FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname IN ('public', 'journal') AND c.relkind IN ('r', 'p') AND NOT c.relispartition
          AND c.relname <> '_sqlx_migrations'
    LOOP
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'thepost_app') THEN
            EXECUTE format('REVOKE ALL ON %I.%I FROM thepost_app', t.schema, t.relname);
            IF t.append_only THEN
                EXECUTE format('GRANT SELECT, INSERT ON %I.%I TO thepost_app', t.schema, t.relname);
            ELSE
                EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I.%I TO thepost_app',
                               t.schema, t.relname);
            END IF;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'thepost_reader') THEN
            EXECUTE format('REVOKE ALL ON %I.%I FROM thepost_reader', t.schema, t.relname);
            IF t.relname IN ('nodes', 'leases', 'event_cursors', 'index_manifests') THEN
                EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I.%I TO thepost_reader',
                               t.schema, t.relname);
            ELSE
                EXECUTE format('GRANT SELECT ON %I.%I TO thepost_reader', t.schema, t.relname);
            END IF;
        END IF;
    END LOOP;
END
$$;

REVOKE ALL ON FUNCTION tp_grant_roles() FROM PUBLIC;

SELECT tp_grant_roles();
