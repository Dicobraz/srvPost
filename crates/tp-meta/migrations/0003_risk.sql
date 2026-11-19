-- Справочник аномалий и threat intelligence (META-87, CTR-95; решение 126; CONTRACTS.md#Risk).
-- Миграция только добавляет объекты: существующие таблицы не меняются; повторное применение — пустая
-- операция. Таблицы уровня установки (risk_packages, ti_sources, ti_list_versions) без tenant_id и без
-- RLS: пакеты поставщика, источники и версии списков общие для установки, их меняет администратор
-- (узел — системной транзакцией). Таблицы организаций (risk_policies, ti_usage, risk_hits) — RLS по
-- tenant_id, как в базовой схеме; строку установки политик читают все (installation_read). Владелец
-- таблиц тоже подчиняется RLS (FORCE).

-- ---------- Пакеты поставщика (решение 126 б) ----------
--
-- Строка на версию: манифест — jsonb по схеме контракта (PackageManifest), номер версии — первичный
-- ключ и только растёт (пакет с номером не выше максимального хранимого отклоняет триггер
-- risk_packages_version_grows — ошибка ограничения). Подпись Ed25519 (signature) и ссылку на BLOB
-- архива пакета (archive) записывает узел после проверки (APP-78); до того — NULL. key_id — из
-- манифеста. Состояние: active — действующий (один, частичный уникальный индекс), previous — хранимый
-- для отката (не больше risk.package.keep; лишние удаляет активация и откат в той же транзакции),
-- rejected — отказ проверки (подпись, lint, пробный прогон; отчёт — report jsonb, действующий пакет
-- не меняется). Очистку старше срока хранения срабатываний ведёт отдельная таблица risk_hits.

CREATE TABLE risk_packages (
    version      bigint PRIMARY KEY,
    manifest     jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    signature    bytea,
    key_id       text NOT NULL,
    archive      text,
    state        text NOT NULL DEFAULT 'previous'
                 CHECK (state IN ('active', 'previous', 'rejected')),
    report       jsonb,
    installed_at timestamptz NOT NULL DEFAULT now()
);

-- Один действующий пакет.
CREATE UNIQUE INDEX risk_packages_active ON risk_packages (version) WHERE state = 'active';

-- Номер версии только растёт: sa-update не ставит пакет со старым или тем же номером.
CREATE FUNCTION risk_package_version_grows() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
    max_version bigint;
BEGIN
    SELECT max(version) INTO max_version FROM risk_packages;
    IF NEW.version <= coalesce(max_version, 0) THEN
        RAISE EXCEPTION 'номер пакета % не растёт (максимальный хранимый %)',
            NEW.version, max_version
            USING ERRCODE '23514';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER risk_packages_version_grows BEFORE INSERT ON risk_packages
    FOR EACH ROW EXECUTE FUNCTION risk_package_version_grows();

-- ---------- Политики уровней (решение 126 а, в) ----------
--
-- Строка на уровень: установка — tenant_id IS NULL (частичный уникальный индекс, не больше одной),
-- организация — уникальный tenant_id. Изменения администратора и его признаки — policy jsonb по схеме
-- контракта (RiskPolicy; новое поле политики — не миграция схемы), версия схемы — schema_version.
-- Внешнего ключа на tenants нет — как у записей ящика (sent_log): организации приходят и уходят,
-- политики и журнал переживают их для отчётов. RLS: строку установки читают все организации
-- (действующий каталог в транзакции организации), пишет её только системная транзакция.

CREATE TABLE risk_policies (
    tenant_id      uuid,
    policy         jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(policy) = 'object'),
    schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version > 0),
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX risk_policies_installation ON risk_policies ((tenant_id IS NULL)) WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX risk_policies_org ON risk_policies (tenant_id) WHERE tenant_id IS NOT NULL;

-- ---------- Источники TI (решение 126 е–к) ----------
--
-- Источник — строка по идентификатору: уровень (tier), доставка (kind) и формат (format) — jsonb
-- перечислений контракта, TTL — ttl_seconds, действие при устаревании (stale), лицензия, организации
-- (tenants) и авторизация (auth) — jsonb; secret_ref — ссылка SecretRef на хранилище секретов, не
-- секрет; origin — происхождение для журнала и отчётов. Сами записи списков — в BLOB, не здесь.

CREATE TABLE ti_sources (
    id          text PRIMARY KEY,
    tier        text NOT NULL CHECK (tier IN ('bundled', 'customer_key', 'import')),
    kind        jsonb NOT NULL,
    format      jsonb NOT NULL,
    ttl_seconds bigint NOT NULL CHECK (ttl_seconds > 0),
    stale       jsonb NOT NULL,
    license     jsonb NOT NULL,
    tenants     jsonb NOT NULL,
    secret_ref  text,
    auth        jsonb NOT NULL,
    origin      text NOT NULL CHECK (origin IN ('vendor', 'gossopka', 'fincert', 'own'))
);

-- Версия списка: содержимое — объект BLOB по ссылке (blob, уникальность — sha256), в строках — только
-- метаданные (миллионы IoC заказчика не хранятся построчно). expires_at — fetched_at + TTL источника
-- на момент записи (устаревание проверяет thepost doctor и журнал). Текущая версия списка — последняя
-- по fetched_at (при равенстве — большая sha256: порядок детерминирован).
CREATE TABLE ti_list_versions (
    list       text NOT NULL,
    source     text NOT NULL,
    sha256     bytea NOT NULL,
    blob       text NOT NULL,
    entries    bigint NOT NULL,
    fetched_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    tlp        jsonb,
    PRIMARY KEY (list, source, fetched_at, sha256)
);

CREATE INDEX ti_list_versions_current ON ti_list_versions (list, fetched_at DESC, sha256 DESC);

-- ---------- Учёт обращений MSSP (решение 126 е) ----------
--
-- Обращения и совпадения по источнику за сутки UTC по каждой организации: record_usage прибавляет
-- (ON CONFLICT DO UPDATE), строки организации видит только она (RLS); сводку по всем организациям
-- читает системная транзакция (MSSP). Внешнего ключа на tenants нет: учёт — метаданные, переживающие
-- удаление организации (отчёты MSSP).

CREATE TABLE ti_usage (
    source    text NOT NULL,
    tenant_id uuid NOT NULL,
    day       date NOT NULL,
    lookups   bigint NOT NULL DEFAULT 0 CHECK (lookups >= 0),
    hits      bigint NOT NULL DEFAULT 0 CHECK (hits >= 0),
    PRIMARY KEY (source, tenant_id, day)
);

-- ---------- Журнал срабатываний (решение 126 а) ----------
--
-- Срабатывание признака на письме организации: применённые (enforce) и «только отчёт» (report) — здесь
-- же, с режимом. message — SHA-256 письма, ord — порядок записи (свежие первыми, при равном моменте —
-- порядок записи). Внешнего ключа на tenants нет (как у политик — журнал переживает организацию).
-- Удаление старше risk.hits.retention — PgMeta::purge_risk_hits_before (роль maintenance), порциями
-- по индексу времени.

CREATE TABLE risk_hits (
    tenant_id uuid NOT NULL,
    message   bytea NOT NULL CHECK (length(message) = 32),
    signal    text NOT NULL,
    strength  smallint NOT NULL CHECK (strength BETWEEN 0 AND 100),
    weight    integer NOT NULL,
    mode      text NOT NULL CHECK (mode IN ('report', 'enforce')),
    at        timestamptz NOT NULL DEFAULT now(),
    ord       bigserial PRIMARY KEY
);

CREATE INDEX risk_hits_tenant_at ON risk_hits (tenant_id, at DESC);

-- ---------- RLS ----------

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['ti_usage', 'risk_hits']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tp_tenant_visible(tenant_id))'
                       ' WITH CHECK (tp_tenant_visible(tenant_id))', t);
    END LOOP;
END
$$;

-- Политики справочника — как политика доверия: уровни организации видит и меняет только своя
-- организация, строку установки читают все (действующий каталог в транзакции организации), меняет —
-- только системная транзакция (у tenant_id IS NULL проверка tp_tenant_visible ложна).
ALTER TABLE risk_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON risk_policies USING (tp_tenant_visible(tenant_id))
    WITH CHECK (tp_tenant_visible(tenant_id));
CREATE POLICY installation_read ON risk_policies FOR SELECT USING (tenant_id IS NULL);

-- Права групповых ролей на новые таблицы.
SELECT tp_grant_roles();
