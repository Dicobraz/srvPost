-- Сессии Admin API (META-64; CTR-61, CONTRACTS.md#Auth, решение 77 синка 12.11): вход выдаёт сессию,
-- значение (`tps_…`) возвращается один раз, в хранилище — только хэш значения (hex SHA-256).
-- Хранилище — основная БД: сессия видна всем узлам роли admin и переживает перезапуск узла.
-- Миграция только добавляет объекты: существующие таблицы не меняются; повторное применение —
-- пустая операция. RLS по tenant_id — как в базовой схеме; владелец таблиц тоже подчиняется (FORCE).

-- ---------- Сессии (admin_sessions) ----------
--
-- Ключ — хэш значения сессии, уникален по инсталляции (значение сессии случайно, повтор хэша —
-- повтор значения). Чтение и удаление (выход) идут системной транзакцией: Bearer не несёт
-- организацию; выпуск (вставка) — в транзакции организации субъекта (RLS проверяет её же).
-- Без внешнего ключа на учётную запись: сессия — служебная запись с коротким сроком, удаляется
-- выходом или очисткой. Истёкшая остаётся до очистки (`purge_expired`) — чтение её не возвращает.

CREATE TABLE admin_sessions (
    hash       text PRIMARY KEY CHECK (hash ~ '^[0-9a-f]{64}$'),
    tenant_id  uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
    account_id uuid NOT NULL,
    login      text NOT NULL,
    groups     jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(groups) = 'array'),
    scopes     jsonb CHECK (scopes IS NULL OR jsonb_typeof(scopes) = 'array'),
    roles      jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(roles) = 'array'),
    expires_at timestamptz NOT NULL
);

-- Чтение и выход — по уникальному хэшу (ключ PRIMARY KEY); очистка — по сроку.
CREATE INDEX admin_sessions_expires ON admin_sessions (expires_at);

-- ---------- RLS ----------

ALTER TABLE admin_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON admin_sessions USING (tp_tenant_visible(tenant_id))
    WITH CHECK (tp_tenant_visible(tenant_id));

-- Права групповых ролей на новую таблицу.
SELECT tp_grant_roles();
