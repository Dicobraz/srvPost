-- Публикации календарей и шаблоны занятости доменов-партнёров (META-34; CTR-36, CONTRACTS.md#Calendar;
-- решение 2026-11-04-calendar-external-api). Миграция только добавляет объекты: существующие таблицы
-- не меняются; повторное применение — пустая операция. Таблицы каталога (основная БД) — RLS по
-- tenant_id, как в базовой схеме; владелец таблиц тоже подчиняется (FORCE).

-- ---------- Ссылки публикации календарей (calendar_publications) ----------
--
-- Одна строка на ссылку (JMAP CalendarPublication, CalDAV-публикация ICS — DAV-20): токен в открытом
-- виде не хранится — только хэш SHA-256 (64 hex, уникален по инсталляции — поиск по нему системной
-- транзакцией: токен не несёт организацию); уровень детализации (detail), срок (expires_at, NULL —
-- без срока) и отзыв (удаление записи — отозванных в списке нет). Истёкшие удаляет обслуживание
-- хранилища (PgMeta::expire_publications), до того отдачу по ним прекращает поиск по токену.
-- Существование календаря проверяет, выдачу и отзыв в журнал аудита записывает вызывающий (SRS 4.4);
-- удаление учётной записи удаляет её ссылки.

CREATE TABLE calendar_publications (
    tenant_id      uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
    account_id     uuid NOT NULL,
    publication_id uuid NOT NULL,
    calendar_id    uuid NOT NULL,
    detail         text NOT NULL CHECK (detail IN ('free_busy', 'limited', 'details')),
    token_hash     text NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz,
    CHECK (expires_at IS NULL OR expires_at > created_at),
    PRIMARY KEY (tenant_id, account_id, publication_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES accounts ON DELETE CASCADE
);

-- Поиск по хэшу — по уникальному индексу; список организации и обслуживание — по времени выдачи.
CREATE INDEX calendar_publications_tenant
    ON calendar_publications (tenant_id, created_at, publication_id);

-- ---------- Шаблоны занятости доменов-партнёров (partner_availability) ----------
--
-- Политика организации (SRS 4.4): шаблон https://-ссылки занятости домена-партнёра — источник
-- `partner` для Availability/get (JMAP-19): `{user}` — локальная часть адреса, `{domain}` — домен;
-- сборку адреса и выборку делает узел (только HTTPS, SSRF-правила отдающего). Домен — партнёр
-- организации (trust_partner_domains, META-85); проверку партнёрства при записи делает узел.
-- Список партнёров меняет политика доверия целиком — строки шаблонов она не трогает: шаблон
-- неактуального домена безвреден и переживает смену списка.

CREATE TABLE partner_availability (
    tenant_id  uuid NOT NULL REFERENCES tenants ON DELETE CASCADE,
    domain     text NOT NULL CHECK (domain = lower(domain)),
    template   text NOT NULL CHECK (template LIKE 'https://%' AND octet_length(template) <= 1024),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, domain)
);

-- ---------- RLS ----------

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['calendar_publications', 'partner_availability']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tp_tenant_visible(tenant_id))'
                       ' WITH CHECK (tp_tenant_visible(tenant_id))', t);
    END LOOP;
END
$$;

-- Права групповых ролей на новые таблицы.
SELECT tp_grant_roles();
