-- Версия книги «Организация» (META-90; issue #6: md5(string_agg) по всем учётным записям тенанта на
-- каждый цикл maintenance.gal_interval — 1.2 с на school-99). Миграция только добавляет объекты:
-- существующие таблицы не меняются; повторное применение — пустая операция. RLS по tenant_id — как
-- в базовой схеме; владелец таблиц тоже подчиняется (FORCE).

-- ---------- Версия книги (gal_versions) ----------
--
-- Одна строка на организацию: version — монотонно растущий счётчик изменений строк книги (учётные
-- записи, оргатрибуты, группы рассылки, почтовые контакты — карточки книги). Строку организации
-- создаёт первый триггер изменения её строк; исходные строки заполнены ниже, до включения RLS.
-- Внешнего ключа на tenants нет — как у записей ящика: организации приходят и уходят, строка
-- версии их переживает (одна строка, безвредна).

CREATE TABLE gal_versions (
    tenant_id uuid NOT NULL,
    version   bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    PRIMARY KEY (tenant_id)
);

-- Организации реестра; созданные позже получат строку от первого изменения строк книги.
INSERT INTO gal_versions (tenant_id)
    SELECT tenant_id FROM tenants
    ON CONFLICT (tenant_id) DO NOTHING;

-- Любое изменение строки книги поднимает версию её организации.
CREATE FUNCTION tp_gal_version_bump() RETURNS trigger
LANGUAGE plpgsql SET search_path = public, pg_temp AS $$
DECLARE
    t uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        t := OLD.tenant_id;
    ELSE
        t := NEW.tenant_id;
    END IF;
    INSERT INTO gal_versions (tenant_id, version) VALUES (t, 1)
        ON CONFLICT (tenant_id) DO UPDATE SET version = gal_versions.version + 1;
    RETURN NULL;
END
$$;

CREATE TRIGGER tp_gal_version_bump AFTER INSERT OR UPDATE OR DELETE ON accounts
    FOR EACH ROW EXECUTE FUNCTION tp_gal_version_bump();
CREATE TRIGGER tp_gal_version_bump AFTER INSERT OR UPDATE OR DELETE ON org_attributes
    FOR EACH ROW EXECUTE FUNCTION tp_gal_version_bump();
CREATE TRIGGER tp_gal_version_bump AFTER INSERT OR UPDATE OR DELETE ON groups
    FOR EACH ROW EXECUTE FUNCTION tp_gal_version_bump();
CREATE TRIGGER tp_gal_version_bump AFTER INSERT OR UPDATE OR DELETE ON mail_contacts
    FOR EACH ROW EXECUTE FUNCTION tp_gal_version_bump();

-- ---------- RLS ----------

ALTER TABLE gal_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE gal_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON gal_versions USING (tp_tenant_visible(tenant_id))
    WITH CHECK (tp_tenant_visible(tenant_id));

-- Права групповых ролей на новые таблицы.
SELECT tp_grant_roles();
