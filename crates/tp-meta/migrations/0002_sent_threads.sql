-- Запись об отправленном и беседы (META-86, CTR-94; решение 125 в, е–ж; CONTRACTS.md#Reply, #Thread).
-- Миграция только добавляет объекты: существующие таблицы не меняются; повторное применение — пустая
-- операция. RLS по tenant_id — как в базовой схеме; владелец таблиц тоже подчиняется (FORCE).

-- ---------- Запись об отправленном (SentLog) ----------
--
-- Запись о письме, отправленном внешним и партнёрским адресатам (решение 125 в): ключ проверки признака
-- «ответ на наше письмо». Метка — случайное значение AEAD-метки Message-ID (шифрует tp-smtp); уникальна в
-- инсталляции, повтор постановки в очередь — та же запись. message_id_hash — SHA-256 канонического
-- Message-ID клиента (ответ с чужим Message-ID, как Rspamd replies). Адресаты — нормализованные адреса
-- (домен в нижнем регистре, A-label); содержимого писем нет. Срок хранения — не меньше smtp.reply.max_age;
-- очистка purge_before — порциями по индексу времени, по всем организациям.

CREATE TABLE sent_log (
    tenant_id       uuid NOT NULL,
    account_id      uuid NOT NULL,
    tag             bytea NOT NULL,
    message_id_hash bytea NOT NULL,
    recipients      text[] NOT NULL,
    thread_id       uuid,
    sent_at         timestamptz NOT NULL,
    PRIMARY KEY (tag)
);

-- Поиск ответов по хэшу Message-ID клиента: свежие первыми.
CREATE INDEX sent_log_mid ON sent_log (tenant_id, message_id_hash, sent_at DESC);
-- Проверки по адресату письма.
CREATE INDEX sent_log_recipients ON sent_log USING gin (recipients);
-- Очистка purge_before: порции старых записей (все организации) по индексу времени.
CREATE INDEX sent_log_purge ON sent_log (sent_at);

-- ---------- Беседы (ThreadStore) ----------
--
-- Беседа учётной записи (JMAP Thread, RFC 8621 §3): threadId неизменяем, беседы задним числом не
-- сливаются. Ключи таблиц содержат tenant_id и account_id: беседы не пересекают учётные записи
-- (одинаковые ключи в разных учётных записях дают разные беседы). Внешних ключей нет (шардирование,
-- SRS 3.6). seq — порядок создания беседы («самая ранняя из найденных»); тот же счётчик — порядок
-- привязки писем. Таблицы на шарде учётной записи, как письма.

-- Порядок создания бесед и привязки писем учётной записи.
CREATE SEQUENCE thread_seq;

-- facts — память беседы для аномалий (решение 125 д): типы вложений, домены ссылок, Reply-To
-- (ограниченные списки без повторов, пределы — ThreadLimits реализации).
CREATE TABLE threads (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    thread_id  uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    seq        bigint NOT NULL,
    facts      jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (tenant_id, account_id, thread_id)
);

-- Письмо — ровно одна беседа, привязка неизменяема (threadId письма не меняется); ord — порядок привязки.
CREATE TABLE thread_messages (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    message_id uuid NOT NULL,
    thread_id  uuid NOT NULL,
    ord        bigint NOT NULL,
    PRIMARY KEY (tenant_id, account_id, message_id)
);

CREATE INDEX thread_messages_thread ON thread_messages (tenant_id, account_id, thread_id, ord);

-- Ключи присоединения (Message-ID писем беседы, каноническая форма join_key): ответ присоединяется к
-- беседе по In-Reply-To/References среди писем учётной записи. Первая привязка ключа не меняется.
CREATE TABLE thread_keys (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    key        text NOT NULL,
    thread_id  uuid NOT NULL,
    PRIMARY KEY (tenant_id, account_id, key)
);

-- Удержание беседы (решение 125 е, как Google Vault): кто, когда, основание. Действует на все письма
-- беседы, включая привязанные после установки; окончательное удаление письма удержанной беседы —
-- Deny в базовой поставке (ThreadHoldHook).
CREATE TABLE thread_holds (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    thread_id  uuid NOT NULL,
    held_by    text NOT NULL,
    held_at    timestamptz NOT NULL,
    reason     text NOT NULL,
    PRIMARY KEY (tenant_id, account_id, thread_id)
);

-- Действие по беседе (решение 125 е; EWS ApplyConversationAction): ThreadRule в jsonb, замена целиком;
-- применяется ко всем письмам беседы, включая будущие.
CREATE TABLE thread_rules (
    tenant_id  uuid NOT NULL,
    account_id uuid NOT NULL,
    thread_id  uuid NOT NULL,
    rule       jsonb NOT NULL,
    PRIMARY KEY (tenant_id, account_id, thread_id)
);

-- ---------- RLS ----------

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'sent_log', 'threads', 'thread_messages', 'thread_keys', 'thread_holds', 'thread_rules']
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tp_tenant_visible(tenant_id))'
                       ' WITH CHECK (tp_tenant_visible(tenant_id))', t);
    END LOOP;
END
$$;

-- Права групповых ролей на новые таблицы и последовательность thread_seq.
SELECT tp_grant_roles();
