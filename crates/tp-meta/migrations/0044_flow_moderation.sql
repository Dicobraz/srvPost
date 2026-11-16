-- Очередь модерации для правил потока почты (META-44; CTR-43, CONTRACTS.md#Groups; решение 2026-11-11 п. 9).
-- `group_id` допускает NULL: письмо задержано правилом потока, а не группой. Источник задержки — ровно один:
-- группа (`group_id` задан, `rule` пуст) или правило (`group_id` пуст, `rule` — имя правила, 1–255 символов
-- без управляющих). Снимок модераторов письма (учётные записи и группы, порядок как в письме) — `moderators`;
-- исходные получатели конверта (адрес доставки одобренного письма правила) — `recipients`. Существующие строки —
-- письма групп: имя правила пусто, модераторы и получатели — пустые.

ALTER TABLE group_held
    ALTER COLUMN group_id DROP NOT NULL,
    ADD COLUMN rule text
        CHECK (rule IS NULL OR (char_length(rule) BETWEEN 1 AND 255 AND rule !~ '[[:cntrl:]]')),
    ADD COLUMN moderators jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(moderators) = 'array'),
    ADD COLUMN recipients text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT group_held_one_source CHECK ((group_id IS NULL) <> (rule IS NULL));
