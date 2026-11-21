//! Маски ключевых слов Postman (WEB-12): карта «слово → смысл → окно веба» — `docs/CONTRACTS.md#Mail
//! keywords` (SRS Postman `S5-02/S5-03/S5-04`). Сервер хранит их как обычные keywords (RFC 8621 §4.1.1),
//! ничего не интерпретирует; читает их веб-клиент (`web/src/mail/keywords.ts`, WEB-03: полосы и чипы
//! категорий, быстрые фильтры «Угрозы/Срок/Ждём/Мне/Истекают», метки сроков).
//!
//! Канон — нижний регистр слова целиком (IMAP-флаги, `flag_of` в `email_set.rs` приводит слово к
//! нижнему регистру на `Email/set`, `Email/get` возвращает канон): Postman может прислать
//! `pm.due.2026-11-25T1800` — вернётся `pm.due.2026-11-25t1800` (round-trip тесты — `email_set.rs`).
//! Дата — `ГГГГ-ММ-ДД`, время — строчная `t` и `ЧЧММ`; Postman ставит рядом и слово с датой, и общее
//! слово (S5-04) — дата и признак сливаются, а не перезаписывают друг друга.

/// Префикс категории: `pm.cat.<id>` (id — таблица категорий аккаунта, Postman держит её у себя;
/// умолчания веба — `web/src/mail/keywords.ts`: `clients`, `team`, `tenders`, `services`, клавиши 1–9).
pub const CATEGORY_PREFIX: &str = "pm.cat.";

/// Срок (быстрый фильтр «Срок»): общий признак без даты.
pub const DUE: &str = "pm.due";
/// Срок с датой и, если задано, временем: `pm.due.2026-11-25` или `pm.due.2026-11-25t1800`.
pub const DUE_PREFIX: &str = "pm.due.";

/// Ждём ответа (быстрый фильтр «Ждём»): общий признак без даты.
pub const WAIT: &str = "pm.wait";
/// Ждём ответа с датой (и временем): `pm.wait.2026-11-25` или `pm.wait.2026-11-25t1800`.
pub const WAIT_PREFIX: &str = "pm.wait.";

/// Исчезнет (быстрый фильтр «Истекают», автоочистка Postman): общий признак без даты.
pub const EXPIRE: &str = "pm.expire";
/// Исчезнет с датой (и временем): `pm.expire.2026-11-25` или `pm.expire.2026-11-25t1800`.
pub const EXPIRE_PREFIX: &str = "pm.expire.";

/// Угроза (быстрый фильтр «Угрозы», красный — только безопасность).
pub const THREAT: &str = "pm.threat";

#[cfg(test)]
mod tests {
    use super::*;

    /// Маски — в нижнем регистре (канон), сроки с датой начинаются с общего слова.
    #[test]
    fn masks_are_canonical() {
        for word in [DUE, WAIT, EXPIRE, THREAT] {
            assert_eq!(
                word.to_lowercase(),
                word,
                "маска не в нижнем регистре: {word}"
            );
        }
        for prefix in [CATEGORY_PREFIX, DUE_PREFIX, WAIT_PREFIX, EXPIRE_PREFIX] {
            assert!(prefix.ends_with('.'), "префикс без точки: {prefix}");
            assert_eq!(prefix.to_lowercase(), prefix);
        }
        for (prefix, general) in [
            (DUE_PREFIX, DUE),
            (WAIT_PREFIX, WAIT),
            (EXPIRE_PREFIX, EXPIRE),
        ] {
            assert!(
                prefix.starts_with(general),
                "{prefix} не начинается с {general}"
            );
        }
    }
}
