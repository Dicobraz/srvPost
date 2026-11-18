//! Брендинг заказчика на PostgreSQL (META-84; CTR-91): набор `tp-testkit`. Без `TEST_DATABASE_URL`
//! тесты пропускаются.

mod common;

use tp_testkit::suite;

/// Набор на своей чистой БД: уровень установки — одна строка на всю БД, параллельные тесты на общей БД его бы
/// делили.
#[tokio::test]
async fn branding_passes_contract_suite() {
    let Some(db) = common::fresh_meta().await else {
        return;
    };
    let meta = &db.meta;
    let org = common::tenant(meta.pool()).await;
    let foreign = common::tenant(meta.pool()).await;
    suite::branding(meta, org, foreign).await;
    db.drop_db().await;
}
