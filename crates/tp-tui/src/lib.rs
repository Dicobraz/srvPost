//! Текстовый интерфейс `thepost admin tui` в стиле Midnight Commander — тонкий клиент Admin API (решение 118).
//!
//! - [`app`] — состояние и клавиши: вход, две панели (дерево ресурсов и список/карточка), F1–F10 (TUI-01);
//! - [`ui`] — отрисовка 80×24 по утверждённому макету; [`theme`] — тема по токенам: пять режимов, палитра
//!   консоли Linux (TUI-06), брендинг сервера поверх — название, знак и роли (TUI-08);
//! - [`schema`] и [`engine`] — общий движок списков, карточек и форм по схеме `openapi_spec()` (TUI-02);
//! - [`layout`] — ручные раскладки главных разделов поверх движка (TUI-03);
//! - [`node`] — конфигурация узла `config.yaml` на самом узле (TUI-04);
//! - [`cli`] — эквивалентная команда `thepost admin …` для действия на экране;
//! - [`mouse`] — события мыши: щелчок, двойной, колесо, граница панелей (TUI-07);
//! - [`cursor`] — плавный курсор: kitty/sixel, глифы 2×2, подсветка ячейки (TUI-07);
//! - [`input`] — мышь консоли Linux из `/dev/input` (TUI-07);
//! - [`term`] — запуск в терминале с клиентом `tp-admin-client` ([`run`]).

pub mod app;
pub mod cli;
pub mod cursor;
pub mod engine;
#[cfg(target_os = "linux")]
pub mod input;
pub mod layout;
pub mod mouse;
pub mod node;
pub mod schema;
pub mod term;
pub mod theme;
pub mod tree;
pub mod ui;

pub use node::{ConfigHost, NodeConfig};
pub use term::{Connect, run};
