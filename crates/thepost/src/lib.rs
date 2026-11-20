//! The Post: сборка ролей узла по config.yaml (SRS 2.1), команды `serve`, `config`, `doctor`, `verify`, `admin`.

pub mod acme;
pub mod admin_cli;
pub mod audit_export;
pub mod cli;
pub mod doctor;
pub mod doctor_dns;
pub mod gal;
pub mod help;
pub mod infra;
pub mod journal;
pub mod local_admin;
pub mod log_reader;
pub mod metrics;
pub mod modules;
pub mod openapi;
pub mod profile_signer;
pub mod protocols;
pub mod roles;
pub mod secrets;
pub mod sections;
pub mod serve;
pub mod services;
pub mod startup;
pub mod trust;
pub mod verify;

/// Веб-клиент под `/mail/` (полоса mod-webmail, решение 2026-11-20): wiring раздачи статики на слушателе
/// JMAP. Файл правит полоса mod-webmail (lanes.toml), остальные файлы крейта — полоса app.
#[cfg(feature = "webmail")]
pub mod webmail;

#[cfg(test)]
mod testutil;
