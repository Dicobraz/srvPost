//! Хранилище секретов узла: ссылки `{ secret: "<путь>#<поле>" }` в config.yaml разрешаются через [`SecretStore`]
//! (CTR-15; решение 2026-10-30 «Секреты — только через хранилище секретов»).
//!
//! Хранилище — клиент OpenBao/Vault [`VaultStore`] по секции `secrets` (PLT-12); вызывающий может подставить своё
//! (тесты — `MemSecretStore`). Без `secrets.url` конфигурация со ссылками на секреты — явная ошибка запуска
//! «хранилище секретов не настроено», без ссылок узел работает.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tp_contracts::config::duration;
use tp_contracts::secrets::{Secret, SecretRef, SecretStore};
use tp_contracts::{Error, Result};
use tp_platform::secrets::{DoctorReport, DoctorStatus};
use tp_platform::{Config, SecretsConfig, VaultStore};

use crate::sections::{DOCTOR, DoctorSection, STARTUP, StartupSection};

/// Имя секции хранилища секретов (регистрирует платформа).
pub const SECRETS: &str = "secrets";

/// Ссылки на секреты во всех секциях конфигурации, без повторов.
pub fn references(cfg: &Config) -> Vec<String> {
    cfg.secret_refs().map(ToString::to_string).collect()
}

/// Сообщение о ненастроенном хранилище секретов с перечнем ссылок.
fn not_configured(refs: &[String]) -> String {
    format!(
        "хранилище секретов не настроено (задайте секцию secrets: url и способ входа), \
         а в конфигурации есть ссылки на секреты: {}",
        refs.join(", ")
    )
}

/// Хранилище узла: заданное вызывающим; иначе клиент OpenBao/Vault по секции `secrets`; без `secrets.url` —
/// «не настроено» (ссылки на секреты в конфигурации — `Invalid`).
pub async fn store(
    cfg: &Config,
    store: Option<Arc<dyn SecretStore>>,
) -> Result<Arc<dyn SecretStore>> {
    store_with_timeout(cfg, store, Duration::ZERO).await
}

/// Хранилище для проверок `thepost doctor` (FIX-10): как [`store`], но таймаут одного запроса к хранилищу —
/// не меньше бюджета [`login_budget`]: под нагрузкой узла и чтения секретов зависимыми проверками (пароль СУБД,
/// ключи TLS, ключи S3) не должны падать из-за транспортного таймаута, пока бюджет не исчерпан.
pub async fn doctor_store(
    cfg: &Config,
    store: Option<Arc<dyn SecretStore>>,
) -> Result<Arc<dyn SecretStore>> {
    store_with_timeout(cfg, store, login_budget(cfg)).await
}

/// [`store`] с таймаутом одного запроса не меньше `min_timeout`.
async fn store_with_timeout(
    cfg: &Config,
    store: Option<Arc<dyn SecretStore>>,
    min_timeout: Duration,
) -> Result<Arc<dyn SecretStore>> {
    if let Some(store) = store {
        return Ok(store);
    }
    let section = cfg.section::<SecretsConfig>(SECRETS)?;
    if section.url.is_some() {
        let section = if section.request_timeout < min_timeout {
            let mut slow = (*section).clone();
            slow.request_timeout = min_timeout;
            slow
        } else {
            (*section).clone()
        };
        let vault = VaultStore::new(&section, cfg.profile())
            .await
            .map_err(context)?;
        return Ok(Arc::new(vault));
    }
    let refs = references(cfg);
    if !refs.is_empty() {
        return Err(Error::Invalid(not_configured(&refs)));
    }
    Ok(Arc::new(NoSecretStore))
}

/// Секреты конфигурации при запуске узла (APP-31, решение 2026-11-11 п. 58): пока хранилище временно недоступно
/// (не запущено, запечатано, не отвечает), вход и чтение повторяются с растущей паузой до
/// `startup.secrets_timeout`; в журнале — причина и время следующей попытки. Отказ, который повтор не исправит
/// (нет секрета, нет прав, ошибка секции), завершает запуск сразу. По истечении срока — ошибка с причиной.
pub async fn wait_ready(cfg: &Config, store: &dyn SecretStore) -> Result<()> {
    let policy = (*cfg.section::<StartupSection>(STARTUP)?).clone();
    let started = tokio::time::Instant::now();
    let result = retry(
        &policy,
        || started.elapsed(),
        tokio::time::sleep,
        || async {
            // Проба на копии: значения подключит `Reloader::with_secret_store`.
            let mut probe = cfg.clone();
            probe.resolve_secrets(store).await
        },
    )
    .await;
    match result {
        Err(e) if e.is_retryable() => Err(Error::Internal(format!(
            "хранилище секретов недоступно: за {} (startup.secrets_timeout) не удалось войти и прочитать              секреты конфигурации; причина: {}",
            duration::format(policy.secrets_timeout),
            cause(cfg).await
        ))),
        other => other,
    }
}

/// Повторяет `op`, пока ошибка временная и не истёк `policy.secrets_timeout`: пауза растёт вдвое от
/// `secrets_retry_initial` до `secrets_retry_max` (не меньше рекомендованной хранилищем `retry_after`) и не
/// выходит за срок. Часы и ожидание — параметры (тесты — без реального времени).
async fn retry<T, Op, OpFut, Sleep, SleepFut>(
    policy: &StartupSection,
    elapsed: impl Fn() -> Duration,
    mut sleep: Sleep,
    mut op: Op,
) -> Result<T>
where
    Op: FnMut() -> OpFut,
    OpFut: Future<Output = Result<T>>,
    Sleep: FnMut(Duration) -> SleepFut,
    SleepFut: Future<Output = ()>,
{
    let mut pause = policy.secrets_retry_initial;
    let mut attempt = 1u32;
    loop {
        let e = match op().await {
            Ok(v) => {
                if attempt > 1 {
                    tracing::info!(
                        attempt,
                        waited = %duration::format(elapsed()),
                        "хранилище секретов доступно, запуск продолжается"
                    );
                }
                return Ok(v);
            }
            Err(e) => e,
        };
        let Error::Unavailable { retry_after } = &e else {
            return Err(e);
        };
        let left = policy.secrets_timeout.saturating_sub(elapsed());
        if left.is_zero() {
            return Err(e);
        }
        let wait = pause
            .max(retry_after.unwrap_or_default())
            .min(policy.secrets_retry_max.max(policy.secrets_retry_initial))
            .min(left);
        tracing::warn!(
            attempt,
            next_attempt_in = %duration::format(wait),
            give_up_in = %duration::format(left),
            "хранилище секретов временно недоступно (не запущено, запечатано или не отвечает), \
             запуск узла ждёт; причины по каждому секрету — в предупреждениях выше"
        );
        sleep(wait).await;
        pause = pause.saturating_mul(2);
        attempt += 1;
    }
}

/// Причина недоступности хранилища для сообщения об ошибке: первая непройденная проверка `thepost doctor`.
async fn cause(cfg: &Config) -> String {
    use tp_platform::secrets::DoctorStatus;
    doctor(cfg)
        .await
        .checks
        .into_iter()
        .find(|c| c.status == DoctorStatus::Fail)
        .map(|c| format!("{}: {} ({})", c.id, c.message, c.value))
        .unwrap_or_else(|| "хранилище не отвечает; подробности — thepost doctor".to_owned())
}

/// Проверки `thepost doctor` для хранилища секретов (PLT-12): секция, доступность, распечатывание, вход узла,
/// срок токена узла. Таймаут ответа при живом хранилище — не `fail`, а повтор в пределах бюджета
/// [`login_budget`] и `warn` «проверка не успела» (FIX-10, issue #5).
pub async fn doctor(cfg: &Config) -> DoctorReport {
    let section = cfg
        .section::<SecretsConfig>(SECRETS)
        .map(|s| (*s).clone())
        .unwrap_or_default();
    let mut report = tp_platform::secrets::doctor(&section, cfg.profile()).await;
    retry_slow_store(cfg, &section, &mut report).await;
    report
}

/// Бюджет doctor'а на проверки хранилища секретов `doctor.secrets_login_budget` (FIX-10).
pub fn login_budget(cfg: &Config) -> Duration {
    cfg.section::<DoctorSection>(DOCTOR)
        .map(|d| d.secrets_login_budget)
        .unwrap_or_default()
}

/// Проверка не прошла из-за транспортного таймаута: у reqwest — «operation timed out» в причине. Остальные
/// отказы (нет соединения, запечатано, 4xx/5xx) — настоящая недоступность или ошибка настройки, повтор и
/// «не успела» к ним не применяются.
fn timed_out(c: &tp_platform::secrets::DoctorCheck) -> bool {
    c.status == DoctorStatus::Fail && c.message.contains("timed out")
}

/// FIX-10 (issue #5): на нагруженном узле (load 20–70 при 8 vCPU) ответ `/v1/auth/approle/login` не укладывается
/// в транспортный `secrets.request_timeout`, хотя `/v1/sys/health` OpenBao отвечает за единицы миллисекунд, а
/// рабочий процесс узла секреты читает — `doctor` ронял `secrets.login` и каскадом зависимые проверки. Здесь
/// проверки `secrets.store`/`secrets.login` с таймаутом повторяются, пока не исчерпан бюджет
/// `doctor.secrets_login_budget` (таймаут запроса каждой попытки — не меньше остатка бюджета, но не меньше
/// транспортного). Удалось — итог с попытки, отмеченной в сообщении; таймаут и после бюджета — `warn`
/// «проверка не успела» с исходной причиной: «хранилище недоступно» (нет соединения, запечатано, 5xx) и
/// «проверка не успела» (таймаут) различаются, ложных аварий мониторинга на работающих узлах нет.
async fn retry_slow_store(cfg: &Config, section: &SecretsConfig, report: &mut DoctorReport) {
    if !report.checks.iter().any(timed_out) {
        return;
    }
    let budget = login_budget(cfg);
    if budget.is_zero() {
        return;
    }
    let transport = section.request_timeout;
    let started = std::time::Instant::now();
    let mut attempt = 2u32;
    while let Some(left) = budget.checked_sub(started.elapsed()) {
        let mut slow = section.clone();
        slow.request_timeout = transport.max(left);
        let retried = tp_platform::secrets::doctor(&slow, cfg.profile()).await;
        let succeeded = !retried.checks.iter().any(timed_out);
        *report = retried;
        if succeeded {
            if let Some(c) = report
                .checks
                .iter_mut()
                .find(|c| c.id == "secrets_login" && c.status == DoctorStatus::Ok)
            {
                c.message = format!(
                    "{} (удалось с попытки {attempt}: ответ дольше транспортного таймаута {})",
                    c.message,
                    duration::format(transport)
                );
            }
            return;
        }
        attempt += 1;
    }
    for c in report.checks.iter_mut().filter(|c| timed_out(c)) {
        c.status = DoctorStatus::Warn;
        c.message = format!(
            "проверка не успела за {} (бюджет doctor.secrets_login_budget): {}; транспортный таймаут {} \
             исчерпан, но это не отказ хранилища: нет соединения или «запечатано» выглядели бы иначе; узел \
             может работать на прочитанных секретах",
            duration::format(budget),
            c.message,
            duration::format(transport)
        );
    }
}

/// Почему хранилище секретов сейчас не обслуживает запросы узла (FIX-10): непройденная (в том числе «не
/// успела») проверка доступности или входа. Зависимые проверки `doctor` — `database.connect`, `tls.key`,
/// `blob.write` и другие, которым нужен секрет, — тогда не самостоятельны: их реальная причина — хранилище,
/// и она указывается в сообщении вместо голого «unavailable»/«нет ответа», отдельного `fail` не добавляется.
pub fn unavailable_cause(report: &DoctorReport) -> Option<String> {
    let bad = |id: &str| {
        report
            .get(id)
            .filter(|c| matches!(c.status, DoctorStatus::Fail | DoctorStatus::Warn))
            .map(|c| format!("{}: {}", id.replacen('_', ".", 1), c.message))
    };
    bad("secrets_store").or_else(|| bad("secrets_login"))
}

/// Хранилище живо, но отвечает медленнее транспортного таймаута — `secrets.login` удался только с повторной
/// попытки в бюджете [`login_budget`] (FIX-10, issue #5). Зависимые проверки с собственным таймаутом
/// (`database.connect` — `meta.doctor.timeout`) могут не успеть по той же причине — CPU-нагрузка узла, —
/// это не самостоятельный отказ: их сообщения отмечают причину, итог — `warn`.
pub fn slow_store(report: &DoctorReport) -> bool {
    report
        .checks
        .iter()
        .any(|c| c.message.contains("удалось с попытки"))
}

fn context(e: Error) -> Error {
    match e {
        Error::Invalid(m) if !m.starts_with(SECRETS) => Error::Invalid(format!("{SECRETS}: {m}")),
        other => other,
    }
}

/// Хранилище не настроено: любое чтение и запись — `Invalid` с пояснением.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSecretStore;

#[async_trait]
impl SecretStore for NoSecretStore {
    async fn get(&self, secret: &SecretRef) -> Result<Secret> {
        Err(Error::Invalid(not_configured(&[secret.to_string()])))
    }

    async fn put(&self, secret: &SecretRef, _: &Secret) -> Result<()> {
        Err(Error::Invalid(format!(
            "хранилище секретов не настроено (задайте секцию secrets: url и способ входа), \
             запись секрета {secret} невозможна"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sections::registry;
    use tp_platform::secrets::DoctorStatus;

    const DEV: &str = "
domain: example.org
profile: dev
database:
  url: postgres://thepost@localhost/thepost?sslmode=disable
  password: { secret: \"thepost/db#password\" }
  tls: { allow_plaintext: true }
blob:
  url: file:///tmp/blob
";

    fn parse(yaml: &str) -> Config {
        registry()
            .expect("registry")
            .parse(yaml, Vec::new())
            .expect("config")
    }

    #[tokio::test]
    async fn missing_store_with_references_is_explicit_error() {
        let cfg = parse(DEV);
        assert_eq!(references(&cfg), vec!["thepost/db#password".to_owned()]);
        let e = store(&cfg, None).await.err().expect("error").to_string();
        assert!(e.contains("хранилище секретов не настроено"), "{e}");
        assert!(e.contains("thepost/db#password"), "{e}");

        let plain = DEV.replace("  password: { secret: \"thepost/db#password\" }\n", "");
        assert!(store(&parse(&plain), None).await.is_ok());
    }

    #[tokio::test]
    async fn vault_store_from_section() {
        let cfg = parse(&format!(
            "{DEV}secrets:\n  url: http://127.0.0.1:1\n  tls: {{ allow_plaintext: true }}\n  auth:\n    token:\n      token_file: /nonexistent/token\n"
        ));
        // Клиент создаётся без обращения к хранилищу; чтение секрета — ошибка хранилища, а не «не настроено».
        let vault = store(&cfg, None).await.expect("vault");
        let r: SecretRef = "thepost/db#password".parse().expect("ref");
        let e = vault.get(&r).await.expect_err("unreachable").to_string();
        assert!(!e.contains("не настроено"), "{e}");

        let report = doctor(&cfg).await;
        assert_eq!(report.status(), DoctorStatus::Fail, "{report:?}");
        assert_eq!(
            report.get("secrets_store").map(|c| c.status),
            Some(DoctorStatus::Fail),
            "{report:?}"
        );
        assert_eq!(
            doctor(&parse(DEV))
                .await
                .get("secrets_config")
                .map(|c| c.status),
            Some(DoctorStatus::Skipped)
        );
    }

    /// Виртуальные часы: ожидание только сдвигает время и вызывает `on_tick`.
    async fn run_virtual(
        policy: &StartupSection,
        cfg: &Config,
        store: &tp_testkit::MemSecretStore,
        ready_at: Duration,
    ) -> (Result<()>, Duration, Vec<Duration>) {
        use std::cell::{Cell, RefCell};
        let now = Cell::new(Duration::ZERO);
        let pauses = RefCell::new(Vec::new());
        store.seal();
        let r = retry(
            policy,
            || now.get(),
            |d| {
                now.set(now.get() + d);
                pauses.borrow_mut().push(d);
                if now.get() >= ready_at {
                    store.unseal();
                }
                std::future::ready(())
            },
            || async {
                let mut probe = cfg.clone();
                probe.resolve_secrets(store).await
            },
        )
        .await;
        (r, now.get(), pauses.into_inner())
    }

    fn mem_store() -> tp_testkit::MemSecretStore {
        let store = tp_testkit::MemSecretStore::new(Arc::new(tp_testkit::SystemClock));
        store.set(&"thepost/db#password".parse().expect("ref"), "pw");
        store
    }

    /// Приёмка APP-31: хранилище отвечает через 20 с — запуск дожидается его без ошибки (и без перезапуска).
    #[tokio::test]
    async fn slow_store_is_awaited() {
        let cfg = parse(DEV);
        let policy = StartupSection::default();
        let store = mem_store();
        let (r, waited, pauses) = run_virtual(&policy, &cfg, &store, Duration::from_secs(20)).await;
        r.expect("start after 20s");
        assert!(waited >= Duration::from_secs(20) && waited < policy.secrets_timeout);
        // Пауза растёт вдвое и ограничена сверху.
        let secs: Vec<u64> = pauses.iter().map(Duration::as_secs).collect();
        assert_eq!(secs, vec![1, 2, 4, 8, 15]);
    }

    #[tokio::test]
    async fn store_down_longer_than_timeout_fails() {
        let cfg = parse(DEV);
        let policy = StartupSection::default();
        let store = mem_store();
        let (r, waited, _) = run_virtual(&policy, &cfg, &store, Duration::from_secs(600)).await;
        assert!(r.expect_err("timeout").is_retryable());
        assert_eq!(waited, policy.secrets_timeout);
    }

    #[tokio::test]
    async fn permanent_failure_is_not_retried() {
        let cfg = parse(DEV);
        let store = mem_store();
        store.forbid("thepost/db");
        let (r, waited, pauses) = {
            let policy = StartupSection::default();
            let now = std::cell::Cell::new(Duration::ZERO);
            let pauses = std::cell::RefCell::new(Vec::new());
            let r: Result<()> = retry(
                &policy,
                || now.get(),
                |d| {
                    pauses.borrow_mut().push(d);
                    std::future::ready(())
                },
                || async {
                    let mut probe = cfg.clone();
                    probe.resolve_secrets(&store).await
                },
            )
            .await;
            (r, now.get(), pauses.into_inner())
        };
        let e = r.expect_err("forbidden").to_string();
        assert!(e.contains("thepost/db#password"), "{e}");
        assert!(pauses.is_empty() && waited.is_zero());
    }

    /// Узел целиком: `wait_ready` на настоящих часах с короткими паузами; истёкший срок — понятная ошибка.
    #[tokio::test]
    async fn wait_ready_real_clock() {
        let fast = "startup:\n  secrets_timeout: 300ms\n  secrets_retry_initial: 20ms\n  secrets_retry_max: 50ms\n";
        let cfg = parse(&format!("{DEV}{fast}"));
        let store = mem_store();
        store.seal();
        let unseal = store.clone();
        let t = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            unseal.unseal();
        });
        wait_ready(&cfg, &store).await.expect("ready");
        t.await.expect("join");

        store.seal();
        let e = wait_ready(&cfg, &store)
            .await
            .expect_err("timeout")
            .to_string();
        assert!(e.contains("хранилище секретов недоступно"), "{e}");
        assert!(e.contains("startup.secrets_timeout"), "{e}");
    }
}
