//! Встроенный клиент ACME для профиля SMB (SRS 6.2): выпуск сертификата по HTTP-01 (ответ на проверку отдаёт
//! служебный HTTP — [`challenge_router`]), продление, когда осталось меньше `min(renew_before, доли срока
//! жизни)` (`acme.renew_share`, по умолчанию ⅓ — сроки публичных сертификатов сокращаются, ballot SC-081v3;
//! cert-manager и Caddy — по той же доле), перечитывание [`TlsCerts`] без перезапуска.
//!
//! Окно продления, подсказанное сервером (ARI, RFC 9773), важнее календаря: для выпущенного сертификата
//! (серийный номер + идентификатор ключа уполномоченного CA из цепочки — [`certificate_identifier`]) сервер
//! отвечает `RenewalInfo` с `suggestedWindow` — продлевать, когда проверка попала в окно; «уже сейчас» —
//! сертификат отмечен к замене (досрочный отзыв, массовый перевыпуск). Сервер без `renewalInfo` в каталоге —
//! как раньше, по календарю; ошибка запроса ARI — предупреждение в журнал, не отказ продления.
//!
//! Ключ TLS — только в хранилище секретов (решение 100, PLT-29): выпущенный ключ пишется новой версией секрета
//! `tls.key` ([`SecretStore::put`]), затем цепочка — в `tls.cert_file`. Ошибка записи ключа — `ERROR` в журнал,
//! прежняя пара остаётся; ошибка записи цепочки — прежний ключ возвращается в секрет. Узлу нужна запись только
//! своего пути ключа TLS (политика хранилища — DEP-44).
//!
//! Учётная запись ACME сохраняется в `state_dir/account.yaml`, список доменов последнего выпуска — в
//! `state_dir/domains` (смена доменов вызывает перевыпуск). Срок действия читается из сертификата на диске.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use instant_acme::{
    Account, AccountBuilder, AccountCredentials, AuthorizationStatus, BodyWrapper, BytesResponse,
    CertificateIdentifier, ChallengeType, HttpClient, Identifier, NewAccount, NewOrder,
    OrderStatus, RetryPolicy,
};
use rustls::pki_types::Der;
use schemars::JsonSchema;
use serde::Deserialize;
use tp_contracts::Error;
use tp_contracts::config::duration;
use tp_contracts::role::CancellationToken;
use tp_contracts::secrets::{Secret, SecretRef, SecretStore};

use crate::tls::{TlsCerts, TlsConfig};

/// Секция `acme`.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct AcmeConfig {
    /// Встроенный клиент ACME включён (SMB). Enterprise — файлы или секреты Kubernetes (cert-manager).
    pub enabled: bool,
    /// Адрес каталога ACME.
    pub directory_url: String,
    /// Контакты учётной записи (`mailto:admin@example.org`).
    pub contact: Vec<String>,
    /// Имена в сертификате (первое — основное). Обязательно при `enabled`.
    pub domains: Vec<String>,
    /// Каталог состояния: учётная запись ACME и список доменов последнего выпуска.
    pub state_dir: PathBuf,
    /// Максимальное окно продления: осталось меньше `min(renew_before, доли срока жизни)` сертификата (`30d`).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub renew_before: Duration,
    /// Доля срока жизни сертификата в окне продления: окно — `min(renew_before, renew_share × срок)` (`0.34` ≈
    /// треть; короткие сертификаты — ballot SC-081v3, профиль Let's Encrypt на 6 дней — продлеваются на заметной
    /// доле срока, а не за фиксированные 30 дней). Значение из `(0, 1]`.
    #[serde(deserialize_with = "share")]
    pub renew_share: f64,
    /// Период проверки срока действия (`12h`).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub check_interval: Duration,
    /// Пауза перед повтором после неудачного выпуска (`1h`).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub retry_interval: Duration,
    /// Время ожидания проверки и выпуска на стороне ACME (`5m`).
    #[serde(with = "duration")]
    #[schemars(with = "duration::HumanDuration")]
    pub order_timeout: Duration,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory_url: instant_acme::LetsEncrypt::Production.url().to_owned(),
            contact: Vec::new(),
            domains: Vec::new(),
            state_dir: PathBuf::from("/var/lib/thepost/acme"),
            renew_before: Duration::from_secs(30 * 86_400),
            renew_share: 1.0 / 3.0,
            check_interval: Duration::from_secs(12 * 3600),
            retry_interval: Duration::from_secs(3600),
            order_timeout: Duration::from_secs(300),
        }
    }
}

/// Доля срока для окна продления (`acme.renew_share`): число из `(0, 1]`, другое — ошибка разбора секции.
fn share<'de, D>(d: D) -> Result<f64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = f64::deserialize(d)?;
    if value.is_finite() && value > 0.0 && value <= 1.0 {
        Ok(value)
    } else {
        Err(serde::de::Error::invalid_value(
            serde::de::Unexpected::Float(value),
            &"a share of the certificate lifetime in (0, 1]",
        ))
    }
}

impl AcmeConfig {
    /// Эффективное окно продления для срока жизни `lifetime` (PLT-37, PLT-40): `min(renew_before,
    /// renew_share × срок)`; срок не определён (`ZERO` — `notBefore` не разобрался) — фиксированное
    /// `renew_before`.
    pub fn renewal_window(&self, lifetime: Duration) -> Duration {
        if lifetime.is_zero() {
            return self.renew_before;
        }
        self.renew_before.min(lifetime.mul_f64(self.renew_share))
    }
}

#[derive(Debug, thiserror::Error)]
enum AcmeError {
    #[error("acme: {0}")]
    Acme(#[from] instant_acme::Error),
    #[error("acme: {0}")]
    Protocol(String),
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("acme state: {0}")]
    State(#[from] serde_yaml_ng::Error),
    #[error("acme.domains is empty")]
    NoDomains,
    #[error("tls.key: secret {secret}: {source}")]
    KeyStore { secret: SecretRef, source: Error },
    #[error("acme: storage task failed")]
    Join,
}

impl From<AcmeError> for Error {
    fn from(e: AcmeError) -> Self {
        match e {
            AcmeError::Acme(_) | AcmeError::Protocol(_) => {
                // Подробности — в журнале: `Unavailable` сообщения не несёт.
                tracing::warn!(error = %e, "acme request failed");
                Error::UNAVAILABLE
            }
            AcmeError::NoDomains => Error::Invalid(e.to_string()),
            AcmeError::KeyStore { source, .. } => source,
            _ => Error::Internal(e.to_string()),
        }
    }
}

/// Ответы на проверки HTTP-01: токен → key authorization. Клонируется; заполняет [`Acme`], отдаёт служебный HTTP.
#[derive(Debug, Clone, Default)]
pub struct Http01Challenges(Arc<RwLock<HashMap<String, String>>>);

impl Http01Challenges {
    /// Ответ на токен.
    pub fn get(&self, token: &str) -> Option<String> {
        self.0
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .get(token)
            .cloned()
    }

    /// Публикует ответ на токен. Заполняет [`Acme`]; открыт для тестов вызывающего (ответ HTTP-01 по токену).
    #[doc(hidden)]
    pub fn insert(&self, token: String, key_authorization: String) {
        self.0
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(token, key_authorization);
    }

    fn remove(&self, token: &str) {
        self.0
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(token);
    }
}

/// Маршрут `/.well-known/acme-challenge/{token}` для служебного HTTP: `service_http::router(..).merge(..)`.
pub fn challenge_router(challenges: Http01Challenges) -> Router {
    Router::new()
        .route(
            "/.well-known/acme-challenge/{token}",
            get(challenge_handler),
        )
        .with_state(challenges)
}

async fn challenge_handler(
    State(challenges): State<Http01Challenges>,
    UrlPath(token): UrlPath<String>,
) -> Response {
    match challenges.get(&token) {
        Some(answer) => answer.into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Клиент ACME узла.
pub struct Acme {
    cfg: AcmeConfig,
    tls: TlsConfig,
    challenges: Http01Challenges,
    certs: Option<Arc<TlsCerts>>,
    keys: Arc<dyn SecretStore>,
    http: Option<Arc<dyn HttpClient>>,
}

impl fmt::Debug for Acme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Acme")
            .field("directory_url", &self.cfg.directory_url)
            .field("domains", &self.cfg.domains)
            .finish_non_exhaustive()
    }
}

impl Acme {
    /// Клиент по секции `acme`: ключ пишется в секрет `tls.key` хранилища `keys` (то же, из которого его читает
    /// `certs`), цепочка — в `tls.cert_file`, затем перечитывается `certs`.
    pub fn new(
        cfg: AcmeConfig,
        tls: TlsConfig,
        challenges: Http01Challenges,
        certs: Option<Arc<TlsCerts>>,
        keys: Arc<dyn SecretStore>,
    ) -> Self {
        // Встроенный HTTP-клиент instant-acme берёт процессный провайдер rustls.
        crate::tls::install_crypto_provider();
        Self {
            cfg,
            tls,
            challenges,
            certs,
            keys,
            http: None,
        }
    }

    /// HTTP-клиент для обращений к ACME вместо встроенного (свои корневые сертификаты, прокси, тесты).
    pub fn with_http(mut self, http: Arc<dyn HttpClient>) -> Self {
        self.http = Some(http);
        self
    }

    /// Выпускает сертификат, если его нет, домены изменились или до истечения меньше `renew_before`.
    /// `true` — сертификат выпущен.
    pub async fn renew_if_needed(&self) -> tp_contracts::Result<bool> {
        self.renew_if_needed_at(SystemTime::now()).await
    }

    /// [`Self::renew_if_needed`] на момент `now`.
    pub async fn renew_if_needed_at(&self, now: SystemTime) -> tp_contracts::Result<bool> {
        if !self.needs_renewal_at(now).await? {
            return Ok(false);
        }
        self.issue().await?;
        Ok(true)
    }

    /// Нужен ли выпуск на момент `now`: сертификата нет, домены изменились, срок истёк — да; иначе окно,
    /// подсказанное сервером (ARI, RFC 9773), пока оно не миновало, — проверка попала в `[start, end)`; без
    /// подсказки (её нет или она миновала) — календарное окно: осталось меньше `min(renew_before, треть срока
    /// жизни)` (⅔ срока прошли). Срок жизни читается из `notBefore`; нестандартное время — прежнее поведение,
    /// фиксированное `renew_before`.
    pub async fn needs_renewal_at(&self, now: SystemTime) -> tp_contracts::Result<bool> {
        if self.cfg.domains.is_empty() {
            return Err(AcmeError::NoDomains.into());
        }
        let cert_file = self.tls.cert_file.clone();
        let domains_file = self.domains_file();
        let (cert_pem, issued_for) = tokio::task::spawn_blocking(move || {
            let cert_pem = std::fs::read_to_string(&cert_file).ok();
            let issued_for = std::fs::read_to_string(&domains_file).ok();
            (cert_pem, issued_for)
        })
        .await
        .map_err(|_| AcmeError::Join)?;
        let Some(chain) = cert_pem else {
            return Ok(true);
        };
        if issued_for.as_deref() != Some(self.domains_text().as_str()) {
            return Ok(true);
        }
        let (not_before, not_after) = pem_validity(&chain);
        let Some(not_after) = not_after else {
            return Ok(true);
        };
        if now >= not_after {
            return Ok(true);
        }
        if let Some(renews) = self.ari_renews(&chain, now).await {
            return Ok(renews);
        }
        // Срок жизни по `notBefore`; если его разобрать не удалось (нестандартный формат) — прежнее поведение,
        // фиксированное `renew_before`.
        let lifetime = not_before
            .and_then(|nb| not_after.duration_since(nb).ok())
            .unwrap_or(Duration::ZERO);
        Ok(now + self.cfg.renewal_window(lifetime) >= not_after)
    }

    /// Окно продления от сервера (ARI): `Some(true)` — проверка попала в подсказанное окно (`start <= now <
    /// end`, «уже сейчас» — сертификат отмечен к замене); `None` — подсказки нет, решает календарь: окно
    /// миновало без выпуска (узел был недоступен), сервер без `renewalInfo` в каталоге — как раньше, без
    /// предупреждений; не удался запрос — предупреждение в журнал.
    async fn ari_renews(&self, chain: &str, now: SystemTime) -> Option<bool> {
        let cert_id = certificate_identifier(chain)?;
        let account = match self.account().await {
            Ok(account) => account,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "acme: account unavailable, renewal follows the calendar"
                );
                return None;
            }
        };
        match account.renewal_info(&cert_id).await {
            Ok((info, _retry_after)) => {
                let start = SystemTime::from(info.suggested_window.start);
                let end = SystemTime::from(info.suggested_window.end);
                tracing::debug!(start = ?start, end = ?end, "acme: renewal window from the server");
                if now >= end { None } else { Some(now >= start) }
            }
            // В каталоге нет `renewalInfo` — сервер ARI не поддерживает.
            Err(instant_acme::Error::Unsupported(_)) => None,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "acme: renewal info unavailable, renewal follows the calendar"
                );
                None
            }
        }
    }

    /// Выпускает сертификат безусловно: заказ, проверки HTTP-01, финализация, запись ключа в секрет и цепочки в
    /// файл, перечитывание TLS.
    pub async fn issue(&self) -> tp_contracts::Result<()> {
        Ok(self.try_issue().await?)
    }

    /// Проверяет сертификат каждые `check_interval` (после ошибки — через `retry_interval`) до сигнала остановки.
    pub async fn run(self, shutdown: CancellationToken) {
        if !self.cfg.enabled {
            return;
        }
        loop {
            let wait = match self.renew_if_needed().await {
                Ok(issued) => {
                    if issued {
                        tracing::info!(domains = ?self.cfg.domains, "acme certificate issued");
                    }
                    self.cfg.check_interval
                }
                Err(e) => {
                    tracing::warn!(error = %e, "acme renewal failed");
                    self.cfg.retry_interval
                }
            };
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(wait.max(Duration::from_secs(1))) => {}
            }
        }
    }

    async fn try_issue(&self) -> Result<(), AcmeError> {
        if self.cfg.domains.is_empty() {
            return Err(AcmeError::NoDomains);
        }
        let key_ref = self.tls.key.clone();
        let account = self.account().await?;
        let identifiers: Vec<Identifier> = self
            .cfg
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
        let mut order = account.new_order(&NewOrder::new(&identifiers)).await?;

        let mut tokens = Vec::new();
        let result = async {
            let mut authorizations = order.authorizations();
            while let Some(authz) = authorizations.next().await {
                let mut authz = authz?;
                match authz.status {
                    AuthorizationStatus::Valid => continue,
                    AuthorizationStatus::Pending => {}
                    status => {
                        return Err(AcmeError::Protocol(format!("authorization is {status:?}")));
                    }
                }
                let mut challenge = authz.challenge(ChallengeType::Http01).ok_or_else(|| {
                    AcmeError::Protocol("no http-01 challenge offered".to_owned())
                })?;
                let token = challenge.token.clone();
                self.challenges.insert(
                    token.clone(),
                    challenge.key_authorization().as_str().to_owned(),
                );
                tokens.push(token);
                challenge.set_ready().await?;
            }
            let retry = RetryPolicy::new().timeout(self.cfg.order_timeout);
            let status = order.poll_ready(&retry).await?;
            if status != OrderStatus::Ready {
                return Err(AcmeError::Protocol(format!("order is {status:?}")));
            }
            let key_pem = order.finalize().await?;
            let chain_pem = order.poll_certificate(&retry).await?;
            Ok((key_pem, chain_pem))
        }
        .await;
        for token in &tokens {
            self.challenges.remove(token);
        }
        let (key_pem, chain_pem) = result?;
        check_pair(&chain_pem, &key_pem)?;
        let key = Secret::new(key_pem);

        // Прежний ключ — для возврата, если цепочку записать не удастся (пары ещё нет — возвращать нечего).
        let previous = match self.keys.get(&key_ref).await {
            Ok(old) => Some(old),
            Err(Error::NotFound) => None,
            Err(source) => return Err(key_not_stored(key_ref, source)),
        };
        if let Err(source) = self.keys.put(&key_ref, &key).await {
            return Err(key_not_stored(key_ref, source));
        }
        let cert_file = self.tls.cert_file.clone();
        let written = tokio::task::spawn_blocking(move || {
            write_atomic(&cert_file, chain_pem.as_bytes(), false)
        })
        .await
        .map_err(|_| AcmeError::Join)
        .and_then(|r| r);
        if let Err(e) = written {
            tracing::error!(error = %e, "acme: certificate chain not written");
            if let Some(old) = previous
                && let Err(source) = self.keys.put(&key_ref, &old).await
            {
                tracing::error!(
                    secret = %key_ref,
                    error = %source,
                    "acme: previous tls key not restored, key and certificate differ"
                );
            }
            return Err(e);
        }
        if let Some(certs) = &self.certs {
            certs
                .reload()
                .await
                .map_err(|e| AcmeError::Protocol(format!("issued certificate rejected: {e}")))?;
        }
        // Список доменов — после пары: его потеря вызывает лишь повторный выпуск.
        let domains_file = self.domains_file();
        let domains = self.domains_text();
        tokio::task::spawn_blocking(move || write_atomic(&domains_file, domains.as_bytes(), false))
            .await
            .map_err(|_| AcmeError::Join)??;
        Ok(())
    }

    /// Учётная запись из `account.yaml` или новая (сохраняется).
    async fn account(&self) -> Result<Account, AcmeError> {
        let path = self.cfg.state_dir.join("account.yaml");
        let read = path.clone();
        let stored = tokio::task::spawn_blocking(move || match std::fs::read_to_string(&read) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(AcmeError::Io { path: read, source }),
        })
        .await
        .map_err(|_| AcmeError::Join)??;
        if let Some(text) = stored {
            let credentials: AccountCredentials = serde_yaml_ng::from_str(&text)?;
            return Ok(self.builder()?.from_credentials(credentials).await?);
        }
        let contact: Vec<&str> = self.cfg.contact.iter().map(String::as_str).collect();
        let (account, credentials) = self
            .builder()?
            .create(
                &NewAccount {
                    contact: &contact,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.cfg.directory_url.clone(),
                None,
            )
            .await?;
        let text = serde_yaml_ng::to_string(&credentials)?;
        tokio::task::spawn_blocking(move || write_private(&path, text.as_bytes()))
            .await
            .map_err(|_| AcmeError::Join)??;
        Ok(account)
    }

    fn builder(&self) -> Result<AccountBuilder, AcmeError> {
        Ok(match &self.http {
            Some(http) => Account::builder_with_http(Box::new(SharedHttp(http.clone()))),
            None => Account::builder()?,
        })
    }

    fn domains_file(&self) -> PathBuf {
        self.cfg.state_dir.join("domains")
    }

    fn domains_text(&self) -> String {
        self.cfg.domains.join("\n")
    }
}

/// Разделяемый HTTP-клиент: `AccountBuilder` забирает клиент во владение.
struct SharedHttp(Arc<dyn HttpClient>);

impl HttpClient for SharedHttp {
    fn request(
        &self,
        req: axum::http::Request<BodyWrapper<axum::body::Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        self.0.request(req)
    }
}

/// Проверяет до записи на диск: цепочка читается, срок известен, ключ соответствует сертификату.
fn check_pair(chain_pem: &str, key_pem: &str) -> Result<(), AcmeError> {
    let bad = |what: &str| AcmeError::Protocol(format!("issued certificate rejected: {what}"));
    if pem_not_after(chain_pem).is_none() {
        return Err(bad("chain is not readable"));
    }
    let chain = rustls_pemfile::certs(&mut chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| bad("chain is not readable"))?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .ok()
        .flatten()
        .ok_or_else(|| bad("key is not readable"))?;
    crate::tls::server_config(chain, key, crate::tls::TlsVersion::Tls13)
        .map_err(|e| bad(&e.to_string()))?;
    Ok(())
}

/// Ключ не записан в секрет: `ERROR` в журнал, прежняя пара остаётся.
fn key_not_stored(secret: SecretRef, source: Error) -> AcmeError {
    tracing::error!(secret = %secret, error = %source, "acme: tls key not stored, previous pair kept");
    AcmeError::KeyStore { secret, source }
}

/// Закрытые данные (учётная запись): права 0600.
fn write_private(path: &Path, data: &[u8]) -> Result<(), AcmeError> {
    write_atomic(path, data, true)
}

/// Запись через временный файл и rename: читатель видит старую или новую версию целиком.
fn write_atomic(path: &Path, data: &[u8], private: bool) -> Result<(), AcmeError> {
    let io = |source| AcmeError::Io {
        path: path.to_owned(),
        source,
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(io)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options.open(&tmp).map_err(io)?;
    file.write_all(data).map_err(io)?;
    file.sync_all().map_err(io)?;
    std::fs::rename(&tmp, path).map_err(io)
}

/// `notAfter` первого сертификата PEM-цепочки.
fn pem_not_after(pem: &str) -> Option<SystemTime> {
    let der = rustls_pemfile::certs(&mut pem.as_bytes()).next()?.ok()?;
    cert_validity(&der).1
}

/// `notBefore` и `notAfter` первого сертификата PEM-цепочки; время, разобрать которое не удалось, — `None`.
fn pem_validity(pem: &str) -> (Option<SystemTime>, Option<SystemTime>) {
    match rustls_pemfile::certs(&mut pem.as_bytes()).next() {
        Some(Ok(der)) => cert_validity(&der),
        _ => (None, None),
    }
}

/// Срок сертификата X.509 (DER): Certificate → TBSCertificate → [version] serial signature issuer validity;
/// `validity` — `notBefore`, `notAfter`. Время в нестандартном формате — `None`.
fn cert_validity(der: &[u8]) -> (Option<SystemTime>, Option<SystemTime>) {
    cert_validity_der(der).unwrap_or_default()
}

/// Ход разбора `cert_validity`; неразобранный сертификат — `None`.
fn cert_validity_der(der: &[u8]) -> Option<(Option<SystemTime>, Option<SystemTime>)> {
    let (_, cert, _) = der_tlv(der).filter(|(tag, _, _)| *tag == 0x30)?;
    let (_, tbs, _) = der_tlv(cert).filter(|(tag, _, _)| *tag == 0x30)?;
    let mut rest = tbs;
    if rest.first() == Some(&0xa0) {
        rest = der_tlv(rest)?.2;
    }
    for _ in 0..3 {
        rest = der_tlv(rest)?.2; // serialNumber, signature, issuer
    }
    let (_, validity, _) = der_tlv(rest).filter(|(tag, _, _)| *tag == 0x30)?;
    let (before_tag, not_before, rest) = der_tlv(validity)?;
    let (after_tag, not_after, _) = der_tlv(rest)?;
    Some((
        der_time(before_tag, not_before),
        der_time(after_tag, not_after),
    ))
}

/// Идентификатор сертификата для ARI (RFC 9773 §4.1): серийный номер и идентификатор ключа уполномоченного CA
/// (AKI) первого сертификата цепочки, base64url. Без AKI (сертификат не от уполномоченного CA) — `None`.
fn certificate_identifier(pem: &str) -> Option<CertificateIdentifier<'static>> {
    let der = rustls_pemfile::certs(&mut pem.as_bytes()).next()?.ok()?;
    cert_identifier_der(&der)
}

/// Идентификатор из DER: TBSCertificate → serialNumber; extensions ([3]) → 2.5.29.35 → `keyIdentifier`.
fn cert_identifier_der(der: &[u8]) -> Option<CertificateIdentifier<'static>> {
    const AKI_OID: &[u8] = &[0x55, 0x1d, 0x23]; // 2.5.29.35 (content)
    let (_, cert, _) = der_tlv(der).filter(|(tag, _, _)| *tag == 0x30)?;
    let (_, tbs, _) = der_tlv(cert).filter(|(tag, _, _)| *tag == 0x30)?;
    let mut rest = tbs;
    if rest.first() == Some(&0xa0) {
        rest = der_tlv(rest)?.2;
    }
    // Серийный номер — байты INTEGER как есть (RFC 9773 §4.1: DER-кодирование, не bigint).
    let (_, serial, mut rest) = der_tlv(rest).filter(|(tag, _, _)| *tag == 0x02)?;
    let mut aki = None;
    while !rest.is_empty() {
        let tag = *rest.first()?;
        if tag == 0xa3 {
            let (_, wrapped, tail) = der_tlv(rest)?;
            rest = tail;
            let (_, extensions, _) = der_tlv(wrapped).filter(|(tag, _, _)| *tag == 0x30)?;
            aki = aki_key_identifier(extensions, AKI_OID);
        } else if (0x01..=0x7f).contains(&tag) || tag == 0xa1 || tag == 0xa2 {
            rest = der_tlv(rest)?.2; // signature, issuer, validity, subject, subjectPKInfo, [1], [2]
        } else {
            return None;
        }
    }
    let aki = aki?;
    Some(CertificateIdentifier::new(
        Der::from(aki),
        Der::from(serial.to_vec()),
    ))
}

/// Байты `keyIdentifier` расширения 2.5.29.35 (AKI); другие расширения пропускаются.
fn aki_key_identifier(mut extensions: &[u8], aki_oid: &[u8]) -> Option<Vec<u8>> {
    while !extensions.is_empty() {
        let (_, ext, tail) = der_tlv(extensions).filter(|(tag, _, _)| *tag == 0x30)?;
        extensions = tail;
        let (_, oid, fields) = der_tlv(ext)?;
        if oid != aki_oid {
            continue;
        }
        // critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING → AuthorityKeyIdentifier SEQUENCE →
        // [0] keyIdentifier.
        let fields = if fields.first() == Some(&0x01) {
            der_tlv(fields)?.2
        } else {
            fields
        };
        let (_, value, _) = der_tlv(fields).filter(|(tag, _, _)| *tag == 0x04)?;
        let (_, sequence, _) = der_tlv(value).filter(|(tag, _, _)| *tag == 0x30)?;
        let (_, key_id, _) = der_tlv(sequence).filter(|(tag, _, _)| *tag == 0x80)?;
        return Some(key_id.to_vec());
    }
    None
}

/// Элемент DER: (тег, содержимое, остаток).
fn der_tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = usize::from(*b.get(1)?);
    let (len, head) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let len = b
            .get(2..2 + n)?
            .iter()
            .fold(0usize, |acc, x| (acc << 8) | usize::from(*x));
        (len, 2 + n)
    };
    let end = head.checked_add(len)?;
    Some((tag, b.get(head..end)?, b.get(end..)?))
}

/// UTCTime (`YYMMDDHHMMSSZ`) или GeneralizedTime (`YYYYMMDDHHMMSSZ`) → время.
fn der_time(tag: u8, value: &[u8]) -> Option<SystemTime> {
    let s = std::str::from_utf8(value).ok()?.strip_suffix('Z')?;
    let (year, rest) = match tag {
        0x17 if s.len() == 12 => {
            let yy: i64 = s.get(..2)?.parse().ok()?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, s.get(2..)?)
        }
        0x18 if s.len() == 14 => (s.get(..4)?.parse().ok()?, s.get(4..)?),
        _ => return None,
    };
    let num = |r: std::ops::Range<usize>| rest.get(r)?.parse::<i64>().ok();
    let (month, day) = (num(0..2)?, num(2..4)?);
    let (hour, min, sec) = (num(4..6)?, num(6..8)?, num(8..10)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return None;
    }
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec;
    Some(UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).ok()?))
}

/// Дней от 1970-01-01 до даты григорианского календаря (H. Hinnant, `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    use axum::body::Bytes;
    use axum::body::HttpBody as _;
    use axum::http::{Method, Request};

    use tp_contracts::secrets::SecretStore;
    use tp_testkit::MemSecretStore;

    use super::*;
    use crate::tls::tests::{CERT_A, CERT_B, KEY_A, TempDir, der};

    /// Хранилище ключа TLS в памяти с записью: число записей, отказ записи по флагу.
    #[derive(Default)]
    struct Keys {
        mem: MemSecretStore,
        puts: AtomicUsize,
        fail_put: AtomicBool,
    }

    #[async_trait::async_trait]
    impl SecretStore for Keys {
        async fn get(&self, secret: &SecretRef) -> tp_contracts::Result<Secret> {
            self.mem.get(secret).await
        }

        async fn put(&self, secret: &SecretRef, value: &Secret) -> tp_contracts::Result<()> {
            if self.fail_put.load(Ordering::SeqCst) {
                return Err(Error::Forbidden);
            }
            self.puts.fetch_add(1, Ordering::SeqCst);
            self.mem.put(secret, value).await
        }
    }

    impl Keys {
        async fn key(&self) -> Option<String> {
            self.mem
                .get(&key_ref())
                .await
                .ok()
                .map(|s| s.expose().to_owned())
        }
    }

    fn key_ref() -> SecretRef {
        SecretRef::new("thepost/tls", "key").expect("ref")
    }

    const BASE: &str = "https://acme.test";
    const TOKEN: &str = "tok-ABC_123";
    const DOMAIN: &str = "mail.example.org";
    /// Идентификатор ключа уполномоченного CA в тестовых сертификатах (AKI, RFC 9773 §4.1).
    const AKI: &[u8] = &[0xC0, 0xFF, 0xEE];
    /// certId тестового сертификата: идентификатор ключа CA — серийный номер 1 (INTEGER `01`), base64url.
    const CERT_ID: &str = "wP_u.AQ";

    /// Мок каталога ACME (RFC 8555) без сети: маршруты по методу и пути. Ответ на проверку HTTP-01 берётся
    /// из [`Http01Challenges`] — как его забрал бы сервер ACME; сертификат выпускается на ключ из CSR.
    struct MockAcme {
        challenges: Http01Challenges,
        /// Вместо выпуска по CSR отдать эту цепочку.
        fixed_chain: Option<String>,
        state: Mutex<MockState>,
        nonces: AtomicUsize,
    }

    #[derive(Default)]
    struct MockState {
        accounts: usize,
        orders: usize,
        validated: bool,
        chain: Option<String>,
        /// Сервер объявил `renewalInfo` в каталоге (поддержка ARI, RFC 9773).
        ari_url: bool,
        /// Окно продления (RFC 3339): подсказка сервера.
        ari_window: Option<(&'static str, &'static str)>,
        /// Endpoint ARI объявлен, но отвечает ошибкой.
        ari_error: bool,
        /// certId последнего запроса ARI.
        last_cert_id: Option<String>,
    }

    type Reply = (u16, Option<String>, String);

    impl MockAcme {
        fn respond(&self, method: &Method, path: &str, body: &[u8]) -> Reply {
            let mut st = self.state.lock().expect("mock state");
            let order = |st: &MockState| {
                let status = match (st.validated, st.chain.is_some()) {
                    (_, true) => "valid",
                    (true, false) => "ready",
                    _ => "pending",
                };
                format!(
                    r#"{{"status":"{status}","authorizations":["{BASE}/authz/1"],"finalize":"{BASE}/order/1/finalize","certificate":"{BASE}/cert/1"}}"#
                )
            };
            let problem = |kind: &str| format!(r#"{{"type":"urn:ietf:params:acme:error:{kind}"}}"#);
            match (method.as_str(), path) {
                ("GET", "/directory") => (
                    200,
                    None,
                    if st.ari_url {
                        format!(
                            r#"{{"newNonce":"{BASE}/nonce","newAccount":"{BASE}/account","newOrder":"{BASE}/order/new","renewalInfo":"{BASE}/renewal-info"}}"#
                        )
                    } else {
                        format!(
                            r#"{{"newNonce":"{BASE}/nonce","newAccount":"{BASE}/account","newOrder":"{BASE}/order/new"}}"#
                        )
                    },
                ),
                ("GET", ari) if ari.starts_with("/renewal-info/") => {
                    st.last_cert_id = Some(ari.trim_start_matches("/renewal-info/").to_owned());
                    if st.ari_error {
                        (500, None, problem("serverInternal"))
                    } else {
                        match st.ari_window {
                            Some((start, end)) => (
                                200,
                                None,
                                format!(
                                    r#"{{"suggestedWindow":{{"start":"{start}","end":"{end}"}}}}"#
                                ),
                            ),
                            None => (404, None, problem("malformed")),
                        }
                    }
                }
                ("HEAD", "/nonce") => (200, None, String::new()),
                ("POST", "/account") => {
                    st.accounts += 1;
                    (
                        201,
                        Some("/acct/1".to_owned()),
                        r#"{"status":"valid"}"#.to_owned(),
                    )
                }
                ("POST", "/order/new") => {
                    st.orders += 1;
                    st.validated = false;
                    st.chain = None;
                    (201, Some("/order/1".to_owned()), order(&st))
                }
                ("POST", "/authz/1") => {
                    let status = if st.validated { "valid" } else { "pending" };
                    (
                        200,
                        None,
                        format!(
                            r#"{{"identifier":{{"type":"dns","value":"{DOMAIN}"}},"status":"{status}","challenges":[{{"type":"dns-01","url":"{BASE}/chall/2","token":"x","status":"pending"}},{{"type":"http-01","url":"{BASE}/chall/1","token":"{TOKEN}","status":"pending"}}]}}"#
                        ),
                    )
                }
                ("POST", "/chall/1") => match self.challenges.get(TOKEN) {
                    // Ключ авторизации — «токен.отпечаток ключа учётной записи».
                    Some(answer) if answer.starts_with(&format!("{TOKEN}.")) => {
                        st.validated = true;
                        (
                            200,
                            None,
                            format!(
                                r#"{{"type":"http-01","url":"{BASE}/chall/1","token":"{TOKEN}","status":"valid"}}"#
                            ),
                        )
                    }
                    _ => (403, None, problem("unauthorized")),
                },
                ("POST", "/order/1") => (200, None, order(&st)),
                ("POST", "/order/1/finalize") => {
                    if !st.validated {
                        return (403, None, problem("orderNotReady"));
                    }
                    let chain = match &self.fixed_chain {
                        Some(chain) => chain.clone(),
                        None => cert_for_csr(body),
                    };
                    st.chain = Some(chain);
                    (200, None, order(&st))
                }
                ("POST", "/cert/1") => (200, None, st.chain.clone().unwrap_or_default()),
                _ => (404, None, problem("malformed")),
            }
        }
    }

    impl HttpClient for MockAcme {
        fn request(
            &self,
            req: Request<BodyWrapper<Bytes>>,
        ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>>
        {
            let (head, mut body) = req.into_parts();
            // Тело запроса — готовые байты: кадр доступен при первом опросе.
            let body = match Pin::new(&mut body).poll_frame(&mut Context::from_waker(Waker::noop()))
            {
                Poll::Ready(Some(frame)) => frame.expect("frame").into_data().unwrap_or_default(),
                Poll::Ready(None) => Bytes::new(),
                Poll::Pending => panic!("request body is not ready"),
            };
            let (status, location, reply) = self.respond(&head.method, head.uri.path(), &body);
            let nonce = self.nonces.fetch_add(1, Ordering::SeqCst);
            let mut rsp = axum::http::Response::builder()
                .status(status)
                .header("replay-nonce", format!("nonce-{nonce}"));
            if let Some(location) = location {
                rsp = rsp.header("location", format!("{BASE}{location}"));
            }
            if head.uri.path().starts_with("/renewal-info/") {
                // ARI отвечает без JWS, сервер подсказывает, когда вернуться (RFC 9773 §4.3.2).
                rsp = rsp.header("retry-after", "3600");
            }
            let (parts, ()) = rsp.body(()).expect("response").into_parts();
            Box::pin(async move {
                Ok(BytesResponse {
                    parts,
                    body: Box::new(Bytes::from(reply)),
                })
            })
        }
    }

    /// Сертификат на открытый ключ из CSR запроса finalize (JWS → payload → `csr`).
    /// Подпись фиктивная: сервер TLS свою цепочку не проверяет, rustls сверяет только ключ.
    fn cert_for_csr(jws: &[u8]) -> String {
        let jws: HashMap<String, String> = serde_yaml_ng::from_slice(jws).expect("jws json");
        let payload = b64url_decode(&jws["payload"]);
        let payload: HashMap<String, String> =
            serde_yaml_ng::from_slice(&payload).expect("payload json");
        let csr = b64url_decode(&payload["csr"]);
        // CertificationRequest → CertificationRequestInfo → version, subject, subjectPKInfo.
        let (_, req, _) = der_tlv(&csr).expect("csr");
        let (_, info, _) = der_tlv(req).expect("info");
        let after_version = der_tlv(info).expect("version").2;
        let spki_and_rest = der_tlv(after_version).expect("subject").2;
        let rest = der_tlv(spki_and_rest).expect("spki").2;
        let spki = &spki_and_rest[..spki_and_rest.len() - rest.len()];

        let alg = tlv(
            0x30,
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
        );
        let cn = [
            &[0x06, 0x03, 0x55, 0x04, 0x03][..],
            &tlv(0x0c, DOMAIN.as_bytes()),
        ]
        .concat();
        let name = tlv(0x30, &tlv(0x31, &tlv(0x30, &cn)));
        let validity = tlv(
            0x30,
            &[tlv(0x17, b"260101000000Z"), tlv(0x18, b"21000101000000Z")].concat(),
        );
        // AKI (2.5.29.35): сертификат, выпущенный уполномоченным CA, — с идентификатором его ключа (RFC 9773).
        let aki = tlv(
            0x30,
            &[
                tlv(0x06, &[0x55, 0x1d, 0x23]),
                tlv(0x04, &tlv(0x30, &tlv(0x80, AKI))),
            ]
            .concat(),
        );
        let tbs = tlv(
            0x30,
            &[
                tlv(0xa0, &tlv(0x02, &[2])),
                tlv(0x02, &[1]),
                alg.clone(),
                name.clone(),
                validity,
                name,
                spki.to_vec(),
                tlv(0xa3, &tlv(0x30, &aki)),
            ]
            .concat(),
        );
        let sig = tlv(0x03, &[0, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        pem_from_der(&tlv(0x30, &[tbs, alg, sig].concat()))
    }

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = content.len();
        if len < 0x80 {
            out.push(u8::try_from(len).expect("short"));
        } else {
            let bytes = len.to_be_bytes();
            let skip = bytes.iter().take_while(|b| **b == 0).count();
            out.push(0x80 | u8::try_from(bytes.len() - skip).expect("len"));
            out.extend_from_slice(&bytes[skip..]);
        }
        out.extend_from_slice(content);
        out
    }

    /// UTCTime (`YYMMDDHHMMSSZ`) с заданной датой; месяц вне 1..=12 делает время нечитаемым (`der_time` → None).
    fn utc(year: i64, month: i64, day: i64) -> Vec<u8> {
        let text = format!("{:02}{:02}{:02}000000Z", year % 100, month, day);
        tlv(0x17, text.as_bytes())
    }

    /// Момент полуночи UTC заданной даты.
    fn civil(year: i64, month: i64, day: i64) -> SystemTime {
        let days = u64::try_from(days_from_civil(year, month, day)).expect("days");
        UNIX_EPOCH + Duration::from_secs(days * 86_400)
    }

    /// PEM-цепочка с заданным серийным номером, AKI и сроком (`notBefore`, `notAfter` — DER-времена).
    /// Подписи нет: календарю продления и ARI нужен разбор сертификата, а не проверка подписи.
    fn cert_chain(serial: &[u8], not_before: Vec<u8>, not_after: Vec<u8>) -> String {
        let alg = tlv(
            0x30,
            &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
        );
        let name = tlv(0x30, &[]);
        let validity = tlv(0x30, &[not_before, not_after].concat());
        // spki: idEcPublicKey без точки кривой — продлению spki не важен.
        let spki = tlv(
            0x30,
            &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01],
        );
        let aki = tlv(
            0x30,
            &[
                tlv(0x06, &[0x55, 0x1d, 0x23]),
                tlv(0x04, &tlv(0x30, &tlv(0x80, AKI))),
            ]
            .concat(),
        );
        let tbs = tlv(
            0x30,
            &[
                tlv(0xa0, &tlv(0x02, &[2])),
                tlv(0x02, serial),
                alg.clone(),
                name.clone(),
                validity,
                name,
                spki,
                tlv(0xa3, &tlv(0x30, &aki)),
            ]
            .concat(),
        );
        let sig = tlv(0x03, &[0, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        pem_from_der(&tlv(0x30, &[tbs, alg, sig].concat()))
    }

    /// DER → PEM (одна секция CERTIFICATE).
    fn pem_from_der(der: &[u8]) -> String {
        let b64 = b64_encode(der);
        let lines: Vec<&str> = b64
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).expect("ascii"))
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            lines.join("\n")
        )
    }

    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn b64_encode(data: &[u8]) -> String {
        let mut out = String::new();
        for chunk in data.chunks(3) {
            let n = chunk.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b))
                << (8 * (3 - chunk.len()));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    fn b64url_decode(s: &str) -> Vec<u8> {
        let mut bits = 0u32;
        let mut n = 0;
        let mut out = Vec::new();
        for c in s.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => continue,
            };
            bits = (bits << 6) | u32::from(v);
            n += 6;
            if n >= 8 {
                n -= 8;
                out.push(((bits >> n) & 0xff) as u8);
            }
        }
        out
    }

    fn setup(dir: &Path, fixed_chain: Option<&str>) -> (Acme, Arc<MockAcme>, TlsConfig, Arc<Keys>) {
        let challenges = Http01Challenges::default();
        let mock = Arc::new(MockAcme {
            challenges: challenges.clone(),
            fixed_chain: fixed_chain.map(str::to_owned),
            state: Mutex::new(MockState::default()),
            nonces: AtomicUsize::new(0),
        });
        let tls = TlsConfig {
            cert_file: dir.join("tls/fullchain.pem"),
            key: key_ref(),
            ..TlsConfig::default()
        };
        let cfg = AcmeConfig {
            enabled: true,
            directory_url: format!("{BASE}/directory"),
            contact: vec!["mailto:admin@example.org".to_owned()],
            domains: vec![DOMAIN.to_owned()],
            state_dir: dir.join("acme"),
            ..AcmeConfig::default()
        };
        let keys = Arc::new(Keys::default());
        let acme =
            Acme::new(cfg, tls.clone(), challenges, None, keys.clone()).with_http(mock.clone());
        (acme, mock, tls, keys)
    }

    #[tokio::test]
    async fn issues_and_renews_with_mock_directory() {
        let dir = TempDir::new("acme-issue");
        let (acme, mock, tls, keys) = setup(&dir.0, None);
        let now = SystemTime::now();
        assert!(
            acme.needs_renewal_at(now).await.expect("check"),
            "no certificate yet"
        );
        assert!(acme.renew_if_needed_at(now).await.expect("issue"));

        let chain = std::fs::read_to_string(&tls.cert_file).expect("chain");
        let key = keys.key().await.expect("key in secret store");
        assert!(key.contains("PRIVATE KEY"));
        check_pair(&chain, &key).expect("key matches certificate");
        let on_disk: Vec<_> = std::fs::read_dir(dir.0.join("tls"))
            .expect("tls dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(on_disk, ["fullchain.pem"], "key is not written to disk");
        assert!(dir.0.join("acme/account.yaml").exists());
        assert_eq!(
            std::fs::read_to_string(dir.0.join("acme/domains")).expect("domains"),
            DOMAIN
        );
        assert_eq!(
            acme.challenges.get(TOKEN),
            None,
            "answer removed after order"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.0.join("acme/account.yaml"))
                .expect("meta")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // Действует до 2100 года: продление — за 30 дней до истечения, учётная запись переиспользуется.
        let not_after = pem_not_after(&chain).expect("not after");
        assert!(!acme.renew_if_needed_at(now).await.expect("fresh"));
        let day = Duration::from_secs(86_400);
        assert!(
            !acme
                .needs_renewal_at(not_after - 31 * day)
                .await
                .expect("check")
        );
        assert!(
            acme.renew_if_needed_at(not_after - 29 * day)
                .await
                .expect("renew")
        );
        {
            let st = mock.state.lock().expect("state");
            assert_eq!((st.accounts, st.orders), (1, 2));
        }
        assert_eq!(
            keys.puts.load(Ordering::SeqCst),
            2,
            "new secret version per issue"
        );
        let renewed = keys.key().await.expect("key");
        assert_ne!(renewed, key, "renewal stores a new key");
        let chain = std::fs::read_to_string(&tls.cert_file).expect("chain");
        check_pair(&chain, &renewed).expect("renewed pair matches");
    }

    #[tokio::test]
    async fn issued_certificate_is_reloaded_into_tls() {
        let dir = TempDir::new("acme-reload");
        let (acme, _mock, tls, keys) = setup(&dir.0, None);
        std::fs::create_dir_all(dir.0.join("tls")).expect("dir");
        std::fs::write(&tls.cert_file, CERT_A).expect("cert");
        keys.mem.set(&key_ref(), KEY_A);
        let certs = Arc::new(TlsCerts::load(&tls, keys.clone()).await.expect("certs"));
        let before = certs.server_config();
        let acme = Acme {
            certs: Some(certs.clone()),
            ..acme
        };
        // Сертификат есть, но выпущен не этим клиентом (нет `domains`) → перевыпуск.
        assert!(acme.renew_if_needed().await.expect("issue"));
        assert!(
            !Arc::ptr_eq(&before, &certs.server_config()),
            "tls reloaded"
        );
        let chain = std::fs::read_to_string(&tls.cert_file).expect("chain");
        assert_ne!(der(&chain), der(CERT_A));
        let key = keys.key().await.expect("key");
        assert_ne!(key, KEY_A, "new key version in the secret");
        check_pair(&chain, &key).expect("listener pair matches");

        let acme = Acme {
            cfg: AcmeConfig {
                domains: vec![DOMAIN.to_owned(), "imap.example.org".to_owned()],
                ..acme.cfg.clone()
            },
            ..acme
        };
        assert!(
            acme.needs_renewal_at(SystemTime::now())
                .await
                .expect("domains changed")
        );
    }

    #[tokio::test]
    async fn failures_leave_pair_untouched() {
        let dir = TempDir::new("acme-fail");
        // Цепочка не соответствует выпущенному ключу.
        let (acme, mock, tls, keys) = setup(&dir.0, Some(CERT_B));
        assert!(acme.issue().await.expect_err("mismatch").is_retryable());
        assert!(!tls.cert_file.exists());
        assert_eq!(keys.key().await, None);
        assert!(mock.state.lock().expect("state").chain.is_some());

        // Ответ на проверку не опубликован: сервер ACME отклоняет проверку, до финализации не доходит.
        let (acme, mock, tls, _keys) = setup(&dir.0, None);
        let acme = Acme {
            challenges: Http01Challenges::default(),
            ..acme
        };
        assert!(acme.issue().await.expect_err("validation").is_retryable());
        assert!(!tls.cert_file.exists());
        assert!(mock.state.lock().expect("state").chain.is_none());

        let acme = Acme {
            cfg: AcmeConfig {
                domains: Vec::new(),
                ..acme.cfg.clone()
            },
            ..acme
        };
        assert!(matches!(acme.issue().await, Err(Error::Invalid(_))));
    }

    #[tokio::test]
    async fn key_store_failure_keeps_previous_pair() {
        let dir = TempDir::new("acme-store-fail");
        let (acme, _mock, tls, keys) = setup(&dir.0, None);
        std::fs::create_dir_all(dir.0.join("tls")).expect("dir");
        std::fs::write(&tls.cert_file, CERT_A).expect("cert");
        keys.mem.set(&key_ref(), KEY_A);
        let certs = Arc::new(TlsCerts::load(&tls, keys.clone()).await.expect("certs"));
        let before = certs.server_config();
        let acme = Acme {
            certs: Some(certs.clone()),
            ..acme
        };

        // Запись ключа запрещена: ни секрет, ни цепочка не меняются, TLS не перечитан.
        keys.fail_put.store(true, Ordering::SeqCst);
        assert_eq!(acme.issue().await, Err(Error::Forbidden));
        assert_eq!(keys.key().await.as_deref(), Some(KEY_A));
        assert_eq!(
            der(&std::fs::read_to_string(&tls.cert_file).expect("chain")),
            der(CERT_A)
        );
        assert!(Arc::ptr_eq(&before, &certs.server_config()));

        // Цепочку записать нельзя (на месте файла — каталог): прежний ключ возвращён в секрет.
        keys.fail_put.store(false, Ordering::SeqCst);
        let blocked = Acme {
            tls: TlsConfig {
                cert_file: dir.0.join("blocked"),
                ..acme.tls.clone()
            },
            ..acme
        };
        std::fs::create_dir_all(dir.0.join("blocked/inner")).expect("dir");
        blocked.issue().await.expect_err("chain not written");
        assert_eq!(
            keys.key().await.as_deref(),
            Some(KEY_A),
            "previous key restored"
        );
        assert_eq!(
            keys.puts.load(Ordering::SeqCst),
            2,
            "new key, then previous"
        );
        assert!(Arc::ptr_eq(&before, &certs.server_config()));
    }

    #[tokio::test]
    async fn challenge_is_served_over_service_http() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let challenges = Http01Challenges::default();
        challenges.insert("tok".to_owned(), "tok.thumb".to_owned());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server =
            tokio::spawn(axum::serve(listener, challenge_router(challenges)).into_future());
        for (path, expect) in [
            ("/.well-known/acme-challenge/tok", "HTTP/1.1 200"),
            ("/.well-known/acme-challenge/other", "HTTP/1.1 404"),
        ] {
            let mut s = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let req = format!("GET {path} HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
            s.write_all(req.as_bytes()).await.expect("write");
            let mut resp = String::new();
            s.read_to_string(&mut resp).await.expect("read");
            assert!(resp.starts_with(expect), "{resp}");
            if expect.ends_with("200") {
                assert!(resp.ends_with("tok.thumb"), "{resp}");
            }
        }
        server.abort();
    }

    /// Встроенный HTTP-клиент (без `with_http`): процессный провайдер rustls поставлен (без него при обоих
    /// провайдерах в сборке instant-acme паникует), обращение к недоступному каталогу — ошибка, а не паника.
    #[tokio::test]
    async fn builtin_http_client_fails_without_panic() {
        let dir = TempDir::new("acme-builtin");
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("bind")
            .local_addr()
            .expect("addr")
            .port();
        let cfg = AcmeConfig {
            enabled: true,
            directory_url: format!("https://127.0.0.1:{port}/directory"),
            domains: vec![DOMAIN.to_owned()],
            state_dir: dir.0.join("acme"),
            ..AcmeConfig::default()
        };
        let tls = TlsConfig {
            cert_file: dir.0.join("tls/fullchain.pem"),
            key: key_ref(),
            ..TlsConfig::default()
        };
        let acme = Acme::new(
            cfg,
            tls.clone(),
            Http01Challenges::default(),
            None,
            Arc::new(Keys::default()),
        );
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
        acme.issue().await.expect_err("directory unreachable");
        assert!(!tls.cert_file.exists());
        // Повторная установка — не ошибка.
        crate::tls::install_crypto_provider();
    }

    #[test]
    fn certificate_expiry_is_parsed() {
        // cert-a: notAfter 2126-10-06 11:35:19 UTC (GeneralizedTime).
        let not_after = pem_not_after(CERT_A).expect("parse");
        let secs = not_after
            .duration_since(UNIX_EPOCH)
            .expect("epoch")
            .as_secs();
        let days = u64::try_from(days_from_civil(2126, 10, 6)).expect("days");
        assert_eq!(secs, days * 86_400 + 11 * 3600 + 35 * 60 + 19);
        let days = u64::try_from(days_from_civil(2049, 12, 31)).expect("days");
        assert_eq!(
            der_time(0x17, b"491231235959Z"),
            Some(UNIX_EPOCH + Duration::from_secs(days * 86_400 + 86_399))
        );
        assert_eq!(der_time(0x17, b"700101000000Z"), Some(UNIX_EPOCH));
        assert_eq!(der_time(0x17, b"701301000000Z"), None);
        assert_eq!(der_time(0x18, b"2026103011Z"), None);
        assert_eq!(days_from_civil(2000, 3, 1), 11_017);
        assert_eq!(pem_not_after("not a pem"), None);
        assert_eq!(cert_validity(&[0x30, 0x82, 0xff]), (None, None));
    }

    /// Календарное окно продления — по доле срока жизни (PLT-37): 90 дней — за 30, короткие — при ⅔ срока.
    #[tokio::test]
    async fn renewal_window_follows_lifetime_share() {
        let dir = TempDir::new("acme-window");
        let (acme, _mock, tls, _keys) = setup(&dir.0, None);
        std::fs::create_dir_all(dir.0.join("tls")).expect("dir");
        std::fs::create_dir_all(dir.0.join("acme")).expect("dir");
        std::fs::write(dir.0.join("acme/domains"), DOMAIN).expect("domains");

        // 90 дней: треть срока (30 дней) не меньше renew_before — окно прежнее, продление за 30 дней.
        std::fs::write(
            &tls.cert_file,
            cert_chain(&[1], utc(2026, 1, 1), utc(2026, 4, 1)),
        )
        .expect("cert");
        assert!(
            acme.needs_renewal_at(civil(2026, 3, 2))
                .await
                .expect("check"),
            "остался месяц — продлевать"
        );
        assert!(
            !acme
                .needs_renewal_at(civil(2026, 2, 28))
                .await
                .expect("check"),
            "до окна ещё два дня"
        );

        // 47 дней (ballot SC-081v3, 2029): не при остатке 30, а при ⅔ срока — остаток ≤ 15⅔ дня.
        std::fs::write(
            &tls.cert_file,
            cert_chain(&[1], utc(2026, 1, 1), utc(2026, 2, 17)),
        )
        .expect("cert");
        assert!(
            !acme
                .needs_renewal_at(civil(2026, 2, 1))
                .await
                .expect("check"),
            "остаток 16 дней больше трети срока"
        );
        assert!(
            acme.needs_renewal_at(civil(2026, 2, 2))
                .await
                .expect("check"),
            "⅔ срока прошли"
        );

        // 6 дней (профиль коротких сертификатов Let's Encrypt): продление при остатке ≤ 2 дней; до этого
        // прежний код продлевал бы на каждой проверке.
        std::fs::write(
            &tls.cert_file,
            cert_chain(&[1], utc(2026, 1, 1), utc(2026, 1, 7)),
        )
        .expect("cert");
        assert!(
            !acme
                .needs_renewal_at(civil(2026, 1, 4))
                .await
                .expect("check"),
            "остаток 3 дня больше трети срока"
        );
        assert!(
            acme.needs_renewal_at(civil(2026, 1, 5))
                .await
                .expect("check")
        );
    }

    /// Сертификат без `notBefore` (разобрать не удалось) — прежнее поведение: фиксированное `renew_before`.
    #[tokio::test]
    async fn unreadable_not_before_keeps_fixed_window() {
        let dir = TempDir::new("acme-nobefore");
        let (acme, _mock, tls, _keys) = setup(&dir.0, None);
        std::fs::create_dir_all(dir.0.join("tls")).expect("dir");
        std::fs::create_dir_all(dir.0.join("acme")).expect("dir");
        std::fs::write(dir.0.join("acme/domains"), DOMAIN).expect("domains");
        std::fs::write(
            &tls.cert_file,
            cert_chain(&[1], utc(2026, 13, 1), utc(2026, 4, 1)),
        )
        .expect("cert");
        assert!(
            !acme
                .needs_renewal_at(civil(2026, 2, 28))
                .await
                .expect("check")
        );
        assert!(
            acme.needs_renewal_at(civil(2026, 3, 2))
                .await
                .expect("check"),
            "фиксированное окно 30 дней без доли срока"
        );
    }

    /// Идентификатор сертификата для ARI — из серийного номера и AKI цепочки (RFC 9773 §4.1).
    #[test]
    fn certificate_identifier_from_chain() {
        let chain = cert_chain(&[0xCA, 0xFE], utc(2026, 1, 1), utc(2026, 2, 17));
        let id = certificate_identifier(&chain).expect("identifier");
        // Идентификатор ключа CA (AKI C0 FF EE) и серийный номер CA FE — base64url.
        assert_eq!(format!("{id}"), "wP_u.yv4");
        // Без AKI (самоподписанный) идентификатора нет.
        let pem = pem_from_der(&[0x30, 0x08, 0x30, 0x06, 0x02, 0x01, 0x01, 0x05, 0x00]);
        assert_eq!(certificate_identifier(&pem), None);
        assert_eq!(certificate_identifier("not a pem"), None);
    }

    /// Окно продления от сервера (ARI, RFC 9773) важнее календаря: будущее окно откладывает продление,
    /// окно с `now` — выпускает, миновавшее — возвращает к календарю PLT-37.
    #[tokio::test]
    async fn renewal_follows_the_server_window() {
        let dir = TempDir::new("acme-ari");
        let (acme, mock, tls, _keys) = setup(&dir.0, None);
        // Сертификат на 47 дней: до окна продления по календарю (⅔ срока) далеко не всегда.
        std::fs::create_dir_all(dir.0.join("tls")).expect("dir");
        std::fs::write(
            &tls.cert_file,
            cert_chain(&[1], utc(2026, 1, 1), utc(2026, 2, 17)),
        )
        .expect("cert");
        std::fs::create_dir_all(dir.0.join("acme")).expect("dir");
        std::fs::write(dir.0.join("acme/domains"), DOMAIN).expect("domains");
        {
            let mut st = mock.state.lock().expect("state");
            st.ari_url = true;
            st.ari_window = Some(("2026-02-01T00:00:00Z", "2026-02-10T00:00:00Z"));
        }

        // Окно в будущем — продления нет, хотя до истечения меньше renew_before (календарь сказал бы «да»).
        assert!(
            !acme
                .needs_renewal_at(civil(2026, 1, 20))
                .await
                .expect("check"),
            "ARI: до окна продления сервер не ждёт выпуск"
        );
        assert_eq!(
            mock.state.lock().expect("state").last_cert_id,
            Some(CERT_ID.to_owned()),
            "сервер опрошен по идентификатору выпущенной цепочки"
        );

        // now внутри окна — выпуск.
        assert!(
            acme.renew_if_needed_at(civil(2026, 2, 5))
                .await
                .expect("renew")
        );

        // Окно миновало — снова календарь PLT-37: свежему сертификату продление не нужно.
        assert!(
            !acme
                .needs_renewal_at(civil(2026, 2, 12))
                .await
                .expect("check")
        );
        // ...а окно, миновавшее без выпуска (узел был недоступен), продление не теряет: решает календарь.
        std::fs::write(
            &tls.cert_file,
            cert_chain(&[1], utc(2026, 1, 1), utc(2026, 2, 17)),
        )
        .expect("cert");
        assert!(
            acme.needs_renewal_at(civil(2026, 2, 12))
                .await
                .expect("check"),
            "⅔ срока прошли, календарь снова решает"
        );
    }

    /// «Заменяющее» окно (сертификат отмечен к замене) — ранний перевыпуск действующего сертификата.
    #[tokio::test]
    async fn replacement_window_renews_a_fresh_certificate() {
        let dir = TempDir::new("acme-ari-replace");
        let (acme, mock, _tls, _keys) = setup(&dir.0, None);
        assert!(
            acme.renew_if_needed_at(civil(2026, 6, 2))
                .await
                .expect("issue")
        );
        {
            let mut st = mock.state.lock().expect("state");
            st.ari_url = true;
            st.ari_window = Some(("2026-06-01T00:00:00Z", "2026-06-03T00:00:00Z"));
        }
        // Сертификат действующий (до 2049 года), календарь молчит — сервер просит заменить сейчас.
        assert!(
            acme.renew_if_needed_at(civil(2026, 6, 2))
                .await
                .expect("renew")
        );
        {
            let st = mock.state.lock().expect("state");
            assert_eq!(st.orders, 2, "перевыпуск по подсказке сервера");
        }
    }

    /// Endpoint ARI отвечает ошибкой — предупреждение в журнал, продление по своему календарю.
    #[tokio::test]
    async fn ari_error_falls_back_to_the_calendar() {
        let dir = TempDir::new("acme-ari-error");
        let (acme, mock, tls, _keys) = setup(&dir.0, None);
        std::fs::create_dir_all(dir.0.join("tls")).expect("dir");
        std::fs::write(
            &tls.cert_file,
            cert_chain(&[1], utc(2026, 1, 1), utc(2026, 2, 17)),
        )
        .expect("cert");
        std::fs::create_dir_all(dir.0.join("acme")).expect("dir");
        std::fs::write(dir.0.join("acme/domains"), DOMAIN).expect("domains");
        {
            let mut st = mock.state.lock().expect("state");
            st.ari_url = true;
            st.ari_window = Some(("2026-02-01T00:00:00Z", "2026-02-10T00:00:00Z"));
            st.ari_error = true;
        }
        // Без подсказки окно решает календарь: ⅔ срока прошли — продлевать.
        assert!(
            acme.needs_renewal_at(civil(2026, 2, 5))
                .await
                .expect("check")
        );
        assert!(
            !acme
                .needs_renewal_at(civil(2026, 1, 20))
                .await
                .expect("check")
        );
    }

    /// Сервер без `renewalInfo` в каталоге — как раньше: календарь решает без обращения к ARI.
    #[tokio::test]
    async fn server_without_ari_keeps_the_calendar() {
        let dir = TempDir::new("acme-no-ari");
        let (acme, mock, tls, _keys) = setup(&dir.0, None);
        std::fs::create_dir_all(dir.0.join("tls")).expect("dir");
        std::fs::write(
            &tls.cert_file,
            cert_chain(&[1], utc(2026, 1, 1), utc(2026, 2, 17)),
        )
        .expect("cert");
        std::fs::create_dir_all(dir.0.join("acme")).expect("dir");
        std::fs::write(dir.0.join("acme/domains"), DOMAIN).expect("domains");
        assert!(
            !acme
                .needs_renewal_at(civil(2026, 1, 20))
                .await
                .expect("check")
        );
        assert!(
            acme.needs_renewal_at(civil(2026, 2, 5))
                .await
                .expect("check")
        );
        assert_eq!(
            mock.state.lock().expect("state").last_cert_id,
            None,
            "запроса ARI не было"
        );
    }

    #[test]
    fn config_from_yaml() {
        let cfg: AcmeConfig = serde_yaml_ng::from_str(
            "enabled: true\ndomains: [mail.example.org]\ncontact: [\"mailto:a@example.org\"]\n",
        )
        .expect("parse");
        assert!(cfg.enabled);
        assert_eq!(cfg.renew_before, Duration::from_secs(30 * 86_400));
        assert_eq!(cfg.renew_share, 1.0 / 3.0);
        assert!(
            cfg.directory_url
                .starts_with("https://acme-v02.api.letsencrypt.org")
        );
        assert!(serde_yaml_ng::from_str::<AcmeConfig>("renew: 1").is_err());
        let cfg: AcmeConfig = serde_yaml_ng::from_str(
            "renew_before: 14d\ncheck_interval: 6h\nretry_interval: 10m\norder_timeout: 2m\n",
        )
        .expect("durations");
        assert_eq!(cfg.renew_before, Duration::from_secs(14 * 86_400));
        assert_eq!(cfg.check_interval, Duration::from_secs(6 * 3600));
        assert_eq!(cfg.retry_interval, Duration::from_secs(600));
        assert_eq!(cfg.order_timeout, Duration::from_secs(120));
        assert!(serde_yaml_ng::from_str::<AcmeConfig>("check_interval: 3600").is_err());
        assert!(serde_yaml_ng::from_str::<AcmeConfig>("renew_before_days: 30").is_err());

        // Доля срока для окна продления (PLT-40): из (0, 1]; ноль, доля больше срока и NaN — ошибка разбора.
        let cfg: AcmeConfig = serde_yaml_ng::from_str("renew_share: 0.5\n").expect("share");
        assert_eq!(cfg.renew_share, 0.5);
        for bad in [
            "renew_share: 0\n",
            "renew_share: 1.5\n",
            "renew_share: -0.5\n",
            "renew_share: .nan\n",
        ] {
            assert!(serde_yaml_ng::from_str::<AcmeConfig>(bad).is_err(), "{bad}");
        }
        // Эффективное окно: min(renew_before, доля × срок); срок не определён — renew_before.
        let day = Duration::from_secs(86_400);
        assert_eq!(
            cfg.renewal_window(Duration::ZERO),
            Duration::from_secs(30 * 86_400)
        );
        assert_eq!(
            cfg.renewal_window(90 * day),
            30 * day,
            "доля 0.5 × 90 > renew_before"
        );
        assert_eq!(
            cfg.renewal_window(47 * day),
            23 * day + Duration::from_secs(43_200),
            "половина срока 47 сут."
        );
    }

    /// Доля срока настраивается (`acme.renew_share`, PLT-40): ½ для 47-дневного сертификата — продление
    /// при остатке ≤ 23½ сут. (⅔ срока), а не при ⅓.
    #[tokio::test]
    async fn renew_share_sets_the_window() {
        let dir = TempDir::new("acme-share");
        let (acme, _mock, tls, _keys) = setup(&dir.0, None);
        let acme = Acme {
            cfg: AcmeConfig {
                renew_share: 0.5,
                ..acme.cfg.clone()
            },
            ..acme
        };
        std::fs::create_dir_all(dir.0.join("tls")).expect("dir");
        std::fs::create_dir_all(dir.0.join("acme")).expect("dir");
        std::fs::write(dir.0.join("acme/domains"), DOMAIN).expect("domains");
        std::fs::write(
            &tls.cert_file,
            cert_chain(&[1], utc(2026, 1, 1), utc(2026, 2, 17)),
        )
        .expect("cert");
        assert!(
            !acme
                .needs_renewal_at(civil(2026, 1, 24))
                .await
                .expect("check"),
            "остаток 24 сут. больше половины срока"
        );
        assert!(
            acme.needs_renewal_at(civil(2026, 1, 25))
                .await
                .expect("check"),
            "остаток 23 сут. не больше половины срока"
        );
    }
}
