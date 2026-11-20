//! Справочник аномалий на узле (APP-78, решение 126; CONTRACTS.md#Risk; SRS 4.3, 4.9).
//!
//! Хранилище — [`RiskStore`] `PgMeta` (META-87) под кэшем узла [`RiskCache`]: действующий каталог
//! ([`RiskStore::effective`]), версии списков, источники и политики кэшируются, сброс — по сигналам
//! `risk_changed` и `Resync` шины ([`RiskCache::watch`], запуск — `serve`, как у
//! [`crate::trust::TrustCache`]); после собственных записей (активация, откат, политика, источник,
//! версия списка) кэш сбрасывается сразу и публикуется `risk_changed` другим узлам. Один и тот же
//! `Arc` получают доставка SMTP и Sieve ([`tp_smtp::Delivery::with_risk`], SMTP-52, SIEVE-15) и
//! Admin API ([`tp_admin::Admin::with_risk`], ADM-51).
//!
//! Пакет поставщика — ZIP: `manifest.json`, `manifest.sig` (сырые 64 байта подписи Ed25519 над
//! каноническим JSON манифеста — [`canonical_manifest`]), `sources.json` (источники TI списков пакета)
//! и файлы списков и образцов. Проверка ([`Verifier::verify`]): подпись ключом из `risk.trusted_keys`
//! по `key_id` (кольцо `ring`); `min_node` не выше версии узла; SHA-256 всех файлов по манифесту и
//! каждый файл пакета — по ссылке из манифеста (лишних нет); lint — схема манифеста, известные
//! детекторы (serde), разбор списков по видам ([`ListKind`]) и Public Suffix List, источники
//! `Bundled` — не из [`FORBIDDEN_BUNDLED`] и с `commercial: true` ([`TiSource::validate`]); пробный
//! прогон — детекторы ([`tp_smtp::risk::scan_message`]) на письмах `samples` с памятью беседы-заглушкой
//! (детекторы беседы срабатывают, когда письмо приносит соответствующий факт), совпадение с `expect` —
//! иначе отказ. Любая ошибка — `Error::Invalid` с отчётом; активный пакет не меняется.
//!
//! Установка ([`Installer`]): архив пакета и содержимое списков — в BLOB по путям `put_raw` (вне
//! транзакций; путь не ключ BLOB писем — «сироты» его не трогают), версии списков и источники — к
//! активации ([`RiskCache::stage`]); затем `put_package` и `activate` (запись манифеста и переключение —
//! в БД, без обращений к BLOB в транзакции). Пакет без активации каталог не меняет. Прошлые версии
//! сверх `risk.package.keep` (хранилище удаляет строки) — архивы из BLOB после фиксации
//! ([`Installer::cleanup`]); откат — [`RiskStore::rollback`] на хранимую.
//!
//! Обновление — роль maintenance ([`RiskUpdate::run`]): раз в `risk.update.interval` узел-держатель
//! лизы ([`UPDATE_LEASE`]) берёт пакет с `risk.update.url` (HTTPS, `If-None-Match`) или из каталога
//! `risk.update.dir` (закрытый контур: файл кладут руками или зеркалом); проверенный — устанавливает и
//! активирует при `risk.update.auto_activate` (по умолчанию да: новые признаки всё равно «только
//! отчёт»), иначе ждёт администратора. Нет пакета или сбой — работает прежний, предупреждение в журнале
//! узла и в `thepost doctor` ([`doctor_risk`]). Первый пакет при пустом хранилище — из поставки
//! (`risk.package.dir`, DEP-57).
//!
//! Срок «только отчёт» ([`aging`]): признак поставщика в режиме `Report` с `since` старше
//! `risk.report_only_days` без решения администратора — действующий каталог получает `Enforce`; переход
//! — событие в журнале узла и строка в отчёте `doctor`.
//!
//! Данные детекторов ([`NodeEnviron`], [`RiskEnviron`]): память бесед получателей — `PgMeta`
//! (`thread_keys` → `threads.facts`, CTR-94/META-86), индексы списков TI — содержимое из BLOB по
//! текущим версиям кэша (`list_current`), Public Suffix List — список [`PSL_LIST`] пакета поставщика
//! (MPL-2.0, DEP-57). Импорт и обновление списков TI ([`AdminNode`], [`RiskNode`]) — форматы `Txt` и
//! `Csv`; RPZ, MISP, STIX/TAXII — коннекторы APP-79.
//!
//! Команды выпуска (DEP-57): `thepost risk verify <файл>` — проверка без установки (тот же отчёт,
//! что у Admin API); `thepost risk pack --manifest <файл> --key <SecretRef|файл>` — сборка и подпись
//! пакета ([`pack`]).
//!
//! Практика: sa-update — подпись обязательна, lint перед установкой, `--install` из файла; Rspamd —
//! `trusted_keys` и карты с подписью EdDSA; Stalwart — вендорские правила отдельно от локальных.
//! Отличие: номер версии только растёт (откат — только на хранимую), обязательный пробный прогон на
//! корпусе пакета.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use publicsuffix::Psl as _;
use ring::signature as ring_sig;
use sha2::Digest;
use time::OffsetDateTime;
use tp_admin::risk::{PackageVerified, RiskNode};
use tp_contracts::blob::BlobStore;
use tp_contracts::bus::{EventBus, EventKind};
use tp_contracts::ids::{AccountId, BlobHash, TenantId};
use tp_contracts::risk::{
    Catalog, Detector, EffectiveCatalog, FeedFormat, Field, HttpAuth, ListFile, ListId, ListKind,
    ListVersion, Mode, PackageEntry, PackageManifest, RiskLevel, RiskPolicy, RiskStore, SampleFile,
    Semver, Signal, SignalId, SourceId, SourceKind, Tenants, TiOrigin, TiSource, Tier,
    UpdateReport, UsageEntry, Verdict, risk_changed,
};
use tp_contracts::role::CancellationToken;
use tp_contracts::secrets::SecretRef;
use tp_contracts::thread::ThreadFacts;
use tp_contracts::{Error, Result};
use tp_meta::PgMeta;
use tp_smtp::config::RiskConfig as ScanLimits;
use tp_smtp::risk::{Findings, ListValue, RiskEnviron, scan_message};

use crate::sections::RiskSection;

/// Список Public Suffix List в пакете поставщика (решение 126 г, DEP-57): идентификатор, по которому
/// детектор «новый домен» находит его среди списков пакета.
pub const PSL_LIST: &str = "public-suffix-list";

/// Префикс путей BLOB для архивов пакетов и содержимого списков (`put_raw`; путь не ключ BLOB писем —
/// ключа учёта у него нет, поиск «сирот» его не трогает).
pub const BLOB_PREFIX: &str = "risk";

/// Лиза обновления пакета (установку ведёт один узел кластера).
pub const UPDATE_LEASE: &str = "risk-update";

/// Путь архива версии пакета в BLOB (удаление — [`Installer::cleanup`]).
fn archive_path(version: u64) -> String {
    format!("{BLOB_PREFIX}/packages/{version}.zip")
}

/// Префикс путей архивов пакетов в BLOB.
const ARCHIVE_PREFIX: &str = "risk/packages/";

/// Путь содержимого списка в BLOB (по SHA-256 — списки неизменяемы, версии различаются хэшем).
fn list_blob_path(sha256: &BlobHash) -> String {
    format!("{BLOB_PREFIX}/lists/{}", hex(sha256.as_bytes()))
}

/// Путь файла импорта источника [`SourceKind::File`] (`risk.import.dir`, закрытый контур).
fn import_file(dir: &Path, source: &SourceId) -> PathBuf {
    dir.join(source.as_str())
}

/// Шестнадцатеричная запись байтов (нижний регистр).
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Канонические байты манифеста для подписи: JSON контракта (`serde_json`) — сериализатор один у
/// `thepost risk pack` и у проверки узла.
pub fn canonical_manifest(manifest: &PackageManifest) -> Result<Vec<u8>> {
    serde_json::to_vec(manifest).map_err(|e| Error::internal(format!("risk: сериализация: {e}")))
}

/// SHA-256 байтов (хэши манифеста и журнала срабатываний).
pub fn sha256(bytes: &[u8]) -> BlobHash {
    BlobHash(sha2::Sha256::digest(bytes).into())
}

// ---------- Ключи подписи ----------

/// Открытый ключ подписи пакетов (Ed25519, 32 байта) из значения конфигурации: base64 или hex; путь к
/// файлу — если значение не разобралось как ключ и файл существует (ключи поставки — DEP-57).
pub fn trusted_key(value: &str) -> Result<Vec<u8>> {
    if let Some(key) = decode_key(value.trim())
        && key.len() == 32
    {
        return Ok(key);
    }
    let path = Path::new(value);
    if path.is_file() {
        let raw = std::fs::read(path)
            .map_err(|e| Error::internal(format!("risk: ключ {}: {e}", path.display())))?;
        let text: String = String::from_utf8_lossy(&raw)
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("");
        if let Some(key) = decode_key(text.trim())
            && key.len() == 32
        {
            return Ok(key);
        }
        return Err(Error::invalid(format!(
            "risk: файл ключа {}: не открытый ключ Ed25519 (base64 или hex, 32 байта)",
            path.display()
        )));
    }
    Err(Error::invalid(format!(
        "risk: значение ключа не разобрано (base64/hex 32 байта или путь к файлу): {}",
        preview(value)
    )))
}

/// Байты ключа из hex или base64 (без пробелов и комментариев); не то — `None`.
fn decode_key(value: &str) -> Option<Vec<u8>> {
    let v: String = value
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if v.is_empty() {
        return None;
    }
    // Hex: чётное число шестнадцатеричных цифр (многобайтовые символы не проходят).
    let hex = v.len().is_multiple_of(2) && v.bytes().all(|b| b.is_ascii_hexdigit());
    if hex {
        let bytes = (0..v.len() / 2)
            .map(|i| u8::from_str_radix(&v[i * 2..i * 2 + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>()
            .ok();
        if bytes.is_some() {
            return bytes;
        }
    }
    base64_decode(&v)
}

/// Base64 стандартный или URL-safe (запасные символы на месте `+` и `/`).
fn base64_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    const ENGINE: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
    let url_safe: String = value
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            _ => c,
        })
        .collect();
    ENGINE
        .decode(value.as_bytes())
        .ok()
        .or_else(|| ENGINE.decode(url_safe.as_bytes()).ok())
}

/// Сокращение длинного значения для сообщения об ошибке.
fn preview(value: &str) -> String {
    let mut s: String = value.chars().take(24).collect();
    if value.chars().count() > 24 {
        s.push('…');
    }
    s
}

/// Проверяет подпись Ed25519: `signature` — сырые 64 байта.
fn verify_ed25519(public: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let key = ring_sig::UnparsedPublicKey::new(&ring_sig::ED25519, public);
    key.verify(message, signature)
        .map_err(|_| Error::invalid("risk: подпись манифеста не соответствует ключу"))
}

/// Закрытый ключ подписи (выпуск пакета, `thepost risk pack --key`): base64/hex PKCS#8 DER либо seed
/// (32 байта — оборачивается в PKCS#8 RFC 8410 v1), из файла или секрета хранилища по `SecretRef`.
pub fn signing_key(raw: &[u8]) -> Result<ring_sig::Ed25519KeyPair> {
    if raw.len() == 32 {
        // RFC 8410: PKCS#8 v1 для Ed25519 — фиксированная обёртка seed (публичный ключ выводится
        // из seed — `from_pkcs8_maybe_unchecked`, v2 с открытым ключом разбирается так же).
        const PREFIX: &[u8] = &[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        let mut pkcs8 = Vec::with_capacity(PREFIX.len() + 32);
        pkcs8.extend_from_slice(PREFIX);
        pkcs8.extend_from_slice(raw);
        return ring_sig::Ed25519KeyPair::from_pkcs8_maybe_unchecked(&pkcs8)
            .map_err(|e| Error::invalid(format!("risk: ключ подписи: {e}")));
    }
    ring_sig::Ed25519KeyPair::from_pkcs8_maybe_unchecked(raw)
        .map_err(|e| Error::invalid(format!("risk: ключ подписи: {e}")))
}

/// Закрытый ключ из значения `--key`: `SecretRef` (`путь#поле` — секрет хранилища) или файл
/// (base64/hex либо DER).
pub async fn signing_key_value(
    spec: &str,
    secrets: &dyn tp_contracts::secrets::SecretStore,
) -> Result<ring_sig::Ed25519KeyPair> {
    let raw: Vec<u8> = if let Ok(secret) = spec.parse::<SecretRef>() {
        let value = secrets.get(&secret).await?.expose().to_owned();
        decode_key(value.trim())
            .ok_or_else(|| Error::invalid("risk: секрет ключа подписи — не base64/hex"))?
    } else {
        let bytes = std::fs::read(spec)
            .map_err(|e| Error::invalid(format!("risk: файл ключа {spec}: {e}")))?;
        let text = String::from_utf8_lossy(&bytes);
        decode_key(text.trim()).unwrap_or(bytes)
    };
    signing_key(&raw)
}

// ---------- Пакет: распаковка и проверка ----------

/// Файлы пакета по путям (без служебных `manifest.json`, `manifest.sig`, `sources.json`).
#[derive(Debug, Default)]
pub struct PackageFiles(BTreeMap<String, Vec<u8>>);

impl PackageFiles {
    /// Содержимое файла.
    pub fn get(&self, path: &str) -> Option<&[u8]> {
        self.0.get(path).map(Vec::as_slice)
    }

    /// Кладёт файл (сборщик пакета и тесты).
    pub fn insert(&mut self, path: impl Into<String>, bytes: Vec<u8>) {
        self.0.insert(path.into(), bytes);
    }

    /// Содержимое файла списка по идентификатору (путь — из манифеста).
    fn list_bytes(&self, lists: &[ListFile], id: &ListId) -> Option<&[u8]> {
        let path = lists.iter().find(|l| &l.id == id)?.path.as_str();
        self.get(path)
    }

    /// Пути и размеры.
    pub fn iter(&self) -> impl Iterator<Item = (&str, usize)> {
        self.0.iter().map(|(p, b)| (p.as_str(), b.len()))
    }
}

/// Проверенный пакет: манифест, подпись, источники, файлы и отчёт «что изменится».
#[derive(Debug)]
pub struct Verified {
    /// Манифест (подпись и lint пройдены; новые признаки — уже «только отчёт»).
    pub manifest: PackageManifest,
    /// Подпись манифеста (сырые 64 байта) — для сборки архива ([`archive_of`]).
    pub signature: Option<Vec<u8>>,
    /// Источники TI списков пакета (`sources.json`; `Bundled` — ставятся пакетом).
    pub sources: Vec<TiSource>,
    /// Файлы пакета (списки, образцы).
    pub files: PackageFiles,
    /// Что изменится при активации относительно действующего каталога.
    pub update: UpdateReport,
    /// Прогнано образцов.
    pub samples: u64,
}

/// Проверка пакета: подпись доверенным ключом, хэши, lint и пробный прогон (APP-78).
#[derive(Debug, Clone)]
pub struct Verifier {
    /// Доверенные ключи: `key_id` → открытый ключ (32 байта).
    trusted: BTreeMap<String, Vec<u8>>,
    /// Версия узла (проверка `min_node`).
    node_version: Semver,
    /// Пределы разбора писем пробного прогона ([`tp_smtp::config::RiskConfig`]).
    limits: ScanLimits,
}

impl Verifier {
    /// Проверка по секции `risk` (ключи читаются при сборке узла; недопустимое значение — ошибка
    /// запуска) и версии узла.
    pub fn new(section: &RiskSection, node_version: Semver) -> Result<Self> {
        let mut trusted = BTreeMap::new();
        for (id, value) in &section.trusted_keys {
            trusted.insert(id.clone(), trusted_key(value)?);
        }
        Ok(Self {
            trusted,
            node_version,
            limits: ScanLimits::default(),
        })
    }

    /// Проверка без секции (тесты и проверка файла ключом напрямую): один доверенный ключ.
    pub fn with_key(key_id: impl Into<String>, public: impl Into<Vec<u8>>) -> Self {
        Self {
            trusted: BTreeMap::from([(key_id.into(), public.into())]),
            node_version: Semver::new(0, 1, 0),
            limits: ScanLimits::default(),
        }
    }

    /// Версия узла для проверки `min_node`.
    pub fn with_node_version(mut self, version: Semver) -> Self {
        self.node_version = version;
        self
    }

    /// Проверяет байты файла пакета. `old` — действующий каталог для отчёта «что изменится» (`None` —
    /// проверка без узла: всё считается добавленным, новые признаки — «только отчёт»). Отказ —
    /// `Error::Invalid` с отчётом (подпись, хэш, lint, пробный прогон); активный пакет не меняется.
    pub fn verify(&self, bytes: &[u8], old: Option<&EffectiveCatalog>) -> Result<Verified> {
        let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes))
            .map_err(|e| Error::invalid(format!("risk: файл не архив ZIP: {e}")))?;
        let manifest: PackageManifest = {
            let raw = zip_entry(&mut zip, "manifest.json")?;
            serde_json::from_slice(&raw)
                .map_err(|e| Error::invalid(format!("risk: manifest.json: {e}")))?
        };
        manifest.validate()?;
        if manifest.min_node > self.node_version {
            return Err(Error::invalid(format!(
                "risk: пакет требует узел не старше {}, этот — {}",
                manifest.min_node, self.node_version
            )));
        }
        // Подпись — над каноническим JSON манифеста, ключ по key_id из risk.trusted_keys.
        let public = self.trusted.get(&manifest.key_id).ok_or_else(|| {
            Error::invalid(format!(
                "risk: ключ {:?} не доверенный (доверенные: {})",
                manifest.key_id,
                self.trusted.keys().cloned().collect::<Vec<_>>().join(", ")
            ))
        })?;
        let signature = zip_entry(&mut zip, "manifest.sig")?;
        if signature.len() != 64 {
            return Err(Error::invalid(format!(
                "risk: manifest.sig — {} байт, подпись Ed25519 — 64",
                signature.len()
            )));
        }
        verify_ed25519(public, &canonical_manifest(&manifest)?, &signature)?;
        // Источники списков пакета: только поставка, lint проверяет и hosts, и лицензию.
        let sources: Vec<TiSource> = match zip_entry_opt(&mut zip, "sources.json")? {
            Some(raw) => serde_json::from_slice(&raw)
                .map_err(|e| Error::invalid(format!("risk: sources.json: {e}")))?,
            None => Vec::new(),
        };
        for source in &sources {
            source
                .validate()
                .map_err(|e| Error::invalid(format!("risk: источник {}: {e}", source.id)))?;
            if source.tier != Tier::Bundled {
                return Err(Error::invalid(format!(
                    "risk: источник {}: в пакете — только источники поставки (bundled)",
                    source.id
                )));
            }
            if source.origin != TiOrigin::Vendor {
                return Err(Error::invalid(format!(
                    "risk: источник {}: происхождение в пакете — vendor ({})",
                    source.id, source.origin
                )));
            }
        }
        for list in &manifest.lists {
            if !sources.iter().any(|s| s.id == list.source) {
                return Err(Error::invalid(format!(
                    "risk: список {}: источник {} не описан в sources.json",
                    list.id, list.source
                )));
            }
        }
        // Файлы пакета: каждый — по ссылке из манифеста, хэш — по манифесту, лишних нет.
        let mut names: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for i in 0..zip.len() {
            let mut file = zip
                .by_index(i)
                .map_err(|e| Error::internal(format!("risk: чтение архива: {e}")))?;
            if file.is_dir() {
                continue;
            }
            let name = file
                .name()
                .map_err(|e| Error::internal(format!("risk: имя записи архива: {e}")))?
                .into_owned();
            if matches!(
                name.as_str(),
                "manifest.json" | "manifest.sig" | "sources.json"
            ) {
                continue;
            }
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|e| Error::internal(format!("risk: чтение {name}: {e}")))?;
            names.insert(name, bytes);
        }
        let mut files = PackageFiles::default();
        for list in &manifest.lists {
            let bytes = names.get(&list.path).ok_or_else(|| {
                Error::invalid(format!("risk: файла списка {} нет в пакете", list.path))
            })?;
            if sha256(bytes) != list.sha256 {
                return Err(Error::invalid(format!(
                    "risk: файл списка {} не совпадает с хэшем манифеста",
                    list.path
                )));
            }
            let parsed = parse_list(list.kind, bytes)?;
            if parsed != list.entries {
                return Err(Error::invalid(format!(
                    "risk: список {}: записей {}, в манифесте {}",
                    list.path, parsed, list.entries
                )));
            }
            files.0.insert(list.path.clone(), bytes.clone());
        }
        for sample in &manifest.samples {
            let bytes = names.get(&sample.path).ok_or_else(|| {
                Error::invalid(format!("risk: файла образца {} нет в пакете", sample.path))
            })?;
            if sha256(bytes) != sample.sha256 {
                return Err(Error::invalid(format!(
                    "risk: файл образца {} не совпадает с хэшем манифеста",
                    sample.path
                )));
            }
            files.0.insert(sample.path.clone(), bytes.clone());
        }
        for name in names.keys() {
            if !files.0.contains_key(name) {
                return Err(Error::invalid(format!(
                    "risk: файл {name} не упомянут в манифесте (лишние файлы в пакете запрещены)"
                )));
            }
        }
        // Public Suffix List пакета (если заявлен) — разбирается.
        if let Some(psl) = manifest.lists.iter().find(|l| l.id.as_str() == PSL_LIST) {
            let bytes = files.get(&psl.path).ok_or_else(|| {
                Error::invalid(format!("risk: файла PSL {} нет в пакете", psl.path))
            })?;
            publicsuffix::List::from_bytes(bytes)
                .map_err(|e| Error::invalid(format!("risk: список PSL не разбирается: {e}")))?;
        }
        // Пробный прогон: детекторы и каталог на образцах пакета (решение 126 б).
        let psl = manifest
            .lists
            .iter()
            .find(|l| l.id.as_str() == PSL_LIST)
            .and_then(|l| files.get(&l.path))
            .and_then(|b| publicsuffix::List::from_bytes(b).ok());
        let mut failed = Vec::new();
        let mut run = 0u64;
        for sample in &manifest.samples {
            run += 1;
            let bytes = files
                .get(&sample.path)
                .ok_or_else(|| Error::internal("файл образца проверен выше"))?;
            let fired = trial_fired(
                &manifest.signals,
                &manifest.lists,
                &files,
                psl.as_ref(),
                bytes,
                &self.limits,
            );
            let expected = expected(sample);
            if fired != expected {
                failed.push(format!(
                    "{}: ожидалось [{}], сработало [{}]",
                    sample.path,
                    expected
                        .iter()
                        .map(|id| id.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    fired
                        .iter()
                        .map(|id| id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        if !failed.is_empty() {
            return Err(Error::invalid(format!(
                "risk: пробный прогон не совпал с ожидаемыми признаками: {}",
                failed.join("; ")
            )));
        }
        // Что изменится: новые для каталога признаки — «только отчёт» (копия манифеста).
        let mut manifest = manifest;
        let update = match old {
            Some(old) => Catalog::apply_update(old, &mut manifest.signals),
            None => {
                let mut report = UpdateReport::default();
                for s in &mut manifest.signals {
                    s.mode = Mode::Report;
                    report.added.push(s.id.clone());
                }
                report
            }
        };
        Ok(Verified {
            manifest,
            signature: Some(signature),
            sources,
            files,
            update,
            samples: run,
        })
    }
}

/// Ожидаемые признаки образца, по возрастанию.
fn expected(sample: &SampleFile) -> Vec<SignalId> {
    let mut ids = sample.expect.clone();
    ids.sort();
    ids
}

/// Служебные и заявленные файлы пакета.
fn zip_entry<R: std::io::Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
    name: &str,
) -> Result<Vec<u8>> {
    zip_entry_opt(zip, name)?
        .ok_or_else(|| Error::invalid(format!("risk: в пакете нет файла {name}")))
}

fn zip_entry_opt<R: std::io::Read + std::io::Seek>(
    zip: &mut zip::ZipArchive<R>,
    name: &str,
) -> Result<Option<Vec<u8>>> {
    let Ok(mut file) = zip.by_name(name) else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|e| Error::internal(format!("risk: чтение {name}: {e}")))?;
    Ok(Some(bytes))
}

/// Число записей списка по его виду ([`ListKind`]): строка — значение, `#` — комментарий; пустые
/// пропускаются. Недопустимая запись — `Invalid` (lint разбора списков).
pub fn parse_list(kind: ListKind, bytes: &[u8]) -> Result<u64> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error::invalid("risk: список — не текст UTF-8"))?;
    let mut count = 0u64;
    for line in text.lines() {
        let value = line.split('#').next().unwrap_or("").trim();
        if value.is_empty() {
            continue;
        }
        match kind {
            ListKind::Ip => {
                let net = value
                    .parse::<ipnet::IpNet>()
                    .or_else(|_| value.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                    .map_err(|_| {
                        Error::invalid(format!("risk: запись списка не IP/подсеть: {value:?}"))
                    })?;
                let _ = net;
            }
            ListKind::Domain => {
                if !valid_domain(value) {
                    return Err(Error::invalid(format!(
                        "risk: запись списка не домен: {value:?}"
                    )));
                }
            }
            ListKind::Url => {
                if !value.starts_with("http://") && !value.starts_with("https://") {
                    return Err(Error::invalid(format!(
                        "risk: запись списка не URL: {value:?}"
                    )));
                }
            }
            ListKind::Sha256 => {
                let ok = value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit());
                if !ok {
                    return Err(Error::invalid(format!(
                        "risk: запись списка не SHA-256: {value:?}"
                    )));
                }
            }
        }
        count += 1;
    }
    Ok(count)
}

/// Доменное имя: метки из букв, цифр и дефисов, без пустых и слишком длинных.
fn valid_domain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.trim_end_matches('.').split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Память беседы-заглушка пробного прогона (решение 126 б): детекторы беседы срабатывают тогда,
/// когда письмо приносит соответствующий факт — новый тип вложения, новый регистрируемый домен
/// ссылки, `Reply-To`, которого не было.
fn trial_memory() -> ThreadFacts {
    ThreadFacts {
        attachments: vec!["trial/placeholder".to_owned()],
        link_domains: vec!["trial.invalid".to_owned()],
        reply_to: vec!["trial@invalid".to_owned()],
    }
}

/// Сработавшие признаки образца при пробном прогоне: детекторы ([`scan_message`]) против признаков
/// пакета; совпадение со списком — по файлам пакета (хранилище ещё не тронуто). Совпадения
/// детерминированы: соединения при прогоне нет ([`Field::SenderIp`] молчит), память — заглушка
/// ([`trial_memory`]).
fn trial_fired(
    signals: &[Signal],
    lists: &[ListFile],
    files: &PackageFiles,
    psl: Option<&publicsuffix::List>,
    raw: &[u8],
    limits: &ScanLimits,
) -> Vec<SignalId> {
    let findings = scan_message(raw, limits);
    let facts = trial_memory();
    let mut fired = Vec::new();
    for signal in signals {
        let hit = match &signal.detector {
            Detector::ThreadNewAttachmentType => findings
                .attachment_types
                .iter()
                .any(|t| !facts.attachments.contains(t)),
            Detector::EncryptedArchive => findings.encrypted_archive,
            Detector::DiskImageOrShortcut => findings.disk_image,
            Detector::ThreadNewLinkDomain => psl.is_some_and(|p| {
                registrable_domains(&findings, p)
                    .iter()
                    .any(|d| !facts.link_domains.iter().any(|x| x.eq_ignore_ascii_case(d)))
            }),
            Detector::ReplyToChanged => findings
                .reply_to
                .iter()
                .any(|rt| findings.from.as_deref() != Some(rt)),
            Detector::ListMatch { list, field } => {
                let Some(content) = files.list_bytes(lists, list) else {
                    continue;
                };
                list_hit(field, &findings, psl, content)
            }
        };
        // Сила детерминированных находок — 100, порог признака не выше 100: срабатывание — факт находки.
        if hit {
            fired.push(signal.id.clone());
        }
    }
    fired.sort();
    fired
}

/// Совпадение значения поля письма со списком пакета (по строкам файла).
fn list_hit(
    field: &Field,
    findings: &Findings,
    psl: Option<&publicsuffix::List>,
    content: &[u8],
) -> bool {
    let values: Vec<String> = std::str::from_utf8(content)
        .unwrap_or("")
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect();
    let contains = |v: &str| values.iter().any(|x| x.eq_ignore_ascii_case(v));
    match field {
        // Соединения при пробном прогоне нет — поле молчит.
        Field::SenderIp => false,
        Field::FromDomain => findings.from_domain.as_deref().is_some_and(contains),
        Field::LinkDomain => {
            let domains = psl
                .map(|p| registrable_domains(findings, p))
                .unwrap_or_else(|| findings.link_hosts.clone());
            domains.iter().any(|d| contains(d))
        }
        Field::LinkUrl => findings.link_urls.iter().any(|u| contains(u)),
        Field::AttachmentSha256 => findings
            .attachment_hashes
            .iter()
            .any(|h| values.iter().any(|v| v.eq_ignore_ascii_case(&hex(h)))),
    }
}

/// Регистрируемые домены ссылок письма (по PSL пакета; без PSL — хосты как есть).
fn registrable_domains(findings: &Findings, psl: &publicsuffix::List) -> Vec<String> {
    let mut out = Vec::new();
    for host in &findings.link_hosts {
        let domain = psl
            .domain(host.as_bytes())
            .map(|d| String::from_utf8_lossy(d.as_bytes()).to_ascii_lowercase())
            .unwrap_or_else(|| host.clone());
        if !out.contains(&domain) {
            out.push(domain);
        }
    }
    out
}

// ---------- Кэш узла ----------

/// Запись кэша: значение и поколение (записи прежнего поколения — устаревшие).
struct Slot<T> {
    value: T,
    generation: u64,
}

/// Кэш справочника: действующий каталог по организации, версии списков, источники и политики уровней.
#[derive(Default)]
struct CacheState {
    /// Растёт при каждом сбросе.
    generation: u64,
    effective: HashMap<TenantId, Slot<Arc<EffectiveCatalog>>>,
    lists: HashMap<ListId, Slot<Arc<Option<ListVersion>>>>,
    sources: Option<Slot<Arc<Vec<TiSource>>>>,
    policies: HashMap<RiskLevel, Slot<Option<RiskPolicy>>>,
}

/// Списки и источники пакета, поставленного до активации.
#[derive(Debug, Default, Clone)]
pub struct Pending {
    /// Версии списков пакета (содержимое — уже в BLOB).
    pub lists: Vec<ListVersion>,
    /// Источники пакета (`Bundled`).
    pub sources: Vec<TiSource>,
}

/// Хранилище справочника под кэшем узла (APP-78): [`RiskStore`] для доставки SMTP, Sieve (через
/// доставку), Admin API и роли обновления — один `Arc` на всех. Записи идут в хранилище `inner`;
/// после фиксации кэш узла сбрасывается и публикуется `risk_changed` (сигнал не публикует `PgMeta` —
/// как у политики доверия). Версии списков и источники проверенного, но не активированного пакета
/// ([`Installer::stage`]) хранит до активации — пакет без активации каталог не меняет.
pub struct RiskCache {
    /// Хранилище (`PgMeta`).
    inner: Arc<dyn RiskStore>,
    /// Шина узла: публикация `risk_changed`; `None` — без публикации (тесты).
    bus: Option<Arc<dyn EventBus>>,
    /// Секция `risk` (срок «только отчёт»), применяется без перезапуска.
    settings: Mutex<RiskSection>,
    /// Кэш и поколение сброса.
    state: Mutex<CacheState>,
    /// Поставленные до активации пакеты: `версия → (списки, источники)`.
    pending: Mutex<BTreeMap<u64, Pending>>,
}

impl std::fmt::Debug for RiskCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RiskCache")
            .field("bus", &self.bus.is_some())
            .finish_non_exhaustive()
    }
}

impl RiskCache {
    /// Кэш над хранилищем `inner` с шиной `bus` и секцией `risk`.
    pub fn new(
        inner: Arc<dyn RiskStore>,
        bus: Option<Arc<dyn EventBus>>,
        section: RiskSection,
    ) -> Self {
        Self {
            inner,
            bus,
            settings: Mutex::new(section),
            state: Mutex::default(),
            pending: Mutex::default(),
        }
    }

    /// Новая секция `risk` (перечитанная конфигурация — срок «только отчёт», без перезапуска).
    pub fn update_section(&self, section: RiskSection) {
        *self.settings.lock().expect("lock") = section;
    }

    /// Кладёт версии списков и источники пакета `version` (после записи архива в BLOB) — до активации.
    pub fn stage(&self, version: u64, pending: Pending) {
        self.pending.lock().expect("lock").insert(version, pending);
    }

    /// Сброс кэша: записи прежнего поколения не выдаются.
    fn invalidate(&self) {
        let mut st = self.state.lock().expect("lock");
        st.generation += 1;
        let generation = st.generation;
        st.effective.retain(|_, v| v.generation == generation);
        st.lists.retain(|_, v| v.generation == generation);
        st.policies.retain(|_, v| v.generation == generation);
        st.sources = st.sources.take().filter(|v| v.generation == generation);
    }

    /// Публикует `risk_changed` (после фиксации записи); ошибка — в журнал узла: запись сделана,
    /// кэши других узлов перечитаются по сроку.
    async fn publish(&self) {
        let Some(bus) = &self.bus else {
            return;
        };
        if let Err(e) = bus.publish(risk_changed()).await {
            tracing::warn!(
                error = %e,
                "risk: сигнал risk_changed не опубликован — кэши узлов перечитаются по сроку"
            );
        }
    }

    /// Следит за сигналами шины до `shutdown`: сброс кэша по `risk_changed` и `Resync` (потеря
    /// сигналов — сверка с хранилищем). Поток завершился — повтор через `retry` со сбросом.
    pub async fn watch(
        self: Arc<Self>,
        bus: Arc<dyn EventBus>,
        shutdown: CancellationToken,
        retry: Duration,
    ) {
        while !shutdown.is_cancelled() {
            match bus.subscribe_system().await {
                Ok(mut events) => {
                    // Сигналы до подписки могли потеряться.
                    self.invalidate();
                    loop {
                        let ev = tokio::select! {
                            () = shutdown.cancelled() => return,
                            ev = events.next() => ev,
                        };
                        match ev.map(|e| e.kind) {
                            Some(EventKind::RiskChanged) | Some(EventKind::Resync) => {
                                self.invalidate()
                            }
                            Some(_) => {}
                            None => break,
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "risk: подписка на сигналы справочника не удалась");
                }
            }
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(retry) => {}
            }
        }
    }

    /// Действующий каталог с учётом срока «только отчёт» ([`aging`]): чтение из кэша, сбой хранилища —
    /// вызывающему (доставка — письмо без срабатываний, Admin API — 500).
    async fn effective_aged(&self, tenant: TenantId) -> Result<Arc<EffectiveCatalog>> {
        let days = self.settings.lock().expect("lock").report_only_days;
        let cached = {
            let st = self.state.lock().expect("lock");
            st.effective
                .get(&tenant)
                .filter(|s| s.generation == st.generation)
                .map(|s| Arc::clone(&s.value))
        };
        if let Some(catalog) = cached {
            return Ok(aging(&catalog, days, OffsetDateTime::now_utc()));
        }
        let catalog = Arc::new(self.inner.effective(tenant).await?);
        let aged = aging(&catalog, days, OffsetDateTime::now_utc());
        let mut st = self.state.lock().expect("lock");
        let generation = st.generation;
        st.effective.insert(
            tenant,
            Slot {
                value: catalog,
                generation,
            },
        );
        Ok(aged)
    }
}

/// Признаки, чей переход «только отчёт» → `Enforce` уже отмечен в журнале этого процесса.
static AGED_SEEN: Mutex<BTreeSet<SignalId>> = Mutex::new(BTreeSet::new());

/// Срок «только отчёт» (APP-78, решение 126 а): признак поставщика в режиме `Report` старше `days`
/// суток без решения администратора (уровни его не меняли — `base` задан, `source` пуст) — `Enforce`
/// в действующем каталоге. Хранилище не меняется; переход — событие журнала узла и строка в отчёте
/// `doctor` (по одному событию на признак за жизнь процесса — [`AGED_SEEN`]).
fn aging(catalog: &EffectiveCatalog, days: u32, now: OffsetDateTime) -> Arc<EffectiveCatalog> {
    let Ok(term) = time::Duration::try_from(Duration::from_secs(u64::from(days) * 86_400)) else {
        return Arc::new(catalog.clone());
    };
    let mut out = catalog.clone();
    let mut changed = Vec::new();
    for e in &mut out.signals {
        if e.source.is_none()
            && let Some(base) = &e.base
            && base.mode == Mode::Report
            && e.signal.mode == Mode::Report
            && base.since + term <= now
        {
            e.signal.mode = Mode::Enforce;
            changed.push(e.signal.id.clone());
        }
    }
    if !changed.is_empty() {
        let mut seen = AGED_SEEN.lock().expect("lock");
        let fresh: Vec<SignalId> = changed
            .into_iter()
            .filter(|id| !seen.contains(id))
            .collect();
        if !fresh.is_empty() {
            tracing::info!(
                signals = %fresh.iter().map(|id| id.as_str()).collect::<Vec<_>>().join(", "),
                "risk: признаки поставщика отработали срок «только отчёт» ({days} сут) и переведены \
                 в enforce; строка — в отчёте doctor"
            );
            seen.extend(fresh);
        }
    }
    Arc::new(out)
}

#[async_trait]
impl RiskStore for RiskCache {
    async fn effective(&self, tenant: TenantId) -> Result<EffectiveCatalog> {
        let aged = self.effective_aged(tenant).await?;
        Ok((*aged).clone())
    }

    /// Запись манифеста в хранилище (маршрут Admin API вызывает после проверки узла); версии списков
    /// и источники уже уложены ([`Installer::stage`]) — здесь только манифест: БД без обращений к BLOB.
    async fn put_package(&self, manifest: &PackageManifest) -> Result<()> {
        self.inner.put_package(manifest).await
    }

    /// Активация: номер строго больше действующего (проверяет хранилище); после фиксации — версии
    /// списков и источники пакета становятся текущими, кэш сбрасывается, `risk_changed` — другим узлам.
    async fn activate(&self, version: u64) -> Result<()> {
        self.inner.activate(version).await?;
        let pending = self.pending.lock().expect("lock").remove(&version);
        if let Some(pending) = pending {
            for source in &pending.sources {
                if let Err(e) = self.inner.put_source(source).await {
                    tracing::warn!(
                        source = %source.id,
                        error = %e,
                        "risk: источник пакета {version} не записан — списки без лицензии и учёта"
                    );
                }
            }
            for list in &pending.lists {
                if let Err(e) = self.inner.put_list_version(list).await {
                    tracing::warn!(
                        list = %list.list.as_str(),
                        error = %e,
                        "risk: версия списка пакета {version} не записана"
                    );
                }
            }
        }
        self.invalidate();
        self.publish().await;
        Ok(())
    }

    /// Откат на хранимую версию; после фиксации — сброс кэша и сигнал.
    async fn rollback(&self, version: u64) -> Result<()> {
        self.inner.rollback(version).await?;
        self.invalidate();
        self.publish().await;
        Ok(())
    }

    async fn packages(&self) -> Result<Vec<PackageEntry>> {
        self.inner.packages().await
    }

    /// Политика уровня из кэша.
    async fn policy(&self, level: RiskLevel) -> Result<Option<RiskPolicy>> {
        let hit = {
            let st = self.state.lock().expect("lock");
            st.policies
                .get(&level)
                .filter(|s| s.generation == st.generation)
                .map(|s| s.value.clone())
        };
        if let Some(policy) = hit {
            return Ok(policy);
        }
        let policy = self.inner.policy(level).await?;
        let mut st = self.state.lock().expect("lock");
        let generation = st.generation;
        st.policies.insert(
            level,
            Slot {
                value: policy.clone(),
                generation,
            },
        );
        Ok(policy)
    }

    /// Запись политики уровня; после фиксации — сброс кэша и сигнал.
    async fn set_policy(&self, level: RiskLevel, policy: &RiskPolicy) -> Result<()> {
        self.inner.set_policy(level, policy).await?;
        self.invalidate();
        self.publish().await;
        Ok(())
    }

    /// Сброс политики уровня; после фиксации — сброс кэша и сигнал.
    async fn reset_policy(&self, level: RiskLevel) -> Result<()> {
        self.inner.reset_policy(level).await?;
        self.invalidate();
        self.publish().await;
        Ok(())
    }

    /// Источники TI из кэша.
    async fn sources(&self) -> Result<Vec<TiSource>> {
        let hit = {
            let st = self.state.lock().expect("lock");
            st.sources
                .as_ref()
                .filter(|s| s.generation == st.generation)
                .map(|s| Arc::clone(&s.value))
        };
        if let Some(sources) = hit {
            return Ok((*sources).clone());
        }
        let sources = Arc::new(self.inner.sources().await?);
        let out = (*sources).clone();
        let mut st = self.state.lock().expect("lock");
        let generation = st.generation;
        st.sources = Some(Slot {
            value: sources,
            generation,
        });
        Ok(out)
    }

    /// Запись или замена источника; после фиксации — сброс кэша и сигнал.
    async fn put_source(&self, source: &TiSource) -> Result<()> {
        self.inner.put_source(source).await?;
        self.invalidate();
        self.publish().await;
        Ok(())
    }

    /// Удаление источника; после фиксации — сброс кэша и сигнал.
    async fn delete_source(&self, id: &SourceId) -> Result<()> {
        self.inner.delete_source(id).await?;
        self.invalidate();
        self.publish().await;
        Ok(())
    }

    /// Запись версии списка текущей; после фиксации — сброс кэша и сигнал.
    async fn put_list_version(&self, version: &ListVersion) -> Result<()> {
        self.inner.put_list_version(version).await?;
        self.invalidate();
        self.publish().await;
        Ok(())
    }

    /// Текущая версия списка из кэша; содержимое — BLOB (читает [`NodeEnviron`]).
    async fn list_current(&self, list: &ListId) -> Result<Option<ListVersion>> {
        let hit = {
            let st = self.state.lock().expect("lock");
            st.lists
                .get(list)
                .filter(|s| s.generation == st.generation)
                .map(|s| Arc::clone(&s.value))
        };
        if let Some(version) = hit {
            return Ok((*version).clone());
        }
        let version = Arc::new(self.inner.list_current(list).await?);
        let mut st = self.state.lock().expect("lock");
        let generation = st.generation;
        st.lists.insert(
            list.clone(),
            Slot {
                value: version,
                generation,
            },
        );
        Ok((*st.lists.get(list).expect("записана выше").value).clone())
    }

    /// Учёт обращений (счётчики памяти сбрасывает [`NodeEnviron`]) — прямо в хранилище.
    async fn record_usage(
        &self,
        source: &SourceId,
        tenant: TenantId,
        lookups: u64,
        hits: u64,
    ) -> Result<()> {
        self.inner.record_usage(source, tenant, lookups, hits).await
    }

    async fn usage(&self, source: &SourceId, since: OffsetDateTime) -> Result<Vec<UsageEntry>> {
        self.inner.usage(source, since).await
    }

    /// Срабатывания — прямо в хранилище (каждое письмо — новая запись, кэш не нужен).
    async fn record_hits(
        &self,
        tenant: TenantId,
        message: BlobHash,
        verdict: &Verdict,
    ) -> Result<()> {
        self.inner.record_hits(tenant, message, verdict).await
    }

    async fn hits(
        &self,
        tenant: TenantId,
        filter: &tp_contracts::risk::HitsQuery,
    ) -> Result<Vec<tp_contracts::risk::HitRecord>> {
        self.inner.hits(tenant, filter).await
    }
}

// ---------- Установка ----------

/// Установка проверенного пакета (APP-78): BLOB — вне транзакций, БД — после. `store` — кэш узла
/// ([`RiskCache`]): версии списков и источники становятся текущими при активации.
#[derive(Clone)]
pub struct Installer {
    /// Хранилище справочника (кэш узла).
    pub store: Arc<RiskCache>,
    /// Хранилище BLOB (архивы пакетов и содержимое списков).
    pub blob: Arc<dyn BlobStore>,
}

impl std::fmt::Debug for Installer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Installer").finish_non_exhaustive()
    }
}

impl Installer {
    /// Установщик над кэшем узла и BLOB.
    pub fn new(store: Arc<RiskCache>, blob: Arc<dyn BlobStore>) -> Self {
        Self { store, blob }
    }

    /// Укладывает результаты проверки: архив пакета и содержимое списков — в BLOB (идемпотентно,
    /// вне транзакций), версии списков и источники — к активации ([`RiskCache::stage`]).
    pub async fn stage(&self, verified: &Verified) -> Result<()> {
        let version = verified.manifest.version;
        let archive = archive_of(verified)?;
        self.blob
            .put_raw(&archive_path(version), archive.into())
            .await?;
        let mut pending = Pending::default();
        for list in &verified.manifest.lists {
            let bytes = verified.files.get(&list.path).ok_or_else(|| {
                Error::internal(format!("risk: файл списка {} потерян", list.path))
            })?;
            let sha256 = sha256(bytes);
            let path = list_blob_path(&sha256);
            self.blob
                .put_raw(&path, Bytes::from(bytes.to_vec()))
                .await?;
            pending.lists.push(ListVersion {
                list: list.id.clone(),
                source: list.source.clone(),
                sha256,
                blob: path,
                entries: list.entries,
                fetched_at: OffsetDateTime::now_utc(),
                tlp: None,
            });
        }
        pending.sources = verified.sources.clone();
        self.store.stage(version, pending);
        Ok(())
    }

    /// Полная установка проверенного пакета: BLOB, манифест ([`RiskStore::put_package`]), активация
    /// ([`RiskStore::activate`]), очистка архивов прошлых версий — после фиксации. Новые для каталога
    /// признаки — «только отчёт» (как в Admin API: отчёт считают до записи). Возвращает отчёт.
    pub async fn install(&self, mut verified: Verified) -> Result<UpdateReport> {
        let old = self.store.effective(TenantId::DEFAULT).await?;
        let update = Catalog::apply_update(&old, &mut verified.manifest.signals);
        self.stage(&verified).await?;
        let version = verified.manifest.version;
        self.store.put_package(&verified.manifest).await?;
        self.store.activate(version).await?;
        tracing::info!(
            version,
            added = update.added.len(),
            removed = update.removed.len(),
            changed = update.changed.len(),
            "risk: пакет поставщика установлен и активирован"
        );
        self.cleanup().await;
        Ok(update)
    }

    /// Удаляет из BLOB архивы версий, которых больше нет в хранилище (активация и откат удаляют
    /// строки сверх `risk.package.keep` — здесь их файлы). Сбои — в журнал, не в отказ установки.
    pub async fn cleanup(&self) {
        let stored: BTreeSet<u64> = match self.store.packages().await {
            Ok(list) => list.into_iter().map(|p| p.version).collect(),
            Err(e) => {
                tracing::warn!(error = %e, "risk: список пакетов не прочитан — архивы не сверены");
                return;
            }
        };
        let mut archives = self.blob.list(ARCHIVE_PREFIX, OffsetDateTime::UNIX_EPOCH);
        while let Some(entry) = archives.next().await {
            let Ok(entry) = entry else { continue };
            let Some(name) = entry.path.strip_prefix(ARCHIVE_PREFIX) else {
                continue;
            };
            let version = name
                .strip_suffix(".zip")
                .and_then(|v| v.parse::<u64>().ok());
            if let Some(v) = version
                && !stored.contains(&v)
                && let Err(e) = self.blob.delete_raw(&entry.path).await
            {
                tracing::warn!(error = %e, path = %entry.path, "risk: архив пакета не удалён");
            }
        }
    }
}

/// Собирает архив пакета (байты для BLOB и `thepost risk pack`): манифест, подпись, источники и
/// файлы — детерминированный ZIP (DEFLATE).
pub fn archive_of(verified: &Verified) -> Result<Vec<u8>> {
    let buf = std::io::Cursor::new(Vec::new());
    let mut zip = zip::ZipWriter::new(buf);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    let mut write = |name: &str, bytes: &[u8]| -> Result<()> {
        zip.start_file(name.to_owned(), options)
            .map_err(|e| Error::internal(format!("risk: архив: {e}")))?;
        std::io::Write::write_all(&mut zip, bytes)
            .map_err(|e| Error::internal(format!("risk: архив: {e}")))
    };
    write("manifest.json", &canonical_manifest(&verified.manifest)?)?;
    if let Some(signature) = &verified.signature {
        write("manifest.sig", signature)?;
    }
    if !verified.sources.is_empty() {
        let json = serde_json::to_vec(&verified.sources)
            .map_err(|e| Error::internal(format!("risk: архив: {e}")))?;
        write("sources.json", &json)?;
    }
    for (path, bytes) in &verified.files.0 {
        write(path, bytes)?;
    }
    zip.finish()
        .map_err(|e| Error::internal(format!("risk: архив: {e}")))
        .map(|buf| buf.into_inner())
}

// ---------- Данные детекторов ----------

/// Разобранный список TI: значения по видам (индекс поиска; вид каждой записи — по её форме).
#[derive(Debug, Default)]
struct ListData {
    /// Подсети и адреса ([`ListValue::Ip`]).
    ip: Vec<ipnet::IpNet>,
    /// Домены и URL ([`ListValue::Domain`], [`ListValue::Url`]; домен списка покрывает поддомены).
    names: Vec<String>,
    /// SHA-256 (hex, нижний регистр; [`ListValue::Sha256`]).
    hashes: Vec<String>,
}

/// Данные узла для детекторов каталога ([`RiskEnviron`], SMTP-52): память бесед — `PgMeta`,
/// индексы списков TI и Public Suffix List — из BLOB по версиям кэша узла (APP-78; выгрузка фидов и
/// форматы RPZ/MISP/STIX — APP-79). Сбой чтения — «нет» (fail-open, письмо доставляется).
pub struct NodeEnviron {
    /// Метаданные (память бесед — SQL по `thread_keys`/`threads`); `None` — проверка списков без
    /// СУБД (тесты и `thepost risk verify`: память бесед молчит).
    meta: Option<PgMeta>,
    /// Хранилище BLOB (содержимое списков).
    blob: Arc<dyn BlobStore>,
    /// Кэш справочника (версии списков).
    store: Arc<RiskCache>,
    /// Разобранные списки: идентификатор → (хэш версии, разобранные значения).
    lists: Mutex<HashMap<ListId, (BlobHash, Arc<ListData>)>>,
    /// Public Suffix List пакета: хэш версии и разобранный список.
    psl: Mutex<Option<(BlobHash, Arc<publicsuffix::List>)>>,
}

impl std::fmt::Debug for NodeEnviron {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeEnviron").finish_non_exhaustive()
    }
}

impl NodeEnviron {
    /// Данные детекторов над `PgMeta`, BLOB и кэшем справочника.
    pub fn new(meta: PgMeta, blob: Arc<dyn BlobStore>, store: Arc<RiskCache>) -> Self {
        Self {
            meta: Some(meta),
            blob,
            store,
            lists: Mutex::default(),
            psl: Mutex::default(),
        }
    }

    /// Данные списков без `PgMeta` (тесты): память бесед молчит.
    pub fn for_lists(blob: Arc<dyn BlobStore>, store: Arc<RiskCache>) -> Self {
        Self {
            meta: None,
            blob,
            store,
            lists: Mutex::default(),
            psl: Mutex::default(),
        }
    }

    /// Разобранный список: кэш по хэшу версии; сбой чтения или разбора — пустой (детектор молчит).
    async fn list_data(&self, list: &ListId) -> Option<Arc<ListData>> {
        let version = self.store.list_current(list).await.ok()??;
        let cached = {
            let cache = self.lists.lock().expect("lock");
            cache
                .get(list)
                .filter(|(sha, _)| *sha == version.sha256)
                .map(|(_, data)| Arc::clone(data))
        };
        if let Some(data) = cached {
            return Some(data);
        }
        let data = Arc::new(
            load_list(self.blob.as_ref(), &version)
                .await
                .unwrap_or_default(),
        );
        self.lists
            .lock()
            .expect("lock")
            .insert(list.clone(), (version.sha256, Arc::clone(&data)));
        Some(data)
    }

    /// Public Suffix List пакета: кэш по хэшу версии списка [`PSL_LIST`].
    async fn psl_list(&self) -> Option<Arc<publicsuffix::List>> {
        let id = ListId::new(PSL_LIST).ok()?;
        let version = self.store.list_current(&id).await.ok()??;
        let cached = {
            let cache = self.psl.lock().expect("lock");
            cache
                .as_ref()
                .filter(|(sha, _)| *sha == version.sha256)
                .map(|(_, list)| Arc::clone(list))
        };
        if let Some(list) = cached {
            return Some(list);
        }
        let bytes = read_raw(self.blob.as_ref(), &version.blob).await.ok()?;
        let list = Arc::new(publicsuffix::List::from_bytes(&bytes).ok()?);
        *self.psl.lock().expect("lock") = Some((version.sha256, Arc::clone(&list)));
        Some(list)
    }

    /// Список доступен организации: источник не ограничен ([`Tenants::All`]) или организация включена.
    async fn list_allows(&self, tenant: TenantId, list: &ListId) -> bool {
        let Some(version) = self.store.list_current(list).await.ok().flatten() else {
            return false;
        };
        let Ok(sources) = self.store.sources().await else {
            return false;
        };
        match sources.iter().find(|s| s.id == version.source) {
            Some(source) => match &source.tenants {
                Tenants::All => true,
                Tenants::Only(tenants) => tenants.contains(&tenant),
            },
            None => false,
        }
    }
}

/// Читает и разбирает содержимое списка из BLOB: вид каждой записи — по её форме (адрес/подсеть,
/// 64 hex, http(s), прочее — домен).
async fn load_list(blob: &dyn BlobStore, version: &ListVersion) -> Result<ListData> {
    let bytes = read_raw(blob, &version.blob).await?;
    let text = String::from_utf8_lossy(&bytes);
    let mut data = ListData::default();
    for line in text.lines() {
        let value = line.split('#').next().unwrap_or("").trim();
        if value.is_empty() {
            continue;
        }
        if let Ok(net) = value.parse::<ipnet::IpNet>() {
            data.ip.push(net);
        } else if let Ok(addr) = value.parse::<std::net::IpAddr>() {
            data.ip.push(ipnet::IpNet::from(addr));
        } else if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
            data.hashes.push(value.to_ascii_lowercase());
        } else {
            data.names
                .push(value.trim_end_matches('.').to_ascii_lowercase());
        }
    }
    Ok(data)
}

/// Читает объект BLOB по произвольному пути целиком.
async fn read_raw(blob: &dyn BlobStore, path: &str) -> Result<Vec<u8>> {
    let mut stream = blob.get_raw(path, None).await?;
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Error::internal(format!("risk: чтение BLOB: {e}")))?;
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Домен `host` совпадает со значением списка: точное имя или поддомен (`drop.example` покрывает
/// `a.drop.example`, но не `notdrop.example`).
fn name_matches(list_value: &str, host: &str) -> bool {
    let host = host.trim_end_matches('.');
    host == list_value || host.ends_with(&format!(".{list_value}"))
}

#[async_trait]
impl RiskEnviron for NodeEnviron {
    /// Память беседы получателя: беседа по каноническим ключам присоединения (CTR-94, `join_key`),
    /// память — `threads.facts` (META-86). Запрос в транзакции организации (RLS); сбой — пустая
    /// память (детекторы беседы молчат, письмо доставляется).
    async fn thread_facts(
        &self,
        tenant: TenantId,
        account: AccountId,
        keys: &[String],
    ) -> Result<ThreadFacts> {
        use tp_contracts::thread::join_key;
        let keys: Vec<String> = keys
            .iter()
            .map(|k| join_key(k))
            .filter(|k| !k.is_empty())
            .collect();
        if keys.is_empty() {
            return Ok(ThreadFacts::new());
        }
        let Some(meta) = &self.meta else {
            tracing::debug!("risk: память беседы не подключена — детекторы беседы молчат");
            return Ok(ThreadFacts::new());
        };
        let mut tx = tp_meta::schema::begin(&meta.pool(), tenant).await?;
        let thread: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT tk.thread_id FROM thread_keys tk
             JOIN threads t ON t.tenant_id = tk.tenant_id AND t.account_id = tk.account_id
                           AND t.thread_id = tk.thread_id
             WHERE tk.tenant_id = $1 AND tk.account_id = $2 AND tk.key = ANY($3)
             ORDER BY t.seq, tk.thread_id LIMIT 1",
        )
        .bind(*tenant.as_uuid())
        .bind(*account.as_uuid())
        .bind(&keys)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| Error::internal(format!("risk: память беседы: {e}")))?;
        let facts = match thread {
            None => ThreadFacts::new(),
            Some(thread) => {
                let facts: Option<serde_json::Value> =
                    sqlx::query_scalar("SELECT facts FROM threads WHERE thread_id = $1")
                        .bind(thread)
                        .fetch_optional(&mut *tx)
                        .await
                        .map_err(|e| Error::internal(format!("risk: память беседы: {e}")))?;
                facts
                    .and_then(|v| serde_json::from_value(v).ok())
                    .unwrap_or_default()
            }
        };
        // Чтение: транзакция откатывается (sqlx делает это при drop).
        drop(tx);
        Ok(facts)
    }

    /// Значение в списке TI организации (индексы активных версий списков; организации источника —
    /// [`Tenants::Only`]). Списка нет — `false`.
    async fn list_contains(
        &self,
        tenant: TenantId,
        list: &ListId,
        value: ListValue<'_>,
    ) -> Result<bool> {
        if !self.list_allows(tenant, list).await {
            return Ok(false);
        }
        let Some(data) = self.list_data(list).await else {
            return Ok(false);
        };
        let hit = match value {
            ListValue::Ip(ip) => data.ip.iter().any(|net| net.contains(&ip)),
            ListValue::Domain(domain) => data.names.iter().any(|n| name_matches(n, domain)),
            ListValue::Url(url) => data
                .names
                .iter()
                .any(|n| url == n || url.starts_with(&format!("{n}/"))),
            ListValue::Sha256(hash) => data.hashes.iter().any(|h| h == &hex(hash)),
        };
        Ok(hit)
    }

    /// Public Suffix List пакета поставщика ([`PSL_LIST`]); пакета нет — `None` (детектор «новый
    /// домен» молчит).
    async fn psl(&self) -> Result<Option<Arc<publicsuffix::List>>> {
        Ok(self.psl_list().await)
    }
}

// ---------- Интерфейс Admin API ----------

/// Операции узла над справочником для Admin API ([`RiskNode`], ADM-51): проверка загруженного пакета
/// (подпись, lint, пробный прогон) с укладкой BLOB и версий списков до активации; импорт и обновление
/// списков TI — форматы `Txt` и `Csv` (RPZ, MISP, STIX/TAXII — коннекторы APP-79).
pub struct AdminNode {
    /// Проверка пакетов.
    pub verifier: Arc<Verifier>,
    /// Установка (BLOB; версии списков и источники — к активации).
    pub installer: Arc<Installer>,
    /// Кэш справочника (действующий каталог для отчёта проверки).
    pub store: Arc<RiskCache>,
    /// BLOB (содержимое списков).
    pub blob: Arc<dyn BlobStore>,
    /// Каталог импорта (`risk.import.dir`).
    pub import_dir: PathBuf,
    /// Хранилище секретов (ключи фидов по `SecretRef`).
    pub secrets: Arc<dyn tp_contracts::secrets::SecretStore>,
}

impl std::fmt::Debug for AdminNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminNode").finish_non_exhaustive()
    }
}

impl AdminNode {
    /// Собирает операции узла.
    pub fn new(
        verifier: Arc<Verifier>,
        installer: Arc<Installer>,
        store: Arc<RiskCache>,
        blob: Arc<dyn BlobStore>,
        section: &RiskSection,
        secrets: Arc<dyn tp_contracts::secrets::SecretStore>,
    ) -> Self {
        Self {
            verifier,
            installer,
            store,
            blob,
            import_dir: section.import.dir.clone(),
            secrets,
        }
    }

    /// Версия списка из байтов: разбор формата (число записей), содержимое — в BLOB.
    async fn list_version(&self, source: &TiSource, bytes: &[u8]) -> Result<ListVersion> {
        let entries = feed_entries(source, bytes)?;
        let sha256 = sha256(bytes);
        let blob = list_blob_path(&sha256);
        self.blob
            .put_raw(&blob, Bytes::from(bytes.to_vec()))
            .await?;
        Ok(ListVersion {
            list: ListId::new(source.id.as_str())
                .unwrap_or_else(|_| ListId::new("list").expect("id")),
            source: source.id.clone(),
            sha256,
            blob,
            entries,
            fetched_at: OffsetDateTime::now_utc(),
            tlp: None,
        })
    }
}

/// Число записей фида по формату источника; маркировка TLP и форматы RPZ/MISP/STIX — коннекторы
/// APP-79 (здесь — отказ с подсказкой).
fn feed_entries(source: &TiSource, bytes: &[u8]) -> Result<u64> {
    match &source.format {
        FeedFormat::Txt => parse_list(ListKind::Domain, bytes),
        FeedFormat::Csv { column } => csv_entries(bytes, column),
        FeedFormat::Rpz | FeedFormat::MispFeed | FeedFormat::Stix21 => {
            Err(Error::invalid(format!(
                "risk: источник {}: формат {:?} разбирает коннектор источников TI (APP-79)",
                source.id, source.format
            )))
        }
    }
}

/// Число записей CSV по колонке с индикатором: заголовок с именем колонки (или её индекс), `#` —
/// комментарий.
fn csv_entries(bytes: &[u8], column: &str) -> Result<u64> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| Error::invalid("risk: CSV — не текст UTF-8"))?;
    // Колонка: индекс, если число; иначе имя — ищется в заголовке (первая строка с ним).
    let explicit = column.parse::<usize>().ok();
    let mut header: Option<usize> = None;
    let mut count = 0u64;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        if line.trim().is_empty() {
            continue;
        }
        let cells: Vec<String> = line
            .split(',')
            .map(|c| c.trim().trim_matches('"').to_owned())
            .collect();
        let position = match (explicit, header) {
            // Индекс задан: строки — данные (ячейка должна быть непустой).
            (Some(i), _) => {
                if cells.get(i).is_none_or(|c| c.is_empty()) {
                    continue;
                }
                i
            }
            (None, Some(i)) => i,
            (None, None) => match cells.iter().position(|c| c == column) {
                // Первая строка — заголовок: данных в ней нет.
                Some(i) => {
                    header = Some(i);
                    continue;
                }
                None => {
                    return Err(Error::invalid(format!(
                        "risk: колонка {column:?} не найдена в заголовке CSV и не индекс"
                    )));
                }
            },
        };
        if cells.get(position).is_some_and(|c| !c.is_empty()) {
            count += 1;
        }
    }
    Ok(count)
}

#[async_trait]
impl RiskNode for AdminNode {
    /// Проверка загруженного файла пакета (подпись, lint, пробный прогон) и укладка: архив и
    /// содержимое списков — в BLOB, версии списков и источники — к активации ([`Installer::stage`]);
    /// манифест записывает маршрут Admin API ([`RiskStore::put_package`]), активация — отдельно.
    async fn verify_package(&self, bytes: &[u8]) -> Result<PackageVerified> {
        let old = self.store.effective(TenantId::DEFAULT).await?;
        let verified = self.verifier.verify(bytes, Some(&old))?;
        self.installer.stage(&verified).await?;
        Ok(PackageVerified {
            manifest: verified.manifest,
            samples: verified.samples,
        })
    }

    /// Импорт файла списка источника (ADM-51): разбор формата, содержимое — в BLOB.
    async fn import_list(&self, source: &TiSource, bytes: &[u8]) -> Result<ListVersion> {
        self.list_version(source, bytes).await
    }

    /// Обновление источника сейчас: `File` — файл из каталога импорта (`risk.import.dir`), `Http` —
    /// выгрузка фида (авторизация — секрет по [`TiSource::key`]); TAXII и форматы RPZ/MISP/STIX —
    /// коннекторы APP-79 (отказ с подсказкой).
    async fn refresh_source(&self, source: &TiSource) -> Result<ListVersion> {
        let bytes = match &source.kind {
            SourceKind::File => {
                let path = import_file(&self.import_dir, &source.id);
                std::fs::read(&path)
                    .map_err(|e| Error::internal(format!("risk: файл {}: {e}", path.display())))?
            }
            SourceKind::Http { url } => fetch_http(source, url, self.secrets.as_ref()).await?,
            SourceKind::Taxii { .. } => {
                return Err(Error::invalid(
                    "risk: коннектор TAXII 2.1 — волна источников TI (APP-79)",
                ));
            }
        };
        self.list_version(source, &bytes).await
    }
}

/// Выгружает фид по HTTP(S) с авторизацией источника (секрет — из хранилища по `key`).
async fn fetch_http(
    source: &TiSource,
    url: &str,
    secrets: &dyn tp_contracts::secrets::SecretStore,
) -> Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| Error::internal(format!("risk: HTTP-клиент: {e}")))?;
    let mut request = client.get(url);
    let secret = || async {
        let reference = source.key.as_ref().ok_or_else(|| {
            Error::invalid(format!(
                "risk: источник {}: авторизация без ключа (key)",
                source.id
            ))
        })?;
        Ok::<_, Error>(secrets.get(reference).await?.expose().to_owned())
    };
    match &source.auth {
        HttpAuth::None => {}
        HttpAuth::Header { name } => {
            request = request.header(name.as_str(), secret().await?);
        }
        HttpAuth::Bearer => {
            request = request.bearer_auth(secret().await?);
        }
        HttpAuth::Basic { user } => {
            request = request.basic_auth(user.as_str(), Some(secret().await?));
        }
        // Сертификат клиента HTTPS-фидов — коннекторы APP-79 (TAXII Kaspersky).
        HttpAuth::ClientCert => {
            return Err(Error::invalid(
                "risk: авторизация сертификатом клиента — волна источников TI (APP-79)",
            ));
        }
    }
    let response = request
        .send()
        .await
        .map_err(|e| Error::internal(format!("risk: выгрузка {}: {e}", source.id)))?;
    if !response.status().is_success() {
        return Err(Error::internal(format!(
            "risk: выгрузка {}: HTTP {}",
            source.id,
            response.status()
        )));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| Error::internal(format!("risk: выгрузка {}: {e}", source.id)))?;
    Ok(bytes.to_vec())
}

// ---------- Обновление (роль maintenance) и первый пакет ----------

/// Итог прохода обновления.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// Источник не принёс новой версии (HTTP 304, в каталоге нет свежего файла).
    UpToDate,
    /// Пакет проверен и установлен; `activated` — активирован сразу (`auto_activate`).
    Installed { version: u64, activated: bool },
    /// Проверка не прошла (`report` — причина): прежний пакет работает.
    Rejected { report: String },
}

/// Срок лизы обновления пакета: проход покрывает выгрузку и установку; после прохода лиза истекает
/// сама — узел с отстающими часами не повторит проход.
fn update_lease_ttl() -> Duration {
    Duration::from_secs(15 * 60)
}

/// Обновление пакета поставщика — шаг роли maintenance (APP-78): раз в `risk.update.interval` узел с
/// лизой [`UPDATE_LEASE`] берёт пакет с `risk.update.url` или из `risk.update.dir`; проверенный —
/// устанавливает и активирует при `auto_activate`. Сбой — предупреждение в журнале узла (в `doctor` —
/// [`doctor_risk`]), прежний пакет работает. При пустом хранилище — первый пакет из поставки
/// (`risk.package.dir`, DEP-57).
#[derive(Clone)]
pub struct RiskUpdate {
    /// Секция `risk` (источник и `auto_activate`).
    pub section: RiskSection,
    /// Проверка пакетов.
    pub verifier: Arc<Verifier>,
    /// Установка.
    pub installer: Arc<Installer>,
    /// Кэш справочника (действующий каталог, пакеты, активация).
    pub store: Arc<RiskCache>,
    /// Лизы кластера.
    pub leases: Arc<dyn tp_contracts::lease::LeaseStore>,
    /// Держатель лиз.
    pub holder: String,
    /// Период проходов (`risk.update.interval`).
    pub interval: Duration,
    /// ETag последней выгрузки (`If-None-Match` следующего прохода).
    etag: Arc<Mutex<Option<String>>>,
}

impl std::fmt::Debug for RiskUpdate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RiskUpdate")
            .field("interval", &self.interval)
            .finish_non_exhaustive()
    }
}

impl RiskUpdate {
    /// Воркер обновления по секции `risk`.
    pub fn new(
        section: RiskSection,
        verifier: Arc<Verifier>,
        installer: Arc<Installer>,
        store: Arc<RiskCache>,
        leases: Arc<dyn tp_contracts::lease::LeaseStore>,
        holder: String,
    ) -> Self {
        Self {
            interval: section.update.interval,
            section,
            verifier,
            installer,
            store,
            leases,
            holder,
            etag: Arc::default(),
        }
    }

    /// Первый проход — при запуске роли (первый пакет из поставки при пустом хранилище), затем раз в
    /// [`RiskUpdate::interval`]; установку ведёт узел с лизой [`UPDATE_LEASE`].
    pub async fn run(self, shutdown: CancellationToken) {
        loop {
            let lease = self
                .leases
                .try_acquire(UPDATE_LEASE, &self.holder, update_lease_ttl())
                .await;
            match lease {
                Ok(Some(lease)) => {
                    let pass = self.pass();
                    tokio::select! {
                        () = shutdown.cancelled() => {
                            drop(lease);
                            return;
                        }
                        _ = pass => {}
                    }
                }
                Ok(None) => {
                    tracing::debug!(
                        lease = UPDATE_LEASE,
                        "risk: обновление пакета ведёт другой узел"
                    );
                }
                Err(e) => {
                    tracing::warn!(error = %e, "risk: лиза обновления не получена, проход пропущен");
                }
            }
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(self.interval.max(Duration::from_millis(1))) => {}
            }
        }
    }

    /// Один проход: пустое хранилище — первый пакет из поставки; иначе — источник обновления.
    pub async fn pass(&self) -> UpdateOutcome {
        let empty = matches!(self.store.packages().await, Ok(list) if list.is_empty());
        if empty && self.section.package.dir.is_some() {
            return self.first_package().await;
        }
        self.update_once().await
    }

    /// Первый пакет из поставки (DEP-57): единственный `*.zip` каталога `risk.package.dir`.
    async fn first_package(&self) -> UpdateOutcome {
        let Some(dir) = &self.section.package.dir else {
            return self.update_once().await;
        };
        let candidates = match packages_in_dir(dir) {
            Ok(list) => list,
            Err(_) => {
                tracing::debug!(
                    dir = %dir.display(),
                    "risk: каталог поставки пакета недоступен — хранилище остаётся пустым"
                );
                return self.update_once().await;
            }
        };
        match candidates.as_slice() {
            [path] => match self.install_file(path).await {
                Ok(outcome) => outcome,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        path = %path.display(),
                        "risk: первый пакет поставки не установлен (предупреждение в doctor)"
                    );
                    UpdateOutcome::Rejected {
                        report: e.to_string(),
                    }
                }
            },
            [] => {
                tracing::warn!(
                    dir = %dir.display(),
                    "risk: хранилище пакетов пусто, а в каталоге поставки пакета нет (*.zip)"
                );
                self.update_once().await
            }
            _ => {
                tracing::warn!(
                    dir = %dir.display(),
                    "risk: в каталоге поставки несколько пакетов — ожидается один (*.zip)"
                );
                UpdateOutcome::Rejected {
                    report: "в каталоге поставки несколько пакетов".to_owned(),
                }
            }
        }
    }

    /// Один проход источника обновления: URL (If-None-Match) или каталог закрытого контура. Сбой —
    /// предупреждение (прежний пакет работает).
    async fn update_once(&self) -> UpdateOutcome {
        let outcome = if let Some(url) = &self.section.update.url {
            self.update_from_url(url).await
        } else if let Some(dir) = &self.section.update.dir {
            self.update_from_dir(dir).await
        } else {
            // Источник не настроен: пакеты ставит администратор (Admin API, `thepost risk verify`).
            return UpdateOutcome::UpToDate;
        };
        if let UpdateOutcome::Rejected { report } = &outcome {
            tracing::warn!(
                report = %report,
                "risk: обновление пакета не удалось — работает прежний (предупреждение в doctor)"
            );
        }
        outcome
    }

    /// Обновление из каталога (`risk.update.dir`): пакет `*.zip` с наибольшим номером в имени,
    /// большим хранимых (`risk-v<номер>.zip` — имя собирает `thepost risk pack`).
    async fn update_from_dir(&self, dir: &Path) -> UpdateOutcome {
        let candidates = match packages_in_dir(dir) {
            Ok(list) => list,
            Err(e) => {
                return UpdateOutcome::Rejected {
                    report: format!("каталог {}: {e}", dir.display()),
                };
            }
        };
        let stored = self
            .store
            .packages()
            .await
            .map(|list| list.iter().map(|p| p.version).max().unwrap_or(0))
            .unwrap_or(0);
        let Some(path) = candidates
            .iter()
            .filter(|p| package_version(p).is_some_and(|v| v > stored))
            .max_by_key(|p| package_version(p).unwrap_or(0))
        else {
            return UpdateOutcome::UpToDate;
        };
        match self.install_file(path).await {
            Ok(outcome) => outcome,
            Err(e) => UpdateOutcome::Rejected {
                report: format!("{}: {e}", path.display()),
            },
        }
    }

    /// Обновление по HTTPS: один запрос за проход, `If-None-Match` по ETag последней выгрузки; ответ —
    /// файл пакета.
    async fn update_from_url(&self, url: &str) -> UpdateOutcome {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build();
        let client = match client {
            Ok(client) => client,
            Err(e) => {
                return UpdateOutcome::Rejected {
                    report: format!("обновление {url}: HTTP-клиент: {e}"),
                };
            }
        };
        let mut request = client.get(url);
        if let Some(etag) = self.etag.lock().expect("lock").as_deref() {
            request = request.header("if-none-match", etag);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(e) => {
                return UpdateOutcome::Rejected {
                    report: format!("обновление {url}: {e}"),
                };
            }
        };
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return UpdateOutcome::UpToDate;
        }
        if !response.status().is_success() {
            return UpdateOutcome::Rejected {
                report: format!("обновление {url}: HTTP {}", response.status()),
            };
        }
        if let Some(etag) = response.headers().get("etag").and_then(|v| v.to_str().ok()) {
            *self.etag.lock().expect("lock") = Some(etag.to_owned());
        }
        let bytes = match response.bytes().await {
            Ok(bytes) => bytes,
            Err(e) => {
                return UpdateOutcome::Rejected {
                    report: format!("обновление {url}: {e}"),
                };
            }
        };
        match self.install_bytes(&bytes).await {
            Ok(outcome) => outcome,
            Err(e) => UpdateOutcome::Rejected {
                report: e.to_string(),
            },
        }
    }

    /// Устанавливает файл пакета (проверка, установка, активация при `auto_activate`).
    async fn install_file(&self, path: &Path) -> Result<UpdateOutcome> {
        let bytes = std::fs::read(path)
            .map_err(|e| Error::internal(format!("risk: файл {}: {e}", path.display())))?;
        self.install_bytes(&bytes).await
    }

    /// Проверяет и устанавливает байты пакета; `auto_activate: false` — пакет поставлен и ждёт
    /// администратора (`POST /api/v1/risk/packages/{version}/activate`).
    async fn install_bytes(&self, bytes: &[u8]) -> Result<UpdateOutcome> {
        let old = self.store.effective(TenantId::DEFAULT).await?;
        let verified = self.verifier.verify(bytes, Some(&old))?;
        let version = verified.manifest.version;
        let stored: BTreeSet<u64> = self
            .store
            .packages()
            .await?
            .into_iter()
            .map(|p| p.version)
            .collect();
        if stored.contains(&version) {
            return Ok(UpdateOutcome::UpToDate);
        }
        self.installer.install(verified).await?;
        let activated = self.section.update.auto_activate;
        if activated {
            self.store.activate(version).await?;
        } else {
            tracing::info!(
                version,
                "risk: пакет поставлен и ждёт активации (risk.update.auto_activate: false)"
            );
        }
        Ok(UpdateOutcome::Installed { version, activated })
    }
}

/// Файлы пакетов каталога (`*.zip`), по имени.
fn packages_in_dir(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| Error::internal(format!("risk: каталог {}: {e}", dir.display())))?;
    for entry in entries {
        let path = entry
            .map_err(|e| Error::internal(format!("risk: каталог {}: {e}", dir.display())))?
            .path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("zip"))
        {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Номер версии из имени файла пакета (`risk-v42.zip`, `risk-42.zip`); нет — `None`.
fn package_version(path: &Path) -> Option<u64> {
    let stem = path.file_stem()?.to_string_lossy();
    stem.rsplit(['-', 'v']).next()?.parse::<u64>().ok()
}

// ---------- Сборка пакета (`thepost risk pack`) ----------

/// Собирает и подписывает пакет из каталога с `manifest.json` (пути списков и образцов —
/// относительные, хэши заполняются по файлам; `sources.json` рядом, DEP-57). Возвращает байты ZIP и
/// подписанный манифест.
pub fn pack(
    manifest_path: &Path,
    key: &ring_sig::Ed25519KeyPair,
) -> Result<(Vec<u8>, PackageManifest)> {
    let dir = manifest_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let raw = std::fs::read(manifest_path)
        .map_err(|e| Error::invalid(format!("risk: manifest.json: {e}")))?;
    let mut manifest: PackageManifest = serde_json::from_slice(&raw)
        .map_err(|e| Error::invalid(format!("risk: manifest.json: {e}")))?;
    manifest.validate()?;
    let read = |path: &str| -> Result<Vec<u8>> {
        std::fs::read(dir.join(path)).map_err(|e| Error::invalid(format!("risk: файл {path}: {e}")))
    };
    for list in &mut manifest.lists {
        let bytes = read(&list.path)?;
        list.sha256 = sha256(&bytes);
        let parsed = parse_list(list.kind, &bytes)?;
        if parsed != list.entries {
            return Err(Error::invalid(format!(
                "risk: список {}: записей {}, в манифесте {}",
                list.path, parsed, list.entries
            )));
        }
    }
    for sample in &mut manifest.samples {
        let bytes = read(&sample.path)?;
        sample.sha256 = sha256(&bytes);
    }
    let sources: Vec<TiSource> = match std::fs::read(dir.join("sources.json")) {
        Ok(raw) => serde_json::from_slice(&raw)
            .map_err(|e| Error::invalid(format!("risk: sources.json: {e}")))?,
        Err(_) if manifest.lists.is_empty() => Vec::new(),
        Err(e) => {
            return Err(Error::invalid(format!(
                "risk: в пакете есть списки, а sources.json не читается: {e}"
            )));
        }
    };
    for source in &sources {
        source
            .validate()
            .map_err(|e| Error::invalid(format!("risk: источник {}: {e}", source.id)))?;
    }
    let mut files = PackageFiles::default();
    for list in &manifest.lists {
        files.0.insert(list.path.clone(), read(&list.path)?);
    }
    for sample in &manifest.samples {
        files.0.insert(sample.path.clone(), read(&sample.path)?);
    }
    let verified = Verified {
        manifest: manifest.clone(),
        signature: Some(key.sign(&canonical_manifest(&manifest)?).as_ref().to_vec()),
        sources,
        files,
        update: UpdateReport::default(),
        samples: u64::try_from(manifest.samples.len()).unwrap_or(u64::MAX),
    };
    let bytes = archive_of(&verified)?;
    Ok((bytes, verified.manifest))
}

// ---------- doctor ----------

/// Каталог с файлами пакетов, если он читается и непуст.
fn packages_in_dir_ok(dir: &Path) -> Option<String> {
    match packages_in_dir(dir) {
        Ok(list) if !list.is_empty() => Some(dir.display().to_string()),
        _ => None,
    }
}

/// Версии и состояния пакетов (`risk_packages`) — системная транзакция, только чтение (транзакция
/// откатывается при drop).
async fn sql_packages(pool: &tp_meta::pool::DbPool) -> Result<Vec<(i64, String)>> {
    let mut tx = tp_meta::schema::begin_system(pool).await?;
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT version, state FROM risk_packages ORDER BY version DESC LIMIT 50")
            .fetch_all(&mut *tx)
            .await
            .map_err(|e| Error::internal(format!("risk_packages: {e}")))?;
    Ok(rows)
}

/// Проверка справочника аномалий (`thepost doctor`, APP-78): ключи подписи, источник обновления,
/// состояние пакетов в БД (первый пакет из поставки не установлен). Сбой обновления — в журнале узла
/// (воркер пишет WARN на каждый неудачный проход, прежний пакет продолжает работать).
pub async fn doctor_risk(
    cfg: &tp_platform::Config,
    pool: Option<&tp_meta::pool::DbPool>,
    report: &mut crate::doctor::Report,
) {
    use crate::doctor::{Status, message};
    let Ok(section) = cfg.section::<RiskSection>(crate::sections::RISK) else {
        return;
    };
    // Ключи подписи: пусто — проверенные пакеты не устанавливаются.
    if section.trusted_keys.is_empty() {
        report.push(
            "risk.trusted_keys",
            Status::Warn,
            "нет",
            "доверенных ключей подписи пакетов нет — установка и обновление пакетов поставщика \
             не работают (risk.trusted_keys)"
                .to_owned(),
        );
    } else {
        let bad: Vec<String> = section
            .trusted_keys
            .iter()
            .filter(|(_, value)| trusted_key(value).is_err())
            .map(|(id, _)| id.clone())
            .collect();
        if bad.is_empty() {
            report.push(
                "risk.trusted_keys",
                Status::Ok,
                section
                    .trusted_keys
                    .keys()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                "ключи подписи читаются".to_owned(),
            );
        } else {
            report.push(
                "risk.trusted_keys",
                Status::Fail,
                bad.join(", "),
                "ключи не разобраны (base64/hex 32 байта или путь к файлу)".to_owned(),
            );
        }
    }
    // Источник обновления.
    if section.update.url.is_none() && section.update.dir.is_none() {
        report.push(
            "risk.update",
            Status::Skipped,
            "",
            "источник обновления не настроен (risk.update.url или risk.update.dir) — пакеты \
             ставит администратор через Admin API"
                .to_owned(),
        );
    }
    // Состояние пакетов: первый пакет из поставки при пустом хранилище.
    let packages = match pool {
        Some(pool) => Some(sql_packages(pool).await),
        None => None,
    };
    match packages {
        None => report.push(
            "risk.packages",
            Status::Skipped,
            "",
            "состояние пакетов — в СУБД, подключение не установлено (см. database.connect)"
                .to_owned(),
        ),
        Some(Err(e)) => report.push("risk.packages", Status::Fail, "", message(&e)),
        Some(Ok(rows)) => match rows.first().map(|(v, state)| (*v, state.as_str())) {
            Some((version, "active")) => report.push(
                "risk.packages",
                Status::Ok,
                format!("активная версия {version}"),
                "пакет поставщика установлен".to_owned(),
            ),
            Some((version, state)) => report.push(
                "risk.packages",
                Status::Warn,
                format!("версия {version} — {state}"),
                "активного пакета нет — активируйте пакет \
                 (POST /api/v1/risk/packages/{version}/activate)"
                    .to_owned(),
            ),
            None => {
                let first = section.package.dir.as_deref().and_then(packages_in_dir_ok);
                report.push(
                    "risk.packages",
                    Status::Warn,
                    "пусто",
                    match first {
                        Some(dir) => format!(
                            "пакетов нет — первый пакет поставки из {dir} поставит роль maintenance \
                             при запуске (письмо каталогом не проверяется)"
                        ),
                        None => "пакетов нет — каталог признаков пуст, письмо не проверяется \
                                 (risk.package.dir, risk.update.dir или Admin API)"
                            .to_owned(),
                    },
                );
            }
        },
    }
}

// ---------- Сборка узла (`services.rs`) и команды ----------

/// Секция `risk` из конфигурации; в config.yaml её нет — умолчания (источника обновления нет, пакеты
/// ставит администратор).
pub fn section_of(cfg: &tp_platform::Config) -> RiskSection {
    cfg.section::<RiskSection>(crate::sections::RISK)
        .map(|s| (*s).clone())
        .unwrap_or_default()
}

/// Версия узла (`min_node` пакета не выше её).
pub fn node_version() -> Semver {
    Semver::from_str(env!("CARGO_PKG_VERSION")).expect("версия узла — semver")
}

/// Отчёт проверки пакета для `thepost risk verify` (тот же, что видит Admin API при загрузке).
pub fn verify_report_text(verified: &Verified) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "✓ пакет версии {}, ключ {}, признаков {}, образцов {}",
        verified.manifest.version,
        verified.manifest.key_id,
        verified.manifest.signals.len(),
        verified.samples
    ));
    let report = &verified.update;
    if !report.added.is_empty() {
        lines.push(format!(
            "  новые признаки (при активации придут «только отчёт»): {}",
            ids(&report.added)
        ));
    }
    if !report.changed.is_empty() {
        lines.push(format!("  изменённые: {}", ids(&report.changed)));
    }
    if !report.removed.is_empty() {
        lines.push(format!("  удалённые: {}", ids(&report.removed)));
    }
    if !report.orphaned_overrides.is_empty() {
        lines.push(format!(
            "  осиротевшие изменения администратора: {}",
            ids(&report.orphaned_overrides)
        ));
    }
    for (path, size) in verified.files.iter() {
        lines.push(format!("  {path}: {size} байт"));
    }
    lines.join("\n")
}

fn ids(list: &[SignalId]) -> String {
    list.iter()
        .map(|id| id.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests;
