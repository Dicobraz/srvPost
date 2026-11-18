//! Брендинг заказчика (решение 122, ADM-48; CONTRACTS.md#Branding, CTR-91): уровни установки и организации —
//! название продукта, основной цвет, роли `design/tokens.toml` и знак PNG.
//!
//! - Уровень установки — `GET|PUT|DELETE /api/v1/branding` (администратор установки), знак —
//!   `PUT|DELETE /api/v1/branding/logo`; уровень организации — те же методы под `/api/v1/orgs/{org}/branding`
//!   (администратор организации и установки; `GET` — и оператор). `PUT` — набор уровня без знака: знак сохраняется,
//!   заданный уровень заменяется целиком; `GET` — свой набор уровня и действующий брендинг
//!   ([`BrandingLevels::effective`]); `DELETE` — сброс уровня. Права и журнал аудита — общий слой доступа
//!   ([`crate::server`]): каждая запись несёт уровень (шаблон маршрута и `{org}`).
//! - Контраст при `PUT` (решение 122, без исключений): организация — [`BrandingLevels::contrast_issues`] поверх
//!   текущего набора установки, установка — [`installation_change_issues`] по действующим палитрам всех
//!   организаций. Не проходит — 422 problem+json с `errors` (роль, пара, тема, контраст, порог; у установки — и
//!   организация). Действующий брендинг отдаётся со страховкой отрисовки [`Branding::safe_palette_over`] —
//!   нечитаемой палитры не бывает и у набора, сохранённого в обход проверки.
//! - Знак — тело `image/png` (иной тип — 415), до 256 КБ (больше — 413) и 1024×1024; PNG проверяется полным
//!   разбором `image` с `Limits` (не PNG, битый файл, превышение размеров — 422). Байты — `BlobStore::put_raw`
//!   по пути [`BrandLogo::path`]; прежний знак после замены или сброса удаляется, если `logo_in_use` — `false`.
//! - Открытый маршрут без входа (экран входа консоли и текстового интерфейса): `GET /api/v1/public/branding` —
//!   название, цвета всех ролей и ссылка на знак по домену имени входа (`TransportStore::cluster`); неизвестный
//!   домен, организация без своего набора и запрос без `domain` — один и тот же ответ (брендинг установки), поэтому
//!   перебор доменов существование организации не раскрывает. `ETag` с `If-None-Match` (304) и
//!   `Cache-Control: public`; знак по хэшу — `immutable`.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, put};
use serde::Deserialize;
use serde::Serialize;
use tp_contracts::blob::BlobStore;
use tp_contracts::branding::{
    self, BrandColor, BrandLogo, Branding, BrandingLevels, BrandingScope, BrandingStore, CliRole,
    ContrastIssue, EffectiveBranding, OrgContrastIssue, Palette, Role, Theme,
    installation_change_issues,
};
use tp_contracts::{BlobHash, Error, TenantId};
use utoipa::{IntoParams, OpenApi, ToSchema};

use crate::extract::{Json, Path, Query};
use crate::server::{Admin, ApiError, ApiResult, Problem, Refused};

/// Маршруты уровня установки (только администратор установки, [`crate::AdminRole::permits`]).
pub const BRANDING_PREFIX: &str = "/api/v1/branding";
/// Знак уровня установки.
pub const LOGO_ROUTE: &str = "/api/v1/branding/logo";
/// Брендинг организации.
pub const ORG_ROUTE: &str = "/api/v1/orgs/{org}/branding";
/// Знак организации.
pub const ORG_LOGO_ROUTE: &str = "/api/v1/orgs/{org}/branding/logo";
/// Открытый маршрут действующего брендинга (без входа).
pub const PUBLIC_ROUTE: &str = "/api/v1/public/branding";
/// Открытый маршрут знака (без входа, по хэшу содержимого).
pub const PUBLIC_LOGO_ROUTE: &str = "/api/v1/public/branding/logo/{hash}";

// Схемы OpenAPI контрактов `tp_contracts::branding` (в `serde` — тот же вид); значений этих типов нет.

/// Фирменный цвет `#RRGGBB` (верхний регистр).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = BrandColor)]
pub struct BrandColorSchema(pub String);

/// Знак заказчика — PNG в BLOB.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = BrandLogo)]
pub struct BrandLogoSchema {
    /// SHA-256 содержимого (hex, 64 символа).
    pub hash: String,
    /// Размер, байт.
    pub size: u64,
    /// Ширина, пикселей.
    pub width: u32,
    /// Высота, пикселей.
    pub height: u32,
}

/// Цвета всех ролей — заданные и выведенные (ключи — имена ролей из `design/tokens.toml`).
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = Palette)]
pub struct PaletteSchema {
    /// Роли светлой темы.
    #[schema(value_type = BTreeMap<String, BrandColorSchema>)]
    pub light: BTreeMap<String, BrandColorSchema>,
    /// Роли тёмной темы.
    #[schema(value_type = BTreeMap<String, BrandColorSchema>)]
    pub dark: BTreeMap<String, BrandColorSchema>,
    /// Подсветка вывода CLI.
    #[schema(value_type = BTreeMap<String, BrandColorSchema>)]
    pub cli: BTreeMap<String, BrandColorSchema>,
}

/// Набор брендинга одного уровня: каждое поле необязательно, незаданное берётся с уровня выше.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = Branding)]
pub struct BrandingSchema {
    /// Название продукта; `null` — встроенное.
    pub product_name: Option<String>,
    /// Основной цвет — источник незаданных ролей бренда этого уровня; `null` — не задан.
    pub primary: Option<BrandColorSchema>,
    /// Заданные роли светлой темы.
    #[schema(value_type = BTreeMap<String, BrandColorSchema>)]
    pub light: BTreeMap<String, BrandColorSchema>,
    /// Заданные роли тёмной темы.
    #[schema(value_type = BTreeMap<String, BrandColorSchema>)]
    pub dark: BTreeMap<String, BrandColorSchema>,
    /// Заданные роли CLI.
    #[schema(value_type = BTreeMap<String, BrandColorSchema>)]
    pub cli: BTreeMap<String, BrandColorSchema>,
    /// Знак; `null` — встроенный.
    pub logo: Option<BrandLogoSchema>,
}

/// Действующий брендинг ([`BrandingLevels::effective`]): название и знак с ближайшего уровня, все цвета ролей.
#[allow(dead_code)]
#[derive(Debug, Serialize, ToSchema)]
#[schema(as = EffectiveBranding)]
pub struct EffectiveBrandingSchema {
    /// Название продукта; `null` — встроенное.
    pub product_name: Option<String>,
    /// Знак; `null` — встроенный знак IT TASK.
    pub logo: Option<BrandLogoSchema>,
    /// Все цвета ролей.
    pub palette: PaletteSchema,
}

/// Замена набора уровня: все поля необязательны, уровень заменяется целиком; знак меняет `PUT …/branding/logo`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BrandingBody {
    /// Название продукта (1–64 символа без управляющих); `null` — не задано.
    #[serde(default)]
    pub product_name: Option<String>,
    /// Основной цвет `#RRGGBB`; из него выводятся незаданные роли бренда уровня.
    #[serde(default)]
    #[schema(value_type = Option<BrandColorSchema>)]
    pub primary: Option<BrandColor>,
    /// Роли светлой темы (`design/tokens.toml`: screen, panel, text, muted, frame, frameA, titleA, head, sel,
    /// selFg, selI, selIFg, fkBg, fkFg, ok, warn, err).
    #[serde(default)]
    #[schema(value_type = BTreeMap<String, BrandColorSchema>)]
    pub light: BTreeMap<Role, BrandColor>,
    /// Роли тёмной темы.
    #[serde(default)]
    #[schema(value_type = BTreeMap<String, BrandColorSchema>)]
    pub dark: BTreeMap<Role, BrandColor>,
    /// Роли подсветки CLI (head, accent, ok, warn, err, muted, json_key, json_number, json_bool).
    #[serde(default)]
    #[schema(value_type = BTreeMap<String, BrandColorSchema>)]
    pub cli: BTreeMap<CliRole, BrandColor>,
}

/// Свои значения уровня и действующий брендинг.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct BrandingView {
    /// Свой набор уровня; `null` — уровень не задан (всё с уровня выше).
    #[schema(value_type = Option<BrandingSchema>)]
    pub own: Option<Branding>,
    /// Действующий брендинг для отрисовки.
    #[schema(value_type = EffectiveBrandingSchema)]
    pub effective: EffectiveBranding,
}

/// Пара ниже порога контраста (поле `field` — слот палитры: `light.sel`, `cli.head`).
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct BrandingIssue {
    /// Слот палитры: `<тема>.<роль>` или `cli.<роль>`.
    pub field: String,
    /// Тема (`light`, `dark`); `null` — роли CLI.
    #[schema(value_type = Option<String>)]
    pub theme: Option<Theme>,
    /// Роль переднего плана (имя из `design/tokens.toml`).
    pub role: String,
    /// Фон: роль (`panel`) или цвет фона терминала (`#0C0C0C`).
    pub bg: String,
    /// Контраст пары.
    pub contrast: f64,
    /// Нужный контраст (текст — 4,5; рамки, заливки и CLI — 3).
    pub min: f64,
}

impl From<&ContrastIssue> for BrandingIssue {
    fn from(i: &ContrastIssue) -> Self {
        Self {
            field: issue_field(i),
            theme: i.theme,
            role: i.fg.to_owned(),
            bg: i.bg.clone(),
            contrast: i.contrast,
            min: i.min,
        }
    }
}

/// Отказ сохранения набора организации: пары ниже порога (RFC 9457 с расширением `errors`).
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct BrandingProblem {
    /// Код HTTP (422).
    pub status: u16,
    /// Краткое описание кода.
    pub title: String,
    /// Пары по-русски, через «; ».
    pub detail: String,
    /// Пары ниже порога.
    pub errors: Vec<BrandingIssue>,
}

/// Пара ниже порога при смене набора установки; `org` — организация, чья палитра ломается (`null` — сам набор).
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct OrgBrandingIssue {
    /// Организация (UUID); `null` — сам набор установки.
    pub org: Option<String>,
    /// Слот палитры: `<тема>.<роль>` или `cli.<роль>`.
    pub field: String,
    /// Тема (`light`, `dark`); `null` — роли CLI.
    #[schema(value_type = Option<String>)]
    pub theme: Option<Theme>,
    /// Роль переднего плана.
    pub role: String,
    /// Фон: роль или цвет фона терминала.
    pub bg: String,
    /// Контраст пары.
    pub contrast: f64,
    /// Нужный контраст.
    pub min: f64,
}

/// Отказ смены набора установки: пары ниже порога у самого набора или у действующей палитры организации.
#[derive(Debug, Clone, PartialEq, Serialize, ToSchema)]
pub struct InstallationBrandingProblem {
    /// Код HTTP (422).
    pub status: u16,
    /// Краткое описание кода.
    pub title: String,
    /// Пары с организациями по-русски, через «; ».
    pub detail: String,
    /// Пары ниже порога.
    pub errors: Vec<OrgBrandingIssue>,
}

/// Действующий брендинг для экрана входа: название, цвета всех ролей и ссылка на знак — без организации.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct PublicBranding {
    /// Название продукта; `null` — встроенное.
    pub product_name: Option<String>,
    /// Цвета всех ролей обеих тем и CLI.
    #[schema(value_type = PaletteSchema)]
    pub palette: Palette,
    /// Ссылка на знак (`/api/v1/public/branding/logo/<hash>`); `null` — встроенный знак IT TASK.
    pub logo: Option<String>,
}

/// Домен имени входа (принятый домен организации); нет — брендинг установки.
#[derive(Debug, Clone, Default, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PublicBrandingParams {
    /// Почтовый домен из имени входа (домены публичны через MX); неизвестный — как без домена.
    pub domain: Option<String>,
}

/// Хранилища брендинга ([`Admin::with_branding`]): наборы уровней и байты знаков.
#[derive(Clone)]
pub struct BrandingStores {
    /// Наборы уровней установки и организаций (`BrandingStore`).
    pub store: Arc<dyn BrandingStore>,
    /// Байты знаков (`put_raw`/`get_raw`/`delete_raw` по [`BrandLogo::path`]).
    pub blobs: Arc<dyn BlobStore>,
}

impl fmt::Debug for BrandingStores {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrandingStores").finish_non_exhaustive()
    }
}

/// Маршруты брендинга за слоем доступа.
pub(crate) fn routes(r: Router<Arc<Admin>>) -> Router<Arc<Admin>> {
    r.route(
        BRANDING_PREFIX,
        get(get_installation)
            .put(put_installation)
            .delete(reset_installation),
    )
    .route(
        LOGO_ROUTE,
        put(put_installation_logo).delete(reset_installation_logo),
    )
    .route(
        ORG_ROUTE,
        get(get_org_branding)
            .put(put_org_branding)
            .delete(reset_org_branding),
    )
    .route(
        ORG_LOGO_ROUTE,
        put(put_org_branding_logo).delete(reset_org_branding_logo),
    )
}

/// Открытые маршруты без входа (как `POST /api/v1/session`): вне слоя доступа.
pub(crate) fn public_routes(r: Router<Arc<Admin>>) -> Router<Arc<Admin>> {
    r.route(PUBLIC_ROUTE, get(public_branding))
        .route(PUBLIC_LOGO_ROUTE, get(public_branding_logo))
}

/// Спецификация OpenAPI маршрутов модуля.
#[derive(Debug, OpenApi)]
#[openapi(
    paths(
        get_installation,
        put_installation,
        reset_installation,
        put_installation_logo,
        reset_installation_logo,
        get_org_branding,
        put_org_branding,
        reset_org_branding,
        put_org_branding_logo,
        reset_org_branding_logo,
        public_branding,
        public_branding_logo
    ),
    components(schemas(
        BrandColorSchema,
        BrandLogoSchema,
        PaletteSchema,
        BrandingSchema,
        EffectiveBrandingSchema,
        BrandingBody,
        BrandingView,
        BrandingIssue,
        BrandingProblem,
        OrgBrandingIssue,
        InstallationBrandingProblem,
        PublicBranding
    ))
)]
pub(crate) struct Doc;

/// Отказ с готовым ответом (422 контраста, 413/415/422 знака) — в боксе, чтобы `Err` оставался компактным
/// ([clippy::result_large_err]); сам ответ отдаёт [`IntoResponse`].
#[derive(Debug)]
pub(crate) struct RefusedResponse(Box<Response>);

impl From<Response> for RefusedResponse {
    fn from(r: Response) -> Self {
        Self(Box::new(r))
    }
}

impl IntoResponse for RefusedResponse {
    fn into_response(self) -> Response {
        *self.0
    }
}

/// Хранилище брендинга; не подключено — 503.
fn stores(a: &Admin) -> std::result::Result<&BrandingStores, Error> {
    a.branding.as_ref().ok_or(Error::UNAVAILABLE)
}

/// Набор уровней и ответ `GET`: свой набор уровня и действующий брендинг.
async fn view(a: &Admin, tenant: Option<TenantId>) -> std::result::Result<BrandingView, Error> {
    let s = stores(a)?;
    let levels = s.store.branding_levels(tenant).await?;
    let effective = levels.effective();
    Ok(BrandingView {
        own: levels.org,
        effective,
    })
}

/// Набор из тела со знаком прежнего набора уровня (`PUT` знак не меняет) и проверкой полей (`validate` — 400).
async fn branding_of_put(
    a: &Admin,
    scope: BrandingScope,
    body: BrandingBody,
) -> std::result::Result<Branding, Error> {
    let s = stores(a)?;
    let old = s.store.branding(scope).await?;
    let branding = Branding {
        product_name: body.product_name,
        primary: body.primary,
        light: body.light,
        dark: body.dark,
        cli: body.cli,
        logo: old.as_ref().and_then(|o| o.logo),
    };
    branding.validate()?;
    Ok(branding)
}

/// Русские подписи ролей для пояснения 422.
fn role_label(role: &str) -> &'static str {
    match role {
        "screen" => "фон экрана",
        "panel" => "панель",
        "text" => "текст",
        "muted" => "вторичный текст",
        "frame" => "рамка",
        "frameA" => "рамка активной панели",
        "titleA" => "заголовок-акцент",
        "head" => "заголовки",
        "sel" => "выделение",
        "selFg" => "текст выделения",
        "selI" => "выделение неактивной панели",
        "selIFg" => "текст выделения неактивной панели",
        "fkBg" => "фон F-клавиш",
        "fkFg" => "текст F-клавиш",
        "ok" => "норма",
        "warn" => "внимание",
        "err" => "ошибка",
        "accent" => "акцент",
        "json_key" => "ключ JSON",
        "json_number" => "число JSON",
        "json_bool" => "логическое значение JSON",
        _ => "роль",
    }
}

/// Контраст по-русски: целое — `3`, дробное — `1,3`.
fn contrast_ru(v: f64) -> String {
    let one = format!("{v:.1}");
    one.strip_suffix(".0").unwrap_or(&one).replace('.', ",")
}

/// Пара по-русски: «светлая тема: выделение sel #F5E663 на панели panel #FFFFFF — 1,3:1, нужно 3:1».
fn issue_ru(issue: &ContrastIssue) -> String {
    let theme = match issue.theme {
        Some(Theme::Light) => "светлая тема",
        Some(Theme::Dark) => "тёмная тема",
        None => "подсветка CLI",
    };
    let bg = match issue.theme {
        Some(_) => format!("{} {}", role_label(&issue.bg), issue.bg),
        None => format!("фон терминала {}", issue.bg_color),
    };
    format!(
        "{theme}: {} {} {} на {} — {} : 1, нужно {} : 1",
        role_label(issue.fg),
        issue.fg,
        issue.fg_color,
        bg,
        contrast_ru(issue.contrast),
        contrast_ru(issue.min),
    )
}

/// Слот палитры пары: `light.sel`, `cli.head`.
fn issue_field(issue: &ContrastIssue) -> String {
    let theme = issue
        .theme
        .map_or_else(|| "cli".to_owned(), |t| t.as_str().to_owned());
    format!("{theme}.{}", issue.fg)
}

/// Ответ 422 problem+json (RFC 9457) с произвольным телом.
fn problem_body<T: Serialize>(status: StatusCode, body: &T) -> Response {
    let mut resp = (status, axum::Json(body)).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    resp
}

/// Ответ 422 problem+json с пояснением и кодом, которых нет у `tp_contracts::Error` (413/415/422 знака).
fn problem_detail(status: StatusCode, detail: &str) -> Response {
    problem_body(
        status,
        &Problem {
            status: status.as_u16(),
            title: status.canonical_reason().unwrap_or_default().to_owned(),
            detail: Some(detail.to_owned()),
        },
    )
}

/// Брендинг установки: свой набор и действующий. Уровень установки читает только администратор установки.
#[utoipa::path(get, path = "/api/v1/branding", tag = "branding",
    responses((status = 200, body = BrandingView), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 503, body = Problem)))]
async fn get_installation(
    State(a): State<Arc<Admin>>,
) -> std::result::Result<Json<BrandingView>, Refused> {
    Ok(Json(view(&a, None).await?))
}

/// Заменяет набор установки (без знака — знак сохраняется). Неверное название или цвет — 400; пары контраста
/// самого набора или действующей палитры хотя бы одной организации ниже порога — 422 problem+json с `errors`
/// (`org` = `null` — сам набор установки); хранилище не подключено — 503.
#[utoipa::path(put, path = "/api/v1/branding", tag = "branding",
    request_body = BrandingBody,
    responses((status = 200, body = BrandingView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem),
        (status = 422, description = "контраст ниже порога (сам набор или организация)", body = InstallationBrandingProblem),
        (status = 503, body = Problem)))]
async fn put_installation(
    State(a): State<Arc<Admin>>,
    Json(body): Json<BrandingBody>,
) -> std::result::Result<Json<BrandingView>, RefusedResponse> {
    let err = |e: Error| RefusedResponse::from(ApiError(e).into_response());
    let s = match stores(&a) {
        Ok(s) => s,
        Err(e) => return Err(err(e)),
    };
    let new = match branding_of_put(&a, BrandingScope::Installation, body).await {
        Ok(n) => n,
        Err(e) => return Err(err(e)),
    };
    let orgs = match s.store.org_brandings().await {
        Ok(o) => o,
        Err(e) => return Err(err(e)),
    };
    let issues = installation_change_issues(Some(&new), &orgs);
    if !issues.is_empty() {
        return Err(installation_refused(issues).into());
    }
    if let Err(e) = s
        .store
        .set_branding(BrandingScope::Installation, &new)
        .await
    {
        return Err(err(e));
    }
    match view(&a, None).await {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(err(e)),
    }
}

/// Сбрасывает набор установки (организации остаются со своими наборами). Не был задан — 404. Прежний знак
/// удаляется из BLOB, если он больше не нужен ни одному уровню.
#[utoipa::path(delete, path = "/api/v1/branding", tag = "branding",
    responses((status = 200, body = BrandingView), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn reset_installation(
    State(a): State<Arc<Admin>>,
) -> std::result::Result<Json<BrandingView>, Refused> {
    let old = stores(&a)?
        .store
        .reset_branding(BrandingScope::Installation)
        .await?;
    let Some(old) = old else {
        return Err(Error::NotFound.into());
    };
    delete_unused_logo(&a, &old).await?;
    Ok(Json(view(&a, None).await?))
}

/// Знак уровня установки: тело — файл PNG (`image/png`; иной тип — 415), до 256 КБ (413) и 1024×1024 (422);
/// не PNG или битый файл — 422. Знак ставится и без названия и цветов уровня. Прежний знак удаляется, если он
/// больше не нужен ни одному уровню.
#[utoipa::path(put, path = "/api/v1/branding/logo", tag = "branding",
    request_body(content = String, content_type = "image/png",
        description = "Файл PNG: до 256 КБ, до 1024×1024 пикселей"),
    responses((status = 200, body = BrandingView), (status = 400, body = Problem), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem),
        (status = 413, description = "больше 256 КБ", body = Problem),
        (status = 415, description = "не image/png", body = Problem),
        (status = 422, description = "не PNG, битый файл или больше 1024×1024", body = Problem),
        (status = 503, body = Problem)))]
async fn put_installation_logo(
    State(a): State<Arc<Admin>>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Json<BrandingView>, RefusedResponse> {
    put_logo(&a, BrandingScope::Installation, &headers, &body).await
}

/// Убирает знак уровня установки (название и цвета остаются); набор не задан или знака нет — 404.
#[utoipa::path(delete, path = "/api/v1/branding/logo", tag = "branding",
    responses((status = 200, body = BrandingView), (status = 401, body = Problem),
        (status = 403, description = "не администратор установки", body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn reset_installation_logo(
    State(a): State<Arc<Admin>>,
) -> std::result::Result<Json<BrandingView>, Refused> {
    let s = stores(&a)?;
    let old = s.store.branding(BrandingScope::Installation).await?;
    let Some(old) = old.filter(|o| o.logo.is_some()) else {
        return Err(Error::NotFound.into());
    };
    let without = Branding {
        logo: None,
        ..old.clone()
    };
    s.store
        .set_branding(BrandingScope::Installation, &without)
        .await?;
    delete_unused_logo(&a, &old).await?;
    Ok(Json(view(&a, None).await?))
}

/// Брендинг организации: свой набор и действующий (организация поверх установки).
#[utoipa::path(get, path = "/api/v1/orgs/{org}/branding", tag = "branding",
    params(("org" = String, Path, description = "Организация (UUID)")),
    responses((status = 200, body = BrandingView), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn get_org_branding(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
) -> ApiResult<Json<BrandingView>> {
    Ok(Json(view(&a, Some(org)).await?))
}

/// Заменяет набор организации (без знака — знак сохраняется). Контраст проверяется по действующему набору
/// организации поверх текущего набора установки: пары ниже порога — 422 problem+json с `errors`; неверное
/// название или цвет — 400; чужая организация — 404.
#[utoipa::path(put, path = "/api/v1/orgs/{org}/branding", tag = "branding",
    params(("org" = String, Path, description = "Организация (UUID)")),
    request_body = BrandingBody,
    responses((status = 200, body = BrandingView), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, body = Problem),
        (status = 422, description = "контраст ниже порога", body = BrandingProblem),
        (status = 503, body = Problem)))]
async fn put_org_branding(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
    Json(body): Json<BrandingBody>,
) -> std::result::Result<Json<BrandingView>, RefusedResponse> {
    let err = |e: Error| RefusedResponse::from(ApiError(e).into_response());
    let s = match stores(&a) {
        Ok(s) => s,
        Err(e) => return Err(err(e)),
    };
    let new = match branding_of_put(&a, BrandingScope::Org(org), body).await {
        Ok(n) => n,
        Err(e) => return Err(err(e)),
    };
    let levels = match s.store.branding_levels(Some(org)).await {
        Ok(l) => l,
        Err(e) => return Err(err(e)),
    };
    let issues = BrandingLevels {
        installation: levels.installation,
        org: Some(new.clone()),
    }
    .contrast_issues();
    if !issues.is_empty() {
        let detail = issues.iter().map(issue_ru).collect::<Vec<_>>().join("; ");
        return Err(problem_body(
            StatusCode::UNPROCESSABLE_ENTITY,
            &BrandingProblem {
                status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
                title: StatusCode::UNPROCESSABLE_ENTITY
                    .canonical_reason()
                    .unwrap_or_default()
                    .to_owned(),
                detail: format!("контраст ниже порога: {detail}"),
                errors: issues.iter().map(&BrandingIssue::from).collect(),
            },
        )
        .into());
    }
    if let Err(e) = s.store.set_branding(BrandingScope::Org(org), &new).await {
        return Err(err(e));
    }
    match view(&a, Some(org)).await {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(err(e)),
    }
}

/// Сбрасывает набор организации — действует брендинг установки. Не был задан — 404. Прежний знак удаляется из
/// BLOB, если он больше не нужен ни одному уровню.
#[utoipa::path(delete, path = "/api/v1/orgs/{org}/branding", tag = "branding",
    params(("org" = String, Path, description = "Организация (UUID)")),
    responses((status = 200, body = BrandingView), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn reset_org_branding(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
) -> std::result::Result<Json<BrandingView>, Refused> {
    let old = stores(&a)?
        .store
        .reset_branding(BrandingScope::Org(org))
        .await?;
    let Some(old) = old else {
        return Err(Error::NotFound.into());
    };
    delete_unused_logo(&a, &old).await?;
    Ok(Json(view(&a, Some(org)).await?))
}

/// Знак организации: правила те же, что у знака установки (PNG до 256 КБ и 1024×1024, полный разбор `image`
/// с `Limits`). Знак ставится и без названия и цветов уровня.
#[utoipa::path(put, path = "/api/v1/orgs/{org}/branding/logo", tag = "branding",
    params(("org" = String, Path, description = "Организация (UUID)")),
    request_body(content = String, content_type = "image/png",
        description = "Файл PNG: до 256 КБ, до 1024×1024 пикселей"),
    responses((status = 200, body = BrandingView), (status = 400, body = Problem), (status = 403, body = Problem),
        (status = 404, body = Problem),
        (status = 413, description = "больше 256 КБ", body = Problem),
        (status = 415, description = "не image/png", body = Problem),
        (status = 422, description = "не PNG, битый файл или больше 1024×1024", body = Problem),
        (status = 503, body = Problem)))]
async fn put_org_branding_logo(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
    headers: HeaderMap,
    body: Bytes,
) -> std::result::Result<Json<BrandingView>, RefusedResponse> {
    put_logo(&a, BrandingScope::Org(org), &headers, &body).await
}

/// Убирает знак организации (название и цвета остаются); набор не задан или знака нет — 404.
#[utoipa::path(delete, path = "/api/v1/orgs/{org}/branding/logo", tag = "branding",
    params(("org" = String, Path, description = "Организация (UUID)")),
    responses((status = 200, body = BrandingView), (status = 403, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn reset_org_branding_logo(
    State(a): State<Arc<Admin>>,
    Path(org): Path<TenantId>,
) -> std::result::Result<Json<BrandingView>, Refused> {
    let s = stores(&a)?;
    let old = s.store.branding(BrandingScope::Org(org)).await?;
    let Some(old) = old.filter(|o| o.logo.is_some()) else {
        return Err(Error::NotFound.into());
    };
    let without = Branding {
        logo: None,
        ..old.clone()
    };
    s.store
        .set_branding(BrandingScope::Org(org), &without)
        .await?;
    delete_unused_logo(&a, &old).await?;
    Ok(Json(view(&a, Some(org)).await?))
}

/// Знак по телу запроса: тип — 415, размер — 413, полный разбор PNG с пределами — 422; байты — в BLOB. Прежний
/// знак удаляется, если не нужен ни одному уровню.
async fn put_logo(
    a: &Admin,
    scope: BrandingScope,
    headers: &HeaderMap,
    body: &[u8],
) -> std::result::Result<Json<BrandingView>, RefusedResponse> {
    let err = |e: Error| RefusedResponse::from(ApiError(e).into_response());
    let s = match stores(a) {
        Ok(s) => s,
        Err(e) => return Err(err(e)),
    };
    // Тип — до разбора: иной тип — 415 problem+json.
    let ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if ct != "image/png" {
        return Err(problem_detail(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            &format!("знак — PNG (image/png), получен {ct:?}"),
        )
        .into());
    }
    if body.len() as u64 > branding::MAX_LOGO_SIZE {
        return Err(problem_detail(
            StatusCode::PAYLOAD_TOO_LARGE,
            &format!(
                "знак — не больше {} КБ, получено {} КБ",
                branding::MAX_LOGO_SIZE / 1024,
                body.len().div_ceil(1024)
            ),
        )
        .into());
    }
    let logo = match decode_png(body) {
        Ok(logo) => logo,
        Err(detail) => {
            return Err(problem_detail(
                StatusCode::UNPROCESSABLE_ENTITY,
                &format!("знак не принят: {detail}"),
            )
            .into());
        }
    };
    let old = match s.store.branding(scope).await {
        Ok(o) => o,
        Err(e) => return Err(err(e)),
    };
    let path = logo.path();
    let mut branding = old.clone().unwrap_or_default();
    branding.logo = Some(logo);
    if let Err(e) = branding.validate() {
        return Err(err(e));
    }
    if let Err(e) = s.blobs.put_raw(&path, Bytes::copy_from_slice(body)).await {
        return Err(err(e));
    }
    if let Err(e) = s.store.set_branding(scope, &branding).await {
        return Err(err(e));
    }
    if let Some(old) = old
        && let Err(e) = delete_unused_logo(a, &old).await
    {
        return Err(err(e));
    }
    let tenant = match scope {
        BrandingScope::Installation => None,
        BrandingScope::Org(t) => Some(t),
    };
    match view(a, tenant).await {
        Ok(v) => Ok(Json(v)),
        Err(e) => Err(err(e)),
    }
}

/// Разбор PNG с пределами ([`branding::MAX_LOGO_SIDE`]): не PNG, битый файл или превышение размеров — пояснение
/// по-русски. Полный разбор — декодер с `Limits` (пределы ширины, высоты и памяти).
fn decode_png(bytes: &[u8]) -> std::result::Result<BrandLogo, String> {
    use image::{ImageFormat, ImageReader, Limits};

    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| format!("файл не читается: {e}"))?;
    if reader.format() != Some(ImageFormat::Png) {
        return Err("файл — не PNG".to_owned());
    }
    let mut limits = Limits::default();
    limits.max_image_width = Some(branding::MAX_LOGO_SIDE);
    limits.max_image_height = Some(branding::MAX_LOGO_SIDE);
    limits.max_alloc = Some(64 * 1024 * 1024);
    reader.limits(limits);
    let decoded = reader
        .decode()
        .map_err(|e| format!("PNG не разобран: {e}"))?;
    let (width, height) = (decoded.width(), decoded.height());
    Ok(BrandLogo {
        hash: tp_mailstore::split::hash(bytes),
        size: bytes.len() as u64,
        width,
        height,
    })
}

/// Удаляет знак набора из BLOB, если `logo_in_use` — `false` (знак другого уровня остаётся).
async fn delete_unused_logo(a: &Admin, branding: &Branding) -> Result<(), Error> {
    let s = a.branding.as_ref().ok_or(Error::UNAVAILABLE)?;
    if let Some(logo) = branding.logo
        && !s.store.logo_in_use(&logo.hash).await?
    {
        s.blobs.delete_raw(&logo.path()).await?;
    }
    Ok(())
}

/// Ответ 422 при смене набора установки: пары самого набора и организаций.
fn installation_refused(issues: Vec<OrgContrastIssue>) -> Response {
    let status = StatusCode::UNPROCESSABLE_ENTITY;
    let whose = |org: Option<TenantId>| {
        org.map_or_else(
            || "набор установки".to_owned(),
            |t| format!("организация {t}"),
        )
    };
    let detail = issues
        .iter()
        .map(|i| format!("{}: {}", whose(i.org), issue_ru(&i.issue)))
        .collect::<Vec<_>>()
        .join("; ");
    problem_body(
        status,
        &InstallationBrandingProblem {
            status: status.as_u16(),
            title: status.canonical_reason().unwrap_or_default().to_owned(),
            detail: format!("контраст ниже порога: {detail}"),
            errors: issues
                .iter()
                .map(|i| OrgBrandingIssue {
                    org: i.org.map(|t| t.to_string()),
                    field: issue_field(&i.issue),
                    theme: i.issue.theme,
                    role: i.issue.fg.to_owned(),
                    bg: i.issue.bg.clone(),
                    contrast: i.issue.contrast,
                    min: i.issue.min,
                })
                .collect(),
        },
    )
}

/// Действующий брендинг для экрана входа — без входа: только название, цвета всех ролей и ссылка на знак.
/// Домен имени входа даёт организацию (`TransportStore::cluster`); неизвестный домен, организация без своего
/// набора и запрос без `domain` — один и тот же ответ (брендинг установки). `ETag` (304 по `If-None-Match`),
/// `Cache-Control: public, max-age=300`.
#[utoipa::path(get, path = "/api/v1/public/branding", tag = "branding", security(()),
    params(PublicBrandingParams),
    responses((status = 200, body = PublicBranding), (status = 304, description = "не изменился"),
        (status = 503, body = Problem)))]
async fn public_branding(
    State(a): State<Arc<Admin>>,
    Query(params): Query<PublicBrandingParams>,
    headers: HeaderMap,
) -> Response {
    let err = |e: Error| ApiError(e).into_response();
    let s = match stores(&a) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    // Организация по принятому домену; ошибка нормализации и неизвестный домен — как без домена: один ответ.
    let tenant = match params.domain.as_deref() {
        None => None,
        Some(d) => {
            let t = match a.transport.as_deref() {
                Some(t) => t,
                None => return err(Error::UNAVAILABLE),
            };
            match t.cluster().await {
                Ok(c) => normalize_domain_quietly(d).and_then(|d| c.domain(&d).map(|x| x.tenant)),
                Err(e) => return err(e),
            }
        }
    };
    let levels = match s.store.branding_levels(tenant).await {
        Ok(l) => l,
        Err(e) => return err(e),
    };
    let effective = levels.effective();
    let body = PublicBranding {
        product_name: effective.product_name.clone(),
        palette: effective.palette,
        logo: effective
            .logo
            .map(|l| PUBLIC_LOGO_ROUTE.replace("{hash}", &l.hash.to_string())),
    };
    let bytes = match serde_json::to_vec(&body) {
        Ok(b) => b,
        Err(e) => return err(Error::internal(format!("брендинг: {e}"))),
    };
    let etag = format!("\"{}\"", tp_mailstore::split::hash(&bytes));
    if matches_etag(&headers, &etag) {
        return cached(StatusCode::NOT_MODIFIED, &etag, "public, max-age=300");
    }
    build_response(
        StatusCode::OK,
        &etag,
        "public, max-age=300",
        "application/json",
        Body::from(bytes),
    )
}

/// Домен в канонической форме; ошибка (не домен) — `None`: ответ тот же, что без домена.
fn normalize_domain_quietly(d: &str) -> Option<String> {
    tp_contracts::transport::normalize_domain(d).ok()
}

/// Знак по хэшу содержимого (путь неизменяем): PNG из BLOB; нет — 404. `ETag` — хэш, `Cache-Control: public,
/// max-age=31536000, immutable`.
#[utoipa::path(get, path = "/api/v1/public/branding/logo/{hash}", tag = "branding", security(()),
    params(("hash" = String, Path, description = "SHA-256 знака (hex; ссылка из действующего брендинга)")),
    responses((status = 200, description = "файл PNG", content_type = "image/png"),
        (status = 304, description = "не изменился"), (status = 400, body = Problem), (status = 404, body = Problem),
        (status = 503, body = Problem)))]
async fn public_branding_logo(
    State(a): State<Arc<Admin>>,
    Path(hash): Path<String>,
    headers: HeaderMap,
) -> Response {
    let err = |e: Error| ApiError(e).into_response();
    let s = match stores(&a) {
        Ok(s) => s,
        Err(e) => return err(e),
    };
    let hash = match BlobHash::from_str(&hash) {
        Ok(h) => h,
        Err(_) => {
            return problem_detail(
                StatusCode::BAD_REQUEST,
                "хэш знака — 64 символа hex (ссылка из действующего брендинга)",
            );
        }
    };
    let etag = format!("\"{hash}\"");
    if matches_etag(&headers, &etag) {
        return cached(
            StatusCode::NOT_MODIFIED,
            &etag,
            "public, max-age=31536000, immutable",
        );
    }
    let path = BrandLogo {
        hash,
        size: 0,
        width: 0,
        height: 0,
    }
    .path();
    let stream = match s.blobs.get_raw(&path, None).await {
        Ok(st) => st,
        Err(e) => return err(e),
    };
    build_response(
        StatusCode::OK,
        &etag,
        "public, max-age=31536000, immutable",
        "image/png",
        Body::from_stream(stream),
    )
}

/// `If-None-Match` совпадает с `etag` (список тегов, префикс `W/`, `*`).
fn matches_etag(headers: &HeaderMap, etag: &str) -> bool {
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v == "*"
                || v.split(',').any(|t| {
                    let t = t.trim();
                    t.strip_prefix("W/").unwrap_or(t) == etag
                })
        })
}

/// Ответ 304 с теми же условиями кэширования (RFC 9110 §15.4.5).
fn cached(status: StatusCode, etag: &str, cache: &'static str) -> Response {
    build_response(status, etag, cache, "", Body::empty())
}

/// Ответ с заголовками кэширования; ошибка построения — 500 problem+json.
fn build_response(
    status: StatusCode,
    etag: &str,
    cache: &'static str,
    content_type: &str,
    body: Body,
) -> Response {
    let mut builder = Response::builder()
        .status(status)
        .header(header::ETAG, etag)
        .header(header::CACHE_CONTROL, cache);
    if !content_type.is_empty() {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    builder.body(body).unwrap_or_else(|e| {
        ApiError(Error::internal(format!("ответ брендинга: {e}"))).into_response()
    })
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use axum::body::Body;
    use axum::body::to_bytes;
    use axum::http::{HeaderMap, Request, StatusCode, header};
    use serde_json::{Value, json};
    use tower::ServiceExt;
    use tp_contracts::TenantId;
    use tp_contracts::branding::{ContrastIssue, Palette};
    use tp_contracts::transport::{AcceptedDomain, DomainKind, TransportStore as _};

    use super::*;
    use crate::testenv::Env;

    /// PNG `w×h` для запросов знака.
    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = image::RgbaImage::from_pixel(w, h, image::Rgba([23, 124, 170, 255]));
        let mut buf = Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut buf, image::ImageFormat::Png)
            .expect("png");
        buf.into_inner()
    }

    /// Запрос с произвольным телом и типом: код, заголовки, байты.
    async fn call_raw(
        env: &Env,
        method: &str,
        path: &str,
        token: Option<&str>,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(t) = token {
            req = req.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        if let Some(ct) = content_type {
            req = req.header(header::CONTENT_TYPE, ct);
        }
        let resp = env
            .router
            .clone()
            .oneshot(req.body(Body::from(body)).expect("request"))
            .await
            .expect("response");
        let (parts, body) = resp.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.expect("body").to_vec();
        (parts.status, parts.headers, bytes)
    }

    /// Запрос знака (тело — байты, тип `ct`): код, заголовки, тело JSON.
    async fn put_logo_call(
        env: &Env,
        path: &str,
        token: &str,
        ct: &str,
        body: Vec<u8>,
    ) -> (StatusCode, HeaderMap, Value) {
        let (s, h, b) = call_raw(env, "PUT", path, Some(token), Some(ct), body).await;
        let v = serde_json::from_slice(&b).unwrap_or(Value::Null);
        (s, h, v)
    }

    fn org_path(org: TenantId) -> String {
        format!("/api/v1/orgs/{org}/branding")
    }

    fn logo_path(hash: &str) -> String {
        PUBLIC_LOGO_ROUTE.replace("{hash}", hash)
    }

    /// Принятый домен `name` организации по умолчанию.
    async fn accept_domain(env: &Env, name: &str) {
        let c = env.transport.cluster().await.expect("cluster");
        let d = AcceptedDomain {
            id: tp_contracts::DomainId::new(),
            tenant: TenantId::DEFAULT,
            name: name.into(),
            kind: DomainKind::Authoritative,
        };
        env.transport
            .put_domain(c.version, &d)
            .await
            .expect("domain");
    }

    /// Приёмка ADM-48: без наборов — палитра IT TASK; набор только с основным проходит; `light.sel` ниже порога —
    /// 422 с `errors`; неверный цвет и неизвестная роль — 400.
    #[tokio::test]
    async fn contrast_on_put() {
        let env = Env::new();
        let (s, _, b) = env.call("GET", BRANDING_PREFIX, Some("root"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["own"], Value::Null);
        assert_eq!(b["effective"]["product_name"], Value::Null);
        assert_eq!(b["effective"]["logo"], Value::Null);
        assert_eq!(b["effective"]["palette"]["light"]["sel"], "#E3107F");
        assert_eq!(b["effective"]["palette"]["dark"]["sel"], "#E3107F");
        let palette: Palette =
            serde_json::from_value(b["effective"]["palette"].clone()).expect("palette");
        assert_eq!(palette.contrast_issues(), Vec::<ContrastIssue>::new());

        // Только основной цвет — обе темы и CLI проходят.
        let (s, _, b) = env
            .call(
                "PUT",
                BRANDING_PREFIX,
                Some("root"),
                Some(json!({"primary": "#177CAA"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["own"]["primary"], "#177CAA");
        let palette: Palette =
            serde_json::from_value(b["effective"]["palette"].clone()).expect("palette");
        assert!(palette.contrast_issues().is_empty(), "проходит");

        // Выделение без контраста с панелью — 422 с errors (роль, пара, тема).
        let (s, h, b) = env
            .call(
                "PUT",
                BRANDING_PREFIX,
                Some("root"),
                Some(json!({"light": {"sel": "#F5E663"}})),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert_eq!(h[header::CONTENT_TYPE], "application/problem+json");
        assert_eq!(b["status"], 422);
        let e = &b["errors"][0];
        assert_eq!(e["field"], "light.sel");
        assert_eq!(e["theme"], "light");
        assert_eq!(e["role"], "sel");
        assert_eq!(e["bg"], "panel");
        assert!(e["contrast"].as_f64().expect("contrast") < 3.0);
        assert_eq!(e["min"], 3.0);
        let detail = b["detail"].as_str().expect("detail");
        assert!(detail.contains("светлая тема"), "{detail}");
        assert!(detail.contains("выделение sel #F5E663"), "{detail}");
        assert!(detail.contains("панель panel #FFFFFF"), "{detail}");
        assert!(detail.contains("нужно 3"), "{detail}");

        // Неверный цвет, неизвестная роль, знак в теле `PUT` набора — 400 problem+json.
        for bad in [
            json!({"primary": "#FFF"}),
            json!({"primary": "177CAA"}),
            json!({"light": {"sel": "#GGGGGG"}}),
            json!({"light": {"unknown": "#177CAA"}}),
            json!({"cli": {"unknown": "#177CAA"}}),
            json!({"product_name": "\u{7}"}),
            json!({"logo": {"hash": "00"}}),
        ] {
            let (s, _, b) = env
                .call("PUT", BRANDING_PREFIX, Some("root"), Some(bad))
                .await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{b}");
        }
    }

    /// Приёмка ADM-48: организация задала только название — название её, знак и цвета установки; сброс возвращает
    /// брендинг установки.
    #[tokio::test]
    async fn org_over_installation() {
        let env = Env::new();
        let (s, _, b) = env
            .call(
                "PUT",
                BRANDING_PREFIX,
                Some("root"),
                Some(json!({"primary": "#177CAA", "product_name": "Почта АО Ромашка"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let org = org_path(TenantId::DEFAULT);
        let (s, _, b) = env
            .call(
                "PUT",
                &org,
                Some("org"),
                Some(json!({"product_name": "Ромашка"})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["own"]["product_name"], "Ромашка");
        assert_eq!(b["effective"]["product_name"], "Ромашка", "название её");
        assert_eq!(
            b["effective"]["palette"]["light"]["frameA"], "#177CAA",
            "цвета установки"
        );

        // Сброс организации — снова брендинг установки; сброс не заданного уровня — 404.
        let (s, _, b) = env.call("DELETE", &org, Some("org"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["own"], Value::Null);
        assert_eq!(b["effective"]["product_name"], "Почта АО Ромашка");
        let (s, _, _) = env.call("DELETE", &org, Some("org"), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    /// Приёмка ADM-48: знак — тип 415, размер 413, полный разбор 422, годный PNG 200 с аудитом; знак без названия
    /// и цветов уровня — 200; прежний знак после замены и сброса удаляется, если не нужен ни одному уровню.
    #[tokio::test]
    async fn logo_flow() {
        let env = Env::new();
        // Не PNG по типу — 415 problem+json.
        let (s, h, b) = put_logo_call(&env, LOGO_ROUTE, "root", "image/jpeg", png(16, 16)).await;
        assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE, "{b}");
        assert_eq!(h[header::CONTENT_TYPE], "application/problem+json");
        assert!(b["detail"].as_str().expect("detail").contains("PNG"));

        // Больше 256 КБ — 413; больше 1024 по стороне — 422; битый файл — 422.
        let (s, _, b) =
            put_logo_call(&env, LOGO_ROUTE, "root", "image/png", vec![0u8; 300 * 1024]).await;
        assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{b}");
        let (s, _, b) = put_logo_call(&env, LOGO_ROUTE, "root", "image/png", png(2048, 16)).await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        let (s, _, _) = put_logo_call(
            &env,
            LOGO_ROUTE,
            "root",
            "image/png",
            b"\x89PNG\r\n\x1a\nbroken".to_vec(),
        )
        .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);

        // Годный PNG — 200, знак в действующем брендинге (без названия и цветов уровня), запись аудита.
        let first = png(16, 16);
        let (s, _, b) = put_logo_call(&env, LOGO_ROUTE, "root", "image/png", first.clone()).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let hash = b["own"]["logo"]["hash"].as_str().expect("hash").to_owned();
        assert_eq!(b["own"]["logo"]["width"], 16);
        assert_eq!(b["own"]["logo"]["size"], first.len());
        assert_eq!(b["effective"]["logo"]["hash"], hash);
        assert!(
            env.audit
                .records()
                .iter()
                .any(|r| r.route == LOGO_ROUTE && r.status == 200),
            "изменение знака — в журнале аудита"
        );

        // Замена знака: прежний удалён из BLOB.
        let second = png(24, 8);
        let (s, _, b) = put_logo_call(&env, LOGO_ROUTE, "root", "image/png", second.clone()).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let new_hash = b["own"]["logo"]["hash"].as_str().expect("hash").to_owned();
        assert_ne!(hash, new_hash);
        let old = BrandLogo {
            hash: BlobHash::from_str(&hash).expect("hash"),
            size: 0,
            width: 0,
            height: 0,
        };
        assert!(
            env.brand_blobs.get_raw(&old.path(), None).await.is_err(),
            "прежний знак удалён"
        );
        assert!(
            env.branding
                .logo_in_use(&BlobHash::from_str(&new_hash).expect("hash"))
                .await
                .expect("in use")
        );

        // Тот же знак у организации: сброс установки знак не удаляет (нужен организации), сброс организации —
        // удаляет; повторный сброс знака — 404.
        let org_logo = format!("{}/logo", org_path(TenantId::DEFAULT));
        let (s, _, _) = put_logo_call(&env, &org_logo, "org", "image/png", second.clone()).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = env.call("DELETE", LOGO_ROUTE, Some("root"), None).await;
        assert_eq!(s, StatusCode::OK);
        let shared = BrandLogo {
            hash: BlobHash::from_str(&new_hash).expect("hash"),
            size: 0,
            width: 0,
            height: 0,
        };
        assert!(
            env.brand_blobs.get_raw(&shared.path(), None).await.is_ok(),
            "знак ещё нужен организации"
        );
        let (s, _, _) = env.call("DELETE", &org_logo, Some("org"), None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(
            env.brand_blobs.get_raw(&shared.path(), None).await.is_err(),
            "знак не нужен ни одному уровню — удалён из BLOB"
        );
        let (s, _, _) = env.call("DELETE", &org_logo, Some("org"), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    /// Приёмка ADM-48: смена установки, под которой не читается свой текст организации, — 422 с организацией;
    /// тот же набор без организаций — 200. Набор, сохранённый в обход проверки, в `effective` — без нарушений.
    #[tokio::test]
    async fn installation_change_over_orgs() {
        let env = Env::new();
        let org = org_path(TenantId::DEFAULT);
        // Свой текст организации читается на светлой панели по умолчанию.
        let (s, _, b) = env
            .call(
                "PUT",
                &org,
                Some("org"),
                Some(json!({"light": {"text": "#161616"}})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");

        // Тёмная панель установки — текст организации не читается: 422 с организацией.
        let (s, h, b) = env
            .call(
                "PUT",
                BRANDING_PREFIX,
                Some("root"),
                Some(json!({"light": {"panel": "#0F1317"}})),
            )
            .await;
        assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{b}");
        assert_eq!(h[header::CONTENT_TYPE], "application/problem+json");
        let e = &b["errors"][0];
        assert_eq!(e["org"], TenantId::DEFAULT.to_string());
        assert_eq!(e["theme"], "light");
        assert_eq!(e["role"], "text");
        assert_eq!(e["bg"], "panel");
        let detail = b["detail"].as_str().expect("detail");
        assert!(detail.contains(&TenantId::DEFAULT.to_string()), "{detail}");

        // Тот же набор без организаций — 200.
        let (s, _, _) = env.call("DELETE", &org, Some("org"), None).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, b) = env
            .call(
                "PUT",
                BRANDING_PREFIX,
                Some("root"),
                Some(json!({"light": {"panel": "#0F1317"}})),
            )
            .await;
        assert_eq!(s, StatusCode::OK, "{b}");

        // Набор, сохранённый в обход проверки (напрямую в хранилище), отдаётся без нарушений.
        let mut bad = Branding::default();
        bad.light.insert(Role::Text, BrandColor::from_hex(0xFFFFFF));
        env.branding
            .set_branding(BrandingScope::Installation, &bad)
            .await
            .expect("set");
        let (_, _, b) = env.call("GET", BRANDING_PREFIX, Some("root"), None).await;
        let palette: Palette =
            serde_json::from_value(b["effective"]["palette"].clone()).expect("palette");
        assert!(palette.contrast_issues().is_empty(), "страховка отрисовки");
        assert_eq!(
            palette.role(Theme::Light, Role::Text),
            Role::Text.it_task(Theme::Light),
            "белый текст белой панели берётся с уровня выше"
        );
    }

    /// Приёмка ADM-48: права — уровень установки только у администратора установки (403 остальным); чужая
    /// организация — 404; оператор — только `GET` своей организации; без входа — 401; хранилище не подключено — 503.
    #[tokio::test]
    async fn roles() {
        let env = Env::new();
        let org = org_path(TenantId::DEFAULT);
        let other = org_path(env.other_tenant);
        for method in ["GET", "PUT", "DELETE"] {
            let (s, _, _) = env
                .call(method, BRANDING_PREFIX, Some("org"), Some(json!({})))
                .await;
            assert_eq!(
                s,
                StatusCode::FORBIDDEN,
                "уровень установки — не организации"
            );
            let (s, _, _) = env.call(method, LOGO_ROUTE, Some("operator"), None).await;
            assert_eq!(s, StatusCode::FORBIDDEN);
        }
        // Чужая организация — 404, своя — 200.
        let (s, _, _) = env.call("PUT", &other, Some("org"), Some(json!({}))).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _, _) = env.call("GET", &other, Some("root"), None).await;
        assert_eq!(s, StatusCode::OK);
        // Оператор: GET своей — ок, изменения — 403; аудитор — только журнал.
        let (s, _, _) = env.call("GET", &org, Some("operator"), None).await;
        assert_eq!(s, StatusCode::OK);
        for method in ["PUT", "DELETE"] {
            let (s, _, _) = env
                .call(method, &org, Some("operator"), Some(json!({})))
                .await;
            assert_eq!(s, StatusCode::FORBIDDEN);
        }
        let (s, _, _) = env.call("GET", &org, Some("auditor"), None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        // Без входа — 401.
        let (s, _, _) = env.call("GET", &org, None, None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        // Хранилище не подключено — 503 и у открытого маршрута.
        let env503 = Env::without_branding();
        let (s, _, _) = env503
            .call("GET", BRANDING_PREFIX, Some("root"), None)
            .await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        let (s, _, _) = env503.call("GET", PUBLIC_ROUTE, None, None).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Приёмка ADM-48: открытый маршрут — неизвестный домен, домен организации без своего набора и запрос без
    /// `domain` побайтно равны; домен организации со своим набором — её значения поверх установки; полей
    /// организации нет; `If-None-Match` — 304; знак по хэшу — PNG с `immutable`.
    #[tokio::test]
    async fn public_route() {
        let env = Env::new();
        accept_domain(&env, "example.test").await;
        env.call(
            "PUT",
            BRANDING_PREFIX,
            Some("root"),
            Some(json!({"product_name": "Почта АО Ромашка", "primary": "#177CAA"})),
        )
        .await;
        let org = org_path(TenantId::DEFAULT);
        env.call(
            "PUT",
            &org,
            Some("org"),
            Some(json!({"product_name": "Ромашка"})),
        )
        .await;

        // Домен организации со своим набором — её название и цвета установки.
        let own = call_raw(
            &env,
            "GET",
            "/api/v1/public/branding?domain=example.test",
            None,
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(own.0, StatusCode::OK);
        let body: Value = serde_json::from_slice(&own.2).expect("body");
        assert_eq!(body["product_name"], "Ромашка");
        assert_eq!(body["palette"]["light"]["frameA"], "#177CAA");
        // Полей организации в ответе нет — только название, палитра и знак.
        let mut keys = body.as_object().expect("object").keys().collect::<Vec<_>>();
        keys.sort();
        assert_eq!(keys, ["logo", "palette", "product_name"]);

        // Сброс организации: домен, неизвестный домен и без домена — побайтно равны.
        env.call("DELETE", &org, Some("org"), None).await;
        let no_domain = call_raw(&env, "GET", PUBLIC_ROUTE, None, None, Vec::new()).await;
        let domain = call_raw(
            &env,
            "GET",
            "/api/v1/public/branding?domain=example.test",
            None,
            None,
            Vec::new(),
        )
        .await;
        let unknown = call_raw(
            &env,
            "GET",
            "/api/v1/public/branding?domain=nowhere.test",
            None,
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(domain.0, StatusCode::OK);
        assert_eq!(unknown.0, StatusCode::OK);
        assert_eq!(domain.2, unknown.2, "неизвестный домен — тот же ответ");
        assert_eq!(domain.2, no_domain.2, "без домена — тот же ответ");
        assert_eq!(domain.1.get(header::ETAG), no_domain.1.get(header::ETAG));
        assert_eq!(domain.1[header::CACHE_CONTROL], "public, max-age=300");
        let body: Value = serde_json::from_slice(&domain.2).expect("body");
        assert_eq!(body["product_name"], "Почта АО Ромашка");

        // If-None-Match — 304.
        let etag = domain.1.get(header::ETAG).cloned().expect("etag");
        let req = Request::builder()
            .uri(PUBLIC_ROUTE)
            .header(header::IF_NONE_MATCH, etag.to_str().expect("etag"))
            .body(Body::empty())
            .expect("request");
        let resp = env.router.clone().oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(resp.headers()[header::CACHE_CONTROL], "public, max-age=300");

        // Знак по хэшу: PNG и immutable; неизвестный — 404; неверный хэш — 400.
        let (s, _, b) = put_logo_call(&env, LOGO_ROUTE, "root", "image/png", png(16, 16)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let hash = b["own"]["logo"]["hash"].as_str().expect("hash").to_owned();
        let (s, h, bytes) = call_raw(&env, "GET", &logo_path(&hash), None, None, Vec::new()).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], "image/png");
        assert_eq!(
            h[header::CACHE_CONTROL],
            "public, max-age=31536000, immutable"
        );
        assert_eq!(bytes, png(16, 16));
        let missing = logo_path(&BlobHash([7u8; 32]).to_string());
        let (s, _, _) = call_raw(&env, "GET", &missing, None, None, Vec::new()).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _, _) = call_raw(
            &env,
            "GET",
            "/api/v1/public/branding/logo/zz",
            None,
            None,
            Vec::new(),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        // Ссылка на знак в открытом маршруте — публичный путь по хэшу.
        let (_, _, bytes) = call_raw(&env, "GET", PUBLIC_ROUTE, None, None, Vec::new()).await;
        let body: Value = serde_json::from_slice(&bytes).expect("body");
        assert_eq!(body["logo"], logo_path(&hash));
    }

    /// Приёмка ADM-48: знак организации — в её действующем брендинге и аудите; оператор знак не меняет; сброс
    /// набора организации удаляет её знак из BLOB.
    #[tokio::test]
    async fn org_logo_and_audit() {
        let env = Env::new();
        let org = org_path(TenantId::DEFAULT);
        let org_logo = format!("{org}/logo");
        let (s, _, b) = put_logo_call(&env, &org_logo, "org", "image/png", png(12, 12)).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        let hash = b["own"]["logo"]["hash"].as_str().expect("hash").to_owned();
        assert_eq!(b["effective"]["logo"]["hash"], hash);
        assert!(
            env.audit
                .records()
                .iter()
                .any(|r| r.route == ORG_LOGO_ROUTE && r.status == 200),
            "знак организации — в журнале аудита"
        );
        let (s, _, _) = put_logo_call(&env, &org_logo, "operator", "image/png", png(4, 4)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, b) = env.call("DELETE", &org, Some("org"), None).await;
        assert_eq!(s, StatusCode::OK, "{b}");
        assert_eq!(b["effective"]["logo"], Value::Null);
        let path = BrandLogo {
            hash: BlobHash::from_str(&hash).expect("hash"),
            size: 0,
            width: 0,
            height: 0,
        }
        .path();
        assert!(env.brand_blobs.get_raw(&path, None).await.is_err());
    }

    /// Все операции модуля — в спецификации (их подхватят консоль, CLI и текстовый интерфейс); открытые — без
    /// входа, уровень установки — со входом.
    #[test]
    fn spec_has_operations() {
        let spec = serde_json::to_value(crate::server::openapi_spec()).expect("spec");
        let paths = spec["paths"].as_object().expect("paths");
        for (path, methods) in [
            (BRANDING_PREFIX, ["get", "put", "delete"].as_slice()),
            (LOGO_ROUTE, ["put", "delete"].as_slice()),
            (ORG_ROUTE, ["get", "put", "delete"].as_slice()),
            (ORG_LOGO_ROUTE, ["put", "delete"].as_slice()),
            (PUBLIC_ROUTE, ["get"].as_slice()),
            (PUBLIC_LOGO_ROUTE, ["get"].as_slice()),
        ] {
            let item = paths
                .get(path)
                .unwrap_or_else(|| panic!("{path} нет в схеме"));
            for m in methods {
                assert!(item.get(m).is_some(), "{m} {path}");
            }
        }
        assert_eq!(
            spec["paths"][PUBLIC_ROUTE]["get"]["security"],
            json!([{}]),
            "открытый маршрут без входа"
        );
        assert!(
            spec["paths"][BRANDING_PREFIX]["get"]
                .get("security")
                .is_none(),
            "уровень установки — под общим входом документа"
        );
    }
}
