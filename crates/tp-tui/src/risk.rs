//! Раздел «Признаки риска» (TUI-10, ADM-51): ручная раскладка — вкладки «Каталог», «Пороги», «Пакеты»,
//! «Источники», «Срабатывания» (маршруты `/api/v1/risk/…` и `/api/v1/orgs/{org}/risk/…`).
//!
//! Каталог — таблица с курсором; F4 — форма изменения веса, действия и режима (свой признак `org.*` —
//! целиком), организация — только в сторону строгости: отказ 422 — текст `detail` сервера у поля формы.
//! «Только отчёт» — знак ▲ у режима, «осиротевшее» изменение — знак ⊘ у признака, пояснения — в строке
//! состояния. Пакеты (администратор установки): список версий, импорт файла с узла (путь — полем ввода,
//! для закрытого контура по SSH), отчёт проверки до активации, активация и откат с подтверждением.
//! Источники TI (администратор установки): свежесть против TTL (устарел — знак ▲ и цвет роли
//! «внимание»), импорт списка файлом, «обновить сейчас», учёт по организациям. Срабатывания — журнал
//! организации с фильтром и листанием. Внизу — эквивалентная команда `thepost admin risk …` (решение
//! 118). Сети нет: действия возвращают эффекты через [`crate::app::Bus`]. Ответы Admin API разбираются
//! как JSON (тонкий клиент по схеме): порядок вкладок и таблиц продублирован константами модуля,
//! соответствие схеме — тесты.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::{Map, Value};

use crate::app::{Bus, Effect, Level, Main, Overlay, Page, Pending as Sent, View};
use crate::engine::{Context, Form, Request};
use crate::schema::catalog;

/// Строк таблицы вкладки в правой панели (под заголовком колонок).
pub const VIS_ROWS: usize = 13;

/// Ширины колонок каталога: признак, вес, действие (▲ — «только отчёт»), источник.
pub const ID_W: u16 = 23;
pub const WEIGHT_W: u16 = 4;
pub const ACTION_W: u16 = 10;
pub const SRC_W: u16 = 6;

/// Ширины колонок пакетов и источников.
pub const VER_W: u16 = 7;
pub const STATE_W: u16 = 24;
pub const SID_W: u16 = 14;
pub const TIER_W: u16 = 8;
pub const FORMAT_W: u16 = 7;
pub const TTL_W: u16 = 5;
pub const FRESH_W: u16 = 8;

/// Ширины колонок срабатываний и учёта.
pub const AT_W: u16 = 16;
pub const HSIG_W: u16 = 13;
pub const STR_W: u16 = 3;
pub const HW_W: u16 = 4;
pub const HMODE_W: u16 = 6;
pub const TENANT_W: u16 = 36;
pub const LOOKUPS_W: u16 = 4;
pub const UHITS_W: u16 = 4;

/// `operationId` операции-раздела дерева («Признаки риска»).
pub const SECTION_OP: &str = "list_org_signals";

/// Вкладка раздела.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Действующий каталог признаков организации.
    Catalog,
    /// Пороги действий организации.
    Thresholds,
    /// Пакеты поставщика (администратор установки).
    Packages,
    /// Источники TI (администратор установки).
    Sources,
    /// Журнал срабатываний организации.
    Hits,
}

/// Вкладки по порядку и подписи строки вкладок.
pub const TABS: [(Tab, &str); 5] = [
    (Tab::Catalog, "Каталог"),
    (Tab::Thresholds, "Пороги"),
    (Tab::Packages, "Пакеты"),
    (Tab::Sources, "Источники"),
    (Tab::Hits, "Срабатывания"),
];

/// Вкладка доступна уровню доступа: пакеты и источники — только администратору установки (403 прочим).
pub fn reachable(tab: Tab, install: bool) -> bool {
    !matches!(tab, Tab::Packages | Tab::Sources) || install
}

/// Что импортируем файлом с узла.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportWhat {
    /// Пакет поставщика (`POST /api/v1/risk/packages`, `application/octet-stream`).
    Package,
    /// Список TI источника (`POST /api/v1/risk/sources/{id}/import`).
    Source(String),
}

/// Ответы в пути для раздела «Признаки риска» ([`crate::app::Pending::Risk`]).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Pending {
    /// `GET` каталога признаков.
    Catalog,
    /// `GET` порогов.
    Thresholds,
    /// `GET` пакетов.
    Packages,
    /// `GET` источников TI.
    Sources,
    /// `GET` срабатываний (первая страница после фильтра; форма — для отказа у поля).
    Hits {
        /// Форма фильтра, если запрос из неё.
        form: Option<Box<Form>>,
    },
    /// `GET` следующей страницы срабатываний (`until`).
    HitsMore,
    /// `PUT` признака (форма — для отказа 422 у поля).
    SaveSignal(Box<Form>),
    /// `PUT` порогов (форма — для отказа 422 у поля).
    SaveThresholds(Box<Form>),
    /// `DELETE` — сброс изменения признака (или удаление своего `org.*`).
    ResetSignal(String),
    /// Загрузка файла пакета с узла (путь — для возврата в поле при отказе).
    ImportPackage {
        /// Введённый путь.
        path: String,
    },
    /// Импорт файла списка источника.
    ImportSource {
        /// Источник.
        id: String,
        /// Введённый путь.
        path: String,
    },
    /// `POST …/refresh` — обновить источник сейчас.
    Refresh(String),
    /// `GET …/usage` — учёт источника по организациям.
    Usage(String),
    /// Активация пакета.
    Activate(u64),
    /// Откат на хранимый пакет.
    Rollback(u64),
}

/// Состояние раздела «Признаки риска».
#[derive(Debug, Clone, PartialEq)]
pub struct Risk {
    /// Организация контекста.
    pub org: String,
    /// Вошёл администратор установки — вкладки «Пакеты» и «Источники» доступны.
    pub install: bool,
    /// Вкладка.
    pub tab: Tab,
    /// Курсор таблицы вкладки.
    pub cur: usize,
    /// Первая видимая строка.
    pub top: usize,
    /// Каталог признаков (`SignalsView.signals`).
    pub signals: Option<Vec<Value>>,
    /// Пороги (`ThresholdsView`).
    pub thresholds: Option<Value>,
    /// Пакеты (`PackagesView.packages`).
    pub packages: Option<Vec<Value>>,
    /// Отчёт проверки загруженного пакета — показан до активации (решение 126 б).
    pub report: Option<Value>,
    /// Источники TI (`SourcesView.sources`).
    pub sources: Option<Vec<Value>>,
    /// Момент последней загрузки данных источника (`fetched_at` ответов импорта и обновления).
    pub fetched: BTreeMap<String, String>,
    /// Учёт источника по организациям (`UsageView`).
    pub usage: Option<Value>,
    /// Срабатывания страницы (`HitsView.hits`).
    pub hits: Option<Vec<Value>>,
    /// Конец интервала следующей страницы срабатываний (`next`).
    pub hits_next: Option<String>,
    /// Применённый фильтр срабатываний (параметры запроса).
    pub hits_filter: Vec<(String, String)>,
}

impl Risk {
    /// Экран «Признаки риска»: каталог организации.
    pub fn new(org: String, install: bool) -> Self {
        Self {
            org,
            install,
            tab: Tab::Catalog,
            cur: 0,
            top: 0,
            signals: None,
            thresholds: None,
            packages: None,
            report: None,
            sources: None,
            fetched: BTreeMap::new(),
            usage: None,
            hits: None,
            hits_next: None,
            hits_filter: Vec::new(),
        }
    }

    /// Строки таблицы вкладки.
    pub fn rows(&self) -> &[Value] {
        match self.tab {
            Tab::Catalog => self.signals.as_deref().unwrap_or(&[]),
            Tab::Thresholds => &[],
            Tab::Packages => self.packages.as_deref().unwrap_or(&[]),
            Tab::Sources => self.sources.as_deref().unwrap_or(&[]),
            Tab::Hits => self.hits.as_deref().unwrap_or(&[]),
        }
    }

    /// Данные вкладки ещё читаются.
    pub fn loading(&self) -> bool {
        match self.tab {
            Tab::Catalog => self.signals.is_none(),
            Tab::Thresholds => self.thresholds.is_none(),
            Tab::Packages => self.packages.is_none(),
            Tab::Sources => self.sources.is_none(),
            Tab::Hits => self.hits.is_none(),
        }
    }

    /// Курсор с прокруткой: видимых строк — [`VIS_ROWS`].
    pub fn select(&mut self, sel: usize) {
        self.cur = sel.min(self.rows().len().saturating_sub(1));
        if self.cur < self.top {
            self.top = self.cur;
        } else if self.cur >= self.top + VIS_ROWS {
            self.top = self.cur + 1 - VIS_ROWS;
        }
    }
}

/// Операция схемы по `operationId` (есть в схеме — тест `risk_operations_in_schema`).
fn op(id: &str) -> &'static crate::schema::Operation {
    catalog()
        .get(id)
        .unwrap_or_else(|| panic!("{id}: нет в схеме"))
}

/// Контекст запроса: организация.
fn ctx(t: &Risk) -> Context {
    Context::from([("org".to_owned(), t.org.clone())])
}

/// Запрос данных вкладки.
fn load(t: &Risk, bus: &mut Bus) -> Effect {
    let (id, p, query) = match t.tab {
        Tab::Catalog => ("list_org_signals", Pending::Catalog, Vec::new()),
        Tab::Thresholds => ("get_org_thresholds", Pending::Thresholds, Vec::new()),
        Tab::Packages => ("list_packages", Pending::Packages, Vec::new()),
        Tab::Sources => ("list_ti_sources", Pending::Sources, Vec::new()),
        Tab::Hits => (
            "list_risk_hits",
            Pending::Hits { form: None },
            t.hits_filter.clone(),
        ),
    };
    let req = Request::new(op(id), &ctx(t), query).expect("запрос раздела риска");
    bus.call(req, Sent::Risk(p))
}

/// Открыть раздел из дерева: каталог признаков организации.
pub(crate) fn open(m: &mut Main, bus: &mut Bus) -> Vec<Effect> {
    let t = Risk::new(m.org.clone(), m.session.install_admin);
    let effect = load(&t, bus);
    m.view = View::Risk(t);
    vec![effect]
}

/// Смена вкладки стрелками ← →: доступные соседи по кругу; мимо вкладок администратора установки —
/// предупреждение.
fn shift_tab(t: &mut Risk, bus: &mut Bus, step: isize) -> Vec<Effect> {
    let at = |tab: Tab| TABS.iter().position(|(x, _)| *x == tab).unwrap_or(0);
    let mut i = at(t.tab) as isize;
    let n = TABS.len() as isize;
    let mut passed_gated = false;
    loop {
        i = (i + step).rem_euclid(n);
        let (tab, _) = TABS[usize::try_from(i).unwrap_or(0)];
        if reachable(tab, t.install) {
            if passed_gated {
                bus.say(Level::Warn, "пакеты и источники — администратору установки");
            }
            t.tab = tab;
            t.cur = 0;
            t.top = 0;
            return vec![load(t, bus)];
        }
        passed_gated = true;
    }
}

/// Клавиша раздела. Стрелки ↑↓ — курсор таблицы, ← → — вкладки; F4 — изменение признака или порогов;
/// F8 — сброс изменения признака (каталог) или откат пакета (пакеты); F5 — активация пакета,
/// «обновить сейчас» источника; F6 — учёт источника; F7 — импорт файла с узла; F2 — фильтр
/// срабатываний; Esc — закрыть отчёт пакета или учёт источника.
pub(crate) fn key(m: &mut Main, bus: &mut Bus, key: KeyEvent) -> Vec<Effect> {
    let View::Risk(t) = &mut m.view else {
        return Vec::new();
    };
    let busy = bus.busy();
    let mut overlay: Option<Overlay> = None;
    let out = match key.code {
        KeyCode::Up => {
            let at = t.cur;
            t.select(at.saturating_sub(1));
            Vec::new()
        }
        KeyCode::Down => {
            let last = t.rows().len().saturating_sub(1);
            if t.tab == Tab::Hits && !busy && t.cur >= last && t.hits_next.is_some() {
                let next = hits_more(t, bus);
                return next;
            }
            let at = t.cur;
            t.select(at + 1);
            Vec::new()
        }
        KeyCode::PageUp => {
            let at = t.cur;
            t.select(at.saturating_sub(VIS_ROWS));
            Vec::new()
        }
        KeyCode::PageDown => {
            let at = t.cur;
            t.select(at + VIS_ROWS);
            Vec::new()
        }
        KeyCode::Home => {
            t.select(0);
            Vec::new()
        }
        KeyCode::End => {
            let n = t.rows().len();
            t.select(n.saturating_sub(1));
            Vec::new()
        }
        KeyCode::Left => shift_tab(t, bus, -1),
        KeyCode::Right => shift_tab(t, bus, 1),
        KeyCode::Esc | KeyCode::Backspace => {
            t.report = None;
            t.usage = None;
            Vec::new()
        }
        KeyCode::Enter | KeyCode::F(4) if t.tab == Tab::Catalog && !busy => {
            overlay = signal_edit(t);
            Vec::new()
        }
        KeyCode::F(4) if t.tab == Tab::Thresholds && !busy => {
            overlay = thresholds_edit(t);
            Vec::new()
        }
        KeyCode::F(8) if t.tab == Tab::Catalog && !busy => reset_signal(t, bus, &mut overlay),
        KeyCode::F(7) if t.tab == Tab::Packages && !busy => {
            overlay = Some(Overlay::RiskImport {
                what: ImportWhat::Package,
                path: String::new(),
                error: None,
            });
            Vec::new()
        }
        KeyCode::F(5) if t.tab == Tab::Packages && !busy => activate(t, bus, &mut overlay),
        KeyCode::F(8) if t.tab == Tab::Packages && !busy => rollback(t, bus, &mut overlay),
        KeyCode::F(5) if t.tab == Tab::Sources && !busy => refresh_source(t, bus),
        KeyCode::F(6) if t.tab == Tab::Sources && !busy => usage(t, bus),
        KeyCode::F(7) if t.tab == Tab::Sources && !busy => {
            import_list(t, bus, &mut overlay);
            Vec::new()
        }
        KeyCode::F(2) if t.tab == Tab::Hits && !busy => {
            overlay = Some(hits_filter(t));
            Vec::new()
        }
        _ => Vec::new(),
    };
    if let Some(ov) = overlay {
        m.overlay = Some(ov);
    }
    out
}

/// F4 каталога: форма изменения признака — вес, действие, режим; свой признак `org.*` — целиком
/// (детектор, вес, порог, действие и режим обязательны).
fn signal_edit(t: &Risk) -> Option<Overlay> {
    let row = t.rows().get(t.cur)?;
    let id = id_of(row);
    let mut c = ctx(t);
    c.insert("id".to_owned(), id.clone());
    let mut prefill = Map::new();
    for name in ["detector", "weight", "threshold", "action", "mode"] {
        if let Some(v) = row.get(name).filter(|v| !v.is_null()) {
            prefill.insert(name.to_owned(), v.clone());
        }
    }
    let mut form = Form::new(op("put_org_signal"), &c, false, &prefill);
    form.retain(if id.starts_with("org.") {
        &["detector", "weight", "threshold", "action", "mode"]
    } else {
        &["weight", "action", "mode"]
    });
    Some(Overlay::RiskSignalEdit {
        form: Box::new(form),
    })
}

/// F4 порогов: форма замены порогов организации целиком — баллы действий, растут со строгостью.
fn thresholds_edit(t: &Risk) -> Option<Overlay> {
    let v = t.thresholds.as_ref()?;
    let mut prefill = Map::new();
    for name in ["tag", "junk", "quarantine", "reject"] {
        let value = v
            .get("own")
            .filter(|o| o.is_object())
            .and_then(|o| o.get(name))
            .or_else(|| v.get("effective").and_then(|e| e.get(name)))
            .cloned()
            .unwrap_or(Value::Null);
        prefill.insert(name.to_owned(), value);
    }
    let form = Form::new(op("put_org_thresholds"), &ctx(t), false, &prefill);
    Some(Overlay::RiskThresholds {
        form: Box::new(form),
    })
}

/// F8 каталога: сброс изменения признака уровня (или удаление своего `org.*`) с подтверждением.
/// Сбрасывать нечего — у признака пакета без изменений — предупреждение.
fn reset_signal(t: &mut Risk, bus: &mut Bus, overlay: &mut Option<Overlay>) -> Vec<Effect> {
    let Some(row) = t.rows().get(t.cur).cloned() else {
        bus.say(Level::Warn, "нет выделенного признака");
        return Vec::new();
    };
    let id = id_of(&row);
    let own = id.starts_with("org.");
    if !own && row.get("source").is_none_or(Value::is_null) {
        bus.say(Level::Warn, "изменения на уровне нет — сбрасывать нечего");
        return Vec::new();
    }
    let mut c = ctx(t);
    c.insert("id".to_owned(), id.clone());
    let req = Request::new(op("reset_org_signal"), &c, Vec::new()).expect("запрос сброса");
    *overlay = Some(Overlay::RiskConfirm {
        req: Box::new(req),
        p: Pending::ResetSignal(id),
    });
    Vec::new()
}

/// F5 пакетов: активация выделенной версии с подтверждением; действующий пакет активировать нельзя.
fn activate(t: &mut Risk, bus: &mut Bus, overlay: &mut Option<Overlay>) -> Vec<Effect> {
    let Some(row) = t.rows().get(t.cur).cloned() else {
        bus.say(Level::Warn, "нет выделенной версии");
        return Vec::new();
    };
    let Some(version) = version_of(&row) else {
        return Vec::new();
    };
    if state_of(&row).0 == "действующий" {
        bus.say(
            Level::Warn,
            "пакет уже действует — активировать можно поставленный или прошлый",
        );
        return Vec::new();
    }
    let mut c = Context::new();
    c.insert("version".to_owned(), version.to_string());
    let req = Request::new(op("activate_package"), &c, Vec::new()).expect("запрос активации");
    *overlay = Some(Overlay::RiskConfirm {
        req: Box::new(req),
        p: Pending::Activate(version),
    });
    Vec::new()
}

/// F8 пакетов: откат на хранимую версию с подтверждением.
fn rollback(t: &mut Risk, bus: &mut Bus, overlay: &mut Option<Overlay>) -> Vec<Effect> {
    let Some(row) = t.rows().get(t.cur).cloned() else {
        bus.say(Level::Warn, "нет выделенной версии");
        return Vec::new();
    };
    let Some(version) = version_of(&row) else {
        return Vec::new();
    };
    let mut c = Context::new();
    c.insert("version".to_owned(), version.to_string());
    let req = Request::new(op("rollback_package"), &c, Vec::new()).expect("запрос отката");
    *overlay = Some(Overlay::RiskConfirm {
        req: Box::new(req),
        p: Pending::Rollback(version),
    });
    Vec::new()
}

/// Идентификатор выделенного источника.
fn source_id_of(t: &Risk, bus: &mut Bus) -> Option<String> {
    let id = t
        .rows()
        .get(t.cur)
        .and_then(|r| r.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if id.is_none() {
        bus.say(Level::Warn, "нет выделенного источника");
    }
    id
}

/// F5 источников: обновить сейчас (коннектор узла, APP-79).
fn refresh_source(t: &mut Risk, bus: &mut Bus) -> Vec<Effect> {
    let Some(id) = source_id_of(t, bus) else {
        return Vec::new();
    };
    let mut c = ctx(t);
    c.insert("id".to_owned(), id.clone());
    let req = Request::new(op("refresh_source"), &c, Vec::new()).expect("запрос обновления");
    bus.say(Level::Ok, format!("обновление источника {id}…"));
    vec![bus.call(req, Sent::Risk(Pending::Refresh(id)))]
}

/// F6 источников: учёт обращений и совпадений по организациям (MSSP).
fn usage(t: &mut Risk, bus: &mut Bus) -> Vec<Effect> {
    let Some(id) = source_id_of(t, bus) else {
        return Vec::new();
    };
    let mut c = ctx(t);
    c.insert("id".to_owned(), id.clone());
    let req = Request::new(op("source_usage"), &c, Vec::new()).expect("запрос учёта");
    bus.say(Level::Ok, "чтение учёта…");
    vec![bus.call(req, Sent::Risk(Pending::Usage(id)))]
}

/// F7 источников: путь к файлу списка на узле (закрытый контур).
fn import_list(t: &Risk, bus: &mut Bus, overlay: &mut Option<Overlay>) {
    let Some(id) = t
        .rows()
        .get(t.cur)
        .and_then(|r| r.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
    else {
        bus.say(Level::Warn, "нет выделенного источника");
        return;
    };
    *overlay = Some(Overlay::RiskImport {
        what: ImportWhat::Source(id),
        path: String::new(),
        error: None,
    });
}

/// F2 срабатываний: форма фильтра (признак, режим, интервал, размер страницы).
fn hits_filter(t: &Risk) -> Overlay {
    let mut prefill = Map::new();
    for (k, v) in &t.hits_filter {
        prefill.insert(k.clone(), Value::String(v.clone()));
    }
    let form = Form::new(op("list_risk_hits"), &ctx(t), true, &prefill);
    Overlay::RiskFilter {
        form: Box::new(form),
    }
}

/// Следующая страница срабатываний: продолжение по `next` (параметр запроса `until`).
fn hits_more(t: &Risk, bus: &mut Bus) -> Vec<Effect> {
    let Some(next) = t.hits_next.clone() else {
        return Vec::new();
    };
    let mut query = t.hits_filter.clone();
    query.push(("until".to_owned(), next));
    let req = Request::new(op("list_risk_hits"), &ctx(t), query).expect("запрос страницы");
    vec![bus.call(req, Sent::Risk(Pending::HitsMore))]
}

/// Ввод пути к файлу на узле и его загрузка (окно импорта пакета или списка источника).
pub(crate) fn import_key(
    m: &mut Main,
    bus: &mut Bus,
    what: ImportWhat,
    mut path: String,
    error: Option<String>,
    key: KeyEvent,
) -> Vec<Effect> {
    let restore = |m: &mut Main, what: &ImportWhat, path: String, error: Option<String>| {
        m.overlay = Some(Overlay::RiskImport {
            what: what.clone(),
            path,
            error,
        });
        Vec::new()
    };
    match key.code {
        KeyCode::Esc => Vec::new(),
        KeyCode::Enter => {
            let path = path.trim().to_owned();
            if path.is_empty() {
                return restore(
                    m,
                    &what,
                    path,
                    Some("введите путь к файлу на узле".to_owned()),
                );
            }
            let View::Risk(_) = &m.view else {
                return Vec::new();
            };
            let (op_id, params, p) = match &what {
                ImportWhat::Package => (
                    "upload_package",
                    Vec::new(),
                    Pending::ImportPackage { path: path.clone() },
                ),
                ImportWhat::Source(id) => (
                    "import_source",
                    vec![id.clone()],
                    Pending::ImportSource {
                        id: id.clone(),
                        path: path.clone(),
                    },
                ),
            };
            let Some(op) = catalog().get(op_id) else {
                return Vec::new();
            };
            let id = bus.call_import(Sent::Risk(p));
            bus.say(Level::Ok, "чтение файла с узла…");
            vec![Effect::Import {
                id,
                op,
                params,
                path,
            }]
        }
        KeyCode::Backspace => {
            path.pop();
            restore(m, &what, path, None)
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            path.push(c);
            restore(m, &what, path, None)
        }
        _ => restore(m, &what, path, error),
    }
}

/// Ответ Admin API: данные вкладки, запись изменения, сброс, активация и откат пакета, импорт и
/// обновление источника, учёт.
pub(crate) fn on_ok(m: &mut Main, bus: &mut Bus, p: Pending, page: Page) -> Vec<Effect> {
    let View::Risk(t) = &mut m.view else {
        return Vec::new();
    };
    let v = page.value;
    match p {
        Pending::Catalog => match v.get("signals").and_then(Value::as_array) {
            Some(rows) => {
                t.signals = Some(rows.clone());
                t.select(t.cur);
            }
            None => bus.say(Level::Err, "каталог признаков: неожиданный ответ сервера"),
        },
        Pending::Thresholds => {
            if v.is_object() {
                t.thresholds = Some(v);
            } else {
                bus.say(Level::Err, "пороги: неожиданный ответ сервера");
            }
        }
        Pending::Packages => match v.get("packages").and_then(Value::as_array) {
            Some(rows) => {
                t.packages = Some(rows.clone());
                // Курсор — на поставленном пакете из отчёта проверки.
                if let Some(rep) = t.report.as_ref()
                    && let Some(ver) = rep.get("version").and_then(Value::as_u64)
                    && let Some(i) = t
                        .packages
                        .as_deref()
                        .unwrap_or(&[])
                        .iter()
                        .position(|r| version_of(r) == Some(ver))
                {
                    t.select(i);
                }
            }
            None => bus.say(Level::Err, "пакеты: неожиданный ответ сервера"),
        },
        Pending::Sources => match v.get("sources").and_then(Value::as_array) {
            Some(rows) => {
                t.sources = Some(rows.clone());
                t.select(t.cur);
            }
            None => bus.say(Level::Err, "источники: неожиданный ответ сервера"),
        },
        Pending::Hits { .. } => {
            let rows = v
                .get("hits")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            t.hits = Some(rows);
            t.hits_next = next_of(&v);
            t.cur = 0;
            t.top = 0;
        }
        Pending::HitsMore => {
            let rows = v
                .get("hits")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let at = t.cur;
            if let Some(h) = t.hits.as_mut() {
                h.extend(rows);
            }
            t.hits_next = next_of(&v);
            t.select(at + 1);
        }
        Pending::SaveSignal(_) => {
            bus.say(Level::Ok, "готово: изменение признака записано");
            t.tab = Tab::Catalog;
            return vec![load(t, bus)];
        }
        Pending::SaveThresholds(_) => {
            bus.say(Level::Ok, "готово: пороги записаны");
            t.tab = Tab::Thresholds;
            return vec![load(t, bus)];
        }
        Pending::ResetSignal(_) => {
            bus.say(Level::Ok, "готово: изменение признака сброшено");
            t.tab = Tab::Catalog;
            return vec![load(t, bus)];
        }
        Pending::Activate(_) => {
            if let Some(rows) = v.get("packages").and_then(Value::as_array) {
                t.packages = Some(rows.clone());
            }
            t.report = None;
            bus.say(Level::Ok, "готово: пакет активирован");
        }
        Pending::Rollback(_) => {
            if let Some(rows) = v.get("packages").and_then(Value::as_array) {
                t.packages = Some(rows.clone());
            }
            t.report = None;
            bus.say(Level::Ok, "готово: откат на прежний пакет");
        }
        Pending::ImportPackage { .. } => {
            if v.is_object() {
                let ver = v.get("version").and_then(Value::as_u64).unwrap_or(0);
                t.report = Some(v.clone());
                bus.say(
                    Level::Ok,
                    format!("пакет версии {ver} проверен и поставлен, не активен"),
                );
            }
            t.tab = Tab::Packages;
            return vec![load(t, bus)];
        }
        Pending::ImportSource { id, .. } | Pending::Refresh(id) => {
            if let Some(at) = v.get("fetched_at").and_then(Value::as_str) {
                t.fetched.insert(id.clone(), at.to_owned());
            }
            bus.say(Level::Ok, "готово: список источника загружен");
            t.tab = Tab::Sources;
            return vec![load(t, bus)];
        }
        Pending::Usage(_) => {
            if v.is_object() {
                t.usage = Some(v);
            } else {
                bus.say(Level::Err, "учёт: неожиданный ответ сервера");
            }
        }
    }
    Vec::new()
}

/// Конец интервала следующей страницы срабатываний.
fn next_of(v: &Value) -> Option<String> {
    v.get("next")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Отказ у поля формы: `detail` — у названного в нём поля (вес, действие, режим, порог), иначе у
/// формы целиком.
fn form_error(
    mut f: Box<Form>,
    problem: Option<&tp_admin::server::Problem>,
    detail: String,
) -> Box<Form> {
    match problem {
        Some(pr) => f.apply_problem(pr),
        None => f.error = Some(detail),
    }
    f
}

/// Отказ Admin API: 422 — текст `detail` сервера у поля формы (вес, действие, режим, порог, путь
/// файла), прочие — в строке состояния.
pub(crate) fn on_err(m: &mut Main, bus: &mut Bus, p: Pending, e: &tp_admin_client::Error) {
    let problem = match e {
        tp_admin_client::Error::Api {
            problem: Some(pr), ..
        } => Some(pr),
        _ => None,
    };
    let detail = match e {
        tp_admin_client::Error::Api {
            problem: Some(pr), ..
        } => pr
            .detail
            .clone()
            .unwrap_or_else(|| format!("{} {}", pr.status, pr.title)),
        _ => e.to_string(),
    };
    let View::Risk(_) = &mut m.view else {
        bus.say(Level::Err, detail);
        return;
    };
    match p {
        Pending::SaveSignal(f) => {
            bus.say(Level::Err, detail.clone());
            m.overlay = Some(Overlay::RiskSignalEdit {
                form: form_error(f, problem, detail),
            });
        }
        Pending::SaveThresholds(f) => {
            bus.say(Level::Err, detail.clone());
            m.overlay = Some(Overlay::RiskThresholds {
                form: form_error(f, problem, detail),
            });
        }
        Pending::Hits { form } => {
            bus.say(Level::Err, detail.clone());
            if let Some(f) = form {
                m.overlay = Some(Overlay::RiskFilter {
                    form: form_error(f, problem, detail),
                });
            }
        }
        Pending::ImportPackage { path } => {
            bus.say(Level::Err, format!("файл не принят: {detail}"));
            m.overlay = Some(Overlay::RiskImport {
                what: ImportWhat::Package,
                path,
                error: Some(detail),
            });
        }
        Pending::ImportSource { id, path } => {
            bus.say(Level::Err, format!("файл не принят: {detail}"));
            m.overlay = Some(Overlay::RiskImport {
                what: ImportWhat::Source(id),
                path,
                error: Some(detail),
            });
        }
        _ => bus.say(Level::Err, detail),
    }
}

// ---------- Каталог: значения и знаки ----------

/// Идентификатор записи.
fn id_of(row: &Value) -> String {
    row.get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// «Осиротевшее» изменение: признака нет в действующем пакете (решение 126 в) — знак ⊘.
pub fn orphaned(row: &Value) -> bool {
    row.get("orphaned").and_then(Value::as_bool) == Some(true)
}

/// Режим «только отчёт» — знак ▲ у режима: балл и действие не применяются, срабатывания — в журнале.
pub fn report_only(row: &Value) -> bool {
    row.get("mode").and_then(Value::as_str) == Some("report")
}

/// Короткое действие признака.
pub fn action_short(v: &Value) -> &'static str {
    match v.as_str() {
        Some("none") => "нет",
        Some("tag") => "пометка",
        Some("junk") => "спам",
        Some("quarantine") => "карантин",
        Some("reject") => "отказ",
        _ => "—",
    }
}

/// Полный режим признака для строки состояния.
pub fn mode_full(v: &Value) -> &'static str {
    match v.as_str() {
        Some("report") => "только отчёт",
        Some("enforce") => "применять",
        _ => "—",
    }
}

/// Уровень-источник значения признака (коротко): пакет без изменений, установка, организация.
pub fn source_label(row: &Value) -> &'static str {
    match row.get("source") {
        Some(Value::String(s)) if s == "installation" => "уст",
        Some(Value::Object(m)) if m.contains_key("org") => "орг",
        _ => "пакет",
    }
}

/// Уровень-источник значения признака (полностью).
pub fn source_full(row: &Value) -> &'static str {
    match row.get("source") {
        Some(Value::String(s)) if s == "installation" => "установка",
        Some(Value::Object(m)) if m.contains_key("org") => "организация",
        _ => "пакет",
    }
}

/// Текст детектора признака: имя варианта или JSON с параметрами.
pub fn detector_text(row: &Value) -> String {
    match row.get("detector") {
        Some(Value::String(s)) => s.clone(),
        Some(v @ Value::Object(_)) => v.to_string(),
        _ => "—".to_owned(),
    }
}

/// Колонки строки каталога: признак (⊘ — осиротевшее), вес, действие (▲ — «только отчёт»),
/// уровень-источник. Полные режим и источник — в строке состояния.
pub fn catalog_cells(row: &Value) -> [String; 4] {
    let id = id_of(row);
    let id = if orphaned(row) {
        format!("⊘{id}")
    } else {
        id
    };
    let weight = row
        .get("weight")
        .filter(|w| !w.is_null())
        .map(|w| w.to_string())
        .unwrap_or_else(|| "—".to_owned());
    let mut action = action_short(row.get("action").unwrap_or(&Value::Null)).to_owned();
    if report_only(row) {
        action = format!("▲{action}");
    }
    [id, weight, action, source_label(row).to_owned()]
}

// ---------- Пороги ----------

/// Источник действующих порогов: установка, организация или константы контракта.
pub fn threshold_source(v: Option<&Value>) -> &'static str {
    match v {
        Some(Value::String(s)) if s == "installation" => "установка",
        Some(Value::Object(m)) if m.contains_key("org") => "организация",
        _ => "константы контракта",
    }
}

/// Строка состояния вкладки порогов: заданы ли, действующие значения (порядок — в таблице) и источник.
pub fn thresholds_status(v: &Value) -> String {
    let own = v.get("own").filter(|o| o.is_object());
    let e = &v["effective"];
    let num = |name: &str| {
        e.get(name)
            .map(|x| x.to_string())
            .unwrap_or_else(|| "—".to_owned())
    };
    format!(
        "Пороги: {} · действуют {} / {} / {} / {} · источник: {}",
        if own.is_some() {
            "заданы"
        } else {
            "не заданы"
        },
        num("tag"),
        num("junk"),
        num("quarantine"),
        num("reject"),
        threshold_source(v.get("source")),
    )
}

// ---------- Пакеты ----------

/// Номер версии пакета.
pub fn version_of(row: &Value) -> Option<u64> {
    row.get("version").and_then(Value::as_u64)
}

/// Состояние пакета и отчёт отклонённого при проверке.
pub fn state_of(row: &Value) -> (&'static str, Option<&str>) {
    match row.get("state") {
        Some(Value::String(s)) if s == "active" => ("действующий", None),
        Some(Value::String(s)) if s == "previous" => ("прошлый", None),
        Some(Value::Object(m)) if m.contains_key("rejected") => (
            "отклонён",
            m.get("rejected")
                .and_then(|r| r.get("report"))
                .and_then(Value::as_str),
        ),
        _ => ("—", None),
    }
}

/// Колонки строки пакетов: версия и состояние.
pub fn package_cells(row: &Value) -> [String; 2] {
    let version = version_of(row)
        .map(|v| v.to_string())
        .unwrap_or_else(|| "—".to_owned());
    [version, state_of(row).0.to_owned()]
}

/// Строки отчёта проверки пакета: что проверено и что изменится при активации (до активации).
pub fn report_lines(report: &Value) -> Vec<String> {
    let u = &report["update"];
    let cnt = |name: &str| {
        u.get(name)
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0)
    };
    let names = |name: &str| {
        u.get(name)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    };
    let mut out = vec![
        format!(
            "Пакет версии {} проверен и поставлен, не активен",
            report.get("version").and_then(Value::as_u64).unwrap_or(0)
        ),
        format!(
            "Подпись Ed25519: ключ {} · пробный прогон: образцов {} · признаков в пакете {}",
            report.get("key_id").and_then(Value::as_str).unwrap_or("—"),
            report.get("samples").and_then(Value::as_u64).unwrap_or(0),
            report.get("signals").and_then(Value::as_u64).unwrap_or(0),
        ),
        format!(
            "Изменится при активации: добавлено {}, изменено {}, удалено {}, осиротевших изменений {}",
            cnt("added"),
            cnt("changed"),
            cnt("removed"),
            cnt("orphaned_overrides"),
        ),
    ];
    let added = names("added");
    if !added.is_empty() {
        out.push(format!("Новые признаки: {added}"));
    }
    out.push("Новые признаки поставщика приходят в режиме «только отчёт»".to_owned());
    out
}

// ---------- Источники TI ----------

/// Короткий уровень источника.
pub fn tier_short(v: &Value) -> &'static str {
    match v.as_str() {
        Some("bundled") => "поставка",
        Some("customer_key") => "ключ",
        Some("import") => "импорт",
        _ => "—",
    }
}

/// Уровень источника для строки состояния.
pub fn tier_full(v: &Value) -> &'static str {
    match v.as_str() {
        Some("bundled") => "в поставке",
        Some("customer_key") => "ключ заказчика",
        Some("import") => "импорт",
        _ => "—",
    }
}

/// Короткий формат фида.
pub fn format_short(v: &Value) -> &'static str {
    match v {
        Value::String(s) => match s.as_str() {
            "txt" => "txt",
            "rpz" => "rpz",
            "misp_feed" => "misp",
            "stix_21" => "stix",
            _ => "—",
        },
        Value::Object(m) if m.contains_key("csv") => "csv",
        _ => "—",
    }
}

/// Доставка источника для строки подробностей.
pub fn kind_text(row: &Value) -> String {
    match row.get("kind") {
        Some(Value::String(s)) if s == "file" => "файл в каталоге импорта".to_owned(),
        Some(Value::Object(m)) if m.contains_key("http") => m["http"]
            .get("url")
            .and_then(Value::as_str)
            .unwrap_or("http")
            .to_owned(),
        Some(Value::Object(m)) if m.contains_key("taxii") => {
            let root = m["taxii"]
                .get("api_root")
                .and_then(Value::as_str)
                .unwrap_or("taxii");
            format!("taxii: {root}")
        }
        _ => "—".to_owned(),
    }
}

/// Организации, которым доступен источник.
pub fn tenants_text(row: &Value) -> String {
    match row.get("tenants") {
        Some(Value::String(s)) if s == "all" => "доступен всем организациям".to_owned(),
        Some(Value::Object(m)) if m.contains_key("only") => {
            let n = m
                .get("only")
                .and_then(Value::as_array)
                .map(|a| a.len())
                .unwrap_or(0);
            format!("доступен {n} организациям")
        }
        _ => "—".to_owned(),
    }
}

/// Момент RFC 3339 (`2026-01-01T00:00:00Z`) в секундах от начала эпохи; не разобран — `None`.
pub fn rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let num = |from: usize, to: usize| s.get(from..to).and_then(|x| x.parse::<i64>().ok());
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    // Доли секунды пропускаем; зона — Z или ±HH:MM.
    let tail = s.get(19..).unwrap_or("");
    let tail = tail.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    let shift = match tail.as_bytes().first() {
        Some(b'Z') | Some(b'z') => 0,
        Some(b'+') | Some(b'-') => {
            let sign = if tail.starts_with('+') { -1 } else { 1 };
            let (oh, om) = (
                tail.get(1..3).and_then(|x| x.parse::<i64>().ok())?,
                tail.get(4..6).and_then(|x| x.parse::<i64>().ok())?,
            );
            sign * (oh * 3600 + om * 60)
        }
        _ => return None,
    };
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec + shift)
}

/// Число дней от начала эпохи для даты по григорианскому календарю (алгоритм Хиннанта).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Длительность humantime (`1h`, `30m`, `1h30m`) в секундах; не разобрана — `None`.
pub fn ttl_secs(s: &str) -> Option<i64> {
    let mut rest = s;
    let mut total = 0i64;
    while !rest.is_empty() {
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        let (num, tail) = rest.split_at(digits);
        let unit_len = usize::from(tail.starts_with("ms") || tail.starts_with("us"));
        let (unit, tail) = tail.split_at((unit_len + 1).min(tail.len()));
        let secs = match unit {
            "d" => 86_400,
            "h" => 3_600,
            "m" => 60,
            "s" => 1,
            // Доли секунды — меньше гранулярности свежести.
            "ms" | "us" | "ns" => 0,
            _ => return None,
        };
        total += num.parse::<i64>().ok()?.checked_mul(secs)?;
        rest = tail;
    }
    Some(total)
}

/// Свежесть данных источника против TTL: `Some(true)` — устарел, `Some(false)` — свеж, `None` —
/// сведений о загрузке нет (импорта и обновления в сеансе не было).
pub fn stale_at(fetched: &str, ttl: &str, now: i64) -> Option<bool> {
    let at = rfc3339(fetched)?;
    let ttl = ttl_secs(ttl)?;
    Some(now.saturating_sub(at).max(0) >= ttl)
}

/// Текущий момент в секундах от начала эпохи.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
        .unwrap_or(0)
}

/// Свежесть источника из состояния раздела.
pub fn stale(t: &Risk, id: &str) -> Option<bool> {
    let ttl = t
        .sources
        .as_deref()
        .unwrap_or(&[])
        .iter()
        .find(|s| s.get("id").and_then(Value::as_str) == Some(id))
        .and_then(|s| s.get("ttl"))
        .and_then(Value::as_str)?;
    let fetched = t.fetched.get(id)?;
    stale_at(fetched, ttl, now_unix())
}

/// Колонки строки источников: источник, уровень, формат, TTL и свежесть (▲ — устарел).
pub fn source_cells(t: &Risk, row: &Value) -> Vec<(String, bool)> {
    let id = id_of(row);
    let fresh = match stale(t, &id) {
        Some(true) => ("▲устарел".to_owned(), true),
        Some(false) => ("свеж".to_owned(), false),
        None => ("—".to_owned(), false),
    };
    vec![
        (id, false),
        (
            tier_short(row.get("tier").unwrap_or(&Value::Null)).to_owned(),
            false,
        ),
        (
            format_short(row.get("format").unwrap_or(&Value::Null)).to_owned(),
            false,
        ),
        (
            row.get("ttl")
                .and_then(Value::as_str)
                .unwrap_or("—")
                .to_owned(),
            false,
        ),
        fresh,
    ]
}

/// Действие при устаревании источника для строки состояния.
fn stale_action_text(row: &Value) -> String {
    match row.get("stale") {
        Some(Value::String(s)) if s == "report" => "признаки в «только отчёт»".to_owned(),
        Some(Value::Object(m)) if m.contains_key("reduce") => {
            let percent = m["reduce"]
                .get("percent")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            format!("вес снижается на {percent} %")
        }
        _ => String::new(),
    }
}

/// Колонки строки учёта источника: организация, обращения, совпадения.
pub fn usage_cells(row: &Value) -> [String; 3] {
    let text = |name: &str| {
        row.get(name)
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".to_owned())
    };
    [text("tenant"), text("lookups"), text("hits")]
}

// ---------- Срабатывания ----------

/// Момент срабатывания — `ГГГГ-ММ-ДД ЧЧ:ММ`.
pub fn at_short(v: &Value) -> String {
    v.as_str()
        .and_then(|s| s.get(..16.min(s.len())))
        .map(|s| s.replace('T', " "))
        .unwrap_or_default()
}

/// Колонки строки срабатываний: момент, признак, сила, вес, режим.
pub fn hit_cells(row: &Value) -> [String; 5] {
    let num = |name: &str| {
        row.get(name)
            .map(|v| v.to_string())
            .unwrap_or_else(|| "—".to_owned())
    };
    let mode = match row.get("mode").and_then(Value::as_str) {
        Some("report") => "▲отчёт".to_owned(),
        Some("enforce") => "примен".to_owned(),
        _ => "—".to_owned(),
    };
    [
        at_short(row.get("at").unwrap_or(&Value::Null)),
        id_of(row),
        num("strength"),
        num("weight"),
        mode,
    ]
}

// ---------- Строки экрана ----------

/// Строка состояния: выделенная запись вкладки. Знакам таблицы — «только отчёт» (▲) и «осиротевшее»
/// (⊘) — пояснение в этой строке; текст умещается в ширину состояния (76 колонок).
pub fn status(t: &Risk) -> String {
    match t.tab {
        Tab::Catalog => match t.rows().get(t.cur) {
            Some(row) => {
                let id = id_of(row);
                if orphaned(row) {
                    return format!("{id} — осиротевшее: признака нет в пакете · F8 — сброс");
                }
                if report_only(row) {
                    return format!("{id} — только отчёт: балл и действие не применяются");
                }
                let weight = row
                    .get("weight")
                    .filter(|w| !w.is_null())
                    .map(|w| w.to_string())
                    .unwrap_or_else(|| "—".to_owned());
                format!(
                    "{id} · вес {weight} · {} · {} · источник: {}",
                    action_short(row.get("action").unwrap_or(&Value::Null)),
                    mode_full(row.get("mode").unwrap_or(&Value::Null)),
                    source_full(row),
                )
            }
            None => "каталог признаков: признаки организации".to_owned(),
        },
        Tab::Thresholds => match t.thresholds.as_ref() {
            Some(v) => thresholds_status(v),
            None => "пороги действий организации".to_owned(),
        },
        Tab::Packages => match t.rows().get(t.cur) {
            Some(row) => {
                let (state, rejected) = state_of(row);
                let mut s = format!(
                    "Версия {} · {}",
                    version_of(row)
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "—".to_owned()),
                    state,
                );
                if let Some(r) = rejected {
                    s.push_str(&format!(": {r}"));
                }
                let staged = t
                    .report
                    .as_ref()
                    .and_then(|r| r.get("version"))
                    .and_then(Value::as_u64);
                if staged == version_of(row) {
                    s.push_str(" · поставлен, не активен — F5 активировать");
                } else if state == "прошлый" {
                    s.push_str(" · хранится для отката (F8)");
                }
                s
            }
            None => "пакеты поставщика: F7 — импорт файла с узла".to_owned(),
        },
        Tab::Sources => {
            if t.usage.is_some() {
                return "учёт источника по организациям: обращения и совпадения".to_owned();
            }
            match t.rows().get(t.cur) {
                Some(row) => {
                    let id = id_of(row);
                    let ttl = row.get("ttl").and_then(Value::as_str).unwrap_or("—");
                    let mut s = format!(
                        "{id} · {} · TTL {ttl}",
                        tier_full(row.get("tier").unwrap_or(&Value::Null)),
                    );
                    match stale(t, &id) {
                        Some(true) => {
                            let action = stale_action_text(row);
                            s.push_str(&format!(
                                " · устарел (TTL){}",
                                if action.is_empty() {
                                    String::new()
                                } else {
                                    format!(" — {action}")
                                }
                            ));
                        }
                        Some(false) => s.push_str(" · данные свежие"),
                        None => s.push_str(" · нет сведений о последней загрузке"),
                    }
                    s
                }
                None => "источники TI установки".to_owned(),
            }
        }
        Tab::Hits => match t.rows().get(t.cur) {
            Some(row) => {
                let num = |name: &str| {
                    row.get(name)
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "—".to_owned())
                };
                let mut s = format!(
                    "{} · {} · сила {} · вес {}",
                    at_short(row.get("at").unwrap_or(&Value::Null)),
                    id_of(row),
                    num("strength"),
                    num("weight"),
                );
                if report_only(row) {
                    s.push_str(" · только отчёт");
                }
                s
            }
            None => "срабатывания признаков в организации".to_owned(),
        },
    }
}

/// Подробности выделенной записи (строка 18): детектор признака или доставка источника.
pub fn detail_line(t: &Risk) -> Option<String> {
    match t.tab {
        Tab::Catalog => {
            let row = t.rows().get(t.cur)?;
            let mut s = format!("{} · детектор: {}", id_of(row), detector_text(row));
            if let Some(th) = row.get("threshold").filter(|v| !v.is_null()) {
                s.push_str(&format!(" · порог срабатывания {th}"));
            }
            Some(s)
        }
        Tab::Sources if t.usage.is_none() => {
            let row = t.rows().get(t.cur)?;
            Some(format!(
                "{} · {} · {}",
                id_of(row),
                kind_text(row),
                tenants_text(row),
            ))
        }
        _ => None,
    }
}

/// Подсказка под таблицей (строка 19).
pub fn hint(t: &Risk) -> &'static str {
    match t.tab {
        Tab::Catalog => "F4 — вес и действие · F8 — сброс · ←→ — вкладка",
        Tab::Thresholds => "F4 — заменить пороги · ←→ — вкладка",
        Tab::Packages if t.report.is_some() => {
            "F5 — активировать версию из отчёта · Esc — к списку"
        }
        Tab::Packages => "F7 — импорт файла с узла · F5 — активировать · F8 — откат",
        Tab::Sources if t.usage.is_some() => "Esc — к списку источников",
        Tab::Sources => "F5 — обновить сейчас · F6 — учёт · F7 — импорт списка",
        Tab::Hits => "F2 — фильтр · ↓ — ещё",
    }
}

/// Подписи F-клавиш раздела по вкладке.
pub fn key_labels(t: &Risk) -> [&'static str; 10] {
    match t.tab {
        Tab::Catalog => [
            "Помощь",
            "",
            "",
            "Правка",
            "",
            "",
            "",
            "Сброс",
            "Меню",
            "Выход",
        ],
        Tab::Thresholds => ["Помощь", "", "", "Правка", "", "", "", "", "Меню", "Выход"],
        Tab::Packages => [
            "Помощь",
            "",
            "",
            "",
            "Актив",
            "",
            "Импорт",
            "Откат",
            "Меню",
            "Выход",
        ],
        Tab::Sources => [
            "Помощь",
            "",
            "",
            "",
            "Обнов",
            "Учет",
            "Импорт",
            "",
            "Меню",
            "Выход",
        ],
        Tab::Hits => ["Помощь", "Фильтр", "", "", "", "", "", "", "Меню", "Выход"],
    }
}

/// Вопрос и пояснение окна подтверждения по действию.
pub fn confirm_text(p: &Pending) -> (&'static str, &'static str) {
    match p {
        Pending::ResetSignal(_) => (
            "Сбросить изменение признака?",
            "Признак получит значение пакета или уровня выше.",
        ),
        Pending::Activate(_) => (
            "Активировать пакет?",
            "Номер поставленного пакета больше действующего; отчёт проверки — на экране.",
        ),
        Pending::Rollback(_) => (
            "Откатить на хранимый пакет?",
            "Каталог вернётся к выбранной версии; номер новой поставки только растёт.",
        ),
        _ => ("Подтвердить?", ""),
    }
}

/// Эквивалентная команда `thepost admin risk …` для действия на экране (решение 118). Уровень
/// организации — всегда с `--org`: без ключа CLI выбирает уровень установки.
pub fn command(t: &Risk) -> String {
    let org = format!("--org {}", t.org);
    match t.tab {
        Tab::Catalog => match t.rows().get(t.cur).map(id_of) {
            Some(id) => format!("thepost admin risk signals set {id} {org}"),
            None => format!("thepost admin risk signals list {org}"),
        },
        Tab::Thresholds => format!("thepost admin risk thresholds show {org}"),
        Tab::Packages => {
            if let Some(ver) = t
                .report
                .as_ref()
                .and_then(|r| r.get("version"))
                .and_then(Value::as_u64)
            {
                format!("thepost admin risk package activate {ver}")
            } else {
                match t.rows().get(t.cur) {
                    Some(row) if state_of(row).0 == "действующий" => {
                        match version_of(row) {
                            Some(v) => format!("thepost admin risk package rollback {v}"),
                            None => "thepost admin risk package list".to_owned(),
                        }
                    }
                    Some(row) => match version_of(row) {
                        Some(v) => format!("thepost admin risk package activate {v}"),
                        None => "thepost admin risk package list".to_owned(),
                    },
                    None => "thepost admin risk package list".to_owned(),
                }
            }
        }
        Tab::Sources if t.usage.is_some() => match t
            .usage
            .as_ref()
            .and_then(|u| u.get("source"))
            .and_then(Value::as_str)
        {
            Some(id) => format!("thepost admin risk source usage {id}"),
            None => "thepost admin risk source list".to_owned(),
        },
        Tab::Sources => match t.rows().get(t.cur).map(id_of) {
            Some(id) => format!("thepost admin risk source refresh {id}"),
            None => "thepost admin risk source list".to_owned(),
        },
        Tab::Hits => {
            let mut s = format!("thepost admin risk hits {org}");
            for (k, v) in &t.hits_filter {
                s.push_str(&format!(" --{} {}", k.replace('_', "-"), v));
            }
            s
        }
    }
}

/// Команда импорта файла с узла для окна ввода пути (решение 118).
pub fn import_command(what: &ImportWhat) -> String {
    match what {
        ImportWhat::Package => "thepost admin risk package import <файл>".to_owned(),
        ImportWhat::Source(id) => format!("thepost admin risk source import {id} <файл>"),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::app::tests::{call, key, ok, section, who, with_accounts};
    use crate::app::{App, LoginForm, Stage};
    use crate::theme::{Brand, Theme};
    use serde_json::json;
    use tp_admin::server::AdminRole;

    pub(crate) const ORG: &str = "00000000-0000-0000-0000-000000000001";

    /// Каталог организации: свой признак, признак поставщика «только отчёт» и «осиротевшее» изменение
    /// (по возрастанию идентификатора, как отвечает сервер).
    pub(crate) fn catalog_json() -> Value {
        json!({"signals": [
            {"id": "org.bad_sender", "origin": "admin",
             "detector": {"list_match": {"list": "own", "field": "from_domain"}},
             "weight": 45, "threshold": 40, "action": "reject", "mode": "enforce",
             "since": "2026-11-10T08:00:00Z", "source": {"org": ORG}, "orphaned": false},
            {"id": "tp.encrypted_archive", "origin": "vendor", "detector": "encrypted_archive",
             "weight": 30, "threshold": 60, "action": "quarantine", "mode": "enforce",
             "since": "2026-11-14T09:00:00Z", "source": null, "orphaned": false},
            {"id": "tp.new_feed_match", "origin": "vendor",
             "detector": {"list_match": {"list": "feodo", "field": "sender_ip"}},
             "weight": 20, "threshold": 50, "action": "tag", "mode": "report",
             "since": "2026-11-19T10:00:00Z", "source": null, "orphaned": false},
            {"id": "tp.removed_signal", "origin": "vendor", "detector": null,
             "weight": 15, "threshold": null, "action": null, "mode": "report",
             "since": null, "source": "installation", "orphaned": true},
        ]})
    }

    /// Пороги организации: не заданы, действуют константы контракта.
    pub(crate) fn thresholds_json() -> Value {
        json!({"own": null, "effective": {"tag": 1, "junk": 6, "quarantine": 10, "reject": 15},
               "source": null})
    }

    /// Пакеты: поставленный (не активен) и действующий.
    pub(crate) fn packages_json() -> Value {
        json!({"packages": [
            {"version": 2, "state": "previous"},
            {"version": 1, "state": "active"},
        ]})
    }

    /// Отчёт проверки загруженного пакета версии 2 (до активации).
    pub(crate) fn report_json() -> Value {
        json!({"version": 2, "key_id": "vendor-2026", "samples": 12, "signals": 34,
               "update": {"added": ["tp.new_feed_match"], "removed": [],
                          "changed": ["tp.encrypted_archive"], "orphaned_overrides": []}})
    }

    /// Источники TI: в поставке (фид) и импорт (файл в закрытом контуре).
    pub(crate) fn sources_json() -> Value {
        json!({"sources": [
            {"id": "abuse_ch_feodo", "tier": "bundled",
             "kind": {"http": {"url": "https://feodotracker.example/ipblocklist"}},
             "format": "txt", "ttl": "1h", "stale": {"reduce": {"percent": 50}},
             "license": {"terms_url": "https://abuse.ch", "attribution": "© abuse.ch",
                         "commercial": true},
             "tenants": "all", "key": null, "auth": "none", "origin": "vendor"},
            {"id": "own_list", "tier": "import", "kind": "file",
             "format": {"csv": {"column": "indicator"}}, "ttl": "30m", "stale": "report",
             "license": {"terms_url": "https://example.org", "attribution": null,
                         "commercial": false},
             "tenants": {"only": [ORG]}, "key": null, "auth": "none", "origin": "own"},
        ]})
    }

    /// Версия списка источника, ставшая текущей (ответ импорта и обновления).
    pub(crate) fn list_version_json(fetched_at: &str) -> Value {
        json!({"list": "own_list", "source": "own_list", "sha256": "abc123", "blob": "b1",
               "entries": 42, "fetched_at": fetched_at, "tlp": "green"})
    }

    /// Срабатывания организации: применённое и «только отчёт».
    pub(crate) fn hits_json() -> Value {
        json!({"hits": [
            {"message": "m1", "signal": "tp.encrypted_archive", "strength": 80, "weight": 30,
             "mode": "enforce", "at": "2026-11-19T12:00:00Z"},
            {"message": "m2", "signal": "tp.new_feed_match", "strength": 55, "weight": 20,
             "mode": "report", "at": "2026-11-19T11:00:00Z"},
        ], "next": "2026-11-19T11:00:00Z"})
    }

    /// Вошедший интерфейс с открытым разделом «Признаки риска» (каталог организации).
    pub(crate) fn with_risk() -> App {
        let mut app = with_accounts();
        let id = call(&section(&mut app, "Признаки риска"), "list_org_signals");
        app.on_result(id, ok(catalog_json()));
        app
    }

    /// Вошедший администратор установки с открытым разделом «Признаки риска».
    pub(crate) fn with_install() -> App {
        let mut app = App::new(
            Theme::new(crate::theme::Mode::Dark, Brand::default()),
            LoginForm::new("https://node:9443".into(), false),
        );
        let mut admin = who();
        admin.roles = vec![AdminRole::InstallationAdmin];
        let fx = app.on_login(Ok((admin, "node:9443".into())));
        let ids: Vec<u64> = fx
            .iter()
            .filter_map(|e| match e {
                Effect::Call(id, _) => Some(*id),
                _ => None,
            })
            .collect();
        app.on_result(ids[0], ok(json!([{"id": ORG, "default": true}])));
        app.on_result(ids[1], ok(json!([])));
        let id = call(&section(&mut app, "Признаки риска"), "list_org_signals");
        app.on_result(id, ok(catalog_json()));
        app
    }

    pub(crate) fn risk_of(app: &App) -> &Risk {
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let View::Risk(t) = &m.view else {
            panic!("не раздел «Признаки риска»");
        };
        t
    }

    pub(crate) fn risk_mut(app: &mut App) -> &mut Risk {
        let Stage::Main(m) = &mut app.stage else {
            panic!("не основной экран");
        };
        let View::Risk(t) = &mut m.view else {
            panic!("не раздел «Признаки риска»");
        };
        t
    }

    /// Курсор на признак `id`.
    fn at_signal(app: &mut App, id: &str) {
        let t = risk_mut(app);
        let i = t
            .rows()
            .iter()
            .position(|r| id_of(r) == id)
            .unwrap_or_else(|| panic!("нет признака {id}"));
        t.select(i);
    }

    /// Отказ 422 (problem+json с `detail`).
    pub(crate) fn refused(detail: &str) -> Result<Page, tp_admin_client::Error> {
        Err(tp_admin_client::Error::Api {
            status: 422,
            problem: Some(tp_admin::server::Problem {
                status: 422,
                title: "Unprocessable Entity".into(),
                detail: Some(detail.to_owned()),
            }),
            message: "PUT: 422".into(),
        })
    }

    /// Операции раздела есть в схеме Admin API.
    #[test]
    fn risk_operations_in_schema() {
        for id in [
            "list_installation_signals",
            "put_installation_signal",
            "reset_installation_signal",
            "list_org_signals",
            "put_org_signal",
            "reset_org_signal",
            "get_installation_thresholds",
            "put_installation_thresholds",
            "get_org_thresholds",
            "put_org_thresholds",
            "list_packages",
            "upload_package",
            "activate_package",
            "rollback_package",
            "list_ti_sources",
            "create_source",
            "get_source",
            "put_source",
            "delete_source",
            "import_source",
            "refresh_source",
            "source_usage",
            "list_risk_hits",
        ] {
            assert!(catalog().get(id).is_some(), "{id}: нет в схеме");
        }
    }

    /// Раздел открывается из дерева: каталог организации прочитан, знаки и строка состояния — на месте.
    #[test]
    fn section_opens_catalog() {
        let app = with_risk();
        let t = risk_of(&app);
        assert_eq!(t.tab, Tab::Catalog);
        assert_eq!(t.rows().len(), 4);
        assert_eq!(t.cur, 0);
        // Признак поставщика «только отчёт» — знак ▲ у действия.
        let row = &t.rows()[2];
        assert_eq!(id_of(row), "tp.new_feed_match");
        assert!(report_only(row));
        assert_eq!(catalog_cells(row)[2], "▲пометка");
        // «Осиротевшее» изменение — знак ⊘ у признака.
        let row = &t.rows()[3];
        assert!(orphaned(row));
        assert_eq!(catalog_cells(row)[0], "⊘tp.removed_signal");
        // Строка CLI и пояснение курсора.
        assert!(!command(t).is_empty(), "строка CLI не пуста");
        assert!(status(t).contains("tp.encrypted_archive"));
    }

    /// Строка состояния каталога: «только отчёт» и «осиротевшее» — с пояснением; строки умещаются
    /// в ширину состояния.
    #[test]
    fn status_explains_marks() {
        let mut app = with_risk();
        at_signal(&mut app, "tp.new_feed_match");
        let s = status(risk_of(&app));
        assert!(s.contains("только отчёт"), "{s}");
        assert!(s.contains("балл и действие не применяются"), "{s}");
        at_signal(&mut app, "tp.removed_signal");
        let s = status(risk_of(&app));
        assert!(s.contains("осиротевшее"), "{s}");
        assert!(s.contains("признака нет в пакете"), "{s}");
        at_signal(&mut app, "tp.encrypted_archive");
        let s = status(risk_of(&app));
        assert!(s.contains("вес 30"), "{s}");
        assert!(s.contains("источник: пакет"), "{s}");
        // Строка состояния рисуется в 76 колонках (меньше ширины экрана).
        for id in [
            "tp.encrypted_archive",
            "tp.new_feed_match",
            "tp.removed_signal",
        ] {
            at_signal(&mut app, id);
            assert!(
                status(risk_of(&app)).chars().count() <= 76,
                "{id}: {}",
                status(risk_of(&app))
            );
        }
    }

    /// F4: форма веса, действия и режима; вес организации ниже установки — 422, текст `detail`
    /// сервера у поля; повторная запись проходит, каталог перечитывается.
    #[test]
    fn f4_weight_below_installation_refused() {
        let mut app = with_risk();
        at_signal(&mut app, "tp.encrypted_archive");
        assert_eq!(
            app.command_line(),
            format!("thepost admin risk signals set tp.encrypted_archive --org {ORG}"),
            "строка CLI соответствует действию"
        );
        assert!(app.on_key(key(KeyCode::F(4))).is_empty());
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::RiskSignalEdit { form }) = &m.overlay else {
            panic!("нет формы признака");
        };
        let names: Vec<&str> = form.fields.iter().map(|f| f.field.name.as_str()).collect();
        assert_eq!(names, ["weight", "action", "mode"]);
        assert_eq!(form.value("weight"), Some("30"));
        assert_eq!(form.value("action"), Some("quarantine"));
        // Вес ниже установки: 20 вместо 30.
        app.on_key(key(KeyCode::Backspace));
        app.on_key(key(KeyCode::Backspace));
        for c in "20".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет записи: {fx:?}");
        };
        assert_eq!(req.op.id, "put_org_signal");
        assert_eq!(req.param("id"), Some("tp.encrypted_archive"));
        assert_eq!(
            req.body,
            Some(json!({"weight": 20, "action": "quarantine", "mode": "enforce"}))
        );
        // Организация смягчила вес — 422 с `errors`; текст `detail` у поля.
        app.on_result(
            *id,
            refused(
                "организация может только ужесточить: tp.encrypted_archive.weight = 20 (базовое 30)",
            ),
        );
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::RiskSignalEdit { form }) = &m.overlay else {
            panic!("форма не вернулась");
        };
        assert_eq!(
            form.value("weight"),
            Some("20"),
            "введённое значение сохранено"
        );
        let weight = form
            .fields
            .iter()
            .find(|f| f.field.name == "weight")
            .expect("поле веса");
        assert_eq!(
            weight.error.as_deref(),
            Some(
                "организация может только ужесточить: tp.encrypted_archive.weight = 20 (базовое 30)"
            ),
            "текст detail у поля веса"
        );
        // Повторная запись проходит: форма закрыта, каталог перечитан.
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, _)] = fx.as_slice() else {
            panic!("нет повторной записи: {fx:?}");
        };
        let fx = app.on_result(*id, ok(json!({"id": "tp.encrypted_archive", "weight": 40})));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет перечитывания: {fx:?}");
        };
        assert_eq!(req.op.id, "list_org_signals");
        app.on_result(*id, ok(catalog_json()));
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        assert!(m.overlay.is_none(), "форма закрыта");
        assert_eq!(
            app.status().map(|(_, s)| s.as_str()),
            Some("готово: изменение признака записано")
        );
    }

    /// F4 у своего признака `org.*`: форма целиком — детектор, вес, порог, действие и режим.
    #[test]
    fn f4_own_signal_full_form() {
        let mut app = with_risk();
        at_signal(&mut app, "org.bad_sender");
        assert!(app.on_key(key(KeyCode::F(4))).is_empty());
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::RiskSignalEdit { form }) = &m.overlay else {
            panic!("нет формы признака");
        };
        let names: Vec<&str> = form.fields.iter().map(|f| f.field.name.as_str()).collect();
        assert_eq!(
            names,
            ["detector", "weight", "threshold", "action", "mode"],
            "свой признак задаётся целиком"
        );
        assert!(
            form.value("detector")
                .is_some_and(|d| d.contains("list_match")),
            "детектор предзаполнен: {:?}",
            form.value("detector")
        );
    }

    /// F8: сброс изменения признака с подтверждением; у признака пакета без изменений —
    /// предупреждение, строка CLI — команда сброса.
    #[test]
    fn f8_reset_signal_with_confirm() {
        let mut app = with_risk();
        // У признака пакета изменения нет — сбрасывать нечего.
        at_signal(&mut app, "tp.encrypted_archive");
        assert!(app.on_key(key(KeyCode::F(8))).is_empty());
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        assert!(m.overlay.is_none(), "подтверждения нет");
        assert_eq!(
            app.status().map(|(_, s)| s.as_str()),
            Some("изменения на уровне нет — сбрасывать нечего")
        );
        // «Осиротевшее» изменение уровня установки — подтверждение и `DELETE`.
        at_signal(&mut app, "tp.removed_signal");
        assert!(app.on_key(key(KeyCode::F(8))).is_empty());
        assert_eq!(
            app.command_line(),
            format!("thepost admin risk signals reset tp.removed_signal --org {ORG}")
        );
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::RiskConfirm { req, p }) = &m.overlay else {
            panic!("нет подтверждения сброса");
        };
        assert_eq!(req.op.id, "reset_org_signal");
        assert!(matches!(p, Pending::ResetSignal(_)));
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет сброса: {fx:?}");
        };
        assert_eq!(req.op.id, "reset_org_signal");
        assert_eq!(req.param("id"), Some("tp.removed_signal"));
        let fx = app.on_result(*id, ok(json!({"id": "tp.removed_signal"})));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет перечитывания: {fx:?}");
        };
        assert_eq!(req.op.id, "list_org_signals");
        app.on_result(*id, ok(catalog_json()));
    }

    /// Вкладки стрелками ← →: администратор организации не видит «Пакеты» и «Источники» (403),
    /// администратор установки — видит; каждая вкладка читается.
    #[test]
    fn tabs_by_level() {
        let mut app = with_risk();
        // Организация: Каталог → Пороги → Срабатывания (мимо пакетов и источников).
        let fx = app.on_key(key(KeyCode::Right));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет чтения порогов: {fx:?}");
        };
        assert_eq!(req.op.id, "get_org_thresholds");
        app.on_result(*id, ok(thresholds_json()));
        assert_eq!(risk_of(&app).tab, Tab::Thresholds);
        let fx = app.on_key(key(KeyCode::Right));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет чтения срабатываний: {fx:?}");
        };
        assert_eq!(req.op.id, "list_risk_hits");
        app.on_result(*id, ok(hits_json()));
        assert_eq!(risk_of(&app).tab, Tab::Hits);
        assert_eq!(
            app.status().map(|(_, s)| s.to_owned()),
            Some("пакеты и источники — администратору установки".to_owned()),
            "мимо закрытых вкладок — предупреждение"
        );
        let fx = app.on_key(key(KeyCode::Left));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет чтения порогов: {fx:?}");
        };
        assert_eq!(req.op.id, "get_org_thresholds");
        app.on_result(*id, ok(thresholds_json()));

        // Администратор установки: Пороги → Пакеты → Источники → Срабатывания.
        let mut app = with_install();
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "get_org_thresholds");
        app.on_result(id, ok(thresholds_json()));
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "list_packages");
        app.on_result(id, ok(packages_json()));
        assert_eq!(risk_of(&app).tab, Tab::Packages);
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "list_ti_sources");
        app.on_result(id, ok(sources_json()));
        assert_eq!(risk_of(&app).tab, Tab::Sources);
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "list_risk_hits");
        app.on_result(id, ok(hits_json()));
        assert_eq!(risk_of(&app).tab, Tab::Hits);
    }

    /// Свежесть источника: TTL против момента загрузки; устаревший — знак ▲.
    #[test]
    fn stale_source_by_ttl() {
        let mut app = with_install();
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "get_org_thresholds");
        app.on_result(id, ok(thresholds_json()));
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "list_packages");
        app.on_result(id, ok(packages_json()));
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "list_ti_sources");
        app.on_result(id, ok(sources_json()));
        let t = risk_of(&app);
        // Сведений о загрузке ещё нет — свежесть неизвестна.
        assert_eq!(stale(t, "own_list"), None);
        // Обновить сейчас: момент загрузки далеко в прошлом, TTL 30m — устарел.
        at_signal(&mut app, "own_list");
        assert_eq!(
            app.command_line(),
            "thepost admin risk source refresh own_list",
            "строка CLI соответствует действию"
        );
        let fx = app.on_key(key(KeyCode::F(5)));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет обновления: {fx:?}");
        };
        assert_eq!(req.op.id, "refresh_source");
        assert_eq!(req.param("id"), Some("own_list"));
        let fx = app.on_result(*id, ok(list_version_json("2020-01-01T00:00:00Z")));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет перечитывания: {fx:?}");
        };
        assert_eq!(req.op.id, "list_ti_sources");
        app.on_result(*id, ok(sources_json()));
        let t = risk_of(&app);
        assert_eq!(stale(t, "own_list"), Some(true));
        let row = t.rows().get(t.cur).expect("источник");
        let cells = source_cells(t, row);
        assert_eq!(cells[4], ("▲устарел".to_owned(), true), "знак устаревания");
        let s = status(t);
        assert!(s.contains("устарел (TTL)"), "{s}");
        assert!(s.contains("признаки в «только отчёт»"), "{s}");
        assert!(s.chars().count() <= 76, "{s}");
    }

    /// Чистая функция свежести: момент RFC 3339 и TTL humantime (now — 2026-11-19T13:00:00Z).
    #[test]
    fn stale_at_pure() {
        let now = 1_795_093_200;
        assert_eq!(stale_at("2026-11-19T12:00:00Z", "1h", now), Some(true));
        assert_eq!(
            stale_at("2026-11-19T12:30:00.500Z", "1h", now),
            Some(false),
            "доли секунды не мешают разбору"
        );
        assert_eq!(
            stale_at("2026-11-19T15:00:00+02:00", "1h", now),
            Some(false),
            "зона сдвигает момент"
        );
        assert_eq!(stale_at("2026-11-19T12:00:00Z", "1h30m", now), Some(false));
        assert_eq!(stale_at("мусор", "1h", now), None);
        assert_eq!(stale_at("2026-11-19T12:00:00Z", "мусор", now), None);
    }

    /// Импорт файла пакета с узла: путь — полем ввода; отчёт проверки показан до активации;
    /// активация и откат — с подтверждением.
    #[test]
    fn package_import_report_then_activate() {
        let mut app = with_install();
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "get_org_thresholds");
        app.on_result(id, ok(thresholds_json()));
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "list_packages");
        app.on_result(id, ok(packages_json()));
        assert_eq!(
            app.command_line(),
            "thepost admin risk package activate 2",
            "курсор на поставленном (не активном) — команда активации"
        );
        // F7 — импорт файла с узла: путь полем ввода.
        assert!(app.on_key(key(KeyCode::F(7))).is_empty());
        assert_eq!(
            app.command_line(),
            "thepost admin risk package import <файл>"
        );
        for c in "/opt/pkgs/vendor-2.pkg".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let [
            Effect::Import {
                id,
                op,
                params,
                path,
            },
        ] = fx.as_slice()
        else {
            panic!("нет загрузки файла: {fx:?}");
        };
        assert_eq!(op.id, "upload_package");
        assert!(params.is_empty());
        assert_eq!(path, "/opt/pkgs/vendor-2.pkg");
        // Файл принят (202): отчёт проверки и перечитывание списка.
        let fx = app.on_result(*id, ok(report_json()));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет перечитывания: {fx:?}");
        };
        assert_eq!(req.op.id, "list_packages");
        app.on_result(*id, ok(packages_json()));
        {
            let t = risk_of(&app);
            let rep = t.report.as_ref().expect("отчёт проверки");
            let lines = report_lines(rep);
            assert!(lines[0].contains("версии 2"), "{}", lines[0]);
            assert!(lines[2].contains("добавлено 1"), "{}", lines[2]);
            assert_eq!(t.cur, 0, "курсор на поставленном пакете");
        }
        assert_eq!(
            app.command_line(),
            "thepost admin risk package activate 2",
            "строка CLI соответствует действию"
        );
        assert!(status(risk_of(&app)).contains("поставлен, не активен"));
        // Активация — с подтверждением.
        assert!(app.on_key(key(KeyCode::F(5))).is_empty());
        assert_eq!(app.command_line(), "thepost admin risk package activate 2");
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::RiskConfirm { req, p }) = &m.overlay else {
            panic!("нет подтверждения активации");
        };
        assert_eq!(req.op.id, "activate_package");
        assert_eq!(req.param("version"), Some("2"));
        assert!(matches!(p, Pending::Activate(2)));
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет активации: {fx:?}");
        };
        assert_eq!(req.op.id, "activate_package");
        // Ответ — пакеты: активный 2, прошлый 1; отчёт закрыт.
        let fx = app.on_result(
            *id,
            ok(json!({"packages": [
                {"version": 2, "state": "active"},
                {"version": 1, "state": "previous"},
            ]})),
        );
        assert!(fx.is_empty());
        let t = risk_of(&app);
        assert!(t.report.is_none(), "отчёт закрыт после активации");
        assert_eq!(state_of(t.rows().first().expect("пакет")).0, "действующий");
        assert!(
            app.status()
                .map(|(_, s)| s.contains("активирован"))
                .unwrap_or(false)
        );
        // Откат на прошлый — с подтверждением.
        let fx = app.on_key(key(KeyCode::Down));
        assert!(fx.is_empty());
        assert_eq!(
            app.command_line(),
            "thepost admin risk package activate 1",
            "прошлый пакет — активация"
        );
        assert!(app.on_key(key(KeyCode::F(8))).is_empty());
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::RiskConfirm { req, p }) = &m.overlay else {
            panic!("нет подтверждения отката");
        };
        assert_eq!(req.op.id, "rollback_package");
        assert!(matches!(p, Pending::Rollback(1)));
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет отката: {fx:?}");
        };
        assert_eq!(req.op.id, "rollback_package");
        app.on_result(*id, ok(packages_json()));
    }

    /// Импорт файла с узла: отказ чтения файла и отказ сервера — текст у поля пути.
    #[test]
    fn import_error_at_path_field() {
        let mut app = with_install();
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "get_org_thresholds");
        app.on_result(id, ok(thresholds_json()));
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "list_packages");
        app.on_result(id, ok(packages_json()));
        assert!(app.on_key(key(KeyCode::F(7))).is_empty());
        // Пустой путь — ошибка у поля.
        assert!(app.on_key(key(KeyCode::Enter)).is_empty());
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::RiskImport { error, .. }) = &m.overlay else {
            panic!("окно импорта не вернулось");
        };
        assert_eq!(
            error.as_deref(),
            Some("введите путь к файлу на узле"),
            "ошибка у поля пути"
        );
        // Отказ сервера (чужая подпись) — текст у поля пути.
        for c in "/tmp/pkg.pkg".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Import { id, .. }] = fx.as_slice() else {
            panic!("нет загрузки файла: {fx:?}");
        };
        let id = *id;
        app.on_result(
            id,
            refused("пакет: чужая подпись, ключ trusted не соответствует манифесту"),
        );
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::RiskImport { path, error, .. }) = &m.overlay else {
            panic!("окно импорта не вернулось");
        };
        assert_eq!(path, "/tmp/pkg.pkg");
        assert_eq!(
            error.as_deref(),
            Some("пакет: чужая подпись, ключ trusted не соответствует манифесту")
        );
    }

    /// Источники: импорт списка файлом и учёт по организациям; Esc закрывает учёт.
    #[test]
    fn source_import_and_usage() {
        let mut app = with_install();
        for op in ["get_org_thresholds", "list_packages"] {
            let fx = app.on_key(key(KeyCode::Right));
            let id = call(&fx, op);
            let value = if op == "get_org_thresholds" {
                thresholds_json()
            } else {
                packages_json()
            };
            app.on_result(id, ok(value));
        }
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "list_ti_sources");
        app.on_result(id, ok(sources_json()));
        at_signal(&mut app, "own_list");
        // F7 — путь к файлу списка на узле.
        assert!(app.on_key(key(KeyCode::F(7))).is_empty());
        assert_eq!(
            app.command_line(),
            "thepost admin risk source import own_list <файл>"
        );
        for c in "/var/import/own.csv".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let [
            Effect::Import {
                id,
                op,
                params,
                path,
            },
        ] = fx.as_slice()
        else {
            panic!("нет загрузки файла: {fx:?}");
        };
        assert_eq!(op.id, "import_source");
        assert_eq!(params, &["own_list".to_owned()]);
        assert_eq!(path, "/var/import/own.csv");
        // Ответ — версия списка: момент загрузки запоминается для свежести.
        let fx = app.on_result(*id, ok(list_version_json("2999-01-01T00:00:00Z")));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет перечитывания: {fx:?}");
        };
        assert_eq!(req.op.id, "list_ti_sources");
        app.on_result(*id, ok(sources_json()));
        let t = risk_of(&app);
        assert_eq!(stale(t, "own_list"), Some(false), "свежий после импорта");
        let row = t.rows().get(t.cur).expect("источник");
        assert_eq!(source_cells(t, row)[4], ("свеж".to_owned(), false));
        // F6 — учёт по организациям.
        let fx = app.on_key(key(KeyCode::F(6)));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет учёта: {fx:?}");
        };
        assert_eq!(req.op.id, "source_usage");
        assert_eq!(req.param("id"), Some("own_list"));
        assert_eq!(
            app.command_line(),
            "thepost admin risk source usage own_list",
            "строка CLI — команда учёта"
        );
        app.on_result(
            *id,
            ok(
                json!({"source": "own_list", "since": "2026-11-01T00:00:00Z",
                      "usage": [{"tenant": ORG, "lookups": 120, "hits": 7}]}),
            ),
        );
        let t = risk_of(&app);
        assert!(t.usage.is_some());
        assert!(status(t).contains("учёт источника"), "{}", status(t));
        // Esc — к списку источников.
        assert!(app.on_key(key(KeyCode::Esc)).is_empty());
        assert!(risk_of(&app).usage.is_none());
    }

    /// Срабатывания: фильтр F2 и листание по `next` (параметр `until`); строка CLI — с условиями.
    #[test]
    fn hits_filter_and_paging() {
        let mut app = with_risk();
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "get_org_thresholds");
        app.on_result(id, ok(thresholds_json()));
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "list_risk_hits");
        app.on_result(id, ok(hits_json()));
        assert_eq!(risk_of(&app).rows().len(), 2);
        assert_eq!(
            app.command_line(),
            format!("thepost admin risk hits --org {ORG}")
        );
        // ↓ на последней строке — следующая страница по `until`.
        let fx = app.on_key(key(KeyCode::Down));
        assert!(fx.is_empty(), "курсор на вторую строку");
        let fx = app.on_key(key(KeyCode::Down));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет следующей страницы: {fx:?}");
        };
        assert_eq!(req.op.id, "list_risk_hits");
        assert_eq!(
            req.query,
            [("until".to_owned(), "2026-11-19T11:00:00Z".to_owned())]
        );
        app.on_result(
            *id,
            ok(
                json!({"hits": [{"message": "m3", "signal": "tp.encrypted_archive", "strength": 40,
                                "weight": 30, "mode": "enforce", "at": "2026-11-19T10:00:00Z"}],
                      "next": null}),
            ),
        );
        let t = risk_of(&app);
        assert_eq!(t.rows().len(), 3);
        assert_eq!(t.hits_next, None);
        // F2 — фильтр по признаку.
        assert!(app.on_key(key(KeyCode::F(2))).is_empty());
        let has_fields = {
            let Stage::Main(m) = &app.stage else {
                panic!("не основной экран");
            };
            let Some(Overlay::RiskFilter { form }) = &m.overlay else {
                panic!("нет формы фильтра");
            };
            let ok = form.fields.iter().any(|f| f.field.name == "signal")
                && form.fields.iter().any(|f| f.field.name == "mode");
            ok
        };
        assert!(has_fields, "поля фильтра из схемы");
        {
            let Stage::Main(m) = &mut app.stage else {
                panic!("не основной экран");
            };
            let Some(Overlay::RiskFilter { form }) = &mut m.overlay else {
                panic!("нет формы фильтра");
            };
            assert!(form.set("signal", "tp.encrypted_archive"));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет фильтра: {fx:?}");
        };
        assert_eq!(
            req.query,
            [("signal".to_owned(), "tp.encrypted_archive".to_owned())]
        );
        let fx = app.on_result(*id, ok(hits_json()));
        assert!(fx.is_empty());
        let t = risk_of(&app);
        assert_eq!(
            t.hits_filter,
            [("signal".to_owned(), "tp.encrypted_archive".to_owned())]
        );
        assert!(app.command_line().contains("--signal tp.encrypted_archive"));
    }

    /// F4 порогов: форма замены целиком, отказ 422 — текст у поля порога.
    #[test]
    fn thresholds_edit_422_at_field() {
        let mut app = with_risk();
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "get_org_thresholds");
        app.on_result(id, ok(thresholds_json()));
        assert!(app.on_key(key(KeyCode::F(4))).is_empty());
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::RiskThresholds { form }) = &m.overlay else {
            panic!("нет формы порогов");
        };
        let names: Vec<&str> = form.fields.iter().map(|f| f.field.name.as_str()).collect();
        assert_eq!(names, ["tag", "junk", "quarantine", "reject"]);
        assert_eq!(form.value("tag"), Some("1"), "предзаполнено действующими");
        assert_eq!(form.value("junk"), Some("6"));
        // Курсор на поле junk и значение выше базового: 12 вместо 6.
        let junk = form.fields.iter().position(|f| f.field.name == "junk");
        drop(&m);
        if let Some(junk) = junk {
            let Stage::Main(m) = &mut app.stage else {
                panic!("не основной экран");
            };
            let Some(Overlay::RiskThresholds { form }) = &mut m.overlay else {
                panic!("нет формы порогов");
            };
            form.focus = junk;
        }
        app.on_key(key(KeyCode::Backspace));
        for c in "12".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет записи порогов: {fx:?}");
        };
        assert_eq!(req.op.id, "put_org_thresholds");
        assert_eq!(
            req.body,
            Some(json!({"tag": 1, "junk": 12, "quarantine": 10, "reject": 15}))
        );
        assert_eq!(
            app.command_line(),
            format!("thepost admin risk thresholds set --org {ORG}"),
            "строка CLI соответствует действию"
        );
        // Организация подняла порог (действие позже) — 422, текст у поля junk.
        app.on_result(
            *id,
            refused(
                "порог junk = 12 выше базового 6: организация может только ужесточить (порог ниже — действие раньше)",
            ),
        );
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::RiskThresholds { form }) = &m.overlay else {
            panic!("форма не вернулась");
        };
        let junk = form
            .fields
            .iter()
            .find(|f| f.field.name == "junk")
            .expect("junk");
        assert_eq!(form.focus, 1, "курсор у поля с отказом");
        assert!(
            junk.error
                .as_deref()
                .is_some_and(|e| e.contains("выше базового 6")),
            "текст detail у поля порога"
        );
        // Исправление на 2 (ниже базового) проходит: пороги перечитаны.
        app.on_key(key(KeyCode::Backspace));
        app.on_key(key(KeyCode::Backspace));
        for c in "2".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет повторной записи: {fx:?}");
        };
        assert_eq!(req.op.id, "put_org_thresholds");
        assert_eq!(
            req.body,
            Some(json!({"tag": 1, "junk": 2, "quarantine": 10, "reject": 15}))
        );
        let fx = app.on_result(*id, ok(thresholds_json()));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет перечитывания: {fx:?}");
        };
        assert_eq!(req.op.id, "get_org_thresholds");
        app.on_result(*id, ok(thresholds_json()));
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        assert!(m.overlay.is_none());
    }

    /// Пороги: строка состояния с действующими значениями и источником.
    #[test]
    fn thresholds_status_line() {
        let mut app = with_risk();
        let fx = app.on_key(key(KeyCode::Right));
        let id = call(&fx, "get_org_thresholds");
        app.on_result(id, ok(thresholds_json()));
        let s = status(risk_of(&app));
        assert!(s.contains("не заданы"), "{s}");
        assert!(s.contains("1 / 6 / 10 / 15"), "{s}");
        assert!(s.contains("константы"), "{s}");
    }
}
