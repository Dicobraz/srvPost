//! Раздел «Доверие» (TUI-09, решение 124): ручная раскладка — движок форм по схеме матрицу не покажет.
//!
//! Таблица функций × четыре типа абонентов (контракт `tp_contracts::trust`, маршруты ADM-49), курсор по клеткам
//! стрелками; F4 — следующее допустимое значение (выше потолка уровня выше не предлагаются), закреплённые
//! клетки — знак ⊘ и пояснение в строке состояния; «выше потолка» — знак ▲ и цвет роли «внимание». F5 —
//! уровень (организация → группа → установка у администратора установки), F8 — сброс уровня с
//! подтверждением; вкладка «Партнёры» (F2) — домены-партнёры и домены автопересылки (F7 — добавить, F8 —
//! удалить); F6 — действующая матрица учётной записи с источником клетки. Ошибка 422 — текст `detail`
//! сервера у клетки (строки 14–16 и строка состояния). Внизу — эквивалентная команда
//! `thepost admin trust …` (решение 118). Сети нет: действия возвращают эффекты через [`crate::app::Bus`].
//! Ответы Admin API разбираются как JSON (тонкий клиент по схеме): порядок значений клеток, таблица функций
//! и закреплённые клетки контракта продублированы константами этого модуля, соответствие контракту — тесты.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::{Map, Value};

use crate::app::{Bus, Effect, Level, Main, Overlay, Page, Pending as Sent, View};
use crate::engine::{Context, Form, Request};
use crate::schema::catalog;

/// Ширина колонки подписи функции.
pub const LABEL_W: u16 = 7;
/// Ширина колонки типа абонента.
pub const CELL_W: u16 = 8;

/// `operationId` операции-раздела дерева («Доверие»).
pub const SECTION_OP: &str = "get_org_trust";

/// Функция матрицы: подпись в таблице (сокращённая), полное название для строки состояния и допустимые
/// значения от узкого к широкому (как в JSON контракта).
#[derive(Debug)]
pub struct FnDef {
    /// Имя клетки в JSON и сообщениях об ошибке (`invite_new`, `freebusy`, …).
    pub f: &'static str,
    /// Подпись строки (до [`LABEL_W`] знаков).
    pub short: &'static str,
    /// Полное название — в строке состояния.
    pub full: &'static str,
    /// Значения от узкого к широкому; допустимо не выше потолка.
    pub values: &'static [&'static str],
}

/// Функции матрицы по порядку (строки таблицы).
pub const FUNCTIONS: [FnDef; 8] = [
    FnDef {
        f: "invite_new",
        short: "Приглаш",
        full: "Новое приглашение",
        values: &["button", "auto"],
    },
    FnDef {
        f: "itip_updates",
        short: "Ответы",
        full: "Ответ и отмена",
        values: &["off", "on"],
    },
    FnDef {
        f: "auto_reply",
        short: "Автоотв",
        full: "Автоответ",
        // «Только ответ на наше письмо» — решение 125 а, лишь у клеток автоответа и MDN.
        values: &["off", "reply_only", "on"],
    },
    FnDef {
        f: "mdn",
        short: "MDN",
        full: "Уведомление о прочтении",
        values: &["off", "reply_only", "on"],
    },
    FnDef {
        f: "auto_forward",
        short: "Пересыл",
        full: "Автопересылка",
        values: &["off", "on"],
    },
    FnDef {
        f: "freebusy",
        short: "Занят",
        full: "Занятость",
        values: &["none", "free_busy", "limited", "details", "all"],
    },
    FnDef {
        f: "sharing",
        short: "Общий",
        full: "Общий доступ",
        values: &["none", "free_busy", "limited", "details", "all"],
    },
    FnDef {
        f: "group_post",
        short: "Группы",
        full: "Письма в группы",
        values: &["closed", "moderated", "open"],
    },
];

/// Типы абонентов по порядку (колонки таблицы).
pub const PEERS: [&str; 4] = ["own", "partner", "neighbor", "external"];

/// Заголовки колонок.
pub const PEER_HEADS: [&str; 4] = ["СВОИ", "ПАРТНЁР", "СОСЕД", "ИНТЕРНЕТ"];

/// Типы абонентов для строки состояния.
const PEER_RU: [&str; 4] = ["свои", "партнёр", "сосед", "интернет"];

/// Левая граница колонки типа абонента `i` внутри правой панели (`x0` — первая колонка).
pub const fn cell_x(x0: u16, i: usize) -> u16 {
    x0 + LABEL_W + 1 + (CELL_W + 1) * i as u16
}

/// Пометка клетки: закреплена контрактом, значение выше потолка, обычная.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mark {
    /// Обычная клетка.
    Plain,
    /// Закреплена контрактом — знак ⊘, не меняется никем.
    Fixed,
    /// Значение уровня шире потолка — знак ▲ и цвет роли «внимание».
    Over,
}

/// Уровень, который показываем и правим.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Установка — администратор установки.
    Installation,
    /// Организация.
    Org,
    /// Группа организации (идентификатор, имя).
    Group(String, String),
    /// Действующая матрица учётной записи (идентификатор, имя входа) — только чтение.
    Account(String, String),
}

impl Scope {
    /// Уровень правится (`PUT`/`DELETE`); учётная запись — только чтение.
    pub fn editable(&self) -> bool {
        !matches!(self, Self::Account(_, _))
    }

    /// `operationId` операций `GET`/`PUT` (у учётной записи вместо `PUT` — `GET`) и `DELETE`.
    fn ops(&self) -> (&'static str, &'static str, Option<&'static str>) {
        match self {
            Self::Installation => (
                "get_installation_trust",
                "put_installation_trust",
                Some("reset_installation_trust"),
            ),
            Self::Org => ("get_org_trust", "put_org_trust", Some("reset_org_trust")),
            Self::Group(_, _) => (
                "get_group_trust",
                "put_group_trust",
                Some("reset_group_trust"),
            ),
            Self::Account(_, _) => ("get_account_trust", "get_account_trust", None),
        }
    }

    /// Подпись уровня для строки «Уровень: …».
    fn line(&self) -> String {
        match self {
            Self::Installation => "установка".to_owned(),
            Self::Org => "организация".to_owned(),
            Self::Group(_, name) => format!("группа «{name}»"),
            Self::Account(_, login) => format!("учётная запись {login}"),
        }
    }
}

/// Вкладка правой панели.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    /// Матрица функций × типов абонентов.
    Matrix,
    /// Домены-партнёры и домены автопересылки (уровень организации).
    Partners,
}

/// Какой список доменов добавляем (F7 — по положению курсора).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainList {
    /// Домены-партнёры.
    Partners,
    /// Домены, куда разрешена автопересылка.
    Forward,
}

/// Ввод домена (F7 на вкладке «Партнёры»).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainInput {
    /// Куда добавить.
    pub list: DomainList,
    /// Введённое имя.
    pub value: String,
    /// Ошибка у поля.
    pub error: Option<String>,
}

/// Чего ищем формой выбора уровня.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pick {
    /// Группа — уровень группы (F5).
    Group,
    /// Учётная запись — действующая матрица (F6).
    Account,
}

/// Заголовок формы выбора.
pub fn pick_title(what: Pick) -> &'static str {
    match what {
        Pick::Group => "Уровень группы — выбор группы",
        Pick::Account => "Действующая матрица учётной записи",
    }
}

/// Ответы в пути для раздела «Доверие» (`crate::app::Pending::Trust`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Pending {
    /// `GET` уровня.
    Load,
    /// `PUT` политики уровня (отказ 422 приписывается клетке под курсором).
    Save,
    /// `PUT` доменов организации.
    Domains,
    /// `DELETE` — сброс уровня.
    Reset,
    /// Поиск группы для уровня группы; форма возвращается с ошибкой, если групп нет.
    PickGroup(Box<Form>),
    /// Поиск учётной записи для действующей матрицы.
    PickAccount(Box<Form>),
}

/// Состояние раздела «Доверие».
#[derive(Debug, Clone, PartialEq)]
pub struct Trust {
    /// Организация контекста.
    pub org: String,
    /// Вошёл администратор установки — уровень установки доступен по F5.
    pub install: bool,
    /// Уровень.
    pub scope: Scope,
    /// Куда возвращает Esc из действующей матрицы учётной записи.
    pub prev: Scope,
    /// Выбранная группа (запоминается между переключениями уровня).
    pub group: Option<(String, String)>,
    /// Выбранная учётная запись (запоминается для F6).
    pub account: Option<(String, String)>,
    /// Вкладка.
    pub tab: Tab,
    /// Курсор матрицы: функция, тип абонента.
    pub cur: (usize, usize),
    /// Курсор вкладки «Партнёры» по строке доменов.
    pub pick: usize,
    /// Ответ `GET` уровня (`TrustView` контракта — как пришёл, JSON).
    pub view: Option<Value>,
    /// Отказ 422 — текст `detail` сервера у клетки.
    pub err: Option<String>,
}

impl Trust {
    /// Экран «Доверие»: уровень организации.
    pub fn new(org: String, install: bool) -> Self {
        Self {
            org,
            install,
            scope: Scope::Org,
            prev: Scope::Org,
            group: None,
            account: None,
            tab: Tab::Matrix,
            cur: (0, 0),
            pick: 0,
            view: None,
            err: None,
        }
    }
}

/// Операция схемы по `operationId` (есть в схеме — тест `trust_operations_in_schema`).
fn op(id: &str) -> &'static crate::schema::Operation {
    catalog()
        .get(id)
        .unwrap_or_else(|| panic!("{id}: нет в схеме"))
}

/// Контекст запроса: организация, группа и учётная запись уровня.
fn ctx(t: &Trust) -> Context {
    let mut ctx = Context::from([("org".to_owned(), t.org.clone())]);
    if let Scope::Group(id, _) = &t.scope {
        ctx.insert("group".to_owned(), id.clone());
    }
    if let Scope::Account(id, _) = &t.scope {
        ctx.insert("account".to_owned(), id.clone());
    }
    ctx
}

/// Запрос `GET` уровня.
fn load(t: &Trust, bus: &mut Bus) -> Effect {
    let (get, _, _) = t.scope.ops();
    let req = Request::new(op(get), &ctx(t), Vec::new()).expect("запрос политики доверия");
    bus.call(req, Sent::Trust(Pending::Load))
}

/// Открыть раздел из дерева: экран и чтение политики организации.
pub(crate) fn open(m: &mut Main, bus: &mut Bus) -> Vec<Effect> {
    let t = Trust::new(m.org.clone(), m.session.install_admin);
    let effect = load(&t, bus);
    m.view = View::Trust(t);
    vec![effect]
}

/// Значение клетки матрицы: объединение значений функций — объект с одним полем (`{"invite": "auto"}`,
/// `{"toggle": "on"}`, `{"detail": "free_busy"}`, `{"post": "open"}`); строкой — само значение.
fn cell_value(v: &Value, f: &str, p: &str) -> String {
    match &v["effective"]["matrix"][f][p] {
        Value::Object(map) => map
            .values()
            .next()
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        Value::String(s) => s.clone(),
        _ => String::new(),
    }
}

/// Значение потолка клетки (то же объединение значений функций).
fn ceiling_value(v: &Value, f: &str, p: &str) -> String {
    match &v["effective"]["ceiling"]["matrix"][f][p] {
        Value::Object(map) => map
            .values()
            .next()
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        _ => String::new(),
    }
}

/// Клетка закреплена контрактом.
pub fn fixed_of(v: &Value, f: &str, p: &str) -> bool {
    v["fixed"][f][p].as_bool() == Some(true)
}

/// Клетка выше потолка уровня выше («выше потолка»).
pub fn over_of(v: &Value, f: &str, p: &str) -> bool {
    v["effective"]["over_ceiling"]
        .as_array()
        .is_some_and(|list| list.iter().any(|o| o["function"] == *f && o["peer"] == *p))
}

/// Уровень-источник клетки: установка, организация или группа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Src {
    /// Установка.
    Installation,
    /// Организация.
    Org,
    /// Группа.
    Group,
}

/// Источник клетки действующей матрицы: уровень, давший значение; `null` — умолчание контракта.
pub fn source_of(v: &Value, f: &str, p: &str) -> Option<Src> {
    match &v["effective"]["source"][f][p] {
        Value::String(s) if s == "installation" => Some(Src::Installation),
        Value::Object(map) if map.contains_key("org") => Some(Src::Org),
        Value::Object(map) if map.contains_key("group") => Some(Src::Group),
        _ => None,
    }
}

/// Буква источника клетки: у — установка, о — организация, г — группа.
pub fn mark_of(src: Src) -> char {
    match src {
        Src::Installation => 'у',
        Src::Org => 'о',
        Src::Group => 'г',
    }
}

/// Название уровня-источника для строки состояния.
pub fn level_label(src: Src) -> &'static str {
    match src {
        Src::Installation => "установка",
        Src::Org => "организация",
        Src::Group => "группа",
    }
}

/// Клавиша раздела. Стрелки — курсор по клеткам и строкам доменов; F2 — вкладка «Партнёры»; F4 (Enter) —
/// следующее допустимое значение клетки; F5 — уровень; F6 — учётная запись; F7/F8 — домены; F8 на матрице —
/// сброс уровня с подтверждением.
pub(crate) fn key(m: &mut Main, bus: &mut Bus, key: KeyEvent) -> Vec<Effect> {
    let View::Trust(t) = &mut m.view else {
        return Vec::new();
    };
    let busy = bus.busy();
    let mut overlay: Option<Overlay> = None;
    let out = match key.code {
        KeyCode::Up => {
            t.err = None;
            match t.tab {
                Tab::Matrix => t.cur.0 = t.cur.0.saturating_sub(1),
                Tab::Partners => t.pick = t.pick.saturating_sub(1),
            }
            Vec::new()
        }
        KeyCode::Down => {
            t.err = None;
            match t.tab {
                Tab::Matrix => t.cur.0 = (t.cur.0 + 1).min(FUNCTIONS.len() - 1),
                Tab::Partners => {
                    let n = partner_rows(t).len();
                    if n > 0 {
                        t.pick = (t.pick + 1).min(n - 1);
                    }
                }
            }
            Vec::new()
        }
        KeyCode::Left => {
            t.err = None;
            match t.tab {
                Tab::Matrix => t.cur.1 = t.cur.1.saturating_sub(1),
                Tab::Partners => t.tab = Tab::Matrix,
            }
            Vec::new()
        }
        KeyCode::Right => {
            t.err = None;
            t.cur.1 = (t.cur.1 + 1).min(PEERS.len() - 1);
            Vec::new()
        }
        KeyCode::Esc | KeyCode::Backspace => match t.tab {
            Tab::Partners => {
                t.tab = Tab::Matrix;
                Vec::new()
            }
            Tab::Matrix => {
                if matches!(t.scope, Scope::Account(_, _)) {
                    t.scope = t.prev.clone();
                    t.err = None;
                    vec![load(t, bus)]
                } else {
                    Vec::new()
                }
            }
        },
        KeyCode::Enter | KeyCode::F(4) if t.tab == Tab::Matrix => {
            if busy {
                Vec::new()
            } else {
                change_cell(t, bus)
            }
        }
        KeyCode::F(2) => {
            if busy {
                Vec::new()
            } else {
                match t.tab {
                    Tab::Partners => {
                        t.tab = Tab::Matrix;
                        Vec::new()
                    }
                    Tab::Matrix => match &t.scope {
                        Scope::Org => {
                            t.tab = Tab::Partners;
                            t.pick = 0;
                            t.err = None;
                            Vec::new()
                        }
                        _ => {
                            bus.say(Level::Warn, "домены — на уровне организации (F5)");
                            Vec::new()
                        }
                    },
                }
            }
        }
        KeyCode::F(5) => {
            if busy {
                Vec::new()
            } else {
                let step = match &t.scope {
                    Scope::Org if t.install => Some(Scope::Installation),
                    Scope::Org => t.group.clone().map(|(id, name)| Scope::Group(id, name)),
                    Scope::Installation => t.group.clone().map(|(id, name)| Scope::Group(id, name)),
                    Scope::Group(_, _) => Some(Scope::Org),
                    Scope::Account(_, _) => Some(t.prev.clone()),
                };
                match step {
                    Some(next) => {
                        t.scope = next;
                        t.tab = Tab::Matrix;
                        t.err = None;
                        vec![load(t, bus)]
                    }
                    None => {
                        overlay = Some(pick_overlay(t, Pick::Group));
                        Vec::new()
                    }
                }
            }
        }
        KeyCode::F(6) => {
            if busy {
                Vec::new()
            } else if let Some((id, login)) = t.account.clone() {
                if !matches!(t.scope, Scope::Account(_, _)) {
                    t.prev = t.scope.clone();
                }
                t.scope = Scope::Account(id, login);
                t.tab = Tab::Matrix;
                t.err = None;
                vec![load(t, bus)]
            } else {
                overlay = Some(pick_overlay(t, Pick::Account));
                Vec::new()
            }
        }
        KeyCode::F(7) if t.tab == Tab::Partners => {
            if busy {
                Vec::new()
            } else {
                let (partners, _) = domains(t);
                let list = if t.pick >= partners.len() {
                    DomainList::Forward
                } else {
                    DomainList::Partners
                };
                overlay = Some(Overlay::TrustDomain(DomainInput {
                    list,
                    value: String::new(),
                    error: None,
                }));
                Vec::new()
            }
        }
        KeyCode::F(8) if t.tab == Tab::Partners => {
            if busy {
                Vec::new()
            } else {
                remove_domain(t, bus)
            }
        }
        KeyCode::F(8) => {
            if busy || !t.scope.editable() {
                Vec::new()
            } else {
                let (_, _, reset) = t.scope.ops();
                let id = reset.expect("уровень со сбросом");
                let req = Request::new(op(id), &ctx(t), Vec::new()).expect("запрос сброса");
                overlay = Some(Overlay::TrustConfirm(req));
                Vec::new()
            }
        }
        _ => Vec::new(),
    };
    if let Some(ov) = overlay {
        m.overlay = Some(ov);
    }
    out
}

/// Форма выбора группы или учётной записи (поля — параметры запроса схемы: у списка групп полей нет, Enter
/// берёт первую запись).
fn pick_overlay(t: &Trust, what: Pick) -> Overlay {
    let mut ctx = Context::new();
    ctx.insert("org".to_owned(), t.org.clone());
    let mut f = Form::new(op("list_groups"), &ctx, true, &Map::new());
    if what == Pick::Account {
        f = Form::new(op("list_accounts"), &ctx, true, &Map::new());
        f.retain(&["login"]);
    }
    Overlay::TrustPick {
        what,
        form: Box::new(f),
    }
}

/// Следующее допустимое значение клетки (F4): из значений не выше потолка, по циклу от самого широкого к
/// самому узкому; закреплённая клетка и клетка без вариантов — `None`.
pub fn next_value(v: &Value, f: &str, p: &str) -> Option<&'static str> {
    let def = FUNCTIONS.iter().find(|d| d.f == f)?;
    if fixed_of(v, f, p) {
        return None;
    }
    let rank = |s: &str| def.values.iter().position(|x| *x == s);
    let top = rank(&ceiling_value(v, f, p))?;
    let cur = cell_value(v, f, p);
    let next = match rank(&cur) {
        Some(i) if i < top => def.values[i + 1],
        Some(_) => def.values[0],
        None if top == 0 => def.values[0],
        // Клетка выше потолка (перечитана после смены уровней): предлагаем самое узкое значение.
        None if def.values[0] != cur => def.values[0],
        None => return None,
    };
    (next != cur).then_some(next)
}

/// Тело `PUT`: политика уровня целиком (незаданные клетки наследуют уровень выше) со сменённой клеткой.
/// Клетки тела — plain-строки (`{"invite_new": {"partner": "auto"}}`), как в схеме Admin API.
fn save_body(v: &Value, f: &str, p: &str, value: &str) -> Value {
    let mut body = match v.get("own") {
        Some(o @ Value::Object(_)) => o.clone(),
        _ => Value::Object(Map::new()),
    };
    let map = body.as_object_mut().expect("тело — объект");
    let cell = map
        .entry(f.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    if let Some(peers) = cell.as_object_mut() {
        peers.insert(p.to_owned(), Value::String(value.to_owned()));
    }
    body
}

/// F4: сменить значение клетки под курсором на следующее допустимое и записать политику уровня целиком.
fn change_cell(t: &mut Trust, bus: &mut Bus) -> Vec<Effect> {
    if !t.scope.editable() {
        return Vec::new();
    }
    let Some(v) = t.view.as_ref() else {
        return Vec::new();
    };
    let (i, j) = t.cur;
    let Some(def) = FUNCTIONS.get(i) else {
        return Vec::new();
    };
    let Some(&p) = PEERS.get(j) else {
        return Vec::new();
    };
    let Some(next) = next_value(v, def.f, p) else {
        bus.say(
            Level::Warn,
            "клетку изменить нельзя: закреплена или потолок равен значению",
        );
        return Vec::new();
    };
    let body = save_body(v, def.f, p, next);
    let (_, put, _) = t.scope.ops();
    let mut req = Request::new(op(put), &ctx(t), Vec::new()).expect("запрос записи политики");
    req.body = Some(body);
    t.err = None;
    bus.say(Level::Ok, "запись политики доверия…");
    vec![bus.call(req, Sent::Trust(Pending::Save))]
}

/// Домены уровня организации: партнёры и автопересылка.
pub fn domains(t: &Trust) -> (Vec<String>, Vec<String>) {
    let own = t.view.as_ref().and_then(|v| v.get("own"));
    let list = |name: &str| {
        own.and_then(|o| o.get(name))
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    (list("partners"), list("auto_forward_domains"))
}

/// Строки вкладки «Партнёры»: сначала партнёры, затем автопересылка; `true` — автопересылка.
pub fn partner_rows(t: &Trust) -> Vec<(bool, String)> {
    let (partners, forwards) = domains(t);
    partners
        .into_iter()
        .map(|d| (false, d))
        .chain(forwards.into_iter().map(|d| (true, d)))
        .collect()
}

/// Тело `PUT` доменов: политика уровня целиком с новыми списками.
fn domains_req(t: &Trust, partners: Vec<String>, forwards: Vec<String>) -> Request {
    let v = t.view.as_ref().expect("политика организации загружена");
    let mut body = match v.get("own") {
        Some(o @ Value::Object(_)) => o.clone(),
        _ => Value::Object(Map::new()),
    };
    let map = body.as_object_mut().expect("тело — объект");
    map.insert(
        "partners".to_owned(),
        Value::Array(partners.into_iter().map(Value::String).collect()),
    );
    map.insert(
        "auto_forward_domains".to_owned(),
        Value::Array(forwards.into_iter().map(Value::String).collect()),
    );
    let (_, put, _) = t.scope.ops();
    let mut req = Request::new(op(put), &ctx(t), Vec::new()).expect("запрос записи доменов");
    req.body = Some(body);
    req
}

/// F7 на вкладке «Партнёры»: ввод домена и запись списков.
pub(crate) fn domain_key(
    m: &mut Main,
    bus: &mut Bus,
    mut d: DomainInput,
    key: KeyEvent,
) -> Vec<Effect> {
    let mut restore = true;
    let out = match key.code {
        KeyCode::Esc => return Vec::new(),
        KeyCode::Enter => {
            let dom = d.value.trim().to_lowercase();
            if dom.is_empty() {
                d.error = Some("введите домен".to_owned());
                Vec::new()
            } else {
                let View::Trust(t) = &mut m.view else {
                    return Vec::new();
                };
                let (mut partners, mut forwards) = domains(t);
                match d.list {
                    DomainList::Partners => partners.push(dom),
                    DomainList::Forward => forwards.push(dom),
                }
                let req = domains_req(t, partners, forwards);
                bus.say(Level::Ok, "запись доменов организации…");
                restore = false;
                vec![bus.call(req, Sent::Trust(Pending::Domains))]
            }
        }
        KeyCode::Backspace => {
            d.value.pop();
            Vec::new()
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            d.value.push(c);
            Vec::new()
        }
        _ => Vec::new(),
    };
    if restore {
        m.overlay = Some(Overlay::TrustDomain(d));
    }
    out
}

/// F8 на вкладке «Партнёры»: убрать выделенный домен и записать списки.
fn remove_domain(t: &mut Trust, bus: &mut Bus) -> Vec<Effect> {
    let Some((forward, dom)) = partner_rows(t).get(t.pick).cloned() else {
        bus.say(Level::Warn, "нет выделенного домена");
        return Vec::new();
    };
    let (mut partners, mut forwards) = domains(t);
    if forward {
        forwards.retain(|x| *x != dom);
    } else {
        partners.retain(|x| *x != dom);
    }
    let req = domains_req(t, partners, forwards);
    bus.say(Level::Ok, "запись доменов организации…");
    vec![bus.call(req, Sent::Trust(Pending::Domains))]
}

/// Ответ Admin API: чтение уровня, запись, сброс, найденная группа или учётная запись.
pub(crate) fn on_ok(m: &mut Main, bus: &mut Bus, p: Pending, page: Page) -> Vec<Effect> {
    let View::Trust(t) = &mut m.view else {
        return Vec::new();
    };
    match p {
        Pending::Load => {
            t.err = None;
            if page.value.is_object() {
                t.view = Some(page.value);
            } else {
                bus.say(Level::Err, "политика доверия: неожиданный ответ сервера");
            }
            Vec::new()
        }
        Pending::Save => {
            t.err = None;
            bus.say(Level::Ok, "готово: политика доверия записана");
            vec![load(t, bus)]
        }
        Pending::Domains => {
            t.err = None;
            bus.say(Level::Ok, "готово: домены организации записаны");
            vec![load(t, bus)]
        }
        Pending::Reset => {
            t.err = None;
            bus.say(Level::Ok, "готово: политика уровня сброшена");
            vec![load(t, bus)]
        }
        Pending::PickGroup(mut f) => {
            let found = page.value.as_array().and_then(|r| r.first()).and_then(|r| {
                let id = r.get("id")?.as_str()?.to_owned();
                let name = r.get("name")?.as_str()?.to_owned();
                Some((id, name))
            });
            match found {
                Some((id, name)) => {
                    t.group = Some((id.clone(), name.clone()));
                    t.scope = Scope::Group(id, name);
                    t.tab = Tab::Matrix;
                    t.err = None;
                    vec![load(t, bus)]
                }
                None => {
                    f.error = Some("в организации нет групп".to_owned());
                    m.overlay = Some(Overlay::TrustPick {
                        what: Pick::Group,
                        form: f,
                    });
                    Vec::new()
                }
            }
        }
        Pending::PickAccount(mut f) => {
            let found = page.value.as_array().and_then(|r| r.first()).and_then(|r| {
                let id = r.get("id")?.as_str()?.to_owned();
                let login = r.get("login")?.as_str()?.to_owned();
                Some((id, login))
            });
            match found {
                Some((id, login)) => {
                    t.account = Some((id.clone(), login.clone()));
                    t.scope = Scope::Account(id, login);
                    t.tab = Tab::Matrix;
                    t.err = None;
                    vec![load(t, bus)]
                }
                None => {
                    if let Some(x) = f.fields.first_mut() {
                        x.error = Some("нет учётной записи с этим именем входа".to_owned());
                    }
                    m.overlay = Some(Overlay::TrustPick {
                        what: Pick::Account,
                        form: f,
                    });
                    Vec::new()
                }
            }
        }
    }
}

/// Отказ Admin API: текст `detail` 422 — у клетки (`t.err`), прочие — в строке состояния.
pub(crate) fn on_err(m: &mut Main, bus: &mut Bus, p: Pending, e: &tp_admin_client::Error) {
    let detail = match e {
        tp_admin_client::Error::Api {
            problem: Some(pr), ..
        } => pr
            .detail
            .clone()
            .unwrap_or_else(|| format!("{} {}", pr.status, pr.title)),
        _ => e.to_string(),
    };
    let View::Trust(t) = &mut m.view else {
        bus.say(Level::Err, detail);
        return;
    };
    match p {
        Pending::Save | Pending::Domains => {
            t.err = Some(detail.clone());
            bus.say(Level::Err, detail);
        }
        Pending::Reset => bus.say(Level::Err, format!("не сброшено: {detail}")),
        Pending::Load => bus.say(Level::Err, detail),
        Pending::PickGroup(mut f) => {
            f.error = Some(detail.clone());
            m.overlay = Some(Overlay::TrustPick {
                what: Pick::Group,
                form: f,
            });
            bus.say(Level::Err, detail);
        }
        Pending::PickAccount(mut f) => {
            f.error = Some(detail.clone());
            m.overlay = Some(Overlay::TrustPick {
                what: Pick::Account,
                form: f,
            });
            bus.say(Level::Err, detail);
        }
    }
}

/// Подписи F-клавиш раздела.
pub fn key_labels(t: &Trust) -> [&'static str; 10] {
    match t.tab {
        Tab::Partners => [
            "Помощь",
            "Матриц",
            "",
            "",
            "Уровень",
            "",
            "Добав",
            "Удалит",
            "Меню",
            "Выход",
        ],
        Tab::Matrix => {
            if t.scope.editable() {
                [
                    "Помощь",
                    "Партн",
                    "",
                    "Знач",
                    "Уровень",
                    "Учетн",
                    "",
                    "Сброс",
                    "Меню",
                    "Выход",
                ]
            } else {
                [
                    "Помощь",
                    "",
                    "",
                    "",
                    "Уровень",
                    "Учетн",
                    "",
                    "",
                    "Меню",
                    "Выход",
                ]
            }
        }
    }
}

/// Короткое значение клетки (в колонку 8 знаков входят знаки ▲, ⊘ и буква источника).
pub fn value_short(v: &str) -> &'static str {
    match v {
        "button" => "кнопка",
        "auto" => "авто",
        "on" => "да",
        "off" | "none" => "нет",
        "reply_only" => "ответ",
        "free_busy" => "св/зан",
        "limited" => "частич",
        "details" => "подроб",
        "all" => "всё",
        "closed" => "закрыт",
        "moderated" => "модер",
        "open" => "открыт",
        _ => "—",
    }
}

/// Текст и пометка клетки матрицы; `sources` — показать источник клетки (действующая матрица учётной записи).
pub fn cell(v: &Value, f: &str, p: &str, sources: bool) -> (String, Mark) {
    let mut text = value_short(&cell_value(v, f, p)).to_owned();
    if sources && let Some(src) = source_of(v, f, p) {
        text.push(' ');
        text.push(mark_of(src));
    }
    let mut mark = Mark::Plain;
    if over_of(v, f, p) {
        text = format!("▲{text}");
        mark = Mark::Over;
    } else if fixed_of(v, f, p) {
        text.push('⊘');
        mark = Mark::Fixed;
    }
    (text, mark)
}

/// Строка «Уровень: …» под матрицей.
pub fn level_line(t: &Trust) -> String {
    match &t.scope {
        Scope::Account(_, login) => format!("Учётная запись: {login}"),
        _ => {
            let set = t
                .view
                .as_ref()
                .is_some_and(|v| v.get("own").is_some_and(Value::is_object));
            format!(
                "Уровень: {} · политика {}",
                t.scope.line(),
                if set {
                    "задана"
                } else {
                    "не задана"
                }
            )
        }
    }
}

/// Строка о доменах под матрицей (уровень организации).
pub fn domain_line(t: &Trust) -> Option<String> {
    if t.tab != Tab::Matrix || !matches!(t.scope, Scope::Org) {
        return None;
    }
    let (partners, forwards) = domains(t);
    Some(format!(
        "Партнёры: {} · автопересылка: {} · F2 — домены",
        partners.len(),
        forwards.len()
    ))
}

/// Строка допустимых значений клетки под курсором (строка 18): выше потолка не предлагаются.
pub fn values_line(t: &Trust) -> Option<String> {
    let v = t.view.as_ref()?;
    if t.tab != Tab::Matrix || !t.scope.editable() {
        return None;
    }
    let def = FUNCTIONS.get(t.cur.0)?;
    let p = PEERS.get(t.cur.1)?;
    if fixed_of(v, def.f, p) {
        return Some("клетка закреплена контрактом — изменить нельзя".to_owned());
    }
    let top = def
        .values
        .iter()
        .position(|x| *x == ceiling_value(v, def.f, p))?;
    let list: Vec<&str> = def.values[..=top].iter().map(|x| value_short(x)).collect();
    if list.is_empty() {
        return None;
    }
    Some(format!("F4 — значение из: {}", list.join(" → ")))
}

/// Подсказка под матрицей (строка 19).
pub fn hint(t: &Trust) -> &'static str {
    match t.tab {
        Tab::Partners => "F7 — добавить · F8 — удалить · F2 — матрица",
        Tab::Matrix => {
            if t.scope.editable() {
                "F4 — значение · F5 — уровень · F8 — сброс"
            } else {
                "Esc — назад к уровню · F6 — другая учётная запись"
            }
        }
    }
}

/// Строка состояния: клетка под курсором или домен (полные названия, потолок, источник, закреплено).
pub fn status(t: &Trust) -> String {
    match t.tab {
        Tab::Partners => match partner_rows(t).get(t.pick) {
            Some((true, d)) => format!("{d} · автопересылка"),
            Some((false, d)) => format!("{d} · партнёр"),
            None => "домены организации: партнёры и автопересылка".to_owned(),
        },
        Tab::Matrix => {
            let Some(v) = t.view.as_ref() else {
                return "чтение политики доверия…".to_owned();
            };
            let (Some(def), Some(&p)) = (FUNCTIONS.get(t.cur.0), PEERS.get(t.cur.1)) else {
                return String::new();
            };
            let mut s = format!(
                "{} · {}: {}",
                def.full,
                PEER_RU[t.cur.1],
                value_short(&cell_value(v, def.f, p))
            );
            match &t.scope {
                Scope::Account(_, _) => {
                    let from = source_of(v, def.f, p)
                        .map(level_label)
                        .unwrap_or("умолчание");
                    s.push_str(&format!(" · источник: {from}"));
                }
                _ => {
                    s.push_str(&format!(
                        " · потолок: {}",
                        value_short(&ceiling_value(v, def.f, p))
                    ));
                    if over_of(v, def.f, p) {
                        s.push_str(" · выше потолка — действует потолок");
                    }
                    if fixed_of(v, def.f, p) {
                        s.push_str(" · закреплено — изменить нельзя");
                    }
                }
            }
            s
        }
    }
}

/// Эквивалентная команда `thepost admin trust …` для действия на экране (решение 118). Без `--org` CLI
/// выбирает уровень установки, поэтому уровень организации — всегда с `--org`.
pub fn command(t: &Trust) -> String {
    let org = format!("--org {}", t.org);
    match t.tab {
        Tab::Partners => {
            if partner_rows(t).get(t.pick).is_some() {
                format!("thepost admin trust partners set <ДОМЕН>… {org}")
            } else {
                format!("thepost admin trust partners list {org}")
            }
        }
        Tab::Matrix => match &t.scope {
            Scope::Installation => "thepost admin trust set --file <ПУТЬ>".to_owned(),
            Scope::Org => format!("thepost admin trust set --file <ПУТЬ> {org}"),
            Scope::Group(_, name) => {
                format!("thepost admin trust set --file <ПУТЬ> {org} --group {name}")
            }
            Scope::Account(_, login) => {
                format!("thepost admin trust show {org} --account {login}")
            }
        },
    }
}

/// Команда сброса уровня для подтверждения (F8): уровень группы — по имени группы (запрос несёт
/// идентификатор, CLI принимает и то и другое); у учётной записи сброса нет — команда показа.
pub fn reset_command(t: &Trust) -> String {
    let org = format!("--org {}", t.org);
    match &t.scope {
        Scope::Installation => "thepost admin trust reset".to_owned(),
        Scope::Org => format!("thepost admin trust reset {org}"),
        Scope::Group(_, name) => format!("thepost admin trust reset {org} --group {name}"),
        Scope::Account(_, _) => command(t),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::app::tests::{call, key, ok, section, who, with_accounts};
    use crate::app::{App, Effect, LoginForm, Stage};
    use crate::theme::{Brand, Mode, Theme};
    use serde_json::json;
    use tp_admin::server::AdminRole;

    /// Политика организации: приглашение партнёру — «авто», домены заданы (как в JSON контракта).
    fn own() -> Value {
        json!({
            "invite_new": {"partner": "auto"},
            "partners": ["partner.example"],
            "auto_forward_domains": ["mail.example"],
        })
    }

    /// Действующая матрица и потолок контракта по умолчанию (клетки — объединения значений функций).
    fn default_effective() -> Value {
        json!({
            "matrix": {
                "invite_new": {
                    "own": {"invite": "auto"}, "partner": {"invite": "button"},
                    "neighbor": {"invite": "button"}, "external": {"invite": "button"},
                },
                "itip_updates": {
                    "own": {"toggle": "on"}, "partner": {"toggle": "on"},
                    "neighbor": {"toggle": "on"}, "external": {"toggle": "on"},
                },
                "auto_reply": {
                    "own": {"toggle": "on"}, "partner": {"toggle": "on"},
                    "neighbor": {"toggle": "on"}, "external": {"toggle": "on"},
                },
                "mdn": {
                    "own": {"toggle": "on"}, "partner": {"toggle": "off"},
                    "neighbor": {"toggle": "off"}, "external": {"toggle": "off"},
                },
                "auto_forward": {
                    "own": {"toggle": "on"}, "partner": {"toggle": "off"},
                    "neighbor": {"toggle": "off"}, "external": {"toggle": "off"},
                },
                "freebusy": {
                    "own": {"detail": "free_busy"}, "partner": {"detail": "none"},
                    "neighbor": {"detail": "none"}, "external": {"detail": "none"},
                },
                "sharing": {
                    "own": {"detail": "all"}, "partner": {"detail": "none"},
                    "neighbor": {"detail": "none"}, "external": {"detail": "none"},
                },
                "group_post": {
                    "own": {"post": "open"}, "partner": {"post": "closed"},
                    "neighbor": {"post": "closed"}, "external": {"post": "closed"},
                },
            },
            "ceiling": {"matrix": {
                "invite_new": {
                    "own": {"invite": "auto"}, "partner": {"invite": "auto"},
                    "neighbor": {"invite": "button"}, "external": {"invite": "button"},
                },
                "itip_updates": {
                    "own": {"toggle": "on"}, "partner": {"toggle": "on"},
                    "neighbor": {"toggle": "on"}, "external": {"toggle": "on"},
                },
                "auto_reply": {
                    "own": {"toggle": "on"}, "partner": {"toggle": "on"},
                    "neighbor": {"toggle": "on"}, "external": {"toggle": "on"},
                },
                "mdn": {
                    "own": {"toggle": "on"}, "partner": {"toggle": "on"},
                    "neighbor": {"toggle": "on"}, "external": {"toggle": "on"},
                },
                "auto_forward": {
                    "own": {"toggle": "on"}, "partner": {"toggle": "on"},
                    "neighbor": {"toggle": "on"}, "external": {"toggle": "on"},
                },
                "freebusy": {
                    "own": {"detail": "details"}, "partner": {"detail": "limited"},
                    "neighbor": {"detail": "none"}, "external": {"detail": "none"},
                },
                "sharing": {
                    "own": {"detail": "all"}, "partner": {"detail": "details"},
                    "neighbor": {"detail": "details"}, "external": {"detail": "details"},
                },
                "group_post": {
                    "own": {"post": "open"}, "partner": {"post": "open"},
                    "neighbor": {"post": "open"}, "external": {"post": "open"},
                },
            }},
            "source": {},
            "over_ceiling": [],
        })
    }

    /// Закреплённые клетки контракта: потолок равен самому узкому значению (TrustFixed::contract).
    fn fixed_json() -> Value {
        json!({
            "invite_new": {"own": false, "partner": false, "neighbor": true, "external": true},
            "itip_updates": {"own": false, "partner": false, "neighbor": false, "external": false},
            "auto_reply": {"own": false, "partner": false, "neighbor": false, "external": false},
            "mdn": {"own": false, "partner": false, "neighbor": false, "external": false},
            "auto_forward": {"own": false, "partner": false, "neighbor": false, "external": false},
            "freebusy": {"own": false, "partner": false, "neighbor": true, "external": true},
            "sharing": {"own": false, "partner": false, "neighbor": false, "external": false},
            "group_post": {"own": false, "partner": false, "neighbor": false, "external": false},
        })
    }

    /// Ответ `GET` уровня из собственной политики и действующей матрицы.
    fn view(own: Value, effective: Value) -> Value {
        json!({"own": own, "effective": effective, "fixed": fixed_json()})
    }

    /// Уровень организации: собственная политика подняла клетку, действует потолок контракта.
    fn org_view() -> Value {
        let mut e = default_effective();
        e["matrix"]["invite_new"]["partner"] = json!({"invite": "auto"});
        e["source"] =
            json!({"invite_new": {"partner": {"org": "00000000-0000-0000-0000-000000000001"}}});
        view(own(), e)
    }

    /// JSON `GET` уровня организации для отрисовки на TestBackend (тесты `ui`).
    pub(crate) fn org_json() -> Value {
        org_view()
    }

    /// JSON: организация подняла занятость партнёру выше потолка установки — знак ▲ (тесты `ui`).
    pub(crate) fn over_json() -> Value {
        let mut e = default_effective();
        e["ceiling"]["matrix"]["freebusy"]["partner"] = json!({"detail": "none"});
        e["over_ceiling"] = json!([{
            "function": "freebusy", "peer": "partner",
            "value": {"detail": "limited"}, "ceiling": {"detail": "none"},
            "level": "installation",
        }]);
        view(json!({"freebusy": {"partner": "limited"}}), e)
    }

    /// Вошедший интерфейс с открытым разделом «Доверие» (уровень организации).
    fn with_trust() -> App {
        let mut app = with_accounts();
        let id = call(&section(&mut app, "Доверие"), SECTION_OP);
        app.on_result(id, ok(org_view()));
        app
    }

    fn trust_of(app: &App) -> &Trust {
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let View::Trust(t) = &m.view else {
            panic!("не раздел «Доверие»");
        };
        t
    }

    fn trust_mut(app: &mut App) -> &mut Trust {
        let Stage::Main(m) = &mut app.stage else {
            panic!("не основной экран");
        };
        let View::Trust(t) = &mut m.view else {
            panic!("не раздел «Доверие»");
        };
        t
    }

    /// Отказ 422 (problem+json с `detail`).
    fn refused(detail: &str) -> Result<Page, tp_admin_client::Error> {
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

    fn cell_at(app: &mut App, f: &str, peer: usize) {
        let t = trust_mut(app);
        t.cur = (
            FUNCTIONS.iter().position(|d| d.f == f).expect("функция"),
            peer,
        );
    }

    /// Операции раздела и уровня есть в схеме Admin API.
    #[test]
    fn trust_operations_in_schema() {
        for id in [
            "get_installation_trust",
            "put_installation_trust",
            "reset_installation_trust",
            "get_org_trust",
            "put_org_trust",
            "reset_org_trust",
            "get_group_trust",
            "put_group_trust",
            "reset_group_trust",
            "get_account_trust",
            "list_groups",
            "list_accounts",
        ] {
            assert!(catalog().get(id).is_some(), "{id}: нет в схеме");
        }
    }

    /// Значения выше потолка не предлагаются (F4 идёт по циклу в пределах потолка); закреплённая клетка
    /// значений не предлагает вовсе.
    #[test]
    fn next_value_stops_at_ceiling() {
        // Установка снизила потолок занятости партнёру до «ограниченных подробностей».
        let mut e = default_effective();
        e["ceiling"]["matrix"]["freebusy"]["partner"] = json!({"detail": "limited"});
        let step = |cur: &str| {
            let mut e = e.clone();
            e["matrix"]["freebusy"]["partner"] = json!({"detail": cur});
            view(Value::Null, e)
        };
        let mut v = step("none");
        let mut seen = vec![cell_value(&v, "freebusy", "partner")];
        for _ in 0..4 {
            let Some(next) = next_value(&v, "freebusy", "partner") else {
                break;
            };
            seen.push(next.to_owned());
            v = step(next);
        }
        // «Подробности» и «всё» выше потолка — не предлагаются: цикл остаётся в пределах потолка, после
        // самого широкого допустимого значения возвращается к самому узкому.
        assert_eq!(
            seen,
            ["none", "free_busy", "limited", "none", "free_busy"],
            "{seen:?}"
        );
        // Приглашение соседу закреплено контрактом («кнопка») — значений нет.
        let fixed = view(Value::Null, default_effective());
        assert_eq!(next_value(&fixed, "invite_new", "neighbor"), None);
    }

    /// F4: следующее допустимое значение, `PUT` политики уровня целиком; отказ 422 — `detail` у клетки.
    #[test]
    fn f4_changes_cell_and_422_at_cell() {
        let mut app = with_trust();
        // MDN партнёру: по умолчанию «нет», потолок «да» — F4 предлагает «да».
        cell_at(&mut app, "mdn", 1);
        assert_eq!(
            app.command_line(),
            "thepost admin trust set --file <ПУТЬ> --org 00000000-0000-0000-0000-000000000001"
        );
        let fx = app.on_key(key(KeyCode::F(4)));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет записи: {fx:?}");
        };
        assert_eq!(req.op.id, "put_org_trust");
        // «Только ответ» — промежуточное значение между «нет» и «да» (решение 125 а).
        assert_eq!(
            req.body,
            Some(json!({
                "invite_new": {"partner": "auto"},
                "partners": ["partner.example"],
                "auto_forward_domains": ["mail.example"],
                "mdn": {"partner": "reply_only"},
            }))
        );
        // Сервер отказал: текст detail у клетки.
        app.on_result(
            *id,
            refused("домен-партнёр из принятых доменов организации"),
        );
        assert_eq!(
            trust_of(&app).err.as_deref(),
            Some("домен-партнёр из принятых доменов организации")
        );
        // Повторная запись прошла: политика перечитывается, ошибка клетки сброшена.
        let fx = app.on_key(key(KeyCode::F(4)));
        let [Effect::Call(id, _)] = fx.as_slice() else {
            panic!("нет записи: {fx:?}");
        };
        let fx = app.on_result(*id, ok(org_view()));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет перечитывания: {fx:?}");
        };
        assert_eq!(req.op.id, "get_org_trust");
        app.on_result(*id, ok(org_view()));
        assert!(trust_of(&app).err.is_none(), "ошибка клетки сброшена");
    }

    /// Закреплённую клетку F4 не меняет; пояснение — в строке состояния.
    #[test]
    fn f4_keeps_fixed_cell() {
        let mut app = with_trust();
        // Приглашение интернету — «кнопка», закреплено контрактом.
        cell_at(&mut app, "invite_new", 3);
        let fx = app.on_key(key(KeyCode::F(4)));
        assert!(fx.is_empty(), "закреплённая клетка не меняется: {fx:?}");
        let t = trust_of(&app);
        assert!(
            t.err.is_none()
                && t.view
                    .as_ref()
                    .is_some_and(|v| fixed_of(v, "invite_new", "external")),
            "клетка закреплена"
        );
    }

    /// F5 — уровни: организация → группа (выбор из списка групп) → назад; F8 — сброс уровня
    /// с подтверждением; строка CLI соответствует уровню и действию.
    #[test]
    fn f5_levels_and_f8_reset() {
        let mut app = with_trust();
        // F5 — группы ещё не выбирали: форма выбора.
        let fx = app.on_key(key(KeyCode::F(5)));
        assert!(fx.is_empty());
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::TrustPick { what, form }) = &m.overlay else {
            panic!("нет формы выбора группы");
        };
        assert_eq!(*what, Pick::Group);
        assert!(form.fields.is_empty(), "у списка групп нет полей фильтра");
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет списка групп: {fx:?}");
        };
        assert_eq!(req.op.id, "list_groups");
        let fx = app.on_result(
            *id,
            ok(json!([{"id": "g1", "name": "Продажи", "members": []}])),
        );
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет чтения политики группы: {fx:?}");
        };
        assert_eq!(req.op.id, "get_group_trust");
        assert_eq!(req.param("group"), Some("g1"));
        assert_eq!(
            app.command_line(),
            "thepost admin trust set --file <ПУТЬ> --org 00000000-0000-0000-0000-000000000001 --group Продажи"
        );
        assert_eq!(
            trust_of(&app).scope,
            Scope::Group("g1".into(), "Продажи".into())
        );
        app.on_result(*id, ok(org_view()));
        // F5 — в уровень группы уже можно вернуться без выбора: организация, затем снова группа.
        let fx = app.on_key(key(KeyCode::F(5)));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет чтения организации: {fx:?}");
        };
        assert_eq!(req.op.id, "get_org_trust");
        app.on_result(*id, ok(org_view()));
        let fx = app.on_key(key(KeyCode::F(5)));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет чтения политики группы: {fx:?}");
        };
        assert_eq!(req.op.id, "get_group_trust", "группа запомнена");
        app.on_result(*id, ok(org_view()));
        // F8 — сброс уровня группы: подтверждение, строка CLI — команда сброса.
        assert!(app.on_key(key(KeyCode::F(8))).is_empty());
        assert_eq!(
            app.command_line(),
            "thepost admin trust reset --org 00000000-0000-0000-0000-000000000001 --group Продажи"
        );
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::TrustConfirm(req)) = &m.overlay else {
            panic!("нет подтверждения сброса");
        };
        assert_eq!(req.op.id, "reset_group_trust");
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет сброса: {fx:?}");
        };
        assert_eq!(req.op.id, "reset_group_trust");
        let fx = app.on_result(*id, ok(org_view()));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет перечитывания: {fx:?}");
        };
        assert_eq!(req.op.id, "get_group_trust");
        app.on_result(*id, ok(org_view()));
        assert!(trust_of(&app).err.is_none());
    }

    /// Администратор установки: F5 от уровня организации — на установку; команда без ключей.
    #[test]
    fn f5_installation_level_for_install_admin() {
        let mut app = App::new(
            Theme::new(Mode::Dark, Brand::default()),
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
        app.on_result(ids[0], ok(json!([{"id": "o1", "default": true}])));
        app.on_result(ids[1], ok(json!([])));
        let id = call(&section(&mut app, "Доверие"), SECTION_OP);
        app.on_result(id, ok(view(Value::Null, default_effective())));
        // Организация → установка (администратор установки).
        let fx = app.on_key(key(KeyCode::F(5)));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет чтения установки: {fx:?}");
        };
        assert_eq!(req.op.id, "get_installation_trust");
        app.on_result(*id, ok(view(Value::Null, default_effective())));
        assert_eq!(
            app.command_line(),
            "thepost admin trust set --file <ПУТЬ>",
            "уровень установки — без ключей"
        );
        assert_eq!(trust_of(&app).scope, Scope::Installation);
    }

    /// F6 — действующая матрица учётной записи с источником клетки; строка CLI — `trust show --account`;
    /// Esc возвращает на уровень организации.
    #[test]
    fn f6_account_matrix_with_sources() {
        let mut app = with_trust();
        assert!(app.on_key(key(KeyCode::F(6))).is_empty());
        for c in "user1@it-task.ru".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет поиска учётной записи: {fx:?}");
        };
        assert_eq!(req.op.id, "list_accounts");
        let fx = app.on_result(
            *id,
            ok(json!([{"id": "acc-1", "login": "user1@it-task.ru"}])),
        );
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет чтения действующей матрицы: {fx:?}");
        };
        assert_eq!(req.op.id, "get_account_trust");
        assert_eq!(req.param("account"), Some("acc-1"));
        app.on_result(*id, ok(org_view()));
        assert_eq!(
            app.command_line(),
            "thepost admin trust show --org 00000000-0000-0000-0000-000000000001 --account user1@it-task.ru"
        );
        // Источник клетки: приглашение партнёру задано организацией — «авто о».
        cell_at(&mut app, "invite_new", 1);
        let t = trust_of(&app);
        assert!(matches!(t.scope, Scope::Account(_, _)));
        let v = t.view.as_ref().expect("матрица загружена");
        let (text, mark) = cell(v, "invite_new", "partner", true);
        assert_eq!(mark, Mark::Plain);
        assert_eq!(text, "авто о", "значение и источник клетки");
        assert!(status(t).contains("источник: организация"));
        // Esc — назад к уровню организации.
        let fx = app.on_key(key(KeyCode::Esc));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет возврата: {fx:?}");
        };
        assert_eq!(req.op.id, "get_org_trust");
        app.on_result(*id, ok(org_view()));
        assert_eq!(trust_of(&app).scope, Scope::Org);
    }

    /// Вкладка «Партнёры» (F2): списки доменов, F7 — добавить (в автопересылку — по положению курсора),
    /// F8 — удалить; 422 — текст `detail`; вне уровня организации — предупреждение.
    #[test]
    fn partners_tab_add_delete() {
        let mut app = with_trust();
        // Вне уровня организации домены недоступны.
        trust_mut(&mut app).scope = Scope::Installation;
        assert!(app.on_key(key(KeyCode::F(2))).is_empty());
        assert_eq!(trust_of(&app).tab, Tab::Matrix, "вкладка не сменилась");
        trust_mut(&mut app).scope = Scope::Org;
        // F2 — вкладка «Партнёры»; курсор на домене — команда записи списков.
        assert!(app.on_key(key(KeyCode::F(2))).is_empty());
        assert_eq!(trust_of(&app).tab, Tab::Partners);
        assert_eq!(
            app.command_line(),
            "thepost admin trust partners set <ДОМЕН>… --org 00000000-0000-0000-0000-000000000001"
        );
        // F7 на строке партнёра — ввод домена, каноническая форма (нижний регистр).
        assert!(app.on_key(key(KeyCode::F(7))).is_empty());
        for c in "Partner.Example ".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет записи доменов: {fx:?}");
        };
        assert_eq!(req.op.id, "put_org_trust");
        assert_eq!(
            req.body.as_ref().and_then(|b| b.get("partners")),
            Some(&json!(["partner.example", "partner.example"]))
        );
        // Домен из принятых доменов организации — 422, текст detail у списка доменов.
        app.on_result(
            *id,
            refused("принятый домен организации не может быть партнёром"),
        );
        assert_eq!(
            trust_of(&app).err.as_deref(),
            Some("принятый домен организации не может быть партнёром")
        );
        // Повторная запись прошла: список перечитан.
        assert!(app.on_key(key(KeyCode::F(7))).is_empty());
        for c in "mail.example".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, _)] = fx.as_slice() else {
            panic!("нет записи доменов: {fx:?}");
        };
        let fx = app.on_result(*id, ok(org_view()));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет перечитывания: {fx:?}");
        };
        assert_eq!(req.op.id, "get_org_trust");
        app.on_result(*id, ok(org_view()));
        assert!(trust_of(&app).err.is_none());
        // Курсор на строку автопересылки, F7 — домен попадает в список автопересылки.
        assert!(app.on_key(key(KeyCode::Down)).is_empty());
        assert!(app.on_key(key(KeyCode::F(7))).is_empty());
        for c in "other.example".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет записи доменов: {fx:?}");
        };
        assert_eq!(
            req.body
                .as_ref()
                .and_then(|b| b.get("auto_forward_domains")),
            Some(&json!(["mail.example", "other.example"]))
        );
        let fx = app.on_result(*id, ok(org_view()));
        let [Effect::Call(id, _)] = fx.as_slice() else {
            panic!("нет перечитывания: {fx:?}");
        };
        app.on_result(*id, ok(org_view()));
        // F8 на строке партнёра — домен удалён из списка партнёров.
        trust_mut(&mut app).pick = 0;
        let fx = app.on_key(key(KeyCode::F(8)));
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет удаления домена: {fx:?}");
        };
        assert_eq!(
            req.body.as_ref().and_then(|b| b.get("partners")),
            Some(&json!([]))
        );
        let fx = app.on_result(*id, ok(org_view()));
        let [Effect::Call(id, _)] = fx.as_slice() else {
            panic!("нет перечитывания: {fx:?}");
        };
        app.on_result(*id, ok(org_view()));
        // F2 — назад к матрице; строка доменов под матрицей.
        assert!(app.on_key(key(KeyCode::F(2))).is_empty());
        assert_eq!(trust_of(&app).tab, Tab::Matrix);
        assert_eq!(
            domain_line(trust_of(&app)).as_deref(),
            Some("Партнёры: 1 · автопересылка: 1 · F2 — домены")
        );
    }

    /// Организация подняла занятость партнёру выше потолка установки: клетка помечена «▲», действует потолок.
    #[test]
    fn over_ceiling_marked() {
        let mut app = with_accounts();
        let id = call(&section(&mut app, "Доверие"), SECTION_OP);
        app.on_result(id, ok(over_json()));
        cell_at(&mut app, "freebusy", 1);
        let t = trust_of(&app);
        let v = t.view.as_ref().expect("матрица");
        let (text, mark) = cell(v, "freebusy", "partner", false);
        assert_eq!(mark, Mark::Over, "клетка выше потолка");
        assert_eq!(text, "▲нет", "действует потолок, знак ▲");
        assert!(status(t).contains("выше потолка"));
    }

    /// Строка состояния: полное название функции, потолок; у закреплённой клетки — пояснение.
    #[test]
    fn status_line_explains_cell() {
        let mut app = with_trust();
        let s = status(trust_of(&app));
        assert!(s.contains("Новое приглашение"), "{s}");
        assert!(s.contains("потолок"), "{s}");
        // Курсор на закреплённой клетке (приглашение соседу — «кнопка»).
        cell_at(&mut app, "invite_new", 2);
        assert!(status(trust_of(&app)).contains("закреплено"));
    }

    /// Групп в организации нет — форма выбора возвращается с ошибкой.
    #[test]
    fn group_pick_without_groups() {
        let mut app = with_trust();
        assert!(app.on_key(key(KeyCode::F(5))).is_empty());
        let fx = app.on_key(key(KeyCode::Enter));
        let id = call(&fx, "list_groups");
        app.on_result(id, ok(json!([])));
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::TrustPick { what, form }) = &m.overlay else {
            panic!("форма выбора не вернулась");
        };
        assert_eq!(*what, Pick::Group);
        assert_eq!(form.error.as_deref(), Some("в организации нет групп"));
    }

    /// Учётная запись не найдена — форма возвращается с ошибкой у поля.
    #[test]
    fn account_pick_not_found() {
        let mut app = with_trust();
        assert!(app.on_key(key(KeyCode::F(6))).is_empty());
        for c in "nobody@it-task.ru".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        let fx = app.on_key(key(KeyCode::Enter));
        let id = call(&fx, "list_accounts");
        app.on_result(id, ok(json!([])));
        let Stage::Main(m) = &app.stage else {
            panic!("не основной экран");
        };
        let Some(Overlay::TrustPick { form, .. }) = &m.overlay else {
            panic!("форма выбора не вернулась");
        };
        assert_eq!(
            form.fields[0].error.as_deref(),
            Some("нет учётной записи с этим именем входа")
        );
    }

    /// Раздел открывается из дерева: уровень организации, политика прочитана.
    #[test]
    fn section_opens_org_level() {
        let app = with_trust();
        let t = trust_of(&app);
        assert_eq!(t.scope, Scope::Org);
        assert_eq!(t.tab, Tab::Matrix);
        let v = t.view.as_ref().expect("политика");
        assert_eq!(
            cell_value(v, "invite_new", "partner"),
            "auto",
            "организация подняла клетку"
        );
        assert_eq!(domains(t).0.len(), 1);
        assert_eq!(
            command(t),
            "thepost admin trust set --file <ПУТЬ> --org 00000000-0000-0000-0000-000000000001"
        );
    }
}
