//! Мышь в текстовом интерфейсе (TUI-07, решение 119): щелчок выбирает строку и панель, двойной — открывает,
//! щелчок по F-клавише внизу — её действие, колесо — прокрутка, перетаскивание границы двух панелей меняет
//! их ширину. Клавиатура остаётся полной: каждое действие доступно и без мыши. Логика чистая — экран
//! проверяется тестами без терминала; пиксельные события (режим `1016`) приводятся к ячейкам до входа
//! ([`crate::cursor::SmoothCursor::point`]), истинные пиксели приходят параметром `px`.

use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};

use crate::app::{App, BODY_ROWS, Effect, LIST_ROWS, Main, Overlay, Panel, Stage, TreeRow, View};
use crate::schema::catalog;
use crate::tree::{ORG_ROWS, SECTIONS};
use crate::ui::{ROW_KEYS, WIDTH};

/// Пороги мыши (SRS 5.5): секция конфигурации крейта со значениями по умолчанию.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseConfig {
    /// Интервал двойного щелчка, мс.
    pub double_click_ms: u64,
    /// Строк прокрутки за один оборот колеса.
    pub wheel_lines: usize,
    /// Наименьшая ширина левой панели, колонок.
    pub min_left: u16,
    /// Наибольшая ширина левой панели, колонок (от ширины экрана — не больше «экран − 24»).
    pub max_left: u16,
    /// Шагов плавного курсора на ячейку (квантование сдвига).
    pub shift_steps: u16,
    /// Ожидание ответа терминала на опрос режима `1016`, мс.
    pub query_timeout_ms: u64,
    /// Размер ячейки консоли Linux по умолчанию, пиксели (уточняется по sysfs).
    pub console_cell: (u16, u16),
}

impl Default for MouseConfig {
    fn default() -> Self {
        Self {
            double_click_ms: 500,
            wheel_lines: 3,
            min_left: 16,
            max_left: 56,
            shift_steps: 8,
            query_timeout_ms: 300,
            console_cell: (8, 16),
        }
    }
}

/// Состояние мыши интерфейса.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MouseState {
    /// Пороги.
    pub cfg: MouseConfig,
    /// Ячейка под курсором.
    pub pos: Option<(u16, u16)>,
    /// Пиксели терминала под курсором (режим `1016`, `/dev/input`).
    pub px: Option<(u16, u16)>,
    /// Последний щелчок: ячейка и момент — для двойного.
    click: Option<((u16, u16), Instant)>,
    /// Идёт перетаскивание границы панелей.
    drag: bool,
}

impl MouseState {
    /// Щелчок в ячейке `(x, y)`: двойной, если предыдущий был в той же ячейке внутри интервала.
    fn double(&mut self, x: u16, y: u16) -> bool {
        let now = Instant::now();
        let hit = self.click.is_some_and(|((cx, cy), at)| {
            (cx, cy) == (x, y)
                && now.duration_since(at).as_millis() < u128::from(self.cfg.double_click_ms)
        });
        self.click = Some(((x, y), now));
        hit
    }

    /// Идёт перетаскивание границы панелей.
    pub fn dragging(&self) -> bool {
        self.drag
    }
}

/// Накопитель координат `/dev/input`: относительные смещения мыши — в абсолютные пиксели экрана.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracker {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

impl Tracker {
    /// Экран `px` пикселей; курсор стартует в левом верхнем углу.
    pub fn new(px: (u16, u16)) -> Self {
        Self {
            x: 0,
            y: 0,
            w: i32::from(px.0),
            h: i32::from(px.1),
        }
    }

    /// Сдвиг от мыши.
    pub fn move_by(&mut self, dx: i32, dy: i32) {
        self.x = (self.x + dx).clamp(0, self.w - 1);
        self.y = (self.y + dy).clamp(0, self.h - 1);
    }

    /// Позиция в пикселях.
    pub fn pos(&self) -> (u16, u16) {
        (self.x.max(0) as u16, self.y.max(0) as u16)
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

impl App {
    /// Событие мыши: координаты `column`/`row` — ячейки, `px` — истинные пиксели, если терминал их даёт.
    pub fn on_mouse(&mut self, ev: &MouseEvent, px: Option<(u16, u16)>) -> Vec<Effect> {
        let (x, y) = (ev.column, ev.row);
        self.mouse.px = px;
        self.mouse.pos = Some((x, y));
        match ev.kind {
            MouseEventKind::Moved => Vec::new(),
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                self.wheel(x, y, ev.kind == MouseEventKind::ScrollDown)
            }
            MouseEventKind::Down(MouseButton::Left) => self.click(x, y),
            MouseEventKind::Drag(MouseButton::Left) => self.drag_border(x),
            MouseEventKind::Up(MouseButton::Left) => {
                self.mouse.drag = false;
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// Щелчок: F-клавиша внизу, панель и строка; двойной — открыть.
    fn click(&mut self, x: u16, y: u16) -> Vec<Effect> {
        let double = self.mouse.double(x, y);
        if y == ROW_KEYS {
            if double {
                return Vec::new();
            }
            let i = usize::from(x) / 8;
            if (0..10).contains(&i) && !self.keys()[i].is_empty() {
                let n = u8::try_from(i + 1).unwrap_or(1);
                return self.on_key(key(KeyCode::F(n)));
            }
            return Vec::new();
        }
        let mut open = false;
        let mut close_help = false;
        if let Stage::Login(f) = &mut self.stage {
            // Поля формы входа: щелчок ставит курсор в поле.
            let at = usize::from(y.saturating_sub(8));
            if let Some(field) = f.fields().get(at) {
                f.focus = *field;
            }
        }
        if let Stage::Main(m) = &mut self.stage {
            let left = m.left;
            if (1..ROW_KEYS - 2).contains(&y) && x.abs_diff(left) <= 1 {
                // Граница панелей: начать перетаскивание.
                self.mouse.drag = true;
                return Vec::new();
            }
            if x < left {
                // Дерево ресурсов.
                m.focus = Panel::Tree;
                if let Some(i) = tree_index(m, y) {
                    m.tree = i;
                    open = double;
                }
            } else {
                m.focus = Panel::Main;
                match &mut m.overlay {
                    Some(Overlay::Menu { sel }) => {
                        if let Some(i) = menu_index(*sel, y) {
                            *sel = i;
                            open = double;
                        }
                    }
                    Some(Overlay::Form(f)) | Some(Overlay::Lookup(f, _)) => {
                        if let Some(i) = form_index(f, y) {
                            f.focus = i;
                        }
                    }
                    Some(Overlay::Help) => close_help = true,
                    Some(Overlay::Confirm(_)) | Some(Overlay::ConfigEdit(_)) => {}
                    None => match &mut m.view {
                        View::List(l) => {
                            if let Some(i) = list_index(y, l.top, l.rows.len()) {
                                l.select(i);
                                open = double;
                            }
                        }
                        View::Config(c) => {
                            if let Some(i) = list_index(y, c.top, c.rows().len()) {
                                c.select(i);
                                open = double;
                            }
                        }
                        View::Card(_) | View::Info { .. } => {}
                    },
                }
            }
        }
        if close_help {
            // Справка закрывается любой клавишей — и щелчком.
            return self.on_key(key(KeyCode::Char(' ')));
        }
        if open {
            // Двойной щелчок — то же, что Enter.
            return self.on_key(key(KeyCode::Enter));
        }
        Vec::new()
    }

    /// Перетаскивание границы: ширина левой панели следует за указателем.
    fn drag_border(&mut self, x: u16) -> Vec<Effect> {
        if !self.mouse.drag {
            return Vec::new();
        }
        if let Stage::Main(m) = &mut self.stage {
            let w = WIDTH.max(x.saturating_add(1));
            let max = self.mouse.cfg.max_left.min(w.saturating_sub(24));
            m.left = x.clamp(self.mouse.cfg.min_left, max.max(self.mouse.cfg.min_left));
        }
        Vec::new()
    }

    /// Колесо: прокрутка панели под указателем (фокус клавиатуры не трогаем).
    fn wheel(&mut self, x: u16, _y: u16, down: bool) -> Vec<Effect> {
        let lines = self.mouse.cfg.wheel_lines;
        let code = if down { KeyCode::Down } else { KeyCode::Up };
        let Stage::Main(m) = &mut self.stage else {
            return Vec::new();
        };
        if x < m.left {
            let n = m.tree_rows().len().saturating_sub(1);
            for _ in 0..lines {
                m.tree = if down {
                    (m.tree + 1).min(n)
                } else {
                    m.tree.saturating_sub(1)
                };
            }
            return Vec::new();
        }
        if let Some(Overlay::Menu { sel }) = &mut m.overlay {
            let n = catalog().ops.len().saturating_sub(1);
            for _ in 0..lines {
                *sel = if down {
                    (*sel + 1).min(n)
                } else {
                    sel.saturating_sub(1)
                };
            }
            return Vec::new();
        }
        let mut effects = Vec::new();
        for _ in 0..lines {
            effects.extend(crate::app::view_key(m, &mut self.bus, key(code)));
        }
        effects
    }
}

/// Строка дерева по строке экрана: разделы с 3-й, другие организации за ними, конфигурация узла на 18-й.
fn tree_index(m: &Main, y: u16) -> Option<usize> {
    let rows = m.tree_rows();
    let y_of = |i: usize| match rows.get(i) {
        Some(TreeRow::Section(s)) => Some(3u16 + *s as u16),
        Some(TreeRow::Org(o)) => Some(3 + SECTIONS.len() as u16 + *o as u16),
        Some(TreeRow::Config) => Some(3 + SECTIONS.len() as u16 + ORG_ROWS as u16 + 1),
        None => None,
    };
    (0..rows.len()).find(|&i| y_of(i) == Some(y))
}

/// Строка меню F9 по строке экрана (листание меню — как в отрисовке).
fn menu_index(sel: usize, y: u16) -> Option<usize> {
    let top = sel.saturating_sub(BODY_ROWS - 1);
    let i = top + usize::from(y.saturating_sub(2));
    let n = catalog().ops.len();
    (2..2 + BODY_ROWS as u16)
        .contains(&y)
        .then_some(i)
        .filter(|i| *i < n)
}

/// Поле формы по строке экрана: строки «поле, под ним ошибка» с 5-й.
fn form_index(f: &mut crate::engine::Form, y: u16) -> Option<usize> {
    let mut lines: Vec<(usize, bool)> = Vec::new();
    for (i, ff) in f.fields.iter().enumerate() {
        lines.push((i, false));
        if ff.error.is_some() {
            lines.push((i, true));
        }
    }
    let rows = 12usize;
    let at = lines.iter().position(|(i, _)| *i == f.focus).unwrap_or(0);
    let top = at.saturating_sub(rows - 2);
    let n = usize::from(y.saturating_sub(5)) + top;
    match lines.get(n) {
        Some((i, false)) => Some(*i),
        _ => None,
    }
}

/// Строка списка по строке экрана.
fn list_index(y: u16, top: usize, len: usize) -> Option<usize> {
    let i = top + usize::from(y.saturating_sub(3));
    (3..3 + LIST_ROWS as u16)
        .contains(&y)
        .then_some(i)
        .filter(|i| *i < len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::tests::{ok, with_accounts, with_members};
    use crate::app::{LoginField, LoginForm, Overlay, Panel, Stage, View};
    use crate::layout;
    use crate::node::load;
    use crate::node::tests::Dir;
    use crate::theme::{Brand, Mode, Theme};
    use crate::ui::{HEIGHT, LEFT};
    use serde_json::json;

    fn mouse(kind: MouseEventKind, x: u16, y: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn click(app: &mut App, x: u16, y: u16) -> Vec<Effect> {
        app.on_mouse(&mouse(MouseEventKind::Down(MouseButton::Left), x, y), None)
    }

    fn down(x: u16, y: u16) -> MouseEvent {
        mouse(MouseEventKind::Down(MouseButton::Left), x, y)
    }

    fn view(app: &App) -> &Main {
        match &app.stage {
            Stage::Main(m) => m,
            Stage::Login(_) => panic!("не вошли"),
        }
    }

    /// Щелчок выбирает строку списка и правую панель; двойной — открывает запись.
    #[test]
    fn click_selects_and_opens() {
        let mut app = with_accounts();
        assert!(click(&mut app, 40, 5).is_empty());
        let m = view(&app);
        assert_eq!(m.focus, Panel::Main);
        let View::List(l) = &m.view else {
            panic!("не список");
        };
        assert_eq!(l.sel, 2, "строка под щелчком");
        // Двойной щелчок по той же строке — открыть (Enter).
        let fx = click(&mut app, 40, 5);
        let [Effect::Call(_, req)] = fx.as_slice() else {
            panic!("нет запроса: {fx:?}");
        };
        assert_eq!(req.op.id, "get_account");
    }

    /// Щелчок по дереву выбирает раздел и панель; двойной — открывает раздел.
    #[test]
    fn click_tree_and_open() {
        let mut app = with_accounts();
        assert!(click(&mut app, 5, 5).is_empty());
        let m = view(&app);
        assert_eq!((m.focus, m.tree), (Panel::Tree, 2));
        assert_eq!(app.command_line(), "thepost admin group list");
        // Двойной — Enter: открывается список групп.
        let fx = click(&mut app, 5, 5);
        assert!(
            matches!(fx.as_slice(), [Effect::Call(_, r)] if r.op.id == "list_groups"),
            "{fx:?}"
        );
    }

    /// F-клавиши внизу: щелчок — её действие; пустая подпись — ничего.
    #[test]
    fn fkeys_bar() {
        let mut app = with_accounts();
        assert!(
            click(&mut app, 8 * 8, 23).is_empty(),
            "F9 открывает меню без запросов"
        );
        assert!(matches!(view(&app).overlay, Some(Overlay::Menu { .. })));
        // Меню: щелчок выбирает операцию, двойной — открывает её. Индекс — по составу каталога
        // (первая операция-список: жёсткий индекс ломается от новых путей схемы).
        let i = catalog()
            .ops
            .iter()
            .position(|o| o.is_list())
            .expect("операция-список");
        let y = 2 + i as u16;
        assert!(click(&mut app, 40, y).is_empty());
        let Some(Overlay::Menu { sel }) = &view(&app).overlay else {
            panic!("нет меню");
        };
        assert_eq!(*sel, i);
        // Двойной щелчок по операции — открыть её экран (список или карточка).
        let fx = click(&mut app, 40, y);
        let want = catalog().ops[i].id.clone();
        assert!(
            matches!(fx.as_slice(), [Effect::Call(_, r)] if r.op.id == want),
            "{fx:?}"
        );
        assert!(
            !matches!(view(&app).overlay, Some(Overlay::Menu { .. })),
            "меню закрыто"
        );
        // F10 — выход; клавиша с пустой подписью — ничего.
        assert_eq!(click(&mut app, 72, 23), vec![Effect::Quit]);
        let mut app = with_accounts();
        let _ = app.on_key(key(KeyCode::F(9)));
        assert!(click(&mut app, 40, 23).is_empty(), "F5 без подписи");
        assert!(matches!(view(&app).overlay, Some(Overlay::Menu { .. })));
    }

    /// Колесо: список под указателем, дерево под указателем; фокус клавиатуры не меняется.
    #[test]
    fn wheel_scrolls() {
        let mut app = with_accounts();
        app.on_mouse(&mouse(MouseEventKind::ScrollDown, 40, 10), None);
        let m = view(&app);
        let View::List(l) = &m.view else { panic!() };
        assert_eq!((l.sel, m.focus), (3, Panel::Main), "три строки за оборот");
        app.on_mouse(&mouse(MouseEventKind::ScrollUp, 40, 10), None);
        let m = view(&app);
        let View::List(l) = &m.view else { panic!() };
        assert_eq!(l.sel, 0);
        // Колесо над деревом листает дерево, не трогая список.
        app.on_mouse(&mouse(MouseEventKind::ScrollDown, 5, 5), None);
        let m = view(&app);
        let View::List(l) = &m.view else { panic!() };
        assert_eq!((m.tree, l.sel), (3, 0));
        assert_eq!(m.focus, Panel::Main, "фокус не меняется");
    }

    /// Перетаскивание границы двух панелей меняет их ширину.
    #[test]
    fn drag_panel_border() {
        let mut app = with_accounts();
        assert!(click(&mut app, LEFT - 1, 10).is_empty());
        assert!(app.mouse.dragging());
        app.on_mouse(
            &mouse(MouseEventKind::Drag(MouseButton::Left), 40, 10),
            None,
        );
        assert_eq!(view(&app).left, 40);
        app.on_mouse(
            &mouse(MouseEventKind::Drag(MouseButton::Left), 10, 10),
            None,
        );
        assert_eq!(view(&app).left, 16, "не уже минимума");
        app.on_mouse(
            &mouse(MouseEventKind::Drag(MouseButton::Left), 79, 10),
            None,
        );
        assert_eq!(view(&app).left, 56, "не шире максимума");
        app.on_mouse(&mouse(MouseEventKind::Up(MouseButton::Left), 79, 10), None);
        assert!(!app.mouse.dragging());
        // Отпущенная граница больше не тянется.
        app.on_mouse(
            &mouse(MouseEventKind::Drag(MouseButton::Left), 30, 10),
            None,
        );
        assert_eq!(view(&app).left, 56);
    }

    /// Конфигурация узла: щелчок выбирает параметр, двойной — правка.
    #[test]
    fn click_config() {
        let dir = Dir::new();
        let node = dir.node("{\"domain\": \"it-task.ru\"}\n");
        let mut app = with_accounts();
        app.node = true;
        let _ = app.on_key(key(KeyCode::Tab));
        let _ = app.on_key(key(KeyCode::End));
        let _ = app.on_key(key(KeyCode::Enter));
        app.on_config(load(&node));
        assert!(click(&mut app, 40, 3).is_empty());
        let m = view(&app);
        let View::Config(c) = &m.view else {
            panic!("не конфигурация");
        };
        assert_eq!(c.sel, 0);
        let fx = click(&mut app, 40, 3);
        assert!(fx.is_empty());
        assert!(matches!(view(&app).overlay, Some(Overlay::ConfigEdit(_))));
    }

    /// Форма входа: щелчок по полю ставит в него курсор; колесо и граница там не действуют.
    #[test]
    fn login_click() {
        let mut app = App::new(
            Theme::new(Mode::Mono, Brand::default()),
            LoginForm::new("https://node:9443".into(), false),
        );
        click(&mut app, 30, 11);
        let Stage::Login(f) = &app.stage else {
            panic!()
        };
        assert_eq!(f.focus, LoginField::Secret);
        app.on_mouse(&mouse(MouseEventKind::ScrollDown, 30, 10), None);
        app.on_mouse(
            &mouse(MouseEventKind::Drag(MouseButton::Left), 40, 10),
            None,
        );
        assert_eq!(app.cursor, None);
    }

    /// Участники группы: щелчок по строке, двойной — состав записи (Enter раскладки).
    #[test]
    fn click_layout_rows() {
        let mut app = with_members();
        let _ = app.on_mouse(&down(40, 4), None);
        let m = view(&app);
        let View::List(l) = &m.view else { panic!() };
        assert_eq!(l.sel, 1);
        assert_eq!(l.layout, Some(&layout::MEMBERS));
        // Двойной по строке раскладки без операции открытия — ничего: участники сами не открываются.
        assert!(click(&mut app, 40, 4).is_empty());
        assert!(matches!(view(&app).view, View::List(_)));
    }

    /// Форма: щелчок по полю выбирает его.
    #[test]
    fn click_form_field() {
        let mut app = with_accounts();
        let _ = app.on_key(key(KeyCode::F(2)));
        assert!(click(&mut app, 40, 7).is_empty());
        let Some(Overlay::Form(f)) = &view(&app).overlay else {
            panic!("нет формы");
        };
        assert!(f.focus > 0, "щелчок по второму полю: {f:?}");
    }

    /// Пиксельные координаты сохраняются для плавного курсора.
    #[test]
    fn pixel_position_kept() {
        let mut app = with_accounts();
        app.on_mouse(&mouse(MouseEventKind::Moved, 7, 15), Some((61, 205)));
        assert_eq!(app.mouse.px, Some((61, 205)));
        assert_eq!(app.mouse.pos, Some((7, 15)));
        assert!(app.cursor.is_none(), "курсор ставит цикл терминала");
    }

    /// Трекер `/dev/input`: смещения копятся и не выходят за экран.
    #[test]
    fn tracker_clamps() {
        let mut t = Tracker::new((1920, 1080));
        t.move_by(100, 50);
        assert_eq!(t.pos(), (100, 50));
        t.move_by(-200, 0);
        assert_eq!(t.pos(), (0, 50));
        t.move_by(5000, 5000);
        assert_eq!(t.pos(), (1919, 1079));
    }

    /// Разметка попаданий: вне строк выбора нет.
    #[test]
    fn hit_rows() {
        let mut app = with_accounts();
        assert!(click(&mut app, 5, 2).is_empty(), "заголовок организации");
        assert_eq!(view(&app).tree, 0, "без смены строки");
        assert!(click(&mut app, 5, 17).is_empty(), "разделитель дерева");
        assert!(click(&mut app, 5, 19).is_empty(), "подпись config.yaml");
        assert_eq!(view(&app).tree, 0);
        assert!(click(&mut app, 40, 2).is_empty(), "заголовки колонок");
        let View::List(l) = &view(&app).view else {
            panic!()
        };
        assert_eq!(l.sel, 0);
        assert!(
            click(&mut app, 40, 17).is_empty(),
            "подробности под списком"
        );
        assert!(click(&mut app, 40, 21).is_empty(), "строка состояния");
    }

    /// Прокрутка в конце списка подгружает следующую страницу.
    #[test]
    fn wheel_loads_next_page() {
        let mut app = with_accounts();
        let _ = app.on_key(key(KeyCode::End));
        let fx = app.on_mouse(&mouse(MouseEventKind::ScrollDown, 40, 10), None);
        let [Effect::Call(id, req)] = fx.as_slice() else {
            panic!("нет запроса: {fx:?}");
        };
        assert_eq!(req.op.id, "list_accounts");
        let _ = app.on_result(
            *id,
            ok(json!([{"id": "acc-20", "login": "user20@it-task.ru"}])),
        );
        let View::List(l) = &view(&app).view else {
            panic!()
        };
        assert_eq!(l.rows.len(), 21);
    }

    /// Щелчок по справке закрывает её.
    #[test]
    fn click_closes_help() {
        let mut app = with_accounts();
        let _ = app.on_key(key(KeyCode::F(1)));
        assert!(matches!(view(&app).overlay, Some(Overlay::Help)));
        assert!(click(&mut app, 40, 10).is_empty());
        assert!(view(&app).overlay.is_none());
    }

    /// Двойной щелчок узнаётся только в той же ячейке и внутри интервала.
    #[test]
    fn double_click_window() {
        let mut app = with_accounts();
        app.mouse.cfg.double_click_ms = 0;
        assert!(
            click(&mut app, 40, 5).is_empty(),
            "первый щелчок — только выбор"
        );
        assert!(
            click(&mut app, 40, 5).is_empty(),
            "нулевой интервал — двойного нет"
        );
        // Другая ячейка — не двойной.
        app.mouse.cfg.double_click_ms = 500;
        assert!(click(&mut app, 5, 2).is_empty());
        assert!(
            click(&mut app, 41, 5).is_empty(),
            "соседняя ячейка — не двойной"
        );
        let View::List(l) = &view(&app).view else {
            panic!()
        };
        assert_eq!(l.sel, 2, "без открытия");
        assert_eq!(HEIGHT, 24);
    }
}
