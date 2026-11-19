//! Тема экрана по токенам `design/tokens.toml` (TUI-06, решение 119): пять режимов, роли как у веб-консоли,
//! градиент строки меню, знак бренда на экране входа и палитра консоли Linux.
//!
//! Цвета берутся только из токенов (`include_str!`), второго списка в коде нет. Брендинг заказчика (TUI-08,
//! решение 122) приходит с сервера — название, знак PNG и палитра ролей обеих тем; своих расчётов цветов нет:
//! роли сервера применяются как есть в truecolor и 256 (ближайший xterm-256 к роли тёмной темы), в 16 цветах и
//! монохроме — встроенные роли TUI-06, палитра консоли Linux — `[palette16]` токенов. Палитра сервера проходит
//! страховку контракта `Palette::guarded` — пара ниже порога берётся с уровня выше (IT TASK).

use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, OnceLock};

use ratatui::buffer::Buffer;
use ratatui::layout::{Rect, Size};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::Widget;
use ratatui_image::picker::{Picker, ProtocolType};
use ratatui_image::protocol::Protocol;
use ratatui_image::{Image, Resize};
use tp_admin::branding::{BrandingView, PublicBranding};

/// Токены фирменного стиля — единственный источник цветов.
const TOKENS: &str = include_str!("../../../design/tokens.toml");
/// Знак IT TASK — куб из `design/logo.svg` (грани в цветах бренда), PNG с прозрачным фоном.
const IT_TASK_MARK: &[u8] = include_bytes!("../assets/it-task.png");
/// Переменная окружения с режимом темы: перекрывает автоопределение, ключ `--theme` перекрывает её.
pub const ENV_THEME: &str = "THEPOST_TUI_THEME";
/// Высота знака на экране входа, строк.
pub const MARK_ROWS: u16 = 4;
/// Наибольшая ширина знака на экране входа, колонок.
pub const MARK_COLS: u16 = 8;
/// Уровни каналов куба xterm-256.
const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];

/// Роль ячейки экрана (как в `design/tokens.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Фон экрана.
    Screen,
    /// Фон панели.
    Panel,
    /// Текст.
    Text,
    /// Вторичный текст.
    Muted,
    /// Рамка неактивной панели.
    Frame,
    /// Рамка активной панели.
    FrameA,
    /// Заголовок активной панели.
    TitleA,
    /// Заголовки колонок.
    Head,
    /// Выделенная строка активной панели.
    Sel,
    /// Выделенная строка неактивной панели.
    SelI,
    /// Номер F-клавиши.
    FkNum,
    /// Подпись F-клавиши.
    Fk,
    /// Строка меню, сплошная (градиент — [`Theme::menu`]).
    Menu,
    /// Знак `$` строки команды.
    Prompt,
    /// Команда CLI.
    Cmd,
    /// Название бренда на экране входа: белое или чёрное по фону режима.
    Name,
    /// Норма ●.
    Ok,
    /// Внимание ▲.
    Warn,
    /// Ошибка ×.
    Err,
}

/// Режим цвета.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Truecolor, тёмный фон.
    Dark,
    /// Truecolor, светлый фон.
    Light,
    /// 256 цветов xterm.
    C256,
    /// 16 цветов терминала.
    C16,
    /// Без цвета: атрибуты.
    Mono,
}

impl Mode {
    /// Режим по имени: `dark`, `light`, `256`, `16`, `mono`.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "dark" => Some(Self::Dark),
            "light" => Some(Self::Light),
            "256" => Some(Self::C256),
            "16" => Some(Self::C16),
            "mono" => Some(Self::Mono),
            _ => None,
        }
    }

    /// Режим по ключу `--theme` (`flag`), `THEPOST_TUI_THEME` и окружению терминала (`var` читает
    /// переменную). `auto` или ничего — автоопределение: `NO_COLOR` → монохром; `COLORTERM=truecolor|24bit`
    /// или Windows Terminal (`WT_SESSION`) → truecolor тёмный; `TERM` с `256color` → 256; `TERM=dumb` →
    /// монохром; прочее, и `TERM=linux`, → 16.
    pub fn detect(
        var: impl Fn(&str) -> Option<String>,
        flag: Option<&str>,
    ) -> Result<Self, String> {
        let set = |name: &str| var(name).filter(|v| !v.is_empty());
        let choice = flag.map(str::to_owned).or_else(|| set(ENV_THEME));
        if let Some(c) = choice.filter(|c| c.trim() != "auto") {
            return Self::parse(&c)
                .ok_or_else(|| format!("тема «{c}»: нужно auto, dark, light, 256, 16 или mono"));
        }
        if set("NO_COLOR").is_some() {
            return Ok(Self::Mono);
        }
        let colorterm = set("COLORTERM").unwrap_or_default().to_ascii_lowercase();
        if colorterm == "truecolor" || colorterm == "24bit" || set("WT_SESSION").is_some() {
            return Ok(Self::Dark);
        }
        let term = set("TERM").unwrap_or_default();
        Ok(if term.contains("256color") {
            Self::C256
        } else if term == "dumb" {
            Self::Mono
        } else {
            Self::C16
        })
    }

    /// Показывается ли знак картинкой: протоколом графики терминала или цветными полублоками.
    pub fn graphics(self) -> bool {
        matches!(self, Self::Dark | Self::Light | Self::C256)
    }
}

/// Цвет `#RRGGBB`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

impl Rgb {
    /// Цвет из `#RRGGBB`.
    pub fn parse(s: &str) -> Option<Self> {
        let h = s.strip_prefix('#')?;
        if h.len() != 6 || !h.is_ascii() {
            return None;
        }
        let byte = |i: usize| u8::from_str_radix(&h[i..i + 2], 16).ok();
        Some(Self(byte(0)?, byte(2)?, byte(4)?))
    }

    /// Смесь: `t` = 0 — этот цвет, 1 — `other`.
    fn mix(self, other: Self, t: f64) -> Self {
        let m = |a: u8, b: u8| (f64::from(a) + (f64::from(b) - f64::from(a)) * t).round() as u8;
        Self(m(self.0, other.0), m(self.1, other.1), m(self.2, other.2))
    }

    fn color(self) -> Color {
        Color::Rgb(self.0, self.1, self.2)
    }

    /// Ближайший цвет xterm-256: куб 6×6×6 (ближайший уровень по каждому каналу) или серая шкала 232–255.
    pub fn xterm256(self) -> u8 {
        let near = |v: u8| {
            (0..6u8)
                .min_by_key(|&i| LEVELS[usize::from(i)].abs_diff(v))
                .unwrap_or_default()
        };
        let dist = |i: u8| {
            let c = xterm_rgb(i);
            [(c.0, self.0), (c.1, self.1), (c.2, self.2)]
                .iter()
                .map(|&(a, b)| u32::from(a.abs_diff(b)).pow(2))
                .sum::<u32>()
        };
        let cube = 16 + 36 * near(self.0) + 6 * near(self.1) + near(self.2);
        (232..=255u8).fold(cube, |best, g| if dist(g) < dist(best) { g } else { best })
    }
}

/// Цвет xterm-256 с номером `i` (куб и серая шкала; 0–15 — по палитре `[palette16]`).
fn xterm_rgb(i: u8) -> Rgb {
    match i {
        0..=15 => tokens().palette16[usize::from(i)],
        16..=231 => {
            let n = usize::from(i - 16);
            Rgb(LEVELS[n / 36], LEVELS[n / 6 % 6], LEVELS[n % 6])
        }
        _ => {
            let g = 8 + 10 * (i - 232);
            Rgb(g, g, g)
        }
    }
}

impl fmt::Display for Rgb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{:02X}{:02X}{:02X}", self.0, self.1, self.2)
    }
}

/// PNG знака бренда.
#[derive(Clone, PartialEq, Eq)]
pub struct Png(pub Arc<[u8]>);

impl fmt::Debug for Png {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Png({} байт)", self.0.len())
    }
}

/// Бренд, из которого строятся роли (решение 122): название, знак и палитра ролей сервера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Brand {
    /// Название на экране входа и в строке меню; встроенное — IT TASK.
    pub name: String,
    /// Знак для экрана входа; нет — только название.
    pub mark: Option<Png>,
    /// Встроенный знак IT TASK: показывается и полублоками, когда терминал не умеет картинки.
    pub builtin_mark: bool,
    /// Роли сервера обеих тем; `None` — встроенные роли TUI-06 (IT TASK).
    pub roles: Option<BrandRoles>,
}

impl Default for Brand {
    /// IT TASK: встроенные роли токенов и знак из `design/logo.svg`.
    fn default() -> Self {
        Self {
            name: "IT TASK".to_owned(),
            mark: Some(Png(Arc::from(IT_TASK_MARK))),
            builtin_mark: true,
            roles: None,
        }
    }
}

impl Brand {
    /// Бренд из действующего брендинга экрана входа (открытый маршрут, TUI-08): палитра проходит страховку
    /// контракта `Palette::guarded` с родителем IT TASK, незаданная роль — цвет IT TASK. Знак — загруженные
    /// байты `logo`: ссылки нет — встроенный куб, по ссылке не загрузился — только название.
    pub fn from_public(pb: PublicBranding, logo: Option<Png>) -> Self {
        let builtin = pb.logo.is_none();
        let palette = pb.palette.guarded(&parent_branding().palette);
        let t = tokens();
        let mut light = t.light;
        let mut dark = t.dark;
        for (map, out) in [(&palette.light, &mut light), (&palette.dark, &mut dark)] {
            for (role, color) in map {
                if let Some(i) = NAMES.iter().position(|n| *n == role.as_str()) {
                    let [r, g, b] = color.rgb();
                    out[i] = Rgb(r, g, b);
                }
            }
        }
        Self {
            name: pb.product_name.unwrap_or_else(|| "IT TASK".to_owned()),
            mark: logo.or_else(|| builtin.then(|| Png(Arc::from(IT_TASK_MARK)))),
            builtin_mark: builtin,
            roles: Some(BrandRoles { light, dark }),
        }
    }

    /// Бренд из действующего брендинга своей организации после входа (`effective`; уровень установки —
    /// администратором установки): та же страховка и знак по хэшу действующего набора.
    pub fn from_effective(view: BrandingView, logo: Option<Png>) -> Self {
        let has_logo = view.effective.logo.is_some();
        let pb = PublicBranding {
            product_name: view.effective.product_name,
            palette: view.effective.palette,
            logo: has_logo.then(String::new),
        };
        Self::from_public(pb, logo)
    }
}

/// Роли сервера (решение 122) — палитра обеих тем из ответа Admin API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BrandRoles {
    /// Светлая тема — `[mode.light]` ролей.
    pub light: [Rgb; N],
    /// Тёмная тема — `[mode.dark]` ролей.
    pub dark: [Rgb; N],
}

/// Родитель страховки `guarded`: пустые карты — `Palette::role` без значения в карте даёт цвет IT TASK
/// (`Role::it_task`), то есть родитель равен `Palette::it_task()` (CTR-91).
fn parent_branding() -> &'static PublicBranding {
    static PARENT: OnceLock<PublicBranding> = OnceLock::new();
    PARENT.get_or_init(|| {
        serde_json::from_str(
            r#"{"product_name":null,"palette":{"light":{},"dark":{},"cli":{}},"logo":null}"#,
        )
        .unwrap_or_else(|e| panic!("пустая палитра брендинга: {e}"))
    })
}

/// Роли токенов — столбцы таблиц `[mode.*]`, в порядке [`NAMES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum T {
    Screen,
    Panel,
    Text,
    Muted,
    Frame,
    FrameA,
    TitleA,
    Head,
    Sel,
    SelFg,
    SelI,
    SelIFg,
    FkBg,
    FkFg,
    Ok,
    Warn,
    Err,
}

const N: usize = 17;
const NAMES: [&str; N] = [
    "screen", "panel", "text", "muted", "frame", "frameA", "titleA", "head", "sel", "selFg",
    "selI", "selIFg", "fkBg", "fkFg", "ok", "warn", "err",
];

/// Разобранные токены.
#[derive(Debug)]
struct Tokens {
    dark: [Rgb; N],
    light: [Rgb; N],
    c256: [u8; N],
    c16: [u8; N],
    mono: [Modifier; N],
    attrs: [Modifier; N],
    palette16: [Rgb; 16],
}

fn tokens() -> &'static Tokens {
    static TOK: OnceLock<Tokens> = OnceLock::new();
    TOK.get_or_init(|| parse_tokens(TOKENS).unwrap_or_else(|e| panic!("design/tokens.toml: {e}")))
}

fn parse_tokens(src: &str) -> Result<Tokens, String> {
    let root: toml::Table = src.parse().map_err(|e| format!("{e}"))?;
    let table = |path: &str| -> Result<&toml::Table, String> {
        path.split('.')
            .try_fold(&root, |t, k| t.get(k).and_then(toml::Value::as_table))
            .ok_or_else(|| format!("нет таблицы [{path}]"))
    };
    let rgb = |v: Option<&toml::Value>, at: &str| {
        v.and_then(toml::Value::as_str)
            .and_then(Rgb::parse)
            .ok_or_else(|| format!("{at}: нужен цвет #RRGGBB"))
    };
    let attrs = |v: Option<&toml::Value>, at: &str| -> Result<Modifier, String> {
        let list = v
            .and_then(toml::Value::as_array)
            .ok_or_else(|| format!("{at}: нужен список атрибутов"))?;
        list.iter().try_fold(Modifier::empty(), |m, a| {
            Ok(m | match a.as_str() {
                Some("bold") => Modifier::BOLD,
                Some("dim") => Modifier::DIM,
                Some("reverse") => Modifier::REVERSED,
                Some("underline") => Modifier::UNDERLINED,
                _ => return Err(format!("{at}: неизвестный атрибут {a:?}")),
            })
        })
    };
    let colors = |path: &str| -> Result<[Rgb; N], String> {
        let t = table(path)?;
        let mut out = [Rgb(0, 0, 0); N];
        for (c, name) in out.iter_mut().zip(NAMES) {
            *c = rgb(t.get(name), &format!("{path}.{name}"))?;
        }
        Ok(out)
    };
    let index = |path: &str, max: u8| -> Result<[u8; N], String> {
        let t = table(path)?;
        let mut out = [0; N];
        for (c, name) in out.iter_mut().zip(NAMES) {
            *c = t
                .get(name)
                .and_then(toml::Value::as_integer)
                .and_then(|n| u8::try_from(n).ok())
                .filter(|n| *n <= max)
                .ok_or_else(|| format!("{path}.{name}: нужен номер 0–{max}"))?;
        }
        Ok(out)
    };
    let (mono_t, attrs_t) = (table("mode.mono")?, table("attrs")?);
    let mut mono = [Modifier::empty(); N];
    let mut role_attrs = [Modifier::empty(); N];
    for ((m, a), name) in mono.iter_mut().zip(role_attrs.iter_mut()).zip(NAMES) {
        *m = attrs(mono_t.get(name), &format!("mode.mono.{name}"))?;
        if let Some(v) = attrs_t.get(name) {
            *a = attrs(Some(v), &format!("attrs.{name}"))?;
        }
    }
    let pal = table("palette16")?
        .get("colors")
        .and_then(toml::Value::as_array)
        .filter(|a| a.len() == 16)
        .ok_or("palette16.colors: нужно 16 цветов")?;
    let mut palette16 = [Rgb(0, 0, 0); 16];
    for (i, (p, c)) in palette16.iter_mut().zip(pal).enumerate() {
        *p = rgb(Some(c), &format!("palette16.colors[{i}]"))?;
    }
    Ok(Tokens {
        dark: colors("mode.dark")?,
        light: colors("mode.light")?,
        c256: index("mode.c256", 255)?,
        c16: index("mode.c16", 15)?,
        mono,
        attrs: role_attrs,
        palette16,
    })
}

/// Знак бренда, подготовленный для терминала (протокол графики или полублоки).
#[derive(Clone)]
pub struct Mark(Arc<Protocol>);

impl Mark {
    /// Размер знака в ячейках.
    pub fn size(&self) -> Size {
        self.0.size()
    }
}

impl fmt::Debug for Mark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self.size();
        write!(f, "Mark({}×{})", s.width, s.height)
    }
}

impl PartialEq for Mark {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// Тема: режим, роли бренда и знак.
#[derive(Debug, Clone, PartialEq)]
pub struct Theme {
    mode: Mode,
    brand: Brand,
    colors: [Color; N],
    attrs: [Modifier; N],
    /// Фон панели в RGB: подложка знака.
    panel: Rgb,
    /// Концы градиента строки меню — роли `sel` и `fkBg` действующей палитры режима.
    gradient: (Rgb, Rgb),
    /// 16 цветов консоли Linux — `[palette16]` токенов (роли сервера в 16 цветов не попадают).
    palette: [Rgb; 16],
    mark: Option<Mark>,
}

impl Theme {
    /// Тема режима `mode` для бренда `brand`; знак — [`Theme::with_mark`]. Роли сервера перекрашивают тему
    /// только в truecolor (`light` или `dark` — по режиму) и 256 (ближайший xterm-256 к роли тёмной темы);
    /// в 16 цветах и монохроме — встроенные роли TUI-06.
    pub fn new(mode: Mode, brand: Brand) -> Self {
        let t = tokens();
        let (mut dark, mut light) = (t.dark, t.light);
        // Роли тёмной темы, заменённые сервером: для них 256-режим берёт ближайший xterm-256, прочие —
        // значения `[mode.c256]` токенов.
        let mut replaced = [false; N];
        if let Some(roles) = &brand.roles {
            for (i, ((d, l), (sd, sl))) in dark
                .iter_mut()
                .zip(light.iter_mut())
                .zip(roles.dark.iter().zip(roles.light.iter()))
                .enumerate()
            {
                if *sd != *d {
                    *d = *sd;
                    replaced[i] = true;
                }
                if *sl != *l {
                    *l = *sl;
                }
            }
        }
        let c256: [u8; N] = std::array::from_fn(|i| {
            if replaced[i] {
                dark[i].xterm256()
            } else {
                t.c256[i]
            }
        });
        let p = T::Panel as usize;
        let (colors, panel) = match mode {
            Mode::Dark => (dark.map(Rgb::color), dark[p]),
            Mode::Light => (light.map(Rgb::color), light[p]),
            Mode::C256 => (c256.map(Color::Indexed), xterm_rgb(c256[p])),
            Mode::C16 => (t.c16.map(ansi16), t.palette16[usize::from(t.c16[p])]),
            Mode::Mono => ([Color::Reset; N], Rgb(0, 0, 0)),
        };
        let (sel, fk) = (T::Sel as usize, T::FkBg as usize);
        let gradient = match mode {
            Mode::Dark | Mode::C256 => (dark[sel], dark[fk]),
            Mode::Light => (light[sel], light[fk]),
            Mode::C16 | Mode::Mono => (t.dark[sel], t.dark[fk]),
        };
        Self {
            mode,
            brand,
            colors,
            attrs: if mode == Mode::Mono { t.mono } else { t.attrs },
            panel,
            gradient,
            palette: t.palette16,
            mark: None,
        }
    }

    /// Тема по окружению ([`Mode::detect`]) и ключу `--theme` (`flag`), бренд IT TASK.
    pub fn from_env(flag: Option<&str>) -> Result<Self, String> {
        let mode = Mode::detect(|k| std::env::var(k).ok(), flag)?;
        Ok(Self::new(mode, Brand::default()))
    }

    /// Режим.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Бренд.
    pub fn brand(&self) -> &Brand {
        &self.brand
    }

    /// 16 цветов консоли Linux — `[palette16]` токенов (роли сервера в 16 цветов не попадают, TUI-06).
    pub fn console_palette(&self) -> &[Rgb; 16] {
        &self.palette
    }

    /// Подготовить знак бренда протоколом `picker`. В 16 цветах и монохроме знака нет — только название;
    /// прозрачный фон знака — цвет панели.
    pub fn with_mark(mut self, picker: &Picker) -> Self {
        self.mark = self.load_mark(picker);
        self
    }

    fn load_mark(&self, picker: &Picker) -> Option<Mark> {
        if !self.mode.graphics() {
            return None;
        }
        // Знак заказчика — только настоящими протоколами графики (kitty, sixel); полублоки — встроенный куб
        // IT TASK (решение 122).
        if !self.brand.builtin_mark && matches!(picker.protocol_type(), ProtocolType::Halfblocks) {
            return None;
        }
        let png = self.brand.mark.as_ref()?;
        let img = image::load_from_memory_with_format(&png.0, image::ImageFormat::Png).ok()?;
        let bg = image::Rgba([self.panel.0, self.panel.1, self.panel.2, 255]);
        let mut flat = image::RgbaImage::from_pixel(img.width(), img.height(), bg);
        image::imageops::overlay(&mut flat, &img.to_rgba8(), 0, 0);
        let protocol = picker
            .new_protocol(
                image::DynamicImage::ImageRgba8(flat),
                Size::new(MARK_COLS, MARK_ROWS),
                Resize::Fit(None),
            )
            .ok()?;
        Some(Mark(Arc::new(protocol)))
    }

    /// Знак бренда, если терминал его покажет.
    pub fn mark(&self) -> Option<&Mark> {
        self.mark.as_ref()
    }

    /// Нарисовать знак в `area`; в 256 цветах полублоки переводятся в ближайшие цвета xterm-256.
    pub fn render_mark(&self, mark: &Mark, area: Rect, buf: &mut Buffer) {
        Image::new(&mark.0).render(area, buf);
        if self.mode != Mode::C256 {
            return;
        }
        let area = area.intersection(buf.area);
        for y in area.top()..area.bottom() {
            for x in area.left()..area.right() {
                let cell = &mut buf[(x, y)];
                for c in [&mut cell.fg, &mut cell.bg] {
                    if let Color::Rgb(r, g, b) = *c {
                        *c = Color::Indexed(Rgb(r, g, b).xterm256());
                    }
                }
            }
        }
    }

    fn fg(&self, r: T) -> Style {
        Style::default()
            .fg(self.colors[r as usize])
            .add_modifier(self.attrs[r as usize])
    }

    fn bg(&self, r: T) -> Style {
        Style::default()
            .bg(self.colors[r as usize])
            .add_modifier(self.attrs[r as usize])
    }

    /// Стиль роли.
    pub fn style(&self, role: Role) -> Style {
        // Жирный в цвете; в монохроме атрибуты — из `[mode.mono]`.
        let bold = if self.mode == Mode::Mono {
            Modifier::empty()
        } else {
            Modifier::BOLD
        };
        match role {
            Role::Screen => self.bg(T::Screen).patch(self.fg(T::Text)),
            Role::Panel => self.bg(T::Panel).patch(self.fg(T::Text)),
            Role::Text | Role::Cmd => self.fg(T::Text),
            Role::Muted => self.fg(T::Muted),
            Role::Frame => self.fg(T::Frame),
            Role::FrameA => self.fg(T::FrameA),
            Role::TitleA | Role::Prompt => self.fg(T::TitleA).add_modifier(bold),
            Role::Head => self.fg(T::Head).add_modifier(bold),
            Role::Sel => self.bg(T::Sel).patch(self.fg(T::SelFg)),
            Role::SelI => self.bg(T::SelI).patch(self.fg(T::SelIFg)),
            Role::FkNum => self.fg(T::Text).add_modifier(Modifier::BOLD),
            Role::Fk | Role::Menu => self.bg(T::FkBg).patch(self.fg(T::FkFg)),
            Role::Name => {
                let fg = if self.mode == Mode::Light {
                    T::Text
                } else {
                    T::SelFg
                };
                Style::default()
                    .fg(self.colors[fg as usize])
                    .add_modifier(Modifier::BOLD)
            }
            Role::Ok => self.fg(T::Ok),
            Role::Warn => self.fg(T::Warn).add_modifier(bold),
            Role::Err => self.fg(T::Err).add_modifier(bold),
        }
    }

    /// Ячейка `x` строки меню шириной `width`: градиент от роли `sel` к роли `fkBg` действующей палитры
    /// режима (решение 122; truecolor, в 256 — ближайшие цвета), в 16 цветах и монохроме — сплошной
    /// [`Role::Menu`].
    pub fn menu(&self, x: u16, width: u16) -> Style {
        let base = self.style(Role::Menu);
        if !self.mode.graphics() {
            return base;
        }
        let t = f64::from(x) / f64::from(width.saturating_sub(1).max(1));
        let c = self.gradient.0.mix(self.gradient.1, t.min(1.0));
        match self.mode {
            Mode::C256 => base.bg(Color::Indexed(c.xterm256())),
            _ => base.bg(c.color()),
        }
    }
}

/// Цвет 0–15 — именованным цветом ANSI (SGR 30–37 и 90–97: их понимает и консоль Linux).
fn ansi16(i: u8) -> Color {
    [
        Color::Black,
        Color::Red,
        Color::Green,
        Color::Yellow,
        Color::Blue,
        Color::Magenta,
        Color::Cyan,
        Color::Gray,
        Color::DarkGray,
        Color::LightRed,
        Color::LightGreen,
        Color::LightYellow,
        Color::LightBlue,
        Color::LightMagenta,
        Color::LightCyan,
        Color::White,
    ][usize::from(i & 15)]
}

/// Возврат палитры консоли Linux по умолчанию.
pub const CONSOLE_RESET: &[u8] = b"\x1b]R";

/// Нужно ли перепрограммировать палитру: консоль Linux (`TERM=linux`) в 16 цветах.
pub fn console_palette_needed(term: Option<&str>, mode: Mode) -> bool {
    term == Some("linux") && mode == Mode::C16
}

/// Палитра консоли Linux под бренд (`ESC ] P nrrggbb`) на время работы интерфейса. При сбросе — выход,
/// ошибка, `SIGTERM` (цикл завершается штатно) — выводится `ESC ] R`; при панике — из обработчика паники
/// ([`ConsolePalette::reset_on_panic`]).
#[derive(Debug)]
pub struct ConsolePalette<W: Write> {
    out: W,
}

impl<W: Write> ConsolePalette<W> {
    /// Поставить 16 цветов `colors` в `out`.
    pub fn set(mut out: W, colors: &[Rgb; 16]) -> io::Result<Self> {
        for (i, c) in colors.iter().enumerate() {
            write!(out, "\x1b]P{i:X}{:02X}{:02X}{:02X}", c.0, c.1, c.2)?;
        }
        out.flush()?;
        Ok(Self { out })
    }

    /// При панике вернуть палитру: обработчик пишет `ESC ] R` в stdout и зовёт прежний.
    pub fn reset_on_panic() {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let mut out = io::stdout();
            let _ = out.write_all(CONSOLE_RESET);
            let _ = out.flush();
            prev(info);
        }));
    }
}

impl<W: Write> Drop for ConsolePalette<W> {
    fn drop(&mut self) {
        let _ = self.out.write_all(CONSOLE_RESET);
        let _ = self.out.flush();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn rgb(s: &str) -> Rgb {
        Rgb::parse(s).unwrap_or_else(|| panic!("{s}"))
    }

    /// Бренд из ответа сервера (JSON открытого маршрута): роли тем — пары «имя — цвет».
    pub(crate) fn server_brand(
        name: Option<&str>,
        dark: &[(&str, &str)],
        light: &[(&str, &str)],
        logo: bool,
    ) -> Brand {
        let roles = |pairs: &[(&str, &str)]| {
            serde_json::Map::from_iter(
                pairs
                    .iter()
                    .map(|(r, c)| (r.to_owned(), serde_json::json!(c))),
            )
        };
        let pb: PublicBranding = serde_json::from_value(serde_json::json!({
            "product_name": name,
            "palette": {"light": roles(light), "dark": roles(dark), "cli": {}},
            "logo": logo.then_some("/api/v1/public/branding/logo/abc"),
        }))
        .expect("брендинг");
        Brand::from_public(pb, None)
    }

    /// Брендинга нет: ответ сервера — только встроенная палитра, тема — IT TASK (TUI-08).
    #[test]
    fn no_branding_is_it_task() {
        let brand = server_brand(None, &[], &[], false);
        assert_eq!(brand.name, "IT TASK");
        assert!(brand.builtin_mark);
        assert!(brand.mark.is_some());
        for mode in [Mode::Dark, Mode::Light, Mode::C256, Mode::C16, Mode::Mono] {
            let plain = Theme::new(mode, Brand::default());
            let server = Theme::new(mode, brand.clone());
            for role in [
                Role::Screen,
                Role::Panel,
                Role::Text,
                Role::Muted,
                Role::Frame,
                Role::FrameA,
                Role::TitleA,
                Role::Head,
                Role::Sel,
                Role::SelI,
                Role::Fk,
                Role::Menu,
                Role::Ok,
                Role::Warn,
                Role::Err,
            ] {
                assert_eq!(server.style(role), plain.style(role), "{mode:?} {role:?}");
            }
            assert_eq!(server.menu(0, 80), plain.menu(0, 80), "{mode:?}");
            assert_eq!(server.menu(40, 80), plain.menu(40, 80), "{mode:?}");
        }
    }

    /// Автоопределение режима по окружению; ключ и переменная перекрывают выбор.
    #[test]
    fn detect_table() {
        type Case<'a> = (&'a [(&'a str, &'a str)], Option<&'a str>, Mode);
        let cases: &[Case] = &[
            (&[], None, Mode::C16),
            (&[("TERM", "linux")], None, Mode::C16),
            (&[("TERM", "xterm")], None, Mode::C16),
            (&[("TERM", "xterm-256color")], None, Mode::C256),
            (&[("TERM", "screen-256color")], None, Mode::C256),
            (&[("TERM", "dumb")], None, Mode::Mono),
            (
                &[("TERM", "xterm-256color"), ("COLORTERM", "truecolor")],
                None,
                Mode::Dark,
            ),
            (&[("COLORTERM", "24bit")], None, Mode::Dark),
            (&[("WT_SESSION", "1")], None, Mode::Dark),
            (
                &[("COLORTERM", "truecolor"), ("NO_COLOR", "1")],
                None,
                Mode::Mono,
            ),
            (
                &[("NO_COLOR", ""), ("TERM", "xterm-256color")],
                None,
                Mode::C256,
            ),
            (&[("NO_COLOR", "1")], Some("light"), Mode::Light),
            (
                &[(ENV_THEME, "256"), ("COLORTERM", "truecolor")],
                None,
                Mode::C256,
            ),
            (&[(ENV_THEME, "mono")], Some("dark"), Mode::Dark),
            (
                &[(ENV_THEME, "auto"), ("TERM", "xterm-256color")],
                None,
                Mode::C256,
            ),
            (&[("COLORTERM", "truecolor")], Some("auto"), Mode::Dark),
            (&[], Some("16"), Mode::C16),
        ];
        for (env, flag, want) in cases {
            let var = |k: &str| {
                env.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| (*v).to_owned())
            };
            assert_eq!(Mode::detect(var, *flag), Ok(*want), "{env:?} {flag:?}");
        }
        assert!(Mode::detect(|_| None, Some("pink")).is_err());
    }

    /// Бренд IT TASK: роли совпадают с токенами, палитра консоли — `[palette16]`.
    #[test]
    fn default_brand_is_tokens() {
        let t = tokens();
        let b = Brand::default();
        let th = Theme::new(Mode::Dark, b.clone());
        assert_eq!(th.console_palette(), &t.palette16);
        // Выделение — #E3107F (белый на нём 4,5:1), текст жирный (решение владельца).
        let sel = th.style(Role::Sel);
        assert_eq!(sel.bg, Some(Color::Rgb(0xE3, 0x10, 0x7F)));
        assert!(sel.add_modifier.contains(Modifier::BOLD));
        assert_eq!(th.style(Role::Fk).bg, Some(Color::Rgb(0x17, 0x7C, 0xAA)));
        // 16 цветов: неактивное выделение — цвет 8, текст 15.
        let c16 = Theme::new(Mode::C16, b.clone());
        assert_eq!(c16.style(Role::SelI).bg, Some(Color::DarkGray));
        assert_eq!(c16.style(Role::SelI).fg, Some(Color::White));
        assert_eq!(
            Theme::new(Mode::C256, b).style(Role::Fk).bg,
            Some(Color::Indexed(26))
        );
    }

    /// Роли сервера применяются в truecolor (обе темы) и 256 (ближайший xterm-256 к роли тёмной темы);
    /// в 16 цветах и монохроме — встроенные роли TUI-06, палитра консоли Linux не меняется. Сервер прислал
    /// светлую палитру IT TASK как тёмную (и наоборот) — все пары проходят контраст.
    #[test]
    fn server_roles_modes() {
        let t = tokens();
        let dark: Vec<(&str, String)> = NAMES
            .iter()
            .zip(t.light)
            .map(|(n, c)| (*n, c.to_string()))
            .collect();
        let light: Vec<(&str, String)> = NAMES
            .iter()
            .zip(t.dark)
            .map(|(n, c)| (*n, c.to_string()))
            .collect();
        let dark_refs: Vec<(&str, &str)> = dark.iter().map(|(n, c)| (*n, c.as_str())).collect();
        let light_refs: Vec<(&str, &str)> = light.iter().map(|(n, c)| (*n, c.as_str())).collect();
        let brand = server_brand(Some("Ромашка"), &dark_refs, &light_refs, false);
        assert_eq!(brand.name, "Ромашка");

        let th = Theme::new(Mode::Dark, brand.clone());
        assert_eq!(
            th.style(Role::Screen).bg,
            Some(Color::Rgb(0xE9, 0xEE, 0xF3))
        );
        assert_eq!(th.style(Role::Panel).bg, Some(Color::Rgb(0xFF, 0xFF, 0xFF)));
        assert_eq!(th.style(Role::Text).fg, Some(Color::Rgb(0x16, 0x16, 0x16)));
        assert_eq!(th.style(Role::Sel).bg, Some(Color::Rgb(0xE3, 0x10, 0x7F)));
        let th = Theme::new(Mode::Light, brand.clone());
        assert_eq!(
            th.style(Role::Screen).bg,
            Some(Color::Rgb(0x0F, 0x13, 0x17))
        );
        assert_eq!(th.style(Role::Text).fg, Some(Color::Rgb(0xD8, 0xE7, 0xF4)));

        // 256: заменённые роли — ближайший xterm-256 к значению тёмной темы сервера.
        let th = Theme::new(Mode::C256, brand.clone());
        assert_eq!(
            th.style(Role::Screen).bg,
            Some(Color::Indexed(rgb("#E9EEF3").xterm256()))
        );
        assert_eq!(
            th.style(Role::Text).fg,
            Some(Color::Indexed(rgb("#161616").xterm256()))
        );
        // Роли, равные IT TASK (sel), — значение `[mode.c256]` токенов.
        assert_eq!(th.style(Role::Sel).bg, Some(Color::Indexed(162)));

        // 16 цветов и монохром — встроенные роли, палитра консоли — токены.
        for mode in [Mode::C16, Mode::Mono] {
            let server = Theme::new(mode, brand.clone());
            let plain = Theme::new(mode, Brand::default());
            assert_eq!(server.style(Role::Screen), plain.style(Role::Screen));
            assert_eq!(server.style(Role::Text), plain.style(Role::Text));
            assert_eq!(server.console_palette(), plain.console_palette());
        }
    }

    /// Пара ниже порога в ответе сервера (данные старой версии) рисуется цветами IT TASK: страховка
    /// `Palette::guarded` берёт пару с уровня выше.
    #[test]
    fn guarded_pair_is_it_task() {
        // Текст цвета фона панели — не читается: текст (и фон) берутся с уровня IT TASK.
        let brand = server_brand(None, &[("text", "#141A20")], &[], false);
        let th = Theme::new(Mode::Dark, brand);
        assert_eq!(th.style(Role::Text).fg, Some(Color::Rgb(0xD8, 0xE7, 0xF4)));
        assert_eq!(
            th.style(Role::Screen).bg,
            Some(Color::Rgb(0x0F, 0x13, 0x17))
        );

        // Светлый фон экрана с тёмными ролями остальной палитры — тоже пара уровня выше.
        let brand = server_brand(None, &[("screen", "#FAFAFA")], &[], false);
        let th = Theme::new(Mode::Dark, brand);
        assert_eq!(
            th.style(Role::Screen).bg,
            Some(Color::Rgb(0x0F, 0x13, 0x17))
        );
        // Роль без пары ниже порога остаётся своей.
        assert_eq!(
            th.style(Role::TitleA).fg,
            Some(Color::Rgb(0xFB, 0x5F, 0xB0))
        );
    }

    /// Бренд заказчика: название, градиент меню от `sel` к `fkBg` его палитры, палитра консоли — IT TASK.
    #[test]
    fn customer_brand() {
        let t = tokens();
        let brand = server_brand(
            Some("ACME"),
            &[("sel", "#C62828"), ("fkBg", "#0A706F")],
            &[],
            false,
        );
        let th = Theme::new(Mode::Dark, brand.clone());
        assert_eq!(th.style(Role::Sel).bg, Some(Color::Rgb(0xC6, 0x28, 0x28)));
        assert_eq!(th.style(Role::Fk).bg, Some(Color::Rgb(0x0A, 0x70, 0x6F)));
        assert_eq!(th.menu(0, 80).bg, Some(Color::Rgb(0xC6, 0x28, 0x28)));
        assert_eq!(th.menu(79, 80).bg, Some(Color::Rgb(0x0A, 0x70, 0x6F)));
        assert_ne!(th.menu(40, 80).bg, th.menu(0, 80).bg);
        // 256 — ближайший xterm-255 к `sel` сервера; палитра консоли Linux не меняется.
        let th = Theme::new(Mode::C256, brand);
        assert_eq!(
            th.style(Role::Sel).bg,
            Some(Color::Indexed(rgb("#C62828").xterm256()))
        );
        assert_eq!(th.console_palette(), &t.palette16);
    }

    /// Знак заказчика: полублоками не показывается (только название), настоящими протоколами — да;
    /// встроенный куб — и полублоками.
    #[test]
    fn customer_mark() {
        let mut png = Vec::new();
        let mut img = image::RgbImage::from_pixel(8, 4, image::Rgb([200, 40, 40]));
        img.write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
            .expect("png");
        let brand = Brand {
            mark: Some(Png(Arc::from(png.as_slice()))),
            builtin_mark: false,
            ..server_brand(Some("ACME"), &[("sel", "#C62828")], &[], false)
        };
        let mut picker = Picker::halfblocks();
        assert!(
            Theme::new(Mode::Dark, brand.clone())
                .with_mark(&picker)
                .mark()
                .is_none()
        );
        picker.set_protocol_type(ProtocolType::Kitty);
        assert!(
            Theme::new(Mode::Dark, brand)
                .with_mark(&picker)
                .mark()
                .is_some()
        );
        for mode in [Mode::C16, Mode::Mono] {
            assert!(
                Theme::new(mode, Brand::default())
                    .with_mark(&picker)
                    .mark()
                    .is_none()
            );
        }
    }

    #[test]
    fn xterm256() {
        assert_eq!(rgb("#E4107F").xterm256(), 162);
        assert_eq!(rgb("#000000").xterm256(), 16);
        assert_eq!(rgb("#FFFFFF").xterm256(), 231);
        assert_eq!(rgb("#121212").xterm256(), 233);
        assert_eq!(xterm_rgb(26), rgb("#005FD7"));
    }

    /// Градиент меню от `sel` (#E3107F) к `fkBg` (#177CAA); в 16 цветах — сплошной основной, в монохроме —
    /// инверсия.
    #[test]
    fn menu_gradient() {
        let dark = Theme::new(Mode::Dark, Brand::default());
        assert_eq!(dark.menu(0, 80).bg, Some(Color::Rgb(0xE3, 0x10, 0x7F)));
        assert_eq!(dark.menu(79, 80).bg, Some(Color::Rgb(0x17, 0x7C, 0xAA)));
        assert_ne!(dark.menu(40, 80).bg, dark.menu(0, 80).bg);
        let c256 = Theme::new(Mode::C256, Brand::default());
        assert_eq!(c256.menu(0, 80).bg, Some(Color::Indexed(162)));
        assert_eq!(
            Theme::new(Mode::C16, Brand::default()).menu(40, 80).bg,
            Some(Color::Blue)
        );
        let mono = Theme::new(Mode::Mono, Brand::default()).menu(40, 80);
        assert!(mono.add_modifier.contains(Modifier::REVERSED));
    }

    /// Палитра консоли Linux: 16 цветов `ESC ] P` при запуске, `ESC ] R` при выходе.
    #[test]
    fn console_palette() {
        assert!(console_palette_needed(Some("linux"), Mode::C16));
        assert!(!console_palette_needed(Some("xterm"), Mode::C16));
        assert!(!console_palette_needed(Some("linux"), Mode::Mono));
        let th = Theme::new(Mode::C16, Brand::default());
        let mut out = Vec::new();
        let guard = ConsolePalette::set(&mut out, th.console_palette()).expect("палитра");
        drop(guard);
        let s = String::from_utf8(out).expect("utf-8");
        assert!(s.starts_with("\x1b]P00F1317"), "{s:?}");
        assert!(s.contains("\x1b]P5E3107F"), "{s:?}");
        assert!(s.contains("\x1b]PFFFFFFF"), "{s:?}");
        assert!(s.ends_with("\x1b]R"), "{s:?}");
        assert_eq!(s.matches("\x1b]P").count(), 16);
    }

    /// Знак IT TASK: картинкой в цветных режимах; в 16 цветах, монохроме и с битым PNG — нет.
    #[test]
    fn mark() {
        let picker = Picker::halfblocks();
        for mode in [Mode::Dark, Mode::Light, Mode::C256] {
            let th = Theme::new(mode, Brand::default()).with_mark(&picker);
            let size = th.mark().map(Mark::size).expect("знак");
            assert!(
                size.width <= MARK_COLS && size.height <= MARK_ROWS,
                "{size:?}"
            );
        }
        for mode in [Mode::C16, Mode::Mono] {
            let th = Theme::new(mode, Brand::default()).with_mark(&picker);
            assert!(th.mark().is_none());
        }
        let broken = Brand {
            mark: Some(Png(Arc::from(&b"not png"[..]))),
            ..Brand::default()
        };
        let th = Theme::new(Mode::Dark, broken).with_mark(&picker);
        assert!(th.mark().is_none());
    }
}
