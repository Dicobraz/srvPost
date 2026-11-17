//! Плавный курсор мыши (TUI-07, решение 119): лучший доступный уровень выбирается при старте по ответам
//! терминала и окружению, ключ `--mouse-cursor` (переменная [`ENV_MOUSE_CURSOR`]) перекрывает.
//!
//! 1. картинка стрелки протоколом kitty graphics по пиксельным координатам мыши (режим `1016`, SGR-Pixels)
//!    со сдвигом внутри ячейки; 2. sixel — та же картинка; кодирование и то и другое — `ratatui-image`,
//!    своей реализации нет; 3. знакогенератор, как в Norton Commander 5: четыре глифа со стрелкой со сдвигом
//!    ставятся блоком 2×2 поверх исходных символов — в терминалах с `DECDLD` (Windows Terminal, mlterm,
//!    contour) глифы загружаются escape-последовательностью, на консоли Linux глифы готовятся для
//!    `KDFONTOP`, но загрузка шрифта — ioctl, запрещённый вне `tp-sys` (вопрос владельцу, см. карточку);
//! 4. подсветка ячейки под мышью — инверсия.
//!
//! Уровень 1/2 требует от терминала пиксельных событий мыши (режим `1016` проверяется запросом `DECRQM`)
//! и размера ячейки — оба ответа уже есть после опроса терминала `ratatui-image`.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::mpsc;
use std::time::Duration;

use crossterm::event::MouseEvent;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::layout::Size;
use ratatui_image::Resize;
use ratatui_image::picker::Picker;
use ratatui_image::protocol::Protocol;

/// Переменная окружения с уровнем курсора: перекрывает автоопределение, ключ `--mouse-cursor` перекрывает её.
pub const ENV_MOUSE_CURSOR: &str = "THEPOST_TUI_MOUSE_CURSOR";
/// Имя загружаемого набора символов DECDLD (`Dscs`): промежуточный `!`, финальный `@`.
const DSCS: &str = "!@";
/// Назначение загруженного набора в G2: глифы печатаются одиночным сдвигом SS2 (`ESC N`), G0 не трогаем.
const G2: &str = "\x1b*!@";
/// Символы четырёх глифов блока 2×2 (Pcn = 1, позиции 2/1–2/4), каждый — с SS2 перед ним.
const GLYPHS: [&str; 4] = ["\u{1b}N!", "\u{1b}N\"", "\u{1b}N#", "\u{1b}N$"];

/// Уровень плавности курсора.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    /// 1: картинка kitty graphics по пиксельным координатам.
    Kitty,
    /// 2: та же картинка по sixel.
    Sixel,
    /// 3: глифы 2×2 (DECDLD; на консоли Linux — когда владелец разрешит `KDFONTOP`).
    Glyphs,
    /// 4: подсветка ячейки под мышью.
    Cell,
    /// Курсор выключен (мышь работает).
    Off,
}

impl Level {
    /// Название уровня.
    pub fn title(self) -> &'static str {
        match self {
            Self::Kitty => "картинка kitty",
            Self::Sixel => "картинка sixel",
            Self::Glyphs => "глифы 2×2",
            Self::Cell => "подсветка ячейки",
            Self::Off => "выключен",
        }
    }

    /// Уровень по имени ключа: `1`–`4`, `kitty`, `sixel`, `glyphs`, `cell`, `off`.
    fn parse(s: &str) -> Option<Self> {
        Some(match s.trim().to_ascii_lowercase().as_str() {
            "1" | "kitty" => Self::Kitty,
            "2" | "sixel" => Self::Sixel,
            "3" | "glyphs" => Self::Glyphs,
            "4" | "cell" => Self::Cell,
            "off" | "none" => Self::Off,
            _ => return None,
        })
    }
}

/// Ответы терминала и окружение — вход выбора уровня.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps {
    /// Терминал ответил поддержкой kitty graphics (опрос `ratatui-image`).
    pub kitty: bool,
    /// Терминал ответил поддержкой sixel.
    pub sixel: bool,
    /// Терминал принял режим `1016` (SGR-Pixels): события мыши в пикселях.
    pub pixel_mouse: bool,
    /// Терминал с `DECDLD` (Windows Terminal, mlterm, contour).
    pub decdld: bool,
    /// Консоль Linux (`TERM=linux`).
    pub console: bool,
    /// Есть доступ к `/dev/input` (группа `input`).
    pub input: bool,
}

/// Лучший доступный уровень по ответам терминала; ключ `flag` (`--mouse-cursor`, `auto` — таблица)
/// перекрывает выбор.
pub fn detect(caps: &Caps, flag: Option<&str>) -> Result<Level, String> {
    if let Some(s) = flag
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != "auto")
        && let Some(level) = Level::parse(s)
    {
        return Ok(level);
    } else if let Some(s) = flag.filter(|s| !s.trim().is_empty() && s.trim() != "auto") {
        return Err(format!(
            "курсор мыши «{s}»: нужно auto, 1, 2, 3, 4, kitty, sixel, glyphs, cell или off"
        ));
    }
    Ok(if caps.kitty && caps.pixel_mouse {
        Level::Kitty
    } else if caps.sixel && caps.pixel_mouse {
        Level::Sixel
    } else if caps.decdld {
        Level::Glyphs
    } else {
        Level::Cell
    })
}

/// Есть ли `DECDLD`: Windows Terminal (`WT_SESSION`) или mlterm/contour по `TERM`.
pub fn decdld_supported(var: impl Fn(&str) -> Option<String>) -> bool {
    let set = |name: &str| var(name).is_some_and(|v| !v.is_empty());
    set("WT_SESSION")
        || matches!(
            var("TERM").as_deref(),
            Some("mlterm") | Some("xterm-mlterm") | Some("contour")
        )
}

/// Стрелка курсора как растр 2×2 ячейки с остриём в `shift` внутри якорной ячейки: 0 — прозрачно,
/// 1 — чёрная заливка, 2 — белая обводка (видна на любом фоне). Пропорции Norton Commander 5:
/// голова шириной ячейки, длина — полторы ячейки.
pub fn arrow(cell: (u16, u16), shift: (u16, u16)) -> Vec<Vec<u8>> {
    let (cw, ch) = (usize::from(cell.0.max(1)), usize::from(cell.1.max(1)));
    let (w, h) = (cw * 2, ch * 2);
    let mut out = vec![vec![0u8; w]; h];
    let (tx, ty) = (
        usize::from(shift.0.min(cell.0.saturating_sub(1))),
        usize::from(shift.1.min(cell.1.saturating_sub(1))),
    );
    let stem = (cw / 4).max(2);
    let head = cw.max(stem + 2);
    let len = (ch + ch / 2).min(h - ty);
    let k = (head - stem) / 2;
    let poly = [
        (0.0f64, 0.0f64),
        (0.0, head as f64),
        (k as f64, head as f64),
        (k as f64, len as f64),
        ((k + stem) as f64, len as f64),
        ((k + stem) as f64, head as f64),
        (head as f64 + 1.0, head as f64),
    ];
    let inside = |x: usize, y: usize| {
        let (px, py) = (f64::from(x as u32) + 0.5, f64::from(y as u32) + 0.5);
        let mut hit = false;
        for i in 0..poly.len() {
            let (x1, y1) = poly[i];
            let (x2, y2) = poly[(i + 1) % poly.len()];
            if (y1 > py) != (y2 > py) && px < (x2 - x1) * (py - y1) / (y2 - y1) + x1 {
                hit = !hit;
            }
        }
        hit
    };
    for y in 0..h.saturating_sub(ty) {
        for x in 0..w.saturating_sub(tx) {
            if !inside(x, y) {
                continue;
            }
            let edge = [
                (x + 1, y),
                (x.saturating_sub(1), y),
                (x, y + 1),
                (x, y.saturating_sub(1)),
            ]
            .iter()
            .any(|&(nx, ny)| nx >= w || ny >= h || !inside(nx, ny));
            out[ty + y][tx + x] = u8::from(edge) + 1;
        }
    }
    out
}

/// Та же стрелка картинкой для `ratatui-image` (уровни 1–2): RGBA с прозрачным фоном.
pub fn arrow_rgba(cell: (u16, u16), shift: (u16, u16)) -> image::DynamicImage {
    let bmp = arrow(cell, shift);
    let (w, h) = (bmp.first().map_or(0, Vec::len), bmp.len());
    let mut img = image::RgbaImage::new(w as u32, h as u32);
    for (y, row) in bmp.iter().enumerate() {
        for (x, v) in row.iter().enumerate() {
            let px = match v {
                2 => [255, 255, 255, 255],
                1 => [0, 0, 0, 255],
                _ => continue,
            };
            img.put_pixel(x as u32, y as u32, image::Rgba(px));
        }
    }
    image::DynamicImage::ImageRgba8(img)
}

/// 1-битный глиф: строки по `ceil(w/8)` байт, старший бит — левый пиксель (формат `KDFONTOP`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Glyph {
    /// Ширина в пикселях.
    pub w: u16,
    /// Высота в пикселях.
    pub h: u16,
    /// Растровые строки подряд.
    pub rows: Vec<u8>,
}

impl Glyph {
    fn new(w: u16, h: u16) -> Self {
        Self {
            w,
            h,
            rows: vec![0; usize::from(h) * usize::from(w.div_ceil(8))],
        }
    }

    /// Пиксель `(x, y)`.
    pub fn pixel(&self, x: u16, y: u16) -> bool {
        let at = usize::from(y) * usize::from(self.w.div_ceil(8)) + usize::from(x / 8);
        self.rows
            .get(at)
            .is_some_and(|b| b & (0x80 >> (x % 8)) != 0)
    }

    fn set(&mut self, x: u16, y: u16) {
        let at = usize::from(y) * usize::from(self.w.div_ceil(8)) + usize::from(x / 8);
        if let Some(b) = self.rows.get_mut(at) {
            *b |= 0x80 >> (x % 8);
        }
    }
}

/// Четыре глифа блока 2×2 под стрелку со сдвигом `shift` внутри якорной ячейки (уровень 3): глиф — своя
/// часть стрелки, фон берут у ячейки, поверх которой стоят. Порядок: верх-лево, верх-право, низ-лево,
/// низ-право.
pub fn arrow_quads(cell: (u16, u16), shift: (u16, u16)) -> [Glyph; 4] {
    let bmp = arrow(cell, shift);
    let (cw, ch) = (usize::from(cell.0.max(1)), usize::from(cell.1.max(1)));
    let mut quads = [
        Glyph::new(cell.0, cell.1),
        Glyph::new(cell.0, cell.1),
        Glyph::new(cell.0, cell.1),
        Glyph::new(cell.0, cell.1),
    ];
    for (y, row) in bmp.iter().enumerate() {
        for (x, v) in row.iter().enumerate() {
            if *v == 0 || x >= cw * 2 || y >= ch * 2 {
                continue;
            }
            let q = usize::from(x >= cw) + 2 * usize::from(y >= ch);
            quads[q].set((x % cw) as u16, (y % ch) as u16);
        }
    }
    quads
}

/// DECDLD-строка загрузки четырёх глифов (VT510: `DCS Pfn;Pcn;Pe;Pcmw;Pss;Pt;Pcmh;Pcss Dscs данные ST`),
/// глифы — sixel-полосами по 6 строк, полосы через `/`, глифы через `;`. `Pe=1` — стирать только
/// перезагружаемые позиции: соседние символы не мигают. Символы набора — [`GLYPHS`].
pub fn decdld(quads: &[Glyph; 4]) -> String {
    let (w, h) = (quads[0].w, quads[0].h);
    let mut s = format!("\x1bP0;1;1;{w};0;2;{h};1{{ {DSCS}");
    for (i, g) in quads.iter().enumerate() {
        if i > 0 {
            s.push(';');
        }
        for band in 0..h.div_ceil(6) {
            if band > 0 {
                s.push('/');
            }
            for x in 0..g.w {
                let mut bits = 0u8;
                for r in 0..6u16 {
                    if g.pixel(x, band * 6 + r) {
                        bits |= 1 << r;
                    }
                }
                s.push(char::from(0x3F + bits));
            }
        }
    }
    s.push_str("\x1b\\");
    s
}

/// DECDLD-строка стирания набора при выходе.
pub fn decdld_erase() -> String {
    format!("\x1bP0;1;2{{ {DSCS}\x1b\\")
}

/// Ответ DECRQM на запрос режима `1016`: `true` — терминал его держит (пиксельные координаты мыши).
pub fn parse_decrqm(bytes: &[u8]) -> Option<bool> {
    let needle = b"\x1b[?1016;";
    let at = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|at| at + needle.len())?;
    match bytes.get(at..at + 3) {
        Some(b"1$y") => Some(true),
        Some(b"0$y") => Some(false),
        _ => None,
    }
}

/// Опрос терминала: включить режим `1016`, спросить `DECRQM`, выключить. Читает stdin с ожиданием не
/// дольше `timeout` — как опрос `ratatui-image`, до запуска цикла событий.
pub fn probe_pixel_mouse(timeout: Duration) -> bool {
    let probe = (|| -> io::Result<bool> {
        enable_raw_mode()?;
        let mut out = io::stdout();
        out.write_all(b"\x1b[?1016h\x1b[?1016$p")?;
        out.flush()?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut input = io::stdin();
            let mut buf = [0u8; 64];
            while let Ok(n) = input.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        let mut got = Vec::new();
        let ok = loop {
            match rx.recv_timeout(timeout) {
                Ok(chunk) => {
                    got.extend_from_slice(&chunk);
                    if let Some(answer) = parse_decrqm(&got) {
                        break answer;
                    }
                }
                Err(_) => break false,
            }
        };
        out.write_all(b"\x1b[?1016l")?;
        out.flush()?;
        disable_raw_mode()?;
        Ok(ok)
    })();
    probe.unwrap_or(false)
}

/// Стрелка курсора, готовая к показу в кадре.
#[derive(Clone)]
pub enum CursorView {
    /// Картинка (kitty/sixel): протокол `ratatui-image` в 2×2 ячейки от `anchor`.
    Image {
        /// Стрелка со сдвигом внутри ячейки.
        mark: CursorMark,
        /// Ячейка острия (левый верх блока 2×2).
        anchor: (u16, u16),
    },
    /// Глифы 2×2 от `anchor` (символы загруженного набора, [`GLYPHS`]).
    Glyphs {
        /// Ячейка острия.
        anchor: (u16, u16),
    },
    /// Подсветка ячейки под мышью.
    Cell,
}

impl CursorView {
    /// Ячейка острия.
    pub fn anchor(&self) -> Option<(u16, u16)> {
        match self {
            Self::Image { anchor, .. } | Self::Glyphs { anchor } => Some(*anchor),
            Self::Cell => None,
        }
    }
}

impl PartialEq for CursorView {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Image { mark: a, anchor: x }, Self::Image { mark: b, anchor: y }) => {
                a == b && x == y
            }
            (Self::Glyphs { anchor: x }, Self::Glyphs { anchor: y }) => x == y,
            (Self::Cell, Self::Cell) => true,
            _ => false,
        }
    }
}

impl std::fmt::Debug for CursorView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Image { anchor, .. } => write!(f, "Image({anchor:?})"),
            Self::Glyphs { anchor } => write!(f, "Glyphs({anchor:?})"),
            Self::Cell => write!(f, "Cell"),
        }
    }
}

/// Стрелка, закодированная протоколом терминала.
#[derive(Clone)]
pub struct CursorMark(pub std::sync::Arc<Protocol>);

impl PartialEq for CursorMark {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for CursorMark {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CursorMark")
    }
}

/// Символы глифов блока 2×2 (в порядке печати) и назначение набора в G2.
pub fn glyph_symbols() -> [&'static str; 4] {
    GLYPHS
}

/// Назначение набора глифов в G2 (после загрузки DECDLD).
pub const GLYPH_G2: &str = G2;

/// Плавный курсор: уровень, размер ячейки и стрелки со сдвигом — по одному на шаг квантования
/// (кэш, у терминала не больше `steps²` картинок). Пишет DECDLD-загрузку глифов, когда шаг меняется.
pub struct SmoothCursor {
    level: Level,
    picker: Option<Picker>,
    cell: (u16, u16),
    steps: u16,
    pixel_mouse: bool,
    marks: HashMap<(u16, u16), CursorMark>,
    glyphs: Option<(u16, u16)>,
    download: Option<String>,
    downloaded: bool,
}

impl std::fmt::Debug for SmoothCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmoothCursor")
            .field("level", &self.level)
            .field("cell", &self.cell)
            .field("marks", &self.marks.len())
            .finish_non_exhaustive()
    }
}

impl SmoothCursor {
    /// Курсор уровня `level`; размер ячейки — из ответа терминала (`picker`) или `8×16`.
    pub fn new(level: Level, picker: Option<&Picker>, steps: u16) -> Self {
        let font = picker.map_or((8, 16), |p| (p.font_size().width, p.font_size().height));
        Self {
            level,
            picker: picker.cloned(),
            cell: (font.0.max(1), font.1.max(1)),
            steps: steps.max(1),
            pixel_mouse: false,
            marks: HashMap::new(),
            glyphs: None,
            download: None,
            downloaded: false,
        }
    }

    /// Уровень.
    pub fn level(&self) -> Level {
        self.level
    }

    /// Размер ячейки в пикселях.
    pub fn cell(&self) -> (u16, u16) {
        self.cell
    }

    /// События мыши приходят в пикселях (режим `1016`).
    pub fn set_pixel_mouse(&mut self, on: bool) {
        self.pixel_mouse = on;
    }

    /// Пиксели события в ячейку; пиксели возвращаются, когда они настоящие.
    pub fn point(&self, ev: &MouseEvent) -> ((u16, u16), Option<(u16, u16)>) {
        if !self.pixel_mouse {
            return ((ev.column, ev.row), None);
        }
        let (cw, ch) = (self.cell.0.max(1), self.cell.1.max(1));
        ((ev.column / cw, ev.row / ch), Some((ev.column, ev.row)))
    }

    /// Сдвиг внутри ячейки, квантованный на `steps` шагов.
    fn shift(&self, px: (u16, u16)) -> (u16, u16) {
        let q = |p: u16, c: u16| (p % c).min(c - 1) * self.steps / c;
        (
            q(px.0, self.cell.0) * self.cell.0 / self.steps,
            q(px.1, self.cell.1) * self.cell.1 / self.steps,
        )
    }

    /// Что показать в кадре: картинка/глифы в ячейке `cell` (пиксели мыши `px` дают сдвиг), подсветка —
    /// по позиции в [`crate::mouse::MouseState`]. Ставит DECDLD-загрузку в очередь, когда шаг сдвига
    /// глифов сменился (забирает [`SmoothCursor::take_download`] до отрисовки).
    pub fn view(&mut self, px: Option<(u16, u16)>, cell: (u16, u16)) -> Option<CursorView> {
        match self.level {
            Level::Off => None,
            Level::Cell => Some(CursorView::Cell),
            Level::Glyphs => {
                let shift = px.map_or((0, 0), |p| self.shift(p));
                if self.glyphs != Some(shift) {
                    self.download = Some(decdld(&arrow_quads(self.cell, shift)));
                    self.glyphs = Some(shift);
                    self.downloaded = true;
                }
                Some(CursorView::Glyphs { anchor: cell })
            }
            Level::Kitty | Level::Sixel => {
                let shift = px.map_or((0, 0), |p| self.shift(p));
                let mark = match self.marks.get(&shift) {
                    Some(mark) => Some(mark.clone()),
                    None => {
                        let mark = self.picker.as_ref().and_then(|p| {
                            p.new_protocol(
                                arrow_rgba(self.cell, shift),
                                Size::new(2, 2),
                                Resize::Fit(None),
                            )
                            .ok()
                            .map(|protocol| CursorMark(std::sync::Arc::new(protocol)))
                        });
                        if let Some(mark) = &mark {
                            self.marks.insert(shift, mark.clone());
                        }
                        mark
                    }
                };
                mark.map(|mark| CursorView::Image { mark, anchor: cell })
            }
        }
    }

    /// Очередь DECDLD-загрузки глифов (вызывается после смены шага сдвига).
    pub fn take_download(&mut self) -> Option<String> {
        self.download.take()
    }

    /// Была ли загрузка глифов: при выходе набор стирается.
    pub fn downloaded(&self) -> bool {
        self.downloaded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Таблица случаев выбора уровня по ответам терминала и окружению.
    #[test]
    fn level_table() {
        type Case = (Caps, Option<&'static str>, Level);
        let caps = |kitty, sixel, pixel, decdld| Caps {
            kitty,
            sixel,
            pixel_mouse: pixel,
            decdld,
            console: false,
            input: false,
        };
        let cases: &[Case] = &[
            // kitty с пиксельной мышью — уровень 1.
            (caps(true, false, true, false), None, Level::Kitty),
            // sixel с пиксельной мышью — уровень 2.
            (caps(false, true, true, false), None, Level::Sixel),
            // kitty опережает sixel.
            (caps(true, true, true, false), None, Level::Kitty),
            // без режима 1016 (xterm без пиксельного режима) — ниже.
            (caps(true, false, false, false), None, Level::Cell),
            (caps(false, true, false, false), None, Level::Cell),
            // терминал с DECDLD — уровень 3.
            (caps(false, false, false, true), None, Level::Glyphs),
            (caps(true, false, false, true), None, Level::Glyphs),
            // консоль Linux с /dev/input — пока уровень 4 (KDFONTOP — вопрос владельцу).
            (
                Caps {
                    console: true,
                    input: true,
                    ..caps(false, false, false, false)
                },
                None,
                Level::Cell,
            ),
            // терминал без ответов — уровень 4.
            (Caps::default(), None, Level::Cell),
            // ключ перекрывает.
            (caps(false, false, false, false), Some("1"), Level::Kitty),
            (caps(true, true, true, true), Some("2"), Level::Sixel),
            (caps(true, true, true, true), Some("3"), Level::Glyphs),
            (caps(true, true, true, true), Some("4"), Level::Cell),
            (caps(true, true, true, true), Some("off"), Level::Off),
            (caps(true, true, true, true), Some("auto"), Level::Kitty),
            (Caps::default(), Some("  kitty "), Level::Kitty),
        ];
        for (caps, flag, want) in cases {
            assert_eq!(detect(caps, *flag), Ok(*want), "{caps:?} {flag:?}");
        }
        assert!(detect(&Caps::default(), Some("розовый")).is_err());
        assert!(detect(&Caps::default(), Some("")).is_ok());
    }

    fn var_of<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            vars.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn decdld_terminals() {
        assert!(decdld_supported(var_of(&[("WT_SESSION", "1")])));
        assert!(decdld_supported(var_of(&[("TERM", "contour")])));
        assert!(decdld_supported(var_of(&[("TERM", "mlterm")])));
        assert!(!decdld_supported(var_of(&[("TERM", "xterm-256color")])));
        assert!(!decdld_supported(var_of(&[])));
    }

    /// Глифы 2×2 строятся для каждого сдвига внутри ячейки и вместе дают стрелку из [`arrow`].
    #[test]
    fn quads_for_every_shift() {
        for cell in [(6u16, 12u16), (8, 16), (10, 19)] {
            for dy in 0..cell.1 {
                for dx in 0..cell.0 {
                    let quads = arrow_quads(cell, (dx, dy));
                    let (cw, ch) = (usize::from(cell.0), usize::from(cell.1));
                    let mut full = vec![vec![false; cw * 2]; ch * 2];
                    for (q, g) in quads.iter().enumerate() {
                        assert_eq!((g.w, g.h), (cell.0, cell.1), "{cell:?} {dx},{dy}");
                        assert_eq!(
                            g.rows.len(),
                            usize::from(g.h) * usize::from(g.w.div_ceil(8))
                        );
                        for y in 0..ch {
                            for x in 0..cw {
                                full[q / 2 * ch + y][q % 2 * cw + x] = g.pixel(x as u16, y as u16);
                            }
                        }
                    }
                    let want = arrow(cell, (dx, dy));
                    for y in 0..ch * 2 {
                        for x in 0..cw * 2 {
                            assert_eq!(full[y][x], want[y][x] != 0, "{cell:?} {dx},{dy} @ {x},{y}");
                        }
                    }
                    // остриё — на месте мыши.
                    assert!(full[usize::from(dy)][usize::from(dx)], "{cell:?} {dx},{dy}");
                }
            }
        }
    }

    /// Стрелка: чёрная заливка и белая обводка, пропорции растут с ячейкой.
    #[test]
    fn arrow_shape() {
        let bmp = arrow((10, 20), (0, 0));
        assert_eq!(
            (bmp.len(), bmp.first().map_or(0, Vec::len)),
            (40, 20),
            "холст 2×2 ячейки"
        );
        let fill = bmp.iter().flatten().filter(|v| **v == 1).count();
        let edge = bmp.iter().flatten().filter(|v| **v == 2).count();
        assert!(fill > 20 && edge > 30, "{fill} {edge}");
        assert_eq!(bmp[0][0], 2, "остриё с обводкой");
        // остриём в другом углу ячейки стрелка смещается.
        let moved = arrow((10, 20), (9, 19));
        assert_eq!(moved[19][9], 2);
        assert_eq!(moved[0][0], 0);
        // маленькая ячейка тоже даёт стрелку.
        assert!(arrow((4, 6), (2, 3)).iter().flatten().any(|v| *v > 0));
    }

    /// DECDLD: параметры, Dscs, четыре глифа sixel-полосами; биты собираются обратно.
    #[test]
    fn decdld_encoding() {
        let cell = (8u16, 13u16);
        let quads = arrow_quads(cell, (3, 5));
        let s = decdld(&quads);
        assert!(s.starts_with("\x1bP0;1;1;8;0;2;13;1{ !@"), "{s:?}");
        let data = s.split_once("{ !@").expect("данные");
        assert_eq!(data.1.matches(';').count(), 3, "четыре глифа");
        assert!(s.ends_with("\x1b\\"));
        assert_eq!(decdld_erase(), "\x1bP0;1;2{ !@\x1b\\");
        // глиф с одним пикселем — один ненулевой sixel.
        let mut dot = Glyph::new(6, 6);
        dot.set(2, 3);
        let one = decdld(&[dot.clone(), dot.clone(), dot.clone(), dot.clone()]);
        assert_eq!(one.matches('\u{3F}').count(), 5 * 4, "пустые колонки");
        assert_eq!(one.matches('G').count(), 4, "колонка с битом 3");
        // psf-строки глифа — по ceil(w/8) байт.
        assert_eq!(dot.rows.len(), 6);
        assert!(dot.pixel(2, 3));
        assert!(!dot.pixel(3, 3));
    }

    /// Ответ DECRQM на режим 1016.
    #[test]
    fn decrqm() {
        assert_eq!(parse_decrqm(b"\x1b[?1016;1$y"), Some(true));
        assert_eq!(parse_decrqm(b"\x1b[?1016;0$y"), Some(false));
        assert_eq!(parse_decrqm(b"\x1b[?1000;1$y"), None);
        assert_eq!(parse_decrqm(b""), None);
    }

    /// Квантованный сдвиг: шаги ложатся в ячейку, у краёв — без переполнения.
    #[test]
    fn shift_steps() {
        let mut c = SmoothCursor::new(Level::Kitty, None, 4);
        c.set_pixel_mouse(true);
        assert_eq!(c.cell(), (8, 16));
        assert_eq!(c.shift((0, 0)), (0, 0));
        assert_eq!(c.shift((4, 8)), (4, 8));
        assert_eq!(c.shift((7, 15)), (6, 12));
        assert_eq!(c.shift((9, 17)), (0, 0), "сдвиг — внутри якорной ячейки");
        assert_eq!(c.point(&mouse(7, 15)), ((0, 0), Some((7, 15))));
        c.set_pixel_mouse(false);
        assert_eq!(c.point(&mouse(7, 15)), ((7, 15), None));
        assert_eq!(
            SmoothCursor::new(Level::Off, None, 4).view(None, (1, 1)),
            None
        );
        assert_eq!(
            SmoothCursor::new(Level::Cell, None, 4).view(None, (1, 1)),
            Some(CursorView::Cell)
        );
    }

    /// Глифы: смена шага ставит загрузку в очередь, повтор — нет.
    #[test]
    fn glyphs_download_once_per_shift() {
        let mut c = SmoothCursor::new(Level::Glyphs, None, 2);
        assert!(c.view(Some((3, 3)), (5, 5)).is_some());
        let first = c.take_download().expect("загрузка");
        assert!(first.starts_with("\x1bP0;"));
        assert!(c.take_download().is_none(), "тот же шаг — без загрузки");
        c.view(Some((5, 5)), (6, 6));
        assert!(c.take_download().is_some());
        assert!(c.downloaded());
    }

    /// Уровни 1–2: стрелка кодируется протоколом (полублоки в тесте) и кэшируется по сдвигу.
    #[test]
    fn image_mark_cached() {
        let picker = Picker::halfblocks();
        let mut c = SmoothCursor::new(Level::Sixel, Some(&picker), 8);
        let a = c.view(Some((4, 10)), (3, 4)).expect("стрелка");
        let CursorView::Image { anchor, .. } = &a else {
            panic!("не картинка: {a:?}");
        };
        assert_eq!(*anchor, (3, 4));
        let b = c.view(Some((4, 10)), (9, 9)).expect("стрелка");
        let (CursorView::Image { mark: ma, .. }, CursorView::Image { mark: mb, .. }) = (&a, &b)
        else {
            unreachable!()
        };
        assert_eq!(ma, mb, "тот же сдвиг — из кэша");
        let d = c.view(Some((5, 10)), (9, 9)).expect("стрелка");
        let CursorView::Image { mark: md, .. } = &d else {
            unreachable!()
        };
        assert_ne!(ma, md, "другой сдвиг — новая стрелка");
    }

    fn mouse(col: u16, row: u16) -> MouseEvent {
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Moved,
            column: col,
            row,
            modifiers: crossterm::event::KeyModifiers::NONE,
        }
    }
}
