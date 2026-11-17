//! `/dev/input` на консоли Linux (TUI-07): консоль не знает терминальной мыши, координаты берутся у
//! устройств ввода (нужна группа `input`; нет доступа — мыши на консоли нет, курсор — уровень 4 в
//! терминалах). Чтение блокирующее — отдельный поток, как поток клавиатуры; экран в пикселях — sysfs
//! framebuffer, ячейка — экран поделён на колонки и строки.

use crate::mouse::Tracker;
use evdev::{Device, EventSummary, KeyCode, RelativeAxisCode};

/// Событие мыши из `/dev/input`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseEv {
    /// Пиксели экрана.
    pub x: u16,
    /// Пиксели экрана.
    pub y: u16,
    /// Что случилось.
    pub kind: Kind,
}

/// Вид события мыши из `/dev/input`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Движение.
    Move,
    /// Левая кнопка нажата.
    Down,
    /// Левая кнопка отпущена.
    Up,
    /// Колесо: обороты (положительные — вниз).
    Wheel(i32),
}

/// Экран консоли: пиксели framebuffer и размер ячейки.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Screen {
    /// Экран в пикселях.
    pub px: (u16, u16),
    /// Ячейка в пикселях.
    pub cell: (u16, u16),
}

impl Screen {
    /// Ячейка пикселя.
    pub fn cell_of(&self, x: u16, y: u16) -> (u16, u16) {
        (x / self.cell.0.max(1), y / self.cell.1.max(1))
    }
}

/// Экран консоли Linux: пиксели из sysfs (`fb0/virtual_size`), ячейка — экран поделён на терминал;
/// `fallback` — размер ячейки, если sysfs молчит.
pub fn screen(fallback: (u16, u16)) -> Option<Screen> {
    let cols_rows = crossterm::terminal::size().ok()?;
    let px = std::fs::read_to_string("/sys/class/graphics/fb0/virtual_size")
        .ok()
        .and_then(|s| {
            let (w, h) = s.trim().split_once(',')?;
            let n = |v: &str| v.parse::<u16>().ok();
            Some((n(w)?, n(h)?))
        })
        .unwrap_or((
            fallback.0.saturating_mul(cols_rows.0),
            fallback.1.saturating_mul(cols_rows.1),
        ));
    Some(Screen {
        px,
        cell: (px.0 / cols_rows.0.max(1), px.1 / cols_rows.1.max(1)),
    })
}

/// Первая мышь `/dev/input`: относительные оси и левая кнопка.
fn first_mouse() -> Option<Device> {
    evdev::enumerate().find_map(|(path, raw)| {
        let rel = raw.supported_relative_axes()?;
        let keys = raw.supported_keys()?;
        (rel.contains(RelativeAxisCode::REL_X)
            && rel.contains(RelativeAxisCode::REL_Y)
            && keys.contains(KeyCode::BTN_LEFT))
        .then(|| Device::open(path).ok())
        .flatten()
    })
}

/// Есть ли доступ к мыши `/dev/input` (группа `input`).
pub fn available() -> bool {
    first_mouse().is_some()
}

/// Поток мыши `/dev/input`: события — в цикл интерфейса (`send`), пока тот открыт.
pub fn spawn<F>(screen: Screen, send: F)
where
    F: Fn(MouseEv) + Send + 'static,
{
    std::thread::spawn(move || {
        let Some(mut dev) = first_mouse() else {
            return;
        };
        let mut t = Tracker::new(screen.px);
        loop {
            let Ok(events) = dev.fetch_events() else {
                break;
            };
            let (mut dx, mut dy, mut wheel, mut button) = (0i32, 0i32, 0i32, None);
            for e in events {
                match e.destructure() {
                    EventSummary::RelativeAxis(_, RelativeAxisCode::REL_X, v) => dx += v,
                    EventSummary::RelativeAxis(_, RelativeAxisCode::REL_Y, v) => dy += v,
                    EventSummary::RelativeAxis(_, RelativeAxisCode::REL_WHEEL, v) => wheel += v,
                    EventSummary::Key(_, KeyCode::BTN_LEFT, v) => button = Some(v == 1),
                    _ => {}
                }
            }
            if dx != 0 || dy != 0 {
                t.move_by(dx, dy);
                let (x, y) = t.pos();
                send(MouseEv {
                    x,
                    y,
                    kind: Kind::Move,
                });
            }
            let (x, y) = t.pos();
            for kind in [
                (wheel != 0).then_some(Kind::Wheel(wheel)),
                button.map(|down| if down { Kind::Down } else { Kind::Up }),
            ]
            .into_iter()
            .flatten()
            {
                send(MouseEv { x, y, kind });
            }
        }
    });
}
