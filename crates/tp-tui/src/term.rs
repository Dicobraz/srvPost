//! Запуск интерфейса в терминале: crossterm, клиент Admin API (`tp-admin-client`) и цикл событий; тема по
//! окружению, знак бренда протоколом графики терминала, палитра консоли Linux на время работы. Мышь (TUI-07):
//! захват событий `crossterm` c пиксельным режимом `1016`, где терминал его принял, плавный курсор —
//! [`crate::cursor`], на консоли Linux координаты из `/dev/input` ([`crate::input`]).

use std::io::{self, Write};
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, Event, KeyEventKind, MouseEvent};
use crossterm::execute;
use ratatui::DefaultTerminal;
use ratatui_image::picker::{Picker, ProtocolType};
use serde_json::Value;
use tokio::sync::mpsc;
use tp_admin::server::WhoAmI;
use tp_admin_client::oidc::{DeviceLogin, prompt_text};
use tp_admin_client::{Client, ENV_TOKEN, ENV_URL, Options, base_url, setting};

use crate::app::{App, Effect, LoginField, LoginForm, LoginRequest, Page, Stage};
use crate::cursor::{self, Caps, Level, SmoothCursor};
use crate::engine::Request;
use crate::mouse::MouseConfig;
use crate::node::{self, ConfigFile, NodeConfig, SaveError, Saved};
use crate::schema::Response;
use crate::theme::{ConsolePalette, Theme, console_palette_needed};
use crate::ui;

/// Как часто поток ввода проверяет, не закрыт ли интерфейс (ожидание клавиши не дольше).
const INPUT_POLL: Duration = Duration::from_millis(200);

/// Байты возврата мыши: режим `1016`, захват `crossterm`, загруженные глифы DECDLD.
fn mouse_reset(pixel: bool, glyphs: bool) -> String {
    let mut s = String::new();
    if glyphs {
        s.push_str(&cursor::decdld_erase());
    }
    if pixel {
        s.push_str("\x1b[?1016l");
    }
    s.push_str("\x1b[?1006l\x1b[?1003l\x1b[?1002l\x1b[?1000l");
    s
}

/// Подключение к Admin API — те же значения, что у CLI `thepost admin` (адрес, CA, `--insecure`, токен).
#[derive(Debug, Default)]
pub struct Connect {
    /// Адрес Admin API; нет — `THEPOST_ADMIN_URL` (поле формы входа можно поправить).
    pub url: Option<String>,
    /// Токен: сессия `tps_…` или токен OIDC; нет — `THEPOST_ADMIN_TOKEN`. Есть — вход без формы.
    pub token: Option<String>,
    /// Имя входа для формы входа по паролю.
    pub user: Option<String>,
    /// Канал: корневые сертификаты, `--insecure`, предельное время запроса.
    pub options: Options,
    /// Вход с устройства через OIDC (настройки `auth.oidc` и `cli.oidc` читает вызывающий код); нет — способа
    /// «OIDC» в форме входа нет.
    pub oidc: Option<DeviceLogin>,
    /// Конфигурация узла, когда интерфейс запущен на самом узле с правом на `config.yaml`; нет — раздел
    /// «Конфигурация узла» только поясняет, где её править.
    pub node: Option<NodeConfig>,
    /// Режим темы (`--theme`): `auto`, `dark`, `light`, `256`, `16`, `mono`; нет — `THEPOST_TUI_THEME` и
    /// автоопределение по `NO_COLOR`, `COLORTERM`, `TERM`.
    pub theme: Option<String>,
    /// Уровень плавного курсора (`--mouse-cursor`): `auto`, `1`–`4`, `kitty`, `sixel`, `glyphs`, `cell`,
    /// `off`; нет — `THEPOST_TUI_MOUSE_CURSOR` и автоопределение по ответам терминала.
    pub mouse_cursor: Option<String>,
    /// Пороги мыши; нет — [`MouseConfig::default`].
    pub mouse: Option<MouseConfig>,
}

enum Msg {
    Term(Event),
    Login(Result<(Client, WhoAmI, String), String>),
    Device(String),
    Done(u64, Result<Page, tp_admin_client::Error>),
    Config(Result<ConfigFile, String>),
    ConfigSaved(Result<Saved, SaveError>),
    /// Мышь консоли Linux из `/dev/input`.
    #[cfg(target_os = "linux")]
    Mouse(crate::input::MouseEv),
    /// `SIGTERM` или закрытие окна: выйти штатно (терминал и палитра консоли возвращаются).
    Quit,
}

/// Текстовый интерфейс `thepost admin tui`: до выхода по F10; терминал возвращается в прежний режим и при ошибке.
pub async fn run(mut connect: Connect) -> Result<(), String> {
    let theme = Theme::from_env(connect.theme.take().as_deref())?;
    let mut terminal = ratatui::try_init().map_err(|e| format!("терминал: {e}"))?;
    let palette = console_palette(&theme);
    // Опрос терминала — до потока ввода (ответ приходит в stdin) и до захвата мыши.
    let picker = if theme.mode().graphics() {
        Some(Picker::from_query_stdio().unwrap_or_else(|_| Picker::halfblocks()))
    } else {
        None
    };
    let theme = if let Some(p) = &picker {
        theme.with_mark(p)
    } else {
        theme
    };
    let cfg = connect.mouse.take().unwrap_or_default();
    let console = std::env::var("TERM").ok().filter(|t| t == "linux");
    // Пиксельную мышь спрашиваем только у терминалов с картинками: остальные всё равно откажут.
    let graphics = picker
        .as_ref()
        .is_some_and(|p| matches!(p.protocol_type(), ProtocolType::Kitty | ProtocolType::Sixel));
    let pixel = graphics && cursor::probe_pixel_mouse(Duration::from_millis(cfg.query_timeout_ms));
    let caps = Caps {
        kitty: picker
            .as_ref()
            .is_some_and(|p| p.protocol_type() == ProtocolType::Kitty),
        sixel: picker
            .as_ref()
            .is_some_and(|p| p.protocol_type() == ProtocolType::Sixel),
        pixel_mouse: pixel,
        decdld: cursor::decdld_supported(|k| std::env::var(k).ok()),
        console: console.is_some(),
        #[cfg(target_os = "linux")]
        input: crate::input::available(),
        #[cfg(not(target_os = "linux"))]
        input: false,
    };
    let level = cursor::detect(&caps, connect.mouse_cursor.take().as_deref())?;
    // Windows: уровень 3 консоли не открывается — привязки дальше не меняются.
    #[allow(unused_mut)]
    let mut cursor = SmoothCursor::new(level, picker.as_ref(), cfg.shift_steps);
    // Уровень 3 на консоли Linux: глифы — в шрифт консоли через `tp-sys` (KDFONTOP), отказ — уровень 4.
    #[allow(unused_mut)]
    let mut console_font = ConsoleFont::new();
    #[cfg(target_os = "linux")]
    console_font.open(console.is_some(), &mut cursor).await;
    // DECDLD-набор — только терминалу: консоль escape-последовательности шрифта не понимает.
    let glyphs = cursor.level() == Level::Glyphs && console.is_none();
    let _mouse = MouseCapture::set(io::stdout(), pixel, glyphs);
    // Шрифт консоли уходит в цикл: возврат шрифта и карты Unicode (RAII) — при выходе из него.
    let result = event_loop(&mut terminal, connect, theme, cursor, cfg, console_font).await;
    let restored = ratatui::try_restore().map_err(|e| format!("терминал: {e}"));
    drop(palette);
    result.and(restored)
}

/// Шрифт консоли Linux на время работы интерфейса (TUI-12, решение 119, вариант 1): уровень 3 плавного
/// курсора ставит глифы в шрифт консоли (`tp_sys::console_font`, `KDFONTOP`); `Drop` возвращает шрифт и
/// карту Unicode как были — при выходе, ошибке и панике. Вне Linux — пустая заглушка.
struct ConsoleFont {
    /// Открытый шрифт; `None` — уровень 4.
    #[cfg(target_os = "linux")]
    font: Option<tp_sys::console_font::ConsoleFont>,
}

impl ConsoleFont {
    fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            font: None,
        }
    }

    /// Открыть шрифт (блокирующие ioctl — в `spawn_blocking`) и занять четыре кода PUA; отказ (не
    /// vt-консоль, нет `CAP_SYS_TTY_CONFIG`) — курсор на уровень 4.
    #[cfg(target_os = "linux")]
    async fn open(&mut self, console: bool, cursor: &mut SmoothCursor) {
        if !console || cursor.level() != Level::Glyphs {
            return;
        }
        let opened = tokio::task::spawn_blocking(tp_sys::console_font::ConsoleFont::open)
            .await
            .ok()
            .and_then(|r| r.ok());
        match opened {
            Some(font) => {
                let (codes, cell) = (font.codes(), font.cell());
                let _ = writeln!(
                    io::stderr(),
                    "шрифт консоли: глифы курсора — коды {codes:?}, ячейка {cell:?}"
                );
                cursor.console_font(Some((codes, cell)));
                self.font = Some(font);
            }
            None => {
                let _ = writeln!(
                    io::stderr(),
                    "шрифт консоли недоступен (нет прав или не vt-консоль) — курсор на уровне 4"
                );
                cursor.console_font(None);
            }
        }
    }

    /// Перерисовать четыре глифа в шрифте консоли; отказ — шрифт возвращается (`Drop`), курсор на
    /// уровень 4.
    #[cfg(target_os = "linux")]
    fn set_glyphs(&mut self, quads: [cursor::Glyph; 4], cur: &mut SmoothCursor) {
        if let Some(mut font) = self.font.take() {
            let rows = quads.map(|g| g.rows);
            match font.set_glyphs(&rows) {
                Ok(()) => self.font = Some(font),
                Err(e) => {
                    let _ = writeln!(io::stderr(), "шрифт консоли: {e} — курсор на уровне 4");
                    cur.console_font(None);
                }
            }
        }
    }
}

/// Палитра бренда на консоли Linux в 16 цветах; возвращается при сбросе и при панике.
fn console_palette(theme: &Theme) -> Option<ConsolePalette<io::Stdout>> {
    let term = std::env::var("TERM").ok();
    if !console_palette_needed(term.as_deref(), theme.mode()) {
        return None;
    }
    ConsolePalette::<io::Stdout>::reset_on_panic();
    ConsolePalette::set(io::stdout(), theme.console_palette()).ok()
}

/// Захват мыши на время работы интерфейса: события `crossterm`, где терминал принял режим `1016` — события
/// в пикселях; загруженные глифы DECDLD стираются. При сбросе и панике терминал возвращается в прежний режим.
struct MouseCapture<W: Write> {
    out: W,
    pixel: bool,
    glyphs: bool,
}

impl<W: Write> MouseCapture<W> {
    fn set(mut out: W, pixel: bool, glyphs: bool) -> Self {
        if pixel {
            let _ = out.write_all(b"\x1b[?1016h");
        }
        if let Err(e) = execute!(&mut out, crossterm::event::EnableMouseCapture) {
            let _ = writeln!(io::stderr(), "мышь: {e}");
        }
        if glyphs {
            // Набор глифов назначается в G2 и печатается одиночным сдвигом SS2.
            let _ = out.write_all(cursor::GLYPH_G2.as_bytes());
        }
        let _ = out.flush();
        let c = Self { out, pixel, glyphs };
        c.reset_on_panic();
        c
    }

    fn reset_on_panic(&self) {
        let (pixel, glyphs) = (self.pixel, self.glyphs);
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let mut out = io::stdout();
            let _ = out.write_all(mouse_reset(pixel, glyphs).as_bytes());
            let _ = out.flush();
            prev(info);
        }));
    }
}

impl<W: Write> Drop for MouseCapture<W> {
    fn drop(&mut self) {
        let _ = self
            .out
            .write_all(mouse_reset(self.pixel, self.glyphs).as_bytes());
        let _ = self.out.flush();
    }
}

async fn event_loop(
    terminal: &mut DefaultTerminal,
    connect: Connect,
    theme: Theme,
    mut cur: SmoothCursor,
    cfg: MouseConfig,
    mut console_font: ConsoleFont,
) -> Result<(), String> {
    let url = setting(connect.url, ENV_URL).unwrap_or_default();
    let token = setting(connect.token, ENV_TOKEN);
    let mut login = LoginForm::new(url.clone(), connect.oidc.is_some());
    if let Some(user) = connect.user {
        login.user = user;
        login.focus = LoginField::Secret;
    }
    let mut app = App::new(theme, login);
    app.node = connect.node.is_some();
    app.mouse.cfg = cfg;
    let node = connect.node;
    let options = connect.options;
    let oidc = connect.oidc.map(Arc::new);
    let (tx, mut rx) = mpsc::unbounded_channel();
    spawn_input(tx.clone());
    spawn_signal(tx.clone());
    #[cfg(target_os = "linux")]
    let console_screen = if std::env::var("TERM").as_deref() == Ok("linux") {
        crate::input::screen(app.mouse.cfg.console_cell)
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    if let Some(screen) = console_screen {
        let tx = tx.clone();
        crate::input::spawn(screen, move |ev| {
            let _ = tx.send(Msg::Mouse(ev));
        });
    }
    let mut client: Option<Client> = None;
    if let Some(token) = token {
        let effects = vec![Effect::Login(LoginRequest::Token { url, token })];
        if let Stage::Login(f) = &mut app.stage {
            f.busy = true;
        }
        apply(
            effects,
            &tx,
            &options,
            &oidc,
            client.as_ref(),
            node.as_ref(),
        );
    }
    loop {
        paint(terminal, &mut app, &mut cur, &mut console_font)?;
        let Some(msg) = rx.recv().await else {
            return Ok(());
        };
        let effects = match msg {
            Msg::Term(Event::Key(k)) if k.kind != KeyEventKind::Release => app.on_key(k),
            Msg::Term(Event::Mouse(m)) => {
                let ((col, row), px) = cur.point(&m);
                app.on_mouse(
                    &MouseEvent {
                        column: col,
                        row,
                        ..m
                    },
                    px,
                )
            }
            Msg::Term(_) => Vec::new(),
            #[cfg(target_os = "linux")]
            Msg::Mouse(ev) => {
                let (col, row) = console_screen.map_or((0, 0), |s| s.cell_of(ev.x, ev.y));
                use crossterm::event::{MouseButton, MouseEventKind};
                let kind = match ev.kind {
                    crate::input::Kind::Move => MouseEventKind::Moved,
                    crate::input::Kind::Down => MouseEventKind::Down(MouseButton::Left),
                    crate::input::Kind::Up => MouseEventKind::Up(MouseButton::Left),
                    crate::input::Kind::Wheel(v) if v > 0 => MouseEventKind::ScrollDown,
                    crate::input::Kind::Wheel(_) => MouseEventKind::ScrollUp,
                };
                app.on_mouse(
                    &MouseEvent {
                        kind,
                        column: col,
                        row,
                        modifiers: crossterm::event::KeyModifiers::NONE,
                    },
                    Some((ev.x, ev.y)),
                )
            }
            Msg::Login(Ok((c, who, server))) => {
                client = Some(c);
                app.on_login(Ok((who, server)))
            }
            Msg::Login(Err(e)) => app.on_login(Err(e)),
            Msg::Device(text) => {
                app.on_device(text);
                Vec::new()
            }
            Msg::Done(id, r) => app.on_result(id, r),
            Msg::Config(r) => {
                app.on_config(r);
                Vec::new()
            }
            Msg::ConfigSaved(r) => app.on_config_saved(r),
            Msg::Quit => return Ok(()),
        };
        if effects.contains(&Effect::Quit) {
            return Ok(());
        }
        apply(
            effects,
            &tx,
            &options,
            &oidc,
            client.as_ref(),
            node.as_ref(),
        );
    }
}

/// Кадр: экран, курсор со сдвигом и загрузка глифов до отрисовки — терминалу escape-строкой DECDLD,
/// консоли Linux — в шрифт через `tp-sys` (короткий ioctl `KDFONTOP`, как запись кадра в stdout).
fn paint(
    terminal: &mut DefaultTerminal,
    app: &mut App,
    cur: &mut SmoothCursor,
    #[cfg(target_os = "linux")] console_font: &mut ConsoleFont,
    #[cfg(not(target_os = "linux"))] _console_font: &mut ConsoleFont,
) -> Result<(), String> {
    let px = app.mouse.px;
    let pos = app.mouse.pos;
    // До первого события мыши курсора нет.
    app.cursor = pos.and_then(|p| cur.view(px, p));
    match cur.take_download() {
        Some(cursor::Download::Escape(dcs)) => {
            let mut out = io::stdout();
            let _ = out.write_all(dcs.as_bytes());
            let _ = out.flush();
        }
        // Консоль: растры — в шрифт; отказ — шрифт возвращается (Drop), курсор на уровень 4.
        #[cfg(target_os = "linux")]
        Some(cursor::Download::Console(quads)) => console_font.set_glyphs(quads, cur),
        #[cfg(not(target_os = "linux"))]
        Some(cursor::Download::Console(_)) => {}
        None => {}
    }
    terminal
        .draw(|f| ui::draw(f, app))
        .map_err(|e| format!("терминал: {e}"))?;
    Ok(())
}

/// Выполнить действия интерфейса: вход, запросы и файл конфигурации узла — задачами, ответы — сообщениями в
/// цикл.
fn apply(
    effects: Vec<Effect>,
    tx: &mpsc::UnboundedSender<Msg>,
    options: &Options,
    oidc: &Option<Arc<DeviceLogin>>,
    client: Option<&Client>,
    node: Option<&NodeConfig>,
) {
    for e in effects {
        match e {
            Effect::Quit => {}
            Effect::ConfigLoad => {
                let tx = tx.clone();
                let node = node.cloned();
                tokio::task::spawn_blocking(move || {
                    let r = node
                        .ok_or_else(|| "конфигурация узла недоступна".to_owned())
                        .and_then(|n| node::load(&n));
                    let _ = tx.send(Msg::Config(r));
                });
            }
            Effect::ConfigSave {
                path,
                value,
                loaded,
            } => {
                let tx = tx.clone();
                let node = node.cloned();
                tokio::task::spawn_blocking(move || {
                    let r = match node {
                        Some(n) => node::save(&n, &loaded, &path, value),
                        None => Err(SaveError {
                            at_field: false,
                            message: "конфигурация узла недоступна".to_owned(),
                        }),
                    };
                    let _ = tx.send(Msg::ConfigSaved(r));
                });
            }
            Effect::Login(req) => {
                let tx = tx.clone();
                let options = options.clone();
                let oidc = oidc.clone();
                tokio::spawn(async move {
                    let r = login(req, &options, oidc, &tx).await;
                    let _ = tx.send(Msg::Login(r));
                });
            }
            Effect::Call(id, req) => {
                let tx = tx.clone();
                let Some(client) = client.cloned() else {
                    let _ = tx.send(Msg::Done(
                        id,
                        Err(tp_admin_client::Error::Client("нет входа".to_owned())),
                    ));
                    continue;
                };
                tokio::spawn(async move {
                    let r = call(&client, req).await;
                    let _ = tx.send(Msg::Done(id, r));
                });
            }
        }
    }
}

/// Поток ввода: события терминала в цикл, пока интерфейс открыт.
fn spawn_input(tx: mpsc::UnboundedSender<Msg>) {
    std::thread::spawn(move || {
        while !tx.is_closed() {
            match event::poll(INPUT_POLL) {
                Ok(true) => match event::read() {
                    Ok(ev) => {
                        if tx.send(Msg::Term(ev)).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                Ok(false) => {}
                Err(_) => break,
            }
        }
    });
}

/// `SIGTERM` (в Windows — закрытие окна консоли) — сообщением в цикл: выход штатный, с возвратом терминала и
/// палитры.
fn spawn_signal(tx: mpsc::UnboundedSender<Msg>) {
    tokio::spawn(async move {
        #[cfg(unix)]
        let stop = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
        #[cfg(windows)]
        let stop = tokio::signal::windows::ctrl_close();
        if let Ok(mut stop) = stop {
            stop.recv().await;
            let _ = tx.send(Msg::Quit);
        }
    });
}

/// Вход тем же клиентом, что у CLI: по паролю (`POST /api/v1/session`), токеном или с устройства (OIDC); затем
/// `whoami`.
async fn login(
    req: LoginRequest,
    options: &Options,
    oidc: Option<Arc<DeviceLogin>>,
    tx: &mpsc::UnboundedSender<Msg>,
) -> Result<(Client, WhoAmI, String), String> {
    let (url, token) = match req {
        LoginRequest::Password {
            url,
            user,
            password,
        } => {
            let anon = Client::anonymous(base_url(&url)?, options)?;
            (url, anon.login(&user, password).await?.session)
        }
        LoginRequest::Token { url, token } => (url, tp_admin_client::token(Some(token))?),
        LoginRequest::Oidc { url } => {
            let oidc =
                oidc.ok_or("вход через OIDC не настроен (auth.oidc и cli.oidc в config.yaml)")?;
            let token = oidc
                .login(|code| {
                    let _ = tx.send(Msg::Device(prompt_text(code)));
                })
                .await?;
            (url, token)
        }
    };
    let base = base_url(&url)?;
    let server = match (base.host_str(), base.port()) {
        (Some(h), Some(p)) => format!("{h}:{p}"),
        (Some(h), None) => h.to_owned(),
        _ => url.clone(),
    };
    let client = Client::new(base, token, options)?;
    let who = client.whoami().await?;
    Ok((client, who, server))
}

/// Запрос экрана к Admin API; следующая страница — по ссылке `Link: rel="next"`.
async fn call(client: &Client, req: Request) -> Result<Page, tp_admin_client::Error> {
    let op = req.op.op();
    let params: Vec<&str> = req.params.iter().map(String::as_str).collect();
    if req.op.response == Response::Empty {
        client
            .call_empty(op, &params, &req.query, req.body.as_ref())
            .await?;
        return Ok(Page {
            value: Value::Null,
            next: None,
        });
    }
    let (value, link): (Value, Option<String>) = client
        .call_page(op, &params, &req.query, req.body.as_ref())
        .await?;
    let next = link.map(|l| client.link_query(&l)).transpose()?;
    Ok(Page { value, next })
}
