//! Выполнение программы над письмом (SIEVE-03): `if`/`elsif`/`else`, `stop`, действия и implicit keep
//! (RFC 5228 §2.10.2), тесты ядра, компараторы `i;octet`, `i;ascii-casemap`, `i;ascii-numeric` и типы сравнения
//! `:is`, `:contains`, `:matches`, `:value`, `:count`, `:regex` (draft-ietf-sieve-regex, SIEVE-15); тест `body`
//! (RFC 5173, SIEVE-05); `environment` (RFC 5183) и `extlists` (RFC 6134) — факты и списки из контекста ядра
//! (SIEVE-15, решение 126 д); команда `signal` (`vnd.thepost.risk`) — признаки в итог правил.
//!
//! Заголовки декодируются (RFC 2047), адреса разбираются по RFC 5322 — `mail-parser`. Ошибка выполнения (в том числе
//! превышение [`Limits::max_steps`] и [`Limits::max_actions`]) отменяет действия скрипта: остаётся implicit keep.
//! Слияние действий в `RulesOutcome` — [`crate::outcome`] (SIEVE-04).

use std::cmp::Ordering;

use mail_parser::decoders::html::html_to_text;
use mail_parser::{
    HeaderForm, HeaderName, HeaderValue, Message, MessageParser, MessageRef, PartKind,
};
use serde::{Deserialize, Serialize};
use tp_contracts::risk::SignalId;
use tp_contracts::sieve::ProcessCalendar;
use tp_contracts::trust::PeerKind;

use crate::Limits;
use crate::compile::{
    Cmd, Comparator, EnvName, FlagOp, Match, MatchKind, Part, Program, Rel, Test, Transform,
};

/// Письмо и конверт на входе выполнения.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// Письмо целиком (RFC 5322).
    pub message: &'a [u8],
    /// Отправитель конверта (`MAIL FROM`), пустой — уведомление о недоставке.
    pub envelope_from: &'a str,
    /// Получатель конверта с подадресом (`anna+news@example.org`).
    pub envelope_to: &'a str,
    /// Существующие папки (`mailboxexists`), путь через `/`.
    pub mailboxes: &'a [String],
    /// Тип абонента — отправителя относительно организации получателя (CTR-93, решение 124): тест `peer`
    /// расширения `vnd.thepost.peer`. Вычисляет вызывающий (ядро); заголовкам письма не доверяем
    /// (RFC 5183, RFC 8601 §5). Умолчание — `external` (безопасное).
    pub peer: PeerKind,
    /// Факты теста `environment` (RFC 5183, SIEVE-15, решение 126 д): ядро и `vnd.thepost.*` — из контекста
    /// ядра (CTR-95), не из заголовков письма.
    pub environment: Environment<'a>,
    /// Внешние списки `extlists` (RFC 6134, SIEVE-15): интерфейс узла (APP-79), в тестах — память. Без
    /// интерфейса списков нет: `:list` — ложь, `valid_ext_list` — ложь.
    pub lists: &'a dyn ExternalLists,
}

impl Default for Context<'_> {
    fn default() -> Self {
        Self {
            message: b"",
            envelope_from: "",
            envelope_to: "",
            mailboxes: &[],
            peer: PeerKind::External,
            environment: Environment::default(),
            lists: &NO_LISTS,
        }
    }
}

/// Этап выполнения `environment "phase"` (RFC 5183 §4): скрипт организации — `before` (до скрипта
/// пользователя), скрипт пользователя — `during`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Скрипт организации (этап before, SIEVE-14).
    Before,
    /// Скрипт пользователя (доставка).
    #[default]
    During,
}

impl Phase {
    /// Значение пункта `phase`.
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Before => "before",
            Phase::During => "during",
        }
    }
}

/// Беседа `environment "vnd.thepost.thread"` (SIEVE-15, решение 126 д): доверенная, известная недоверенная
/// или данных нет. Считает вызывающий по памяти беседы; заголовкам письма не доверяем.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadTrust {
    /// Доверенная беседа (`RulesInput::thread_trusted`).
    Trusted,
    /// Беседа не доверена.
    Untrusted,
    /// Факта нет (умолчание контекста без данных).
    #[default]
    None,
}

impl ThreadTrust {
    /// Значение пункта `vnd.thepost.thread`.
    pub fn as_str(self) -> &'static str {
        match self {
            ThreadTrust::Trusted => "trusted",
            ThreadTrust::Untrusted => "untrusted",
            ThreadTrust::None => "none",
        }
    }
}

/// Факты теста `environment` (RFC 5183, SIEVE-15): пункты ядра (`domain`, `host`, `phase`) и `vnd.thepost.*`
/// (CTR-95, решение 126 д). Значения считает Rust до Sieve и передаёт вызывающий с контекстом.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Environment<'a> {
    /// `domain` — домен получателя (домен `RulesInput::recipient`).
    pub domain: &'a str,
    /// `host` — имя узла (`Rules::with_node`); пусто, когда не задано.
    pub host: &'a str,
    /// `phase` — этап выполнения.
    pub phase: Phase,
    /// `vnd.thepost.thread` — беседа с отправителем.
    pub thread: ThreadTrust,
    /// `vnd.thepost.reply` — письмо ответ на наше письмо (`PeerContext::reply`): `yes`|`no`.
    pub reply: bool,
    /// `vnd.thepost.risk.score` — балл справочника аномалий до Sieve (`Verdict::score`).
    pub risk_score: u32,
    /// `vnd.thepost.risk.signals` — сработавшие признаки (`Verdict::hits`, затем `report_only`), через запятую.
    pub risk_signals: &'a [SignalId],
}

/// Поиск во внешних списках `extlists` (RFC 6134, SIEVE-15): узел передаёт интерфейс (APP-79) — списки TI и
/// адресные книги по URI `tag:` (CTR-95); в тестах — память. Методы синхронные: узел ищет по индексам в памяти.
pub trait ExternalLists: std::fmt::Debug + Send + Sync + 'static {
    /// Есть ли `value` в списке `uri` (`:list`).
    fn contains(&self, uri: &str, value: &str) -> bool;
    /// Существует ли список `uri` (`valid_ext_list`).
    fn valid(&self, uri: &str) -> bool;
}

/// Списков нет — умолчание [`Context::lists`] (и [`crate::Rules`] без `with_lists`).
#[derive(Debug)]
pub(crate) struct NoLists;

impl ExternalLists for NoLists {
    fn contains(&self, _uri: &str, _value: &str) -> bool {
        false
    }

    fn valid(&self, _uri: &str) -> bool {
        false
    }
}

pub(crate) const NO_LISTS: NoLists = NoLists;

/// Параметры `vacation` из скрипта (RFC 5230); решение «отвечать ли» — SIEVE-06.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VacationAction {
    /// `:days`.
    pub days: Option<u64>,
    /// `:subject`.
    pub subject: Option<String>,
    /// `:from`.
    pub from: Option<String>,
    /// `:addresses`.
    pub addresses: Vec<String>,
    /// `:mime` — `reason` содержит MIME-сущность.
    pub mime: bool,
    /// `:handle`.
    pub handle: Option<String>,
    /// Текст ответа.
    pub reason: String,
}

/// Действие скрипта в порядке выполнения.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// `keep` во «Входящие» с флагами.
    Keep {
        /// Флаги IMAP.
        flags: Vec<String>,
    },
    /// `discard`.
    Discard,
    /// `fileinto`.
    FileInto {
        /// Папка.
        mailbox: String,
        /// `:copy` — implicit keep не отменяется.
        copy: bool,
        /// `:create`.
        create: bool,
        /// Флаги IMAP.
        flags: Vec<String>,
    },
    /// `redirect`.
    Redirect {
        /// Адрес.
        address: String,
        /// `:copy` — implicit keep не отменяется.
        copy: bool,
    },
    /// `vacation`.
    Vacation(VacationAction),
    /// `processcalendar` (RFC 9671 §3, SIEVE-14): параметры для приёма iTIP; интерпретатор их только
    /// записывает, применяет вызывающий. Не отменяет implicit keep (RFC 9671 §3).
    ProcessCalendar(ProcessCalendar),
}

/// Итог выполнения.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Outcome {
    /// Действия в порядке выполнения; при ошибке — пусто.
    pub actions: Vec<Action>,
    /// Implicit keep: ни `keep`, ни `discard`, ни `fileinto`/`redirect` без `:copy` не выполнены, или ошибка.
    pub implicit_keep: bool,
    /// Флаги implicit keep — внутренняя переменная `imap4flags` в конце выполнения.
    pub flags: Vec<String>,
    /// Ошибка выполнения (без содержимого письма).
    pub error: Option<String>,
    /// Выполнение закончилось командой `stop`.
    pub stopped: bool,
    /// Признаки команды `signal` (расширение `vnd.thepost.risk`, SIEVE-15) в порядке срабатывания, без
    /// повторов; вызывающий прибавляет их к вердикту справочника. Не действие: implicit keep не отменяют.
    pub signals: Vec<(SignalId, Option<u16>)>,
}

/// Выполняет программу над письмом.
pub fn run(program: &Program, ctx: &Context<'_>, limits: &Limits) -> Outcome {
    let mut ex = Exec {
        ctx: *ctx,
        limits,
        headers: parse_headers(ctx.message),
        steps: 0,
        actions: Vec::new(),
        flags: Vec::new(),
        cancel_keep: false,
        vacation: false,
        calendar: false,
        body: None,
        signals: Vec::new(),
    };
    match ex.block(&program.commands) {
        Ok(flow) => Outcome {
            stopped: matches!(flow, Flow::Stop),
            implicit_keep: !ex.cancel_keep,
            actions: ex.actions,
            flags: ex.flags,
            error: None,
            signals: ex.signals,
        },
        Err(Fail(e)) => Outcome {
            implicit_keep: true,
            error: Some(e),
            ..Outcome::default()
        },
    }
}

pub(crate) struct Hdr {
    pub(crate) name: String,
    /// Значение после RFC 2047, без ведущих и хвостовых пробелов.
    pub(crate) value: String,
    /// Границы сырого значения в письме.
    pub(crate) start: usize,
    pub(crate) end: usize,
}

struct Fail(String);

enum Flow {
    Next,
    Stop,
}

struct Exec<'a> {
    ctx: Context<'a>,
    limits: &'a Limits,
    headers: Vec<Hdr>,
    steps: u64,
    actions: Vec<Action>,
    flags: Vec<String>,
    cancel_keep: bool,
    vacation: bool,
    calendar: bool,
    /// Признаки команды `signal` (без повторов; повтор с другим весом не проходит проверку скрипта).
    signals: Vec<(SignalId, Option<u16>)>,
    /// Разобранное письмо для теста `body` (разбирается при первом тесте; `Some(None)` — не разобрано).
    body: Option<Option<Message<'a>>>,
}

impl Exec<'_> {
    fn step(&mut self, n: u64) -> Result<(), Fail> {
        self.steps = self.steps.saturating_add(n);
        if self.steps > self.limits.max_steps {
            return Err(steps_exceeded(self.limits));
        }
        Ok(())
    }

    fn block(&mut self, cmds: &[Cmd]) -> Result<Flow, Fail> {
        for c in cmds {
            self.step(1)?;
            if let Flow::Stop = self.cmd(c)? {
                return Ok(Flow::Stop);
            }
        }
        Ok(Flow::Next)
    }

    fn cmd(&mut self, c: &Cmd) -> Result<Flow, Fail> {
        match c {
            Cmd::If {
                branches,
                otherwise,
            } => {
                for (test, body) in branches {
                    if self.test(test)? {
                        return self.block(body);
                    }
                }
                if let Some(body) = otherwise {
                    return self.block(body);
                }
            }
            Cmd::Stop => return Ok(Flow::Stop),
            Cmd::Keep { flags } => {
                let flags = flags.clone().unwrap_or_else(|| self.flags.clone());
                self.act(Action::Keep { flags }, true)?;
            }
            Cmd::Discard => self.act(Action::Discard, true)?,
            Cmd::FileInto {
                mailbox,
                copy,
                create,
                flags,
            } => {
                let flags = flags.clone().unwrap_or_else(|| self.flags.clone());
                self.act(
                    Action::FileInto {
                        mailbox: mailbox.clone(),
                        copy: *copy,
                        create: *create,
                        flags,
                    },
                    !*copy,
                )?;
            }
            Cmd::Redirect { address, copy } => self.act(
                Action::Redirect {
                    address: address.clone(),
                    copy: *copy,
                },
                !*copy,
            )?,
            Cmd::Flags { op, flags } => self.set_flags(*op, flags),
            Cmd::Vacation(v) => {
                if self.vacation {
                    return Err(Fail("vacation выполнен второй раз".into()));
                }
                self.vacation = true;
                self.act(Action::Vacation(v.clone()), false)?;
            }
            Cmd::ProcessCalendar(p) => {
                // Не чаще одного раза за скрипт (RFC 9671 §3); implicit keep не отменяет.
                if self.calendar {
                    return Err(Fail("processcalendar выполнен второй раз".into()));
                }
                self.calendar = true;
                self.act(Action::ProcessCalendar(p.clone()), false)?;
            }
            Cmd::Signal { id, weight } => {
                // Не действие: implicit keep не отменяет, к числу действий не считается. Повтор признака —
                // один признак (повтор с другим весом не проходит проверку скрипта).
                if !self.signals.iter().any(|(i, _)| i == id) {
                    self.signals.push((id.clone(), *weight));
                }
            }
        }
        Ok(Flow::Next)
    }

    fn act(&mut self, action: Action, cancels_keep: bool) -> Result<(), Fail> {
        if self.actions.len() >= self.limits.max_actions {
            return Err(Fail(format!(
                "больше {} действий за выполнение",
                self.limits.max_actions
            )));
        }
        if matches!(action, Action::Redirect { .. }) {
            let n = self
                .actions
                .iter()
                .filter(|a| matches!(a, Action::Redirect { .. }))
                .count();
            if n >= self.limits.max_redirects {
                return Err(Fail(format!(
                    "больше {} перенаправлений за выполнение",
                    self.limits.max_redirects
                )));
            }
        }
        self.actions.push(action);
        self.cancel_keep |= cancels_keep;
        Ok(())
    }

    fn set_flags(&mut self, op: FlagOp, flags: &[String]) {
        match op {
            FlagOp::Set => {
                self.flags.clear();
                add_flags(&mut self.flags, flags);
            }
            FlagOp::Add => add_flags(&mut self.flags, flags),
            FlagOp::Remove => self
                .flags
                .retain(|f| !flags.iter().any(|x| x.eq_ignore_ascii_case(f))),
        }
    }

    fn test(&mut self, t: &Test) -> Result<bool, Fail> {
        self.step(1)?;
        Ok(match t {
            Test::True => true,
            Test::False => false,
            Test::Not(x) => !self.test(x)?,
            Test::AllOf(tests) => {
                for x in tests {
                    if !self.test(x)? {
                        return Ok(false);
                    }
                }
                true
            }
            Test::AnyOf(tests) => {
                for x in tests {
                    if self.test(x)? {
                        return Ok(true);
                    }
                }
                false
            }
            Test::Exists(names) => {
                self.step(len_u64(self.headers.len()))?;
                names
                    .iter()
                    .all(|n| self.headers.iter().any(|h| h.name.eq_ignore_ascii_case(n)))
            }
            Test::Size { over, limit } => {
                let size = len_u64(self.ctx.message.len());
                if *over { size > *limit } else { size < *limit }
            }
            Test::Header {
                m,
                names,
                keys,
                list,
            } => {
                let values = self.header_values(names)?;
                if *list {
                    self.list_hit(&values, keys)?
                } else {
                    self.matches(m, &values, keys)?
                }
            }
            Test::Address {
                m,
                part,
                names,
                keys,
                list,
            } => {
                let values = self.address_values(names, *part)?;
                if *list {
                    self.list_hit(&values, keys)?
                } else {
                    self.matches(m, &values, keys)?
                }
            }
            Test::Envelope {
                m,
                part,
                names,
                keys,
                list,
            } => {
                let values: Vec<String> = names
                    .iter()
                    .filter_map(|n| {
                        let raw = if n == "from" {
                            self.ctx.envelope_from
                        } else {
                            self.ctx.envelope_to
                        };
                        address_part(strip_angle(raw), *part)
                    })
                    .collect();
                if *list {
                    self.list_hit(&values, keys)?
                } else {
                    self.matches(m, &values, keys)?
                }
            }
            Test::Body { m, transform, keys } => {
                let values = self.body_values(transform)?;
                self.matches(m, &values, keys)?
            }
            Test::HasFlag { m, keys } => {
                let values = self.flags.clone();
                self.matches(m, &values, keys)?
            }
            Test::MailboxExists(names) => names.iter().all(|n| {
                self.ctx.mailboxes.iter().any(|mb| {
                    mb == n || (mb.eq_ignore_ascii_case("INBOX") && n.eq_ignore_ascii_case("INBOX"))
                })
            }),
            Test::Peer { m, keys } => {
                // Тип абонента — из контекста ядра (CTR-93), заголовки письма не читаются (решение 124).
                let values = [self.ctx.peer.as_str().to_owned()];
                self.matches(m, &values, keys)?
            }
            Test::Environment { m, name, keys } => {
                // Факты — из контекста ядра (CTR-95, решение 126 д), заголовки письма не читаются:
                // подделка `X-ThePost-Thread` и подобных на тест не влияет.
                let value = self.env_value(*name);
                self.matches(m, &[value], keys)?
            }
            Test::ValidExtList(uris) => uris.iter().all(|u| self.ctx.lists.valid(u)),
        })
    }

    /// Значение пункта `environment` (RFC 5183, SIEVE-15) из контекста.
    fn env_value(&self, name: EnvName) -> String {
        let env = &self.ctx.environment;
        match name {
            EnvName::Domain => env.domain.to_owned(),
            EnvName::Host => env.host.to_owned(),
            EnvName::Phase => env.phase.as_str().to_owned(),
            EnvName::Thread => env.thread.as_str().to_owned(),
            EnvName::Reply => if env.reply { "yes" } else { "no" }.to_owned(),
            EnvName::RiskScore => env.risk_score.to_string(),
            EnvName::RiskSignals => env
                .risk_signals
                .iter()
                .map(SignalId::as_str)
                .collect::<Vec<_>>()
                .join(","),
        }
    }

    /// Поиск значений во внешних списках (`:list`, RFC 6134, SIEVE-15): истина, если хоть одно значение есть
    /// хоть в одном списке. Поиск — интерфейс узла (APP-79), здесь — только шаги лимита.
    fn list_hit(&mut self, values: &[String], uris: &[String]) -> Result<bool, Fail> {
        for v in values {
            for u in uris {
                self.step(1)?;
                if self.ctx.lists.contains(u, v) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Значения теста `body` (RFC 5173): `:raw` — тело как есть, `:text` — текст частей `text/*` (HTML — без
    /// разметки), `:content` — декодированные части указанных типов. Всего не больше [`Limits::max_body_scan`] байт.
    fn body_values(&mut self, transform: &Transform) -> Result<Vec<String>, Fail> {
        let raw = self.ctx.message;
        let mut scan = Scan {
            left: self.limits.max_body_scan,
            out: Vec::new(),
        };
        if let Transform::Raw = transform {
            let body = raw.get(body_offset(raw)..).unwrap_or_default();
            let body = body.get(..scan.left.min(body.len())).unwrap_or_default();
            scan.push(&String::from_utf8_lossy(body));
            return Ok(scan.out);
        }
        if self.body.is_none() {
            self.step(1 + len_u64(raw.len()) / 1024)?;
            self.body = Some(MessageParser::default().parse(raw));
        }
        if let Some(Some(msg)) = &self.body {
            let types = match transform {
                Transform::Content(types) => Some(types.as_slice()),
                _ => None,
            };
            collect(msg.root(), types, &mut scan);
        }
        Ok(scan.out)
    }

    fn header_values(&mut self, names: &[String]) -> Result<Vec<String>, Fail> {
        self.step(len_u64(self.headers.len()))?;
        Ok(self
            .headers
            .iter()
            .filter(|h| names.iter().any(|n| h.name.eq_ignore_ascii_case(n)))
            .map(|h| h.value.clone())
            .collect())
    }

    fn address_values(&mut self, names: &[String], part: Part) -> Result<Vec<String>, Fail> {
        self.step(len_u64(self.headers.len()))?;
        let mut out = Vec::new();
        for h in &self.headers {
            if !names.iter().any(|n| h.name.eq_ignore_ascii_case(n)) {
                continue;
            }
            let raw = self.ctx.message.get(h.start..h.end).unwrap_or_default();
            out.extend(
                parse_addresses(raw)
                    .iter()
                    .filter_map(|a| address_part(a, part)),
            );
        }
        Ok(out)
    }

    /// Сравнение значений с ключами: истина, если подошла хоть одна пара (для `:count` — число значений).
    fn matches(&mut self, m: &Match, values: &[String], keys: &[String]) -> Result<bool, Fail> {
        if let MatchKind::Count(rel) = m.kind {
            let n = values.len().to_string();
            return Ok(keys.iter().any(|k| rel.holds(compare(m.cmp, &n, k))));
        }
        for k in keys {
            let pattern = matches!(m.kind, MatchKind::Matches).then(|| glob_pattern(k));
            for v in values {
                self.step(1 + len_u64(v.len()) / 256)?;
                let hit = match m.kind {
                    MatchKind::Is => compare(m.cmp, v, k) == Ordering::Equal,
                    MatchKind::Contains => contains(m.cmp, v, k),
                    MatchKind::Value(rel) => rel.holds(compare(m.cmp, v, k)),
                    // `:regex` (draft-ietf-sieve-regex, SIEVE-15): шаблоны скомпилированы при проверке
                    // скрипта с лимитами `sieve.regex`, поиск крейта `regex` за линейное время (без ReDoS).
                    MatchKind::Regex => m
                        .regex
                        .iter()
                        .filter_map(|r| r.re.as_ref())
                        .any(|re| re.is_match(v)),
                    MatchKind::Matches => {
                        let chars: Vec<char> = v.chars().collect();
                        let p = pattern.as_deref().unwrap_or_default();
                        match glob(p, &chars, m.cmp, &mut self.steps, self.limits.max_steps) {
                            Some(hit) => hit,
                            None => return Err(steps_exceeded(self.limits)),
                        }
                    }
                    MatchKind::Count(_) => false,
                };
                if hit {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
}

fn steps_exceeded(limits: &Limits) -> Fail {
    Fail(format!(
        "превышен лимит шагов выполнения ({})",
        limits.max_steps
    ))
}

fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

fn add_flags(to: &mut Vec<String>, flags: &[String]) {
    for f in flags {
        if !to.iter().any(|x| x.eq_ignore_ascii_case(f)) {
            to.push(f.clone());
        }
    }
}

impl Rel {
    fn holds(self, o: Ordering) -> bool {
        match self {
            Rel::Gt => o == Ordering::Greater,
            Rel::Ge => o != Ordering::Less,
            Rel::Lt => o == Ordering::Less,
            Rel::Le => o != Ordering::Greater,
            Rel::Eq => o == Ordering::Equal,
            Rel::Ne => o != Ordering::Equal,
        }
    }
}

/// Порядок по компаратору (RFC 4790 §9): `i;ascii-numeric` — по числу из ведущих цифр, строка без цифр в начале —
/// «бесконечность».
fn compare(cmp: Comparator, a: &str, b: &str) -> Ordering {
    match cmp {
        Comparator::Octet => a.as_bytes().cmp(b.as_bytes()),
        Comparator::AsciiCasemap => a
            .bytes()
            .map(|c| c.to_ascii_lowercase())
            .cmp(b.bytes().map(|c| c.to_ascii_lowercase())),
        Comparator::AsciiNumeric => match (numeric(a), numeric(b)) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Greater,
            (Some(_), None) => Ordering::Less,
            (Some(x), Some(y)) => x.len().cmp(&y.len()).then_with(|| x.cmp(y)),
        },
    }
}

/// Ведущие цифры без ведущих нулей; `None` — строка не начинается с цифры.
fn numeric(s: &str) -> Option<&str> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    Some(s.get(..end).unwrap_or_default().trim_start_matches('0'))
}

fn contains(cmp: Comparator, v: &str, k: &str) -> bool {
    match cmp {
        Comparator::Octet => v.contains(k),
        Comparator::AsciiCasemap => v.to_ascii_lowercase().contains(&k.to_ascii_lowercase()),
        Comparator::AsciiNumeric => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Glob {
    Star,
    One,
    Lit(char),
}

/// Шаблон `:matches`: `*` — любая последовательность, `?` — один символ, `\` экранирует следующий символ.
fn glob_pattern(k: &str) -> Vec<Glob> {
    let mut out = Vec::new();
    let mut it = k.chars();
    while let Some(c) = it.next() {
        let g = match c {
            '*' => Glob::Star,
            '?' => Glob::One,
            '\\' => Glob::Lit(it.next().unwrap_or('\\')),
            c => Glob::Lit(c),
        };
        if g == Glob::Star && out.last() == Some(&Glob::Star) {
            continue;
        }
        out.push(g);
    }
    out
}

/// Сопоставление с шаблоном за O(n·m) с возвратом к последней `*`; `None` — исчерпан лимит шагов.
fn glob(p: &[Glob], s: &[char], cmp: Comparator, steps: &mut u64, max: u64) -> Option<bool> {
    let eq = |a: char, b: char| match cmp {
        Comparator::Octet => a == b,
        Comparator::AsciiCasemap | Comparator::AsciiNumeric => a.eq_ignore_ascii_case(&b),
    };
    let (mut pi, mut si) = (0usize, 0usize);
    let mut star: Option<(usize, usize)> = None;
    while let Some(&c) = s.get(si) {
        *steps = steps.saturating_add(1);
        if *steps > max {
            return None;
        }
        match p.get(pi) {
            Some(Glob::Star) => {
                star = Some((pi + 1, si));
                pi += 1;
                continue;
            }
            Some(Glob::One) => {
                pi += 1;
                si += 1;
                continue;
            }
            Some(Glob::Lit(x)) if eq(*x, c) => {
                pi += 1;
                si += 1;
                continue;
            }
            _ => {}
        }
        let Some((sp, ss)) = star else {
            return Some(false);
        };
        let ss = ss + 1;
        star = Some((sp, ss));
        pi = sp;
        si = ss;
    }
    Some(
        p.get(pi..)
            .unwrap_or_default()
            .iter()
            .all(|g| *g == Glob::Star),
    )
}

// ---------- Письмо ----------

/// Накопитель значений `body` с остатком лимита.
struct Scan {
    left: usize,
    out: Vec<String>,
}

impl Scan {
    fn push(&mut self, s: &str) {
        let mut end = s.len().min(self.left);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        self.left -= end;
        self.out.push(s.get(..end).unwrap_or_default().to_owned());
    }
}

/// Начало тела: после первой пустой строки; её нет — тела нет.
fn body_offset(raw: &[u8]) -> usize {
    let mut i = 0;
    while let Some(n) = raw
        .get(i..)
        .and_then(|r| r.iter().position(|&b| b == b'\n'))
    {
        let next = i + n + 1;
        match raw.get(next..) {
            Some([b'\n', ..]) => return next + 1,
            Some([b'\r', b'\n', ..]) => return next + 2,
            _ => i = next,
        }
    }
    raw.len()
}

/// Подходит ли часть `ty/sub` под список `:content` (RFC 5173 §5.2): `""` — любая, `type` — любой подтип,
/// `type/subtype` — точно.
fn wanted(types: &[String], ty: &str, sub: &str) -> bool {
    types.iter().any(|t| match t.split_once('/') {
        None => t.is_empty() || t.eq_ignore_ascii_case(ty),
        Some((a, b)) => {
            !a.is_empty()
                && !b.is_empty()
                && a.eq_ignore_ascii_case(ty)
                && b.eq_ignore_ascii_case(sub)
        }
    })
}

/// Собирает значения частей письма и вложенных писем: `types = None` — `:text`, иначе `:content`.
fn collect(msg: MessageRef<'_>, types: Option<&[String]>, scan: &mut Scan) {
    for part in msg.parts() {
        if scan.left == 0 {
            return;
        }
        let (ty, sub) = part.content_type().map_or(("text", "plain"), |c| {
            (c.ctype(), c.subtype().unwrap_or(""))
        });
        let hit = match types {
            None => ty.eq_ignore_ascii_case("text"),
            Some(types) => wanted(types, ty, sub),
        };
        match part.kind() {
            PartKind::Text if hit => {
                if let Some(s) = part.text() {
                    scan.push(&s);
                }
            }
            PartKind::Html if hit && types.is_none() => {
                if let Some(s) = part.text() {
                    scan.push(&html_to_text(&s));
                }
            }
            PartKind::Html if hit => {
                if let Some(s) = part.text() {
                    scan.push(&s);
                }
            }
            PartKind::Binary | PartKind::InlineBinary if hit && types.is_some() => {
                scan.push(&String::from_utf8_lossy(&part.decoded()));
            }
            PartKind::Message(inner) => {
                // Вложенное письмо: по `message/rfc822` — его заголовки, части — как у внешнего.
                if hit && types.is_some() {
                    scan.push(&String::from_utf8_lossy(inner.root_part().raw_headers()));
                }
                collect(inner, types, scan);
            }
            _ => {}
        }
    }
}

/// Заголовки верхнего уровня: имя, значение после RFC 2047 и границы сырого значения.
pub(crate) fn parse_headers(raw: &[u8]) -> Vec<Hdr> {
    let Some(msg) = MessageParser::new().parse_headers(raw) else {
        return Vec::new();
    };
    // Значение каждого поля — как текст с RFC 2047 (в 0.11 это default_header_text): тестам и действиям
    // нужен исходный вид значения, поэтому структурные формы known-заголовков 1.0 переигрываются
    // (`parse_as`): `Message-ID` и `Received` — со скобками и сырым путём, адреса — как написаны.
    msg.headers()
        .iter()
        .map(|h| Hdr {
            name: h.name().as_str().to_owned(),
            value: header_text(&h.parse_as(HeaderForm::Text).value()),
            start: h.offset_start() as usize,
            end: h.offset_end() as usize,
        })
        .collect()
}

fn header_text(v: &HeaderValue<'_>) -> String {
    match v {
        HeaderValue::Text(s) => s.trim().to_owned(),
        HeaderValue::TextList(l) => l.iter().collect::<Vec<_>>().join(", "),
        _ => String::new(),
    }
}

/// Адреса из сырого значения заголовка (RFC 5322, группы раскрываются); имена и комментарии отбрасываются.
pub(crate) fn parse_addresses(raw: &[u8]) -> Vec<String> {
    let mut buf = Vec::with_capacity(raw.len() + 9);
    buf.extend_from_slice(b"From:");
    buf.extend_from_slice(raw);
    buf.extend_from_slice(b"\r\n\r\n");
    let parser = MessageParser::new().header(HeaderName::From, HeaderForm::Addresses);
    let Some(msg) = parser.parse_headers(&buf) else {
        return Vec::new();
    };
    msg.from()
        .map(|list| {
            list.mailboxes()
                .filter_map(|mailbox| mailbox.address())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(crate) fn strip_angle(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix('<')
        .and_then(|x| x.strip_suffix('>'))
        .unwrap_or(s)
}

/// Часть адреса (RFC 5228 §2.7.4, RFC 5233): локальная часть — до последней `@`, `:user`/`:detail` — по первому `+`;
/// `:detail` без `+` — нет значения.
pub(crate) fn address_part(addr: &str, part: Part) -> Option<String> {
    let (local, domain) = addr.rsplit_once('@').unwrap_or((addr, ""));
    let v = match part {
        Part::All => addr,
        Part::Local => local,
        Part::Domain => domain,
        Part::User => local.split_once('+').map_or(local, |(u, _)| u),
        Part::Detail => local.split_once('+')?.1,
    };
    Some(v.to_owned())
}
