//! Проверка скрипта и компиляция в программу (SIEVE-02): известные команды и тесты, аргументы, `require` для каждого
//! расширения (RFC 5228 §3.2), компараторы и типы сравнения. Профиль «админский» для скрипта организации
//! ([`AdminProfile`], SIEVE-14) добавляет к общей проверке запреты решения 124 д. Его же расширения SIEVE-15
//! (решение 126 д): команда `signal` (`vnd.thepost.risk`), `environment` (RFC 5183), `extlists` (RFC 6134) и
//! `:regex` (draft-ietf-sieve-regex) — только скрипту организации.

use std::collections::{BTreeMap, BTreeSet};

use tp_contracts::risk::SignalId;
use tp_contracts::sieve::ProcessCalendar;

use crate::ast::{self, Arg, Command};
use crate::run::VacationAction;
use crate::{Diagnostic, Limits, Pos};

/// Поддерживаемые расширения — их же объявляют ManageSieve (`SIEVE`) и JMAP Sieve (`sieveExtensions`).
/// `processcalendar` (RFC 9671, SIEVE-14) и `vnd.thepost.peer` (вендорское, RFC 5228 §6) — доверенная матрица:
/// тип абонента из контекста ядра, не из заголовков письма.
pub const EXTENSIONS: &[&str] = &[
    "fileinto",
    "envelope",
    "imap4flags",
    "vacation",
    "body",
    "relational",
    "subaddress",
    "copy",
    "mailbox",
    "encoded-character",
    "comparator-i;ascii-numeric",
    "processcalendar",
    "vnd.thepost.peer",
];

/// Расширения только профиля «админский» (скрипт организации, SIEVE-15, решение 126 д): `vnd.thepost.risk` —
/// команда `signal`, `environment` (RFC 5183) с пунктами `vnd.thepost.*`, `extlists` (RFC 6134) и `regex`
/// (draft-ietf-sieve-regex). В [`EXTENSIONS`] их нет: ManageSieve и JMAP Sieve пользователя их не показывают,
/// `require` в скрипте пользователя — ошибка проверки.
pub const ADMIN_EXTENSIONS: &[&str] = &["environment", "extlists", "regex", "vnd.thepost.risk"];

/// Компараторы ядра: в `require` допустимы, но не обязательны (RFC 5228 §2.7.3).
const IMPLICIT: &[&str] = &["comparator-i;octet", "comparator-i;ascii-casemap"];

/// Проверенная программа: результат [`check`] / [`compile`], вход [`crate::run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    pub(crate) commands: Vec<Cmd>,
    extensions: Vec<String>,
}

impl Program {
    /// Расширения из `require` (без компараторов ядра), по алфавиту.
    pub fn extensions(&self) -> &[String] {
        &self.extensions
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Cmd {
    If {
        branches: Vec<(Test, Vec<Cmd>)>,
        otherwise: Option<Vec<Cmd>>,
    },
    Stop,
    Keep {
        flags: Option<Vec<String>>,
    },
    Discard,
    FileInto {
        mailbox: String,
        copy: bool,
        create: bool,
        flags: Option<Vec<String>>,
    },
    Redirect {
        address: String,
        copy: bool,
    },
    Flags {
        op: FlagOp,
        flags: Vec<String>,
    },
    Vacation(VacationAction),
    /// `processcalendar` (RFC 9671 §3, SIEVE-14): параметры вносят приглашение применяющий (приём iTIP у
    /// вызывающего); интерпретатор лишь записывает их в [`crate::run::Action::ProcessCalendar`].
    ProcessCalendar(ProcessCalendar),
    /// `signal "<id>" [:weight N]` расширения `vnd.thepost.risk` (SIEVE-15, решение 126 д): признак в итог
    /// правил ([`crate::run::Outcome::signals`]). Вес — каталога признака (`None`) или заданный; скрипт
    /// может только повысить риск.
    Signal {
        /// Идентификатор признака каталога или `org.<имя>`.
        id: SignalId,
        /// `:weight N`; `None` — действующий вес признака каталога (для `org.*` — 1).
        weight: Option<u16>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FlagOp {
    Set,
    Add,
    Remove,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Test {
    True,
    False,
    Not(Box<Test>),
    AllOf(Vec<Test>),
    AnyOf(Vec<Test>),
    Exists(Vec<String>),
    Size {
        over: bool,
        limit: u64,
    },
    Header {
        m: Match,
        names: Vec<String>,
        keys: Vec<String>,
        /// `:list` (RFC 6134, SIEVE-15): `keys` — имена внешних списков (URI `tag:`), совпадение — поиск в них.
        list: bool,
    },
    Address {
        m: Match,
        part: Part,
        names: Vec<String>,
        keys: Vec<String>,
        /// `:list` — как у [`Test::Header`].
        list: bool,
    },
    Envelope {
        m: Match,
        part: Part,
        names: Vec<String>,
        keys: Vec<String>,
        /// `:list` — как у [`Test::Header`].
        list: bool,
    },
    Body {
        m: Match,
        transform: Transform,
        keys: Vec<String>,
    },
    HasFlag {
        m: Match,
        keys: Vec<String>,
    },
    MailboxExists(Vec<String>),
    /// `peer` расширения `vnd.thepost.peer` (RFC 5228 §6, SIEVE-14): тип абонента из контекста ядра
    /// ([`crate::run::Context::peer`], CTR-93), не из заголовков письма.
    Peer {
        m: Match,
        keys: Vec<String>,
    },
    /// `environment` (RFC 5183, SIEVE-15): пункт [`EnvName`] — из контекста ядра
    /// ([`crate::run::Context::environment`], CTR-95), не из заголовков письма.
    Environment {
        m: Match,
        name: EnvName,
        keys: Vec<String>,
    },
    /// `valid_ext_list` (RFC 6134 §4, SIEVE-15): все имена списков существуют.
    ValidExtList(Vec<String>),
}

/// Пункт теста `environment` (RFC 5183 §4): ядро — `domain`, `host`, `phase`; наши `vnd.thepost.*`
/// (SIEVE-15, решение 126 д) — факты, которые считает Rust до Sieve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvName {
    /// `domain` — домен получателя.
    Domain,
    /// `host` — имя узла.
    Host,
    /// `phase` — этап выполнения (`before` у скрипта организации, `during` у скрипта пользователя).
    Phase,
    /// `vnd.thepost.thread` — `trusted`|`untrusted`|`none`.
    Thread,
    /// `vnd.thepost.reply` — `yes`|`no`.
    Reply,
    /// `vnd.thepost.risk.score` — балл справочника до Sieve.
    RiskScore,
    /// `vnd.thepost.risk.signals` — сработавшие признаки через запятую.
    RiskSignals,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Match {
    pub cmp: Comparator,
    pub kind: MatchKind,
    /// Скомпилированные шаблоны `:regex` (порядок ключей); пусто у остальных типов сравнения.
    pub regex: Vec<CompiledRegex>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MatchKind {
    Is,
    Contains,
    Matches,
    Value(Rel),
    Count(Rel),
    /// `:regex` (draft-ietf-sieve-regex, SIEVE-15): только профиль «админский», шаблоны компилируются при
    /// проверке скрипта.
    Regex,
}

/// Скомпилированный шаблон `:regex` (draft-ietf-sieve-regex): равенство программ — по исходному шаблону.
#[derive(Debug, Clone)]
pub(crate) struct CompiledRegex {
    /// Исходный шаблон (для сравнения и отладки).
    pub pattern: String,
    /// Скомпилированное выражение; `None` — не скомпилировался при проверке (ошибка уже записана).
    pub re: Option<regex::Regex>,
}

impl PartialEq for CompiledRegex {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for CompiledRegex {}

/// Оператор `relational` (RFC 5231).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rel {
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Ne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Comparator {
    Octet,
    AsciiCasemap,
    AsciiNumeric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Part {
    All,
    Local,
    Domain,
    User,
    Detail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Transform {
    Raw,
    Text,
    Content(Vec<String>),
}

/// Проверка с лимитами по умолчанию — устаревший путь: проверять [`compile`] с [`Limits`] секции `sieve`.
/// Остаётся, пока её вызывают JMAP (`tp-jmap`, JMAP-35) и CLI (`thepost`, ADM-35); затем удаляется (SIEVE-13).
pub fn check(text: &str) -> Result<Program, Vec<Diagnostic>> {
    compile(text.as_bytes(), &Limits::default())
}

/// Профиль проверки «админский» — скрипт организации (этап before, доверенный; SIEVE-14, решение 124 д):
/// админский Sieve сужает внутри потолка, расширить права не может. `vacation` запрещён; `redirect` — на
/// внутренний адрес или на домен, куда открыта автопересылка (адреса литеральные: расширения `variables` нет);
/// прочее — как у пользователя. Проверку при сохранении вызывает Admin API (ADM-49), ошибка — [`Diagnostic`] со
/// строкой и столбцом.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AdminProfile {
    /// Внутренние домены (принятые домены организаций установки, нижний регистр): пересылка на них — внутренняя.
    pub internal_domains: Vec<String>,
    /// Домены, куда открыта автопересылка (`TrustPolicy::auto_forward_domains`, нижний регистр): `redirect`
    /// наружу — только на них.
    pub forward_domains: Vec<String>,
}

/// Разбор и проверка: все найденные ошибки с позициями (ошибка разбора — одна). Профиль пользователя:
/// расширения [`ADMIN_EXTENSIONS`] (в том числе `vnd.thepost.risk`) недоступны — `require` — ошибка.
pub fn compile(src: &[u8], limits: &Limits) -> Result<Program, Vec<Diagnostic>> {
    compile_with(src, limits, None, false)
}

/// Проверка скрипта организации при доставке (SIEVE-15): как [`compile`], но расширения [`ADMIN_EXTENSIONS`]
/// (`signal`, `environment`, `extlists`, `:regex`) допустимы; запреты профиля (домены `redirect`, `vacation`)
/// не применяются — их проверяет [`compile_admin`] при сохранении (ADM-49), а доставка доверяет сохранённому
/// тексту. Пользовательский скрипт так не компилируется.
pub fn compile_trusted(src: &[u8], limits: &Limits) -> Result<Program, Vec<Diagnostic>> {
    compile_with(src, limits, None, true)
}

/// Проверка профилем «админский» (скрипт организации, SIEVE-14): к проверке [`compile`] добавляются запреты
/// [`AdminProfile`] и допускаются расширения [`ADMIN_EXTENSIONS`].
pub fn compile_admin(
    src: &[u8],
    limits: &Limits,
    profile: &AdminProfile,
) -> Result<Program, Vec<Diagnostic>> {
    compile_with(src, limits, Some(profile), false)
}

fn compile_with(
    src: &[u8],
    limits: &Limits,
    admin: Option<&AdminProfile>,
    trusted: bool,
) -> Result<Program, Vec<Diagnostic>> {
    let script = ast::parse(src, limits).map_err(|d| vec![d])?;
    let mut c = Compiler {
        admin,
        trusted: admin.is_some() || trusted,
        limits: *limits,
        ..Compiler::default()
    };
    let commands = c.block(&script.commands, true);
    if c.diags.is_empty() {
        Ok(Program {
            commands,
            extensions: c.exts.into_iter().collect(),
        })
    } else {
        Err(c.diags)
    }
}

// ---------- Аргументы ----------

/// Вид значения тега или позиционного аргумента.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Flag,
    Num,
    Str,
    List,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Flag => "ничего",
            Kind::Num => "число",
            Kind::Str => "строка",
            Kind::List => "список строк",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Val<'a> {
    Flag,
    Num(u64),
    Str(&'a str),
    List(&'a [String]),
}

#[derive(Debug, Default)]
struct Parsed<'a> {
    tags: Vec<(&'a str, Pos, Val<'a>)>,
    pos: Vec<(Val<'a>, Pos)>,
}

impl<'a> Parsed<'a> {
    fn get(&self, tag: &str) -> Option<(Val<'a>, Pos)> {
        self.tags
            .iter()
            .find(|(t, _, _)| *t == tag)
            .map(|(_, p, v)| (*v, *p))
    }

    fn has(&self, tag: &str) -> bool {
        self.get(tag).is_some()
    }

    fn num(&self, tag: &str) -> Option<u64> {
        match self.get(tag) {
            Some((Val::Num(n), _)) => Some(n),
            _ => None,
        }
    }
}

fn value(a: &Arg, kind: Kind) -> Option<Val<'_>> {
    match (a, kind) {
        (Arg::Number { value, .. }, Kind::Num) => Some(Val::Num(*value)),
        (
            Arg::Strings {
                values,
                list: false,
                ..
            },
            Kind::Str,
        ) => values.first().map(|s| Val::Str(s.as_str())),
        (Arg::Strings { values, .. }, Kind::List) => Some(Val::List(values.as_slice())),
        _ => None,
    }
}

const MATCH_TAGS: &[(&str, Kind)] = &[
    ("comparator", Kind::Str),
    ("is", Kind::Flag),
    ("contains", Kind::Flag),
    ("matches", Kind::Flag),
    ("value", Kind::Str),
    ("count", Kind::Str),
    ("regex", Kind::Flag),
];

const PART_TAGS: &[(&str, Kind)] = &[
    ("all", Kind::Flag),
    ("localpart", Kind::Flag),
    ("domain", Kind::Flag),
    ("user", Kind::Flag),
    ("detail", Kind::Flag),
];

const BODY_TAGS: &[(&str, Kind)] = &[
    ("raw", Kind::Flag),
    ("content", Kind::List),
    ("text", Kind::Flag),
];

// ---------- Компилятор ----------

#[derive(Debug, Default)]
struct Compiler<'a> {
    exts: BTreeSet<String>,
    diags: Vec<Diagnostic>,
    encoded: bool,
    /// Профиль «админский» (скрипт организации, SIEVE-14): запреты решения 124 д.
    admin: Option<&'a AdminProfile>,
    /// Скрипт организации (сохранение профилем «админский» или доставка): допустимы [`ADMIN_EXTENSIONS`].
    trusted: bool,
    /// Лимиты секции `sieve` (предел `signal`, лимиты `:regex`).
    limits: Limits,
    /// Признаки команды `signal`: идентификатор → вес (повтор с другим весом — ошибка проверки).
    signals: BTreeMap<String, Option<u16>>,
}

impl Compiler<'_> {
    /// Скрипту организации доступны расширения [`ADMIN_EXTENSIONS`].
    fn is_trusted(&self) -> bool {
        self.admin.is_some() || self.trusted
    }

    fn err(&mut self, pos: Pos, message: impl Into<String>) {
        self.diags.push(Diagnostic::new(pos, message));
    }

    fn need(&mut self, ext: &str, pos: Pos) {
        if !self.exts.contains(ext) {
            self.err(pos, format!("расширение {ext:?} не объявлено в require"));
        }
    }

    /// Раскладывает аргументы: теги из `tags` (с значениями), затем позиционные ровно вида `positional`.
    fn args<'a>(
        &mut self,
        what: &str,
        at: Pos,
        args: &'a [Arg],
        tags: &[(&str, Kind)],
        positional: &[Kind],
    ) -> Option<Parsed<'a>> {
        let mut out = Parsed::default();
        let mut ok = true;
        let mut raw = Vec::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            let Arg::Tag { name, pos } = a else {
                raw.push(a);
                continue;
            };
            let Some(&(_, kind)) = tags.iter().find(|(t, _)| *t == name.as_str()) else {
                self.err(*pos, format!("{what}: неизвестный тег :{name}"));
                ok = false;
                continue;
            };
            if out.has(name) {
                self.err(*pos, format!("{what}: тег :{name} указан дважды"));
                ok = false;
            }
            let val = if kind == Kind::Flag {
                Val::Flag
            } else if let Some(v) = it.next().and_then(|v| value(v, kind)) {
                v
            } else {
                self.err(
                    *pos,
                    format!("{what}: после :{name} ожидается {}", kind.name()),
                );
                ok = false;
                continue;
            };
            out.tags.push((name.as_str(), *pos, val));
        }
        if raw.len() != positional.len() {
            let pos = raw.get(positional.len()).map_or(at, |a| a.pos());
            self.err(
                pos,
                format!(
                    "{what}: ожидается позиционных аргументов: {}, указано: {}",
                    positional.len(),
                    raw.len()
                ),
            );
            return None;
        }
        for (a, kind) in raw.into_iter().zip(positional) {
            match value(a, *kind) {
                Some(v) => out.pos.push((v, a.pos())),
                None => {
                    self.err(a.pos(), format!("{what}: ожидается {}", kind.name()));
                    ok = false;
                }
            }
        }
        ok.then_some(out)
    }

    fn decode(&mut self, s: &str, pos: Pos) -> String {
        if !self.encoded || !s.contains("${") {
            return s.to_owned();
        }
        match decode_encoded(s) {
            Ok(v) => v,
            Err(e) => {
                self.err(pos, e);
                s.to_owned()
            }
        }
    }

    fn string(&mut self, (v, pos): (Val<'_>, Pos)) -> String {
        match v {
            Val::Str(s) => self.decode(s, pos),
            Val::List(l) => l.first().map(|s| self.decode(s, pos)).unwrap_or_default(),
            Val::Flag | Val::Num(_) => String::new(),
        }
    }

    fn list(&mut self, (v, pos): (Val<'_>, Pos)) -> Vec<String> {
        match v {
            Val::List(l) => l.iter().map(|s| self.decode(s, pos)).collect(),
            Val::Str(s) => vec![self.decode(s, pos)],
            Val::Flag | Val::Num(_) => Vec::new(),
        }
    }

    /// Имена заголовков: field-name RFC 5322 (печатные ASCII без двоеточия).
    fn header_names(&mut self, v: (Val<'_>, Pos)) -> Vec<String> {
        let pos = v.1;
        let names = self.list(v);
        for n in &names {
            if n.is_empty() || !n.bytes().all(|b| (33..=126).contains(&b) && b != b':') {
                self.err(pos, format!("недопустимое имя заголовка {n:?}"));
            }
        }
        names
    }

    /// Флаги IMAP: строки списка делятся по пробелам (RFC 5232 §3).
    fn flags(&mut self, v: (Val<'_>, Pos)) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for s in self.list(v) {
            for f in s.split_ascii_whitespace() {
                if !out.iter().any(|x| x.eq_ignore_ascii_case(f)) {
                    out.push(f.to_owned());
                }
            }
        }
        out
    }

    /// Тип сравнения и компаратор по тегам; второе значение — тип сравнения задан явно (для запрета вместе
    /// с `:list`). Шаблоны `:regex` компилируются здесь (draft-ietf-sieve-regex, SIEVE-15): лимиты секции
    /// `sieve.regex`, превышение — ошибка проверки, а не выполнения; регистр — по компаратору
    /// (`i;ascii-casemap` — без учёта регистра, `i;octet` — с учётом).
    fn matcher(&mut self, p: &Parsed<'_>, keys: &[String], key_pos: Pos) -> (Match, bool) {
        let mut kind = None;
        for &(tag, pos, val) in &p.tags {
            let k = match tag {
                "is" => MatchKind::Is,
                "contains" => MatchKind::Contains,
                "matches" => MatchKind::Matches,
                "regex" => {
                    self.need("regex", pos);
                    MatchKind::Regex
                }
                "value" | "count" => {
                    self.need("relational", pos);
                    let rel = match val {
                        Val::Str(s) => rel_of(s),
                        _ => None,
                    };
                    let Some(rel) = rel else {
                        self.err(
                            pos,
                            "оператор сравнения — один из \"gt\", \"ge\", \"lt\", \"le\", \"eq\", \"ne\"",
                        );
                        continue;
                    };
                    if tag == "value" {
                        MatchKind::Value(rel)
                    } else {
                        MatchKind::Count(rel)
                    }
                }
                _ => continue,
            };
            if kind.replace(k).is_some() {
                self.err(pos, "указано несколько типов сравнения");
            }
        }
        let explicit = kind.is_some();
        let kind = kind.unwrap_or(MatchKind::Is);
        let cmp = match p.get("comparator") {
            None => Comparator::AsciiCasemap,
            Some(v) => {
                let pos = v.1;
                let name = self.string(v);
                let cmp = match name.as_str() {
                    "i;octet" => Comparator::Octet,
                    "i;ascii-casemap" => Comparator::AsciiCasemap,
                    "i;ascii-numeric" => {
                        self.need("comparator-i;ascii-numeric", pos);
                        Comparator::AsciiNumeric
                    }
                    other => {
                        self.err(pos, format!("неизвестный компаратор {other:?}"));
                        Comparator::AsciiCasemap
                    }
                };
                if cmp == Comparator::AsciiNumeric
                    && matches!(
                        kind,
                        MatchKind::Contains | MatchKind::Matches | MatchKind::Regex
                    )
                {
                    self.err(
                        pos,
                        "компаратор \"i;ascii-numeric\" не поддерживает :contains, :matches и :regex",
                    );
                }
                cmp
            }
        };
        let regex = if kind == MatchKind::Regex {
            self.regexes(keys, key_pos, cmp)
        } else {
            Vec::new()
        };
        (Match { cmp, kind, regex }, explicit)
    }

    /// Компилирует шаблоны `:regex` при проверке (`regex::RegexBuilder` с `size_limit` и `dfa_size_limit`
    /// из `sieve.regex`): поиск крейта `regex` за линейное время — без ReDoS (решение 126 д).
    fn regexes(&mut self, keys: &[String], key_pos: Pos, cmp: Comparator) -> Vec<CompiledRegex> {
        keys.iter()
            .map(|k| {
                let built = regex::RegexBuilder::new(k)
                    .size_limit(self.limits.regex_size_limit)
                    .dfa_size_limit(self.limits.regex_dfa_size_limit)
                    .case_insensitive(cmp == Comparator::AsciiCasemap)
                    .build();
                match built {
                    Ok(re) => CompiledRegex {
                        pattern: k.clone(),
                        re: Some(re),
                    },
                    Err(e) => {
                        self.err(
                            key_pos,
                            format!("regex: шаблон {k:?} не компилируется: {e}"),
                        );
                        CompiledRegex {
                            pattern: k.clone(),
                            re: None,
                        }
                    }
                }
            })
            .collect()
    }

    /// `:list` у `header`/`address`/`envelope` (RFC 6134, SIEVE-15): требует `extlists`, совместим только с
    /// `:comparator` (не тип сравнения), ключи — имена списков (URI `tag:`).
    fn list_tag(
        &mut self,
        p: &Parsed<'_>,
        keys: &[String],
        key_pos: Pos,
        explicit_match: bool,
    ) -> bool {
        let Some((_, pos)) = p.get("list") else {
            return false;
        };
        self.need("extlists", pos);
        if explicit_match {
            self.err(
                pos,
                ":list — это тип сравнения, другой тип не задаётся вместе с ним",
            );
        }
        for k in keys {
            if !valid_list_uri(k) {
                self.err(
                    key_pos,
                    format!("имя списка {k:?} — не URI \"tag:\" (RFC 6134, RFC 4151)"),
                );
            }
        }
        true
    }

    fn part(&mut self, p: &Parsed<'_>) -> Part {
        let mut part = None;
        for &(tag, pos, _) in &p.tags {
            let x = match tag {
                "all" => Part::All,
                "localpart" => Part::Local,
                "domain" => Part::Domain,
                "user" | "detail" => {
                    self.need("subaddress", pos);
                    if tag == "user" {
                        Part::User
                    } else {
                        Part::Detail
                    }
                }
                _ => continue,
            };
            if part.replace(x).is_some() {
                self.err(pos, "указано несколько частей адреса");
            }
        }
        part.unwrap_or(Part::All)
    }

    // ---------- Команды ----------

    fn block(&mut self, cmds: &[Command], top: bool) -> Vec<Cmd> {
        let mut out: Vec<Cmd> = Vec::new();
        let mut require_allowed = top;
        let mut open_if = false;
        for c in cmds {
            if c.name == "require" {
                if !require_allowed {
                    self.err(c.pos, "require допустим только в начале скрипта");
                }
                self.require(c);
                continue;
            }
            require_allowed = false;
            match c.name.as_str() {
                "if" => {
                    let test = self.condition(c);
                    let body = self.body(c);
                    out.push(Cmd::If {
                        branches: vec![(test, body)],
                        otherwise: None,
                    });
                    open_if = true;
                }
                "elsif" => {
                    let test = self.condition(c);
                    let body = self.body(c);
                    match out.last_mut() {
                        Some(Cmd::If { branches, .. }) if open_if => branches.push((test, body)),
                        _ => self.err(c.pos, "elsif без предшествующего if"),
                    }
                }
                "else" => {
                    self.bare(c);
                    let body = self.body(c);
                    match out.last_mut() {
                        Some(Cmd::If { otherwise, .. }) if open_if => *otherwise = Some(body),
                        _ => self.err(c.pos, "else без предшествующего if"),
                    }
                    open_if = false;
                }
                _ => {
                    open_if = false;
                    if c.block.is_some() {
                        self.err(c.pos, format!("у команды {} не может быть блока", c.name));
                    }
                    if let Some(t) = c.tests.first() {
                        self.err(t.pos, format!("у команды {} не может быть теста", c.name));
                    }
                    if let Some(cmd) = self.simple(c) {
                        out.push(cmd);
                    }
                }
            }
        }
        out
    }

    fn require(&mut self, c: &Command) {
        if c.block.is_some() || !c.tests.is_empty() {
            self.err(c.pos, "require: ожидается список расширений и «;»");
        }
        let Some(p) = self.args("require", c.pos, &c.args, &[], &[Kind::List]) else {
            return;
        };
        let Some(&(Val::List(list), pos)) = p.pos.first() else {
            return;
        };
        for e in list {
            let e = e.to_ascii_lowercase();
            if EXTENSIONS.contains(&e.as_str()) {
                if e == "encoded-character" {
                    self.encoded = true;
                }
                self.exts.insert(e);
            } else if ADMIN_EXTENSIONS.contains(&e.as_str()) {
                // SIEVE-15 (решение 126 д): расширения справочника аномалий — только скрипту организации.
                if self.is_trusted() {
                    self.exts.insert(e);
                } else {
                    self.err(
                        pos,
                        format!(
                            "расширение {e:?} доступно только скрипту организации (админский профиль)"
                        ),
                    );
                }
            } else if !IMPLICIT.contains(&e.as_str()) {
                self.err(pos, format!("расширение {e:?} не поддерживается"));
            }
        }
    }

    /// Тест `if`/`elsif`: ровно один, не списком; других аргументов нет.
    fn condition(&mut self, c: &Command) -> Test {
        if let Some(a) = c.args.first() {
            self.err(a.pos(), format!("{}: ожидается тест", c.name));
        }
        match (c.tests.as_slice(), c.test_list) {
            ([t], false) => self.test(t),
            _ => {
                self.err(c.pos, format!("{} ожидает один тест", c.name));
                Test::False
            }
        }
    }

    fn bare(&mut self, c: &Command) {
        if let Some(a) = c.args.first() {
            self.err(a.pos(), format!("у {} нет аргументов", c.name));
        } else if let Some(t) = c.tests.first() {
            self.err(t.pos, format!("у {} нет теста", c.name));
        }
    }

    fn body(&mut self, c: &Command) -> Vec<Cmd> {
        match &c.block {
            Some(b) => self.block(b, false),
            None => {
                self.err(c.pos, format!("{} ожидает блок {{…}}", c.name));
                Vec::new()
            }
        }
    }

    fn simple(&mut self, c: &Command) -> Option<Cmd> {
        let name = c.name.as_str();
        match name {
            "stop" | "discard" => {
                self.args(name, c.pos, &c.args, &[], &[])?;
                Some(if name == "stop" {
                    Cmd::Stop
                } else {
                    Cmd::Discard
                })
            }
            "keep" => {
                let p = self.args(name, c.pos, &c.args, &[("flags", Kind::List)], &[])?;
                let flags = self.flags_tag(&p);
                Some(Cmd::Keep { flags })
            }
            "fileinto" => {
                self.need("fileinto", c.pos);
                let p = self.args(
                    name,
                    c.pos,
                    &c.args,
                    &[
                        ("copy", Kind::Flag),
                        ("create", Kind::Flag),
                        ("flags", Kind::List),
                    ],
                    &[Kind::Str],
                )?;
                let copy = self.copy_tag(&p);
                let create = match p.get("create") {
                    Some((_, pos)) => {
                        self.need("mailbox", pos);
                        true
                    }
                    None => false,
                };
                let flags = self.flags_tag(&p);
                let mailbox = self.string(p.pos[0]);
                if mailbox.is_empty() {
                    self.err(p.pos[0].1, "fileinto: пустое имя папки");
                }
                Some(Cmd::FileInto {
                    mailbox,
                    copy,
                    create,
                    flags,
                })
            }
            "redirect" => {
                let p = self.args(name, c.pos, &c.args, &[("copy", Kind::Flag)], &[Kind::Str])?;
                let copy = self.copy_tag(&p);
                let address = self.string(p.pos[0]);
                if !valid_address(&address) {
                    self.err(
                        p.pos[0].1,
                        format!("redirect: некорректный адрес {address:?}"),
                    );
                }
                self.admin_redirect(&address, p.pos[0].1);
                Some(Cmd::Redirect { address, copy })
            }
            "setflag" | "addflag" | "removeflag" => {
                self.need("imap4flags", c.pos);
                let p = self.args(name, c.pos, &c.args, &[], &[Kind::List])?;
                let flags = self.flags(p.pos[0]);
                let op = match name {
                    "setflag" => FlagOp::Set,
                    "addflag" => FlagOp::Add,
                    _ => FlagOp::Remove,
                };
                Some(Cmd::Flags { op, flags })
            }
            "vacation" => {
                self.need("vacation", c.pos);
                let p = self.args(
                    name,
                    c.pos,
                    &c.args,
                    &[
                        ("days", Kind::Num),
                        ("subject", Kind::Str),
                        ("from", Kind::Str),
                        ("addresses", Kind::List),
                        ("mime", Kind::Flag),
                        ("handle", Kind::Str),
                    ],
                    &[Kind::Str],
                )?;
                let subject = p.get("subject").map(|v| self.string(v));
                let from = p.get("from").map(|v| self.string(v));
                let handle = p.get("handle").map(|v| self.string(v));
                let addresses = p.get("addresses").map(|v| self.list(v)).unwrap_or_default();
                let reason = self.string(p.pos[0]);
                if self.admin.is_some() {
                    self.err(
                        c.pos,
                        "vacation в скрипте организации запрещён (решение 124 д): автоответ — настройка учётной записи",
                    );
                }
                Some(Cmd::Vacation(VacationAction {
                    days: p.num("days"),
                    subject,
                    from,
                    addresses,
                    mime: p.has("mime"),
                    handle,
                    reason,
                }))
            }
            "processcalendar" => {
                self.need("processcalendar", c.pos);
                let p = self.args(
                    name,
                    c.pos,
                    &c.args,
                    &[
                        ("allowpublic", Kind::Flag),
                        ("addresses", Kind::List),
                        ("updatesonly", Kind::Flag),
                        ("calendarid", Kind::Str),
                        ("deletecancelled", Kind::Flag),
                        ("organizers", Kind::Str),
                        ("outcome", Kind::Str),
                        ("reason", Kind::Str),
                    ],
                    &[],
                )?;
                if let Some((val, pos)) = p.get("organizers") {
                    // `:organizers` (RFC 9671 §3) — имя внешнего списка организаторов (RFC 6134): с extlists
                    // (SIEVE-15 снимает запрет SIEVE-14) допустимо в скрипте организации. Имя проверяется
                    // (URI tag:); фильтрацию по списку применяет приём iTIP вызывающего — поле действия
                    // `ProcessCalendar` контракта получит его волной контрактов, пока значение проверено.
                    self.need("extlists", pos);
                    let uri = self.string((val, pos));
                    if !valid_list_uri(&uri) {
                        self.err(
                            pos,
                            format!("имя списка {uri:?} — не URI \"tag:\" (RFC 6134, RFC 4151)"),
                        );
                    }
                }
                let updates_only = p.has("updatesonly");
                if updates_only && let Some((_, pos)) = p.get("calendarid") {
                    self.err(
                        pos,
                        "processcalendar: :updatesonly и :calendarid вместе не задаются (RFC 9671 §3)",
                    );
                }
                // :outcome и :reason (RFC 9671 §3) принимаются: расширения variables нет, итог действия и его
                // причина — в журнале доставки (RulesOutcome), не в переменных скрипта.
                let addresses = p.get("addresses").map(|v| self.list(v)).unwrap_or_default();
                let calendar_id = p.get("calendarid").map(|v| self.string(v));
                Some(Cmd::ProcessCalendar(ProcessCalendar {
                    allow_public: p.has("allowpublic"),
                    addresses,
                    updates_only,
                    calendar_id,
                    delete_cancelled: p.has("deletecancelled"),
                }))
            }
            "signal" => {
                // SIEVE-15 (решение 126 д): только скрипт организации — скрипт может только повысить риск,
                // вычесть балл, снять признак или изменить порог команда не может.
                if !self.is_trusted() {
                    self.err(
                        c.pos,
                        "команда signal доступна только скрипту организации \
                         (расширение vnd.thepost.risk)",
                    );
                }
                self.need("vnd.thepost.risk", c.pos);
                let p = self.args(name, c.pos, &c.args, &[("weight", Kind::Num)], &[Kind::Str])?;
                let id = self.string(p.pos[0]);
                let weight = match p.get("weight") {
                    Some((Val::Num(n), pos)) => {
                        let max = u64::from(self.limits.max_signal_weight);
                        if n > max {
                            self.err(
                                pos,
                                format!(
                                    "signal: вес {n} больше предела sieve.risk.max_weight ({max})"
                                ),
                            );
                        }
                        Some(u16::try_from(n).unwrap_or(self.limits.max_signal_weight))
                    }
                    _ => None,
                };
                match SignalId::new(&id) {
                    Ok(id) => {
                        if self
                            .signals
                            .get(id.as_str())
                            .is_some_and(|prev| *prev != weight)
                        {
                            self.err(
                                p.pos[0].1,
                                format!("signal: признак {id} указан с разными весами"),
                            );
                        } else {
                            self.signals.insert(id.as_str().to_owned(), weight);
                        }
                        Some(Cmd::Signal { id, weight })
                    }
                    Err(_) => {
                        self.err(
                            p.pos[0].1,
                            format!(
                                "signal: идентификатор признака {id:?} — [a-z0-9._-], до 64 символов"
                            ),
                        );
                        None
                    }
                }
            }
            _ => {
                self.err(c.pos, format!("неизвестная команда {name}"));
                None
            }
        }
    }

    fn copy_tag(&mut self, p: &Parsed<'_>) -> bool {
        match p.get("copy") {
            Some((_, pos)) => {
                self.need("copy", pos);
                true
            }
            None => false,
        }
    }

    /// Профиль «админский» (SIEVE-14): `redirect` скрипта организации — только на внутренний адрес (домен из
    /// `AdminProfile::internal_domains`) или на домен с открытой автопересылкой (`forward_domains`); адреса
    /// литеральные, расширения `variables` нет.
    fn admin_redirect(&mut self, address: &str, pos: Pos) {
        let Some(profile) = self.admin else {
            return;
        };
        let domain = address
            .rsplit('@')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let allowed = profile
            .internal_domains
            .iter()
            .chain(&profile.forward_domains)
            .any(|d| d.eq_ignore_ascii_case(&domain));
        if !allowed {
            self.err(
                pos,
                format!(
                    "redirect в скрипте организации — только на внутренний адрес или домен с открытой \
                     автопересылкой: {address:?}"
                ),
            );
        }
    }

    fn flags_tag(&mut self, p: &Parsed<'_>) -> Option<Vec<String>> {
        let v = p.get("flags")?;
        self.need("imap4flags", v.1);
        Some(self.flags(v))
    }

    // ---------- Тесты ----------

    fn test(&mut self, t: &ast::Test) -> Test {
        let name = t.name.as_str();
        match name {
            "true" | "false" | "not" | "allof" | "anyof" => {
                if let Some(a) = t.args.first() {
                    self.err(a.pos(), format!("у теста {name} нет аргументов"));
                }
            }
            _ => {
                if let Some(x) = t.tests.first() {
                    self.err(
                        x.pos,
                        format!("у теста {name} не может быть вложенного теста"),
                    );
                }
            }
        }
        match name {
            "true" | "false" => {
                if let Some(x) = t.tests.first() {
                    self.err(
                        x.pos,
                        format!("у теста {name} не может быть вложенного теста"),
                    );
                }
                if name == "true" {
                    Test::True
                } else {
                    Test::False
                }
            }
            "not" => match (t.tests.as_slice(), t.test_list) {
                ([x], false) => Test::Not(Box::new(self.test(x))),
                _ => {
                    self.err(t.pos, "not ожидает один тест");
                    Test::False
                }
            },
            "allof" | "anyof" => {
                if !t.test_list || t.tests.is_empty() {
                    self.err(t.pos, format!("{name} ожидает список тестов в скобках"));
                }
                let tests = t.tests.iter().map(|x| self.test(x)).collect();
                if name == "allof" {
                    Test::AllOf(tests)
                } else {
                    Test::AnyOf(tests)
                }
            }
            "exists" => {
                let Some(p) = self.args(name, t.pos, &t.args, &[], &[Kind::List]) else {
                    return Test::False;
                };
                Test::Exists(self.header_names(p.pos[0]))
            }
            "size" => {
                let Some(p) = self.args(
                    name,
                    t.pos,
                    &t.args,
                    &[("over", Kind::Flag), ("under", Kind::Flag)],
                    &[Kind::Num],
                ) else {
                    return Test::False;
                };
                let over = p.has("over");
                if over == p.has("under") {
                    self.err(t.pos, "size: нужен ровно один из :over и :under");
                }
                let limit = match p.pos[0].0 {
                    Val::Num(n) => n,
                    _ => 0,
                };
                Test::Size { over, limit }
            }
            "header" => {
                let tags: Vec<(&str, Kind)> = MATCH_TAGS
                    .iter()
                    .copied()
                    .chain([("list", Kind::Flag)])
                    .collect();
                let Some(p) = self.args(name, t.pos, &t.args, &tags, &[Kind::List, Kind::List])
                else {
                    return Test::False;
                };
                let names = self.header_names(p.pos[0]);
                let keys = self.list(p.pos[1]);
                let (m, explicit) = self.matcher(&p, &keys, p.pos[1].1);
                let list = self.list_tag(&p, &keys, p.pos[1].1, explicit);
                Test::Header {
                    m,
                    names,
                    keys,
                    list,
                }
            }
            "address" | "envelope" => {
                if name == "envelope" {
                    self.need("envelope", t.pos);
                }
                let tags: Vec<(&str, Kind)> = MATCH_TAGS
                    .iter()
                    .chain(PART_TAGS)
                    .copied()
                    .chain([("list", Kind::Flag)])
                    .collect();
                let Some(p) = self.args(name, t.pos, &t.args, &tags, &[Kind::List, Kind::List])
                else {
                    return Test::False;
                };
                let part = self.part(&p);
                let keys = self.list(p.pos[1]);
                let (m, explicit) = self.matcher(&p, &keys, p.pos[1].1);
                let list = self.list_tag(&p, &keys, p.pos[1].1, explicit);
                if name == "address" {
                    let names = self.header_names(p.pos[0]);
                    Test::Address {
                        m,
                        part,
                        names,
                        keys,
                        list,
                    }
                } else {
                    let pos = p.pos[0].1;
                    let names: Vec<String> = self
                        .list(p.pos[0])
                        .into_iter()
                        .map(|n| n.to_ascii_lowercase())
                        .collect();
                    for n in &names {
                        if n != "from" && n != "to" {
                            self.err(pos, format!("envelope: неизвестная часть конверта {n:?}"));
                        }
                    }
                    Test::Envelope {
                        m,
                        part,
                        names,
                        keys,
                        list,
                    }
                }
            }
            "body" => {
                self.need("body", t.pos);
                let tags: Vec<(&str, Kind)> = MATCH_TAGS.iter().chain(BODY_TAGS).copied().collect();
                let Some(p) = self.args(name, t.pos, &t.args, &tags, &[Kind::List]) else {
                    return Test::False;
                };
                let keys = self.list(p.pos[0]);
                let (m, _) = self.matcher(&p, &keys, p.pos[0].1);
                let mut transform = None;
                for &(tag, pos, val) in &p.tags {
                    let x = match tag {
                        "raw" => Transform::Raw,
                        "text" => Transform::Text,
                        "content" => Transform::Content(self.list((val, pos))),
                        _ => continue,
                    };
                    if transform.replace(x).is_some() {
                        self.err(pos, "body: указано несколько преобразований");
                    }
                }
                Test::Body {
                    m,
                    transform: transform.unwrap_or(Transform::Text),
                    keys,
                }
            }
            "hasflag" => {
                self.need("imap4flags", t.pos);
                let Some(p) = self.args(name, t.pos, &t.args, MATCH_TAGS, &[Kind::List]) else {
                    return Test::False;
                };
                let keys = self.flags(p.pos[0]);
                let (m, _) = self.matcher(&p, &keys, p.pos[0].1);
                Test::HasFlag { m, keys }
            }
            "mailboxexists" => {
                self.need("mailbox", t.pos);
                let Some(p) = self.args(name, t.pos, &t.args, &[], &[Kind::List]) else {
                    return Test::False;
                };
                Test::MailboxExists(self.list(p.pos[0]))
            }
            "peer" => {
                self.need("vnd.thepost.peer", t.pos);
                let Some(p) = self.args(name, t.pos, &t.args, MATCH_TAGS, &[Kind::List]) else {
                    return Test::False;
                };
                let keys = self.list(p.pos[0]);
                let (m, _) = self.matcher(&p, &keys, p.pos[0].1);
                Test::Peer { m, keys }
            }
            "environment" => {
                self.need("environment", t.pos);
                let Some(p) = self.args(name, t.pos, &t.args, MATCH_TAGS, &[Kind::Str, Kind::List])
                else {
                    return Test::False;
                };
                let item = self.string(p.pos[0]).to_ascii_lowercase();
                let name = match item.as_str() {
                    "domain" => EnvName::Domain,
                    "host" => EnvName::Host,
                    "phase" => EnvName::Phase,
                    "vnd.thepost.thread" => EnvName::Thread,
                    "vnd.thepost.reply" => EnvName::Reply,
                    "vnd.thepost.risk.score" => EnvName::RiskScore,
                    "vnd.thepost.risk.signals" => EnvName::RiskSignals,
                    _ => {
                        self.err(
                            p.pos[0].1,
                            format!("environment: неизвестный пункт {item:?}"),
                        );
                        return Test::False;
                    }
                };
                let keys = self.list(p.pos[1]);
                let (m, _) = self.matcher(&p, &keys, p.pos[1].1);
                Test::Environment { m, name, keys }
            }
            "valid_ext_list" => {
                self.need("extlists", t.pos);
                let Some(p) = self.args(name, t.pos, &t.args, &[], &[Kind::List]) else {
                    return Test::False;
                };
                let names = self.list(p.pos[0]);
                for n in &names {
                    if !valid_list_uri(n) {
                        self.err(
                            p.pos[0].1,
                            format!("имя списка {n:?} — не URI \"tag:\" (RFC 6134, RFC 4151)"),
                        );
                    }
                }
                Test::ValidExtList(names)
            }
            _ => {
                self.err(t.pos, format!("неизвестный тест {name}"));
                Test::False
            }
        }
    }
}

fn rel_of(s: &str) -> Option<Rel> {
    Some(match s.to_ascii_lowercase().as_str() {
        "gt" => Rel::Gt,
        "ge" => Rel::Ge,
        "lt" => Rel::Lt,
        "le" => Rel::Le,
        "eq" => Rel::Eq,
        "ne" => Rel::Ne,
        _ => return None,
    })
}

/// Имя внешнего списка (`:list`, RFC 6134 §3; `valid_ext_list`; `:organizers` RFC 9671): URI схемы `tag:`
/// (RFC 4151) — `tag:<владелец>,<дата>:<имя>` — на список TI или адресную книгу (CTR-95, SIEVE-15). Разрешает
/// имя узел — интерфейсом APP-79; здесь проверяется только схема и непустая часть.
fn valid_list_uri(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    match lower.strip_prefix("tag:") {
        Some(rest) => !rest.is_empty() && rest.contains(':'),
        None => false,
    }
}

/// Адрес `redirect`: `local@domain` без пробелов и угловых скобок.
fn valid_address(a: &str) -> bool {
    match a.rsplit_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && !domain.is_empty()
                && !a
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '<' | '>' | ','))
        }
        None => false,
    }
}

/// `${hex:…}` и `${unicode:…}` (RFC 5228 §2.4.2.4). Нераспознанная запись остаётся как есть; код Unicode вне
/// диапазона и не UTF-8 после `hex` — ошибка.
pub(crate) fn decode_encoded(s: &str) -> Result<String, String> {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("${") {
        out.extend_from_slice(rest.get(..i).unwrap_or_default().as_bytes());
        let after = rest.get(i + 2..).unwrap_or_default();
        let one = after
            .find('}')
            .and_then(|j| decode_one(after.get(..j).unwrap_or_default()).map(|r| (j, r)));
        match one {
            Some((j, r)) => {
                out.extend(r?);
                rest = after.get(j + 1..).unwrap_or_default();
            }
            None => {
                out.extend_from_slice(b"${");
                rest = after;
            }
        }
    }
    out.extend_from_slice(rest.as_bytes());
    String::from_utf8(out).map_err(|_| "${hex:…} даёт текст не в UTF-8".to_owned())
}

/// Одна запись без `${` и `}`: `None` — не по грамматике.
fn decode_one(inner: &str) -> Option<Result<Vec<u8>, String>> {
    let (name, seq) = inner.split_once(':')?;
    let hex = if name.eq_ignore_ascii_case("hex") {
        true
    } else if name.eq_ignore_ascii_case("unicode") {
        false
    } else {
        return None;
    };
    let items: Vec<&str> = seq.split_ascii_whitespace().collect();
    if items.is_empty()
        || items
            .iter()
            .any(|x| !x.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return None;
    }
    if hex {
        if items.iter().any(|x| x.len() > 2) {
            return None;
        }
        return Some(Ok(items
            .iter()
            .filter_map(|x| u8::from_str_radix(x, 16).ok())
            .collect()));
    }
    let mut out = Vec::new();
    for x in items {
        let digits = x.trim_start_matches('0');
        let code = if digits.is_empty() {
            Some(0)
        } else if digits.len() > 6 {
            None
        } else {
            u32::from_str_radix(digits, 16).ok()
        };
        let Some(c) = code.and_then(char::from_u32) else {
            return Some(Err(format!("недопустимый код Unicode {x}")));
        };
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    }
    Some(Ok(out))
}
