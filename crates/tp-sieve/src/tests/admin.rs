//! Расширения админского профиля (SIEVE-15, решение 126 д): `signal` (`vnd.thepost.risk`), `environment`
//! (RFC 5183) с пунктами `vnd.thepost.*`, `extlists` (RFC 6134) и `:regex` (draft-ietf-sieve-regex) —
//! проверка, выполнение и то, что пользователю они недоступны.

use std::collections::BTreeMap;

use tp_contracts::risk::SignalId;
use tp_contracts::trust::PeerKind;

use crate::{
    ADMIN_EXTENSIONS, Action, Context, EXTENSIONS, Environment, ExternalLists, Limits, Outcome,
    Phase, Program, ThreadTrust, compile, compile_admin, compile_trusted,
};

/// Письмо с фактами для подделки: заголовки `X-ThePost-*` не должны влиять на тесты.
const MAIL: &str = "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.org>\r\n\
                    Subject: Report 42\r\nX-ThePost-Thread: trusted\r\nX-ThePost-Reply: yes\r\n\
                    X-Custom: 192.0.2.10\r\n\r\nThe quick brown fox";

const ADMIN_PROFILE: crate::AdminProfile = crate::AdminProfile {
    internal_domains: Vec::new(),
    forward_domains: Vec::new(),
};

/// Первая ошибка проверки скрипта организации.
fn first_error(text: &str) -> crate::Diagnostic {
    match compile_trusted(text.as_bytes(), &Limits::default()) {
        Ok(_) => panic!("скрипт организации прошёл проверку: {text}"),
        Err(d) => d.into_iter().next().expect("ошибка"),
    }
}

/// Первая ошибка проверки пользовательского скрипта.
fn user_error(text: &str) -> crate::Diagnostic {
    match compile(text.as_bytes(), &Limits::default()) {
        Ok(_) => panic!("пользовательский скрипт прошёл проверку: {text}"),
        Err(d) => d.into_iter().next().expect("ошибка"),
    }
}

fn trusted(text: &str) -> Program {
    match compile_trusted(text.as_bytes(), &Limits::default()) {
        Ok(p) => p,
        Err(d) => panic!("{text}: {:?}", d.first().expect("ошибка")),
    }
}

/// Факты `environment` по умолчанию для тестов (этап `before` — скрипт организации).
fn env() -> Environment<'static> {
    Environment {
        domain: "example.org",
        host: "mail.example.org",
        phase: Phase::Before,
        thread: ThreadTrust::None,
        reply: false,
        risk_score: 0,
        risk_signals: &[],
    }
}

/// Внешние списки в памяти (как интерфейс узла APP-79 в тестах): URI → значения.
#[derive(Debug)]
pub(super) struct MemLists(BTreeMap<&'static str, Vec<&'static str>>);

impl MemLists {
    pub(super) fn new(entries: &[(&'static str, &[&'static str])]) -> Self {
        Self(
            entries
                .iter()
                .map(|(uri, values)| (*uri, values.to_vec()))
                .collect(),
        )
    }
}

impl ExternalLists for MemLists {
    fn contains(&self, uri: &str, value: &str) -> bool {
        self.0
            .get(uri)
            .is_some_and(|values| values.iter().any(|v| v.eq_ignore_ascii_case(value)))
    }

    fn valid(&self, uri: &str) -> bool {
        self.0.contains_key(uri)
    }
}

const NO_LISTS: MemLists = MemLists(BTreeMap::new());

fn run_on(
    script: &str,
    mail: &str,
    environment: Environment<'_>,
    lists: &dyn ExternalLists,
) -> Outcome {
    let program = trusted(script);
    let mailboxes = ["INBOX".to_owned()];
    let ctx = Context {
        message: mail.as_bytes(),
        envelope_from: "alice@example.com",
        envelope_to: "bob@example.org",
        mailboxes: &mailboxes,
        peer: PeerKind::External,
        environment,
        lists,
    };
    crate::run(&program, &ctx, &Limits::default())
}

/// Условие истинно на письме с данными фактами и списками.
fn holds(environment: Environment<'_>, lists: &dyn ExternalLists, mail: &str, cond: &str) -> bool {
    let script = format!(
        "require [\"environment\", \"extlists\", \"envelope\", \"relational\", \"comparator-i;ascii-numeric\"];\n\
         if {cond} {{ discard; }}"
    );
    let o = run_on(&script, mail, environment, lists);
    assert!(o.error.is_none(), "{cond}: {:?}", o.error);
    o.actions.iter().any(|a| matches!(a, Action::Discard))
}

/// Сигнал каталога из строки.
fn signal(id: &str, weight: Option<u16>) -> (SignalId, Option<u16>) {
    (SignalId::new(id).expect("id"), weight)
}

// ---------- signal (vnd.thepost.risk) ----------

/// `signal` — признак в итог выполнения: вес каталога (`None`), заданный вес, повтор без веса.
#[test]
fn signal_runs() {
    let script = "require \"vnd.thepost.risk\";\n\
                  signal \"tp.attach.encrypted_archive\";\n\
                  if header :contains \"subject\" \"Report\" { signal \"org.x\" :weight 5; }\n\
                  signal \"org.x\" :weight 5;\n\
                  signal \"org.zero\" :weight 0;";
    let o = run_on(script, MAIL, env(), &NO_LISTS);
    assert!(o.error.is_none());
    assert!(
        o.signals
            == [
                signal("tp.attach.encrypted_archive", None),
                signal("org.x", Some(5)),
                signal("org.zero", Some(0)),
            ],
        "{:?}",
        o.signals
    );
    // Не действие: implicit keep не отменяет и в действия не попадает.
    assert!(o.actions.is_empty() && o.implicit_keep);
}

/// Вес больше предела и повтор одного `id` с разными весами — ошибка проверки со строкой и столбцом.
#[test]
fn signal_check_errors() {
    let d = first_error("require \"vnd.thepost.risk\";\nsignal \"org.x\" :weight 11;");
    assert_eq!((d.line, d.column), (2, 16), "{d}");
    assert!(
        d.message
            .contains("вес 11 больше предела sieve.risk.max_weight (10)"),
        "{d}"
    );

    // Отрицательный вес: в Sieve нет отрицательных чисел — ошибка разбора с позицией знака.
    let d = first_error("require \"vnd.thepost.risk\";\nsignal \"org.x\" :weight -1;");
    assert_eq!((d.line, d.column), (2, 24), "{d}");

    let d = first_error(
        "require \"vnd.thepost.risk\";\nsignal \"org.x\" :weight 3;\nsignal \"org.x\" :weight 4;",
    );
    assert_eq!((d.line, d.column), (3, 8), "{d}");
    assert!(d.message.contains("с разными весами"), "{d}");

    // Повтор с тем же весом — допустим; недопустимый идентификатор — ошибка.
    assert!(
        compile_trusted(
            "require \"vnd.thepost.risk\"; signal \"org.x\" :weight 3; signal \"org.x\" :weight 3;"
                .as_bytes(),
            &Limits::default()
        )
        .is_ok()
    );
    let d = first_error("require \"vnd.thepost.risk\"; signal \"Org X!\";");
    assert!(d.message.contains("идентификатор признака"), "{d}");

    // Предел веса — конфигурация `sieve.risk.max_weight`.
    let limits = Limits {
        max_signal_weight: 15,
        ..Limits::default()
    };
    assert!(
        compile_trusted(
            "require \"vnd.thepost.risk\"; signal \"org.x\" :weight 15;".as_bytes(),
            &limits
        )
        .is_ok()
    );
}

/// Расширения админского профиля в скрипте пользователя — ошибка проверки.
#[test]
fn admin_extensions_are_org_only() {
    assert!(
        EXTENSIONS.iter().all(|e| !ADMIN_EXTENSIONS.contains(e)),
        "ManageSieve и JMAP Sieve пользователя их не показывают"
    );
    for ext in ADMIN_EXTENSIONS {
        let d = user_error(&format!("require {ext:?};"));
        assert_eq!((d.line, d.column), (1, 9), "{ext}: {d}");
        assert!(
            d.message.contains("доступно только скрипту организации"),
            "{ext}: {d}"
        );
    }
    // Команда signal в скрипте пользователя — ошибка со строкой и столбцом.
    let d = user_error("signal \"org.x\";");
    assert_eq!((d.line, d.column), (1, 1), "{d}");
    assert!(
        d.message
            .contains("signal доступна только скрипту организации"),
        "{d}"
    );
    // Расширения админского профиля объявляет и проверка при сохранении (ADM-49), но не пользовательская.
    assert!(
        compile_admin(
            "require [\"vnd.thepost.risk\", \"environment\", \"extlists\", \"regex\"];".as_bytes(),
            &Limits::default(),
            &ADMIN_PROFILE
        )
        .is_ok()
    );
}

// ---------- environment (RFC 5183) ----------

/// Пункты `environment` — из контекста, не из заголовков письма.
#[test]
fn environment_facts() {
    let mut facts: Environment<'_> = env();
    facts.thread = ThreadTrust::Trusted;
    facts.reply = true;
    facts.risk_score = 7;
    let signals = [
        SignalId::new("tp.attach.encrypted_archive").expect("id"),
        SignalId::new("org.x").expect("id"),
    ];
    facts.risk_signals = &signals;

    // Заголовок X-ThePost-Thread: trusted не делает беседу доверенной.
    let none = env();
    assert!(!holds(
        none,
        &NO_LISTS,
        MAIL,
        "environment \"vnd.thepost.thread\" \"trusted\""
    ));
    assert!(holds(
        facts,
        &NO_LISTS,
        MAIL,
        "environment \"vnd.thepost.thread\" \"trusted\""
    ));
    assert!(holds(
        facts,
        &NO_LISTS,
        MAIL,
        "environment \"vnd.thepost.reply\" \"yes\""
    ));
    assert!(holds(
        none,
        &NO_LISTS,
        MAIL,
        "environment \"vnd.thepost.reply\" \"no\""
    ));

    // Ядро RFC 5183.
    assert!(holds(
        facts,
        &NO_LISTS,
        MAIL,
        "environment \"domain\" \"example.org\""
    ));
    assert!(holds(
        facts,
        &NO_LISTS,
        MAIL,
        "environment \"host\" \"mail.example.org\""
    ));
    assert!(holds(
        facts,
        &NO_LISTS,
        MAIL,
        "environment \"phase\" \"before\""
    ));
    assert!(!holds(
        facts,
        &NO_LISTS,
        MAIL,
        "environment \"phase\" \"during\""
    ));

    // Балл до Sieve и сработавшие признаки.
    assert!(holds(
        facts,
        &NO_LISTS,
        MAIL,
        "environment \"vnd.thepost.risk.score\" :value \"ge\" :comparator \"i;ascii-numeric\" \"7\""
    ));
    assert!(!holds(
        facts,
        &NO_LISTS,
        MAIL,
        "environment \"vnd.thepost.risk.score\" :value \"ge\" :comparator \"i;ascii-numeric\" \"8\""
    ));
    assert!(holds(
        facts,
        &NO_LISTS,
        MAIL,
        "environment \"vnd.thepost.risk.signals\" :is \"tp.attach.encrypted_archive,org.x\""
    ));
    assert!(holds(
        facts,
        &NO_LISTS,
        MAIL,
        "environment \"vnd.thepost.risk.signals\" :contains \"org.x\""
    ));
    assert!(!holds(
        none,
        &NO_LISTS,
        MAIL,
        "environment \"vnd.thepost.risk.signals\" :contains \"org.x\""
    ));

    // Три значения беседы; `none` — контекст без факта.
    let mut untrusted = env();
    untrusted.thread = ThreadTrust::Untrusted;
    assert!(holds(
        untrusted,
        &NO_LISTS,
        MAIL,
        "environment \"vnd.thepost.thread\" \"untrusted\""
    ));
    assert!(holds(
        none,
        &NO_LISTS,
        MAIL,
        "environment \"vnd.thepost.thread\" \"none\""
    ));

    // Неизвестный пункт — ошибка проверки.
    let d = first_error("require \"environment\";\nenvironment \"vnd.thepost.other\" \"x\";");
    assert_eq!((d.line, d.column), (2, 13), "{d}");
    assert!(d.message.contains("неизвестный пункт"), "{d}");
    let d = user_error("require \"environment\"; if environment \"host\" \"x\" { }");
    assert!(
        d.message.contains("доступно только скрипту организации"),
        "{d}"
    );
}

// ---------- extlists (RFC 6134) ----------

/// `:list` и `valid_ext_list` — поиск в списках из памяти (интерфейс узла, APP-79).
#[test]
fn extlists_lookup() {
    const FEODO: &str = "tag:node.example,2026-11-14:ti/feodo";
    const ADDRBOOK: &str = "tag:node.example,2026-11-14:addrbook/org";
    let lists = MemLists::new(&[
        (FEODO, &["192.0.2.10", "bad.example"]),
        (ADDRBOOK, &["alice@example.com"]),
    ]);

    // Письмо с доменом From из списка TI.
    let mail_bad = "From: a@bad.example\r\n\r\nx";

    // Значение заголовка целиком; адрес — часть адреса; конверт.
    assert!(holds(
        env(),
        &lists,
        MAIL,
        &format!("header :list \"X-Custom\" {FEODO:?}")
    ));
    assert!(holds(
        env(),
        &lists,
        MAIL,
        &format!("address :list \"From\" {ADDRBOOK:?}")
    ));
    assert!(holds(
        env(),
        &lists,
        MAIL,
        &format!("envelope :list \"from\" {ADDRBOOK:?}")
    ));
    assert!(holds(
        env(),
        &lists,
        mail_bad,
        &format!("address :list :domain \"From\" {FEODO:?}")
    ));
    // Домен From не в списке; значение From целиком («Alice <…>») — не адрес из книги.
    assert!(!holds(
        env(),
        &lists,
        MAIL,
        &format!("address :list :domain \"From\" {FEODO:?}")
    ));
    assert!(!holds(
        env(),
        &lists,
        mail_bad,
        &format!("address :list \"From\" {FEODO:?}")
    ));
    assert!(!holds(
        env(),
        &lists,
        MAIL,
        &format!("header :list \"From\" {ADDRBOOK:?}")
    ));

    // `valid_ext_list`: известный список — истина, отсутствующий — ложь.
    assert!(holds(
        env(),
        &lists,
        MAIL,
        &format!("valid_ext_list [{FEODO:?}, {ADDRBOOK:?}]")
    ));
    assert!(!holds(
        env(),
        &lists,
        MAIL,
        "valid_ext_list \"tag:node.example,2026-11-14:ti/nope\""
    ));

    // Без интерфейса списков (Rules без with_lists) всё — ложь.
    assert!(!holds(
        env(),
        &NO_LISTS,
        mail_bad,
        &format!("address :list :domain \"From\" {FEODO:?}")
    ));
    assert!(!holds(
        env(),
        &NO_LISTS,
        MAIL,
        &format!("valid_ext_list {FEODO:?}")
    ));

    // Имя списка — URI tag:; другой тип сравнения с :list и неизвестное имя — ошибки проверки.
    let d = first_error(&format!(
        "require \"extlists\";\nif header :list {FEODO:?} {{ }}"
    ));
    assert!(d.message.contains("позиционных аргументов"), "{d}");
    let d = first_error("require \"extlists\";\nif header :list :contains \"From\" \"x\" { }");
    assert_eq!((d.line, d.column), (2, 11), "{d}");
    assert!(d.message.contains(":list — это тип сравнения"), "{d}");
    let d = first_error("require \"extlists\";\nif header :list \"From\" \"feodo\" { }");
    assert_eq!((d.line, d.column), (2, 24), "{d}");
    assert!(d.message.contains("не URI \"tag:\""), "{d}");
    let d = first_error("require \"extlists\";\nif valid_ext_list \"nope\" { }");
    assert!(d.message.contains("не URI \"tag:\""), "{d}");
}

/// `:organizers` у `processcalendar` (RFC 9671) — допустим с `extlists` (SIEVE-15 снимает запрет SIEVE-14).
#[test]
fn processcalendar_organizers() {
    const URI: &str = "tag:node.example,2026-11-14:addrbook/org";
    assert!(
        compile_trusted(
            format!(
                "require [\"processcalendar\", \"extlists\"];\nprocesscalendar :organizers {URI:?};"
            )
            .as_bytes(),
            &Limits::default()
        )
        .is_ok()
    );
    // Без extlists — ошибка require; не URI — ошибка.
    let d = first_error(&format!(
        "require \"processcalendar\";\nprocesscalendar :organizers {URI:?};"
    ));
    assert!(d.message.contains("\"extlists\" не объявлено"), "{d}");
    let d = first_error(
        "require [\"processcalendar\", \"extlists\"];\nprocesscalendar :organizers \"addrbook\";",
    );
    assert!(d.message.contains("не URI \"tag:\""), "{d}");
}

// ---------- :regex (draft-ietf-sieve-regex) ----------

/// Шаблоны `:regex`: совпадение, регистр по компаратору, `$`/`^`, `:count` с ними не задаются.
#[test]
fn regex_matches() {
    let cond = |pattern: &str| format!("header :regex \"Subject\" {pattern:?}");
    assert!(holds_regex(&cond("^Report")));
    assert!(holds_regex(&cond("PORT 42$")));
    // Умолчание i;ascii-casemap — без учёта регистра; i;octet — с учётом.
    assert!(holds_regex(&cond("report")));
    assert!(!holds_regex(
        "header :regex :comparator \"i;octet\" \"Subject\" \"report\""
    ));
    assert!(holds_regex(
        "header :regex :comparator \"i;octet\" \"Subject\" \"Report\""
    ));
    // Чередование и классы.
    assert!(holds_regex(&cond("^(Plain|Report)")));
    assert!(holds_regex(&cond("[0-9]{2}")));
    assert!(!holds_regex(&cond("^Plain")));
    // regex у address, envelope и body — тот же механизм.
    assert!(holds_regex(
        "address :regex :domain \"From\" \"example\\.com$\""
    ));
    assert!(holds_regex("envelope :regex \"from\" \"^alice@\""));
    assert!(holds_regex("body :regex \"quick brown\""));
}

fn holds_regex(cond: &str) -> bool {
    let script = format!("require [\"regex\", \"envelope\", \"body\"];\nif {cond} {{ discard; }}");
    let o = run_on(&script, MAIL, env(), &NO_LISTS);
    assert!(o.error.is_none(), "{cond}: {:?}", o.error);
    o.actions.iter().any(|a| matches!(a, Action::Discard))
}

/// Шаблон `(a+)+$` на длинной строке — за линейное время (крейт `regex`, без ReDoS).
#[test]
fn regex_is_linear() {
    // 100 000 «a» и «b» в конце: возвратный движок завис бы, крейт regex — нет.
    let mut subject = String::with_capacity(100_004);
    subject.push_str("Subject: ");
    subject.push_str(&"a".repeat(100_000));
    subject.push('b');
    let mail = format!("From: a@x.example\r\n{subject}\r\n\r\nx");
    let script = "require \"regex\";\nif header :regex \"Subject\" \"(a+)+$\" { discard; }";
    let o = run_on(script, &mail, env(), &NO_LISTS);
    assert!(o.error.is_none(), "{:?}", o.error);
    assert!(
        o.actions.is_empty() && o.implicit_keep,
        "нет совпадения — implicit keep"
    );
    // С совпадением — discard.
    let mail = format!(
        "From: a@x.example\r\nSubject: {}\r\n\r\nx",
        "a".repeat(1000)
    );
    let o = run_on(script, &mail, env(), &NO_LISTS);
    assert!(o.actions.iter().any(|a| matches!(a, Action::Discard)));
}

/// `:regex` — только админский профиль; шаблон больше `size_limit` и второй тип сравнения — ошибки проверки.
#[test]
fn regex_check_errors() {
    let d = user_error("require \"regex\"; if header :regex \"Subject\" \"x\" { }");
    assert!(
        d.message.contains("доступно только скрипту организации"),
        "{d}"
    );
    let d = first_error("if header :regex \"Subject\" \"x\" { }");
    assert!(d.message.contains("\"regex\" не объявлено"), "{d}");
    // Шаблон больше size_limit — ошибка проверки (компиляция при проверке скрипта), не выполнения.
    let limits = Limits {
        regex_size_limit: 1,
        ..Limits::default()
    };
    let d = match compile_trusted(
        "require \"regex\";\nif header :regex \"Subject\" \"a+\" { }".as_bytes(),
        &limits,
    ) {
        Ok(_) => panic!("шаблон прошёл проверку с size_limit 1"),
        Err(d) => d.into_iter().next().expect("ошибка"),
    };
    assert_eq!((d.line, d.column), (2, 28), "{d}");
    assert!(d.message.contains("не компилируется"), "{d}");

    // Второй тип сравнения и числовой компаратор — ошибки.
    let d = first_error("require \"regex\";\nif header :regex :contains \"Subject\" \"x\" { }");
    assert_eq!((d.line, d.column), (2, 18), "{d}");
    assert!(
        d.message.contains("указано несколько типов сравнения"),
        "{d}"
    );
    let d = first_error(
        "require [\"regex\", \"comparator-i;ascii-numeric\"];\n\
         if header :regex :comparator \"i;ascii-numeric\" \"Subject\" \"1\" { }",
    );
    assert!(
        d.message
            .contains("не поддерживает :contains, :matches и :regex"),
        "{d}"
    );
}
