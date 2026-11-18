//! Email/query и Email/queryChanges (RFC 8621 §4.4–4.5).
//!
//! Нетекстовые условия (папка, даты, размер, ключевые слова, вложения, цепочки) проверяются по метаданным
//! писем (`MessageStore`), текстовые (`text`, `from`, `to`, `cc`, `bcc`, `subject`, `body`, `header`) — запросом
//! к `SearchIndex` на каждое условие; результаты пересекаются (SRS 4.6). Сортировка — по метаданным.
//! Фильтр, любое совпадение которого проходит через текстовые термы (PERF-07), не выгружает все письма
//! папок: метаданные читаются только для кандидатов — писем из результатов термов ([`restrict`]).
//! Поиск по тексту (`text`, `body`) в чужом ящике — запись `AuditAction::Search` в журнал аудита до выполнения
//! (решение 114, JMAP-43; [`crate::audit::search`]).

use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use futures::{StreamExt, stream};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tp_contracts::meta::{Address, Message, MessageQuery};
use tp_contracts::search::{SearchSort, Snippet, TextField, TextQuery};
use tp_contracts::{Error, MailboxId, MessageId, ModSeq, Result};

use crate::core::error::{MethodError, MethodResult, changes_error};
use crate::core::query_cache::{QueryList, Token};
use crate::core::request::{
    Comparator, QueryChangesArgs, QueryWindow, apply_window, map_changes, object, parse_args,
    parse_state, query_changes_response, state_string,
};
use crate::core::{Ctx, thread_id};
use crate::email_get::{has_keyword, threads};

/// Поддерживаемые свойства сортировки (`emailQuerySortOptions`).
pub(crate) const SORT_OPTIONS: &[&str] = &[
    "receivedAt",
    "sentAt",
    "size",
    "from",
    "to",
    "subject",
    "hasKeyword",
    "allInThreadHaveKeyword",
    "someInThreadHaveKeyword",
];

/// Условие фильтра (RFC 8621 §4.4.1).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Condition {
    in_mailbox: Option<String>,
    in_mailbox_other_than: Option<Vec<String>>,
    before: Option<String>,
    after: Option<String>,
    min_size: Option<u64>,
    max_size: Option<u64>,
    all_in_thread_have_keyword: Option<String>,
    some_in_thread_have_keyword: Option<String>,
    none_in_thread_have_keyword: Option<String>,
    has_keyword: Option<String>,
    not_keyword: Option<String>,
    has_attachment: Option<bool>,
    text: Option<String>,
    from: Option<String>,
    to: Option<String>,
    cc: Option<String>,
    bcc: Option<String>,
    subject: Option<String>,
    body: Option<String>,
    header: Option<Vec<String>>,
}

/// Разобранное условие: даты и текстовые термы.
#[derive(Debug)]
struct Cond {
    c: Condition,
    before: Option<OffsetDateTime>,
    after: Option<OffsetDateTime>,
    terms: Vec<(TextField, String)>,
}

impl Cond {
    fn uses_threads(&self) -> bool {
        self.c.all_in_thread_have_keyword.is_some()
            || self.c.some_in_thread_have_keyword.is_some()
            || self.c.none_in_thread_have_keyword.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    And,
    Or,
    Not,
}

#[derive(Debug)]
enum Filter {
    Op(Op, Vec<Filter>),
    Cond(Box<Cond>),
}

fn unsupported(why: impl Into<String>) -> MethodError {
    MethodError::with("unsupportedFilter", why)
}

/// `UTCDate` (RFC 3339); неверная строка — `invalidArguments`.
pub(crate) fn utc(s: &str) -> MethodResult<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339)
        .map_err(|_| MethodError::invalid(format!("bad UTCDate: {s}")))
}

fn parse_filter(v: &Value) -> MethodResult<Filter> {
    let Value::Object(m) = v else {
        return Err(unsupported("filter must be an object"));
    };
    if let Some(op) = m.get("operator") {
        let op = match op.as_str() {
            Some("AND") => Op::And,
            Some("OR") => Op::Or,
            Some("NOT") => Op::Not,
            _ => return Err(unsupported("operator")),
        };
        let conds = m
            .get("conditions")
            .and_then(Value::as_array)
            .ok_or_else(|| unsupported("conditions"))?;
        return Ok(Filter::Op(
            op,
            conds
                .iter()
                .map(parse_filter)
                .collect::<MethodResult<_>>()?,
        ));
    }
    let c: Condition = serde_json::from_value(v.clone()).map_err(|e| unsupported(e.to_string()))?;
    let before = c.before.as_deref().map(utc).transpose()?;
    let after = c.after.as_deref().map(utc).transpose()?;
    let mut terms = Vec::new();
    for (field, text) in [
        (TextField::Any, &c.text),
        (TextField::From, &c.from),
        (TextField::To, &c.to),
        (TextField::Cc, &c.cc),
        (TextField::Bcc, &c.bcc),
        (TextField::Subject, &c.subject),
        (TextField::Body, &c.body),
    ] {
        if let Some(t) = text {
            terms.push((field, t.clone()));
        }
    }
    match c.header.as_deref() {
        None => {}
        Some([name]) => terms.push((TextField::Header(name.clone()), String::new())),
        Some([name, value]) => terms.push((TextField::Header(name.clone()), value.clone())),
        Some(_) => return Err(MethodError::invalid("header: [name] or [name, value]")),
    }
    Ok(Filter::Cond(Box::new(Cond {
        c,
        before,
        after,
        terms,
    })))
}

fn walk<'f>(f: &'f Filter, out: &mut Vec<&'f Cond>) {
    match f {
        Filter::Op(_, fs) => fs.iter().for_each(|f| walk(f, out)),
        Filter::Cond(c) => out.push(c),
    }
}

/// Надмножество результатов запроса (PERF-07): объединение результатов текстовых термов, через которые
/// обязано пройти любое подходящее письмо. `None` — сужения нет: условие без текстовых термов совпадает
/// с любым письмом, `NOT` ищет в дополнении к результатам терма. В `text` — результаты термов,
/// запрошенных в [`run`]; терма нет в карте (не запрашивался) — без сужения.
fn restrict(
    f: &Filter,
    text: &HashMap<(TextField, String), HashSet<MessageId>>,
) -> Option<HashSet<MessageId>> {
    match f {
        Filter::Cond(c) if c.terms.is_empty() => None,
        Filter::Cond(c) => {
            let mut out = HashSet::new();
            for t in &c.terms {
                out.extend(text.get(t)?.iter().copied());
            }
            Some(out)
        }
        // «И»: результат вложен в результат каждого условия — достаточно одного сужающего поддерева.
        Filter::Op(Op::And, fs) => {
            let (mut out, mut any) = (HashSet::new(), false);
            for f in fs {
                if let Some(s) = restrict(f, text) {
                    out.extend(s);
                    any = true;
                }
            }
            any.then_some(out)
        }
        // «Или»: совпадение проходит хотя бы через одно условие — сужают все.
        Filter::Op(Op::Or, fs) => {
            let mut out = HashSet::new();
            for f in fs {
                out.extend(restrict(f, text)?);
            }
            Some(out)
        }
        // Отрицание — дополнение к результатам термов.
        Filter::Op(Op::Not, _) => None,
    }
}

/// Строка запроса для записи аудита (решение 114): условия поиска по тексту письма — только `text` и `body`, как
/// `BODY`/`TEXT` в IMAP-23; поиск по адресам, теме и заголовкам не записывается. Формат — `поле "значение"`
/// (кавычки в значении экранированы), несколько условий — через пробел. Нетекстовых условий — `None`.
fn search_detail(f: &Filter) -> Option<String> {
    fn terms(f: &Filter, out: &mut Vec<String>) {
        match f {
            Filter::Op(_, fs) => fs.iter().for_each(|f| terms(f, out)),
            Filter::Cond(c) => {
                out.extend(c.terms.iter().filter_map(|(field, value)| {
                    let name = match field {
                        TextField::Any => "text",
                        TextField::Body => "body",
                        _ => return None,
                    };
                    Some(format!("{name} \"{}\"", value.replace('"', "\\\"")))
                }));
            }
        }
    }
    let mut out = Vec::new();
    terms(f, &mut out);
    (!out.is_empty()).then(|| out.join(" "))
}

/// Данные для проверки условий: результаты текстовых запросов и цепочки.
struct Eval<'a> {
    text: HashMap<(TextField, String), HashSet<MessageId>>,
    threads: HashMap<String, Vec<&'a Message>>,
}

impl Eval<'_> {
    fn thread(&self, m: &Message) -> &[&Message] {
        self.threads.get(&thread_id(m)).map_or(&[], Vec::as_slice)
    }

    fn matches(&self, f: &Filter, m: &Message) -> bool {
        match f {
            Filter::Op(Op::And, fs) => fs.iter().all(|f| self.matches(f, m)),
            Filter::Op(Op::Or, fs) => fs.iter().any(|f| self.matches(f, m)),
            Filter::Op(Op::Not, fs) => !fs.iter().any(|f| self.matches(f, m)),
            Filter::Cond(c) => self.cond(c, m),
        }
    }

    fn cond(&self, k: &Cond, m: &Message) -> bool {
        let c = &k.c;
        let mailbox = m.mailbox.to_string();
        let kw = |w: &Option<String>, f: &dyn Fn(&str) -> bool| w.as_deref().is_none_or(f);
        c.in_mailbox.as_ref().is_none_or(|id| *id == mailbox)
            && c.in_mailbox_other_than
                .as_ref()
                .is_none_or(|ids| !ids.contains(&mailbox))
            && k.before.is_none_or(|t| m.received_at < t)
            && k.after.is_none_or(|t| m.received_at >= t)
            && c.min_size.is_none_or(|s| m.size >= s)
            && c.max_size.is_none_or(|s| m.size < s)
            && kw(&c.has_keyword, &|w| has_keyword(m, w))
            && kw(&c.not_keyword, &|w| !has_keyword(m, w))
            && kw(&c.all_in_thread_have_keyword, &|w| {
                self.thread(m).iter().all(|x| has_keyword(x, w))
            })
            && kw(&c.some_in_thread_have_keyword, &|w| {
                self.thread(m).iter().any(|x| has_keyword(x, w))
            })
            && kw(&c.none_in_thread_have_keyword, &|w| {
                !self.thread(m).iter().any(|x| has_keyword(x, w))
            })
            && c.has_attachment.is_none_or(|a| m.meta.has_attachment == a)
            && k.terms
                .iter()
                .all(|t| self.text.get(t).is_some_and(|ids| ids.contains(&m.id)))
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QueryArgs {
    account_id: String,
    filter: Option<Value>,
    sort: Option<Vec<Comparator>>,
    #[serde(default)]
    collapse_threads: bool,
    #[serde(flatten)]
    window: QueryWindow,
}

/// Строка сортировки адреса: имя или адрес первого получателя, без учёта регистра.
fn addr_key(list: &[Address]) -> String {
    list.first()
        .map(|a| {
            a.name
                .clone()
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| a.email.clone())
        })
        .unwrap_or_default()
        .to_lowercase()
}

/// Базовая тема (RFC 5256 §2.1, упрощённо): без `Re:`/`Fwd:`/`Fw:` в начале, без учёта регистра.
fn base_subject(s: Option<&str>) -> String {
    let mut s = s.unwrap_or_default().trim().to_lowercase();
    loop {
        let stripped = ["re:", "fwd:", "fw:"]
            .iter()
            .find_map(|p| s.strip_prefix(p))
            .map(|r| r.trim_start().to_owned());
        match stripped {
            Some(r) => s = r,
            None => return s,
        }
    }
}

fn compare(c: &Comparator, x: &Message, y: &Message, ev: &Eval<'_>) -> Ordering {
    let kw = c.keyword.as_deref().unwrap_or_default();
    let in_thread = |m: &Message, all: bool| {
        let t = ev.thread(m);
        if all {
            t.iter().all(|x| has_keyword(x, kw))
        } else {
            t.iter().any(|x| has_keyword(x, kw))
        }
    };
    let (ex, ey) = (&x.meta.envelope, &y.meta.envelope);
    match c.property.as_str() {
        "receivedAt" => x.received_at.cmp(&y.received_at),
        "sentAt" => ex.date.cmp(&ey.date),
        "size" => x.size.cmp(&y.size),
        "from" => addr_key(&ex.from).cmp(&addr_key(&ey.from)),
        "to" => addr_key(&ex.to).cmp(&addr_key(&ey.to)),
        "subject" => base_subject(ex.subject.as_deref()).cmp(&base_subject(ey.subject.as_deref())),
        "hasKeyword" => has_keyword(x, kw).cmp(&has_keyword(y, kw)),
        "allInThreadHaveKeyword" => in_thread(x, true).cmp(&in_thread(y, true)),
        "someInThreadHaveKeyword" => in_thread(x, false).cmp(&in_thread(y, false)),
        _ => Ordering::Equal,
    }
}

/// Числовые свойства сортировки, допускающие кэш: ключ — число, `receivedAt` и конверт не меняются
/// после приёма (флаги и папка покрываются токеном версий папок; текстовые и цепочечные свойства —
/// не кэшируются).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Part {
    ReceivedAt,
    SentAt,
    Size,
}

/// Сортировка `sort` как набор числовых ключей; есть нечисловое свойство — `None` (без кэша).
fn numeric_sort(sort: &[Comparator]) -> Option<Vec<(Part, bool)>> {
    sort.iter()
        .map(|c| {
            let p = match c.property.as_str() {
                "receivedAt" => Part::ReceivedAt,
                "sentAt" => Part::SentAt,
                "size" => Part::Size,
                _ => return None,
            };
            Some((p, c.is_ascending))
        })
        .collect()
}

/// Меньше любой реальной даты (`sentAt` без заголовка), по модулю безопасно отрицать.
const NO_DATE: i128 = i128::MIN / 4;

/// Ключ сортировки письма: части уже ориентированы (меньше — раньше в списке); при равенстве всех
/// частей письма упорядочены по идентификатору — то же, что [`chain`] на тех же критериях.
fn key_of(m: &Message, spec: &[(Part, bool)]) -> Box<[i128]> {
    spec.iter()
        .map(|(p, asc)| {
            let raw = match p {
                Part::ReceivedAt => m.received_at.unix_timestamp_nanos(),
                Part::SentAt => m
                    .meta
                    .envelope
                    .date
                    .map_or(NO_DATE, |t| t.unix_timestamp_nanos()),
                Part::Size => m.size as i128,
            };
            if *asc { raw } else { -raw }
        })
        .collect()
}

/// Ключ кэшируемого запроса: фильтр (как прислан) и сортировка (по ключам). Окно в ключ не входит —
/// страница берётся из полного списка. Один ключ — одинаковый результат при том же наборе писем.
fn query_key(filter: &Option<Value>, spec: &[(Part, bool)]) -> String {
    format!("{filter:?}|{spec:?}")
}

/// Метаданные писем-кандидатов точными чтениями (PERF-07): уникальный фильтр находит немного писем —
/// вместо полной выгрузки папок читаются только кандидаты, параллельно. Письма нечитаемых папок
/// представителя пропускаются (`boxes`, JMAP-49), как не попавшие в полную выгрузку.
async fn fetch_candidates(
    ctx: &Ctx<'_>,
    ids: &HashSet<MessageId>,
    boxes: &Option<Vec<MailboxId>>,
) -> MethodResult<Vec<Message>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let len = ids.len();
    let n = ctx.jmap.cfg.query_cache.max_parallel_get.max(1).min(len);
    let (store, scope) = (ctx.jmap.d.messages.clone(), ctx.scope);
    // Список копируется: стрим владеет элементами — будущее `Send` при любом времени жизни займа
    // (та же форма, что в `Email/get`).
    let ids: Vec<MessageId> = ids.iter().copied().collect();
    let got: Vec<Result<Option<Message>>> = stream::iter(ids)
        .map(|id| {
            let store = store.clone();
            async move { store.get(scope, id).await }
        })
        .buffer_unordered(n)
        .collect()
        .await;
    let mut out = Vec::with_capacity(len);
    for r in got {
        match r {
            Ok(Some(m)) if boxes.as_ref().is_none_or(|b| b.contains(&m.mailbox)) => {
                out.push(m);
            }
            Ok(_) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(out)
}

/// Результаты запроса: идентификаторы писем по порядку; `threads` — условия или сортировка по цепочкам.
/// Кэшируемые запросы ([`numeric_sort`], без текстовых термов, цепочек и свёртки) берут список из кэша
/// ([`crate::core::query_cache`]), при изменениях — обновляют его по журналу ([`try_patch`]) вместо
/// полной загрузки всех писем (PERF-02).
async fn run(
    ctx: &Ctx<'_>,
    a: &QueryArgs,
    token: &Token,
    state: ModSeq,
) -> MethodResult<(Vec<MessageId>, bool)> {
    let filter = a.filter.as_ref().map(parse_filter).transpose()?;
    let sort = sort_of(a)?;
    let mut conds = Vec::new();
    if let Some(f) = &filter {
        walk(f, &mut conds);
    }
    let thread_sort = sort.iter().any(|c| c.property.contains("InThread"));
    let uses_threads = thread_sort || conds.iter().any(|c| c.uses_threads());
    // Одна папка, если её задаёт условие верхнего уровня, а цепочки не нужны.
    let only: Option<MailboxId> = match &filter {
        Some(Filter::Cond(c)) if !uses_threads => {
            c.c.in_mailbox.as_deref().and_then(|s| s.parse().ok())
        }
        _ => None,
    };
    // Поиск представителя по тексту в чужом ящике — запись `Search` до выполнения (решение 114): без записи
    // результат не выдаётся; свой ящик не записывается ([`crate::audit::search`]).
    if let Some(detail) = filter.as_ref().and_then(search_detail) {
        crate::audit::search(ctx, only, &detail).await?;
    }
    let mut text = HashMap::new();
    for (field, value) in conds.iter().flat_map(|c| c.terms.iter()) {
        let key = (field.clone(), value.clone());
        if text.contains_key(&key) {
            continue;
        }
        let q = TextQuery::term(field.clone(), value.clone());
        let limit = ctx.jmap.cfg.max_search_results as usize;
        let hits = ctx
            .jmap
            .d
            .search
            .query(ctx.scope, &[], &q, SearchSort::NewestFirst, limit)
            .await?;
        text.insert(key, hits.into_iter().collect::<HashSet<_>>());
    }
    let spec = numeric_sort(&sort).filter(|_| {
        !uses_threads && !a.collapse_threads && conds.iter().all(|c| c.terms.is_empty())
    });
    // Кандидаты текстовых термов (PERF-07): результат фильтра с текстом вложен в их результаты —
    // метаданные читаются только для кандидатов. Цепочки и свёртка требуют писем вне результатов
    // текста; кандидатов больше порога — полная выгрузка не хуже точных чтений.
    let mut cand = if uses_threads || a.collapse_threads {
        None
    } else {
        filter.as_ref().and_then(|f| restrict(f, &text))
    };
    if cand
        .as_ref()
        .is_some_and(|c| c.len() > ctx.jmap.cfg.query_candidates_max as usize)
    {
        cand = None;
    }
    let scope = (ctx.scope.tenant, ctx.scope.account);
    // Кэш — только свой аккаунт: записи кэша лежат в пространстве владельца и охватывают все его папки
    // (JMAP-49).
    let key = spec
        .as_deref()
        .filter(|_| ctx.access.is_own() && ctx.jmap.cfg.query_cache.max_bytes > 0)
        .map(|s| query_key(&a.filter, s));
    let mut built: Option<QueryList> = None;
    if let Some(k) = &key {
        // Попадание — готовый список; блокировка без `await` — `Caches` не `Send`.
        let hit = {
            let mut caches = ctx.jmap.caches();
            caches.lookup_query(scope, k, token)
        };
        if let Some(ids) = hit {
            return Ok((ids, false));
        }
        // Устаревшая запись — база инкрементального обновления; не удалось — полная пересборка.
        let stale = {
            let mut caches = ctx.jmap.caches();
            caches.stale_query(scope, k)
        };
        if let Some((base_state, list)) = stale {
            let (ids, keys, boxes) = list;
            built = try_patch(
                ctx,
                base_state,
                ids,
                keys,
                boxes,
                filter.as_ref(),
                spec.as_deref().unwrap_or(&[]),
            )
            .await;
        }
    }
    let (ids, keys, boxes) = match built {
        Some(b) => b,
        None => {
            // Папки чтения: одна из фильтра или все; у представителя — только общие с правом `r` (JMAP-49),
            // нечитаемая папка фильтра — пустой результат. Кандидаты текста (PERF-07) читаются точными
            // чтениями с тем же ограничением папок.
            let boxes = ctx.access.query_boxes(only);
            let msgs = match cand {
                Some(c) => fetch_candidates(ctx, &c, &boxes).await?,
                None => ctx.jmap.messages_of(ctx.scope, boxes).await?,
            };
            let ev = Eval {
                text,
                threads: if uses_threads || a.collapse_threads {
                    threads(&msgs)
                } else {
                    HashMap::new()
                },
            };
            match &spec {
                Some(s) => key_order(&msgs, filter.as_ref(), s, &ev),
                None => (
                    order(&msgs, filter.as_ref(), &sort, &ev, a.collapse_threads),
                    Vec::new(),
                    Vec::new(),
                ),
            }
        }
    };
    if let Some(k) = &key {
        ctx.jmap.caches().store_query(
            scope,
            k,
            token.clone(),
            state,
            (ids.clone(), keys.clone(), boxes.clone()),
        );
    }
    Ok((ids, uses_threads))
}

/// Инкрементальное обновление записи кэша по журналу: удалённые убрать (по фактическому
/// существованию — журнал сворачивает скрытие с восстановлением в одно `destroyed`), созданные
/// и изменённые перечитать и переоценить фильтр, порядок поддержать вставкой по ключу. `None` —
/// журнал недоступен или изменений больше `patch_max` — полная пересборка. Каждый патч сворачивает
/// журнал от своей базы, поэтому конкурентные обновления безопасны («последний записавший»
/// несёт актуальный токен).
async fn try_patch(
    ctx: &Ctx<'_>,
    base_state: ModSeq,
    mut ids: Vec<MessageId>,
    mut keys: Vec<Box<[i128]>>,
    mut boxes: Vec<MailboxId>,
    filter: Option<&Filter>,
    spec: &[(Part, bool)],
) -> Option<QueryList> {
    let cap = ctx.jmap.cfg.query_cache.patch_max;
    let c = ctx
        .jmap
        .d
        .changes
        .message_changes(ctx.scope, None, base_state, cap.saturating_add(1))
        .await
        .ok()?;
    if c.has_more || c.created.len() + c.updated.len() + c.destroyed.len() > cap {
        return None;
    }
    let ev = Eval {
        text: HashMap::new(),
        threads: HashMap::new(),
    };
    // «Удалённые» по журналу: журнал сворачивает «изменено, скрыто и восстановлено в интервале»
    // в один `destroyed`, хотя письмо существует — проверяем фактическое существование каждого.
    let mut gone: HashSet<MessageId> = HashSet::new();
    for id in c.destroyed.iter().map(|m| m.id) {
        match ctx.jmap.d.messages.get(ctx.scope, id).await.ok().flatten() {
            Some(m) => upsert(&mut ids, &mut keys, &mut boxes, m, filter, spec, &ev),
            None => {
                gone.insert(id);
            }
        }
    }
    if !gone.is_empty() {
        remove_gone(&mut ids, &mut keys, &mut boxes, &gone);
    }
    // Созданные и изменённые: свежие метаданные, по папкам из журнала — одним запросом на папку.
    let mut fetch: HashMap<MailboxId, Vec<MessageId>> = HashMap::new();
    for m in c.created.iter().chain(&c.updated) {
        fetch.entry(m.mailbox).or_default().push(m.id);
    }
    let mut rest: HashSet<MessageId> = fetch.values().flatten().copied().collect();
    for (mb, group) in fetch {
        let n = group.len();
        let found = ctx
            .jmap
            .d
            .messages
            .list(ctx.scope, mb, MessageQuery::Ids(group), n)
            .await
            .ok()?; // папка удалена между журналом и выборкой — пересборка
        for m in found {
            rest.remove(&m.id);
            upsert(&mut ids, &mut keys, &mut boxes, m, filter, spec, &ev);
        }
    }
    // Не найденные пакетно (перенесены между чтением журнала и выборкой) — по одному; нет — удалено.
    for id in rest {
        match ctx.jmap.d.messages.get(ctx.scope, id).await.ok().flatten() {
            Some(m) => upsert(&mut ids, &mut keys, &mut boxes, m, filter, spec, &ev),
            None => remove_gone(&mut ids, &mut keys, &mut boxes, &HashSet::from([id])),
        }
    }
    Some((ids, keys, boxes))
}

/// Вставляет или обновляет письмо в списке, отсортированном по ключам; не под фильтром — убрать.
fn upsert(
    ids: &mut Vec<MessageId>,
    keys: &mut Vec<Box<[i128]>>,
    boxes: &mut Vec<MailboxId>,
    m: Message,
    filter: Option<&Filter>,
    spec: &[(Part, bool)],
    ev: &Eval<'_>,
) {
    let id = m.id;
    let old = ids.iter().position(|x| *x == id);
    if !filter.is_none_or(|f| ev.matches(f, &m)) {
        if let Some(p) = old {
            ids.remove(p);
            keys.remove(p);
            boxes.remove(p);
        }
        return;
    }
    let key = key_of(&m, spec);
    if let Some(p) = old {
        ids.remove(p);
        keys.remove(p);
        boxes.remove(p);
    }
    let at = insert_pos(keys, ids, &key, id);
    ids.insert(at, id);
    keys.insert(at, key);
    boxes.insert(at, m.mailbox);
}

/// Первая позиция, где (ключ, идентификатор) ≥ заданного.
fn insert_pos(keys: &[Box<[i128]>], ids: &[MessageId], key: &[i128], id: MessageId) -> usize {
    let (mut lo, mut hi) = (0, keys.len());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if keys[mid].as_ref().cmp(key).then(ids[mid].cmp(&id)) == Ordering::Less {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    lo
}

/// Убирает письма `gone` из параллельных списков.
fn remove_gone(
    ids: &mut Vec<MessageId>,
    keys: &mut Vec<Box<[i128]>>,
    boxes: &mut Vec<MailboxId>,
    gone: &HashSet<MessageId>,
) {
    let mut i = 0;
    while i < ids.len() {
        if gone.contains(&ids[i]) {
            ids.remove(i);
            keys.remove(i);
            boxes.remove(i);
        } else {
            i += 1;
        }
    }
}

/// Идентификаторы писем под фильтром в порядке (ключ сортировки, идентификатор); параллельно ключи
/// и папки. Порядок совпадает с [`order`] на тех же критериях — проверено тестом.
fn key_order(
    msgs: &[Message],
    filter: Option<&Filter>,
    spec: &[(Part, bool)],
    ev: &Eval<'_>,
) -> QueryList {
    let mut hits: Vec<(MessageId, Box<[i128]>, MailboxId)> = msgs
        .iter()
        .filter(|m| filter.is_none_or(|f| ev.matches(f, m)))
        .map(|m| (m.id, key_of(m, spec), m.mailbox))
        .collect();
    hits.sort_by(|(x, kx, _), (y, ky, _)| kx.as_ref().cmp(ky.as_ref()).then(x.cmp(y)));
    let mut ids = Vec::with_capacity(hits.len());
    let mut keys = Vec::with_capacity(hits.len());
    let mut boxes = Vec::with_capacity(hits.len());
    for (id, key, mb) in hits {
        ids.push(id);
        keys.push(key);
        boxes.push(mb);
    }
    (ids, keys, boxes)
}

/// Сортировка запроса (по умолчанию — новые первыми); неизвестное свойство — `unsupportedSort`.
fn sort_of(a: &QueryArgs) -> MethodResult<Vec<Comparator>> {
    let sort = a.sort.clone().unwrap_or_else(|| {
        vec![Comparator {
            property: "receivedAt".into(),
            is_ascending: false,
            collation: None,
            keyword: None,
        }]
    });
    for c in &sort {
        if !SORT_OPTIONS.contains(&c.property.as_str()) {
            return Err(MethodError::with("unsupportedSort", c.property.clone()));
        }
        if c.property.contains("Keyword") && c.keyword.is_none() {
            return Err(MethodError::invalid("keyword required"));
        }
    }
    Ok(sort)
}

/// Порядок писем по критериям `sort`, при равенстве — по идентификатору.
fn chain(sort: &[Comparator], x: &Message, y: &Message, ev: &Eval<'_>) -> Ordering {
    for c in sort {
        let o = compare(c, x, y, ev);
        let o = if c.is_ascending { o } else { o.reverse() };
        if o != Ordering::Equal {
            return o;
        }
    }
    x.id.cmp(&y.id)
}

/// Идентификаторы писем под фильтром по порядку `sort`; с `collapse` — первое письмо каждой цепочки.
fn order(
    msgs: &[Message],
    filter: Option<&Filter>,
    sort: &[Comparator],
    ev: &Eval<'_>,
    collapse: bool,
) -> Vec<MessageId> {
    let mut hits: Vec<&Message> = msgs
        .iter()
        .filter(|m| filter.is_none_or(|f| ev.matches(f, m)))
        .collect();
    hits.sort_by(|x, y| chain(sort, x, y, ev));
    let mut seen = HashSet::new();
    hits.into_iter()
        .filter(|m| !collapse || seen.insert(thread_id(m)))
        .map(|m| m.id)
        .collect()
}

/// `Email/query` (свой аккаунт или чужой по ACL — JMAP-49).
pub(crate) async fn query(
    ctx: &mut Ctx<'_>,
    args: Map<String, Value>,
) -> MethodResult<Map<String, Value>> {
    let a: QueryArgs = parse_args(args)?;
    ctx.open_mail(&a.account_id).await?;
    let (state, token) = ctx.state_full().await?;
    let (ids, uses_threads) = run(ctx, &a, &token, state).await?;
    let ids = ids.iter().map(|id| id.to_string()).collect::<Vec<_>>();
    let mut out = object(json!({
        "accountId": a.account_id,
        "queryState": state_string(state),
        "canCalculateChanges": !a.collapse_threads && !uses_threads,
        "collapseThreads": a.collapse_threads,
    }));
    apply_window(&ids, &a.window, ctx.jmap.cfg.max_query_limit, &mut out)?;
    Ok(out)
}

/// `Email/queryChanges` по журналу изменений писем. С `collapseThreads` и условиями по цепочкам позиция
/// письма зависит от других писем — `cannotCalculateChanges`.
pub(crate) async fn query_changes(
    ctx: &mut Ctx<'_>,
    args: Map<String, Value>,
) -> MethodResult<Map<String, Value>> {
    let qc: QueryChangesArgs = parse_args(args.clone())?;
    ctx.open_mail(&qc.account_id).await?;
    let mut q = args;
    q.retain(|k, _| {
        matches!(
            k.as_str(),
            "accountId" | "filter" | "sort" | "collapseThreads"
        )
    });
    let a: QueryArgs = parse_args(q)?;
    if a.collapse_threads {
        return Err(MethodError::new("cannotCalculateChanges"));
    }
    let since = parse_state(&qc.since_query_state)?;
    let limit = qc.limit(ctx.jmap.cfg.max_changes)?;
    let mut c = ctx
        .jmap
        .d
        .changes
        .message_changes(ctx.scope, None, since, limit.saturating_add(1))
        .await
        .map_err(changes_error)?;
    // Представителю сообщаются только изменения читаемых папок (JMAP-49): изменения остальных папок
    // ящика его запросу не принадлежат и писем этих папок не раскрывают.
    if !ctx.access.is_own() {
        c.created.retain(|m| ctx.access.reads_mail(m.mailbox));
        c.updated.retain(|m| ctx.access.reads_mail(m.mailbox));
        c.destroyed.retain(|m| ctx.access.reads_mail(m.mailbox));
    }
    let c = map_changes(c, |m| m.id.to_string());
    let (state, token) = ctx.state_full().await?;
    let (ids, uses_threads) = run(ctx, &a, &token, state).await?;
    if uses_threads {
        return Err(MethodError::new("cannotCalculateChanges"));
    }
    let ids = ids.iter().map(|id| id.to_string()).collect::<Vec<_>>();
    query_changes_response(&qc, &ids, &c, limit)
}

/// Текстовая часть фильтра: термы условий в дереве операторов; нетекстовые условия отбрасываются.
fn text_of(f: &Filter) -> Option<TextQuery> {
    match f {
        Filter::Cond(c) => {
            let mut terms: Vec<TextQuery> = c
                .terms
                .iter()
                .map(|(field, text)| TextQuery::term(field.clone(), text.clone()))
                .collect();
            match terms.len() {
                0 => None,
                1 => terms.pop(),
                _ => Some(TextQuery::And(terms)),
            }
        }
        Filter::Op(op, fs) => {
            let qs: Vec<TextQuery> = fs.iter().filter_map(text_of).collect();
            if qs.is_empty() {
                return None;
            }
            Some(match op {
                Op::And => TextQuery::And(qs),
                Op::Or => TextQuery::Or(qs),
                Op::Not => TextQuery::Not(Box::new(TextQuery::Or(qs))),
            })
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SnippetArgs {
    account_id: String,
    filter: Option<Value>,
    email_ids: Vec<String>,
}

/// `SearchSnippet/get` (RFC 8621 §5): фрагменты с `<mark>` от `SearchIndex::snippet` по текстовой части фильтра.
pub(crate) async fn snippet_get(
    ctx: &mut Ctx<'_>,
    args: Map<String, Value>,
) -> MethodResult<Map<String, Value>> {
    let a: SnippetArgs = parse_args(args)?;
    ctx.check_account(&a.account_id)?;
    if a.email_ids.len() > ctx.jmap.cfg.max_objects_in_get as usize {
        return Err(MethodError::new("requestTooLarge"));
    }
    let q = a
        .filter
        .as_ref()
        .map(parse_filter)
        .transpose()?
        .as_ref()
        .and_then(text_of);
    let d = &ctx.jmap.d;
    let (mut list, mut not_found) = (Vec::new(), Vec::new());
    for id in a.email_ids {
        let msg = match MessageId::from_str(ctx.resolve_id(&id)) {
            Ok(mid) => d.messages.get(ctx.scope, mid).await?,
            Err(_) => None,
        };
        let Some(m) = msg else {
            not_found.push(id);
            continue;
        };
        let s = match &q {
            Some(q) => match d.search.snippet(ctx.scope, m.id, q).await {
                Ok(s) => s,
                // Письмо ещё не проиндексировано.
                Err(Error::NotFound) => Snippet::default(),
                Err(e) => return Err(e.into()),
            },
            None => Snippet::default(),
        };
        list.push(json!({"emailId": id, "subject": s.subject, "preview": s.preview}));
    }
    Ok(object(json!({
        "accountId": a.account_id,
        "list": list,
        "notFound": if not_found.is_empty() { Value::Null } else { json!(not_found) },
    })))
}

/// Аргументы `Email/query` на письмах `msgs` без хранилища (цель fuzz `query`, [`crate::fuzz`]): текстовое
/// условие находит письма, в теме которых есть его значение (без учёта регистра). Паника — нарушен инвариант:
/// `NOT` не обращает фильтр, `AND`/`OR` из него же меняют результат, найдено не то или не в порядке
/// сортировки, окно (`position`, `anchor`, `limit`) не часть результатов.
pub(crate) fn fuzz(args: Map<String, Value>, msgs: &[Message], max_limit: u32) {
    let Ok(a) = parse_args::<QueryArgs>(args) else {
        return;
    };
    let Ok(filter) = a.filter.as_ref().map(parse_filter).transpose() else {
        return;
    };
    let Ok(sort) = sort_of(&a) else {
        return;
    };
    let mut conds = Vec::new();
    if let Some(f) = &filter {
        walk(f, &mut conds);
    }
    let mut text = HashMap::new();
    for (field, value) in conds.iter().flat_map(|c| c.terms.iter()) {
        let needle = value.to_lowercase();
        let hits = msgs
            .iter()
            .filter(|m| {
                let subject = m.meta.envelope.subject.as_deref().unwrap_or_default();
                subject.to_lowercase().contains(&needle)
            })
            .map(|m| m.id)
            .collect();
        text.insert((field.clone(), value.clone()), hits);
    }
    let ev = Eval {
        text,
        threads: threads(msgs),
    };
    if let (Some(f), Some(v)) = (&filter, &a.filter) {
        let _ = text_of(f);
        for (op, conditions) in [
            ("NOT", json!([v])),
            ("AND", json!([v, v])),
            ("OR", json!([v])),
        ] {
            let Ok(w) = parse_filter(&json!({ "operator": op, "conditions": conditions })) else {
                panic!("{op} из разобранного фильтра не разобран: {v}");
            };
            for m in msgs {
                let expect = ev.matches(f, m) != (op == "NOT");
                assert_eq!(ev.matches(&w, m), expect, "{op}: {v}");
            }
        }
    }
    let ids = order(msgs, filter.as_ref(), &sort, &ev, a.collapse_threads);
    let by_id: HashMap<MessageId, &Message> = msgs.iter().map(|m| (m.id, m)).collect();
    let found: Vec<&Message> = ids
        .iter()
        .map(|id| *by_id.get(id).unwrap_or_else(|| panic!("чужое письмо {id}")))
        .collect();
    let matching: Vec<&Message> = msgs
        .iter()
        .filter(|m| filter.as_ref().is_none_or(|f| ev.matches(f, m)))
        .collect();
    let expected = if a.collapse_threads {
        matching
            .iter()
            .map(|m| thread_id(m))
            .collect::<HashSet<_>>()
            .len()
    } else {
        matching.len()
    };
    assert_eq!(ids.len(), expected, "найдено писем");
    assert_eq!(
        ids.iter().collect::<HashSet<_>>().len(),
        ids.len(),
        "повтор"
    );
    for pair in found.windows(2) {
        assert_eq!(
            chain(&sort, pair[0], pair[1], &ev),
            Ordering::Less,
            "порядок"
        );
    }
    let strings = ids.iter().map(ToString::to_string).collect::<Vec<_>>();
    window(&strings, &a.window, max_limit);
}

/// Окно `/query` над `ids`: страница — отрезок результатов с нужной позиции, не длиннее `limit`.
fn window(ids: &[String], w: &QueryWindow, max_limit: u32) {
    let mut out = Map::new();
    if apply_window(ids, w, max_limit, &mut out).is_err() {
        assert!(
            w.anchor.as_ref().is_some_and(|x| !ids.contains(x)),
            "ошибка окна без чужого якоря"
        );
        return;
    }
    let len = ids.len();
    let pos = out
        .get("position")
        .and_then(Value::as_u64)
        .and_then(|p| usize::try_from(p).ok())
        .unwrap_or_else(|| panic!("position: {out:?}"));
    let page: Vec<String> = out
        .get("ids")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_else(|| panic!("ids: {out:?}"));
    let cap = u64::from(max_limit);
    let limit = usize::try_from(w.limit.unwrap_or(cap).min(cap)).unwrap_or(usize::MAX);
    assert!(pos <= len, "position {pos} > {len}");
    assert_eq!(
        page,
        ids[pos..len.min(pos.saturating_add(limit))],
        "страница"
    );
    let signed = |n: usize| i64::try_from(n).unwrap_or(i64::MAX);
    let expect = match &w.anchor {
        Some(anchor) => ids
            .iter()
            .position(|id| id == anchor)
            .map(|at| signed(at).saturating_add(w.anchor_offset)),
        None if w.position < 0 => Some(signed(len).saturating_add(w.position)),
        None => Some(w.position),
    };
    let expect = expect.map(|p| usize::try_from(p.max(0)).unwrap_or(usize::MAX).min(len));
    assert_eq!(Some(pos), expect, "позиция окна");
    assert_eq!(
        out.get("total").and_then(Value::as_u64),
        w.calculate_total.then_some(len as u64),
        "total"
    );
    if w.limit.is_some_and(|l| l > cap) {
        assert_eq!(out.get("limit").and_then(Value::as_u64), Some(cap), "limit");
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use time::{Duration, OffsetDateTime};
    use tp_contracts::mailstore::MailStore;
    use tp_contracts::meta::{Flag, FlagOp, SpecialUse};

    use crate::testenv::{Env, mail};

    /// Четыре письма: две цепочки, разные даты, размеры, флаги, вложение.
    async fn fixture(env: &Env) -> Vec<String> {
        let inbox = env.mailbox(SpecialUse::Inbox);
        let junk = env.mailbox(SpecialUse::Junk);
        let t0 = OffsetDateTime::now_utc() - Duration::days(10);
        let att = "MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n";
        let att_body = "--b\r\nContent-Type: text/plain\r\n\r\nсчёт во вложении\r\n--b\r\n\
                        Content-Type: application/pdf; name=a.pdf\r\nContent-Disposition: attachment; filename=a.pdf\r\n\
                        Content-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n--b--";
        let mails = [
            (
                inbox,
                mail(
                    "Отчёт за квартал",
                    "Boris <boris@x.org>",
                    "Message-ID: <q1@x>\r\n",
                    "цифры за квартал",
                ),
                vec![Flag::Seen],
                0,
            ),
            (
                inbox,
                mail(
                    "Re: Отчёт за квартал",
                    "anna@x.org",
                    "References: <q1@x>\r\n",
                    "спасибо, отчёт получен",
                ),
                vec![],
                1,
            ),
            (
                junk,
                mail(
                    "Акция",
                    "shop@spam.example",
                    "List-Id: <promo.spam.example>\r\n",
                    "скидки",
                ),
                vec![Flag::Flagged],
                2,
            ),
            (
                inbox,
                mail("Счёт", "billing@x.org", att, att_body),
                vec![Flag::Seen, Flag::Flagged],
                3,
            ),
        ];
        let mut ids = Vec::new();
        for (mb, raw, flags, day) in mails {
            let id = env
                .deliver_at(
                    mb,
                    &raw,
                    flags.into_iter().collect(),
                    t0 + Duration::days(day),
                )
                .await;
            ids.push(id.to_string());
        }
        ids
    }

    async fn ids(env: &Env, args: serde_json::Value) -> serde_json::Value {
        let mut a = args;
        a["accountId"] = json!(env.account());
        env.call("Email/query", a, "Email/query").await["ids"].clone()
    }

    #[tokio::test]
    async fn filters_and_search() {
        let env = Env::new().await;
        let m = fixture(&env).await;
        let inbox = env.mailbox(SpecialUse::Inbox).to_string();
        let t0 = OffsetDateTime::now_utc() - time::Duration::days(10);
        // Граница между письмами 1-го и 2-го дня (а не ровно 2-й день): `t0` фикстуры чуть раньше `t0` теста.
        let day2 =
            crate::email_get::utc_date(t0 + time::Duration::days(2) - time::Duration::hours(12));
        // По умолчанию — новые сверху.
        assert_eq!(ids(&env, json!({})).await, json!([m[3], m[2], m[1], m[0]]));
        assert_eq!(
            ids(&env, json!({"filter": {"inMailbox": inbox}})).await,
            json!([m[3], m[1], m[0]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"inMailboxOtherThan": [inbox]}})).await,
            json!([m[2]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"before": day2}})).await,
            json!([m[1], m[0]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"after": day2}})).await,
            json!([m[3], m[2]])
        );
        assert_eq!(
            ids(
                &env,
                json!({"filter": {"hasKeyword": "$flagged", "notKeyword": "$seen"}})
            )
            .await,
            json!([m[2]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"hasAttachment": true}})).await,
            json!([m[3]])
        );
        let sizes = env
            .call(
                "Email/get",
                json!({"accountId": env.account(), "ids": m, "properties": ["size"]}),
                "Email/get",
            )
            .await;
        let size = |i: usize| sizes["list"][i]["size"].as_u64().expect("size");
        let big = (0..4).max_by_key(|i| size(*i)).expect("max");
        assert_eq!(
            ids(&env, json!({"filter": {"minSize": size(big)}})).await,
            json!([m[big]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"maxSize": size(big)}}))
                .await
                .as_array()
                .map(Vec::len),
            Some(3)
        );
        // Текстовые условия — через SearchIndex (подстрока без учёта регистра в FakeSearch).
        assert_eq!(
            ids(&env, json!({"filter": {"text": "квартал"}})).await,
            json!([m[1], m[0]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"from": "boris"}})).await,
            json!([m[0]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"subject": "акция"}})).await,
            json!([m[2]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"body": "вложении"}})).await,
            json!([m[3]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"header": ["List-Id"]}})).await,
            json!([m[2]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"header": ["List-Id", "promo"]}})).await,
            json!([m[2]])
        );
        assert_eq!(
            ids(
                &env,
                json!({"filter": {"operator": "AND", "conditions": [
                {"text": "отчёт"}, {"operator": "NOT", "conditions": [{"hasKeyword": "$seen"}]}]}})
            )
            .await,
            json!([m[1]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"operator": "OR", "conditions": [{"from": "shop"}, {"hasAttachment": true}]}})).await,
            json!([m[3], m[2]])
        );
        // Цепочки: в цепочке m0+m1 не все письма прочитаны.
        assert_eq!(
            ids(
                &env,
                json!({"filter": {"someInThreadHaveKeyword": "$seen", "inMailbox": inbox}})
            )
            .await,
            json!([m[3], m[1], m[0]])
        );
        assert_eq!(
            ids(&env, json!({"filter": {"allInThreadHaveKeyword": "$seen"}})).await,
            json!([m[3]])
        );
        assert_eq!(
            ids(
                &env,
                json!({"filter": {"noneInThreadHaveKeyword": "$seen"}})
            )
            .await,
            json!([m[2]])
        );
        let r = env
            .calls(json!([
                ["Email/query", {"accountId": env.account(), "filter": {"color": "red"}}, "a"],
                ["Email/query", {"accountId": env.account(), "sort": [{"property": "color"}]}, "b"],
                ["Email/query", {"accountId": env.account(), "filter": {"before": "yesterday"}}, "c"]
            ]))
            .await;
        assert_eq!(r[0][1]["type"], "unsupportedFilter");
        assert_eq!(r[1][1]["type"], "unsupportedSort");
        assert_eq!(r[2][1]["type"], "invalidArguments");
    }

    #[tokio::test]
    async fn sort_window_collapse() {
        let env = Env::new().await;
        let m = fixture(&env).await;
        let asc = |p: &str| json!({"sort": [{"property": p, "isAscending": true}]});
        assert_eq!(
            ids(&env, asc("receivedAt")).await,
            json!([m[0], m[1], m[2], m[3]])
        );
        // Базовая тема: «Re:» не учитывается, сравнение без регистра; одинаковые — по второму критерию.
        assert_eq!(
            ids(&env, json!({"sort": [{"property": "subject"}, {"property": "receivedAt", "isAscending": false}]})).await,
            json!([m[2], m[1], m[0], m[3]])
        );
        assert_eq!(
            ids(&env, asc("from")).await,
            json!([m[1], m[3], m[0], m[2]])
        );
        assert_eq!(
            ids(&env, json!({"sort": [{"property": "hasKeyword", "keyword": "$flagged", "isAscending": false}, {"property": "size"}]})).await
                .as_array()
                .map(|a| a.len()),
            Some(4)
        );
        let r = env
            .call(
                "Email/query",
                json!({"accountId": env.account(), "collapseThreads": true, "calculateTotal": true, "position": 1, "limit": 2}),
                "Email/query",
            )
            .await;
        assert_eq!(r["ids"], json!([m[2], m[1]]));
        assert_eq!(
            (r["total"].clone(), r["position"].clone()),
            (json!(3), json!(1))
        );
        assert_eq!(r["canCalculateChanges"], false);
        let r = env
            .call(
                "Email/query",
                json!({"accountId": env.account(), "anchor": m[2], "anchorOffset": -1, "limit": 2}),
                "Email/query",
            )
            .await;
        assert_eq!(r["ids"], json!([m[3], m[2]]));
        let r = env
            .call(
                "Email/query",
                json!({"accountId": env.account(), "position": -1}),
                "Email/query",
            )
            .await;
        assert_eq!(
            (r["ids"].clone(), r["position"].clone()),
            (json!([m[0]]), json!(3))
        );
    }

    /// Пример RFC 8621 §4.10: Email/query и Email/get по ссылке на результат.
    #[tokio::test]
    async fn query_then_get_by_reference() {
        let env = Env::new().await;
        let m = fixture(&env).await;
        let acc = env.account();
        let r = env
            .calls(json!([
                ["Email/query", {"accountId": acc, "filter": {"inMailbox": env.mailbox(SpecialUse::Inbox).to_string()},
                    "sort": [{"property": "receivedAt", "isAscending": false}], "collapseThreads": true,
                    "position": 0, "limit": 20, "calculateTotal": true}, "t0"],
                ["Email/get", {"accountId": acc, "#ids": {"resultOf": "t0", "name": "Email/query", "path": "/ids"},
                    "properties": ["threadId"]}, "t1"],
                ["Thread/get", {"accountId": acc, "#ids": {"resultOf": "t1", "name": "Email/get", "path": "/list/*/threadId"}}, "t2"]
            ]))
            .await;
        assert_eq!(r[0][1]["ids"], json!([m[3], m[1]]));
        assert_eq!(r[1][1]["list"].as_array().map(Vec::len), Some(2));
        assert_eq!(r[2][1]["list"][1]["emailIds"], json!([m[0], m[1]]));
    }

    #[tokio::test]
    async fn query_changes() {
        let env = Env::new().await;
        let m = fixture(&env).await;
        let acc = env.account();
        let filter = json!({"hasKeyword": "$seen"});
        let q = env
            .call(
                "Email/query",
                json!({"accountId": acc, "filter": filter}),
                "Email/query",
            )
            .await;
        assert_eq!(q["ids"], json!([m[3], m[0]]));
        assert_eq!(q["canCalculateChanges"], true);
        let id1 = m[1].parse().expect("id");
        env.store
            .set_flags(env.scope, &[id1], FlagOp::Add([Flag::Seen].into()), None)
            .await
            .expect("flags");
        env.deliver(
            env.mailbox(SpecialUse::Inbox),
            &mail("new", "a@x.org", "", "x"),
            [Flag::Seen].into(),
        )
        .await;
        let qc = env
            .call(
                "Email/queryChanges",
                json!({"accountId": acc, "filter": filter, "sinceQueryState": q["queryState"], "calculateTotal": true}),
                "Email/queryChanges",
            )
            .await;
        assert_eq!(qc["removed"], json!([m[1]]));
        assert_eq!(qc["added"].as_array().map(Vec::len), Some(2));
        assert_eq!(qc["added"][1], json!({"id": m[1], "index": 2}));
        assert_eq!(qc["total"], 4);
        assert_eq!(qc["oldQueryState"], q["queryState"]);
        let r = env
            .calls(json!([
                ["Email/queryChanges", {"accountId": acc, "sinceQueryState": q["queryState"], "collapseThreads": true}, "a"],
                ["Email/queryChanges", {"accountId": acc, "sinceQueryState": q["queryState"], "maxChanges": 1}, "b"],
                ["Email/queryChanges", {"accountId": acc, "sinceQueryState": q["queryState"],
                    "filter": {"allInThreadHaveKeyword": "$seen"}}, "c"]
            ]))
            .await;
        assert_eq!(r[0][1]["type"], "cannotCalculateChanges");
        assert_eq!(r[1][1]["type"], "tooManyChanges");
        assert_eq!(r[2][1]["type"], "cannotCalculateChanges");
    }

    /// Полное число результатов запроса без фильтра (`total`).
    async fn total(env: &Env) -> Value {
        env.call(
            "Email/query",
            json!({"accountId": env.account(), "calculateTotal": true}),
            "Email/query",
        )
        .await["total"]
            .clone()
    }

    /// Кэш `Email/query` прозрачен: приём, смена флагов, перенос и окончательное удаление отражаются
    /// в результатах так же, как при полной пересборке (PERF-02: повтор запроса — из кэша,
    /// изменения — инкрементально по журналу).
    #[tokio::test]
    async fn query_cache_transparent() {
        let env = Env::new().await;
        let m = fixture(&env).await;
        let inbox = env.mailbox(SpecialUse::Inbox);
        // Пересборка, затем попадание: тот же список и total.
        assert_eq!(total(&env).await, json!(4));
        assert_eq!(total(&env).await, json!(4));
        // Приём — патч по журналу: новое письмо наверху.
        let fresh = env
            .deliver(
                inbox,
                &mail("Новые цифры", "cilia@x.org", "", "свежие цифры"),
                [].into(),
            )
            .await
            .to_string();
        assert_eq!(total(&env).await, json!(5));
        let first = env
            .call(
                "Email/query",
                json!({"accountId": env.account(), "limit": 1}),
                "Email/query",
            )
            .await["ids"]
            .clone();
        assert_eq!(first, json!([fresh]));
        // Флаг — патч: до смены письма с `$flagged` — m[3] и m[2], после — добавляется m[0].
        use tp_contracts::meta::MessageStore as _;
        assert_eq!(
            ids(&env, json!({"filter": {"hasKeyword": "$flagged"}})).await,
            json!([m[3], m[2]])
        );
        let id0: tp_contracts::MessageId = m[0].parse().expect("id");
        env.meta
            .set_flags(env.scope, &[id0], FlagOp::Add([Flag::Flagged].into()), None)
            .await
            .expect("flags");
        assert_eq!(
            ids(&env, json!({"filter": {"hasKeyword": "$flagged"}})).await,
            json!([m[3], m[2], m[0]])
        );
        // Перенос из папки — патч: письмо пропадает из фильтра по папке и появляется в архиве.
        let archive = env.mailbox(SpecialUse::Archive);
        let in_inbox = env
            .call(
                "Email/query",
                json!({"accountId": env.account(), "filter": {"inMailbox": inbox.to_string()}, "calculateTotal": true}),
                "Email/query",
            )
            .await;
        assert_eq!(in_inbox["total"], json!(4));
        env.meta
            .move_to(env.scope, &[id0], archive)
            .await
            .expect("move");
        let in_inbox = env
            .call(
                "Email/query",
                json!({"accountId": env.account(), "filter": {"inMailbox": inbox.to_string()}, "calculateTotal": true}),
                "Email/query",
            )
            .await;
        assert_eq!(in_inbox["total"], json!(3));
        assert!(
            !in_inbox["ids"]
                .as_array()
                .expect("ids")
                .contains(&json!(m[0]))
        );
        let in_archive = ids(&env, json!({"filter": {"inMailbox": archive.to_string()}})).await;
        assert_eq!(in_archive, json!([m[0]]));
        // Окончательное удаление (из корзины) — патч: письмо исчезает из запроса без фильтра.
        let id2: tp_contracts::MessageId = m[2].parse().expect("id");
        env.meta
            .to_trash(env.scope, &[id2])
            .await
            .expect("to trash");
        env.meta
            .expunge_final(env.scope, &[id2])
            .await
            .expect("expunge");
        assert_eq!(total(&env).await, json!(4));
        let rest = env
            .call(
                "Email/query",
                json!({"accountId": env.account(), "calculateTotal": true}),
                "Email/query",
            )
            .await["ids"]
            .clone();
        assert!(!rest.as_array().expect("ids").contains(&json!(m[2])));
        // Порядок и состав совпадают с полной пересборкой (кэш отключён).
        use crate::JmapConfig;
        use crate::core::config::QueryCacheConfig;
        let off = JmapConfig {
            query_cache: QueryCacheConfig {
                max_bytes: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let env = Env::with(off, Vec::new()).await;
        let m = fixture(&env).await;
        assert_eq!(ids(&env, json!({})).await, json!([m[3], m[2], m[1], m[0]]));
    }

    /// Порядок по числовым ключам (кэш) совпадает с порядком по компаратору (`chain`) на тех же
    /// критериях: направление, несколько критериев, `sentAt` без даты, равенство — по идентификатору.
    #[tokio::test]
    async fn cache_order_matches_comparator() {
        use std::collections::HashMap;
        use tp_contracts::meta::{MessageQuery, MessageStore as _};

        use super::{Comparator, Eval, key_order, numeric_sort, order};
        use crate::email_get::threads;

        let env = Env::new().await;
        fixture(&env).await;
        let mut msgs = Vec::new();
        for role in [SpecialUse::Inbox, SpecialUse::Junk] {
            msgs.extend(
                env.meta
                    .list(env.scope, env.mailbox(role), MessageQuery::All, usize::MAX)
                    .await
                    .expect("list"),
            );
        }
        let ev = Eval {
            text: HashMap::new(),
            threads: threads(&msgs),
        };
        let cases = [
            json!([{"property": "receivedAt", "isAscending": false}]),
            json!([{"property": "receivedAt", "isAscending": true}]),
            json!([{"property": "size"}, {"property": "receivedAt", "isAscending": false}]),
            json!([{"property": "sentAt"}, {"property": "size", "isAscending": false}]),
            json!([{"property": "sentAt", "isAscending": true}, {"property": "size", "isAscending": true}]),
        ];
        for sort in cases {
            let sort: Vec<Comparator> = serde_json::from_value(sort).expect("sort");
            let spec = numeric_sort(&sort).expect("numeric");
            let (key_ids, _, _) = key_order(&msgs, None, &spec, &ev);
            assert_eq!(key_ids, order(&msgs, None, &sort, &ev, false));
        }
    }

    /// Кандидаты запроса (PERF-07): сужение выборки результатами текстовых термов. `AND` — достаточно
    /// одного сужающего поддерева, `OR` — сужают все условия; `NOT` и условие без текстовых термов
    /// не сужают.
    #[test]
    fn restrict_by_terms() {
        use std::collections::{HashMap, HashSet};

        use super::{Filter, parse_filter, restrict};
        use tp_contracts::search::TextField;

        fn f(v: serde_json::Value) -> Filter {
            parse_filter(&v).expect("filter")
        }
        let a: tp_contracts::MessageId =
            "00000000-0000-0000-0000-00000000000a".parse().expect("id");
        let b: tp_contracts::MessageId =
            "00000000-0000-0000-0000-00000000000b".parse().expect("id");
        let text = HashMap::from([
            ((TextField::Any, "α".into()), HashSet::from([a, b])),
            ((TextField::Subject, "β".into()), HashSet::from([b])),
        ]);
        let r = |v| restrict(&f(v), &text);
        assert_eq!(r(json!({"text": "α"})), Some(HashSet::from([a, b])));
        // Условие из нескольких термов — объединение их результатов (пересечение не шире).
        assert_eq!(
            r(json!({"text": "α", "subject": "β"})),
            Some(HashSet::from([a, b]))
        );
        // «И»: нетекстовое условие не мешает сужению текстовым.
        assert_eq!(
            r(json!({"operator": "AND", "conditions": [{"text": "α"}, {"hasKeyword": "$seen"}]})),
            Some(HashSet::from([a, b]))
        );
        // «Или»: сужают все условия; нетекстовое условие выключает сужение.
        assert_eq!(
            r(json!({"operator": "OR", "conditions": [{"text": "α"}, {"subject": "β"}]})),
            Some(HashSet::from([a, b]))
        );
        assert_eq!(
            r(json!({"operator": "OR", "conditions": [{"text": "α"}, {"hasKeyword": "$seen"}]})),
            None
        );
        // Отрицание терма — дополнение; нетекстовый фильтр не сужает.
        assert_eq!(
            r(json!({"operator": "NOT", "conditions": [{"text": "α"}]})),
            None
        );
        assert_eq!(r(json!({"hasKeyword": "$seen"})), None);
    }

    /// Кандидатный путь (PERF-07) прозрачен: ответ с текстовым фильтром на точных чтениях — как при
    /// полной выгрузке (порог `queryCandidatesMax`), пустые результаты терма — пустой список,
    /// `NOT` по тексту — дополнение.
    #[tokio::test]
    async fn text_query_candidates() {
        use crate::JmapConfig;

        let env = Env::new().await;
        let m = fixture(&env).await;
        assert_eq!(
            ids(&env, json!({"filter": {"text": "несуществуемое"}})).await,
            json!([])
        );
        assert_eq!(
            ids(
                &env,
                json!({"filter": {"text": "отчёт", "hasKeyword": "$seen"}})
            )
            .await,
            json!([m[0]])
        );
        let few = JmapConfig {
            query_candidates_max: 1,
            ..Default::default()
        };
        let env = Env::with(few, Vec::new()).await;
        let m = fixture(&env).await;
        assert_eq!(
            ids(&env, json!({"filter": {"text": "квартал"}})).await,
            json!([m[1], m[0]])
        );
        assert_eq!(
            ids(
                &env,
                json!({"filter": {"operator": "NOT", "conditions": [{"text": "квартал"}]}})
            )
            .await,
            json!([m[3], m[2]])
        );
    }
}
