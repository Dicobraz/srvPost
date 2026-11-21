//! Учёт параллельных сессий учётных записей (WEB-12): лимит `jmap.session_limit`, окно активности
//! `jmap.session_window`. Активная сессия —
//! - соединение push учётной записи (EventSource, WebSocket): считается ровно, пока соединение открыто
//!   ([`Sessions::enter_push`], слот освобождается при закрытии);
//! - доступ HTTP-клиента (ключ — учётные данные: токен Bearer или пара «вход:пароль»): считается с
//!   последней активностью в окне ([`Sessions::enter`], сессия, запрос API, загрузка, скачивание).
//!
//! Один клиент с одним токеном — одна HTTP-сессия (вкладки одного браузера не размножают сессии);
//! разные клиенты (веб, Postman, Thunderbird) — разные ключи. Клиент, открывший и push, и HTTP-запросы,
//! занимает два слота (счёт консервативный). Превышение — структурированная ошибка
//! `urn:ietf:params:jmap:error:limit` ([`crate::core::Problem::session_limit`]): как у Exchange и Gmail,
//! новые сессии не принимаются, а активные не вытесняются. Окно освобождает слот сессии без активности
//! дольше окна — упавший клиент не держит лимит, как тайм-аут простоя IMAP Gmail.
//!
//! Состояние — в памяти узла (как соединения push `crate::disable::Sessions` и слоты одновременных
//! запросов): в кластере лимит действует на узел; честный учёт на кластер потребовал бы общего
//! состояния узлов (precedent в кодовой базе нет) — ограничение v1, описано в PR.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tp_contracts::auth::Credentials;
use tp_contracts::meta::AccountScope;

/// Полная чистка истёкших HTTP-сессий всех учётных записей — каждые столько касаний (истёкшие записи
/// своей учётной записи снимаются при каждом касании).
const SWEEP_EVERY: usize = 1024;

/// Ключ HTTP-сессии клиента: первые 8 байт SHA-256 учётных данных (токен или пара «вход:пароль»).
/// Секрет не хранится; совпадение хэшей разных клиентов для десятков сессий одной записи пренебрежимо.
pub(crate) fn session_key(creds: &Credentials) -> u64 {
    let text = match creds {
        Credentials::Password { login, secret } => format!("password:{login}\0{secret}"),
        Credentials::Bearer(token) => format!("bearer:{token}"),
        Credentials::Gssapi { principal, authzid } => {
            format!("gssapi:{principal}\0{}", authzid.as_deref().unwrap_or(""))
        }
    };
    u64::from_be_bytes(
        Sha256::digest(text.as_bytes())[..8]
            .try_into()
            .expect("8 байт"),
    )
}

/// Активные сессии одной учётной записи.
#[derive(Default)]
struct Active {
    /// Соединения push (EventSource, WebSocket) — идентификаторы открытых соединений.
    push: HashSet<u64>,
    /// HTTP-сессии: ключ доступа → последняя активность.
    recent: HashMap<u64, Instant>,
}

#[derive(Default)]
struct State {
    accounts: HashMap<AccountScope, Active>,
    next: u64,
    touches: usize,
}

/// Учёт сессий сервера; состояние общее для всех запросов (`Arc` — для слотов соединений push).
#[derive(Clone)]
pub(crate) struct Sessions {
    inner: Arc<SessionsInner>,
}

struct SessionsInner {
    /// Наибольшее число параллельных сессий учётной записи; `0` — учёт выключен.
    limit: u32,
    window: Duration,
    state: Mutex<State>,
}

impl Sessions {
    /// Учёт с лимитом и окном из конфига (`jmap.session_limit`, `jmap.session_window`).
    pub(crate) fn new(limit: u32, window: Duration) -> Self {
        Self {
            inner: Arc::new(SessionsInner {
                limit,
                window,
                state: Mutex::new(State::default()),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Сколько сессий учётной записи учитывается сейчас: истёкшие окна снимаются (диагностика и тесты).
    pub(crate) fn count(&self, scope: AccountScope) -> usize {
        if self.inner.limit == 0 {
            return 0;
        }
        let mut state = self.lock();
        let mut inner = Inner {
            state: &mut state,
            limit: self.inner.limit,
            window: self.inner.window,
        };
        inner.expire(scope, Instant::now());
        inner.count(scope)
    }

    /// Пускает HTTP-сессию клиента `key` учётной записи `scope`: обновляет активность или занимает
    /// слот; `false` — лимит достигнут (новая сессия не принимается,
    /// [`crate::core::Problem::session_limit`]).
    pub(crate) fn enter(&self, scope: AccountScope, key: u64) -> bool {
        if self.inner.limit == 0 {
            return true;
        }
        let mut state = self.lock();
        let mut inner = Inner {
            state: &mut state,
            limit: self.inner.limit,
            window: self.inner.window,
        };
        inner.enter(scope, key, Instant::now())
    }

    /// Регистрирует соединение push учётной записи; `None` — лимит достигнут. Слот освобождается при
    /// закрытии соединения ([`PushSession::Drop`]).
    pub(crate) fn enter_push(&self, scope: AccountScope) -> Option<PushSession> {
        if self.inner.limit == 0 {
            return Some(PushSession {
                sessions: self.clone(),
                scope,
                id: 0,
            });
        }
        let mut state = self.lock();
        {
            let mut inner = Inner {
                state: &mut state,
                limit: self.inner.limit,
                window: self.inner.window,
            };
            inner.sweep();
            inner.expire(scope, Instant::now());
        }
        let limit = self.inner.limit as usize;
        let state: &mut State = &mut state;
        let busy = match state.accounts.get(&scope) {
            Some(a) => a.push.len() + a.recent.len(),
            None => 0,
        };
        if busy >= limit {
            return None;
        }
        state.next += 1;
        let id = state.next;
        state.accounts.entry(scope).or_default().push.insert(id);
        Some(PushSession {
            sessions: self.clone(),
            scope,
            id,
        })
    }
}

/// Слот соединения push: держится, пока соединение открыто.
pub(crate) struct PushSession {
    sessions: Sessions,
    scope: AccountScope,
    /// `0` — учёт выключен, слота нет.
    id: u64,
}

impl Drop for PushSession {
    fn drop(&mut self) {
        if self.id == 0 {
            return;
        }
        let mut state = self.sessions.lock();
        let empty = {
            let Some(active) = state.accounts.get_mut(&self.scope) else {
                return;
            };
            active.push.remove(&self.id);
            active.push.is_empty() && active.recent.is_empty()
        };
        if empty {
            state.accounts.remove(&self.scope);
        }
    }
}

/// Операции над состоянием с известными лимитами; `enter` тестируется с произвольным `now`.
struct Inner<'a> {
    state: &'a mut State,
    limit: u32,
    window: Duration,
}

impl Inner<'_> {
    /// Сколько сессий учётной записи учитывается: соединения push и HTTP-сессии в окне.
    fn count(&self, scope: AccountScope) -> usize {
        match self.state.accounts.get(&scope) {
            Some(active) => active.push.len() + active.recent.len(),
            None => 0,
        }
    }

    fn enter(&mut self, scope: AccountScope, key: u64, now: Instant) -> bool {
        self.state.touches += 1;
        if self.state.touches >= SWEEP_EVERY {
            self.sweep();
        }
        self.expire(scope, now);
        let limit = self.limit as usize;
        let state = &mut *self.state;
        let active = state.accounts.entry(scope).or_default();
        if active.recent.contains_key(&key) {
            active.recent.insert(key, now);
            return true;
        }
        if active.push.len() + active.recent.len() >= limit {
            return false;
        }
        active.recent.insert(key, now);
        true
    }

    /// Снимает HTTP-сессии учётной записи без активности дольше окна; опустевшая запись учётной
    /// записи удаляется.
    fn expire(&mut self, scope: AccountScope, now: Instant) {
        let Some(active) = self.state.accounts.get_mut(&scope) else {
            return;
        };
        active
            .recent
            .retain(|_, at| now.duration_since(*at) <= self.window);
        if active.push.is_empty() && active.recent.is_empty() {
            self.state.accounts.remove(&scope);
        }
    }

    /// Полная чистка: истёкшие HTTP-сессии и пустые учётные записи.
    fn sweep(&mut self) {
        self.state.touches = 0;
        for scope in self.state.accounts.keys().copied().collect::<Vec<_>>() {
            self.expire(scope, Instant::now());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tracker(limit: u32) -> Sessions {
        Sessions::new(limit, Duration::from_secs(300))
    }

    fn scope() -> AccountScope {
        AccountScope {
            tenant: tp_contracts::TenantId::new(),
            account: tp_contracts::AccountId::new(),
        }
    }

    fn at(offset_secs: u64) -> Instant {
        Instant::now() + Duration::from_secs(offset_secs)
    }

    /// N сессий при лимите N входят, N+1-я — нет, первые не страдают.
    #[test]
    fn limit_n_plus_one() {
        let s = tracker(2);
        let scope = scope();
        assert!(s.enter(scope, 1), "первая сессия");
        assert!(s.enter(scope, 2), "вторая сессия");
        assert!(!s.enter(scope, 3), "третья сверх лимита");
        assert!(s.enter(scope, 1), "принятая сессия не страдает");
        assert_eq!(s.count(scope), 2);
    }

    /// Лимит общий для учётной записи: HTTP-сессии и соединения push занимают одни слоты.
    #[test]
    fn push_and_http_share_limit() {
        let s = tracker(2);
        let scope = scope();
        let a = s.enter_push(scope).expect("push первой");
        assert!(s.enter(scope, 1), "http второй");
        assert!(s.enter_push(scope).is_none(), "push третьей сверх лимита");
        assert!(s.enter(scope, 2).is_none(), "http третьей сверх лимита");
        assert!(s.enter(scope, 1), "активная не страдает");
        drop(a);
        assert!(s.enter(scope, 2), "слот освободился с закрытием push");
        assert_eq!(s.count(scope), 1);
    }

    /// HTTP-сессия без активности дольше окна освобождает слот; активность продлевает.
    #[test]
    fn window_expires() {
        let window = Duration::from_secs(100);
        let s = Sessions::new(2, window);
        let scope = scope();
        let t0 = at(0);
        {
            let mut state = s.lock();
            let mut inner = Inner {
                state: &mut state,
                limit: 2,
                window,
            };
            assert!(inner.enter(scope, 1, t0));
            // На границе окна живы обе.
            assert!(inner.enter(scope, 2, t0 + window));
            assert!(inner.enter(scope, 1, t0 + window), "активность продлевает");
            // Спустя окно без активности обе истекли — третья входит.
            assert!(inner.enter(scope, 3, t0 + 2 * window + Duration::from_secs(1)));
            assert_eq!(inner.count(scope), 1);
        }
        assert_eq!(s.count(scope), 1);
    }

    /// Учётные записи не зависят: чужая — под своим лимитом.
    #[test]
    fn accounts_are_independent() {
        let s = tracker(1);
        let (a, b) = (scope(), scope());
        assert!(s.enter(a, 1));
        assert!(!s.enter(a, 2));
        assert!(s.enter(b, 1), "чужая учётная запись под своим лимитом");
        assert_eq!(s.count(a), 1);
        assert_eq!(s.count(b), 1);
    }

    /// Учёт выключен (`limit = 0`) — лимита нет и счётчик пуст.
    #[test]
    fn disabled() {
        let s = tracker(0);
        let scope = scope();
        for key in 0..10 {
            assert!(s.enter(scope, key));
        }
        assert!(s.enter_push(scope).is_some());
        assert_eq!(s.count(scope), 0);
    }

    /// Ключ сессии — из учётных данных: разные токены — разные сессии, один токен — одна.
    #[test]
    fn keys_from_credentials() {
        let token = |t: &str| Credentials::Bearer(t.into());
        let pass = |l: &str, s: &str| Credentials::Password {
            login: l.into(),
            secret: s.into(),
        };
        assert_ne!(session_key(&token("a")), session_key(&token("b")));
        assert_ne!(session_key(&token("a")), session_key(&pass("a", "b")));
        assert_eq!(
            session_key(&pass("u@x.test", "secret")),
            session_key(&pass("u@x.test", "secret"))
        );
    }
}
