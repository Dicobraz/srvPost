//! Службы ролей узла в Rpc (APP-46, SRS 2.8, Ф3): запросы узел → узел обслуживают включённые роли —
//! `search/query` (поиск по индексам ящиков на узле-владельце, роль search) и `admin/state` (состояние
//! узла для администрирования, роль admin). Матрица разрешений «роль → службы» — `cluster.rpc.permissions`
//! на принимающем узле (tp-cluster). Остальные службы ролей — карточки своих полос.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tp_contracts::Error;
use tp_contracts::Result;
use tp_contracts::ids::MailboxId;
use tp_contracts::load::{LoadLevel, LoadMonitor};
use tp_contracts::membership::NodeId;
use tp_contracts::meta::AccountScope;
use tp_contracts::rpc::{RpcHandler, RpcRequest};
use tp_contracts::search::{SearchIndex, SearchSort, TextQuery};
use tp_platform::service_http::Health;
use tp_search::Search;

/// Имя службы поиска роли search (`search/query`).
pub const SEARCH_QUERY: &str = "query";

/// Имя службы состояния узла роли admin (`admin/state`).
pub const NODE_STATE: &str = "state";

/// Запрос [`SearchQuery`]: ключ вызова — `<tenant>/<учётная запись>`, тело — условия поиска.
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchQueryRequest {
    /// Организация.
    pub tenant: tp_contracts::TenantId,
    /// Учётная запись.
    pub account: tp_contracts::AccountId,
    /// Папки поиска (пусто — все папки).
    #[serde(default)]
    pub mailboxes: Vec<MailboxId>,
    /// Условия поиска (дерево текстовых условий).
    pub q: TextQuery,
    /// Порядок результатов.
    #[serde(default)]
    pub sort: SearchSort,
    /// Не больше писем в ответе.
    pub limit: usize,
}

/// Обработчик `search/query`: поиск по индексам ящиков этого узла (`Search` узла, SRS 2.8 — «поиск по
/// индексу на узле-владельце»). Ответ — JSON-массив идентификаторов писем; письма, которых уже нет,
/// вызывающий отбрасывает (индекс может отставать).
#[derive(Debug)]
pub struct SearchQuery {
    search: Arc<Search>,
}

impl SearchQuery {
    /// Обработчик поиска узла `search`.
    pub fn new(search: Arc<Search>) -> Self {
        Self { search }
    }
}

#[async_trait]
impl RpcHandler for SearchQuery {
    async fn handle(&self, request: RpcRequest) -> Result<Bytes> {
        let q: SearchQueryRequest = serde_json::from_slice(&request.body)
            .map_err(|e| Error::invalid(format!("search/query: {e}")))?;
        let ids = SearchIndex::query(
            &*self.search,
            AccountScope {
                tenant: q.tenant,
                account: q.account,
            },
            &q.mailboxes,
            &q.q,
            q.sort,
            q.limit,
        )
        .await?;
        let out =
            serde_json::to_vec(&ids).map_err(|e| Error::internal(format!("search/query: {e}")))?;
        Ok(Bytes::from(out))
    }
}

/// Состояние узла для администрирования ([`NodeState`], SRS 2.8 — «состояние узлов для администрирования»).
#[derive(Debug, Serialize)]
pub struct NodeStateReport {
    /// Имя узла в членстве.
    pub node: NodeId,
    /// Версия сборки.
    pub version: &'static str,
    /// Узел готов (не drain, все роли готовы).
    pub ready: bool,
    /// Узел выводится из пула (drain).
    pub draining: bool,
    /// Уровень нагрузки узла.
    pub load: LoadLevel,
    /// Роли узла и их готовность.
    pub roles: Vec<RoleStatus>,
}

/// Готовность одной роли узла.
#[derive(Debug, Serialize)]
pub struct RoleStatus {
    /// Роль.
    pub role: String,
    /// Готова принимать работу.
    pub ready: bool,
}

/// Обработчик `admin/state`: снимок состояния этого узла (готовность, роли, уровень нагрузки) для Admin API.
pub struct NodeState {
    node: NodeId,
    health: Health,
    load: Arc<dyn LoadMonitor>,
}

impl std::fmt::Debug for NodeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeState")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

impl NodeState {
    /// Обработчик состояния узла `node`: готовность ролей — `health`, уровень нагрузки — `load`.
    pub fn new(node: NodeId, health: Health, load: Arc<dyn LoadMonitor>) -> Self {
        Self { node, health, load }
    }
}

#[async_trait]
impl RpcHandler for NodeState {
    async fn handle(&self, _request: RpcRequest) -> Result<Bytes> {
        let report = NodeStateReport {
            node: self.node.clone(),
            version: env!("CARGO_PKG_VERSION"),
            ready: self.health.is_ready(),
            draining: self.health.is_draining(),
            load: *self.load.subscribe().borrow(),
            roles: self
                .health
                .roles_status()
                .into_iter()
                .map(|(role, ready)| RoleStatus { role, ready })
                .collect(),
        };
        let out = serde_json::to_vec(&report)
            .map_err(|e| Error::internal(format!("admin/state: {e}")))?;
        Ok(Bytes::from(out))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use tp_contracts::ids::AccountId;
    use tp_contracts::load::fixed_load;
    use tp_contracts::search::TextField;

    fn request(key: &str, body: Bytes) -> RpcRequest {
        RpcRequest {
            caller: NodeId::new("node-a").expect("node"),
            key: key.to_owned(),
            body,
            deadline: Duration::from_secs(5),
        }
    }

    /// `search/query`: разбор тела, поиск (учётная запись без индекса — пустой ответ) и ответ JSON.
    #[tokio::test]
    async fn search_query_returns_empty_for_unknown_account() {
        let dir = tempfile::tempdir().expect("tempdir");
        let indexes = Arc::new(tp_search::IndexManager::new(tp_search::IndexConfig {
            dir: dir.path().to_owned(),
            ..tp_search::IndexConfig::default()
        }));
        let search = Arc::new(Search::new(indexes, tp_search::QueryConfig::default()));
        let handler = SearchQuery::new(search);
        let body = serde_json::to_vec(&SearchQueryRequest {
            tenant: tp_contracts::TenantId::DEFAULT,
            account: AccountId::new(),
            mailboxes: Vec::new(),
            q: TextQuery::Term {
                field: TextField::Subject,
                text: "письмо".into(),
            },
            sort: SearchSort::default(),
            limit: 10,
        })
        .expect("body");
        let out = handler
            .handle(request("default/unknown", Bytes::from(body)))
            .await
            .expect("handle");
        let ids: Vec<tp_contracts::MessageId> = serde_json::from_slice(&out).expect("ids");
        assert!(ids.is_empty(), "{ids:?}");
    }

    /// `search/query`: неразборчивое тело — `Invalid`, значение тела в текст ошибки не попадает.
    #[tokio::test]
    async fn search_query_rejects_bad_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        let indexes = Arc::new(tp_search::IndexManager::new(tp_search::IndexConfig {
            dir: dir.path().to_owned(),
            ..tp_search::IndexConfig::default()
        }));
        let handler = SearchQuery::new(Arc::new(Search::new(
            indexes,
            tp_search::QueryConfig::default(),
        )));
        let e = handler
            .handle(request("x", Bytes::from_static(b"not json")))
            .await
            .expect_err("bad body");
        assert!(matches!(e, Error::Invalid(_)), "{e:?}");
    }

    /// `admin/state`: снимок готовности ролей и уровня нагрузки.
    #[tokio::test]
    async fn node_state_reports_roles_and_load() {
        let health = Health::default();
        let ready = health.register("imap");
        ready.set(true);
        let handler = NodeState::new(
            NodeId::new("node-a").expect("node"),
            health,
            fixed_load(LoadLevel::Elevated),
        );
        let out = handler
            .handle(request("", Bytes::new()))
            .await
            .expect("handle");
        let report: serde_json::Value = serde_json::from_slice(&out).expect("report");
        assert_eq!(report["node"], "node-a");
        assert_eq!(report["ready"], serde_json::json!(false), "{report}");
        assert_eq!(report["draining"], serde_json::json!(false));
        assert_eq!(report["load"], "elevated");
        assert_eq!(report["roles"][0]["role"], "imap");
        assert_eq!(report["roles"][0]["ready"], serde_json::json!(true));
    }
}
