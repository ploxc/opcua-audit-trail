//! OPC UA browser for the web UI.
//!
//! Each UI user gets their own session per target, opened directly to the
//! upstream server with the gateway's certificate and the login the user
//! enters in the UI (never stored). The browser is read-only.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use opcua::client::{ClientBuilder, IdentityToken, Password, Session};
use opcua::crypto::{CertificateStore, SecurityPolicy};
use opcua::types::{
    AttributeId, BrowseDescription, BrowseDirection, BrowseResultMask, DataValue,
    EndpointDescription, NodeClassMask, NodeId, ReadValueId, ReferenceTypeId, TimestampsToReturn,
    UserTokenType,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::auth::AuthUser;
use super::{ApiError, ApiResult, AppState};
use crate::audit::event::{AuditValue, ClientContext, UserIdentity};
use crate::audit::{AuditEntry, AuditEvent};
use crate::relay::audit_map::audit_value;
use crate::relay::endpoints::is_relayable_token;
use crate::users::Role;

const IDLE_TIMEOUT: Duration = Duration::from_secs(600);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_BROWSE_PAGES: usize = 20;

struct Entry {
    session: Arc<Session>,
    /// The session's event loop; once it ends, the session is dead.
    event_loop: tokio::task::JoinHandle<opcua::types::StatusCode>,
    last_used: Instant,
    ui_user: String,
    target: String,
}

#[derive(Default)]
pub struct BrowserSessions {
    map: Mutex<HashMap<(String, String), Entry>>,
}

impl BrowserSessions {
    /// The user's live session on the target. A session whose connection
    /// ended (PLC restart, network) is dropped, so the UI can reconnect.
    fn get(&self, user: &str, target: &str) -> Option<Arc<Session>> {
        let key = (user.to_string(), target.to_string());
        let mut map = self.map.lock();
        let entry = map.get_mut(&key)?;
        if entry.event_loop.is_finished() {
            map.remove(&key);
            return None;
        }
        entry.last_used = Instant::now();
        Some(entry.session.clone())
    }

    /// Ends every browser session of a UI user (deleted, lost the role).
    pub async fn close_user(&self, state: &AppState, user: &str) {
        let entries: Vec<Entry> = {
            let mut map = self.map.lock();
            let keys: Vec<_> = map.keys().filter(|(u, _)| u == user).cloned().collect();
            keys.into_iter().filter_map(|k| map.remove(&k)).collect()
        };
        for entry in entries {
            close(state, entry).await;
        }
    }

    /// Ends every browser session on a target (removed or changed).
    pub async fn close_target(&self, state: &AppState, target: &str) {
        let entries: Vec<Entry> = {
            let mut map = self.map.lock();
            let keys: Vec<_> = map.keys().filter(|(_, t)| t == target).cloned().collect();
            keys.into_iter().filter_map(|k| map.remove(&k)).collect()
        };
        for entry in entries {
            close(state, entry).await;
        }
    }

    fn take(&self, user: &str, target: &str) -> Option<Entry> {
        self.map
            .lock()
            .remove(&(user.to_string(), target.to_string()))
    }

    /// Closes sessions nobody used for a while. Runs until the process ends.
    pub async fn reap_idle(self: Arc<Self>, state: AppState) {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let idle: Vec<Entry> = {
                let mut map = self.map.lock();
                let keys: Vec<_> = map
                    .iter()
                    .filter(|(_, e)| e.last_used.elapsed() > IDLE_TIMEOUT)
                    .map(|(k, _)| k.clone())
                    .collect();
                keys.into_iter().filter_map(|k| map.remove(&k)).collect()
            };
            for entry in idle {
                close(&state, entry).await;
            }
        }
    }
}

fn browser_client(ui_user: &str) -> ClientContext {
    ClientContext {
        remote_addr: "web-ui".into(),
        application_name: Some("Gateway web browser".into()),
        user: Some(UserIdentity::UserName {
            name: format!("ui:{ui_user}"),
        }),
        ..Default::default()
    }
}

async fn close(state: &AppState, entry: Entry) {
    let _ = entry.session.disconnect().await;
    let entry_record = AuditEntry::new(AuditEvent::SessionClosed)
        .target(entry.target)
        .client(browser_client(&entry.ui_user));
    let _ = state.audit.record(entry_record).await;
}

#[derive(Deserialize)]
pub struct ConnectRequest {
    /// Login on the upstream server; anonymous when absent.
    username: Option<String>,
    password: Option<String>,
}

#[derive(Serialize)]
pub struct ConnectResponse {
    security_policy: String,
    security_mode: String,
    user: String,
}

/// The most secure endpoint that supports the requested login type, by the
/// gateway's own ranking (the server's `security_level` comes from an
/// unauthenticated answer). A password is never sent in the clear: a user
/// name login needs a secured channel or an encrypting token policy.
fn pick_endpoint(
    endpoints: &[EndpointDescription],
    token: UserTokenType,
) -> Option<EndpointDescription> {
    let mut candidates: Vec<_> = endpoints
        .iter()
        .filter(|e| {
            let policy = SecurityPolicy::from_uri(e.security_policy_uri.as_ref());
            policy != SecurityPolicy::Unknown
                && policy.is_supported()
                && e.user_identity_tokens.iter().flatten().any(|t| {
                    t.token_type == token
                        && is_relayable_token(t)
                        && (token != UserTokenType::UserName
                            || policy != SecurityPolicy::None
                            || !matches!(
                                SecurityPolicy::from_uri(t.security_policy_uri.as_ref()),
                                SecurityPolicy::None | SecurityPolicy::Unknown
                            ))
                })
        })
        .collect();
    candidates.sort_by_key(|e| {
        std::cmp::Reverse((crate::relay::endpoints::security_of(e), e.security_level))
    });
    candidates.first().map(|e| (*e).clone())
}

pub async fn connect(
    State(s): State<AppState>,
    user: AuthUser,
    Path(target_name): Path<String>,
    Json(req): Json<ConnectRequest>,
) -> ApiResult<ConnectResponse> {
    user.require(Role::Operator)?;
    let relay = s
        .targets
        .relay(&target_name)
        .await
        .ok_or_else(|| ApiError::not_found(format!("unknown target '{target_name}'")))?;
    if let Some(old) = s.browser.take(&user.username, &target_name) {
        close(&s, old).await;
    }

    let (identity, token_type, login) = match (req.username.filter(|u| !u.is_empty()), req.password)
    {
        (Some(u), p) => (
            IdentityToken::UserName(u.clone(), Password::new(p.unwrap_or_default())),
            UserTokenType::UserName,
            u,
        ),
        (None, _) => (
            IdentityToken::Anonymous,
            UserTokenType::Anonymous,
            "anonymous".into(),
        ),
    };
    let endpoints = relay.upstream_endpoints().await.map_err(|status| {
        ApiError(
            StatusCode::BAD_GATEWAY,
            format!("target unreachable: {status}"),
        )
    })?;
    let mut endpoint = pick_endpoint(&endpoints, token_type).ok_or_else(|| {
        ApiError::bad_request(anyhow::anyhow!(
            "the target offers no endpoint for this kind of login (a password is only sent \
             over a secured channel or encrypted)"
        ))
    })?;
    // Trust is checked on connect, but not the validity dates (see below).
    if SecurityPolicy::from_uri(endpoint.security_policy_uri.as_ref()) != SecurityPolicy::None {
        let cert = opcua::crypto::X509::from_byte_string(&endpoint.server_certificate)
            .map_err(|e| ApiError::bad_request(anyhow::anyhow!("server certificate: {e}")))?;
        if cert.is_time_valid(&chrono::Utc::now()).is_err() {
            return Err(ApiError::bad_request(anyhow::anyhow!(
                "the target's certificate is expired or not yet valid"
            )));
        }
    }
    // Connect to the configured URL, not the (possibly unreachable) host name
    // the server advertises.
    endpoint.endpoint_url = relay.config.endpoint_url.as_str().into();

    let pki_dir = s.config.gateway.pki_dir.clone();
    let mut store = CertificateStore::new(&pki_dir);
    // Trust is still checked. Skipped are the host name and application URI
    // checks (PLC certificates often lack the address they are reached by)
    // and, by async-opcua, the validity dates, which are checked above.
    store.set_skip_verify_certs(true);
    let client = ClientBuilder::new()
        .application_name(s.config.gateway.application_name.clone())
        .application_uri(s.config.gateway.application_uri())
        .pki_dir(pki_dir)
        .create_sample_keypair(false)
        .session_retry_limit(0)
        .session_name(format!("Gateway web browser ({})", user.username))
        .client()
        .map_err(|e| anyhow::anyhow!(e.join("; ")))?;
    let (session, event_loop) = client
        .session_builder()
        .connect_to_endpoint_directly(endpoint.clone())
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .user_identity_token(identity)
        .build(Arc::new(opcua::core::sync::RwLock::new(store)))
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut handle = event_loop.spawn();
    // A refused connection (e.g. an untrusted certificate) ends the event
    // loop at once; don't wait for the timeout then.
    let (connected, ended) = tokio::select! {
        c = tokio::time::timeout(CONNECT_TIMEOUT, session.wait_for_connection()) => {
            (c.unwrap_or(false), None)
        }
        status = &mut handle => (false, Some(status)),
    };
    if !connected {
        let status = match ended {
            Some(status) => status.ok(),
            None => {
                handle.abort();
                handle.await.ok()
            }
        };
        let hint = match status {
            Some(s)
                if format!("{s}").contains("Certificate")
                    || format!("{s}").contains("Security") =>
            {
                "Trust the target's server certificate first (Targets page)."
            }
            _ => "Is the target's certificate trusted, and the login right?",
        };
        return Err(ApiError(
            StatusCode::BAD_GATEWAY,
            format!(
                "could not open a session on the target{}. {hint}",
                status.map(|s| format!(" ({s})")).unwrap_or_default()
            ),
        ));
    }

    let entry = AuditEntry::new(AuditEvent::SessionCreated {
        session_name: format!("web browser as {login}"),
    })
    .target(target_name.clone())
    .client(browser_client(&user.username));
    let _ = s.audit.record_committed(entry).await;
    let replaced = s.browser.map.lock().insert(
        (user.username.clone(), target_name.clone()),
        Entry {
            session,
            event_loop: handle,
            last_used: Instant::now(),
            ui_user: user.username.clone(),
            target: target_name,
        },
    );
    // Two connects at once: close the session that lost, not leak it.
    if let Some(old) = replaced {
        close(&s, old).await;
    }
    let policy = SecurityPolicy::from_uri(endpoint.security_policy_uri.as_ref());
    Ok(Json(ConnectResponse {
        security_policy: policy.to_str().into(),
        security_mode: format!("{:?}", endpoint.security_mode),
        user: login,
    }))
}

pub async fn disconnect(
    State(s): State<AppState>,
    user: AuthUser,
    Path(target): Path<String>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Operator)?;
    if let Some(entry) = s.browser.take(&user.username, &target) {
        close(&s, entry).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

fn session(s: &AppState, user: &AuthUser, target: &str) -> Result<Arc<Session>, ApiError> {
    user.require(Role::Operator)?;
    s.browser.get(&user.username, target).ok_or_else(|| {
        ApiError(
            StatusCode::CONFLICT,
            "not connected to this target; connect first".into(),
        )
    })
}

fn parse_node(node: &str) -> Result<NodeId, ApiError> {
    NodeId::from_str(node)
        .map_err(|_| ApiError::bad_request(anyhow::anyhow!("invalid node id '{node}'")))
}

#[derive(Deserialize)]
pub struct NodeQuery {
    node: Option<String>,
}

#[derive(Serialize)]
pub struct BrowseItem {
    node_id: String,
    browse_name: String,
    display_name: String,
    node_class: String,
    /// Whether the node has children the tree can unfold.
    has_children: bool,
}

/// Hierarchical references followed by the tree.
fn children_of(node: NodeId) -> BrowseDescription {
    BrowseDescription {
        node_id: node,
        browse_direction: BrowseDirection::Forward,
        reference_type_id: ReferenceTypeId::HierarchicalReferences.into(),
        include_subtypes: true,
        node_class_mask: NodeClassMask::empty().bits(),
        result_mask: BrowseResultMask::None as u32,
    }
}

/// Finds the nodes without children, with one browse (one reference per
/// node) per batch of nodes. On error, every node keeps its arrow.
async fn mark_leaves(session: &Session, items: &mut [(NodeId, BrowseItem)]) {
    for batch in items.chunks_mut(100) {
        let descriptions: Vec<_> = batch.iter().map(|(n, _)| children_of(n.clone())).collect();
        let Ok(results) = session.browse(&descriptions, 1, None).await else {
            return;
        };
        let mut continuation_points = Vec::new();
        for ((_, item), result) in batch.iter_mut().zip(&results) {
            if result.status_code.is_good() {
                item.has_children = result.references.as_ref().is_some_and(|r| !r.is_empty());
            }
            if !result.continuation_point.is_null_or_empty() {
                continuation_points.push(result.continuation_point.clone());
            }
        }
        // Servers keep few continuation points: release them right away.
        if !continuation_points.is_empty() {
            let _ = session.browse_next(true, &continuation_points).await;
        }
    }
}

pub async fn browse(
    State(s): State<AppState>,
    user: AuthUser,
    Path(target): Path<String>,
    Query(q): Query<NodeQuery>,
) -> ApiResult<Vec<BrowseItem>> {
    let session = session(&s, &user, &target)?;
    let node = match q.node.as_deref() {
        Some(n) => parse_node(n)?,
        None => opcua::types::ObjectId::ObjectsFolder.into(),
    };
    let description = BrowseDescription {
        result_mask: BrowseResultMask::All as u32,
        ..children_of(node)
    };
    let upstream = |e: opcua::types::Error| ApiError(StatusCode::BAD_GATEWAY, e.to_string());
    let mut results = session
        .browse(&[description], 0, None)
        .await
        .map_err(upstream)?;
    let mut items = Vec::new();
    for _ in 0..MAX_BROWSE_PAGES {
        let Some(result) = results.pop() else { break };
        if result.status_code.is_bad() {
            return Err(ApiError(
                StatusCode::BAD_GATEWAY,
                result.status_code.to_string(),
            ));
        }
        items.extend(result.references.iter().flatten().map(|r| {
            (
                r.node_id.node_id.clone(),
                BrowseItem {
                    node_id: r.node_id.node_id.to_string(),
                    browse_name: r.browse_name.to_string(),
                    display_name: r.display_name.text.as_ref().to_string(),
                    node_class: format!("{:?}", r.node_class),
                    has_children: true,
                },
            )
        }));
        if result.continuation_point.is_null_or_empty() {
            break;
        }
        results = session
            .browse_next(false, &[result.continuation_point])
            .await
            .map_err(upstream)?;
    }
    mark_leaves(&session, &mut items).await;
    Ok(Json(items.into_iter().map(|(_, item)| item).collect()))
}

#[derive(Serialize)]
pub struct AttributeItem {
    attribute: String,
    /// Absent when the server returned only a status.
    value: Option<AuditValue>,
    /// Not Good: the status code, e.g. `BadWaitingForInitialData (0x80320000)`.
    status: Option<String>,
    status_description: Option<String>,
    /// For the Value attribute.
    source_timestamp: Option<String>,
    server_timestamp: Option<String>,
    /// A readable form, e.g. the name of a standard data type.
    note: Option<String>,
}

/// All attributes of a node, including those the server answers with a bad
/// status (e.g. a value it has not received yet); attributes the node does
/// not have are left out.
pub async fn attributes(
    State(s): State<AppState>,
    user: AuthUser,
    Path(target): Path<String>,
    Query(q): Query<NodeQuery>,
) -> ApiResult<Vec<AttributeItem>> {
    let session = session(&s, &user, &target)?;
    let node = parse_node(q.node.as_deref().unwrap_or_default())?;
    let ids: Vec<u32> = (1..=27).collect();
    let reads: Vec<ReadValueId> = ids
        .iter()
        .map(|&attribute_id| ReadValueId {
            node_id: node.clone(),
            attribute_id,
            ..Default::default()
        })
        .collect();
    let values = session
        .read(&reads, TimestampsToReturn::Both, 0.0)
        .await
        .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(
        ids.iter()
            .zip(values)
            .filter_map(|(&id, v)| attribute_item(id, v))
            .collect(),
    ))
}

fn attribute_item(id: u32, v: DataValue) -> Option<AttributeItem> {
    let status = v.status.unwrap_or_default();
    if status == opcua::types::StatusCode::BadAttributeIdInvalid
        || (status.is_good() && v.value.is_none())
    {
        return None;
    }
    let attribute = AttributeId::from_u32(id).ok();
    let time = |t: Option<opcua::types::DateTime>| {
        t.filter(|t| !t.is_null())
            .map(|t| t.as_chrono().to_rfc3339())
    };
    let is_value = attribute == Some(AttributeId::Value);
    let note = match (&attribute, &v.value) {
        (Some(AttributeId::DataType), Some(opcua::types::Variant::NodeId(n)))
            if n.namespace == 0 =>
        {
            match &n.identifier {
                opcua::types::Identifier::Numeric(i) => {
                    opcua::types::DataTypeId::try_from(i.to_owned())
                        .ok()
                        .map(|t| format!("{t:?}"))
                }
                _ => None,
            }
        }
        _ => None,
    };
    Some(AttributeItem {
        attribute: attribute
            .map(|a| format!("{a:?}"))
            .unwrap_or_else(|| id.to_string()),
        value: v.value.as_ref().map(audit_value),
        status: (!status.is_good()).then(|| format!("{status} (0x{:08X})", status.bits())),
        status_description: (!status.is_good())
            .then(|| status.sub_code().description().to_string()),
        source_timestamp: if is_value {
            time(v.source_timestamp)
        } else {
            None
        },
        server_timestamp: if is_value {
            time(v.server_timestamp)
        } else {
            None
        },
        note,
    })
}

#[derive(Deserialize)]
pub struct ValuesRequest {
    nodes: Vec<String>,
}

#[derive(Serialize)]
pub struct ValueItem {
    node_id: String,
    value: Option<AuditValue>,
    status: String,
    source_timestamp: Option<String>,
}

/// Current values of a set of nodes (the UI polls this for live values).
pub async fn values(
    State(s): State<AppState>,
    user: AuthUser,
    Path(target): Path<String>,
    Json(req): Json<ValuesRequest>,
) -> ApiResult<Vec<ValueItem>> {
    let session = session(&s, &user, &target)?;
    if req.nodes.len() > 500 {
        return Err(ApiError::bad_request(anyhow::anyhow!(
            "at most 500 nodes per request"
        )));
    }
    let nodes: Vec<NodeId> = req
        .nodes
        .iter()
        .map(|n| parse_node(n))
        .collect::<Result<_, _>>()?;
    let reads: Vec<ReadValueId> = nodes
        .iter()
        .map(|n| ReadValueId {
            node_id: n.clone(),
            attribute_id: AttributeId::Value as u32,
            ..Default::default()
        })
        .collect();
    let values: Vec<DataValue> = session
        .read(&reads, TimestampsToReturn::Source, 0.0)
        .await
        .map_err(|e| ApiError(StatusCode::BAD_GATEWAY, e.to_string()))?;
    Ok(Json(
        req.nodes
            .into_iter()
            .zip(values)
            .map(|(node_id, v)| ValueItem {
                node_id,
                value: v.value.as_ref().map(audit_value),
                status: v.status.unwrap_or_default().to_string(),
                source_timestamp: v.source_timestamp.map(|t| t.to_string()),
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use opcua::types::{DataTypeId, NodeId, StatusCode as Status, Variant};

    use super::*;

    fn with_status(status: Status) -> DataValue {
        DataValue {
            status: Some(status),
            ..Default::default()
        }
    }

    #[test]
    fn bad_statuses_are_shown_and_missing_attributes_left_out() {
        let value = AttributeId::Value as u32;
        let item = attribute_item(value, with_status(Status::BadWaitingForInitialData)).unwrap();
        assert!(item.value.is_none());
        assert_eq!(
            item.status.as_deref(),
            Some("BadWaitingForInitialData (0x80320000)")
        );
        assert!(item.status_description.unwrap().contains("Waiting"));

        assert!(attribute_item(value, with_status(Status::BadAttributeIdInvalid)).is_none());

        let data_type = attribute_item(
            AttributeId::DataType as u32,
            DataValue::new_now(Variant::NodeId(Box::new(NodeId::from(DataTypeId::Double)))),
        )
        .unwrap();
        assert_eq!(data_type.note.as_deref(), Some("Double"));
        assert!(data_type.status.is_none() && data_type.source_timestamp.is_none());
    }
}
