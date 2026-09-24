//! The OPC UA relay: accepts clients on a target's listen address and forwards
//! their traffic to the upstream server, auditing changes on the way.
//!
//! See ARCHITECTURE.md ("Relay design") for what is rewritten and why.

pub(crate) mod audit_map;
mod connection;
pub mod endpoints;
pub mod ignore;
pub mod transport;
pub mod upstream;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use opcua::client::Client;
use opcua::crypto::{CertificateStore, PrivateKey, SecurityPolicy, X509};
use opcua::types::{
    ByteString, DecodingOptions, EndpointDescription, MessageSecurityMode, NodeId, StatusCode,
};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::audit::event::ClientContext;
use crate::audit::AuditHandle;
use crate::config::{Config, TargetConfig};
use crate::discovery::{self, TargetStatuses};
use transport::Limits;

/// Request handles the gateway uses in client sessions start here, far away
/// from the small numbers clients count up from.
const GATEWAY_REQUEST_HANDLES: u32 = 0xF000_0000;

/// The gateway's own application identity, shared by all targets.
pub struct GatewayIdentity {
    pub certificate: X509,
    pub certificate_bytes: ByteString,
    pub private_key: PrivateKey,
    pub certificate_store: Arc<RwLock<CertificateStore>>,
    pub application_uri: String,
    pub application_name: String,
    /// Name shown to clients as the server's application name.
    pub server_name: String,
}

impl GatewayIdentity {
    #[cfg(test)]
    pub fn new(
        certificate: X509,
        private_key: PrivateKey,
        application_uri: String,
        application_name: String,
        server_name: String,
    ) -> Self {
        Self {
            certificate_bytes: certificate.as_byte_string(),
            certificate,
            private_key,
            certificate_store: Arc::new(RwLock::new(CertificateStore::new(&std::env::temp_dir()))),
            application_uri,
            application_name,
            server_name,
        }
    }

    pub fn load(config: &Config, target: &TargetConfig) -> anyhow::Result<Self> {
        let store = CertificateStore::new(&config.gateway.pki_dir);
        let certificate = store.read_own_cert().map_err(anyhow::Error::msg)?;
        let private_key = store.read_own_pkey().map_err(anyhow::Error::msg)?;
        Ok(Self {
            certificate_bytes: certificate.as_byte_string(),
            certificate,
            private_key,
            certificate_store: Arc::new(RwLock::new(store)),
            application_uri: config.gateway.application_uri(),
            application_name: config.gateway.application_name.clone(),
            server_name: format!("{} ({})", config.gateway.application_name, target.name),
        })
    }
}

/// What the gateway remembers about a session, keyed by its authentication token.
/// Sessions outlive connections: a client may reconnect and re-activate.
pub struct SessionEntry {
    pub client: ClientContext,
    pub client_certificate: Option<X509>,
    /// Last server nonce the gateway gave the client.
    pub downstream_nonce: ByteString,
    /// Last server nonce the upstream server gave the gateway.
    pub upstream_nonce: ByteString,
    pub timeout: Duration,
    pub last_used: Instant,
    /// Security of the channel the session was created on. It may only be
    /// re-activated over a channel at least as secure.
    pub security_policy: SecurityPolicy,
    pub security_mode: MessageSecurityMode,
    /// The connection the session belongs to (created or last activated on).
    pub connection_id: u64,
}

#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<NodeId, SessionEntry>>,
}

impl SessionRegistry {
    pub fn insert(&self, token: NodeId, entry: SessionEntry) {
        let mut sessions = self.sessions.lock();
        let now = Instant::now();
        // Forget sessions the upstream server has certainly timed out by now.
        sessions.retain(|_, s| now.duration_since(s.last_used) < s.timeout.saturating_mul(2));
        sessions.insert(token, entry);
    }

    pub fn with<T>(&self, token: &NodeId, f: impl FnOnce(&mut SessionEntry) -> T) -> Option<T> {
        let mut sessions = self.sessions.lock();
        sessions.get_mut(token).map(|s| {
            s.last_used = Instant::now();
            f(s)
        })
    }

    /// The session's client, if the session belongs to `connection_id`.
    pub fn client_of(&self, token: &NodeId, connection_id: u64) -> Option<ClientContext> {
        self.with(token, |s| s.client.clone())
            .filter(|_| self.owned_by(token, connection_id))
    }

    fn owned_by(&self, token: &NodeId, connection_id: u64) -> bool {
        self.sessions
            .lock()
            .get(token)
            .is_some_and(|s| s.connection_id == connection_id)
    }

    /// Removes the session if it belongs to `connection_id`.
    pub fn remove_owned(&self, token: &NodeId, connection_id: u64) -> Option<SessionEntry> {
        let mut sessions = self.sessions.lock();
        if sessions.get(token)?.connection_id != connection_id {
            return None;
        }
        sessions.remove(token)
    }
}

/// A connected client, for the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct ClientInfo {
    pub remote_addr: String,
    pub connected_at: DateTime<Utc>,
    pub security_policy: String,
    pub security_mode: String,
    pub application_uri: Option<String>,
    pub application_name: Option<String>,
    pub user: Option<String>,
}

/// Everything the connections of one target share.
pub struct RelayTarget {
    pub config: TargetConfig,
    pub gateway: Arc<GatewayIdentity>,
    pub statuses: TargetStatuses,
    pub discovery: Arc<Client>,
    pub audit: AuditHandle,
    pub names: audit_map::NameCache,
    pub sessions: SessionRegistry,
    pub clients: RwLock<BTreeMap<u64, ClientInfo>>,
    pub limits: Limits,
    pub decoding: DecodingOptions,
    channel_ids: AtomicU32,
    connection_ids: AtomicU64,
    request_handles: AtomicU32,
    /// Cancelled when the target is removed or reconfigured: stops the
    /// listener and closes all its connections.
    pub shutdown: CancellationToken,
    /// Bumped when certificates are untrusted: every connection re-checks
    /// its client and server certificate and closes if one is revoked.
    pub trust_changed: tokio::sync::watch::Sender<u64>,
    /// Nodes whose value writes are summarised; changeable while running.
    pub ignore: ignore::IgnoreList,
    /// Ignored writes since the last summary.
    pub ignored: ignore::IgnoredWrites,
}

impl RelayTarget {
    pub fn new(
        config: TargetConfig,
        gateway: Arc<GatewayIdentity>,
        statuses: TargetStatuses,
        discovery: Arc<Client>,
        audit: AuditHandle,
    ) -> Self {
        let limits = Limits::default();
        Self {
            decoding: transport::decoding_options(&limits),
            limits,
            gateway,
            statuses,
            discovery,
            audit,
            names: audit_map::NameCache::default(),
            sessions: SessionRegistry::default(),
            clients: RwLock::new(BTreeMap::new()),
            channel_ids: AtomicU32::new(1),
            connection_ids: AtomicU64::new(1),
            request_handles: AtomicU32::new(GATEWAY_REQUEST_HANDLES),
            shutdown: CancellationToken::new(),
            trust_changed: tokio::sync::watch::Sender::new(0),
            ignore: ignore::IgnoreList::new(&config.ignore),
            ignored: ignore::IgnoredWrites::default(),
            config,
        }
    }

    /// Opens a secure channel to the target with the gateway's certificate
    /// (no session) and records whether the target accepts the gateway, so
    /// a missing trust shows on the target before any client connects.
    pub async fn check_gateway_trust(&self) {
        use crate::discovery::GatewayTrust;
        let result = match self.upstream_endpoints().await {
            Err(status) => GatewayTrust::Failed {
                detail: format!("target not reachable ({status})"),
            },
            Ok(endpoints) => {
                let secure = endpoints
                    .into_iter()
                    .filter(|e| {
                        SecurityPolicy::from_uri(e.security_policy_uri.as_ref())
                            != SecurityPolicy::None
                    })
                    .max_by_key(|e| e.security_level);
                match secure {
                    None => GatewayTrust::NoSecureEndpoint,
                    Some(endpoint) => {
                        let policy =
                            SecurityPolicy::from_uri(endpoint.security_policy_uri.as_ref());
                        let connect = upstream::Upstream::connect(
                            &self.gateway,
                            &self.config.endpoint_url,
                            endpoint,
                            &self.limits,
                            self.decoding.clone(),
                        );
                        match tokio::time::timeout(Duration::from_secs(15), connect).await {
                            Err(_) => GatewayTrust::Failed {
                                detail: "no answer within 15 s".into(),
                            },
                            // Some servers check the gateway's certificate
                            // only when a session is created: create one
                            // (without logging in) and close it again.
                            Ok(Ok(upstream)) => {
                                let result = self.probe_session(&upstream, policy).await;
                                upstream.close().await;
                                result
                            }
                            Ok(Err(upstream::UpstreamError::Untrusted { .. })) => {
                                GatewayTrust::TargetNotTrusted
                            }
                            Ok(Err(upstream::UpstreamError::Other(e))) => {
                                let detail = e.to_string();
                                if detail.contains("BadSecurityChecksFailed")
                                    || detail.contains("BadCertificateUntrusted")
                                {
                                    GatewayTrust::Refused { detail }
                                } else {
                                    GatewayTrust::Failed { detail }
                                }
                            }
                        }
                    }
                }
            }
        };
        self.set_gateway_trust(result).await;
    }

    /// Stores what the trust check, or a client's connection, found. When
    /// the target starts refusing the gateway, the trail gets one
    /// upstream_unavailable record (a warning), not one per client.
    pub async fn set_gateway_trust(&self, result: crate::discovery::GatewayTrust) {
        use crate::discovery::GatewayTrust;
        let newly_refused = {
            let mut statuses = self.statuses.write().await;
            let Some(status) = statuses.get_mut(&self.config.name) else {
                return;
            };
            if status.gateway_trust == result {
                return;
            }
            tracing::info!(target = %self.config.name, "gateway trust: {result:?}");
            let was_refused = matches!(status.gateway_trust, GatewayTrust::Refused { .. });
            status.gateway_trust = result.clone();
            match &result {
                GatewayTrust::Refused { detail } if !was_refused => Some(detail.clone()),
                _ => None,
            }
        };
        if let Some(detail) = newly_refused {
            let event = crate::audit::AuditEvent::UpstreamUnavailable {
                endpoint_url: self.config.endpoint_url.clone(),
                reason: format!(
                    "the target refused the gateway ({detail}); it probably does not trust \
                     the gateway's certificate yet (trust it on the target, e.g. move it from \
                     its rejected to its trusted certificates)"
                ),
            };
            let entry = crate::audit::AuditEntry::new(event).target(self.config.name.clone());
            let _ = self.audit.record(entry).await;
        }
    }

    async fn probe_session(
        &self,
        upstream: &upstream::Upstream,
        policy: SecurityPolicy,
    ) -> crate::discovery::GatewayTrust {
        use crate::discovery::GatewayTrust;
        use opcua::core::{RequestMessage, ResponseMessage};
        use opcua::types::{CloseSessionRequest, CreateSessionRequest, DateTime, RequestHeader};
        let header = || RequestHeader {
            timestamp: DateTime::now(),
            request_handle: self.next_request_handle(),
            timeout_hint: 10_000,
            ..Default::default()
        };
        let request = CreateSessionRequest {
            request_header: header(),
            client_description: endpoints::client_description(&self.gateway),
            server_uri: Default::default(),
            endpoint_url: self.config.endpoint_url.as_str().into(),
            session_name: format!("{} trust check", self.gateway.application_name).into(),
            client_nonce: opcua::crypto::random::byte_string(32),
            client_certificate: self.gateway.certificate_bytes.clone(),
            requested_session_timeout: 10_000.0,
            max_response_message_size: 0,
        };
        let refused = |status: StatusCode| {
            matches!(
                status,
                StatusCode::BadSecurityChecksFailed
                    | StatusCode::BadCertificateUntrusted
                    | StatusCode::BadCertificateInvalid
                    | StatusCode::BadCertificateUriInvalid
            )
        };
        match upstream
            .send(RequestMessage::from(request), Duration::from_secs(10))
            .await
        {
            Ok(ResponseMessage::CreateSession(r)) if r.response_header.service_result.is_good() => {
                let close = CloseSessionRequest {
                    request_header: RequestHeader {
                        authentication_token: r.authentication_token.clone(),
                        ..header()
                    },
                    delete_subscriptions: true,
                };
                let _ = upstream
                    .send(RequestMessage::from(close), Duration::from_secs(5))
                    .await;
                GatewayTrust::Trusted {
                    policy: policy.to_str().to_string(),
                }
            }
            Ok(other) => {
                let status = other.response_header().service_result;
                if refused(status) {
                    GatewayTrust::Refused {
                        detail: status.to_string(),
                    }
                } else {
                    GatewayTrust::Failed {
                        detail: format!("CreateSession: {status}"),
                    }
                }
            }
            Err(e) if refused(e.status()) => GatewayTrust::Refused {
                detail: e.status().to_string(),
            },
            Err(e) => GatewayTrust::Failed {
                detail: format!("CreateSession: {}", e.status()),
            },
        }
    }

    /// Records the summaries of ignored writes since the last call.
    pub async fn record_ignored(&self) {
        for event in self.ignored.take() {
            let entry = crate::audit::AuditEntry::new(event).target(self.config.name.clone());
            let _ = self.audit.record(entry).await;
        }
    }

    /// Makes every connection re-check its certificates.
    pub fn recheck_trust(&self) {
        self.trust_changed.send_modify(|n| *n += 1);
    }

    /// Request handle for requests the gateway itself sends in a client's
    /// session (the reads for old values and names).
    fn next_request_handle(&self) -> u32 {
        self.request_handles.fetch_add(1, Ordering::Relaxed)
    }

    fn next_channel_id(&self) -> u32 {
        self.channel_ids.fetch_add(1, Ordering::Relaxed)
    }

    /// Upstream endpoints from the target monitor's cache, or discovered now,
    /// without those below the target's minimum security.
    pub async fn upstream_endpoints(&self) -> Result<Vec<EndpointDescription>, StatusCode> {
        let min = self.config.min_security;
        if let Some(status) = self.statuses.read().await.get(&self.config.name) {
            if !status.raw_endpoints.is_empty() {
                return Ok(endpoints::at_least(status.raw_endpoints.clone(), min));
            }
        }
        discovery::discover_raw(&self.discovery, &self.config.endpoint_url)
            .await
            .map(|e| endpoints::at_least(e, min))
            .map_err(|e| {
                tracing::warn!(target = %self.config.name, "{e:#}");
                StatusCode::BadServerNotConnected
            })
    }

    pub fn clients(&self) -> Vec<ClientInfo> {
        self.clients.read().values().cloned().collect()
    }
}

/// Binds the target's listen address.
pub async fn bind(target: &RelayTarget) -> std::io::Result<tokio::net::TcpListener> {
    tokio::net::TcpListener::bind(target.config.listen).await
}

/// New connections per second one address may open (with a burst of twice
/// that): enough for any HMI, too few to flood the audit trail.
const CONNECTION_RATE: f64 = 5.0;

struct AddressState {
    active: usize,
    tokens: f64,
    last: Instant,
    refused: u64,
    reason: &'static str,
}

/// Decides which new connections a target accepts.
struct Admission {
    max_total: usize,
    max_per_address: usize,
    active: usize,
    addresses: HashMap<std::net::IpAddr, AddressState>,
}

impl Admission {
    fn admit(&mut self, ip: std::net::IpAddr) -> Result<(), ()> {
        let now = Instant::now();
        let full = self.active >= self.max_total;
        let state = self.addresses.entry(ip).or_insert(AddressState {
            active: 0,
            tokens: 2.0 * CONNECTION_RATE,
            last: now,
            refused: 0,
            reason: "",
        });
        state.tokens = (state.tokens
            + now.duration_since(state.last).as_secs_f64() * CONNECTION_RATE)
            .min(2.0 * CONNECTION_RATE);
        state.last = now;
        let reason = if full {
            "too many connections to this target"
        } else if state.active >= self.max_per_address {
            "too many connections from this address"
        } else if state.tokens < 1.0 {
            "too many new connections per second from this address"
        } else {
            state.tokens -= 1.0;
            state.active += 1;
            self.active += 1;
            return Ok(());
        };
        state.refused += 1;
        state.reason = reason;
        Err(())
    }

    fn release(&mut self, ip: std::net::IpAddr) {
        self.active = self.active.saturating_sub(1);
        if let Some(state) = self.addresses.get_mut(&ip) {
            state.active = state.active.saturating_sub(1);
        }
    }

    /// Refusals since the last call, per address; forgets idle addresses.
    fn take_refused(&mut self) -> Vec<(std::net::IpAddr, u64, &'static str)> {
        let refused = self
            .addresses
            .iter_mut()
            .filter(|(_, s)| s.refused > 0)
            .map(|(ip, s)| (*ip, std::mem::take(&mut s.refused), s.reason))
            .collect();
        self.addresses
            .retain(|_, s| s.active > 0 || s.last.elapsed() < Duration::from_secs(60));
        refused
    }
}

/// Accepts clients for one target until its `shutdown` token is cancelled.
pub async fn serve(target: Arc<RelayTarget>, listener: tokio::net::TcpListener) {
    tracing::info!(
        target = %target.config.name,
        "accepting OPC UA clients on opc.tcp://{} -> {}",
        target.config.listen,
        target.config.endpoint_url
    );
    let admission = Arc::new(Mutex::new(Admission {
        max_total: target.config.max_connections,
        max_per_address: target.config.max_connections_per_address,
        active: 0,
        addresses: HashMap::new(),
    }));
    // Refused connections are recorded as one summary per address.
    let mut report = tokio::time::interval(Duration::from_secs(10));
    // The summary interval is read each time: it can change while running.
    let mut next_summary = Instant::now() + target.audit.settings().ignored_summary();
    // Whether the target accepts the gateway: soon after start, then with
    // every discovery interval, and at once when trust changes.
    let mut next_trust_check = Instant::now() + Duration::from_secs(2);
    let mut trust = target.trust_changed.subscribe();
    loop {
        tokio::select! {
            _ = target.shutdown.cancelled() => break,
            _ = tokio::time::sleep_until(next_trust_check.into()) => {
                target.check_gateway_trust().await;
                next_trust_check = Instant::now()
                    + Duration::from_secs(target.config.discovery_interval_secs.max(10));
            }
            Ok(()) = trust.changed() => {
                next_trust_check = Instant::now();
            }
            _ = tokio::time::sleep_until(next_summary.into()) => {
                target.record_ignored().await;
                next_summary = Instant::now() + target.audit.settings().ignored_summary();
            }
            _ = report.tick() => {
                let refused = admission.lock().take_refused();
                for (ip, count, reason) in refused {
                    tracing::warn!(target = %target.config.name, "refused {count} connections from {ip}: {reason}");
                    let entry = crate::audit::AuditEntry::new(crate::audit::AuditEvent::ConnectionsRefused {
                        remote_addr: ip.to_string(),
                        count,
                        reason: reason.into(),
                    })
                    .target(target.config.name.clone());
                    let _ = target.audit.record(entry).await;
                }
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    if admission.lock().admit(peer.ip()).is_err() {
                        drop(stream);
                        continue;
                    }
                    let _ = stream.set_nodelay(true);
                    let id = target.connection_ids.fetch_add(1, Ordering::Relaxed);
                    let target = target.clone();
                    let admission = admission.clone();
                    tokio::spawn(async move {
                        connection::run(target, stream, peer, id).await;
                        admission.lock().release(peer.ip());
                    });
                }
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    }
    target.record_ignored().await;
    tracing::info!(target = %target.config.name, "stopped accepting clients");
}
