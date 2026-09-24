//! The OPC UA relay: accepts clients on a target's listen address and forwards
//! their traffic to the upstream server, auditing changes on the way.
//!
//! See ARCHITECTURE.md ("Relay design") for what is rewritten and why.

pub(crate) mod audit_map;
mod connection;
pub mod endpoints;
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
use crate::config::{AuditConfig, Config, FailMode, TargetConfig};
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
    pub fail_mode: FailMode,
    pub record_old_value: bool,
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
}

impl RelayTarget {
    pub fn new(
        config: TargetConfig,
        gateway: Arc<GatewayIdentity>,
        statuses: TargetStatuses,
        discovery: Arc<Client>,
        audit: AuditHandle,
        audit_config: &AuditConfig,
    ) -> Self {
        let limits = Limits::default();
        Self {
            decoding: transport::decoding_options(&limits),
            limits,
            config,
            gateway,
            statuses,
            discovery,
            audit,
            fail_mode: audit_config.fail_mode,
            record_old_value: audit_config.record_old_value,
            names: audit_map::NameCache::default(),
            sessions: SessionRegistry::default(),
            clients: RwLock::new(BTreeMap::new()),
            channel_ids: AtomicU32::new(1),
            connection_ids: AtomicU64::new(1),
            request_handles: AtomicU32::new(GATEWAY_REQUEST_HANDLES),
            shutdown: CancellationToken::new(),
            trust_changed: tokio::sync::watch::Sender::new(0),
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

/// Accepts clients for one target until its `shutdown` token is cancelled.
pub async fn serve(target: Arc<RelayTarget>, listener: tokio::net::TcpListener) {
    tracing::info!(
        target = %target.config.name,
        "accepting OPC UA clients on opc.tcp://{} -> {}",
        target.config.listen,
        target.config.endpoint_url
    );
    loop {
        tokio::select! {
            _ = target.shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    let _ = stream.set_nodelay(true);
                    let id = target.connection_ids.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(connection::run(target.clone(), stream, peer, id));
                }
                Err(e) => {
                    tracing::warn!("accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
        }
    }
    tracing::info!(target = %target.config.name, "stopped accepting clients");
}
