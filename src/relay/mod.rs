//! The OPC UA relay: accepts clients on a target's listen address and forwards
//! their traffic to the upstream server, auditing changes on the way.
//!
//! See ARCHITECTURE.md ("Relay design") for what is rewritten and why.

mod audit_map;
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
use opcua::crypto::{CertificateStore, PrivateKey, X509};
use opcua::types::{ByteString, DecodingOptions, EndpointDescription, NodeId, StatusCode};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;

use crate::audit::event::ClientContext;
use crate::audit::AuditHandle;
use crate::config::{Config, FailMode, TargetConfig};
use crate::discovery::{self, TargetStatuses};
use transport::Limits;

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
        sessions.retain(|_, s| now.duration_since(s.last_used) < s.timeout * 2);
        sessions.insert(token, entry);
    }

    pub fn with<T>(&self, token: &NodeId, f: impl FnOnce(&mut SessionEntry) -> T) -> Option<T> {
        let mut sessions = self.sessions.lock();
        sessions.get_mut(token).map(|s| {
            s.last_used = Instant::now();
            f(s)
        })
    }

    pub fn client(&self, token: &NodeId) -> Option<ClientContext> {
        self.with(token, |s| s.client.clone())
    }

    pub fn remove(&self, token: &NodeId) -> Option<SessionEntry> {
        self.sessions.lock().remove(token)
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
    pub sessions: SessionRegistry,
    pub clients: RwLock<BTreeMap<u64, ClientInfo>>,
    pub limits: Limits,
    pub decoding: DecodingOptions,
    channel_ids: AtomicU32,
    connection_ids: AtomicU64,
}

impl RelayTarget {
    pub fn new(
        config: TargetConfig,
        gateway: Arc<GatewayIdentity>,
        statuses: TargetStatuses,
        discovery: Arc<Client>,
        audit: AuditHandle,
        fail_mode: FailMode,
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
            fail_mode,
            sessions: SessionRegistry::default(),
            clients: RwLock::new(BTreeMap::new()),
            channel_ids: AtomicU32::new(1),
            connection_ids: AtomicU64::new(1),
        }
    }

    fn next_channel_id(&self) -> u32 {
        self.channel_ids.fetch_add(1, Ordering::Relaxed)
    }

    /// Upstream endpoints from the target monitor's cache, or discovered now.
    pub async fn upstream_endpoints(&self) -> Result<Vec<EndpointDescription>, StatusCode> {
        if let Some(status) = self.statuses.read().await.get(&self.config.name) {
            if !status.raw_endpoints.is_empty() {
                return Ok(status.raw_endpoints.clone());
            }
        }
        discovery::discover_raw(&self.discovery, &self.config.endpoint_url)
            .await
            .map_err(|e| {
                tracing::warn!(target = %self.config.name, "{e:#}");
                StatusCode::BadServerNotConnected
            })
    }

    pub fn clients(&self) -> Vec<ClientInfo> {
        self.clients.read().values().cloned().collect()
    }
}

/// Accepts clients for one target until the process stops.
pub async fn serve(target: Arc<RelayTarget>) {
    let listener = match tokio::net::TcpListener::bind(target.config.listen).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!(
                target = %target.config.name,
                "cannot listen on {}: {e}",
                target.config.listen
            );
            return;
        }
    };
    tracing::info!(
        target = %target.config.name,
        "accepting OPC UA clients on opc.tcp://{} -> {}",
        target.config.listen,
        target.config.endpoint_url
    );
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let _ = stream.set_nodelay(true);
                let id = target.connection_ids.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(connection::run(target.clone(), stream, peer, id));
            }
            Err(e) => {
                tracing::warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}
