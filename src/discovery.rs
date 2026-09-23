//! Endpoint discovery of upstream servers and a per-target status monitor.
//!
//! The endpoints found here drive "follow the target" mode: the gateway offers
//! clients the same security policies, modes and user token types.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use chrono::{DateTime, Utc};
use opcua::client::{Client, ClientBuilder};
use opcua::crypto::{SecurityPolicy, X509};
use opcua::types::{EndpointDescription, MessageSecurityMode, UserTokenType};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::audit::{AuditEntry, AuditEvent, AuditHandle};
use crate::config::{Config, TargetConfig};
use crate::pki::CertificateInfo;

#[derive(Debug, Clone, Serialize)]
pub struct EndpointInfo {
    pub endpoint_url: String,
    pub security_policy: String,
    pub security_policy_uri: String,
    pub security_mode: String,
    pub security_level: u8,
    pub user_tokens: Vec<UserTokenInfo>,
    pub server_application_uri: String,
    pub server_application_name: String,
    pub server_certificate: Option<CertificateInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserTokenInfo {
    pub policy_id: String,
    pub token_type: String,
    /// Policy used to encrypt the token; empty means "same as the channel".
    pub security_policy_uri: String,
}

fn security_mode_name(mode: MessageSecurityMode) -> &'static str {
    match mode {
        MessageSecurityMode::None => "None",
        MessageSecurityMode::Sign => "Sign",
        MessageSecurityMode::SignAndEncrypt => "SignAndEncrypt",
        _ => "Invalid",
    }
}

fn token_type_name(token_type: UserTokenType) -> &'static str {
    match token_type {
        UserTokenType::Anonymous => "Anonymous",
        UserTokenType::UserName => "UserName",
        UserTokenType::Certificate => "Certificate",
        UserTokenType::IssuedToken => "IssuedToken",
    }
}

impl From<&EndpointDescription> for EndpointInfo {
    fn from(e: &EndpointDescription) -> Self {
        let policy_uri = e.security_policy_uri.as_ref().to_string();
        let certificate = X509::from_byte_string(&e.server_certificate)
            .ok()
            .map(|c| CertificateInfo::from_x509(&c));
        Self {
            endpoint_url: e.endpoint_url.as_ref().to_string(),
            security_policy: SecurityPolicy::from_uri(&policy_uri).to_str().to_string(),
            security_policy_uri: policy_uri,
            security_mode: security_mode_name(e.security_mode).to_string(),
            security_level: e.security_level,
            user_tokens: e
                .user_identity_tokens
                .iter()
                .flatten()
                .map(|t| UserTokenInfo {
                    policy_id: t.policy_id.as_ref().to_string(),
                    token_type: token_type_name(t.token_type).to_string(),
                    security_policy_uri: t.security_policy_uri.as_ref().to_string(),
                })
                .collect(),
            server_application_uri: e.server.application_uri.as_ref().to_string(),
            server_application_name: e.server.application_name.text.as_ref().to_string(),
            server_certificate: certificate,
        }
    }
}

/// Builds the OPC UA client the gateway uses for discovery.
pub fn discovery_client(config: &Config) -> anyhow::Result<Client> {
    ClientBuilder::new()
        .application_name(config.gateway.application_name.clone())
        .application_uri(config.gateway.application_uri())
        .pki_dir(config.gateway.pki_dir.clone())
        .create_sample_keypair(false)
        .session_retry_limit(0)
        .request_timeout(Duration::from_secs(5))
        .client()
        .map_err(|errors| anyhow!("invalid discovery client config: {}", errors.join("; ")))
}

/// Calls GetEndpoints on the server. Needs no security and no trust: it is the
/// unauthenticated first step every OPC UA client does.
pub async fn discover(client: &Client, endpoint_url: &str) -> anyhow::Result<Vec<EndpointInfo>> {
    let endpoints = client
        .get_server_endpoints_from_url(endpoint_url)
        .await
        .map_err(|e| anyhow!("GetEndpoints on {endpoint_url} failed: {e}"))?;
    let mut infos: Vec<EndpointInfo> = endpoints.iter().map(EndpointInfo::from).collect();
    infos.sort_by_key(|e| std::cmp::Reverse(e.security_level));
    Ok(infos)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamState {
    Unknown,
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetStatus {
    pub name: String,
    pub listen: String,
    pub endpoint_url: String,
    pub state: UpstreamState,
    pub last_check: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub endpoints: Vec<EndpointInfo>,
}

impl TargetStatus {
    fn new(target: &TargetConfig) -> Self {
        Self {
            name: target.name.clone(),
            listen: target.listen.to_string(),
            endpoint_url: target.endpoint_url.clone(),
            state: UpstreamState::Unknown,
            last_check: None,
            last_error: None,
            endpoints: Vec::new(),
        }
    }
}

pub type TargetStatuses = Arc<RwLock<BTreeMap<String, TargetStatus>>>;

pub fn initial_statuses(config: &Config) -> TargetStatuses {
    Arc::new(RwLock::new(
        config
            .targets
            .iter()
            .map(|t| (t.name.clone(), TargetStatus::new(t)))
            .collect(),
    ))
}

/// Re-discovers one target forever, updating its status and auditing changes
/// in upstream availability.
pub async fn monitor_target(
    client: Arc<Client>,
    target: TargetConfig,
    statuses: TargetStatuses,
    audit: AuditHandle,
) {
    let mut tick = tokio::time::interval(Duration::from_secs(target.discovery_interval_secs));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let result = discover(&client, &target.endpoint_url).await;

        let mut map = statuses.write().await;
        let Some(status) = map.get_mut(&target.name) else {
            return;
        };
        let previous = status.state;
        status.last_check = Some(Utc::now());
        let event = match result {
            Ok(endpoints) => {
                let event =
                    (previous != UpstreamState::Available).then(|| AuditEvent::UpstreamAvailable {
                        endpoint_url: target.endpoint_url.clone(),
                        endpoints: endpoints.len(),
                    });
                status.state = UpstreamState::Available;
                status.last_error = None;
                status.endpoints = endpoints;
                event
            }
            Err(e) => {
                let reason = format!("{e:#}");
                tracing::warn!(target = %target.name, "{reason}");
                let event = (previous != UpstreamState::Unavailable).then(|| {
                    AuditEvent::UpstreamUnavailable {
                        endpoint_url: target.endpoint_url.clone(),
                        reason: reason.clone(),
                    }
                });
                status.state = UpstreamState::Unavailable;
                status.last_error = Some(reason);
                event
            }
        };
        drop(map);
        if let Some(event) = event {
            let _ = audit
                .record(AuditEntry::new(event).target(target.name.clone()))
                .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::store::AuditQuery;
    use crate::audit::AuditReader;
    use opcua::crypto::SecurityPolicy;
    use opcua::server::{ServerBuilder, ServerHandle, ServerUserToken, ANONYMOUS_USER_TOKEN_ID};

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    /// In-process OPC UA server standing in for a PLC.
    fn start_test_server(pki: &std::path::Path, port: u16) -> ServerHandle {
        let tokens = [ANONYMOUS_USER_TOKEN_ID, "operator"];
        let (server, handle) = ServerBuilder::new()
            .application_name("Test PLC")
            .application_uri("urn:test-plc")
            .host("127.0.0.1")
            .port(port)
            .pki_dir(pki)
            .create_sample_keypair(true)
            .discovery_urls(vec!["/".into()])
            .add_user_token("operator", ServerUserToken::user_pass("operator", "secret"))
            .add_endpoint(
                "none",
                (
                    "/",
                    SecurityPolicy::None,
                    MessageSecurityMode::None,
                    &tokens as &[&str],
                ),
            )
            .add_endpoint(
                "basic256sha256_sign_encrypt",
                (
                    "/",
                    SecurityPolicy::Basic256Sha256,
                    MessageSecurityMode::SignAndEncrypt,
                    &tokens as &[&str],
                ),
            )
            .build()
            .unwrap();
        tokio::spawn(server.run());
        handle
    }

    fn test_config(dir: &std::path::Path, port: u16) -> Config {
        let mut config: Config = toml::from_str(&format!(
            r#"
            [[targets]]
            name = "plc1"
            listen = "127.0.0.1:0"
            endpoint_url = "opc.tcp://127.0.0.1:{port}/"
            discovery_interval_secs = 1
            "#
        ))
        .unwrap();
        config.gateway.pki_dir = dir.join("gateway-pki");
        config
    }

    #[tokio::test]
    async fn discovers_policies_and_user_tokens() {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let server = start_test_server(&dir.path().join("plc-pki"), port);
        let config = test_config(dir.path(), port);
        let client = discovery_client(&config).unwrap();

        // The server needs a moment to start listening.
        let mut endpoints = Vec::new();
        for _ in 0..50 {
            match discover(&client, &config.targets[0].endpoint_url).await {
                Ok(e) => {
                    endpoints = e;
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
        server.cancel();

        assert_eq!(endpoints.len(), 2);
        let secure = &endpoints[0];
        assert_eq!(secure.security_policy, "Basic256Sha256");
        assert_eq!(secure.security_mode, "SignAndEncrypt");
        assert_eq!(secure.server_application_uri, "urn:test-plc");
        assert!(secure.server_certificate.is_some());
        let tokens: Vec<_> = secure
            .user_tokens
            .iter()
            .map(|t| t.token_type.as_str())
            .collect();
        assert!(tokens.contains(&"Anonymous"));
        assert!(tokens.contains(&"UserName"));
        assert_eq!(endpoints[1].security_mode, "None");
    }

    #[tokio::test]
    async fn monitor_audits_availability_changes() {
        let dir = tempfile::tempdir().unwrap();
        let port = free_port();
        let config = test_config(dir.path(), port);
        let db = dir.path().join("audit.db");
        let audit = crate::audit::start(&db, &config.audit).unwrap();
        let statuses = initial_statuses(&config);
        let client = Arc::new(discovery_client(&config).unwrap());
        tokio::spawn(monitor_target(
            client,
            config.targets[0].clone(),
            statuses.clone(),
            audit.clone(),
        ));

        let wait_for = |state: UpstreamState| {
            let statuses = statuses.clone();
            async move {
                for _ in 0..100 {
                    if statuses.read().await["plc1"].state == state {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                panic!("target never became {state:?}");
            }
        };

        // Nothing listens yet: unavailable. Then the server comes up.
        wait_for(UpstreamState::Unavailable).await;
        let server = start_test_server(&dir.path().join("plc-pki"), port);
        wait_for(UpstreamState::Available).await;
        server.cancel();
        audit.flush().await;

        let kinds: Vec<String> = AuditReader::new(&db)
            .query(AuditQuery::default())
            .await
            .unwrap()
            .into_iter()
            .rev()
            .map(|r| r.entry.event.kind().to_string())
            .collect();
        assert_eq!(kinds, ["upstream_unavailable", "upstream_available"]);
    }
}
