//! The audit event model.
//!
//! Every record is an [`AuditEntry`]: when it happened, which target and which
//! client it concerns, and the [`AuditEvent`] itself. A write request with
//! several `WriteValue`s produces one `Write` event per value, all sharing the
//! same `request_handle`, so the trail can be queried per node.

use chrono::{DateTime, Utc};

/// Shortens text a client chose before it goes into the audit trail, so
/// nobody can fill the disk with a few huge requests.
pub fn clip(text: &str, max_chars: usize) -> String {
    match text.char_indices().nth(max_chars) {
        None => text.to_string(),
        Some((cut, _)) => format!("{}… ({} characters)", &text[..cut], text.chars().count()),
    }
}

/// Limits for [`clip`].
pub const MAX_NAME: usize = 256;
pub const MAX_TEXT: usize = 1024;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientContext>,
    pub event: AuditEvent,
}

impl AuditEntry {
    pub fn new(event: AuditEvent) -> Self {
        Self {
            ts: Utc::now(),
            target: None,
            client: None,
            event,
        }
    }

    pub fn target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    #[allow(dead_code)] // used by the relay (next milestone) and tests
    pub fn client(mut self, client: ClientContext) -> Self {
        self.client = Some(client);
        self
    }
}

/// Who did it: everything the gateway knows about the downstream client.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClientContext {
    pub remote_addr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_thumbprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<UserIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UserIdentity {
    Anonymous,
    UserName { name: String },
    Certificate { subject: String, thumbprint: String },
    IssuedToken,
}

impl UserIdentity {
    /// Short form used for the indexed `user` column.
    pub fn label(&self) -> String {
        match self {
            UserIdentity::Anonymous => "anonymous".into(),
            UserIdentity::UserName { name } => name.clone(),
            UserIdentity::Certificate { subject, .. } => subject.clone(),
            UserIdentity::IssuedToken => "issued-token".into(),
        }
    }
}

/// A value as it appears in the audit trail: the OPC UA data type name and a
/// JSON rendering of the value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditValue {
    pub data_type: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEvent {
    // Gateway lifecycle
    GatewayStarted {
        version: String,
    },
    GatewayStopped,
    ConfigChanged {
        by: String,
        summary: String,
    },
    UiLogin {
        user: String,
    },
    UiLoginFailed {
        user: String,
    },
    /// Records that audit records up to and including `last_seq` were deleted by
    /// retention. `last_hash` is the hash of that record, so the remaining chain
    /// stays verifiable from this point on.
    RetentionPruned {
        deleted: u64,
        last_seq: i64,
        last_hash: String,
    },
    /// Records that could not be stored (fail-open mode) since the last report.
    EventsLost {
        count: u64,
    },

    // Upstream server
    UpstreamAvailable {
        endpoint_url: String,
        endpoints: usize,
    },
    UpstreamUnavailable {
        endpoint_url: String,
        reason: String,
    },
    /// The security the upstream server offers changed (policy, mode,
    /// certificate or login types). The gateway follows it, so this also
    /// changes what clients are offered.
    UpstreamEndpointsChanged {
        endpoint_url: String,
        before: Vec<String>,
        after: Vec<String>,
    },

    // Client connections and sessions
    ClientConnected,
    /// Connections refused because a limit was reached, summed per address.
    ConnectionsRefused {
        remote_addr: String,
        count: u64,
        reason: String,
    },
    ClientDisconnected {
        reason: String,
    },
    SecureChannelOpened {
        security_policy: String,
        security_mode: String,
    },
    SessionCreated {
        session_name: String,
    },
    SessionActivated,
    SessionClosed,
    AuthenticationFailed {
        status: String,
    },
    CertificateRejected {
        subject: String,
        thumbprint: String,
        reason: String,
    },

    // Changes to the server
    /// Fail-closed mode: committed before a change request is forwarded, so
    /// nothing reaches the server without a record. The outcome follows as
    /// `write`/`call`/... records with the same `request_handle`.
    ChangeIntent {
        request_handle: u32,
        service: String,
        node_ids: Vec<String>,
        /// Per node: what is about to be written or called with.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        details: Vec<serde_json::Value>,
    },
    Write {
        request_handle: u32,
        node_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
        attribute: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        index_range: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        old_value: Option<AuditValue>,
        new_value: AuditValue,
        /// Status code, source and server timestamp written along with the
        /// value, when the client set them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        written_status: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_timestamp: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server_timestamp: Option<String>,
        status: String,
    },
    Call {
        request_handle: u32,
        object_id: String,
        method_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_name: Option<String>,
        input_arguments: Vec<AuditValue>,
        status: String,
    },
    HistoryUpdate {
        request_handle: u32,
        node_id: String,
        details: String,
        status: String,
    },
    NodeManagement {
        request_handle: u32,
        service: String,
        node_id: String,
        status: String,
    },
    /// A client took over subscriptions, possibly those of another session.
    SubscriptionsTransferred {
        request_handle: u32,
        subscription_ids: Vec<u32>,
        status: String,
    },
}

impl AuditEvent {
    /// Stable name of the event type, stored in the indexed `kind` column.
    pub fn kind(&self) -> &'static str {
        match self {
            AuditEvent::GatewayStarted { .. } => "gateway_started",
            AuditEvent::GatewayStopped => "gateway_stopped",
            AuditEvent::ConfigChanged { .. } => "config_changed",
            AuditEvent::UiLogin { .. } => "ui_login",
            AuditEvent::UiLoginFailed { .. } => "ui_login_failed",
            AuditEvent::RetentionPruned { .. } => "retention_pruned",
            AuditEvent::EventsLost { .. } => "events_lost",
            AuditEvent::UpstreamAvailable { .. } => "upstream_available",
            AuditEvent::UpstreamUnavailable { .. } => "upstream_unavailable",
            AuditEvent::UpstreamEndpointsChanged { .. } => "upstream_endpoints_changed",
            AuditEvent::ClientConnected => "client_connected",
            AuditEvent::ConnectionsRefused { .. } => "connections_refused",
            AuditEvent::ClientDisconnected { .. } => "client_disconnected",
            AuditEvent::SecureChannelOpened { .. } => "secure_channel_opened",
            AuditEvent::SessionCreated { .. } => "session_created",
            AuditEvent::SessionActivated => "session_activated",
            AuditEvent::SessionClosed => "session_closed",
            AuditEvent::AuthenticationFailed { .. } => "authentication_failed",
            AuditEvent::CertificateRejected { .. } => "certificate_rejected",
            AuditEvent::ChangeIntent { .. } => "change_intent",
            AuditEvent::Write { .. } => "write",
            AuditEvent::Call { .. } => "call",
            AuditEvent::HistoryUpdate { .. } => "history_update",
            AuditEvent::NodeManagement { .. } => "node_management",
            AuditEvent::SubscriptionsTransferred { .. } => "subscriptions_transferred",
        }
    }

    /// The node this event is about, if any; stored in the indexed `node_id` column.
    pub fn node_id(&self) -> Option<&str> {
        match self {
            AuditEvent::Write { node_id, .. }
            | AuditEvent::HistoryUpdate { node_id, .. }
            | AuditEvent::NodeManagement { node_id, .. } => Some(node_id),
            AuditEvent::Call { method_id, .. } => Some(method_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_matches_serde_tag() {
        let events = [
            AuditEvent::GatewayStopped,
            AuditEvent::SessionActivated,
            AuditEvent::Write {
                request_handle: 1,
                node_id: "ns=3;s=\"DB1\".\"Setpoint\"".into(),
                display_name: None,
                attribute: "Value".into(),
                index_range: None,
                old_value: None,
                new_value: AuditValue {
                    data_type: "Double".into(),
                    value: 12.5.into(),
                },
                written_status: None,
                source_timestamp: None,
                server_timestamp: None,
                status: "Good".into(),
            },
        ];
        for event in events {
            let json = serde_json::to_value(&event).unwrap();
            assert_eq!(json["type"], event.kind());
        }
    }
}
