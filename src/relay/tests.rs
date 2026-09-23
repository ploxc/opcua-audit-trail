//! End-to-end tests: a real OPC UA client talks to a real OPC UA server
//! through the gateway, and the audit trail is checked.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use opcua::client::{ClientBuilder, IdentityToken, Password, Session};
use opcua::crypto::{CertificateStore, SecurityPolicy};
use opcua::types::{
    AttributeId, CallMethodRequest, DataValue, MessageSecurityMode, NodeId, NumericRange, ObjectId,
    ReadValueId, StatusCode, TimestampsToReturn, Variant, WriteValue,
};

use super::{bind, serve, GatewayIdentity, RelayTarget};
use crate::audit::event::{AuditEvent, UserIdentity};
use crate::audit::store::{AuditQuery, StoredRecord};
use crate::audit::{AuditHandle, AuditReader};
use crate::config::{Config, FailMode};
use crate::discovery;
use crate::pki::Pki;
use crate::testutil::{free_port, start_test_plc, trust, wait_listening, TestPlc};

struct Harness {
    // Field order matters: the server stops before its directory is removed.
    _plc: TestPlc,
    dir: tempfile::TempDir,
    gateway_url: String,
    gateway_pki: PathBuf,
    db: PathBuf,
    audit: AuditHandle,
    setpoint: NodeId,
    read_only: NodeId,
    method: NodeId,
}

/// Starts a test server ("the PLC") and a gateway in front of it.
async fn harness(fail_mode: FailMode) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let plc = start_test_plc(dir.path()).await;
    let server_port = plc.port;

    // Gateway.
    let gateway_port = free_port();
    let mut config: Config = toml::from_str(&format!(
        r#"
        [audit]
        fail_mode = "{}"
        [[targets]]
        name = "plc1"
        listen = "127.0.0.1:{gateway_port}"
        endpoint_url = "opc.tcp://127.0.0.1:{server_port}/"
        "#,
        match fail_mode {
            FailMode::Open => "open",
            FailMode::Closed => "closed",
        }
    ))
    .unwrap();
    config.gateway.pki_dir = dir.path().join("gateway-pki");
    config.gateway.application_uri = Some("urn:test-gateway".into());
    let pki = Pki::open(&config.gateway.pki_dir).unwrap();
    pki.ensure_own_certificate(&config.gateway).unwrap();
    // The gateway trusts the PLC. The server creates its keypair on build.
    trust(&config.gateway.pki_dir, &plc.certificate);

    let db = dir.path().join("audit.db");
    let audit = crate::audit::start(&db, &config.audit).unwrap();
    let statuses = discovery::initial_statuses(&config);
    let client = Arc::new(discovery::discovery_client(&config).unwrap());
    let target = config.targets[0].clone();
    let relay = Arc::new(RelayTarget::new(
        target.clone(),
        Arc::new(GatewayIdentity::load(&config, &target).unwrap()),
        statuses,
        client,
        audit.clone(),
        &config.audit,
    ));
    let listener = bind(&relay).await.unwrap();
    tokio::spawn(serve(relay, listener));

    let gateway_url = format!("opc.tcp://127.0.0.1:{gateway_port}/");
    wait_listening(gateway_port).await;

    Harness {
        gateway_pki: config.gateway.pki_dir.clone(),
        setpoint: plc.setpoint.clone(),
        read_only: plc.read_only.clone(),
        method: plc.method.clone(),
        _plc: plc,
        dir,
        gateway_url,
        db,
        audit,
    }
}

impl Harness {
    /// Connects a test client through the gateway. `trusted` controls whether
    /// the gateway trusts the client's certificate.
    async fn connect(
        &self,
        name: &str,
        policy: SecurityPolicy,
        mode: MessageSecurityMode,
        identity: IdentityToken,
        trusted: bool,
    ) -> Result<Arc<Session>, StatusCode> {
        self.connect_with(name, policy, mode, identity, trusted, 60_000)
            .await
    }

    async fn connect_with(
        &self,
        name: &str,
        policy: SecurityPolicy,
        mode: MessageSecurityMode,
        identity: IdentityToken,
        trusted: bool,
        channel_lifetime_ms: u32,
    ) -> Result<Arc<Session>, StatusCode> {
        let client_pki = self.dir.path().join(format!("client-{name}-pki"));
        let mut client = ClientBuilder::new()
            .channel_lifetime(channel_lifetime_ms)
            .application_name(format!("Test HMI {name}"))
            .application_uri(format!("urn:test-hmi-{name}"))
            .pki_dir(&client_pki)
            .create_sample_keypair(true)
            .trust_server_certs(true)
            .session_retry_limit(0)
            .client()
            .unwrap();
        if trusted {
            trust(&self.gateway_pki, &client_pki.join("own/cert.der"));
        }
        let (session, event_loop) = client
            .connect_to_matching_endpoint(
                (self.gateway_url.as_str(), policy.to_uri(), mode),
                identity,
            )
            .await
            .map_err(|e| e.status())?;
        let handle = event_loop.spawn();
        let connected =
            tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
                .await
                .unwrap_or(false);
        if connected {
            Ok(session)
        } else {
            let status = tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or(StatusCode::BadTimeout);
            Err(status)
        }
    }

    async fn records(&self, kind: &str) -> Vec<StoredRecord> {
        self.audit.flush().await;
        let mut rows = AuditReader::new(&self.db)
            .query(AuditQuery {
                kind: Some(kind.into()),
                ..Default::default()
            })
            .await
            .unwrap();
        rows.reverse();
        rows
    }

    async fn verify_chain(&self) {
        self.audit.flush().await;
        let report = AuditReader::new(&self.db).verify().await.unwrap();
        assert!(report.ok(), "{:?}", report.error);
    }
}

fn write_value(node: &NodeId, value: f64) -> WriteValue {
    WriteValue {
        node_id: node.clone(),
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
        value: DataValue::new_now(value),
    }
}

async fn read_value(session: &Session, node: &NodeId) -> Variant {
    let results = session
        .read(
            &[ReadValueId {
                node_id: node.clone(),
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            }],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await
        .unwrap();
    results[0].value.clone().unwrap()
}

fn operator() -> IdentityToken {
    IdentityToken::UserName("operator".into(), Password::new("secret"))
}

#[tokio::test]
async fn anonymous_write_through_insecure_channel_is_audited() {
    let h = harness(FailMode::Open).await;
    let session = h
        .connect(
            "a",
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
            false,
        )
        .await
        .unwrap();

    let results = session
        .write(&[write_value(&h.setpoint, 12.5)])
        .await
        .unwrap();
    assert_eq!(results, vec![StatusCode::Good]);
    assert_eq!(
        read_value(&session, &h.setpoint).await,
        Variant::Double(12.5)
    );
    session.disconnect().await.unwrap();

    let writes = h.records("write").await;
    assert_eq!(writes.len(), 1);
    let record = &writes[0];
    assert_eq!(record.entry.target.as_deref(), Some("plc1"));
    let client = record.entry.client.as_ref().unwrap();
    assert_eq!(client.application_uri.as_deref(), Some("urn:test-hmi-a"));
    assert_eq!(client.user, Some(UserIdentity::Anonymous));
    let AuditEvent::Write {
        node_id,
        display_name,
        old_value,
        new_value,
        status,
        ..
    } = &record.entry.event
    else {
        panic!("not a write: {:?}", record.entry.event);
    };
    assert_eq!(node_id, &h.setpoint.to_string());
    assert_eq!(display_name.as_deref(), Some("Setpoint"));
    assert_eq!(old_value.as_ref().unwrap().value, serde_json::json!(0.0));
    assert_eq!(new_value.value, serde_json::json!(12.5));
    assert_eq!(status, "Good");

    // Reads are not audited; the session lifecycle is. The client connects
    // twice: once for GetEndpoints, once for the session.
    assert_eq!(h.records("client_connected").await.len(), 2);
    assert_eq!(h.records("session_created").await.len(), 1);
    assert_eq!(h.records("session_activated").await.len(), 1);
    assert_eq!(h.records("session_closed").await.len(), 1);
    h.verify_chain().await;
}

async fn secure_write_as_operator(policy: SecurityPolicy, mode: MessageSecurityMode) {
    let h = harness(FailMode::Open).await;
    let session = h
        .connect("b", policy, mode, operator(), true)
        .await
        .unwrap();
    let results = session
        .write(&[write_value(&h.setpoint, 42.0)])
        .await
        .unwrap();
    assert_eq!(results, vec![StatusCode::Good]);
    assert_eq!(
        read_value(&session, &h.setpoint).await,
        Variant::Double(42.0)
    );
    session.disconnect().await.unwrap();

    let writes = h.records("write").await;
    assert_eq!(writes.len(), 1);
    let client = writes[0].entry.client.as_ref().unwrap();
    assert_eq!(
        client.user,
        Some(UserIdentity::UserName {
            name: "operator".into()
        })
    );
    assert!(client.certificate_thumbprint.is_some());
    // The first channel is the client's insecure GetEndpoints call.
    let channels = h.records("secure_channel_opened").await;
    let secured = channels.iter().any(|r| {
        matches!(&r.entry.event, AuditEvent::SecureChannelOpened { security_policy, security_mode }
            if security_policy == policy.to_str() && security_mode == &format!("{mode:?}"))
    });
    assert!(secured, "no {policy:?}/{mode:?} channel in {channels:?}");
    h.verify_chain().await;
}

#[tokio::test]
async fn username_write_through_basic256sha256_sign_and_encrypt() {
    secure_write_as_operator(
        SecurityPolicy::Basic256Sha256,
        MessageSecurityMode::SignAndEncrypt,
    )
    .await;
}

#[tokio::test]
async fn username_write_through_basic256sha256_sign() {
    secure_write_as_operator(SecurityPolicy::Basic256Sha256, MessageSecurityMode::Sign).await;
}

#[tokio::test]
async fn username_write_through_aes256_rsa_pss() {
    secure_write_as_operator(
        SecurityPolicy::Aes256Sha256RsaPss,
        MessageSecurityMode::SignAndEncrypt,
    )
    .await;
}

#[tokio::test]
async fn wrong_password_is_audited() {
    let h = harness(FailMode::Open).await;
    let result = h
        .connect(
            "c",
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::UserName("operator".into(), Password::new("wrong")),
            true,
        )
        .await;
    assert!(result.is_err());

    let failures = h.records("authentication_failed").await;
    assert!(!failures.is_empty());
    let client = failures[0].entry.client.as_ref().unwrap();
    assert_eq!(
        client.user,
        Some(UserIdentity::UserName {
            name: "operator".into()
        })
    );
    assert!(h.records("session_activated").await.is_empty());
}

#[tokio::test]
async fn untrusted_client_certificate_is_rejected() {
    let h = harness(FailMode::Open).await;
    let result = h
        .connect(
            "d",
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::Anonymous,
            false,
        )
        .await;
    assert!(result.is_err());

    let rejected = h.records("certificate_rejected").await;
    assert_eq!(rejected.len(), 1);
    // The administrator finds it in the rejected folder.
    let dir = CertificateStore::new(&h.gateway_pki).rejected_certs_dir();
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1);
}

#[tokio::test]
async fn method_call_is_audited() {
    let h = harness(FailMode::Open).await;
    let session = h
        .connect(
            "e",
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
            false,
        )
        .await
        .unwrap();
    let result = session
        .call_one(CallMethodRequest {
            object_id: ObjectId::ObjectsFolder.into(),
            method_id: h.method.clone(),
            input_arguments: Some(vec![Variant::Int32(3)]),
        })
        .await
        .unwrap();
    assert_eq!(result.status_code, StatusCode::Good);

    let calls = h.records("call").await;
    assert_eq!(calls.len(), 1);
    let AuditEvent::Call {
        method_id,
        display_name,
        input_arguments,
        status,
        ..
    } = &calls[0].entry.event
    else {
        unreachable!()
    };
    assert_eq!(method_id, &h.method.to_string());
    assert_eq!(display_name.as_deref(), Some("Reset"));
    assert_eq!(input_arguments[0].value, serde_json::json!(3));
    assert_eq!(status, "Good");
}

#[tokio::test]
async fn subscriptions_work_through_the_gateway() {
    use opcua::client::{DataChangeCallback, MonitoredItem};
    use opcua::types::MonitoredItemCreateRequest;

    let h = harness(FailMode::Open).await;
    let session = h
        .connect(
            "f",
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            operator(),
            true,
        )
        .await
        .unwrap();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let subscription = session
        .create_subscription(
            Duration::from_millis(100),
            100,
            10,
            0,
            0,
            true,
            DataChangeCallback::new(move |value: DataValue, _item: &MonitoredItem| {
                let _ = tx.send(value);
            }),
        )
        .await
        .unwrap();
    session
        .create_monitored_items(
            subscription,
            TimestampsToReturn::Both,
            vec![MonitoredItemCreateRequest::from(h.setpoint.clone())],
        )
        .await
        .unwrap();

    session
        .write(&[write_value(&h.setpoint, 7.0)])
        .await
        .unwrap();
    let saw_seven = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(v) = rx.recv().await {
            if v.value == Some(Variant::Double(7.0)) {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(saw_seven, "data change for the write did not arrive");
}

#[tokio::test]
async fn fail_closed_records_intent_before_forwarding() {
    let h = harness(FailMode::Closed).await;
    let session = h
        .connect(
            "g",
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
            false,
        )
        .await
        .unwrap();
    session
        .write(&[write_value(&h.setpoint, 1.0)])
        .await
        .unwrap();

    let intents = h.records("change_intent").await;
    let writes = h.records("write").await;
    assert_eq!(intents.len(), 1);
    assert_eq!(writes.len(), 1);
    assert!(intents[0].seq < writes[0].seq);
    h.verify_chain().await;
}

#[tokio::test]
async fn rejected_write_is_audited_with_status() {
    let h = harness(FailMode::Open).await;
    let session = h
        .connect(
            "h",
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
            false,
        )
        .await
        .unwrap();
    // The server rejects writes to a read-only variable.
    let results = session
        .write(&[write_value(&h.read_only, 5.0)])
        .await
        .unwrap();
    assert!(results[0].is_bad(), "{results:?}");

    let writes = h.records("write").await;
    let AuditEvent::Write { status, .. } = &writes[0].entry.event else {
        unreachable!()
    };
    assert_eq!(status, &results[0].to_string());
}

#[tokio::test]
async fn secure_channel_token_renewal_keeps_the_connection() {
    let h = harness(FailMode::Open).await;
    // The gateway grants at least 10 s; the client renews at 75 % of that.
    // Without working renewal the channel would expire after ~13 s.
    let session = h
        .connect_with(
            "i",
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            operator(),
            true,
            10_000,
        )
        .await
        .unwrap();
    for value in [1.0, 2.0, 3.0] {
        let results = session
            .write(&[write_value(&h.setpoint, value)])
            .await
            .unwrap();
        assert_eq!(results, vec![StatusCode::Good]);
        tokio::time::sleep(Duration::from_secs(7)).await;
    }
    assert_eq!(
        read_value(&session, &h.setpoint).await,
        Variant::Double(3.0)
    );
    // Still one connection for the session (plus the GetEndpoints one):
    // the channel was renewed, not re-established.
    assert_eq!(h.records("client_connected").await.len(), 2);
    assert_eq!(h.records("session_created").await.len(), 1);
    let olds: Vec<_> = h
        .records("write")
        .await
        .into_iter()
        .map(|r| match r.entry.event {
            AuditEvent::Write { old_value, .. } => old_value.map(|v| v.value),
            _ => None,
        })
        .collect();
    assert_eq!(
        olds,
        [0.0, 1.0, 2.0].map(|v| Some(serde_json::json!(v))).to_vec()
    );
}
