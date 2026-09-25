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
    relay: Arc<RelayTarget>,
    setpoint: NodeId,
    read_only: NodeId,
    method: NodeId,
}

/// Starts a test server ("the PLC") and a gateway in front of it.
async fn harness(fail_mode: FailMode) -> Harness {
    harness_with_latency(fail_mode, None).await
}

/// A TCP proxy in front of the PLC that delays every PLC -> gateway byte by
/// `delay` (order preserved): a PLC on a real network.
async fn delaying_proxy(plc_port: u16, delay: Duration) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((down, _)) = listener.accept().await {
            let up = tokio::net::TcpStream::connect(("127.0.0.1", plc_port))
                .await
                .unwrap();
            let (mut down_r, mut down_w) = down.into_split();
            let (mut up_r, mut up_w) = up.into_split();
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut down_r, &mut up_w).await;
                let _ = up_w.shutdown().await;
            });
            let (tx, mut rx) =
                tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match up_r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let due = tokio::time::Instant::now() + delay;
                            if tx.send((due, buf[..n].to_vec())).is_err() {
                                break;
                            }
                        }
                    }
                }
            });
            tokio::spawn(async move {
                while let Some((due, bytes)) = rx.recv().await {
                    tokio::time::sleep_until(due).await;
                    if down_w.write_all(&bytes).await.is_err() {
                        break;
                    }
                }
                let _ = down_w.shutdown().await;
            });
        }
    });
    port
}

async fn harness_with_latency(fail_mode: FailMode, latency: Option<Duration>) -> Harness {
    harness_with(fail_mode, latency, "").await
}

/// `target_options`: extra TOML lines for the target.
async fn harness_with(
    fail_mode: FailMode,
    latency: Option<Duration>,
    target_options: &str,
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let plc = start_test_plc(dir.path()).await;
    let server_port = match latency {
        Some(delay) => delaying_proxy(plc.port, delay).await,
        None => plc.port,
    };

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
        {target_options}
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
    ));
    let listener = bind(&relay).await.unwrap();
    tokio::spawn(serve(relay.clone(), listener));

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
        relay,
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

/// Audit finding P2: revoking trust in a client certificate ends its
/// connection at once, not when the client next reconnects.
#[tokio::test]
async fn untrusting_a_client_closes_its_connection() {
    let h = harness(FailMode::Open).await;
    let session = h
        .connect(
            "p2",
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            operator(),
            true,
        )
        .await
        .unwrap();
    assert_eq!(
        read_value(&session, &h.setpoint).await,
        Variant::Double(0.0)
    );

    let pki = Pki::open(&h.gateway_pki).unwrap();
    for cert in pki.trusted() {
        if cert.subject.contains("Test HMI p2") {
            pki.untrust(&cert.thumbprint).unwrap();
        }
    }
    h.relay.recheck_trust();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let result = session
        .read(
            &[ReadValueId {
                node_id: h.setpoint.clone(),
                attribute_id: AttributeId::Value as u32,
                ..Default::default()
            }],
            TimestampsToReturn::Neither,
            0.0,
        )
        .await;
    assert!(result.is_err(), "the revoked client can still read");
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
    // The intent already carries the value that is about to be written.
    let AuditEvent::ChangeIntent { details, .. } = &intents[0].entry.event else {
        panic!("expected an intent");
    };
    assert_eq!(details[0]["new_value"]["value"], serde_json::json!(1.0));
    h.verify_chain().await;
}

/// Audit finding R1: a client that sends a write and disconnects before the
/// response must not leave a change on the PLC without a record.
async fn write_then_disconnect(fail_mode: FailMode) {
    use std::collections::HashSet;
    let h = harness_with_latency(fail_mode, Some(Duration::from_millis(150))).await;
    let reader = h
        .connect(
            "r1-reader",
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
            false,
        )
        .await
        .unwrap();
    let client_pki = h.dir.path().join("client-r1-pki");
    let mut client = ClientBuilder::new()
        .application_name("Test HMI r1")
        .application_uri("urn:test-hmi-r1")
        .pki_dir(&client_pki)
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .client()
        .unwrap();

    let mut applied = Vec::new();
    for i in 0..4 {
        let value = 1000.0 + f64::from(i);
        let (session, event_loop) = client
            .connect_to_matching_endpoint(
                (
                    h.gateway_url.as_str(),
                    SecurityPolicy::None.to_uri(),
                    MessageSecurityMode::None,
                ),
                IdentityToken::Anonymous,
            )
            .await
            .unwrap();
        let handle = event_loop.spawn();
        assert!(
            tokio::time::timeout(Duration::from_secs(10), session.wait_for_connection())
                .await
                .unwrap_or(false)
        );
        // Fire the write, then kill the socket before the response arrives.
        let node = h.setpoint.clone();
        let write_session = session.clone();
        let writer = tokio::spawn(async move {
            let _ = write_session.write(&[write_value(&node, value)]).await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        handle.abort();
        writer.abort();
        drop(session);
        tokio::time::sleep(Duration::from_millis(300)).await;
        if read_value(&reader, &h.setpoint).await == Variant::Double(value) {
            applied.push(value);
        }
    }
    assert!(!applied.is_empty(), "no write reached the PLC");

    // The gateway finishes the writes after the client is gone.
    let mut missing = applied.clone();
    for _ in 0..50 {
        let recorded: HashSet<String> = h
            .records("write")
            .await
            .into_iter()
            .filter_map(|r| match r.entry.event {
                AuditEvent::Write { new_value, .. } => Some(new_value.value.to_string()),
                _ => None,
            })
            .collect();
        missing.retain(|v| !recorded.contains(&serde_json::json!(v).to_string()));
        if missing.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        missing.is_empty(),
        "writes applied on the PLC without an audit record: {missing:?}"
    );
    h.verify_chain().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_is_recorded_when_client_disconnects_fail_open() {
    write_then_disconnect(FailMode::Open).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn write_is_recorded_when_client_disconnects_fail_closed() {
    write_then_disconnect(FailMode::Closed).await;
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

/// Writes to an ignored node are summarised, not recorded one by one; other
/// items of the same request, and other clients (for a client-specific
/// rule), are recorded as usual.
#[tokio::test]
async fn ignored_writes_are_summarised() {
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
    h.relay.summarise.set(&[crate::config::SummariseGroup {
        nodes: vec![h.setpoint.to_string()],
        ..Default::default()
    }]);

    for i in 0..3 {
        let results = session
            .write(&[write_value(&h.setpoint, i as f64)])
            .await
            .unwrap();
        assert_eq!(results, vec![StatusCode::Good]);
    }
    // One request, an ignored and a recorded item: the recorded one keeps
    // its own result.
    let results = session
        .write(&[
            write_value(&h.setpoint, 7.0),
            write_value(&h.read_only, 1.0),
        ])
        .await
        .unwrap();
    assert_eq!(results[0], StatusCode::Good);
    assert!(results[1].is_bad());
    assert_eq!(
        read_value(&session, &h.setpoint).await,
        Variant::Double(7.0)
    );

    let writes = h.records("write").await;
    assert_eq!(writes.len(), 1, "only the read-only node is recorded");
    let AuditEvent::Write {
        node_id, status, ..
    } = &writes[0].entry.event
    else {
        panic!()
    };
    assert_eq!(node_id, &h.read_only.to_string());
    assert_eq!(status, &results[1].to_string());
    assert!(h.records("ignored_writes").await.is_empty());

    h.relay.record_ignored().await;
    let summaries = h.records("ignored_writes").await;
    assert_eq!(summaries.len(), 1);
    let AuditEvent::IgnoredWrites {
        node_id,
        count,
        failed,
        last_value,
        clients,
        ..
    } = &summaries[0].entry.event
    else {
        panic!()
    };
    assert_eq!(node_id, &h.setpoint.to_string());
    assert_eq!((*count, *failed), (4, 0));
    assert_eq!(last_value.value, serde_json::json!(7.0));
    assert_eq!(clients.len(), 1);
    assert!(clients[0].starts_with("127.0.0.1 "), "{clients:?}");
    // The summary is filed under the node, like its writes.
    assert_eq!(
        summaries[0].entry.event.node_id(),
        Some(h.setpoint.to_string().as_str())
    );

    // A group for another client summarises nothing from this one.
    h.relay.summarise.set(&[crate::config::SummariseGroup {
        client: Some("urn:another-hmi".into()),
        nodes: vec![h.setpoint.to_string()],
        ..Default::default()
    }]);
    session
        .write(&[write_value(&h.setpoint, 8.0)])
        .await
        .unwrap();
    assert_eq!(h.records("write").await.len(), 2);
    session.disconnect().await.unwrap();
    h.verify_chain().await;
}

/// With a minimum security above None, clients still discover the secure
/// endpoints over an insecure channel (OPC UA requires it), but cannot open
/// a session over it.
#[tokio::test]
async fn discovery_works_over_none_when_none_is_not_offered() {
    let h = harness_with(FailMode::Open, None, r#"min_security = "sign_and_encrypt""#).await;
    let client = ClientBuilder::new()
        .application_name("probe")
        .application_uri("urn:probe")
        .pki_dir(h.dir.path().join("probe-pki"))
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(0)
        .client()
        .unwrap();
    let endpoints = client
        .get_server_endpoints_from_url(h.gateway_url.as_str())
        .await
        .expect("GetEndpoints over an insecure channel");
    assert!(!endpoints.is_empty());
    assert!(endpoints
        .iter()
        .all(|e| e.security_mode == MessageSecurityMode::SignAndEncrypt));

    let session = h
        .connect(
            "a",
            SecurityPolicy::None,
            MessageSecurityMode::None,
            IdentityToken::Anonymous,
            false,
        )
        .await;
    assert!(session.is_err(), "no session over None");
    let session = h
        .connect(
            "a",
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
            IdentityToken::Anonymous,
            true,
        )
        .await
        .expect("a secure session");
    session.disconnect().await.unwrap();
}
