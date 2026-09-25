//! Shared test helpers: an in-process OPC UA server standing in for a PLC.

use std::path::{Path, PathBuf};
use std::time::Duration;

use opcua::crypto::{CertificateStore, SecurityPolicy};
use opcua::server::address_space::{MethodBuilder, VariableBuilder};
use opcua::server::diagnostics::NamespaceMetadata;
use opcua::server::node_manager::memory::{simple_node_manager, SimpleNodeManager};
use opcua::server::{ServerBuilder, ServerHandle, ServerUserToken, ANONYMOUS_USER_TOKEN_ID};
use opcua::types::{DataTypeId, MessageSecurityMode, NodeId, ObjectId};

pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Puts a certificate file into a PKI directory's trust list.
pub fn trust(store_dir: &Path, cert_file: &Path) {
    let cert = CertificateStore::read_cert(cert_file).unwrap();
    let dir = CertificateStore::new(store_dir).trusted_certs_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(cert_file, dir.join(CertificateStore::cert_file_name(&cert))).unwrap();
}

pub async fn wait_listening(port: u16) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("nothing listens on port {port}");
}

/// A test server with anonymous and `operator`/`secret` logins, endpoints for
/// None, Basic256Sha256 (Sign, SignAndEncrypt) and Aes256Sha256RsaPss, and:
/// a writable Double `Setpoint`, a read-only `ReadOnly` and a method `Reset`.
pub struct TestPlc {
    pub handle: ServerHandle,
    pub port: u16,
    pub url: String,
    /// The server's own certificate file.
    pub certificate: PathBuf,
    pub setpoint: NodeId,
    pub read_only: NodeId,
    pub method: NodeId,
}

impl Drop for TestPlc {
    fn drop(&mut self) {
        self.handle.cancel();
    }
}

pub async fn start_test_plc(dir: &Path) -> TestPlc {
    let server_port = free_port();
    let tokens = [ANONYMOUS_USER_TOKEN_ID, "operator"];
    let endpoint =
        |policy: SecurityPolicy, mode: MessageSecurityMode| ("/", policy, mode, &tokens as &[&str]);
    let (server, handle) = ServerBuilder::new()
        .application_name("Test PLC")
        .application_uri("urn:test-plc")
        .host("127.0.0.1")
        .port(server_port)
        .pki_dir(dir.join("plc-pki"))
        .create_sample_keypair(true)
        // The PLC trusts the gateway (in production: only the gateway).
        .trust_client_certs(true)
        .discovery_urls(vec!["/".into()])
        .add_user_token("operator", ServerUserToken::user_pass("operator", "secret"))
        .add_endpoint(
            "none",
            endpoint(SecurityPolicy::None, MessageSecurityMode::None),
        )
        .add_endpoint(
            "b256_sign",
            endpoint(SecurityPolicy::Basic256Sha256, MessageSecurityMode::Sign),
        )
        .add_endpoint(
            "b256_encrypt",
            endpoint(
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::SignAndEncrypt,
            ),
        )
        .add_endpoint(
            "pss_encrypt",
            endpoint(
                SecurityPolicy::Aes256Sha256RsaPss,
                MessageSecurityMode::SignAndEncrypt,
            ),
        )
        .with_node_manager(simple_node_manager(
            NamespaceMetadata {
                namespace_uri: "urn:test".into(),
                ..Default::default()
            },
            "test",
        ))
        .build()
        .unwrap();
    tokio::spawn(server.run());

    let manager = handle
        .node_managers()
        .get_of_type::<SimpleNodeManager>()
        .unwrap();
    let ns = handle.get_namespace_index("urn:test").unwrap();
    let setpoint = NodeId::new(ns, "Setpoint");
    let method = NodeId::new(ns, "Reset");
    let read_only = NodeId::new(ns, "ReadOnly");
    {
        let mut space = manager.address_space().write();
        VariableBuilder::new(&setpoint, "Setpoint", "Setpoint")
            .data_type(DataTypeId::Double)
            .value(0.0f64)
            .writable()
            .organized_by(ObjectId::ObjectsFolder)
            .insert(&mut *space);
        VariableBuilder::new(&read_only, "ReadOnly", "ReadOnly")
            .data_type(DataTypeId::Double)
            .value(1.0f64)
            .organized_by(ObjectId::ObjectsFolder)
            .insert(&mut *space);
        MethodBuilder::new(&method, "Reset", "Reset")
            .component_of(ObjectId::ObjectsFolder)
            .executable(true)
            .user_executable(true)
            .input_args(
                &mut *space,
                &NodeId::new(ns, "ResetArgs"),
                &[("Level", DataTypeId::Int32).into()],
            )
            .insert(&mut *space);
    }
    manager
        .inner()
        .add_method_callback(method.clone(), |_args| Ok(Vec::new()));

    wait_listening(server_port).await;
    TestPlc {
        handle,
        port: server_port,
        url: format!("opc.tcp://127.0.0.1:{server_port}/"),
        certificate: dir.join("plc-pki/own/cert.der"),
        setpoint,
        read_only,
        method,
    }
}

/// A new self-signed certificate (DER), for tests that need any certificate.
pub fn self_signed_der() -> Vec<u8> {
    let dir = tempfile::tempdir().unwrap();
    let store = opcua::crypto::CertificateStore::new(dir.path());
    let (cert, _) = store
        .create_and_store_application_instance_cert(
            &opcua::crypto::X509Data {
                key_size: 2048,
                common_name: "test".into(),
                organization: "test".into(),
                organizational_unit: "test".into(),
                country: String::new(),
                state: String::new(),
                alt_host_names: opcua::crypto::X509Data::alt_host_names(
                    "urn:test", None, false, false, false,
                ),
                certificate_duration_days: 1,
            },
            true,
        )
        .unwrap();
    cert.to_der().unwrap()
}
