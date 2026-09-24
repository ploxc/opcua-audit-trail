//! A stand-in PLC for trying the gateway without hardware.
//!
//! ```sh
//! cargo run --example demo_plc              # opc.tcp://127.0.0.1:4840/
//! cargo run --example demo_plc -- 0.0.0.0 4850
//! ```
//!
//! Logins: anonymous, or `operator` / `operator`. Security: None and
//! Basic256Sha256 (Sign, SignAndEncrypt). The server trusts every client
//! certificate, which a real PLC must not do. Its PKI lives in `./demo-plc-pki`.
//!
//! Address space (namespace `urn:demo-plc:line`), under Objects/Line1:
//! `Setpoint` (Double, writable), `Temperature` (Double, simulated),
//! `Running` (Boolean, writable), `Counter` (Int32, counts up),
//! `Recipe` (String, writable), `ResetCounter()` (method).

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use opcua::crypto::SecurityPolicy;
use opcua::server::address_space::{MethodBuilder, ObjectBuilder, VariableBuilder};
use opcua::server::diagnostics::NamespaceMetadata;
use opcua::server::node_manager::memory::{simple_node_manager, SimpleNodeManager};
use opcua::server::{ServerBuilder, ServerUserToken, ANONYMOUS_USER_TOKEN_ID};
use opcua::types::{DataTypeId, DataValue, MessageSecurityMode, NodeId, ObjectId, Variant};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,opcua=warn".into()),
        )
        .init();
    let mut args = std::env::args().skip(1);
    let host = args.next().unwrap_or_else(|| "127.0.0.1".into());
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(4840);

    let tokens = [ANONYMOUS_USER_TOKEN_ID, "operator"];
    let (server, handle) = ServerBuilder::new()
        .application_name("Demo PLC")
        .application_uri("urn:demo-plc")
        .product_uri("urn:demo-plc")
        .host(host.clone())
        .port(port)
        .pki_dir("./demo-plc-pki")
        .create_sample_keypair(true)
        .trust_client_certs(true)
        .discovery_urls(vec!["/".into()])
        .add_user_token(
            "operator",
            ServerUserToken::user_pass("operator", "operator"),
        )
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
            "sign",
            (
                "/",
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::Sign,
                &tokens as &[&str],
            ),
        )
        .add_endpoint(
            "encrypt",
            (
                "/",
                SecurityPolicy::Basic256Sha256,
                MessageSecurityMode::SignAndEncrypt,
                &tokens as &[&str],
            ),
        )
        .with_node_manager(simple_node_manager(
            NamespaceMetadata {
                namespace_uri: "urn:demo-plc:line".into(),
                ..Default::default()
            },
            "demo",
        ))
        .build()
        .expect("server configuration");

    let manager = handle
        .node_managers()
        .get_of_type::<SimpleNodeManager>()
        .expect("demo node manager");
    let ns = handle
        .get_namespace_index("urn:demo-plc:line")
        .expect("namespace");
    let line = NodeId::new(ns, "Line1");
    let temperature = NodeId::new(ns, "Line1.Temperature");
    let counter = NodeId::new(ns, "Line1.Counter");
    let reset = NodeId::new(ns, "Line1.ResetCounter");
    {
        let mut space = manager.address_space().write();
        ObjectBuilder::new(&line, "Line1", "Line1")
            .organized_by(ObjectId::ObjectsFolder)
            .insert(&mut *space);
        let variable = |id: &str, data_type: DataTypeId, value: Variant, writable: bool| {
            let node = NodeId::new(ns, format!("Line1.{id}"));
            let mut builder = VariableBuilder::new(&node, id, id)
                .data_type(data_type)
                .value(value)
                .component_of(line.clone());
            if writable {
                builder = builder.writable();
            }
            builder
        };
        variable("Setpoint", DataTypeId::Double, 65.0f64.into(), true).insert(&mut *space);
        variable("Temperature", DataTypeId::Double, 20.0f64.into(), false).insert(&mut *space);
        variable("Running", DataTypeId::Boolean, false.into(), true).insert(&mut *space);
        variable("Counter", DataTypeId::Int32, 0i32.into(), false).insert(&mut *space);
        variable("Recipe", DataTypeId::String, "Default".into(), true).insert(&mut *space);
        MethodBuilder::new(&reset, "ResetCounter", "ResetCounter")
            .component_of(line.clone())
            .executable(true)
            .user_executable(true)
            .insert(&mut *space);
    }

    let count = Arc::new(AtomicI32::new(0));
    let reset_count = count.clone();
    manager.inner().add_method_callback(reset, move |_| {
        reset_count.store(0, Ordering::Relaxed);
        Ok(Vec::new())
    });

    // Simulate the process: temperature drifts, the counter counts.
    let sim_manager = manager.clone();
    let subscriptions = handle.subscriptions().clone();
    tokio::spawn(async move {
        let mut t: f64 = 0.0;
        let mut tick = tokio::time::interval(Duration::from_millis(1000));
        loop {
            tick.tick().await;
            t += 1.0;
            let n = count.fetch_add(1, Ordering::Relaxed) + 1;
            let temp = 60.0 + 5.0 * (t / 20.0).sin();
            sim_manager
                .set_values(
                    &subscriptions,
                    [
                        (
                            &temperature,
                            None,
                            DataValue::new_now((temp * 10.0).round() / 10.0),
                        ),
                        (&counter, None, DataValue::new_now(n)),
                    ]
                    .into_iter(),
                )
                .ok();
        }
    });

    println!("Demo PLC on opc.tcp://{host}:{port}/  (logins: anonymous, operator/operator)");
    server.run().await.expect("server");
}
