//! A client that keeps changing the demo PLC, to see the audit trail fill up.
//!
//! ```sh
//! cargo run --example demo_client -- opc.tcp://127.0.0.1:4841/            # anonymous
//! cargo run --example demo_client -- opc.tcp://127.0.0.1:4841/ operator operator
//! cargo run --example demo_client -- opc.tcp://127.0.0.1:4841/ operator operator --secure
//! ```
//!
//! It connects without security (`None`), or with `--secure` with
//! Basic256Sha256 SignAndEncrypt (its certificate is in `./demo-client-pki`),
//! writes `Setpoint`, `Running` and `Recipe` and calls `ResetCounter` every
//! few seconds.

use std::time::Duration;

use opcua::client::{ClientBuilder, IdentityToken, Password};
use opcua::crypto::SecurityPolicy;
use opcua::types::{
    AttributeId, CallMethodRequest, DataValue, MessageSecurityMode, NodeId, NumericRange,
    WriteValue,
};

#[tokio::main]
async fn main() {
    let all: Vec<String> = std::env::args().skip(1).collect();
    let secure = all.iter().any(|a| a == "--secure");
    let mut args = all.into_iter().filter(|a| !a.starts_with("--"));
    let url = args
        .next()
        .unwrap_or_else(|| "opc.tcp://127.0.0.1:4841/".into());
    let identity = match (args.next(), args.next()) {
        (Some(user), Some(password)) => IdentityToken::UserName(user, Password::new(password)),
        _ => IdentityToken::Anonymous,
    };

    let mut client = ClientBuilder::new()
        .application_name("Demo HMI")
        .application_uri("urn:demo-hmi")
        .pki_dir("./demo-client-pki")
        .create_sample_keypair(true)
        .trust_server_certs(true)
        .session_retry_limit(3)
        .client()
        .expect("client configuration");
    let (session, event_loop) = client
        .connect_to_matching_endpoint(
            if secure {
                (
                    url.as_str(),
                    SecurityPolicy::Basic256Sha256.to_uri(),
                    MessageSecurityMode::SignAndEncrypt,
                )
            } else {
                (
                    url.as_str(),
                    SecurityPolicy::None.to_uri(),
                    MessageSecurityMode::None,
                )
            },
            identity,
        )
        .await
        .expect("connect");
    event_loop.spawn();
    session.wait_for_connection().await;
    println!("connected to {url}");

    let ns = session
        .get_namespace_index("urn:demo-plc:line")
        .await
        .expect("the demo PLC's namespace");
    let node = |name: &str| NodeId::new(ns, format!("Line1.{name}"));
    let write = |name: &str, value: DataValue| WriteValue {
        node_id: node(name),
        attribute_id: AttributeId::Value as u32,
        index_range: NumericRange::None,
        value,
    };

    let mut step: u32 = 0;
    loop {
        step += 1;
        let setpoint = 60.0 + f64::from(step % 7) * 2.5;
        let result = session
            .write(&[
                write("Setpoint", DataValue::new_now(setpoint)),
                write("Running", DataValue::new_now(step.is_multiple_of(2))),
            ])
            .await;
        println!("write Setpoint={setpoint}: {result:?}");
        if step.is_multiple_of(3) {
            let recipe = ["Default", "Batch A", "Batch B"][(step / 3 % 3) as usize];
            let result = session
                .write(&[write("Recipe", DataValue::new_now(recipe))])
                .await;
            println!("write Recipe={recipe}: {result:?}");
        }
        if step.is_multiple_of(5) {
            let result = session
                .call_one(CallMethodRequest {
                    object_id: NodeId::new(ns, "Line1"),
                    method_id: node("ResetCounter"),
                    input_arguments: None,
                })
                .await
                .map(|r| r.status_code);
            println!("call ResetCounter: {result:?}");
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}
