# Try it without a PLC

A stand-in PLC and a client that keeps writing to it, all on your machine
(needs Rust):

```sh
cargo run --example demo_plc                       # a stand-in PLC on :4840
cargo run -- init                                  # config.toml + certificate
# add to config.toml:
#   [[targets]]
#   name = "line1"
#   listen = "0.0.0.0:4841"
#   endpoint_url = "opc.tcp://127.0.0.1:4840/"
cargo run -- run                                   # prints the first admin password
cargo run --example demo_client -- opc.tcp://127.0.0.1:4841/
```

Open http://127.0.0.1:8080 and log in as `admin` with the password `run`
printed, then choose your own. Watch the writes arrive in the audit trail.

## Locked down

To try it as a PLC should be (only the gateway may connect, encrypted, with a
login), start the stand-in PLC with `--strict` and the client with
`--secure`:

```sh
cargo run --example demo_plc -- --strict           # SignAndEncrypt only, login operator/operator
# target: add  min_security = "sign_and_encrypt"
cargo run --example demo_client -- opc.tcp://127.0.0.1:4841/ operator operator --secure
```

Then trust, one step at a time (see [Certificates](certificates.md)):

1. The PLC certificate in the gateway: **Targets → Trust…**.
2. The gateway certificate in the PLC: move it from `demo-plc-pki/rejected`
   to `demo-plc-pki/trusted`.
3. The client certificate in the gateway: **Certificates → Trust**.

The same client pointed directly at the PLC (`opc.tcp://127.0.0.1:4840/`)
stays locked out.

## Closer to the real thing

[`docker/opc-plc`](../../docker/opc-plc/README.md) starts Microsoft's open
source OPC PLC (many changing values, several security policies), locked
down the same way.

To load the gateway, `cargo run --release --example stress -- all` runs
stress scenarios against it (see the comment at the top of
`examples/stress.rs`).
