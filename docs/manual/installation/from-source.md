# From source

```sh
cargo build --release
./target/release/opcua-audit-gateway init        # writes config.toml, creates pki/
./target/release/opcua-audit-gateway discover opc.tcp://192.168.0.10:4840
# add a [[targets]] block to config.toml (or add targets in the web UI), then:
./target/release/opcua-audit-gateway run         # web UI on http://127.0.0.1:8080
./target/release/opcua-audit-gateway verify      # check the audit trail's hash chain
```

`run` prints the first admin password (see [First login](../first-login.md)).
Clients now connect to the gateway (`opc.tcp://<gateway>:<listen port>`)
instead of the PLC.

`discover` lists the server's security policies, modes and login methods
(example output):

```
server: PLCnext (urn:PLCnext:AXC F 2152)
security policy          mode             level  user tokens
Basic256Sha256           SignAndEncrypt       3  Anonymous, UserName
None                     None                 0  Anonymous, UserName
```

See [Targets](../targets.md) for the `[[targets]]` block.

## Development

```sh
cargo test          # includes tests against an in-process OPC UA server
cargo clippy --all-targets -- -D warnings
```

Set `RUST_LOG=debug` for verbose logging.
