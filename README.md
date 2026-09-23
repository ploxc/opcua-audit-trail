# OPC UA Audit Gateway

A transparent OPC UA gateway that records **who writes what, when**.

Put it between your OPC UA clients and your PLC. Clients connect to the gateway
instead of the PLC; the gateway forwards everything and keeps a tamper-evident
audit trail of every write, method call and client session. It is a single Rust
binary that runs standalone (Linux, Windows, macOS, ARM PLCs such as PLCnext) or
in Docker.

> **Status: milestone 1 of 7.** Configuration, certificates, the audit store,
> target discovery/monitoring and the REST API work. The OPC UA relay itself is
> the next milestone, so clients cannot connect through the gateway yet.
> See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and roadmap.

## Quick start (binary)

```sh
cargo build --release
./target/release/opcua-audit-gateway init        # writes config.toml, creates pki/
./target/release/opcua-audit-gateway discover opc.tcp://192.168.0.10:4840
# add a [[targets]] block to config.toml, then:
./target/release/opcua-audit-gateway run         # web UI on http://127.0.0.1:8080
./target/release/opcua-audit-gateway verify      # check the audit trail's hash chain
```

`discover` lists the server's security policies, modes and login methods (example output):

```
server: PLCnext (urn:PLCnext:AXC F 2152)
security policy          mode             level  user tokens
Basic256Sha256           SignAndEncrypt       3  Anonymous, UserName
None                     None                 0  Anonymous, UserName
```

## Quick start (Docker)

```sh
# edit docker/config.toml (targets, certificate_hostnames), then
docker compose up -d
```

Data (certificates and the audit database) lives in the `gateway-data` volume.

## REST API

| Method | Path | |
|---|---|---|
| GET | `/api/status` | Version, certificate, targets with upstream state and endpoints |
| GET | `/api/targets` | Target status only |
| POST | `/api/targets/{name}/discover` | Discover a configured target now |
| POST | `/api/discover` | `{"endpoint_url": "opc.tcp://…"}`: discover any server |
| GET | `/api/certificates` | Own, trusted and rejected certificates |
| GET | `/api/audit` | Audit records, newest first. Filters: `target`, `kind`, `user`, `node_id`, `since`, `until`, `before_seq`, `limit` |
| GET | `/api/audit/verify` | Verify the hash chain |

The API has no authentication yet and binds to `127.0.0.1` by default.

## Development

```sh
cargo test          # includes tests against an in-process OPC UA server
cargo clippy --all-targets -- -D warnings
```

Set `RUST_LOG=debug` for verbose logging.

## License

MIT
