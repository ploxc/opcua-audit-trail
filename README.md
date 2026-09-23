# OPC UA Audit Gateway

A transparent OPC UA gateway that records **who writes what, when**.

Put it between your OPC UA clients and your PLC. Clients connect to the gateway
instead of the PLC; the gateway forwards everything and keeps a tamper-evident
audit trail of every write, method call and client session. It is a single Rust
binary that runs standalone (Linux, Windows, macOS, ARM PLCs such as PLCnext) or
in Docker.

> **Status: milestones 1–4 of 7.** The relay works for security `None`, `Sign`
> and `SignAndEncrypt` (all RSA policies), anonymous and user name logins, and
> every service (reads, writes, subscriptions, method calls, …). Writes, method
> calls, history updates, node management, sessions and connections are
> audited, with old value → new value and the node's display name.
> Next: the web UI.
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

Clients now connect to the gateway (`opc.tcp://<gateway>:<listen port>`)
instead of the PLC.

`discover` lists the server's security policies, modes and login methods (example output):

```
server: PLCnext (urn:PLCnext:AXC F 2152)
security policy          mode             level  user tokens
Basic256Sha256           SignAndEncrypt       3  Anonymous, UserName
None                     None                 0  Anonymous, UserName
```

## Certificates

The gateway follows standard OPC UA trust handling, in its `pki/` directory:

* **PLC → gateway.** The PLC must trust the gateway certificate,
  `pki/own/cert.der`. Import it into the PLC's trust list. The PLC should
  trust *only* the gateway, so no client can bypass it.
* **Gateway → PLC.** On the first secure connection the PLC certificate lands
  in `pki/rejected/`. Move it to `pki/trusted/`.
* **Client → gateway.** Unknown client certificates land in `pki/rejected/`,
  and each one is recorded as `certificate_rejected` in the audit trail. Move a
  certificate to `pki/trusted/` to allow that client.

The web UI will turn these moves into buttons.

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
| GET | `/api/targets/{name}/clients` | Clients connected through the gateway |
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
