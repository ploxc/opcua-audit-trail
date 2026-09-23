# OPC UA Audit Gateway

A transparent OPC UA gateway that records **who writes what, when**.

Put it between your OPC UA clients and your PLC. Clients connect to the gateway
instead of the PLC; the gateway forwards everything and keeps a tamper-evident
audit trail of every write, method call and client session. It is a single Rust
binary that runs standalone (Linux, Windows, macOS, ARM PLCs such as PLCnext) or
in Docker.

> **Status: milestones 1–5 of 7.** The relay works for security `None`, `Sign`
> and `SignAndEncrypt` (all RSA policies), anonymous and user name logins, and
> every service (reads, writes, subscriptions, method calls, …). Writes, method
> calls, history updates, node management, sessions and connections are
> audited, with old value → new value and the node's display name. The web UI
> covers status, the audit trail, targets, certificates, an OPC UA browser and
> users. Next: packaging (Windows service, systemd, releases) and HTTPS.
> See [ARCHITECTURE.md](ARCHITECTURE.md) for the design and roadmap.

## Try it without a PLC

```sh
cargo run --example demo_plc                       # a stand-in PLC on :4840
cargo run -- init                                  # config.toml + certificate
# add to config.toml:
#   [[targets]]
#   name = "line1"
#   listen = "0.0.0.0:4841"
#   endpoint_url = "opc.tcp://127.0.0.1:4840/"
cargo run -- run                                   # prints the admin password once
cargo run --example demo_client -- opc.tcp://127.0.0.1:4841/
```

Open http://127.0.0.1:8080 and log in as `admin` to watch the writes arrive.

## Quick start (binary)

```sh
cargo build --release
./target/release/opcua-audit-gateway init        # writes config.toml, creates pki/
./target/release/opcua-audit-gateway discover opc.tcp://192.168.0.10:4840
# add a [[targets]] block to config.toml, then:
./target/release/opcua-audit-gateway run         # web UI on http://127.0.0.1:8080
                                                 # (first start prints the admin password)
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

The web UI's **Certificates** page does all of this with buttons. The
**Targets** page can trust a PLC certificate directly from discovery.

## Quick start (Docker)

```sh
# edit docker/config.toml (targets, certificate_hostnames), then
docker compose up -d
```

Data (certificates, users and the audit database) lives in the `gateway-data`
volume. The initial admin password is in `docker compose logs gateway`.

## Web UI

| Page | Role | |
|---|---|---|
| Dashboard | auditor | Reachability of each target, connected clients, latest changes |
| Audit trail | auditor | Filters, record details, live mode, CSV export, integrity check |
| Targets | auditor (admin edits) | Add/edit/remove targets without a restart, discovery, trust the PLC certificate |
| Certificates | auditor (admin acts) | Gateway certificate (download/import/regenerate), trust or reject certificates |
| Browser | operator | Read-only address space browser with live values |
| Users | admin | Users and roles |

Roles are cumulative: auditor < operator < admin. Manage users from the
command line with `opcua-audit-gateway user add|passwd|role|delete|list`.

## REST API

All routes need a session cookie from `POST /api/login`. State-changing
requests also need the header `X-Requested-With: opcua-audit-gateway`.

| Method | Path | |
|---|---|---|
| GET | `/api/status` | Version, certificate, targets with upstream state and endpoints |
| GET | `/api/targets` | Target status only |
| GET | `/api/targets/{name}/clients` | Clients connected through the gateway |
| POST | `/api/targets/{name}/discover` | Discover a configured target now |
| POST | `/api/discover` | `{"endpoint_url": "opc.tcp://…"}`: discover any server |
| GET | `/api/certificates` | Own, trusted and rejected certificates |
| GET | `/api/audit` | Audit records, newest first. Filters: `target`, `kind`, `user`, `node_id`, `since`, `until`, `before_seq`, `limit` |
| GET | `/api/audit.csv` | The same filters, as CSV |
| GET | `/api/audit/verify` | Verify the hash chain |
| | `/api/targets`, `/api/certificates/…`, `/api/users`, `/api/browser/{target}/…` | Used by the UI; see `src/web/mod.rs` |

The web UI serves plain HTTP. Put it behind a TLS reverse proxy (or keep it on
`127.0.0.1`) until built-in HTTPS arrives.

## Development

```sh
cargo test          # includes tests against an in-process OPC UA server
cargo clippy --all-targets -- -D warnings
```

Set `RUST_LOG=debug` for verbose logging.

## License

MIT
