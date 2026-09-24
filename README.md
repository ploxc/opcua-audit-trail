# OPC UA Audit Gateway

A transparent OPC UA gateway that records **who writes what, when**.

Put it between your OPC UA clients and your PLC. Clients connect to the gateway
instead of the PLC; the gateway forwards everything and keeps a tamper-evident
audit trail of every write, method call and client session. It is a single Rust
binary that runs standalone (Linux, Windows, macOS, ARM PLCs such as PLCnext) or
in Docker.

> **Status: all 7 roadmap milestones done; not yet tested against real PLCs.** The relay works for security `None`, `Sign`
> and `SignAndEncrypt` (all RSA policies), anonymous and user name logins, and
> every service (reads, writes, subscriptions, method calls, …). Writes, method
> calls, history updates, node management, sessions and connections are
> audited, with old value → new value and the node's display name. The web UI
> covers status, the audit trail, targets, certificates, an OPC UA browser and
> users. Audit records can be exported to QuestDB and syslog. It installs as
> a systemd or Windows service or runs as a container, with optional HTTPS.
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

## Installation

Release archives (Linux x86_64/ARM64/ARMv7 static, Windows, macOS) and
multi-arch images (`ghcr.io/harted/opcua-audit-trail`) are built for every
`v*` tag.

### Linux (systemd)

```sh
tar xzf opcua-audit-gateway-*-linux-amd64.tar.gz && cd opcua-audit-gateway-*
sudo ./install.sh ./opcua-audit-gateway
sudo nano /etc/opcua-audit-gateway/config.toml    # or add targets in the web UI
journalctl -u opcua-audit-gateway | grep password  # initial admin password
```

The service runs as the unprivileged user `opcua-gw` with a hardened unit.
Data, certificates and the audit trail live in `/var/lib/opcua-audit-gateway`.
Running `install.sh` again upgrades the binary and keeps config and data.
On a PLCnext controller use the `armv7` archive or the container image.

### Windows (service)

```powershell
opcua-audit-gateway.exe --config C:\gateway\config.toml init
opcua-audit-gateway.exe --config C:\gateway\config.toml service install   # as administrator
sc start OpcUaAuditGateway
```

Logs go to `C:\gateway\logs` (daily files, kept 14 days), including the
initial admin password. `service uninstall` removes the service. Any command
accepts `--log-dir` to log to files instead of the console.

### Docker

```sh
docker compose up -d
docker compose logs gateway | grep password
```

Everything (config, certificates, users, audit trail) lives in the `/data`
volume. On the first start `/data/config.toml` is created from
`docker/config.toml`. Manage targets in the web UI. To change other settings:
`docker compose cp gateway:/data/config.toml .`, edit the file,
`docker compose cp config.toml gateway:/data/config.toml`, then
`docker compose restart gateway`.

## HTTPS

```toml
[web]
listen = "0.0.0.0:8443"
tls = true                          # uses the gateway certificate, or:
# tls_certificate = "web-cert.pem"  # PEM chain, e.g. from your plant CA
# tls_private_key = "web-key.pem"
```

With the gateway certificate, browsers ask once to accept it. To avoid that,
import `pki/own/cert.der` as trusted, or use a certificate from your own CA.
With TLS the session cookie is marked `Secure`.

## Audit export

The audit trail lives in the gateway (SQLite) and can also be copied to other
systems. Each destination keeps its own position in `data/export-state.json`:
nothing is skipped while a destination is down, and records are delivered at
least once.

```toml
[export.questdb]              # long-term storage and SQL analysis
url = "http://questdb:9000"   # ILP over HTTP; each batch is acknowledged
table = "opcua_audit"         # created on first write
# token = "…"  or  username = "…" / password = "…"

[export.syslog]               # SIEM: Graylog, Splunk, Wazuh, rsyslog, …
address = "siem.local:514"
protocol = "tcp"              # RFC 6587 framing; "udp" is fire-and-forget
facility = 16                 # local0
```

Every exported record carries its sequence number and hash. Once records are
outside the gateway, rewriting the local database no longer goes unnoticed:
compare the hashes. In QuestDB, make retries idempotent with
`ALTER TABLE opcua_audit DEDUP ENABLE UPSERT KEYS(ts, seq)`.

The dashboard shows each destination's state and how many records are waiting.

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

By default the web UI serves plain HTTP on `127.0.0.1`. For remote access,
enable HTTPS (see above).

## Development

```sh
cargo test          # includes tests against an in-process OPC UA server
cargo clippy --all-targets -- -D warnings
```

Set `RUST_LOG=debug` for verbose logging.

## License

MIT
