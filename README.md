# OPC UA Audit Gateway

A transparent OPC UA gateway that records **who writes what, when**.

Put it between your OPC UA clients and your PLC. Clients connect to the gateway
instead of the PLC; the gateway forwards everything and keeps a tamper-evident
audit trail of every write, method call and client session. It is a single Rust
binary that runs standalone (Linux, Windows, macOS, ARM PLCs such as PLCnext) or
in Docker.

> **Status: a working concept, not production ready.** The code was written
> with Claude (Anthropic), from my idea and OPC UA/PLC domain knowledge, and
> tested as described in [What is tested](#what-is-tested). If there is
> interest, I'm open to developing it further.

What it does today:

- **Relay:** works for security `None`, `Sign` and `SignAndEncrypt` (all RSA
  policies), anonymous and user name logins, and every service (reads, writes,
  subscriptions, method calls, …).
- **Audit trail:** writes, method calls, history updates, node management,
  sessions and connections are recorded, with old value → new value and the
  node's display name, in a hash chain that shows any tampering.
- **Web UI:** status, the audit trail, targets, certificates, an OPC UA
  browser, users and settings.
- **Export:** audit records to QuestDB.
- **Installation:** packaging for a systemd or Windows service and for a
  container, with optional HTTPS.

See [ARCHITECTURE.md](ARCHITECTURE.md) for the design, and
[docs/audit](docs/audit/) for the security audit and its independent
verification.

## What is tested

Tested:

- About 90 automated tests: relay, audit store and hash chain, export, web API
  and certificates. The end-to-end tests run a real OPC UA client and server
  through the gateway.
- The web UI, in a browser (Chromium), page by page.
- By hand against [OPC PLC](docker/opc-plc/) (Microsoft's simulator, in
  Docker) with the Prosys OPC UA Browser as client:
  - encrypted connections up to `Aes256-Sha256-RsaPss`;
  - certificate trust in both directions;
  - user name logins and writes.
- Against Siemens PLCSIM Advanced.

Not tested yet (the code and files are there, but nobody has run them for
real):

- The Docker image and `docker-compose.yml` of the gateway itself.
- The Linux service installation (systemd, `packaging/linux`) and the Windows
  service.
- The release workflow (binaries and multi-arch images).
- Export to a real QuestDB (tested against a stand-in only).
- Real PLCs on a real network, over longer periods and under load.

## Try it without a PLC

```sh
cargo run --example demo_plc                       # a stand-in PLC on :4840
cargo run -- init                                  # config.toml + certificate
# add to config.toml:
#   [[targets]]
#   name = "line1"
#   listen = "0.0.0.0:4841"
#   endpoint_url = "opc.tcp://127.0.0.1:4840/"
cargo run -- run                                   # admin password: data/initial-admin-password.txt
cargo run --example demo_client -- opc.tcp://127.0.0.1:4841/
```

Open http://127.0.0.1:8080 and log in as `admin` with the password from
`data/initial-admin-password.txt`. You choose a new password at the first
login (the file is removed then). Then watch the writes arrive.

To try it locked down, as a PLC should be (only the gateway may connect,
encrypted, with a login), start the stand-in PLC with `--strict` and the
client with `--secure`:

```sh
cargo run --example demo_plc -- --strict           # SignAndEncrypt only, login operator/operator
# target: add  min_security = "sign_and_encrypt"
cargo run --example demo_client -- opc.tcp://127.0.0.1:4841/ operator operator --secure
```

Then trust, one step at a time: the PLC certificate in the gateway (**Targets
→ Trust server certificate**), the gateway certificate in the PLC (move it from
`demo-plc-pki/rejected` to `demo-plc-pki/trusted`), and the client certificate
in the gateway (**Certificates → Trust**). The same client pointed directly at
the PLC (`opc.tcp://127.0.0.1:4840/`) stays locked out.

For a simulated PLC closer to the real thing (many changing values, several
security policies), [`docker/opc-plc`](docker/opc-plc/README.md) starts
Microsoft's open source OPC PLC, locked down the same way.

## Quick start (binary)

```sh
cargo build --release
./target/release/opcua-audit-gateway init        # writes config.toml, creates pki/
./target/release/opcua-audit-gateway discover opc.tcp://192.168.0.10:4840
# add a [[targets]] block to config.toml, then:
./target/release/opcua-audit-gateway run         # web UI on http://127.0.0.1:8080
                                                 # (admin password: data/initial-admin-password.txt)
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

## Security per target

```toml
[[targets]]
name = "line1"
listen = "0.0.0.0:4841"
endpoint_url = "opc.tcp://192.168.0.10:4840"
min_security = "sign_and_encrypt"   # "none" (default), "sign", "sign_and_encrypt"
max_connections = 50                # client connections at once (default)
max_connections_per_address = 10    # per client address (default)
```

The gateway offers clients the endpoints the PLC advertises. Endpoint
discovery is not authenticated, so set `min_security` as soon as the PLC
supports security: endpoints below it are never offered or used, whatever
the network says. The connection limits protect the PLC, which accepts only a
few secure channels.

## Installation

Release archives (Linux x86_64/ARM64/ARMv7 static, Windows, macOS) and
multi-arch images (`ghcr.io/harted/opcua-audit-trail`) are built for every
`v*` tag.

### Linux (systemd)

```sh
tar xzf opcua-audit-gateway-*-linux-amd64.tar.gz && cd opcua-audit-gateway-*
sudo ./install.sh ./opcua-audit-gateway
sudo nano /etc/opcua-audit-gateway/config.toml    # or add targets in the web UI
sudo cat /var/lib/opcua-audit-gateway/initial-admin-password.txt  # first login
```

The service runs as the unprivileged user `opcua-gw` with a hardened unit.
Data, certificates and the audit trail live in `/var/lib/opcua-audit-gateway`.
Running `install.sh` again upgrades the binary and keeps config and data.
On a PLCnext controller use the `armv7` archive or the container image.

### Windows (service)

Put the executable where only administrators can change it and the config in
its own directory, e.g. (as administrator):

```powershell
$exe = "C:\Program Files\OPC UA Audit Gateway\opcua-audit-gateway.exe"
& $exe --config "C:\ProgramData\OPC UA Audit Gateway\config.toml" init
& $exe --config "C:\ProgramData\OPC UA Audit Gateway\config.toml" service install
sc start OpcUaAuditGateway
```

The service runs under its own virtual account
(`NT SERVICE\OpcUaAuditGateway`), not as LocalSystem. `service install`
restricts the config, data, certificate and log directories to that account,
SYSTEM and administrators; don't point them at shared directories. Logs go to
`logs` next to the config (daily files, kept 14 days). The initial admin
password is in `initial-admin-password.txt` in the data directory.
`service uninstall` removes the service; install it again after an upgrade
from a version that ran as LocalSystem. Any command accepts `--log-dir` to log
to files instead of the console.

### Docker

```sh
docker compose up -d
docker compose cp gateway:/data/initial-admin-password.txt .   # first login
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
With TLS the session cookie is `Secure` and `__Host-` prefixed, and HSTS is
sent. Without TLS, keep the UI on loopback: there it only answers requests for
`localhost`/`127.0.0.1`/`[::1]`, so a web page cannot reach it through DNS
rebinding.

## Audit export

The audit trail lives in the gateway (SQLite) and can also be copied to other
systems. Each destination keeps its own position in `data/export-state.json`:
nothing is skipped while a destination is down, and records are delivered at
least once.

```toml
[export.questdb]              # long-term storage and SQL analysis
url = "http://questdb:9000"   # ILP over HTTP(S); each batch is acknowledged
table = "opcua_audit"         # created on first write
# token = "…"  or  username = "…" / password = "…"  (use https off-host)
# ca_file = "questdb-ca.pem"  # https with a private CA; default: public roots
```

In the web UI (Settings), a private CA is pasted as PEM text; the gateway
keeps it in `data/questdb-ca.pem`. Syslog export is not supported (any more):
see [docs/export/SYSLOG.md](docs/export/SYSLOG.md).

Every exported record carries its sequence number, its hash and the previous
record's hash. Once records are outside the gateway, rewriting the local
database no longer goes unnoticed: `verify` checks the chain against the last
record each destination acknowledged. Note the head that `verify` prints and
check it later, for example from another machine's copy:

```sh
opcua-audit-gateway verify --expect 1234:<hash printed by the earlier run>
```

If an exporter's last position is no longer in the trail (a truncated or
rebuilt database), it records an `export_gap` and the dashboard raises it.
In QuestDB, make retries idempotent with
`ALTER TABLE opcua_audit DEDUP ENABLE UPSERT KEYS(ts, seq)`.

The dashboard shows each destination's state and how many records are waiting.

## Noisy nodes (life bits, counters)

An HMI that writes a life bit every second adds 86 400 records a day and
buries the writes that matter. Such nodes can be **summarised**: their value
writes are no longer recorded one by one, but counted, and every hour one
`ignored_writes` record per node says how many writes there were (and how many
failed), from which clients, from when to when, and the last value. A write
to such a node therefore never goes unnoticed entirely.

In the web UI (admin): **Audit trail → Most written** lists the nodes written
most in the last 24 hours. **Summarise…** opens a dialog that explains what
happens and asks whose writes to summarise: every client's, or only one
client's (the same node written by anyone else stays recorded one by one).
The same button is in a write record's details and on a variable in the
Browser. Summarised nodes carry a *summarised* label in the audit trail and the
Browser, and each target lists them under **Summarised nodes**, with **Record
every write again** to undo it. Changes apply at once, without disconnecting
clients, and are audited (`config_changed`).

In `config.toml`:

```toml
[audit]
ignored_summary_secs = 3600         # one summary per node per hour (default; also in Settings)

[[targets]]
name = "line1"
# …
[[targets.ignore]]
node_id = 'ns=3;s="DB1"."Life"'     # as shown in the audit trail
name = "Life bit"                   # optional, shown in the web UI
[[targets.ignore]]
node_id = "ns=3;i=1234"
client = "10.0.0.5"                 # only from this address or application URI
```

Only writes of a node's value are summarised; method calls, other attributes
and other services are always recorded. Summarised writes skip the read of the
old value, which also saves the PLC a request per write. In `fail_mode =
"closed"` they are not held back for a committed record; a summary that has
not been written yet is lost if the gateway crashes.

## Web UI

| Page | Role | |
|---|---|---|
| Dashboard | auditor | Reachability of each target, connected clients, latest changes |
| Audit trail | auditor | Filters, record details, live mode, CSV export, integrity check, most written nodes (admin summarises them) |
| Targets | auditor (operator discovers, admin edits) | Add/edit/remove targets without a restart, discovery, trust the PLC certificate |
| Certificates | auditor (admin acts) | Gateway certificate (download/import/regenerate), trust or reject certificates |
| Browser | operator | Read-only address space browser with live values |
| Users | admin | Users and roles |
| Settings | auditor (admin edits) | Retention, fail mode, old values, summary interval, QuestDB export, certificate host names; web server and paths shown read-only |

Settings are saved in `config.toml` (comments are kept) and applied at once,
without a restart or disconnecting clients. Passwords and tokens are never
shown again once saved. Shortening the retention deletes older records right
away. The web server's address, HTTPS and the data paths take effect only at
start, and a wrong value could lock you out, so they are changed in the file.

Roles are cumulative: auditor < operator < admin. Manage users from the
command line with `opcua-audit-gateway user add|passwd|role|delete|list`
(also to reset a lost admin password: `user passwd admin`, which also creates
the admin if the gateway has not run yet). A user that does not exist is
reported before any password is asked, with the path of the user database, so
a command run against the wrong config is noticed at once. Changing a
password, a role or removing a user ends that user's sessions; sessions also
expire after 8 hours idle and 24 hours in total. Failed logins are rate
limited per address and per user.

## REST API

All routes need a session cookie from `POST /api/login`. State-changing
requests also need the header `X-Requested-With: opcua-audit-gateway`.

| Method | Path | |
|---|---|---|
| GET | `/api/status` | Version, certificate, targets with upstream state and endpoints |
| GET | `/api/targets` | Target status only |
| GET | `/api/targets/{name}/clients` | Clients connected through the gateway |
| POST | `/api/targets/{name}/discover` | Discover a configured target now |
| POST | `/api/discover` | `{"endpoint_url": "opc.tcp://…"}`: discover any server (admin, audited) |
| GET | `/api/certificates` | Own, trusted and rejected certificates |
| GET | `/api/audit` | Audit records, newest first. Filters: `target`, `kind`, `user`, `node_id`, `since`, `until`, `before_seq`, `limit` |
| GET | `/api/audit.csv` | The same filters, as CSV |
| GET | `/api/audit/verify` | Verify the hash chain |
| GET | `/api/audit/most-written` | Nodes with the most recorded writes (`hours`, default 24) |
| POST | `/api/targets/{name}/ignore`, `…/ignore/remove` | `{"node_id": "…", "client": "…"}`: summarise a node's writes, or record them again (admin, audited) |
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
