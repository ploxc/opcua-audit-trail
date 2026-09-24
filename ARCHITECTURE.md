# Architecture

OPC UA Audit Gateway is a transparent OPC UA gateway. It sits between OPC UA
clients (SCADA, HMI, MES, engineering tools) and an OPC UA server (usually a
PLC), forwards everything, and keeps a tamper-evident audit trail of **who
changed what, when**: every write, method call, history update and node
management call, plus every client connection and session event.

Reads, browses and subscriptions are forwarded but not audited.

## Why the gateway terminates OPC UA

With `Sign` or `SignAndEncrypt`, OPC UA traffic is signed and encrypted end to
end, so passive sniffing cannot see what is written. The gateway therefore
acts as an **OPC UA server towards the clients** and as an **OPC UA client towards
the upstream server**, with its own application instance certificate on both sides.

```
 SCADA / HMI / UaExpert           opcua-audit-gateway (one binary)                    PLC
 ┌──────────┐  opc.tcp:4841  ┌──────────────────────────────────────────┐  opc.tcp  ┌──────┐
 │ client A │───────────────▶│ server channel ── relay ── client channel │─────────▶│ OPC  │
 │ client B │───────────────▶│ server channel ── relay ── client channel │─────────▶│ UA   │
 └──────────┘                │                    │ audit events          │          │server│
                             │                    ▼                       │          └──────┘
                             │  SQLite (hash chain)  ──▶ optional QuestDB │
                             │  Web UI / REST API :8080                   │
                             └──────────────────────────────────────────┘
```

## Deployment topologies

* **On the PLC**, e.g. as a container on a PLCnext controller. Same IP as the
  PLC, different port (e.g. `4841`), with the PLC's own server bound to localhost
  or firewalled.
* **On an edge device** next to one or more PLCs. One listen port per target.

In both cases **the gateway must be the only client the PLC accepts**.
Otherwise clients can bypass it and the audit trail is incomplete. Enforce this
with the PLC's trust list (only the gateway certificate is trusted) and/or the
firewall. The web UI will warn when the upstream server accepts `None`
security with anonymous access.

## Relay design

### One upstream connection per client

Every downstream TCP connection gets its own upstream TCP connection, secure
channel and session. As a result:

* the PLC still sees one session per client, so its session list stays meaningful;
* user-based access rights on the PLC keep working (identity passthrough, below);
* subscriptions, method calls, history and anything vendor-specific work
  without the gateway re-implementing an address space. It forwards messages; it
  does not proxy nodes.

### Message handling

Each side negotiates its own secure channel (Hello/Acknowledge buffer sizes,
security policy, token renewal). The relay decodes complete service requests
and responses on one side and re-encodes and re-chunks them on the other. It
only changes what is bound to certificates or to the channel:

| Service | Rewritten |
|---|---|
| `GetEndpoints`, `FindServers` | Endpoint URLs and server certificate become the gateway's; policies are filtered by the endpoint settings |
| `CreateSession` | Client side: the client's certificate and nonce are validated, and the gateway's own certificate, nonce and signature are returned. Upstream: the gateway's certificate and application description are sent, and the client's session name is kept, suffixed `via gateway` |
| `ActivateSession` | Client signature verified; new signature created upstream; user identity token decrypted and re-encrypted for the upstream server |
| `CloseSession`, `CloseSecureChannel` | Mirrored to the other side |
| everything else | Forwarded unchanged; request and response are correlated by `requestHandle` |

### Implementation notes

* **Upstream channel.** The upstream side uses async-opcua's client secure
  channel (`AsyncSecureChannel`), which handles Hello, OpenSecureChannel,
  token renewal, chunking and request matching. The downstream side is the
  gateway's own server transport (`src/relay/transport.rs`) on top of
  async-opcua's `SecureChannel`.
* **Byte-exact pass-through.** Structures the gateway does not know (vendor
  UDTs, custom types) are kept as opaque bytes and re-encoded unchanged.
* **Ordering.** Requests are forwarded in the order the client sends them.
  Responses return as soon as they arrive, so a pending `Publish` never blocks
  other requests.
* **Sessions outlive connections.** Sessions are tracked by authentication
  token, so a client that reconnects can re-activate its session on a new
  connection. The upstream server sees the same gateway certificate and accepts
  it.
* **Timeouts.** The upstream timeout is the client's `timeoutHint` plus 5 s,
  so the client always sees its own timeout first.
* **Disconnects.** When a client disconnects, the relay still waits (up to
  30 s) for the responses to its audited requests, so a write that reached
  the PLC is recorded with its result even if the client is gone. A request
  that may or may not have reached the PLC is recorded as uncertain, with
  the reason ("no response; the server may have applied it").
* **Resource limits.** Frames are checked against the negotiated size from
  their header, before they are buffered. Each target limits client
  connections in total (`max_connections`, 50) and per address
  (`max_connections_per_address`, 10), plus the rate of new ones; refused
  connections are summarised as `connections_refused`. Client-supplied
  strings in audit records are truncated.
* **Channel renewal.** A renewal must keep the security policy, mode and
  client certificate the channel was opened with; this is checked before the
  message is parsed. A client certificate that is no longer trusted closes
  its connections.

### What is audited

| Service | Audit record |
|---|---|
| `Write` | One `write` record per `WriteValue`: node, attribute, index range, new value, old value (optional), result status |
| `Call` | Object, method, input arguments, result status |
| `HistoryUpdate` | Node, kind of update, result status |
| `AddNodes`, `DeleteNodes`, `AddReferences`, `DeleteReferences` | Node, service, result status |
| Connection & session | TCP connect/disconnect, secure channel (policy, mode), session create/activate/close, failed logins, rejected certificates |
| Gateway | Start/stop, configuration changes (who, what), discovery from the UI, upstream availability and endpoint changes, refused connections, retention, lost events, truncated trail, clock jumps, export gaps |

The status comes from the upstream response, so **rejected writes are audited
too** (`BadUserAccessDenied` is valuable information).

**Summarised nodes.** Value writes to nodes on a target's ignore list (a life
bit, a seconds counter), optionally only from one client, are taken out of
the write before it is audited: they skip the old-value read and are counted
per node instead. Every `ignored_summary_secs` (and when the target stops)
one `ignored_writes` record per node gives the count, the failures, the
clients, the time span and the last value. The list can change while clients
are connected; changes are audited. Everything else in the same request is
recorded as usual, with its own result.

**Old value and display name.** With `record_old_value = true`, the relay
sends one `Read` in the client's own session right before a `Write`. It asks
for the current value of every written node and, for nodes not yet in the
per-target name cache, their `DisplayName`. Method calls get the method's
`DisplayName` the same way. The read and the change are queued back to back,
so they reach the server in that order. The change does not wait for the
read, which usually adds only the server's time to answer the read. The read
runs with the client's permissions: if the user may not read a node, the old
value simply stays empty.

### Future: write policies

The point where a request has been decoded and is about to be forwarded is a
hook. Version 1 only audits. Later versions can plug in allow/deny rules per
client, user or node there (e.g. "HMI 3 is read-only"), and the response will
be `BadUserAccessDenied` without contacting the PLC.

## Security

### Gateway certificate

The gateway generates its own self-signed application instance certificate on
first start (`pki/own/cert.der`, RSA 2048, 5 years, `subjectAltName` = application
URI + host names + IPs + `certificate_hostnames` from the config). Importing a
certificate and key (e.g. one issued by a plant CA) is supported through the
PKI directory and, later, the web UI.

The same certificate is used downstream (clients must trust it) and upstream
(the PLC must trust it, and only it).

### Trust lists

Standard OPC UA layout: unknown client certificates land in `pki/rejected/` and
are moved to `pki/trusted/` by an administrator, also with one click in the web
UI. `pki/rejected/` is capped, so unknown clients cannot fill the disk. Trusting
a PLC certificate from the web UI names the thumbprint the administrator saw;
if the PLC now presents another certificate, nothing is trusted.

### Following the target

By default the gateway follows the upstream server. It periodically runs
`GetEndpoints` on the target and offers clients the same security policies,
security modes and user token types. Changes are audited
(`upstream_endpoints_changed`).

Discovery itself is not authenticated, so someone on the network could hand
the gateway an endpoint list without security. `min_security` per target
(`none`, `sign`, `sign_and_encrypt`) sets a floor: endpoints below it are
neither offered to clients nor used upstream. When the gateway creates the
upstream session, it also checks the endpoints the server returns (which are
signed) against what discovery showed. A session is bound to the connection
and to the security it was activated with; another connection can only take
it over with at least the same security.

### User identity: passthrough

| Client token | Upstream |
|---|---|
| Anonymous | Anonymous |
| UserName / password | Same user name and password, re-encrypted for the upstream server |
| X509 user certificate | **Cannot be passed through**: the client signs with a private key the gateway does not have. Per target: reject, or log in with a configured service account (the audit trail records the real certificate) |
| Issued token | Same as X509 |

The password is only in gateway memory for the time it takes to re-encrypt it.
It is never logged or stored.

## Audit trail

### Storage

The primary store is an **embedded SQLite database** (`data/audit.db`, WAL mode),
so the standalone binary is fully functional and Docker is optional. Optionally,
records are also shipped to **QuestDB** (same compose file or central server) for
long-term analytics across gateways; the local store remains the source of truth
and doubles as the buffer while QuestDB is unreachable.

A dedicated writer thread batches records (up to 512 per transaction). Callers
never touch the database directly.

### Tamper evidence

Records form a SHA-256 hash chain:

```
hash(n) = sha256( hash(n-1) "\n" seq(n) "\n" body(n) )      hash(0) = 000…0
```

`body` is the exact JSON of the record as written. Indexed columns (`ts`, `kind`,
`node_id`, …) are checked against the body during verification.
`opcua-audit-gateway verify` (and `GET /api/audit/verify`) detects modified,
inserted or deleted records.

**Retention** deletes the oldest records and appends a `retention_pruned`
record that names the last deleted sequence number and hash, in one
transaction. Only a prefix of the chain is ever deleted, so the remaining
chain stays verifiable and the gap is accounted for. If the system clock
jumped, retention is skipped and a `clock_jumped` record is written.

A separate row keeps the highest sequence number and hash ever written, so
cutting off the newest records is detected too (`trail_truncated`), and the
database runs with `synchronous = FULL`.

The chain proves integrity *within* the database. Someone with write access to
the file could rebuild the entire chain. The export (QuestDB) is the
answer: every exported record carries its hash, so once records are outside
the device, a rebuilt local chain no longer matches the copy. `verify` checks
the chain against the last record each destination acknowledged, and against
heads noted down earlier (`verify --expect SEQ:HASH`; every run prints the
current head). An exporter that finds its last position gone or changed
records `export_gap` and the dashboard shows it.

### Fail mode

* `open` (default): forwarding never waits on the audit store. Events that
  cannot be queued or written are counted and recorded later as `events_lost`.
  The UI shows the counter.
* `closed`: a write is only forwarded after its audit record has been committed.
  If that fails, the client gets `BadInternalError` and the PLC is not touched.

## Web UI

Served by the same binary (axum). The frontend is plain JavaScript without a
build step (`src/web/ui/`), embedded in the binary, so one `cargo build`
produces everything, also for ARMv7. A strict Content-Security-Policy (no
inline scripts) applies. All rendering goes through an escaping template
helper.

The look follows the Ploxc brand, as in Modbux and on ploxc.com: primary
`#5b9279`, dark `#181818`/`#1F1F1F`, light `#fafafa`/`#ffffff`, the Inter
font and Material icons. Light or dark follows the system until the user
picks one. Inter (SIL Open Font License, `src/web/ui/fonts/OFL.txt`) is
embedded, so the UI needs no internet access.

* **Dashboard**: upstream status per target, active client sessions (IP,
  application, user, security, since), last writes, lost audit events.
* **Targets**: endpoint URL, *Discover* (policies, modes, user tokens, server
  certificate), follow vs. custom settings.
* **Certificates**: own certificate (regenerate/import), trusted and rejected
  clients, trusted upstream servers.
* **Browser**: address space tree, attributes, live values. It uses a separate
  gateway session and is read-only by default; writes from the UI are audited
  under the UI user.
* **Audit log**: filters (time, target, client, user, node, event type), live
  tail, CSV export, chain verification.
* **Users**: local users with roles `admin` (configuration), `operator`
  (browser) and `auditor` (audit log only). LDAP/AD later. Sessions are
  HttpOnly/SameSite=Strict cookies, checked against the user store on every
  request (changing a password, role or removing a user ends them), expire
  after 8 hours idle and 24 hours in total. Every state-changing request needs a custom header
  (CSRF protection). Logins are rate limited per address and per user. The
  initial `admin` password is written to `initial-admin-password.txt` in the
  data directory (not to the log) and must be changed at the first login.
  UI logins and every change made through the UI are audited. HTTPS with
  rustls (`ring` provider), using the gateway certificate or PEM files; with
  TLS the cookie is `__Host-` prefixed and `Secure`, and HSTS is sent.
* **Discovery** of an arbitrary URL is admin-only and audited, so the UI
  cannot be used to probe the plant network.
* **Settings**: retention, fail mode, old values, the summary interval, export
  destinations and certificate host names. Written back to `config.toml`
  (only those keys; comments stay) and applied live: the relay, retention
  and exporters read shared settings, and exporters restart with the new
  destinations. Export positions are kept per destination, so a new one gets
  the whole trail and the old one's last record stays a `verify` anchor.
  Secrets are write-only. The web listener, TLS and paths stay file-only.
* Confirmations use an in-page dialog that explains the consequence.

The web UI binds to `127.0.0.1` by default; on a loopback address it only
accepts requests whose `Host` is a loopback name (against DNS rebinding). The
compose file only publishes it on the host's loopback. Security headers (CSP,
`X-Frame-Options`, `nosniff`, no referrer) are sent on every response.

Targets can be changed at runtime: they are written back to `config.toml`
with the file's comments preserved (atomically, readable by the service
only).

### Web UI code

The frontend lives in `src/web/ui/`: `index.html`, `style.css` (grouped in
commented sections: tokens and theme, layout, sidebar, forms, tables, badges,
alerts, dialogs, then per page), the Inter fonts and native ES modules in
`js/`. There is no build step and no npm dependency at runtime; the gateway
embeds every file with `include_str!` and serves the modules under `/js/`
(`SCRIPTS` in `src/web/mod.rs`, which a new module must be added to; a test
checks that every file in `js/` is served).

| Module | Contents |
| --- | --- |
| `js/main.js` | Start-up, routing (the page list), rendering of the sidebar and the page, periodic refresh, event delegation; merges the pages' actions and forms |
| `js/html.js` | The escaping `html` template tag, `Html`, `when`, `flag` |
| `js/api.js` | `fetch` helpers for `/api` (`get`, `post`, `put`, `del`) |
| `js/state.js` | The shared `state`, the role check `can`, and the `render`/`renderPage`/`load`/`schedule` hooks that main.js implements |
| `js/format.js` | Times, values, user labels, event labels and groups |
| `js/components.js` | Icons, logos, header buttons, badges, foldable sections, dialog, toast, form helpers |
| `js/ignore.js` | Summarised (ignored) nodes: badge, controls and their actions |
| `js/alarms.js` | Unacknowledged warning and error counts in the sidebar |
| `js/pages/*.js` | One module per page (dashboard, audit, targets, certificates, browser, users, settings, account with the login screens): its view, and its `actions` and `forms` |

Rendering replaces `innerHTML` with the output of `html` templates; events
are handled by delegation on `data-action` (clicks, and changes of selects
and checkboxes) and `data-form` (submits), because the CSP forbids inline
handlers. Page modules never import main.js: they redraw through the hooks in
`state.js`, which keeps the import graph free of cycles. The code is
formatted with Prettier (`src/web/ui/.prettierrc.json`: width 100, markup in
templates left as written).

## Build and deployment

* One binary per platform: Linux x86_64 / ARM64 / ARMv7 (static musl; ARMv7
  for PLCnext AXC F 2152), Windows, macOS. Built by `.github/workflows/release.yml`
  for every `v*` tag, with SHA-256 checksums.
* Linux: `packaging/linux/install.sh` installs a hardened systemd unit that runs
  as a dedicated user (`UMask=0077`, syscall filter, no new privileges,
  read-only system). Windows: `service install` registers an auto-start
  service under its own virtual account, restricts its directories to that
  account and administrators, and logs to daily files.
* CI: the token is read-only except for the publishing jobs, and actions are
  pinned to commits.
* Container: distroless, non-root. The release image is built from the musl
  binaries for amd64, arm64 and arm/v7, and published to GHCR. Config, PKI,
  users and the audit trail live in `/data`; the config is created from a
  template on first start, so the web UI can update it.
  `docker-compose.yml` has an optional QuestDB profile.
* Configuration: one TOML file; relative paths resolve against the file's
  directory.

## Testing

* Unit tests for configuration, PKI, audit chain, pipeline and API.
* Integration tests start an in-process async-opcua server as a stand-in PLC.
  The relay milestone adds async-opcua clients on the other side, covering
  every security policy and mode.
* Regression tests for the findings of the security audit
  (`docs/audit/`), e.g. a write whose client disconnects before the response
  is still recorded.
* Interoperability matrix, tested manually per release: Phoenix Contact PLCnext,
  Siemens S7-1500, Beckhoff TwinCAT (TF6100), Codesys-based runtimes; clients
  UaExpert, plus the SCADA packages in use.

## Roadmap

| Milestone | Content | Status |
|---|---|---|
| 1. Foundation | Config, PKI, audit store with hash chain and retention, discovery and target monitor, REST API, status page, CI, Docker | ✅ done |
| 2. Relay, security `None` | Binary protocol relay, session handling, request/response correlation, `write`/`call` audit, connection events | ✅ done |
| 3. Relay, `Sign` / `SignAndEncrypt` | Certificate and signature rewriting, user token re-encryption, trust lists | ✅ done (interop with real PLCs pending) |
| 4. Old values & display names | Read-before-write, node name cache | ✅ done |
| 5. Web UI | Login and roles, targets, discovery, certificates, audit viewer, dashboard, browser | ✅ done |
| 6. Export | QuestDB (ILP/HTTP) export with persisted positions; exported hashes anchor the chain (syslog was removed, see docs/export/SYSLOG.md) | ✅ done |
| 7. Packaging | HTTPS for the UI, Windows service, systemd unit and installer, file logging, release workflow (binaries + multi-arch images) | ✅ done |

## Decision log

| Question | Decision |
|---|---|
| Certificate towards clients | Own gateway certificate by default, import optional |
| Placement | On the PLC (container, other port) or on an edge device; the PLC trusts only the gateway |
| Upstream login | Passthrough of the client's user identity |
| Old value | Configurable, on by default |
| Audit store unavailable | Fail-open with counting/reporting; fail-closed optional |
| Storage | Embedded SQLite always; QuestDB optional. Standalone binary is first-class, Docker optional |
| Targets per instance | Several, one listen port each |
| Integrity | Hash chain + retention |
| Blocking writes | Not in v1; the relay has a hook for it |
| X509 / issued user tokens | Rejected with `BadIdentityTokenRejected` and audited, and not offered in the endpoint list; a per-target service account is a later option |
| Fail-closed guarantee | A `change_intent` record is committed before a change request is forwarded; the outcome follows as a normal record |
| Web UI login | Local users with roles |
| Frontend technology | Vanilla JS without a build step, instead of Svelte: a single `cargo build`, no Node toolchain in CI or cross builds |
| UI style | Ploxc brand (Modbux, ploxc.com), with fonts and icons embedded in the binary |
| Browser identity | Direct session on the target with the gateway certificate and a login entered in the UI (not stored), read-only |
| Noisy nodes | Summarised per node and interval, never dropped silently; admin-only, audited, optionally per client |
| Security review | Audit in `docs/audit/AUDIT.md`, independently verified in `VERIFICATION.md`; all findings fixed except those listed there as accepted |
