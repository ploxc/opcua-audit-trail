# Security and correctness audit

> **Verified independently:** see [VERIFICATION.md](VERIFICATION.md).
> - 29 findings were confirmed, R2 is plausible, and R7 was refuted and withdrawn.
> - About 30 further findings were added (N1–N25 plus Info items), three of them High.
> - Two of the "found sound" statements below were corrected.
>
> - All findings except the withdrawn R7 and a few accepted items are fixed;
>   see [VERIFICATION.md, section 5](VERIFICATION.md#5-fix-status).
>
> This file is kept as it was written.

**Scope:** the whole repository at commit `bbfa4cf` (after PR #2): the relay, the audit trail, export, the web UI and API, certificates, configuration, and packaging.
**Method:** manual code review. I checked library behaviour against the async-opcua 0.19 sources. I did not write any proof-of-concept exploits; independent agents verify the findings in [VERIFICATION.md](VERIFICATION.md).
**Author:** the same assistant that wrote the code. That is why the findings are verified independently.

## Severity

| Level | Meaning |
|---|---|
| **High** | Defeats the product's core promise (every change audited, the channel secure), or can be exploited remotely with realistic preconditions. |
| **Medium** | Denial of service, a loss of audit data or tamper evidence, or a weakness that needs an extra precondition. |
| **Low** | Defence in depth, a narrow precondition, or admin-only impact. |
| **Info** | Inaccurate docs or behaviour that is surprising but not harmful. |

## Summary

| ID | Severity | Title |
|---|---|---|
| R1 | High | A write in flight when the client disconnects reaches the PLC without an audit record |
| R2 | High | Secure channel renewal can change the certificate, policy and mode (channel takeover or downgrade) |
| R3 | Medium | Unauthenticated memory exhaustion: chunk size and total message size are not bounded |
| R4 | Medium | No limit on client connections; each one opens an upstream channel on the PLC |
| R5 | Medium | Unauthenticated parties can flood the audit trail (unbounded values, connection events, failed logins) |
| R6 | Medium | Unauthenticated discovery silently decides which security the gateway offers and uses |
| A1 | Medium | The hash chain has no external anchor: the tail can be truncated or the chain rebuilt |
| A2 | Medium | Retention deletes recent records after a clock jump |
| E1 | Medium | The exporter silently skips records that retention pruned or that the database renumbered |
| W1 | Medium | No login rate limit; concurrent argon2 hashing lets anyone exhaust memory or CPU |
| W2 | Medium | Web sessions survive password, role and user changes made with the CLI, and the user's own password change |
| A3 | Low | `synchronous=NORMAL`: a fail-closed "committed" record can be lost on power failure |
| A4 | Low | Pruning and its anchor record are not one transaction (a crash causes a false tamper alarm) |
| A5 | Low | `verify` does not check the `target`, `user`, `remote_addr` and `application_uri` columns |
| E2 | Low | `export-state.json` is written without fsync; a corrupt file stops the gateway from starting |
| E3 | Low | Exporters have no TLS: credentials and audit data travel in cleartext |
| W3 | Low | A user update can change the role, then fail on the password, leaving the role change unaudited |
| W4 | Low | Operators can make the gateway connect to any host and port (`/api/discover`) |
| W5 | Low | "Trust server certificate" trusts whatever certificate the target presents at click time |
| W6 | Low | The initial admin password is written to the logs and never has to be changed |
| P1 | Low | Private keys and a rewritten `config.toml` get the default file mode |
| R7 | Low | A huge session timeout from the server can panic the session registry (Duration overflow) |
| R8 | Low | Requests are still processed after the connection started closing |
| R9 | Low | Requests carrying another session's token are attributed to that session's user |
| P2 | Low | Revoking trust in a client certificate does not close its active connections |
| K1 | Low | Release workflow: write permissions for every job; actions pinned by tag only |
| I1 | Info | The browser's `skip_verify_certs` also skips expiry checks, which the comment does not say |
| I2 | Info | A write of only a status code or timestamp is recorded as a `Null` value |
| I3 | Info | The CSV formula guard misses a leading tab or carriage return |
| I4 | Info | UDP syslog truncation produces invalid JSON |
| I5 | Info | A write whose response is lost is recorded as failed, although the PLC may have applied it |

---

## High

### R1: A write in flight when the client disconnects reaches the PLC without an audit record
- **Location:** `src/relay/connection.rs:211`, `:288-289`, `:127-131`
- **Scenario:**
  1. A client sends a Write, or a Write queued behind a slow request, and closes the TCP connection before the response arrives.
  2. The connection loop sees `PollResult::Closed` and returns. The `FuturesUnordered` holding the forward future is dropped.
  3. The request is already in async-opcua's upstream send queue (`Request::send` hands it to an mpsc channel that the separate event-loop task drains).
  4. `upstream.close()` then queues CloseSecureChannel behind it. The PLC executes the write.
  5. The audit record is written only after the response, in `forward()`, so it is never written.

  In fail-closed mode the `change_intent` record exists but the outcome does not. In the default fail-open mode there is nothing. A malicious client can do this deliberately. A crashing HMI does it by accident.
- **Evidence:**
  - `forward()` records events only after `ctx.upstream.send(...)` returns (lines 1046-1095).
  - `AsyncSecureChannel::send` → `Request::send` → `sender.send_timeout(message)`; the event loop (`upstream.rs:112-125`) sends independently of the caller future.
- **Recommendation:**
  - Run each forwarded change request as its own task (`tokio::spawn`), so it completes and records even when the downstream connection is gone.
  - When the connection ends, wait (with a bound) for outstanding change requests before closing the upstream channel.
  - As a last resort, record a "change forwarded, outcome unknown" event before the request is queued.

### R2: Secure channel renewal can change the certificate, policy and mode
- **Location:** `src/relay/connection.rs:427-440` (renew branch), `:497-511`; `src/relay/transport.rs:296`
- **Scenario:** an attacker on the path between a client and the gateway injects an OpenSecureChannel **Renew** into an established Sign or SignAndEncrypt connection. The attacker needs the next sequence number: it is visible in Sign mode and guessable in SignAndEncrypt mode.
  - **Variant a, certificate swap.** The renew is signed with the attacker's own untrusted certificate. `SecureChannel::verify_and_remove_security_server` only checks that the header certificate signed the message ("This code doesn't *care* if the cert is trusted"). The renew branch skips `check_client_certificate`, and `set_remote_cert_from_byte_string` installs the attacker's certificate. The gateway encrypts its nonce to the attacker and derives new keys with it. The attacker now owns the channel and can inject requests into the victim's activated session, under the victim's identity.
  - **Variant b, downgrade.** The renew uses the SecurityPolicy None header. async-opcua sets `self.security_policy = None` for every OPN. The renew branch then only checks the nonce if the policy is not None, sets mode None, and skips key derivation. From then on the gateway accepts unsigned plaintext messages on the victim's channel.
- **Evidence:**
  - Renew checks only `issued` and nonce reuse (lines 428-440).
  - The mode consistency, "offered" and trust checks run only for Issue (lines 441-484).
  - async-opcua `secure_channel.rs:906-913` sets the policy from each OPN.
- **Recommendation:**
  - Record the issued policy, mode and client-certificate thumbprint, and require a renew to match all three.
  - Inspect the asymmetric header in `Downstream::process` before calling `verify_and_remove_security_server` for any OPN after the first. The library call already mutates the channel policy.
  - On mismatch, close the connection and stop processing queued requests (see R8).

## Medium

### R3: Unauthenticated memory exhaustion
- **Location:** `src/relay/transport.rs:36-46`, `:296-309`
- **Scenario:** before or after OpenSecureChannel, a client sends intermediate chunks. `TcpCodec` limits each chunk only to `max_message_size`, which is 64 MiB. The negotiated receive buffer (65 535 bytes) is not enforced. The transport keeps up to 4 096 chunks per message and never sums their size.
  - One connection can therefore make the gateway hold gigabytes within the 10 s channel deadline.
  - Several connections kill the process with an out-of-memory error, which takes down every target.
  - PLCnext devices have 2 GB of RAM.
- **Evidence:** async-opcua `message_chunk.rs:172` checks against `decoding_options.max_message_size`. `pending_chunks` checks only the chunk count.
- **Recommendation:**
  - Reject chunks larger than the negotiated receive buffer size.
  - Track the total pending bytes against `max_message_size`.
  - Lower the defaults, for example 16 MiB per message and 512 chunks.
  - Limit connections that have not issued a channel yet (R4).

### R4: No connection limit; each connection opens an upstream channel
- **Location:** `src/relay/mod.rs:237-251`, `src/relay/connection.rs:333-386`
- **Scenario:** when the PLC offers SecurityPolicy None, anyone who can reach the listen port can open many connections and send one request each. Each connection creates its own upstream secure channel. PLCs allow few channels or sessions (often 10 to 32), so legitimate clients are locked out. The PLC only accepts the gateway, so the gateway is the choke point.
- **Recommendation:** add a per-target limit on concurrent connections and on upstream channels, with an audit event when the limit is hit. Optionally add a per-IP limit and a rate limit on Hello.

### R5: Unauthenticated audit flooding
- **Location:**
  - `src/relay/connection.rs:101` (`ClientConnected` after Hello)
  - `src/relay/audit_map.rs:455-491` (strings and arrays are not truncated)
  - `src/web/auth.rs:147-153` (failed login records any user name)
- **Scenario:** the disk fills and the export stalls. With fail-closed mode, every legitimate write is then refused. Three unauthenticated sources feed it:
  - Every TCP connection with a Hello creates two records.
  - A Write with an invalid session token is still forwarded, rejected by the PLC, and recorded with its full new value. A 16 MiB string or a 4-million-element array becomes a multi-megabyte record.
  - Failed web logins record user names up to the 2 MB JSON body limit.

  Very large records can also exceed QuestDB line limits. The export then retries the same batch forever (poison record), and nothing newer reaches QuestDB.
- **Recommendation:**
  - Cap the rendered size of every value, like byte strings are already capped (4 KiB), and truncate user names.
  - Rate-limit connection and login-failure records per source (aggregate them into one "n events" record).
  - Consider a disk-space guard that raises an alarm before the store fails.

### R6: Discovery decides the offered security, without authentication or an audit trail
- **Location:** `src/discovery.rs:198-209`, `src/relay/endpoints.rs:50-79`, `src/relay/connection.rs:605-765`
- **Scenario:**
  - The endpoint list comes from GetEndpoints over an unauthenticated None channel and is refreshed every `discovery_interval_secs`.
  - An attacker between the gateway and the PLC, or a misconfigured PLC, can drop the secure endpoints. The gateway then offers only the weaker policy to clients and uses it upstream.
  - The trust list still protects certificates, but not the choice of policy.
  - The spec's countermeasure is not implemented: clients compare `CreateSessionResponse.server_endpoints` with the discovered list, and the gateway does not. No audit event records that the offered security changed.
- **Recommendation:**
  - Check the upstream `server_endpoints` in CreateSession against the discovered list.
  - Add an optional per-target minimum security (for example "no None", "SignAndEncrypt only").
  - Record an `upstream_endpoints_changed` event with the old and new policies when the list changes.

### A1: The hash chain has no external anchor
- **Location:** `src/audit/store.rs:296-376`
- **Scenario:**
  - Someone with write access to `audit.db` can delete the newest N records. The remaining chain still verifies.
  - They can also rewrite everything from any point and recompute the hashes, because no secret or signature is involved.
  - `verify` only proves internal consistency.
  - Exported hashes (QuestDB, syslog) can reveal this, but nothing compares them, and without export there is no anchor at all.
- **Recommendation:**
  - Document the guarantee precisely.
  - Periodically write the chain head (seq plus hash) to an external place (syslog already carries it).
  - Add `verify --against <exported head>`.
  - Optionally add an HMAC with a key kept outside the data directory, or signed checkpoints.
  - Record the head at shutdown and check it at start (`gateway_started` could include the expected head).

### A2: Retention deletes recent records after a clock jump
- **Location:** `src/audit/store.rs:141-164`
- **Scenario:**
  1. `prune_before` takes the *highest* seq whose `ts` is older than the cutoff and deletes everything up to it.
  2. An edge device or PLC without a real-time-clock battery often boots with a 1970 or 2000 clock until NTP syncs, and the records written in that window get old timestamps.
  3. The next hourly retention deletes every record up to those seqs, including legitimate recent ones.
- **Recommendation:** only prune the contiguous old prefix: `last_seq = (SELECT MIN(seq) FROM audit WHERE ts >= cutoff) - 1`. Record a warning event when timestamps go backwards.

### E1: The exporter silently skips pruned or renumbered records
- **Location:** `src/export/mod.rs:215-240`
- **Scenario:** both cases drop records without a trace.
  - A destination is down for longer than `retention_days`. Retention deletes the unexported records, and `after(position)` simply continues after the gap.
  - `audit.db` is recreated (seq starts at 1 again) while `export-state.json` still holds 5 000. Nothing is exported until seq passes 5 000.
- **Recommendation:**
  - Detect gaps (`first seq returned != position + 1`) and a position beyond `head_seq`.
  - Record an event and show the gap in the status.
  - Optionally let retention wait for export, or warn when unexported records are about to be pruned.

### W1: No login rate limit; argon2 as a denial-of-service amplifier
- **Location:** `src/web/auth.rs:137-160`
- **Scenario:**
  - Every login runs argon2 with the defaults (19 MiB, 2 passes) on the blocking pool, which has up to 512 threads. Hundreds of concurrent requests therefore need gigabytes of RAM.
  - The 500 ms sleep after a failure does not slow down parallel guessing.
  - There is no lockout and no per-IP limit.
- **Recommendation:** limit concurrent password checks (a semaphore of, say, 4), add a per-IP and per-user failure back-off, and record repeated failures once rather than one record per attempt (see R5).

### W2: Sessions survive credential changes
- **Location:** `src/web/auth.rs:59-71` (role cached at login), `:204-223`; `src/main.rs` (`user` commands)
- **Scenario:**
  - `opcua-audit-gateway user passwd|role|delete` changes the database, but the running gateway keeps the web sessions in memory. The session keeps its old role until it has been idle for 8 hours, and never expires while in use.
  - The same holds for a user's own password change: other sessions of that user stay valid.
  - Resetting a compromised account with the CLI therefore does not lock the attacker out.
- **Recommendation:**
  - Check the user and role in the database on every request (or keep a per-user version counter).
  - End the user's other sessions on a password change.
  - Add an absolute session lifetime.

## Low

### A3: `synchronous=NORMAL` weakens fail-closed
- **Location:** `src/audit/store.rs:61`
- **Issue:** in WAL mode with `NORMAL`, the last committed transactions can be lost on power failure. In fail-closed mode the relay forwards a write after an intent was acknowledged that may not survive a power cut.
- **Recommendation:** use `synchronous=FULL` in fail-closed mode.

### A4: Pruning is not atomic
- **Location:** `src/audit/store.rs:155-162`
- **Issue:** the DELETE and the `retention_pruned` append run in separate transactions. A crash in between leaves a gap that `verify` reports as tampering.
- **Recommendation:** run both in one transaction.

### A5: `verify` ignores some indexed columns
- **Location:** `src/audit/store.rs:341-346`
- **Issue:** only `ts`, `kind` and `node_id` are compared with the body. With database access, the `user` and `target` columns can be changed without breaking `verify`, which hides records from filtered views.
- **Recommendation:** compare all indexed columns.

### E2: The export position is not durable
- **Location:** `src/export/mod.rs:112-119`
- **Issue:** the file is written to tmp and renamed without fsync. After a power loss the file can be empty. `ExportState::open` then fails, and `export::start(...)?` stops the gateway from starting.
- **Recommendation:** fsync the file and its directory, and treat an unreadable state file as position 0 with a warning.

### E3: Exporters have no TLS
- **Location:** `src/export/questdb.rs:50`, `src/export/syslog.rs`
- **Issue:** the QuestDB token or password and every record travel in cleartext. The config refuses `https://` and says to use a proxy.
- **Recommendation:** support TLS (rustls is already a dependency) for QuestDB and for syslog over TCP (RFC 5425).

### W3: A partial user update is not audited
- **Location:** `src/web/mod.rs:703-733`
- **Issue:** `{role, password}`: the role is changed first. If the password then fails validation, the handler returns before `config_changed` and `remove_user`. The role change is live but not audited, and old sessions keep the old role.
- **Recommendation:** validate everything first, apply in one step, and always audit what was applied.

### W4: Operators can make the gateway connect anywhere
- **Location:** `src/web/mod.rs:407-424`
- **Issue:** `/api/discover` (operator role) opens a TCP connection and OPC UA discovery to any `opc.tcp://host:port`. The gateway usually bridges network zones, so this allows scanning the PLC network from the gateway.
- **Recommendation:** make it admin-only, or restrict it to configured targets.

### W5: Trust-on-first-use without confirming the thumbprint
- **Location:** `src/web/mod.rs:373-400`
- **Issue:** the button runs a fresh discovery and trusts the first certificate returned. The certificate the admin reviewed in the UI earlier is not bound to the request, so an attacker present at click time wins.
- **Recommendation:** send the reviewed thumbprint and trust only a certificate with that thumbprint.

### W6: The initial admin password is in the logs
- **Location:** `src/main.rs:322-336`
- **Issue:** the password is kept in journald, log files (14 days) or `docker logs`, readable by anyone with log access, and changing it is optional.
- **Recommendation:** force a password change at first login, or write the password to a 0600 file once.

### P1: Default file modes for secrets
- **Location:** `src/pki.rs:195-200` (imported private key), `src/targets.rs:217-219` (config rewrite)
- **Issue:**
  - `std::fs::write` creates files with 0644 under a typical umask.
  - Rewriting `config.toml` through the UI replaces the file, so its mode (for example 0600, because it holds QuestDB credentials) becomes 0644.
  - install.sh's 0750 directories limit the exposure on Linux.
- **Recommendation:** create key and config files with 0600 (`OpenOptions::mode`), keep the original mode on rewrite, and add `UMask=0077` to the systemd unit.

### R7: Duration overflow in the session registry
- **Location:** `src/relay/mod.rs:109`
- **Issue:** `s.timeout * 2` panics when the server revises the session timeout to a huge value. Every later CreateSession on that target then panics while the entry lives, which is forever. This needs a server that does not clamp the timeout.
- **Recommendation:** clamp the timeout and use `saturating_mul`.

### R8: Requests are processed while closing
- **Location:** `src/relay/connection.rs:179-219`
- **Issue:** after `close()`, for example on "secure channel expired", a rejected renew or target shutdown, the loop keeps decoding and handling incoming requests until the send buffer is flushed.
- **Recommendation:** once `close_reason` is set, drop new requests.

### R9: Attribution by session token
- **Location:** `src/relay/connection.rs:1018-1026`
- **Issue:** the audit user comes from the session registry, keyed by the token in the request. A client that sends another session's token (visible on None channels) creates failed records under that session's user name. The remote address is correct.
- **Recommendation:** bind registry entries to the connection or channel that activated them, and record a mismatch explicitly.

### P2: Revoked trust does not end active connections
- **Location:** `src/pki.rs:116-127`
- **Issue:** a client whose certificate is untrusted keeps its open channel until it disconnects.
- **Recommendation:** close the target's connections that use that thumbprint.

### K1: CI supply chain
- **Location:** `.github/workflows/release.yml:15-17`
- **Issue:** `contents: write` and `packages: write` apply to every job, including the build jobs that run `cargo install cross` (latest). Actions are pinned by tag, not by SHA.
- **Recommendation:** grant write permissions per job (publish and image only), pin actions by SHA, and pin the `cross` version.

## Info

### I1: The browser skips more than the comment says
- **Location:** `src/web/browser.rs:184-186`
- **Issue:** async-opcua's `skip_verify_certs` also skips the not-before and not-after checks, so the browser accepts an expired trusted PLC certificate. Trust itself is checked.

### I2: Writes without a value
- **Location:** `src/relay/audit_map.rs:108-113`
- **Issue:** only `DataValue.value` is recorded. A write that sets only the status code or timestamps is recorded as `Null`.

### I3: CSV formula guard
- **Location:** `src/web/mod.rs:628`
- **Issue:** OWASP also lists a leading tab (`\t`) and carriage return (`\r`).

### I4: UDP syslog truncation
- **Location:** `src/export/syslog.rs:81-83`
- **Issue:** messages over 8 000 bytes are cut, and the JSON body becomes invalid.

### I5: Lost responses
- **Location:** `src/relay/connection.rs:1080`
- **Issue:** a timeout or disconnect produces a fault response, so the write is recorded with that fault as its status. The PLC may nevertheless have applied it. A distinct status such as `outcome unknown` would be more honest.

## Areas reviewed and found sound
- **XSS in the SPA:** every interpolation goes through the escaping `html` template. The only raw `Html` values are static markup and numeric sequence numbers.
- **Content security policy:** it forbids inline scripts.
- **SQL:** all queries use parameters, and the `limit` is clamped.
- **Session validation in CreateSession and ActivateSession:**
  - The channel certificate must equal the session certificate, and the client signature is checked.
  - The upstream server signature and certificate identity are checked.
  - Password decryption and re-encryption use the right nonces.
- **Trust:** client and upstream certificates are validated against the trust list on Issue. The browser also checks trust.
- **Web API:**
  - The CSRF header is required on every state-changing method.
  - Cookies are HttpOnly and SameSite=Strict.
  - The role check is the first statement of every handler.
- **Certificate management:** thumbprint lookups scan the directory, so there is no path traversal.
- **Config rewrite:** it is atomic, and validation runs before anything is applied.
- **Syslog structured-data escaping and ILP escaping:** quotes, backslashes, `]`, commas, spaces, `=` and newlines are handled.
