# Security audit

**Status:** open findings only. Fixed findings are removed from this file;
the git history keeps them.

**Reviews:**
- **First audit** at `bbfa4cf`, with an independent verification that added
  findings N1–N25. Every finding of that round is fixed, except the ones
  still listed below (W6, N8, N12, N14, N23) and the accepted items. The
  fixes are in `ead63fb`, `2f7698e`, `81812d2`, `c186a74` and `ec325e0`.
- **Second review** at `4d1470d` (2026-09-25), after the first-login change,
  HTTPS by default, the MCP endpoint and API tokens. Findings S1–S20.

**Method:** manual code review by three independent agents (MCP and tokens;
login, HTTPS and Docker; the status of the first audit), with the main
claims checked against the code again. No proof-of-concept exploits.

## Severity

| Level | Meaning |
|---|---|
| **High** | Defeats the product's core promise (every change audited, the channel secure), or can be exploited remotely with realistic preconditions. |
| **Medium** | Denial of service, a loss of audit data or tamper evidence, or a weakness that needs an extra precondition. |
| **Low** | Defence in depth, a narrow precondition, or admin-only impact. |
| **Info** | Behaviour that is surprising but not harmful. |

## Summary

| ID | Severity | Title |
|---|---|---|
| N8 | Medium | Fail-open, the default, drops write records under load |
| S6 | Low | The forced-change allow-list matches path suffixes (`/api/users/me` passes) |
| S7 | Low | Two forced password changes at once: the last one wins |
| S8 | Low | A forced change accepts the password the admin chose |
| S9 | Low | The per-user login block locks out the real admin; behind a proxy all clients share one address |
| S10 | Low | Web certificate: the download can differ from the certificate in use; a mismatched key pair stops the whole gateway |
| S11 | Low | Private keys are world-readable for a moment before `chmod 600` |
| S12 | Low | An empty `OPCUA_GATEWAY_WEB_TLS` silently turns HTTPS off |
| S13 | Low | The MCP scope `settings` can shorten retention (deleting history) and switch fail-closed off |
| S14 | Low | A token's change scopes come back when its user is made admin again |
| S15 | Low | MCP arguments that are not an object skip the unknown-argument check |
| S16 | Low | Credentials in a QuestDB URL are recorded unredacted in `mcp_query` |
| N12 | Low | Browser sessions outlive an untrusted certificate and a password change |
| N14 | Low | Certificate import writes certificate and key separately |
| N23 | Low | Fail-open accounting: the lost counter is in memory only; a dead writer thread is not restarted |
| S17 | Info | A failed `mcp_query` record does not stop the tool call |
| S18 | Info | `/mcp` tells unauthenticated callers whether MCP is on |
| S19 | Info | Export status clamps `pending`, so a stalled export can look healthy |
| S20 | Info | A failed random generator would give an empty session token |

## Medium

### N8: Fail-open, the default, drops write records under load

- **Issue:** when the audit queue is full, only an `events_lost` count
  remains (`audit/mod.rs`); a 200 ms wait was added, nothing more.
- **Recommendation:** make `fail_mode = "closed"` the default for new
  installs, or persist lost records' essentials and raise an error.

## Low

### S6: Forced-change allow-list matches suffixes

`auth.rs`: `["/me", "/me/password", "/logout"].iter().any(|p| path.ends_with(p))`
also lets `PUT/DELETE /api/users/me`, `/api/targets/me` and
`DELETE /api/certificates/rejected/me` through while a password change is
forced. **Fix:** compare exact paths.

### S7: Two forced changes at once

`forced` is read when the request arrives and the password is set later
without checking again: two sessions with the forced password both succeed,
the last one wins and ends the other. **Fix:** update only
`WHERE must_change_password = 1` and fail when no row changed.

### S8: A forced change accepts the admin-chosen password

After an admin reset the user can enter the same password again and clear
the flag (the default `admin` is too short, so not there). **Fix:** refuse a
new password equal to the current one.

### S9: The per-user login block locks out the real admin

20 wrong attempts from anywhere block `admin` for 15 minutes, before the
password is checked, and it can be repeated. Behind a reverse proxy or
Docker's userland proxy all clients share one address, so 5 failures block
everyone. **Fix:** let a correct password through the per-user block (keep
the per-address block, use the forwarded address only behind a configured
proxy), or back off instead of blocking.

### S10: Web certificate download and key pair

After Regenerate the downloads serve the new certificate while the server
still presents the old one; with `tls_certificate` configured they serve a
leftover or 404. `ensure_web_certificate` checks that the files exist, not
that key and certificate match: a crash halfway leaves a pair that makes
`server_config` fail, and `main.rs` then stops the whole gateway, relay
included. Regenerate runs RSA key generation on the async runtime.
**Fix:** download the certificate in use, check the pair and regenerate
when it does not match, keep the relay running when HTTPS setup fails, use
`spawn_blocking`.

### S11: Keys world-readable for a moment

Private keys are written with the process umask and then set to 0600
(`pki.rs` `protect_private_key`, `web/tls.rs`). The systemd unit sets
`UMask=0077`; manual runs on shared hosts do not. **Fix:** create key files
with mode 0600.

### S12: An empty environment value turns HTTPS off

`OPCUA_GATEWAY_WEB_TLS=` (or an unset `${VAR}` in compose) means `false`
(`config.rs` `apply_env`). **Fix:** treat an empty value as not set.

### S13: `settings` through MCP can delete history

`update_audit_settings` accepts `retention_days: 1` (older records deleted
for good) and `fail_mode: "open"`. **Fix:** from MCP, refuse shorter
retention and switching fail-closed off; those stay in the web UI.

### S14: Scopes come back after re-promotion

Change scopes only apply while the token's user is an admin, but they stay
stored: demoting and later promoting the user brings them back silently.
**Fix:** clear tokens' scopes when a user stops being admin.

### S15: Non-object MCP arguments skip the argument check

The unknown-argument check only runs when `arguments` is an object; an
array or string runs a read tool unfiltered (e.g. an unfiltered search).
**Fix:** refuse arguments that are not an object.

### S16: Credentials in a QuestDB URL in `mcp_query`

`redact()` hides `password` and `token` keys, not user info in a URL
(`http://u:p@host`). The config refuses such URLs, but the arguments are
recorded before that. **Fix:** strip user info from URLs in `redact()`.

### N12: Browser sessions outlive changes

Closed when their target or user changes, but not when a certificate is
untrusted or the user's password changes.

### N14: Certificate import is not atomic

Certificate and key are written separately; expiry, URI and a timestamped
backup were added. See also S10.

### N23: Fail-open accounting gaps

The lost counter lives in memory only, and a writer thread that died is
not restarted (`audit/mod.rs`). **Fix:** persist the counter, restart the
thread or stop the gateway.

## Info

- **S17:** `record()` ignores a failure to write the `mcp_query` record, so
  the tool call still runs. Consistent with fail-open; in fail-closed mode
  the call should be refused.
- **S18:** `/mcp` answers 404 "turned off" before authentication, so anyone
  can tell whether MCP is on.
- **S19:** export status clamps `pending`; `gap` and `last_error` do show a
  stall.
- **S20:** the session token is `byte_string(32).value.unwrap_or_default()`;
  a failed random generator would give an empty token. Fail the request
  instead.

## Accepted

- **N22:** the `user` label mixes identity kinds. Every record also carries
  the identity kind and the client, so records can be told apart; the label
  stays short for filtering.
- **Error details in the UI:** they help the administrator diagnose
  connections and certificates, and only logged-in users see them.
- **Unreadable record body:** the exporter stops on it and shows the error;
  skipping it would hide a damaged or changed database.
- **Exported body:** records are exported with their hash and `prev_hash`
  as fields, not as the exact hashed JSON; the local `verify` against
  exported heads covers the threat.
- **Base images by digest:** distroless tags that receive security updates.

## Reviewed and found sound

- **XSS:** every interpolation goes through the escaping `html` template;
  raw `Html` values are static markup, numbers or escaped strings. The CSP
  forbids inline scripts.
- **SQL:** all queries use parameters; `limit` is clamped.
- **OPC UA sessions:** channel and session certificates must match, client
  and server signatures are checked, passwords are re-encrypted with the
  right nonces.
- **Web API:** the CSRF header on every state-changing request; cookies
  HttpOnly and SameSite=Strict, `__Host-` and Secure with TLS; a new session
  token at login and after a password change; the role check first in every
  handler; HSTS only with a configured certificate.
- **API tokens:** SHA-256 of a 256-bit secret, compared in constant time;
  refused when MCP is off, for a user who must change their password, and
  after the user is deleted. `/mcp` ignores cookies and needs a bearer
  header, so its CSRF exemption is safe.
- **MCP change tools:** unknown arguments are refused before they are
  applied; they call the web API's handlers, so role checks, validation
  and records are the same. No tool writes to a PLC.
- **Certificates:** thumbprint lookups scan the directory, so no path
  traversal; the versioned `/js/<hash>/` route only serves known modules.
- **Config rewrite:** atomic, validated before anything is applied.
