# Security audit

**Status:** no open findings. Fixed findings are removed from this file;
the git history keeps them. What remains are the accepted items and what
was reviewed and found sound.

**Reviews:**
- **First audit** at `bbfa4cf`, with an independent verification that added
  findings N1–N25. Every finding of that round is fixed, except the ones
  still listed below (W6, N8, N12, N14, N23) and the accepted items. The
  fixes are in `ead63fb`, `2f7698e`, `81812d2`, `c186a74` and `ec325e0`.
- **Second review** at `4d1470d` (2026-09-25), after the first-login change,
  HTTPS by default, the MCP endpoint and API tokens. Findings S1–S20. All
  of them, and the remaining W6, N8, N12, N14 and N23, are fixed on the
  branch `security-audit-2`, one commit per finding or group.

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

No open findings.

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
