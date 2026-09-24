# Independent verification of the audit

[AUDIT.md](AUDIT.md) was written by the same assistant that wrote the code. Seven independent agents checked it along two tracks. None of them saw the others' results.

| Track | Agents | What they got | Task |
|---|---|---|---|
| **Blind** (no context) | 3: relay; audit trail + export; web, config + packaging | The code only, in an isolated worktree of the audited commit. They were told not to read `docs/audit/` or the git history. | Audit their area from scratch. |
| **With context** | 4, split by finding: relay (R1, R2, R7-R9); DoS + discovery (R3-R6, I2, I5); audit trail + export (A1-A5, E1-E3, I4); web, PKI + CI (W1-W6, P1, P2, K1, I1, I3) | The code and AUDIT.md. | Try to prove each finding wrong, confirm it with a test or proof of concept where possible, and judge the severity and the recommendation. |

- All agents worked on commit `bbfa4cf`, the audited code.
- The verifiers wrote 34 throwaway tests and proofs of concept. They are not committed; they will come back as regression tests together with the fixes.
- I (the author) re-checked the two library claims the new findings rest on: the async-opcua `token_renewal_deadline` units, and the underflow in `legacy_secret_decrypt`. Both hold.

## Result in one paragraph

Of the 31 findings in AUDIT.md:
- **29 were confirmed**, 21 of them by tests or proofs of concept.
- **1 is plausible but unproven**: R2 (the analysis holds; no wire-level exploit was built).
- **1 was refuted**: R7 (the Duration overflow is arithmetically unreachable).

The most important confirmation is **R1**. A proof of concept showed that writes reach the PLC without an audit record: 10 of 10 with 150 ms of PLC latency, 3 of 34 even with an in-process PLC. The chain still verified afterwards.

The blind auditors independently found 24 of the 30 findings that were not refuted. They missed R1, R6, R8, R9, P2 and I2. Between them, all seven agents also found about 30 issues that AUDIT.md missed, **three of them High**:
- a remote panic in password-token decryption,
- ILP injection that stalls the QuestDB export,
- the Windows service running as LocalSystem.

Two statements under "Areas reviewed and found sound" in AUDIT.md are wrong (see *Corrections*).

## 1. The findings in AUDIT.md

| ID | Audit | Verdict | Verifiers' severity | How | Found blind? |
|---|---|---|---|---|---|
| R1 | High | **Confirmed** | High | PoC | no |
| R2 | High | Plausible | High (needs an on-path attacker for variant a) | Code + library analysis | yes |
| R3 | Medium | **Confirmed** | **High** when None is offered | Test (see note 1) | partly |
| R4 | Medium | Confirmed | Medium–High (see N5) | Code | yes |
| R5 | Medium | **Confirmed** | Medium | Test (see note 2) | yes |
| R6 | Medium | Confirmed | Medium | Code (see note 3) | no |
| A1 | Medium | **Confirmed** | Medium (a blind agent rated it High) | Tests (see note 4) | yes |
| A2 | Medium | **Confirmed** | Medium | Tests (see note 5) | yes |
| E1 | Medium | **Confirmed** | Medium | Tests (see note 6) | yes |
| W1 | Medium | **Confirmed** | Medium | Test: 128 concurrent failed logins use +1.4 GiB RSS | yes |
| W2 | Medium | **Confirmed** | Medium (upper end) | Tests (see note 7) | yes |
| A3 | Low | Confirmed | Low (a blind agent rated it Medium) | `PRAGMA synchronous` = 1 | yes |
| A4 | Low | **Confirmed** | Low+ | Test (see note 8) | yes |
| A5 | Low | **Confirmed** | Low (a blind agent rated it Medium) | Test: a changed `user` column hides the record from the real user's filter; `verify` passes | yes |
| E2 | Low | Confirmed | Low | Test: an empty or truncated state file makes `export::start` fail, so the gateway does not start | yes |
| E3 | Low | Confirmed | Low (it also weakens A1's export anchor) | Code | yes |
| W3 | Low | **Confirmed** | Low (a blind agent rated it Medium) | Test: role changed, request 400, 0 `config_changed` records | yes |
| W4 | Low | Confirmed | Low (error texts work as a port-scan oracle; nothing is audited) | Code | yes |
| W5 | Low | Confirmed | Low (a blind agent rated it Medium) | Code | yes |
| W6 | Low | **Confirmed** | Low (a blind agent rated it Medium) | Code | yes |
| P1 | Low | **Confirmed**, worse | Low | Test (see note 9) | yes |
| R7 | Low | **Refuted** | none | `from_millis(u64::MAX) * 2` does not overflow; reaching the panic needs 500× more | no |
| R8 | Low | Confirmed | Low (it enables R2) | Code | no |
| R9 | Low | Confirmed, worse | Low | Code (see note 10) | no |
| P2 | Low | Confirmed | Low (a renew never re-checks trust, so the channel lives as long as the client keeps renewing) | Code | no |
| K1 | Low | Confirmed | Low (a blind agent rated it Medium) | Code (`rust-toolchain@stable` is a branch ref, not a tag) | yes |
| I1 | Info | **Confirmed** | Info | Test: an expired trusted certificate is accepted; an untrusted one is still rejected | yes |
| I2 | Info | Confirmed | **Low** (status codes and source timestamps are dropped even when a value is written) | Code | no |
| I3 | Info | **Confirmed**, worse | Info | Test: `\t=1+1` passes; `-3.5` is exported as `'-3.5` (corrupts numbers) | yes |
| I4 | Info | **Confirmed** | Low (key ordering cuts off `node_id` and `status` first) | Test: a 9 332-byte message becomes invalid JSON | yes |
| I5 | Info | Confirmed | Info/Low | Code | yes |

Notes:
1. **R3:** an 8 MiB chunk is accepted before OpenSecureChannel, and 16 of them add 144 MiB RSS. The codec also buffers the whole declared frame, up to 4 GiB, before any size check.
2. **R5:** a rejected 5 MiB write, sent anonymously, produced a 5.2 MB audit record.
3. **R6:** nothing reads the upstream `server_endpoints`, and no event records an endpoint change.
4. **A1:** truncating the tail, rebuilding the chain, and a forged `retention_pruned` record without any rehashing all pass `verify`.
5. **A2:** after a backward clock jump, retention deletes 5 of today's records. After a *forward* jump it deletes everything.
6. **E1:** a gap left by retention is not flagged, and a renumbered database exports nothing. The status shows `pending 0` and no error.
7. **W2:** after CLI changes the old cookie keeps its role, and **a deleted admin can create a new admin**. After your own password change, your other sessions stay valid.
8. **A4:** a crash between the DELETE and the anchor gives a false tamper alarm. If the DELETE emptied the table, the chain silently restarts at seq 1.
9. **P1:** async-opcua writes the *generated* private key as 0644 with `File::create`. A UI target change turns a 0600 `config.toml` into 0644.
10. **R9:** a CloseSession with another session's token also removes the victim's registry entry, and the victim's later writes lose their user attribution.

## 2. New findings (not in AUDIT.md)

Numbered N1 and up. The source is B (blind agent) or V (verifier with context). The confirmation column says how each one was established.

### High
| ID | Finding | Location | Source | Confirmation |
|---|---|---|---|---|
| N1 | **ILP tag injection.** `escape_name` turns `\n` into a bare, unescaped space. A user name such as `bob\nforged=1i` (recorded for a failed login, before authentication) ends the tag set, so the line is malformed. QuestDB then rejects the batch and the exporter retries it forever, which removes the off-box anchor. Tabs pass through; `"` in tags is not escaped. | `src/export/questdb.rs:99` | B | Malformed line reproduced; the QuestDB rejection is unverified. |
| N2 | **Remote panic in password decryption.** `legacy_secret_decrypt` computes `actual_size - nonce_len`, which underflows when the decrypted length prefix is small. An ActivateSession with a crafted UserName token (possible anonymously over None) panics the connection task. The upstream PLC session leaks (no `close()`, no `client_disconnected` record); repeating it exhausts the PLC's sessions. | `src/relay/connection.rs:805-811`; async-opcua-crypto `user_identity.rs:295` | B | Unit test `panicked=true`; library code re-read by the author. |
| N3 | **The Windows service runs as LocalSystem** (`account_name: None`) from the directory the README suggests (`C:\gateway`). Authenticated users can write there by default, so a local user can replace the exe or config (code runs as SYSTEM), add an admin to `gateway.db`, or read the key and the admin password in the logs. | `src/service.rs`, README | B | Unverified (no Windows test); follows from the code and the default ACLs. |

### Medium
| ID | Finding | Location | Source | Confirmation |
|---|---|---|---|---|
| N4 | **Session takeover over a None channel.** The ActivateSession signature check depends on the *current* channel's policy. A session created over Sign/SignAndEncrypt can be re-activated over a None channel with no proof of possession. Only the secrecy of the token protects it. | `src/relay/connection.rs:879-905` | B | Code |
| N5 | **Channel expiry is 1000× too long.** async-opcua's `token_renewal_deadline` applies `Duration::seconds` to a lifetime in milliseconds. The gateway's "secure channel expired" close effectively never fires (3.7 h at the 10 s minimum, 55 days at 1 h). This amplifies R3 and R4. | `src/relay/connection.rs:523`; async-opcua-core `secure_channel.rs:465` | V | Test measured it; library code re-read by the author. |
| N6 | **The codec buffers the whole declared frame** (up to `u32::MAX`) before `max_message_size` is checked. The Hello phase is affected too. | async-opcua-core `tcp_codec.rs:73-86` | V | Test: a declared 1 GiB frame took +97 MiB RSS after 96 MiB was sent. |
| N7 | **The browser can send the operator's PLC password in plaintext.** `pick_endpoint` ranks by the server-advertised `security_level` and accepts a None endpoint with UserName tokens. | `src/web/browser.rs:118-136` | B | Code + library |
| N8 | **Fail-open, the default, drops individual write records under load.** When the queue (10 000) is full, only an `events_lost` count remains. This is a documented trade-off, but the default. | `src/audit/mod.rs:55-69` | B | Code |
| N9 | **An empty audit table restarts the chain at seq 1 without a warning.** The cause can be a crash during pruning, a forward clock jump or deletion. Sequence numbers are then reused, the exporter skips the new records, and downstream the same seq has two hashes. | `src/audit/store.rs:83-90` | B, V | Test (`next seq = [1]`, `verify ok`) |
| N10 | **Syslog over TCP loses a batch when the receiver restarts.** A write into the kernel buffer counts as delivered, and the peer's close is only noticed on the next write. There is also no write timeout, so a receiver that stops reading hangs the exporter. | `src/export/syslog.rs:87-114` | B, V | Test: seq 2 was reported delivered, but nobody read it. |

### Low
| ID | Finding | Source |
|---|---|---|
| N11 | Target names are barely validated on the server (a newline allows log forging; the UI pattern is client-side only). Test confirmed. | B |
| N12 | Browser sessions outlive the deletion or change of their target and untrusted certificates. Test: browse still returns 200. | B |
| N13 | A config write failure after a target restart leaves a running relay that is neither in the config nor audited. | B, V |
| N14 | Certificate import is not atomic (certificate and key in two writes), checks no expiry or URI, keeps one `.bak`; the web TLS certificate is only loaded at start. | B, V |
| N15 | Windows only (unverified): async-opcua names certificate files after the CN and strips only `/`. A CN containing `\` could write outside `pki/`, and unknown client certificates land in `rejected/` automatically. | B, V |
| N16 | `pki/rejected/` grows without limit (one file per self-signed client) and is parsed synchronously on every `/api/status` poll. | B, V |
| N17 | A race between two browser connects for the same user and target leaks a PLC session (unverified). | B |
| N18 | `install.sh` runs `init` as root in a directory owned by the service user, so a planted symlink is followed. | B |
| N19 | The systemd unit lacks `UMask`, `SystemCallFilter`, `RestrictAddressFamilies`, `ProtectClock`, `MemoryDenyWriteExecute`, … | B |
| N20 | `change_intent` has no values: after a crash, only "node X was written" survives in fail-closed mode. | B |
| N21 | TransferSubscriptions is not audited (it can take over another session's monitored items). | B |
| N22 | The `user` label cannot tell identity kinds apart (a user called `anonymous`, `ui:admin`, or a certificate subject). | B |
| N23 | Gaps in fail-open accounting: the lost counter is only in memory, a dead writer thread is not restarted, failures of `record_committed` are not counted, and a large retention DELETE blocks the writer. | B |
| N24 | The Acknowledge returns the client's own Hello limits as the server's receive limits (the directions are mixed up; interop). | V |
| N25 | A `certificate_rejected` record for the upstream certificate has no client context. | V |

### Info
- Exported records cannot be verified on their own: `prev_hash` and the exact body are not exported.
- A body that cannot be read stops the export forever (poison record).
- The export status shows "healthy" while stalled, because `pending` is clamped to 0.
- Missing response headers and checks:
  - no `Cache-Control: no-store` on the API or the CSV;
  - no HSTS;
  - no `base-uri` or `form-action` in the CSP;
  - no `__Host-` cookie prefix;
  - no Host header check (DNS rebinding reaches the login).
- Error details, including file paths, are shown in the UI.
- The UI keeps browser state after logout.
- A QuestDB URL containing `user:pass@` is shown in the status.
- An empty user update ends sessions and records an empty change.
- Base images are not pinned by digest; compose uses `questdb:latest`.

## 3. Corrections to AUDIT.md
- **R7 is withdrawn.** The panic cannot be reached.
- **"ILP escaping handles … newlines" is wrong.** Newlines become unescaped spaces in tag values (N1).
- **"Config rewrite … validation runs before anything is applied" is incomplete.** Validation does, but a failed write leaves a running, unrecorded target (N13).
- **R3 is understated.** The real per-frame limit is about 4 GiB (N6), and the exposure window is hours, not 10 s (N5).
- **P1 names the wrong main culprit.** The generated key, written by the library, is 0644 too.
- **Recommendations the verifiers sharpened:**
  - R1: spawned requests must hold the upstream until they finish, and "sent, outcome unknown" must be recorded.
  - R2: the check has to happen *before* `verify_and_remove_security_server`, because the library changes the channel policy while parsing.
  - A2: the proposed query needs a COALESCE, and forward clock jumps need their own guard.
  - E1: store and check `(seq, hash)` of the last exported record; a check on the position alone misses a recreated database.
  - W2: a session version counter must live in the database, because the CLI is a separate process.

## 4. Fix priority

1. **Audit completeness and channel security:** R1, R2 (+R8), N2, N4.
2. **Availability before authentication:** R3 + N5 + N6, R4, R5, W1.
3. **Tamper evidence and export:** N1, A2 + N9, A4, E1, N10, A1 (anchoring), A3, A5, E2.
4. **Web and operations:** W2, W3, N7, N3 (Windows service account and ACLs), P1 + N19, N11–N18, W4–W6, K1.
5. The rest of the Low and Info findings.
