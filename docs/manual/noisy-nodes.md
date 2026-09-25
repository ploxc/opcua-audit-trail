# Noisy nodes (life bits, counters)

An HMI that writes a life bit every second adds 86 400 records a day and
buries the writes that matter. Such nodes can be **summarised**: their value
writes are no longer recorded one by one, but counted, and every hour one
`ignored_writes` record per node says how many writes there were (and how
many failed), from which clients, from when to when, and the last value. A
write to such a node therefore never goes unnoticed entirely.

## In the web UI (admin)

- **Audit trail → Most written** lists the nodes written most in the last 24
  hours. **Summarise…** opens a dialog that explains what happens and asks
  whose writes to summarise: every client's, or only one client's (the same
  node written by anyone else stays recorded one by one).
- The same button is in a write record's details and on a variable in the
  Browser.
- Summarised nodes carry a *summarised* label in the audit trail and the
  Browser, and each target lists them under **Summarised nodes**, with
  **Record every write again** to undo it.

Changes apply at once, without disconnecting clients, and are audited
(`config_changed`).

## In `config.toml`

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

## What is not summarised

Only writes of a node's value are summarised; method calls, other attributes
and other services are always recorded. Summarised writes skip the read of
the old value, which also saves the PLC a request per write. In
`fail_mode = "closed"` they are not held back for a committed record; a
summary that has not been written yet is lost if the gateway crashes.
