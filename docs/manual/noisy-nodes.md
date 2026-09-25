# Noisy nodes (life bits, counters)

An HMI that writes a life bit every second adds 86 400 records a day and
buries the writes that matter. Such nodes can be **summarised**: their value
writes are no longer recorded one by one, but counted, and every hour one
`ignored_writes` record per node says how many writes there were (and how
many failed), from which clients, from when to when, and the last value. A
write to such a node therefore never goes unnoticed entirely.

A target keeps its summarised nodes in **groups**, e.g. "HMI line 1": a
name, optionally one client (IP address or application URI; the same nodes
written by anyone else stay recorded one by one), and the nodes. A write is
summarised when a group for its client, or one for every client, has the
node. At most 1000 nodes per target, over all its groups.

## In the web UI (admin)

- Each target shows its groups under **Summarised nodes**, with **Add
  nodes…** (tick nodes among the most written, for that group's client, or
  paste node ids one per line), **Rename**, **Remove group** and a remove
  button per node.
- **Audit trail → Most written**, a write record's details and a variable in
  the Browser have **Summarise…**: add the node to a group that fits the
  client, or start a new group for that client or for every client.
- Summarised nodes carry a *summarised* label in the audit trail and the
  Browser.

Changes apply at once, without disconnecting clients, and each is audited as
one `config_changed` record, e.g. "target 'plc1': 12 nodes added to 'HMI line
1' (from 192.168.1.20)".

## In `config.toml`

```toml
[audit]
ignored_summary_secs = 3600         # one summary per node per hour (default; also in Settings)

[[targets]]
name = "line1"
# …
[[targets.summarise]]
name = "HMI line 1"                 # optional, for people
client = "192.168.1.20"             # optional: only from this address or application URI
nodes = [                           # as shown in the audit trail
  'ns=3;s="DB1"."Life"',
  "ns=3;i=1234",
]
```

The older form, one `[[targets.ignore]]` table per node, still loads: its
rules become groups (one per client, one for every client), and the file is
written with groups the next time the web UI saves it.

## What is not summarised

Only writes of a node's value are summarised; method calls, other attributes
and other services are always recorded. Summarised writes skip the read of
the old value, which also saves the PLC a request per write. In
`fail_mode = "closed"` they are not held back for a committed record; a
summary that has not been written yet is lost if the gateway crashes.
