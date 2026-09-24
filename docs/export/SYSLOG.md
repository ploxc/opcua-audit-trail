# Syslog export (removed)

Earlier versions could also send the audit trail to a syslog receiver (a
SIEM such as Graylog, Splunk, Wazuh or rsyslog). It was taken out of the
gateway to keep it small: QuestDB is the one supported export. This page
describes what it did, so it can be brought back if someone needs it.

## What syslog is

Syslog is the standard way to send log lines over the network to a central
collector. Security teams often collect everything in a SIEM through syslog,
so an export there puts the audit trail next to their other logs.

## How the export worked

- **Format:** one RFC 5424 message per audit record. The structured data
  carried the sequence number, the record's hash and the previous record's
  hash, target, event kind, user, client and node; the message itself was the
  record as JSON. Like the QuestDB export, the hashes anchored the local chain.
- **Transport:**
  - `udp`: fire and forget. A message could be lost, or cut off when it was
    larger than a datagram.
  - `tcp`: RFC 6587 octet counting.
  - `tls`: RFC 5425 over TLS, with an optional `ca_file` for a private CA.
- **Facility:** configurable, default 16 (local0).
- **Delivery:** the same exporter loop as QuestDB. It kept a position per
  destination in `data/export-state.json`, delivered at least once, and
  detected gaps.

Configuration was:

```toml
[export.syslog]
address = "siem.local:6514"
protocol = "tls"         # "tcp" or "udp"
# ca_file = "siem-ca.pem"
facility = 16
interval_secs = 5
```

A config file that still has an `[export.syslog]` section loads. The section
is ignored with a warning, and saving settings in the web UI removes it.

## Bringing it back

The code is in the git history as `src/export/syslog.rs`. The last commit
that has it is `901f428`:

```sh
git show 901f428:src/export/syslog.rs
``` Restoring it takes:

- the file itself;
- the `Syslog` sink in `src/export/mod.rs`;
- `SyslogConfig` in `src/config.rs` and writing it in `src/targets.rs`;
- the settings API and page.

Known weaknesses when it was removed:

- Over TCP, a batch counted as delivered once it was in the kernel buffer, so
  a receiver restart could lose one batch.
- Over UDP there is no delivery guarantee at all.
