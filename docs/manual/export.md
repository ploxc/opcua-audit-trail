# Audit export

The audit trail lives in the gateway (SQLite) and can also be copied to
QuestDB, for long-term storage and SQL analysis. The destination keeps its
own position in `<data_dir>/export-state.json`: nothing is skipped while it
is down, and records are delivered at least once.

In **Settings** (admin) or in `config.toml`:

```toml
[export.questdb]
url = "http://questdb:9000"   # ILP over HTTP(S); each batch is acknowledged
table = "opcua_audit"         # created on first write
# token = "…"  or  username = "…" / password = "…"  (use https off-host)
# ca_file = "questdb-ca.pem"  # https with a private CA; default: public roots
```

- In the web UI a private CA is pasted as PEM text; the gateway keeps it in
  `<data_dir>/questdb-ca.pem`.
- Changing the URL's host drops the stored password or token, unless new ones
  are given: they are never sent to another server.
- QuestDB is not bundled with the gateway; use one you run.
- Syslog: not supported (see [docs/export/SYSLOG.md](../export/SYSLOG.md)).

## Tamper evidence

Every exported record carries its sequence number, its hash and the previous
record's hash. Once records are outside the gateway, rewriting the local
database no longer goes unnoticed: `verify` checks the chain against the last
record each destination acknowledged.

If the destination's last position is no longer in the trail (a truncated or
rebuilt database), the gateway records an `export_gap` error and the
dashboard raises it. In QuestDB, make retries idempotent with
`ALTER TABLE opcua_audit DEDUP ENABLE UPSERT KEYS(ts, seq)`.

The dashboard shows the destination's state and how many records are
waiting.
