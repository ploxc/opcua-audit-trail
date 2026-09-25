# Audit trail

Every write, method call, history update and node management request through
the gateway is recorded, with who (the OPC UA login and the client's address,
application and certificate), when, the node and its display name, the old
and new value, and the result. So are client connections, sessions, logins,
certificate decisions, configuration changes and the gateway's own events.

The trail lives in `<data_dir>/audit.db` (SQLite). The **Audit trail** page
filters it, shows each record, follows it live and exports it as CSV.

## Integrity

Each record carries the hash of the one before it (a hash chain), so a
changed or deleted record shows. Check it with **Audit trail → Verify** or:

```sh
opcua-audit-gateway verify
```

Note the head that `verify` prints and check it later, e.g. from another
machine's copy: `opcua-audit-gateway verify --expect 1234:<hash>`. An
[export](export.md) anchors the chain outside the gateway.

## Settings

In **Settings** (admin) or `[audit]` in `config.toml`:

```toml
[audit]
retention_days = 365      # 0 keeps everything; shortening deletes older records at once
fail_mode = "open"        # or "closed" (the default in the Docker image)
record_old_value = true   # read the value before each write, for old → new
```

- **`fail_mode = "open"`:** writes always reach the PLC; if the trail cannot
  keep up or fails, the lost records are counted and raised as an error.
- **`fail_mode = "closed"`:** a write only reaches the PLC after its record
  is stored. If the trail fails (e.g. a full disk), clients can no longer
  write.
- **`record_old_value`** costs one extra read on the PLC per write.

Nodes that are written constantly can be summarised instead: see
[Noisy nodes](noisy-nodes.md).

## Errors and warnings

Some records are errors or warnings and are counted in the sidebar until
acknowledged; see [Web UI](web-ui.md#errors-and-warnings).
