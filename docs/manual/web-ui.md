# Web UI

| Page | Role | |
|---|---|---|
| Dashboard | auditor | Reachability of each target, connected clients, latest changes, problems that need attention |
| Audit trail | auditor | Filters, record details, live mode, CSV export, integrity check, most written nodes (admin summarises them) |
| Targets | auditor (operator discovers, admin edits) | Add/edit/remove targets without a restart, discovery, trust the PLC certificate |
| Certificates | auditor (admin acts) | Gateway certificate (download/import/regenerate), trust or reject certificates |
| Browser | operator | Read-only address space browser with live values |
| Users | admin | Users, roles and everyone's API tokens |
| Settings | auditor (admin edits) | Retention, fail mode, old values, summary interval, QuestDB export, certificate host names, MCP; web server and paths shown read-only |
| Account | everyone | Own password and API tokens |

## Errors and warnings

The sidebar counts errors and warnings until someone acknowledges them.

- **Error (red):** something is broken and needs action: the trail or its
  copies may be incomplete, or clients cannot reach a target (unreachable,
  or no trust between gateway and PLC), or the target's security changed.
- **Warning (orange):** something to look at while everything works: a
  refused client certificate, login or API token, refused connections, a
  clock that jumped.

## Settings

Settings are saved in `config.toml` (comments are kept) and applied at once,
without a restart or disconnecting clients. Passwords and tokens are never
shown again once saved. Shortening the retention deletes older records right
away.

The web server's address, HTTPS and the data paths take effect only at
start, and a wrong value could lock you out, so they are changed in the file
(see [Configuration](configuration.md)).
