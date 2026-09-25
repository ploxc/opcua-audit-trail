# Configuration

## The config file

One TOML file, `config.toml`. `opcua-audit-gateway init` writes a commented
example; relative paths in it are resolved against the file's directory.

| How it runs | Config file |
|---|---|
| Docker | `/data/config.toml` in the volume (created from [`docker/config.toml`](../../docker/config.toml) at the first start) |
| Linux (systemd) | `/etc/opcua-audit-gateway/config.toml` |
| Windows (service) | the `--config` given at `service install` |
| A terminal | `./config.toml`, or `--config <file>` |

Most of it is managed in the web UI: targets, certificates, and the settings
on the Settings page. Those changes are written back into the file (comments
are kept) and apply at once.

Only these need the file and a restart: `[web]` (address, HTTPS,
certificates, `allowed_hosts`, `trusted_proxies`) and the `[gateway]` paths.

Sections:

- `[gateway]`: application name and URI, `pki_dir`, `data_dir`, certificate
  host names.
- `[web]`: `listen`, `tls`, `tls_certificate`/`tls_private_key`,
  `allowed_hosts`, `trusted_proxies`; see [HTTPS](https.md) and
  [Users](users.md).
- `[audit]`: retention, fail mode, old values, summary interval; see
  [Audit trail](audit-trail.md).
- `[export.questdb]`: see [Audit export](export.md).
- `[mcp]`: `enabled`; see [AI assistants](ai-assistants.md).
- `[[targets]]`: see [Targets](targets.md) and [Noisy nodes](noisy-nodes.md).

## Environment variables

| Variable | Meaning |
|---|---|
| `OPCUA_GATEWAY_CONFIG` | The config file (same as `--config`) |
| `OPCUA_GATEWAY_LOG_DIR` | Log to daily files in this directory instead of the console (same as `--log-dir`) |
| `OPCUA_GATEWAY_WEB_TLS` | `true`/`false`: overrides `[web] tls` (set to `true` in the container image) |
| `OPCUA_GATEWAY_ADMIN_PASSWORD` | The first admin password, used only when `admin` is created (see [First login](first-login.md)) |
| `RUST_LOG` | Log level, e.g. `debug` |
