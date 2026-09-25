# AI assistants (MCP)

An AI assistant such as Claude can answer questions about the trail ("who
changed Line1.Setpoint yesterday?", "which clients are connected?", "is the
trail intact?"), and help configure the gateway, through the
[Model Context Protocol](https://modelcontextprotocol.io) endpoint at `/mcp`,
on the same address as the web UI.

## Turning it on

1. **Settings → AI assistants (MCP) → MCP endpoint on** (admin). Off, the
   endpoint answers nothing and every token stops working.
2. The endpoint only answers over [HTTPS](https.md), or over plain HTTP when
   the web UI listens on loopback only: the token is a password.
3. **Account → New token.** It acts as you and is shown once.

## Connecting an assistant

**Claude Code:**

```sh
claude mcp add --transport http opcua-audit https://127.0.0.1:8080/mcp \
  --header "Authorization: Bearer gwt_…"
```

Run it in a folder of its own: without `--scope`, it is only added for the
current folder.

**Claude Desktop** only runs local servers; it connects through
`mcp-remote`. In `claude_desktop_config.json` (quit Claude Desktop first, or
it overwrites the file):

```json
{
  "mcpServers": {
    "opcua-audit": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://127.0.0.1:8080/mcp",
               "--header", "Authorization:${AUTH}"],
      "env": {
        "AUTH": "Bearer gwt_…",
        "NODE_EXTRA_CA_CERTS": "/path/to/opcua-audit-gateway-web.pem"
      }
    }
  }
}
```

If Node is installed with nvm, use the full path to `npx` and add its folder
to `PATH` in `env`.

**Other MCP clients:** Streamable HTTP transport, URL `…/mcp`, header
`Authorization: Bearer <token>`.

**The self-signed certificate:** Node-based clients must trust it:
download it on **Settings → Web UI and files** and set `NODE_EXTRA_CA_CERTS` (see
[HTTPS](https.md)). Download it again after it is regenerated.

## What an assistant can do

Every token can read: `search_audit_trail` (the same filters as the Audit
trail page), `get_audit_record`, `gateway_status` (targets, connected
clients, unacknowledged warnings, exports), `most_written_nodes` and
`verify_audit_trail` and `list_unacknowledged_alarms`.

What a token may **change** is chosen when it is created, per area:

- **Targets:** add, change and remove targets; discover; summarised nodes.
- **Certificates:** trust and untrust OPC UA certificates.
- **Settings:** audit, export and certificate host names. Retention only
  longer, and fail-closed not off: those stay in the web UI.
- **Alarms** (operators too): acknowledge errors and warnings; the assistant
  shows them and asks first.

A token with nothing ticked only reads, so a leaked read token cannot change
anything. Give a token only what it needs, and delete it when the work is
done.

Assistants never write values to a PLC, and never change users, the MCP
settings, API tokens or the web server. Clients such as Claude ask before
each tool call; allow the read tools permanently if you like, and keep
confirming changes.

## What is recorded

- Every tool call is an `mcp_query` record, with the token's user, the
  token's id and the arguments (passwords and tokens hidden).
- Changes are `config_changed` records "by admin (via MCP, token …)";
  acknowledgements are `alarms_acknowledged` records, marked the same way.
- A refused token is an `api_token_rejected` warning.

Tokens are stored as a SHA-256 hash. Delete one on the Account page; admins
see and revoke everyone's on the Users page. Resetting a user's password or
deleting the user deletes their tokens.
