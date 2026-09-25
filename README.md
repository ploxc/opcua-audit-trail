# OPC UA Audit Gateway

A transparent OPC UA gateway that records **who writes what, when**.

Put it between your OPC UA clients and your PLC. Clients connect to the gateway
instead of the PLC; the gateway forwards everything and keeps a tamper-evident
audit trail of every write, method call and client session. It is a single Rust
binary that runs standalone (Linux, Windows, macOS, ARM PLCs such as PLCnext) or
in Docker.

> **Status: a working concept, not production ready.** The code was written
> with Claude (Anthropic), from my idea and OPC UA/PLC domain knowledge, and
> tested as described in [What is tested](#what-is-tested). If there is
> interest, I'm open to developing it further.

What it does today:

- **Relay:** relays security `None`, `Sign` and `SignAndEncrypt` (all RSA
  policies), anonymous and user name logins, and every service (reads, writes,
  subscriptions, method calls, …).
- **Audit trail:** writes, method calls, history updates, node management,
  sessions and connections are recorded, with old value → new value and the
  node's display name, in a hash chain that shows any tampering.
- **Web UI:** status, the audit trail, targets, certificates, an OPC UA
  browser, users and settings.
- **Export:** audit records to QuestDB.
- **AI assistants:** an MCP endpoint, so Claude can search the trail or help
  configure the gateway, with per-token permissions.
- **Installation:** Docker, a systemd or Windows service, or a plain binary,
  with HTTPS.

**[Manual](docs/manual/README.md)** for installation, setup and use;
[ARCHITECTURE.md](ARCHITECTURE.md) for the design.

## Quick start (Docker)

```sh
curl -LO https://raw.githubusercontent.com/ploxc/opcua-audit-trail/main/docker-compose.yml
docker compose up -d
docker compose logs gateway        # the first admin password
```

Open **https://127.0.0.1:8080** (a self-signed certificate: accept it once)
and log in as `admin` with the password from the logs. Then connect your
first PLC: [Your first PLC](docs/manual/first-target.md) takes you through
it step by step. Clients then connect to the gateway
(`opc.tcp://<gateway>:4841`, the first target's port) instead of the PLC.

- Other ways to install: [Linux](docs/manual/installation/linux.md) ·
  [Windows](docs/manual/installation/windows.md) ·
  [macOS](docs/manual/installation/macos.md) ·
  [from source](docs/manual/installation/from-source.md)
- No PLC at hand? [Try it without a PLC](docs/manual/try-without-a-plc.md).
- Everything else: the [manual](docs/manual/README.md).

## Screenshots

The audit trail: every write with who, from which client, old → new value and
the result.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/audit-trail-dark.png">
  <img alt="Audit trail" src="docs/screenshots/audit-trail-light.png">
</picture>

<details>
<summary>Dashboard, targets and the OPC UA browser</summary>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/dashboard-dark.png">
  <img alt="Dashboard with connected clients and the latest changes" src="docs/screenshots/dashboard-light.png">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/targets-dark.png">
  <img alt="A target with its endpoints, logins and certificates" src="docs/screenshots/targets-light.png">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/screenshots/browser-dark.png">
  <img alt="The OPC UA browser with attributes and a watched value" src="docs/screenshots/browser-light.png">
</picture>

</details>

## What is tested

About 100 automated tests, including end-to-end tests with a real OPC UA
client and server through the gateway. By hand: the web UI; the Docker image
against [OPC PLC](docker/opc-plc/) (Microsoft's simulator) with the Prosys
OPC UA Browser, encrypted up to `Aes256-Sha256-RsaPss`, trust both ways;
Siemens PLCSIM Advanced; the MCP endpoint from Claude Desktop and Claude
chat; the release workflow as a dry run.

Not tested yet: the Linux and Windows service installations, publishing a
real release, export to a real QuestDB, and real PLCs on a real network over
longer periods and under load.

## License

MIT
