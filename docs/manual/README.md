# Manual

How to install, set up and use the OPC UA Audit Gateway. For the design, see
[ARCHITECTURE.md](../../ARCHITECTURE.md).

## Getting started

- [Try it without a PLC](try-without-a-plc.md): a stand-in PLC and client on
  your machine.
- Installation:
  [Docker](installation/docker.md) ·
  [Linux (systemd)](installation/linux.md) ·
  [Windows (service)](installation/windows.md) ·
  [macOS](installation/macos.md) ·
  [From source](installation/from-source.md)
- [First login](first-login.md): where the first admin password comes from.
- [HTTPS](https.md): the web UI's certificate and how to trust it.

## Connecting PLCs and clients

- [Targets](targets.md): one per PLC; discovery and security per target.
- [Certificates](certificates.md): trust between clients, the gateway and
  the PLC.

## Using it

- [Web UI](web-ui.md): the pages and who may use them.
- [Users and roles](users.md): the web UI's users, also from the command
  line.
- [Audit trail](audit-trail.md): what is recorded, integrity, retention,
  fail mode.
- [Noisy nodes](noisy-nodes.md): summarise life bits and counters.
- [Audit export](export.md): copies in QuestDB.
- [AI assistants (MCP)](ai-assistants.md): let Claude read the trail or help
  configure.

## Reference

- [Configuration](configuration.md): the config file and environment
  variables.
