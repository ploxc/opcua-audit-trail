# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Manual:** a Performance page with measurements on a PLCnext AXC F 2152
  (what reads, writes and new sessions cost through the gateway, and what
  `fail_mode` and `record_old_value` change), and how to measure your own.
- **Stress test:** `--write-node`, `--watch-node` and `--string-node` run the
  scenarios on a real PLC's nodes; a number is written as the node's own
  type.

### Changed

- **Certificates page:** everything about certificates in one place. The
  gateway's host names moved there from Settings, next to the certificate
  that carries them; saving them offers a new certificate. The web UI's
  HTTPS certificate moved there too. Both cards show the host names a
  certificate lacks, so a client that would refuse it is visible beforehand.
- The web UI is built with Preact (vendored, no build step). It looks the
  same, but a refresh no longer disturbs what is being typed on any page: the
  Targets page keeps refreshing the targets' status while a target is edited,
  and the audit trail's Live mode leaves the filters alone. Leaving a page
  drops an unsaved edit.
- **Stress test:** no longer checks the server certificate's host name and
  dates (it trusts every server anyway), so a PLC whose certificate names
  only its host name, or whose clock is off, works; a hint when the server
  refuses anonymous logins.
- The container image has a description on its package page: that it is the
  Docker image, how to start it and where the first password is.

### Fixed

- A client whose certificate lists its application URI after another name
  (node-opcua puts the DNS name first) was refused with
  `BadCertificateUriInvalid`; the URI may now be anywhere among the
  certificate's alternative names, as the specification allows.

- The target name's check (letters, digits, `.`, `_`, `-`) had an invalid
  pattern, so browsers skipped it; it works now.
- The Account page said HTTPS for MCP could be turned on under Settings; it
  names the config file now (`tls = true` under `[web]`, then restart).

## [0.1.0] - 2026-09-26

The first release: a working concept, not production ready. See
[What is tested](README.md#what-is-tested).

### Added

- **Relay:** a transparent OPC UA gateway between clients and a PLC, for
  security `None`, `Sign` and `SignAndEncrypt` (RSA policies up to
  `Aes256-Sha256-RsaPss`), anonymous and user name logins, and every service.
  A minimum security per target, and connection limits that protect the PLC.
- **Audit trail:** every write, method call, history update and node
  management request, with who, from which client, old → new value and the
  result, plus sessions, connections and certificate decisions. A hash chain
  shows any tampering (`verify`). Fail-open or fail-closed; retention.
- **Summarised nodes:** noisy nodes (life bits, counters) in groups per
  client or for every client, recorded as a periodic summary instead of one
  record per write.
- **Web UI:** dashboard, audit trail (filters, live, CSV, integrity check,
  most written nodes), targets, certificates (trust both ways), an OPC UA
  browser, users and roles, settings. Errors and warnings are counted until
  acknowledged.
- **AI assistants (MCP):** an endpoint for Claude and other assistants to
  search the trail, and, with per-token permissions, to configure targets,
  certificates and settings or acknowledge alarms. Off by default; HTTPS
  only.
- **Export:** a copy of the trail in QuestDB, which also anchors the hash
  chain outside the gateway.
- **Installation:** a Docker image (linux/amd64, arm64, arm/v7) and
  `docker-compose.yml` with HTTPS by default, static Linux binaries with a
  systemd service, a Windows service, and macOS binaries.
- **Manual:** installation, first login, your first PLC, HTTPS and the rest in
  [docs/manual](docs/manual/README.md).

[Unreleased]: https://github.com/ploxc/opcua-audit-trail/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ploxc/opcua-audit-trail/releases/tag/v0.1.0
