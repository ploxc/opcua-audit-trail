# CLAUDE.md

A transparent OPC UA gateway that records who writes what, when. Design:
[ARCHITECTURE.md](ARCHITECTURE.md). User docs: [docs/manual](docs/manual/README.md).

## Build and check

```sh
cargo fmt
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked        # ~130 tests, incl. end-to-end through an in-process OPC UA server
docker compose build && docker compose up -d   # the real thing, HTTPS on 8080
```

CI runs these on Linux, macOS and Windows, plus cross builds and the Docker
image. Merge only when all checks are green.

## Where things are

- `src/relay/`: the OPC UA relay; `audit_map.rs` turns requests into audit
  records, `ignore.rs` the summarised nodes.
- `src/audit/`: the trail (SQLite, hash chain); `event.rs` has every event
  kind and the error/warning `Severity`.
- `src/web/`: the web API (`mod.rs`), settings, login, TLS, and `mcp.rs`, the
  MCP endpoint for AI assistants.
- `src/web/ui/`: the web UI, plain JavaScript without a build step, embedded
  in the binary.
- `examples/`: `demo_plc`, `demo_client`, `stress`.
- `tools/screenshots/`: remakes the README screenshots (`npm install && npm
  run shoot`): a fresh gateway, the demo PLC and two demo clients, Chrome
  headless in light and dark. Rerun it when the UI changes visibly.

## Rules that are easy to break

- **A new UI module** must be added to `SCRIPTS` in `src/web/mod.rs`
  (`every_ui_module_is_served` checks it). Script URLs carry a hash of the UI,
  so browsers never run old code.
- **A new audit event kind** needs a label in `EVENT_LABELS`
  (`src/web/ui/js/format.js`); if it is an error or warning, add it to
  `Severity::kinds` and to `ERROR_EVENTS`/`WARNING_EVENTS`. A test keeps them
  equal. Error = something broken that needs action; warning = look at it
  while everything works.
- **MCP change tools call the web API's handlers** with the token's user, so
  role checks, validation and `config_changed` records are the same. Never
  add a tool that writes to a PLC, or one that changes users, MCP settings,
  tokens or the web server.
- **Config changes from the UI** are written with `toml_edit`
  (`src/targets.rs`), keeping the user's comments.
- **Tests that read source files** (`include_str!`) must strip `\r`: Windows
  checkouts have CRLF.
- **Secrets never go into audit records or logs** (see `redact()` in
  `mcp.rs`).

## Style

- Code, comments and docs in English; short sentences, no more than needed.
- User docs live in `docs/manual/` (one page per topic); the README is an
  overview with a Docker quick start. Update the manual with the behaviour.
- **CHANGELOG.md** ([Keep a Changelog](https://keepachangelog.com)): every
  change a user notices goes under `[Unreleased]` in the same PR. A release
  moves it to a version section; then tag `vX.Y.Z` (the tag publishes the
  GitHub release and the images at once; its notes link to the changelog).
- Match the surrounding code; doc comments say why, not what.
