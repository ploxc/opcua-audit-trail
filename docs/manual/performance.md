# Performance

What the gateway costs, measured on a real PLC, and how to measure your own.

## Measured on a PLCnext

The gateway ran natively on a Phoenix Contact AXC F 2152 (ARMv7, two cores),
next to the PLC runtime, in front of the PLC's own OPC UA server. Four
clients, `Basic256Sha256` SignAndEncrypt, user name login, 20 to 30 seconds
per run.

| | Direct to the PLC | Through the gateway |
|---|---|---|
| New session (connect, read, close) | 0.44 s | 3.2 s |
| Monitored items: notifications | 940/s | 790/s |
| Writes, `fail_mode = "closed"`, old value recorded (default) | 284/s, p50 10 ms | 20/s, p50 145 ms |
| Writes, `fail_mode = "open"`, old value recorded | | 54/s, p50 54 ms |
| Writes, `fail_mode = "open"`, `record_old_value = false` | | 87/s, p50 32 ms |

What this means:

- **Reading costs little.** Subscriptions and reads only pass through.
- **A write costs most.** Per write, the gateway:
  - reads the old value from the PLC first (`record_old_value`, about 20 ms
    here);
  - in `closed` mode waits until the record is on disk before it forwards
    the write (about 90 ms on the PLC's flash);
  - encrypts twice and hashes the record, on the same cores as the PLC
    runtime.
- **A new session costs seconds** on this CPU: the gateway does the RSA
  handshake twice (client to gateway, gateway to PLC). A client that stays
  connected, like an HMI, pays this once.

For operating a machine this is plenty: a button press is one write. Keep
the defaults unless you measure a problem; `open` and `record_old_value =
false` trade evidence for speed (see [Audit trail](audit-trail.md)).

On a PC or a server the gateway is much faster; there the PLC is usually the
limit.

## Measure your own

`examples/stress.rs` runs the same scenarios against your gateway, and with
`--direct` against the PLC first, so you see what the gateway adds:

```sh
cargo build --release --example stress
N="ns=6;s=Arp.Plc.Eclr/MainInstance"
./target/release/examples/stress writes \
  --url opc.tcp://gateway:4841/ --direct opc.tcp://plc:4840/ \
  --secure --user admin --password '…' \
  --write-node "$N.setpoint" --watch-node "$N.level" --string-node "$N.name" \
  --duration 20
```

- Scenarios: `writes`, `subscribe`, `sessions`, `reconnect`, `large`, `soak`
  and `all`; see the top of `examples/stress.rs`.
- `--write-node` is written as its own number type (Float, Int16, …).
  Choose a node that is safe to change: the test writes values from 50 to
  about 60.
- Without the node options it uses the demo PLC's `Line1.*` nodes.
- The gateway and, for `--direct`, the PLC must trust the client
  certificate in `./stress-client-pki/own/`. Some PLCs want it as PEM:
  `openssl x509 -inform der -in cert.der -out cert.pem`.
- `sessions` and `reconnect` open many sessions. A PLC has a session limit;
  `reconnect` fills it on purpose until the sessions time out.
- `--api http://127.0.0.1:8080 --api-user … --api-password …` also checks
  that every answered write has an audit record (plain HTTP only, so a
  gateway without HTTPS).
