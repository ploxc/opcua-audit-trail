# Targets

A target is one PLC (OPC UA server) behind the gateway. Clients connect to
the target's `listen` port on the gateway instead of to the PLC.

Targets are added, changed and removed on the **Targets** page, without a
restart; or in `config.toml`:

```toml
[[targets]]
name = "line1"                      # short, unique; used in audit records
listen = "0.0.0.0:4841"             # where clients connect (one port per target)
endpoint_url = "opc.tcp://192.168.0.10:4840"
min_security = "sign_and_encrypt"   # "none" (default), "sign", "sign_and_encrypt"
max_connections = 50                # client connections at once (default)
max_connections_per_address = 10    # per client address (default)
```

In Docker, publish every target's `listen` port in `docker-compose.yml`.

## Discovery

The gateway asks the PLC for its endpoints (security policies, modes, login
types, certificate) at start and at regular intervals; **Check now** on the
Targets page does it at once. From the command line:
`opcua-audit-gateway discover opc.tcp://192.168.0.10:4840`.

A target's card shows:

- **Reachable / Unreachable:** whether discovery reaches the PLC.
- **Target not trusted / Refuses the gateway:** secure connections need
  trust both ways; see [Certificates](certificates.md). Until then, clients
  cannot connect securely.

## Security per target

The gateway offers clients the endpoints the PLC advertises. Endpoint
discovery is not authenticated, so set `min_security` as soon as the PLC
supports security: endpoints below it are never offered or used, whatever
the network says.

The connection limits protect the PLC, which accepts only a few secure
channels. The gateway also accepts at most 5 new connections per second from
one address.
