# A locked-down simulated PLC (Microsoft OPC PLC)

[OPC PLC](https://github.com/Azure-Samples/iot-edge-opc-plc) is an open source
OPC UA server that simulates a PLC. This setup starts it the way a PLC behind
the gateway should be configured, so exclusive access can be tried without
hardware:

- encrypted connections only (Basic256Sha256), no `None`;
- login `operator` / `operator`, no anonymous access;
- only client certificates in `pki/trusted/certs` may connect.

It runs in Docker (Linux, Windows, macOS with Docker Desktop).

## Run

```sh
docker compose -f docker/opc-plc/compose.yml up
```

Address space: `Objects/Line1` with `Setpoint`, `Running`, `Recipe`,
`LifeBit` (writable) and `ReadOnly` (writes are rejected), plus OPC PLC's own
simulated nodes that keep changing. Change `nodes.json` to add your own.

## Connect the gateway

1. Add a target (web UI **Targets → Add target**, or `config.toml`):

   ```toml
   [[targets]]
   name = "opc-plc"
   listen = "0.0.0.0:4841"
   endpoint_url = "opc.tcp://localhost:50000"
   min_security = "sign_and_encrypt"
   ```

2. **Discover**, then **Trust server certificate** (compare the thumbprint
   with `pki/own/certs`).
3. Connect a client to the gateway (`opc.tcp://<gateway>:4841`, Sign &
   Encrypt, login `operator` / `operator`). The first attempt fails: OPC PLC
   refuses the gateway. Its certificate is now in
   `docker/opc-plc/pki/rejected/certs`; move it to
   `docker/opc-plc/pki/trusted/certs`.
4. Connect again. The gateway itself refuses the unknown client the first
   time: trust it under **Certificates**. Then reads and writes work, and every
   write is in the audit trail with the user `operator`.

Without an OPC UA client at hand, the gateway's demo client plays the HMI:

```sh
cargo run --example demo_client -- opc.tcp://127.0.0.1:4841/ operator operator \
    --secure --namespace=http://microsoft.com/Opc/OpcPlc/
```

It writes `Setpoint`, `Running` and `Recipe` every few seconds (its
`ResetCounter` call fails here: OPC PLC has no such method).

## What to check

| Try | Expected |
|---|---|
| A client directly to `opc.tcp://localhost:50000` | Refused: OPC PLC trusts only the gateway |
| A client to the gateway without security | Only encrypted endpoints are offered |
| A wrong password | Refused, recorded as `authentication_failed` |
| A write to `ReadOnly` | Rejected by the PLC, recorded with its bad status |
| `LifeBit` written every second | Shows in **Most written**; summarise it |
| Untrust the client in the gateway | The client is disconnected at once |

To start over, stop the container and delete `docker/opc-plc/pki`. On Linux
the container writes that folder as root: use `sudo` to move or delete files.
