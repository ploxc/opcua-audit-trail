# Linux (systemd)

Release archives are built for x86_64, ARM64 and ARMv7 (static binaries).

```sh
tar xzf opcua-audit-gateway-*-linux-amd64.tar.gz && cd opcua-audit-gateway-*
sudo ./install.sh ./opcua-audit-gateway
sudo nano /etc/opcua-audit-gateway/config.toml    # or add targets in the web UI
```

The web UI is on http://127.0.0.1:8080. The first password is in the journal
(see [First login](../first-login.md)):

```sh
sudo journalctl -u opcua-audit-gateway | grep "first login"
```

- The service runs as the unprivileged user `opcua-gw` with a hardened unit.
- Config: `/etc/opcua-audit-gateway/config.toml`. Data, certificates and the
  audit trail: `/var/lib/opcua-audit-gateway`.
- Running `install.sh` again upgrades the binary and keeps config and data.
- On a PLCnext controller use the `armv7` archive or the container image.

For access to the web UI from other machines, enable [HTTPS](../https.md).
