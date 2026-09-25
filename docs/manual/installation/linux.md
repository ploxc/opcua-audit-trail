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
- **Upgrade:** run `install.sh` from the new archive; config and data are
  kept.
- On a PLCnext controller use the `armv7` archive or the container image.

The web UI only listens on this machine. For access from other machines, set
under `[web]` in the config `listen = "0.0.0.0:8080"` and `tls = true` (see
[HTTPS](../https.md)), then `sudo systemctl restart opcua-audit-gateway`.
Logs: `journalctl -u opcua-audit-gateway`.
