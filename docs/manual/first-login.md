# First login

The first start creates the web UI user `admin`. Its first password must be
changed at the first login, before anything else is possible. There is no
default password.

Where the first password comes from:

| How it runs | First password |
|---|---|
| Docker | `OPCUA_GATEWAY_ADMIN_PASSWORD` in `docker-compose.yml` when set; otherwise a random one, shown once by `docker compose logs gateway` |
| Linux (systemd) | Random, in the journal: `sudo journalctl -u opcua-audit-gateway \| grep "first login"` |
| Windows (service) | A service has no console: set it before the first start with `user passwd admin` (see [Windows](installation/windows.md)) |
| A terminal (`run`, macOS, from source) | Random, printed in the terminal at the first start |

The random password is printed to the console (stdout) only, never to a log
file:

```
  Web UI first login: admin / <password>
  (shown once; it must be changed at the first login. Lost it? opcua-audit-gateway user passwd admin)
```

`OPCUA_GATEWAY_ADMIN_PASSWORD` needs at least 8 characters and is only used
when the gateway creates `admin`, on the very first start.

**Lost it?** Set a new one on the command line, with the same config as the
gateway:

```sh
opcua-audit-gateway user passwd admin
```

This also creates `admin` if the gateway has not run yet. See
[Users and roles](users.md).
