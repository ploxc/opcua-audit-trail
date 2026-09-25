# Docker

The image `ghcr.io/ploxc/opcua-audit-trail` (linux/amd64, arm64, arm/v7) is
published for every release, with the tags `latest`, `X.Y` and `X.Y.Z`. All
you need is [`docker-compose.yml`](../../../docker-compose.yml) (also attached
to every release):

```sh
curl -LO https://raw.githubusercontent.com/ploxc/opcua-audit-trail/main/docker-compose.yml
docker compose up -d
docker compose logs gateway        # the first admin password
```

The web UI is on **https://127.0.0.1:8080**, with a self-signed certificate:
accept it once in the browser, or trust it (see [HTTPS](../https.md)). Log
in as `admin` (see [First login](../first-login.md)), then connect
[your first PLC](../first-target.md).

In a checkout, `docker compose build` builds the image from the source.

## What the compose file sets

- **Ports:** the web UI on `127.0.0.1:8080` (this machine only), and `4841`
  for OPC UA clients of the first target. **Every further target needs its
  own port line**, e.g. `"4842:4842"`. For the web UI from other machines,
  publish `"8080:8080"`.
- **`OPCUA_GATEWAY_WEB_TLS: "true"`:** HTTPS for the web UI. `"false"` only
  behind a TLS reverse proxy.
- **`OPCUA_GATEWAY_ADMIN_PASSWORD`** (commented out): choose the first admin
  password yourself.
- **The `gateway-data` volume at `/data`:** config, certificates, users and
  the audit trail.

The container's config ([`docker/config.toml`](../../../docker/config.toml),
copied to `/data/config.toml` at the first start) differs from the defaults
in two ways:

- **Fail mode `closed`:** a write only reaches the PLC once its record is
  stored. If the trail cannot be written (e.g. a full disk), clients cannot
  write. Change it in Settings → Audit trail.
- **The gateway's name:** the container does not know the host's name or IP,
  which clients use. Add them under Settings → Gateway certificate before a
  PLC trusts the certificate (see [Your first PLC](../first-target.md)).

## Changing the config

Targets, certificates and most settings are managed in the web UI. For the
rest (see [Configuration](../configuration.md)):

```sh
docker compose cp gateway:/data/config.toml .
# edit config.toml
docker compose cp config.toml gateway:/data/config.toml
docker compose restart gateway
```

## Upgrading and starting over

- **Upgrade:** `docker compose pull && docker compose up -d`. The volume is
  kept.
- **Start over:** `docker compose down -v` deletes the container **and the
  volume**: the audit trail, users and certificates are gone, and PLCs must
  trust the new gateway certificate.
