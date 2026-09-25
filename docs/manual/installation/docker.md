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

The web UI is on **https://127.0.0.1:8080**. It uses a self-signed
certificate: accept it once in the browser, or trust it (see
[HTTPS](../https.md)). Log in as `admin` with the first password (see
[First login](../first-login.md)), choose a new one, and add targets.

In a checkout, `docker compose build` builds the image from the source
instead of pulling it.

## What the compose file sets

- **Ports:** the web UI on `127.0.0.1:8080` (this machine only), and one port
  per target for OPC UA clients (`4841`; add a line per further target).
  For access to the web UI from other machines, publish `"8080:8080"` and add
  the host name or IP to the certificate host names (Settings), then
  regenerate the web certificate.
- **`OPCUA_GATEWAY_WEB_TLS: "true"`:** HTTPS for the web UI and the MCP
  endpoint. `"false"` only behind a TLS reverse proxy.
- **`OPCUA_GATEWAY_ADMIN_PASSWORD`** (commented out): the first admin
  password, if you want to choose it.
- **The `gateway-data` volume at `/data`:** config, certificates, users and
  the audit trail.

## Configuration in the volume

On the first start `/data/config.toml` is created from
[`docker/config.toml`](../../../docker/config.toml). Targets, certificates and
most settings are managed in the web UI. For the rest (see
[Configuration](../configuration.md)):

```sh
docker compose cp gateway:/data/config.toml .
# edit config.toml
docker compose cp config.toml gateway:/data/config.toml
docker compose restart gateway
```

The image has no shell. To look around in the volume, use a helper
container: `docker run --rm -it --volumes-from <container> alpine sh`.

## Upgrading and starting over

- **Upgrade:** `docker compose pull && docker compose up -d`. The volume is
  kept.
- **Start over:** `docker compose down -v` deletes the container **and the
  volume**: the audit trail, users and certificates are gone, and PLCs must
  trust the new gateway certificate.
