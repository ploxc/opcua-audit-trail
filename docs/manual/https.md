# HTTPS

The web UI and the MCP endpoint are served over HTTPS when `tls` is on:

```toml
[web]
listen = "0.0.0.0:8443"
tls = true                          # a self-signed certificate of its own, or:
# tls_certificate = "web-cert.pem"  # PEM chain, e.g. from your plant CA
# tls_private_key = "web-key.pem"
```

The container image has HTTPS on by default: `OPCUA_GATEWAY_WEB_TLS`
(`true`/`false`, in `docker-compose.yml`) overrides `tls` in the config file.

## The web UI's own certificate

Without `tls_certificate`, the web UI generates a self-signed certificate of
its own in `<data_dir>/web-pki`. It is separate from the gateway's OPC UA
certificate, so renewing it never concerns a PLC.

It names `localhost`, `127.0.0.1`, the machine and the certificate host names
(Settings, under Gateway certificate). Opening the UI by another name gives
a name mismatch: add the name there, then **Settings → Web UI → Regenerate**
and restart the gateway.

## Trusting it

Browsers ask once to accept a self-signed certificate. To stop that, trust
it: **Settings → Web UI → Download (.pem)**. It is self-signed, so there is
no separate root CA: the certificate itself is what you trust.

- **macOS:** open the .pem; in Keychain Access, open the certificate, expand
  **Trust** and set it to **Always Trust**. Restart the browser (Chrome and
  Safari use the keychain; Firefox has its own store).
- **Windows:** import it into **Trusted Root Certification Authorities**.
- **AI assistants and other Node programs:** start them with
  `NODE_EXTRA_CA_CERTS=/path/to/opcua-audit-gateway-web.pem` (see
  [AI assistants](ai-assistants.md)).

After **Regenerate**, trust the new certificate again (and update the file
Node programs use).

## Security details

- With TLS the session cookie is `Secure` and `__Host-` prefixed.
- HSTS is only sent with a configured certificate: with a self-signed one it
  would stop browsers from letting you accept it.
- Without TLS, keep the UI on loopback: there it only answers requests for
  `localhost`/`127.0.0.1`/`[::1]`, so a web page cannot reach it through DNS
  rebinding. On other addresses it answers to IP addresses, the machine's
  names and the certificate host names; add a reverse proxy's name with
  `allowed_hosts = ["audit.example.com"]` under `[web]`.
- The MCP endpoint refuses plain HTTP unless the web UI listens on loopback
  only.
