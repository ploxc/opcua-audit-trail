# Certificates

Secure OPC UA connections need trust in three places. The gateway follows
standard OPC UA trust handling, in its `pki/` directory; the **Certificates**
and **Targets** pages do all of it with buttons.

1. **Gateway → PLC.** The gateway must trust the PLC's certificate. On the
   first secure connection it lands in `pki/rejected/`. Trust it on the
   **Targets** page (**Trust…**, which shows its thumbprint first) or move it
   to `pki/trusted/`.
2. **PLC → gateway.** The PLC must trust the gateway's certificate
   (`pki/own/cert.der`; **Certificates → Download**). Import it into the PLC's
   trust list; many servers keep refused certificates in a `rejected` folder,
   and moving it to `trusted` does it. The PLC should trust **only** the
   gateway, so no client can bypass it.
3. **Client → gateway.** Unknown client certificates land in `pki/rejected/`
   and are recorded as `certificate_rejected`. **Certificates → Trust**
   allows that client.

Step 2 can only be checked after step 1: until the gateway trusts the PLC,
the target shows **Target not trusted**; then **Refuses the gateway** until
the PLC trusts the gateway.

## The gateway certificate

- **Download** as .der or .pem, **Import** one issued by your plant CA, or
  **Regenerate** it. After regenerating or importing, every PLC must trust
  the new one.
- The host names and IP addresses clients use to reach the gateway go into
  it (Settings, Gateway certificate); they are used the next time it is
  generated.
- This certificate is for OPC UA only; the web UI has its own (see
  [HTTPS](https.md)).
