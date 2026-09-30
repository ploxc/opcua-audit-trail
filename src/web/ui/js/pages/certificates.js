// Certificates page, everything about certificates in one place: the
// gateway's OPC UA certificate with the host names it must carry, the web
// UI's HTTPS certificate, certificates waiting for a decision, and trusted
// ones.

import { html, safe, submit, useState } from "../vdom.js";
import { del, post, put } from "../api.js";
import { MenuButton, dialog, formData, readFile, toast } from "../components.js";
import { time } from "../format.js";
import { can, load, state } from "../state.js";

// One certificate in a table, with its buttons.
function certRow(c, actions) {
  return html`<tr key=${c.thumbprint}>
    <td>${c.subject}<div class="mono muted small">${c.thumbprint}</div></td>
    <td class="nowrap small">${time(c.not_after)}</td>
    <td class="actions-cell">${actions}</td>
  </tr>`;
}

// A table of certificates, or `empty` when there are none.
const certTable = (certs, actions, empty) =>
  certs.length
    ? html`<div class="table-wrap">
        <table class="middle">
          <thead>
            <tr>
              <th>Certificate</th>
              <th>Expires</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            ${certs.map((x) => certRow(x, actions(x)))}
          </tbody>
        </table>
      </div>`
    : html`<p class="muted small">${empty}</p>`;

const trust = (thumb) =>
  safe(async () => {
    await post(`/certificates/rejected/${thumb}/trust`);
    toast("Certificate trusted");
    await load();
  });

const remove = (thumb) =>
  safe(async () => {
    await del(`/certificates/rejected/${thumb}`);
    await load();
  });

const untrust = (thumb) =>
  safe(async () => {
    const confirmed = await dialog({
      title: "Revoke trust?",
      body:
        "Applications using this certificate can no longer connect securely; " +
        "their connections are closed.",
      confirm: "Revoke",
      danger: true,
    });
    if (!confirmed) return;
    await post(`/certificates/trusted/${thumb}/untrust`);
    await load();
  });

/** Asks, then makes a new gateway certificate with the current host names. */
async function regenerateOwn() {
  const confirmed = await dialog({
    title: "Generate a new gateway certificate?",
    body:
      "It names the host names below. Every PLC and client must trust the new one. " +
      "All targets restart, which disconnects their clients.",
    confirm: "Generate",
    danger: true,
  });
  if (!confirmed) return;
  await post("/certificates/own/regenerate");
  toast("New certificate generated: let every PLC trust it");
  await load();
}
const regenerate = safe(regenerateOwn);

/** Saves the host names; offers a new certificate when the current one lacks them. */
const saveHostnames = submit(async (form) => {
  const names = formData(form)
    .certificate_hostnames.split(/[\s,;]+/)
    .filter(Boolean);
  await put("/settings/gateway", { certificate_hostnames: names });
  await load();
  form.reset();
  if (state.certificates.own?.missing_hostnames?.length) await regenerateOwn();
  else toast("Saved");
});

const regenerateWebCertificate = safe(async () => {
  const ok = await dialog({
    title: "New HTTPS certificate?",
    confirm: "Regenerate",
    body:
      "It names the host names above. The web UI uses it after the gateway restarts. " +
      "Browsers and AI assistants that trusted the current one must trust the new one. " +
      "PLCs are not affected.",
  });
  if (!ok) return;
  await post("/web-certificate/regenerate");
  toast("New certificate: restart the gateway to use it");
  await load();
});

/** Stops the gateway; its service manager (systemd) starts it again. */
async function restartGateway(https) {
  const ok = await dialog({
    title: "Restart the gateway?",
    confirm: "Restart",
    danger: true,
    body:
      "Clients are disconnected for a few seconds and reconnect. Everyone logs in again." +
      (https ? " The web UI then answers on https:// only." : ""),
  });
  if (!ok) return;
  await post("/restart");
  toast("Restarting…");
  // Back when it is up; with HTTPS on the new address.
  const scheme = https ? "https:" : location.protocol;
  setTimeout(() => location.replace(`${scheme}//${location.host}/`), 8000);
}

const turnOnHttps = (web) =>
  safe(async () => {
    const ok = await dialog({
      title: "Turn on HTTPS?",
      confirm: "Turn on",
      body:
        "Written to the config file; it applies after a restart. The web UI then answers on " +
        "https:// only, with a self-signed certificate of its own: browsers warn until it is " +
        "trusted (download it here afterwards).",
    });
    if (!ok) return;
    await post("/settings/web/https");
    await load();
    if (web.can_restart) await restartGateway(true);
    else toast("Saved: restart the gateway to switch to HTTPS");
  });

// Names the configured host names a certificate does not carry yet.
const missing = (c, fix) =>
  c?.missing_hostnames?.length > 0 &&
  html`<div class="alert warn small">
    Not in this certificate yet:${" "}
    <span class="mono">${c.missing_hostnames.join(", ")}</span>. Clients that use these names refuse
    it. ${fix}
  </div>`;

export function CertificatesPage() {
  const [importing, setImporting] = useState(false);
  const c = state.certificates;
  const st = state.settings;
  if (!c || !st) return html`<p class="muted">Loading…</p>`;
  const admin = can("admin");
  return html`
    <div class="page-head">
      <div class="inline"><${MenuButton} /><h1>Certificates</h1></div>
    </div>
    <div class="card">
      <div class="card-head">
        <h2>Gateway certificate (OPC UA)</h2>
        <div class="inline">
          <a class="button small" href="/api/certificates/own/cert.pem">Download (.pem)</a>
          <a class="button small" href="/api/certificates/own/cert.der">Download (.der)</a>
          ${
            admin &&
            html`<button class="small" onClick=${() => setImporting(true)}>Import…</button>
            <button class="small danger" onClick=${regenerate}>Regenerate</button>`
          }
        </div>
      </div>
      ${
        c.own
          ? html`<dl class="kv">
            <dt>Subject</dt>
            <dd>${c.own.subject}</dd>
            <dt>Thumbprint</dt>
            <dd class="mono">${c.own.thumbprint}</dd>
            <dt>Valid</dt>
            <dd>${time(c.own.not_before)} – ${time(c.own.not_after)}</dd>
            <dt>Application URI</dt>
            <dd class="mono">${st.gateway.application_uri}</dd>
          </dl>`
          : html`<p class="muted">No certificate.</p>`
      }
      ${missing(c.own, admin ? "Regenerate to add them." : "An administrator can regenerate it.")}
      <form class="setting" onSubmit=${saveHostnames}>
        <label class="title" for="hostnames">Host names and IP addresses</label>
        <div class="inline">
          <input
            id="hostnames"
            name="certificate_hostnames"
            placeholder="gateway.local, 192.168.0.20"
            defaultValue=${st.gateway.certificate_hostnames.join(", ")}
            disabled=${!admin}
          />
          ${admin && html`<button class="primary" type="submit">Save</button>`}
        </div>
        <p class="help">
          How clients reach the gateway. Both certificates on this page name them; a client refuses a
          certificate that lacks the name it connected with.
        </p>
      </form>
      <p class="hint">
        Clients trust this certificate to connect securely; each PLC must trust it too, and ideally
        nothing else.
      </p>
      ${importing && html`<${ImportForm} close=${() => setImporting(false)} />`}
    </div>
    ${webCard(st.web, admin)}
    <div class="card">
      <div class="card-head">
        <h2>Waiting for a decision</h2>
        <span class="muted small">${c.rejected.length} rejected</span>
      </div>
      <p class="section-note">
        Unknown clients and servers land here. Trust a certificate to let that application connect.
      </p>
      ${certTable(
        c.rejected,
        (x) =>
          admin &&
          html`<button class="small primary" onClick=${trust(x.thumbprint)}>Trust</button>${" "}
            <button class="small danger" onClick=${remove(x.thumbprint)}>Delete</button>`,
        "Nothing waiting.",
      )}
    </div>
    <div class="card">
      <div class="card-head">
        <h2>Trusted</h2>
        <span class="muted small">${c.trusted.length} certificates</span>
      </div>
      ${certTable(
        c.trusted,
        (x) =>
          admin &&
          html`<button class="small danger" onClick=${untrust(x.thumbprint)}>
            Revoke trust
          </button>`,
        "No trusted certificates yet.",
      )}
    </div>`;
}

// The web UI's own HTTPS certificate: separate from the OPC UA one, so
// renewing it never concerns a PLC.
function webCard(web, admin) {
  const cert = !web.tls_certificate && web.certificate;
  return html`<div class="card">
    <div class="card-head">
      <h2>Web UI certificate (HTTPS)</h2>
      ${
        cert &&
        html`<div class="inline">
          <a class="button small" href="/api/web-certificate/cert.pem">Download (.pem)</a>
          <a class="button small" href="/api/web-certificate/cert.der">Download (.der)</a>
          ${
            admin &&
            html`<button class="small" onClick=${regenerateWebCertificate}>Regenerate</button>`
          }
        </div>`
      }
    </div>
    <dl class="kv">
      <dt>HTTPS</dt>
      <dd>${httpsState(web, admin)}</dd>
      ${
        web.tls_certificate
          ? html`<dt>Certificate</dt>
              <dd class="mono">${web.tls_certificate}</dd>`
          : cert &&
            html`<dt>Subject</dt>
              <dd>${cert.subject}</dd>
              <dt>Thumbprint</dt>
              <dd class="mono">${cert.thumbprint}</dd>
              <dt>Valid</dt>
              <dd>${time(cert.not_before)} – ${time(cert.not_after)}</dd>`
      }
    </dl>
    ${cert && missing(cert, admin ? "Regenerate it, then restart the gateway." : "")}
    ${
      cert &&
      html`<p class="hint">
        Self-signed, so there is no separate root CA: trust this certificate itself. macOS: open the
        .pem, then in Keychain Access set it to <i>Always Trust</i>. Windows: import it into${" "}
        <i>Trusted Root Certification Authorities</i>. AI assistants (Node):${" "}
        <span class="mono">NODE_EXTRA_CA_CERTS=/path/to/opcua-audit-gateway-web.pem</span>.
      </p>`
    }
  </div>`;
}

// Whether HTTPS is on, and the button to turn it on or apply it.
function httpsState(web, admin) {
  if (web.tls_env) {
    return html`${web.tls ? "on" : "off"}${" "}
      <span class="muted small">(set by <span class="mono">${web.tls_env}</span>)</span>`;
  }
  if (web.tls && web.tls_running) return "on";
  if (web.tls) {
    return html`on after a restart${" "}
      ${
        admin && web.can_restart
          ? html`<button class="small" onClick=${safe(() => restartGateway(true))}>
              Restart now
            </button>`
          : html`<span class="muted small">(restart the gateway to apply it)</span>`
      }`;
  }
  return html`off${" "}
    ${admin && html`<button class="small" onClick=${turnOnHttps(web)}>Turn on…</button>`}`;
}

// Installing a certificate and key made elsewhere.
function ImportForm({ close }) {
  /** Installs the imported certificate and key (sent as base64). */
  const install = submit(async (form) => {
    const cert = await readFile(form.certificate.files[0]);
    const key = await readFile(form.private_key.files[0]);
    await post("/certificates/own", { certificate: cert, private_key: key });
    close();
    toast("Certificate installed");
    await load();
  });
  return html`<form class="mt" onSubmit=${install}>
    <div class="form-grid">
      <div>
        <label>Certificate (DER or PEM)</label>
        <input type="file" name="certificate" required />
      </div>
      <div>
        <label>Private key (PEM)</label>
        <input type="file" name="private_key" required />
      </div>
      <div class="inline">
        <button class="primary" type="submit">Install</button>
        <button type="button" onClick=${close}>Cancel</button>
      </div>
    </div>
    <p class="hint">All targets restart with the new certificate. PLCs and clients must trust it.</p>
  </form>`;
}
