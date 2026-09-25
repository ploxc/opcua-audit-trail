// Certificates page: the gateway's own certificate (download, import,
// regenerate), certificates waiting for a decision, and trusted ones.

import { html, when } from "../html.js";
import { del, post } from "../api.js";
import { dialog, formData, menuButton, readFile, toast } from "../components.js";
import { time } from "../format.js";
import { can, load, renderPage, state } from "../state.js";

// One certificate in a table, with its buttons.
function certRow(c, actions) {
  return html`<tr>
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

export function certificatesView() {
  const c = state.certificates;
  if (!c) return html`<p class="muted">Loading…</p>`;
  const admin = can("admin");
  return html`
    <div class="page-head">
      <div class="inline">${menuButton}<h1>Certificates</h1></div>
    </div>
    <div class="card">
      <div class="card-head">
        <h2>Gateway certificate</h2>
        <div class="inline">
          <a class="button small" href="/api/certificates/own/cert.pem">Download (.pem)</a>
          <a class="button small" href="/api/certificates/own/cert.der">Download (.der)</a>
          ${when(
            admin,
            html`<button class="small" data-action="show-import">Import…</button>
              <button class="small danger" data-action="regenerate">Regenerate</button>`,
          )}
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
          </dl>`
          : html`<p class="muted">No certificate.</p>`
      }
      <p class="hint">
        Clients trust this certificate to connect securely; each PLC must trust it too, and ideally
        nothing else.
      </p>
      <p class="hint">
        It is also the web UI's HTTPS certificate, unless another one is configured
        (<span class="mono">tls_certificate</span>). It is self-signed, so there is no separate
        root CA: trust this certificate itself. macOS: open the .pem, then in Keychain Access set
        it to <i>Always Trust</i>. Windows: import it into <i>Trusted Root Certification
        Authorities</i>. AI assistants (Node): <span class="mono">NODE_EXTRA_CA_CERTS=/path/to/opcua-audit-gateway.pem</span>.
        After regenerating the certificate, trust the new one.
      </p>
      ${when(state.showImport, importForm)}
    </div>
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
          when(
            admin,
            html`<button class="small primary" data-action="trust-cert" data-thumb="${x.thumbprint}">
                Trust
              </button>
              <button class="small danger" data-action="delete-cert" data-thumb="${x.thumbprint}">
                Delete
              </button>`,
          ),
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
          when(
            admin,
            html`<button class="small danger" data-action="untrust-cert" data-thumb="${x.thumbprint}">
              Revoke trust
            </button>`,
          ),
        "No trusted certificates yet.",
      )}
    </div>`;
}

// Installing a certificate and key made elsewhere.
const importForm = () => html`<form data-form="import" class="mt">
  <div class="form-grid">
    <div>
      <label>Certificate (DER or PEM)</label>
      <input type="file" name="certificate" required>
    </div>
    <div>
      <label>Private key (PEM)</label>
      <input type="file" name="private_key" required>
    </div>
    <div class="inline">
      <button class="primary" type="submit">Install</button>
      <button type="button" data-action="hide-import">Cancel</button>
    </div>
  </div>
  <p class="hint">All targets restart with the new certificate. PLCs and clients must trust it.</p>
</form>`;

export const actions = {
  async "trust-cert"(el) {
    await post(`/certificates/rejected/${el.dataset.thumb}/trust`);
    toast("Certificate trusted");
    await load();
  },
  async "delete-cert"(el) {
    await del(`/certificates/rejected/${el.dataset.thumb}`);
    await load();
  },
  async "untrust-cert"(el) {
    const confirmed = await dialog({
      title: "Revoke trust?",
      body:
        "Applications using this certificate can no longer connect securely; " +
        "their connections are closed.",
      confirm: "Revoke",
      danger: true,
    });
    if (!confirmed) return;
    await post(`/certificates/trusted/${el.dataset.thumb}/untrust`);
    await load();
  },
  "show-import"() {
    state.showImport = true;
    renderPage();
  },
  "hide-import"() {
    state.showImport = false;
    renderPage();
  },
  async regenerate() {
    const confirmed = await dialog({
      title: "Generate a new gateway certificate?",
      body:
        "Every PLC and client must trust the new one. " +
        "All targets restart, which disconnects their clients.",
      confirm: "Generate",
      danger: true,
    });
    if (!confirmed) return;
    await post("/certificates/own/regenerate");
    toast("New certificate generated");
    await load();
  },
};

export const forms = {
  /** Installs the imported certificate and key (sent as base64). */
  async import(form) {
    const cert = await readFile(form.certificate.files[0]);
    const key = await readFile(form.private_key.files[0]);
    await post("/certificates/own", { certificate: cert, private_key: key });
    state.showImport = false;
    toast("Certificate installed");
    await load();
  },
};
