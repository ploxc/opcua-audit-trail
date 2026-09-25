// Settings page: the audit trail (retention, fail mode, old values, summary
// interval), the export to QuestDB, the gateway certificate's host names,
// and read-only information about the web UI and files.

import { flag, html, when } from "../html.js";
import { get, post, put } from "../api.js";
import { dialog, formData, menuButton, toast } from "../components.js";
import { can, renderPage, state } from "../state.js";
import { time } from "../format.js";

// How an export destination is doing, from the last /status answer.
function exportState(name) {
  const e = (state.status?.exports || []).find((x) => x.name === name);
  if (!e) return "";
  const kind = e.last_error || e.gap ? "bad" : e.pending > 0 ? "warn" : "ok";
  const text = e.last_error
    ? `Failing: ${e.last_error}`
    : e.gap
      ? `Gap: ${e.gap}`
      : e.pending > 0
        ? `${e.pending} records waiting`
        : "Up to date";
  return html`<div class="alert ${kind} small">${text}</div>`;
}

/**
 * A password or token field. The server never sends a secret back: when one
 * is set, the field is empty with a placeholder, and a checkbox removes it.
 */
function secretField(prefix, name, label, isSet, off) {
  return html`<div>
    <label>${label}</label>
    <input
      name="${prefix}_${name}"
      type="password"
      autocomplete="new-password"
      placeholder="${isSet ? "•••••• (unchanged)" : ""}"
      ${off}
    >
    ${when(
      isSet,
      html`<label class="inline small">
        <input type="checkbox" name="${prefix}_${name}_clear" ${off}> remove
      </label>`,
    )}
  </div>`;
}

export function settingsView() {
  const st = state.settings;
  const head = html`<div class="page-head">
    <div class="inline">${menuButton}<h1>Settings</h1></div>
  </div>`;
  if (!st) return html`${head}<p class="muted">Loading…</p>`;
  // Only admins can change settings; others see them disabled.
  const edit = can("admin");
  const off = flag(!edit, "disabled");
  const save = when(
    edit,
    html`<div class="actions mt"><button class="primary" type="submit">Save</button></div>`,
  );
  return html`${head}
    <p class="section-note">
      Saved in <span class="mono">${st.config_file}</span> and applied at once, without
      disconnecting clients. ${edit ? "" : "Only administrators can change settings."} Settings per
      target (security, summarised nodes) are on the <a href="#/targets">Targets</a> page.
    </p>
    <div class="settings-grid">
      ${auditCard(st.audit, off, save)}
      ${exportCard(st.export.questdb, off, save)}
      ${gatewayCard(st, off, save)}
      ${mcpCard(st.mcp, off, save)}
      ${webCard(st)}
    </div>`;
}

// ---------- the cards ----------

function auditCard(a, off, save) {
  return html`<form class="card" data-form="settings-audit">
    <h2>Audit trail</h2>
    <div class="setting">
      <label class="title" for="retention">Keep records for</label>
      <div class="inline-input">
        <input
          id="retention"
          name="retention_days"
          type="number"
          min="0"
          max="36500"
          required
          value="${a.retention_days}"
          ${off}
        >
        days
      </div>
      <p class="help">
        Older records are deleted for good; the rest of the chain stays verifiable. 0 keeps
        everything.
      </p>
    </div>
    <div class="setting">
      <span class="title">When the audit trail cannot be written</span>
      <fieldset class="choice">
        <label>
          <input
            type="radio"
            name="fail_mode"
            value="open"
            ${flag(a.fail_mode === "open", "checked")}
            ${off}
          >
          Keep forwarding writes
          <span class="muted small">
            Clients are never held up; records that could not be stored are counted and reported.
          </span>
        </label>
        <label>
          <input
            type="radio"
            name="fail_mode"
            value="closed"
            ${flag(a.fail_mode === "closed", "checked")}
            ${off}
          >
          Reject writes
          <span class="muted small">
            A write only reaches the PLC after its record is stored. Safer, but the audit trail must
            never fail.
          </span>
        </label>
      </fieldset>
    </div>
    <div class="setting">
      <label class="inline">
        <input type="checkbox" name="record_old_value" ${flag(a.record_old_value, "checked")} ${off}>
        Record the old value of each write
      </label>
      <p class="help">
        The value is read just before the write, so the trail shows old → new. One extra read per
        write on the PLC.
      </p>
    </div>
    <div class="setting">
      <label class="title" for="summary">Summarised nodes: one record every</label>
      <div class="inline-input">
        <input
          id="summary"
          name="summary_minutes"
          type="number"
          min="1"
          max="1440"
          required
          value="${Math.max(1, Math.round(a.ignored_summary_secs / 60))}"
          ${off}
        >
        minutes
      </div>
      <p class="help">
        For nodes a target summarises (like a life bit): one record per node per interval instead
        of one per write.
      </p>
    </div>
    <dl class="kv small readonly-kv">
      <dt>Database</dt>
      <dd class="mono">${a.database}</dd>
    </dl>
    ${save}
  </form>`;
}

// `q` is the QuestDB export, or null when there is none.
function exportCard(q, off, save) {
  return html`<form class="card" data-form="settings-export">
    <h2>Export</h2>
    <p class="section-note">
      A copy of every record outside the gateway, for long-term storage and as proof that the local
      trail was not rewritten. A new destination receives the whole trail. A new scheme, host or
      port forgets the stored password and token: enter them again.
    </p>
    <div class="setting">
      <label class="inline title">
        <input type="checkbox" name="questdb_on" ${flag(q, "checked")} ${off}> QuestDB
      </label>
      ${exportState("questdb")}
      <div class="form-grid">
        <div>
          <label>URL</label>
          <input name="q_url" placeholder="http://questdb:9000" value="${q?.url || ""}" ${off}>
        </div>
        <div>
          <label>Table</label>
          <input name="q_table" value="${q?.table || "opcua_audit"}" ${off}>
        </div>
        <div>
          <label>User name</label>
          <input name="q_username" autocomplete="off" value="${q?.username || ""}" ${off}>
        </div>
        ${secretField("q", "password", "Password", q?.password_set, off)}
        ${secretField("q", "token", "Or a token", q?.token_set, off)}
        <div>
          <label>Every (s)</label>
          <input name="q_interval" type="number" min="1" value="${q?.interval_secs || 5}" ${off}>
        </div>
      </div>
      <div class="mt-xs">
        <label>CA certificate for https with a private CA (PEM; empty: public roots)</label>
        <textarea
          name="q_ca_pem"
          rows="6"
          class="mono small"
          spellcheck="false"
          placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----"
          ${off}
        >${q?.ca_pem || ""}</textarea>
      </div>
    </div>
    ${save}
  </form>`;
}

function gatewayCard(st, off, save) {
  return html`<form class="card" data-form="settings-gateway">
    <h2>Gateway certificate</h2>
    <dl class="kv small readonly-kv">
      <dt>Application name</dt>
      <dd>${st.gateway.application_name}</dd>
      <dt>Application URI</dt>
      <dd class="mono">${st.gateway.application_uri}</dd>
    </dl>
    <div class="setting">
      <label class="title" for="hostnames">Host names and IP addresses</label>
      <input
        id="hostnames"
        name="certificate_hostnames"
        placeholder="gateway.local, 192.168.0.20"
        value="${st.gateway.certificate_hostnames.join(", ")}"
        ${off}
      >
      <p class="help">
        How clients reach the gateway, put in its certificate. Used when the certificate is
        generated: after a change, generate a new one on the
        <a href="#/certificates">Certificates</a> page.
      </p>
    </div>
    ${save}
  </form>`;
}

/** What a token can be allowed to change, for people: a name and what it covers. */
export const SCOPE_LABELS = {
  targets: ["Targets", "add, change and remove PLCs; summarised nodes"],
  certificates: ["Certificates", "trust and untrust OPC UA certificates"],
  settings: ["Settings", "audit trail, export, certificate host names"],
  alarms: ["Alarms", "acknowledge errors and warnings, after showing them to you"],
};

/** The role a token's user needs for a scope (as mcp_scope_role in config.rs). */
export const scopeRole = (scope) => (scope === "alarms" ? "operator" : "admin");

function mcpCard(m, off, save) {
  return html`<form class="card" data-form="settings-mcp">
    <h2>AI assistants (MCP)</h2>
    <div class="setting">
      <label class="inline">
        <input type="checkbox" name="enabled" ${flag(m.enabled, "checked")} ${off}>
        MCP endpoint on
      </label>
      <p class="help">
        Lets an AI assistant such as Claude read the audit trail and the gateway status with an
        <a href="#/account">API token</a>, which each user creates on their Account page. Every
        question is recorded in the trail. Off: the endpoint
        answers nothing and tokens stop working.
      </p>
      <p class="help">
        What an assistant may change (targets, certificates, …) is chosen per token when an
        administrator creates it. Assistants never write to a PLC, and never change these MCP
        settings or API tokens.
      </p>
      ${when(
        !m.transport_ok,
        html`<div class="alert bad small">
          The web UI uses plain HTTP on a network address, so the endpoint refuses requests: the
          token would cross the network unencrypted. Set <span class="mono">tls = true</span>
          under <span class="mono">[web]</span> and restart.
        </div>`,
      )}
    </div>
    ${save}
  </form>`;
}

// Settings that only apply at start-up, so they are shown, not edited.
function webCard(st) {
  const https = st.web.tls
    ? st.web.tls_certificate
      ? html`on, <span class="mono">${st.web.tls_certificate}</span>`
      : "on, with its own self-signed certificate"
    : "off";
  return html`<div class="card">
    <h2>Web UI and files</h2>
    <dl class="kv small readonly-kv">
      <dt>Listens on</dt>
      <dd class="mono">${st.web.listen}</dd>
      <dt>HTTPS</dt>
      <dd>
        ${https}
        ${when(st.web.tls_env, () => html`<span class="muted small">(set by
          <span class="mono">${st.web.tls_env}</span>)</span>`)}
      </dd>
      <dt>Certificates</dt>
      <dd class="mono">${st.gateway.pki_dir}</dd>
      <dt>Data</dt>
      <dd class="mono">${st.gateway.data_dir}</dd>
    </dl>
    <p class="help small muted">
      These take effect only when the gateway starts, and a wrong value can lock you out: change
      them in the <span class="mono">[web]</span> and <span class="mono">[gateway]</span> sections
      of the config file, then restart the gateway.
    </p>
    ${when(st.web.certificate && !st.web.tls_certificate, () => webCertificate(st.web.certificate))}
  </div>`;
}

// The web UI's own HTTPS certificate: separate from the gateway's OPC UA
// certificate, so renewing it never concerns a PLC.
function webCertificate(c) {
  return html`<div class="setting">
    <div class="card-head">
      <span class="title">HTTPS certificate</span>
      <div class="inline">
        <a class="button small" href="/api/web-certificate/cert.pem">Download (.pem)</a>
        <a class="button small" href="/api/web-certificate/cert.der">Download (.der)</a>
        ${when(
          can("admin"),
          html`<button class="small" data-action="regenerate-web-certificate">Regenerate</button>`,
        )}
      </div>
    </div>
    <dl class="kv small readonly-kv">
      <dt>Subject</dt>
      <dd>${c.subject}</dd>
      <dt>Thumbprint</dt>
      <dd class="mono">${c.thumbprint}</dd>
      <dt>Valid</dt>
      <dd>${time(c.not_before)} – ${time(c.not_after)}</dd>
    </dl>
    <p class="help small">
      Self-signed, so there is no separate root CA: trust this certificate itself. macOS: open the
      .pem, then in Keychain Access set it to <i>Always Trust</i>. Windows: import it into
      <i>Trusted Root Certification Authorities</i>. AI assistants (Node):
      <span class="mono">NODE_EXTRA_CA_CERTS=/path/to/opcua-audit-gateway-web.pem</span>. It
      names localhost, this machine and the host names under Gateway certificate; after changing
      those, regenerate it and restart the gateway. This is not the certificate PLCs trust
      (that is on the <a href="#/certificates">Certificates</a> page).
    </p>
  </div>`;
}

// ---------- forms ----------

export const actions = {
  async "regenerate-web-certificate"() {
    const ok = await dialog({
      title: "New HTTPS certificate?",
      confirm: "Regenerate",
      body:
        "The web UI uses it after the gateway restarts. Browsers and AI assistants that " +
        "trusted the current one must trust the new one. PLCs are not affected.",
    });
    if (!ok) return;
    await post("/web-certificate/regenerate");
    toast("New certificate: restart the gateway to use it");
    state.settings = await get("/settings");
    renderPage();
  },
};

export const forms = {
  /** Saves the audit settings; shortening retention or failing closed asks first. */
  async "settings-audit"(form) {
    const d = formData(form);
    const body = {
      retention_days: Number(d.retention_days),
      fail_mode: d.fail_mode,
      record_old_value: form.elements.record_old_value.checked,
      ignored_summary_secs: Number(d.summary_minutes) * 60,
    };
    const old = state.settings.audit;
    const shorter =
      body.retention_days > 0 &&
      (old.retention_days === 0 || body.retention_days < old.retention_days);
    if (shorter) {
      const confirmed = await dialog({
        title: `Keep records for ${body.retention_days} days?`,
        confirm: "Save",
        danger: true,
        body: html`<p>
            Records older than ${body.retention_days} days are deleted for good, starting right
            away.
          </p>
          <p class="muted small">Exported copies (QuestDB) are not affected.</p>`,
      });
      if (!confirmed) return;
    }
    if (body.fail_mode === "closed" && old.fail_mode !== "closed") {
      const confirmed = await dialog({
        title: "Reject writes when the trail cannot be written?",
        confirm: "Save",
        body:
          "From now on, a write only reaches the PLC after its record is stored. " +
          "If the audit trail fails (e.g. a full disk), clients can no longer write.",
      });
      if (!confirmed) return;
    }
    await put("/settings/audit", body);
    toast("Audit trail settings saved");
    state.settings = await get("/settings");
    state.status = await get("/status");
    renderPage();
  },

  /**
   * Saves the export settings. A secret is only sent when typed (or removed),
   * so saving other fields keeps it.
   */
  async "settings-export"(form) {
    const d = formData(form);
    const on = (name) => form.elements[name].checked;
    const secret = (body, name, prefix) => {
      if (d[`${prefix}_${name}`]) body[name] = d[`${prefix}_${name}`];
      else if (form.elements[`${prefix}_${name}_clear`]?.checked) body[name] = "";
    };
    const body = {};
    if (on("questdb_on")) {
      body.questdb = {
        url: d.q_url,
        table: d.q_table || "opcua_audit",
        username: d.q_username || null,
        ca_pem: d.q_ca_pem || "",
        interval_secs: Number(d.q_interval) || 5,
      };
      secret(body.questdb, "password", "q");
      secret(body.questdb, "token", "q");
    }
    await put("/settings/export", body);
    toast("Export settings saved");
    state.settings = await get("/settings");
    state.status = await get("/status");
    renderPage();
  },

  async "settings-mcp"(form) {
    const enabled = form.elements.enabled.checked;
    await put("/settings/mcp", { enabled });
    toast(enabled ? "MCP endpoint on" : "MCP endpoint off");
    state.settings = await get("/settings");
    renderPage();
  },

  async "settings-gateway"(form) {
    const names = formData(form)
      .certificate_hostnames.split(/[\s,;]+/)
      .filter(Boolean);
    await put("/settings/gateway", { certificate_hostnames: names });
    toast("Saved. Generate a new certificate to use it (Certificates page).");
    state.settings = await get("/settings");
    renderPage();
  },
};
