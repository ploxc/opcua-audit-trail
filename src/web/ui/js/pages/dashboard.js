// Dashboard page: warnings, key figures, one card per target with its
// connected clients, the audit export state and the latest changes.

import { html, when } from "../html.js";
import { get } from "../api.js";
import { menuButton, stateBadge } from "../components.js";
import { CHANGE_EVENTS, clientUrl, since } from "../format.js";
import { can, state } from "../state.js";
import { auditTable } from "./audit.js";

export function dashboardView() {
  const s = state.status;
  if (!s) return html`<p class="muted">Loading…</p>`;
  const targets = s.targets;
  const up = targets.filter((t) => t.status?.state === "available").length;
  const clients = targets.reduce((n, t) => n + t.clients.length, 0);
  const recent = state.dashboardChanges || [];
  return html`
    <div class="page-head">
      <div class="inline">${menuButton}<h1>Dashboard</h1></div>
      <span class="muted small">Gateway ${s.version} · updates every 5 s</span>
    </div>
    ${alerts(s)}
    <div class="stats">
      <div class="stat">
        <div class="label">Targets reachable</div>
        <div class="value ${up < targets.length ? "bad" : ""}">${up} / ${targets.length}</div>
      </div>
      <div class="stat">
        <div class="label">Connected clients</div>
        <div class="value">${clients}</div>
      </div>
      <div class="stat">
        <div class="label">Changes today</div>
        <div class="value">${state.changesToday ?? "…"}</div>
      </div>
      <div class="stat">
        <div class="label">Audit mode</div>
        <div class="value small">${s.fail_mode === "closed" ? "Fail-closed" : "Fail-open"}</div>
        <div class="muted small">
          retention ${s.retention_days ? s.retention_days + " days" : "forever"}
        </div>
      </div>
    </div>
    ${when(
      !targets.length,
      html`<div class="card">
        <h2>No targets yet</h2>
        <p class="muted">
          A target is an OPC UA server (usually a PLC) that clients reach through the gateway.
        </p>
        ${when(can("admin"), html`<a class="button primary" href="#/targets">Add a target</a>`)}
      </div>`,
    )}
    ${targets.map((t) => targetCard(t))}
    ${when(s.exports?.length, () => exportCard(s.exports))}
    <div class="card">
      <div class="card-head">
        <h2>Latest changes</h2>
        <a href="#/audit" class="small">Full audit trail</a>
      </div>
      ${auditTable(recent, { compact: true })}
    </div>`;
}

// Problems that need attention: failing exports, lost events, certificates
// waiting for a decision.
function alerts(s) {
  return html`${when(
    s.exports?.some((e) => e.last_error),
    html`<div class="alert warn">
        Audit export is failing; records wait in the local store and are sent once the destination
        is back.
      </div>`,
  )}
    ${s.exports
      ?.filter((e) => e.gap)
      .map((e) => html`<div class="alert bad">Export to ${e.name}: ${e.gap}</div>`)}
    ${when(
      s.lost_audit_events > 0,
      html`<div class="alert bad">
        ${s.lost_audit_events} audit events could not be stored. Check the disk of the audit
        database.
      </div>`,
    )}
    ${when(
      s.rejected_certificates > 0 && can("admin"),
      html`<div class="alert warn">
        ${s.rejected_certificates} certificate(s) are waiting for a decision.
        <a href="#/certificates">Review</a>
      </div>`,
    )}`;
}

// One target: where clients connect, the server behind it, and its clients.
function targetCard(t) {
  const st = t.status || {};
  const clientRow = (c) => html`<tr>
    <td class="mono nowrap">${c.remote_addr}</td>
    <td>
      ${c.application_name || c.application_uri || html`<span class="muted">discovery only</span>`}
    </td>
    <td>${c.user || ""}</td>
    <td class="nowrap">${c.security_policy} <span class="muted">${c.security_mode}</span></td>
    <td class="nowrap">${since(c.connected_at)}</td>
  </tr>`;
  return html`<div class="card">
    <div class="card-head">
      <div class="inline"><h2>${t.name}</h2>${stateBadge(st.state)}</div>
      <span class="muted small">checked ${since(st.last_check)}</span>
    </div>
    <dl class="kv">
      <dt>Clients connect to</dt>
      <dd class="mono">${clientUrl(t.listen)}</dd>
      <dt>Target server</dt>
      <dd class="mono">${t.endpoint_url}</dd>
      ${when(
        st.endpoints?.length,
        html`<dt>Server</dt>
          <dd>
            ${st.endpoints?.[0]?.server_application_name}
            <span class="muted">${st.endpoints?.[0]?.server_application_uri}</span>
          </dd>`,
      )}
      ${when(st.last_error, html`<dt>Error</dt><dd class="small">${st.last_error}</dd>`)}
    </dl>
    <h3 class="mt">Connected clients</h3>
    ${
      t.clients.length
        ? html`<div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Address</th>
                <th>Application</th>
                <th>User</th>
                <th>Security</th>
                <th>Since</th>
              </tr>
            </thead>
            <tbody>${t.clients.map(clientRow)}</tbody>
          </table>
        </div>`
        : html`<p class="muted small">No clients connected.</p>`
    }
  </div>`;
}

// Where copies of the audit trail go, and how far each one is.
function exportCard(exports) {
  const row = (e) => html`<tr>
    <td>${e.destination}</td>
    <td>
      ${
        e.last_error
          ? html`<span class="badge bad" title="${e.last_error}">Failing</span>
            <div class="small muted">${e.last_error}</div>`
          : html`<span class="badge ok">OK</span>`
      }
    </td>
    <td class="num">#${e.exported_seq}</td>
    <td class="num">${e.pending}</td>
    <td class="small">${since(e.last_success) || "—"}</td>
  </tr>`;
  return html`<div class="card">
    <div class="card-head">
      <h2>Audit export</h2>
      <span class="muted small">copies outside the gateway anchor the hash chain</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Destination</th>
            <th>State</th>
            <th>Exported up to</th>
            <th>Waiting</th>
            <th>Last delivery</th>
          </tr>
        </thead>
        <tbody>${exports.map(row)}</tbody>
      </table>
    </div>
  </div>`;
}

/** Loads the status, the latest changes and the number of changes today. */
export async function refreshDashboard() {
  state.status = await get("/status");
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const [changes, writesToday, callsToday] = await Promise.all([
    get("/audit?limit=200"),
    get(`/audit?kind=write&limit=1000&since=${encodeURIComponent(today.toISOString())}`),
    get(`/audit?kind=call&limit=1000&since=${encodeURIComponent(today.toISOString())}`),
  ]);
  // The API filters on one kind at a time; the change kinds are picked here.
  state.dashboardChanges = changes.filter((r) => CHANGE_EVENTS.has(r.event.type)).slice(0, 10);
  const n = writesToday.length + callsToday.length;
  state.changesToday = n >= 1000 ? "1000+" : n;
}
