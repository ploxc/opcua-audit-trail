// OPC UA Audit Gateway web UI. No build step, no dependencies.
//
// Rendering uses the `html` tagged template: every interpolated value is
// escaped unless it is itself `html` output, so server data can never inject
// markup. Events are handled by delegation on `data-action` attributes
// (the Content-Security-Policy forbids inline handlers).

// ---------- templating ----------

class Html {
  constructor(s) { this.s = s; }
  toString() { return this.s; }
}
const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ESC[c]);
const fmt = (v) => (v instanceof Html ? v.s : Array.isArray(v) ? v.map(fmt).join("") : esc(v));
function html(strings, ...values) {
  let out = "";
  strings.forEach((s, i) => { out += s + (i < values.length ? fmt(values[i]) : ""); });
  return new Html(out);
}
// `then` may be a function, so branches that dereference optional data are
// only evaluated when the condition holds.
const when = (cond, then, otherwise = "") =>
  cond ? (typeof then === "function" ? then() : then) : otherwise;

// ---------- icons ----------

// Material icons (filled, Apache 2.0), the set Modbux uses.
const ICON_PATHS = {
  dashboard: '<path d="M3 13h8V3H3v10zm0 8h8v-6H3v6zm10 0h8V11h-8v10zm0-18v6h8V3h-8z"/>',
  audit: '<path d="M19.5 3.5 18 2l-1.5 1.5L15 2l-1.5 1.5L12 2l-1.5 1.5L9 2 7.5 3.5 6 2v14H3v3c0 1.66 1.34 3 3 3h12c1.66 0 3-1.34 3-3V2l-1.5 1.5zM19 19c0 .55-.45 1-1 1s-1-.45-1-1v-3H8V5h11v14z"/><path d="M9 7h6v2H9zm7 0h2v2h-2zm-7 3h6v2H9zm7 0h2v2h-2z"/>',
  targets: '<path d="M13 22h8v-7h-3v-4h-5V9h3V2H8v7h3v2H6v4H3v7h8v-7H8v-2h8v2h-3z"/>',
  certificates: '<path d="M12 1 3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm-2 16-4-4 1.41-1.41L10 14.17l6.59-6.59L18 9l-8 8z"/>',
  browser: '<path d="M22 11V3h-7v3H9V3H2v8h7V8h2v10h4v3h7v-8h-7v3h-2V8h2v3z"/>',
  users: '<path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z"/>',
  account: '<circle cx="10" cy="8" r="4"/><path d="M10.67 13.02c-.22-.01-.44-.02-.67-.02-2.42 0-4.68.67-6.61 1.82-.88.52-1.39 1.5-1.39 2.53V20h9.26a6.963 6.963 0 0 1-.59-6.98zM20.75 16c0-.22-.03-.42-.06-.63l1.14-1.01-1-1.73-1.45.49c-.32-.27-.68-.48-1.08-.63L18 11h-2l-.3 1.49c-.4.15-.76.36-1.08.63l-1.45-.49-1 1.73 1.14 1.01c-.03.21-.06.41-.06.63s.03.42.06.63l-1.14 1.01 1 1.73 1.45-.49c.32.27.68.48 1.08.63L16 21h2l.3-1.49c.4-.15.76-.36 1.08-.63l1.45.49 1-1.73-1.14-1.01c.03-.21.06-.41.06-.63zM17 18c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/>',
  dark: '<path d="M12 3a9 9 0 1 0 9 9c0-.46-.04-.92-.1-1.36a5.389 5.389 0 0 1-4.4 2.26 5.403 5.403 0 0 1-3.14-9.8c-.44-.06-.9-.1-1.36-.1z"/>',
  light: '<path d="M12 7c-2.76 0-5 2.24-5 5s2.24 5 5 5 5-2.24 5-5-2.24-5-5-5zM2 13h2c.55 0 1-.45 1-1s-.45-1-1-1H2c-.55 0-1 .45-1 1s.45 1 1 1zm18 0h2c.55 0 1-.45 1-1s-.45-1-1-1h-2c-.55 0-1 .45-1 1s.45 1 1 1zM11 2v2c0 .55.45 1 1 1s1-.45 1-1V2c0-.55-.45-1-1-1s-1 .45-1 1zm0 18v2c0 .55.45 1 1 1s1-.45 1-1v-2c0-.55-.45-1-1-1s-1 .45-1 1zM5.99 4.58a.996.996 0 0 0-1.41 0 .996.996 0 0 0 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0s.39-1.03 0-1.41L5.99 4.58zm12.37 12.37a.996.996 0 0 0-1.41 0 .996.996 0 0 0 0 1.41l1.06 1.06c.39.39 1.03.39 1.41 0a.996.996 0 0 0 0-1.41l-1.06-1.06zm1.06-10.96a.996.996 0 0 0 0-1.41.996.996 0 0 0-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06zM7.05 18.36a.996.996 0 0 0 0-1.41.996.996 0 0 0-1.41 0l-1.06 1.06c-.39.39-.39 1.03 0 1.41s1.03.39 1.41 0l1.06-1.06z"/>',
  menu: '<path d="M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z"/>',
  logout: '<path d="m17 7-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"/>',
};
const icon = (name, cls = "") =>
  new Html(`<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICON_PATHS[name]}</svg>`);

const LOGO_PATH = "m 107.60293,0.64220653 c -35.769829,0 -65.039135,29.45982647 -65.039135,65.27483247 V 94.927484 L 30.45287,82.757639 7.3579379,105.74314 32.676186,131.18345 7.3579379,156.5017 30.214018,179.35778 55.477552,154.09425 80.619032,179.35778 103.71607,156.37227 75.147546,127.66697 V 65.917039 c 0,-18.289883 14.380372,-32.691083 32.455384,-32.691083 18.07499,0 32.45538,14.4012 32.45538,32.691083 0,18.275197 -14.35769,32.665875 -32.41224,32.68897 l -16.215592,-0.09996 -0.124161,32.583751 16.296613,0.1 v 0.002 c 35.7698,0 65.03913,-29.45983 65.03913,-65.274832 0,-35.815005 -29.26933,-65.27483198 -65.03913,-65.27483198 z";
const logo = (cls = "") =>
  new Html(`<svg class="logo ${cls}" viewBox="0 0 180 180" aria-hidden="true"><circle class="dot" cx="107.599" cy="65.927" r="16.292"/><path class="mark" d="${LOGO_PATH}"/></svg>`);

const menuButton = new Html(`<button class="icon-button menu-button" data-action="menu" aria-label="Menu">${icon("menu").s}</button>`);
const THEME_KEY = "ploxc-color-mode";
// Both icons are rendered; the stylesheet shows the one for the other mode.
const themeButton = () => html`<button class="icon-button" data-action="theme" title="Light or dark mode" aria-label="Toggle light or dark mode">${icon("light", "icon-sun")}${icon("dark", "icon-moon")}</button>`;
const ploxcLink = () => html`<a class="ploxc-link" href="https://ploxc.com" target="_blank" rel="noopener">${logo()}Ploxc</a>`;

// ---------- API ----------

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, path, body) {
  const options = {
    method,
    headers: { "X-Requested-With": "opcua-audit-gateway" },
    credentials: "same-origin",
  };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch("/api" + path, options);
  if (response.status === 401 && path !== "/login") {
    state.user = null;
    render();
    throw new ApiError(401, "Not logged in");
  }
  const text = await response.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!response.ok) {
    throw new ApiError(response.status, (data && data.error) || response.statusText);
  }
  return data;
}
const get = (path) => api("GET", path);
const post = (path, body = {}) => api("POST", path, body);
const put = (path, body) => api("PUT", path, body);
const del = (path) => api("DELETE", path);

// ---------- state ----------

const ROLE_LEVEL = { auditor: 0, operator: 1, admin: 2 };
const state = {
  user: undefined,
  status: null,
  audit: { rows: [], filters: {}, selected: null, olderAvailable: false, live: false },
  targets: { editing: null, discovery: {} },
  certificates: null,
  browser: { target: "", connection: null, tree: {}, expanded: new Set(), selected: null, attributes: [], watch: [], values: {} },
  users: [],
  version: "",
};
const can = (role) => state.user && ROLE_LEVEL[state.user.role] >= ROLE_LEVEL[role];

// ---------- helpers ----------

function toast(message, kind = "") {
  let host = document.querySelector(".toast-host");
  if (!host) {
    host = document.createElement("div");
    host.className = "toast-host";
    document.body.append(host);
  }
  const t = document.createElement("div");
  t.className = "toast " + kind;
  t.textContent = message;
  host.append(t);
  setTimeout(() => t.remove(), kind === "bad" ? 7000 : 3500);
}
const fail = (e) => { if (e.status !== 401) toast(e.message, "bad"); };

// OPC UA timestamps carry up to 9 fraction digits; Date parses 3.
const time = (iso) => (iso ? new Date(String(iso).replace(/(\.\d{3})\d+/, "$1")).toLocaleString() : "");
const since = (iso) => {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.round(s)} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
};
const clientUrl = (listen) => {
  const [host, port] = [listen.slice(0, listen.lastIndexOf(":")), listen.slice(listen.lastIndexOf(":") + 1)];
  const shown = host === "0.0.0.0" || host === "[::]" ? location.hostname : host;
  return `opc.tcp://${shown}:${port}`;
};
const valueText = (v) => {
  if (!v) return "";
  const x = v.value;
  if (x === null || x === undefined) return "null";
  if (typeof x === "object") return JSON.stringify(x);
  return String(x);
};
const statusBadge = (status) => {
  if (!status) return "";
  const kind = status.startsWith("Good") ? "ok" : status.startsWith("Uncertain") ? "warn" : "bad";
  return html`<span class="badge plain ${kind}">${status}</span>`;
};
const stateBadge = (s) => {
  const map = { available: ["ok", "Connected"], unavailable: ["bad", "Unreachable"], unknown: ["neutral", "Checking…"] };
  const [kind, label] = map[s] || map.unknown;
  return html`<span class="badge ${kind}">${label}</span>`;
};
const userLabel = (client) => {
  const u = client && client.user;
  if (!u) return "";
  if (u.kind === "anonymous") return "anonymous";
  if (u.kind === "user_name") return u.name;
  if (u.kind === "certificate") return u.subject;
  return u.kind;
};
const EVENT_LABELS = {
  write: "Write", call: "Method call", history_update: "History update", node_management: "Node management",
  change_intent: "Change intent", client_connected: "Client connected", client_disconnected: "Client disconnected",
  secure_channel_opened: "Secure channel", session_created: "Session created", session_activated: "Session activated",
  session_closed: "Session closed", authentication_failed: "Login failed", certificate_rejected: "Certificate rejected",
  upstream_available: "Target reachable", upstream_unavailable: "Target unreachable", gateway_started: "Gateway started",
  gateway_stopped: "Gateway stopped", config_changed: "Configuration changed", ui_login: "UI login",
  ui_login_failed: "UI login failed", retention_pruned: "Retention", events_lost: "Events lost",
  upstream_endpoints_changed: "Target security changed", subscriptions_transferred: "Subscriptions transferred",
  connections_refused: "Connections refused",
};
const CHANGE_EVENTS = new Set(["write", "call", "history_update", "node_management", "subscriptions_transferred"]);
const eventBadge = (type) => {
  const kind = CHANGE_EVENTS.has(type) ? "accent"
    : /failed|rejected|unavailable|lost|changed$/.test(type) && type !== "config_changed" ? "bad"
    : type === "change_intent" ? "warn" : "neutral";
  return html`<span class="badge plain ${kind}">${EVENT_LABELS[type] || type}</span>`;
};
function eventSummary(e) {
  switch (e.type) {
    case "write":
      return html`<div>${e.display_name || e.node_id}${when(e.display_name, html` <span class="muted mono">${e.node_id}</span>`)}${when(e.attribute !== "Value", html` <span class="muted">(${e.attribute})</span>`)}</div>
        <div class="change">${when(e.old_value, html`<span class="old">${valueText(e.old_value)}</span><span class="arrow">→</span>`)}${valueText(e.new_value)} <span class="muted">${e.new_value.data_type}</span>${when(e.written_status, html` <span class="muted">status ${e.written_status}</span>`)}${when(e.source_timestamp, html` <span class="muted">source time ${e.source_timestamp}</span>`)}</div>`;
    case "call":
      return html`<div>${e.display_name || e.method_id} <span class="muted mono">${e.object_id}</span></div>
        <div class="change">(${e.input_arguments.map(valueText).join(", ")})</div>`;
    case "history_update": return html`${e.details} on <span class="mono">${e.node_id}</span>`;
    case "node_management": return html`${e.service} <span class="mono">${e.node_id}</span>`;
    case "change_intent": return html`${e.service}: <span class="mono">${e.node_ids.join(", ")}</span>`;
    case "secure_channel_opened": return `${e.security_policy} / ${e.security_mode}`;
    case "session_created": return e.session_name;
    case "authentication_failed": return e.status;
    case "certificate_rejected": return html`${e.subject} <span class="muted">${e.reason}</span>`;
    case "client_disconnected": return e.reason;
    case "upstream_available": return `${e.endpoint_url} (${e.endpoints} endpoints)`;
    case "upstream_endpoints_changed": return html`<div>${e.endpoint_url}</div><div class="small muted">before: ${e.before.join("; ")}</div><div class="small">now: ${e.after.join("; ")}</div>`;
    case "subscriptions_transferred": return `subscriptions ${e.subscription_ids.join(", ")}`;
    case "connections_refused": return `${e.count} from ${e.remote_addr}: ${e.reason}`;
    case "upstream_unavailable": return e.reason;
    case "config_changed": return html`<b>${e.by}</b>: ${e.summary}`;
    case "ui_login": case "ui_login_failed": return e.user;
    case "retention_pruned": return `${e.deleted} records removed`;
    case "events_lost": return `${e.count} events could not be stored`;
    case "gateway_started": return `version ${e.version}`;
    default: return "";
  }
}

// ---------- routing ----------

const PAGES = [
  { id: "dashboard", label: "Dashboard", role: "auditor", icon: "dashboard" },
  { id: "audit", label: "Audit trail", role: "auditor", icon: "audit" },
  { id: "targets", label: "Targets", role: "auditor", icon: "targets" },
  { id: "certificates", label: "Certificates", role: "auditor", icon: "certificates" },
  { id: "browser", label: "Browser", role: "operator", icon: "browser" },
  { id: "users", label: "Users", role: "admin", icon: "users" },
  { id: "account", label: "Account", role: "auditor", icon: "account", hidden: true },
];
const currentPage = () => {
  const id = location.hash.replace(/^#\/?/, "").split("?")[0] || "dashboard";
  const page = PAGES.find((p) => p.id === id);
  return page && can(page.role) ? page : PAGES[0];
};

// ---------- rendering ----------

const app = document.getElementById("app");
let refreshTimer = null;

function render() {
  if (state.user === undefined) return;
  if (!state.user) {
    app.innerHTML = loginView().s;
    app.querySelector("input[name=username]")?.focus();
    return;
  }
  const page = currentPage();
  const rejected = state.status?.rejected_certificates || 0;
  app.innerHTML = html`<div class="shell">
    <aside class="sidebar">
      <div class="brand">${logo()}<div>Audit Gateway<small>OPC UA</small></div></div>
      <nav class="nav">
        ${PAGES.filter((p) => !p.hidden && can(p.role)).map((p) => html`<a href="#/${p.id}" class="${p.id === page.id ? "active" : ""}">
          ${icon(p.icon)}${p.label}
          ${when(p.id === "certificates" && rejected, html`<span class="count" title="Certificates waiting for a decision">${rejected}</span>`)}
        </a>`)}
      </nav>
      <div class="sidebar-foot">
        <div class="user-row">
          <div class="who">${state.user.username}<small>${state.user.role}</small></div>
          <div class="tools">
            <a href="#/account" class="button icon-button" title="Account" aria-label="Account">${icon("account")}</a>
            ${themeButton()}
            <button class="icon-button" data-action="logout" title="Log out" aria-label="Log out">${icon("logout")}</button>
          </div>
        </div>
        <div class="made-by">${ploxcLink()}<span class="version">${state.version}</span></div>
      </div>
    </aside>
    <main class="main" id="page">${pageView(page)}</main>
  </div>`.s;
}

function renderPage() {
  const el = document.getElementById("page");
  if (!el) return render();
  // A periodic refresh must not wipe what the user is typing: keep the
  // values of the form that has focus, and the focus itself.
  const active = document.activeElement;
  const typing = active && el.contains(active) && /^(INPUT|SELECT|TEXTAREA)$/.test(active.tagName) && active.type !== "file";
  const form = typing ? active.closest("form[data-form]") : null;
  const kept = form ? [...form.elements].filter((e) => e.name && e.type !== "file").map((e) => [e.name, e.type === "checkbox" ? e.checked : e.value]) : [];
  const focusName = typing ? active.name : null;
  el.innerHTML = pageView(currentPage()).s;
  if (form) {
    const again = el.querySelector(`form[data-form="${form.dataset.form}"]`);
    for (const [name, value] of kept) {
      const input = again?.elements.namedItem(name);
      if (!input || input instanceof RadioNodeList) continue;
      if (input.type === "checkbox") input.checked = value; else input.value = value;
    }
    again?.elements.namedItem(focusName)?.focus?.();
  }
}

function pageView(page) {
  switch (page.id) {
    case "dashboard": return dashboardView();
    case "audit": return auditView();
    case "targets": return targetsView();
    case "certificates": return certificatesView();
    case "browser": return browserView();
    case "users": return usersView();
    case "account": return accountView();
  }
  return html``;
}

// ---------- login ----------

function loginView() {
  return html`<div class="login">${logo("login-backdrop")}<form class="card" data-form="login">
    <div class="brand">${logo()}<div>Audit Gateway<small>OPC UA</small></div></div>
    <div class="field"><label for="u">User name</label><input id="u" name="username" autocomplete="username" required></div>
    <div class="field"><label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required></div>
    <div id="login-error" class="alert bad hidden"></div>
    <button class="primary" type="submit">Sign in</button>
  </form>
  <div class="login-foot">${ploxcLink()}<span class="version">${state.version}</span></div>
  <div class="login-theme">${themeButton()}</div></div>`;
}

// ---------- dashboard ----------

function dashboardView() {
  const s = state.status;
  if (!s) return html`<p class="muted">Loading…</p>`;
  const targets = s.targets;
  const up = targets.filter((t) => t.status?.state === "available").length;
  const clients = targets.reduce((n, t) => n + t.clients.length, 0);
  const recent = state.dashboardChanges || [];
  return html`
    <div class="page-head"><div class="inline">${menuButton}<h1>Dashboard</h1></div>
      <span class="muted small">Gateway ${s.version} · updates every 5 s</span></div>
    ${when(s.exports?.some((e) => e.last_error), html`<div class="alert warn">Audit export is failing; records wait in the local store and are sent once the destination is back.</div>`)}
    ${when(s.lost_audit_events > 0, html`<div class="alert bad">${s.lost_audit_events} audit events could not be stored. Check the disk of the audit database.</div>`)}
    ${when(s.rejected_certificates > 0 && can("admin"), html`<div class="alert warn">${s.rejected_certificates} certificate(s) are waiting for a decision. <a href="#/certificates">Review</a></div>`)}
    <div class="stats">
      <div class="stat"><div class="label">Targets reachable</div><div class="value ${up < targets.length ? "bad" : ""}">${up} / ${targets.length}</div></div>
      <div class="stat"><div class="label">Connected clients</div><div class="value">${clients}</div></div>
      <div class="stat"><div class="label">Changes today</div><div class="value">${state.changesToday ?? "…"}</div></div>
      <div class="stat"><div class="label">Audit mode</div><div class="value small">${s.fail_mode === "closed" ? "Fail-closed" : "Fail-open"}</div><div class="muted small">retention ${s.retention_days ? s.retention_days + " days" : "forever"}</div></div>
    </div>
    ${when(!targets.length, html`<div class="card"><h2>No targets yet</h2><p class="muted">A target is an OPC UA server (usually a PLC) that clients reach through the gateway.</p>${when(can("admin"), html`<a class="button primary" href="#/targets">Add a target</a>`)}</div>`)}
    ${targets.map((t) => targetCard(t))}
    ${when(s.exports?.length, () => html`<div class="card"><div class="card-head"><h2>Audit export</h2><span class="muted small">copies outside the gateway anchor the hash chain</span></div>
      <div class="table-wrap"><table><thead><tr><th>Destination</th><th>State</th><th>Exported up to</th><th>Waiting</th><th>Last delivery</th></tr></thead>
      <tbody>${s.exports.map((e) => html`<tr><td>${e.destination}</td>
        <td>${e.last_error ? html`<span class="badge bad" title="${e.last_error}">Failing</span><div class="small muted">${e.last_error}</div>` : html`<span class="badge ok">OK</span>`}</td>
        <td class="num">#${e.exported_seq}</td><td class="num">${e.pending}</td><td class="small">${since(e.last_success) || "—"}</td></tr>`)}</tbody></table></div></div>`)}
    <div class="card">
      <div class="card-head"><h2>Latest changes</h2><a href="#/audit" class="small">Full audit trail</a></div>
      ${auditTable(recent, { compact: true })}
    </div>`;
}

function targetCard(t) {
  const st = t.status || {};
  return html`<div class="card">
    <div class="card-head">
      <div class="inline"><h2>${t.name}</h2>${stateBadge(st.state)}</div>
      <span class="muted small">checked ${since(st.last_check)}</span>
    </div>
    <dl class="kv">
      <dt>Clients connect to</dt><dd class="mono">${clientUrl(t.listen)}</dd>
      <dt>Target server</dt><dd class="mono">${t.endpoint_url}</dd>
      ${when(st.endpoints?.length, html`<dt>Server</dt><dd>${st.endpoints?.[0]?.server_application_name} <span class="muted">${st.endpoints?.[0]?.server_application_uri}</span></dd>`)}
      ${when(st.last_error, html`<dt>Error</dt><dd class="small">${st.last_error}</dd>`)}
    </dl>
    <h3 class="mt">Connected clients</h3>
    ${t.clients.length ? html`<div class="table-wrap"><table>
      <thead><tr><th>Address</th><th>Application</th><th>User</th><th>Security</th><th>Since</th></tr></thead>
      <tbody>${t.clients.map((c) => html`<tr>
        <td class="mono nowrap">${c.remote_addr}</td>
        <td>${c.application_name || c.application_uri || html`<span class="muted">discovery only</span>`}</td>
        <td>${c.user || ""}</td>
        <td class="nowrap">${c.security_policy} <span class="muted">${c.security_mode}</span></td>
        <td class="nowrap">${since(c.connected_at)}</td></tr>`)}</tbody></table></div>`
      : html`<p class="muted small">No clients connected.</p>`}
  </div>`;
}

async function refreshDashboard() {
  state.status = await get("/status");
  const today = new Date(); today.setHours(0, 0, 0, 0);
  const [changes, writesToday, callsToday] = await Promise.all([
    get("/audit?limit=200"),
    get(`/audit?kind=write&limit=1000&since=${encodeURIComponent(today.toISOString())}`),
    get(`/audit?kind=call&limit=1000&since=${encodeURIComponent(today.toISOString())}`),
  ]);
  state.dashboardChanges = changes.filter((r) => CHANGE_EVENTS.has(r.event.type)).slice(0, 10);
  const n = writesToday.length + callsToday.length;
  state.changesToday = n >= 1000 ? "1000+" : n;
}

// ---------- audit ----------

function auditTable(rows, { compact = false, selectable = false } = {}) {
  if (!rows.length) return html`<p class="empty">No records.</p>`;
  return html`<div class="table-wrap"><table>
    <thead><tr>${when(!compact, html`<th>#</th>`)}<th>Time</th><th>Target</th><th>Event</th><th>Client / user</th><th>Details</th><th>Result</th></tr></thead>
    <tbody>${rows.map((r) => html`<tr class="${selectable ? "clickable" : ""} ${state.audit.selected === r.seq ? "selected" : ""}" ${new Html(selectable ? `data-action="select-record" data-seq="${r.seq}"` : "")}>
      ${when(!compact, html`<td class="num muted">${r.seq}</td>`)}
      <td class="nowrap">${time(r.ts)}</td>
      <td>${r.target || ""}</td>
      <td>${eventBadge(r.event.type)}</td>
      <td>${r.client ? html`<div>${userLabel(r.client)}</div><div class="muted small">${r.client.application_name || ""} ${r.client.remote_addr}</div>` : ""}</td>
      <td>${eventSummary(r.event)}</td>
      <td>${statusBadge(r.event.status)}</td>
    </tr>`)}</tbody></table></div>`;
}

function auditQuery(extra = {}) {
  const f = { ...state.audit.filters, ...extra };
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) {
    if (v === "" || v === undefined || v === null) continue;
    params.set(k, (k === "since" || k === "until") ? new Date(v).toISOString() : v);
  }
  return params.toString();
}

function auditView() {
  const a = state.audit;
  const f = a.filters;
  const targets = state.status?.targets || [];
  const selected = a.rows.find((r) => r.seq === a.selected);
  return html`
    <div class="page-head"><div class="inline">${menuButton}<h1>Audit trail</h1></div>
      <div class="actions">
        <label class="inline small"><input type="checkbox" name="live" data-action="live" ${new Html(a.live ? "checked" : "")}> Live</label>
        <button data-action="verify">Verify integrity</button>
        <a class="button" href="/api/audit.csv?${auditQuery({ limit: "" })}">Export CSV</a>
      </div></div>
    ${when(a.verify, () => a.verify.error
      ? html`<div class="alert bad"><b>Integrity check failed.</b> ${a.verify.error}</div>`
      : html`<div class="alert ok">All ${a.verify.records} records (#${a.verify.first_seq}–#${a.verify.last_seq}) are intact. Chain head <span class="mono">${a.verify.head_hash.slice(0, 16)}…</span></div>`)}
    <form class="card filters" data-form="audit-filter">
      <div><label>Target</label><select name="target"><option value="">All</option>${targets.map((t) => html`<option ${new Html(f.target === t.name ? "selected" : "")}>${t.name}</option>`)}</select></div>
      <div><label>Event</label><select name="kind"><option value="">All</option>${Object.entries(EVENT_LABELS).map(([k, v]) => html`<option value="${k}" ${new Html(f.kind === k ? "selected" : "")}>${v}</option>`)}</select></div>
      <div><label>User</label><input name="user" value="${f.user || ""}" placeholder="exact name"></div>
      <div><label>Node</label><input name="node_id" value="${f.node_id || ""}" placeholder="ns=3;s=…"></div>
      <div><label>From</label><input type="datetime-local" name="since" value="${f.since || ""}"></div>
      <div><label>Until</label><input type="datetime-local" name="until" value="${f.until || ""}"></div>
      <div class="inline"><button class="primary" type="submit">Filter</button><button type="button" data-action="clear-filter">Clear</button></div>
    </form>
    <div class="${selected ? "split" : ""}">
      <div class="card">${auditTable(a.rows, { selectable: true })}
        ${when(a.olderAvailable, html`<div class="inline"><button data-action="older">Older records</button></div>`)}</div>
      ${when(selected, () => html`<div class="card detail"><div class="card-head"><h2>Record #${selected.seq}</h2><button class="small" data-action="close-record">Close</button></div>
        <dl class="kv"><dt>Time</dt><dd>${time(selected.ts)}</dd><dt>Hash</dt><dd class="mono small">${selected.hash}</dd></dl>
        <h3 class="mt">Record</h3><pre class="json">${JSON.stringify({ target: selected.target, client: selected.client, event: selected.event }, null, 2)}</pre></div>`)}
    </div>`;
}

async function loadAudit(append = false) {
  const a = state.audit;
  const extra = { limit: 100 };
  if (append && a.rows.length) extra.before_seq = a.rows[a.rows.length - 1].seq;
  const rows = await get("/audit?" + auditQuery(extra));
  a.rows = append ? a.rows.concat(rows) : rows;
  a.olderAvailable = rows.length === 100;
}

// ---------- targets ----------

function endpointsTable(endpoints, trustedThumbs) {
  if (!endpoints?.length) return html`<p class="muted small">No endpoints.</p>`;
  const cert = endpoints.find((e) => e.server_certificate)?.server_certificate;
  return html`
    ${when(cert, html`<dl class="kv small"><dt>Server certificate</dt><dd>${cert?.subject} ${trustedThumbs.has(cert?.thumbprint)
      ? html`<span class="badge ok">trusted</span>` : html`<span class="badge warn">not trusted</span>`}<div class="mono muted">${cert?.thumbprint}</div></dd></dl>`)}
    <div class="table-wrap"><table><thead><tr><th>Security policy</th><th>Mode</th><th>Level</th><th>Logins</th></tr></thead>
    <tbody>${endpoints.map((e) => html`<tr><td>${e.security_policy}</td><td>${e.security_mode}</td><td class="num">${e.security_level}</td>
      <td>${e.user_tokens.map((u) => html`<span class="badge plain ${u.token_type === "Certificate" || u.token_type === "IssuedToken" ? "neutral" : "accent"}" title="${u.token_type === "Certificate" || u.token_type === "IssuedToken" ? "Cannot be relayed by the gateway" : ""}">${u.token_type}</span> `)}</td></tr>`)}</tbody></table></div>`;
}

function targetsView() {
  const s = state.status;
  if (!s) return html`<p class="muted">Loading…</p>`;
  const editing = state.targets.editing;
  const trusted = new Set((state.certificates?.trusted || []).map((c) => c.thumbprint));
  return html`
    <div class="page-head"><div class="inline">${menuButton}<h1>Targets</h1></div>
      ${when(can("admin") && !editing, html`<div class="actions"><button class="primary" data-action="new-target">Add target</button></div>`)}</div>
    <p class="section-note">Each target is an OPC UA server behind the gateway. Clients connect to the gateway's listen address; the gateway follows the target's security settings.</p>
    ${when(editing, () => targetForm(editing))}
    ${s.targets.map((t) => html`<div class="card">
      <div class="card-head"><div class="inline"><h2>${t.name}</h2>${stateBadge(t.status?.state)}</div>
        <div class="inline">
          ${when(can("operator"), html`<button class="small" data-action="discover-target" data-name="${t.name}">Discover</button>`)}
          ${when(can("admin"), html`<button class="small" data-action="trust-server" data-name="${t.name}">Trust server certificate</button>
            <button class="small" data-action="edit-target" data-name="${t.name}">Edit</button>
            <button class="small danger" data-action="delete-target" data-name="${t.name}">Delete</button>`)}
        </div></div>
      <dl class="kv"><dt>Clients connect to</dt><dd class="mono">${clientUrl(t.listen)} <span class="muted">(listening on ${t.listen})</span></dd>
        <dt>Target server</dt><dd class="mono">${t.endpoint_url}</dd>
        <dt>Discovery every</dt><dd>${t.discovery_interval_secs} s</dd>
        <dt>Minimum security</dt><dd>${MIN_SECURITY[t.min_security || "none"]}</dd>
        ${when(t.status?.last_error, html`<dt>Error</dt><dd class="small">${t.status?.last_error}</dd>`)}</dl>
      <h3 class="mt">Endpoints offered to clients</h3>
      ${endpointsTable(state.targets.discovery[t.name] || t.status?.endpoints, trusted)}
    </div>`)}`;
}

const MIN_SECURITY = { none: "Follow the target (incl. None)", sign: "Sign or better", sign_and_encrypt: "Sign & encrypt only" };

function targetForm(t) {
  const isNew = t.original === null;
  const trusted = new Set((state.certificates?.trusted || []).map((c) => c.thumbprint));
  return html`<form class="card" data-form="target">
    <h2>${isNew ? "Add target" : `Edit ${t.original}`}</h2>
    <div class="form-grid">
      <div><label>Name</label><input name="name" value="${t.name}" required pattern="[A-Za-z0-9._-]+" title="letters, digits, . _ -"></div>
      <div><label>Listen address (for clients)</label><input name="listen" value="${t.listen}" required placeholder="0.0.0.0:4841"></div>
      <div><label>Target endpoint URL</label><input name="endpoint_url" value="${t.endpoint_url}" required placeholder="opc.tcp://192.168.0.10:4840"></div>
      <div><label>Discovery interval (s)</label><input name="discovery_interval_secs" type="number" min="1" value="${t.discovery_interval_secs}"></div>
      <div><label>Minimum security</label><select name="min_security">${Object.entries(MIN_SECURITY).map(([k, v]) => html`<option value="${k}" ${new Html((t.min_security || "none") === k ? "selected" : "")}>${v}</option>`)}</select></div>
    </div>
    <p class="hint">On the PLC itself, use another port than the PLC's own server (e.g. 4841) and let the PLC's server accept only the gateway.</p>
    <div class="inline"><button class="primary" type="submit">${isNew ? "Add" : "Save"}</button>
      <button type="button" data-action="discover-url">Discover endpoints</button>
      <button type="button" data-action="cancel-target">Cancel</button></div>
    ${when(t.endpoints, () => html`<h3 class="mt">Endpoints of ${t.endpoint_url}</h3>${endpointsTable(t.endpoints, trusted)}`)}
  </form>`;
}

// ---------- certificates ----------

function certRow(c, actions) {
  return html`<tr><td>${c.subject}<div class="mono muted small">${c.thumbprint}</div></td>
    <td class="nowrap small">${time(c.not_after)}</td><td class="nowrap">${actions}</td></tr>`;
}

function certificatesView() {
  const c = state.certificates;
  if (!c) return html`<p class="muted">Loading…</p>`;
  const admin = can("admin");
  return html`
    <div class="page-head"><div class="inline">${menuButton}<h1>Certificates</h1></div></div>
    <div class="card"><div class="card-head"><h2>Gateway certificate</h2>
      <div class="inline"><a class="button small" href="/api/certificates/own/cert.der">Download</a>
      ${when(admin, html`<button class="small" data-action="show-import">Import…</button><button class="small danger" data-action="regenerate">Regenerate</button>`)}</div></div>
      ${c.own ? html`<dl class="kv"><dt>Subject</dt><dd>${c.own.subject}</dd><dt>Thumbprint</dt><dd class="mono">${c.own.thumbprint}</dd>
        <dt>Valid</dt><dd>${time(c.own.not_before)} – ${time(c.own.not_after)}</dd></dl>` : html`<p class="muted">No certificate.</p>`}
      <p class="hint">Clients trust this certificate to connect securely; each PLC must trust it too, and ideally nothing else.</p>
      ${when(state.showImport, html`<form data-form="import" class="mt"><div class="form-grid">
        <div><label>Certificate (DER or PEM)</label><input type="file" name="certificate" required></div>
        <div><label>Private key (PEM)</label><input type="file" name="private_key" required></div>
        <div class="inline"><button class="primary" type="submit">Install</button><button type="button" data-action="hide-import">Cancel</button></div></div>
        <p class="hint">All targets restart with the new certificate. PLCs and clients must trust it.</p></form>`)}
    </div>
    <div class="card"><div class="card-head"><h2>Waiting for a decision</h2><span class="muted small">${c.rejected.length} rejected</span></div>
      <p class="section-note">Unknown clients and servers land here. Trust a certificate to let that application connect.</p>
      ${c.rejected.length ? html`<div class="table-wrap"><table><thead><tr><th>Certificate</th><th>Expires</th><th></th></tr></thead><tbody>
        ${c.rejected.map((x) => certRow(x, when(admin, html`<button class="small primary" data-action="trust-cert" data-thumb="${x.thumbprint}">Trust</button>
          <button class="small danger" data-action="delete-cert" data-thumb="${x.thumbprint}">Delete</button>`)))}</tbody></table></div>`
        : html`<p class="muted small">Nothing waiting.</p>`}
    </div>
    <div class="card"><div class="card-head"><h2>Trusted</h2><span class="muted small">${c.trusted.length} certificates</span></div>
      ${c.trusted.length ? html`<div class="table-wrap"><table><thead><tr><th>Certificate</th><th>Expires</th><th></th></tr></thead><tbody>
        ${c.trusted.map((x) => certRow(x, when(admin, html`<button class="small danger" data-action="untrust-cert" data-thumb="${x.thumbprint}">Revoke trust</button>`)))}</tbody></table></div>`
        : html`<p class="muted small">No trusted certificates yet.</p>`}
    </div>`;
}

// ---------- browser ----------

function treeView(nodeId) {
  const children = state.browser.tree[nodeId];
  if (!children) return html``;
  return html`<ul>${children.map((c) => {
    const open = state.browser.expanded.has(c.node_id);
    const leafish = c.node_class === "Method";
    return html`<li><div class="node ${state.browser.selected === c.node_id ? "selected" : ""}" data-action="select-node" data-node="${c.node_id}">
      <span class="toggle" data-action="toggle-node" data-node="${c.node_id}">${leafish ? "" : open ? "▾" : "▸"}</span>
      <span>${c.display_name || c.browse_name}</span><span class="kind">${c.node_class}</span></div>
      ${when(open, () => treeView(c.node_id))}</li>`;
  })}</ul>`;
}

function browserView() {
  const b = state.browser;
  const targets = state.status?.targets || [];
  if (!b.connection) {
    return html`<div class="page-head"><div class="inline">${menuButton}<h1>Browser</h1></div></div>
      <form class="card" data-form="browser-connect"><h2>Connect to a target</h2>
      <p class="section-note">Opens a read-only session directly on the target, with the gateway's certificate. The login is only used for this session and never stored.</p>
      <div class="form-grid">
        <div><label>Target</label><select name="target">${targets.map((t) => html`<option ${new Html(b.target === t.name ? "selected" : "")}>${t.name}</option>`)}</select></div>
        <div><label>User name (empty = anonymous)</label><input name="username" autocomplete="off"></div>
        <div><label>Password</label><input name="password" type="password" autocomplete="off"></div>
        <div><button class="primary" type="submit" ${new Html(targets.length ? "" : "disabled")}>Connect</button></div>
      </div></form>`;
  }
  const watch = b.watch;
  return html`<div class="page-head"><div class="inline">${menuButton}<h1>Browser</h1>
      <span class="badge ok">${b.target}</span><span class="muted small">${b.connection.security_policy} / ${b.connection.security_mode} as ${b.connection.user}</span></div>
      <div class="actions"><button data-action="browser-disconnect">Disconnect</button></div></div>
    <div class="browser">
      <div class="card"><h2>Objects</h2><div class="tree">${treeView("root")}</div></div>
      <div>
        <div class="card"><div class="card-head"><h2>${b.selected ? "Attributes" : "Select a node"}</h2>
          ${when(b.selected && b.attributes.some((a) => a.attribute === "Value"), html`<button class="small" data-action="watch" data-node="${b.selected}">Watch value</button>`)}</div>
          ${when(b.selected, html`<div class="table-wrap"><table><tbody>${b.attributes.map((a) => html`<tr><th>${a.attribute}</th>
            <td class="mono">${attributeText(a)} <span class="muted">${a.value.data_type}</span></td></tr>`)}</tbody></table></div>`)}
        </div>
        <div class="card"><div class="card-head"><h2>Watch list</h2><span class="muted small">refreshes every second</span></div>
          ${watch.length ? html`<div class="table-wrap"><table><thead><tr><th>Node</th><th>Value</th><th>Status</th><th>Source time</th><th></th></tr></thead><tbody>
            ${watch.map((n) => { const v = b.values[n.node_id] || {}; return html`<tr><td>${n.name}<div class="mono muted small">${n.node_id}</div></td>
              <td class="mono">${valueText(v.value)}</td><td>${statusBadge(v.status)}</td><td class="nowrap small">${time(v.source_timestamp)}</td>
              <td><button class="small" data-action="unwatch" data-node="${n.node_id}">Remove</button></td></tr>`; })}</tbody></table></div>`
            : html`<p class="muted small">Select a variable and choose “Watch value”.</p>`}
        </div>
      </div>
    </div>`;
}

const NODE_CLASSES = { 1: "Object", 2: "Variable", 4: "Method", 8: "ObjectType", 16: "VariableType", 32: "ReferenceType", 64: "DataType", 128: "View" };
const ACCESS_BITS = ["CurrentRead", "CurrentWrite", "HistoryRead", "HistoryWrite", "SemanticChange", "StatusWrite", "TimestampWrite"];
function attributeText(a) {
  const v = a.value.value;
  if (a.attribute === "NodeClass") return NODE_CLASSES[v] || v;
  if (a.attribute === "AccessLevel" || a.attribute === "UserAccessLevel") {
    const names = ACCESS_BITS.filter((_, i) => v & (1 << i));
    return names.length ? names.join(", ") : "none";
  }
  return valueText(a.value);
}

async function browseInto(nodeId) {
  const b = state.browser;
  const query = nodeId === "root" ? "" : `?node=${encodeURIComponent(nodeId)}`;
  b.tree[nodeId] = await get(`/browser/${encodeURIComponent(b.target)}/browse${query}`);
}

// ---------- users & account ----------

function usersView() {
  return html`<div class="page-head"><div class="inline">${menuButton}<h1>Users</h1></div></div>
    <div class="card"><div class="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Created</th><th></th></tr></thead><tbody>
      ${state.users.map((u) => html`<tr><td>${u.username}</td>
        <td><select name="role-${u.username}" data-action="set-role" data-user="${u.username}">${["auditor", "operator", "admin"].map((r) => html`<option ${new Html(u.role === r ? "selected" : "")}>${r}</option>`)}</select></td>
        <td class="small nowrap">${time(u.created_at)}</td>
        <td class="nowrap"><button class="small" data-action="reset-password" data-user="${u.username}">Reset password</button>
          <button class="small danger" data-action="delete-user" data-user="${u.username}">Delete</button></td></tr>`)}
    </tbody></table></div></div>
    <form class="card" data-form="new-user"><h2>Add user</h2><div class="form-grid">
      <div><label>User name</label><input name="username" required></div>
      <div><label>Password (min. 8)</label><input name="password" type="password" minlength="8" required autocomplete="new-password"></div>
      <div><label>Role</label><select name="role"><option>auditor</option><option>operator</option><option>admin</option></select></div>
      <div><button class="primary" type="submit">Add</button></div></div>
      <p class="hint">Auditor: dashboard and audit trail. Operator: also the browser. Admin: also targets, certificates and users.</p></form>`;
}

function accountView() {
  return html`<div class="page-head"><div class="inline">${menuButton}<h1>Account</h1></div></div>
    <form class="card" data-form="password"><h2>Change password</h2><div class="form-grid">
      <div><label>Current password</label><input name="current" type="password" required autocomplete="current-password"></div>
      <div><label>New password (min. 8)</label><input name="new" type="password" minlength="8" required autocomplete="new-password"></div>
      <div><button class="primary" type="submit">Change</button></div></div></form>`;
}

// ---------- data loading per page ----------

async function load() {
  const page = currentPage();
  try {
    switch (page.id) {
      case "dashboard": await refreshDashboard(); break;
      case "audit": state.status ||= await get("/status"); await loadAudit(); break;
      case "targets": state.status = await get("/status"); state.certificates = await get("/certificates"); break;
      case "certificates": state.certificates = await get("/certificates"); state.status = await get("/status"); break;
      case "browser": state.status ||= await get("/status"); break;
      case "users": state.users = await get("/users"); break;
    }
  } catch (e) { fail(e); }
  renderPage();
  schedule(page.id);
}

function schedule(pageId) {
  clearInterval(refreshTimer);
  refreshTimer = null;
  const every = (ms, fn) => { refreshTimer = setInterval(async () => { try { await fn(); renderPage(); } catch (e) { fail(e); } }, ms); };
  if (pageId === "dashboard") every(5000, refreshDashboard);
  if (pageId === "audit" && state.audit.live) every(3000, () => loadAudit());
  if (pageId === "browser" && state.browser.connection && state.browser.watch.length) every(1000, pollWatch);
}

async function pollWatch() {
  const b = state.browser;
  const values = await post(`/browser/${encodeURIComponent(b.target)}/values`, { nodes: b.watch.map((w) => w.node_id) });
  for (const v of values) b.values[v.node_id] = v;
}

// ---------- events ----------

const formData = (form) => Object.fromEntries(new FormData(form).entries());
const readFile = (file) => new Promise((resolve, reject) => {
  const r = new FileReader();
  r.onload = () => resolve(r.result.split(",")[1]);
  r.onerror = reject;
  r.readAsDataURL(file);
});

const actions = {
  async logout() { await post("/logout"); state.user = null; render(); },
  theme() {
    // Like ploxc.com: follow the system until the user picks a mode.
    const root = document.documentElement;
    const dark = root.dataset.theme ? root.dataset.theme === "dark" : matchMedia("(prefers-color-scheme: dark)").matches;
    root.dataset.theme = dark ? "light" : "dark";
    try { localStorage.setItem(THEME_KEY, root.dataset.theme); } catch {}
  },
  menu() { document.querySelector(".shell")?.classList.toggle("nav-open"); },
  // audit
  "select-record"(el) { const seq = Number(el.dataset.seq); state.audit.selected = state.audit.selected === seq ? null : seq; renderPage(); },
  "close-record"() { state.audit.selected = null; renderPage(); },
  async older() { await loadAudit(true); renderPage(); },
  async verify() { state.audit.verify = await get("/audit/verify"); renderPage(); },
  async "clear-filter"() { state.audit.filters = {}; await loadAudit(); renderPage(); },
  live(el) { state.audit.live = el.checked; schedule("audit"); },
  // targets
  "new-target"() { state.targets.editing = { original: null, name: "", listen: "0.0.0.0:4841", endpoint_url: "opc.tcp://", discovery_interval_secs: 60, min_security: "none" }; renderPage(); },
  "edit-target"(el) {
    const t = state.status.targets.find((x) => x.name === el.dataset.name);
    state.targets.editing = { original: t.name, name: t.name, listen: t.listen, endpoint_url: t.endpoint_url, discovery_interval_secs: t.discovery_interval_secs, min_security: t.min_security || "none" };
    renderPage();
  },
  "cancel-target"() { state.targets.editing = null; renderPage(); },
  async "discover-url"(el) {
    const form = el.closest("form");
    Object.assign(state.targets.editing, formData(form));
    state.targets.editing.endpoints = await post("/discover", { endpoint_url: state.targets.editing.endpoint_url });
    renderPage();
  },
  async "discover-target"(el) { state.targets.discovery[el.dataset.name] = await post(`/targets/${encodeURIComponent(el.dataset.name)}/discover`); toast("Discovery done"); renderPage(); },
  async "trust-server"(el) {
    const cert = await post(`/targets/${encodeURIComponent(el.dataset.name)}/trust-server`);
    toast(`Trusted ${cert.subject}`);
    state.certificates = await get("/certificates");
    renderPage();
  },
  async "delete-target"(el) {
    if (!confirm(`Delete target ${el.dataset.name}? Its clients are disconnected.`)) return;
    await del(`/targets/${encodeURIComponent(el.dataset.name)}`);
    toast("Target deleted");
    await load();
  },
  // certificates
  async "trust-cert"(el) { await post(`/certificates/rejected/${el.dataset.thumb}/trust`); toast("Certificate trusted"); await load(); },
  async "delete-cert"(el) { await del(`/certificates/rejected/${el.dataset.thumb}`); await load(); },
  async "untrust-cert"(el) {
    if (!confirm("Revoke trust? Applications using this certificate can no longer connect securely.")) return;
    await post(`/certificates/trusted/${el.dataset.thumb}/untrust`); await load();
  },
  "show-import"() { state.showImport = true; renderPage(); },
  "hide-import"() { state.showImport = false; renderPage(); },
  async regenerate() {
    if (!confirm("Generate a new gateway certificate? Every PLC and client must trust the new one; all targets restart.")) return;
    await post("/certificates/own/regenerate"); toast("New certificate generated"); await load();
  },
  // browser
  async "toggle-node"(el, event) {
    event.stopPropagation();
    const b = state.browser;
    const id = el.dataset.node;
    if (b.expanded.has(id)) b.expanded.delete(id);
    else { if (!b.tree[id]) await browseInto(id); b.expanded.add(id); }
    renderPage();
  },
  async "select-node"(el) {
    const b = state.browser;
    b.selected = el.dataset.node;
    b.attributes = await get(`/browser/${encodeURIComponent(b.target)}/attributes?node=${encodeURIComponent(b.selected)}`);
    renderPage();
  },
  watch(el) {
    const b = state.browser;
    const id = el.dataset.node;
    if (!b.watch.some((w) => w.node_id === id)) {
      const name = b.attributes.find((a) => a.attribute === "DisplayName");
      b.watch.push({ node_id: id, name: name ? valueText(name.value) : id });
    }
    renderPage(); schedule("browser");
  },
  unwatch(el) { state.browser.watch = state.browser.watch.filter((w) => w.node_id !== el.dataset.node); renderPage(); schedule("browser"); },
  async "browser-disconnect"() {
    const b = state.browser;
    await post(`/browser/${encodeURIComponent(b.target)}/disconnect`);
    Object.assign(b, { connection: null, tree: {}, expanded: new Set(), selected: null, attributes: [], watch: [], values: {} });
    renderPage(); schedule("browser");
  },
  // users
  async "set-role"(el) { await put(`/users/${encodeURIComponent(el.dataset.user)}`, { role: el.value }); toast("Role changed"); await load(); },
  async "reset-password"(el) {
    const password = prompt(`New password for ${el.dataset.user} (min. 8 characters)`);
    if (!password) return;
    await put(`/users/${encodeURIComponent(el.dataset.user)}`, { password }); toast("Password reset");
  },
  async "delete-user"(el) {
    if (!confirm(`Delete user ${el.dataset.user}?`)) return;
    await del(`/users/${encodeURIComponent(el.dataset.user)}`); await load();
  },
};

const forms = {
  async login(form) {
    const err = form.querySelector("#login-error");
    try {
      state.user = await post("/login", formData(form));
      render(); await load();
    } catch (e) {
      err.textContent = e.message;
      err.classList.remove("hidden");
    }
  },
  async "audit-filter"(form) {
    state.audit.filters = formData(form);
    state.audit.selected = null;
    await loadAudit(); renderPage();
  },
  async target(form) {
    const t = state.targets.editing;
    const data = formData(form);
    const body = { name: data.name, listen: data.listen, endpoint_url: data.endpoint_url, discovery_interval_secs: Number(data.discovery_interval_secs) || 60, min_security: data.min_security || "none" };
    if (t.original === null) await post("/targets", body);
    else await put(`/targets/${encodeURIComponent(t.original)}`, body);
    toast(t.original === null ? "Target added" : "Target saved");
    state.targets.editing = null;
    await load();
  },
  async import(form) {
    const cert = await readFile(form.certificate.files[0]);
    const key = await readFile(form.private_key.files[0]);
    await post("/certificates/own", { certificate: cert, private_key: key });
    state.showImport = false; toast("Certificate installed"); await load();
  },
  async "browser-connect"(form) {
    const data = formData(form);
    const b = state.browser;
    b.target = data.target;
    const body = data.username ? { username: data.username, password: data.password } : {};
    b.connection = await post(`/browser/${encodeURIComponent(b.target)}/connect`, body);
    await browseInto("root");
    renderPage();
  },
  async "new-user"(form) { await post("/users", formData(form)); form.reset(); toast("User added"); await load(); },
  async password(form) { await post("/me/password", formData(form)); form.reset(); toast("Password changed"); },
};

document.addEventListener("click", async (event) => {
  const el = event.target.closest("[data-action]");
  if (!el || el.tagName === "SELECT" || (el.tagName === "INPUT" && el.type === "checkbox")) return;
  const action = actions[el.dataset.action];
  if (!action) return;
  event.preventDefault();
  try { await action(el, event); } catch (e) { fail(e); }
});

document.addEventListener("change", async (event) => {
  const el = event.target.closest("select[data-action], input[type=checkbox][data-action]");
  if (!el) return;
  try { await actions[el.dataset.action]?.(el, event); } catch (e) { fail(e); }
});

document.addEventListener("submit", async (event) => {
  const form = event.target.closest("form[data-form]");
  if (!form) return;
  event.preventDefault();
  const button = form.querySelector("button[type=submit]");
  if (button) button.disabled = true;
  try { await forms[form.dataset.form](form); } catch (e) { fail(e); } finally { if (button) button.disabled = false; }
});

window.addEventListener("hashchange", () => {
  document.querySelector(".shell")?.classList.remove("nav-open");
  render(); load();
});

// ---------- start ----------

try {
  const theme = localStorage.getItem(THEME_KEY);
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
} catch {}

(async () => {
  try { state.version = (await get("/health")).version; } catch {}
  try { state.user = await get("/me"); } catch { state.user = null; }
  render();
  if (state.user) await load();
})();
