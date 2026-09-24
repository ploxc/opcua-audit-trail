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
  settings: '<path d="M19.14 12.94c.04-.3.06-.61.06-.94 0-.32-.02-.64-.07-.94l2.03-1.58a.49.49 0 0 0 .12-.61l-1.92-3.32a.488.488 0 0 0-.59-.22l-2.39.96c-.5-.38-1.03-.7-1.62-.94l-.36-2.54a.484.484 0 0 0-.48-.41h-3.84c-.24 0-.43.17-.47.41l-.36 2.54c-.59.24-1.13.57-1.62.94l-2.39-.96c-.22-.08-.47 0-.59.22L2.74 8.87c-.12.21-.08.47.12.61l2.03 1.58c-.05.3-.09.63-.09.94s.02.64.07.94l-2.03 1.58a.49.49 0 0 0-.12.61l1.92 3.32c.12.22.37.29.59.22l2.39-.96c.5.38 1.03.7 1.62.94l.36 2.54c.05.24.24.41.48.41h3.84c.24 0 .44-.17.47-.41l.36-2.54c.59-.24 1.13-.56 1.62-.94l2.39.96c.22.08.47 0 .59-.22l1.92-3.32c.12-.22.07-.47-.12-.61l-2.01-1.58zM12 15.6c-1.98 0-3.6-1.62-3.6-3.6s1.62-3.6 3.6-3.6 3.6 1.62 3.6 3.6-1.62 3.6-3.6 3.6z"/>',
  logout: '<path d="m17 7-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"/>',
};
const icon = (name, cls = "") =>
  new Html(`<svg class="icon ${cls}" viewBox="0 0 24 24" aria-hidden="true">${ICON_PATHS[name]}</svg>`);

const LOGO_PATH = "m 107.60293,0.64220653 c -35.769829,0 -65.039135,29.45982647 -65.039135,65.27483247 V 94.927484 L 30.45287,82.757639 7.3579379,105.74314 32.676186,131.18345 7.3579379,156.5017 30.214018,179.35778 55.477552,154.09425 80.619032,179.35778 103.71607,156.37227 75.147546,127.66697 V 65.917039 c 0,-18.289883 14.380372,-32.691083 32.455384,-32.691083 18.07499,0 32.45538,14.4012 32.45538,32.691083 0,18.275197 -14.35769,32.665875 -32.41224,32.68897 l -16.215592,-0.09996 -0.124161,32.583751 16.296613,0.1 v 0.002 c 35.7698,0 65.03913,-29.45983 65.03913,-65.274832 0,-35.815005 -29.26933,-65.27483198 -65.03913,-65.27483198 z";
const logo = (cls = "") =>
  new Html(`<svg class="logo ${cls}" viewBox="0 0 180 180" aria-hidden="true"><circle class="dot" cx="107.599" cy="65.927" r="16.292"/><path class="mark" d="${LOGO_PATH}"/></svg>`);
// The gateway's own mark: traffic enters on the left and leaves through the
// gateway (the ring) towards the target and the audit trail.
const gatewayLogo = (cls = "") =>
  new Html(`<svg class="logo gateway-logo ${cls}" viewBox="0 0 512 512" aria-hidden="true"><g class="mark-line" fill="none" stroke-width="75.1" stroke-linecap="round"><line x1="143.3" y1="256" x2="37.6" y2="256"/><line x1="342.3" y1="183.6" x2="423.3" y2="115.6"/><line x1="342.3" y1="328.4" x2="423.3" y2="396.4"/><circle cx="256" cy="256" r="112.7"/></g><circle class="dot" cx="256" cy="256" r="37.6"/></svg>`);

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
  browser: { target: "", connection: null, tree: {}, expanded: new Set(), selected: null, attributes: [], watch: [], values: {}, watchError: null },
  users: [],
  version: "",
};
const can = (role) => state.user && ROLE_LEVEL[state.user.role] >= ROLE_LEVEL[role];

// ---------- helpers ----------

// A dialog in the page, instead of the browser's confirm() and prompt().
// Resolves with the form's fields when confirmed, or null when cancelled.
function dialog({ title, body = "", confirm = "OK", danger = false }) {
  return new Promise((resolve) => {
    const d = document.createElement("dialog");
    d.className = "dialog";
    d.innerHTML = html`<form method="dialog"><h2>${title}</h2><div class="dialog-body">${body}</div>
      <div class="dialog-actions"><button type="submit" value="" formnovalidate>Cancel</button>
      <button type="submit" value="ok" class="${danger ? "danger" : "primary"}">${confirm}</button></div></form>`.s;
    document.body.append(d);
    d.addEventListener("close", () => {
      const data = d.returnValue === "ok" ? Object.fromEntries(new FormData(d.querySelector("form"))) : null;
      d.remove();
      resolve(data);
    });
    d.showModal();
    d.querySelector(".dialog-body input:not([type=radio]), .dialog-actions button[value=ok]")?.focus();
  });
}

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
const fail = (e) => {
  // 409 from the browser API: its session on the target is gone.
  if (e.status === 409 && state.browser.connection) return browserLost();
  if (e.status !== 401) toast(e.message, "bad");
};

const BROWSER_EMPTY = () => ({ connection: null, tree: {}, expanded: new Set(), selected: null, attributes: [], watch: [], values: {}, watchError: null });

/// The browser session ended (idle timeout, gateway restart, target down):
/// back to the connect form, with one message instead of one per refresh.
function browserLost() {
  Object.assign(state.browser, BROWSER_EMPTY());
  toast("The browser session on the target has ended. Connect again to continue.", "bad");
  renderPage();
  schedule(currentPage().id);
}

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
  connections_refused: "Connections refused", trail_truncated: "Trail cut off", clock_jumped: "Clock jumped",
  export_gap: "Export gap", ignored_writes: "Summarised writes", alarms_acknowledged: "Acknowledged",
};
const CHANGE_EVENTS = new Set(["write", "call", "history_update", "node_management", "subscriptions_transferred", "ignored_writes"]);
// The same as the gateway's severities (src/audit/event.rs).
const ERROR_EVENTS = new Set(["events_lost", "trail_truncated", "export_gap", "upstream_endpoints_changed"]);
const WARNING_EVENTS = new Set(["upstream_unavailable", "certificate_rejected", "authentication_failed", "ui_login_failed", "connections_refused", "clock_jumped"]);
const eventBadge = (type) => {
  const kind = ERROR_EVENTS.has(type) ? "bad" : WARNING_EVENTS.has(type) ? "warn"
    : CHANGE_EVENTS.has(type) ? "accent" : "neutral";
  return html`<span class="badge plain ${kind}">${EVENT_LABELS[type] || type}</span>`;
};
function eventSummary(e, target) {
  switch (e.type) {
    case "write":
      return html`<div>${e.display_name || e.node_id}${when(e.display_name, html` <span class="muted mono">${e.node_id}</span>`)} ${summarisedBadge(target, e.node_id)}${when(e.attribute !== "Value", html` <span class="muted">(${e.attribute})</span>`)}</div>
        <div class="change">${when(e.old_value, html`<span class="old">${valueText(e.old_value)}</span><span class="arrow">→</span>`)}${valueText(e.new_value)} <span class="muted">${e.new_value.data_type}</span>${when(e.written_status, html` <span class="muted">status ${e.written_status}</span>`)}${when(e.source_timestamp, () => html` <span class="muted" title="${e.source_timestamp}">source time ${time(e.source_timestamp)}</span>`)}</div>`;
    case "ignored_writes":
      return html`<div>${e.display_name || e.node_id}${when(e.display_name, html` <span class="muted mono">${e.node_id}</span>`)}</div>
        <div class="change">${e.count} writes${when(e.failed, html`, <b>${e.failed} failed</b>`)}, ${time(e.first)} – ${time(e.last)}, last ${valueText(e.last_value)}</div>
        <div class="small muted">${e.clients.join("; ")}</div>`;
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
    case "trail_truncated": return `records ${e.found_seq + 1} to ${e.expected_seq} are missing`;
    case "clock_jumped": return `by ${e.seconds} s`;
    case "export_gap": return `${e.destination}: ${e.reason}`;
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
  { id: "settings", label: "Settings", role: "auditor", icon: "settings" },
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
  if (state.user.must_change_password) {
    app.innerHTML = mustChangeView().s;
    app.querySelector("input[name=current]")?.focus();
    return;
  }
  const page = currentPage();
  const rejected = state.status?.rejected_certificates || 0;
  app.innerHTML = html`<div class="shell">
    <aside class="sidebar">
      <div class="brand">${gatewayLogo()}<div>Audit Gateway<small>OPC UA</small></div></div>
      <nav class="nav">
        ${PAGES.filter((p) => !p.hidden && can(p.role)).map((p) => html`<a href="#/${p.id}" class="${p.id === page.id ? "active" : ""}">
          ${icon(p.icon)}${p.label}
          ${when(p.id === "certificates" && rejected, html`<span class="count" title="Certificates waiting for a decision">${rejected}</span>`)}
          ${when(p.id === "audit", () => html`<span class="alarm-counts">${alarmCounts()}</span>`)}
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
  // Scroll positions inside the page (e.g. the browser tree) survive too.
  const scrolls = [...el.querySelectorAll("[data-keep-scroll]")].map((e) => [e.dataset.keepScroll, e.scrollTop, e.scrollLeft]);
  el.innerHTML = pageView(currentPage()).s;
  for (const [key, top, left] of scrolls) {
    const again = el.querySelector(`[data-keep-scroll="${key}"]`);
    if (again) { again.scrollTop = top; again.scrollLeft = left; }
  }
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
    case "settings": return settingsView();
  }
  return html``;
}

// ---------- login ----------

function loginView() {
  return html`<div class="login"><form class="card" data-form="login">
    <div class="brand">${gatewayLogo()}<div>Audit Gateway<small>OPC UA</small></div></div>
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
    ${s.exports?.filter((e) => e.gap).map((e) => html`<div class="alert bad">Export to ${e.name}: ${e.gap}</div>`)}
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

// ---------- ignored nodes ----------

const targetOf = (name) => (state.status?.targets || []).find((t) => t.name === name);
const ignoreRules = (target, nodeId) => (targetOf(target)?.ignore || []).filter((r) => r.node_id === nodeId);
// What an ignore rule for one client names: its application URI, else its address.
const clientKey = (client) => client?.application_uri || (client?.remote_addr || "").replace(/:\d+$/, "").replace(/^\[|\]$/g, "");
function summaryEvery() {
  const s = state.status?.ignored_summary_secs || 3600;
  return s % 3600 === 0 ? `${s / 3600} h` : s % 60 === 0 ? `${s / 60} min` : `${s} s`;
}

const isSummarised = (target, nodeId) => ignoreRules(target, nodeId).length > 0;
const summarisedBadge = (target, nodeId) => when(isSummarised(target, nodeId), () =>
  html`<span class="badge plain neutral" title="Writes to this node are recorded as one summary every ${summaryEvery()}">summarised</span>`);
const clientLabel = (client) => client ? [client.application_name, clientKey(client) === client.application_uri ? (client.remote_addr || "").replace(/:\d+$/, "") : ""].filter(Boolean).join(" ") || clientKey(client) : "";

// Whether writes to a node are summarised, and the button to change that.
// `node` is { target, node_id, name, client }.
function ignoreControls(node, { compact = false } = {}) {
  const { target, node_id: nodeId } = node;
  if (!target || !nodeId || !targetOf(target)) return "";
  const rules = ignoreRules(target, nodeId);
  const data = (r) => new Html(`data-target="${esc(target)}" data-node="${esc(nodeId)}" data-client="${esc(r?.client || "")}"`);
  if (rules.length) {
    const recordAgain = when(can("admin"), () => rules.map((r) => html`<button class="small" data-action="unignore" ${data(r)}>Record every write again</button>`));
    const who = rules.map((r) => r.client ? `from ${r.client}` : "from every client").join(", ");
    if (compact) return html`<span class="badge plain neutral" title="Summarised ${who}">summarised</span>`;
    return html`<div class="alert info small"><b>Summarised.</b> Writes to this node ${who} are not recorded one by one: every ${summaryEvery()} one record says how many there were, from whom, and the last value.<div class="button-row">${recordAgain}</div></div>`;
  }
  if (!can("admin")) return "";
  const button = html`<button class="small" data-action="ignore" ${data(null)} data-name="${node.name || ""}"
    data-client-key="${clientKey(node.client)}" data-client-label="${clientLabel(node.client)}">${compact ? "Summarise…" : "Summarise writes…"}</button>`;
  if (compact) return button;
  return html`<div class="ignore-box"><p class="small muted">Is this node written constantly, like a life bit or a clock? Its writes can be summarised instead of recorded one by one.</p><div class="button-row">${button}</div></div>`;
}

function mostWrittenCard() {
  const top = state.audit.top;
  const body = !top ? html`<p class="muted">Loading…</p>`
    : !top.length ? html`<p class="empty">No writes recorded in the last 24 hours.</p>`
    : html`<div class="table-wrap"><table><thead><tr><th>Target</th><th>Node</th><th class="num">Writes</th><th>Last written by</th><th></th></tr></thead>
      <tbody>${top.map((n) => html`<tr>
        <td>${n.target || ""}</td>
        <td><a href="#" data-action="filter-node" data-node="${n.node_id}">${n.display_name || n.node_id}</a>${when(n.display_name, html`<div class="muted mono small">${n.node_id}</div>`)}</td>
        <td class="num">${n.count}</td>
        <td>${n.last.client ? html`<div>${userLabel(n.last.client)}</div><div class="muted small">${n.last.client.application_name || ""} ${n.last.client.remote_addr}</div>` : ""}</td>
        <td>${ignoreControls({ target: n.target, node_id: n.node_id, name: n.display_name, client: n.last.client }, { compact: true })}</td></tr>`)}</tbody></table></div>`;
  return html`<div class="card"><div class="card-head"><h2>Most written nodes, last 24 hours</h2><button class="small" data-action="toggle-top">Close</button></div>
    <p class="section-note">Nodes that fill the trail, such as a life bit or a clock, can be summarised: one record per interval instead of one per write.</p>${body}</div>`;
}

// ---------- warnings and errors ----------

const alarm = (severity) => (state.alarms || []).find((a) => a.severity === severity);
const unacked = (severity) => alarm(severity)?.unacknowledged || 0;
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

function alarmCounts() {
  const e = unacked("error"), w = unacked("warning");
  return html`${when(e, html`<span class="count bad" title="${plural(e, "error")} not acknowledged">${e}</span>`)}${when(w, html`<span class="count warn" title="${plural(w, "warning")} not acknowledged">${w}</span>`)}`;
}

// Keeps the badges in the sidebar current on every page.
async function refreshAlarms() {
  if (!state.user || state.user.must_change_password) return;
  try { state.alarms = await get("/alarms"); } catch { return; }
  const el = document.querySelector(".alarm-counts");
  if (el) el.innerHTML = alarmCounts().s;
}
setInterval(refreshAlarms, 10000);

function alarmBar() {
  const e = unacked("error"), w = unacked("warning");
  const f = state.audit.filters;
  const showing = f.kinds ? (f.kinds === alarm("error")?.kinds.join(",") ? "error" : "warning") : null;
  if (!e && !w && !showing) return "";
  const block = (severity, n, word) => when(n, html`<div class="alarm-line"><b>${plural(n, word)}</b> not acknowledged
    <button class="small" data-action="show-alarms" data-severity="${severity}">Show</button>
    ${when(can("operator"), html`<button class="small" data-action="ack-alarms" data-severity="${severity}">Acknowledge ${word}s</button>`)}</div>`);
  return html`<div class="alert ${e ? "bad" : "warn"} alarm-bar">
    ${block("error", e, "error")}${block("warning", w, "warning")}
    ${when(!e && !w, html`<div class="alarm-line">Everything is acknowledged.</div>`)}
    ${when(showing, html`<div class="alarm-line small">Showing only unacknowledged ${showing}s. <button class="small" data-action="clear-filter">Show everything</button></div>`)}
  </div>`;
}

// ---------- audit ----------

function auditTable(rows, { compact = false, selectable = false } = {}) {
  if (!rows.length) return html`<p class="empty">No records.</p>`;
  return html`<div class="table-wrap"><table>
    <thead><tr>${when(!compact, html`<th>#</th>`)}<th>Time</th><th>Target</th><th>Event</th><th>Client / user</th><th>Details</th><th>Result</th></tr></thead>
    <tbody>${rows.map((r) => html`<tr class="${selectable ? "clickable" : ""} ${state.audit.selected === r.seq ? "selected" : ""}" ${new Html(selectable ? `data-action="select-record" data-seq="${r.seq}"` : "")}>
      ${when(!compact, html`<td class="num muted">${r.seq}</td>`)}
      <td class="nowrap">${time(r.ts)}</td>
      <td class="target">${r.target || ""}</td>
      <td>${eventBadge(r.event.type)}</td>
      <td class="client">${r.client ? html`<div>${userLabel(r.client)}</div><div class="muted small" title="${r.client.application_uri || ""}">${r.client.application_name || ""} <span class="nowrap">${r.client.remote_addr}</span></div>` : ""}</td>
      <td>${eventSummary(r.event, r.target)}</td>
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
        <button data-action="toggle-top">Most written</button>
        <button data-action="verify">Verify integrity</button>
        <a class="button" href="/api/audit.csv?${auditQuery({ limit: "" })}">Export CSV</a>
      </div></div>
    ${when(a.verify, () => a.verify.error
      ? html`<div class="alert bad"><b>Integrity check failed.</b> ${a.verify.error}</div>`
      : html`<div class="alert ok">All ${a.verify.records} records (#${a.verify.first_seq}–#${a.verify.last_seq}) are intact. Chain head <span class="mono">${a.verify.head_hash.slice(0, 16)}…</span></div>`)}
    ${alarmBar()}
    ${when(a.showTop, mostWrittenCard)}
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
        ${when((selected.event.type === "write" && selected.event.attribute === "Value") || selected.event.type === "ignored_writes",
          () => ignoreControls({ target: selected.target, node_id: selected.event.node_id, name: selected.event.display_name, client: selected.client }))}
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

const MODE_RANK = { None: 0, Sign: 1, SignAndEncrypt: 2 };
const MIN_RANK = { none: 0, sign: 1, sign_and_encrypt: 2 };
const relayed = (u) => u.token_type !== "Certificate" && u.token_type !== "IssuedToken";

// The target's endpoints, and which of them clients are offered.
function endpointsTable(endpoints, minSecurity) {
  if (!endpoints?.length) return html`<p class="muted small">No endpoints known yet: press Discover.</p>`;
  const min = MIN_RANK[minSecurity || "none"];
  return html`<div class="table-wrap"><table><thead><tr><th>Security policy</th><th>Mode</th><th>Logins</th><th>For clients</th></tr></thead>
    <tbody>${endpoints.map((e) => {
      const offered = (MODE_RANK[e.security_mode] ?? 0) >= min;
      return html`<tr class="${offered ? "" : "dimmed"}"><td>${e.security_policy}</td><td>${e.security_mode}</td>
        <td>${e.user_tokens.map((u) => html`<span class="badge plain ${relayed(u) ? "accent" : "neutral"}" title="${relayed(u) ? "Passed on to the target" : "Cannot be passed on by the gateway"}">${u.token_type}</span> `)}</td>
        <td>${offered ? html`<span class="badge ok">offered</span>` : html`<span class="badge plain neutral" title="Below the minimum security">hidden</span>`}</td></tr>`;
    })}</tbody></table></div>`;
}

// A section of a card that opens on click; closed unless opened (the
// state survives the periodic refresh).
function fold(key, title, summary, body) {
  const open = state.open?.has(key);
  return html`<div class="fold"><button type="button" class="fold-head" data-action="fold" data-key="${key}">
      <span class="chevron">${open ? "▾" : "▸"}</span><h3>${title}</h3><span class="fold-summary">${summary}</span></button>
    ${when(open, body)}</div>`;
}

// Whether the target accepts the gateway's certificate (checked by the
// gateway with a secure channel, before any client needs it).
function gatewayTrust(g) {
  switch (g?.state) {
    case "trusted": return html`<div class="alert ok small">The target accepts the gateway (checked with ${g.policy}).</div>`;
    case "refused": return html`<div class="alert bad small"><b>The target refuses the gateway.</b> It does not trust this certificate yet, so no client can connect securely.
      Download it below and trust it on the target: on a PLC, add it to its OPC UA trust list; on OPC PLC, move it from <span class="mono">pki/rejected/certs</span> to <span class="mono">pki/trusted/certs</span>.
      Then press Discover to check again.</div>`;
    case "target_not_trusted": return html`<div class="alert warn small">Not checked yet: trust the target's certificate first (above).</div>`;
    case "no_secure_endpoint": return html`<div class="muted small">The target offers no secure endpoint, so it needs no certificate from the gateway.</div>`;
    case "failed": return html`<div class="alert warn small">Could not check: ${g.detail}</div>`;
    default: return html`<div class="muted small">Checking whether the target accepts the gateway…</div>`;
  }
}

// Everything about security for one target: endpoints, logins, certificates.
// `editing` puts the minimum security choice in place.
function securitySection(t, endpoints, { editing = false } = {}) {
  const trusted = new Set((state.certificates?.trusted || []).map((c) => c.thumbprint));
  const cert = endpoints?.find((e) => e.server_certificate)?.server_certificate;
  const own = state.status?.certificate;
  const min = t.min_security || "none";
  const offered = (endpoints || []).filter((e) => (MODE_RANK[e.security_mode] ?? 0) >= MIN_RANK[min]).length;
  const g = t.status?.gateway_trust?.state;
  const summary = html`${endpoints?.length ? `${offered} of ${endpoints.length} endpoints offered` : "not discovered yet"} ·
    ${cert ? (trusted.has(cert.thumbprint) ? html`<span class="badge plain ok">target trusted</span>` : html`<span class="badge plain warn">target not trusted</span>`) : ""}
    ${g === "trusted" ? html`<span class="badge plain ok">accepts the gateway</span>` : g === "refused" ? html`<span class="badge plain bad">refuses the gateway</span>` : ""}`;
  const body = () => html`<div class="security-block">
      <h4>Endpoints</h4>
      <p class="help">Clients choose one of the offered endpoints themselves; the gateway offers what the target offers, from the minimum security up.</p>
      ${editing ? html`<div class="inline-input mb"><label for="min_security">Minimum security</label>
          <select id="min_security" name="min_security" data-action="target-min">${Object.entries(MIN_SECURITY).map(([k, v]) => html`<option value="${k}" ${flag(min === k, "selected")}>${v}</option>`)}</select></div>`
        : html`<p class="small">Minimum security: <b>${MIN_SECURITY[min]}</b></p>`}
      ${endpointsTable(endpoints, min)}
    </div>
    <div class="security-block">
      <h4>Logins</h4>
      <p class="help">There is no login to set here: each client logs in itself (anonymous or user name and password, as the target allows), and the gateway passes that login on to the target. So the target's own user rights apply, per user, and the audit trail shows who it was. Certificate logins cannot be passed on and are refused. The <a href="#/browser">Browser</a> asks for a login when it connects.</p>
    </div>
    <div class="security-block">
      <h4>Certificates</h4>
      <dl class="kv small">
        <dt>Target's certificate</dt><dd>${cert ? html`${cert.subject} ${trusted.has(cert.thumbprint) ? html`<span class="badge ok">trusted</span>` : html`<span class="badge warn">not trusted</span>
            ${when(can("admin") && !editing, html` <button type="button" class="small" data-action="trust-server" data-name="${t.name}">Trust…</button>`)}`}
            <div class="mono muted">${cert.thumbprint}</div>
            ${when(!trusted.has(cert.thumbprint), html`<div class="muted">The gateway only makes encrypted connections to a target it trusts.</div>`)}`
          : html`<span class="muted">Unknown: discover the target first.</span>`}</dd>
        <dt>Gateway's certificate</dt><dd>${own ? html`${own.subject}<div class="mono muted">${own.thumbprint}</div>` : ""}
          ${gatewayTrust(t.status?.gateway_trust)}
          <div class="muted">The target must trust this one (import it on the PLC), and should trust only this one, so no client can bypass the gateway.
            The same certificate for all targets: see <a href="#/certificates">Certificates</a>.</div>
          <a class="button small mt-xs" href="/api/certificates/own/cert.der">Download</a></dd>
        <dt>Client certificates</dt><dd class="muted">Clients connecting securely are accepted on the <a href="#/certificates">Certificates</a> page${state.status?.rejected_certificates ? html` (<b>${state.status.rejected_certificates} waiting</b>)` : ""}.</dd>
      </dl>
    </div>`;
  // Open while editing: the minimum security is chosen there.
  return editing ? html`<h3 class="mt">Security</h3>${body()}` : fold(`${t.name}:security`, "Security", summary, body);
}

function targetsView() {
  const s = state.status;
  if (!s) return html`<p class="muted">Loading…</p>`;
  const editing = state.targets.editing;
  return html`
    <div class="page-head"><div class="inline">${menuButton}<h1>Targets</h1></div>
      ${when(can("admin") && !editing, html`<div class="actions"><button class="primary" data-action="new-target">Add target</button></div>`)}</div>
    <p class="section-note">Each target is an OPC UA server (a PLC) behind the gateway. Clients (HMI, SCADA) connect to the gateway instead of the target.
      The gateway keeps no session of its own on the target: for every client, it opens a connection to the target with the gateway's certificate and passes that client's requests and login on, recording every change.</p>
    ${when(editing?.original === null, () => targetForm(editing))}
    ${s.targets.map((t) => editing?.original === t.name ? targetForm(editing, t) : html`<div class="card">
      <div class="card-head"><div class="inline"><h2>${t.name}</h2>${stateBadge(t.status?.state)}${when(t.status?.gateway_trust?.state === "refused", html`<span class="badge bad">refuses the gateway</span>`)}</div>
        <div class="inline">
          ${when(can("operator"), html`<button class="small" data-action="discover-target" data-name="${t.name}">Discover</button>`)}
          ${when(can("admin") && !editing, html`<button class="small" data-action="edit-target" data-name="${t.name}">Edit</button>
            <button class="small danger" data-action="delete-target" data-name="${t.name}">Delete</button>`)}
        </div></div>
      <dl class="kv"><dt>Clients connect to</dt><dd class="mono">${clientUrl(t.listen)} <span class="muted">(listening on ${t.listen})</span></dd>
        <dt>Target server</dt><dd class="mono">${t.endpoint_url}</dd>
        <dt>Discovery every</dt><dd>${t.discovery_interval_secs} s</dd>
        ${when(t.status?.last_error, html`<dt>Error</dt><dd class="small">${t.status?.last_error}</dd>`)}</dl>
      ${securitySection(t, state.targets.discovery[t.name] || t.status?.endpoints)}
      ${summarisedNodes(t)}
    </div>`)}`;
}

function summarisedNodes(t) {
  const rules = t.ignore || [];
  return fold(`${t.name}:summarised`, "Summarised nodes", rules.length ? plural(rules.length, "node") : "none", () => html`
    <p class="section-note">Writes to these nodes are not recorded one by one: every ${summaryEvery()} one record per node says how many there were, from whom, and the last value.
      Add nodes from <a href="#/audit">Audit trail → Most written</a>, a write's details, or the <a href="#/browser">Browser</a>.</p>
    ${rules.length ? html`<div class="table-wrap"><table><thead><tr><th>Node</th><th>Writes from</th><th></th></tr></thead><tbody>
      ${rules.map((r) => html`<tr><td>${r.name || r.node_id}${when(r.name, html`<div class="muted mono small">${r.node_id}</div>`)}</td>
        <td>${r.client ? html`only <span class="mono">${r.client}</span><div class="muted small">other clients are recorded one by one</div>` : "every client"}</td>
        <td>${when(can("admin"), html`<button class="small" data-action="unignore" data-target="${t.name}" data-node="${r.node_id}" data-client="${r.client || ""}">Record every write again</button>`)}</td></tr>`)}
    </tbody></table></div>` : html`<p class="muted small">None: every write is recorded.</p>`}`);
}

const MIN_SECURITY = { none: "Follow the target (incl. None)", sign: "Sign or better", sign_and_encrypt: "Sign & encrypt only" };

// Adding a target, or editing one in its own card (`current` is the saved target).
function targetForm(t, current = null) {
  const isNew = t.original === null;
  const endpoints = t.endpoints || (current && (state.targets.discovery[current.name] || current.status?.endpoints));
  return html`<form class="card" data-form="target">
    <div class="card-head"><h2>${isNew ? "Add target" : html`Edit ${t.original}`}</h2>
      <div class="inline"><button type="button" class="small" data-action="cancel-target">Cancel</button><button class="primary small" type="submit">${isNew ? "Add" : "Save"}</button></div></div>
    <div class="form-grid">
      <div><label>Name</label><input name="name" value="${t.name}" required pattern="[A-Za-z0-9._-]+" title="letters, digits, . _ -"></div>
      <div><label>Listen address (for clients)</label><input name="listen" value="${t.listen}" required placeholder="0.0.0.0:4841"></div>
      <div><label>Target endpoint URL</label><input name="endpoint_url" value="${t.endpoint_url}" required placeholder="opc.tcp://192.168.0.10:4840"></div>
      <div><label>Discovery every (s)</label><input name="discovery_interval_secs" type="number" min="1" value="${t.discovery_interval_secs}"></div>
      <div><button type="button" data-action="discover-url">Discover endpoints</button></div>
    </div>
    <p class="hint">On the PLC itself, use another port than the PLC's own server (e.g. 4841) and let the PLC's server accept only the gateway.</p>
    ${securitySection({ ...(current || {}), ...t, name: t.original || t.name }, endpoints, { editing: true })}
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
    const leaf = c.has_children === false || c.node_class === "Method" || state.browser.tree[c.node_id]?.length === 0;
    return html`<li><div class="node ${state.browser.selected === c.node_id ? "selected" : ""}" data-action="select-node" data-node="${c.node_id}">
      ${leaf ? html`<span class="toggle"></span>` : html`<span class="toggle" data-action="toggle-node" data-node="${c.node_id}">${open ? "▾" : "▸"}</span>`}
      <span>${c.display_name || c.browse_name}</span><span class="kind">${c.node_class}</span>${summarisedBadge(state.browser.target, c.node_id)}</div>
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
      <div class="card"><h2>Objects</h2><div class="tree" data-keep-scroll="tree">${treeView("root")}</div></div>
      <div>
        <div class="card"><div class="card-head"><h2>${b.selected ? "Attributes" : "Select a node"}</h2>
          ${when(b.selected && b.attributes.some((a) => a.attribute === "Value"), html`<button class="small" data-action="watch" data-node="${b.selected}">Watch value</button>`)}</div>
          ${when(b.selected, html`<div class="table-wrap"><table><tbody>${b.attributes.map((a) => html`<tr><th>${a.attribute}</th>
            <td class="mono">${attributeText(a)} <span class="muted">${a.value.data_type}</span></td></tr>`)}</tbody></table></div>`)}
          ${when(b.selected && b.attributes.some((a) => a.attribute === "Value"), () => ignoreControls({ target: b.target, node_id: b.selected, name: browserNodeName() }))}
        </div>
        <div class="card"><div class="card-head"><h2>Watch list</h2><span class="muted small">refreshes every second</span></div>
          ${when(b.watchError, html`<div class="alert warn">Values cannot be read right now: ${b.watchError}</div>`)}
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
// The selected node's display name, as the watch list shows it.
function browserNodeName() {
  const name = state.browser.attributes.find((a) => a.attribute === "DisplayName");
  return name ? valueText(name.value) : "";
}

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

// ---------- settings ----------

const flag = (cond, name) => new Html(cond ? name : "");

function exportState(name) {
  const e = (state.status?.exports || []).find((x) => x.name === name);
  if (!e) return "";
  const kind = e.last_error || e.gap ? "bad" : e.pending > 0 ? "warn" : "ok";
  const text = e.last_error ? `Failing: ${e.last_error}` : e.gap ? `Gap: ${e.gap}` : e.pending > 0 ? `${e.pending} records waiting` : "Up to date";
  return html`<div class="alert ${kind} small">${text}</div>`;
}

function secretField(prefix, name, label, isSet, off) {
  return html`<div><label>${label}</label><input name="${prefix}_${name}" type="password" autocomplete="new-password" placeholder="${isSet ? "•••••• (unchanged)" : ""}" ${off}>
    ${when(isSet, html`<label class="inline small"><input type="checkbox" name="${prefix}_${name}_clear" ${off}> remove</label>`)}</div>`;
}

function settingsView() {
  const st = state.settings;
  const head = html`<div class="page-head"><div class="inline">${menuButton}<h1>Settings</h1></div></div>`;
  if (!st) return html`${head}<p class="muted">Loading…</p>`;
  const edit = can("admin");
  const off = flag(!edit, "disabled");
  const a = st.audit;
  const q = st.export.questdb;
  const sl = st.export.syslog;
  const save = when(edit, html`<div class="actions mt"><button class="primary" type="submit">Save</button></div>`);
  return html`${head}
  <p class="section-note">Saved in <span class="mono">${st.config_file}</span> and applied at once, without disconnecting clients. ${edit ? "" : "Only administrators can change settings."}
    Settings per target (security, summarised nodes) are on the <a href="#/targets">Targets</a> page.</p>
  <div class="settings-grid">
    <form class="card" data-form="settings-audit"><h2>Audit trail</h2>
      <div class="setting"><label class="title" for="retention">Keep records for</label>
        <div class="inline-input"><input id="retention" name="retention_days" type="number" min="0" max="36500" required value="${a.retention_days}" ${off}> days</div>
        <p class="help">Older records are deleted for good; the rest of the chain stays verifiable. 0 keeps everything.</p></div>
      <div class="setting"><span class="title">When the audit trail cannot be written</span>
        <fieldset class="choice">
          <label><input type="radio" name="fail_mode" value="open" ${flag(a.fail_mode === "open", "checked")} ${off}> Keep forwarding writes
            <span class="muted small">Clients are never held up; records that could not be stored are counted and reported.</span></label>
          <label><input type="radio" name="fail_mode" value="closed" ${flag(a.fail_mode === "closed", "checked")} ${off}> Reject writes
            <span class="muted small">A write only reaches the PLC after its record is stored. Safer, but the audit trail must never fail.</span></label>
        </fieldset></div>
      <div class="setting"><label class="inline"><input type="checkbox" name="record_old_value" ${flag(a.record_old_value, "checked")} ${off}> Record the old value of each write</label>
        <p class="help">The value is read just before the write, so the trail shows old → new. One extra read per write on the PLC.</p></div>
      <div class="setting"><label class="title" for="summary">Summarised nodes: one record every</label>
        <div class="inline-input"><input id="summary" name="summary_minutes" type="number" min="1" max="1440" required value="${Math.max(1, Math.round(a.ignored_summary_secs / 60))}" ${off}> minutes</div>
        <p class="help">For nodes a target summarises (like a life bit): one record per node per interval instead of one per write.</p></div>
      <dl class="kv small readonly-kv"><dt>Database</dt><dd class="mono">${a.database}</dd></dl>
      ${save}
    </form>

    <form class="card" data-form="settings-export"><h2>Export</h2>
      <p class="section-note">A copy of every record outside the gateway, for long-term storage and as proof that the local trail was not rewritten. A new destination receives the whole trail.</p>
      <div class="setting"><label class="inline title"><input type="checkbox" name="questdb_on" ${flag(q, "checked")} ${off}> QuestDB</label>
        ${exportState("questdb")}
        <div class="form-grid">
          <div><label>URL</label><input name="q_url" placeholder="http://questdb:9000" value="${q?.url || ""}" ${off}></div>
          <div><label>Table</label><input name="q_table" value="${q?.table || "opcua_audit"}" ${off}></div>
          <div><label>User name</label><input name="q_username" autocomplete="off" value="${q?.username || ""}" ${off}></div>
          ${secretField("q", "password", "Password", q?.password_set, off)}
          ${secretField("q", "token", "Or a token", q?.token_set, off)}
          <div><label>CA file (https, private CA)</label><input name="q_ca_file" placeholder="public roots" value="${q?.ca_file || ""}" ${off}></div>
          <div><label>Every (s)</label><input name="q_interval" type="number" min="1" value="${q?.interval_secs || 5}" ${off}></div>
        </div></div>
      <div class="setting subsection"><label class="inline title"><input type="checkbox" name="syslog_on" ${flag(sl, "checked")} ${off}> Syslog (SIEM)</label>
        ${exportState("syslog")}
        <div class="form-grid">
          <div><label>Address</label><input name="s_address" placeholder="siem.local:6514" value="${sl?.address || ""}" ${off}></div>
          <div><label>Protocol</label><select name="s_protocol" ${off}>${[["tls", "TLS (RFC 5425)"], ["tcp", "TCP"], ["udp", "UDP (no delivery guarantee)"]].map(([v, l]) => html`<option value="${v}" ${flag((sl?.protocol || "tls") === v, "selected")}>${l}</option>`)}</select></div>
          <div><label>Facility</label><input name="s_facility" type="number" min="0" max="23" value="${sl?.facility ?? 16}" ${off}></div>
          <div><label>CA file (TLS, private CA)</label><input name="s_ca_file" placeholder="public roots" value="${sl?.ca_file || ""}" ${off}></div>
          <div><label>Every (s)</label><input name="s_interval" type="number" min="1" value="${sl?.interval_secs || 5}" ${off}></div>
        </div></div>
      ${save}
    </form>

    <form class="card" data-form="settings-gateway"><h2>Gateway certificate</h2>
      <dl class="kv small readonly-kv"><dt>Application name</dt><dd>${st.gateway.application_name}</dd>
        <dt>Application URI</dt><dd class="mono">${st.gateway.application_uri}</dd></dl>
      <div class="setting"><label class="title" for="hostnames">Host names and IP addresses</label>
        <input id="hostnames" name="certificate_hostnames" placeholder="gateway.local, 192.168.0.20" value="${st.gateway.certificate_hostnames.join(", ")}" ${off}>
        <p class="help">How clients reach the gateway, put in its certificate. Used when the certificate is generated: after a change, generate a new one on the <a href="#/certificates">Certificates</a> page.</p></div>
      ${save}
    </form>

    <div class="card"><h2>Web UI and files</h2>
      <dl class="kv small readonly-kv"><dt>Listens on</dt><dd class="mono">${st.web.listen}</dd>
        <dt>HTTPS</dt><dd>${st.web.tls ? (st.web.tls_certificate ? html`on, <span class="mono">${st.web.tls_certificate}</span>` : "on, with the gateway certificate") : "off"}</dd>
        <dt>Certificates</dt><dd class="mono">${st.gateway.pki_dir}</dd>
        <dt>Data</dt><dd class="mono">${st.gateway.data_dir}</dd></dl>
      <p class="help small muted">These take effect only when the gateway starts, and a wrong value can lock you out: change them in the <span class="mono">[web]</span> and <span class="mono">[gateway]</span> sections of the config file, then restart the gateway.</p>
    </div>
  </div>`;
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

/// A password someone else chose (first start, reset by an admin) is
/// replaced before anything else.
function mustChangeView() {
  return html`<div class="login"><form class="card" data-form="password">
    <div class="brand">${gatewayLogo()}<div>Choose a new password<small>${state.user.username}</small></div></div>
    <p class="section-note">Your password was set by someone else. Choose your own to continue.</p>
    <div class="field"><label for="c">Current password</label><input id="c" name="current" type="password" required autocomplete="current-password"></div>
    <div class="field"><label for="n">New password (min. 8)</label><input id="n" name="new" type="password" minlength="8" required autocomplete="new-password"></div>
    <button class="primary" type="submit">Continue</button>
    <p class="mt"><button type="button" class="link small" data-action="logout">Log out</button></p>
  </form></div>`;
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
  // Nothing loads until a forced password change is done.
  if (!state.user || state.user.must_change_password) return;
  refreshAlarms();
  const page = currentPage();
  try {
    switch (page.id) {
      case "dashboard": await refreshDashboard(); break;
      case "audit": state.status ||= await get("/status"); await loadAudit(); break;
      case "targets": state.status = await get("/status"); state.certificates = await get("/certificates"); break;
      case "certificates": state.certificates = await get("/certificates"); state.status = await get("/status"); break;
      case "browser": state.status ||= await get("/status"); break;
      case "users": state.users = await get("/users"); break;
      case "settings": state.settings = await get("/settings"); state.status = await get("/status"); break;
    }
  } catch (e) { fail(e); }
  renderPage();
  schedule(page.id);
}

function schedule(pageId) {
  clearInterval(refreshTimer);
  refreshTimer = null;
  const every = (ms, fn) => { refreshTimer = setInterval(async () => { try { if (await fn() !== false) renderPage(); } catch (e) { fail(e); } }, ms); };
  if (pageId === "dashboard") every(5000, refreshDashboard);
  // Target status (a new target starts as "Checking…"), but not while a
  // target is being edited: that would redraw the form.
  if (pageId === "targets") every(5000, async () => {
    if (state.targets.editing) return false;
    state.status = await get("/status");
  });
  if (pageId === "audit" && state.audit.live) every(3000, () => loadAudit());
  if (pageId === "browser" && state.browser.connection && state.browser.watch.length) every(1000, pollWatch);
}

async function pollWatch() {
  const b = state.browser;
  try {
    const values = await post(`/browser/${encodeURIComponent(b.target)}/values`, { nodes: b.watch.map((w) => w.node_id) });
    for (const v of values) b.values[v.node_id] = v;
    b.watchError = null;
  } catch (e) {
    // A lost session ends the browser; anything else is shown in place,
    // not as a new message every second.
    if (e.status === 409 || e.status === 401) throw e;
    b.watchError = e.message;
  }
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
  async logout() {
    await post("/logout");
    // Start from a clean page: nothing of this user's session stays behind.
    location.hash = "";
    location.reload();
  },
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
  fold(el) {
    state.open ||= new Set();
    const key = el.dataset.key;
    if (state.open.has(key)) state.open.delete(key); else state.open.add(key);
    renderPage();
  },
  async "show-alarms"(el) {
    const a = alarm(el.dataset.severity);
    if (!a) return;
    state.audit.filters = { kinds: a.kinds.join(","), after_seq: String(a.acknowledged_up_to) };
    state.audit.selected = null;
    await loadAudit(); renderPage();
  },
  async "ack-alarms"(el) {
    const severity = el.dataset.severity;
    const n = unacked(severity);
    if (!await dialog({ title: `Acknowledge ${plural(n, severity)}?`, confirm: "Acknowledge",
      body: html`<p>They stay in the audit trail, and the acknowledgement is recorded there too, under your name.</p><p class="muted small">New ${severity}s after this moment count again.</p>` })) return;
    state.alarms = await post("/alarms/acknowledge", { severity });
    if (state.audit.filters.kinds) state.audit.filters = {};
    await loadAudit(); render(); load();
  },
  async "toggle-top"() {
    const a = state.audit;
    a.showTop = !a.showTop;
    a.top = null;
    renderPage();
    if (a.showTop) { a.top = await get("/audit/most-written?hours=24"); renderPage(); }
  },
  async "filter-node"(el) {
    state.audit.filters = { ...state.audit.filters, node_id: el.dataset.node };
    state.audit.selected = null;
    await loadAudit(); renderPage();
  },
  async ignore(el) {
    const { target, node, name, clientKey: key, clientLabel: label } = el.dataset;
    const title = name || node;
    const choice = await dialog({
      title: `Summarise writes to ${title}?`,
      body: html`<p>Now every write to <b>${title}</b> <span class="mono muted">${node}</span> on target <b>${target}</b> becomes its own record.
          A node that is written constantly, like a life bit or a clock, buries the writes that matter.</p>
        <p>Summarised, its writes are counted instead: every ${summaryEvery()} one record says how many writes there were (and how many failed), from which clients, and the last value.</p>
        <fieldset class="choice"><legend>Which writes?</legend>
          <label><input type="radio" name="scope" value="" checked> From every client</label>
          ${when(key, () => html`<label><input type="radio" name="scope" value="${key}"> Only from ${label || key}
            <span class="muted small">Writes to this node by any other client stay recorded one by one.</span></label>`)}
        </fieldset>
        <p class="muted small">Method calls and writes to other nodes are always recorded. You can undo this at any time (on the target's page, or here).</p>`,
      confirm: "Summarise writes",
    });
    if (!choice) return;
    await post(`/targets/${encodeURIComponent(target)}/ignore`, { node_id: node, client: choice.scope || null, name: name || null });
    state.status = await get("/status");
    toast(`Writes to ${title} are now summarised`);
    renderPage();
  },
  async unignore(el) {
    const { target, node, client } = el.dataset;
    await post(`/targets/${encodeURIComponent(target)}/ignore/remove`, { node_id: node, client: client || null });
    state.status = await get("/status");
    toast("Every write to this node is recorded again");
    renderPage();
  },
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
  "target-min"(el) {
    Object.assign(state.targets.editing, formData(el.closest("form")));
    renderPage();
  },
  async "discover-url"(el) {
    const form = el.closest("form");
    Object.assign(state.targets.editing, formData(form));
    state.targets.editing.endpoints = await post("/discover", { endpoint_url: state.targets.editing.endpoint_url });
    renderPage();
  },
  async "discover-target"(el) { state.targets.discovery[el.dataset.name] = await post(`/targets/${encodeURIComponent(el.dataset.name)}/discover`); toast("Discovery done"); renderPage(); },
  async "trust-server"(el) {
    const t = (state.status?.targets || []).find((x) => x.name === el.dataset.name);
    const endpoints = state.targets.discovery[el.dataset.name] || t?.status?.endpoints || [];
    const shown = endpoints.find((e) => e.server_certificate)?.server_certificate;
    if (!shown) { toast("No certificate known yet: discover the target first.", "bad"); return; }
    if (!await dialog({ title: "Trust this server certificate?", confirm: "Trust",
      body: html`<p><b>${shown.subject}</b></p><p>Thumbprint <span class="mono">${shown.thumbprint}</span></p><p>Compare the thumbprint with the one shown on the PLC first.</p>` })) return;
    const cert = await post(`/targets/${encodeURIComponent(el.dataset.name)}/trust-server`, { thumbprint: shown.thumbprint });
    toast(`Trusted ${cert.subject}`);
    state.certificates = await get("/certificates");
    renderPage();
  },
  async "delete-target"(el) {
    if (!await dialog({ title: `Delete target ${el.dataset.name}?`, body: "Its clients are disconnected. The audit trail keeps its records.", confirm: "Delete", danger: true })) return;
    await del(`/targets/${encodeURIComponent(el.dataset.name)}`);
    toast("Target deleted");
    await load();
  },
  // certificates
  async "trust-cert"(el) { await post(`/certificates/rejected/${el.dataset.thumb}/trust`); toast("Certificate trusted"); await load(); },
  async "delete-cert"(el) { await del(`/certificates/rejected/${el.dataset.thumb}`); await load(); },
  async "untrust-cert"(el) {
    if (!await dialog({ title: "Revoke trust?", body: "Applications using this certificate can no longer connect securely; their connections are closed.", confirm: "Revoke", danger: true })) return;
    await post(`/certificates/trusted/${el.dataset.thumb}/untrust`); await load();
  },
  "show-import"() { state.showImport = true; renderPage(); },
  "hide-import"() { state.showImport = false; renderPage(); },
  async regenerate() {
    if (!await dialog({ title: "Generate a new gateway certificate?", body: "Every PLC and client must trust the new one. All targets restart, which disconnects their clients.", confirm: "Generate", danger: true })) return;
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
    Object.assign(b, BROWSER_EMPTY());
    renderPage(); schedule("browser");
  },
  // users
  async "set-role"(el) { await put(`/users/${encodeURIComponent(el.dataset.user)}`, { role: el.value }); toast("Role changed"); await load(); },
  async "reset-password"(el) {
    const input = await dialog({ title: `New password for ${el.dataset.user}`, confirm: "Set password",
      body: html`<div class="field"><label for="new-password">Password (min. 8 characters)</label><input id="new-password" name="password" type="password" minlength="8" required autocomplete="new-password"></div>
        <p class="muted small">The user's sessions end; they log in with the new password.</p>` });
    if (!input) return;
    await put(`/users/${encodeURIComponent(el.dataset.user)}`, { password: input.password }); toast("Password reset");
  },
  async "delete-user"(el) {
    if (!await dialog({ title: `Delete user ${el.dataset.user}?`, body: "Their sessions end at once. The audit trail keeps their records.", confirm: "Delete", danger: true })) return;
    await del(`/users/${encodeURIComponent(el.dataset.user)}`); await load();
  },
};

const forms = {
  async "settings-audit"(form) {
    const d = formData(form);
    const body = {
      retention_days: Number(d.retention_days),
      fail_mode: d.fail_mode,
      record_old_value: form.elements.record_old_value.checked,
      ignored_summary_secs: Number(d.summary_minutes) * 60,
    };
    const old = state.settings.audit;
    if (body.retention_days > 0 && (old.retention_days === 0 || body.retention_days < old.retention_days)) {
      if (!await dialog({ title: `Keep records for ${body.retention_days} days?`, confirm: "Save", danger: true,
        body: html`<p>Records older than ${body.retention_days} days are deleted for good, starting right away.</p>
          <p class="muted small">Exported copies (QuestDB, syslog) are not affected.</p>` })) return;
    }
    if (body.fail_mode === "closed" && old.fail_mode !== "closed") {
      if (!await dialog({ title: "Reject writes when the trail cannot be written?", confirm: "Save",
        body: "From now on, a write only reaches the PLC after its record is stored. If the audit trail fails (e.g. a full disk), clients can no longer write." })) return;
    }
    await put("/settings/audit", body);
    toast("Audit trail settings saved");
    state.settings = await get("/settings"); state.status = await get("/status"); renderPage();
  },
  async "settings-export"(form) {
    const d = formData(form);
    const on = (name) => form.elements[name].checked;
    const secret = (body, name, prefix) => {
      if (d[`${prefix}_${name}`]) body[name] = d[`${prefix}_${name}`];
      else if (form.elements[`${prefix}_${name}_clear`]?.checked) body[name] = "";
    };
    const body = {};
    if (on("questdb_on")) {
      body.questdb = { url: d.q_url, table: d.q_table || "opcua_audit", username: d.q_username || null,
        ca_file: d.q_ca_file || null, interval_secs: Number(d.q_interval) || 5 };
      secret(body.questdb, "password", "q");
      secret(body.questdb, "token", "q");
    }
    if (on("syslog_on")) {
      body.syslog = { address: d.s_address, protocol: d.s_protocol, facility: Number(d.s_facility),
        ca_file: d.s_ca_file || null, interval_secs: Number(d.s_interval) || 5 };
    }
    await put("/settings/export", body);
    toast("Export settings saved");
    state.settings = await get("/settings"); state.status = await get("/status"); renderPage();
  },
  async "settings-gateway"(form) {
    const names = formData(form).certificate_hostnames.split(/[\s,;]+/).filter(Boolean);
    await put("/settings/gateway", { certificate_hostnames: names });
    toast("Saved. Generate a new certificate to use it (Certificates page).");
    state.settings = await get("/settings"); renderPage();
  },
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
  async password(form) {
    const wasForced = state.user.must_change_password;
    await post("/me/password", formData(form));
    form.reset(); toast("Password changed");
    state.user = await get("/me");
    if (wasForced) { render(); await load(); }
  },
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
