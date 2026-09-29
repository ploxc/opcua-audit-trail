// Browser page: a read-only session on a target, with its node tree, the
// attributes of the selected node and a watch list refreshed every second.

import { html, safe, submit } from "../vdom.js";
import { get, post } from "../api.js";
import { MenuButton, formData, statusBadge } from "../components.js";
import { time, valueText } from "../format.js";
import { SummariseControls, summarisedBadge } from "../summarise.js";
import { BROWSER_EMPTY, redraw, schedule, state } from "../state.js";

const NODE_CLASSES = {
  1: "Object",
  2: "Variable",
  4: "Method",
  8: "ObjectType",
  16: "VariableType",
  32: "ReferenceType",
  64: "DataType",
  128: "View",
};
// The bits of AccessLevel and UserAccessLevel, lowest first.
const ACCESS_BITS = [
  "CurrentRead",
  "CurrentWrite",
  "HistoryRead",
  "HistoryWrite",
  "SemanticChange",
  "StatusWrite",
  "TimestampWrite",
];
const VALUE_RANKS = {
  "-3": "scalar or one dimension",
  "-2": "any",
  "-1": "scalar",
  0: "one or more dimensions",
  1: "one dimension",
};

// ---------- node tree ----------

/** Opens or closes a node, browsing its children the first time. */
const toggleNode = (id) =>
  safe(async (event) => {
    // The click must not also select the node.
    event.stopPropagation();
    const b = state.browser;
    if (b.expanded.has(id)) b.expanded.delete(id);
    else {
      if (!b.tree[id]) await browseInto(id);
      b.expanded.add(id);
    }
    redraw();
  });

const selectNode = (id) =>
  safe(async () => {
    const b = state.browser;
    b.selected = id;
    b.attributes = await get(
      `/browser/${encodeURIComponent(b.target)}/attributes?node=${encodeURIComponent(id)}`,
    );
    redraw();
  });

/** The children of a node that were browsed, and below them the ones opened. */
function tree(nodeId) {
  const children = state.browser.tree[nodeId];
  if (!children) return null;
  const item = (c) => {
    const open = state.browser.expanded.has(c.node_id);
    // Without children (as far as known): no toggle.
    const leaf =
      c.has_children === false ||
      c.node_class === "Method" ||
      state.browser.tree[c.node_id]?.length === 0;
    const toggle = leaf
      ? html`<span class="toggle"></span>`
      : html`<span class="toggle" onClick=${toggleNode(c.node_id)}>${open ? "▾" : "▸"}</span>`;
    return html`<li key=${c.node_id}>
      <div
        class="node ${state.browser.selected === c.node_id ? "selected" : ""}"
        onClick=${selectNode(c.node_id)}
      >
        ${toggle}
        <span>${c.display_name || c.browse_name}</span>
        <span class="kind">${c.node_class}</span>
        ${summarisedBadge(state.browser.target, c.node_id)}
      </div>
      ${open && tree(c.node_id)}
    </li>`;
  };
  return html`<ul>
    ${children.map(item)}
  </ul>`;
}

/** Browses the children of a node ("root": the Objects folder) into the tree. */
async function browseInto(nodeId) {
  const b = state.browser;
  const query = nodeId === "root" ? "" : `?node=${encodeURIComponent(nodeId)}`;
  b.tree[nodeId] = await get(`/browser/${encodeURIComponent(b.target)}/browse${query}`);
}

// ---------- attributes ----------

// The selected node's display name, as the watch list shows it.
function browserNodeName() {
  const name = state.browser.attributes.find((a) => a.attribute === "DisplayName");
  return name?.value ? valueText(name.value) : "";
}

// One attribute: its value, or the status the server gave instead (e.g. a
// value it has not received from its data source yet), and for the value
// its timestamps.
function attributeRow(a) {
  // Each part only when its data is there (e.g. `a.status` is null for a
  // good value, `a.value` null for a bad one).
  const value =
    a.value &&
    html`<span class="mono">${attributeText(a)}</span>
      ${a.note && html` <span class="badge plain neutral">${a.note}</span>`}${" "}
      <span class="muted small">${a.value.data_type}</span>`;
  const status =
    a.status &&
    html`<div>
        <span class="badge plain ${a.status.startsWith("Uncertain") ? "warn" : "bad"} mono">
          ${a.status}
        </span>
      </div>
      <div class="muted small">${a.status_description}</div>`;
  const source = a.source_timestamp && `Source ${time(a.source_timestamp)}`;
  const server = a.server_timestamp && `Server ${time(a.server_timestamp)}`;
  const stamps =
    (source || server) &&
    html`<div class="muted small">${[source, server].filter(Boolean).join(" · ")}</div>`;
  return html`<tr key=${a.attribute}>
    <th>${a.attribute}</th>
    <td>${value}${status}${stamps}</td>
  </tr>`;
}

// An attribute's value in words where a number alone says little.
function attributeText(a) {
  const v = a.value.value;
  if (a.attribute === "ValueRank") return `${v} (${VALUE_RANKS[v] || `${v} dimensions`})`;
  if (a.attribute === "MinimumSamplingInterval") {
    return v === 0 ? "0 (as fast as possible)" : v < 0 ? `${v} (not known)` : `${v} ms`;
  }
  if (a.attribute === "NodeClass") return NODE_CLASSES[v] || v;
  if (a.attribute === "AccessLevel" || a.attribute === "UserAccessLevel") {
    const names = ACCESS_BITS.filter((_, i) => v & (1 << i));
    return names.length ? names.join(", ") : "none";
  }
  return valueText(a.value);
}

// ---------- the page ----------

const disconnect = safe(async () => {
  const b = state.browser;
  await post(`/browser/${encodeURIComponent(b.target)}/disconnect`);
  Object.assign(b, BROWSER_EMPTY());
  redraw();
  schedule("browser");
});

function watch() {
  const b = state.browser;
  const id = b.selected;
  if (!b.watch.some((w) => w.node_id === id)) {
    b.watch.push({ node_id: id, name: browserNodeName() || id });
  }
  redraw();
  schedule("browser");
}

const unwatch = (id) => () => {
  state.browser.watch = state.browser.watch.filter((w) => w.node_id !== id);
  redraw();
  schedule("browser");
};

export function BrowserPage() {
  const b = state.browser;
  const targets = state.status?.targets || [];
  if (!b.connection) return connectForm(b, targets);
  const hasValue = b.selected && b.attributes.some((a) => a.attribute === "Value");
  return html`<div class="page-head">
      <div class="inline">
        <${MenuButton} /><h1>Browser</h1>
        <span class="badge ok">${b.target}</span>
        <span class="muted small">
          ${b.connection.security_policy} / ${b.connection.security_mode} as ${b.connection.user}
        </span>
      </div>
      <div class="actions"><button onClick=${disconnect}>Disconnect</button></div>
    </div>
    <div class="browser">
      <div class="card">
        <h2>Objects</h2>
        <div class="tree">${tree("root")}</div>
      </div>
      <div>
        <div class="card">
          <div class="card-head">
            <h2>${b.selected ? "Attributes" : "Select a node"}</h2>
            ${hasValue && html`<button class="small" onClick=${watch}>Watch value</button>`}
          </div>
          ${
            b.selected &&
            html`<div class="table-wrap">
            <table class="attributes">
              <tbody>
                ${b.attributes.map(attributeRow)}
              </tbody>
            </table>
          </div>`
          }
          ${
            hasValue &&
            html`<${SummariseControls}
            node=${{ target: b.target, node_id: b.selected, name: browserNodeName() }}
          />`
          }
        </div>
        ${watchCard(b)}
      </div>
    </div>`;
}

/** Opens the session and browses the Objects folder. */
const connect = submit(async (form) => {
  const data = formData(form);
  const b = state.browser;
  b.target = data.target;
  const body = data.username ? { username: data.username, password: data.password } : {};
  b.connection = await post(`/browser/${encodeURIComponent(b.target)}/connect`, body);
  await browseInto("root");
  redraw();
});

// Before a session: choose a target and a login.
function connectForm(b, targets) {
  return html`<div class="page-head">
      <div class="inline"><${MenuButton} /><h1>Browser</h1></div>
    </div>
    <form class="card" onSubmit=${connect}>
      <h2>Connect to a target</h2>
      <p class="section-note">
        Opens a read-only session directly on the target, with the gateway's certificate. The login
        is only used for this session and never stored.
      </p>
      <div class="form-grid">
        <div>
          <label>Target</label>
          <select name="target">
            ${targets.map((t) => html`<option selected=${b.target === t.name}>${t.name}</option>`)}
          </select>
        </div>
        <div>
          <label>User name (empty = anonymous)</label>
          <input name="username" autocomplete="off" />
        </div>
        <div>
          <label>Password</label>
          <input name="password" type="password" autocomplete="off" />
        </div>
        <div>
          <button class="primary" type="submit" disabled=${!targets.length}>Connect</button>
        </div>
      </div>
    </form>`;
}

// The values being watched, with their status and source time.
function watchCard(b) {
  const row = (n) => {
    const v = b.values[n.node_id] || {};
    return html`<tr key=${n.node_id}>
      <td>${n.name}<div class="mono muted small">${n.node_id}</div></td>
      <td class="mono">${valueText(v.value)}</td>
      <td>${statusBadge(v.status)}</td>
      <td class="nowrap small">${time(v.source_timestamp)}</td>
      <td><button class="small" onClick=${unwatch(n.node_id)}>Remove</button></td>
    </tr>`;
  };
  return html`<div class="card">
    <div class="card-head">
      <h2>Watch list</h2>
      <span class="muted small">refreshes every second</span>
    </div>
    ${
      b.watchError &&
      html`<div class="alert warn">Values cannot be read right now: ${b.watchError}</div>`
    }
    ${
      b.watch.length
        ? html`<div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Node</th>
                <th>Value</th>
                <th>Status</th>
                <th>Source time</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${b.watch.map(row)}
            </tbody>
          </table>
        </div>`
        : html`<p class="muted small">Select a variable and choose “Watch value”.</p>`
    }
  </div>`;
}

/**
 * Reads the watched values (every second, see main.js). A lost session is
 * passed on to end the browser; other errors are shown in the watch list
 * instead of as a new message every second.
 */
export async function pollWatch() {
  const b = state.browser;
  try {
    const values = await post(`/browser/${encodeURIComponent(b.target)}/values`, {
      nodes: b.watch.map((w) => w.node_id),
    });
    for (const v of values) b.values[v.node_id] = v;
    b.watchError = null;
  } catch (e) {
    if (e.status === 409 || e.status === 401) throw e;
    b.watchError = e.message;
  }
}
