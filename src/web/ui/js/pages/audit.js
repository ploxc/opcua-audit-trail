// Audit trail page: the filters, the table of records (also used by the
// dashboard), paging, a record's details, the most written nodes, the bar of
// unacknowledged warnings and errors, and the integrity check.

import { html, safe, submit } from "../vdom.js";
import { get, post } from "../api.js";
import { MenuButton, dialog, eventBadge, formData, statusBadge } from "../components.js";
import { EVENT_GROUPS, eventsByLabel, plural, time, userLabel, valueText } from "../format.js";
import { SummariseControls, summarisedBadge } from "../summarise.js";
import { alarm, unacked } from "../alarms.js";
import { can, load, redraw, schedule, state } from "../state.js";

// ---------- the records table ----------

// A node as the trail names it: its display name, then its id.
const nodeName = (e) =>
  html`${e.display_name || e.node_id}${
    e.display_name && html` <span class="muted mono">${e.node_id}</span>`
  }`;

/** The "Details" cell of a record: what happened, per event type. */
function eventSummary(e, target) {
  switch (e.type) {
    case "write": {
      const attribute =
        e.attribute !== "Value" && html` <span class="muted">(${e.attribute})</span>`;
      const old =
        e.old_value &&
        html`<span class="old">${valueText(e.old_value)}</span><span class="arrow">→</span>`;
      const written =
        e.written_status && html` <span class="muted">status ${e.written_status}</span>`;
      const sourceTime =
        e.source_timestamp &&
        html` <span class="muted" title=${e.source_timestamp}>
            source time ${time(e.source_timestamp)}
          </span>`;
      return html`<div>${nodeName(e)} ${summarisedBadge(target, e.node_id)}${attribute}</div>
        <div class="change">
          ${old}${valueText(e.new_value)}${" "}
          <span class="muted">${e.new_value.data_type}</span>${written}${sourceTime}
        </div>`;
    }
    case "ignored_writes":
      return html`<div>${nodeName(e)}</div>
        <div class="change">
          ${e.count} writes${e.failed > 0 && html`, <b>${e.failed} failed</b>`}, ${time(e.first)} –${" "}
          ${time(e.last)}, last ${valueText(e.last_value)}
        </div>
        <div class="small muted">${e.clients.join("; ")}</div>`;
    case "call":
      return html`<div>
          ${e.display_name || e.method_id} <span class="muted mono">${e.object_id}</span>
        </div>
        <div class="change">(${e.input_arguments.map(valueText).join(", ")})</div>`;
    case "history_update":
      return html`${e.details} on <span class="mono">${e.node_id}</span>`;
    case "node_management":
      return html`${e.service} <span class="mono">${e.node_id}</span>`;
    case "change_intent":
      return html`${e.service}: <span class="mono">${e.node_ids.join(", ")}</span>`;
    case "secure_channel_opened":
      return `${e.security_policy} / ${e.security_mode}`;
    case "session_created":
      return e.session_name;
    case "authentication_failed":
      return e.status;
    case "certificate_rejected":
      return html`${e.subject} <span class="muted">${e.reason}</span>`;
    case "client_disconnected":
      return e.reason;
    case "upstream_available":
      return `${e.endpoint_url} (${e.endpoints} endpoints)`;
    case "upstream_endpoints_changed":
      return html`<div>${e.endpoint_url}</div>
        <div class="small muted">before: ${e.before.join("; ")}</div>
        <div class="small">now: ${e.after.join("; ")}</div>`;
    case "subscriptions_transferred":
      return `subscriptions ${e.subscription_ids.join(", ")}`;
    case "connections_refused":
      return `${e.count} from ${e.remote_addr}: ${e.reason}`;
    case "trail_truncated":
      return `records ${e.found_seq + 1} to ${e.expected_seq} are missing`;
    case "clock_jumped":
      return `by ${e.seconds} s`;
    case "export_gap":
      return `${e.destination}: ${e.reason}`;
    case "upstream_unavailable":
      return e.reason;
    case "target_not_trusted":
      return `${e.endpoint_url}: the gateway does not trust its certificate`;
    case "target_refused_gateway":
      return `${e.endpoint_url}: ${e.detail}`;
    case "target_trust_restored":
      return `${e.endpoint_url} (${e.policy})`;
    case "api_token_rejected":
      return `token ${e.token}`;
    case "config_changed":
      return html`<b>${e.by}</b>: ${e.summary}`;
    case "ui_login":
    case "ui_login_failed":
      return e.user;
    case "mcp_query":
      return html`<b>${e.by}</b>: ${e.tool} <span class="muted mono">${e.arguments}</span>`;
    case "retention_pruned":
      return `${e.deleted} records removed`;
    case "events_lost":
      return `${e.count} events could not be stored`;
    case "gateway_started":
      return `version ${e.version}`;
    default:
      return "";
  }
}

/**
 * A table of audit records. `compact` leaves out the record number (the
 * dashboard); `selectable` rows open the record's details on click.
 */
export function AuditTable({ rows, compact = false, selectable = false }) {
  if (!rows.length) return html`<p class="empty">No records.</p>`;
  const select = (seq) => () => {
    state.audit.selected = state.audit.selected === seq ? null : seq;
    redraw();
  };
  const row = (r) => html`<tr
    key=${r.seq}
    class="${selectable ? "clickable" : ""} ${state.audit.selected === r.seq ? "selected" : ""}"
    onClick=${selectable ? select(r.seq) : undefined}
  >
    ${!compact && html`<td class="num muted">${r.seq}</td>`}
    <td class="nowrap">${time(r.ts)}</td>
    <td>${eventBadge(r.event.type)}</td>
    <td class="target">${r.target || ""}</td>
    <td class="client">${r.client ? clientCell(r.client) : ""}</td>
    <td>${eventSummary(r.event, r.target)}</td>
    <td>${statusBadge(r.event.status)}</td>
  </tr>`;
  return html`<div class="table-wrap">
    <table>
      <thead>
        <tr>
          ${!compact && html`<th>#</th>`}
          <th>Time</th>
          <th>Event</th>
          <th>Target</th>
          <th>Client / user</th>
          <th>Details</th>
          <th>Result</th>
        </tr>
      </thead>
      <tbody>
        ${rows.map(row)}
      </tbody>
    </table>
  </div>`;
}

// Who made a record: the user, then the application and its address.
const clientCell = (client) =>
  html`<div>${userLabel(client)}</div>
    <div class="muted small" title=${client.application_uri || ""}>
      ${client.application_name || ""} <span class="nowrap">${client.remote_addr}</span>
    </div>`;

// ---------- filters and paging ----------

/** The query string of the current filters, plus `extra` parameters. */
function auditQuery(extra = {}) {
  const f = { ...state.audit.filters, ...extra };
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(f)) {
    if (v === "" || v === undefined || v === null) continue;
    // The datetime-local inputs are in local time; the API wants UTC.
    params.set(k, k === "since" || k === "until" ? new Date(v).toISOString() : v);
  }
  return params.toString();
}

const PAGE = 100;

// New filters start at the newest page.
function setFilters(f) {
  Object.assign(state.audit, { filters: f, cursor: null, back: [] });
}

/** Shows other records: new filters, or another page (`move`, see loadAudit). */
async function show({ filters, move } = {}) {
  if (filters) setFilters(filters);
  state.audit.selected = null;
  await loadAudit(move);
  redraw();
}

// Pages of 100 records, fetched one at a time: the page only ever holds one.
function pager(a) {
  if (!a.rows.length || (!a.back.length && !a.olderAvailable)) return null;
  const first = a.rows[0].seq,
    last = a.rows[a.rows.length - 1].seq;
  return html`<div class="pager">
    <span class="muted small">Page ${a.back.length + 1} · records #${last}–#${first}</span>
    <div class="inline">
      <button
        class="small"
        disabled=${!a.back.length}
        onClick=${safe(() => show({ move: "first" }))}
      >
        « Newest
      </button>
      <button
        class="small"
        disabled=${!a.back.length}
        onClick=${safe(() => show({ move: "newer" }))}
      >
        ‹ Newer
      </button>
      <button
        class="small"
        disabled=${!a.olderAvailable}
        onClick=${safe(() => show({ move: "older" }))}
      >
        Older ›
      </button>
    </div>
  </div>`;
}

/**
 * Loads the current page of records; `move` ("first", "older" or "newer")
 * goes to another page first.
 */
export async function loadAudit(move) {
  const a = state.audit;
  if (move === "first") {
    a.cursor = null;
    a.back = [];
  }
  if (move === "older" && a.rows.length) {
    a.back.push(a.cursor);
    a.cursor = a.rows[a.rows.length - 1].seq;
  }
  if (move === "newer" && a.back.length) a.cursor = a.back.pop();
  // One more than a page, to know whether there is an older page.
  const extra = { limit: PAGE + 1 };
  if (a.cursor !== null) extra.before_seq = a.cursor;
  const rows = await get("/audit?" + auditQuery(extra));
  a.olderAvailable = rows.length > PAGE;
  a.rows = rows.slice(0, PAGE);
}

// ---------- most written nodes ----------

/** Opens or closes the most written nodes. */
const toggleTop = safe(async () => {
  const a = state.audit;
  a.showTop = !a.showTop;
  a.top = null;
  redraw();
  if (a.showTop) {
    a.top = await get("/audit/most-written?hours=24");
    redraw();
  }
});

/** The nodes written most in the last 24 hours, with a button to summarise each. */
function mostWrittenCard() {
  const top = state.audit.top;
  // Filters the records on a node.
  const filterNode = (nodeId) =>
    safe((event) => {
      event.preventDefault();
      return show({ filters: { ...state.audit.filters, node_id: nodeId } });
    });
  const row = (n) => html`<tr>
    <td>${n.target || ""}</td>
    <td>
      <a href="#" onClick=${filterNode(n.node_id)}>${n.display_name || n.node_id}</a>
      ${n.display_name && html`<div class="muted mono small">${n.node_id}</div>`}
    </td>
    <td class="num">${n.count}</td>
    <td>
      ${
        n.last.client
          ? html`<div>${userLabel(n.last.client)}</div>
            <div class="muted small">
              ${n.last.client.application_name || ""} ${n.last.client.remote_addr}
            </div>`
          : ""
      }
    </td>
    <td>
      <${SummariseControls}
        node=${{
          target: n.target,
          node_id: n.node_id,
          name: n.display_name,
          client: n.last.client,
        }}
        compact
      />
    </td>
  </tr>`;
  const body = !top
    ? html`<p class="muted">Loading…</p>`
    : !top.length
      ? html`<p class="empty">No writes recorded in the last 24 hours.</p>`
      : html`<div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Target</th>
                <th>Node</th>
                <th class="num">Writes</th>
                <th>Last written by</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${top.map(row)}
            </tbody>
          </table>
        </div>`;
  return html`<div class="card">
    <div class="card-head">
      <h2>Most written nodes, last 24 hours</h2>
      <button class="small" onClick=${toggleTop}>Close</button>
    </div>
    <p class="section-note">
      Nodes that fill the trail, such as a life bit or a clock, can be summarised: one record per
      interval instead of one per write.
    </p>
    ${body}
  </div>`;
}

// ---------- unacknowledged warnings and errors ----------

/** Shows the unacknowledged records of one severity. */
const showAlarms = (severity) =>
  safe(async () => {
    const a = alarm(severity);
    if (!a) return;
    await show({ filters: { kinds: a.kinds.join(","), after_seq: String(a.acknowledged_up_to) } });
  });

/** Acknowledges every record of one severity, after asking. */
const ackAlarms = (severity) =>
  safe(async () => {
    const n = unacked(severity);
    const confirmed = await dialog({
      title: `Acknowledge ${plural(n, severity)}?`,
      confirm: "Acknowledge",
      body: html`<p>
          They stay in the audit trail, and the acknowledgement is recorded there too, under your
          name.
        </p>
        <p class="muted small">New ${severity}s after this moment count again.</p>`,
    });
    if (!confirmed) return;
    state.alarms = await post("/alarms/acknowledge", { severity });
    if (state.audit.filters.after_seq) setFilters({});
    await loadAudit();
    load();
  });

const clearFilter = safe(() => show({ filters: {} }));

/**
 * The bar above the records: how many warnings and errors nobody acknowledged,
 * with buttons to show and to acknowledge them.
 */
function alarmBar() {
  const e = unacked("error"),
    w = unacked("warning");
  const f = state.audit.filters;
  // Which severity the filters show, when they were set by "Show".
  const showing =
    f.kinds && f.after_seq
      ? f.kinds === alarm("error")?.kinds.join(",")
        ? "error"
        : "warning"
      : null;
  if (!e && !w && !showing) return null;
  const block = (severity, n, word) =>
    n > 0 &&
    html`<div class="alarm-line">
      <b>${plural(n, word)}</b> not acknowledged${" "}
      <button class="small" onClick=${showAlarms(severity)}>Show</button>
      ${
        can("operator") &&
        html`<button class="small" onClick=${ackAlarms(severity)}>Acknowledge ${word}s</button>`
      }
    </div>`;
  return html`<div class="alert ${e ? "bad" : "warn"} alarm-bar">
    ${block("error", e, "error")}${block("warning", w, "warning")}
    ${!e && !w && html`<div class="alarm-line">Everything is acknowledged.</div>`}
    ${
      showing &&
      html`<div class="alarm-line small">
      Showing only unacknowledged ${showing}s.${" "}
      <button class="small" onClick=${clearFilter}>Show everything</button>
    </div>`
    }
  </div>`;
}

// ---------- the page ----------

/** The "Live" toggle: reloads the records every 3 s. */
function toggleLive() {
  state.audit.live = !state.audit.live;
  schedule("audit");
  redraw();
}

const verify = safe(async () => {
  state.audit.verify = await get("/audit/verify");
  redraw();
});

export function AuditPage() {
  const a = state.audit;
  const f = a.filters;
  const targets = state.status?.targets || [];
  const selected = a.rows.find((r) => r.seq === a.selected);
  return html`
    <div class="page-head">
      <div class="inline"><${MenuButton} /><h1>Audit trail</h1></div>
      <div class="actions">
        <button
          class="live-toggle ${a.live ? "on" : ""}"
          onClick=${toggleLive}
          aria-pressed=${a.live ? "true" : "false"}
          title=${a.live ? "Stop reloading" : "Reload the records every 3 s"}
        >
          <span class="live-dot"></span>Live
        </button>
        <button onClick=${toggleTop}>Most written</button>
        <button onClick=${verify}>Verify integrity</button>
        <a class="button" href="/api/audit.csv?${auditQuery({ limit: "" })}">Export CSV</a>
      </div>
    </div>
    ${a.verify && verifyResult(a.verify)} ${alarmBar()} ${a.showTop && mostWrittenCard()}
    <${Filters} key=${JSON.stringify(f)} f=${f} targets=${targets} />
    <div class=${selected ? "split" : ""}>
      <div class="card"><${AuditTable} rows=${a.rows} selectable />${pager(a)}</div>
      ${selected && recordDetail(selected)}
    </div>`;
}

// The outcome of "Verify integrity".
const verifyResult = (v) =>
  v.error
    ? html`<div class="alert bad"><b>Integrity check failed.</b> ${v.error}</div>`
    : html`<div class="alert ok">
        All ${v.records} records (#${v.first_seq}–#${v.last_seq}) are intact. Chain head${" "}
        <span class="mono">${v.head_hash.slice(0, 16)}…</span>
      </div>`;

/**
 * The filter form above the records. Its fields start from the filters in
 * use; the `key` above draws it afresh when they change (e.g. "Clear").
 */
function Filters({ f, targets }) {
  const filter = submit((form) => show({ filters: formData(form) }));
  return html`<form class="card filters" onSubmit=${filter}>
    <div>
      <label>Target</label>
      <select name="target">
        <option value="">All</option>
        ${targets.map((t) => html`<option selected=${f.target === t.name}>${t.name}</option>`)}
      </select>
    </div>
    <div>
      <label>Type</label>
      <select name="kinds">
        <option value="">All</option>
        ${EVENT_GROUPS.map(
          ([, label, kinds]) =>
            html`<option value=${kinds.join(",")} selected=${f.kinds === kinds.join(",")}>
              ${label}
            </option>`,
        )}
      </select>
    </div>
    <div>
      <label>Event</label>
      <select name="kind">
        <option value="">All</option>
        ${eventsByLabel().map(
          ([k, v]) => html`<option value=${k} selected=${f.kind === k}>${v}</option>`,
        )}
      </select>
    </div>
    <div>
      <label>User</label>
      <input name="user" defaultValue=${f.user || ""} placeholder="part of the name" />
    </div>
    <div>
      <label>Node</label>
      <input name="node_id" defaultValue=${f.node_id || ""} placeholder="part of the id or name" />
    </div>
    <div>
      <label>From</label>
      <input type="datetime-local" name="since" defaultValue=${f.since || ""} />
    </div>
    <div>
      <label>Until</label>
      <input type="datetime-local" name="until" defaultValue=${f.until || ""} />
    </div>
    <div class="inline">
      <button class="primary" type="submit">Filter</button>
      <button type="button" onClick=${clearFilter}>Clear</button>
    </div>
  </form>`;
}

// The details card of the selected record, next to the table.
function recordDetail(selected) {
  const e = selected.event;
  // Only value writes (and their summaries) can be summarised.
  const summarisable =
    (e.type === "write" && e.attribute === "Value") || e.type === "ignored_writes";
  // The record as stored, without its number, time and hash (shown above).
  const record = { target: selected.target, client: selected.client, event: e };
  const close = () => {
    state.audit.selected = null;
    redraw();
  };
  return html`<div class="card detail">
    <div class="card-head">
      <h2>Record #${selected.seq}</h2>
      <button class="small" onClick=${close}>Close</button>
    </div>
    <dl class="kv">
      <dt>Time</dt>
      <dd>${time(selected.ts)}</dd>
      <dt>Hash</dt>
      <dd class="mono small">${selected.hash}</dd>
    </dl>
    ${
      summarisable &&
      html`<${SummariseControls}
      node=${{
        target: selected.target,
        node_id: e.node_id,
        name: e.display_name,
        client: selected.client,
      }}
    />`
    }
    <h3 class="mt">Record</h3>
    <pre class="json">${JSON.stringify(record, null, 2)}</pre>
  </div>`;
}
