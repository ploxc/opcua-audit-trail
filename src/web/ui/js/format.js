// Formatting of times, values and names, and the labels and groups of the
// audit event types.

// ---------- times ----------

/**
 * A timestamp in the browser's locale. OPC UA timestamps carry up to 9
 * fraction digits; Date parses 3.
 */
export const time = (iso) =>
  iso ? new Date(String(iso).replace(/(\.\d{3})\d+/, "$1")).toLocaleString() : "";

/** How long ago a timestamp was, e.g. "5 min ago". */
export const since = (iso) => {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.round(s)} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
};

// ---------- values and names ----------

/**
 * The URL clients use for a target listening on `listen`. A wildcard address
 * is replaced by the host name this page was loaded from.
 */
export const clientUrl = (listen) => {
  const [host, port] = [
    listen.slice(0, listen.lastIndexOf(":")),
    listen.slice(listen.lastIndexOf(":") + 1),
  ];
  const shown = host === "0.0.0.0" || host === "[::]" ? location.hostname : host;
  return `opc.tcp://${shown}:${port}`;
};

/** An OPC UA variant ({ value, data_type }) as text. */
export const valueText = (v) => {
  if (!v) return "";
  const x = v.value;
  if (x === null || x === undefined) return "null";
  if (typeof x === "object") return JSON.stringify(x);
  return String(x);
};

/** Who a client logged in as. */
export const userLabel = (client) => {
  const u = client && client.user;
  if (!u) return "";
  if (u.kind === "anonymous") return "anonymous";
  if (u.kind === "user_name") return u.name;
  if (u.kind === "certificate") return u.subject;
  return u.kind;
};

/** "1 error", "2 errors". */
export const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;

// ---------- audit event types ----------

export const EVENT_LABELS = {
  write: "Write",
  call: "Method call",
  history_update: "History update",
  node_management: "Node management",
  change_intent: "Change intent",
  client_connected: "Client connected",
  client_disconnected: "Client disconnected",
  secure_channel_opened: "Secure channel",
  session_created: "Session created",
  session_activated: "Session activated",
  session_closed: "Session closed",
  authentication_failed: "Login failed",
  certificate_rejected: "Certificate rejected",
  upstream_available: "Target reachable",
  upstream_unavailable: "Target unreachable",
  gateway_started: "Gateway started",
  gateway_stopped: "Gateway stopped",
  config_changed: "Configuration changed",
  ui_login: "UI login",
  ui_login_failed: "UI login failed",
  mcp_query: "MCP query",
  retention_pruned: "Retention",
  events_lost: "Events lost",
  upstream_endpoints_changed: "Target security changed",
  subscriptions_transferred: "Subscriptions transferred",
  connections_refused: "Connections refused",
  trail_truncated: "Trail cut off",
  clock_jumped: "Clock jumped",
  export_gap: "Export gap",
  ignored_writes: "Summarised writes",
  alarms_acknowledged: "Acknowledged",
  discovery: "Discovery",
};

/** Events that change something on a target: the dashboard's "Latest changes". */
export const CHANGE_EVENTS = new Set([
  "write",
  "call",
  "history_update",
  "node_management",
  "subscriptions_transferred",
  "ignored_writes",
]);

// The same as the gateway's severities (src/audit/event.rs).
export const ERROR_EVENTS = new Set([
  "events_lost",
  "trail_truncated",
  "export_gap",
  "upstream_endpoints_changed",
]);
export const WARNING_EVENTS = new Set([
  "upstream_unavailable",
  "certificate_rejected",
  "authentication_failed",
  "ui_login_failed",
  "connections_refused",
  "clock_jumped",
]);

// Groups of events to filter on; the kinds are sent as one list.
export const EVENT_GROUPS = [
  ["errors", "Errors", [...ERROR_EVENTS]],
  ["warnings", "Warnings", [...WARNING_EVENTS]],
  [
    "changes",
    "Writes and other changes",
    [
      "write",
      "ignored_writes",
      "call",
      "history_update",
      "node_management",
      "change_intent",
      "subscriptions_transferred",
    ],
  ],
  [
    "connections",
    "Clients and sessions",
    [
      "client_connected",
      "client_disconnected",
      "secure_channel_opened",
      "session_created",
      "session_activated",
      "session_closed",
      "authentication_failed",
      "certificate_rejected",
      "connections_refused",
    ],
  ],
  [
    "targets",
    "Targets",
    ["upstream_available", "upstream_unavailable", "upstream_endpoints_changed"],
  ],
  [
    "gateway",
    "Gateway and configuration",
    [
      "gateway_started",
      "gateway_stopped",
      "config_changed",
      "retention_pruned",
      "events_lost",
      "trail_truncated",
      "clock_jumped",
      "export_gap",
      "alarms_acknowledged",
      "discovery",
    ],
  ],
  ["ui", "Web UI logins", ["ui_login", "ui_login_failed"]],
  ["mcp", "AI assistants (MCP)", ["mcp_query"]],
];

/** [type, label] of every event type, sorted by label: the "Event" filter. */
export const eventsByLabel = () =>
  Object.entries(EVENT_LABELS).sort((a, b) => a[1].localeCompare(b[1]));
