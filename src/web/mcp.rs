//! MCP endpoint: lets an AI assistant (Claude Desktop, Claude Code, …) read
//! the audit trail and the gateway's status.
//!
//! Streamable HTTP transport without sessions or server-sent events: every
//! JSON-RPC request is a POST to `/mcp` and gets one JSON answer. Clients log
//! in with an API token (`Authorization: Bearer gwt_…`) that a user creates
//! on their Account page; the token acts as that user. Every tool only reads,
//! and every tool call is itself recorded in the trail (`mcp_query`).
//!
//! Off unless an admin turns it on (`[mcp] enabled`, Settings page). The
//! token is a password: the endpoint refuses plain HTTP unless the web UI
//! only listens on loopback.

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use super::auth::{AuthUser, ClientAddr};
use super::AppState;
use crate::audit::event::{clip, ClientContext, MAX_TEXT};
use crate::audit::store::{AuditQuery, StoredRecord};
use crate::audit::{AuditEntry, AuditEvent};
use crate::users::Role;

/// Protocol versions this endpoint speaks, newest first.
const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];
/// Records per search at most: enough to answer, small enough for a model.
const MAX_RECORDS: u32 = 200;

const INSTRUCTIONS: &str = "\
This is an OPC UA audit gateway: OPC UA clients (HMI, SCADA, engineering \
tools) connect to PLCs through it, and it records who changed what, when, in \
a tamper-evident audit trail (a hash chain). Use search_audit_trail to answer \
questions like 'who changed Line1.Setpoint yesterday' (event type 'write'; \
the record has the old and new value, the client's address, application and \
login). Times are UTC. gateway_status shows the targets (PLCs), whether they \
are reachable and which clients are connected. If this token may change the \
configuration, tools for that are listed too (targets, certificates, \
settings): explain what you will change and get the user's confirmation first. \
Nothing here writes values to a PLC.";

/// POST /mcp: one JSON-RPC message.
pub async fn post(
    State(s): State<AppState>,
    ClientAddr(address): ClientAddr,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    if !s.targets.config().await.mcp.enabled {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "the MCP endpoint is turned off (Settings, AI assistants)"})),
        )
            .into_response();
    }
    if !transport_is_safe(&s.config.web) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "the MCP endpoint needs HTTPS: set tls = true under [web]"})),
        )
            .into_response();
    }
    let Some(user) = authenticate(&s, &headers) else {
        rejected(&s, &headers, address).await;
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
            Json(json!({"error": "a valid API token is needed (Authorization: Bearer gwt_…)"})),
        )
            .into_response();
    };
    let message: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return Json(error(Value::Null, -32700, &format!("parse error: {e}"))).into_response()
        }
    };
    let client = ClientContext {
        remote_addr: address.map(|a| a.to_string()).unwrap_or_default(),
        application_name: Some("MCP".into()),
        ..Default::default()
    };
    // What the token was created with, and only for an admin.
    let changes = if user.role >= Role::Admin {
        user.scopes.clone()
    } else {
        Vec::new()
    };
    let ctx = Caller {
        changes,
        user,
        client,
        agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|v| clip(v, 128)),
    };
    // No batches (protocol 2025-06-18 has none): one request could
    // otherwise run thousands of tool calls, an empty one included.
    if message.is_array() {
        return Json(error(
            Value::Null,
            -32600,
            "invalid request: batches are not supported",
        ))
        .into_response();
    }
    match handle(&s, &ctx, message).await {
        Some(answer) => Json(answer).into_response(),
        // Notifications and responses get no answer.
        None => StatusCode::ACCEPTED.into_response(),
    }
}

/// Whether MCP may answer: over HTTPS always, over plain HTTP only when the
/// web UI listens on loopback, so the token cannot cross a network in clear.
pub fn transport_is_safe(web: &crate::config::WebConfig) -> bool {
    web.tls || web.listen.ip().is_loopback()
}

/// GET and DELETE /mcp: no server-sent events and no sessions here.
pub async fn not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        [(header::ALLOW, "POST")],
        "this MCP endpoint only answers POST requests",
    )
        .into_response()
}

struct TokenUser {
    username: String,
    token: String,
    role: Role,
    /// What the token may change, chosen when it was created.
    scopes: Vec<String>,
}

struct Caller {
    user: TokenUser,
    client: ClientContext,
    agent: Option<String>,
    /// What this caller may change: the token's scopes, and only for an
    /// admin. Empty: read only.
    changes: Vec<String>,
}

impl Caller {
    /// The token's user for the web API handlers, marked as acting via MCP.
    fn auth_user(&self) -> AuthUser {
        AuthUser {
            username: self.user.username.clone(),
            role: self.user.role,
            must_change_password: false,
            via_token: Some(self.user.token.clone()),
        }
    }

    /// The tools this caller sees and may call.
    fn tools(&self) -> Vec<Value> {
        let mut all = tools();
        all.extend(
            change_tools()
                .into_iter()
                .filter(|(scope, _)| self.changes.iter().any(|c| c == scope))
                .map(|(_, tool)| tool),
        );
        all
    }
}

/// A refused API token is a warning in the trail, like a failed login: at
/// most one record per address a minute, so a flood cannot fill the trail
/// (the log has every one). Requests without a token are not recorded.
async fn rejected(s: &AppState, headers: &HeaderMap, address: Option<std::net::IpAddr>) {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    static LAST: Mutex<Option<HashMap<std::net::IpAddr, Instant>>> = Mutex::new(None);
    let Some(secret) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return;
    };
    // The id part only: never the secret.
    let token = secret
        .trim()
        .strip_prefix("gwt_")
        .and_then(|rest| rest.split('_').next())
        .map(|id| clip(id, 32))
        .unwrap_or_else(|| "(not a gateway token)".into());
    if let Some(ip) = address {
        let mut last = LAST.lock().expect("not poisoned");
        let last = last.get_or_insert_with(HashMap::new);
        let now = Instant::now();
        last.retain(|_, t| now.duration_since(*t) < Duration::from_secs(60));
        if last.contains_key(&ip) {
            return;
        }
        last.insert(ip, now);
    }
    let client = ClientContext {
        remote_addr: address.map(|a| a.to_string()).unwrap_or_default(),
        application_name: Some("MCP".into()),
        ..Default::default()
    };
    let _ = s
        .audit
        .record(AuditEntry::new(AuditEvent::ApiTokenRejected { token }).client(client))
        .await;
}

/// The token's user, if the token is valid and the user may read the trail.
fn authenticate(s: &AppState, headers: &HeaderMap) -> Option<TokenUser> {
    let secret = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?
        .trim();
    let (username, scopes) = match s.users.verify_token(secret) {
        Ok(Some(u)) => u,
        Ok(None) => {
            tracing::warn!("MCP request with an unknown API token");
            return None;
        }
        Err(e) => {
            tracing::warn!("checking an API token: {e:#}");
            return None;
        }
    };
    let state = s.users.session_state(&username).ok()??;
    if state.role < Role::Auditor || state.must_change_password {
        return None;
    }
    // The id part only: never the secret.
    let token = secret.split('_').nth(1).unwrap_or_default().to_string();
    Some(TokenUser {
        username,
        token,
        role: state.role,
        scopes,
    })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn result(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

async fn handle(s: &AppState, ctx: &Caller, message: Value) -> Option<Value> {
    let id = message.get("id").cloned();
    let method = message.get("method").and_then(Value::as_str);
    let (Some(id), Some(method)) = (id, method) else {
        // A notification (no id) or a response: nothing to answer.
        return None;
    };
    let params = message.get("params").cloned().unwrap_or(json!({}));
    Some(match method {
        "initialize" => {
            let asked = params.get("protocolVersion").and_then(Value::as_str);
            let version = asked
                .filter(|v| PROTOCOL_VERSIONS.contains(v))
                .unwrap_or(PROTOCOL_VERSIONS[0]);
            result(
                id,
                json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {
                        "name": "opcua-audit-gateway",
                        "title": "OPC UA Audit Gateway",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                    "instructions": INSTRUCTIONS,
                }),
            )
        }
        "ping" => result(id, json!({})),
        "tools/list" => result(id, json!({"tools": ctx.tools()})),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = match params.get("arguments") {
                None | Some(Value::Null) => json!({}),
                Some(a) => a.clone(),
            };
            let Some(tool) = ctx.tools().into_iter().find(|t| t["name"] == name) else {
                let hint = if change_tools().iter().any(|(_, t)| t["name"] == name) {
                    " (this token may not use it: an admin chooses a token's permissions when \
                     creating it)"
                } else {
                    ""
                };
                return Some(error(id, -32602, &format!("unknown tool '{name}'{hint}")));
            };
            // Arguments are an object (or absent); anything else would skip
            // the check below and run the tool unfiltered.
            if !args.is_object() {
                return Some(error(id, -32602, "arguments must be an object"));
            }
            // An argument the tool does not know would otherwise be ignored
            // silently, and a search would return unfiltered records.
            let known = &tool["inputSchema"]["properties"];
            let unknown: Vec<&String> = args
                .as_object()
                .map(|a| {
                    a.keys()
                        .filter(|k| known.get(k.as_str()).is_none())
                        .collect()
                })
                .unwrap_or_default();
            if !unknown.is_empty() {
                let allowed: Vec<&String> = known
                    .as_object()
                    .map(|p| p.keys().collect())
                    .unwrap_or_default();
                return Some(result(
                    id,
                    json!({
                        "content": [{"type": "text", "text": format!(
                            "unknown argument(s) {unknown:?} for {name}; allowed: {allowed:?}"
                        )}],
                        "isError": true,
                    }),
                ));
            }
            record(s, ctx, name, &args).await;
            let outcome = if change_tools().iter().any(|(_, t)| t["name"] == name) {
                change(s, ctx, name, args.clone()).await
            } else {
                call(s, name, &args).await
            };
            let answer = match outcome {
                Ok(v) => json!({
                    "content": [{"type": "text", "text": v.to_string()}],
                    "structuredContent": v,
                    "isError": false,
                }),
                Err(e) => json!({
                    "content": [{"type": "text", "text": format!("{e:#}")}],
                    "isError": true,
                }),
            };
            result(id, answer)
        }
        other => error(id, -32601, &format!("method '{other}' not found")),
    })
}

/// Arguments without secrets (passwords, tokens, user info in URLs), for
/// the trail.
fn redact(args: &Value) -> Value {
    match args {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| {
                    let secret = matches!(k.as_str(), "password" | "token");
                    let v = if secret && !v.is_null() {
                        json!("(hidden)")
                    } else {
                        redact(v)
                    };
                    (k.clone(), v)
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(redact).collect()),
        Value::String(text) => Value::String(strip_userinfo(text)),
        other => other.clone(),
    }
}

/// A URL without user and password (`http://u:p@host` -> `http://(hidden)@host`);
/// other text unchanged.
fn strip_userinfo(text: &str) -> String {
    let Some(start) = text.find("://").map(|i| i + 3) else {
        return text.to_string();
    };
    let rest = &text[start..];
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{}(hidden){}", &text[..start], &rest[at..]),
        None => text.to_string(),
    }
}

/// Who asked what: every tool call is a record in the trail.
async fn record(s: &AppState, ctx: &Caller, tool: &str, args: &Value) {
    tracing::info!(user = %ctx.user.username, tool, "MCP tool call");
    let mut client = ctx.client.clone();
    if let Some(agent) = &ctx.agent {
        client.application_name = Some(format!("MCP · {agent}"));
    }
    let _ = s
        .audit
        .record(
            AuditEntry::new(AuditEvent::McpQuery {
                by: ctx.user.username.clone(),
                token: ctx.user.token.clone(),
                tool: tool.to_string(),
                arguments: clip(&redact(args).to_string(), MAX_TEXT),
            })
            .client(client),
        )
        .await;
}

fn tools() -> Vec<Value> {
    use crate::audit::event::Severity;
    let kinds = format!(
        "Event types: write (a value written; old and new value), call (a method \
         called), history_update, node_management, change_intent (fail-closed mode: \
         recorded before a change is forwarded; its outcome follows as a write/call \
         record with the same request_handle), ignored_writes (summary of writes to \
         summarised noisy nodes), client_connected, client_disconnected, \
         secure_channel_opened, session_created, session_activated, session_closed, \
         authentication_failed, certificate_rejected, connections_refused, \
         upstream_available, upstream_unavailable, upstream_endpoints_changed, \
         target_not_trusted, target_refused_gateway, target_trust_restored, \
         subscriptions_transferred, alarms_acknowledged, gateway_started, \
         gateway_stopped, config_changed, ui_login, ui_login_failed, \
         api_token_rejected, mcp_query, discovery, retention_pruned, events_lost, \
         trail_truncated, clock_jumped, export_gap. Errors (something is broken: \
         audit or client connections): {}. Warnings (something to look at): {}.",
        Severity::Error.kinds().join(", "),
        Severity::Warning.kinds().join(", "),
    );
    vec![
        json!({
            "name": "search_audit_trail",
            "title": "Search the audit trail",
            "description": format!(
                "Audit records, newest first, filtered by any combination of \
                 the arguments. Each record has seq (its number in the chain), \
                 ts (UTC), target (the PLC), client (address, application, \
                 login) and event (type and details). Page back with \
                 before_seq = the lowest seq you got. {kinds}"
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target (PLC) name, exact."},
                    "event": {"type": "string", "description": "One event type, e.g. write. Several: comma separated."},
                    "user": {"type": "string", "description": "Part of the OPC UA login or web UI user name."},
                    "node": {"type": "string", "description": "Part of the node id or display name, e.g. Setpoint."},
                    "since": {"type": "string", "format": "date-time", "description": "From this time (RFC 3339, e.g. 2026-09-24T00:00:00Z)."},
                    "until": {"type": "string", "format": "date-time", "description": "Up to this time (RFC 3339)."},
                    "before_seq": {"type": "integer", "description": "Only records before this seq (paging)."},
                    "limit": {"type": "integer", "minimum": 1, "maximum": MAX_RECORDS, "default": 50},
                },
                "additionalProperties": false,
            },
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
        }),
        json!({
            "name": "get_audit_record",
            "title": "One audit record",
            "description": "One audit record by its seq, with its hash and the previous record's hash.",
            "inputSchema": {
                "type": "object",
                "properties": {"seq": {"type": "integer"}},
                "required": ["seq"],
                "additionalProperties": false,
            },
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
        }),
        json!({
            "name": "gateway_status",
            "title": "Gateway status",
            "description": "The gateway's version, its targets (PLCs) with \
                their endpoint, whether they are reachable and accept the \
                gateway, the clients connected to each right now, the \
                unacknowledged warnings and errors, audit records lost, and \
                the state of the exports.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
        }),
        json!({
            "name": "most_written_nodes",
            "title": "Most written nodes",
            "description": "The 10 nodes with the most recorded writes in the \
                last hours, with the count and the most recent write.",
            "inputSchema": {
                "type": "object",
                "properties": {"hours": {"type": "integer", "minimum": 1, "maximum": 8784, "default": 24}},
                "additionalProperties": false,
            },
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
        }),
        json!({
            "name": "verify_audit_trail",
            "title": "Verify the audit trail",
            "description": "Checks the whole hash chain (and the records \
                exported last): whether any record was changed or removed. \
                Returns the number of records, the head hash and an error if \
                the chain is broken. Can take a while on a large trail.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
            "annotations": {"readOnlyHint": true, "openWorldHint": false},
        }),
    ]
}

fn string(args: &Value, key: &str) -> Option<String> {
    args.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(String::from)
}

fn time(args: &Value, key: &str) -> anyhow::Result<Option<chrono::DateTime<chrono::Utc>>> {
    string(args, key)
        .map(|v| {
            chrono::DateTime::parse_from_rfc3339(&v)
                .map(|t| t.with_timezone(&chrono::Utc))
                .map_err(|e| anyhow::anyhow!("{key}: not an RFC 3339 time ({e})"))
        })
        .transpose()
}

/// A record without the hashes: what a model needs to answer.
fn compact(r: StoredRecord) -> Value {
    let mut v = serde_json::to_value(&r).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.remove("hash");
        o.remove("prev_hash");
    }
    v
}

async fn call(s: &AppState, tool: &str, args: &Value) -> anyhow::Result<Value> {
    match tool {
        "search_audit_trail" => {
            let event = string(args, "event");
            let (kind, kinds) = match event {
                Some(e) if e.contains(',') => (None, Some(e)),
                e => (e, None),
            };
            let limit = args
                .get("limit")
                .and_then(Value::as_u64)
                .unwrap_or(50)
                .clamp(1, MAX_RECORDS.into()) as u32;
            let q = AuditQuery {
                target: string(args, "target"),
                kind,
                kinds,
                user: string(args, "user"),
                node_id: string(args, "node"),
                since: time(args, "since")?,
                until: time(args, "until")?,
                before_seq: args.get("before_seq").and_then(Value::as_i64),
                limit: Some(limit),
                ..Default::default()
            };
            let records = s.reader.query(q).await?;
            let more = records.len() as u32 == limit;
            Ok(json!({
                "records": records.into_iter().map(compact).collect::<Vec<_>>(),
                "more": more,
            }))
        }
        "get_audit_record" => {
            let seq = args
                .get("seq")
                .and_then(Value::as_i64)
                .ok_or_else(|| anyhow::anyhow!("seq is required"))?;
            let q = AuditQuery {
                before_seq: Some(seq.saturating_add(1)),
                limit: Some(1),
                ..Default::default()
            };
            let record = s.reader.query(q).await?.into_iter().find(|r| r.seq == seq);
            match record {
                Some(r) => Ok(serde_json::to_value(r)?),
                None => anyhow::bail!("no record {seq} (removed by retention, or not written yet)"),
            }
        }
        "gateway_status" => {
            let exports: Vec<_> = s.exports.statuses().read().values().cloned().collect();
            let alarms = s.reader.alarms().await?;
            Ok(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "application_name": s.config.gateway.application_name,
                "targets": super::target_views(s).await,
                "unacknowledged": alarms.iter().map(|a| json!({
                    "severity": a.severity,
                    "count": a.unacknowledged,
                    "event_types": a.kinds,
                })).collect::<Vec<_>>(),
                "lost_audit_events": s.audit.lost_events(),
                "exports": exports,
            }))
        }
        "most_written_nodes" => {
            let hours = args
                .get("hours")
                .and_then(Value::as_i64)
                .unwrap_or(24)
                .clamp(1, 24 * 366);
            let since = chrono::Utc::now() - chrono::Duration::hours(hours);
            Ok(json!({"since": since, "nodes": s.reader.most_written(since, 10).await?}))
        }
        "verify_audit_trail" => {
            let anchors =
                crate::export::anchors_from(&s.config.gateway.data_dir.join("export-state.json"));
            let report = s.reader.verify_against(anchors).await?;
            Ok(json!({
                "intact": report.ok(),
                "records": report.records,
                "first_seq": report.first_seq,
                "last_seq": report.last_seq,
                "head_hash": report.head_hash,
                "error": report.error,
            }))
        }
        other => anyhow::bail!("unknown tool '{other}'"),
    }
}

// ---------- changes ----------
//
// Tools that change the gateway's configuration, per scope. They call the
// web API's handlers, so they check the same role, validate the same way and
// record the same `config_changed` records (with "via MCP, token …"). None
// writes to a PLC, and none changes users, MCP, API tokens or the web server.

/// A change tool: its name, what it does, and its arguments.
fn change_tool(name: &str, description: &str, properties: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": format!(
            "{description} Changes the gateway's configuration: confirm with the user first."
        ),
        "annotations": {"readOnlyHint": false, "destructiveHint": true, "openWorldHint": false},
        "inputSchema": {
            "type": "object",
            "properties": properties,
            "required": required,
            "additionalProperties": false,
        },
    })
}

/// A read tool that belongs to a scope (what the changes work on).
fn scope_read_tool(name: &str, description: &str, properties: Value) -> Value {
    json!({
        "name": name,
        "description": description,
        "annotations": {"readOnlyHint": true, "openWorldHint": false},
        "inputSchema": {"type": "object", "properties": properties, "additionalProperties": false},
    })
}

fn change_tools() -> Vec<(&'static str, Value)> {
    let text = |d: &str| json!({"type": "string", "description": d});
    let target_fields = json!({
        "name": text("Short unique name, e.g. line1. Used in audit records."),
        "listen": text("Where clients connect, e.g. 0.0.0.0:4841 (a free port per target)."),
        "endpoint_url": text("The PLC's endpoint, e.g. opc.tcp://192.168.0.10:4840."),
        "min_security": {"type": "string", "enum": ["none", "sign", "sign_and_encrypt"],
            "description": "Lowest security offered to clients and used towards the PLC."},
        "discovery_interval_secs": {"type": "integer", "minimum": 1},
        "max_connections": {"type": "integer", "minimum": 1},
        "max_connections_per_address": {"type": "integer", "minimum": 1},
    });
    let mut update_fields = target_fields.clone();
    update_fields["new_name"] = text("Rename the target.");
    update_fields["name"] = text("The target to change.");
    let rule = json!({
        "target": text("Target name."),
        "node_id": text("The node as in the audit trail, e.g. ns=3;s=\"DB1\".\"Life\"."),
        "client": text("Only writes from this client (IP address or application URI)."),
    });
    let mut rule_add = rule.clone();
    rule_add["name"] = text("Display name, for people reading the list.");
    let thumbprint = json!({"thumbprint": text("The certificate's SHA-1 thumbprint (hex).")});
    vec![
        (
            "targets",
            scope_read_tool(
                "list_targets",
                "The configured targets (PLCs) with their settings and summarised nodes.",
                json!({}),
            ),
        ),
        (
            "targets",
            change_tool(
                "discover_endpoints",
                "Asks an OPC UA server for its endpoints (security modes, user tokens, \
             certificate), to check a PLC before adding it. Recorded as a discovery.",
                json!({"endpoint_url": text("e.g. opc.tcp://192.168.0.10:4840")}),
                &["endpoint_url"],
            ),
        ),
        (
            "targets",
            change_tool(
                "add_target",
                "Adds a target: the gateway starts accepting clients for that PLC.",
                target_fields,
                &["name", "listen", "endpoint_url"],
            ),
        ),
        (
            "targets",
            change_tool(
                "update_target",
                "Changes a target; only the given fields change. Clients of the target \
             are disconnected.",
                update_fields,
                &["name"],
            ),
        ),
        (
            "targets",
            change_tool(
                "delete_target",
                "Removes a target: its clients are disconnected and no longer audited.",
                json!({"name": text("Target name.")}),
                &["name"],
            ),
        ),
        (
            "targets",
            change_tool(
                "summarise_node",
                "Writes to this node are summarised periodically instead of recorded one \
             by one (for noisy nodes such as a life bit).",
                rule_add,
                &["target", "node_id"],
            ),
        ),
        (
            "targets",
            change_tool(
                "record_node_again",
                "Undoes summarise_node: every write to the node is recorded again.",
                rule,
                &["target", "node_id"],
            ),
        ),
        (
            "certificates",
            scope_read_tool(
                "list_certificates",
                "The gateway's own certificate and the trusted and rejected ones.",
                json!({}),
            ),
        ),
        (
            "certificates",
            change_tool(
                "trust_server_certificate",
                "Trusts the certificate a target's PLC presents, after checking it has this \
             thumbprint (see discover_endpoints).",
                json!({"target": text("Target name."), "thumbprint": text("SHA-1 thumbprint (hex).")}),
                &["target", "thumbprint"],
            ),
        ),
        (
            "certificates",
            change_tool(
                "trust_rejected_certificate",
                "Trusts a rejected certificate (e.g. an OPC UA client's): it may connect.",
                thumbprint.clone(),
                &["thumbprint"],
            ),
        ),
        (
            "certificates",
            change_tool(
                "untrust_certificate",
                "Removes a certificate from the trusted ones.",
                thumbprint.clone(),
                &["thumbprint"],
            ),
        ),
        (
            "certificates",
            change_tool(
                "delete_rejected_certificate",
                "Deletes a rejected certificate.",
                thumbprint,
                &["thumbprint"],
            ),
        ),
        (
            "settings",
            scope_read_tool(
                "get_settings",
                "The audit, export and certificate settings.",
                json!({}),
            ),
        ),
        (
            "settings",
            change_tool(
                "update_audit_settings",
                "Changes audit settings; only the given fields change. Retention can only \
             get longer and fail-closed cannot be switched off here (web UI only).",
                json!({
                    "retention_days": {"type": "integer", "minimum": 0,
                        "description": "Keep records this many days; 0 keeps everything."},
                    "fail_mode": {"type": "string", "enum": ["open", "closed"],
                        "description": "closed: a write only reaches the PLC once recorded."},
                    "record_old_value": {"type": "boolean"},
                    "ignored_summary_secs": {"type": "integer", "minimum": 1},
                }),
                &[],
            ),
        ),
        (
            "settings",
            change_tool(
                "update_export_settings",
                "Sets or removes (null) the QuestDB export. Omitted password/token keep \
             the stored one while the URL's scheme, host and port stay the same.",
                json!({"questdb": {"type": ["object", "null"], "properties": {
                "url": text("e.g. http://questdb:9000"),
                "table": text("Table name, e.g. opcua_audit."),
                "username": text("Basic auth user."),
                "password": text("Basic auth password."),
                "token": text("Bearer token."),
                "ca_pem": text("CA certificates (PEM) for https with a private CA."),
                "interval_secs": {"type": "integer", "minimum": 1},
            }, "required": ["url", "table", "interval_secs"]}}),
                &["questdb"],
            ),
        ),
        (
            "settings",
            change_tool(
                "update_certificate_hostnames",
                "The host names and IP addresses clients use to reach the gateway, put in \
             its certificate when it is generated next.",
                json!({"certificate_hostnames": {"type": "array", "items": {"type": "string"}}}),
                &["certificate_hostnames"],
            ),
        ),
    ]
}

/// A web API handler's answer as a tool result.
async fn reply(response: impl IntoResponse) -> anyhow::Result<Value> {
    let response = response.into_response();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 4 << 20).await?;
    let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    if !status.is_success() {
        let message = value["error"].as_str().unwrap_or(status.as_str());
        anyhow::bail!("{message}");
    }
    // structuredContent must be an object.
    Ok(match value {
        Value::Null => json!({"ok": true}),
        Value::Object(_) => value,
        other => json!({"items": other}),
    })
}

/// `base` with the fields of `changes` put over it.
fn overlay(mut base: Value, changes: &Value, skip: &[&str]) -> Value {
    if let (Some(b), Some(c)) = (base.as_object_mut(), changes.as_object()) {
        for (k, v) in c {
            if !skip.contains(&k.as_str()) {
                b.insert(k.clone(), v.clone());
            }
        }
    }
    base
}

fn arg<T: serde::de::DeserializeOwned>(args: &Value) -> anyhow::Result<T> {
    serde_json::from_value(args.clone()).map_err(|e| anyhow::anyhow!("invalid arguments: {e}"))
}

fn required(args: &Value, key: &str) -> anyhow::Result<String> {
    string(args, key).ok_or_else(|| anyhow::anyhow!("'{key}' is required"))
}

async fn change(s: &AppState, ctx: &Caller, tool: &str, args: Value) -> anyhow::Result<Value> {
    use axum::extract::{Path, State};
    let st = || State(s.clone());
    let user = ctx.auth_user();
    match tool {
        "list_targets" => reply(super::targets(st(), user).await).await,
        "discover_endpoints" => {
            reply(super::discover_url(st(), user, Json(arg(&args)?)).await).await
        }
        "add_target" => reply(super::create_target(st(), user, Json(arg(&args)?)).await).await,
        "update_target" => {
            let name = required(&args, "name")?;
            let current = super::target_config(s, &name)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e.1))?;
            let mut target = overlay(serde_json::to_value(current)?, &args, &["name", "new_name"]);
            target["name"] = json!(string(&args, "new_name").unwrap_or_else(|| name.clone()));
            reply(super::update_target(st(), user, Path(name), Json(arg(&target)?)).await).await
        }
        "delete_target" => {
            let name = required(&args, "name")?;
            reply(super::delete_target(st(), user, Path(name)).await).await
        }
        "summarise_node" | "record_node_again" => {
            let target = required(&args, "target")?;
            let rule = overlay(json!({}), &args, &["target"]);
            if tool == "summarise_node" {
                reply(super::ignore_node(st(), user, Path(target), Json(arg(&rule)?)).await).await
            } else {
                reply(super::unignore_node(st(), user, Path(target), Json(arg(&rule)?)).await).await
            }
        }
        "list_certificates" => reply(super::certificates(st(), user).await).await,
        "trust_server_certificate" => {
            let target = required(&args, "target")?;
            let body = overlay(json!({}), &args, &["target"]);
            reply(super::trust_server(st(), user, Path(target), Json(arg(&body)?)).await).await
        }
        "trust_rejected_certificate" => {
            let t = required(&args, "thumbprint")?;
            reply(super::trust_rejected(st(), user, Path(t)).await).await
        }
        "untrust_certificate" => {
            let t = required(&args, "thumbprint")?;
            reply(super::untrust(st(), user, Path(t)).await).await
        }
        "delete_rejected_certificate" => {
            let t = required(&args, "thumbprint")?;
            reply(super::delete_rejected(st(), user, Path(t)).await).await
        }
        "get_settings" => reply(super::settings::get(st(), user).await).await,
        "update_audit_settings" => {
            let config = s.targets.config().await.audit;
            // What deletes history or lets writes pass unrecorded stays in
            // the web UI: an assistant could be talked into it.
            if let Some(days) = args.get("retention_days").and_then(Value::as_u64) {
                let current = u64::from(config.retention_days);
                if days != 0 && (current == 0 || days < current) {
                    anyhow::bail!(
                        "shorter retention deletes records for good: change it in the web UI \
                         (Settings)"
                    );
                }
            }
            if args["fail_mode"] == "open" && config.fail_mode == crate::config::FailMode::Closed {
                anyhow::bail!(
                    "switching fail-closed off lets writes pass unrecorded: change it in the \
                     web UI (Settings)"
                );
            }
            let current = serde_json::to_value(config)?;
            let audit = overlay(current, &args, &[]);
            reply(super::settings::put_audit(st(), user, Json(arg(&audit)?)).await).await
        }
        "update_export_settings" => {
            reply(super::settings::put_export(st(), user, Json(arg(&args)?)).await).await
        }
        "update_certificate_hostnames" => {
            reply(super::settings::put_gateway(st(), user, Json(arg(&args)?)).await).await
        }
        other => anyhow::bail!("unknown tool '{other}'"),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    #[test]
    fn redacts_credentials_in_urls() {
        // Audit finding S16.
        let args = json!({"questdb": {"url": "https://audit:s3cret@questdb:9000/x?a=b@c",
                                      "password": "pw", "table": "t"}});
        let text = super::redact(&args).to_string();
        assert!(
            !text.contains("s3cret") && !text.contains("audit:"),
            "{text}"
        );
        assert!(
            text.contains("https://(hidden)@questdb:9000/x?a=b@c"),
            "{text}"
        );
        assert!(!text.contains("\"pw\""));
        assert_eq!(
            super::strip_userinfo("http://questdb:9000"),
            "http://questdb:9000"
        );
        assert_eq!(super::strip_userinfo("a@b"), "a@b");
    }
}
