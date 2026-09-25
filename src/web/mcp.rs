//! MCP endpoint: lets an AI assistant (Claude Desktop, Claude Code, …) read
//! the audit trail and the gateway's status.
//!
//! Streamable HTTP transport without sessions or server-sent events: every
//! JSON-RPC request is a POST to `/mcp` and gets one JSON answer. Clients log
//! in with an API token (`Authorization: Bearer gwt_…`) that a user creates
//! on their Account page; the token acts as that user. Every tool only reads,
//! and every tool call is itself recorded in the trail (`mcp_query`).

use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use super::auth::ClientAddr;
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
are reachable and which clients are connected. Everything here is read-only.";

/// POST /mcp: one JSON-RPC message (or a batch).
pub async fn post(
    State(s): State<AppState>,
    ClientAddr(address): ClientAddr,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let Some(user) = authenticate(&s, &headers) else {
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
    let ctx = Caller {
        user,
        client,
        agent: headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|v| clip(v, 128)),
    };
    let answers = match message {
        Value::Array(batch) => {
            let mut out = Vec::new();
            for m in batch {
                out.extend(handle(&s, &ctx, m).await);
            }
            if out.is_empty() {
                return StatusCode::ACCEPTED.into_response();
            }
            Value::Array(out)
        }
        m => match handle(&s, &ctx, m).await {
            Some(answer) => answer,
            // Notifications and responses get no answer.
            None => return StatusCode::ACCEPTED.into_response(),
        },
    };
    Json(answers).into_response()
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
}

struct Caller {
    user: TokenUser,
    client: ClientContext,
    agent: Option<String>,
}

/// The token's user, if the token is valid and the user may read the trail.
fn authenticate(s: &AppState, headers: &HeaderMap) -> Option<TokenUser> {
    let secret = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?
        .trim();
    let username = match s.users.verify_token(secret) {
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
    Some(TokenUser { username, token })
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
        "tools/list" => result(id, json!({"tools": tools()})),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            let Some(tool) = tools().into_iter().find(|t| t["name"] == name) else {
                return Some(error(id, -32602, &format!("unknown tool '{name}'")));
            };
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
            let answer = match call(s, name, &args).await {
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
                arguments: clip(&args.to_string(), MAX_TEXT),
            })
            .client(client),
        )
        .await;
}

fn tools() -> Vec<Value> {
    let kinds = "Event types: write (a value written; old and new value), call \
        (a method called), history_update, node_management, change_intent (a \
        write the gateway could not audit fully), ignored_writes (summary of \
        writes to summarised noisy nodes), client_connected, \
        client_disconnected, secure_channel_opened, session_created, \
        session_activated, session_closed, authentication_failed, \
        certificate_rejected, connections_refused, upstream_available, \
        upstream_unavailable, upstream_endpoints_changed, \
        subscriptions_transferred, alarms_acknowledged, gateway_started, \
        gateway_stopped, config_changed, ui_login, ui_login_failed, \
        mcp_query, discovery, retention_pruned, events_lost, trail_truncated, \
        clock_jumped, export_gap.";
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
