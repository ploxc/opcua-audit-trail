//! Settings outside the targets: the audit trail, export and the gateway's
//! certificate host names. Changes are written to the config file and applied
//! at once; the web server and the gateway identity are shown read-only
//! (they need a restart).

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use super::auth::AuthUser;
use super::{ApiError, ApiResult, AppState};
use crate::config::{AuditConfig, FailMode, QuestDbConfig};
use crate::users::Role;

#[derive(Serialize)]
pub struct SettingsView {
    config_file: String,
    audit: AuditView,
    export: ExportView,
    gateway: GatewayView,
    web: WebView,
}

#[derive(Serialize)]
struct AuditView {
    retention_days: u32,
    fail_mode: FailMode,
    record_old_value: bool,
    ignored_summary_secs: u64,
    database: String,
}

/// Export settings without secrets: only whether one is set.
#[derive(Serialize)]
struct ExportView {
    questdb: Option<QuestDbView>,
}

#[derive(Serialize)]
struct QuestDbView {
    url: String,
    table: String,
    username: Option<String>,
    password_set: bool,
    token_set: bool,
    /// The CA certificates (PEM) the https endpoint is verified with.
    ca_pem: Option<String>,
    interval_secs: u64,
}

#[derive(Serialize)]
struct GatewayView {
    application_name: String,
    application_uri: String,
    certificate_hostnames: Vec<String>,
    pki_dir: String,
    data_dir: String,
}

#[derive(Serialize)]
struct WebView {
    listen: String,
    tls: bool,
    tls_certificate: Option<String>,
}

pub async fn get(State(s): State<AppState>, user: AuthUser) -> ApiResult<SettingsView> {
    user.require(Role::Auditor)?;
    let c = s.targets.config().await;
    let path = |p: &std::path::Path| p.display().to_string();
    Ok(Json(SettingsView {
        config_file: path(s.targets.config_path()),
        audit: AuditView {
            retention_days: c.audit.retention_days,
            fail_mode: c.audit.fail_mode,
            record_old_value: c.audit.record_old_value,
            ignored_summary_secs: c.audit.ignored_summary_secs,
            database: path(&c.audit_database()),
        },
        export: ExportView {
            questdb: c.export.questdb.as_ref().map(|q| QuestDbView {
                url: q.url.clone(),
                table: q.table.clone(),
                username: q.username.clone(),
                password_set: q.password.is_some(),
                token_set: q.token.is_some(),
                ca_pem: q.ca_file.as_deref().map(read_pem),
                interval_secs: q.interval_secs,
            }),
        },
        gateway: GatewayView {
            application_name: c.gateway.application_name.clone(),
            application_uri: c.gateway.application_uri(),
            certificate_hostnames: c.gateway.certificate_hostnames.clone(),
            pki_dir: path(&c.gateway.pki_dir),
            data_dir: path(&c.gateway.data_dir),
        },
        web: WebView {
            listen: c.web.listen.to_string(),
            tls: c.web.tls,
            tls_certificate: c.web.tls_certificate.as_deref().map(path),
        },
    }))
}

pub async fn put_audit(
    State(s): State<AppState>,
    user: AuthUser,
    Json(new): Json<AuditConfig>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    let (old, config) = s
        .targets
        .update_settings(|c| {
            // The database location is not changed from the web UI.
            c.audit = AuditConfig {
                database: c.audit.database.clone(),
                ..new
            };
        })
        .await
        .map_err(ApiError::bad_request)?;
    s.audit.settings().apply(&config.audit);
    let (a, b) = (&old.audit, &config.audit);
    let mut changes = Vec::new();
    let days = |d: u32| match d {
        0 => "forever".to_string(),
        d => format!("{d} days"),
    };
    if a.retention_days != b.retention_days {
        changes.push(format!(
            "retention {} -> {}",
            days(a.retention_days),
            days(b.retention_days)
        ));
    }
    if a.fail_mode != b.fail_mode {
        changes.push(format!("fail mode {:?} -> {:?}", a.fail_mode, b.fail_mode).to_lowercase());
    }
    if a.record_old_value != b.record_old_value {
        changes.push(format!(
            "old values {}",
            if b.record_old_value {
                "recorded"
            } else {
                "not recorded"
            }
        ));
    }
    if a.ignored_summary_secs != b.ignored_summary_secs {
        changes.push(format!(
            "summaries of summarised nodes every {} s -> {} s",
            a.ignored_summary_secs, b.ignored_summary_secs
        ));
    }
    if !changes.is_empty() {
        s.config_changed(&user, format!("audit settings: {}", changes.join(", ")))
            .await;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// The CA file's contents, or why they cannot be shown.
fn read_pem(path: &std::path::Path) -> String {
    match std::fs::read_to_string(path) {
        Ok(pem) if pem.len() <= MAX_PEM => pem,
        Ok(_) => format!("# {} is too large to show", path.display()),
        Err(e) => format!("# {} cannot be read: {e}", path.display()),
    }
}

const MAX_PEM: usize = 256 * 1024;

/// Where a CA pasted in the settings is kept, next to the export state.
fn managed_ca(data_dir: &std::path::Path) -> std::path::PathBuf {
    data_dir.join("questdb-ca.pem")
}

/// A secret in a form: absent keeps the stored one, empty removes it.
fn secret(input: Option<String>, stored: Option<String>) -> Option<String> {
    match input {
        None => stored,
        Some(v) if v.is_empty() => None,
        Some(v) => Some(v),
    }
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestDbInput {
    url: String,
    table: String,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    token: Option<String>,
    /// CA certificates (PEM) for https with a private CA; empty: public
    /// roots.
    #[serde(default)]
    ca_pem: Option<String>,
    interval_secs: u64,
}

/// `null` (or absent) turns a destination off.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportInput {
    #[serde(default)]
    questdb: Option<QuestDbInput>,
}

pub async fn put_export(
    State(s): State<AppState>,
    user: AuthUser,
    Json(input): Json<ExportInput>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    let current = s.targets.config().await;
    let mut export = crate::config::ExportConfig::default();
    let ca = current.gateway.data_dir.join("questdb-ca.pem.new");
    if let Some(q) = input.questdb {
        let stored = current.export.questdb.clone();
        let pem = non_empty(q.ca_pem);
        if let Some(pem) = &pem {
            if pem.len() > MAX_PEM || !pem.contains("-----BEGIN CERTIFICATE-----") {
                return Err(ApiError::bad_request(anyhow::anyhow!(
                    "QuestDB: the CA must be one or more PEM certificates (-----BEGIN CERTIFICATE-----)"
                )));
            }
            std::fs::write(&ca, format!("{pem}\n")).map_err(|e| ApiError::bad_request(e.into()))?;
        }
        export.questdb = Some(QuestDbConfig {
            url: q.url.trim().trim_end_matches('/').to_string(),
            table: q.table.trim().to_string(),
            username: non_empty(q.username),
            password: secret(q.password, stored.as_ref().and_then(|s| s.password.clone())),
            token: secret(q.token, stored.as_ref().and_then(|s| s.token.clone())),
            ca_file: pem.map(|_| ca.clone()),
            interval_secs: q.interval_secs,
        });
    }
    if export.questdb.as_ref().is_some_and(|q| q.table.is_empty()) {
        return Err(ApiError::bad_request(anyhow::anyhow!(
            "QuestDB: table is empty"
        )));
    }
    if export
        .questdb
        .as_ref()
        .is_some_and(|q| q.interval_secs == 0)
    {
        return Err(ApiError::bad_request(anyhow::anyhow!(
            "the interval must be at least 1 s"
        )));
    }
    // Fails on a bad URL or an unusable CA, before anything changes.
    crate::export::Exports::check(&export).map_err(ApiError::bad_request)?;
    let old_ca = current
        .export
        .questdb
        .as_ref()
        .and_then(|q| q.ca_file.as_deref())
        .map(read_pem);
    let new_ca = export
        .questdb
        .as_ref()
        .and_then(|q| q.ca_file.as_deref())
        .map(read_pem);
    if let Some(file) = export.questdb.as_mut().and_then(|q| q.ca_file.as_mut()) {
        *file = managed_ca(&current.gateway.data_dir);
        std::fs::rename(&ca, &*file).map_err(|e| ApiError::bad_request(e.into()))?;
    }
    let (old, config) = s
        .targets
        .update_settings(|c| c.export = export)
        .await
        .map_err(ApiError::bad_request)?;
    s.exports
        .apply(&config.export)
        .map_err(ApiError::bad_request)?;
    let describe = |name: &str, before: Option<String>, after: Option<String>| match (before, after)
    {
        (None, None) => None,
        (None, Some(a)) => Some(format!("{name} export to {a} turned on")),
        (Some(b), None) => Some(format!("{name} export to {b} turned off")),
        (Some(b), Some(a)) if a != b => Some(format!("{name} export moved from {b} to {a}")),
        (Some(_), Some(a)) => Some(format!("{name} export to {a} changed")),
    };
    let quest = |c: &crate::config::ExportConfig| {
        c.questdb
            .as_ref()
            .map(|q| format!("{} (table {})", q.url, q.table))
    };
    let questdb_same = old_ca == new_ca
        && format!("{:?}", old.export.questdb) == format!("{:?}", config.export.questdb);
    let changes: Vec<String> = [(!questdb_same)
        .then(|| describe("QuestDB", quest(&old.export), quest(&config.export)))
        .flatten()]
    .into_iter()
    .flatten()
    .collect();
    if !changes.is_empty() {
        s.config_changed(&user, changes.join("; ")).await;
    }
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayInput {
    certificate_hostnames: Vec<String>,
}

pub async fn put_gateway(
    State(s): State<AppState>,
    user: AuthUser,
    Json(input): Json<GatewayInput>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    let mut names = Vec::new();
    for name in input.certificate_hostnames {
        let name = name.trim().to_string();
        if name.is_empty() {
            continue;
        }
        let valid = name.len() <= 253
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-:[]".contains(c));
        if !valid {
            return Err(ApiError::bad_request(anyhow::anyhow!(
                "'{}' is not a host name or IP address",
                name.escape_debug()
            )));
        }
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let (old, config) = s
        .targets
        .update_settings(|c| c.gateway.certificate_hostnames = names)
        .await
        .map_err(ApiError::bad_request)?;
    if old.gateway.certificate_hostnames != config.gateway.certificate_hostnames {
        s.config_changed(
            &user,
            format!(
                "certificate host names: {}",
                config.gateway.certificate_hostnames.join(", ")
            ),
        )
        .await;
    }
    Ok(StatusCode::NO_CONTENT)
}
