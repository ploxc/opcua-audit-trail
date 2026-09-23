//! Web UI and REST API.
//!
//! Every API route except `/api/health` and `/api/login` needs a logged-in
//! user. Roles are cumulative: auditor (read) < operator (browser, discovery)
//! < admin (configuration, certificates, users).

pub mod auth;
pub mod browser;

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use opcua::client::Client;
use opcua::crypto::X509;
use serde::{Deserialize, Serialize};

use crate::audit::event::AuditEvent;
use crate::audit::store::{AuditQuery, StoredRecord, VerifyReport};
use crate::audit::{AuditEntry, AuditHandle, AuditReader};
use crate::config::{Config, TargetConfig};
use crate::discovery::{self, EndpointInfo, TargetStatus, TargetStatuses};
use crate::pki::{CertificateInfo, Pki};
use crate::relay::ClientInfo;
use crate::targets::TargetManager;
use crate::users::{Role, User, UserStore};
use auth::{AuthUser, Sessions};
use browser::BrowserSessions;

#[derive(Clone)]
pub struct AppState {
    /// Configuration as loaded at start (gateway, web and audit sections).
    pub config: Arc<Config>,
    pub targets: Arc<TargetManager>,
    pub statuses: TargetStatuses,
    pub audit: AuditHandle,
    pub reader: AuditReader,
    pub client: Arc<Client>,
    pub pki: Arc<Pki>,
    pub users: Arc<UserStore>,
    pub sessions: Arc<Sessions>,
    pub browser: Arc<BrowserSessions>,
}

impl AppState {
    /// Records a configuration change made through the UI.
    async fn config_changed(&self, user: &AuthUser, summary: String) {
        tracing::info!(user = %user.username, "{summary}");
        let _ = self
            .audit
            .record_committed(AuditEntry::new(AuditEvent::ConfigChanged {
                by: user.username.clone(),
                summary,
            }))
            .await;
    }
}

pub struct ApiError(pub StatusCode, pub String);

impl ApiError {
    pub fn not_found(what: impl Into<String>) -> Self {
        Self(StatusCode::NOT_FOUND, what.into())
    }

    pub fn bad_request(e: anyhow::Error) -> Self {
        Self(StatusCode::BAD_REQUEST, format!("{e:#}"))
    }

    /// The upstream server could not be reached or answered with an error.
    fn upstream(e: anyhow::Error) -> Self {
        Self(StatusCode::BAD_GATEWAY, format!("{e:#}"))
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

pub type ApiResult<T> = Result<Json<T>, ApiError>;

pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/health", get(health))
        .route("/login", post(auth::login))
        .route("/logout", post(auth::logout))
        .route("/me", get(auth::me))
        .route("/me/password", post(auth::change_password))
        .route("/status", get(status))
        .route("/targets", get(targets).post(create_target))
        .route("/targets/{name}", put(update_target).delete(delete_target))
        .route("/targets/{name}/clients", get(target_clients))
        .route("/targets/{name}/discover", post(discover_target))
        .route("/targets/{name}/trust-server", post(trust_server))
        .route("/discover", post(discover_url))
        .route("/certificates", get(certificates))
        .route("/certificates/own/cert.der", get(own_certificate_der))
        .route("/certificates/own", post(import_own))
        .route("/certificates/own/regenerate", post(regenerate_own))
        .route(
            "/certificates/rejected/{thumbprint}/trust",
            post(trust_rejected),
        )
        .route(
            "/certificates/rejected/{thumbprint}",
            delete(delete_rejected),
        )
        .route("/certificates/trusted/{thumbprint}/untrust", post(untrust))
        .route("/audit", get(audit_query))
        .route("/audit.csv", get(audit_csv))
        .route("/audit/verify", get(audit_verify))
        .route("/users", get(list_users).post(create_user))
        .route("/users/{name}", put(update_user).delete(delete_user))
        .route("/browser/{target}/connect", post(browser::connect))
        .route("/browser/{target}/disconnect", post(browser::disconnect))
        .route("/browser/{target}/browse", get(browser::browse))
        .route("/browser/{target}/attributes", get(browser::attributes))
        .route("/browser/{target}/values", post(browser::values));

    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/style.css", get(style_css))
        .nest("/api", api)
        .layer(axum::middleware::from_fn(auth::csrf))
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, "DENY".parse().expect("valid"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().expect("valid"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        "no-referrer".parse().expect("valid"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
            .parse()
            .expect("valid"),
    );
    response
}

async fn index() -> Html<&'static str> {
    Html(include_str!("ui/index.html"))
}

async fn app_js() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("ui/app.js"),
    )
}

async fn style_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("ui/style.css"),
    )
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    application_name: String,
    application_uri: String,
    certificate: Option<CertificateInfo>,
    lost_audit_events: u64,
    fail_mode: crate::config::FailMode,
    record_old_value: bool,
    retention_days: u32,
    rejected_certificates: usize,
    targets: Vec<TargetView>,
}

#[derive(Serialize)]
struct TargetView {
    #[serde(flatten)]
    config: TargetConfig,
    status: Option<TargetStatus>,
    clients: Vec<ClientInfo>,
}

async fn target_views(s: &AppState) -> Vec<TargetView> {
    let statuses = s.statuses.read().await.clone();
    let mut views = Vec::new();
    for config in s.targets.targets().await {
        let clients = match s.targets.relay(&config.name).await {
            Some(r) => r.clients(),
            None => Vec::new(),
        };
        views.push(TargetView {
            status: statuses.get(&config.name).cloned(),
            config,
            clients,
        });
    }
    views
}

async fn status(State(s): State<AppState>, user: AuthUser) -> ApiResult<StatusResponse> {
    user.require(Role::Auditor)?;
    Ok(Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        application_name: s.config.gateway.application_name.clone(),
        application_uri: s.config.gateway.application_uri(),
        certificate: s
            .pki
            .own_certificate()
            .ok()
            .map(|c| CertificateInfo::from_x509(&c)),
        lost_audit_events: s.audit.lost_events(),
        fail_mode: s.config.audit.fail_mode,
        record_old_value: s.config.audit.record_old_value,
        retention_days: s.config.audit.retention_days,
        rejected_certificates: s.pki.rejected().len(),
        targets: target_views(&s).await,
    }))
}

async fn targets(State(s): State<AppState>, user: AuthUser) -> ApiResult<Vec<TargetView>> {
    user.require(Role::Auditor)?;
    Ok(Json(target_views(&s).await))
}

async fn create_target(
    State(s): State<AppState>,
    user: AuthUser,
    Json(target): Json<TargetConfig>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    let summary = format!(
        "added target '{}' ({} -> {})",
        target.name, target.listen, target.endpoint_url
    );
    s.targets
        .upsert(target, None)
        .await
        .map_err(ApiError::bad_request)?;
    s.config_changed(&user, summary).await;
    Ok(StatusCode::CREATED)
}

async fn update_target(
    State(s): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
    Json(target): Json<TargetConfig>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    let summary = format!(
        "changed target '{name}' to '{}' ({} -> {})",
        target.name, target.listen, target.endpoint_url
    );
    s.targets
        .upsert(target, Some(&name))
        .await
        .map_err(ApiError::bad_request)?;
    s.config_changed(&user, summary).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_target(
    State(s): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    s.targets
        .remove(&name)
        .await
        .map_err(ApiError::bad_request)?;
    s.config_changed(&user, format!("removed target '{name}'"))
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn target_clients(
    State(s): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
) -> ApiResult<Vec<ClientInfo>> {
    user.require(Role::Auditor)?;
    s.targets
        .relay(&name)
        .await
        .map(|r| Json(r.clients()))
        .ok_or_else(|| ApiError::not_found(format!("unknown target '{name}'")))
}

async fn target_url(s: &AppState, name: &str) -> Result<String, ApiError> {
    s.targets
        .targets()
        .await
        .into_iter()
        .find(|t| t.name == name)
        .map(|t| t.endpoint_url)
        .ok_or_else(|| ApiError::not_found(format!("unknown target '{name}'")))
}

async fn discover_target(
    State(s): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
) -> ApiResult<Vec<EndpointInfo>> {
    user.require(Role::Operator)?;
    let url = target_url(&s, &name).await?;
    discovery::discover(&s.client, &url)
        .await
        .map(Json)
        .map_err(ApiError::upstream)
}

/// Trusts the certificate the target presents in GetEndpoints.
async fn trust_server(
    State(s): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
) -> ApiResult<CertificateInfo> {
    user.require(Role::Admin)?;
    let url = target_url(&s, &name).await?;
    let endpoints = discovery::discover_raw(&s.client, &url)
        .await
        .map_err(ApiError::upstream)?;
    let cert = endpoints
        .iter()
        .find_map(|e| X509::from_byte_string(&e.server_certificate).ok())
        .ok_or_else(|| {
            ApiError::bad_request(anyhow::anyhow!("the target presents no certificate"))
        })?;
    let info = s.pki.trust(&cert)?;
    s.config_changed(
        &user,
        format!(
            "trusted server certificate {} [{}] of target '{name}'",
            info.subject, info.thumbprint
        ),
    )
    .await;
    Ok(Json(info))
}

#[derive(Deserialize)]
struct DiscoverRequest {
    endpoint_url: String,
}

/// Discovery of any URL, so the UI can inspect a server before adding it.
async fn discover_url(
    State(s): State<AppState>,
    user: AuthUser,
    Json(req): Json<DiscoverRequest>,
) -> ApiResult<Vec<EndpointInfo>> {
    user.require(Role::Operator)?;
    if !req.endpoint_url.starts_with("opc.tcp://") {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "endpoint_url must start with opc.tcp://".into(),
        ));
    }
    discovery::discover(&s.client, &req.endpoint_url)
        .await
        .map(Json)
        .map_err(ApiError::upstream)
}

#[derive(Serialize)]
struct CertificatesResponse {
    own: Option<CertificateInfo>,
    trusted: Vec<CertificateInfo>,
    rejected: Vec<CertificateInfo>,
}

async fn certificates(
    State(s): State<AppState>,
    user: AuthUser,
) -> ApiResult<CertificatesResponse> {
    user.require(Role::Auditor)?;
    Ok(Json(CertificatesResponse {
        own: s
            .pki
            .own_certificate()
            .ok()
            .map(|c| CertificateInfo::from_x509(&c)),
        trusted: s.pki.trusted(),
        rejected: s.pki.rejected(),
    }))
}

async fn own_certificate_der(
    State(s): State<AppState>,
    user: AuthUser,
) -> Result<Response, ApiError> {
    user.require(Role::Auditor)?;
    let der = s.pki.own_certificate_der()?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/pkix-cert"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"opcua-audit-gateway.der\"",
            ),
        ],
        der,
    )
        .into_response())
}

#[derive(Deserialize)]
struct ImportRequest {
    /// Certificate, DER or PEM, base64 encoded.
    certificate: String,
    /// Private key, PEM, base64 encoded.
    private_key: String,
}

async fn import_own(
    State(s): State<AppState>,
    user: AuthUser,
    Json(req): Json<ImportRequest>,
) -> ApiResult<CertificateInfo> {
    use base64::Engine;
    user.require(Role::Admin)?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let cert = b64
        .decode(req.certificate.trim())
        .map_err(|e| ApiError::bad_request(anyhow::anyhow!("certificate: {e}")))?;
    let key = b64
        .decode(req.private_key.trim())
        .map_err(|e| ApiError::bad_request(anyhow::anyhow!("private key: {e}")))?;
    let cert = s
        .pki
        .import_own(&cert, &key)
        .map_err(ApiError::bad_request)?;
    let info = CertificateInfo::from_x509(&cert);
    s.targets.restart_all().await;
    s.config_changed(
        &user,
        format!(
            "imported gateway certificate {} [{}]",
            info.subject, info.thumbprint
        ),
    )
    .await;
    Ok(Json(info))
}

async fn regenerate_own(State(s): State<AppState>, user: AuthUser) -> ApiResult<CertificateInfo> {
    user.require(Role::Admin)?;
    let cert = s.pki.regenerate_own(&s.config.gateway)?;
    let info = CertificateInfo::from_x509(&cert);
    s.targets.restart_all().await;
    s.config_changed(
        &user,
        format!(
            "generated new gateway certificate {} [{}]",
            info.subject, info.thumbprint
        ),
    )
    .await;
    Ok(Json(info))
}

async fn trust_rejected(
    State(s): State<AppState>,
    user: AuthUser,
    Path(thumbprint): Path<String>,
) -> ApiResult<CertificateInfo> {
    user.require(Role::Admin)?;
    let info = s
        .pki
        .trust_rejected(&thumbprint)
        .map_err(ApiError::bad_request)?;
    s.config_changed(
        &user,
        format!("trusted certificate {} [{}]", info.subject, info.thumbprint),
    )
    .await;
    Ok(Json(info))
}

async fn delete_rejected(
    State(s): State<AppState>,
    user: AuthUser,
    Path(thumbprint): Path<String>,
) -> ApiResult<CertificateInfo> {
    user.require(Role::Admin)?;
    let info = s
        .pki
        .delete_rejected(&thumbprint)
        .map_err(ApiError::bad_request)?;
    s.config_changed(
        &user,
        format!(
            "deleted rejected certificate {} [{}]",
            info.subject, info.thumbprint
        ),
    )
    .await;
    Ok(Json(info))
}

async fn untrust(
    State(s): State<AppState>,
    user: AuthUser,
    Path(thumbprint): Path<String>,
) -> ApiResult<CertificateInfo> {
    user.require(Role::Admin)?;
    let info = s.pki.untrust(&thumbprint).map_err(ApiError::bad_request)?;
    s.config_changed(
        &user,
        format!(
            "revoked trust in certificate {} [{}]",
            info.subject, info.thumbprint
        ),
    )
    .await;
    Ok(Json(info))
}

async fn audit_query(
    State(s): State<AppState>,
    user: AuthUser,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Vec<StoredRecord>> {
    user.require(Role::Auditor)?;
    Ok(Json(s.reader.query(q).await?))
}

/// The filtered audit trail as CSV, newest first (up to 100 000 records).
async fn audit_csv(
    State(s): State<AppState>,
    user: AuthUser,
    Query(mut q): Query<AuditQuery>,
) -> Result<Response, ApiError> {
    user.require(Role::Auditor)?;
    let mut out = String::from(
        "seq,time,target,event,client_address,client_application,user,node_id,display_name,old_value,new_value,status,details,hash\n",
    );
    let mut total = 0;
    q.limit = Some(1000);
    loop {
        let page = s.reader.query(q.clone()).await?;
        let Some(last) = page.last() else { break };
        q.before_seq = Some(last.seq);
        for record in &page {
            out.push_str(&csv_row(record));
        }
        total += page.len();
        if page.len() < 1000 || total >= 100_000 {
            break;
        }
    }
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"audit-trail.csv\"",
            ),
        ],
        Body::from(out),
    )
        .into_response())
}

fn csv_field(value: &str) -> String {
    // Quote everything; neutralise spreadsheet formulas.
    let value = if value.starts_with(['=', '+', '-', '@']) {
        format!("'{value}")
    } else {
        value.to_string()
    };
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn csv_row(record: &StoredRecord) -> String {
    let entry = &record.entry;
    let client = entry.client.as_ref();
    let event = serde_json::to_value(&entry.event).unwrap_or_default();
    let get = |key: &str| -> String {
        match event.get(key) {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Object(o)) if o.contains_key("value") => o["value"].to_string(),
            Some(v) => v.to_string(),
        }
    };
    let fields = [
        record.seq.to_string(),
        entry.ts.to_rfc3339(),
        entry.target.clone().unwrap_or_default(),
        entry.event.kind().to_string(),
        client.map(|c| c.remote_addr.clone()).unwrap_or_default(),
        client
            .and_then(|c| c.application_name.clone().or(c.application_uri.clone()))
            .unwrap_or_default(),
        client
            .and_then(|c| c.user.as_ref().map(|u| u.label()))
            .unwrap_or_default(),
        entry.event.node_id().unwrap_or_default().to_string(),
        get("display_name"),
        get("old_value"),
        get("new_value"),
        get("status"),
        event.to_string(),
        record.hash.clone(),
    ];
    let mut line = fields
        .iter()
        .map(|f| csv_field(f))
        .collect::<Vec<_>>()
        .join(",");
    line.push('\n');
    line
}

async fn audit_verify(State(s): State<AppState>, user: AuthUser) -> ApiResult<VerifyReport> {
    user.require(Role::Auditor)?;
    Ok(Json(s.reader.verify().await?))
}

async fn list_users(State(s): State<AppState>, user: AuthUser) -> ApiResult<Vec<User>> {
    user.require(Role::Admin)?;
    Ok(Json(s.users.list()?))
}

#[derive(Deserialize)]
struct NewUser {
    username: String,
    password: String,
    role: Role,
}

async fn create_user(
    State(s): State<AppState>,
    user: AuthUser,
    Json(req): Json<NewUser>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    let users = s.users.clone();
    let (name, role) = (req.username.clone(), req.role);
    tokio::task::spawn_blocking(move || users.create(&req.username, &req.password, req.role))
        .await
        .map_err(|e| anyhow::anyhow!(e))?
        .map_err(ApiError::bad_request)?;
    s.config_changed(&user, format!("created user '{name}' ({})", role.as_str()))
        .await;
    Ok(StatusCode::CREATED)
}

#[derive(Deserialize)]
struct UserUpdate {
    role: Option<Role>,
    password: Option<String>,
}

async fn update_user(
    State(s): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
    Json(req): Json<UserUpdate>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    let mut changes = Vec::new();
    if let Some(role) = req.role {
        s.users
            .set_role(&name, role)
            .map_err(ApiError::bad_request)?;
        changes.push(format!("role {}", role.as_str()));
    }
    if let Some(password) = req.password {
        let users = s.users.clone();
        let n = name.clone();
        tokio::task::spawn_blocking(move || users.set_password(&n, &password))
            .await
            .map_err(|e| anyhow::anyhow!(e))?
            .map_err(ApiError::bad_request)?;
        changes.push("password reset".into());
    }
    s.sessions.remove_user(&name);
    s.config_changed(
        &user,
        format!("changed user '{name}': {}", changes.join(", ")),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_user(
    State(s): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    s.users.delete(&name).map_err(ApiError::bad_request)?;
    s.sessions.remove_user(&name);
    s.config_changed(&user, format!("deleted user '{name}'"))
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
