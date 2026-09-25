//! Web UI and REST API.
//!
//! Every API route except `/api/health` and `/api/login` needs a logged-in
//! user. Roles are cumulative: auditor (read) < operator (browser, discovery)
//! < admin (configuration, certificates, users).

pub mod auth;
pub mod browser;
mod mcp;
mod settings;
pub mod tls;

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
use crate::config::{Config, IgnoreRule, TargetConfig};
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
    pub exports: Arc<crate::export::Exports>,
    /// The certificate the web server presents (DER); `None` without HTTPS.
    pub web_certificate: Option<Arc<Vec<u8>>>,
}

impl AppState {
    /// Records a configuration change made through the UI.
    async fn config_changed(&self, user: &AuthUser, summary: String) {
        tracing::info!(user = %user.actor(), "{summary}");
        let _ = self
            .audit
            .record_committed(AuditEntry::new(AuditEvent::ConfigChanged {
                by: user.actor(),
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
        .route("/me/tokens", get(list_tokens).post(create_token))
        .route("/me/tokens/{id}", delete(delete_token))
        .route("/tokens", get(all_tokens))
        .route("/users/{name}/tokens/{id}", delete(revoke_token))
        .route("/status", get(status))
        .route("/targets", get(targets).post(create_target))
        .route("/targets/{name}", put(update_target).delete(delete_target))
        .route("/targets/{name}/clients", get(target_clients))
        .route("/targets/{name}/discover", post(discover_target))
        .route("/targets/{name}/trust-server", post(trust_server))
        .route("/targets/{name}/ignore", post(ignore_node))
        .route("/targets/{name}/ignore/remove", post(unignore_node))
        .route("/discover", post(discover_url))
        .route("/certificates", get(certificates))
        .route("/certificates/own/cert.der", get(own_certificate_der))
        .route("/certificates/own/cert.pem", get(own_certificate_pem))
        .route("/web-certificate/cert.pem", get(web_certificate_pem))
        .route("/web-certificate/cert.der", get(web_certificate_der))
        .route(
            "/web-certificate/regenerate",
            post(regenerate_web_certificate),
        )
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
        .route("/audit/most-written", get(audit_most_written))
        .route("/alarms", get(alarms))
        .route("/alarms/acknowledge", post(acknowledge_alarms))
        .route("/settings", get(settings::get))
        .route("/settings/audit", put(settings::put_audit))
        .route("/settings/export", put(settings::put_export))
        .route("/settings/gateway", put(settings::put_gateway))
        .route("/settings/mcp", put(settings::put_mcp))
        .route("/users", get(list_users).post(create_user))
        .route("/users/{name}", put(update_user).delete(delete_user))
        .route("/browser/{target}/connect", post(browser::connect))
        .route("/browser/{target}/disconnect", post(browser::disconnect))
        .route("/browser/{target}/browse", get(browser::browse))
        .route("/browser/{target}/attributes", get(browser::attributes))
        .route("/browser/{target}/values", post(browser::values));

    Router::new()
        .route("/", get(index))
        .route("/js/{*path}", get(script))
        .route("/style.css", get(style_css))
        .route("/favicon.svg", get(favicon))
        .route("/fonts/{file}", get(font))
        .nest("/api", api)
        // For AI assistants: API tokens, not the session cookie.
        .route(
            "/mcp",
            post(mcp::post)
                .get(mcp::not_allowed)
                .delete(mcp::not_allowed),
        )
        .layer(axum::middleware::from_fn(auth::csrf))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security_headers,
        ))
        .with_state(state)
}

/// The host name of a Host header, without the port.
fn host_name(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port)) if port.chars().all(|c| c.is_ascii_digit()) && !name.ends_with(':') => {
            name
        }
        _ => host,
    }
}

/// Whether a Host header names this machine's loopback interface.
fn is_loopback_host(host: &str) -> bool {
    matches!(host_name(host), "localhost" | "127.0.0.1" | "[::1]")
}

/// Whether the UI answers to this Host header. On loopback only loopback
/// names; elsewhere also IP addresses, this machine's names, the gateway's
/// `certificate_hostnames` and `[web] allowed_hosts`. Any other name could
/// be a DNS rebinding page that resolves to this address.
fn host_allowed(host: &str, loopback: bool, names: &[String]) -> bool {
    if is_loopback_host(host) {
        return true;
    }
    if loopback {
        return false;
    }
    let name = host_name(host).to_ascii_lowercase();
    let ip = name.trim_start_matches('[').trim_end_matches(']');
    !name.is_empty()
        && (ip.parse::<std::net::IpAddr>().is_ok()
            || names.iter().any(|n| n.eq_ignore_ascii_case(&name)))
}

async fn security_headers(
    State(s): State<AppState>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // Only known host names: a web page on another site cannot reach the UI
    // through a DNS name that resolves to its address (DNS rebinding).
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .or_else(|| request.uri().authority().map(|a| a.as_str()))
        .unwrap_or("")
        .to_string();
    let loopback = s.config.web.listen.ip().is_loopback();
    let mut names = s.config.web.allowed_hosts.clone();
    if !loopback {
        names.extend(s.targets.config().await.gateway.certificate_hostnames);
        names.extend(opcua::crypto::X509Data::computer_hostnames());
    }
    if !host_allowed(&host, loopback, &names) {
        return ApiError(StatusCode::MISDIRECTED_REQUEST, "unknown host name".into())
            .into_response();
    }
    let path = request.uri().path();
    let api = path.starts_with("/api/") || path == "/mcp";
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    if api {
        // Audit records, users and certificates must not stay in caches.
        headers.insert(header::CACHE_CONTROL, "no-store".parse().expect("valid"));
    } else if !headers.contains_key(header::CACHE_CONTROL) {
        // The UI is embedded in the binary: after an upgrade the browser
        // must check again instead of running the old scripts.
        headers.insert(header::CACHE_CONTROL, "no-cache".parse().expect("valid"));
    }
    // Not with the gateway's own certificate: browsers do not trust it, and
    // with HSTS they no longer let the user accept it.
    if s.config.web.tls && s.config.web.tls_certificate.is_some() {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            "max-age=31536000".parse().expect("valid"),
        );
    }
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
        "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; \
         base-uri 'none'; form-action 'self'"
            .parse()
            .expect("valid"),
    );
    response
}

/// The page, pointing at this build's scripts and styles: their URLs carry a
/// hash of the UI, so a browser never runs an older version after an
/// upgrade (a relative import in a module keeps the versioned folder).
async fn index() -> Html<String> {
    let v = ui_version();
    Html(
        include_str!("ui/index.html")
            .replace("/js/main.js", &format!("/js/{v}/main.js"))
            .replace("/style.css", &format!("/style.css?v={v}")),
    )
}

/// A short hash of every embedded script and the stylesheet.
fn ui_version() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(|| {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        for (name, source) in SCRIPTS {
            hash.update(name.as_bytes());
            hash.update(source.as_bytes());
        }
        hash.update(include_str!("ui/style.css").as_bytes());
        hex::encode(&hash.finalize()[..6])
    })
}

/// The UI's JavaScript modules (`ui/js/`, see ARCHITECTURE.md), by their path
/// under `/js/`. A new module must be added here.
const SCRIPTS: &[(&str, &str)] = &[
    ("main.js", include_str!("ui/js/main.js")),
    ("html.js", include_str!("ui/js/html.js")),
    ("api.js", include_str!("ui/js/api.js")),
    ("state.js", include_str!("ui/js/state.js")),
    ("format.js", include_str!("ui/js/format.js")),
    ("components.js", include_str!("ui/js/components.js")),
    ("ignore.js", include_str!("ui/js/ignore.js")),
    ("alarms.js", include_str!("ui/js/alarms.js")),
    ("pages/account.js", include_str!("ui/js/pages/account.js")),
    ("pages/audit.js", include_str!("ui/js/pages/audit.js")),
    ("pages/browser.js", include_str!("ui/js/pages/browser.js")),
    (
        "pages/certificates.js",
        include_str!("ui/js/pages/certificates.js"),
    ),
    (
        "pages/dashboard.js",
        include_str!("ui/js/pages/dashboard.js"),
    ),
    ("pages/settings.js", include_str!("ui/js/pages/settings.js")),
    ("pages/targets.js", include_str!("ui/js/pages/targets.js")),
    ("pages/users.js", include_str!("ui/js/pages/users.js")),
];

/// `/js/<version>/<module>`: cached for good, since a new build has a new
/// version. `/js/<module>` (no version) is still served, not cached.
async fn script(Path(path): Path<String>) -> Response {
    let (path, versioned) = match path.split_once('/') {
        Some((v, rest)) if v == ui_version() => (rest.to_string(), true),
        _ => (path, false),
    };
    match SCRIPTS.iter().find(|(name, _)| *name == path) {
        Some((_, source)) => {
            let cache = if versioned {
                "public, max-age=31536000, immutable"
            } else {
                "no-cache"
            };
            (
                [
                    (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
                    (header::CACHE_CONTROL, cache),
                ],
                *source,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn style_css() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("ui/style.css"),
    )
}

async fn favicon() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "image/svg+xml")],
        include_str!("ui/favicon.svg"),
    )
}

/// Inter (SIL Open Font License, `ui/fonts/OFL.txt`), served from the binary so
/// the UI needs no internet access.
async fn font(Path(file): Path<String>) -> Response {
    let bytes: &'static [u8] = match file.as_str() {
        "inter-latin.woff2" => include_bytes!("ui/fonts/inter-latin.woff2"),
        "inter-latin-ext.woff2" => include_bytes!("ui/fonts/inter-latin-ext.woff2"),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, "font/woff2"),
            (header::CACHE_CONTROL, "public, max-age=604800"),
        ],
        bytes,
    )
        .into_response()
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    /// Hash of the embedded UI: an open page that has another one reloads.
    ui_version: &'static str,
    application_name: String,
    application_uri: String,
    certificate: Option<CertificateInfo>,
    lost_audit_events: u64,
    fail_mode: crate::config::FailMode,
    record_old_value: bool,
    retention_days: u32,
    ignored_summary_secs: u64,
    rejected_certificates: usize,
    exports: Vec<crate::export::ExportStatus>,
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
    // Copy out first: the lock must not be held across the awaits below.
    let exports = s.exports.statuses().read().values().cloned().collect();
    Ok(Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        ui_version: ui_version(),
        application_name: s.config.gateway.application_name.clone(),
        application_uri: s.config.gateway.application_uri(),
        certificate: s
            .pki
            .own_certificate()
            .ok()
            .map(|c| CertificateInfo::from_x509(&c)),
        lost_audit_events: s.audit.lost_events(),
        fail_mode: s.audit.settings().fail_mode(),
        record_old_value: s.audit.settings().record_old_value(),
        retention_days: s.audit.settings().retention_days(),
        ignored_summary_secs: s.audit.settings().ignored_summary().as_secs(),
        rejected_certificates: s.pki.rejected_count(),
        exports,
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
    Json(mut target): Json<TargetConfig>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    // Ignored nodes have their own routes; editing a target keeps them.
    let old = target_config(&s, &name).await?;
    target.ignore = old.ignore.clone();
    let summary = target_changes(&old, &target);
    s.targets
        .upsert(target, Some(&name))
        .await
        .map_err(ApiError::bad_request)?;
    s.browser.close_target(&s, &name).await;
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
    s.browser.close_target(&s, &name).await;
    s.config_changed(&user, format!("removed target '{name}'"))
        .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn target_config(s: &AppState, name: &str) -> Result<TargetConfig, ApiError> {
    s.targets
        .targets()
        .await
        .into_iter()
        .find(|t| t.name == name)
        .ok_or_else(|| ApiError::not_found(format!("unknown target '{name}'")))
}

fn describe_rule(rule: &IgnoreRule) -> String {
    let node = match &rule.name {
        Some(name) => format!("{name} ({})", rule.node_id),
        None => rule.node_id.clone(),
    };
    match &rule.client {
        Some(client) => format!("{node} from {client}"),
        None => node,
    }
}

/// Summarises a node's value writes instead of recording each one.
async fn ignore_node(
    State(s): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
    Json(mut rule): Json<IgnoreRule>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    rule.node_id = rule.node_id.trim().to_string();
    rule.client = rule
        .client
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty());
    rule.name = rule
        .name
        .map(|n| crate::audit::event::clip(n.trim(), crate::audit::event::MAX_NAME))
        .filter(|n| !n.is_empty());
    let mut rules = target_config(&s, &name).await?.ignore;
    if rules.iter().any(|r| r.same(&rule)) {
        return Ok(StatusCode::NO_CONTENT);
    }
    let summary = format!(
        "target '{name}': writes to {} are summarised instead of recorded",
        describe_rule(&rule)
    );
    rules.push(rule);
    s.targets
        .set_ignore(&name, rules)
        .await
        .map_err(ApiError::bad_request)?;
    s.config_changed(&user, summary).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn unignore_node(
    State(s): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
    Json(rule): Json<IgnoreRule>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    let mut rules = target_config(&s, &name).await?.ignore;
    let before = rules.len();
    rules.retain(|r| !r.same(&rule));
    if rules.len() == before {
        return Err(ApiError::not_found(format!(
            "{} is not ignored on '{name}'",
            describe_rule(&rule)
        )));
    }
    s.targets
        .set_ignore(&name, rules)
        .await
        .map_err(ApiError::bad_request)?;
    s.config_changed(
        &user,
        format!(
            "target '{name}': writes to {} are recorded again",
            describe_rule(&rule)
        ),
    )
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
    let result = discovery::discover_raw(&s.client, &url).await;
    // "Check now": the target's status (availability, endpoints) and whether
    // it accepts the gateway are updated at once, not at the next interval.
    let relay = s.targets.relay(&name).await;
    let endpoints = match &result {
        Ok(raw) => Ok(raw.iter().map(EndpointInfo::from).collect()),
        Err(e) => Err(anyhow::anyhow!("{e:#}")),
    };
    if let Some(relay) = relay {
        discovery::apply_discovery(&relay.config, &s.statuses, &s.audit, result).await;
        relay.check_gateway_trust().await;
    }
    endpoints.map(Json).map_err(ApiError::upstream)
}

#[derive(Deserialize)]
struct TrustServerRequest {
    /// The thumbprint the admin reviewed: only that certificate is trusted.
    thumbprint: String,
}

/// Trusts the certificate the target presents in GetEndpoints, if it is the
/// one with the reviewed thumbprint.
async fn trust_server(
    State(s): State<AppState>,
    user: AuthUser,
    Path(name): Path<String>,
    Json(req): Json<TrustServerRequest>,
) -> ApiResult<CertificateInfo> {
    user.require(Role::Admin)?;
    let url = target_url(&s, &name).await?;
    let endpoints = discovery::discover_raw(&s.client, &url)
        .await
        .map_err(ApiError::upstream)?;
    let cert = endpoints
        .iter()
        .filter_map(|e| X509::from_byte_string(&e.server_certificate).ok())
        .find(|c| {
            c.thumbprint()
                .as_hex_string()
                .eq_ignore_ascii_case(req.thumbprint.trim())
        })
        .ok_or_else(|| {
            ApiError::bad_request(anyhow::anyhow!(
                "the target does not present the certificate {} (any more); discover it again",
                req.thumbprint
            ))
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
    // Now the gateway can check whether the target accepts it.
    if let Some(relay) = s.targets.relay(&name).await {
        relay.check_gateway_trust().await;
    }
    Ok(Json(info))
}

#[derive(Deserialize)]
struct DiscoverRequest {
    endpoint_url: String,
}

/// Discovery of any URL, so the UI can inspect a server before adding it.
/// Admins only, and recorded: it makes the gateway connect anywhere.
async fn discover_url(
    State(s): State<AppState>,
    user: AuthUser,
    Json(req): Json<DiscoverRequest>,
) -> ApiResult<Vec<EndpointInfo>> {
    user.require(Role::Admin)?;
    if !req.endpoint_url.starts_with("opc.tcp://") {
        return Err(ApiError(
            StatusCode::BAD_REQUEST,
            "endpoint_url must start with opc.tcp://".into(),
        ));
    }
    let _ = s
        .audit
        .record_committed(AuditEntry::new(AuditEvent::Discovery {
            by: user.actor(),
            endpoint_url: crate::audit::event::clip(&req.endpoint_url, 1024),
        }))
        .await;
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

/// The same certificate as PEM, for OPC UA clients that want that format.
async fn own_certificate_pem(
    State(s): State<AppState>,
    user: AuthUser,
) -> Result<Response, ApiError> {
    user.require(Role::Auditor)?;
    let der = s.pki.own_certificate_der()?;
    Ok(certificate_file(&der, "opcua-audit-gateway", true))
}

/// A certificate as a download, DER or PEM.
fn certificate_file(der: &[u8], name: &str, pem: bool) -> Response {
    if !pem {
        return (
            [
                (header::CONTENT_TYPE, "application/pkix-cert".to_string()),
                (
                    header::CONTENT_DISPOSITION,
                    format!("attachment; filename=\"{name}.der\""),
                ),
            ],
            der.to_vec(),
        )
            .into_response();
    }
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut text = String::from("-----BEGIN CERTIFICATE-----\n");
    for line in b64.as_bytes().chunks(64) {
        text.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
        text.push('\n');
    }
    text.push_str("-----END CERTIFICATE-----\n");
    (
        [
            (header::CONTENT_TYPE, "application/x-pem-file".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}.pem\""),
            ),
        ],
        text,
    )
        .into_response()
}

/// The web UI's own HTTPS certificate: what browsers, the operating system
/// and Node (NODE_EXTRA_CA_CERTS) import to trust it.
async fn web_certificate(s: &AppState, user: &AuthUser, pem: bool) -> Result<Response, ApiError> {
    user.require(Role::Auditor)?;
    // The one the server presents: after Regenerate that is still the old
    // one until the restart, and with configured PEM files it is theirs.
    let der = s
        .web_certificate
        .as_ref()
        .ok_or_else(|| ApiError::not_found("the web UI does not use HTTPS"))?;
    Ok(certificate_file(der, "opcua-audit-gateway-web", pem))
}

async fn web_certificate_pem(
    State(s): State<AppState>,
    user: AuthUser,
) -> Result<Response, ApiError> {
    web_certificate(&s, &user, true).await
}

async fn web_certificate_der(
    State(s): State<AppState>,
    user: AuthUser,
) -> Result<Response, ApiError> {
    web_certificate(&s, &user, false).await
}

/// A new web UI certificate, e.g. after adding host names. The web server
/// uses it from the next start.
async fn regenerate_web_certificate(
    State(s): State<AppState>,
    user: AuthUser,
) -> ApiResult<CertificateInfo> {
    user.require(Role::Admin)?;
    let config = s.targets.config().await;
    // RSA key generation takes a while: not on the async runtime.
    let cert = tokio::task::spawn_blocking(move || tls::regenerate_web_certificate(&config))
        .await
        .map_err(|e| anyhow::anyhow!(e))??;
    let info = CertificateInfo::from_x509(&cert);
    s.config_changed(
        &user,
        format!(
            "generated a new web UI certificate [{}] (used after a restart)",
            info.thumbprint
        ),
    )
    .await;
    Ok(Json(info))
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
        .import_own(&cert, &key, &s.targets.config().await.gateway)
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
    let cert = s.pki.regenerate_own(&s.targets.config().await.gateway)?;
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
    s.targets.recheck_trust().await;
    // Open browser sessions were set up with the old trust.
    s.browser.close_all(&s).await;
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

/// Warnings and errors that nobody has acknowledged yet, per severity.
async fn alarms(
    State(s): State<AppState>,
    user: AuthUser,
) -> ApiResult<Vec<crate::audit::store::AlarmCount>> {
    user.require(Role::Auditor)?;
    Ok(Json(s.reader.alarms().await?))
}

#[derive(Deserialize)]
struct AcknowledgeRequest {
    severity: crate::audit::event::Severity,
}

/// Acknowledges every record of a severity up to now. The acknowledgement
/// is itself a record in the trail: who, which severity, up to where.
async fn acknowledge_alarms(
    State(s): State<AppState>,
    user: AuthUser,
    Json(req): Json<AcknowledgeRequest>,
) -> ApiResult<Vec<crate::audit::store::AlarmCount>> {
    user.require(Role::Operator)?;
    s.audit.flush().await;
    let current = s.reader.alarms().await?;
    let count = current
        .iter()
        .find(|a| a.severity == req.severity)
        .map_or(0, |a| a.unacknowledged);
    if count > 0 {
        let up_to_seq = s.reader.head_seq().await?;
        s.audit
            .record_committed(AuditEntry::new(AuditEvent::AlarmsAcknowledged {
                by: user.username.clone(),
                severity: req.severity,
                up_to_seq,
                count: count as u64,
            }))
            .await
            .map_err(|e| ApiError::from(anyhow::anyhow!("{e}")))?;
    }
    Ok(Json(s.reader.alarms().await?))
}

#[derive(Deserialize)]
struct MostWrittenQuery {
    /// Look back this many hours (default 24, at most a year).
    hours: Option<u32>,
}

/// The nodes written most often recently: what floods the audit trail.
async fn audit_most_written(
    State(s): State<AppState>,
    user: AuthUser,
    Query(q): Query<MostWrittenQuery>,
) -> ApiResult<Vec<crate::audit::store::WrittenNode>> {
    user.require(Role::Auditor)?;
    let hours = q.hours.unwrap_or(24).clamp(1, 24 * 366);
    let since = chrono::Utc::now() - chrono::Duration::hours(hours.into());
    Ok(Json(s.reader.most_written(since, 10).await?))
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

/// What an edit of a target changed, e.g.
/// `changed target 'plc1': endpoint opc.tcp://a:4840 -> opc.tcp://b:4840`.
fn target_changes(old: &TargetConfig, new: &TargetConfig) -> String {
    let mut changes = Vec::new();
    let mut diff = |what: &str, a: String, b: String| {
        if a != b {
            changes.push(format!("{what} {a} -> {b}"));
        }
    };
    diff("name", old.name.clone(), new.name.clone());
    diff("listen", old.listen.to_string(), new.listen.to_string());
    diff(
        "endpoint",
        old.endpoint_url.clone(),
        new.endpoint_url.clone(),
    );
    diff(
        "minimum security",
        format!("{:?}", old.min_security),
        format!("{:?}", new.min_security),
    );
    diff(
        "discovery every",
        format!("{} s", old.discovery_interval_secs),
        format!("{} s", new.discovery_interval_secs),
    );
    diff(
        "max connections",
        old.max_connections.to_string(),
        new.max_connections.to_string(),
    );
    diff(
        "max connections per address",
        old.max_connections_per_address.to_string(),
        new.max_connections_per_address.to_string(),
    );
    if changes.is_empty() {
        format!("saved target '{}' unchanged", old.name)
    } else {
        format!("changed target '{}': {}", old.name, changes.join(", "))
    }
}

#[test]
fn target_changes_name_only_what_changed() {
    let old: TargetConfig = toml::from_str(
        r#"name = "plc1"
listen = "0.0.0.0:4841"
endpoint_url = "opc.tcp://a:4840""#,
    )
    .unwrap();
    let mut new = old.clone();
    assert_eq!(target_changes(&old, &new), "saved target 'plc1' unchanged");
    new.endpoint_url = "opc.tcp://b:4840".into();
    assert_eq!(
        target_changes(&old, &new),
        "changed target 'plc1': endpoint opc.tcp://a:4840 -> opc.tcp://b:4840"
    );
}

fn csv_field(value: &str) -> String {
    // Quote everything; neutralise spreadsheet formulas, but leave numbers
    // (-3.5) as they are.
    let value =
        if value.starts_with(['=', '+', '-', '@', '\t', '\r']) && value.parse::<f64>().is_err() {
            format!("'{value}")
        } else {
            value.to_string()
        };
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn csv_row(record: &StoredRecord) -> String {
    let f = crate::export::fields(record);
    // The sequence number is a plain number; everything else is quoted.
    let fields = [
        record.entry.ts.to_rfc3339(),
        f.target,
        f.kind.to_string(),
        f.client_address,
        f.client_application,
        f.user,
        f.node_id,
        f.display_name,
        f.old_value,
        f.new_value,
        f.status,
        f.event_json,
        record.hash.clone(),
    ];
    let mut line = std::iter::once(record.seq.to_string())
        .chain(fields.iter().map(|f| csv_field(f)))
        .collect::<Vec<_>>()
        .join(",");
    line.push('\n');
    line
}

async fn audit_verify(State(s): State<AppState>, user: AuthUser) -> ApiResult<VerifyReport> {
    user.require(Role::Auditor)?;
    // The records exported last must still be in the trail, unchanged.
    let anchors = crate::export::anchors_from(&s.config.gateway.data_dir.join("export-state.json"));
    Ok(Json(s.reader.verify_against(anchors).await?))
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
    // The admin chose the password: the user replaces it at the first login.
    tokio::task::spawn_blocking(move || {
        users.create_with(&req.username, &req.password, req.role, true)
    })
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
    // All or nothing; a reset password must be replaced at the next login.
    let users = s.users.clone();
    let n = name.clone();
    let new_password = req.password.is_some();
    let changes = tokio::task::spawn_blocking(move || {
        users.update(&n, req.role, req.password.as_deref(), true)
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))?
    .map_err(ApiError::bad_request)?;
    s.sessions.remove_user(&name);
    if new_password || req.role.is_some_and(|r| r < Role::Operator) {
        s.browser.close_user(&s, &name).await;
    }
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
    s.browser.close_user(&s, &name).await;
    s.config_changed(&user, format!("deleted user '{name}'"))
        .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Every user's API tokens (admins): to see and revoke them.
async fn all_tokens(
    State(s): State<AppState>,
    user: AuthUser,
) -> ApiResult<Vec<crate::users::UserToken>> {
    user.require(Role::Admin)?;
    Ok(Json(s.users.all_tokens()?))
}

/// Revokes any user's API token (admins).
async fn revoke_token(
    State(s): State<AppState>,
    user: AuthUser,
    Path((name, id)): Path<(String, String)>,
) -> Result<StatusCode, ApiError> {
    user.require(Role::Admin)?;
    let token = s
        .users
        .delete_token(&name, &id)
        .map_err(|e| ApiError::not_found(format!("{e:#}")))?;
    s.config_changed(
        &user,
        format!("revoked API token '{token}' ({id}) of user '{name}'"),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// The logged-in user's API tokens (for the MCP endpoint).
async fn list_tokens(
    State(s): State<AppState>,
    user: AuthUser,
) -> ApiResult<Vec<crate::users::ApiToken>> {
    Ok(Json(s.users.tokens(&user.username)?))
}

#[derive(Deserialize)]
struct NewToken {
    name: String,
    /// What the token may change through MCP; empty: read only.
    #[serde(default)]
    scopes: Vec<String>,
}

/// Creates a token; its secret is in this answer only.
async fn create_token(
    State(s): State<AppState>,
    user: AuthUser,
    Json(req): Json<NewToken>,
) -> ApiResult<crate::users::NewApiToken> {
    // Changes need an admin, like in the web UI.
    for scope in &req.scopes {
        user.require(crate::config::mcp_scope_role(scope))?;
    }
    let token = s
        .users
        .create_token(&user.username, &req.name, &req.scopes)
        .map_err(ApiError::bad_request)?;
    let access = if token.token.scopes.is_empty() {
        "read only".to_string()
    } else {
        format!("may change {}", token.token.scopes.join(", "))
    };
    s.config_changed(
        &user,
        format!(
            "created API token '{}' ({}, {access})",
            token.token.name, token.token.id
        ),
    )
    .await;
    Ok(Json(token))
}

async fn delete_token(
    State(s): State<AppState>,
    user: AuthUser,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let name = s
        .users
        .delete_token(&user.username, &id)
        .map_err(|e| ApiError::not_found(format!("{e:#}")))?;
    s.config_changed(&user, format!("deleted API token '{name}' ({id})"))
        .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests;
