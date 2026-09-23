//! REST API (and, later, the embedded web UI).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use opcua::client::Client;
use serde::{Deserialize, Serialize};

use crate::audit::store::{AuditQuery, StoredRecord, VerifyReport};
use crate::audit::{AuditHandle, AuditReader};
use crate::config::Config;
use crate::discovery::{self, EndpointInfo, TargetStatus, TargetStatuses};
use crate::pki::{CertificateInfo, Pki};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub statuses: TargetStatuses,
    pub audit: AuditHandle,
    pub reader: AuditReader,
    pub client: Arc<Client>,
    pub pki: Arc<Pki>,
}

pub struct ApiError(StatusCode, String);

impl ApiError {
    fn not_found(what: impl Into<String>) -> Self {
        Self(StatusCode::NOT_FOUND, what.into())
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

type ApiResult<T> = Result<Json<T>, ApiError>;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/health", get(health))
        .route("/api/status", get(status))
        .route("/api/targets", get(targets))
        .route("/api/targets/{name}/discover", post(discover_target))
        .route("/api/discover", post(discover_url))
        .route("/api/certificates", get(certificates))
        .route("/api/audit", get(audit_query))
        .route("/api/audit/verify", get(audit_verify))
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("web/index.html"))
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
    targets: Vec<TargetStatus>,
}

async fn status(State(s): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        application_name: s.config.gateway.application_name.clone(),
        application_uri: s.config.gateway.application_uri(),
        certificate: s
            .pki
            .own_certificate()
            .ok()
            .map(|c| CertificateInfo::from_x509(&c)),
        lost_audit_events: s.audit.lost_events(),
        targets: s.statuses.read().await.values().cloned().collect(),
    })
}

async fn targets(State(s): State<AppState>) -> Json<Vec<TargetStatus>> {
    Json(s.statuses.read().await.values().cloned().collect())
}

async fn discover_target(
    State(s): State<AppState>,
    Path(name): Path<String>,
) -> ApiResult<Vec<EndpointInfo>> {
    let target = s
        .config
        .target(&name)
        .ok_or_else(|| ApiError::not_found(format!("unknown target '{name}'")))?;
    discovery::discover(&s.client, &target.endpoint_url)
        .await
        .map(Json)
        .map_err(ApiError::upstream)
}

#[derive(Deserialize)]
struct DiscoverRequest {
    endpoint_url: String,
}

/// Discovery of an arbitrary URL, so the UI can inspect a server before it is
/// added as a target.
async fn discover_url(
    State(s): State<AppState>,
    Json(req): Json<DiscoverRequest>,
) -> ApiResult<Vec<EndpointInfo>> {
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

async fn certificates(State(s): State<AppState>) -> Json<CertificatesResponse> {
    Json(CertificatesResponse {
        own: s
            .pki
            .own_certificate()
            .ok()
            .map(|c| CertificateInfo::from_x509(&c)),
        trusted: s.pki.trusted(),
        rejected: s.pki.rejected(),
    })
}

async fn audit_query(
    State(s): State<AppState>,
    Query(q): Query<AuditQuery>,
) -> ApiResult<Vec<StoredRecord>> {
    Ok(Json(s.reader.query(q).await?))
}

async fn audit_verify(State(s): State<AppState>) -> ApiResult<VerifyReport> {
    Ok(Json(s.reader.verify().await?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEntry, AuditEvent};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    async fn state(dir: &std::path::Path) -> AppState {
        let mut config = Config::default();
        config.gateway.pki_dir = dir.join("pki");
        let pki = Pki::open(&config.gateway.pki_dir).unwrap();
        let db = dir.join("audit.db");
        let audit = crate::audit::start(&db, &config.audit).unwrap();
        audit
            .record_committed(AuditEntry::new(AuditEvent::GatewayStarted {
                version: "test".into(),
            }))
            .await
            .unwrap();
        AppState {
            statuses: discovery::initial_statuses(&config),
            client: Arc::new(discovery::discovery_client(&config).unwrap()),
            config: Arc::new(config),
            audit,
            reader: AuditReader::new(&db),
            pki: Arc::new(pki),
        }
    }

    async fn get_json(app: Router, uri: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .oneshot(Request::get(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn audit_endpoints() {
        let dir = tempfile::tempdir().unwrap();
        let app = router(state(dir.path()).await);

        let (code, body) = get_json(app.clone(), "/api/audit?kind=gateway_started").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body[0]["event"]["type"], "gateway_started");
        assert_eq!(body[0]["seq"], 1);

        let (code, body) = get_json(app, "/api/audit/verify").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["records"], 1);
        assert!(body["error"].is_null());
    }

    #[tokio::test]
    async fn unknown_target_is_404() {
        let dir = tempfile::tempdir().unwrap();
        let app = router(state(dir.path()).await);
        let resp = app
            .oneshot(
                Request::post("/api/targets/nope/discover")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
