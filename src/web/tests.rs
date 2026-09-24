//! API tests against a test OPC UA server.

use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use super::auth::{CSRF_HEADER, CSRF_VALUE};
use super::{router, AppState};
use crate::audit::AuditReader;
use crate::config::{Config, EXAMPLE_CONFIG};
use crate::discovery;
use crate::pki::Pki;
use crate::targets::TargetManager;
use crate::testutil::{free_port, start_test_plc, TestPlc};
use crate::users::{Role, UserStore};

struct Web {
    app: Router,
    plc: TestPlc,
    config_path: PathBuf,
    pki_dir: PathBuf,
    _dir: tempfile::TempDir,
}

async fn web() -> Web {
    let dir = tempfile::tempdir().unwrap();
    let plc = start_test_plc(dir.path()).await;
    let config_path = dir.path().join("config.toml");
    std::fs::write(&config_path, EXAMPLE_CONFIG).unwrap();
    let config = Config::load(&config_path).unwrap();
    let pki = Pki::open(&config.gateway.pki_dir).unwrap();
    pki.ensure_own_certificate(&config.gateway).unwrap();

    let db = config.audit_database();
    let audit = crate::audit::start(&db, &config.audit).unwrap();
    let users = UserStore::open(&config.gateway.data_dir.join("gateway.db")).unwrap();
    users
        .create("admin", "admin-password", Role::Admin)
        .unwrap();
    users
        .create("operator", "operator-password", Role::Operator)
        .unwrap();
    users
        .create("auditor", "auditor-password", Role::Auditor)
        .unwrap();

    let statuses = discovery::initial_statuses(&config);
    let client = Arc::new(discovery::discovery_client(&config).unwrap());
    let targets = Arc::new(TargetManager::new(
        config_path.clone(),
        config.clone(),
        statuses.clone(),
        client.clone(),
        audit.clone(),
    ));
    let state = AppState {
        config: Arc::new(config.clone()),
        targets,
        statuses,
        audit,
        reader: AuditReader::new(&db),
        client,
        pki: Arc::new(pki),
        users: Arc::new(users),
        sessions: Default::default(),
        browser: Default::default(),
        exports: Default::default(),
    };
    Web {
        app: router(state),
        plc,
        config_path,
        pki_dir: config.gateway.pki_dir.clone(),
        _dir: dir,
    }
}

impl Web {
    async fn send(
        &self,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value, Option<String>) {
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header(CSRF_HEADER, CSRF_VALUE);
        if let Some(c) = cookie {
            request = request.header(header::COOKIE, c);
        }
        let request = match body {
            Some(b) => request
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string())),
            None => request.body(Body::empty()),
        }
        .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let set_cookie = response
            .headers()
            .get(header::SET_COOKIE)
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string());
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
        (status, value, set_cookie)
    }

    async fn login(&self, user: &str) -> String {
        let (status, _, cookie) = self
            .send(
                Method::POST,
                "/api/login",
                None,
                Some(json!({ "username": user, "password": format!("{user}-password") })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        cookie.unwrap()
    }

    async fn get(&self, uri: &str, cookie: &str) -> (StatusCode, Value) {
        let (s, v, _) = self.send(Method::GET, uri, Some(cookie), None).await;
        (s, v)
    }

    async fn post(&self, uri: &str, cookie: &str, body: Value) -> (StatusCode, Value) {
        let (s, v, _) = self.send(Method::POST, uri, Some(cookie), Some(body)).await;
        (s, v)
    }

    async fn add_target(&self, cookie: &str) -> StatusCode {
        self.post(
            "/api/targets",
            cookie,
            json!({
                "name": "plc1",
                "listen": format!("127.0.0.1:{}", free_port()),
                "endpoint_url": self.plc.url,
            }),
        )
        .await
        .0
    }
}

#[tokio::test]
async fn login_and_roles() {
    let w = web().await;
    let (status, _, _) = w.send(Method::GET, "/api/status", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _, cookie) = w
        .send(
            Method::POST,
            "/api/login",
            None,
            Some(json!({ "username": "admin", "password": "wrong" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(cookie.is_none());

    let auditor = w.login("auditor").await;
    let (status, me) = w.get("/api/me", &auditor).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["role"], "auditor");
    assert_eq!(w.get("/api/status", &auditor).await.0, StatusCode::OK);
    assert_eq!(w.add_target(&auditor).await, StatusCode::FORBIDDEN);
    assert_eq!(w.get("/api/users", &auditor).await.0, StatusCode::FORBIDDEN);

    let admin = w.login("admin").await;
    assert_eq!(w.add_target(&admin).await, StatusCode::CREATED);
    let (_, targets) = w.get("/api/targets", &auditor).await;
    assert_eq!(targets[0]["name"], "plc1");
    let saved = Config::load(&w.config_path).unwrap();
    assert_eq!(saved.targets[0].endpoint_url, w.plc.url);

    // Logins and the change are in the audit trail.
    let (_, failed) = w.get("/api/audit?kind=ui_login_failed", &auditor).await;
    assert_eq!(failed[0]["event"]["user"], "admin");
    let (_, changes) = w.get("/api/audit?kind=config_changed", &auditor).await;
    assert!(changes[0]["event"]["summary"]
        .as_str()
        .unwrap()
        .contains("added target 'plc1'"));

    // Logout ends the session.
    let (status, _, _) = w
        .send(Method::POST, "/api/logout", Some(&auditor), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(w.get("/api/me", &auditor).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn state_changes_need_the_csrf_header() {
    let w = web().await;
    let admin = w.login("admin").await;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/api/logout")
        .header(header::COOKIE, &admin)
        .body(Body::empty())
        .unwrap();
    let response = w.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn certificate_trust_flow() {
    let w = web().await;
    let admin = w.login("admin").await;
    // A client certificate lands in rejected, as the relay would do.
    let rejected = opcua::crypto::CertificateStore::new(&w.pki_dir).rejected_certs_dir();
    std::fs::copy(&w.plc.certificate, rejected.join("client.der")).unwrap();

    let (_, certs) = w.get("/api/certificates", &admin).await;
    let thumb = certs["rejected"][0]["thumbprint"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _) = w
        .post(
            &format!("/api/certificates/rejected/{thumb}/trust"),
            &admin,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, certs) = w.get("/api/certificates", &admin).await;
    assert_eq!(certs["trusted"][0]["thumbprint"], thumb);
    assert!(certs["rejected"].as_array().unwrap().is_empty());

    let (status, _) = w
        .post(
            &format!("/api/certificates/trusted/{thumb}/untrust"),
            &admin,
            json!({}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let (_, certs) = w.get("/api/certificates", &admin).await;
    assert_eq!(certs["rejected"][0]["thumbprint"], thumb);

    let (status, der, _) = w
        .send(
            Method::GET,
            "/api/certificates/own/cert.der",
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!der.as_str().unwrap_or_default().is_empty());
}

#[tokio::test]
async fn browser_needs_operator_and_reads_the_address_space() {
    let w = web().await;
    let admin = w.login("admin").await;
    assert_eq!(w.add_target(&admin).await, StatusCode::CREATED);
    // Trust the PLC straight from discovery.
    let (status, cert) = w
        .post("/api/targets/plc1/trust-server", &admin, json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{cert}");

    let auditor = w.login("auditor").await;
    let (status, _) = w
        .post("/api/browser/plc1/connect", &auditor, json!({}))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let operator = w.login("operator").await;
    let (status, connected) = w
        .post(
            "/api/browser/plc1/connect",
            &operator,
            json!({ "username": "operator", "password": "secret" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{connected}");
    assert_ne!(connected["security_policy"], "None");

    let (status, items) = w.get("/api/browser/plc1/browse", &operator).await;
    assert_eq!(status, StatusCode::OK, "{items}");
    let setpoint = items
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["display_name"] == "Setpoint")
        .expect("Setpoint in the Objects folder");
    let node = setpoint["node_id"].as_str().unwrap();

    let (status, attributes) = w
        .get(
            &format!("/api/browser/plc1/attributes?node={}", urlencode(node)),
            &operator,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{attributes}");
    assert!(attributes
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["attribute"] == "Value" && a["value"]["value"] == json!(0.0)));

    let (status, values) = w
        .post(
            "/api/browser/plc1/values",
            &operator,
            json!({ "nodes": [node] }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(values[0]["value"]["data_type"], "Double");

    let (_, sessions) = w.get("/api/audit?kind=session_created", &admin).await;
    assert_eq!(sessions[0]["client"]["user"]["name"], "ui:operator");
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[tokio::test]
async fn csv_export() {
    let w = web().await;
    let auditor = w.login("auditor").await;
    let (status, csv, _) = w
        .send(Method::GET, "/api/audit.csv", Some(&auditor), None)
        .await;
    assert_eq!(status, StatusCode::OK);
    let csv = csv.as_str().unwrap();
    assert!(csv.starts_with("seq,time,target,event"));
    assert!(csv.contains("\"ui_login\""));
}

#[tokio::test]
async fn user_management() {
    let w = web().await;
    let admin = w.login("admin").await;
    let (status, _) = w
        .post(
            "/api/users",
            &admin,
            json!({ "username": "jens", "password": "jens-password", "role": "auditor" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let jens = w.login("jens").await;

    // Changing a user's role ends their sessions.
    let (status, _, _) = w
        .send(
            Method::PUT,
            "/api/users/jens",
            Some(&admin),
            Some(json!({ "role": "operator" })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(w.get("/api/me", &jens).await.0, StatusCode::UNAUTHORIZED);

    // The last admin cannot be removed.
    let (status, _, _) = w
        .send(Method::DELETE, "/api/users/admin", Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (_, users) = w.get("/api/users", &admin).await;
    assert_eq!(users.as_array().unwrap().len(), 4);
}
