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
    let exports = crate::export::Exports::start(
        &Default::default(),
        AuditReader::new(&db),
        audit.clone(),
        &config.gateway.data_dir.join("export-state.json"),
    )
    .unwrap();
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
        exports,
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
            .header(header::HOST, "127.0.0.1:8080")
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
        .header(header::HOST, "127.0.0.1")
        .header(header::COOKIE, &admin)
        .body(Body::empty())
        .unwrap();
    let response = w.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn ui_assets_are_embedded() {
    let w = web().await;
    for (uri, status, content_type) in [
        ("/", StatusCode::OK, "text/html; charset=utf-8"),
        ("/favicon.svg", StatusCode::OK, "image/svg+xml"),
        ("/fonts/inter-latin.woff2", StatusCode::OK, "font/woff2"),
        ("/fonts/inter-latin-ext.woff2", StatusCode::OK, "font/woff2"),
        (
            "/js/main.js",
            StatusCode::OK,
            "text/javascript; charset=utf-8",
        ),
        (
            "/js/pages/audit.js",
            StatusCode::OK,
            "text/javascript; charset=utf-8",
        ),
    ] {
        let request = Request::get(uri)
            .header(header::HOST, "localhost:8080")
            .body(Body::empty())
            .unwrap();
        let response = w.app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), status, "{uri}");
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            content_type,
            "{uri}"
        );
    }
    for uri in ["/fonts/other.woff2", "/js/other.js", "/app.js"] {
        let request = Request::get(uri)
            .header(header::HOST, "localhost")
            .body(Body::empty())
            .unwrap();
        let response = w.app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

/// Every module in `ui/js/` is embedded: a module missing from the table in
/// mod.rs would only fail in the browser.
#[tokio::test]
async fn every_ui_module_is_served() {
    fn modules(dir: &std::path::Path, prefix: &str, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            if entry.file_type().unwrap().is_dir() {
                modules(&entry.path(), &format!("{prefix}{name}/"), out);
            } else if name.ends_with(".js") {
                out.push(format!("{prefix}{name}"));
            }
        }
    }
    let mut found = Vec::new();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/web/ui/js");
    modules(&dir, "", &mut found);
    assert!(found.len() > 1);
    let w = web().await;
    for module in found {
        let request = Request::get(format!("/js/{module}"))
            .header(header::HOST, "localhost")
            .body(Body::empty())
            .unwrap();
        let response = w.app.clone().oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{module}");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let on_disk = std::fs::read(dir.join(&module)).unwrap();
        assert_eq!(body.as_ref(), on_disk.as_slice(), "{module}");
    }
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
    // Trust the PLC straight from discovery: only the certificate with the
    // thumbprint the admin reviewed (audit finding W5).
    let (status, endpoints) = w
        .post("/api/targets/plc1/discover", &admin, json!({}))
        .await;
    assert_eq!(status, StatusCode::OK, "{endpoints}");
    let thumbprint = endpoints[0]["server_certificate"]["thumbprint"]
        .as_str()
        .unwrap()
        .to_string();
    let (status, _) = w
        .post(
            "/api/targets/plc1/trust-server",
            &admin,
            json!({ "thumbprint": "00".repeat(20) }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, cert) = w
        .post(
            "/api/targets/plc1/trust-server",
            &admin,
            json!({ "thumbprint": thumbprint }),
        )
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

/// A forced change needs no current password (the user just logged in with
/// it); any other change does.
#[tokio::test]
async fn own_password_change() {
    let w = web().await;
    let operator = w.login("operator").await;
    let (status, _) = w
        .post(
            "/api/me/password",
            &operator,
            json!({ "new": "new-password" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let admin = w.login("admin").await;
    let (status, _, _) = w
        .send(
            Method::PUT,
            "/api/users/operator",
            Some(&admin),
            Some(json!({ "password": "reset-password" })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, cookie) = w
        .send(
            Method::POST,
            "/api/login",
            None,
            Some(json!({ "username": "operator", "password": "reset-password" })),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let operator = cookie.unwrap();
    let (status, _, cookie) = w
        .send(
            Method::POST,
            "/api/me/password",
            Some(&operator),
            Some(json!({ "new": "new-password" })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, me) = w.get("/api/me", &cookie.unwrap()).await;
    assert_eq!(me["must_change_password"], false);
}

#[tokio::test]
async fn ignore_list_is_admin_only_audited_and_kept_on_edit() {
    let w = web().await;
    let admin = w.login("admin").await;
    let operator = w.login("operator").await;
    assert_eq!(w.add_target(&admin).await, StatusCode::CREATED);
    let life = json!({ "node_id": " ns=3;s=\"DB1\".\"Life\" ", "client": "" });

    let (status, _) = w
        .post("/api/targets/plc1/ignore", &operator, life.clone())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _) = w
        .post("/api/targets/plc1/ignore", &admin, life.clone())
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Adding it again changes nothing; an invalid node id is refused.
    let (status, _) = w
        .post("/api/targets/plc1/ignore", &admin, life.clone())
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = w
        .post(
            "/api/targets/plc1/ignore",
            &admin,
            json!({ "node_id": "nonsense" }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Trimmed, the empty client dropped; saved in the config file.
    let (_, targets) = w.get("/api/targets", &operator).await;
    assert_eq!(
        targets[0]["ignore"],
        json!([{ "node_id": "ns=3;s=\"DB1\".\"Life\"" }])
    );
    assert_eq!(
        Config::load(&w.config_path).unwrap().targets[0]
            .ignore
            .len(),
        1
    );

    // Editing the target in the form keeps the ignored nodes.
    let mut edited = targets[0].clone();
    for key in ["ignore", "status", "clients"] {
        edited.as_object_mut().unwrap().remove(key);
    }
    edited["discovery_interval_secs"] = json!(30);
    let (status, _, _) = w
        .send(Method::PUT, "/api/targets/plc1", Some(&admin), Some(edited))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, targets) = w.get("/api/targets", &operator).await;
    assert_eq!(targets[0]["ignore"].as_array().unwrap().len(), 1);

    let rule = json!({ "node_id": "ns=3;s=\"DB1\".\"Life\"" });
    let (status, _) = w
        .post("/api/targets/plc1/ignore/remove", &admin, rule.clone())
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = w
        .post("/api/targets/plc1/ignore/remove", &admin, rule)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, targets) = w.get("/api/targets", &operator).await;
    assert!(targets[0].get("ignore").is_none());

    let (_, changes) = w.get("/api/audit?kind=config_changed", &admin).await;
    let summaries: Vec<&str> = changes
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["event"]["summary"].as_str().unwrap())
        .collect();
    assert!(summaries[0].contains("recorded again"), "{summaries:?}");
    assert!(summaries
        .iter()
        .any(|s| s.contains("summarised instead of recorded")));

    let (status, top) = w.get("/api/audit/most-written?hours=1", &operator).await;
    assert_eq!(status, StatusCode::OK);
    assert!(top.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn settings_are_saved_applied_and_keep_secrets() {
    let w = web().await;
    let admin = w.login("admin").await;
    let auditor = w.login("auditor").await;

    let (status, settings) = w.get("/api/settings", &auditor).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(settings["audit"]["retention_days"], 365);
    assert!(settings["export"]["questdb"].is_null());

    let audit = json!({
        "retention_days": 30,
        "fail_mode": "closed",
        "record_old_value": false,
        "ignored_summary_secs": 600
    });
    let (status, _, _) = w
        .send(
            Method::PUT,
            "/api/settings/audit",
            Some(&auditor),
            Some(audit.clone()),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = w
        .send(
            Method::PUT,
            "/api/settings/audit",
            Some(&admin),
            Some(audit),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Applied at once, saved, and the rest of the file is untouched.
    let (_, status_view) = w.get("/api/status", &auditor).await;
    assert_eq!(status_view["retention_days"], 30);
    assert_eq!(status_view["fail_mode"], "closed");
    assert_eq!(status_view["ignored_summary_secs"], 600);
    let saved = Config::load(&w.config_path).unwrap();
    assert_eq!(saved.audit.retention_days, 30);
    assert!(!saved.audit.record_old_value);
    assert!(std::fs::read_to_string(&w.config_path)
        .unwrap()
        .contains("# OPC UA Audit Gateway configuration."));

    // Export: the token is stored but never shown; an absent secret keeps
    // it, an empty one removes it.
    let questdb = |token: Option<&str>| {
        let mut q = json!({
            "url": "http://127.0.0.1:1/",
            "table": "audit",
            "interval_secs": 5
        });
        if let Some(t) = token {
            q["token"] = json!(t);
        }
        json!({ "questdb": q })
    };
    let (status, _, _) = w
        .send(
            Method::PUT,
            "/api/settings/export",
            Some(&admin),
            Some(questdb(Some("s3cret"))),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, settings) = w.get("/api/settings", &auditor).await;
    assert_eq!(settings["export"]["questdb"]["url"], "http://127.0.0.1:1");
    assert_eq!(settings["export"]["questdb"]["token_set"], true);
    assert!(!settings.to_string().contains("s3cret"));
    let (_, status_view) = w.get("/api/status", &auditor).await;
    assert_eq!(status_view["exports"][0]["name"], "questdb");

    w.send(
        Method::PUT,
        "/api/settings/export",
        Some(&admin),
        Some(questdb(None)),
    )
    .await;
    let saved = Config::load(&w.config_path).unwrap();
    assert_eq!(
        saved.export.questdb.unwrap().token.as_deref(),
        Some("s3cret")
    );
    w.send(
        Method::PUT,
        "/api/settings/export",
        Some(&admin),
        Some(questdb(Some(""))),
    )
    .await;
    assert!(Config::load(&w.config_path)
        .unwrap()
        .export
        .questdb
        .unwrap()
        .token
        .is_none());

    // A bad destination changes nothing.
    let (status, _, _) = w
        .send(
            Method::PUT,
            "/api/settings/export",
            Some(&admin),
            Some(json!({ "questdb": { "url": "ftp://x", "table": "t", "interval_secs": 5 } })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(Config::load(&w.config_path)
        .unwrap()
        .export
        .questdb
        .is_some());

    // Turning export off stops the exporter.
    w.send(
        Method::PUT,
        "/api/settings/export",
        Some(&admin),
        Some(json!({})),
    )
    .await;
    assert!(Config::load(&w.config_path)
        .unwrap()
        .export
        .questdb
        .is_none());
    let (_, status_view) = w.get("/api/status", &auditor).await;
    assert!(status_view["exports"].as_array().unwrap().is_empty());

    let (status, _, _) = w
        .send(
            Method::PUT,
            "/api/settings/gateway",
            Some(&admin),
            Some(json!({ "certificate_hostnames": ["gw.local", " 10.0.0.2 ", ""] })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        Config::load(&w.config_path)
            .unwrap()
            .gateway
            .certificate_hostnames,
        ["gw.local", "10.0.0.2"]
    );
    let (status, _, _) = w
        .send(
            Method::PUT,
            "/api/settings/gateway",
            Some(&admin),
            Some(json!({ "certificate_hostnames": ["not a host"] })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // Every change is audited, without the secret.
    let (_, changes) = w.get("/api/audit?kind=config_changed", &admin).await;
    let text = changes.to_string();
    assert!(text.contains("retention 365 days -> 30 days"), "{text}");
    assert!(text.contains("QuestDB export to http://127.0.0.1:1 (table audit) turned on"));
    assert!(text.contains("certificate host names: gw.local, 10.0.0.2"));
    assert!(!text.contains("s3cret"));
}

#[tokio::test]
async fn warnings_and_errors_until_acknowledged() {
    let w = web().await;
    let admin = w.login("admin").await;
    let auditor = w.login("auditor").await;
    let operator = w.login("operator").await;
    // Two failed logins: warnings.
    for _ in 0..2 {
        w.send(
            Method::POST,
            "/api/login",
            None,
            Some(json!({ "username": "admin", "password": "wrong" })),
        )
        .await;
    }
    let count = |alarms: &Value, severity: &str| {
        alarms
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["severity"] == severity)
            .unwrap()["unacknowledged"]
            .as_i64()
            .unwrap()
    };
    let (_, alarms) = w.get("/api/alarms", &auditor).await;
    assert_eq!(count(&alarms, "warning"), 2);
    assert_eq!(count(&alarms, "error"), 0);

    // "Show": the unacknowledged warnings, by their kinds and position.
    let warning = alarms
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["severity"] == "warning")
        .unwrap();
    let kinds: Vec<&str> = warning["kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k.as_str().unwrap())
        .collect();
    let (_, rows) = w
        .get(
            &format!(
                "/api/audit?kinds={}&after_seq={}",
                kinds.join(","),
                warning["acknowledged_up_to"]
            ),
            &auditor,
        )
        .await;
    assert_eq!(rows.as_array().unwrap().len(), 2);

    // Auditors only look; operators acknowledge, and that is recorded.
    let (status, _) = w
        .post(
            "/api/alarms/acknowledge",
            &auditor,
            json!({ "severity": "warning" }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, alarms) = w
        .post(
            "/api/alarms/acknowledge",
            &operator,
            json!({ "severity": "warning" }),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(count(&alarms, "warning"), 0);
    let (_, acks) = w.get("/api/audit?kind=alarms_acknowledged", &admin).await;
    assert_eq!(acks[0]["event"]["by"], "operator");
    assert_eq!(acks[0]["event"]["count"], 2);

    // A new warning after that counts again.
    w.send(
        Method::POST,
        "/api/login",
        None,
        Some(json!({ "username": "admin", "password": "wrong" })),
    )
    .await;
    let (_, alarms) = w.get("/api/alarms", &auditor).await;
    assert_eq!(count(&alarms, "warning"), 1);
}

impl Web {
    /// A JSON-RPC request to /mcp with a bearer token (no cookie, no CSRF
    /// header: MCP clients send neither).
    /// MCP is off until an admin turns it on.
    async fn enable_mcp(&self, on: bool) {
        let admin = self.login("admin").await;
        let (status, _, _) = self
            .send(
                Method::PUT,
                "/api/settings/mcp",
                Some(&admin),
                Some(json!({ "enabled": on })),
            )
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    async fn mcp(&self, token: &str, body: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/mcp")
            .header(header::HOST, "127.0.0.1:8080")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn mcp_tool(&self, token: &str, name: &str, arguments: Value) -> Value {
        let (status, answer) = self
            .mcp(
                token,
                json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["result"]["isError"], false, "{answer}");
        answer["result"]["structuredContent"].clone()
    }
}

#[tokio::test]
async fn mcp_reads_the_trail_with_a_token_and_records_every_call() {
    let w = web().await;
    let auditor = w.login("auditor").await;

    // Any role may create its own tokens; the secret is in this answer only.
    let (status, token) = w
        .post("/api/me/tokens", &auditor, json!({ "name": "Claude" }))
        .await;
    assert_eq!(status, StatusCode::OK);
    let secret = token["secret"].as_str().unwrap().to_string();
    assert!(secret.starts_with("gwt_"));
    let (_, list) = w.get("/api/me/tokens", &auditor).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(list[0].get("secret").is_none());

    // Off by default, for everyone.
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    assert_eq!(w.mcp(&secret, ping.clone()).await.0, StatusCode::NOT_FOUND);
    w.enable_mcp(true).await;
    assert_eq!(w.mcp(&secret, ping).await.0, StatusCode::OK);

    // No token, a wrong one, or only the session cookie: refused.
    assert_eq!(
        w.mcp("gwt_nope_nope", json!({})).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (status, _, _) = w
        .send(
            Method::POST,
            "/mcp",
            Some(&auditor),
            Some(json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Handshake, notification, tool list.
    let (status, init) = w
        .mcp(
            &secret,
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                   "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                              "clientInfo": {"name": "test", "version": "1"}}}),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    assert!(init["result"]["capabilities"]["tools"].is_object());
    let (status, _) = w
        .mcp(
            &secret,
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let (_, tools) = w
        .mcp(
            &secret,
            json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        )
        .await;
    let names: Vec<_> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"search_audit_trail"));
    assert!(names.contains(&"verify_audit_trail"));

    // The auditor's login is in the trail; the tools find it.
    let found = w
        .mcp_tool(
            &secret,
            "search_audit_trail",
            json!({"event": "ui_login", "user": "auditor"}),
        )
        .await;
    assert!(!found["records"].as_array().unwrap().is_empty(), "{found}");
    let status = w.mcp_tool(&secret, "gateway_status", json!({})).await;
    assert!(status["targets"].is_array());
    let verify = w.mcp_tool(&secret, "verify_audit_trail", json!({})).await;
    assert_eq!(verify["intact"], true);

    // A misspelt filter is refused instead of returning everything.
    let (_, wrong) = w
        .mcp(
            &secret,
            json!({"jsonrpc": "2.0", "id": 8, "method": "tools/call",
                   "params": {"name": "search_audit_trail", "arguments": {"kind": "write"}}}),
        )
        .await;
    assert_eq!(wrong["result"]["isError"], true, "{wrong}");

    // Every tool call is itself a record, with the token's user.
    let calls = w
        .mcp_tool(&secret, "search_audit_trail", json!({"event": "mcp_query"}))
        .await;
    let calls = calls["records"].as_array().unwrap();
    assert!(calls.len() >= 3, "{calls:?}");
    assert!(calls.iter().all(|r| r["event"]["by"] == "auditor"));

    // A deleted token no longer works.
    let id = token["id"].as_str().unwrap();
    let (status, _, _) = w
        .send(
            Method::DELETE,
            &format!("/api/me/tokens/{id}"),
            Some(&auditor),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        w.mcp(
            &secret,
            json!({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn mcp_tokens_end_with_their_user() {
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
    // A password an admin chose must be changed first, also for tokens.
    let (status, _) = w
        .post("/api/me/tokens", &jens, json!({ "name": "x" }))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, cookie) = w
        .send(
            Method::POST,
            "/api/me/password",
            Some(&jens),
            Some(json!({ "current": "jens-password", "new": "jens-password-2" })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let jens = cookie.unwrap();
    let (_, token) = w
        .post("/api/me/tokens", &jens, json!({ "name": "x" }))
        .await;
    let secret = token["secret"].as_str().unwrap().to_string();
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    w.enable_mcp(true).await;
    assert_eq!(w.mcp(&secret, ping.clone()).await.0, StatusCode::OK);

    // Audit finding S3: admins see every token and revoke any of them...
    let (_, second) = w
        .post("/api/me/tokens", &jens, json!({ "name": "y" }))
        .await;
    let second_secret = second["secret"].as_str().unwrap().to_string();
    let (status, _) = w.get("/api/tokens", &jens).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, all) = w.get("/api/tokens", &admin).await;
    assert_eq!(all.as_array().unwrap().len(), 2, "{all}");
    assert!(all.to_string().contains("\"username\":\"jens\""));
    assert!(!all.to_string().contains(&second_secret));
    let id = second["id"].as_str().unwrap();
    let (status, _, _) = w
        .send(
            Method::DELETE,
            &format!("/api/users/jens/tokens/{id}"),
            Some(&admin),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        w.mcp(&second_secret, ping.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, records) = w
        .get("/api/audit?kind=config_changed&limit=5", &admin)
        .await;
    assert!(
        records.to_string().contains("revoked API token"),
        "{records}"
    );

    // ...and a password reset by an admin deletes the user's tokens.
    let (status, _, _) = w
        .send(
            Method::PUT,
            "/api/users/jens",
            Some(&admin),
            Some(json!({ "password": "reset-password" })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(
        w.mcp(&secret, ping.clone()).await.0,
        StatusCode::UNAUTHORIZED
    );
    let (_, all) = w.get("/api/tokens", &admin).await;
    assert!(all.as_array().unwrap().is_empty(), "{all}");

    let (status, _, _) = w
        .send(Method::DELETE, "/api/users/jens", Some(&admin), None)
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

/// The token is a password: plain HTTP only on a loopback-only web UI.
#[test]
fn mcp_needs_https_off_loopback() {
    use crate::config::WebConfig;
    let web = |listen: &str, tls: bool| WebConfig {
        listen: listen.parse().unwrap(),
        tls,
        ..Default::default()
    };
    assert!(super::mcp::transport_is_safe(&web("127.0.0.1:8080", false)));
    assert!(!super::mcp::transport_is_safe(&web("0.0.0.0:8080", false)));
    assert!(super::mcp::transport_is_safe(&web("0.0.0.0:8080", true)));
}

/// Changes through MCP need both: the token was created with the scope, and
/// its user is an admin.
#[tokio::test]
async fn mcp_changes_need_token_scope_and_admin() {
    let w = web().await;
    let admin = w.login("admin").await;
    let (status, _, _) = w
        .send(
            Method::PUT,
            "/api/settings/mcp",
            Some(&admin),
            Some(json!({ "enabled": true })),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let token = |user: String, scopes: Value| {
        let w = &w;
        async move {
            let (status, t) = w
                .post(
                    "/api/me/tokens",
                    &user,
                    json!({ "name": "t", "scopes": scopes }),
                )
                .await;
            assert_eq!(status, StatusCode::OK, "{t}");
            t["secret"].as_str().unwrap().to_string()
        }
    };
    let names = |tools: Value| -> Vec<String> {
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    };
    let list = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});

    // Read only token: no change tools.
    let read = token(admin.clone(), json!([])).await;
    let tools = names(w.mcp(&read, list.clone()).await.1);
    assert!(!tools.contains(&"add_target".to_string()));

    // Targets only: the certificate tools are not there.
    let config = token(admin.clone(), json!(["targets"])).await;
    let tools = names(w.mcp(&config, list.clone()).await.1);
    assert!(tools.contains(&"add_target".to_string()));
    assert!(!tools.contains(&"trust_rejected_certificate".to_string()));
    let call = |name: &str, arguments: Value| {
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": name, "arguments": arguments}})
    };
    let (_, refused) = w
        .mcp(
            &config,
            call("trust_rejected_certificate", json!({"thumbprint": "00"})),
        )
        .await;
    assert!(refused["error"]["message"]
        .as_str()
        .unwrap()
        .contains("may not"));

    // A change goes through the same checks and is recorded as via MCP.
    let (_, added) = w
        .mcp(
            &config,
            call(
                "add_target",
                json!({"name": "plc9", "listen": format!("127.0.0.1:{}", free_port()),
                       "endpoint_url": w.plc.url}),
            ),
        )
        .await;
    assert_eq!(added["result"]["isError"], false, "{added}");
    let (_, updated) = w
        .mcp(
            &config,
            call(
                "update_target",
                json!({"name": "plc9", "min_security": "sign"}),
            ),
        )
        .await;
    assert_eq!(updated["result"]["isError"], false, "{updated}");
    let (_, targets) = w.get("/api/targets", &admin).await;
    let plc9 = targets
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["config"]["name"] == "plc9" || t["name"] == "plc9")
        .cloned()
        .unwrap_or_default();
    assert!(plc9.to_string().contains("sign"), "{targets}");
    let (_, records) = w
        .get("/api/audit?kind=config_changed&limit=5", &admin)
        .await;
    assert!(records.to_string().contains("via MCP"), "{records}");

    // A password never lands in the trail.
    let settings = token(admin.clone(), json!(["settings"])).await;
    let (_, _) = w
        .mcp(
            &settings,
            call(
                "update_export_settings",
                json!({"questdb": {"url": "http://127.0.0.1:1", "table": "t",
                                   "username": "u", "password": "secret-pass-1",
                                   "interval_secs": 5}}),
            ),
        )
        .await;
    let (_, queries) = w.get("/api/audit?kind=mcp_query&limit=50", &admin).await;
    assert!(queries.to_string().contains("update_export_settings"));
    assert!(!queries.to_string().contains("secret-pass-1"));

    // Audit finding S1: there is no users scope, and no user tools.
    let (status, _) = w
        .post(
            "/api/me/tokens",
            &admin,
            json!({ "name": "t", "scopes": ["users"] }),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let all = token(
        admin.clone(),
        json!(["targets", "certificates", "settings"]),
    )
    .await;
    let tools = names(w.mcp(&all, list.clone()).await.1);
    assert!(tools.iter().all(|t| !t.contains("user")), "{tools:?}");

    // Only an admin can give a token permissions.
    let auditor = w.login("auditor").await;
    let (status, _) = w
        .post(
            "/api/me/tokens",
            &auditor,
            json!({ "name": "t", "scopes": ["targets"] }),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

/// The gateway certificate as PEM, to trust the web UI's HTTPS.
#[tokio::test]
async fn own_certificate_as_pem() {
    let w = web().await;
    let auditor = w.login("auditor").await;
    let (status, pem) = w.get("/api/certificates/own/cert.pem", &auditor).await;
    assert_eq!(status, StatusCode::OK);
    let pem = pem.as_str().unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----\n"), "{pem}");
    assert!(pem.trim_end().ends_with("-----END CERTIFICATE-----"));
    assert!(pem.lines().all(|l| l.len() <= 64));
}

/// The page points at this build's scripts: a browser that cached an older
/// build's cannot run them after an upgrade.
#[tokio::test]
async fn scripts_have_versioned_urls() {
    let w = web().await;
    let get = |uri: String| {
        let app = w.app.clone();
        async move {
            let request = Request::get(uri)
                .header(header::HOST, "localhost:8080")
                .body(Body::empty())
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            let cache = response
                .headers()
                .get(header::CACHE_CONTROL)
                .map(|v| v.to_str().unwrap().to_string());
            let body = response.into_body().collect().await.unwrap().to_bytes();
            (cache, String::from_utf8_lossy(&body).to_string())
        }
    };
    let (cache, page) = get("/".into()).await;
    assert_eq!(cache.as_deref(), Some("no-cache"));
    let main = page
        .split('"')
        .find(|s| s.starts_with("/js/") && s.ends_with("/main.js"))
        .unwrap()
        .to_string();
    assert_ne!(main, "/js/main.js", "{page}");
    let (cache, source) = get(main.clone()).await;
    assert!(cache.unwrap().contains("immutable"));
    assert!(source.contains("import"));
    // A module imported relatively from it is in the same versioned folder.
    let (_, account) = get(main.replace("main.js", "pages/account.js")).await;
    assert!(account.contains("tokensCard"));
}

/// Audit finding S2: stored QuestDB credentials are not sent to a new server.
#[tokio::test]
async fn export_credentials_stay_with_their_server() {
    let w = web().await;
    let admin = w.login("admin").await;
    let put = |url: &str, password: Option<&str>| {
        let mut q = json!({"url": url, "table": "t", "username": "u", "interval_secs": 5});
        if let Some(p) = password {
            q["password"] = json!(p);
        }
        json!({ "questdb": q })
    };
    let send = |body: Value| {
        let (w, admin) = (&w, &admin);
        async move {
            let (status, v, _) = w
                .send(Method::PUT, "/api/settings/export", Some(admin), Some(body))
                .await;
            assert_eq!(status, StatusCode::NO_CONTENT, "{v}");
            let (_, settings) = w.get("/api/settings", admin).await;
            settings["export"]["questdb"]["password_set"] == true
        }
    };
    assert!(send(put("http://127.0.0.1:9000", Some("pw"))).await);
    // Same server, another table: kept.
    assert!(send(put("http://127.0.0.1:9000/", None)).await);
    // Another host: forgotten unless given again.
    assert!(!send(put("http://localhost:9000", None)).await);
    assert!(send(put("http://localhost:9000", Some("pw2"))).await);
    assert!(!send(put("http://localhost:9001", None)).await);
}

/// Audit finding S4: JSON-RPC batches are refused, an empty one included.
#[tokio::test]
async fn mcp_refuses_batches() {
    let w = web().await;
    w.enable_mcp(true).await;
    let admin = w.login("admin").await;
    let (_, token) = w
        .post("/api/me/tokens", &admin, json!({ "name": "t" }))
        .await;
    let secret = token["secret"].as_str().unwrap();
    let ping = json!({"jsonrpc": "2.0", "id": 1, "method": "ping"});
    for batch in [json!([]), json!([ping.clone(), ping.clone()])] {
        let (status, answer) = w.mcp(secret, batch).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["error"]["code"], -32600, "{answer}");
    }
    let (_, records) = w.get("/api/audit?kind=mcp_query", &admin).await;
    assert!(records.as_array().unwrap().is_empty());
    assert_eq!(w.mcp(secret, ping).await.0, StatusCode::OK);
}

/// Audit finding S5: off loopback the UI still only answers to known names.
#[test]
fn host_check_on_every_address() {
    use super::host_allowed;
    let names = vec!["gateway.local".to_string()];
    // Loopback listener: loopback names only.
    assert!(host_allowed("localhost:8080", true, &names));
    assert!(!host_allowed("gateway.local:8080", true, &names));
    assert!(!host_allowed("192.168.0.20:8080", true, &names));
    // Any other listener: also IP addresses and the configured names.
    assert!(host_allowed("127.0.0.1:8080", false, &names));
    assert!(host_allowed("192.168.0.20:8443", false, &names));
    assert!(host_allowed("[fe80::1]:8443", false, &names));
    assert!(host_allowed("Gateway.Local:8443", false, &names));
    assert!(host_allowed("gateway.local", false, &names));
    assert!(!host_allowed("attacker.example:8443", false, &names));
    assert!(!host_allowed("", false, &names));
}

/// Audit finding S6: while a password change is forced, only /me,
/// /me/password and /logout answer, not paths that merely end like them.
#[tokio::test]
async fn forced_change_allows_exact_paths_only() {
    let w = web().await;
    let admin = w.login("admin").await;
    let (status, _) = w
        .post(
            "/api/users",
            &admin,
            json!({ "username": "me", "password": "me-password", "role": "admin" }),
        )
        .await;
    assert_eq!(status, StatusCode::CREATED);
    let me = w.login("me").await;
    assert_eq!(w.get("/api/me", &me).await.0, StatusCode::OK);
    let (status, _, _) = w
        .send(
            Method::PUT,
            "/api/users/me",
            Some(&me),
            Some(json!({ "role": "auditor" })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = w
        .send(Method::DELETE, "/api/users/me", Some(&me), None)
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (_, users) = w.get("/api/users", &admin).await;
    assert!(users.to_string().contains("\"username\":\"me\""));
    let (status, _, _) = w.send(Method::POST, "/api/logout", Some(&me), None).await;
    assert!(status.is_success(), "{status}");
}

/// Audit finding S9: failures from elsewhere do not lock out the real user;
/// behind a trusted proxy the client's own address counts.
#[tokio::test]
async fn user_block_lets_the_right_password_in() {
    let w = web().await;
    let login = |password: &str| {
        let w = &w;
        let body = json!({ "username": "admin", "password": password });
        async move { w.send(Method::POST, "/api/login", None, Some(body)).await.0 }
    };
    for _ in 0..20 {
        assert_eq!(login("wrong-password").await, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(login("wrong-password").await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(login("admin-password").await, StatusCode::OK);
}

#[test]
fn forwarded_address_only_from_trusted_proxies() {
    use super::auth::client_address;
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    let proxy = [ip("10.0.0.1")];
    let xff = Some("203.0.113.9, 10.0.0.1");
    // Not from the proxy: the header is ignored.
    assert_eq!(
        client_address(Some(ip("198.51.100.7")), xff, &proxy),
        Some(ip("198.51.100.7"))
    );
    // From the proxy: the last address that is not a proxy.
    assert_eq!(
        client_address(Some(ip("10.0.0.1")), xff, &proxy),
        Some(ip("203.0.113.9"))
    );
    assert_eq!(
        client_address(Some(ip("10.0.0.1")), None, &proxy),
        Some(ip("10.0.0.1"))
    );
    assert_eq!(
        client_address(Some(ip("10.0.0.1")), xff, &[]),
        Some(ip("10.0.0.1"))
    );
}
