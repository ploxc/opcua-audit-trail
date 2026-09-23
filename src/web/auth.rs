//! Web UI login: session cookies, roles and CSRF protection.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use axum::extract::{FromRequestParts, Request, State};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use super::{ApiError, AppState};
use crate::audit::{AuditEntry, AuditEvent};
use crate::users::Role;

pub const COOKIE: &str = "gw_session";
/// Sessions end after this long without activity.
const IDLE_TIMEOUT: Duration = Duration::from_secs(8 * 3600);
/// Header every state-changing request must carry. Browsers do not let other
/// sites set custom headers on cross-site requests, so this stops CSRF.
pub const CSRF_HEADER: &str = "x-requested-with";
pub const CSRF_VALUE: &str = "opcua-audit-gateway";

struct WebSession {
    username: String,
    role: Role,
    last_seen: Instant,
}

#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, WebSession>>,
}

impl Sessions {
    fn create(&self, username: &str, role: Role) -> String {
        let token = hex::encode(
            opcua::crypto::random::byte_string(32)
                .value
                .unwrap_or_default(),
        );
        let mut map = self.map.lock();
        map.retain(|_, s| s.last_seen.elapsed() < IDLE_TIMEOUT);
        map.insert(
            token.clone(),
            WebSession {
                username: username.to_string(),
                role,
                last_seen: Instant::now(),
            },
        );
        token
    }

    fn get(&self, token: &str) -> Option<AuthUser> {
        let mut map = self.map.lock();
        let session = map.get_mut(token)?;
        if session.last_seen.elapsed() >= IDLE_TIMEOUT {
            map.remove(token);
            return None;
        }
        session.last_seen = Instant::now();
        Some(AuthUser {
            username: session.username.clone(),
            role: session.role,
        })
    }

    fn remove(&self, token: &str) {
        self.map.lock().remove(token);
    }

    /// Ends all sessions of a user (deleted, role or password changed).
    pub fn remove_user(&self, username: &str) {
        self.map.lock().retain(|_, s| s.username != username);
    }
}

/// The logged-in user of a request. Extracting it rejects anonymous requests.
#[derive(Debug, Clone, Serialize)]
pub struct AuthUser {
    pub username: String,
    pub role: Role,
}

impl AuthUser {
    pub fn require(&self, role: Role) -> Result<(), ApiError> {
        if self.role >= role {
            Ok(())
        } else {
            Err(ApiError(
                StatusCode::FORBIDDEN,
                format!("this needs the {} role", role.as_str()),
            ))
        }
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let jar = CookieJar::from_headers(&parts.headers);
        jar.get(COOKIE)
            .and_then(|c| state.sessions.get(c.value()))
            .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "not logged in".into()))
    }
}

/// Rejects state-changing requests without the CSRF header.
pub async fn csrf(request: Request, next: Next) -> Response {
    let safe = matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    );
    let marked = request
        .headers()
        .get(CSRF_HEADER)
        .is_some_and(|v| v == CSRF_VALUE);
    if safe || marked {
        next.run(request).await
    } else {
        ApiError(StatusCode::FORBIDDEN, "missing CSRF header".into()).into_response()
    }
}

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

pub async fn login(
    State(s): State<AppState>,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<AuthUser>), ApiError> {
    let users = s.users.clone();
    let (username, password) = (req.username.clone(), req.password);
    let user = tokio::task::spawn_blocking(move || users.verify(&username, &password))
        .await
        .map_err(|e| anyhow::anyhow!(e))??;
    let Some(user) = user else {
        let _ = s
            .audit
            .record_committed(AuditEntry::new(AuditEvent::UiLoginFailed {
                user: req.username,
            }))
            .await;
        // Slow down guessing a little more than argon2 already does.
        tokio::time::sleep(Duration::from_millis(500)).await;
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "wrong user name or password".into(),
        ));
    };
    let token = s.sessions.create(&user.username, user.role);
    let _ = s
        .audit
        .record_committed(AuditEntry::new(AuditEvent::UiLogin {
            user: user.username.clone(),
        }))
        .await;
    let cookie = Cookie::build((COOKIE, token))
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .build();
    Ok((
        jar.add(cookie),
        Json(AuthUser {
            username: user.username,
            role: user.role,
        }),
    ))
}

pub async fn logout(State(s): State<AppState>, jar: CookieJar) -> (CookieJar, StatusCode) {
    if let Some(c) = jar.get(COOKIE) {
        s.sessions.remove(c.value());
    }
    (
        jar.remove(Cookie::build(COOKIE).path("/")),
        StatusCode::NO_CONTENT,
    )
}

pub async fn me(user: AuthUser) -> Json<AuthUser> {
    Json(user)
}

#[derive(Deserialize)]
pub struct PasswordChange {
    current: String,
    new: String,
}

/// Any user may change their own password.
pub async fn change_password(
    State(s): State<AppState>,
    user: AuthUser,
    Json(req): Json<PasswordChange>,
) -> Result<StatusCode, ApiError> {
    let users = s.users.clone();
    let name = user.username.clone();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        if users.verify(&name, &req.current)?.is_none() {
            anyhow::bail!("the current password is wrong");
        }
        users.set_password(&name, &req.new)
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))?
    .map_err(ApiError::bad_request)?;
    s.config_changed(&user, format!("changed own password ({})", user.username))
        .await;
    Ok(StatusCode::NO_CONTENT)
}
