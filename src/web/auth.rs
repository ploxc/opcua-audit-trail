//! Web UI login: session cookies, roles, CSRF protection and brute-force limits.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use axum::extract::connect_info::ConnectInfo;
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
use crate::audit::event::{clip, ClientContext};
use crate::audit::{AuditEntry, AuditEvent};
use crate::users::Role;

pub const COOKIE: &str = "gw_session";
/// With HTTPS the cookie gets the `__Host-` prefix: browsers then only
/// accept it from this host, over HTTPS, for the whole site.
pub const SECURE_COOKIE: &str = "__Host-gw_session";
/// Sessions end after this long without activity...
const IDLE_TIMEOUT: Duration = Duration::from_secs(8 * 3600);
/// ...and after this long in any case.
const MAX_LIFETIME: Duration = Duration::from_secs(24 * 3600);
/// Header every state-changing request must carry. Browsers do not let other
/// sites set custom headers on cross-site requests, so this stops CSRF.
pub const CSRF_HEADER: &str = "x-requested-with";
pub const CSRF_VALUE: &str = "opcua-audit-gateway";

/// Failed logins from one address before it is blocked, and for how long.
const MAX_FAILURES_PER_ADDRESS: u32 = 5;
/// Failed logins for one user name (from any address) before it is blocked.
const MAX_FAILURES_PER_USER: u32 = 20;
const BLOCK_TIME: Duration = Duration::from_secs(15 * 60);
/// Password checks at once: each needs about 19 MiB (argon2).
const CONCURRENT_CHECKS: usize = 4;

struct WebSession {
    username: String,
    /// The user's session epoch at login; a password or role change ends
    /// every older session.
    epoch: i64,
    created: Instant,
    last_seen: Instant,
}

#[derive(Default)]
struct Failures {
    count: u32,
    last: Option<Instant>,
}

impl Failures {
    fn blocked(&self, max: u32) -> Option<Duration> {
        let last = self.last?;
        (self.count >= max && last.elapsed() < BLOCK_TIME).then(|| BLOCK_TIME - last.elapsed())
    }

    fn add(&mut self) {
        if self.last.is_some_and(|l| l.elapsed() >= BLOCK_TIME) {
            self.count = 0;
        }
        self.count += 1;
        self.last = Some(Instant::now());
    }
}

pub struct Sessions {
    map: Mutex<HashMap<String, WebSession>>,
    by_address: Mutex<HashMap<IpAddr, Failures>>,
    by_user: Mutex<HashMap<String, Failures>>,
    checks: tokio::sync::Semaphore,
}

impl Default for Sessions {
    fn default() -> Self {
        Self {
            map: Default::default(),
            by_address: Default::default(),
            by_user: Default::default(),
            checks: tokio::sync::Semaphore::new(CONCURRENT_CHECKS),
        }
    }
}

impl Sessions {
    fn create(&self, username: &str, epoch: i64) -> String {
        let token = hex::encode(
            opcua::crypto::random::byte_string(32)
                .value
                .unwrap_or_default(),
        );
        let mut map = self.map.lock();
        map.retain(|_, s| {
            s.last_seen.elapsed() < IDLE_TIMEOUT && s.created.elapsed() < MAX_LIFETIME
        });
        let now = Instant::now();
        map.insert(
            token.clone(),
            WebSession {
                username: username.to_string(),
                epoch,
                created: now,
                last_seen: now,
            },
        );
        token
    }

    /// The user name and epoch of a live session.
    fn get(&self, token: &str) -> Option<(String, i64)> {
        let mut map = self.map.lock();
        let session = map.get_mut(token)?;
        if session.last_seen.elapsed() >= IDLE_TIMEOUT || session.created.elapsed() >= MAX_LIFETIME
        {
            map.remove(token);
            return None;
        }
        session.last_seen = Instant::now();
        Some((session.username.clone(), session.epoch))
    }

    fn remove(&self, token: &str) {
        self.map.lock().remove(token);
    }

    /// Ends all sessions of a user (deleted, role or password changed).
    pub fn remove_user(&self, username: &str) {
        self.map.lock().retain(|_, s| s.username != username);
    }

    /// How long a login from this address for this user must wait, if it must.
    fn blocked(&self, address: Option<IpAddr>, username: &str) -> Option<Duration> {
        let by_address = address.and_then(|a| {
            self.by_address
                .lock()
                .get(&a)
                .and_then(|f| f.blocked(MAX_FAILURES_PER_ADDRESS))
        });
        by_address.or_else(|| {
            self.by_user
                .lock()
                .get(username)
                .and_then(|f| f.blocked(MAX_FAILURES_PER_USER))
        })
    }

    /// Counts a failed login; returns true when it starts a block.
    fn failed(&self, address: Option<IpAddr>, username: &str) -> bool {
        let mut blocked = false;
        if let Some(address) = address {
            let mut map = self.by_address.lock();
            if map.len() > 10_000 {
                map.retain(|_, f| f.last.is_some_and(|l| l.elapsed() < BLOCK_TIME));
            }
            let f = map.entry(address).or_default();
            f.add();
            blocked |= f.count == MAX_FAILURES_PER_ADDRESS;
        }
        if username.len() <= 64 {
            let mut map = self.by_user.lock();
            if map.len() > 10_000 {
                map.retain(|_, f| f.last.is_some_and(|l| l.elapsed() < BLOCK_TIME));
            }
            let f = map.entry(username.to_string()).or_default();
            f.add();
            blocked |= f.count == MAX_FAILURES_PER_USER;
        }
        blocked
    }

    fn succeeded(&self, address: Option<IpAddr>, username: &str) {
        if let Some(address) = address {
            self.by_address.lock().remove(&address);
        }
        self.by_user.lock().remove(username);
    }
}

/// The client's address, when the server runs with connection info.
pub struct ClientAddr(pub Option<IpAddr>);

impl<S: Send + Sync> FromRequestParts<S> for ClientAddr {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        Ok(ClientAddr(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip()),
        ))
    }
}

/// The logged-in user of a request. Extracting it rejects anonymous requests.
#[derive(Debug, Clone, Serialize)]
pub struct AuthUser {
    pub username: String,
    pub role: Role,
    pub must_change_password: bool,
    /// Set when an AI assistant acts through MCP: the token's id.
    #[serde(skip)]
    pub via_token: Option<String>,
}

impl AuthUser {
    /// Who did it, for audit records: the user, and the token when an AI
    /// assistant acted through MCP.
    pub fn actor(&self) -> String {
        match &self.via_token {
            Some(token) => format!("{} (via MCP, token {token})", self.username),
            None => self.username.clone(),
        }
    }

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

pub fn cookie_name(tls: bool) -> &'static str {
    if tls {
        SECURE_COOKIE
    } else {
        COOKIE
    }
}

impl FromRequestParts<AppState> for AuthUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let unauthorized = || ApiError(StatusCode::UNAUTHORIZED, "not logged in".into());
        let jar = CookieJar::from_headers(&parts.headers);
        let token = jar
            .get(cookie_name(state.config.web.tls))
            .ok_or_else(unauthorized)?
            .value()
            .to_string();
        let (username, epoch) = state.sessions.get(&token).ok_or_else(unauthorized)?;
        // The user database decides: a deleted user, or a password or role
        // changed since login (also with the command line), ends the session.
        let current = state
            .users
            .session_state(&username)?
            .filter(|s| s.epoch == epoch);
        let Some(current) = current else {
            state.sessions.remove(&token);
            return Err(unauthorized());
        };
        let user = AuthUser {
            username,
            role: current.role,
            must_change_password: current.must_change_password,
            via_token: None,
        };
        let path = parts.uri.path();
        let allowed = ["/me", "/me/password", "/logout"]
            .iter()
            .any(|p| path.ends_with(p));
        if user.must_change_password && !allowed {
            return Err(ApiError(
                StatusCode::FORBIDDEN,
                "choose a new password first".into(),
            ));
        }
        Ok(user)
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
    // The MCP endpoint ignores cookies and needs a bearer token, which a
    // cross-site request cannot carry.
    let mcp = request.uri().path() == "/mcp";
    if safe || marked || mcp {
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

fn session_cookie(tls: bool, token: String) -> Cookie<'static> {
    Cookie::build((cookie_name(tls), token))
        .secure(tls)
        .http_only(true)
        .same_site(SameSite::Strict)
        .path("/")
        .build()
}

fn web_client(address: Option<IpAddr>) -> ClientContext {
    ClientContext {
        remote_addr: address.map(|a| a.to_string()).unwrap_or_default(),
        application_name: Some("web UI".into()),
        ..Default::default()
    }
}

pub async fn login(
    State(s): State<AppState>,
    ClientAddr(address): ClientAddr,
    jar: CookieJar,
    Json(req): Json<LoginRequest>,
) -> Result<(CookieJar, Json<AuthUser>), ApiError> {
    if let Some(wait) = s.sessions.blocked(address, &req.username) {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "too many failed logins; try again in {} minutes",
                wait.as_secs().div_ceil(60)
            ),
        ));
    }
    // Few password checks at once: each takes a lot of memory.
    let Ok(Ok(_permit)) =
        tokio::time::timeout(Duration::from_secs(5), s.sessions.checks.acquire()).await
    else {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "too many logins at once; try again".into(),
        ));
    };
    let users = s.users.clone();
    let (username, password) = (req.username.clone(), req.password);
    let user = tokio::task::spawn_blocking(move || users.verify(&username, &password))
        .await
        .map_err(|e| anyhow::anyhow!(e))??;
    let Some(user) = user else {
        let starts_block = s.sessions.failed(address, &req.username);
        let _ = s
            .audit
            .record_committed(
                AuditEntry::new(AuditEvent::UiLoginFailed {
                    user: clip(&req.username, 64),
                })
                .client(web_client(address)),
            )
            .await;
        if starts_block {
            let _ = s
                .audit
                .record_committed(AuditEntry::new(AuditEvent::ConnectionsRefused {
                    remote_addr: address.map(|a| a.to_string()).unwrap_or_default(),
                    count: u64::from(MAX_FAILURES_PER_ADDRESS),
                    reason: format!(
                        "web UI logins blocked for {} minutes after repeated failures (user {})",
                        BLOCK_TIME.as_secs() / 60,
                        clip(&req.username, 64)
                    ),
                }))
                .await;
        }
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "wrong user name or password".into(),
        ));
    };
    s.sessions.succeeded(address, &user.username);
    let state = s
        .users
        .session_state(&user.username)?
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "user was just deleted".into()))?;
    let token = s.sessions.create(&user.username, state.epoch);
    let _ = s
        .audit
        .record_committed(
            AuditEntry::new(AuditEvent::UiLogin {
                user: user.username.clone(),
            })
            .client(web_client(address)),
        )
        .await;
    Ok((
        jar.add(session_cookie(s.config.web.tls, token)),
        Json(AuthUser {
            username: user.username,
            role: state.role,
            must_change_password: state.must_change_password,
            via_token: None,
        }),
    ))
}

pub async fn logout(State(s): State<AppState>, jar: CookieJar) -> (CookieJar, StatusCode) {
    let name = cookie_name(s.config.web.tls);
    if let Some(c) = jar.get(name) {
        s.sessions.remove(c.value());
    }
    (
        jar.remove(Cookie::build(name).path("/")),
        StatusCode::NO_CONTENT,
    )
}

pub async fn me(user: AuthUser) -> Json<AuthUser> {
    Json(user)
}

#[derive(Deserialize)]
pub struct PasswordChange {
    /// Not needed for a forced change: the user just logged in with it.
    #[serde(default)]
    current: Option<String>,
    new: String,
}

/// Any user may change their own password, giving the current one unless
/// the change is forced. All their other sessions end; this one continues
/// with a new cookie.
pub async fn change_password(
    State(s): State<AppState>,
    user: AuthUser,
    jar: CookieJar,
    Json(req): Json<PasswordChange>,
) -> Result<(CookieJar, StatusCode), ApiError> {
    let users = s.users.clone();
    let name = user.username.clone();
    let forced = user.must_change_password;
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        if !forced {
            let current = req.current.unwrap_or_default();
            if users.verify(&name, &current)?.is_none() {
                anyhow::bail!("the current password is wrong");
            }
        }
        users.set_password(&name, &req.new)
    })
    .await
    .map_err(|e| anyhow::anyhow!(e))?
    .map_err(ApiError::bad_request)?;
    s.sessions.remove_user(&user.username);
    let state = s
        .users
        .session_state(&user.username)?
        .ok_or_else(|| ApiError(StatusCode::UNAUTHORIZED, "user was just deleted".into()))?;
    let token = s.sessions.create(&user.username, state.epoch);
    s.config_changed(&user, format!("changed own password ({})", user.username))
        .await;
    Ok((
        jar.add(session_cookie(s.config.web.tls, token)),
        StatusCode::NO_CONTENT,
    ))
}
