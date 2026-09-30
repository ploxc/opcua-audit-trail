//! `GET /api/events`: live updates for the web UI as Server-Sent Events.
//!
//! Almost everything the UI shows live produces an audit record, so one
//! signal is enough: "records up to this seq are committed". The stream
//! carries only that number; the UI fetches what it shows through the
//! normal API with its role checks, so nothing else leaks through it.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use futures::Stream;

use super::auth::{session_role, session_token, AuthUser};
use super::{ApiError, AppState};
use crate::users::Role;

/// How often the stream sends a comment, and checks that the session is
/// still valid. Keeps proxies from closing an idle connection.
const KEEP_ALIVE: Duration = Duration::from_secs(15);
/// At most this many events a second: a burst of writes is one refresh.
const MIN_GAP: Duration = Duration::from_millis(300);

pub async fn events(
    State(s): State<AppState>,
    user: AuthUser,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    user.require(Role::Auditor)?;
    // The extractor accepted the cookie, so it is there.
    let token = session_token(&s, &headers).unwrap_or_default();
    let mut response = Sse::new(stream(s, token)).into_response();
    // nginx and alike buffer responses unless told not to.
    response
        .headers_mut()
        .insert("x-accel-buffering", HeaderValue::from_static("no"));
    Ok(response)
}

enum Next {
    Committed(i64),
    KeepAlive,
    End,
}

fn stream(s: AppState, token: String) -> impl Stream<Item = Result<Event, Infallible>> {
    let mut committed = s.audit.committed();
    // The first event says where the trail is, so the UI knows the stream
    // is up; after a reconnect it reloads everything anyway.
    committed.mark_changed();
    futures::stream::unfold(
        (s, token, committed),
        |(s, token, mut committed)| async move {
            let next = tokio::select! {
                changed = committed.changed() => match changed {
                    Ok(()) => Next::Committed(*committed.borrow_and_update()),
                    Err(_) => Next::End,
                },
                _ = tokio::time::sleep(KEEP_ALIVE) => Next::KeepAlive,
                _ = s.stopping.cancelled() => Next::End,
            };
            // Logged out, expired, or the password or role changed: stop.
            if session_role(&s, &token).is_none_or(|r| r < Role::Auditor) {
                return None;
            }
            let event = match next {
                Next::Committed(seq) => {
                    tokio::time::sleep(MIN_GAP).await;
                    // Records committed during the pause are in this event.
                    let seq = seq.max(*committed.borrow_and_update());
                    Event::default().event("audit").data(seq.to_string())
                }
                Next::KeepAlive => Event::default().comment(""),
                Next::End => return None,
            };
            Some((Ok(event), (s, token, committed)))
        },
    )
}
