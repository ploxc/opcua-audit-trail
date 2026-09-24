//! One downstream client connection and its upstream counterpart.
//!
//! The connection loop answers the secure channel and discovery services
//! itself, rewrites the session services (certificates, nonces, signatures,
//! user tokens) and forwards everything else unchanged. Forwarded requests run
//! as futures in a `FuturesUnordered`, so slow requests (Publish) never block
//! others. Newly pushed futures are first polled in push order, so requests
//! reach the upstream channel in the order the client sent them.
//!
//! Audited requests (changes and session services) are seen through to the
//! end when the client disconnects: once a change may have reached the
//! server, its outcome is recorded.

use std::future::Future;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use futures::stream::FuturesUnordered;
use futures::{FutureExt, StreamExt};
use opcua::core::comms::secure_channel::{Role, SecureChannel};
use opcua::core::comms::security_header::SecurityHeader;
use opcua::core::{RequestMessage, ResponseMessage};
use opcua::crypto::{
    create_signature_data, legacy_decrypt_secret, legacy_encrypt_secret, random,
    verify_signature_data, SecurityPolicy, X509,
};
use opcua::types::{
    ActivateSessionRequest, ActivateSessionResponse, AnonymousIdentityToken, ByteString,
    ChannelSecurityToken, CreateSessionRequest, CreateSessionResponse, DateTime,
    EndpointDescription, ExtensionObject, FindServersResponse, GetEndpointsResponse,
    IssuedIdentityToken, MessageSecurityMode, OpenSecureChannelRequest, OpenSecureChannelResponse,
    ReadRequest, RequestHeader, ResponseHeader, SecurityTokenRequestType, ServiceFault,
    SignatureData, StatusCode, TimestampsToReturn, UserNameIdentityToken, UserTokenType,
    X509IdentityToken,
};
use tokio::net::TcpStream;

use super::audit_map;
use super::endpoints::{self, gateway_endpoints, matching_upstream};
use super::transport::{ChannelBinding, Downstream, PollResult, Request};
use super::upstream::{Upstream, UpstreamError};
use super::{ClientInfo, RelayTarget, SessionEntry};
use crate::audit::event::{AuditEntry, AuditEvent, ClientContext, UserIdentity};
use crate::config::FailMode;

/// Upper bound for secure channel token lifetimes granted to clients.
const MAX_TOKEN_LIFETIME_MS: u32 = 3_600_000;
const MIN_TOKEN_LIFETIME_MS: u32 = 10_000;
const NONCE_LENGTH: usize = 32;
const PRE_READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How long audited requests may take to finish after the client is gone.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a closing connection may take to flush its last messages.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// A request in progress.
struct Pending {
    /// Seen through to the end when the client disconnects.
    audited: bool,
    future: BoxFuture<'static, (u32, ResponseMessage)>,
}

impl Future for Pending {
    type Output = (u32, ResponseMessage);

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.future.as_mut().poll(cx)
    }
}

/// Orders security settings: None < Sign < SignAndEncrypt.
fn security_rank(policy: SecurityPolicy, mode: MessageSecurityMode) -> u8 {
    match (policy, mode) {
        (SecurityPolicy::None, _) => 0,
        (_, MessageSecurityMode::Sign) => 1,
        (_, MessageSecurityMode::SignAndEncrypt) => 2,
        _ => 0,
    }
}

fn fault(request_handle: u32, status: StatusCode) -> ResponseMessage {
    ServiceFault::new(request_handle, status).into()
}

fn policy_name(policy: SecurityPolicy) -> String {
    policy.to_str().to_string()
}

fn mode_name(mode: MessageSecurityMode) -> String {
    format!("{mode:?}")
}

/// Everything a request future needs, detached from the connection.
#[derive(Clone)]
struct Ctx {
    target: Arc<RelayTarget>,
    upstream: Arc<Upstream>,
    connection_id: u64,
    /// Security of the downstream channel.
    policy: SecurityPolicy,
    mode: MessageSecurityMode,
    client_certificate: Option<X509>,
    client: ClientContext,
    /// Upstream endpoints (to build the endpoint list for CreateSession).
    upstream_endpoints: Arc<Vec<EndpointDescription>>,
    /// URL from the client's Hello.
    hello_url: String,
}

impl Ctx {
    async fn audit(&self, client: &ClientContext, event: AuditEvent) {
        let entry = AuditEntry::new(event)
            .target(self.target.config.name.clone())
            .client(client.clone());
        let _ = self.target.audit.record(entry).await;
    }
}

pub async fn run(target: Arc<RelayTarget>, stream: TcpStream, peer: SocketAddr, id: u64) {
    let transport = match Downstream::accept(stream, &target.limits, target.decoding.clone()).await
    {
        Ok(t) => t,
        Err(status) => {
            tracing::debug!(%peer, "handshake failed: {status}");
            return;
        }
    };
    let client = ClientContext {
        remote_addr: peer.to_string(),
        ..Default::default()
    };
    record(&target, &client, AuditEvent::ClientConnected).await;

    let channel = SecureChannel::new(
        target.gateway.certificate_store.clone(),
        Role::Server,
        Arc::new(parking_lot::RwLock::new(
            opcua::types::ContextOwned::new_default(
                opcua::types::NamespaceMap::new(),
                target.decoding.clone(),
            ),
        )),
    );
    let mut connection = Connection {
        deadline: Instant::now() + target.limits.hello_timeout,
        target: target.clone(),
        id,
        client,
        transport,
        channel,
        issued: false,
        last_token_id: 0,
        upstream_endpoints: Arc::new(Vec::new()),
        upstream: None,
        pending: FuturesUnordered::new(),
        close_reason: None,
        trust: target.trust_changed.subscribe(),
    };
    let reason = match AssertUnwindSafe(connection.run()).catch_unwind().await {
        Ok(reason) => reason,
        Err(_) => {
            tracing::error!(%peer, "connection handler failed unexpectedly");
            "internal error".into()
        }
    };
    connection.finish_audited().await;
    if let Some(upstream) = connection.upstream.take() {
        upstream.close().await;
    }
    target.clients.write().remove(&id);
    record(
        &target,
        &connection.client,
        AuditEvent::ClientDisconnected { reason },
    )
    .await;
}

async fn record(target: &RelayTarget, client: &ClientContext, event: AuditEvent) {
    let entry = AuditEntry::new(event)
        .target(target.config.name.clone())
        .client(client.clone());
    let _ = target.audit.record(entry).await;
}

struct Connection {
    target: Arc<RelayTarget>,
    id: u64,
    client: ClientContext,
    transport: Downstream,
    channel: SecureChannel,
    issued: bool,
    last_token_id: u32,
    upstream_endpoints: Arc<Vec<EndpointDescription>>,
    upstream: Option<Arc<Upstream>>,
    pending: FuturesUnordered<Pending>,
    deadline: Instant,
    close_reason: Option<String>,
    trust: tokio::sync::watch::Receiver<u64>,
}

impl Connection {
    fn close(&mut self, status: StatusCode, reason: &str) {
        if self.close_reason.is_none() {
            self.close_reason = Some(reason.to_string());
            self.deadline = Instant::now() + CLOSE_TIMEOUT;
        }
        self.transport.enqueue_error(status, reason);
    }

    /// Lets audited requests that may already have reached the server finish,
    /// so their outcome is recorded even though the client is gone.
    async fn finish_audited(&mut self) {
        let mut audited: FuturesUnordered<Pending> = std::mem::take(&mut self.pending)
            .into_iter()
            .filter(|p| p.audited)
            .collect();
        if audited.is_empty() {
            return;
        }
        let drain = async { while audited.next().await.is_some() {} };
        if tokio::time::timeout(DRAIN_TIMEOUT, drain).await.is_ok() {
            return;
        }
        // Still no response: closing the upstream channel makes the remaining
        // requests fail, and they are recorded with an unknown outcome.
        if let Some(upstream) = self.upstream.take() {
            upstream.close().await;
        }
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, async {
            while audited.next().await.is_some() {}
        })
        .await;
    }

    fn transport_closing(&self) -> bool {
        self.close_reason.is_some()
    }

    fn respond(&mut self, request_id: u32, response: ResponseMessage) {
        if let Err(status) = self.transport.enqueue(&self.channel, response, request_id) {
            self.close(status, "failed to encode response");
        }
    }

    async fn run(&mut self) -> String {
        loop {
            let upstream_closed = async {
                match &self.upstream {
                    Some(u) => u.closed.cancelled().await,
                    None => std::future::pending().await,
                }
            };
            let shutdown = self.target.shutdown.clone();
            let mut trust = self.trust.clone();
            tokio::select! {
                _ = shutdown.cancelled(), if !self.transport_closing() => {
                    self.close(StatusCode::BadServerHalted, "target stopped or reconfigured");
                }
                Ok(()) = trust.changed(), if !self.transport_closing() => {
                    self.trust.mark_unchanged();
                    if let Err(reason) = self.still_trusted() {
                        self.close(StatusCode::BadCertificateUntrusted, &reason);
                    }
                }
                _ = tokio::time::sleep_until(self.deadline.into()) => {
                    if self.transport_closing() {
                        // The client does not take its last messages.
                        break;
                    }
                    self.close(StatusCode::BadTimeout, "secure channel expired");
                }
                Some((request_id, response)) = self.pending.next(), if !self.pending.is_empty() => {
                    self.respond(request_id, response);
                }
                _ = upstream_closed => {
                    self.upstream = None;
                    self.close(StatusCode::BadServerNotConnected, "upstream connection lost");
                }
                result = self.transport.poll(&mut self.channel) => match result {
                    PollResult::Request(request) => self.handle(request).await,
                    PollResult::Recoverable(status, request_id, handle) => {
                        self.respond(request_id, fault(handle, status));
                    }
                    PollResult::Error(status) => {
                        self.close(status, &format!("transport error: {status}"));
                    }
                    PollResult::Closed => break,
                    PollResult::Sent | PollResult::Chunk => {}
                },
            }
        }
        self.close_reason
            .take()
            .unwrap_or_else(|| "connection closed".into())
    }

    async fn handle(&mut self, request: Request) {
        if self.transport_closing() {
            // Nothing new is started on a connection that is going away.
            return;
        }
        let request_id = request.request_id;
        let handle = request.message.request_handle_value();
        if !self.issued && !matches!(request.message, RequestMessage::OpenSecureChannel(_)) {
            self.close(
                StatusCode::BadSecureChannelIdInvalid,
                "request before OpenSecureChannel",
            );
            return;
        }
        match request.message {
            RequestMessage::OpenSecureChannel(r) => {
                self.open_secure_channel(request_id, &request.security_header, &r)
                    .await;
            }
            RequestMessage::CloseSecureChannel(_) => {
                self.close_reason = Some("client closed the secure channel".into());
                self.deadline = Instant::now() + CLOSE_TIMEOUT;
                self.transport.set_closing();
            }
            RequestMessage::GetEndpoints(r) => {
                let url = self.url(r.endpoint_url.as_ref());
                let response = match self.refresh_upstream_endpoints().await {
                    Ok(()) => GetEndpointsResponse {
                        response_header: ResponseHeader::new_good(&r.request_header),
                        endpoints: Some(gateway_endpoints(
                            &self.upstream_endpoints,
                            &self.target.gateway,
                            &url,
                        )),
                    }
                    .into(),
                    Err(status) => fault(handle, status),
                };
                self.respond(request_id, response);
            }
            RequestMessage::FindServers(r) => {
                let url = self.url(r.endpoint_url.as_ref());
                let response = FindServersResponse {
                    response_header: ResponseHeader::new_good(&r.request_header),
                    servers: Some(vec![endpoints::server_description(
                        &self.target.gateway,
                        &url,
                    )]),
                };
                self.respond(request_id, response.into());
            }
            RequestMessage::FindServersOnNetwork(_)
            | RequestMessage::RegisterServer(_)
            | RequestMessage::RegisterServer2(_) => {
                self.respond(request_id, fault(handle, StatusCode::BadServiceUnsupported));
            }
            message => {
                let audited = audit_map::is_audited(&message)
                    || matches!(
                        message,
                        RequestMessage::CreateSession(_)
                            | RequestMessage::ActivateSession(_)
                            | RequestMessage::CloseSession(_)
                    );
                let ctx = match self.ctx().await {
                    Ok(ctx) => ctx,
                    Err(status) => {
                        self.respond(request_id, fault(handle, status));
                        return;
                    }
                };
                let future: BoxFuture<'static, ResponseMessage> = match message {
                    RequestMessage::CreateSession(r) => create_session(ctx, r).boxed(),
                    RequestMessage::ActivateSession(r) => activate_session(ctx, r).boxed(),
                    RequestMessage::CloseSession(r) => {
                        close_session(ctx, RequestMessage::CloseSession(r)).boxed()
                    }
                    other => forward(ctx, other).boxed(),
                };
                self.pending.push(Pending {
                    audited,
                    future: async move { (request_id, future.await) }.boxed(),
                });
            }
        }
    }

    /// The URL the client used: from the request, else from its Hello.
    fn url(&self, requested: &str) -> String {
        if requested.is_empty() {
            self.transport.endpoint_url.clone()
        } else {
            requested.to_string()
        }
    }

    async fn refresh_upstream_endpoints(&mut self) -> Result<(), StatusCode> {
        match self.target.upstream_endpoints().await {
            Ok(endpoints) => {
                self.upstream_endpoints = Arc::new(endpoints);
                Ok(())
            }
            Err(status) if self.upstream_endpoints.is_empty() => Err(status),
            Err(_) => Ok(()),
        }
    }

    async fn ctx(&mut self) -> Result<Ctx, StatusCode> {
        let upstream = self.ensure_upstream().await?;
        let policy = self.channel.security_policy();
        Ok(Ctx {
            target: self.target.clone(),
            upstream,
            connection_id: self.id,
            policy,
            mode: self.channel.security_mode(),
            client_certificate: if policy == SecurityPolicy::None {
                None
            } else {
                self.channel.remote_cert()
            },
            client: self.client.clone(),
            upstream_endpoints: self.upstream_endpoints.clone(),
            hello_url: self.transport.endpoint_url.clone(),
        })
    }

    async fn ensure_upstream(&mut self) -> Result<Arc<Upstream>, StatusCode> {
        if let Some(upstream) = &self.upstream {
            return Ok(upstream.clone());
        }
        if self.upstream_endpoints.is_empty() {
            self.refresh_upstream_endpoints().await?;
        }
        let policy = self.channel.security_policy();
        let mode = self.channel.security_mode();
        let endpoint = matching_upstream(&self.upstream_endpoints, policy, mode)
            .cloned()
            .ok_or(StatusCode::BadSecurityPolicyRejected)?;
        let target = &self.target;
        match Upstream::connect(
            &target.gateway,
            &target.config.endpoint_url,
            endpoint,
            &target.limits,
            target.decoding.clone(),
        )
        .await
        {
            Ok(upstream) => {
                self.upstream = Some(upstream.clone());
                Ok(upstream)
            }
            Err(UpstreamError::Untrusted {
                subject,
                thumbprint,
                status,
            }) => {
                tracing::warn!(
                    target = %target.config.name,
                    "upstream certificate {subject} [{thumbprint}] is not trusted; \
                     trust it to allow secure connections"
                );
                record(
                    target,
                    &self.client,
                    AuditEvent::CertificateRejected {
                        subject,
                        thumbprint,
                        reason: format!("upstream server certificate not trusted ({status})"),
                    },
                )
                .await;
                Err(StatusCode::BadServerNotConnected)
            }
            Err(UpstreamError::Other(e)) => {
                tracing::warn!(target = %target.config.name, "upstream connect failed: {e}");
                Err(StatusCode::BadServerNotConnected)
            }
        }
    }

    async fn open_secure_channel(
        &mut self,
        request_id: u32,
        security_header: &SecurityHeader,
        request: &OpenSecureChannelRequest,
    ) {
        let SecurityHeader::Asymmetric(header) = security_header else {
            self.close(
                StatusCode::BadSecurityChecksFailed,
                "OpenSecureChannel without asymmetric header",
            );
            return;
        };
        if request.client_protocol_version != self.transport.protocol_version {
            self.respond(
                request_id,
                fault(
                    request.request_header.request_handle,
                    StatusCode::BadProtocolVersionUnsupported,
                ),
            );
            self.close(
                StatusCode::BadProtocolVersionUnsupported,
                "protocol version mismatch",
            );
            return;
        }

        let policy = self.channel.security_policy();
        let mode = request.security_mode;
        let renew = request.request_type == SecurityTokenRequestType::Renew;
        let reject = |this: &mut Self, status: StatusCode, reason: &str| {
            this.respond(
                request_id,
                fault(request.request_header.request_handle, status),
            );
            this.close(status, reason);
        };

        let channel_id = if renew {
            if !self.issued {
                return reject(
                    self,
                    StatusCode::BadSecureChannelIdInvalid,
                    "renew before issue",
                );
            }
            // The transport already checked that policy and certificate are
            // the issued ones; the mode must not change either.
            if mode != self.channel.security_mode() {
                return reject(
                    self,
                    StatusCode::BadSecurityModeRejected,
                    "renewal with a different security mode",
                );
            }
            if policy != SecurityPolicy::None
                && request.client_nonce.as_ref() == self.channel.remote_nonce()
            {
                return reject(self, StatusCode::BadNonceInvalid, "nonce reused on renew");
            }
            if policy != SecurityPolicy::None {
                // Trust may have been revoked since the channel was issued.
                if let Err(status) = self
                    .check_client_certificate(&header.sender_certificate)
                    .await
                {
                    return reject(self, status, "client certificate no longer trusted");
                }
            }
            self.channel.secure_channel_id()
        } else {
            if self.issued {
                return reject(self, StatusCode::BadSecureChannelIdInvalid, "second issue");
            }
            let consistent = match mode {
                MessageSecurityMode::None => policy == SecurityPolicy::None,
                MessageSecurityMode::Sign | MessageSecurityMode::SignAndEncrypt => {
                    policy != SecurityPolicy::None
                }
                _ => false,
            };
            if !consistent {
                return reject(
                    self,
                    StatusCode::BadSecurityModeRejected,
                    "invalid security mode",
                );
            }
            // Offer exactly what the upstream server offers. When the upstream
            // is unreachable only an insecure channel is accepted, which is
            // enough to discover that it is down.
            let known = self.refresh_upstream_endpoints().await.is_ok();
            let offered = gateway_endpoints(&self.upstream_endpoints, &self.target.gateway, "")
                .iter()
                .any(|e| {
                    e.security_mode == mode
                        && SecurityPolicy::from_uri(e.security_policy_uri.as_ref()) == policy
                });
            if !offered && (known || policy != SecurityPolicy::None) {
                return reject(
                    self,
                    StatusCode::BadSecurityPolicyRejected,
                    "security policy not offered by the target",
                );
            }
            if policy != SecurityPolicy::None {
                if let Err(status) = self
                    .check_client_certificate(&header.sender_certificate)
                    .await
                {
                    return reject(self, status, "client certificate rejected");
                }
            }
            self.target.next_channel_id()
        };

        let revised_lifetime = request
            .requested_lifetime
            .clamp(MIN_TOKEN_LIFETIME_MS, MAX_TOKEN_LIFETIME_MS);
        self.last_token_id += 1;
        let token = ChannelSecurityToken {
            channel_id,
            token_id: self.last_token_id,
            created_at: DateTime::now(),
            revised_lifetime,
        };
        let setup = (|| {
            self.channel.set_security_mode(mode);
            self.channel.set_security_token(token.clone());
            self.channel
                .set_remote_cert_from_byte_string(&header.sender_certificate)?;
            self.channel
                .validate_secure_channel_nonce_length(&request.client_nonce)?;
            self.channel
                .set_remote_nonce_from_byte_string(&request.client_nonce)?;
            self.channel.create_random_nonce();
            if policy != SecurityPolicy::None && mode != MessageSecurityMode::None {
                self.channel.derive_keys();
            }
            Ok::<_, opcua::types::Error>(())
        })();
        if let Err(e) = setup {
            return reject(self, e.status(), "invalid OpenSecureChannel request");
        }

        let response = OpenSecureChannelResponse {
            response_header: ResponseHeader::new_good(&request.request_header),
            server_protocol_version: 0,
            security_token: token,
            server_nonce: self.channel.local_nonce_as_byte_string(),
        };
        self.respond(request_id, response.into());
        // The token expires after its lifetime; allow a quarter more for a
        // late renewal. (async-opcua's `token_renewal_deadline` reads the
        // lifetime, in milliseconds, as seconds.)
        self.deadline = Instant::now() + Duration::from_millis(u64::from(revised_lifetime) * 4 / 3);

        if !renew {
            self.issued = true;
            self.transport.binding = Some(ChannelBinding {
                policy_uri: header.security_policy_uri.as_ref().to_string(),
                certificate: header.sender_certificate.clone(),
            });
            self.target.clients.write().insert(
                self.id,
                ClientInfo {
                    remote_addr: self.client.remote_addr.clone(),
                    connected_at: chrono::Utc::now(),
                    security_policy: policy_name(policy),
                    security_mode: mode_name(mode),
                    application_uri: None,
                    application_name: None,
                    user: None,
                },
            );
            record(
                &self.target,
                &self.client,
                AuditEvent::SecureChannelOpened {
                    security_policy: policy_name(policy),
                    security_mode: mode_name(mode),
                },
            )
            .await;
        }
    }

    /// Whether the client's and the upstream server's certificates are still
    /// trusted (after an administrator revoked trust in one).
    fn still_trusted(&self) -> Result<(), String> {
        let store = self.target.gateway.certificate_store.read();
        let policy = self.channel.security_policy();
        if policy != SecurityPolicy::None {
            if let Some(cert) = self.channel.remote_cert() {
                store
                    .validate_or_reject_application_instance_cert(&cert, policy, None, None)
                    .map_err(|_| "client certificate is no longer trusted".to_string())?;
            }
        }
        if let Some(upstream) = &self.upstream {
            let policy = upstream.security_policy();
            if let (true, Some(cert)) =
                (policy != SecurityPolicy::None, &upstream.server_certificate)
            {
                store
                    .validate_or_reject_application_instance_cert(cert, policy, None, None)
                    .map_err(|_| "upstream server certificate is no longer trusted".to_string())?;
            }
        }
        Ok(())
    }

    /// Checks the client's application instance certificate against the trust
    /// list. Unknown certificates land in `pki/rejected/` for an administrator.
    async fn check_client_certificate(
        &mut self,
        certificate: &ByteString,
    ) -> Result<(), StatusCode> {
        let cert = X509::from_byte_string(certificate).map_err(|e| e.status())?;
        self.client.certificate_thumbprint = Some(cert.thumbprint().as_hex_string());
        let policy = self.channel.security_policy();
        let result = self
            .target
            .gateway
            .certificate_store
            .read()
            .validate_or_reject_application_instance_cert(&cert, policy, None, None);
        if let Err(e) = result {
            record(
                &self.target,
                &self.client,
                AuditEvent::CertificateRejected {
                    subject: cert.subject_name(),
                    thumbprint: cert.thumbprint().as_hex_string(),
                    reason: e.to_string(),
                },
            )
            .await;
            return Err(e.status());
        }
        Ok(())
    }
}

trait RequestHandle {
    fn request_handle_value(&self) -> u32;
}

impl RequestHandle for RequestMessage {
    fn request_handle_value(&self) -> u32 {
        self.request_header().request_handle
    }
}

/// How long to wait for the upstream response: the client's own timeout plus a
/// margin, so the client times out first and sees its own error.
fn upstream_timeout(timeout_hint_ms: u32) -> Duration {
    if timeout_hint_ms == 0 {
        Duration::from_secs(600)
    } else {
        Duration::from_millis(u64::from(timeout_hint_ms))
            .clamp(Duration::from_secs(1), Duration::from_secs(3600))
            + Duration::from_secs(5)
    }
}

async fn create_session(ctx: Ctx, request: Box<CreateSessionRequest>) -> ResponseMessage {
    let handle = request.request_header.request_handle;
    let gateway = &ctx.target.gateway;

    // The client must present the certificate it opened the channel with.
    if ctx.policy != SecurityPolicy::None {
        let Some(channel_cert) = &ctx.client_certificate else {
            return fault(handle, StatusCode::BadCertificateInvalid);
        };
        let same = X509::from_byte_string(&request.client_certificate)
            .map(|c| c.thumbprint().value() == channel_cert.thumbprint().value())
            .unwrap_or(false);
        if !same {
            return fault(handle, StatusCode::BadCertificateInvalid);
        }
        if request.client_nonce.len() < NONCE_LENGTH {
            return fault(handle, StatusCode::BadNonceInvalid);
        }
        if channel_cert
            .is_application_uri_valid(request.client_description.application_uri.as_ref())
            .is_err()
        {
            return fault(handle, StatusCode::BadCertificateUriInvalid);
        }
    }

    let session_name = if request.session_name.is_empty() {
        request
            .client_description
            .application_name
            .text
            .as_ref()
            .to_string()
    } else {
        request.session_name.as_ref().to_string()
    };
    let client_nonce = random::byte_string(NONCE_LENGTH);
    let upstream_request = CreateSessionRequest {
        request_header: request.request_header.clone(),
        client_description: endpoints::client_description(gateway),
        server_uri: Default::default(),
        endpoint_url: ctx.target.config.endpoint_url.as_str().into(),
        session_name: format!("{session_name} via {}", gateway.application_name).into(),
        client_nonce: client_nonce.clone(),
        client_certificate: gateway.certificate_bytes.clone(),
        requested_session_timeout: request.requested_session_timeout,
        max_response_message_size: request.max_response_message_size,
    };
    let timeout = upstream_timeout(request.request_header.timeout_hint);
    let response = match ctx.upstream.send(upstream_request.into(), timeout).await {
        Ok(r) => r,
        Err(e) => return fault(handle, e.status()),
    };
    let ResponseMessage::CreateSession(upstream) = response else {
        return response;
    };

    // Check that the session really comes from the server we trust.
    let upstream_policy = ctx.upstream.security_policy();
    if upstream_policy != SecurityPolicy::None {
        let verified = X509::from_byte_string(&upstream.server_certificate)
            .ok()
            .filter(|cert| {
                ctx.upstream
                    .server_certificate
                    .as_ref()
                    .is_some_and(|c| c.thumbprint().value() == cert.thumbprint().value())
            })
            .map(|cert| {
                verify_signature_data(
                    &upstream.server_signature,
                    upstream_policy,
                    &cert,
                    &gateway.certificate,
                    client_nonce.as_ref(),
                )
                .is_ok()
            })
            .unwrap_or(false);
        if !verified {
            tracing::error!("upstream CreateSession signature invalid");
            return fault(handle, StatusCode::BadApplicationSignatureInvalid);
        }
        // The endpoints the server lists here come over the secured channel;
        // discovery did not. Anything missing from discovery means it was
        // tampered with, e.g. to hide the more secure endpoints.
        if let Some(missing) = endpoints::missing_from_discovery(
            upstream.server_endpoints.as_deref().unwrap_or_default(),
            &ctx.upstream_endpoints,
            ctx.target.config.min_security,
        ) {
            tracing::error!(
                target = %ctx.target.config.name,
                "the upstream server offers {missing}, which discovery did not return"
            );
            ctx.audit(
                &ctx.client,
                AuditEvent::AuthenticationFailed {
                    status: format!(
                        "BadSecurityChecksFailed: the upstream server offers {missing}, \
                         which discovery did not return"
                    ),
                },
            )
            .await;
            return fault(handle, StatusCode::BadSecurityChecksFailed);
        }
    }

    let server_signature = if ctx.policy == SecurityPolicy::None {
        SignatureData::null()
    } else {
        match create_signature_data(
            &gateway.private_key,
            ctx.policy,
            &request.client_certificate,
            &request.client_nonce,
        ) {
            Ok(s) => s,
            Err(e) => return fault(handle, e.status()),
        }
    };
    let server_nonce = random::byte_string(NONCE_LENGTH);

    let client = ClientContext {
        application_uri: Some(
            request
                .client_description
                .application_uri
                .as_ref()
                .to_string(),
        ),
        application_name: Some(
            request
                .client_description
                .application_name
                .text
                .as_ref()
                .to_string(),
        ),
        session_id: Some(upstream.session_id.to_string()),
        ..ctx.client.clone()
    };
    ctx.target.sessions.insert(
        upstream.authentication_token.clone(),
        SessionEntry {
            client: client.clone(),
            client_certificate: ctx.client_certificate.clone(),
            downstream_nonce: server_nonce.clone(),
            upstream_nonce: upstream.server_nonce.clone(),
            timeout: Duration::from_millis(upstream.revised_session_timeout.max(0.0) as u64),
            last_used: Instant::now(),
            security_policy: ctx.policy,
            security_mode: ctx.mode,
            connection_id: ctx.connection_id,
        },
    );
    if let Some(info) = ctx.target.clients.write().get_mut(&ctx.connection_id) {
        info.application_uri = client.application_uri.clone();
        info.application_name = client.application_name.clone();
    }
    ctx.audit(&client, AuditEvent::SessionCreated { session_name })
        .await;

    CreateSessionResponse {
        response_header: upstream.response_header.clone(),
        session_id: upstream.session_id.clone(),
        authentication_token: upstream.authentication_token.clone(),
        revised_session_timeout: upstream.revised_session_timeout,
        server_nonce,
        server_certificate: gateway.certificate_bytes.clone(),
        // Must equal what GetEndpoints returned for this URL: clients compare
        // the two to detect tampering.
        server_endpoints: Some(gateway_endpoints(
            &ctx.upstream_endpoints,
            gateway,
            if request.endpoint_url.is_empty() {
                &ctx.hello_url
            } else {
                request.endpoint_url.as_ref()
            },
        )),
        server_software_certificates: None,
        server_signature,
        max_request_message_size: upstream.max_request_message_size,
    }
    .into()
}

/// A client identity token translated for the upstream server.
struct Identity {
    user: UserIdentity,
    upstream_token: ExtensionObject,
}

/// The password of a user name token, decrypted with the gateway's key.
fn decrypt_password(
    token: &UserNameIdentityToken,
    nonce: &[u8],
    key: &opcua::crypto::PrivateKey,
) -> Result<ByteString, StatusCode> {
    if token.encryption_algorithm.is_empty() {
        return Ok(token.password.clone());
    }
    // async-opcua panics on some malformed secrets (a length underflow); a
    // client must not be able to crash its connection with one.
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        legacy_decrypt_secret(token, nonce, key)
    }))
    .map_err(|_| StatusCode::BadIdentityTokenInvalid)?
    .map_err(|e| e.status())
}

fn translate_identity(
    ctx: &Ctx,
    token: &ExtensionObject,
    downstream_nonce: &ByteString,
    upstream_nonce: &ByteString,
) -> Result<Identity, (StatusCode, UserIdentity)> {
    let upstream_endpoint = &ctx.upstream.endpoint;
    let anonymous = || -> Result<Identity, (StatusCode, UserIdentity)> {
        let policy = endpoints::token_policy_of_type(upstream_endpoint, UserTokenType::Anonymous)
            .ok_or((
            StatusCode::BadIdentityTokenRejected,
            UserIdentity::Anonymous,
        ))?;
        Ok(Identity {
            user: UserIdentity::Anonymous,
            upstream_token: ExtensionObject::new(AnonymousIdentityToken {
                policy_id: policy.policy_id.clone(),
            }),
        })
    };

    if token.is_null() || token.inner_as::<AnonymousIdentityToken>().is_some() {
        return anonymous();
    }
    if let Some(t) = token.inner_as::<UserNameIdentityToken>() {
        let user = UserIdentity::UserName {
            name: t.user_name.as_ref().to_string(),
        };
        let fail = |status: StatusCode| (status, user.clone());
        let password = decrypt_password(
            t,
            downstream_nonce.as_ref(),
            &ctx.target.gateway.private_key,
        )
        .map_err(fail)?;
        let policy = endpoints::token_policy(upstream_endpoint, &t.policy_id)
            .or_else(|| endpoints::token_policy_of_type(upstream_endpoint, UserTokenType::UserName))
            .ok_or_else(|| fail(StatusCode::BadIdentityTokenRejected))?;
        let server_cert = X509::from_byte_string(&upstream_endpoint.server_certificate).ok();
        let encrypted = legacy_encrypt_secret(
            ctx.upstream.security_policy(),
            upstream_endpoint.security_mode,
            policy,
            upstream_nonce.as_ref(),
            &server_cert,
            password.as_ref(),
        )
        .map_err(|e| fail(e.status()))?;
        return Ok(Identity {
            user: user.clone(),
            upstream_token: ExtensionObject::new(UserNameIdentityToken {
                policy_id: policy.policy_id.clone(),
                user_name: t.user_name.clone(),
                password: encrypted.secret,
                encryption_algorithm: encrypted.encryption_algorithm,
            }),
        });
    }
    if let Some(t) = token.inner_as::<X509IdentityToken>() {
        // Signed with the user's private key: cannot be relayed.
        let user = X509::from_byte_string(&t.certificate_data)
            .map(|c| UserIdentity::Certificate {
                subject: c.subject_name(),
                thumbprint: c.thumbprint().as_hex_string(),
            })
            .unwrap_or(UserIdentity::Certificate {
                subject: "invalid certificate".into(),
                thumbprint: String::new(),
            });
        return Err((StatusCode::BadIdentityTokenRejected, user));
    }
    if token.inner_as::<IssuedIdentityToken>().is_some() {
        return Err((
            StatusCode::BadIdentityTokenRejected,
            UserIdentity::IssuedToken,
        ));
    }
    Err((StatusCode::BadIdentityTokenInvalid, UserIdentity::Anonymous))
}

async fn activate_session(ctx: Ctx, request: Box<ActivateSessionRequest>) -> ResponseMessage {
    let handle = request.request_header.request_handle;
    let token = request.request_header.authentication_token.clone();
    let gateway = &ctx.target.gateway;
    let Some((client, session_cert, downstream_nonce, upstream_nonce, session_security)) =
        ctx.target.sessions.with(&token, |s| {
            (
                s.client.clone(),
                s.client_certificate.clone(),
                s.downstream_nonce.clone(),
                s.upstream_nonce.clone(),
                security_rank(s.security_policy, s.security_mode),
            )
        })
    else {
        return fault(handle, StatusCode::BadSessionIdInvalid);
    };
    // The connection may be new (reconnect): record under its address.
    let client = ClientContext {
        remote_addr: ctx.client.remote_addr.clone(),
        ..client
    };

    // A session keeps the security it was created with: re-activating it
    // over a weaker channel would skip the proof of the client's key.
    if security_rank(ctx.policy, ctx.mode) < session_security {
        ctx.audit(
            &client,
            AuditEvent::AuthenticationFailed {
                status: format!(
                    "{}: session re-activation over a less secure channel",
                    StatusCode::BadSecurityModeInsufficient
                ),
            },
        )
        .await;
        return fault(handle, StatusCode::BadSecurityModeInsufficient);
    }

    if ctx.policy != SecurityPolicy::None {
        let same_client = matches!(
            (&session_cert, &ctx.client_certificate),
            (Some(a), Some(b)) if a.thumbprint().value() == b.thumbprint().value()
        );
        let signature_ok = same_client
            && session_cert.as_ref().is_some_and(|cert| {
                verify_signature_data(
                    &request.client_signature,
                    ctx.policy,
                    cert,
                    &gateway.certificate,
                    downstream_nonce.as_ref(),
                )
                .is_ok()
            });
        if !signature_ok {
            ctx.audit(
                &client,
                AuditEvent::AuthenticationFailed {
                    status: StatusCode::BadApplicationSignatureInvalid.to_string(),
                },
            )
            .await;
            return fault(handle, StatusCode::BadApplicationSignatureInvalid);
        }
    }

    let identity = match translate_identity(
        &ctx,
        &request.user_identity_token,
        &downstream_nonce,
        &upstream_nonce,
    ) {
        Ok(identity) => identity,
        Err((status, user)) => {
            let client = ClientContext {
                user: Some(user),
                ..client
            };
            ctx.audit(
                &client,
                AuditEvent::AuthenticationFailed {
                    status: status.to_string(),
                },
            )
            .await;
            return fault(handle, status);
        }
    };

    let upstream_policy = ctx.upstream.security_policy();
    let client_signature = if upstream_policy == SecurityPolicy::None {
        SignatureData::null()
    } else {
        match create_signature_data(
            &gateway.private_key,
            upstream_policy,
            &ctx.upstream.endpoint.server_certificate,
            &upstream_nonce,
        ) {
            Ok(s) => s,
            Err(e) => return fault(handle, e.status()),
        }
    };
    let upstream_request = ActivateSessionRequest {
        request_header: request.request_header.clone(),
        client_signature,
        client_software_certificates: None,
        locale_ids: request.locale_ids.clone(),
        user_identity_token: identity.upstream_token,
        user_token_signature: SignatureData::null(),
    };
    let timeout = upstream_timeout(request.request_header.timeout_hint);
    let response = match ctx.upstream.send(upstream_request.into(), timeout).await {
        Ok(r) => r,
        Err(e) => return fault(handle, e.status()),
    };
    let client = ClientContext {
        user: Some(identity.user.clone()),
        ..client
    };

    match response {
        ResponseMessage::ActivateSession(upstream)
            if upstream.response_header.service_result.is_good() =>
        {
            let server_nonce = random::byte_string(NONCE_LENGTH);
            ctx.target.sessions.with(&token, |s| {
                s.downstream_nonce = server_nonce.clone();
                s.upstream_nonce = upstream.server_nonce.clone();
                s.client = client.clone();
                // From now on the session belongs to this connection.
                s.connection_id = ctx.connection_id;
            });
            if let Some(info) = ctx.target.clients.write().get_mut(&ctx.connection_id) {
                info.user = Some(identity.user.label());
                info.application_uri = client.application_uri.clone();
                info.application_name = client.application_name.clone();
            }
            ctx.audit(&client, AuditEvent::SessionActivated).await;
            ActivateSessionResponse {
                response_header: upstream.response_header.clone(),
                server_nonce,
                results: upstream.results.clone(),
                diagnostic_infos: upstream.diagnostic_infos.clone(),
            }
            .into()
        }
        other => {
            ctx.audit(
                &client,
                AuditEvent::AuthenticationFailed {
                    status: other.response_header().service_result.to_string(),
                },
            )
            .await;
            other
        }
    }
}

async fn close_session(ctx: Ctx, request: RequestMessage) -> ResponseMessage {
    let token = request.request_header().authentication_token.clone();
    let response = forward(ctx.clone(), request).await;
    // Only the connection the session belongs to can end it here; another
    // connection presenting its token must not erase it.
    if let Some(entry) = ctx.target.sessions.remove_owned(&token, ctx.connection_id) {
        let client = ClientContext {
            remote_addr: ctx.client.remote_addr.clone(),
            ..entry.client
        };
        ctx.audit(&client, AuditEvent::SessionClosed).await;
    }
    response
}

/// Forwards a request unchanged and audits it if it changes the server.
async fn forward(ctx: Ctx, request: RequestMessage) -> ResponseMessage {
    let header = request.request_header();
    let handle = header.request_handle;
    let timeout = upstream_timeout(header.timeout_hint);
    // Attribute the request to the session's user only if the session
    // belongs to this connection; a borrowed token proves nothing.
    let client = ctx
        .target
        .sessions
        .client_of(&header.authentication_token, ctx.connection_id)
        .map(|c| ClientContext {
            remote_addr: ctx.client.remote_addr.clone(),
            ..c
        })
        .unwrap_or_else(|| ctx.client.clone());

    let mut plan = audit_map::plan(&request);
    let pre_read = plan
        .as_mut()
        .and_then(|p| p.pre_read(ctx.target.record_old_value, &ctx.target.names));
    let fail_closed = ctx.target.fail_mode == FailMode::Closed;
    if let (Some(plan), true) = (&plan, fail_closed) {
        let entry = AuditEntry::new(plan.intent())
            .target(ctx.target.config.name.clone())
            .client(client.clone());
        if let Err(e) = ctx.target.audit.record_committed(entry).await {
            tracing::error!(
                "fail-closed: rejecting {} because the audit store failed: {e}",
                plan.service()
            );
            return fault(handle, StatusCode::BadInternalError);
        }
    }

    let response = match pre_read {
        None => ctx.upstream.send(request, timeout).await,
        Some(pre) => {
            // Queue the read right before the change, in the client's own
            // session, without waiting: both reach the server in order and the
            // change is not delayed by an extra round trip.
            let read = ReadRequest {
                request_header: RequestHeader {
                    authentication_token: header.authentication_token.clone(),
                    timestamp: DateTime::now(),
                    request_handle: ctx.target.next_request_handle(),
                    timeout_hint: PRE_READ_TIMEOUT.as_millis() as u32,
                    ..Default::default()
                },
                max_age: 0.0,
                timestamps_to_return: TimestampsToReturn::Neither,
                nodes_to_read: Some(pre.nodes_to_read.clone()),
            };
            // `biased`: poll (and so queue) the read first.
            let (read, response) = tokio::join!(
                biased;
                ctx.upstream.send(read.into(), PRE_READ_TIMEOUT),
                ctx.upstream.send(request, timeout)
            );
            if let (Some(plan), Ok(ResponseMessage::Read(read))) = (plan.as_mut(), read) {
                plan.apply_pre_read(
                    pre,
                    read.results.as_deref().unwrap_or_default(),
                    &ctx.target.names,
                );
            }
            response
        }
    };
    let (response, unknown) = match response {
        Ok(response) => (response, None),
        Err(e) => (fault(handle, e.status()), e.maybe_sent.then(|| e.status())),
    };

    if let Some(plan) = plan {
        let events = match unknown {
            Some(status) => plan.events_unknown(&response, status),
            None => plan.events(&response),
        };
        for event in events {
            let entry = AuditEntry::new(event)
                .target(ctx.target.config.name.clone())
                .client(client.clone());
            if fail_closed {
                if let Err(e) = ctx.target.audit.record_committed(entry).await {
                    tracing::error!("audit record for a forwarded change failed: {e}");
                }
            } else {
                let _ = ctx.target.audit.record(entry).await;
            }
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use opcua::crypto::{legacy_encrypt_secret, X509Data};
    use opcua::types::UserTokenPolicy;

    use super::*;

    /// Audit finding N2: a secret whose decrypted length is shorter than the
    /// nonce made async-opcua panic.
    #[test]
    fn malformed_password_secret_is_rejected_not_panicking() {
        let (cert, key) = X509::cert_and_pkey(&X509Data::sample_cert()).unwrap();
        let policy = UserTokenPolicy {
            policy_id: "user".into(),
            token_type: UserTokenType::UserName,
            security_policy_uri: SecurityPolicy::Basic256Sha256.to_uri().into(),
            ..Default::default()
        };
        // Encrypted with an empty nonce and password: the length prefix is 0.
        let secret = legacy_encrypt_secret(
            SecurityPolicy::None,
            MessageSecurityMode::None,
            &policy,
            &[],
            &Some(cert),
            b"",
        )
        .unwrap();
        let token = UserNameIdentityToken {
            policy_id: "user".into(),
            user_name: "operator".into(),
            password: secret.secret,
            encryption_algorithm: secret.encryption_algorithm,
        };
        assert_eq!(
            decrypt_password(&token, &[7u8; 32], &key),
            Err(StatusCode::BadIdentityTokenInvalid)
        );
    }

    #[test]
    fn security_is_ordered() {
        let none = security_rank(SecurityPolicy::None, MessageSecurityMode::None);
        let sign = security_rank(SecurityPolicy::Basic256Sha256, MessageSecurityMode::Sign);
        let encrypt = security_rank(
            SecurityPolicy::Basic256Sha256,
            MessageSecurityMode::SignAndEncrypt,
        );
        assert!(none < sign && sign < encrypt);
        // A None policy is None whatever the mode says.
        assert_eq!(
            security_rank(SecurityPolicy::None, MessageSecurityMode::SignAndEncrypt),
            none
        );
    }
}
