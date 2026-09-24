//! Client side of the relay: one secure channel to the upstream server per
//! downstream connection, built on async-opcua's client channel (Hello,
//! OpenSecureChannel, token renewal, chunking and request matching).

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use opcua::client::transport::{TcpConnector, TransportConfiguration, TransportPollResult};
use opcua::client::{AsyncSecureChannel, SessionRetryPolicy};
use opcua::core::{RequestMessage, ResponseMessage};
use opcua::crypto::{SecurityPolicy, X509};
use opcua::types::{ContextOwned, EndpointDescription, Error, NamespaceMap, NodeId, StatusCode};
use tokio_util::sync::CancellationToken;

use super::transport::Limits;
use super::GatewayIdentity;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Requested lifetime of upstream security tokens (renewed automatically).
const CHANNEL_LIFETIME_MS: u32 = 3_600_000;

#[derive(Debug)]
pub enum UpstreamError {
    /// The upstream server certificate is not in the trust list (it has been
    /// put in `pki/rejected/` for an administrator).
    Untrusted {
        subject: String,
        thumbprint: String,
        status: StatusCode,
    },
    Other(Error),
}

impl From<Error> for UpstreamError {
    fn from(e: Error) -> Self {
        UpstreamError::Other(e)
    }
}

pub struct Upstream {
    channel: AsyncSecureChannel,
    pub endpoint: EndpointDescription,
    /// The upstream server certificate (verified against the trust list when
    /// the channel is secured).
    pub server_certificate: Option<X509>,
    /// Cancelled when the upstream connection is gone.
    pub closed: CancellationToken,
}

impl Upstream {
    /// Opens a secure channel to `connect_url` using `endpoint`'s security
    /// settings. The server certificate must be in the gateway's trust list.
    pub async fn connect(
        gateway: &GatewayIdentity,
        connect_url: &str,
        endpoint: EndpointDescription,
        limits: &Limits,
        decoding: opcua::types::DecodingOptions,
    ) -> Result<Arc<Self>, UpstreamError> {
        let policy = SecurityPolicy::from_uri(endpoint.security_policy_uri.as_ref());
        let server_certificate = X509::from_byte_string(&endpoint.server_certificate).ok();
        if policy != SecurityPolicy::None {
            let cert = server_certificate.as_ref().ok_or_else(|| {
                Error::new(
                    StatusCode::BadCertificateInvalid,
                    "upstream endpoint has no valid certificate",
                )
            })?;
            gateway
                .certificate_store
                .read()
                .validate_or_reject_application_instance_cert(cert, policy, None, None)
                .map_err(|e| UpstreamError::Untrusted {
                    subject: cert.subject_name(),
                    thumbprint: cert.thumbprint().as_hex_string(),
                    status: e.status(),
                })?;
        }

        let channel = AsyncSecureChannel::new(
            gateway.certificate_store.clone(),
            endpoint.clone().into(),
            SessionRetryPolicy::never(),
            true,
            Arc::new(ArcSwap::new(Arc::new(NodeId::null()))),
            TransportConfiguration {
                send_buffer_size: limits.send_buffer_size,
                recv_buffer_size: limits.receive_buffer_size,
                max_message_size: limits.max_message_size,
                max_chunk_count: limits.max_chunk_count,
            },
            CHANNEL_LIFETIME_MS,
            Arc::new(parking_lot::RwLock::new(ContextOwned::new_default(
                NamespaceMap::new(),
                decoding,
            ))),
        );
        let connector = TcpConnector::new(connect_url)?;
        let mut event_loop =
            tokio::time::timeout(CONNECT_TIMEOUT, channel.connect_no_retry(&connector))
                .await
                .map_err(|_| {
                    Error::new(
                        StatusCode::BadTimeout,
                        format!("timeout connecting to {connect_url}"),
                    )
                })??;

        let closed = CancellationToken::new();
        let loop_closed = closed.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = loop_closed.cancelled() => break,
                    r = event_loop.poll() => {
                        if let TransportPollResult::Closed(status) = r {
                            tracing::debug!("upstream channel closed: {status}");
                            break;
                        }
                    }
                }
            }
            loop_closed.cancel();
        });

        Ok(Arc::new(Self {
            channel,
            endpoint,
            server_certificate,
            closed,
        }))
    }

    pub fn security_policy(&self) -> SecurityPolicy {
        SecurityPolicy::from_uri(self.endpoint.security_policy_uri.as_ref())
    }

    pub async fn send(
        &self,
        request: RequestMessage,
        timeout: Duration,
    ) -> Result<ResponseMessage, Error> {
        if self.closed.is_cancelled() {
            return Err(Error::new(
                StatusCode::BadServerNotConnected,
                "upstream connection closed",
            ));
        }
        self.channel.send(request, timeout).await
    }

    /// Closes the channel politely (CloseSecureChannel), then stops the event loop.
    pub async fn close(&self) {
        if !self.closed.is_cancelled() {
            self.channel.close_channel().await;
            // Give the event loop a moment to flush the close message.
            let _ = tokio::time::timeout(Duration::from_millis(500), self.closed.cancelled()).await;
            self.closed.cancel();
        }
    }
}
