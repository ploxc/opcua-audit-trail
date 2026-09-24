//! Server side of the relay: the `opc.tcp` transport towards a downstream client.
//!
//! Handles the Hello/Acknowledge handshake, reassembles and decrypts incoming
//! chunks into complete requests, and chunks, signs and encrypts responses.
//! Security itself lives in the [`SecureChannel`]; this type only moves bytes.

use std::time::Duration;

use bytes::BytesMut;
use futures::StreamExt;
use opcua::core::comms::buffer::SendBuffer;
use opcua::core::comms::chunker::Chunker;
use opcua::core::comms::message_chunk::{MessageChunk, MessageChunkHeader, MessageIsFinalType};
use opcua::core::comms::secure_channel::SecureChannel;
use opcua::core::comms::security_header::SecurityHeader;
use opcua::core::comms::sequence_number::SequenceNumberHandle;
use opcua::core::comms::tcp_codec::{Message, TcpCodec};
use opcua::core::comms::tcp_types::{AcknowledgeMessage, ErrorMessage};
use opcua::core::{RequestMessage, ResponseMessage};
use opcua::types::{
    ByteString, DecodingOptions, Error, ResponseHeader, ServiceFault, SimpleBinaryDecodable,
    SimpleBinaryEncodable, StatusCode,
};
use tokio::io::{AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_util::codec::{Decoder, FramedRead};

/// Buffer and message limits.
#[derive(Debug, Clone)]
pub struct Limits {
    pub send_buffer_size: usize,
    pub receive_buffer_size: usize,
    /// Largest message the gateway sends or accepts from the upstream server.
    pub max_message_size: usize,
    pub max_chunk_count: usize,
    /// Largest request a client may send. Every byte of it is held in memory
    /// until the request is complete, before anyone is authenticated.
    pub max_request_size: usize,
    pub max_request_chunks: usize,
    pub hello_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            send_buffer_size: 65535,
            receive_buffer_size: 65535,
            max_message_size: 64 * 1024 * 1024,
            max_chunk_count: 4096,
            max_request_size: 8 * 1024 * 1024,
            max_request_chunks: 1024,
            hello_timeout: Duration::from_secs(10),
        }
    }
}

/// Largest Hello the gateway reads (the endpoint URL is at most 4096 bytes).
const MAX_HELLO_SIZE: usize = 8192;
/// Largest OpenSecureChannel request before a channel exists (it carries a
/// certificate of a few kilobytes).
const MAX_OPEN_SIZE: usize = 64 * 1024;

/// async-opcua's codec buffers as many bytes as a frame header announces
/// (up to 4 GiB) before checking anything. This one refuses a frame whose
/// announced size exceeds the limit as soon as its header has arrived.
pub struct LimitedCodec {
    inner: TcpCodec,
    max_frame: usize,
}

impl Decoder for LimitedCodec {
    type Item = Message;
    type Error = std::io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Message>, Self::Error> {
        if buf.len() >= 8 {
            let size = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
            if size > self.max_frame {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "frame of {size} bytes exceeds the negotiated {} bytes",
                        self.max_frame
                    ),
                ));
            }
        }
        self.inner.decode(buf)
    }
}

/// Decoding limits for relayed messages. Generous, because the gateway must not
/// reject what the upstream server would accept.
pub fn decoding_options(limits: &Limits) -> DecodingOptions {
    DecodingOptions {
        max_message_size: limits.max_message_size,
        max_chunk_count: limits.max_chunk_count,
        max_string_length: 16 * 1024 * 1024,
        max_byte_string_length: 16 * 1024 * 1024,
        max_array_length: 4 * 1024 * 1024,
        ..DecodingOptions::default()
    }
}

#[derive(Debug)]
pub struct Request {
    pub message: RequestMessage,
    pub request_id: u32,
    pub security_header: SecurityHeader,
}

#[derive(Debug)]
pub enum PollResult {
    Sent,
    Chunk,
    Request(Request),
    /// A request could not be decoded; answer it with a fault and carry on.
    Recoverable(StatusCode, u32, u32),
    Error(StatusCode),
    Closed,
}

/// The security of an issued secure channel. Every later OpenSecureChannel
/// (a renewal) must present exactly this policy and certificate.
#[derive(Debug, Clone)]
pub struct ChannelBinding {
    pub policy_uri: String,
    pub certificate: ByteString,
}

pub struct Downstream {
    read: FramedRead<ReadHalf<TcpStream>, LimitedCodec>,
    write: WriteHalf<TcpStream>,
    send_buffer: SendBuffer,
    pending_chunks: Vec<MessageChunk>,
    /// Size of `pending_chunks` in bytes.
    pending_bytes: usize,
    /// What the client may send: chunks per request and bytes per request.
    max_request_chunks: usize,
    max_request_size: usize,
    sequence_numbers: SequenceNumberHandle,
    closing: bool,
    /// Set once the channel is issued.
    pub binding: Option<ChannelBinding>,
    /// Endpoint URL the client used in its Hello.
    pub endpoint_url: String,
    pub protocol_version: u32,
}

fn min_zero_infinite(ours: u32, theirs: u32) -> u32 {
    match (ours, theirs) {
        (0, t) => t,
        (o, 0) => o,
        (o, t) => o.min(t),
    }
}

impl Downstream {
    /// Waits for the client's Hello and answers with an Acknowledge.
    pub async fn accept(
        stream: TcpStream,
        limits: &Limits,
        decoding: DecodingOptions,
    ) -> Result<Self, StatusCode> {
        let (read, mut write) = tokio::io::split(stream);
        let mut read = FramedRead::new(
            read,
            LimitedCodec {
                inner: TcpCodec::new(decoding.clone()),
                max_frame: MAX_HELLO_SIZE,
            },
        );

        let result = tokio::time::timeout(limits.hello_timeout, read.next()).await;
        let hello = match result {
            Ok(Some(Ok(Message::Hello(hello)))) => hello,
            Ok(Some(Ok(_))) => {
                return Err(send_error(
                    &mut write,
                    StatusCode::BadCommunicationError,
                    "expected Hello",
                )
                .await)
            }
            Ok(Some(Err(_))) | Ok(None) => return Err(StatusCode::BadCommunicationError),
            Err(_) => {
                return Err(send_error(
                    &mut write,
                    StatusCode::BadTimeout,
                    "timeout waiting for Hello",
                )
                .await)
            }
        };
        if !hello.is_valid_buffer_sizes() {
            return Err(send_error(
                &mut write,
                StatusCode::BadCommunicationError,
                "invalid Hello buffer sizes",
            )
            .await);
        }
        if hello.protocol_version > 0 {
            return Err(send_error(
                &mut write,
                StatusCode::BadProtocolVersionUnsupported,
                "protocol version unsupported",
            )
            .await);
        }

        let mut send_buffer = SendBuffer::new(
            limits.send_buffer_size,
            limits.max_message_size,
            limits.max_chunk_count,
            true,
        );
        // The Acknowledge states what the gateway accepts; the Hello's message
        // size and chunk count are what the client accepts, i.e. limits for
        // the responses.
        let ack = AcknowledgeMessage::new(
            0,
            (limits.receive_buffer_size as u32).min(hello.send_buffer_size),
            (limits.send_buffer_size as u32).min(hello.receive_buffer_size),
            limits.max_request_size as u32,
            limits.max_request_chunks as u32,
        );
        send_buffer.revise(
            ack.send_buffer_size as usize,
            min_zero_infinite(limits.max_message_size as u32, hello.max_message_size) as usize,
            min_zero_infinite(limits.max_chunk_count as u32, hello.max_chunk_count) as usize,
        );
        // From now on no frame may exceed the receive buffer the client got.
        read.decoder_mut().max_frame = ack.receive_buffer_size as usize;
        let mut buf = Vec::with_capacity(ack.byte_len());
        ack.encode(&mut buf)
            .map_err(|_| StatusCode::BadEncodingError)?;
        write
            .write_all(&buf)
            .await
            .map_err(|_| StatusCode::BadCommunicationError)?;

        Ok(Self {
            read,
            write,
            send_buffer,
            pending_chunks: Vec::new(),
            pending_bytes: 0,
            max_request_chunks: limits.max_request_chunks,
            max_request_size: limits.max_request_size,
            sequence_numbers: SequenceNumberHandle::new(true),
            closing: false,
            binding: None,
            endpoint_url: hello.endpoint_url.as_ref().to_string(),
            protocol_version: hello.protocol_version,
        })
    }

    pub fn set_closing(&mut self) {
        self.closing = true;
    }

    /// Queues a fatal error; the connection closes once it is sent.
    pub fn enqueue_error(&mut self, status: StatusCode, reason: &str) {
        if !self.closing {
            self.send_buffer
                .write_error(ErrorMessage::new(status, reason));
        }
        self.closing = true;
    }

    pub fn enqueue(
        &mut self,
        channel: &SecureChannel,
        message: ResponseMessage,
        request_id: u32,
    ) -> Result<(), StatusCode> {
        match self.send_buffer.write(request_id, message, channel) {
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::warn!("failed to encode response: {e}");
                // The response did not fit (e.g. too large): answer with a fault
                // so the client is not left waiting.
                let Some((request_id, request_handle)) = e.full_context() else {
                    return Err(e.status());
                };
                let fault = ServiceFault {
                    response_header: ResponseHeader::new_service_result(request_handle, e.status()),
                };
                self.send_buffer
                    .write(request_id, ResponseMessage::from(fault), channel)
                    .map(|_| ())
                    .map_err(|e| e.status())
            }
        }
    }

    /// Makes progress on sending and receiving. Cancellation safe. Once the
    /// connection is closing, nothing more is read: only queued data is sent.
    pub async fn poll(&mut self, channel: &mut SecureChannel) -> PollResult {
        if self.send_buffer.should_encode_chunks() {
            if let Err(e) = self.send_buffer.encode_next_chunk(channel) {
                return PollResult::Error(e);
            }
        }
        if self.closing {
            if self.send_buffer.can_read() {
                return match self.send_buffer.read_into_async(&mut self.write).await {
                    Ok(()) => PollResult::Sent,
                    Err(_) => PollResult::Closed,
                };
            }
            let _ = self.write.shutdown().await;
            return PollResult::Closed;
        }
        if self.send_buffer.can_read() {
            tokio::select! {
                r = self.send_buffer.read_into_async(&mut self.write) => match r {
                    Ok(()) => PollResult::Sent,
                    Err(_) => PollResult::Closed,
                },
                incoming = self.read.next() => self.handle_incoming(incoming, channel),
            }
        } else {
            let incoming = self.read.next().await;
            self.handle_incoming(incoming, channel)
        }
    }

    fn handle_incoming(
        &mut self,
        incoming: Option<Result<Message, std::io::Error>>,
        channel: &mut SecureChannel,
    ) -> PollResult {
        match incoming {
            None => PollResult::Closed,
            Some(Err(e)) => {
                tracing::debug!("read error: {e}");
                PollResult::Error(StatusCode::BadConnectionClosed)
            }
            Some(Ok(message)) => match self.process(message, channel) {
                Ok(None) => PollResult::Chunk,
                Ok(Some(request)) => {
                    self.pending_chunks.clear();
                    self.pending_bytes = 0;
                    PollResult::Request(request)
                }
                Err(e) => {
                    self.pending_chunks.clear();
                    self.pending_bytes = 0;
                    match e.full_context() {
                        Some((id, handle)) => PollResult::Recoverable(e.status(), id, handle),
                        None => {
                            tracing::warn!("rejecting message: {e}");
                            PollResult::Error(e.status())
                        }
                    }
                }
            },
        }
    }

    fn process(
        &mut self,
        message: Message,
        channel: &mut SecureChannel,
    ) -> Result<Option<Request>, Error> {
        let Message::Chunk(chunk) = message else {
            return Err(Error::new(
                StatusCode::BadUnexpectedError,
                "unexpected message type after Hello",
            ));
        };
        let header = chunk.message_header(&channel.decoding_options())?;
        if self.binding.is_none() && !header.message_type.is_open_secure_channel() {
            // Nothing but OpenSecureChannel is accepted, let alone buffered,
            // before a channel exists.
            return Err(Error::new(
                StatusCode::BadSecureChannelIdInvalid,
                "message before OpenSecureChannel",
            ));
        }
        if header.message_type.is_open_secure_channel() {
            if let Some(binding) = &self.binding {
                // Checked before the library sees the chunk: parsing an
                // OpenSecureChannel switches the channel to its policy.
                check_renewal(&chunk, binding, &channel.decoding_options())?;
            }
        }
        if header.is_final == MessageIsFinalType::FinalError {
            // The client aborted a multi-chunk request.
            self.pending_chunks.clear();
            self.pending_bytes = 0;
            return Ok(None);
        }
        let chunk = channel.verify_and_remove_security_server(chunk.data)?;
        if self.pending_chunks.len() >= self.max_request_chunks {
            return Err(Error::decoding(
                "message exceeds the negotiated chunk count",
            ));
        }
        self.pending_bytes += chunk.data.len();
        let limit = if self.binding.is_none() {
            MAX_OPEN_SIZE
        } else {
            self.max_request_size
        };
        if self.pending_bytes > limit {
            return Err(Error::decoding(
                "message exceeds the negotiated message size",
            ));
        }
        let info = chunk.chunk_info(channel)?;
        self.sequence_numbers
            .validate_and_increment(info.sequence_header.sequence_number)?;
        self.pending_chunks.push(chunk);
        if header.is_final == MessageIsFinalType::Intermediate {
            return Ok(None);
        }

        let first = self.pending_chunks[0].chunk_info(channel)?;
        Chunker::validate_chunks(channel, &self.pending_chunks)?;
        let request_id = first.sequence_header.request_id;
        let message = Chunker::decode(&self.pending_chunks, channel, None)
            .map_err(|e| e.with_request_id(request_id))?;
        Ok(Some(Request {
            message,
            request_id,
            security_header: first.security_header,
        }))
    }
}

/// A renewal must keep the issued channel's security policy and certificate.
/// Otherwise anyone on the network path could re-key the channel with their
/// own certificate, or downgrade it to SecurityPolicy None.
fn check_renewal(
    chunk: &MessageChunk,
    binding: &ChannelBinding,
    options: &DecodingOptions,
) -> Result<(), Error> {
    let mut stream = std::io::Cursor::new(&chunk.data[..]);
    MessageChunkHeader::decode(&mut stream, options)?;
    let SecurityHeader::Asymmetric(header) =
        SecurityHeader::decode_from_stream(&mut stream, true, options)?
    else {
        return Err(Error::new(
            StatusCode::BadSecurityChecksFailed,
            "OpenSecureChannel without asymmetric security header",
        ));
    };
    if header.security_policy_uri.as_ref() != binding.policy_uri
        || header.sender_certificate != binding.certificate
    {
        return Err(Error::new(
            StatusCode::BadSecurityChecksFailed,
            "secure channel renewal with a different security policy or certificate",
        ));
    }
    Ok(())
}

async fn send_error(
    write: &mut WriteHalf<TcpStream>,
    status: StatusCode,
    reason: &str,
) -> StatusCode {
    let err = ErrorMessage::new(status, reason);
    let mut buf = Vec::with_capacity(err.byte_len());
    if err.encode(&mut buf).is_ok() {
        let _ = write.write_all(&buf).await;
    }
    status
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use opcua::core::comms::chunker::Chunker;
    use opcua::core::comms::secure_channel::Role;
    use opcua::crypto::{CertificateStore, SecurityPolicy};
    use opcua::types::{
        ContextOwned, MessageSecurityMode, NamespaceMap, OpenSecureChannelRequest,
        SecurityTokenRequestType,
    };

    use super::*;

    /// An OpenSecureChannel renewal as a client with SecurityPolicy None sends it.
    fn none_renewal() -> MessageChunk {
        let dir = tempfile::tempdir().unwrap();
        let channel = SecureChannel::new(
            Arc::new(parking_lot::RwLock::new(CertificateStore::new(dir.path()))),
            Role::Client,
            Arc::new(parking_lot::RwLock::new(ContextOwned::new_default(
                NamespaceMap::new(),
                DecodingOptions::default(),
            ))),
        );
        let request = OpenSecureChannelRequest {
            request_type: SecurityTokenRequestType::Renew,
            security_mode: MessageSecurityMode::None,
            requested_lifetime: 60_000,
            ..Default::default()
        };
        let mut chunks = Chunker::encode(
            SequenceNumberHandle::new(true),
            1,
            0,
            0,
            &channel,
            &RequestMessage::from(request),
        )
        .unwrap();
        chunks.remove(0)
    }

    /// Audit finding R3: a frame announcing more than the limit is refused
    /// from its header, before anything is buffered.
    #[test]
    fn oversized_frame_is_refused_from_its_header() {
        let mut codec = LimitedCodec {
            inner: TcpCodec::new(DecodingOptions::default()),
            max_frame: 65535,
        };
        let mut buf = BytesMut::new();
        buf.extend_from_slice(b"MSGF");
        buf.extend_from_slice(&(1u32 << 30).to_le_bytes());
        assert!(codec.decode(&mut buf).is_err());

        let mut small = BytesMut::new();
        small.extend_from_slice(b"MSGF");
        small.extend_from_slice(&100u32.to_le_bytes());
        assert!(
            codec.decode(&mut small).unwrap().is_none(),
            "waits for the rest"
        );
    }

    /// Audit finding R2: a renewal may not switch policy or certificate.
    #[test]
    fn renewal_must_keep_policy_and_certificate() {
        let chunk = none_renewal();
        let options = DecodingOptions::default();
        let same = ChannelBinding {
            policy_uri: SecurityPolicy::None.to_uri().to_string(),
            certificate: ByteString::null(),
        };
        assert!(check_renewal(&chunk, &same, &options).is_ok());

        // Issued as Basic256Sha256: a None renewal is a downgrade.
        let secure = ChannelBinding {
            policy_uri: SecurityPolicy::Basic256Sha256.to_uri().to_string(),
            certificate: ByteString::null(),
        };
        let err = check_renewal(&chunk, &secure, &options).unwrap_err();
        assert_eq!(err.status(), StatusCode::BadSecurityChecksFailed);

        // Same policy, other certificate.
        let other_cert = ChannelBinding {
            policy_uri: SecurityPolicy::None.to_uri().to_string(),
            certificate: ByteString::from(vec![1u8, 2, 3]),
        };
        assert!(check_renewal(&chunk, &other_cert, &options).is_err());
    }
}
