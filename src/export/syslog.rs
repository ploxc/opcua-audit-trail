//! Syslog destination (RFC 5424), for SIEMs such as Graylog, Splunk or Wazuh.
//!
//! Each record is one message: structured data carries sequence number,
//! hashes, target, node and status, the message is the record as JSON. TCP
//! and TLS (RFC 5425) use octet-counting framing (RFC 6587); UDP is
//! fire-and-forget. Plain syslog has no acknowledgements: a receiver that
//! restarts can lose what it had not processed yet, so compare exported
//! sequence numbers when completeness matters.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use chrono::SecondsFormat;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::audit::store::StoredRecord;
use crate::config::{SyslogConfig, SyslogProtocol};

/// A connected stream receiver (plain TCP or TLS).
trait Stream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> Stream for T {}

const APP_NAME: &str = "opcua-audit-gateway";
/// Enterprise number reserved for documentation (RFC 5612).
const SD_ID: &str = "audit@32473";
/// Keep UDP datagrams below common receiver limits.
const MAX_UDP_MESSAGE: usize = 8000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A receiver that stops reading must not hang the exporter.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

pub struct SyslogSink {
    address: String,
    protocol: SyslogProtocol,
    facility: u8,
    hostname: String,
    tls: Option<Arc<rustls::ClientConfig>>,
    stream: Option<Box<dyn Stream>>,
    udp: Option<UdpSocket>,
}

impl SyslogSink {
    pub fn new(config: &SyslogConfig) -> anyhow::Result<Self> {
        let hostname = opcua::crypto::X509Data::computer_hostnames()
            .into_iter()
            .next()
            .map(|h| {
                h.chars()
                    .filter(|c| c.is_ascii_graphic())
                    .collect::<String>()
            })
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| "-".into());
        let tls = match config.protocol {
            SyslogProtocol::Tls => Some(super::tls::client_config(config.ca_file.as_deref())?),
            _ => None,
        };
        Ok(Self {
            address: config.address.clone(),
            protocol: config.protocol,
            facility: config.facility,
            hostname,
            tls,
            stream: None,
            udp: None,
        })
    }

    pub fn destination(&self) -> String {
        let protocol = match self.protocol {
            SyslogProtocol::Udp => "udp",
            SyslogProtocol::Tcp => "tcp",
            SyslogProtocol::Tls => "tls",
        };
        format!("syslog {protocol}://{}", self.address)
    }

    pub async fn send(&mut self, records: &[StoredRecord]) -> anyhow::Result<()> {
        match self.protocol {
            SyslogProtocol::Udp => {
                if self.udp.is_none() {
                    let bind = if self.address.starts_with('[') {
                        "[::]:0"
                    } else {
                        "0.0.0.0:0"
                    };
                    let socket = UdpSocket::bind(bind).await?;
                    socket
                        .connect(&self.address)
                        .await
                        .with_context(|| format!("resolving {}", self.address))?;
                    self.udp = Some(socket);
                }
                let socket = self.udp.as_ref().expect("set above");
                for record in records {
                    let mut message = self.message(record);
                    if message.len() > MAX_UDP_MESSAGE {
                        // Shorten the values, not the message: the JSON stays
                        // valid and node, status and hashes stay in.
                        message = self.message_with(record, true);
                        truncate(&mut message, MAX_UDP_MESSAGE);
                    }
                    socket.send(message.as_bytes()).await?;
                }
                Ok(())
            }
            SyslogProtocol::Tcp | SyslogProtocol::Tls => {
                // A receiver that went away is only noticed on the second
                // write after it; look for its close first.
                if let Some(stream) = self.stream.as_mut() {
                    let mut byte = [0u8; 1];
                    if let Ok(Ok(0) | Err(_)) =
                        tokio::time::timeout(Duration::ZERO, stream.read(&mut byte)).await
                    {
                        self.stream = None;
                    }
                }
                if self.stream.is_none() {
                    self.stream = Some(self.connect().await?);
                }
                let mut buffer = Vec::new();
                for record in records {
                    let message = self.message(record);
                    buffer.extend_from_slice(format!("{} ", message.len()).as_bytes());
                    buffer.extend_from_slice(message.as_bytes());
                }
                let stream = self.stream.as_mut().expect("set above");
                let result = tokio::time::timeout(WRITE_TIMEOUT, async {
                    stream.write_all(&buffer).await?;
                    stream.flush().await
                })
                .await
                .unwrap_or_else(|_| {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "the receiver does not take data",
                    ))
                });
                if let Err(e) = result {
                    // Reconnect next time; the batch is retried.
                    self.stream = None;
                    return Err(e).with_context(|| format!("writing to {}", self.address));
                }
                Ok(())
            }
        }
    }

    async fn connect(&self) -> anyhow::Result<Box<dyn Stream>> {
        let connect = async {
            Ok::<Box<dyn Stream>, anyhow::Error>(match &self.tls {
                None => Box::new(
                    TcpStream::connect(&self.address)
                        .await
                        .with_context(|| format!("connecting to {}", self.address))?,
                ),
                Some(tls) => {
                    let (host, port) = super::tls::host_port(&self.address)?;
                    Box::new(super::tls::connect(tls.clone(), &host, port).await?)
                }
            })
        };
        tokio::time::timeout(CONNECT_TIMEOUT, connect)
            .await
            .map_err(|_| anyhow::anyhow!("timeout connecting to {}", self.address))?
    }

    pub fn message(&self, record: &StoredRecord) -> String {
        self.message_with(record, false)
    }

    /// `compact` replaces written values and arguments by a marker, for
    /// receivers with a size limit.
    fn message_with(&self, record: &StoredRecord, compact: bool) -> String {
        let entry = &record.entry;
        let kind = entry.event.kind();
        let pri = u16::from(self.facility) * 8 + u16::from(severity(kind));
        let ts = entry.ts.to_rfc3339_opts(SecondsFormat::Micros, true);
        let mut event = serde_json::to_value(&entry.event).unwrap_or_default();
        if compact {
            if let Some(event) = event.as_object_mut() {
                for key in ["old_value", "new_value", "input_arguments", "details"] {
                    if event.contains_key(key) {
                        event.insert(key.into(), serde_json::json!({ "truncated": true }));
                    }
                }
            }
        }
        let json = serde_json::json!({
            "seq": record.seq,
            "hash": record.hash,
            "prev_hash": record.prev_hash,
            "ts": ts,
            "target": entry.target,
            "client": entry.client,
            "event": event,
        });
        let mut sd = format!(
            "[{SD_ID} seq=\"{}\" hash=\"{}\" prev_hash=\"{}\"",
            record.seq, record.hash, record.prev_hash
        );
        if let Some(target) = &entry.target {
            sd.push_str(&format!(" target=\"{}\"", sd_escape(target)));
        }
        if let Some(node) = entry.event.node_id() {
            sd.push_str(&format!(" node=\"{}\"", sd_escape(node)));
        }
        if let Some(status) = event.get("status").and_then(|s| s.as_str()) {
            sd.push_str(&format!(" status=\"{}\"", sd_escape(status)));
        }
        sd.push(']');
        format!(
            "<{pri}>1 {ts} {} {APP_NAME} - {kind} {sd} {json}",
            self.hostname
        )
    }
}

/// Changes are notices, failures warnings, the rest informational.
fn severity(kind: &str) -> u8 {
    match kind {
        "trail_truncated" => 3,
        "authentication_failed"
        | "certificate_rejected"
        | "ui_login_failed"
        | "upstream_unavailable"
        | "upstream_endpoints_changed"
        | "connections_refused"
        | "clock_jumped"
        | "export_gap"
        | "events_lost" => 4,
        "write"
        | "call"
        | "history_update"
        | "node_management"
        | "change_intent"
        | "subscriptions_transferred"
        | "config_changed"
        | "retention_pruned" => 5,
        _ => 6,
    }
}

fn sd_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(']', "\\]")
}

fn truncate(message: &mut String, max: usize) {
    if message.len() > max {
        let mut cut = max;
        while !message.is_char_boundary(cut) {
            cut -= 1;
        }
        message.truncate(cut);
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;

    use super::*;
    use crate::export::tests::write_record;

    fn config(address: String, protocol: SyslogProtocol) -> SyslogConfig {
        SyslogConfig {
            address,
            protocol,
            facility: 16,
            interval_secs: 1,
            ca_file: None,
        }
    }

    #[test]
    fn message_format() {
        let sink = SyslogSink::new(&config("127.0.0.1:514".into(), SyslogProtocol::Udp)).unwrap();
        let m = sink.message(&write_record(9));
        // local0 (16) * 8 + notice (5)
        assert!(m.starts_with("<133>1 "), "{m}");
        assert!(m.contains(
            " opcua-audit-gateway - write [audit@32473 seq=\"9\" hash=\"hash9\" prev_hash=\"hash8\" \
             target=\"line 1\" node=\"ns=3;s=\\\"DB1\\\".\\\"Set point\\\"\" status=\"Good\"] {"
        ), "{m}");
        let json: serde_json::Value =
            serde_json::from_str(&m[m.find(" {").unwrap() + 1..]).unwrap();
        assert_eq!(json["event"]["new_value"]["value"], 2.5);
    }

    #[tokio::test]
    async fn udp_delivery() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut sink = SyslogSink::new(&config(
            receiver.local_addr().unwrap().to_string(),
            SyslogProtocol::Udp,
        ))
        .unwrap();
        sink.send(&[write_record(1), write_record(2)])
            .await
            .unwrap();
        let mut buf = vec![0u8; 16384];
        for seq in [1, 2] {
            let n = receiver.recv(&mut buf).await.unwrap();
            let m = String::from_utf8_lossy(&buf[..n]);
            assert!(m.contains(&format!("seq=\"{seq}\"")));
        }
    }

    #[tokio::test]
    async fn tcp_octet_counting() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut sink = SyslogSink::new(&config(
            listener.local_addr().unwrap().to_string(),
            SyslogProtocol::Tcp,
        ))
        .unwrap();
        let accept = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut data = Vec::new();
            let mut buf = [0u8; 4096];
            while data.iter().filter(|&&b| b == b'<').count() < 2 || !data.ends_with(b"}") {
                let n = stream.read(&mut buf).await.unwrap();
                data.extend_from_slice(&buf[..n]);
            }
            String::from_utf8(data).unwrap()
        });
        sink.send(&[write_record(1), write_record(2)])
            .await
            .unwrap();
        let data = accept.await.unwrap();
        // "<len> <message><len> <message>"
        let (len, rest) = data.split_once(' ').unwrap();
        let len: usize = len.parse().unwrap();
        assert!(rest[..len].starts_with("<133>1 "));
        assert!(rest[len..]
            .split_once(' ')
            .unwrap()
            .1
            .starts_with("<133>1 "));
    }

    /// Audit finding E3: syslog over TLS (RFC 5425 framing), verified
    /// against the configured CA file.
    #[tokio::test]
    async fn tls_delivery() {
        let dir = tempfile::tempdir().unwrap();
        let (server, ca_file) = crate::export::tls::tests::localhost_server(dir.path());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut stream = tokio_rustls::TlsAcceptor::from(server)
                .accept(tcp)
                .await
                .unwrap();
            let mut data = Vec::new();
            let mut buf = [0u8; 4096];
            while data.iter().filter(|&&b| b == b'<').count() < 2 || !data.ends_with(b"}") {
                let n = stream.read(&mut buf).await.unwrap();
                data.extend_from_slice(&buf[..n]);
            }
            String::from_utf8(data).unwrap()
        });
        let mut sink = SyslogSink::new(&SyslogConfig {
            ca_file: Some(ca_file),
            ..config(format!("localhost:{port}"), SyslogProtocol::Tls)
        })
        .unwrap();
        sink.send(&[write_record(1), write_record(2)])
            .await
            .unwrap();
        let data = accept.await.unwrap();
        let (len, rest) = data.split_once(' ').unwrap();
        let len: usize = len.parse().unwrap();
        assert!(rest[..len].contains("seq=\"1\""));
        assert!(rest[len..].contains("seq=\"2\""));
    }

    /// Audit finding I4: a large record is shortened in its values, so the
    /// JSON stays valid and says which node was written.
    #[test]
    fn large_udp_records_keep_valid_json() {
        let sink = SyslogSink::new(&config("127.0.0.1:514".into(), SyslogProtocol::Udp)).unwrap();
        let mut record = write_record(3);
        if let crate::audit::event::AuditEvent::Write { new_value, .. } = &mut record.entry.event {
            new_value.value = serde_json::json!("x".repeat(9000));
        }
        let m = sink.message_with(&record, true);
        assert!(m.len() < MAX_UDP_MESSAGE);
        let json: serde_json::Value =
            serde_json::from_str(&m[m.find(" {").unwrap() + 1..]).unwrap();
        assert_eq!(json["event"]["node_id"], "ns=3;s=\"DB1\".\"Set point\"");
        assert_eq!(json["event"]["new_value"]["truncated"], true);
    }

    /// Audit finding N10: after the receiver closed the connection, the next
    /// batch goes over a new connection instead of into the void.
    #[tokio::test]
    async fn tcp_reconnects_after_the_receiver_closed() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut sink = SyslogSink::new(&config(
            listener.local_addr().unwrap().to_string(),
            SyslogProtocol::Tcp,
        ))
        .unwrap();
        sink.send(&[write_record(1)]).await.unwrap();
        let (mut first, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 16384];
        let _ = first.read(&mut buf).await.unwrap();
        drop(first); // the receiver restarts
        tokio::time::sleep(Duration::from_millis(200)).await;

        sink.send(&[write_record(2)]).await.unwrap();
        let (mut second, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("a new connection")
            .unwrap();
        let n = second.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("seq=\"2\""));
    }
}
