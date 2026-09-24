//! Syslog destination (RFC 5424), for SIEMs such as Graylog, Splunk or Wazuh.
//!
//! Each record is one message: structured data carries sequence number, hash
//! and target, the message is the record as JSON. TCP uses octet-counting
//! framing (RFC 6587) and is reliable; UDP is fire-and-forget.

use std::time::Duration;

use anyhow::Context;
use chrono::SecondsFormat;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

use crate::audit::store::StoredRecord;
use crate::config::{SyslogConfig, SyslogProtocol};

const APP_NAME: &str = "opcua-audit-gateway";
/// Enterprise number reserved for documentation (RFC 5612).
const SD_ID: &str = "audit@32473";
/// Keep UDP datagrams below common receiver limits.
const MAX_UDP_MESSAGE: usize = 8000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct SyslogSink {
    address: String,
    protocol: SyslogProtocol,
    facility: u8,
    hostname: String,
    tcp: Option<TcpStream>,
    udp: Option<UdpSocket>,
}

impl SyslogSink {
    pub fn new(config: &SyslogConfig) -> Self {
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
        Self {
            address: config.address.clone(),
            protocol: config.protocol,
            facility: config.facility,
            hostname,
            tcp: None,
            udp: None,
        }
    }

    pub fn destination(&self) -> String {
        let protocol = match self.protocol {
            SyslogProtocol::Udp => "udp",
            SyslogProtocol::Tcp => "tcp",
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
                    truncate(&mut message, MAX_UDP_MESSAGE);
                    socket.send(message.as_bytes()).await?;
                }
                Ok(())
            }
            SyslogProtocol::Tcp => {
                if self.tcp.is_none() {
                    let stream =
                        tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.address))
                            .await
                            .map_err(|_| anyhow::anyhow!("timeout connecting to {}", self.address))?
                            .with_context(|| format!("connecting to {}", self.address))?;
                    self.tcp = Some(stream);
                }
                let mut buffer = Vec::new();
                for record in records {
                    let message = self.message(record);
                    buffer.extend_from_slice(format!("{} ", message.len()).as_bytes());
                    buffer.extend_from_slice(message.as_bytes());
                }
                let stream = self.tcp.as_mut().expect("set above");
                let result = async {
                    stream.write_all(&buffer).await?;
                    stream.flush().await
                }
                .await;
                if let Err(e) = result {
                    // Reconnect next time; the batch is retried.
                    self.tcp = None;
                    return Err(e).with_context(|| format!("writing to {}", self.address));
                }
                Ok(())
            }
        }
    }

    pub fn message(&self, record: &StoredRecord) -> String {
        let entry = &record.entry;
        let kind = entry.event.kind();
        let pri = u16::from(self.facility) * 8 + u16::from(severity(kind));
        let ts = entry.ts.to_rfc3339_opts(SecondsFormat::Micros, true);
        let json = serde_json::json!({
            "seq": record.seq,
            "hash": record.hash,
            "ts": ts,
            "target": entry.target,
            "client": entry.client,
            "event": entry.event,
        });
        let mut sd = format!("[{SD_ID} seq=\"{}\" hash=\"{}\"", record.seq, record.hash);
        if let Some(target) = &entry.target {
            sd.push_str(&format!(" target=\"{}\"", sd_escape(target)));
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
        "authentication_failed"
        | "certificate_rejected"
        | "ui_login_failed"
        | "upstream_unavailable"
        | "events_lost" => 4,
        "write" | "call" | "history_update" | "node_management" | "change_intent"
        | "config_changed" | "retention_pruned" => 5,
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
        }
    }

    #[test]
    fn message_format() {
        let sink = SyslogSink::new(&config("127.0.0.1:514".into(), SyslogProtocol::Udp));
        let m = sink.message(&write_record(9));
        // local0 (16) * 8 + notice (5)
        assert!(m.starts_with("<133>1 "), "{m}");
        assert!(m.contains(" opcua-audit-gateway - write [audit@32473 seq=\"9\" hash=\"hash9\" target=\"line 1\"] {"));
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
        ));
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
        ));
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
}
