//! QuestDB destination: InfluxDB Line Protocol over HTTP(S) (`POST /write`).
//!
//! HTTP (unlike ILP over TCP) confirms every batch, so the export position
//! only moves on after QuestDB stored the records. The table is created by
//! QuestDB on first write. For exactly-once results after retries, enable
//! deduplication on it: `ALTER TABLE opcua_audit DEDUP ENABLE UPSERT KEYS(ts, seq)`.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST};
use hyper::{Request, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};

use super::fields;
use crate::audit::store::StoredRecord;
use crate::config::QuestDbConfig;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct QuestDbSink {
    client: Client<HttpConnector, Full<Bytes>>,
    /// Set for `https` URLs.
    tls: Option<Arc<rustls::ClientConfig>>,
    uri: Uri,
    table: String,
    authorization: Option<String>,
}

impl QuestDbSink {
    pub fn new(config: &QuestDbConfig) -> anyhow::Result<Self> {
        let uri: Uri = format!("{}/write?precision=n", config.url.trim_end_matches('/'))
            .parse()
            .with_context(|| format!("invalid QuestDB url {}", config.url))?;
        let authorization = match (&config.token, &config.username, &config.password) {
            (Some(token), _, _) => Some(format!("Bearer {token}")),
            (None, Some(user), password) => Some(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(format!(
                    "{user}:{}",
                    password.as_deref().unwrap_or_default()
                ))
            )),
            _ => None,
        };
        let tls = match uri.scheme_str() {
            Some("https") => Some(super::tls::client_config(config.ca_file.as_deref())?),
            _ => None,
        };
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
            tls,
            uri,
            table: config.table.clone(),
            authorization,
        })
    }

    pub fn destination(&self) -> String {
        format!("{} (table {})", self.uri, self.table)
    }

    /// Sends the records. If QuestDB rejects the batch as malformed, they are
    /// sent one by one, and a record it still rejects is replaced by a
    /// minimal line (sequence number, hashes, type) so it cannot block the
    /// export forever.
    pub async fn send(&mut self, records: &[StoredRecord]) -> anyhow::Result<()> {
        let body: String = records.iter().map(|r| line(&self.table, r)).collect();
        match self.post(body).await? {
            None => return Ok(()),
            Some((status, text)) if status != StatusCode::BAD_REQUEST => {
                bail!("QuestDB answered {status}: {text}")
            }
            Some(_) => {}
        }
        for record in records {
            if let Some((_, text)) = self.post(line(&self.table, record)).await? {
                tracing::warn!(
                    "QuestDB rejected audit record {}: {text}; exporting a minimal line",
                    record.seq
                );
                if let Some((status, text)) =
                    self.post(minimal_line(&self.table, record, &text)).await?
                {
                    bail!("QuestDB rejected record {} ({status}): {text}", record.seq);
                }
            }
        }
        Ok(())
    }

    /// POSTs a body. `None` on success, else the status and QuestDB's reason.
    async fn post(&self, body: String) -> anyhow::Result<Option<(StatusCode, String)>> {
        let mut request =
            Request::post(self.uri.clone()).header(CONTENT_TYPE, "text/plain; charset=utf-8");
        if let Some(auth) = &self.authorization {
            request = request.header(AUTHORIZATION, auth);
        }
        let response = tokio::time::timeout(REQUEST_TIMEOUT, async {
            match &self.tls {
                None => {
                    let request = request.body(Full::new(Bytes::from(body)))?;
                    self.client
                        .request(request)
                        .await
                        .map_err(|e| anyhow!("cannot reach QuestDB at {}: {e}", self.uri))
                        .map(|r| r.map(|b| b.boxed()))
                }
                Some(tls) => {
                    let host = self.uri.host().context("QuestDB url has no host")?;
                    let port = self.uri.port_u16().unwrap_or(443);
                    let stream = super::tls::connect(tls.clone(), host, port).await?;
                    let (mut sender, connection) =
                        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
                    tokio::spawn(connection);
                    let authority = self.uri.authority().map_or(host, |a| a.as_str());
                    let request = request
                        .header(HOST, authority)
                        .body(Full::new(Bytes::from(body)))?;
                    sender
                        .send_request(request)
                        .await
                        .map_err(|e| anyhow!("cannot reach QuestDB at {}: {e}", self.uri))
                        .map(|r| r.map(|b| b.boxed()))
                }
            }
        })
        .await
        .map_err(|_| anyhow!("QuestDB did not answer within {REQUEST_TIMEOUT:?}"))??;
        let status = response.status();
        if status.is_success() {
            return Ok(None);
        }
        let text = response
            .into_body()
            .collect()
            .await
            .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
            .unwrap_or_default();
        Ok(Some((status, text.trim().to_string())))
    }
}

/// Escapes a table name, symbol (tag) key or value. Line breaks and other
/// control characters become an escaped space: unescaped, a line break would
/// start a new line and a space would end the tag set.
fn escape_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ',' | ' ' | '=' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => out.push_str("\\ "),
            c => out.push(c),
        }
    }
    out
}

/// Escapes a string field value (without the surrounding quotes).
fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// One ILP line: `table,target=…,kind=…,user=… seq=12i,… <ts in ns>\n`.
pub fn line(table: &str, record: &StoredRecord) -> String {
    let f = fields(record);
    let mut out = escape_name(table);
    for (key, value) in [
        ("target", &f.target),
        ("kind", &f.kind.to_string()),
        ("user", &f.user),
    ] {
        if !value.is_empty() {
            out.push(',');
            out.push_str(key);
            out.push('=');
            out.push_str(&escape_name(value));
        }
    }
    out.push_str(&format!(" seq={}i", record.seq));
    let strings = [
        ("hash", &record.hash),
        ("prev_hash", &record.prev_hash),
        ("node_id", &f.node_id),
        ("display_name", &f.display_name),
        ("data_type", &f.data_type),
        ("old_value", &f.old_value),
        ("new_value", &f.new_value),
        ("status", &f.status),
        ("client_address", &f.client_address),
        ("client_application", &f.client_application),
        ("event", &f.event_json),
    ];
    for (key, value) in strings {
        if !value.is_empty() {
            out.push_str(&format!(",{key}=\"{}\"", escape_string(value)));
        }
    }
    out.push_str(&format!(" {}\n", timestamp(record)));
    out
}

/// A line QuestDB cannot refuse: identity and hashes only.
fn minimal_line(table: &str, record: &StoredRecord, reason: &str) -> String {
    format!(
        "{},kind={} seq={}i,hash=\"{}\",prev_hash=\"{}\",event=\"{}\" {}\n",
        escape_name(table),
        record.entry.event.kind(),
        record.seq,
        record.hash,
        record.prev_hash,
        escape_string(&format!("not exportable: {reason}")),
        timestamp(record)
    )
}

fn timestamp(record: &StoredRecord) -> i64 {
    record.entry.ts.timestamp_nanos_opt().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use tokio::sync::Mutex;

    use super::*;
    use crate::audit::event::{ClientContext, UserIdentity};
    use crate::export::tests::write_record;

    #[test]
    fn ilp_line_is_escaped() {
        let l = line("opcua_audit", &write_record(7));
        assert!(l.starts_with("opcua_audit,target=line\\ 1,kind=write,user=operator seq=7i,"));
        assert!(l.contains(r#"node_id="ns=3;s=\"DB1\".\"Set point\"""#));
        assert!(l.contains(r#"client_application="HMI, \"north\"""#));
        assert!(l.contains(r#"old_value="1.5",new_value="2.5""#));
        assert!(l.ends_with("\n"));
        assert_eq!(l.matches('\n').count(), 1);
    }

    /// Audit finding N1: a line break in a user name (which any client can
    /// choose) must not end the tag set or the line.
    #[test]
    fn control_characters_in_tags_stay_inside_the_tag() {
        let mut record = write_record(8);
        record.entry.client = Some(ClientContext {
            user: Some(UserIdentity::UserName {
                name: "bob\nforged=1i\tx\"".into(),
            }),
            ..Default::default()
        });
        let l = line("opcua_audit", &record);
        assert!(l.contains(r#",user=bob\ forged\=1i\ x" seq=8i,"#), "{l}");
        assert_eq!(l.matches('\n').count(), 1);
        // The tag set ends at the first unescaped space.
        let tags_end = l
            .char_indices()
            .find(|&(i, c)| c == ' ' && !l[..i].ends_with('\\'))
            .unwrap()
            .0;
        assert!(l[tags_end..].starts_with(" seq=8i,"));
    }

    #[tokio::test]
    async fn posts_batches_and_reports_errors() {
        type Seen = Arc<Mutex<Vec<(Option<String>, String)>>>;
        let seen: Seen = Default::default();
        let seen_https: Seen = Default::default();
        async fn write(
            State(seen): State<Seen>,
            headers: axum::http::HeaderMap,
            body: String,
        ) -> StatusCode {
            let auth = headers
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_string());
            seen.lock().await.push((auth, body));
            StatusCode::NO_CONTENT
        }
        let app = axum::Router::new()
            .route("/write", post(write))
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let mut sink = QuestDbSink::new(&QuestDbConfig {
            url: format!("http://{addr}"),
            ca_file: None,
            table: "opcua_audit".into(),
            token: Some("secret".into()),
            username: None,
            password: None,
            interval_secs: 1,
        })
        .unwrap();
        sink.send(&[write_record(1), write_record(2)])
            .await
            .unwrap();
        let seen = seen.lock().await;
        assert_eq!(seen[0].0.as_deref(), Some("Bearer secret"));
        assert_eq!(seen[0].1.lines().count(), 2);

        drop(seen);

        // The same over HTTPS, verified against the configured CA file.
        let dir = tempfile::tempdir().unwrap();
        let (server, ca_file) = crate::export::tls::tests::localhost_server(dir.path());
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new()
            .route("/write", post(write))
            .with_state(seen_https.clone());
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(server);
        tokio::spawn(async move {
            axum_server::from_tcp_rustls(listener, tls)
                .unwrap()
                .serve(app.into_make_service())
                .await
                .unwrap()
        });
        let mut https = QuestDbSink::new(&QuestDbConfig {
            url: format!("https://localhost:{port}"),
            ca_file: Some(ca_file),
            table: "opcua_audit".into(),
            token: None,
            username: Some("audit".into()),
            password: Some("pw".into()),
            interval_secs: 1,
        })
        .unwrap();
        https.send(&[write_record(3)]).await.unwrap();
        let seen_https = seen_https.lock().await;
        assert_eq!(seen_https[0].0.as_deref(), Some("Basic YXVkaXQ6cHc="));
        assert!(seen_https[0].1.contains("seq=3i"));

        let mut down = QuestDbSink::new(&QuestDbConfig {
            url: "http://127.0.0.1:1".into(),
            ca_file: None,
            table: "t".into(),
            token: None,
            username: None,
            password: None,
            interval_secs: 1,
        })
        .unwrap();
        assert!(down.send(&[write_record(1)]).await.is_err());
    }

    /// A record QuestDB refuses is replaced by a minimal line instead of
    /// blocking every later record.
    #[tokio::test]
    async fn a_rejected_record_does_not_block_the_export() {
        type Seen = Arc<Mutex<Vec<String>>>;
        let seen: Seen = Default::default();
        async fn write(State(seen): State<Seen>, body: String) -> StatusCode {
            if body.contains("poison") {
                return StatusCode::BAD_REQUEST;
            }
            seen.lock().await.push(body);
            StatusCode::NO_CONTENT
        }
        let app = axum::Router::new()
            .route("/write", post(write))
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut sink = QuestDbSink::new(&QuestDbConfig {
            url: format!("http://{addr}"),
            ca_file: None,
            table: "t".into(),
            token: None,
            username: None,
            password: None,
            interval_secs: 1,
        })
        .unwrap();
        let mut poison = write_record(2);
        poison.entry.target = Some("poison".into());
        sink.send(&[write_record(1), poison, write_record(3)])
            .await
            .unwrap();
        let seen = seen.lock().await;
        assert_eq!(seen.len(), 3, "{seen:?}");
        assert!(seen[1].contains("seq=2i") && seen[1].contains("not exportable"));
    }
}
