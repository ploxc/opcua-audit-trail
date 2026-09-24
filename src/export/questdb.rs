//! QuestDB destination: InfluxDB Line Protocol over HTTP (`POST /write`).
//!
//! HTTP (unlike ILP over TCP) confirms every batch, so the export position
//! only moves on after QuestDB stored the records. The table is created by
//! QuestDB on first write. For exactly-once results after retries, enable
//! deduplication on it: `ALTER TABLE opcua_audit DEDUP ENABLE UPSERT KEYS(ts, seq)`.

use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::{Request, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;

use super::fields;
use crate::audit::store::StoredRecord;
use crate::config::QuestDbConfig;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

pub struct QuestDbSink {
    client: Client<HttpConnector, Full<Bytes>>,
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
        Ok(Self {
            client: Client::builder(TokioExecutor::new()).build_http(),
            uri,
            table: config.table.clone(),
            authorization,
        })
    }

    pub fn destination(&self) -> String {
        format!("{} (table {})", self.uri, self.table)
    }

    pub async fn send(&mut self, records: &[StoredRecord]) -> anyhow::Result<()> {
        let mut body = String::with_capacity(records.len() * 400);
        for record in records {
            body.push_str(&line(&self.table, record));
        }
        let mut request =
            Request::post(self.uri.clone()).header(CONTENT_TYPE, "text/plain; charset=utf-8");
        if let Some(auth) = &self.authorization {
            request = request.header(AUTHORIZATION, auth);
        }
        let request = request.body(Full::new(Bytes::from(body)))?;
        let response = tokio::time::timeout(REQUEST_TIMEOUT, self.client.request(request))
            .await
            .map_err(|_| anyhow!("QuestDB did not answer within {REQUEST_TIMEOUT:?}"))?
            .map_err(|e| anyhow!("cannot reach QuestDB at {}: {e}", self.uri))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let text = response
            .into_body()
            .collect()
            .await
            .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
            .unwrap_or_default();
        bail!("QuestDB answered {status}: {}", text.trim())
    }
}

/// Escapes a table name, symbol (tag) key or value.
fn escape_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ',' | ' ' | '=' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' => out.push(' '),
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
            '\n' | '\r' => out.push(' '),
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
    let ns = record.entry.ts.timestamp_nanos_opt().unwrap_or_default();
    out.push_str(&format!(" {ns}\n"));
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use tokio::sync::Mutex;

    use super::*;
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

    #[tokio::test]
    async fn posts_batches_and_reports_errors() {
        type Seen = Arc<Mutex<Vec<(Option<String>, String)>>>;
        let seen: Seen = Default::default();
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

        let mut down = QuestDbSink::new(&QuestDbConfig {
            url: "http://127.0.0.1:1".into(),
            table: "t".into(),
            token: None,
            username: None,
            password: None,
            interval_secs: 1,
        })
        .unwrap();
        assert!(down.send(&[write_record(1)]).await.is_err());
    }
}
