//! Ships the audit trail to external systems.
//!
//! Each destination keeps its own position (the last exported sequence
//! number) in `<data_dir>/export-state.json`, so nothing is lost or skipped
//! when a destination is down or the gateway restarts; records are delivered
//! at least once. Every exported record carries its hash: once records are
//! outside the gateway, the local chain can no longer be rebuilt unnoticed.

pub mod questdb;
pub mod syslog;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;

use crate::audit::store::StoredRecord;
use crate::audit::AuditReader;
use crate::config::ExportConfig;

/// Flat, human-oriented view of a record, shared by CSV and the exporters.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RecordFields {
    pub target: String,
    pub kind: &'static str,
    pub user: String,
    pub client_address: String,
    pub client_application: String,
    pub node_id: String,
    pub display_name: String,
    pub data_type: String,
    pub old_value: String,
    pub new_value: String,
    pub status: String,
    /// The event as JSON.
    pub event_json: String,
}

pub fn fields(record: &StoredRecord) -> RecordFields {
    let entry = &record.entry;
    let client = entry.client.as_ref();
    let event = serde_json::to_value(&entry.event).unwrap_or_default();
    let text = |key: &str| -> String {
        match event.get(key) {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
        }
    };
    let value = |key: &str| -> String {
        match event.get(key).and_then(|v| v.get("value")) {
            None => String::new(),
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(v) => v.to_string(),
        }
    };
    let data_type = event
        .get("new_value")
        .and_then(|v| v.get("data_type"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    RecordFields {
        target: entry.target.clone().unwrap_or_default(),
        kind: entry.event.kind(),
        user: client
            .and_then(|c| c.user.as_ref().map(|u| u.label()))
            .unwrap_or_default(),
        client_address: client.map(|c| c.remote_addr.clone()).unwrap_or_default(),
        client_application: client
            .and_then(|c| c.application_name.clone().or(c.application_uri.clone()))
            .unwrap_or_default(),
        node_id: entry.event.node_id().unwrap_or_default().to_string(),
        display_name: text("display_name"),
        data_type,
        old_value: value("old_value"),
        new_value: value("new_value"),
        status: text("status"),
        event_json: event.to_string(),
    }
}

/// Export positions, persisted as JSON.
pub struct ExportState {
    path: PathBuf,
    positions: Mutex<BTreeMap<String, i64>>,
}

impl ExportState {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let positions = match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text)
                .with_context(|| format!("reading {}", path.display()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self {
            path: path.to_path_buf(),
            positions: Mutex::new(positions),
        })
    }

    pub fn position(&self, name: &str) -> i64 {
        self.positions.lock().get(name).copied().unwrap_or(0)
    }

    fn set(&self, name: &str, seq: i64) -> anyhow::Result<()> {
        let mut positions = self.positions.lock();
        positions.insert(name.to_string(), seq);
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&*positions)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportStatus {
    pub name: String,
    pub destination: String,
    /// Sequence number of the last record delivered.
    pub exported_seq: i64,
    /// Records waiting to be delivered.
    pub pending: i64,
    pub last_success: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

pub type ExportStatuses = Arc<RwLock<BTreeMap<String, ExportStatus>>>;

pub enum Sink {
    QuestDb(questdb::QuestDbSink),
    Syslog(syslog::SyslogSink),
}

impl Sink {
    fn name(&self) -> &'static str {
        match self {
            Sink::QuestDb(_) => "questdb",
            Sink::Syslog(_) => "syslog",
        }
    }

    fn destination(&self) -> String {
        match self {
            Sink::QuestDb(s) => s.destination(),
            Sink::Syslog(s) => s.destination(),
        }
    }

    fn batch_size(&self) -> u32 {
        match self {
            Sink::QuestDb(_) => 1000,
            Sink::Syslog(_) => 200,
        }
    }

    async fn send(&mut self, records: &[StoredRecord]) -> anyhow::Result<()> {
        match self {
            Sink::QuestDb(s) => s.send(records).await,
            Sink::Syslog(s) => s.send(records).await,
        }
    }
}

/// Starts one exporter task per configured destination.
pub fn start(
    config: &ExportConfig,
    reader: AuditReader,
    state_path: &Path,
) -> anyhow::Result<ExportStatuses> {
    let statuses: ExportStatuses = Default::default();
    let mut sinks = Vec::new();
    if let Some(q) = &config.questdb {
        sinks.push((
            Sink::QuestDb(questdb::QuestDbSink::new(q)?),
            Duration::from_secs(q.interval_secs),
        ));
    }
    if let Some(s) = &config.syslog {
        sinks.push((
            Sink::Syslog(syslog::SyslogSink::new(s)),
            Duration::from_secs(s.interval_secs),
        ));
    }
    if sinks.is_empty() {
        return Ok(statuses);
    }
    let state = Arc::new(ExportState::open(state_path)?);
    for (sink, interval) in sinks {
        tokio::spawn(run(
            sink,
            reader.clone(),
            state.clone(),
            statuses.clone(),
            interval,
        ));
    }
    Ok(statuses)
}

pub async fn run(
    mut sink: Sink,
    reader: AuditReader,
    state: Arc<ExportState>,
    statuses: ExportStatuses,
    interval: Duration,
) {
    let name = sink.name();
    let mut position = state.position(name);
    statuses.write().insert(
        name.into(),
        ExportStatus {
            name: name.into(),
            destination: sink.destination(),
            exported_seq: position,
            pending: 0,
            last_success: None,
            last_error: None,
        },
    );
    let mut failures: u32 = 0;
    loop {
        let result: anyhow::Result<usize> = async {
            let records = reader.after(position, sink.batch_size()).await?;
            if records.is_empty() {
                return Ok(0);
            }
            sink.send(&records).await?;
            let last = records.last().expect("not empty").seq;
            state.set(name, last)?;
            position = last;
            Ok(records.len())
        }
        .await;
        let head = reader.head_seq().await.unwrap_or(position);
        let delay = {
            let mut map = statuses.write();
            let status = map.get_mut(name).expect("inserted above");
            status.exported_seq = position;
            status.pending = (head - position).max(0);
            match &result {
                Ok(n) => {
                    if *n > 0 {
                        status.last_success = Some(Utc::now());
                    }
                    status.last_error = None;
                    failures = 0;
                    // A full batch means there is more: continue right away.
                    if *n as u32 == sink.batch_size() {
                        Duration::ZERO
                    } else {
                        interval
                    }
                }
                Err(e) => {
                    let message = format!("{e:#}");
                    if status.last_error.as_deref() != Some(message.as_str()) {
                        tracing::warn!("audit export to {name} failed: {message}");
                    }
                    status.last_error = Some(message);
                    failures = failures.saturating_add(1);
                    (interval * failures).min(Duration::from_secs(60))
                }
            }
        };
        tokio::time::sleep(delay).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::{AuditEntry, AuditEvent, AuditValue, ClientContext, UserIdentity};

    pub fn write_record(seq: i64) -> StoredRecord {
        StoredRecord {
            seq,
            hash: format!("hash{seq}"),
            entry: AuditEntry::new(AuditEvent::Write {
                request_handle: 1,
                node_id: "ns=3;s=\"DB1\".\"Set point\"".into(),
                display_name: Some("Set point".into()),
                attribute: "Value".into(),
                index_range: None,
                old_value: Some(AuditValue {
                    data_type: "Double".into(),
                    value: 1.5.into(),
                }),
                new_value: AuditValue {
                    data_type: "Double".into(),
                    value: 2.5.into(),
                },
                status: "Good".into(),
            })
            .target("line 1")
            .client(ClientContext {
                remote_addr: "10.0.0.5:5000".into(),
                application_name: Some("HMI, \"north\"".into()),
                user: Some(UserIdentity::UserName {
                    name: "operator".into(),
                }),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn fields_flatten_a_write() {
        let f = fields(&write_record(7));
        assert_eq!(f.kind, "write");
        assert_eq!(f.user, "operator");
        assert_eq!(f.old_value, "1.5");
        assert_eq!(f.new_value, "2.5");
        assert_eq!(f.data_type, "Double");
        assert_eq!(f.display_name, "Set point");
        assert_eq!(f.status, "Good");
    }

    #[tokio::test]
    async fn exporter_ships_everything_once_and_resumes() {
        use crate::config::{AuditConfig, SyslogConfig, SyslogProtocol};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let audit = crate::audit::start(&db, &AuditConfig::default()).unwrap();
        for _ in 0..5 {
            audit
                .record_committed(AuditEntry::new(AuditEvent::SessionActivated))
                .await
                .unwrap();
        }
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let export = ExportConfig {
            questdb: None,
            syslog: Some(SyslogConfig {
                address: receiver.local_addr().unwrap().to_string(),
                protocol: SyslogProtocol::Udp,
                facility: 16,
                interval_secs: 1,
            }),
        };
        let state_path = dir.path().join("export-state.json");
        let statuses = start(&export, AuditReader::new(&db), &state_path).unwrap();

        let mut buf = vec![0u8; 16384];
        let mut seqs = Vec::new();
        for _ in 0..5 {
            let n = tokio::time::timeout(Duration::from_secs(5), receiver.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            let m = String::from_utf8_lossy(&buf[..n]).to_string();
            let seq: i64 = m
                .split("seq=\"")
                .nth(1)
                .unwrap()
                .split('"')
                .next()
                .unwrap()
                .parse()
                .unwrap();
            seqs.push(seq);
        }
        assert_eq!(seqs, vec![1, 2, 3, 4, 5]);
        for _ in 0..50 {
            // The status is updated right after the position is saved.
            if statuses.read()["syslog"].exported_seq == 5 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let status_now = statuses.read()["syslog"].clone();
        assert_eq!(
            ExportState::open(&state_path).unwrap().position("syslog"),
            5,
            "{status_now:?}"
        );
        let status = statuses.read()["syslog"].clone();
        assert_eq!(status.exported_seq, 5);
        assert!(status.last_error.is_none());
    }

    #[test]
    fn state_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export-state.json");
        let state = ExportState::open(&path).unwrap();
        assert_eq!(state.position("questdb"), 0);
        state.set("questdb", 42).unwrap();
        assert_eq!(ExportState::open(&path).unwrap().position("questdb"), 42);
    }
}
