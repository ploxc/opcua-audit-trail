//! Ships the audit trail to external systems.
//!
//! Each destination keeps its own position (the last exported sequence
//! number) in `<data_dir>/export-state.json`, so nothing is lost or skipped
//! when a destination is down or the gateway restarts; records are delivered
//! at least once. Every exported record carries its hash: once records are
//! outside the gateway, the local chain can no longer be rebuilt unnoticed.

pub mod questdb;
pub mod syslog;
mod tls;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, Utc};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;

use crate::audit::store::{Anchor, StoredRecord};
use crate::audit::{AuditEntry, AuditEvent, AuditHandle, AuditReader};
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

/// The last exported records, as anchors for `verify`, read from the state
/// file without changing it. Empty if there is none or it is unreadable.
pub fn anchors_from(state_path: &Path) -> Vec<Anchor> {
    let Ok(text) = std::fs::read_to_string(state_path) else {
        return Vec::new();
    };
    let Ok(stored) = serde_json::from_str::<BTreeMap<String, StoredPosition>>(&text) else {
        return Vec::new();
    };
    ExportState {
        path: state_path.to_path_buf(),
        positions: Mutex::new(
            stored
                .into_iter()
                .filter_map(|(name, p)| match p {
                    StoredPosition::Position(p) => Some((name, p)),
                    StoredPosition::Seq(_) => None,
                })
                .collect(),
        ),
    }
    .anchors()
}

/// The last record a destination received.
#[derive(Debug, Clone, Default, PartialEq, Serialize, serde::Deserialize)]
pub struct Position {
    pub seq: i64,
    /// Empty in state files from before hashes were kept.
    #[serde(default)]
    pub hash: String,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum StoredPosition {
    Seq(i64),
    Position(Position),
}

/// Export positions, persisted as JSON.
pub struct ExportState {
    path: PathBuf,
    positions: Mutex<BTreeMap<String, Position>>,
}

impl ExportState {
    /// Reads the positions. An unreadable file (e.g. cut by a power loss) is
    /// set aside: exporting starts over, which only means duplicates.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        let positions = match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str::<BTreeMap<String, StoredPosition>>(&text) {
                Ok(stored) => stored
                    .into_iter()
                    .map(|(name, p)| {
                        let p = match p {
                            StoredPosition::Seq(seq) => Position {
                                seq,
                                hash: String::new(),
                            },
                            StoredPosition::Position(p) => p,
                        };
                        (name, p)
                    })
                    .collect(),
                Err(e) => {
                    let aside = path.with_extension("json.corrupt");
                    tracing::error!(
                        "{} is unreadable ({e}); moved to {} and exporting from the start",
                        path.display(),
                        aside.display()
                    );
                    let _ = std::fs::rename(path, &aside);
                    BTreeMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        Ok(Self {
            path: path.to_path_buf(),
            positions: Mutex::new(positions),
        })
    }

    pub fn position(&self, name: &str) -> Position {
        self.positions.lock().get(name).cloned().unwrap_or_default()
    }

    /// The exported records as anchors for `verify`: the trail must still
    /// contain each of them unchanged (unless retention removed it).
    pub fn anchors(&self) -> Vec<Anchor> {
        self.positions
            .lock()
            .iter()
            .filter(|(_, p)| p.seq > 0 && !p.hash.is_empty())
            .map(|(name, p)| Anchor {
                seq: p.seq,
                hash: p.hash.clone(),
                source: format!("the last record exported to {name}"),
            })
            .collect()
    }

    fn set(&self, name: &str, position: Position) -> anyhow::Result<()> {
        let mut positions = self.positions.lock();
        positions.insert(name.to_string(), position);
        crate::fsutil::write_atomic(&self.path, &serde_json::to_vec_pretty(&*positions)?, None)
            .with_context(|| format!("writing {}", self.path.display()))
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
    /// The last gap found between what was exported and the trail.
    pub gap: Option<String>,
}

pub type ExportStatuses = Arc<RwLock<BTreeMap<String, ExportStatus>>>;

pub enum Sink {
    QuestDb(Box<questdb::QuestDbSink>),
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
    audit: AuditHandle,
    state_path: &Path,
) -> anyhow::Result<ExportStatuses> {
    let statuses: ExportStatuses = Default::default();
    let mut sinks = Vec::new();
    if let Some(q) = &config.questdb {
        sinks.push((
            Sink::QuestDb(Box::new(questdb::QuestDbSink::new(q)?)),
            Duration::from_secs(q.interval_secs),
        ));
    }
    if let Some(s) = &config.syslog {
        sinks.push((
            Sink::Syslog(syslog::SyslogSink::new(s)?),
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
            audit.clone(),
            state.clone(),
            statuses.clone(),
            interval,
        ));
    }
    Ok(statuses)
}

/// Checks that `records` continue exactly after `position`. Returns why not.
fn gap(position: &Position, records: &[StoredRecord], head: i64) -> Option<(i64, String)> {
    if position.seq > head {
        return Some((
            head,
            format!(
                "the audit trail ends at record {head}, before the last exported record {}: \
                 it was cut off or replaced",
                position.seq
            ),
        ));
    }
    let first = records.first()?;
    if position.seq == 0 {
        return None;
    }
    if first.seq != position.seq + 1 {
        Some((
            first.seq,
            format!(
                "records {} to {} were removed before they were exported",
                position.seq + 1,
                first.seq - 1
            ),
        ))
    } else if !position.hash.is_empty() && first.prev_hash != position.hash {
        Some((
            first.seq,
            format!(
                "record {} does not follow the exported record {}: the trail was rewritten or replaced",
                first.seq, position.seq
            ),
        ))
    } else {
        None
    }
}

pub async fn run(
    mut sink: Sink,
    reader: AuditReader,
    audit: AuditHandle,
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
            exported_seq: position.seq,
            pending: 0,
            last_success: None,
            last_error: None,
            gap: None,
        },
    );
    let mut failures: u32 = 0;
    loop {
        let result: anyhow::Result<usize> = async {
            let head = reader.head_seq().await?;
            let mut records = reader.after(position.seq, sink.batch_size()).await?;
            if let Some((next_seq, reason)) = gap(&position, &records, head) {
                tracing::error!("audit export to {name}: {reason}");
                statuses.write().get_mut(name).expect("inserted").gap = Some(reason.clone());
                let _ = audit
                    .record_committed(AuditEntry::new(AuditEvent::ExportGap {
                        destination: name.into(),
                        after_seq: position.seq,
                        next_seq,
                        reason,
                    }))
                    .await;
                if position.seq > head {
                    // A new trail: export it from its start.
                    position = Position::default();
                    records = reader.after(0, sink.batch_size()).await?;
                }
            }
            if records.is_empty() {
                return Ok(0);
            }
            sink.send(&records).await?;
            let last = records.last().expect("not empty");
            let next = Position {
                seq: last.seq,
                hash: last.hash.clone(),
            };
            state.set(name, next.clone())?;
            position = next;
            Ok(records.len())
        }
        .await;
        let head = reader.head_seq().await.unwrap_or(position.seq);
        let delay = {
            let mut map = statuses.write();
            let status = map.get_mut(name).expect("inserted above");
            status.exported_seq = position.seq;
            status.pending = (head - position.seq).max(0);
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
            prev_hash: format!("hash{}", seq - 1),
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
                written_status: None,
                source_timestamp: None,
                server_timestamp: None,
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
                ca_file: None,
            }),
        };
        let state_path = dir.path().join("export-state.json");
        let statuses = start(&export, AuditReader::new(&db), audit.clone(), &state_path).unwrap();

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
            ExportState::open(&state_path)
                .unwrap()
                .position("syslog")
                .seq,
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
        assert_eq!(state.position("questdb").seq, 0);
        let position = Position {
            seq: 42,
            hash: "abc".into(),
        };
        state.set("questdb", position.clone()).unwrap();
        assert_eq!(
            ExportState::open(&path).unwrap().position("questdb"),
            position
        );
    }

    /// Audit finding E2: an unreadable state file (e.g. after a power cut)
    /// no longer stops the gateway from starting.
    #[test]
    fn unreadable_state_starts_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export-state.json");
        std::fs::write(&path, "{\"syslog\": 12").unwrap();
        let state = ExportState::open(&path).unwrap();
        assert_eq!(state.position("syslog").seq, 0);
        assert!(dir.path().join("export-state.json.corrupt").exists());
        // State files from before hashes were kept still load.
        std::fs::write(&path, "{\"syslog\": 12}").unwrap();
        assert_eq!(ExportState::open(&path).unwrap().position("syslog").seq, 12);
    }

    fn record_at(seq: i64, prev_hash: &str) -> StoredRecord {
        StoredRecord {
            prev_hash: prev_hash.into(),
            ..write_record(seq)
        }
    }

    /// Audit finding E1: records missing between the last export and the
    /// trail (pruned before export, a rewritten or replaced trail) are found.
    #[test]
    fn gaps_are_found() {
        let at = |seq: i64, hash: &str| Position {
            seq,
            hash: hash.into(),
        };
        // Continuous.
        assert!(gap(&at(5, "h5"), &[record_at(6, "h5")], 6).is_none());
        // Removed before export.
        let (next, reason) = gap(&at(2, "h2"), &[record_at(8, "h7")], 8).unwrap();
        assert_eq!(next, 8);
        assert!(reason.contains("3 to 7"), "{reason}");
        // Rewritten: the next record links to another hash.
        assert!(gap(&at(5, "h5"), &[record_at(6, "other")], 6).is_some());
        // Replaced: the trail ends before the exported position.
        assert!(gap(&at(5000, "h"), &[], 3).is_some());
        // Old state without a hash: only the numbering is checked.
        assert!(gap(&at(5, ""), &[record_at(6, "anything")], 6).is_none());
    }
}
