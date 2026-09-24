//! Ships the audit trail to external systems.
//!
//! Each destination keeps its own position (the last exported sequence
//! number) in `<data_dir>/export-state.json`, so nothing is lost or skipped
//! when a destination is down or the gateway restarts; records are delivered
//! at least once. Every exported record carries its hash: once records are
//! outside the gateway, the local chain can no longer be rebuilt unnoticed.

pub mod questdb;
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
        // A web UI user (who changed settings, logged in, acknowledged)
        // is in the event itself.
        user: client
            .and_then(|c| c.user.as_ref().map(|u| u.label()))
            .or_else(|| {
                let by = text("by");
                let by = if by.is_empty() { text("user") } else { by };
                (!by.is_empty() && by != "gateway").then(|| format!("ui:{by}"))
            })
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

    #[cfg(test)]
    pub fn position(&self, key: &str) -> Position {
        self.positions.lock().get(key).cloned().unwrap_or_default()
    }

    /// The position of a destination, stored under `key` (kind and address,
    /// so a new destination starts from the beginning of the trail while the
    /// old one's position stays as an anchor). State files from before keep
    /// one position per `kind`; that one is taken over by the destination.
    pub fn position_for(&self, kind: &str, key: &str) -> Position {
        let mut positions = self.positions.lock();
        if let Some(p) = positions.get(key) {
            return p.clone();
        }
        match positions.remove(kind) {
            Some(p) => {
                positions.insert(key.to_string(), p.clone());
                p
            }
            None => Position::default(),
        }
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
}

impl Sink {
    fn name(&self) -> &'static str {
        match self {
            Sink::QuestDb(_) => "questdb",
        }
    }

    fn destination(&self) -> String {
        match self {
            Sink::QuestDb(s) => s.destination(),
        }
    }

    /// Where the records go, to tell destinations apart in the state file.
    fn key(&self) -> String {
        format!("{} {}", self.name(), self.destination())
    }

    fn batch_size(&self) -> u32 {
        match self {
            Sink::QuestDb(_) => 1000,
        }
    }

    async fn send(&mut self, records: &[StoredRecord]) -> anyhow::Result<()> {
        match self {
            Sink::QuestDb(s) => s.send(records).await,
        }
    }
}

/// The running exporters. They are replaced as a whole when the export
/// settings change.
pub struct Exports {
    reader: AuditReader,
    audit: AuditHandle,
    state_path: PathBuf,
    state: Mutex<Option<Arc<ExportState>>>,
    statuses: ExportStatuses,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Exports {
    /// Starts one exporter task per configured destination.
    pub fn start(
        config: &ExportConfig,
        reader: AuditReader,
        audit: AuditHandle,
        state_path: &Path,
    ) -> anyhow::Result<Arc<Self>> {
        let exports = Arc::new(Self {
            reader,
            audit,
            state_path: state_path.to_path_buf(),
            state: Mutex::new(None),
            statuses: Default::default(),
            tasks: Mutex::new(Vec::new()),
        });
        exports.apply(config)?;
        Ok(exports)
    }

    pub fn statuses(&self) -> ExportStatuses {
        self.statuses.clone()
    }

    /// Checks that `config` can be used (URLs, CA files), without applying it.
    pub fn check(config: &ExportConfig) -> anyhow::Result<()> {
        sinks(config).map(|_| ())
    }

    /// Stops the current exporters and starts those of `config`. A
    /// destination that stays the same continues where it was.
    pub fn apply(&self, config: &ExportConfig) -> anyhow::Result<()> {
        let sinks = sinks(config)?;
        for task in self.tasks.lock().drain(..) {
            task.abort();
        }
        self.statuses.write().clear();
        if sinks.is_empty() {
            return Ok(());
        }
        let state = {
            let mut state = self.state.lock();
            match &*state {
                Some(s) => s.clone(),
                None => state
                    .insert(Arc::new(ExportState::open(&self.state_path)?))
                    .clone(),
            }
        };
        let mut tasks = self.tasks.lock();
        for (sink, interval) in sinks {
            tasks.push(tokio::spawn(run(
                sink,
                self.reader.clone(),
                self.audit.clone(),
                state.clone(),
                self.statuses.clone(),
                interval,
            )));
        }
        Ok(())
    }
}

fn sinks(config: &ExportConfig) -> anyhow::Result<Vec<(Sink, Duration)>> {
    let mut sinks = Vec::new();
    if let Some(q) = &config.questdb {
        sinks.push((
            Sink::QuestDb(Box::new(questdb::QuestDbSink::new(q)?)),
            Duration::from_secs(q.interval_secs.max(1)),
        ));
    }
    Ok(sinks)
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
    let key = sink.key();
    let mut position = state.position_for(name, &key);
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
            state.set(&key, next.clone())?;
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
    fn web_ui_users_fill_the_user_field() {
        let record = |event| StoredRecord {
            entry: AuditEntry::new(event),
            ..write_record(1)
        };
        let user = |event| fields(&record(event)).user;
        assert_eq!(
            user(AuditEvent::ConfigChanged {
                by: "admin".into(),
                summary: "x".into()
            }),
            "ui:admin"
        );
        assert_eq!(user(AuditEvent::UiLogin { user: "jan".into() }), "ui:jan");
        assert_eq!(
            user(AuditEvent::ConfigChanged {
                by: "gateway".into(),
                summary: "x".into()
            }),
            ""
        );
        assert_eq!(fields(&write_record(1)).user, "operator");
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

    /// A QuestDB stand-in that collects the `seq` of every line it gets.
    async fn questdb_receiver() -> (String, Arc<Mutex<Vec<i64>>>) {
        use axum::extract::State;
        let seen: Arc<Mutex<Vec<i64>>> = Default::default();
        async fn write(State(seen): State<Arc<Mutex<Vec<i64>>>>, body: String) {
            for line in body.lines() {
                let seq = line
                    .split(" seq=")
                    .nth(1)
                    .unwrap()
                    .split('i')
                    .next()
                    .unwrap();
                seen.lock().push(seq.parse().unwrap());
            }
        }
        let app = axum::Router::new()
            .route("/write", axum::routing::post(write))
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, seen)
    }

    async fn wait_for(what: impl Fn() -> bool) {
        for _ in 0..100 {
            if what() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out");
    }

    #[tokio::test]
    async fn exporter_ships_everything_once_and_resumes() {
        use crate::config::{AuditConfig, QuestDbConfig};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("audit.db");
        let audit = crate::audit::start(&db, &AuditConfig::default()).unwrap();
        for _ in 0..5 {
            audit
                .record_committed(AuditEntry::new(AuditEvent::SessionActivated))
                .await
                .unwrap();
        }
        let (url, seen) = questdb_receiver().await;
        let questdb = |url: String| QuestDbConfig {
            url,
            ca_file: None,
            table: "opcua_audit".into(),
            token: None,
            username: None,
            password: None,
            interval_secs: 1,
        };
        let export = ExportConfig {
            questdb: Some(questdb(url)),
            ..Default::default()
        };
        let state_path = dir.path().join("export-state.json");
        let exports =
            Exports::start(&export, AuditReader::new(&db), audit.clone(), &state_path).unwrap();
        let statuses = exports.statuses();

        // The status is updated right after the position is saved.
        wait_for(|| {
            statuses
                .read()
                .get("questdb")
                .is_some_and(|s| s.exported_seq == 5)
        })
        .await;
        assert_eq!(*seen.lock(), vec![1, 2, 3, 4, 5]);
        let anchors = ExportState::open(&state_path).unwrap().anchors();
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0].seq, 5);
        assert!(statuses.read()["questdb"].last_error.is_none());

        // Another server is a new destination: it gets the whole trail,
        // and the first one's position stays as an anchor.
        let (second_url, second) = questdb_receiver().await;
        exports
            .apply(&ExportConfig {
                questdb: Some(questdb(second_url)),
                ..Default::default()
            })
            .unwrap();
        wait_for(|| second.lock().first() == Some(&1)).await;
        wait_for(|| ExportState::open(&state_path).unwrap().anchors().len() == 2).await;

        // No destinations: the exporters stop and their status goes.
        exports.apply(&ExportConfig::default()).unwrap();
        assert!(statuses.read().is_empty());
    }

    /// State files from before destinations were told apart keep one
    /// position per kind; the configured destination takes it over.
    #[test]
    fn a_position_per_kind_is_taken_over() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("export-state.json");
        std::fs::write(&path, r#"{"questdb": {"seq": 12, "hash": "h12"}}"#).unwrap();
        let state = ExportState::open(&path).unwrap();
        assert_eq!(
            state.position_for("questdb", "questdb http://a:9000").seq,
            12
        );
        assert_eq!(
            state.position_for("questdb", "questdb http://a:9000").seq,
            12
        );
        // Only one destination can take it over.
        assert_eq!(
            state.position_for("questdb", "questdb http://b:9000").seq,
            0
        );
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
        std::fs::write(&path, "{\"questdb\": 12").unwrap();
        let state = ExportState::open(&path).unwrap();
        assert_eq!(state.position("questdb").seq, 0);
        assert!(dir.path().join("export-state.json.corrupt").exists());
        // State files from before hashes were kept still load.
        std::fs::write(&path, "{\"questdb\": 12}").unwrap();
        assert_eq!(
            ExportState::open(&path).unwrap().position("questdb").seq,
            12
        );
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
