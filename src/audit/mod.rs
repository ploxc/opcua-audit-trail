//! Audit pipeline: callers hand events to an [`AuditHandle`]; a dedicated writer
//! thread batches them into the [`store::AuditStore`].
//!
//! The forwarding path never waits on disk in fail-open mode: events are queued
//! with `try_send`, and anything that cannot be queued or stored is counted and
//! reported later as an `EventsLost` record. In fail-closed mode the caller waits
//! until its record is committed and gets an error otherwise, so the relay can
//! refuse the write.

pub mod event;
pub mod store;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::Context;
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, oneshot};

use crate::config::{AuditConfig, FailMode};
pub use event::{AuditEntry, AuditEvent};
use store::{Anchor, AuditQuery, AuditStore, StoredRecord, VerifyReport};

const QUEUE_CAPACITY: usize = 10_000;
const MAX_BATCH: usize = 512;
/// How long fail-open waits for room in a full queue before counting an
/// event as lost: a burst of writes slows down a little instead of losing
/// records.
const QUEUE_WAIT: std::time::Duration = std::time::Duration::from_millis(200);

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit writer has stopped")]
    WriterStopped,
    #[error("audit store failed: {0}")]
    Store(String),
}

type Ack = oneshot::Sender<Result<i64, String>>;

enum Command {
    Append(Box<AuditEntry>, Option<Ack>),
    Prune(DateTime<Utc>, oneshot::Sender<Result<u64, String>>),
    Flush(oneshot::Sender<()>),
    /// Makes the writer panic, to test that it is restarted.
    #[cfg(test)]
    Panic,
}

/// The audit settings that can change while the gateway runs (from the
/// web UI). Everything that uses them reads them when it needs them.
#[derive(Debug)]
pub struct AuditSettings {
    fail_closed: AtomicBool,
    record_old_value: AtomicBool,
    retention_days: AtomicU32,
    ignored_summary_secs: AtomicU64,
    /// Wakes the retention task after a change, so a shorter period applies
    /// at once.
    changed: tokio::sync::Notify,
}

impl AuditSettings {
    pub fn new(config: &AuditConfig) -> Self {
        let settings = Self {
            fail_closed: AtomicBool::new(false),
            record_old_value: AtomicBool::new(false),
            retention_days: AtomicU32::new(0),
            ignored_summary_secs: AtomicU64::new(1),
            changed: tokio::sync::Notify::new(),
        };
        settings.apply(config);
        settings
    }

    pub fn apply(&self, config: &AuditConfig) {
        self.fail_closed
            .store(config.fail_mode == FailMode::Closed, Ordering::Relaxed);
        self.record_old_value
            .store(config.record_old_value, Ordering::Relaxed);
        self.retention_days
            .store(config.retention_days, Ordering::Relaxed);
        self.ignored_summary_secs
            .store(config.ignored_summary_secs.max(1), Ordering::Relaxed);
        self.changed.notify_waiters();
    }

    pub fn fail_mode(&self) -> FailMode {
        if self.fail_closed.load(Ordering::Relaxed) {
            FailMode::Closed
        } else {
            FailMode::Open
        }
    }

    pub fn record_old_value(&self) -> bool {
        self.record_old_value.load(Ordering::Relaxed)
    }

    /// `0` keeps everything.
    pub fn retention_days(&self) -> u32 {
        self.retention_days.load(Ordering::Relaxed)
    }

    pub fn ignored_summary(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.ignored_summary_secs.load(Ordering::Relaxed))
    }
}

/// Events that could not be stored and are not reported yet. Also kept in
/// `<database>.lost`, so a restart before the `EventsLost` record does not
/// forget them.
pub struct LostEvents {
    count: AtomicU64,
    /// Events of the batch being written that nobody waits for: counted as
    /// lost if the writer dies before the batch is stored.
    in_flight: AtomicU64,
    path: PathBuf,
    /// The value last written to the file; its lock orders the writes.
    saved: Mutex<u64>,
}

impl LostEvents {
    fn open(database: &Path) -> Self {
        let mut path = database.as_os_str().to_owned();
        path.push(".lost");
        let path = PathBuf::from(path);
        let count = std::fs::read_to_string(&path)
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0);
        if count > 0 {
            tracing::warn!("{count} audit events were lost before the last stop; reporting them");
        }
        Self {
            count: AtomicU64::new(count),
            in_flight: AtomicU64::new(0),
            path,
            saved: Mutex::new(count),
        }
    }

    fn add(&self, n: u64) {
        self.count.fetch_add(n, Ordering::Relaxed);
    }

    fn load(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Writes the current count to the file if it changed.
    fn save(&self) {
        let mut saved = self.saved.lock().unwrap_or_else(|e| e.into_inner());
        self.save_locked(&mut saved);
    }

    fn save_locked(&self, saved: &mut u64) {
        let now = self.load();
        if now == *saved {
            return;
        }
        let result = if now == 0 {
            std::fs::remove_file(&self.path).or_else(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Ok(()),
                _ => Err(e),
            })
        } else {
            crate::fsutil::write_atomic(&self.path, now.to_string().as_bytes(), None)
        };
        match result {
            Ok(()) => *saved = now,
            Err(e) => tracing::warn!("saving the lost audit events count: {e}"),
        }
    }
}

#[derive(Clone)]
pub struct AuditHandle {
    tx: mpsc::Sender<Command>,
    settings: Arc<AuditSettings>,
    lost: Arc<LostEvents>,
}

impl AuditHandle {
    /// Records an event. In fail-open mode this never blocks and only fails if
    /// the event could not even be counted; in fail-closed mode it returns once
    /// the record is committed.
    pub async fn record(&self, entry: AuditEntry) -> Result<(), AuditError> {
        match self.settings.fail_mode() {
            FailMode::Open => {
                let lost = match self.tx.try_send(Command::Append(Box::new(entry), None)) {
                    Ok(()) => false,
                    Err(mpsc::error::TrySendError::Full(command)) => {
                        self.tx.send_timeout(command, QUEUE_WAIT).await.is_err()
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => true,
                };
                if lost {
                    self.lost.add(1);
                }
                Ok(())
            }
            FailMode::Closed => self.record_committed(entry).await.map(|_| ()),
        }
    }

    /// Records an event and waits for it to be committed, whatever the fail mode.
    /// Returns the record's sequence number.
    pub async fn record_committed(&self, entry: AuditEntry) -> Result<i64, AuditError> {
        let result = async {
            let (ack, done) = oneshot::channel();
            self.tx
                .send(Command::Append(Box::new(entry), Some(ack)))
                .await
                .map_err(|_| AuditError::WriterStopped)?;
            done.await
                .map_err(|_| AuditError::WriterStopped)?
                .map_err(AuditError::Store)
        }
        .await;
        if result.is_err() && self.settings.fail_mode() == FailMode::Open {
            // Callers in fail-open mode carry on; the loss is reported.
            self.lost.add(1);
        }
        result
    }

    pub async fn prune_before(&self, cutoff: DateTime<Utc>) -> Result<u64, AuditError> {
        let (ack, done) = oneshot::channel();
        self.tx
            .send(Command::Prune(cutoff, ack))
            .await
            .map_err(|_| AuditError::WriterStopped)?;
        done.await
            .map_err(|_| AuditError::WriterStopped)?
            .map_err(AuditError::Store)
    }

    /// Waits until everything queued so far has been handled.
    pub async fn flush(&self) {
        let (ack, done) = oneshot::channel();
        if self.tx.send(Command::Flush(ack)).await.is_ok() {
            let _ = done.await;
        }
    }

    /// The live audit settings.
    pub fn settings(&self) -> &AuditSettings {
        &self.settings
    }

    /// Events lost since the last `EventsLost` record was written.
    pub fn lost_events(&self) -> u64 {
        self.lost.load()
    }
}

/// Starts the writer thread. It stops once every [`AuditHandle`] is dropped.
/// A writer that panics is restarted with the store opened again; if that
/// keeps failing, the gateway stops rather than run without an audit trail.
pub fn start(path: &Path, config: &AuditConfig) -> anyhow::Result<AuditHandle> {
    let mut store = AuditStore::open(path)?;
    let (tx, mut rx) = mpsc::channel(QUEUE_CAPACITY);
    let lost = Arc::new(LostEvents::open(path));
    let writer_lost = lost.clone();
    let db = path.to_path_buf();
    std::thread::Builder::new()
        .name("audit-writer".into())
        .spawn(move || {
            let mut restarts = Vec::new();
            loop {
                let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    writer_loop(&mut store, &mut rx, &writer_lost)
                }));
                if run.is_ok() {
                    break;
                }
                // The batch being written is not acknowledged: fail-closed
                // callers get an error, fail-open ones count it as lost.
                restarts.retain(|t: &std::time::Instant| t.elapsed().as_secs() < 60);
                restarts.push(std::time::Instant::now());
                let reopened = if restarts.len() <= 3 {
                    AuditStore::open(&db)
                } else {
                    Err(anyhow::anyhow!(
                        "it failed {} times in a minute",
                        restarts.len()
                    ))
                };
                writer_lost.add(writer_lost.in_flight.swap(0, Ordering::Relaxed));
                match reopened {
                    Ok(s) => {
                        tracing::error!("audit writer failed; restarted it");
                        store = s;
                    }
                    Err(e) => {
                        tracing::error!("audit writer failed and cannot restart ({e:#}): stopping");
                        std::process::exit(1);
                    }
                }
            }
        })
        .context("starting audit writer thread")?;
    // Saves the lost count every second while there are handles.
    let weak = Arc::downgrade(&lost);
    std::thread::Builder::new()
        .name("audit-lost".into())
        .spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            match weak.upgrade() {
                Some(lost) => lost.save(),
                None => break,
            }
        })
        .context("starting audit counter thread")?;
    Ok(AuditHandle {
        tx,
        settings: Arc::new(AuditSettings::new(config)),
        lost,
    })
}

fn writer_loop(store: &mut AuditStore, rx: &mut mpsc::Receiver<Command>, lost: &LostEvents) {
    while let Some(first) = rx.blocking_recv() {
        let mut batch = Vec::new();
        let mut acks = Vec::new();
        let mut after = Vec::new();

        let mut next = Some(first);
        while let Some(cmd) = next.take() {
            match cmd {
                Command::Append(entry, ack) => {
                    batch.push(*entry);
                    acks.push(ack);
                }
                other => {
                    after.push(other);
                    break;
                }
            }
            if batch.len() < MAX_BATCH {
                next = rx.try_recv().ok();
            }
        }

        if !batch.is_empty() {
            write_batch(store, batch, acks, lost);
        }
        for cmd in after {
            match cmd {
                Command::Prune(cutoff, ack) => {
                    let _ = ack.send(store.prune_before(cutoff).map_err(|e| e.to_string()));
                }
                Command::Flush(ack) => {
                    let _ = ack.send(());
                }
                #[cfg(test)]
                Command::Panic => panic!("test: audit writer panics"),
                Command::Append(..) => unreachable!("appends are batched above"),
            }
        }
    }
}

fn write_batch(
    store: &mut AuditStore,
    mut batch: Vec<AuditEntry>,
    acks: Vec<Option<Ack>>,
    lost: &LostEvents,
) {
    // Held until the result is saved: the file never runs behind a report.
    let mut saved = lost.saved.lock().unwrap_or_else(|e| e.into_inner());
    let lost_before = lost.count.swap(0, Ordering::Relaxed);
    if lost_before > 0 {
        batch.push(AuditEntry::new(AuditEvent::EventsLost {
            count: lost_before,
        }));
    }
    let unacked = acks.iter().filter(|a| a.is_none()).count() as u64;
    lost.in_flight
        .store(lost_before + unacked, Ordering::Relaxed);
    let result = store.append(&batch);
    lost.in_flight.store(0, Ordering::Relaxed);
    match result {
        Ok(seqs) => {
            for (ack, seq) in acks.into_iter().zip(seqs) {
                if let Some(ack) = ack {
                    let _ = ack.send(Ok(seq));
                }
            }
        }
        Err(e) => {
            tracing::error!("audit store write failed: {e:#}");
            lost.add(lost_before + unacked);
            for ack in acks.into_iter().flatten() {
                let _ = ack.send(Err(e.to_string()));
            }
        }
    }
    lost.save_locked(&mut saved);
}

/// Read access for the web UI and the CLI. Uses its own read-only connection,
/// so queries never hold up the writer (WAL mode).
#[derive(Clone)]
pub struct AuditReader {
    path: PathBuf,
    conn: Arc<Mutex<Option<rusqlite::Connection>>>,
}

impl AuditReader {
    pub fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            conn: Arc::new(Mutex::new(None)),
        }
    }

    async fn with_conn<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&rusqlite::Connection) -> anyhow::Result<T> + Send + 'static,
    {
        let path = self.path.clone();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().unwrap_or_else(|p| p.into_inner());
            if guard.is_none() {
                *guard = Some(store::open_reader(&path)?);
            }
            f(guard.as_ref().expect("connection was just opened"))
        })
        .await?
    }

    pub async fn query(&self, q: AuditQuery) -> anyhow::Result<Vec<StoredRecord>> {
        self.with_conn(move |c| store::query(c, &q)).await
    }

    pub async fn after(&self, after_seq: i64, limit: u32) -> anyhow::Result<Vec<StoredRecord>> {
        self.with_conn(move |c| store::query_after(c, after_seq, limit))
            .await
    }

    pub async fn most_written(
        &self,
        since: DateTime<Utc>,
        limit: u32,
    ) -> anyhow::Result<Vec<store::WrittenNode>> {
        self.with_conn(move |c| store::most_written(c, &since, limit))
            .await
    }

    pub async fn alarms(&self) -> anyhow::Result<Vec<store::AlarmCount>> {
        self.with_conn(store::alarms).await
    }

    pub async fn head_seq(&self) -> anyhow::Result<i64> {
        self.with_conn(store::head_seq).await
    }

    #[cfg(test)]
    pub async fn verify(&self) -> anyhow::Result<VerifyReport> {
        self.with_conn(store::verify).await
    }

    pub async fn verify_against(&self, anchors: Vec<Anchor>) -> anyhow::Result<VerifyReport> {
        self.with_conn(move |c| store::verify_against(c, &anchors))
            .await
    }
}

/// Periodically applies the retention policy. It trusts the wall clock only
/// while it keeps pace with the time that really passed: after a jump that
/// round is skipped and the jump is recorded.
/// The retention period is read every round, so a change applies within the
/// hour (`0` keeps everything).
pub async fn run_retention(handle: AuditHandle) {
    let period = std::time::Duration::from_secs(3600);
    let mut tick = tokio::time::interval(period);
    let mut last: Option<(std::time::Instant, DateTime<Utc>)> = None;
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = handle.settings().changed.notified() => {}
        }
        let now = (std::time::Instant::now(), Utc::now());
        if let Some((mono, wall)) = last {
            let real = chrono::Duration::from_std(now.0 - mono).unwrap_or_default();
            let jump = (now.1 - wall) - real;
            if jump.num_seconds().abs() > 300 {
                tracing::warn!(
                    "the system clock jumped by {} s; retention skipped",
                    jump.num_seconds()
                );
                let _ = handle
                    .record(AuditEntry::new(AuditEvent::ClockJumped {
                        seconds: jump.num_seconds(),
                    }))
                    .await;
                last = Some(now);
                continue;
            }
        }
        last = Some(now);
        let retention_days = handle.settings().retention_days();
        if retention_days == 0 {
            continue;
        }
        let cutoff = now.1 - chrono::Duration::days(i64::from(retention_days));
        loop {
            match handle.prune_before(cutoff).await {
                Ok(0) => break,
                Ok(n) => {
                    tracing::info!("retention removed {n} audit records");
                    if n < store::MAX_PRUNE as u64 {
                        break;
                    }
                    // More to go: let other records through in between.
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
                Err(AuditError::WriterStopped) => return,
                Err(e) => {
                    tracing::error!("audit retention failed: {e}");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(fail_mode: FailMode) -> AuditConfig {
        AuditConfig {
            fail_mode,
            ..AuditConfig::default()
        }
    }

    #[tokio::test]
    async fn fail_open_records_are_written() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let handle = start(&path, &config(FailMode::Open)).unwrap();
        for _ in 0..3 {
            handle
                .record(AuditEntry::new(AuditEvent::SessionActivated))
                .await
                .unwrap();
        }
        handle.flush().await;

        let reader = AuditReader::new(&path);
        let rows = reader.query(AuditQuery::default()).await.unwrap();
        assert_eq!(rows.len(), 3);
        assert!(reader.verify().await.unwrap().ok());
    }

    #[tokio::test]
    async fn fail_closed_returns_sequence_numbers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let handle = start(&path, &config(FailMode::Closed)).unwrap();
        let a = handle
            .record_committed(AuditEntry::new(AuditEvent::SessionActivated))
            .await
            .unwrap();
        let b = handle
            .record_committed(AuditEntry::new(AuditEvent::SessionClosed))
            .await
            .unwrap();
        assert_eq!((a, b), (1, 2));
    }

    #[tokio::test]
    async fn lost_events_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let handle = start(&path, &config(FailMode::Open)).unwrap();
        handle.lost.count.store(5, Ordering::Relaxed);
        handle
            .record(AuditEntry::new(AuditEvent::SessionActivated))
            .await
            .unwrap();
        handle.flush().await;

        let rows = AuditReader::new(&path)
            .query(AuditQuery {
                kind: Some("events_lost".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].entry.event, AuditEvent::EventsLost { count: 5 });
        assert_eq!(handle.lost_events(), 0);
    }

    #[tokio::test]
    async fn writer_is_restarted_after_a_panic() {
        // Audit finding N23: a writer that died used to stay dead.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let handle = start(&path, &config(FailMode::Closed)).unwrap();
        handle.tx.send(Command::Panic).await.unwrap();
        let seq = handle
            .record_committed(AuditEntry::new(AuditEvent::SessionActivated))
            .await
            .unwrap();
        assert_eq!(seq, 1);
        assert!(AuditReader::new(&path).verify().await.unwrap().ok());
    }

    #[tokio::test]
    async fn lost_count_survives_a_restart() {
        // Audit finding N23: the count is kept on disk until it is reported.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let handle = start(&path, &config(FailMode::Open)).unwrap();
        handle.lost.add(7);
        handle.lost.save();
        drop(handle);
        std::thread::sleep(std::time::Duration::from_millis(100));

        let handle = start(&path, &config(FailMode::Open)).unwrap();
        assert_eq!(handle.lost_events(), 7);
        handle
            .record_committed(AuditEntry::new(AuditEvent::SessionActivated))
            .await
            .unwrap();
        let rows = AuditReader::new(&path)
            .query(AuditQuery {
                kind: Some("events_lost".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(rows[0].entry.event, AuditEvent::EventsLost { count: 7 });
        assert!(!dir.path().join("audit.db.lost").exists());
    }
}
