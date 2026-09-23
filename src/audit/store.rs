//! SQLite-backed, tamper-evident audit store.
//!
//! Records form a hash chain: each record stores the hash of its predecessor and
//! `hash = sha256(prev_hash "\n" seq "\n" body)`, where `body` is the exact JSON
//! text of the [`AuditEntry`]. Changing, inserting or deleting a record breaks
//! the chain from that point on, which [`verify`] detects.
//!
//! Retention deletes the oldest records and then appends a
//! [`AuditEvent::RetentionPruned`] record naming the last deleted sequence
//! number and hash, so the remaining chain stays verifiable.

use std::path::Path;

use anyhow::{bail, Context};
use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::event::{AuditEntry, AuditEvent};

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS audit (
    seq             INTEGER PRIMARY KEY,
    ts              TEXT NOT NULL,
    target          TEXT,
    kind            TEXT NOT NULL,
    remote_addr     TEXT,
    application_uri TEXT,
    user            TEXT,
    node_id         TEXT,
    body            TEXT NOT NULL,
    prev_hash       TEXT NOT NULL,
    hash            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts);
CREATE INDEX IF NOT EXISTS audit_target_ts ON audit (target, ts);
CREATE INDEX IF NOT EXISTS audit_node ON audit (node_id);
CREATE INDEX IF NOT EXISTS audit_user ON audit (user);
"#;

fn record_hash(prev_hash: &str, seq: i64, body: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(b"\n");
    hasher.update(seq.to_string().as_bytes());
    hasher.update(b"\n");
    hasher.update(body.as_bytes());
    hex::encode(hasher.finalize())
}

/// Fixed-width UTC timestamps, so that string order equals time order in SQL.
fn ts_column(ts: &DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn configure(conn: &Connection) -> rusqlite::Result<()> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(())
}

/// The single writer of the audit database.
pub struct AuditStore {
    conn: Connection,
    last_seq: i64,
    last_hash: String,
}

impl AuditStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("creating directory {}", dir.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening audit database {}", path.display()))?;
        configure(&conn)?;
        conn.execute_batch(SCHEMA)?;
        let (last_seq, last_hash) = conn
            .query_row(
                "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or((0, GENESIS_HASH.to_string()));
        Ok(Self {
            conn,
            last_seq,
            last_hash,
        })
    }

    /// Appends entries in one transaction and returns their sequence numbers.
    /// On error nothing is written and the chain head is unchanged.
    pub fn append(&mut self, entries: &[AuditEntry]) -> anyhow::Result<Vec<i64>> {
        let tx = self.conn.transaction()?;
        let mut seq = self.last_seq;
        let mut hash = self.last_hash.clone();
        let mut seqs = Vec::with_capacity(entries.len());
        {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO audit (seq, ts, target, kind, remote_addr, application_uri, user,
                                    node_id, body, prev_hash, hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            )?;
            for entry in entries {
                seq += 1;
                let body = serde_json::to_string(entry)?;
                let new_hash = record_hash(&hash, seq, &body);
                let client = entry.client.as_ref();
                stmt.execute(params![
                    seq,
                    ts_column(&entry.ts),
                    entry.target,
                    entry.event.kind(),
                    client.map(|c| &c.remote_addr),
                    client.and_then(|c| c.application_uri.as_ref()),
                    client.and_then(|c| c.user.as_ref()).map(|u| u.label()),
                    entry.event.node_id(),
                    body,
                    hash,
                    new_hash,
                ])?;
                hash = new_hash;
                seqs.push(seq);
            }
        }
        tx.commit()?;
        self.last_seq = seq;
        self.last_hash = hash;
        Ok(seqs)
    }

    /// Deletes records older than `cutoff` and appends a `RetentionPruned`
    /// record. Returns the number of deleted records.
    pub fn prune_before(&mut self, cutoff: DateTime<Utc>) -> anyhow::Result<u64> {
        let last: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT seq, hash FROM audit WHERE ts < ?1 ORDER BY seq DESC LIMIT 1",
                [ts_column(&cutoff)],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((last_seq, last_hash)) = last else {
            return Ok(0);
        };
        // The chain head may be deleted too: the prune record links to it
        // through the in-memory `last_hash`.
        let deleted = self
            .conn
            .execute("DELETE FROM audit WHERE seq <= ?1", [last_seq])? as u64;
        self.append(&[AuditEntry::new(AuditEvent::RetentionPruned {
            deleted,
            last_seq,
            last_hash,
        })])?;
        Ok(deleted)
    }
}

/// Filter for [`query`]. All fields are optional and combined with AND.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct AuditQuery {
    pub target: Option<String>,
    pub kind: Option<String>,
    pub user: Option<String>,
    pub node_id: Option<String>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    /// Only records with a sequence number below this one (for paging backwards).
    pub before_seq: Option<i64>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredRecord {
    pub seq: i64,
    pub hash: String,
    #[serde(flatten)]
    pub entry: AuditEntry,
}

pub fn open_reader(path: &Path) -> anyhow::Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening audit database {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

/// Newest records first.
pub fn query(conn: &Connection, q: &AuditQuery) -> anyhow::Result<Vec<StoredRecord>> {
    let mut sql = String::from("SELECT seq, hash, body FROM audit WHERE 1=1");
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    let mut add = |clause: &str, value: Box<dyn rusqlite::ToSql>| {
        args.push(value);
        sql.push_str(&format!(" AND {clause} ?{}", args.len()));
    };
    if let Some(v) = &q.target {
        add("target =", Box::new(v.clone()));
    }
    if let Some(v) = &q.kind {
        add("kind =", Box::new(v.clone()));
    }
    if let Some(v) = &q.user {
        add("user =", Box::new(v.clone()));
    }
    if let Some(v) = &q.node_id {
        add("node_id =", Box::new(v.clone()));
    }
    if let Some(v) = &q.since {
        add("ts >=", Box::new(ts_column(v)));
    }
    if let Some(v) = &q.until {
        add("ts <", Box::new(ts_column(v)));
    }
    if let Some(v) = q.before_seq {
        add("seq <", Box::new(v));
    }
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    sql.push_str(&format!(" ORDER BY seq DESC LIMIT {limit}"));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (seq, hash, body) = row?;
        let entry = serde_json::from_str(&body)
            .with_context(|| format!("audit record {seq} has an unreadable body"))?;
        out.push(StoredRecord { seq, hash, entry });
    }
    Ok(out)
}

#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub records: u64,
    pub first_seq: Option<i64>,
    pub last_seq: Option<i64>,
    pub head_hash: String,
    /// `None` when the whole chain checks out.
    pub error: Option<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.error.is_none()
    }
}

/// Walks the whole chain and checks every link, hash and indexed column.
pub fn verify(conn: &Connection) -> anyhow::Result<VerifyReport> {
    let mut stmt = conn.prepare(
        "SELECT seq, ts, kind, node_id, body, prev_hash, hash FROM audit ORDER BY seq ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut report = VerifyReport {
        records: 0,
        first_seq: None,
        last_seq: None,
        head_hash: GENESIS_HASH.to_string(),
        error: None,
    };
    // Set when the first remaining record does not start the chain; a later
    // RetentionPruned record must vouch for exactly that gap.
    let mut unexplained_gap: Option<(i64, String)> = None;

    while let Some(row) = rows.next()? {
        let seq: i64 = row.get(0)?;
        let ts: String = row.get(1)?;
        let kind: String = row.get(2)?;
        let node_id: Option<String> = row.get(3)?;
        let body: String = row.get(4)?;
        let prev_hash: String = row.get(5)?;
        let hash: String = row.get(6)?;

        let fail = |msg: String| -> anyhow::Result<()> { bail!("record {seq}: {msg}") };
        let result: anyhow::Result<()> = (|| {
            match report.last_seq {
                None if seq == 1 && prev_hash != GENESIS_HASH => {
                    fail("first record does not link to the genesis hash".into())?
                }
                None if seq != 1 => unexplained_gap = Some((seq - 1, prev_hash.clone())),
                None => {}
                Some(last) if seq != last + 1 => fail(format!("sequence gap after record {last}"))?,
                Some(_) if prev_hash != report.head_hash => {
                    fail("does not link to the previous record".into())?
                }
                Some(_) => {}
            }
            if record_hash(&prev_hash, seq, &body) != hash {
                fail("hash mismatch (record was modified)".into())?;
            }
            let entry: AuditEntry = serde_json::from_str(&body)
                .map_err(|e| anyhow::anyhow!("record {seq}: unreadable body: {e}"))?;
            if ts_column(&entry.ts) != ts
                || entry.event.kind() != kind
                || entry.event.node_id() != node_id.as_deref()
            {
                fail("indexed columns do not match the record body".into())?;
            }
            if let AuditEvent::RetentionPruned {
                last_seq,
                last_hash,
                ..
            } = &entry.event
            {
                if unexplained_gap.as_ref() == Some(&(*last_seq, last_hash.clone())) {
                    unexplained_gap = None;
                }
            }
            Ok(())
        })();

        if let Err(e) = result {
            report.error = Some(e.to_string());
            return Ok(report);
        }
        report.records += 1;
        report.first_seq.get_or_insert(seq);
        report.last_seq = Some(seq);
        report.head_hash = hash;
    }

    if let Some((seq, _)) = unexplained_gap {
        report.error = Some(format!(
            "records up to {seq} are missing and no retention record accounts for them"
        ));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::{AuditValue, ClientContext, UserIdentity};

    fn write_event(node: &str, value: f64) -> AuditEntry {
        AuditEntry::new(AuditEvent::Write {
            request_handle: 7,
            node_id: node.into(),
            display_name: None,
            attribute: "Value".into(),
            index_range: None,
            old_value: None,
            new_value: AuditValue {
                data_type: "Double".into(),
                value: value.into(),
            },
            status: "Good".into(),
        })
        .target("plc1")
        .client(ClientContext {
            remote_addr: "10.0.0.5:50123".into(),
            user: Some(UserIdentity::UserName {
                name: "operator".into(),
            }),
            ..Default::default()
        })
    }

    fn store() -> (tempfile::TempDir, AuditStore, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.db");
        let store = AuditStore::open(&path).unwrap();
        (dir, store, path)
    }

    #[test]
    fn appends_and_verifies() {
        let (_dir, mut store, path) = store();
        let seqs = store
            .append(&[write_event("ns=2;s=A", 1.0), write_event("ns=2;s=B", 2.0)])
            .unwrap();
        assert_eq!(seqs, vec![1, 2]);

        let reader = open_reader(&path).unwrap();
        let report = verify(&reader).unwrap();
        assert!(report.ok(), "{:?}", report.error);
        assert_eq!(report.records, 2);

        let rows = query(
            &reader,
            &AuditQuery {
                user: Some("operator".into()),
                node_id: Some("ns=2;s=B".into()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].seq, 2);
    }

    #[test]
    fn chain_continues_after_reopen() {
        let (_dir, mut store, path) = store();
        store.append(&[write_event("ns=2;s=A", 1.0)]).unwrap();
        drop(store);
        let mut store = AuditStore::open(&path).unwrap();
        assert_eq!(store.last_seq, 1);
        store.append(&[write_event("ns=2;s=A", 2.0)]).unwrap();
        assert!(verify(&open_reader(&path).unwrap()).unwrap().ok());
    }

    #[test]
    fn detects_modified_value() {
        let (_dir, mut store, path) = store();
        store
            .append(&[write_event("ns=2;s=A", 1.0), write_event("ns=2;s=A", 2.0)])
            .unwrap();
        store
            .conn
            .execute(
                "UPDATE audit SET body = replace(body, '1.0', '9.0') WHERE seq = 1",
                [],
            )
            .unwrap();
        let report = verify(&open_reader(&path).unwrap()).unwrap();
        assert!(report.error.unwrap().contains("record 1: hash mismatch"));
    }

    #[test]
    fn detects_deleted_record() {
        let (_dir, mut store, path) = store();
        store
            .append(&[
                write_event("ns=2;s=A", 1.0),
                write_event("ns=2;s=A", 2.0),
                write_event("ns=2;s=A", 3.0),
            ])
            .unwrap();
        store
            .conn
            .execute("DELETE FROM audit WHERE seq = 2", [])
            .unwrap();
        let report = verify(&open_reader(&path).unwrap()).unwrap();
        assert!(report.error.unwrap().contains("sequence gap"));
    }

    #[test]
    fn detects_deleted_head_of_chain() {
        let (_dir, mut store, path) = store();
        store
            .append(&[write_event("ns=2;s=A", 1.0), write_event("ns=2;s=A", 2.0)])
            .unwrap();
        store
            .conn
            .execute("DELETE FROM audit WHERE seq = 1", [])
            .unwrap();
        let report = verify(&open_reader(&path).unwrap()).unwrap();
        assert!(report.error.unwrap().contains("missing"));
    }

    #[test]
    fn detects_tampered_index_column() {
        let (_dir, mut store, path) = store();
        store.append(&[write_event("ns=2;s=A", 1.0)]).unwrap();
        store
            .conn
            .execute("UPDATE audit SET node_id = 'ns=2;s=Other'", [])
            .unwrap();
        let report = verify(&open_reader(&path).unwrap()).unwrap();
        assert!(report.error.unwrap().contains("indexed columns"));
    }

    #[test]
    fn retention_keeps_chain_verifiable() {
        let (_dir, mut store, path) = store();
        let mut old = write_event("ns=2;s=A", 1.0);
        old.ts = Utc::now() - chrono::Duration::days(400);
        store.append(&[old.clone(), old]).unwrap();
        store.append(&[write_event("ns=2;s=A", 2.0)]).unwrap();

        let deleted = store
            .prune_before(Utc::now() - chrono::Duration::days(365))
            .unwrap();
        assert_eq!(deleted, 2);

        let report = verify(&open_reader(&path).unwrap()).unwrap();
        assert!(report.ok(), "{:?}", report.error);
        assert_eq!(report.first_seq, Some(3));
        assert_eq!(report.last_seq, Some(4));
    }
}
