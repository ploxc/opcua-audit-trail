//! SQLite-backed, tamper-evident audit store.
//!
//! Records form a hash chain: each record stores the hash of its predecessor and
//! `hash = sha256(prev_hash "\n" seq "\n" body)`, where `body` is the exact JSON
//! text of the [`AuditEntry`]. Changing, inserting or deleting a record breaks
//! the chain from that point on, which [`verify`] detects.
//!
//! Retention deletes the oldest records and, in the same transaction, appends
//! a [`AuditEvent::RetentionPruned`] record naming the last deleted sequence
//! number and hash, so the remaining chain stays verifiable.
//!
//! What the chain proves: records between the first and the last one were
//! not changed, removed or reordered by someone who did not recompute the
//! hashes. It cannot prove that the newest records were not cut off, or that
//! the whole chain was not rebuilt: that needs an anchor outside the
//! database, such as the hashes the exporters ship, or a head noted down and
//! passed to `verify --expect`.

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
-- The newest record ever written, updated with every append. If the audit
-- table ends before it, records were removed.
CREATE TABLE IF NOT EXISTS chain_head (
    id   INTEGER PRIMARY KEY CHECK (id = 1),
    seq  INTEGER NOT NULL,
    hash TEXT NOT NULL
);
"#;

/// Most records one retention run deletes, so the writer is not blocked
/// for long; the next run continues.
pub const MAX_PRUNE: i64 = 20_000;

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
    // FULL: a committed record survives a power cut. Fail-closed forwards a
    // change as soon as its intent is committed.
    conn.pragma_update(None, "synchronous", "FULL")?;
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
        let table_head: Option<(i64, String)> = conn
            .query_row(
                "SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let written: Option<(i64, String)> = conn
            .query_row("SELECT seq, hash FROM chain_head WHERE id = 1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        let found = table_head.as_ref().map_or(0, |(seq, _)| *seq);
        let (last_seq, last_hash, truncated) = match (table_head, written) {
            // Sequence numbers are never reused: continue after the newest
            // record ever written, even if it is gone.
            (_, Some((seq, hash))) if found < seq => (seq, hash, true),
            (Some((seq, hash)), _) => (seq, hash, false),
            (None, _) => (0, GENESIS_HASH.to_string(), false),
        };
        let mut store = Self {
            conn,
            last_seq,
            last_hash,
        };
        if truncated {
            tracing::error!(
                "the audit trail ends at record {found}, but record {last_seq} was written: \
                 the newest records are missing"
            );
            store.append(&[AuditEntry::new(AuditEvent::TrailTruncated {
                expected_seq: last_seq,
                found_seq: found,
            })])?;
        }
        Ok(store)
    }

    /// Appends entries in one transaction and returns their sequence numbers.
    /// On error nothing is written and the chain head is unchanged.
    pub fn append(&mut self, entries: &[AuditEntry]) -> anyhow::Result<Vec<i64>> {
        let tx = self.conn.transaction()?;
        let (seqs, seq, hash) = insert(&tx, entries, self.last_seq, &self.last_hash)?;
        tx.commit()?;
        self.last_seq = seq;
        self.last_hash = hash;
        Ok(seqs)
    }

    /// Deletes records older than `cutoff` and, in the same transaction,
    /// appends a `RetentionPruned` record. Returns the number deleted, at
    /// most [`MAX_PRUNE`].
    ///
    /// Only the oldest records in one piece are deleted, up to the first
    /// record at or after `cutoff`, and never the newest record: a record
    /// with a wrong (too old) timestamp between newer ones keeps them all.
    /// Nothing is deleted while the newest record is dated in the future,
    /// i.e. the clock went back.
    pub fn prune_before(&mut self, cutoff: DateTime<Utc>) -> anyhow::Result<u64> {
        let head: Option<(i64, String)> = self
            .conn
            .query_row(
                "SELECT seq, ts FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((head_seq, head_ts)) = head else {
            return Ok(0);
        };
        if head_ts > ts_column(&(Utc::now() + chrono::Duration::minutes(5))) {
            tracing::warn!("retention skipped: the newest audit record is dated after now");
            return Ok(0);
        }
        let first_seq: i64 = self
            .conn
            .query_row("SELECT MIN(seq) FROM audit", [], |r| r.get(0))?;
        let first_kept: Option<i64> = self.conn.query_row(
            "SELECT MIN(seq) FROM audit WHERE ts >= ?1",
            [ts_column(&cutoff)],
            |r| r.get(0),
        )?;
        let last_seq =
            (first_kept.unwrap_or(head_seq).min(head_seq) - 1).min(first_seq + MAX_PRUNE - 1);
        if last_seq < first_seq {
            return Ok(0);
        }
        let last_hash: String =
            self.conn
                .query_row("SELECT hash FROM audit WHERE seq = ?1", [last_seq], |r| {
                    r.get(0)
                })?;
        let tx = self.conn.transaction()?;
        let deleted = tx.execute("DELETE FROM audit WHERE seq <= ?1", [last_seq])? as u64;
        let (_, seq, hash) = insert(
            &tx,
            &[AuditEntry::new(AuditEvent::RetentionPruned {
                deleted,
                last_seq,
                last_hash,
            })],
            self.last_seq,
            &self.last_hash,
        )?;
        tx.commit()?;
        self.last_seq = seq;
        self.last_hash = hash;
        Ok(deleted)
    }
}

/// The indexed columns of a record, derived from its entry. `append` writes
/// them and `verify` checks them with the same function.
/// ts, target, kind, remote_addr, application_uri, user, node_id.
type Columns = (
    String,
    Option<String>,
    &'static str,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn columns(entry: &AuditEntry) -> Columns {
    let client = entry.client.as_ref();
    (
        ts_column(&entry.ts),
        entry.target.clone(),
        entry.event.kind(),
        client.map(|c| c.remote_addr.clone()),
        client.and_then(|c| c.application_uri.clone()),
        client.and_then(|c| c.user.as_ref()).map(|u| u.label()),
        entry.event.node_id().map(str::to_string),
    )
}

/// Inserts entries after (`seq`, `hash`) and moves the chain head along.
/// Returns their sequence numbers and the new head.
fn insert(
    tx: &rusqlite::Transaction,
    entries: &[AuditEntry],
    mut seq: i64,
    hash: &str,
) -> anyhow::Result<(Vec<i64>, i64, String)> {
    let mut hash = hash.to_string();
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
            let (ts, target, kind, remote_addr, application_uri, user, node_id) = columns(entry);
            stmt.execute(params![
                seq,
                ts,
                target,
                kind,
                remote_addr,
                application_uri,
                user,
                node_id,
                body,
                hash,
                new_hash,
            ])?;
            hash = new_hash;
            seqs.push(seq);
        }
    }
    tx.execute(
        "INSERT INTO chain_head (id, seq, hash) VALUES (1, ?1, ?2)
         ON CONFLICT (id) DO UPDATE SET seq = excluded.seq, hash = excluded.hash",
        params![seq, hash],
    )?;
    Ok((seqs, seq, hash))
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
    /// Only records with a sequence number above this one.
    pub after_seq: Option<i64>,
    /// Several kinds, comma separated (e.g. the kinds of a severity).
    pub kinds: Option<String>,
    pub limit: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StoredRecord {
    pub seq: i64,
    pub hash: String,
    pub prev_hash: String,
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

/// A node that was written often: candidates for the ignore list.
#[derive(Debug, Clone, Serialize)]
pub struct WrittenNode {
    pub target: Option<String>,
    pub node_id: String,
    pub display_name: Option<String>,
    pub count: i64,
    /// The most recent write to it.
    pub last: StoredRecord,
}

/// The nodes with the most recorded writes since `since`, most first.
/// Which writes `most_written` counts.
#[derive(Debug, Default, Clone)]
pub struct WrittenFilter {
    pub target: Option<String>,
    /// Only writes from this client: its IP address or application URI.
    pub client: Option<String>,
}

pub fn most_written(
    conn: &Connection,
    since: &DateTime<Utc>,
    limit: u32,
    filter: &WrittenFilter,
) -> anyhow::Result<Vec<WrittenNode>> {
    let mut stmt = conn.prepare(
        "SELECT a.target, a.node_id, c.n, a.seq, a.hash, a.body, a.prev_hash
         FROM (SELECT target, node_id, COUNT(*) AS n, MAX(seq) AS last FROM audit
               WHERE kind = 'write' AND ts >= ?1
                 AND (?3 IS NULL OR target = ?3)
                 AND (?4 IS NULL OR application_uri = ?4 OR remote_addr = ?4
                      OR substr(remote_addr, 1, length(?4) + 1) = ?4 || ':'
                      OR substr(remote_addr, 1, length(?4) + 3) = '[' || ?4 || ']:')
               GROUP BY target, node_id
               ORDER BY n DESC LIMIT ?2) AS c
         JOIN audit AS a ON a.seq = c.last
         ORDER BY c.n DESC",
    )?;
    let args = params![ts_column(since), limit, filter.target, filter.client];
    let rows = stmt.query_map(args, |r| {
        Ok((
            r.get::<_, Option<String>>(0)?,
            r.get::<_, Option<String>>(1)?,
            r.get::<_, i64>(2)?,
            r.get::<_, i64>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
            r.get::<_, String>(6)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (target, node_id, count, seq, hash, body, prev_hash) = row?;
        let entry: AuditEntry = serde_json::from_str(&body)
            .with_context(|| format!("audit record {seq} has an unreadable body"))?;
        let display_name = match &entry.event {
            crate::audit::event::AuditEvent::Write { display_name, .. } => display_name.clone(),
            _ => None,
        };
        out.push(WrittenNode {
            target,
            node_id: node_id.unwrap_or_default(),
            display_name,
            count,
            last: StoredRecord {
                seq,
                hash,
                prev_hash,
                entry,
            },
        });
    }
    Ok(out)
}

/// Unacknowledged records of one severity.
#[derive(Debug, Clone, Serialize)]
pub struct AlarmCount {
    pub severity: crate::audit::event::Severity,
    /// Acknowledged up to and including this record (0: never).
    pub acknowledged_up_to: i64,
    pub unacknowledged: i64,
    /// The event kinds of this severity, for filtering.
    pub kinds: Vec<&'static str>,
}

/// For each severity, how many records came after the last acknowledgement.
pub fn alarms(conn: &Connection) -> anyhow::Result<Vec<AlarmCount>> {
    use crate::audit::event::{AuditEvent, Severity};
    let mut marks = std::collections::HashMap::new();
    let mut stmt = conn.prepare(
        "SELECT body FROM audit WHERE kind = 'alarms_acknowledged' ORDER BY seq DESC LIMIT 100",
    )?;
    for body in stmt.query_map([], |r| r.get::<_, String>(0))? {
        if let Ok(entry) = serde_json::from_str::<AuditEntry>(&body?) {
            if let AuditEvent::AlarmsAcknowledged {
                severity,
                up_to_seq,
                ..
            } = entry.event
            {
                marks.entry(severity).or_insert(up_to_seq);
            }
        }
    }
    let mut out = Vec::new();
    for severity in Severity::ALL {
        let mark = marks.get(&severity).copied().unwrap_or(0);
        let kinds = severity.kinds();
        let list = kinds
            .iter()
            .map(|k| format!("'{k}'"))
            .collect::<Vec<_>>()
            .join(", ");
        let count: i64 = conn.query_row(
            &format!("SELECT COUNT(*) FROM audit WHERE seq > ?1 AND kind IN ({list})"),
            [mark],
            |r| r.get(0),
        )?;
        out.push(AlarmCount {
            severity,
            acknowledged_up_to: mark,
            unacknowledged: count,
            kinds: kinds.to_vec(),
        });
    }
    Ok(out)
}

/// Newest records first.
pub fn query(conn: &Connection, q: &AuditQuery) -> anyhow::Result<Vec<StoredRecord>> {
    let mut sql = String::from("SELECT seq, hash, body, prev_hash FROM audit WHERE 1=1");
    let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
    // `clause` refers to the value as `{v}`.
    let mut add = |clause: &str, value: Box<dyn rusqlite::ToSql>| {
        args.push(value);
        let clause = if clause.contains("{v}") {
            clause.replace("{v}", &format!("?{}", args.len()))
        } else {
            format!("{clause} ?{}", args.len())
        };
        sql.push_str(&format!(" AND {clause}"));
    };
    if let Some(v) = &q.target {
        add("target =", Box::new(v.clone()));
    }
    if let Some(v) = &q.kind {
        add("kind =", Box::new(v.clone()));
    }
    // User and node match on part of the text, ignoring case: the user also
    // who did something in the web UI, the node also its display name.
    if let Some(v) = &q.user {
        add(
            "instr(lower(coalesce(user, json_extract(body, '$.event.by'), \
             json_extract(body, '$.event.user'))), lower({v})) > 0",
            Box::new(v.clone()),
        );
    }
    if let Some(v) = &q.node_id {
        add(
            "(instr(lower(node_id), lower({v})) > 0 \
             OR instr(lower(json_extract(body, '$.event.display_name')), lower({v})) > 0)",
            Box::new(v.clone()),
        );
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
    if let Some(v) = q.after_seq {
        add("seq >", Box::new(v));
    }
    if let Some(kinds) = &q.kinds {
        let kinds: Vec<&str> = kinds
            .split(',')
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .collect();
        if !kinds.is_empty() {
            let mut marks = Vec::new();
            for k in kinds {
                args.push(Box::new(k.to_string()));
                marks.push(format!("?{}", args.len()));
            }
            sql.push_str(&format!(" AND kind IN ({})", marks.join(", ")));
        }
    }
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    sql.push_str(&format!(" ORDER BY seq DESC LIMIT {limit}"));

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (seq, hash, body, prev_hash) = row?;
        let entry = serde_json::from_str(&body)
            .with_context(|| format!("audit record {seq} has an unreadable body"))?;
        out.push(StoredRecord {
            seq,
            hash,
            prev_hash,
            entry,
        });
    }
    Ok(out)
}

/// Records after `after_seq`, oldest first (for exporting).
pub fn query_after(
    conn: &Connection,
    after_seq: i64,
    limit: u32,
) -> anyhow::Result<Vec<StoredRecord>> {
    let mut stmt = conn.prepare_cached(
        "SELECT seq, hash, body, prev_hash FROM audit WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![after_seq, limit], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
        ))
    })?;
    let mut out = Vec::new();
    for row in rows {
        let (seq, hash, body, prev_hash) = row?;
        let entry = serde_json::from_str(&body)
            .with_context(|| format!("audit record {seq} has an unreadable body"))?;
        out.push(StoredRecord {
            seq,
            hash,
            prev_hash,
            entry,
        });
    }
    Ok(out)
}

/// Sequence number of the newest record (0 when empty).
pub fn head_seq(conn: &Connection) -> anyhow::Result<i64> {
    Ok(conn.query_row("SELECT COALESCE(MAX(seq), 0) FROM audit", [], |r| r.get(0))?)
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

/// A record known from outside the database (an exporter's last delivery,
/// or a head noted down earlier): the trail must still contain it, unchanged.
#[derive(Debug, Clone, PartialEq)]
pub struct Anchor {
    pub seq: i64,
    pub hash: String,
    /// Where it comes from, for the error message.
    pub source: String,
}

/// Walks the whole chain and checks every link, hash and indexed column.
#[cfg(test)]
pub fn verify(conn: &Connection) -> anyhow::Result<VerifyReport> {
    verify_against(conn, &[])
}

/// [`verify`], and checks that every anchor is still in the trail.
pub fn verify_against(conn: &Connection, anchors: &[Anchor]) -> anyhow::Result<VerifyReport> {
    let mut report = verify_chain(conn)?;
    if !report.ok() {
        return Ok(report);
    }
    for anchor in anchors {
        let problem = if report.last_seq.is_none_or(|last| anchor.seq > last) {
            Some(format!(
                "records up to {} are missing: {} had record {} (hash {})",
                anchor.seq, anchor.source, anchor.seq, anchor.hash
            ))
        } else if report.first_seq.is_some_and(|first| anchor.seq < first) {
            None // pruned by retention since
        } else {
            let hash: Option<String> = conn
                .query_row("SELECT hash FROM audit WHERE seq = ?1", [anchor.seq], |r| {
                    r.get(0)
                })
                .optional()?;
            (hash.as_deref() != Some(anchor.hash.as_str())).then(|| {
                format!(
                    "record {} differs from {} (hash {})",
                    anchor.seq, anchor.source, anchor.hash
                )
            })
        };
        if let Some(problem) = problem {
            report.error = Some(problem);
            break;
        }
    }
    Ok(report)
}

fn verify_chain(conn: &Connection) -> anyhow::Result<VerifyReport> {
    let mut stmt = conn.prepare(
        "SELECT seq, ts, kind, node_id, body, prev_hash, hash, target, remote_addr,
                application_uri, user
         FROM audit ORDER BY seq ASC",
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
        let stored: (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = (row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?);

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
            let (c_ts, c_target, c_kind, c_remote, c_uri, c_user, c_node) = columns(&entry);
            if c_ts != ts
                || c_kind != kind
                || c_node != node_id
                || (c_target, c_remote, c_uri, c_user) != stored
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
            display_name: Some(format!("Tag {node}")),
            attribute: "Value".into(),
            index_range: None,
            old_value: None,
            new_value: AuditValue {
                data_type: "Double".into(),
                value: value.into(),
            },
            written_status: None,
            source_timestamp: None,
            server_timestamp: None,
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

        // User and node match on part of the text, ignoring case.
        let find = |user: &str, node: &str| {
            query(
                &reader,
                &AuditQuery {
                    user: Some(user.into()),
                    node_id: Some(node.into()),
                    ..Default::default()
                },
            )
            .unwrap()
            .len()
        };
        assert_eq!(find("OPER", "s=b"), 1);
        assert_eq!(find("oper", "ns=2"), 2);
        assert_eq!(find("nobody", "ns=2"), 0);
        assert_eq!(find("", "TAG ns=2;s=A"), 1, "by display name");
    }

    #[test]
    fn the_user_filter_finds_web_ui_actions() {
        let (_dir, mut store, path) = store();
        store
            .append(&[
                write_event("ns=2;s=A", 1.0),
                AuditEntry::new(AuditEvent::ConfigChanged {
                    by: "Admin".into(),
                    summary: "created user 'jan'".into(),
                }),
                AuditEntry::new(AuditEvent::UiLoginFailed { user: "jan".into() }),
            ])
            .unwrap();
        let reader = open_reader(&path).unwrap();
        let find = |user: &str| {
            query(
                &reader,
                &AuditQuery {
                    user: Some(user.into()),
                    ..Default::default()
                },
            )
            .unwrap()
            .iter()
            .map(|r| r.seq)
            .collect::<Vec<_>>()
        };
        assert_eq!(find("adm"), vec![2]);
        assert_eq!(find("JAN"), vec![3]);
        assert_eq!(find("oper"), vec![1]);
    }

    #[test]
    fn most_written_nodes_come_first() {
        let (_dir, mut store, path) = store();
        let mut entries = Vec::new();
        for i in 0..5 {
            entries.push(write_event("ns=2;s=Life", i as f64));
        }
        entries.push(write_event("ns=2;s=Set", 1.0));
        entries.push(write_event("ns=2;s=Set", 2.0));
        let mut old = write_event("ns=2;s=Old", 1.0);
        old.ts = Utc::now() - chrono::Duration::days(2);
        entries.push(old);
        entries.push(AuditEntry::new(AuditEvent::GatewayStopped));
        store.append(&entries).unwrap();

        let reader = open_reader(&path).unwrap();
        let since = Utc::now() - chrono::Duration::days(1);
        let all = WrittenFilter::default();
        let top = most_written(&reader, &since, 10, &all).unwrap();
        let summary: Vec<_> = top.iter().map(|n| (n.node_id.as_str(), n.count)).collect();
        assert_eq!(summary, [("ns=2;s=Life", 5), ("ns=2;s=Set", 2)]);
        assert_eq!(top[0].target.as_deref(), Some("plc1"));
        assert_eq!(top[0].last.seq, 5, "the most recent write");
        assert_eq!(most_written(&reader, &since, 1, &all).unwrap().len(), 1);
        let count = |target: Option<&str>, client: Option<&str>| {
            let filter = WrittenFilter {
                target: target.map(Into::into),
                client: client.map(Into::into),
            };
            most_written(&reader, &since, 10, &filter).unwrap().len()
        };
        let addr = top[0]
            .last
            .entry
            .client
            .as_ref()
            .unwrap()
            .remote_addr
            .clone();
        let ip = addr
            .rsplit_once(':')
            .unwrap()
            .0
            .trim_matches(['[', ']'])
            .to_string();
        assert_eq!(count(Some("plc1"), Some(&ip)), 2);
        assert_eq!(count(Some("plc2"), None), 0);
        assert_eq!(count(None, Some("10.9.9.9")), 0);
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

    fn at(ts: DateTime<Utc>, value: f64) -> AuditEntry {
        let mut e = write_event("ns=2;s=A", value);
        e.ts = ts;
        e
    }

    fn seqs(conn: &Connection) -> Vec<i64> {
        let mut stmt = conn.prepare("SELECT seq FROM audit ORDER BY seq").unwrap();
        stmt.query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
    }

    /// Audit finding A2: records with a wrong, too old timestamp between
    /// newer ones (a clock that was wrong at boot) must not take the newer
    /// ones with them; the newest record always stays.
    #[test]
    fn retention_deletes_only_the_old_prefix() {
        let (_dir, mut store, path) = store();
        let old = Utc::now() - chrono::Duration::days(400);
        let epoch = DateTime::from_timestamp(0, 0).unwrap();
        store.append(&[at(old, 1.0), at(old, 2.0)]).unwrap(); // 1, 2
        store.append(&[write_event("ns=2;s=A", 3.0)]).unwrap(); // 3: today
        store.append(&[at(epoch, 4.0)]).unwrap(); // 4: clock not set yet
        store.append(&[write_event("ns=2;s=A", 5.0)]).unwrap(); // 5: today
        let deleted = store
            .prune_before(Utc::now() - chrono::Duration::days(365))
            .unwrap();
        assert_eq!(deleted, 2);
        assert_eq!(seqs(&store.conn), vec![3, 4, 5, 6]);
        assert!(verify(&open_reader(&path).unwrap()).unwrap().ok());

        // Everything older than the cutoff (clock far ahead): the newest
        // record still stays.
        let deleted = store
            .prune_before(Utc::now() + chrono::Duration::days(3650))
            .unwrap();
        assert_eq!(deleted, 3);
        assert_eq!(seqs(&store.conn), vec![6, 7]);
        assert!(verify(&open_reader(&path).unwrap()).unwrap().ok());
    }

    /// Nothing is pruned while the newest record is dated in the future:
    /// the clock went back.
    #[test]
    fn retention_waits_when_the_clock_went_back() {
        let (_dir, mut store, _path) = store();
        let old = Utc::now() - chrono::Duration::days(400);
        store.append(&[at(old, 1.0)]).unwrap();
        store
            .append(&[at(Utc::now() + chrono::Duration::days(30), 2.0)])
            .unwrap();
        let deleted = store
            .prune_before(Utc::now() - chrono::Duration::days(365))
            .unwrap();
        assert_eq!(deleted, 0);
    }

    /// Audit finding A3: committed records survive a power cut.
    #[test]
    fn commits_are_durable() {
        let (_dir, store, _path) = store();
        let sync: i64 = store
            .conn
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(sync, 2, "FULL");
    }

    /// Audit finding A5: every indexed column must match the record body.
    #[test]
    fn detects_tampered_user_column() {
        let (_dir, mut store, path) = store();
        store.append(&[write_event("ns=2;s=A", 1.0)]).unwrap();
        store
            .conn
            .execute("UPDATE audit SET user = 'someone_else'", [])
            .unwrap();
        let report = verify(&open_reader(&path).unwrap()).unwrap();
        assert!(report.error.unwrap().contains("indexed columns"));
    }

    /// Audit finding N9: when the newest records are gone, numbering
    /// continues after them (no sequence number is used twice), the loss is
    /// recorded and `verify` keeps reporting it.
    #[test]
    fn a_cut_off_tail_is_noticed_at_start() {
        let (_dir, mut store, path) = store();
        for i in 0..5 {
            store
                .append(&[write_event("ns=2;s=A", f64::from(i))])
                .unwrap();
        }
        drop(store);
        let conn = Connection::open(&path).unwrap();
        conn.execute("DELETE FROM audit WHERE seq > 3", []).unwrap();
        drop(conn);

        let mut store = AuditStore::open(&path).unwrap();
        assert_eq!(seqs(&store.conn), vec![1, 2, 3, 6]);
        let kind: String = store
            .conn
            .query_row("SELECT kind FROM audit WHERE seq = 6", [], |r| r.get(0))
            .unwrap();
        assert_eq!(kind, "trail_truncated");
        assert_eq!(
            store.append(&[write_event("ns=2;s=A", 9.0)]).unwrap(),
            vec![7]
        );
        assert!(!verify(&open_reader(&path).unwrap()).unwrap().ok());
    }

    /// Audit finding A1: a trail cut off while the gateway was stopped, or
    /// rebuilt, still verifies on its own; a record known from outside (an
    /// export, a noted head) catches both.
    #[test]
    fn anchors_catch_truncation_and_rebuilding() {
        let (_dir, mut store, path) = store();
        for i in 0..5 {
            store
                .append(&[write_event("ns=2;s=A", f64::from(i))])
                .unwrap();
        }
        let hash4: String = store
            .conn
            .query_row("SELECT hash FROM audit WHERE seq = 4", [], |r| r.get(0))
            .unwrap();
        let anchor = Anchor {
            seq: 4,
            hash: hash4.clone(),
            source: "test".into(),
        };
        let reader = open_reader(&path).unwrap();
        assert!(verify_against(&reader, std::slice::from_ref(&anchor))
            .unwrap()
            .ok());

        // Cut off the tail (and the head marker, as someone with file
        // access would): the chain alone still verifies.
        store
            .conn
            .execute("DELETE FROM audit WHERE seq > 3", [])
            .unwrap();
        store.conn.execute("DELETE FROM chain_head", []).unwrap();
        assert!(verify(&reader).unwrap().ok());
        let report = verify_against(&reader, &[anchor]).unwrap();
        assert!(report.error.unwrap().contains("missing"));

        // A record with another hash than the one exported.
        let other = Anchor {
            seq: 3,
            hash: "0".repeat(64),
            source: "test".into(),
        };
        let report = verify_against(&reader, &[other]).unwrap();
        assert!(report.error.unwrap().contains("differs"));
    }
}
