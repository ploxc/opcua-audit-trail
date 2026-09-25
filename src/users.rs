//! Web UI users: stored in `<data_dir>/gateway.db` with argon2 password hashes.

use std::path::Path;

use anyhow::{bail, Context};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use chrono::Utc;
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

/// Roles are cumulative: an admin can do everything an operator can, and an
/// operator everything an auditor can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Read the dashboard and the audit trail.
    Auditor,
    /// Also use the OPC UA browser.
    Operator,
    /// Also change configuration, certificates and users.
    Admin,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Auditor => "auditor",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> anyhow::Result<Self> {
        Ok(match s {
            "auditor" => Role::Auditor,
            "operator" => Role::Operator,
            "admin" => Role::Admin,
            other => bail!("unknown role '{other}' (use admin, operator or auditor)"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct User {
    pub username: String,
    pub role: Role,
    pub created_at: String,
    /// Set for passwords someone else chose (initial admin, reset by an
    /// admin): the user must choose a new one before doing anything else.
    pub must_change_password: bool,
}

/// What a web session needs to know about its user on every request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionState {
    pub role: Role,
    /// Bumped by every change of password or role: older sessions end.
    pub epoch: i64,
    pub must_change_password: bool,
}

pub struct UserStore {
    conn: Mutex<Connection>,
}

const MIN_PASSWORD_LENGTH: usize = 8;

fn hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))
}

fn validate(username: &str, password: &str) -> anyhow::Result<()> {
    if username.is_empty()
        || username.len() > 64
        || !username
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-@".contains(c))
    {
        bail!("user names use letters, digits and . _ - @ (max. 64)");
    }
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        bail!("passwords need at least {MIN_PASSWORD_LENGTH} characters");
    }
    Ok(())
}

impl UserStore {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening user database {}", path.display()))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                username      TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL,
                created_at    TEXT NOT NULL
            );",
        )?;
        // Tokens for the MCP endpoint: only a SHA-256 of the secret is
        // kept (the secret is 32 random bytes, so a slow hash adds nothing).
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS api_tokens (
                id         TEXT PRIMARY KEY,
                username   TEXT NOT NULL,
                name       TEXT NOT NULL,
                hash       TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used  TEXT
            );",
        )?;
        // What the token may change through MCP (comma separated scopes),
        // added later.
        let scopes: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('api_tokens') WHERE name = 'scopes'",
            [],
            |r| r.get(0),
        )?;
        if !scopes {
            conn.execute_batch(
                "ALTER TABLE api_tokens ADD COLUMN scopes TEXT NOT NULL DEFAULT ''",
            )?;
        }
        // Columns added later.
        for (column, definition) in [
            ("session_epoch", "INTEGER NOT NULL DEFAULT 0"),
            ("must_change_password", "INTEGER NOT NULL DEFAULT 0"),
        ] {
            let exists: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('users') WHERE name = ?1",
                [column],
                |r| r.get(0),
            )?;
            if !exists {
                conn.execute_batch(&format!(
                    "ALTER TABLE users ADD COLUMN {column} {definition}"
                ))?;
            }
        }
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn count(&self) -> anyhow::Result<u64> {
        let n: i64 = self
            .conn
            .lock()
            .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        Ok(n as u64)
    }

    pub fn create(&self, username: &str, password: &str, role: Role) -> anyhow::Result<()> {
        self.create_with(username, password, role, false)
    }

    /// `must_change_password`: the user has to replace the password at the
    /// first login (it was chosen by someone else).
    pub fn create_with(
        &self,
        username: &str,
        password: &str,
        role: Role,
        must_change_password: bool,
    ) -> anyhow::Result<()> {
        validate(username, password)?;
        let hash = hash(password)?;
        let inserted = self.conn.lock().execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, created_at, must_change_password)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                username,
                hash,
                role.as_str(),
                Utc::now().to_rfc3339(),
                must_change_password
            ],
        )?;
        if inserted == 0 {
            bail!("user '{username}' already exists");
        }
        Ok(())
    }

    /// Creates `admin` with the first password (from the environment, or a
    /// random one printed once), which has to be changed at the first login.
    pub fn create_initial_admin(&self, password: &str) -> anyhow::Result<()> {
        validate("admin", password)?;
        let inserted = self.conn.lock().execute(
            "INSERT OR IGNORE INTO users (username, password_hash, role, created_at, must_change_password)
             VALUES ('admin', ?1, ?2, ?3, 1)",
            params![
                hash(password)?,
                Role::Admin.as_str(),
                Utc::now().to_rfc3339()
            ],
        )?;
        if inserted == 0 {
            bail!("user 'admin' already exists");
        }
        Ok(())
    }

    /// Returns the user if the password is right. Always runs a hash
    /// verification, so response time does not reveal whether a user exists.
    pub fn verify(&self, username: &str, password: &str) -> anyhow::Result<Option<User>> {
        let row: Option<(String, String, String, bool)> = self
            .conn
            .lock()
            .query_row(
                "SELECT password_hash, role, created_at, must_change_password
                 FROM users WHERE username = ?1",
                [username],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()?;
        // Verifying against a dummy hash keeps the timing the same for
        // unknown users.
        static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let dummy = DUMMY.get_or_init(|| hash(&random_password()).unwrap_or_default());
        let stored = row.as_ref().map_or(dummy.as_str(), |r| r.0.as_str());
        let ok = PasswordHash::new(stored)
            .map(|h| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &h)
                    .is_ok()
            })
            .unwrap_or(false);
        match row {
            Some((_, role, created_at, must_change_password)) if ok => Ok(Some(User {
                username: username.to_string(),
                role: Role::parse(&role)?,
                created_at,
                must_change_password,
            })),
            _ => Ok(None),
        }
    }

    /// The user's current role and session epoch; `None` if the user is gone.
    pub fn session_state(&self, username: &str) -> anyhow::Result<Option<SessionState>> {
        let row: Option<(String, i64, bool)> = self
            .conn
            .lock()
            .query_row(
                "SELECT role, session_epoch, must_change_password FROM users WHERE username = ?1",
                [username],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(role, epoch, must_change_password)| {
            Ok(SessionState {
                role: Role::parse(&role)?,
                epoch,
                must_change_password,
            })
        })
        .transpose()
    }

    pub fn list(&self) -> anyhow::Result<Vec<User>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT username, role, created_at, must_change_password FROM users ORDER BY username",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
            ))
        })?;
        rows.map(|r| {
            let (username, role, created_at, must_change_password) = r?;
            Ok(User {
                username,
                role: Role::parse(&role)?,
                created_at,
                must_change_password,
            })
        })
        .collect()
    }

    /// Sets the user's own new password. Ends the user's sessions.
    pub fn set_password(&self, username: &str, password: &str) -> anyhow::Result<()> {
        self.update(username, None, Some(password), false)
            .map(|_| ())
    }

    /// Changes the role. Ends the user's sessions.
    pub fn set_role(&self, username: &str, role: Role) -> anyhow::Result<()> {
        self.update(username, Some(role), None, false).map(|_| ())
    }

    /// Changes role and/or password in one step: either all of it is
    /// applied or none. `must_change_password` marks a password chosen by
    /// someone else. Ends the user's sessions. Returns what changed.
    pub fn update(
        &self,
        username: &str,
        role: Option<Role>,
        password: Option<&str>,
        must_change_password: bool,
    ) -> anyhow::Result<Vec<String>> {
        if role.is_none() && password.is_none() {
            bail!("nothing to change");
        }
        // Everything that can fail is checked before anything is written.
        let hash = match password {
            Some(p) => {
                validate(username, p)?;
                Some(hash(p)?)
            }
            None => None,
        };
        let mut conn = self.conn.lock();
        let tx = conn.transaction()?;
        let exists: bool = tx.query_row(
            "SELECT COUNT(*) > 0 FROM users WHERE username = ?1",
            [username],
            |r| r.get(0),
        )?;
        if !exists {
            bail!("no user '{username}'");
        }
        let mut changes = Vec::new();
        if let Some(role) = role {
            Self::ensure_admin_remains(&tx, username, Some(role))?;
            tx.execute(
                "UPDATE users SET role = ?2 WHERE username = ?1",
                params![username, role.as_str()],
            )?;
            changes.push(format!("role {}", role.as_str()));
        }
        if let Some(hash) = hash {
            tx.execute(
                "UPDATE users SET password_hash = ?2, must_change_password = ?3 WHERE username = ?1",
                params![username, hash, must_change_password],
            )?;
            changes.push("password".into());
        }
        tx.execute(
            "UPDATE users SET session_epoch = session_epoch + 1 WHERE username = ?1",
            [username],
        )?;
        tx.commit()?;
        Ok(changes)
    }

    pub fn delete(&self, username: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        Self::ensure_admin_remains(&conn, username, None)?;
        let n = conn.execute("DELETE FROM users WHERE username = ?1", [username])?;
        if n == 0 {
            bail!("no user '{username}'");
        }
        conn.execute("DELETE FROM api_tokens WHERE username = ?1", [username])?;
        Ok(())
    }

    /// Creates an API token for a user. Returns it with its secret, which is
    /// shown once and not stored.
    pub fn create_token(
        &self,
        username: &str,
        name: &str,
        scopes: &[String],
    ) -> anyhow::Result<NewApiToken> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 64 {
            bail!("a token needs a name of 1 to 64 characters");
        }
        if let Some(bad) = scopes
            .iter()
            .find(|s| !crate::config::MCP_SCOPES.contains(&s.as_str()))
        {
            bail!("unknown scope '{bad}'");
        }
        let mut scopes = scopes.to_vec();
        scopes.sort();
        scopes.dedup();
        let id = random_hex(6);
        let secret = format!("gwt_{id}_{}", random_hex(32));
        let conn = self.conn.lock();
        let exists: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM users WHERE username = ?1",
            [username],
            |r| r.get(0),
        )?;
        if !exists {
            bail!("no user '{username}'");
        }
        let created_at = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO api_tokens (id, username, name, hash, created_at, scopes) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                id,
                username,
                name,
                token_hash(&secret),
                created_at,
                scopes.join(",")
            ],
        )?;
        Ok(NewApiToken {
            token: ApiToken {
                id,
                name: name.to_string(),
                scopes,
                created_at,
                last_used: None,
            },
            secret,
        })
    }

    pub fn tokens(&self, username: &str) -> anyhow::Result<Vec<ApiToken>> {
        let conn = self.conn.lock();
        let mut stmt = conn.prepare(
            "SELECT id, name, created_at, last_used, scopes FROM api_tokens \
             WHERE username = ?1 ORDER BY created_at",
        )?;
        let rows = stmt.query_map([username], |r| {
            Ok(ApiToken {
                id: r.get(0)?,
                name: r.get(1)?,
                created_at: r.get(2)?,
                last_used: r.get(3)?,
                scopes: split_scopes(&r.get::<_, String>(4)?),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Deletes one of a user's tokens; returns its name.
    pub fn delete_token(&self, username: &str, id: &str) -> anyhow::Result<String> {
        let conn = self.conn.lock();
        let name: Option<String> = conn
            .query_row(
                "SELECT name FROM api_tokens WHERE id = ?1 AND username = ?2",
                [id, username],
                |r| r.get(0),
            )
            .optional()?;
        let Some(name) = name else {
            bail!("no such token");
        };
        conn.execute("DELETE FROM api_tokens WHERE id = ?1", [id])?;
        Ok(name)
    }

    /// The user a token belongs to and its scopes, if it is valid; notes
    /// its use.
    pub fn verify_token(&self, secret: &str) -> anyhow::Result<Option<(String, Vec<String>)>> {
        // gwt_<12 hex id>_<64 hex secret>
        let Some(id) = secret
            .strip_prefix("gwt_")
            .and_then(|rest| rest.split_once('_'))
            .map(|(id, _)| id)
        else {
            return Ok(None);
        };
        let conn = self.conn.lock();
        let row: Option<(String, String, String)> = conn
            .query_row(
                "SELECT username, hash, scopes FROM api_tokens WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((username, hash, scopes)) = row else {
            return Ok(None);
        };
        if !constant_time_eq(hash.as_bytes(), token_hash(secret).as_bytes()) {
            return Ok(None);
        }
        conn.execute(
            "UPDATE api_tokens SET last_used = ?1 WHERE id = ?2",
            params![Utc::now().to_rfc3339(), id],
        )?;
        Ok(Some((username, split_scopes(&scopes))))
    }

    /// Refuses changes that would leave nobody able to administer the gateway.
    fn ensure_admin_remains(
        conn: &Connection,
        username: &str,
        new_role: Option<Role>,
    ) -> anyhow::Result<()> {
        if new_role == Some(Role::Admin) {
            return Ok(());
        }
        let other_admins: i64 = conn.query_row(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND username != ?1",
            [username],
            |r| r.get(0),
        )?;
        let is_admin: bool = conn
            .query_row(
                "SELECT role = 'admin' FROM users WHERE username = ?1",
                [username],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(false);
        if is_admin && other_admins == 0 {
            bail!("'{username}' is the last admin");
        }
        Ok(())
    }
}

/// An API token as listed (never with its secret).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiToken {
    pub id: String,
    pub name: String,
    /// What the token may change through MCP; empty: read only.
    pub scopes: Vec<String>,
    pub created_at: String,
    pub last_used: Option<String>,
}

/// A token just created, with the secret the user must copy now.
#[derive(Debug, Clone, Serialize)]
pub struct NewApiToken {
    #[serde(flatten)]
    pub token: ApiToken,
    pub secret: String,
}

fn random_hex(bytes: usize) -> String {
    use argon2::password_hash::rand_core::RngCore;
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// The stored scopes that still exist: a scope that was removed (`users`)
/// is ignored, the token keeps its other scopes.
fn split_scopes(s: &str) -> Vec<String> {
    s.split(',')
        .filter(|x| crate::config::MCP_SCOPES.contains(x))
        .map(String::from)
        .collect()
}

fn token_hash(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(secret.as_bytes()))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A random password (for the dummy hash that evens out login timing).
pub fn random_password() -> String {
    use argon2::password_hash::rand_core::RngCore;
    const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    bytes
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, UserStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = UserStore::open(&dir.path().join("gateway.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn create_and_verify() {
        let (_dir, users) = store();
        users.create("jens", "correct horse", Role::Admin).unwrap();
        assert!(users.create("jens", "another pass", Role::Auditor).is_err());
        assert_eq!(
            users.verify("jens", "correct horse").unwrap().unwrap().role,
            Role::Admin
        );
        assert!(users.verify("jens", "wrong").unwrap().is_none());
        assert!(users.verify("nobody", "correct horse").unwrap().is_none());
        assert!(users.create("x", "short", Role::Auditor).is_err());
        assert!(users
            .create("bad name", "long enough", Role::Auditor)
            .is_err());
    }

    #[test]
    fn last_admin_is_protected() {
        let (_dir, users) = store();
        users
            .create("admin", "admin-password", Role::Admin)
            .unwrap();
        users
            .create("op", "operator-password", Role::Operator)
            .unwrap();
        assert!(users.delete("admin").is_err());
        assert!(users.set_role("admin", Role::Auditor).is_err());
        users.set_role("op", Role::Admin).unwrap();
        users.delete("admin").unwrap();
        assert_eq!(users.list().unwrap().len(), 1);
    }

    #[test]
    fn password_change() {
        let (_dir, users) = store();
        users.create("a", "first-password", Role::Auditor).unwrap();
        users.set_password("a", "second-password").unwrap();
        assert!(users.verify("a", "first-password").unwrap().is_none());
        assert!(users.verify("a", "second-password").unwrap().is_some());
    }

    /// Audit finding W3: a failing part of an update applies nothing.
    #[test]
    fn updates_are_all_or_nothing() {
        let (_dir, users) = store();
        users.create("a", "first-password", Role::Auditor).unwrap();
        let epoch = users.session_state("a").unwrap().unwrap().epoch;
        assert!(users
            .update("a", Some(Role::Admin), Some("short"), false)
            .is_err());
        let state = users.session_state("a").unwrap().unwrap();
        assert_eq!(state.role, Role::Auditor);
        assert_eq!(state.epoch, epoch);

        users
            .update("a", Some(Role::Operator), Some("second-password"), true)
            .unwrap();
        let state = users.session_state("a").unwrap().unwrap();
        assert_eq!(state.role, Role::Operator);
        assert!(state.epoch > epoch, "sessions end");
        assert!(state.must_change_password);
        users.set_password("a", "third-password").unwrap();
        assert!(
            !users
                .session_state("a")
                .unwrap()
                .unwrap()
                .must_change_password
        );
    }

    #[test]
    fn initial_admin_must_change_password() {
        // Audit finding W6: no well-known password; a short one is refused.
        let (_dir, users) = store();
        assert!(users.create_initial_admin("admin").is_err());
        users.create_initial_admin("first-password").unwrap();
        let admin = users.verify("admin", "first-password").unwrap().unwrap();
        assert!(admin.must_change_password);
        assert!(users.verify("admin", "admin").unwrap().is_none());
        assert!(users.create_initial_admin("other-password").is_err());
    }

    #[test]
    fn removed_scope_is_ignored() {
        // Audit finding S1: tokens stored with the removed `users` scope keep
        // working with their other scopes.
        let (_dir, users) = store();
        users.create("a", "a-password", Role::Admin).unwrap();
        let token = users
            .create_token("a", "t", &["targets".to_string()])
            .unwrap();
        users
            .conn
            .lock()
            .execute("UPDATE api_tokens SET scopes = 'targets,users'", [])
            .unwrap();
        let (user, scopes) = users.verify_token(&token.secret).unwrap().unwrap();
        assert_eq!(user, "a");
        assert_eq!(scopes, vec!["targets".to_string()]);
        assert_eq!(
            users.tokens("a").unwrap()[0].scopes,
            vec!["targets".to_string()]
        );
    }

    #[test]
    fn random_passwords_differ() {
        assert_ne!(random_password(), random_password());
        assert_eq!(random_password().len(), 20);
    }
}
