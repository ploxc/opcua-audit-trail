//! Gateway configuration, loaded from a TOML file.
//!
//! Relative paths in the file are resolved against the directory that contains
//! the config file, so the gateway behaves the same whether it runs from a shell,
//! as a Windows service (whose working directory is `System32`) or in a container.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub gateway: GatewayConfig,
    #[serde(default)]
    pub web: WebConfig,
    #[serde(default)]
    pub audit: AuditConfig,
    #[serde(default)]
    pub export: ExportConfig,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub targets: Vec<TargetConfig>,
}

/// The MCP endpoint for AI assistants. Off unless an admin turns it on; it
/// only answers over HTTPS, or on a loopback-only web UI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct McpConfig {
    pub enabled: bool,
    /// No longer used: what a token may change is chosen per token. Still
    /// read, so a config that has it keeps loading; dropped when saved.
    #[serde(skip_serializing)]
    pub allow: Vec<String>,
}

/// Overrides `[web] tls` (true/false), e.g. in docker-compose.yml.
pub const WEB_TLS_ENV: &str = "OPCUA_GATEWAY_WEB_TLS";

/// What an API token can be allowed to change through MCP (chosen when the
/// token is created). The MCP settings themselves, API tokens and the web
/// server are never among them.
pub const MCP_SCOPES: [&str; 3] = ["targets", "certificates", "settings"];

/// Copies of the audit trail outside the gateway. Every record carries its
/// hash, so an external copy also anchors the local chain: rewriting the
/// local database no longer goes unnoticed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportConfig {
    pub questdb: Option<QuestDbConfig>,
    /// No longer supported (see docs/export/SYSLOG.md); ignored with a
    /// warning so an old config file still loads.
    #[serde(default, skip_serializing)]
    pub syslog: Option<serde::de::IgnoredAny>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuestDbConfig {
    /// QuestDB HTTP endpoint, e.g. `http://questdb:9000` or `https://…`.
    pub url: String,
    /// CA certificates (PEM) to verify an `https` endpoint with, e.g. the
    /// plant CA. Without it the usual public roots are used.
    pub ca_file: Option<PathBuf>,
    #[serde(default = "default_questdb_table")]
    pub table: String,
    /// Bearer token (QuestDB Enterprise), or use `username` + `password`.
    pub token: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default = "default_export_interval")]
    pub interval_secs: u64,
}

fn default_questdb_table() -> String {
    "opcua_audit".into()
}

fn default_export_interval() -> u64 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GatewayConfig {
    /// Application name presented to clients and to upstream servers.
    pub application_name: String,
    /// Application URI. Must match the URI in the application instance certificate.
    /// Defaults to `urn:<hostname>:opcua-audit-gateway`.
    pub application_uri: Option<String>,
    /// Directory holding the OPC UA certificate store (own, private, trusted, rejected).
    pub pki_dir: PathBuf,
    /// Directory for runtime data such as the audit database.
    pub data_dir: PathBuf,
    /// Extra host names or IP addresses to put in the certificate's subjectAltName.
    /// Needed in containers, where the host's name is not visible to the gateway.
    pub certificate_hostnames: Vec<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            application_name: "OPC UA Audit Gateway".into(),
            application_uri: None,
            pki_dir: "pki".into(),
            data_dir: "data".into(),
            certificate_hostnames: Vec::new(),
        }
    }
}

impl GatewayConfig {
    pub fn application_uri(&self) -> String {
        self.application_uri.clone().unwrap_or_else(|| {
            let host = opcua::crypto::X509Data::computer_hostnames()
                .into_iter()
                .next()
                .unwrap_or_else(|| "localhost".into());
            format!("urn:{host}:opcua-audit-gateway")
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WebConfig {
    /// Address of the web UI and REST API. Defaults to loopback only.
    pub listen: SocketAddr,
    /// Serve the UI over HTTPS. Uses the gateway's OPC UA certificate unless
    /// `tls_certificate` and `tls_private_key` point to PEM files.
    pub tls: bool,
    pub tls_certificate: Option<PathBuf>,
    pub tls_private_key: Option<PathBuf>,
    /// Further host names the UI answers to when it listens on a
    /// non-loopback address (e.g. a reverse proxy's name). Loopback names, IP
    /// addresses, this machine's names and `certificate_hostnames` are
    /// always accepted; any other name is refused (DNS rebinding).
    pub allowed_hosts: Vec<String>,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            listen: ([127, 0, 0, 1], 8080).into(),
            tls: false,
            tls_certificate: None,
            tls_private_key: None,
            allowed_hosts: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailMode {
    /// Keep forwarding writes when the audit store cannot keep up or fails.
    /// Lost events are counted and reported.
    Open,
    /// Reject a write towards the server unless its audit record was committed.
    Closed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AuditConfig {
    /// SQLite database file. Defaults to `<data_dir>/audit.db`.
    pub database: Option<PathBuf>,
    /// Delete audit records older than this many days. `0` keeps everything.
    pub retention_days: u32,
    pub fail_mode: FailMode,
    /// Read the current value right before forwarding a write, so the audit
    /// trail shows `old -> new`. Costs one extra round trip per write.
    pub record_old_value: bool,
    /// How often writes to ignored nodes (see `ignore` per target) are
    /// recorded as one `ignored_writes` summary per node.
    pub ignored_summary_secs: u64,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            database: None,
            retention_days: 365,
            fail_mode: FailMode::Open,
            record_old_value: true,
            ignored_summary_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    /// Short unique name, used in the UI and in audit records.
    pub name: String,
    /// Address where the gateway accepts OPC UA clients for this target.
    pub listen: SocketAddr,
    /// Endpoint URL of the upstream OPC UA server, e.g. `opc.tcp://192.168.0.10:4840`.
    pub endpoint_url: String,
    /// How often the upstream endpoints are re-discovered.
    #[serde(default = "default_discovery_interval")]
    pub discovery_interval_secs: u64,
    /// Endpoints below this security are neither offered to clients nor used
    /// upstream, whatever the server advertises. Discovery is not
    /// authenticated, so this is the defence against a stripped endpoint list.
    #[serde(default)]
    pub min_security: MinSecurity,
    /// Most client connections at once, and per client address. Every
    /// connection can open a channel on the PLC, which allows only a few.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_max_connections_per_address")]
    pub max_connections_per_address: usize,
    /// Nodes whose value writes are summarised instead of recorded one by
    /// one, e.g. a life bit an HMI writes every second.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ignore: Vec<IgnoreRule>,
}

/// Most ignore rules per target.
pub const MAX_IGNORE_RULES: usize = 1000;

/// A node whose value writes are not recorded one by one. They are counted
/// and recorded periodically as an `ignored_writes` summary (how many, from
/// which clients, the last value), so they never go unnoticed entirely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreRule {
    /// The node as shown in the audit trail, e.g. `ns=3;s="DB1"."Life"`.
    pub node_id: String,
    /// Only writes from this client (its IP address or application URI);
    /// the same node written by any other client is recorded as usual.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// The node's display name, for people reading the list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl IgnoreRule {
    /// Whether two rules are for the same node and client.
    pub fn same(&self, other: &IgnoreRule) -> bool {
        self.node_id == other.node_id && self.client == other.client
    }

    pub fn node(&self) -> anyhow::Result<opcua::types::NodeId> {
        self.node_id
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("'{}' is not a node id", self.node_id.escape_debug()))
    }
}

fn default_max_connections() -> usize {
    50
}

fn default_max_connections_per_address() -> usize {
    10
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MinSecurity {
    /// Follow the server, including SecurityPolicy None.
    #[default]
    None,
    Sign,
    SignAndEncrypt,
}

impl MinSecurity {
    pub fn as_str(self) -> &'static str {
        match self {
            MinSecurity::None => "none",
            MinSecurity::Sign => "sign",
            MinSecurity::SignAndEncrypt => "sign_and_encrypt",
        }
    }
}

fn default_discovery_interval() -> u64 {
    60
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file {}", path.display()))?;
        let mut config: Config =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        let base = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        config.resolve_paths(&base);
        config.apply_env(|name| std::env::var(name).ok())?;
        config.validate()?;
        Ok(config)
    }

    /// Settings the environment overrides, e.g. from docker-compose.yml.
    fn apply_env(&mut self, var: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
        if let Some(v) = var(WEB_TLS_ENV) {
            self.web.tls = match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" | "" => false,
                other => bail!("{WEB_TLS_ENV}: '{other}' is not true or false"),
            };
        }
        Ok(())
    }

    fn resolve_paths(&mut self, base: &Path) {
        let resolve = |p: &mut PathBuf| {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        };
        resolve(&mut self.gateway.pki_dir);
        resolve(&mut self.gateway.data_dir);
        for p in [&mut self.web.tls_certificate, &mut self.web.tls_private_key]
            .into_iter()
            .flatten()
        {
            resolve(p);
        }
        if let Some(db) = self.audit.database.as_mut() {
            resolve(db);
        }
        if let Some(q) = self.export.questdb.as_mut() {
            if let Some(p) = q.ca_file.as_mut() {
                resolve(p);
            }
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.audit.ignored_summary_secs == 0 {
            bail!("audit.ignored_summary_secs must be > 0");
        }
        if self.web.tls_certificate.is_some() != self.web.tls_private_key.is_some() {
            bail!("web: set both tls_certificate and tls_private_key, or neither");
        }
        if self.web.tls_certificate.is_some() && !self.web.tls {
            bail!("web: tls_certificate is set but tls = false");
        }
        if let Some(q) = &self.export.questdb {
            let Some(rest) = q
                .url
                .strip_prefix("http://")
                .or_else(|| q.url.strip_prefix("https://"))
            else {
                bail!("export.questdb.url must start with http:// or https://");
            };
            if rest.split('/').next().unwrap_or_default().contains('@') {
                bail!("export.questdb.url must not contain credentials; use token or username/password");
            }
            if q.token.is_some() && (q.username.is_some() || q.password.is_some()) {
                bail!("export.questdb: use either token or username/password");
            }
            if q.interval_secs == 0 {
                bail!("export.questdb.interval_secs must be > 0");
            }
        }
        if self.export.syslog.is_some() {
            tracing::warn!("[export.syslog] is no longer supported and is ignored");
        }
        let mut names = std::collections::HashSet::new();
        let mut listens = std::collections::HashSet::new();
        for t in &self.targets {
            // The name ends up in logs, audit records and URLs.
            if t.name.is_empty()
                || t.name.len() > 64
                || !t
                    .name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
            {
                bail!(
                    "target name '{}' must be 1-64 letters, digits, '.', '_' or '-'",
                    t.name.escape_debug()
                );
            }
            if !names.insert(&t.name) {
                bail!("duplicate target name '{}'", t.name);
            }
            if !listens.insert(t.listen) {
                bail!("targets '{}' share listen address {}", t.name, t.listen);
            }
            if t.listen == self.web.listen {
                bail!("target '{}' uses the web UI address {}", t.name, t.listen);
            }
            if !t.endpoint_url.starts_with("opc.tcp://") {
                bail!(
                    "target '{}': endpoint_url must start with opc.tcp:// (got '{}')",
                    t.name,
                    t.endpoint_url
                );
            }
            if t.discovery_interval_secs == 0 {
                bail!("target '{}': discovery_interval_secs must be > 0", t.name);
            }
            if t.max_connections == 0 || t.max_connections_per_address == 0 {
                bail!("target '{}': connection limits must be > 0", t.name);
            }
            if t.ignore.len() > MAX_IGNORE_RULES {
                bail!(
                    "target '{}': at most {MAX_IGNORE_RULES} ignored nodes",
                    t.name
                );
            }
            let mut rules = HashSet::new();
            for rule in &t.ignore {
                let node = rule
                    .node()
                    .with_context(|| format!("target '{}': ignore", t.name))?;
                if rule
                    .client
                    .as_ref()
                    .is_some_and(|c| c.trim().is_empty() || c.len() > 256)
                {
                    bail!(
                        "target '{}': ignore client must be an address or application URI",
                        t.name
                    );
                }
                if !rules.insert((node, rule.client.clone())) {
                    bail!("target '{}': {} is ignored twice", t.name, rule.node_id);
                }
            }
        }
        Ok(())
    }

    pub fn audit_database(&self) -> PathBuf {
        self.audit
            .database
            .clone()
            .unwrap_or_else(|| self.gateway.data_dir.join("audit.db"))
    }
}

/// Commented starting point written by `opcua-audit-gateway init`.
pub const EXAMPLE_CONFIG: &str = r#"# OPC UA Audit Gateway configuration.
# Relative paths are resolved against the directory of this file.

[gateway]
application_name = "OPC UA Audit Gateway"
# application_uri = "urn:my-host:opcua-audit-gateway"
pki_dir = "pki"
data_dir = "data"
# Host names / IPs clients use to reach the gateway (added to the certificate).
# certificate_hostnames = ["gateway.local", "192.168.0.20"]

[web]
# Loopback only by default. For remote access enable HTTPS, e.g.
#   listen = "0.0.0.0:8443"
#   tls = true                        # uses the gateway certificate, or:
#   tls_certificate = "web-cert.pem"  # PEM chain
#   tls_private_key = "web-key.pem"   # PEM (PKCS#8, PKCS#1 or SEC1)
# Off loopback the UI only answers to IP addresses, this machine's names and
# certificate_hostnames; add other names (e.g. a reverse proxy's) here:
#   allowed_hosts = ["audit.example.com"]
listen = "127.0.0.1:8080"

[audit]
retention_days = 365
# "open": writes keep flowing if the audit store fails (events are counted as lost).
# "closed": a write is rejected unless its audit record was committed.
fail_mode = "open"
record_old_value = true
# Writes to ignored nodes (see [[targets.ignore]]) are recorded as one
# summary per node this often.
ignored_summary_secs = 3600

# Optional copies of the audit trail outside the gateway. Records carry their
# hash, so an external copy also proves the local trail was not rewritten.
# [export.questdb]
# url = "http://questdb:9000"   # or https://…
# table = "opcua_audit"
# ca_file = "questdb-ca.pem"    # for https with a private CA

# One block per upstream OPC UA server.
# [[targets]]
# name = "plc1"
# listen = "0.0.0.0:4841"
# endpoint_url = "opc.tcp://192.168.0.10:4840"
# discovery_interval_secs = 60
# min_security = "sign_and_encrypt"   # "none" (default), "sign", "sign_and_encrypt"
# max_connections = 50                # clients at once
# max_connections_per_address = 10
#
# A node written so often it floods the trail (a life bit): its value writes
# are summarised every ignored_summary_secs instead of recorded one by one.
# [[targets.ignore]]
# node_id = 'ns=3;s="DB1"."Life"'
# client = "10.0.0.5"               # optional: only from this address or application URI
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_overrides_tls() {
        let env =
            |value: &'static str| move |name: &str| (name == WEB_TLS_ENV).then(|| value.into());
        let mut c = Config::default();
        c.apply_env(env("true")).unwrap();
        assert!(c.web.tls);
        c.apply_env(env("0")).unwrap();
        assert!(!c.web.tls);
        assert!(c.apply_env(env("maybe")).is_err());
        c.web.tls = true;
        c.apply_env(|_| None).unwrap();
        assert!(c.web.tls, "unset keeps the file's value");
    }

    fn parse(text: &str) -> anyhow::Result<Config> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn example_config_parses() {
        let config = parse(EXAMPLE_CONFIG).unwrap();
        assert!(config.targets.is_empty());
        assert_eq!(config.audit.fail_mode, FailMode::Open);
    }

    #[test]
    fn rejects_duplicate_listen_address() {
        let err = parse(
            r#"
            [[targets]]
            name = "a"
            listen = "0.0.0.0:4841"
            endpoint_url = "opc.tcp://10.0.0.1:4840"
            [[targets]]
            name = "b"
            listen = "0.0.0.0:4841"
            endpoint_url = "opc.tcp://10.0.0.2:4840"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("share listen address"));
    }

    #[test]
    fn rejects_non_opc_tcp_url() {
        let err = parse(
            r#"
            [[targets]]
            name = "a"
            listen = "0.0.0.0:4841"
            endpoint_url = "http://10.0.0.1:4840"
            "#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("opc.tcp://"));
    }

    #[test]
    fn relative_paths_follow_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, EXAMPLE_CONFIG).unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.gateway.pki_dir, dir.path().join("pki"));
        assert_eq!(config.audit_database(), dir.path().join("data/audit.db"));
    }
}
