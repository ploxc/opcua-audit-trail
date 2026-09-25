//! Gateway configuration, loaded from a TOML file.
//!
//! Relative paths in the file are resolved against the directory that contains
//! the config file, so the gateway behaves the same whether it runs from a shell,
//! as a Windows service (whose working directory is `System32`) or in a container.

use std::collections::{BTreeMap, HashSet};
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
pub const MCP_SCOPES: [&str; 4] = ["targets", "certificates", "settings", "alarms"];

/// The role a token's user needs for a scope: the same as in the web UI
/// (operators acknowledge alarms; the rest is configuration, for admins).
pub fn mcp_scope_role(scope: &str) -> crate::users::Role {
    match scope {
        "alarms" => crate::users::Role::Operator,
        _ => crate::users::Role::Admin,
    }
}

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
    /// Reverse proxies in front of the UI: from these addresses the client's
    /// address is taken from `X-Forwarded-For` (login limits and records).
    pub trusted_proxies: Vec<std::net::IpAddr>,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            listen: ([127, 0, 0, 1], 8080).into(),
            tls: false,
            tls_certificate: None,
            tls_private_key: None,
            allowed_hosts: Vec::new(),
            trusted_proxies: Vec::new(),
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
    /// How often writes to summarised nodes (see `summarise` per target) are
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
    /// Groups of nodes whose value writes are summarised instead of
    /// recorded one by one, e.g. the life bits an HMI writes every second.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub summarise: Vec<SummariseGroup>,
    /// The old form of `summarise`, one rule per node. Still read; turned
    /// into groups when the file is loaded, and written as groups.
    #[serde(default, skip_serializing)]
    pub ignore: Vec<IgnoreRule>,
}

/// Most summarised nodes per target, over all its groups.
pub const MAX_SUMMARISED_NODES: usize = 1000;
/// Most summarise groups per target.
pub const MAX_SUMMARISE_GROUPS: usize = 100;

/// Nodes whose value writes are not recorded one by one. They are counted
/// and recorded periodically as an `ignored_writes` summary per node (how
/// many, from which clients, the last value), so they never go unnoticed
/// entirely.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummariseGroup {
    /// For people reading the list, e.g. "HMI line 1".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Only writes from this client (its IP address or application URI);
    /// the same nodes written by any other client are recorded as usual.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client: Option<String>,
    /// The nodes as shown in the audit trail, e.g. `ns=3;s="DB1"."Life"`.
    #[serde(default)]
    pub nodes: Vec<String>,
    /// Display names of the nodes, where known, for people reading the list.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub names: BTreeMap<String, String>,
}

impl SummariseGroup {
    /// "'HMI line 1' (from 10.0.0.5)", for audit records and messages.
    pub fn label(&self) -> String {
        let name = match &self.name {
            Some(n) => format!("'{n}'"),
            None => "an unnamed group".into(),
        };
        match &self.client {
            Some(c) => format!("{name} (from {c})"),
            None => format!("{name} (from every client)"),
        }
    }
}

/// Parses a node id as shown in the audit trail.
pub fn parse_node(node_id: &str) -> anyhow::Result<opcua::types::NodeId> {
    node_id
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("'{}' is not a node id", node_id.escape_debug()))
}

/// The old per-node form of a summarised node (`[[targets.ignore]]`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoreRule {
    pub node_id: String,
    #[serde(default)]
    pub client: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
}

/// Summarise groups: valid node ids and clients, no node twice in a group,
/// and at most MAX_SUMMARISED_NODES nodes in all.
fn validate_summarise(t: &TargetConfig) -> anyhow::Result<()> {
    let name = &t.name;
    if t.summarise.len() > MAX_SUMMARISE_GROUPS {
        bail!("target '{name}': at most {MAX_SUMMARISE_GROUPS} summarise groups");
    }
    let total: usize = t.summarise.iter().map(|g| g.nodes.len()).sum();
    if total > MAX_SUMMARISED_NODES {
        bail!("target '{name}': at most {MAX_SUMMARISED_NODES} summarised nodes (got {total})");
    }
    for g in &t.summarise {
        if g.name
            .as_ref()
            .is_some_and(|n| n.trim().is_empty() || n.chars().count() > 100)
        {
            bail!("target '{name}': a summarise group name must be 1 to 100 characters");
        }
        if g.client
            .as_ref()
            .is_some_and(|c| c.trim().is_empty() || c.len() > 256)
        {
            bail!("target '{name}': summarise client must be an address or application URI");
        }
        let mut nodes = HashSet::new();
        for node_id in &g.nodes {
            let node =
                parse_node(node_id).with_context(|| format!("target '{name}': summarise"))?;
            if !nodes.insert(node) {
                bail!(
                    "target '{name}': {node_id} is twice in summarise group {}",
                    g.label()
                );
            }
        }
        if let Some(extra) = g.names.keys().find(|k| !g.nodes.contains(k)) {
            bail!("target '{name}': summarise names {extra}, which is not in the group");
        }
    }
    Ok(())
}

impl TargetConfig {
    /// Moves old `ignore` rules into `summarise` groups: one per client, and
    /// one for the rules without a client.
    pub fn migrate_ignore(&mut self) {
        for rule in std::mem::take(&mut self.ignore) {
            let client = rule
                .client
                .map(|c| c.trim().to_string())
                .filter(|c| !c.is_empty());
            let group = match self.summarise.iter().position(|g| g.client == client) {
                Some(i) => &mut self.summarise[i],
                None => {
                    self.summarise.push(SummariseGroup {
                        client,
                        ..Default::default()
                    });
                    self.summarise.last_mut().expect("just pushed")
                }
            };
            let node_id = rule.node_id.trim().to_string();
            if !group.nodes.contains(&node_id) {
                group.nodes.push(node_id.clone());
            }
            if let Some(name) = rule.name.filter(|n| !n.trim().is_empty()) {
                group.names.insert(node_id, name);
            }
        }
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
        for t in &mut config.targets {
            t.migrate_ignore();
        }
        config.apply_env(|name| std::env::var(name).ok())?;
        config.validate()?;
        Ok(config)
    }

    /// Settings the environment overrides, e.g. from docker-compose.yml.
    fn apply_env(&mut self, var: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
        // Empty counts as not set: an unset ${VAR} in a compose file must
        // not silently turn HTTPS off.
        let value = var(WEB_TLS_ENV).filter(|v| !v.trim().is_empty());
        if let Some(v) = value {
            self.web.tls = match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
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
            validate_summarise(t)?;
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
# Behind a reverse proxy, its address, so logins are limited per client
# (from X-Forwarded-For) instead of for everyone at once:
#   trusted_proxies = ["127.0.0.1"]
listen = "127.0.0.1:8080"

[audit]
retention_days = 365
# "closed": a write is rejected unless its audit record was committed.
# "open": writes keep flowing if the audit store fails or cannot keep up
# (those records are lost; only their number is recorded).
fail_mode = "closed"
record_old_value = true
# Writes to summarised nodes (see [[targets.summarise]]) are recorded as one
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
# [[targets.summarise]]
# name = "HMI line 1"               # optional, for people reading the list
# client = "10.0.0.5"               # optional: only from this address or application URI
# nodes = ['ns=3;s="DB1"."Life"', 'ns=3;s="DB1"."Clock"']
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
        // Audit finding S12: empty is not "false".
        c.apply_env(env("")).unwrap();
        assert!(c.web.tls, "empty keeps the file's value");
        c.apply_env(env("  ")).unwrap();
        assert!(c.web.tls);
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
        // Audit finding N8: new configs lose no write records; a config
        // without the key (an existing one) stays fail-open.
        assert_eq!(config.audit.fail_mode, FailMode::Closed);
        assert_eq!(
            parse("[audit]\nretention_days = 30\n")
                .unwrap()
                .audit
                .fail_mode,
            FailMode::Open
        );
        let docker = include_str!("../docker/config.toml").replace("\r\n", "\n");
        assert_eq!(parse(&docker).unwrap().audit.fail_mode, FailMode::Closed);
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

    const TARGET: &str = r#"
        [[targets]]
        name = "plc1"
        listen = "127.0.0.1:4841"
        endpoint_url = "opc.tcp://127.0.0.1:4840"
    "#;

    #[test]
    fn ignore_rules_become_groups_per_client() {
        let mut config: Config = toml::from_str(&format!(
            r#"{TARGET}
            [[targets.ignore]]
            node_id = "ns=3;i=1"
            name = "Life"
            [[targets.ignore]]
            node_id = "ns=3;i=2"
            client = "10.0.0.5"
            [[targets.ignore]]
            node_id = "ns=3;i=3"
            [[targets.ignore]]
            node_id = "ns=3;i=1"
            client = " 10.0.0.5 "
            "#
        ))
        .unwrap();
        let t = &mut config.targets[0];
        t.migrate_ignore();
        assert!(t.ignore.is_empty());
        assert_eq!(
            t.summarise,
            vec![
                SummariseGroup {
                    nodes: vec!["ns=3;i=1".into(), "ns=3;i=3".into()],
                    names: [("ns=3;i=1".to_string(), "Life".to_string())].into(),
                    ..Default::default()
                },
                SummariseGroup {
                    client: Some("10.0.0.5".into()),
                    nodes: vec!["ns=3;i=2".into(), "ns=3;i=1".into()],
                    ..Default::default()
                },
            ]
        );
        config.validate().unwrap();
    }

    #[test]
    fn summarise_groups_are_validated() {
        let group = |body: &str| parse(&format!("{TARGET}\n[[targets.summarise]]\n{body}"));
        group(
            r#"name = "HMI"
                 client = "10.0.0.5"
                 nodes = ["ns=3;i=1", "ns=3;i=2"]"#,
        )
        .unwrap();
        assert!(group(r#"nodes = ["ns=3;i=1", "ns=3;i=1"]"#).is_err());
        assert!(group(r#"nodes = ["nonsense"]"#).is_err());
        assert!(group(
            r#"client = " "
                        nodes = []"#
        )
        .is_err());
        assert!(group(
            r#"nodes = ["ns=3;i=1"]
                         names = { "ns=3;i=2" = "x" }"#
        )
        .is_err());
        // The same node for one client and for everyone is fine.
        parse(&format!(
            "{TARGET}
            [[targets.summarise]]
            client = \"10.0.0.5\"
            nodes = [\"ns=3;i=1\"]
            [[targets.summarise]]
            nodes = [\"ns=3;i=1\"]"
        ))
        .unwrap();
        // The limit counts nodes, not groups.
        let nodes: Vec<String> = (0..=MAX_SUMMARISED_NODES)
            .map(|i| format!("\"ns=3;i={i}\""))
            .collect();
        let err = group(&format!("nodes = [{}]", nodes.join(","))).unwrap_err();
        assert!(err.to_string().contains("summarised nodes"), "{err}");
    }
}
