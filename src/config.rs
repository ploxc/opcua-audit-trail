//! Gateway configuration, loaded from a TOML file.
//!
//! Relative paths in the file are resolved against the directory that contains
//! the config file, so the gateway behaves the same whether it runs from a shell,
//! as a Windows service (whose working directory is `System32`) or in a container.

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
    pub targets: Vec<TargetConfig>,
}

/// Copies of the audit trail outside the gateway. Every record carries its
/// hash, so an external copy also anchors the local chain: rewriting the
/// local database no longer goes unnoticed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportConfig {
    pub questdb: Option<QuestDbConfig>,
    pub syslog: Option<SyslogConfig>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyslogProtocol {
    Udp,
    Tcp,
    /// Syslog over TLS (RFC 5425).
    Tls,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyslogConfig {
    /// `host:port` of the syslog receiver (SIEM, Graylog, rsyslog, …).
    pub address: String,
    #[serde(default = "default_syslog_protocol")]
    pub protocol: SyslogProtocol,
    /// Syslog facility number; 16 = local0.
    #[serde(default = "default_syslog_facility")]
    pub facility: u8,
    #[serde(default = "default_export_interval")]
    pub interval_secs: u64,
    /// CA certificates (PEM) for `protocol = "tls"`; default: public roots.
    pub ca_file: Option<PathBuf>,
}

fn default_syslog_protocol() -> SyslogProtocol {
    SyslogProtocol::Udp
}

fn default_syslog_facility() -> u8 {
    16
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
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            listen: ([127, 0, 0, 1], 8080).into(),
            tls: false,
            tls_certificate: None,
            tls_private_key: None,
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
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            database: None,
            retention_days: 365,
            fail_mode: FailMode::Open,
            record_old_value: true,
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
        config.validate()?;
        Ok(config)
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
        if let Some(s) = self.export.syslog.as_mut() {
            if let Some(p) = s.ca_file.as_mut() {
                resolve(p);
            }
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
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
        if let Some(s) = &self.export.syslog {
            if s.facility > 23 {
                bail!("export.syslog.facility must be 0..=23");
            }
            if s.interval_secs == 0 {
                bail!("export.syslog.interval_secs must be > 0");
            }
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
listen = "127.0.0.1:8080"

[audit]
retention_days = 365
# "open": writes keep flowing if the audit store fails (events are counted as lost).
# "closed": a write is rejected unless its audit record was committed.
fail_mode = "open"
record_old_value = true

# Optional copies of the audit trail outside the gateway. Records carry their
# hash, so an external copy also proves the local trail was not rewritten.
# [export.questdb]
# url = "http://questdb:9000"
# table = "opcua_audit"
#
# [export.syslog]
# address = "siem.local:514"
# protocol = "tcp"          # or "udp"

# One block per upstream OPC UA server.
# [[targets]]
# name = "plc1"
# listen = "0.0.0.0:4841"
# endpoint_url = "opc.tcp://192.168.0.10:4840"
# discovery_interval_secs = 60
"#;

#[cfg(test)]
mod tests {
    use super::*;

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
