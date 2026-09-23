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
    pub targets: Vec<TargetConfig>,
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
    /// Address of the web UI and REST API. Defaults to loopback only until the UI
    /// has authentication.
    pub listen: SocketAddr,
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            listen: ([127, 0, 0, 1], 8080).into(),
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
        if let Some(db) = self.audit.database.as_mut() {
            resolve(db);
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let mut names = std::collections::HashSet::new();
        let mut listens = std::collections::HashSet::new();
        for t in &self.targets {
            if t.name.trim().is_empty() {
                bail!("target name must not be empty");
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
        }
        Ok(())
    }

    pub fn audit_database(&self) -> PathBuf {
        self.audit
            .database
            .clone()
            .unwrap_or_else(|| self.gateway.data_dir.join("audit.db"))
    }

    pub fn target(&self, name: &str) -> Option<&TargetConfig> {
        self.targets.iter().find(|t| t.name == name)
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
# Loopback only until the web UI has authentication.
listen = "127.0.0.1:8080"

[audit]
retention_days = 365
# "open": writes keep flowing if the audit store fails (events are counted as lost).
# "closed": a write is rejected unless its audit record was committed.
fail_mode = "open"
record_old_value = true

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
