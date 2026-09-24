//! Runs the configured targets and applies changes from the web UI without a
//! restart: each change is validated, written to the config file (keeping the
//! file's comments and other sections) and the affected target is restarted.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use opcua::client::Client;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::audit::AuditHandle;
use crate::config::{Config, TargetConfig};
use crate::discovery::{self, TargetStatus, TargetStatuses};
use crate::relay::{self, GatewayIdentity, RelayTarget};

struct Running {
    relay: Arc<RelayTarget>,
    monitor: CancellationToken,
    server: tokio::task::JoinHandle<()>,
}

impl Running {
    /// Stops the target and waits until its port is released.
    async fn stop(self) {
        self.relay.shutdown.cancel();
        self.monitor.cancel();
        let _ = self.server.await;
    }
}

pub struct TargetManager {
    config_path: PathBuf,
    /// The configuration as currently applied.
    config: Mutex<Config>,
    running: Mutex<BTreeMap<String, Running>>,
    statuses: TargetStatuses,
    discovery: Arc<Client>,
    audit: AuditHandle,
}

impl TargetManager {
    pub fn new(
        config_path: PathBuf,
        config: Config,
        statuses: TargetStatuses,
        discovery: Arc<Client>,
        audit: AuditHandle,
    ) -> Self {
        Self {
            config_path,
            config: Mutex::new(config),
            running: Mutex::new(BTreeMap::new()),
            statuses,
            discovery,
            audit,
        }
    }

    /// Starts every configured target. A target whose port cannot be bound
    /// is logged and skipped, so one bad target does not stop the others.
    pub async fn start_all(&self) {
        let config = self.config.lock().await.clone();
        let mut running = self.running.lock().await;
        for target in &config.targets {
            match self.start(&config, target).await {
                Ok(r) => {
                    running.insert(target.name.clone(), r);
                }
                Err(e) => tracing::error!(target = %target.name, "{e:#}"),
            }
        }
    }

    async fn start(&self, config: &Config, target: &TargetConfig) -> anyhow::Result<Running> {
        let relay = Arc::new(RelayTarget::new(
            target.clone(),
            Arc::new(GatewayIdentity::load(config, target)?),
            self.statuses.clone(),
            self.discovery.clone(),
            self.audit.clone(),
            &config.audit,
        ));
        let listener = relay::bind(&relay)
            .await
            .with_context(|| format!("cannot listen on {}", target.listen))?;
        self.statuses
            .write()
            .await
            .insert(target.name.clone(), TargetStatus::new(target));
        let monitor = CancellationToken::new();
        tokio::spawn(discovery::monitor_target(
            self.discovery.clone(),
            target.clone(),
            self.statuses.clone(),
            self.audit.clone(),
            monitor.clone(),
        ));
        let server = tokio::spawn(relay::serve(relay.clone(), listener));
        Ok(Running {
            relay,
            monitor,
            server,
        })
    }

    pub async fn targets(&self) -> Vec<TargetConfig> {
        self.config.lock().await.targets.clone()
    }

    pub async fn relay(&self, name: &str) -> Option<Arc<RelayTarget>> {
        self.running.lock().await.get(name).map(|r| r.relay.clone())
    }

    /// Adds a target, or replaces the one called `replaces`.
    pub async fn upsert(&self, target: TargetConfig, replaces: Option<&str>) -> anyhow::Result<()> {
        let mut config = self.config.lock().await;
        let mut new_config = config.clone();
        match replaces {
            Some(old) => {
                let Some(slot) = new_config.targets.iter_mut().find(|t| t.name == old) else {
                    bail!("unknown target '{old}'");
                };
                *slot = target.clone();
            }
            None => new_config.targets.push(target.clone()),
        }
        new_config.validate()?;

        let mut running = self.running.lock().await;
        // Stop the old instance first: it may hold the same port.
        let old = match replaces.and_then(|name| running.remove(name)) {
            Some(old) => {
                let old_target = old.relay.config.clone();
                old.stop().await;
                self.statuses.write().await.remove(&old_target.name);
                Some(old_target)
            }
            None => None,
        };
        match self.start(&new_config, &target).await {
            Ok(r) => {
                running.insert(target.name.clone(), r);
            }
            Err(e) => {
                // Put the old target back as it was.
                if let Some(old_target) = old {
                    if let Ok(r) = self.start(&config, &old_target).await {
                        running.insert(old_target.name.clone(), r);
                    }
                }
                return Err(e);
            }
        }
        write_targets(&self.config_path, &new_config.targets)?;
        *config = new_config;
        Ok(())
    }

    pub async fn remove(&self, name: &str) -> anyhow::Result<()> {
        let mut config = self.config.lock().await;
        if !config.targets.iter().any(|t| t.name == name) {
            bail!("unknown target '{name}'");
        }
        let mut new_config = config.clone();
        new_config.targets.retain(|t| t.name != name);
        write_targets(&self.config_path, &new_config.targets)?;
        let stopped = self.running.lock().await.remove(name);
        if let Some(r) = stopped {
            r.stop().await;
        }
        self.statuses.write().await.remove(name);
        *config = new_config;
        Ok(())
    }

    /// Makes every connection re-check its certificates (after trust in one
    /// was revoked), closing those that are no longer trusted.
    pub async fn recheck_trust(&self) {
        for running in self.running.lock().await.values() {
            running.relay.recheck_trust();
        }
    }

    /// Restarts every target, e.g. after the gateway certificate changed.
    pub async fn restart_all(&self) {
        self.stop_all().await;
        self.start_all().await;
    }

    /// Stops all targets (gateway shutdown).
    pub async fn stop_all(&self) {
        let running = std::mem::take(&mut *self.running.lock().await);
        for r in running.into_values() {
            r.stop().await;
        }
    }
}

/// Replaces the `[[targets]]` tables in the config file, keeping everything
/// else (other sections, comments, formatting) as it was.
fn write_targets(path: &std::path::Path, targets: &[TargetConfig]) -> anyhow::Result<()> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .with_context(|| format!("parsing {}", path.display()))?;
    let mut array = toml_edit::ArrayOfTables::new();
    for t in targets {
        let mut table = toml_edit::Table::new();
        table["name"] = toml_edit::value(t.name.as_str());
        table["listen"] = toml_edit::value(t.listen.to_string());
        table["endpoint_url"] = toml_edit::value(t.endpoint_url.as_str());
        table["discovery_interval_secs"] = toml_edit::value(t.discovery_interval_secs as i64);
        if t.min_security != crate::config::MinSecurity::None {
            table["min_security"] = toml_edit::value(t.min_security.as_str());
        }
        array.push(table);
    }
    if targets.is_empty() {
        doc.remove("targets");
    } else {
        doc["targets"] = toml_edit::Item::ArrayOfTables(array);
    }
    // Write atomically, so a crash never leaves a half-written config.
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, doc.to_string()).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EXAMPLE_CONFIG;

    fn target(name: &str, port: u16) -> TargetConfig {
        TargetConfig {
            name: name.into(),
            listen: ([127, 0, 0, 1], port).into(),
            endpoint_url: "opc.tcp://127.0.0.1:1/".into(),
            discovery_interval_secs: 60,
            min_security: Default::default(),
        }
    }

    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    async fn manager(dir: &std::path::Path) -> TargetManager {
        let path = dir.join("config.toml");
        std::fs::write(&path, EXAMPLE_CONFIG).unwrap();
        let config = Config::load(&path).unwrap();
        crate::pki::Pki::open(&config.gateway.pki_dir)
            .unwrap()
            .ensure_own_certificate(&config.gateway)
            .unwrap();
        let audit = crate::audit::start(&dir.join("audit.db"), &config.audit).unwrap();
        let statuses = discovery::initial_statuses(&config);
        let client = Arc::new(discovery::discovery_client(&config).unwrap());
        TargetManager::new(path, config, statuses, client, audit)
    }

    #[tokio::test]
    async fn add_update_remove_are_persisted_and_applied() {
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path()).await;
        let path = dir.path().join("config.toml");

        let port = free_port();
        m.upsert(target("plc1", port), None).await.unwrap();
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok());
        let saved = Config::load(&path).unwrap();
        assert_eq!(saved.targets.len(), 1);
        // The rest of the file, comments included, is untouched.
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("# OPC UA Audit Gateway configuration."));

        // Duplicate names are rejected and change nothing.
        assert!(m.upsert(target("plc1", free_port()), None).await.is_err());

        // Reconfiguring on the same port works (the old listener is gone
        // before the new one binds), and moving to another port frees it.
        m.upsert(target("plc1", port), Some("plc1")).await.unwrap();
        let port2 = free_port();
        m.upsert(target("plc1", port2), Some("plc1")).await.unwrap();
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port2))
            .await
            .is_ok());
        assert!(tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err());

        m.remove("plc1").await.unwrap();
        assert!(Config::load(&path).unwrap().targets.is_empty());
        assert!(m.relay("plc1").await.is_none());
    }

    #[tokio::test]
    async fn port_in_use_is_reported_and_nothing_is_saved() {
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path()).await;
        let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = blocker.local_addr().unwrap().port();
        let err = m.upsert(target("plc1", port), None).await.unwrap_err();
        assert!(format!("{err:#}").contains("cannot listen"));
        assert!(Config::load(&dir.path().join("config.toml"))
            .unwrap()
            .targets
            .is_empty());
    }
}
