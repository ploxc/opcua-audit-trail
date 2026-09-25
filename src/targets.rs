//! Runs the configured targets and applies changes from the web UI without a
//! restart: each change is validated, written to the config file (keeping the
//! file's comments and other sections) and the affected target is restarted.
//! It also owns the other settings the web UI changes, so the file has one
//! writer.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use opcua::client::Client;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::audit::AuditHandle;
use crate::config::{Config, SummariseGroup, TargetConfig};
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

    pub fn config_path(&self) -> &std::path::Path {
        &self.config_path
    }

    /// The configuration as currently applied.
    pub async fn config(&self) -> Config {
        self.config.lock().await.clone()
    }

    /// Changes settings outside the targets (audit, export, gateway host
    /// names): validates the result, writes it to the config file and
    /// returns the configuration before and after. Applying it to the
    /// running parts is up to the caller.
    pub async fn update_settings(
        &self,
        change: impl FnOnce(&mut Config),
    ) -> anyhow::Result<(Config, Config)> {
        let mut config = self.config.lock().await;
        let mut new_config = config.clone();
        change(&mut new_config);
        new_config.validate()?;
        write_settings(&self.config_path, &new_config)?;
        let old = std::mem::replace(&mut *config, new_config.clone());
        Ok((old, new_config))
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
        let started = self.start(&new_config, &target).await;
        // Only a change that is running and saved counts; otherwise the old
        // target is put back as it was.
        let result = match started {
            Ok(r) => match write_targets(&self.config_path, &new_config.targets) {
                Ok(()) => {
                    running.insert(target.name.clone(), r);
                    *config = new_config;
                    return Ok(());
                }
                Err(e) => {
                    r.stop().await;
                    self.statuses.write().await.remove(&target.name);
                    Err(e)
                }
            },
            Err(e) => Err(e),
        };
        if let Some(old_target) = old {
            if let Ok(r) = self.start(&config, &old_target).await {
                running.insert(old_target.name.clone(), r);
            }
        }
        result
    }

    /// Changes a target's summarise groups with `change`, under the lock,
    /// so concurrent changes do not undo each other. Applied to the running
    /// target directly: connected clients stay connected. Nothing changes if
    /// `change` fails or the result is not valid.
    pub async fn update_summarise<T, E: From<anyhow::Error>>(
        &self,
        name: &str,
        change: impl FnOnce(&mut Vec<SummariseGroup>) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut config = self.config.lock().await;
        let mut new_config = config.clone();
        let Some(target) = new_config.targets.iter_mut().find(|t| t.name == name) else {
            return Err(anyhow::anyhow!("unknown target '{name}'").into());
        };
        let out = change(&mut target.summarise)?;
        let groups = target.summarise.clone();
        new_config.validate()?;
        write_targets(&self.config_path, &new_config.targets)?;
        if let Some(running) = self.running.lock().await.get(name) {
            running.relay.summarise.set(&groups);
        }
        *config = new_config;
        Ok(out)
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

/// Writes the `[audit]`, `[export]` and `[mcp]` settings and the gateway's
/// certificate host names into the config file, changing only those keys
/// (comments and everything else stay as they are).
fn write_settings(path: &std::path::Path, config: &Config) -> anyhow::Result<()> {
    use toml_edit::{value, Array, Item, Table};
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let mut doc: toml_edit::DocumentMut = text
        .parse()
        .with_context(|| format!("parsing {}", path.display()))?;

    fn table<'a>(parent: &'a mut Table, key: &str) -> &'a mut Table {
        if !parent.get(key).is_some_and(Item::is_table) {
            let mut t = Table::new();
            t.set_implicit(key == "export");
            parent.insert(key, Item::Table(t));
        }
        parent[key].as_table_mut().expect("just made a table")
    }
    fn set_opt(t: &mut Table, key: &str, v: Option<String>) {
        match v {
            Some(v) => t[key] = value(v),
            None => {
                t.remove(key);
            }
        }
    }

    let root = doc.as_table_mut();
    let gateway = table(root, "gateway");
    if config.gateway.certificate_hostnames.is_empty() {
        gateway.remove("certificate_hostnames");
    } else {
        gateway["certificate_hostnames"] = value(Array::from_iter(
            config
                .gateway
                .certificate_hostnames
                .iter()
                .map(String::as_str),
        ));
    }

    let a = &config.audit;
    let audit = table(root, "audit");
    audit["retention_days"] = value(i64::from(a.retention_days));
    audit["fail_mode"] = value(match a.fail_mode {
        crate::config::FailMode::Open => "open",
        crate::config::FailMode::Closed => "closed",
    });
    audit["record_old_value"] = value(a.record_old_value);
    audit["ignored_summary_secs"] = value(a.ignored_summary_secs as i64);

    let export = table(root, "export");
    match &config.export.questdb {
        None => {
            export.remove("questdb");
        }
        Some(q) => {
            let t = table(export, "questdb");
            t["url"] = value(q.url.as_str());
            t["table"] = value(q.table.as_str());
            set_opt(t, "token", q.token.clone());
            set_opt(t, "username", q.username.clone());
            set_opt(t, "password", q.password.clone());
            set_opt(
                t,
                "ca_file",
                q.ca_file.as_ref().map(|p| p.display().to_string()),
            );
            t["interval_secs"] = value(q.interval_secs as i64);
        }
    }
    if config.mcp.enabled || root.contains_key("mcp") {
        let mcp = table(root, "mcp");
        mcp["enabled"] = value(config.mcp.enabled);
        mcp.remove("allow");
    }
    let export = table(root, "export");
    // Syslog export is no longer supported.
    export.remove("syslog");
    if export.is_empty() {
        root.remove("export");
    }
    crate::fsutil::write_atomic(path, doc.to_string().as_bytes(), None)
        .with_context(|| format!("writing {}", path.display()))
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
        let defaults: TargetConfig = toml::from_str(
            "name = \"x\"\nlisten = \"127.0.0.1:1\"\nendpoint_url = \"opc.tcp://x\"",
        )
        .expect("valid");
        if t.max_connections != defaults.max_connections {
            table["max_connections"] = toml_edit::value(t.max_connections as i64);
        }
        if t.max_connections_per_address != defaults.max_connections_per_address {
            table["max_connections_per_address"] =
                toml_edit::value(t.max_connections_per_address as i64);
        }
        if !t.summarise.is_empty() {
            let mut groups = toml_edit::ArrayOfTables::new();
            for g in &t.summarise {
                let mut table = toml_edit::Table::new();
                if let Some(name) = &g.name {
                    table["name"] = toml_edit::value(name.as_str());
                }
                if let Some(client) = &g.client {
                    table["client"] = toml_edit::value(client.as_str());
                }
                // One node per line: a group can hold hundreds.
                let mut nodes: toml_edit::Array = g.nodes.iter().map(String::as_str).collect();
                for node in nodes.iter_mut() {
                    node.decor_mut().set_prefix("\n  ");
                }
                nodes.set_trailing("\n");
                nodes.set_trailing_comma(true);
                table["nodes"] = toml_edit::value(nodes);
                if !g.names.is_empty() {
                    let mut names = toml_edit::Table::new();
                    for (node, name) in &g.names {
                        names[node.as_str()] = toml_edit::value(name.as_str());
                    }
                    table["names"] = toml_edit::Item::Table(names);
                }
                groups.push(table);
            }
            table["summarise"] = toml_edit::Item::ArrayOfTables(groups);
        }
        array.push(table);
    }
    if targets.is_empty() {
        doc.remove("targets");
    } else {
        doc["targets"] = toml_edit::Item::ArrayOfTables(array);
    }
    // Atomic and durable, keeping the file's permissions (it may hold
    // export credentials).
    crate::fsutil::write_atomic(path, doc.to_string().as_bytes(), None)
        .with_context(|| format!("writing {}", path.display()))
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
            max_connections: 50,
            max_connections_per_address: 10,
            summarise: Vec::new(),
            ignore: Vec::new(),
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
    async fn summarise_groups_are_saved_and_applied_live() {
        let dir = tempfile::tempdir().unwrap();
        let m = manager(dir.path()).await;
        let path = dir.path().join("config.toml");
        m.upsert(target("plc1", free_port()), None).await.unwrap();
        let relay = m.relay("plc1").await.unwrap();

        let groups = vec![
            SummariseGroup {
                name: Some("Life bits".into()),
                nodes: vec!["ns=3;s=\"DB1\".\"Life\"".into(), "ns=3;i=8".into()],
                names: [("ns=3;i=8".to_string(), "Clock".to_string())].into(),
                ..Default::default()
            },
            SummariseGroup {
                client: Some("10.0.0.5".into()),
                nodes: vec!["ns=3;i=7".into()],
                ..Default::default()
            },
        ];
        let set = |g: Vec<SummariseGroup>| {
            move |groups: &mut Vec<SummariseGroup>| -> anyhow::Result<()> {
                *groups = g;
                Ok(())
            }
        };
        m.update_summarise("plc1", set(groups.clone()))
            .await
            .unwrap();
        // The same relay (no restart), with the new groups.
        let same = m.relay("plc1").await.unwrap();
        assert!(Arc::ptr_eq(&relay, &same));
        let life = "ns=3;s=\"DB1\".\"Life\"".parse().unwrap();
        assert!(same.summarise.matches(&life, &Default::default()));
        // Saved, and read back identically.
        assert_eq!(Config::load(&path).unwrap().targets[0].summarise, groups);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("[[targets.summarise]]"), "{text}");

        // Invalid groups change nothing.
        let mut bad = groups.clone();
        bad[1].nodes.push("ns=3;i=7".into());
        assert!(m.update_summarise("plc1", set(bad)).await.is_err());
        assert_eq!(Config::load(&path).unwrap().targets[0].summarise, groups);
        assert!(m.update_summarise("nope", set(Vec::new())).await.is_err());

        m.update_summarise("plc1", set(Vec::new())).await.unwrap();
        assert!(Config::load(&path).unwrap().targets[0].summarise.is_empty());
        assert!(same.summarise.is_empty());
    }

    #[tokio::test]
    async fn old_ignore_rules_are_written_as_groups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            format!(
                "{EXAMPLE_CONFIG}
[[targets]]
name = \"plc1\"
listen = \"127.0.0.1:{}\"
endpoint_url = \"opc.tcp://127.0.0.1:1/\"

[[targets.ignore]]
node_id = \"ns=3;i=1\"
name = \"Life\"

[[targets.ignore]]
node_id = \"ns=3;i=2\"
client = \"10.0.0.5\"
",
                free_port()
            ),
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        let t = &config.targets[0];
        assert!(t.ignore.is_empty());
        assert_eq!(t.summarise.len(), 2);
        write_targets(&path, &config.targets).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("targets.ignore"), "{text}");
        assert_eq!(
            Config::load(&path).unwrap().targets[0].summarise,
            t.summarise
        );
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
