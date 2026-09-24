//! Ignored nodes: value writes that would flood the audit trail (a life bit,
//! a seconds counter) are not recorded one by one. They are counted per node
//! and recorded periodically as one `ignored_writes` summary: how many, how
//! many failed, from which clients, first and last time, and the last value.
//! A write to an ignored node therefore never goes unnoticed entirely.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use opcua::types::NodeId;
use parking_lot::{Mutex, RwLock};

use crate::audit::event::{AuditEvent, AuditValue, ClientContext};
use crate::config::IgnoreRule;

/// Most clients listed in one summary.
const MAX_CLIENTS: usize = 20;
/// Most nodes summarised at once; writes to further nodes are recorded as
/// usual until the next summary.
const MAX_NODES: usize = 10_000;

struct Rule {
    node: NodeId,
    client: Option<String>,
}

/// The ignore rules of a target. They can change while clients are
/// connected.
#[derive(Default)]
pub struct IgnoreList {
    rules: RwLock<Vec<Rule>>,
}

impl IgnoreList {
    pub fn new(rules: &[IgnoreRule]) -> Self {
        let list = Self::default();
        list.set(rules);
        list
    }

    /// Replaces the rules. Rules that are not valid node ids are skipped
    /// (the configuration is validated before it gets here).
    pub fn set(&self, rules: &[IgnoreRule]) {
        *self.rules.write() = rules
            .iter()
            .filter_map(|r| {
                Some(Rule {
                    node: r.node().ok()?,
                    client: r.client.as_ref().map(|c| c.trim().to_string()),
                })
            })
            .collect();
    }

    pub fn is_empty(&self) -> bool {
        self.rules.read().is_empty()
    }

    /// Whether a value write to `node` by `client` is ignored.
    pub fn matches(&self, node: &NodeId, client: &ClientContext) -> bool {
        self.rules.read().iter().any(|r| {
            &r.node == node
                && r.client.as_deref().is_none_or(|c| {
                    c == client_ip(&client.remote_addr)
                        || client.application_uri.as_deref() == Some(c)
                })
        })
    }
}

/// The IP address of `ip:port` or `[v6]:port`.
pub fn client_ip(remote_addr: &str) -> &str {
    let host = remote_addr
        .rsplit_once(':')
        .map_or(remote_addr, |(host, _)| host);
    host.trim_start_matches('[').trim_end_matches(']')
}

struct Summary {
    display_name: Option<String>,
    count: u64,
    failed: u64,
    first: DateTime<Utc>,
    last: DateTime<Utc>,
    last_value: AuditValue,
    last_status: String,
    clients: BTreeSet<String>,
}

/// Ignored writes counted since the last summary.
#[derive(Default)]
pub struct IgnoredWrites {
    nodes: Mutex<BTreeMap<String, Summary>>,
}

impl IgnoredWrites {
    /// Counts one ignored write. Returns false if too many nodes are
    /// pending already; the caller then records the write as usual.
    pub fn add(
        &self,
        node_id: &str,
        display_name: Option<String>,
        value: AuditValue,
        status: &str,
        client: &ClientContext,
    ) -> bool {
        let now = Utc::now();
        let mut nodes = self.nodes.lock();
        if !nodes.contains_key(node_id) && nodes.len() >= MAX_NODES {
            return false;
        }
        let summary = nodes.entry(node_id.to_string()).or_insert_with(|| Summary {
            display_name: None,
            count: 0,
            failed: 0,
            first: now,
            last: now,
            last_value: value.clone(),
            last_status: String::new(),
            clients: BTreeSet::new(),
        });
        summary.count += 1;
        if !status.starts_with("Good") {
            summary.failed += 1;
        }
        summary.last = now;
        summary.last_value = value;
        summary.last_status = status.to_string();
        if display_name.is_some() {
            summary.display_name = display_name;
        }
        if summary.clients.len() < MAX_CLIENTS {
            summary.clients.insert(client_label(client));
        }
        true
    }

    /// The summaries since the last call, one event per node.
    pub fn take(&self) -> Vec<AuditEvent> {
        std::mem::take(&mut *self.nodes.lock())
            .into_iter()
            .map(|(node_id, s)| AuditEvent::IgnoredWrites {
                node_id,
                display_name: s.display_name,
                count: s.count,
                failed: s.failed,
                first: s.first,
                last: s.last,
                last_value: s.last_value,
                last_status: s.last_status,
                clients: s.clients.into_iter().collect(),
            })
            .collect()
    }
}

/// `10.0.0.5 HMI-3 (operator)`: address, application and user.
fn client_label(client: &ClientContext) -> String {
    let mut label = client_ip(&client.remote_addr).to_string();
    if let Some(app) = client
        .application_name
        .as_ref()
        .or(client.application_uri.as_ref())
    {
        label.push(' ');
        label.push_str(app);
    }
    if let Some(user) = &client.user {
        label.push_str(&format!(" ({})", user.label()));
    }
    crate::audit::event::clip(&label, crate::audit::event::MAX_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::UserIdentity;

    fn client(addr: &str, uri: &str) -> ClientContext {
        ClientContext {
            remote_addr: addr.into(),
            application_uri: Some(uri.into()),
            application_name: Some("HMI".into()),
            user: Some(UserIdentity::Anonymous),
            ..Default::default()
        }
    }

    fn rule(node_id: &str, client: Option<&str>) -> IgnoreRule {
        IgnoreRule {
            node_id: node_id.into(),
            client: client.map(Into::into),
            name: None,
        }
    }

    #[test]
    fn rules_match_node_and_optionally_client() {
        let life: NodeId = "ns=3;s=\"DB1\".\"Life\"".parse().unwrap();
        let other: NodeId = "ns=3;s=\"DB1\".\"Set\"".parse().unwrap();
        let hmi = client("10.0.0.5:50000", "urn:hmi");
        let scada = client("[fe80::1]:50000", "urn:scada");

        let list = IgnoreList::new(&[rule("ns=3;s=\"DB1\".\"Life\"", None)]);
        assert!(list.matches(&life, &hmi) && list.matches(&life, &scada));
        assert!(!list.matches(&other, &hmi));

        list.set(&[rule("ns=3;s=\"DB1\".\"Life\"", Some("10.0.0.5"))]);
        assert!(list.matches(&life, &hmi));
        assert!(!list.matches(&life, &scada), "another client is recorded");

        list.set(&[rule("ns=3;s=\"DB1\".\"Life\"", Some("urn:scada"))]);
        assert!(list.matches(&life, &scada) && !list.matches(&life, &hmi));

        list.set(&[rule("ns=3;s=\"DB1\".\"Life\"", Some("fe80::1"))]);
        assert!(list.matches(&life, &scada));

        list.set(&[]);
        assert!(list.is_empty() && !list.matches(&life, &hmi));
    }

    #[test]
    fn writes_are_summarised_per_node() {
        let writes = IgnoredWrites::default();
        let value = |v: i64| AuditValue {
            data_type: "Int64".into(),
            value: v.into(),
        };
        let hmi = client("10.0.0.5:50000", "urn:hmi");
        for i in 0..5 {
            assert!(writes.add("ns=3;i=1", Some("Life".into()), value(i), "Good", &hmi));
        }
        writes.add("ns=3;i=1", None, value(9), "BadUserAccessDenied", &hmi);
        writes.add(
            "ns=3;i=2",
            None,
            value(1),
            "Good",
            &client("10.0.0.6:1", "urn:x"),
        );

        let events = writes.take();
        assert_eq!(events.len(), 2);
        let AuditEvent::IgnoredWrites {
            node_id,
            display_name,
            count,
            failed,
            last_value,
            last_status,
            clients,
            ..
        } = &events[0]
        else {
            panic!("{events:?}")
        };
        assert_eq!(node_id, "ns=3;i=1");
        assert_eq!(display_name.as_deref(), Some("Life"));
        assert_eq!((*count, *failed), (6, 1));
        assert_eq!(last_value.value, 9);
        assert_eq!(last_status, "BadUserAccessDenied");
        assert_eq!(clients, &["10.0.0.5 HMI (anonymous)"]);
        assert!(writes.take().is_empty(), "taken summaries start over");
    }
}
