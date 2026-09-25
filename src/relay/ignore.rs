//! Summarised nodes: value writes that would flood the audit trail (a life bit,
//! a seconds counter) are not recorded one by one. They are counted per node
//! and recorded periodically as one `ignored_writes` summary: how many, how
//! many failed, from which clients, first and last time, and the last value.
//! A write to an ignored node therefore never goes unnoticed entirely.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Utc};
use opcua::types::NodeId;
use parking_lot::{Mutex, RwLock};

use crate::audit::event::{AuditEvent, AuditValue, ClientContext};
use crate::config::{parse_node, SummariseGroup};

/// Most clients listed in one summary.
const MAX_CLIENTS: usize = 20;
/// Most nodes summarised at once; writes to further nodes are recorded as
/// usual until the next summary.
const MAX_NODES: usize = 10_000;

/// The nodes a target summarises, per client, for a quick lookup per
/// write. They can change while clients are connected.
#[derive(Default)]
pub struct SummariseList {
    lookup: RwLock<Lookup>,
}

#[derive(Default)]
struct Lookup {
    /// Nodes summarised whoever writes them.
    all: HashSet<NodeId>,
    /// Nodes summarised for one client, by its address or application URI.
    by_client: HashMap<String, HashSet<NodeId>>,
}

impl SummariseList {
    pub fn new(groups: &[SummariseGroup]) -> Self {
        let list = Self::default();
        list.set(groups);
        list
    }

    /// Replaces the groups. Node ids that do not parse are skipped (the
    /// configuration is validated before it gets here).
    pub fn set(&self, groups: &[SummariseGroup]) {
        let mut lookup = Lookup::default();
        for g in groups {
            let nodes = match &g.client {
                Some(c) => lookup.by_client.entry(c.trim().to_string()).or_default(),
                None => &mut lookup.all,
            };
            nodes.extend(g.nodes.iter().filter_map(|n| parse_node(n).ok()));
        }
        lookup.by_client.retain(|_, nodes| !nodes.is_empty());
        *self.lookup.write() = lookup;
    }

    pub fn is_empty(&self) -> bool {
        let lookup = self.lookup.read();
        lookup.all.is_empty() && lookup.by_client.is_empty()
    }

    /// Whether a value write to `node` by `client` is summarised.
    pub fn matches(&self, node: &NodeId, client: &ClientContext) -> bool {
        let lookup = self.lookup.read();
        let for_client = |key: &str| lookup.by_client.get(key).is_some_and(|n| n.contains(node));
        lookup.all.contains(node)
            || for_client(client_ip(&client.remote_addr))
            || client.application_uri.as_deref().is_some_and(for_client)
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

    fn group(client: Option<&str>, nodes: &[&str]) -> SummariseGroup {
        SummariseGroup {
            client: client.map(Into::into),
            nodes: nodes.iter().map(|n| n.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn groups_match_node_and_optionally_client() {
        const LIFE: &str = "ns=3;s=\"DB1\".\"Life\"";
        let life: NodeId = LIFE.parse().unwrap();
        let other: NodeId = "ns=3;s=\"DB1\".\"Set\"".parse().unwrap();
        let hmi = client("10.0.0.5:50000", "urn:hmi");
        let scada = client("[fe80::1]:50000", "urn:scada");

        let list = SummariseList::new(&[group(None, &[LIFE, "ns=3;i=1"])]);
        assert!(list.matches(&life, &hmi) && list.matches(&life, &scada));
        assert!(!list.matches(&other, &hmi));

        list.set(&[group(Some("10.0.0.5"), &[LIFE])]);
        assert!(list.matches(&life, &hmi));
        assert!(!list.matches(&life, &scada), "another client is recorded");

        list.set(&[group(Some(" urn:scada "), &[LIFE])]);
        assert!(list.matches(&life, &scada) && !list.matches(&life, &hmi));

        list.set(&[group(Some("fe80::1"), &[LIFE])]);
        assert!(list.matches(&life, &scada));

        // A node in a client's group and in the group for everyone: both apply.
        list.set(&[
            group(Some("10.0.0.5"), &[LIFE]),
            group(None, &[LIFE]),
            group(Some("10.0.0.5"), &["ns=3;s=\"DB1\".\"Set\""]),
        ]);
        assert!(list.matches(&life, &scada) && list.matches(&other, &hmi));
        assert!(!list.matches(&other, &scada));

        // An empty group summarises nothing.
        list.set(&[group(Some("10.0.0.5"), &[])]);
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
