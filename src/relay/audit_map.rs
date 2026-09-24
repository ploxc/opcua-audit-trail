//! Turns change requests and their responses into audit events.
//!
//! [`plan`] captures what is needed from a request before it is forwarded
//! (the request itself is moved into the upstream channel); [`AuditPlan::events`]
//! combines that with the response, so every record carries the server's
//! actual result, including rejections.

use std::collections::HashMap;

use opcua::core::{RequestMessage, ResponseMessage};
use opcua::types::{
    AttributeId, DataValue, DeleteAtTimeDetails, DeleteEventDetails, DeleteRawModifiedDetails,
    ExtensionObject, NodeId, NumericRange, ReadValueId, StatusCode, UpdateDataDetails,
    UpdateEventDetails, UpdateStructureDataDetails, Variant,
};
use parking_lot::Mutex;
use serde_json::{json, Value};

use crate::audit::event::{clip, AuditEvent, AuditValue, MAX_NAME, MAX_TEXT};

/// Byte strings and opaque structures longer than this are truncated in the trail.
const MAX_BYTES: usize = 4096;
/// Arrays longer than this keep only their first elements in the trail.
const MAX_ELEMENTS: usize = 256;
/// A value whose rendering is still larger than this is replaced by a preview.
const MAX_VALUE_JSON: usize = 64 * 1024;
/// When a whole request fails at the service level (nothing was applied),
/// at most this many of its items are recorded one by one.
const MAX_FAILED_ITEMS: usize = 100;

/// Most node names the per-target cache keeps before it starts over.
const NAME_CACHE_SIZE: usize = 100_000;

pub struct WriteItem {
    /// Position in the request, and so in the response's results.
    index: usize,
    node: NodeId,
    attribute_id: u32,
    range: NumericRange,
    node_id: String,
    attribute: String,
    index_range: Option<String>,
    new_value: AuditValue,
    written_status: Option<String>,
    source_timestamp: Option<String>,
    server_timestamp: Option<String>,
    old_value: Option<AuditValue>,
    display_name: Option<String>,
}

pub struct CallItem {
    method: NodeId,
    object_id: String,
    method_id: String,
    input_arguments: Vec<AuditValue>,
    display_name: Option<String>,
}

/// Display names of nodes, per target, so a name is read only once.
#[derive(Default)]
pub struct NameCache {
    names: Mutex<HashMap<NodeId, String>>,
}

impl NameCache {
    fn get(&self, node: &NodeId) -> Option<String> {
        self.names.lock().get(node).cloned()
    }

    fn insert(&self, node: NodeId, name: String) {
        let mut names = self.names.lock();
        if names.len() >= NAME_CACHE_SIZE {
            names.clear();
        }
        names.insert(node, name);
    }
}

enum PreReadKind {
    OldValue,
    Name,
}

/// Reads sent together with a change request: old values and display names.
pub struct PreRead {
    pub nodes_to_read: Vec<ReadValueId>,
    targets: Vec<(usize, PreReadKind)>,
}

pub struct HistoryItem {
    node_id: String,
    details: String,
}

pub enum AuditPlan {
    Write(u32, Vec<WriteItem>),
    Call(u32, Vec<CallItem>),
    HistoryUpdate(u32, Vec<HistoryItem>),
    NodeManagement(u32, &'static str, Vec<String>),
    TransferSubscriptions(u32, Vec<u32>),
}

/// Whether a request is audited. Such requests are also seen through to the
/// end when the client disconnects, so their outcome is always recorded.
pub fn is_audited(request: &RequestMessage) -> bool {
    matches!(
        request,
        RequestMessage::Write(_)
            | RequestMessage::Call(_)
            | RequestMessage::HistoryUpdate(_)
            | RequestMessage::AddNodes(_)
            | RequestMessage::DeleteNodes(_)
            | RequestMessage::AddReferences(_)
            | RequestMessage::DeleteReferences(_)
            | RequestMessage::TransferSubscriptions(_)
    )
}

/// Returns a plan for requests that change the server, `None` for all others.
pub fn plan(request: &RequestMessage) -> Option<AuditPlan> {
    let handle = request.request_header().request_handle;
    match request {
        RequestMessage::Write(r) => Some(AuditPlan::Write(
            handle,
            r.nodes_to_write
                .iter()
                .flatten()
                .enumerate()
                .map(|(index, w)| WriteItem {
                    index,
                    node: w.node_id.clone(),
                    attribute_id: w.attribute_id,
                    range: w.index_range.clone(),
                    old_value: None,
                    display_name: None,
                    node_id: clip(&w.node_id.to_string(), MAX_TEXT),
                    attribute: attribute_name(w.attribute_id),
                    index_range: (!w.index_range.is_none()).then(|| w.index_range.to_string()),
                    new_value: w
                        .value
                        .value
                        .as_ref()
                        .map(audit_value)
                        .unwrap_or_else(|| audit_value(&Variant::Empty)),
                    written_status: w.value.status.map(|s| s.to_string()),
                    source_timestamp: w.value.source_timestamp.map(|t| t.to_string()),
                    server_timestamp: w.value.server_timestamp.map(|t| t.to_string()),
                })
                .collect(),
        )),
        RequestMessage::Call(r) => Some(AuditPlan::Call(
            handle,
            r.methods_to_call
                .iter()
                .flatten()
                .map(|c| CallItem {
                    method: c.method_id.clone(),
                    display_name: None,
                    object_id: clip(&c.object_id.to_string(), MAX_TEXT),
                    method_id: clip(&c.method_id.to_string(), MAX_TEXT),
                    input_arguments: c
                        .input_arguments
                        .iter()
                        .flatten()
                        .map(audit_value)
                        .collect(),
                })
                .collect(),
        )),
        RequestMessage::HistoryUpdate(r) => Some(AuditPlan::HistoryUpdate(
            handle,
            r.history_update_details
                .iter()
                .flatten()
                .map(history_item)
                .collect(),
        )),
        RequestMessage::AddNodes(r) => Some(AuditPlan::NodeManagement(
            handle,
            "AddNodes",
            r.nodes_to_add
                .iter()
                .flatten()
                .map(|n| {
                    clip(
                        &format!("{} (parent {})", n.requested_new_node_id, n.parent_node_id),
                        MAX_TEXT,
                    )
                })
                .collect(),
        )),
        RequestMessage::DeleteNodes(r) => Some(AuditPlan::NodeManagement(
            handle,
            "DeleteNodes",
            r.nodes_to_delete
                .iter()
                .flatten()
                .map(|n| clip(&n.node_id.to_string(), MAX_TEXT))
                .collect(),
        )),
        RequestMessage::AddReferences(r) => Some(AuditPlan::NodeManagement(
            handle,
            "AddReferences",
            r.references_to_add
                .iter()
                .flatten()
                .map(|n| {
                    clip(
                        &format!("{} -> {}", n.source_node_id, n.target_node_id),
                        MAX_TEXT,
                    )
                })
                .collect(),
        )),
        RequestMessage::DeleteReferences(r) => Some(AuditPlan::NodeManagement(
            handle,
            "DeleteReferences",
            r.references_to_delete
                .iter()
                .flatten()
                .map(|n| {
                    clip(
                        &format!("{} -> {}", n.source_node_id, n.target_node_id),
                        MAX_TEXT,
                    )
                })
                .collect(),
        )),
        RequestMessage::TransferSubscriptions(r) => Some(AuditPlan::TransferSubscriptions(
            handle,
            r.subscription_ids.clone().unwrap_or_default(),
        )),
        _ => None,
    }
}

/// The status of item `i`: the item's own result, or the service result if
/// the whole request failed, or `unknown` if no response arrived.
fn item_status(
    results: Option<&[StatusCode]>,
    i: usize,
    service_result: StatusCode,
    unknown: Option<&str>,
) -> String {
    if let Some(unknown) = unknown {
        return unknown.to_string();
    }
    if service_result.is_bad() {
        return service_result.to_string();
    }
    results
        .and_then(|r| r.get(i).copied())
        .unwrap_or(StatusCode::BadUnexpectedError)
        .to_string()
}

/// Writes to ignored nodes, taken out of a write plan: they are summarised
/// instead of recorded one by one.
pub struct IgnoredItems(Vec<WriteItem>);

/// One ignored write and its outcome.
pub struct IgnoredWrite {
    pub node_id: String,
    pub display_name: Option<String>,
    pub value: AuditValue,
    pub status: String,
}

impl IgnoredItems {
    /// The outcome of each ignored write. `names` supplies display names
    /// already known (ignored nodes are not read before the write).
    pub fn outcomes(
        self,
        response: &ResponseMessage,
        unknown: Option<StatusCode>,
        names: &NameCache,
    ) -> Vec<IgnoredWrite> {
        let service_result = response.response_header().service_result;
        let results = match response {
            ResponseMessage::Write(r) => r.results.clone(),
            _ => None,
        };
        let unknown = unknown.map(|s| format!("Uncertain: no response ({s})"));
        self.0
            .into_iter()
            .map(|w| IgnoredWrite {
                status: item_status(
                    results.as_deref(),
                    w.index,
                    service_result,
                    unknown.as_deref(),
                ),
                display_name: names.get(&w.node),
                node_id: w.node_id,
                value: w.new_value,
            })
            .collect()
    }
}

impl AuditPlan {
    /// Takes the value writes for which `ignored` is true out of a write
    /// plan. Writes to other attributes (e.g. access rights) and other
    /// services are never ignored. Returns `None` if nothing was taken.
    pub fn take_ignored(&mut self, ignored: impl Fn(&NodeId) -> bool) -> Option<IgnoredItems> {
        let AuditPlan::Write(_, items) = self else {
            return None;
        };
        let (taken, kept): (Vec<_>, Vec<_>) = std::mem::take(items)
            .into_iter()
            .partition(|w| w.attribute_id == AttributeId::Value as u32 && ignored(&w.node));
        *items = kept;
        (!taken.is_empty()).then_some(IgnoredItems(taken))
    }

    /// A plan with nothing left to record (all its writes were ignored).
    pub fn is_empty(&self) -> bool {
        matches!(self, AuditPlan::Write(_, items) if items.is_empty())
    }

    /// Fills in cached names and returns the reads still needed: the current
    /// value of written nodes (when `old_values`) and uncached display names.
    pub fn pre_read(&mut self, old_values: bool, names: &NameCache) -> Option<PreRead> {
        let mut pre = PreRead {
            nodes_to_read: Vec::new(),
            targets: Vec::new(),
        };
        let want_name =
            |pre: &mut PreRead, i: usize, node: &NodeId, name: &mut Option<String>| match names
                .get(node)
            {
                Some(cached) => *name = Some(cached),
                None => {
                    pre.nodes_to_read.push(ReadValueId {
                        node_id: node.clone(),
                        attribute_id: AttributeId::DisplayName as u32,
                        ..Default::default()
                    });
                    pre.targets.push((i, PreReadKind::Name));
                }
            };
        match self {
            AuditPlan::Write(_, items) => {
                for (i, item) in items.iter_mut().enumerate() {
                    if old_values {
                        pre.nodes_to_read.push(ReadValueId {
                            node_id: item.node.clone(),
                            attribute_id: item.attribute_id,
                            index_range: item.range.clone(),
                            ..Default::default()
                        });
                        pre.targets.push((i, PreReadKind::OldValue));
                    }
                    want_name(&mut pre, i, &item.node, &mut item.display_name);
                }
            }
            AuditPlan::Call(_, items) => {
                for (i, item) in items.iter_mut().enumerate() {
                    want_name(&mut pre, i, &item.method, &mut item.display_name);
                }
            }
            AuditPlan::HistoryUpdate(..)
            | AuditPlan::NodeManagement(..)
            | AuditPlan::TransferSubscriptions(..) => {}
        }
        (!pre.nodes_to_read.is_empty()).then_some(pre)
    }

    /// Applies the results of [`AuditPlan::pre_read`]. Failed reads (e.g. no
    /// read access for this user) simply leave the field empty.
    pub fn apply_pre_read(&mut self, pre: PreRead, results: &[DataValue], names: &NameCache) {
        let good = |d: &DataValue| d.status.is_none_or(|s| s.is_good());
        for ((i, kind), result) in pre.targets.into_iter().zip(results) {
            if !good(result) {
                continue;
            }
            let Some(value) = &result.value else {
                continue;
            };
            match (kind, &mut *self) {
                (PreReadKind::OldValue, AuditPlan::Write(_, items)) => {
                    items[i].old_value = Some(audit_value(value));
                }
                (PreReadKind::Name, plan) => {
                    let Variant::LocalizedText(text) = value else {
                        continue;
                    };
                    let name = clip(text.text.as_ref(), MAX_NAME);
                    match plan {
                        AuditPlan::Write(_, items) => {
                            let item = &mut items[i];
                            names.insert(item.node.clone(), name.clone());
                            item.display_name = Some(name);
                        }
                        AuditPlan::Call(_, items) => {
                            let item = &mut items[i];
                            names.insert(item.method.clone(), name.clone());
                            item.display_name = Some(name);
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
    }

    pub fn service(&self) -> &'static str {
        match self {
            AuditPlan::Write(..) => "Write",
            AuditPlan::Call(..) => "Call",
            AuditPlan::HistoryUpdate(..) => "HistoryUpdate",
            AuditPlan::NodeManagement(_, service, _) => service,
            AuditPlan::TransferSubscriptions(..) => "TransferSubscriptions",
        }
    }

    /// The record committed before forwarding in fail-closed mode.
    pub fn intent(&self) -> AuditEvent {
        let (request_handle, node_ids, details): (u32, Vec<String>, Vec<Value>) = match self {
            AuditPlan::Write(h, items) => (
                *h,
                items.iter().map(|i| i.node_id.clone()).collect(),
                items
                    .iter()
                    .map(|i| json!({ "attribute": i.attribute, "new_value": i.new_value }))
                    .collect(),
            ),
            AuditPlan::Call(h, items) => (
                *h,
                items.iter().map(|i| i.method_id.clone()).collect(),
                items
                    .iter()
                    .map(|i| json!({ "object_id": i.object_id, "input_arguments": i.input_arguments }))
                    .collect(),
            ),
            AuditPlan::HistoryUpdate(h, items) => (
                *h,
                items.iter().map(|i| i.node_id.clone()).collect(),
                items.iter().map(|i| json!({ "details": i.details })).collect(),
            ),
            AuditPlan::NodeManagement(h, _, nodes) => (*h, nodes.clone(), Vec::new()),
            AuditPlan::TransferSubscriptions(h, ids) => {
                (*h, ids.iter().map(|id| id.to_string()).collect(), Vec::new())
            }
        };
        AuditEvent::ChangeIntent {
            request_handle,
            service: self.service().into(),
            node_ids,
            details,
        }
    }

    /// Events for the outcome. A service-level failure (ServiceFault or a bad
    /// service result) applies to every item.
    pub fn events(self, response: &ResponseMessage) -> Vec<AuditEvent> {
        self.events_with(response, None)
    }

    /// Events for a request that was sent, but whose response never arrived:
    /// the server may or may not have applied it.
    pub fn events_unknown(self, response: &ResponseMessage, status: StatusCode) -> Vec<AuditEvent> {
        self.events_with(
            response,
            Some(format!(
                "Uncertain: no response ({status}); the server may have applied it"
            )),
        )
    }

    fn events_with(self, response: &ResponseMessage, unknown: Option<String>) -> Vec<AuditEvent> {
        let service_result = response.response_header().service_result;
        let mut events = self.events_all(response, service_result, unknown.clone());
        // A request that failed as a whole changed nothing: a sample of its
        // items is enough, and keeps junk requests from flooding the trail.
        if service_result.is_bad() && unknown.is_none() && events.len() > MAX_FAILED_ITEMS {
            let omitted = events.len() - MAX_FAILED_ITEMS;
            events.truncate(MAX_FAILED_ITEMS);
            tracing::info!(
                "recorded {MAX_FAILED_ITEMS} items of a failed request, omitted {omitted}"
            );
        }
        events
    }

    fn events_all(
        self,
        response: &ResponseMessage,
        service_result: StatusCode,
        unknown: Option<String>,
    ) -> Vec<AuditEvent> {
        let item_status = |results: Option<Vec<StatusCode>>, i: usize| -> String {
            item_status(results.as_deref(), i, service_result, unknown.as_deref())
        };

        match self {
            AuditPlan::Write(request_handle, items) => {
                let results = match response {
                    ResponseMessage::Write(r) => r.results.clone(),
                    _ => None,
                };
                items
                    .into_iter()
                    .map(|w| AuditEvent::Write {
                        status: item_status(results.clone(), w.index),
                        request_handle,
                        node_id: w.node_id,
                        display_name: w.display_name,
                        attribute: w.attribute,
                        index_range: w.index_range,
                        old_value: w.old_value,
                        new_value: w.new_value,
                        written_status: w.written_status,
                        source_timestamp: w.source_timestamp,
                        server_timestamp: w.server_timestamp,
                    })
                    .collect()
            }
            AuditPlan::Call(request_handle, items) => {
                let results = match response {
                    ResponseMessage::Call(r) => r
                        .results
                        .as_ref()
                        .map(|r| r.iter().map(|c| c.status_code).collect()),
                    _ => None,
                };
                items
                    .into_iter()
                    .enumerate()
                    .map(|(i, c)| AuditEvent::Call {
                        request_handle,
                        object_id: c.object_id,
                        method_id: c.method_id,
                        display_name: c.display_name,
                        input_arguments: c.input_arguments,
                        status: item_status(results.clone(), i),
                    })
                    .collect()
            }
            AuditPlan::HistoryUpdate(request_handle, items) => {
                let results = match response {
                    ResponseMessage::HistoryUpdate(r) => r
                        .results
                        .as_ref()
                        .map(|r| r.iter().map(|h| h.status_code).collect()),
                    _ => None,
                };
                items
                    .into_iter()
                    .enumerate()
                    .map(|(i, h)| AuditEvent::HistoryUpdate {
                        request_handle,
                        node_id: h.node_id,
                        details: h.details,
                        status: item_status(results.clone(), i),
                    })
                    .collect()
            }
            AuditPlan::NodeManagement(request_handle, service, nodes) => {
                let results: Option<Vec<StatusCode>> = match response {
                    ResponseMessage::AddNodes(r) => r
                        .results
                        .as_ref()
                        .map(|r| r.iter().map(|a| a.status_code).collect()),
                    ResponseMessage::DeleteNodes(r) => r.results.clone(),
                    ResponseMessage::AddReferences(r) => r.results.clone(),
                    ResponseMessage::DeleteReferences(r) => r.results.clone(),
                    _ => None,
                };
                nodes
                    .into_iter()
                    .enumerate()
                    .map(|(i, node_id)| AuditEvent::NodeManagement {
                        request_handle,
                        service: service.into(),
                        node_id,
                        status: item_status(results.clone(), i),
                    })
                    .collect()
            }
            AuditPlan::TransferSubscriptions(request_handle, subscription_ids) => {
                // One record for the request; the per-subscription results
                // are summarised in the status.
                let results: Option<Vec<StatusCode>> = match response {
                    ResponseMessage::TransferSubscriptions(r) => r
                        .results
                        .as_ref()
                        .map(|r| r.iter().map(|t| t.status_code).collect()),
                    _ => None,
                };
                let status = if unknown.is_some() || service_result.is_bad() {
                    item_status(None, 0)
                } else {
                    let results = results.unwrap_or_default();
                    if results.iter().all(|s| s.is_good()) && !results.is_empty() {
                        "Good".to_string()
                    } else {
                        results
                            .iter()
                            .map(|s| s.to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                };
                vec![AuditEvent::SubscriptionsTransferred {
                    request_handle,
                    subscription_ids,
                    status,
                }]
            }
        }
    }
}

fn attribute_name(id: u32) -> String {
    AttributeId::from_u32(id)
        .map(|a| format!("{a:?}"))
        .unwrap_or_else(|_| format!("Attribute({id})"))
}

fn history_item(details: &ExtensionObject) -> HistoryItem {
    macro_rules! try_details {
        ($($t:ty => $name:literal),*) => {
            $(if let Some(d) = details.inner_as::<$t>() {
                return HistoryItem { node_id: clip(&d.node_id.to_string(), MAX_TEXT), details: $name.into() };
            })*
        };
    }
    try_details!(
        UpdateDataDetails => "UpdateData",
        UpdateStructureDataDetails => "UpdateStructureData",
        UpdateEventDetails => "UpdateEvent",
        DeleteRawModifiedDetails => "DeleteRawModified",
        DeleteAtTimeDetails => "DeleteAtTime",
        DeleteEventDetails => "DeleteEvent"
    );
    HistoryItem {
        node_id: String::new(),
        details: format!("unknown ({})", details.binary_type_id()),
    }
}

/// Renders a value for the audit trail.
pub fn audit_value(v: &Variant) -> AuditValue {
    let data_type = match v {
        Variant::Empty => "Null".to_string(),
        Variant::Array(a) => format!("{}[]", a.value_type),
        other => other
            .scalar_type_id()
            .map(|t| t.to_string())
            .unwrap_or_else(|| "Unknown".into()),
    };
    let mut value = json_value(v);
    let rendered = value.to_string();
    if rendered.len() > MAX_VALUE_JSON {
        value = json!({ "preview": clip(&rendered, MAX_TEXT), "length": rendered.len(), "truncated": true });
    }
    AuditValue { data_type, value }
}

fn text(s: &str) -> Value {
    if s.chars().count() > MAX_TEXT {
        json!({ "text": clip(s, MAX_TEXT), "length": s.chars().count(), "truncated": true })
    } else {
        json!(s)
    }
}

fn float(f: f64) -> Value {
    serde_json::Number::from_f64(f)
        .map(Value::Number)
        .unwrap_or_else(|| Value::String(f.to_string()))
}

fn bytes(b: &[u8]) -> Value {
    if b.len() > MAX_BYTES {
        json!({ "hex": hex::encode(&b[..MAX_BYTES]), "length": b.len(), "truncated": true })
    } else {
        json!({ "hex": hex::encode(b) })
    }
}

fn json_value(v: &Variant) -> Value {
    match v {
        Variant::Empty => Value::Null,
        Variant::Boolean(b) => json!(b),
        Variant::SByte(n) => json!(n),
        Variant::Byte(n) => json!(n),
        Variant::Int16(n) => json!(n),
        Variant::UInt16(n) => json!(n),
        Variant::Int32(n) => json!(n),
        Variant::UInt32(n) => json!(n),
        Variant::Int64(n) => json!(n),
        Variant::UInt64(n) => json!(n),
        Variant::Float(f) => float(f64::from(*f)),
        Variant::Double(f) => float(*f),
        Variant::String(s) => s.value().as_ref().map_or(Value::Null, |s| text(s)),
        Variant::DateTime(d) => json!(d.to_string()),
        Variant::Guid(g) => json!(g.to_string()),
        Variant::StatusCode(s) => json!(s.to_string()),
        Variant::ByteString(b) => b.value.as_deref().map_or(Value::Null, bytes),
        Variant::XmlElement(x) => text(&x.to_string()),
        Variant::QualifiedName(q) => text(&q.to_string()),
        Variant::LocalizedText(t) => text(t.text.as_ref()),
        Variant::NodeId(n) => text(&n.to_string()),
        Variant::ExpandedNodeId(n) => text(&n.to_string()),
        Variant::ExtensionObject(e) => extension_object(e),
        Variant::Variant(inner) => json_value(inner),
        Variant::DataValue(d) => d.value.as_ref().map_or(Value::Null, json_value),
        Variant::DiagnosticInfo(d) => json!(format!("{d:?}")),
        Variant::Array(a) => {
            let values: Vec<Value> = a.values.iter().take(MAX_ELEMENTS).map(json_value).collect();
            let truncated = a.values.len() > MAX_ELEMENTS;
            match &a.dimensions {
                Some(dims) if dims.len() > 1 => {
                    json!({ "dimensions": dims, "values": values, "truncated": truncated })
                }
                _ if truncated => {
                    json!({ "values": values, "length": a.values.len(), "truncated": true })
                }
                _ => Value::Array(values),
            }
        }
    }
}

fn extension_object(e: &ExtensionObject) -> Value {
    if e.is_null() {
        return Value::Null;
    }
    let type_id = e.binary_type_id().to_string();
    if let Some(raw) = e.inner_as::<opcua::types::ByteStringBody>() {
        let body = raw.raw_body().value.as_deref().map_or(Value::Null, bytes);
        return json!({ "encoding_id": type_id, "body": body });
    }
    let mut text = format!("{:?}", e.body);
    if text.len() > MAX_BYTES {
        text.truncate(MAX_BYTES);
        text.push('…');
    }
    json!({ "encoding_id": type_id, "body": text })
}

#[cfg(test)]
mod tests {
    use super::*;
    use opcua::types::{
        DataValue, NodeId, RequestHeader, ResponseHeader, WriteRequest, WriteResponse, WriteValue,
    };

    fn write_request() -> RequestMessage {
        WriteRequest {
            request_header: RequestHeader {
                request_handle: 42,
                ..Default::default()
            },
            nodes_to_write: Some(vec![
                WriteValue {
                    node_id: NodeId::new(3, "\"DB1\".\"Setpoint\""),
                    attribute_id: AttributeId::Value as u32,
                    index_range: Default::default(),
                    value: DataValue::new_now(12.5f64),
                },
                WriteValue {
                    node_id: NodeId::new(3, "\"DB1\".\"Mode\""),
                    attribute_id: AttributeId::Value as u32,
                    index_range: Default::default(),
                    value: DataValue::new_now(Variant::from(vec![1i32, 2, 3])),
                },
            ]),
        }
        .into()
    }

    #[test]
    fn write_events_carry_item_results() {
        let plan = plan(&write_request()).unwrap();
        let response: ResponseMessage = WriteResponse {
            response_header: ResponseHeader::new_good(42),
            results: Some(vec![StatusCode::Good, StatusCode::BadUserAccessDenied]),
            diagnostic_infos: None,
        }
        .into();
        let events = plan.events(&response);
        assert_eq!(events.len(), 2);
        let AuditEvent::Write {
            request_handle,
            node_id,
            attribute,
            new_value,
            status,
            ..
        } = &events[0]
        else {
            panic!("expected a write event");
        };
        assert_eq!(*request_handle, 42);
        assert_eq!(node_id, "ns=3;s=\"DB1\".\"Setpoint\"");
        assert_eq!(attribute, "Value");
        assert_eq!(new_value.data_type, "Double");
        assert_eq!(new_value.value, json!(12.5));
        assert_eq!(status, "Good");

        let AuditEvent::Write {
            new_value, status, ..
        } = &events[1]
        else {
            panic!("expected a write event");
        };
        assert_eq!(new_value.data_type, "Int32[]");
        assert_eq!(new_value.value, json!([1, 2, 3]));
        assert_eq!(status, "BadUserAccessDenied");
    }

    #[test]
    fn service_fault_applies_to_all_items() {
        let plan = plan(&write_request()).unwrap();
        let fault: ResponseMessage =
            opcua::types::ServiceFault::new(42, StatusCode::BadSessionIdInvalid).into();
        for event in plan.events(&fault) {
            let AuditEvent::Write { status, .. } = event else {
                panic!("expected a write event");
            };
            assert_eq!(status, "BadSessionIdInvalid");
        }
    }

    #[test]
    fn pre_read_fills_old_values_and_names() {
        let names = NameCache::default();
        let mut plan = plan(&write_request()).unwrap();
        let pre = plan.pre_read(true, &names).unwrap();
        // Old value + display name for each of the two nodes.
        assert_eq!(pre.nodes_to_read.len(), 4);
        let results = vec![
            DataValue::new_now(10.0f64),
            DataValue::new_now(opcua::types::LocalizedText::from("Setpoint")),
            DataValue {
                status: Some(StatusCode::BadUserAccessDenied),
                ..Default::default()
            },
            DataValue::new_now(opcua::types::LocalizedText::from("Mode")),
        ];
        plan.apply_pre_read(pre, &results, &names);
        let response: ResponseMessage = WriteResponse {
            response_header: ResponseHeader::new_good(42),
            results: Some(vec![StatusCode::Good, StatusCode::Good]),
            diagnostic_infos: None,
        }
        .into();
        let events = plan.events(&response);
        let AuditEvent::Write {
            old_value,
            display_name,
            ..
        } = &events[0]
        else {
            unreachable!()
        };
        assert_eq!(old_value.as_ref().unwrap().value, json!(10.0));
        assert_eq!(display_name.as_deref(), Some("Setpoint"));
        let AuditEvent::Write { old_value, .. } = &events[1] else {
            unreachable!()
        };
        assert!(old_value.is_none(), "unreadable old value stays empty");

        // Names come from the cache the second time.
        let mut plan = super::plan(&write_request()).unwrap();
        let pre = plan.pre_read(false, &names);
        assert!(pre.is_none());
    }

    /// Audit finding R5: a client chooses the value, so it must not decide
    /// how large the audit record gets.
    #[test]
    fn huge_values_are_truncated() {
        let big = audit_value(&Variant::from("x".repeat(5 * 1024 * 1024)));
        assert!(big.value.to_string().len() < 2 * MAX_TEXT);
        assert_eq!(big.value["truncated"], json!(true));

        let array = audit_value(&Variant::from(vec![1i32; 1_000_000]));
        assert!(array.value.to_string().len() < 4 * 1024);
        assert_eq!(array.value["length"], json!(1_000_000));

        let strings = audit_value(&Variant::from(vec!["y".repeat(1000); 256]));
        assert!(strings.value.to_string().len() <= MAX_VALUE_JSON + 2 * MAX_TEXT);
    }

    #[test]
    fn reads_are_not_audited() {
        let read: RequestMessage = opcua::types::ReadRequest::default().into();
        assert!(plan(&read).is_none());
    }
}
