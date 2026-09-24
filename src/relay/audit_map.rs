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

use crate::audit::event::{AuditEvent, AuditValue};

/// Byte strings and opaque structures longer than this are truncated in the trail.
const MAX_BYTES: usize = 4096;

/// Most node names the per-target cache keeps before it starts over.
const NAME_CACHE_SIZE: usize = 100_000;

pub struct WriteItem {
    node: NodeId,
    attribute_id: u32,
    range: NumericRange,
    node_id: String,
    attribute: String,
    index_range: Option<String>,
    new_value: AuditValue,
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
                .map(|w| WriteItem {
                    node: w.node_id.clone(),
                    attribute_id: w.attribute_id,
                    range: w.index_range.clone(),
                    old_value: None,
                    display_name: None,
                    node_id: w.node_id.to_string(),
                    attribute: attribute_name(w.attribute_id),
                    index_range: (!w.index_range.is_none()).then(|| w.index_range.to_string()),
                    new_value: w
                        .value
                        .value
                        .as_ref()
                        .map(audit_value)
                        .unwrap_or_else(|| audit_value(&Variant::Empty)),
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
                    object_id: c.object_id.to_string(),
                    method_id: c.method_id.to_string(),
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
                .map(|n| format!("{} (parent {})", n.requested_new_node_id, n.parent_node_id))
                .collect(),
        )),
        RequestMessage::DeleteNodes(r) => Some(AuditPlan::NodeManagement(
            handle,
            "DeleteNodes",
            r.nodes_to_delete
                .iter()
                .flatten()
                .map(|n| n.node_id.to_string())
                .collect(),
        )),
        RequestMessage::AddReferences(r) => Some(AuditPlan::NodeManagement(
            handle,
            "AddReferences",
            r.references_to_add
                .iter()
                .flatten()
                .map(|n| format!("{} -> {}", n.source_node_id, n.target_node_id))
                .collect(),
        )),
        RequestMessage::DeleteReferences(r) => Some(AuditPlan::NodeManagement(
            handle,
            "DeleteReferences",
            r.references_to_delete
                .iter()
                .flatten()
                .map(|n| format!("{} -> {}", n.source_node_id, n.target_node_id))
                .collect(),
        )),
        _ => None,
    }
}

impl AuditPlan {
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
            AuditPlan::HistoryUpdate(..) | AuditPlan::NodeManagement(..) => {}
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
                    let name = text.text.as_ref().to_string();
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
        }
    }

    /// The record committed before forwarding in fail-closed mode.
    pub fn intent(&self) -> AuditEvent {
        let (request_handle, node_ids) = match self {
            AuditPlan::Write(h, items) => (*h, items.iter().map(|i| i.node_id.clone()).collect()),
            AuditPlan::Call(h, items) => (*h, items.iter().map(|i| i.method_id.clone()).collect()),
            AuditPlan::HistoryUpdate(h, items) => {
                (*h, items.iter().map(|i| i.node_id.clone()).collect())
            }
            AuditPlan::NodeManagement(h, _, nodes) => (*h, nodes.clone()),
        };
        AuditEvent::ChangeIntent {
            request_handle,
            service: self.service().into(),
            node_ids,
        }
    }

    /// Events for the outcome. A service-level failure (ServiceFault or a bad
    /// service result) applies to every item.
    pub fn events(self, response: &ResponseMessage) -> Vec<AuditEvent> {
        let service_result = response.response_header().service_result;
        let item_status = |results: Option<Vec<StatusCode>>, i: usize| -> String {
            if service_result.is_bad() {
                return service_result.to_string();
            }
            results
                .and_then(|r| r.get(i).copied())
                .unwrap_or(StatusCode::BadUnexpectedError)
                .to_string()
        };

        match self {
            AuditPlan::Write(request_handle, items) => {
                let results = match response {
                    ResponseMessage::Write(r) => r.results.clone(),
                    _ => None,
                };
                items
                    .into_iter()
                    .enumerate()
                    .map(|(i, w)| AuditEvent::Write {
                        request_handle,
                        node_id: w.node_id,
                        display_name: w.display_name,
                        attribute: w.attribute,
                        index_range: w.index_range,
                        old_value: w.old_value,
                        new_value: w.new_value,
                        status: item_status(results.clone(), i),
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
                return HistoryItem { node_id: d.node_id.to_string(), details: $name.into() };
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
    AuditValue {
        data_type,
        value: json_value(v),
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
        Variant::String(s) => s.value().as_ref().map_or(Value::Null, |s| json!(s)),
        Variant::DateTime(d) => json!(d.to_string()),
        Variant::Guid(g) => json!(g.to_string()),
        Variant::StatusCode(s) => json!(s.to_string()),
        Variant::ByteString(b) => b.value.as_deref().map_or(Value::Null, bytes),
        Variant::XmlElement(x) => json!(x.to_string()),
        Variant::QualifiedName(q) => json!(q.to_string()),
        Variant::LocalizedText(t) => json!(t.text.as_ref()),
        Variant::NodeId(n) => json!(n.to_string()),
        Variant::ExpandedNodeId(n) => json!(n.to_string()),
        Variant::ExtensionObject(e) => extension_object(e),
        Variant::Variant(inner) => json_value(inner),
        Variant::DataValue(d) => d.value.as_ref().map_or(Value::Null, json_value),
        Variant::DiagnosticInfo(d) => json!(format!("{d:?}")),
        Variant::Array(a) => {
            let values: Vec<Value> = a.values.iter().map(json_value).collect();
            match &a.dimensions {
                Some(dims) if dims.len() > 1 => json!({ "dimensions": dims, "values": values }),
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

    #[test]
    fn reads_are_not_audited() {
        let read: RequestMessage = opcua::types::ReadRequest::default().into();
        assert!(plan(&read).is_none());
    }
}
