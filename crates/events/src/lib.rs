//! The event record. Normative source: `docs/spec.md#4-event-record-schema`.
//! The schema is the project's interface contract; both deployment
//! topologies emit it identically.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Attributed,
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Mcp,
    A2a,
    AgentUnidentified,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub ts: String,
    pub host: String,
    pub process: String,
    pub pid: u32,
    pub transport: String,
    pub mode: Mode,
    pub verdict: Verdict,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub peer: String,
    pub dedup: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Vec<String>>,
    pub source: String,
    pub schema_version: String,
}
