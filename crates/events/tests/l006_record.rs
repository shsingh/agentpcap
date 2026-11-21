// L006 — the event record contract: required fields present, `mode` and
// `verdict` constrained to the spec enumerations, `schema_version` pinned.
// Spec: docs/spec.md#4-event-record-schema.

use agentpcap_events::{Event, Mode, Verdict};

#[test]
fn l006_required_fields_serialize() {
    let e = Event {
        ts: "2026-11-21T07:00:00Z".into(),
        host: "lap-1".into(),
        process: "agent-mcp-client".into(),
        pid: 42,
        transport: "stdio-pipe".into(),
        mode: Mode::Attributed,
        verdict: Verdict::Mcp,
        event: "tools-call".into(),
        method: Some("tools/call".into()),
        tool_name: Some("read".into()),
        cap_fingerprint: Some("ab12cd34".into()),
        protocol_version: Some("2025-11-25".into()),
        session_id: Some("s-1".into()),
        peer: "pipe:1234->1235".into(),
        dedup: "5t-1".into(),
        evidence: Some(vec!["stdio-pipe".into()]),
        source: "tap".into(),
        payload: None,
        schema_version: "1.0".into(),
    };
    let v = serde_json::to_value(&e).unwrap();
    for k in ["ts", "host", "process", "pid", "transport", "mode", "verdict",
              "event", "peer", "dedup", "schema_version", "source"] {
        assert!(v.get(k).is_some(), "required field {k} missing");
    }
    assert_eq!(v["mode"].as_str().unwrap(), "attributed");
    assert_eq!(v["verdict"].as_str().unwrap(), "mcp");
}

#[test]
fn l006_enumerations_serialise_to_spec_forms() {
    assert_eq!(serde_json::to_value(Mode::Opaque).unwrap(), "opaque");
    assert_eq!(serde_json::to_value(Verdict::AgentUnidentified).unwrap(), "agent-unidentified");
    assert_eq!(serde_json::to_value(Verdict::A2a).unwrap(), "a2a");
    assert_eq!(serde_json::to_value(Verdict::Other).unwrap(), "other");
}
