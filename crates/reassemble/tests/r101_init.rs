// R101 — the init session event: the initialize request and its result
// merge into one record; the capability fingerprint hashes the result's
// capabilities by the ledger hash rule; protocolVersion rides evidence.
// Spec: docs/spec.md#6-classification, docs/spec.md#4-event-record-schema.

use agentpcap_events::{Mode, Verdict};
use agentpcap_reassemble::{capability_fingerprint, Frame, Reassembler};
use serde_json::json;

fn frame(peer: &str, pid: u32, ppid: u32, payload: serde_json::Value) -> Frame {
    Frame {
        transport: "stdio-pipe".into(),
        peer: peer.into(),
        pid,
        ppid,
        comm: "test".into(),
        payload,
        tap_evidence: vec!["stdio-pipe".into(), format!("lineage:parent-{ppid}")],
    }
}

#[test]
fn r101_the_initialize_pair_merges_into_one_init_event() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    let req = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "cell-client", "version": "0"}}
    });
    let resp = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "cell-server", "version": "0"}
        }
    });
    // the client writes the request on channel A; the child server
    // (parent 1001) answers on channel B
    let none = r.feed(frame("pipe:100", 1001, 100, req));
    assert!(none.is_empty(), "a request parks, no event yet");
    let out = r.feed(frame("pipe:101", 2002, 1001, resp));
    assert_eq!(out.len(), 1, "the response binds the pair and emits");
    let ev = &out[0];
    assert_eq!(ev.event, "init");
    assert_eq!(ev.verdict, Verdict::Mcp);
    assert_eq!(ev.method.as_deref(), Some("initialize"));
    let caps = json!({"tools": {}});
    assert_eq!(
        ev.cap_fingerprint.as_deref(),
        Some(capability_fingerprint(&caps).as_str()),
        "the fingerprint recomputes from the server capabilities"
    );
    assert_eq!(ev.protocol_version.as_deref(), Some("2025-06-18"));
    assert_eq!(
        ev.payload.as_ref().unwrap()["result"]["serverInfo"]["name"],
        json!("cell-server"),
        "the merged payload carries the result half"
    );
    assert_eq!(
        ev.payload.as_ref().unwrap()["request"]["method"],
        json!("initialize"),
        "the merged payload carries the request half"
    );
    assert_eq!(ev.peer, "pipe-pair:1001:2002");
    assert_eq!(ev.session_id.as_deref(), Some("pipe-pair:1001:2002"));
    assert!(ev.dedup.starts_with("stdio-pipe:pipe-pair:1001:2002:init:1@"));
    let evidence = ev.evidence.as_ref().unwrap();
    assert!(
        evidence.contains(&"reassembled:init".to_string())
            && evidence.iter().any(|e| e.starts_with("chan:pipe:")),
        "the evidence carries the reassembly line and both channels"
    );
    assert_eq!(ev.mode, Mode::Attributed);
    assert_eq!(ev.pid, 1001, "the record names the request writer");
    assert_eq!(ev.process, "test");
}
