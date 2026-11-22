// R102 — the tools-list session event: the request and the result merge;
// the discovered tool names and the count ride the evidence (16 cap).
// Spec: docs/spec.md#6-classification, docs/spec.md#4-event-record-schema.

use agentpcap_events::{Mode, Verdict};
use agentpcap_reassemble::{Frame, Reassembler};
use serde_json::json;

fn frame(peer: &str, pid: u32, ppid: u32, payload: serde_json::Value) -> Frame {
    Frame {
        transport: "stdio-pipe".into(),
        peer: peer.into(),
        pid,
        ppid,
        comm: "test".into(),
        payload,
        tap_evidence: vec!["stdio-pipe".into()],
    }
}

#[test]
fn r102_the_tools_list_result_names_its_tools() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    let req = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}});
    let resp = json!({
        "jsonrpc": "2.0", "id": 2,
        "result": {"tools": [
            {"name": "read", "description": "read a file"},
            {"name": "write", "description": "write a file"}
        ]}
    });
    let parked = r.feed(frame("pipe:100", 3001, 100, req));
    assert!(parked.is_empty(), "the request parks");
    let out = r.feed(frame("pipe:101", 4002, 3001, resp));
    assert_eq!(out.len(), 1);
    let ev = &out[0];
    assert_eq!(ev.event, "tools-list");
    assert_eq!(ev.verdict, Verdict::Mcp);
    assert!(ev.dedup.starts_with("stdio-pipe:pipe-pair:3001:4002:tools-list:2@"));
    let evidence = ev.evidence.as_ref().unwrap().clone();
    assert!(evidence.contains(&"tools:2".to_string()), "evidence: {evidence:?}");
    assert!(evidence.contains(&"tool:read".to_string()) && evidence.contains(&"tool:write".to_string()));
    assert_eq!(
        ev.payload.as_ref().unwrap()["result"]["tools"][0]["name"],
        json!("read")
    );
    assert!(ev.tool_name.is_none(), "tools-list carries no single tool name");
}
