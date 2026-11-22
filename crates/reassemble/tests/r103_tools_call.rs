// R103 — the tools-call session event: tool_name carries the request's
// params.name; the result text rides the merged payload.
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
        comm: "client".into(),
        payload,
        tap_evidence: vec!["stdio-pipe".into()],
    }
}

#[test]
fn r103_the_tools_call_record_carries_the_tool_name_and_result() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    let req = json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "read", "arguments": {"path": "/etc/hostname"}}
    });
    let resp = json!({
        "jsonrpc": "2.0", "id": 3,
        "result": {"content": [{"type": "text", "text": "hello-from-read"}]}
    });
    let parked = r.feed(frame("pipe:100", 3001, 100, req));
    assert!(parked.is_empty());
    let out = r.feed(frame("pipe:101", 4002, 3001, resp));
    assert_eq!(out.len(), 1);
    let ev = &out[0];
    assert_eq!(ev.event, "tools-call");
    assert_eq!(ev.verdict, Verdict::Mcp);
    assert_eq!(ev.tool_name.as_deref(), Some("read"));
    assert_eq!(
        ev.payload.as_ref().unwrap()["result"]["content"][0]["text"],
        json!("hello-from-read")
    );
    assert!(ev.dedup.starts_with("stdio-pipe:pipe-pair:3001:4002:tools-call:3@"));
}
