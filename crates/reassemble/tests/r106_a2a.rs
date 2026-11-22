// R106 — the A2A face: message/send frames classify verdict `a2a` with
// the a2a-handoff event, from protocol semantics, never a catalog.
// Spec: docs/spec.md#6-classification.

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
fn r106_the_message_send_pair_carries_the_a2a_handoff() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    let req = json!({
        "jsonrpc": "2.0", "id": 7, "method": "message/send",
        "params": {"message": {"role": "agent", "parts": []}}
    });
    let resp = json!({
        "jsonrpc": "2.0", "id": 7,
        "result": {"id": "task-1", "status": {"state": "submitted"}}
    });
    assert!(r.feed(frame("pipe:100", 3001, 100, req)).is_empty());
    let out = r.feed(frame("pipe:101", 4002, 3001, resp));
    assert_eq!(out.len(), 1);
    let ev = &out[0];
    assert_eq!(ev.verdict, Verdict::A2a);
    assert_eq!(ev.event, "a2a-handoff");
    assert_eq!(ev.method.as_deref(), Some("message/send"));
    assert_eq!(ev.dedup, "stdio-pipe:pipe-pair:3001:4002:a2a-handoff:7");
}
