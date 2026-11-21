// R108 — the error face: a matched JSON-RPC error response keeps its
// error object in the merged payload and carries the error-response
// evidence. Spec: docs/spec.md#4-event-record-schema
// (capture scope never narrows silently).

use agentpcap_events::Mode;
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

fn dying(mut frame: Frame) -> Frame {
    // the writer died inside the pop window: the by-id fallback's face
    frame.tap_evidence.push("fd-unresolved-at-pop".into());
    frame
}

#[test]
fn r108_the_error_response_keeps_its_error_object() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    let req = json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                     "params": {"name": "gone", "arguments": {}}});
    let resp = json!({
        "jsonrpc": "2.0", "id": 4,
        "error": {"code": -32601, "message": "Method not found"}
    });
    assert!(r.feed(frame("pipe:100", 3001, 100, req)).is_empty());
    // the server died inside the window: the by-id fallback binds
    let out = r.feed(dying(frame("pipe:999", 4002, 0, resp)));
    assert_eq!(out.len(), 1, "the error response binds");
    let ev = &out[0];
    assert_eq!(ev.event, "tools-call");
    assert_eq!(
        ev.payload.as_ref().unwrap()["result"]["code"],
        json!(-32601),
        "the error object rides the merged payload"
    );
    assert_eq!(
        ev.payload.as_ref().unwrap()["result"]["message"],
        json!("Method not found")
    );
    let evidence = ev.evidence.as_ref().unwrap().clone();
    assert!(
        evidence.contains(&"error-response".to_string()),
        "evidence: {evidence:?}"
    );
}
