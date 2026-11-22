// R112 — the completed-id face: a bound id's empty vec leaves the
// pending map, so a later client's ride of the same id binds through
// the by-id fallback without the stale face blocking it. The
// scenario: A completes id 1 through its pairing; B parks id 1; B's
// dying writer needs the fallback; the bind lands on B's request.
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

fn dying(mut frame: Frame) -> Frame {
    frame.tap_evidence.push("fd-unresolved-at-pop".into());
    frame
}

#[test]
fn r112_the_completed_id_leaves_the_map_and_the_reused_id_still_binds() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // client A parks id 1 and completes it through its pairing parent
    let req_a = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    let resp_a = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"tools": [{"name": "read", "description": "read a file"}]}
    });
    assert!(r.feed(frame("pipe:100", 1001, 100, req_a)).is_empty());
    let bound = r.feed(frame("pipe:101", 2002, 1001, resp_a));
    assert_eq!(bound.len(), 1, "A's pair binds");
    assert_eq!(bound[0].peer, "pipe-pair:1001:2002");
    // client B parks id 1 later; B's writer dies inside the window so
    // the response needs the by-id fallback
    let req_b = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "fetch", "arguments": {}}});
    let resp_b = json!({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"text": "b-ok"}]}});
    assert!(r.feed(frame("pipe:200", 3003, 100, req_b)).is_empty());
    let out = r.feed(dying(frame("pipe:999", 4004, 0, resp_b)));
    assert_eq!(out.len(), 1, "B's response binds through the fallback");
    let ev = &out[0];
    assert_eq!(ev.verdict, Verdict::Mcp);
    assert_eq!(ev.event, "tools-call");
    assert_eq!(ev.tool_name.as_deref(), Some("fetch"));
    assert_eq!(
        ev.payload.as_ref().unwrap()["result"]["content"][0]["text"],
        json!("b-ok")
    );
    assert_eq!(ev.peer, "pipe:200", "the bind keys B's own channel");
    // nothing stale rides: the flush has nothing left to answer
    assert!(r.flush().is_empty(), "the pending state stays clean");
}
