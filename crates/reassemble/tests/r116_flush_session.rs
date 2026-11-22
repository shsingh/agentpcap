// R116 — the flush-session resolve: after a pair binds on a channel,
// a later unanswered request on that channel keys the BOUND session
// (pipe-pair face with the fingerprint), never a raw channel that
// reads as a separate face. Two pairs on one channel is honest
// ambiguity: the raw channel face answers.
// Spec: docs/spec.md#6-classification.

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

#[test]
fn r116_the_flush_of_a_known_channel_rides_the_bound_session() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // initialize binds the pair pipe-pair:700:8002 (the session records
    // both half channels: pipe:100 and pipe:101)
    let init_req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let init_resp = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"protocolVersion": "2025-06-18",
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "p116-server", "version": "0"}}
    });
    assert!(r.feed(frame("pipe:100", 700, 100, init_req)).is_empty());
    let bound = r.feed(frame("pipe:101", 8002, 700, init_resp));
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].peer, "pipe-pair:700:8002");
    let fingerprint = bound[0].cap_fingerprint.clone().expect("the fused face");
    // a later tools/call on the same request channel never answers
    let call_req = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                          "params": {"name": "fetch"}});
    assert!(r.feed(frame("pipe:100", 700, 100, call_req)).is_empty());
    let flushed = r.flush();
    assert_eq!(flushed.len(), 1);
    let ev = &flushed[0];
    assert_eq!(
        ev.session_id.as_deref(),
        Some("pipe-pair:700:8002"),
        "the flush keys the bound session"
    );
    assert_eq!(
        ev.cap_fingerprint.as_deref(),
        Some(fingerprint.as_str()),
        "the flush carries the session's capability face"
    );
    let evidence = ev.evidence.as_ref().unwrap().clone();
    assert!(evidence.contains(&"no-response".to_string()));
}

#[test]
fn r116_the_ambiguous_channel_answers_its_raw_face() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // two servers bind two pairs from the SAME request channel face:
    // a later lost on that channel is honest ambiguity, the raw face
    let req1 = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    let req2 = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}});
    let r1 = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}});
    let r2 = json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}});
    assert!(r.feed(frame("pipe:100", 700, 100, req1)).is_empty());
    assert!(r.feed(frame("pipe:100", 700, 100, req2)).is_empty());
    let b1 = r.feed(frame("pipe:101", 8002, 700, r1));
    let b2 = r.feed(frame("pipe:102", 9003, 700, r2));
    assert_eq!(b1.len(), 1, "the first pair binds");
    assert_eq!(b2.len(), 1, "the second pair binds");
    assert_eq!(b1[0].peer, "pipe-pair:700:8002");
    assert_eq!(b2[0].peer, "pipe-pair:700:9003");
    let lost = json!({"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {}});
    assert!(r.feed(frame("pipe:100", 700, 100, lost)).is_empty());
    let flushed = r.flush();
    assert_eq!(flushed.len(), 1);
    assert_eq!(
        flushed[0].peer, "pipe:100",
        "the ambiguous channel answers its raw face"
    );
}
