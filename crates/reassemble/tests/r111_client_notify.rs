// R111 — the client notification face: notifications/initialized rides
// the request channel from the client itself. The record keys the
// client's own face and never a pair the client is not a member of.
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
fn r111_the_client_notification_keys_the_client_face_until_a_pair_binds() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // the client parked a request: it owns a pending bucket
    let req = json!({"jsonrpc": "2.0", "id": 31, "method": "initialize", "params": {}});
    assert!(r.feed(frame("pipe:100", 700, 100, req)).is_empty());
    let init = json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}});
    let out = r.feed(frame("pipe:100", 700, 100, init));
    assert_eq!(out.len(), 1, "the notification emits on arrival");
    // no pair has bound yet: the record keys the client's own face
    assert_eq!(out[0].session_id.as_deref(), Some("client:700"));
    let evidence = out[0].evidence.as_ref().unwrap().clone();
    assert!(
        evidence.contains(&"notification:client-side".to_string()),
        "evidence: {evidence:?}"
    );
    // the initialize response binds the pair: the session records both
    // halves' channels
    let resp = json!({
        "jsonrpc": "2.0", "id": 31,
        "result": {"protocolVersion": "2025-06-18",
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "pair-server", "version": "0"}}
    });
    let bound = r.feed(frame("pipe:101", 8002, 700, resp));
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].peer, "pipe-pair:700:8002");
    // a second client notification on the request channel now rides the
    // BOUND session, never a split face
    let again = json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {}});
    let out = r.feed(frame("pipe:100", 700, 100, again));
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].session_id.as_deref(),
        Some("pipe-pair:700:8002"),
        "the notification joins the session its channel merged into"
    );
    // the capability face rides the notification: its session's face
    assert_eq!(
        out[0].cap_fingerprint.as_deref(),
        bound[0].cap_fingerprint.as_deref(),
        "the notification shares the session's capability face"
    );
}
