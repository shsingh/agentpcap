// R117 — the session-resolution faces the multi-server client rides:
// (1) a notification on a channel two pairs share keys the client face
// (never an arbitrary pair); (2) a dying writer's by-id fallback after
// the initialize binds carries the BOUND session's face - its
// fingerprint and protocol version ride, never a separate raw face.
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

fn dying(mut frame: Frame) -> Frame {
    frame.tap_evidence.push("fd-unresolved-at-pop".into());
    frame
}

#[test]
fn r117_the_shared_channel_notification_keys_the_client_face() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // two servers bind two pairs from ONE request channel (the shared
    // face)
    let req1 = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    let req2 = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}});
    let r1 = json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": []}});
    let r2 = json!({"jsonrpc": "2.0", "id": 2, "result": {"tools": []}});
    assert!(r.feed(frame("pipe:100", 700, 100, req1)).is_empty());
    assert!(r.feed(frame("pipe:100", 700, 100, req2)).is_empty());
    let b1 = r.feed(frame("pipe:101", 8002, 700, r1));
    let b2 = r.feed(frame("pipe:102", 9003, 700, r2));
    assert_eq!(b1[0].peer, "pipe-pair:700:8002");
    assert_eq!(b2[0].peer, "pipe-pair:700:9003");
    // a client notification on the shared channel: two pairs match the
    // channel, the evidence identifies none - the client face answers,
    // never an arbitrary session
    let note = json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {}});
    let out = r.feed(frame("pipe:100", 700, 100, note));
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].session_id.as_deref(),
        Some("client:700"),
        "the shared channel never picks an arbitrary pair"
    );
    assert!(
        out[0].cap_fingerprint.is_none(),
        "no foreign fingerprint rides the ambiguous face"
    );
}

#[test]
fn r117_the_dying_writer_fallback_carries_the_bound_session() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // initialize binds the pair
    let init_req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let init_resp = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"protocolVersion": "2025-06-18",
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "r117-server", "version": "0"}}
    });
    assert!(r.feed(frame("pipe:100", 700, 100, init_req)).is_empty());
    let bound = r.feed(frame("pipe:101", 8002, 700, init_resp));
    assert_eq!(bound.len(), 1);
    let fingerprint = bound[0].cap_fingerprint.clone().expect("the fused face");
    // a later tools/call parks; the server exits before the tap pops
    // its fd: the dying writer's by-id fallback carries the BOUND
    // session's face
    let call_req = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                          "params": {"name": "fetch"}});
    let call_resp = json!({"jsonrpc": "2.0", "id": 2,
                           "result": {"content": [{"text": "ok"}]}});
    assert!(r.feed(frame("pipe:100", 700, 100, call_req)).is_empty());
    let out = r.feed(dying(frame("pipe:999", 9004, 0, call_resp)));
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].session_id.as_deref(),
        Some("pipe-pair:700:8002"),
        "the fallback carries the bound session"
    );
    assert_eq!(
        out[0].cap_fingerprint.as_deref(),
        Some(fingerprint.as_str()),
        "the session's fingerprint rides the fallback merge"
    );
    assert_eq!(out[0].protocol_version.as_deref(), Some("2025-06-18"));
}
