// R114 — the unresolved-face rule: a dying writer's `unresolved`
// placeholder is not a session channel. A response bound through a
// dead writer never registers `unresolved` on the session, so a later
// notification from another dead writer cannot hijack the session's
// capability face. Spec: docs/spec.md#6-classification.

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
fn r114_the_placeholder_never_registers_and_never_matches() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // client A parks id 1; its writer dies inside the window; the
    // response binds through the by-id fallback - the response frame's
    // peer carries the `unresolved` placeholder
    let req_a = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let resp_a = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                   "serverInfo": {"name": "a-server", "version": "0"}}
    });
    assert!(r.feed(frame("pipe:100", 1001, 100, req_a)).is_empty());
    let bound = r.feed(dying(frame("unresolved", 2002, 0, resp_a)));
    assert_eq!(bound.len(), 1, "A's pair binds through the fallback");
    assert_eq!(
        bound[0].cap_fingerprint.is_some(),
        true,
        "A's session carries its capability face"
    );
    // a later notification from ANOTHER dead writer carries no channel:
    // it never matches A's session through a placeholder
    let note = json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {}});
    let out = r.feed(dying(frame("unresolved", 3003, 0, note)));
    assert_eq!(out.len(), 1);
    assert_ne!(
        out[0].session_id.as_deref(),
        Some(bound[0].peer.as_str()),
        "the placeholder must never resolve into A's session"
    );
    // the orphan face keeps its own session key (its own pipe-pair face
    // from the pairing parent or the client face)
    eprintln!("r114 receipt: A session={} note session={}", bound[0].peer, out[0].session_id.as_deref().unwrap_or("?"));
}
