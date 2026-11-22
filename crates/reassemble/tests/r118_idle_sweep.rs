// R118 — the idle face: a request parked longer than the ttl rides the
// no-response face once at the sweep and then leaves the pending map;
// the idle session follows. The deployed service never grows its
// in-memory faces without limit (ADR-0008).
// Spec: docs/spec.md#11-coexistence-and-flow-deduplication.

use agentpcap_events::Mode;
use agentpcap_reassemble::{Frame, Reassembler};
use serde_json::json;
use std::time::Duration;

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
fn r118_the_stale_park_rides_the_no_response_face_once() {
    let mut r = Reassembler::new_with_ttl(
        "lab-host".into(),
        Mode::Attributed,
        "tap".into(),
        Duration::from_millis(400),
    );
    let req = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    assert!(r.feed(frame("pipe:100", 700, 100, req)).is_empty());

    // inside the ttl: nothing expires
    assert!(r.sweep().is_empty());

    std::thread::sleep(Duration::from_millis(500));
    let swept = r.sweep();
    assert_eq!(swept.len(), 1, "the stale park rides the loss face");
    assert!(
        swept[0].evidence.as_ref().is_some_and(|e| e.contains(&"no-response".to_string())),
        "the no-response evidence rides"
    );
    assert_eq!(swept[0].peer, "pipe:100", "no pair bound: the raw face answers");
    // the pending face left the map: a second sweep finds nothing
    assert!(r.sweep().is_empty(), "the sweep never re-emits a stale park");
}

#[test]
fn r118_the_idle_session_expires() {
    let mut r = Reassembler::new_with_ttl(
        "lab-host".into(),
        Mode::Attributed,
        "tap".into(),
        Duration::from_millis(400),
    );
    // initialize binds a session (fingerprint + protocolVersion face)
    let init_req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let init_resp = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"protocolVersion": "2025-06-18",
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "r118-server", "version": "0"}}
    });
    assert!(r.feed(frame("pipe:100", 700, 100, init_req)).is_empty());
    let bound = r.feed(frame("pipe:101", 8002, 700, init_resp));
    assert_eq!(bound.len(), 1);
    assert_eq!(bound[0].session_id.as_deref(), Some("pipe-pair:700:8002"));

    std::thread::sleep(Duration::from_millis(500));
    // the sweep expires the idle session (nothing pending: empty out)
    assert!(r.sweep().is_empty());
    // a later notify on the channel falls back to the parent-pair face
    // (no pair bound, the pending bucket followed the request out) — a
    // stale fingerprint never rides a post-expiry face
    let note = json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {}});
    let out = r.feed(frame("pipe:100", 700, 100, note));
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0].session_id.as_deref(),
        Some("pipe-pair:100:700"),
        "the expired session falls back to the parent-pair face"
    );
    assert!(
        out[0].cap_fingerprint.is_none(),
        "no stale fingerprint rides the post-expiry face"
    );
}
