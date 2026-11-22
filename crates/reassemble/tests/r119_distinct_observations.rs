// R119 — separate observations never share a key: two identical
// notifications inside one second ride distinct observation numbers,
// so both land in the ledger (the writer refuses replays, not
// repeated observations).
// Spec: docs/spec.md#11-coexistence-and-flow-deduplication.

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
fn r119_identical_notifications_keep_distinct_keys() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // the initialize binds the session (the fingerprint face rides)
    let init_req = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
    let init_resp = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"protocolVersion": "2025-06-18",
                   "capabilities": {"tools": {}},
                   "serverInfo": {"name": "r119-server", "version": "0"}}
    });
    assert!(r.feed(frame("pipe:100", 700, 100, init_req)).is_empty());
    let bound = r.feed(frame("pipe:101", 8002, 700, init_resp));
    assert_eq!(bound.len(), 1);

    // two IDENTICAL notifications back-to-back (same second face)
    let note = json!({"jsonrpc": "2.0", "method": "notifications/message",
                      "params": {"level": "info"}});
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let first = r.feed(frame("pipe:100", 700, 100, note.clone()));
    let second = r.feed(frame("pipe:100", 700, 100, note));
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert!(
        first[0].dedup != second[0].dedup,
        "separate observations never share a key: {} vs {}",
        first[0].dedup,
        second[0].dedup
    );
    assert_eq!(first[0].session_id.as_deref(), Some("pipe-pair:700:8002"));
    assert_eq!(second[0].session_id.as_deref(), Some("pipe-pair:700:8002"));
}
