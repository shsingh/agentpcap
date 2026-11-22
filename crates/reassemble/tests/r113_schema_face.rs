// R113 — the schema face and the flush time face (ADR-0007): the
// reassembled records carry schema_version 2.0, and the flush face
// stamps the request's observation time, never the capture window's
// end. Spec: docs/spec.md#4-event-record-schema.

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
fn r113_the_session_face_carries_2_0_and_the_flush_rides_the_observation_time() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // a bound pair: the merged record carries the 2.0 face
    let req = json!({"jsonrpc": "2.0", "id": 41, "method": "tools/list", "params": {}});
    let resp = json!({"jsonrpc": "2.0", "id": 41, "result": {"tools": []}});
    assert!(r.feed(frame("pipe:100", 700, 100, req)).is_empty());
    let bound = r.feed(frame("pipe:101", 4002, 700, resp));
    assert_eq!(bound.len(), 1);
    assert_eq!(
        bound[0].schema_version, "2.0",
        "the session-event face carries the 2.0 version"
    );
    // a lost request parks long before the flush: its flush record
    // stamps the observation time, not the window's end - the strict
    // reject: a capture-end face would stamp the same second as the
    // gate, and `ev.ts < gate` would fail
    let early = json!({"jsonrpc": "2.0", "id": 42, "method": "initialize", "params": {}});
    assert!(r.feed(frame("pipe:102", 700, 100, early)).is_empty());
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let flush_moment = agentpcap_ledger::now_rfc3339();
    let flushed = r.flush();
    assert_eq!(flushed.len(), 1);
    let ev = &flushed[0];
    assert_eq!(
        ev.schema_version, "2.0",
        "the flush face carries the 2.0 version"
    );
    assert!(
        ev.ts < flush_moment,
        "the flush stamps the observation time, strictly before the gate: ts={} gate={flush_moment}",
        ev.ts
    );
}
