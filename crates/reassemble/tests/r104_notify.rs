// R104 — the notify session event: a server-initiated notification
// emits on arrival, keyed by the pipe pair.
// Spec: docs/spec.md#6-classification, docs/spec.md#4-event-record-schema.

use agentpcap_events::{Mode, Verdict};
use agentpcap_reassemble::{Frame, Reassembler};
use serde_json::json;

fn frame(peer: &str, pid: u32, ppid: u32, payload: serde_json::Value) -> Frame {
    Frame {
        transport: "stdio-pipe".into(),
        peer: peer.into(),
        pid,
        ppid,
        comm: "server".into(),
        payload,
        tap_evidence: vec!["stdio-pipe".into()],
    }
}

#[test]
fn r104_the_server_notification_emits_on_arrival() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    let note = json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {}});
    let out = r.feed(frame("pipe:101", 4002, 3001, note));
    assert_eq!(out.len(), 1, "the notification needs no response");
    let ev = &out[0];
    assert_eq!(ev.event, "notify");
    assert_eq!(ev.verdict, Verdict::Mcp);
    assert_eq!(ev.pid, 4002, "the record names the server as the writer");
    assert_eq!(ev.session_id.as_deref(), Some("pipe-pair:3001:4002"));
    let second = r.feed(frame(
        "pipe:101",
        4002,
        3001,
        json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {}}),
    ));
    assert_eq!(second.len(), 1);
    assert_ne!(
        second[0].dedup, ev.dedup,
        "two notifications keep distinct dedupe keys"
    );
}
