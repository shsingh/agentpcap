// R115 — the framing face: the verdict requires valid JSON-RPC
// framing. A frame with a broken `jsonrpc` member never receives
// `mcp` or `a2a` from its method name, in the merged record, on the
// flush face, or on notifications. Spec: docs/spec.md#6-classification.

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
fn r115_the_unframed_pair_stays_agent_unidentified() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // the probe's text filter admits it: `{` plus the `jsonrpc` member
    // inside the sniff window - but the member's face is broken
    let req = json!({"jsonrpc": null, "id": 7, "method": "tools/call",
                     "params": {"name": "read"}});
    let resp = json!({"jsonrpc": null, "id": 7,
                      "result": {"content": [{"text": "done"}]}});
    assert!(r.feed(frame("pipe:100", 700, 100, req)).is_empty());
    let out = r.feed(dying(frame("pipe:999", 4002, 0, resp)));
    assert_eq!(out.len(), 1, "the pair still merges, unframed and honest");
    assert_eq!(out[0].verdict, Verdict::AgentUnidentified);
    assert_eq!(out[0].event, "unidentified");
    assert_eq!(out[0].method.as_deref(), Some("tools/call"));
}

#[test]
fn r115_the_unframed_flush_stays_agent_unidentified() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    let req = json!({"jsonrpc": 2.0, "id": 8, "method": "tools/list", "params": {}});
    assert!(r.feed(frame("pipe:100", 700, 100, req)).is_empty());
    let flushed = r.flush();
    assert_eq!(flushed.len(), 1);
    assert_eq!(flushed[0].verdict, Verdict::AgentUnidentified);
    assert_eq!(flushed[0].event, "unidentified");
}

#[test]
fn r115_the_unframed_notification_stays_agent_unidentified() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    let note = json!({"jsonrpc": 3.0, "method": "notifications/message", "params": {}});
    let out = r.feed(frame("pipe:101", 4002, 3001, note));
    assert_eq!(out.len(), 1, "the notification emits on arrival");
    assert_eq!(out[0].verdict, Verdict::AgentUnidentified);
    assert_eq!(out[0].event, "unidentified");
}
