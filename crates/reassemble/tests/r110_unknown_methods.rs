// R110 — the unknown method face: a matched pair whose method carries
// no MCP or A2A protocol semantics records verdict agent-unidentified,
// from the protocol semantics, never a catalog. The event face stays
// `unidentified`.
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
fn r110_the_unknown_method_pair_stays_agent_unidentified() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    let req = json!({"jsonrpc": "2.0", "id": 21, "method": "browser/search", "params": {}});
    let resp = json!({"jsonrpc": "2.0", "id": 21, "result": {"hits": 3}});
    assert!(r.feed(frame("pipe:100", 700, 100, req)).is_empty());
    let out = r.feed(dying(frame("pipe:999", 4002, 0, resp)));
    assert_eq!(out.len(), 1, "the pair still merges, the faces stay honest");
    let ev = &out[0];
    assert_eq!(ev.event, "unidentified");
    assert_eq!(ev.verdict, agentpcap_events::Verdict::AgentUnidentified);
}

#[test]
fn r110_the_task_handoff_prefix_rides_a2a() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    let req = json!({"jsonrpc": "2.0", "id": 22, "method": "tasks/cancel", "params": {}});
    let resp = json!({"jsonrpc": "2.0", "id": 22, "result": {"state": "done"}});
    assert!(r.feed(frame("pipe:100", 700, 100, req)).is_empty());
    let out = r.feed(dying(frame("pipe:999", 4002, 0, resp)));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].verdict, agentpcap_events::Verdict::A2a);
    assert_eq!(out[0].event, "a2a-handoff");
}
