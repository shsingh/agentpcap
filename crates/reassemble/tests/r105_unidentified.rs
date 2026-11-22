// R105 — unidentified-flow events as first-class records: an orphan
// response (no pending request), the unframed shape, and the burst
// cadence evidence. The absence of MCP-Protocol-Version never
// produces the verdict by itself. Spec: docs/spec.md#6-classification.

use agentpcap_events::{Mode, Verdict};
use agentpcap_reassemble::{Frame, Reassembler};
use serde_json::json;

fn frame(peer: &str, pid: u32, ppid: u32, payload: serde_json::Value) -> Frame {
    Frame {
        transport: "stdio-pipe".into(),
        peer: peer.into(),
        pid,
        ppid,
        comm: "some-writer".into(),
        payload,
        tap_evidence: vec!["stdio-pipe".into()],
    }
}

#[test]
fn r105_agent_shaped_frames_without_a_bind_stay_first_class() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // the orphan response: a result with no pending request
    let orphan = json!({"jsonrpc": "2.0", "id": 9, "result": {"content": []}});
    let out = r.feed(frame("pipe:101", 4002, 3001, orphan));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].verdict, Verdict::AgentUnidentified);
    assert_eq!(out[0].event, "unidentified");
    let evidence = out[0].evidence.as_ref().unwrap().clone();
    assert!(evidence.contains(&"orphan-response".to_string()), "evidence: {evidence:?}");
    assert_eq!(out[0].pid, 4002, "the record names its writer");
    // a second agent-shaped frame inside the window rides the cadence
    let again = json!({"jsonrpc": "2.0", "id": 10, "result": {"content": []}});
    let out = r.feed(frame("pipe:101", 4002, 3001, again));
    assert_eq!(out.len(), 1);
    let evidence = out[0].evidence.as_ref().unwrap().clone();
    assert!(
        evidence.contains(&"cadence:burst-2-in-1s".to_string()),
        "evidence: {evidence:?}"
    );
    // the unframed shape: agent-shaped JSON with no protocol face
    let unframed = json!({"tool_calls": 3, "stream": true});
    let out = r.feed(frame("pipe:102", 5001, 100, unframed));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].verdict, Verdict::AgentUnidentified);
    let evidence = out[0].evidence.as_ref().unwrap().clone();
    assert!(evidence.contains(&"request-shape:unframed".to_string()));
}
