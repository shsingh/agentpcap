// R121 — the reply-side header faces: a Streamable HTTP reply carries
// Mc-Session-Id and MCP-Protocol-Version; the merged event's session id
// prefers the reply-observed http-session face and the version face
// rides the evidence even when the request's side carried none.
// Spec: docs/spec.md#5-collectors (the Streamable HTTP MUST),
// docs/spec.md#6-classification.

use agentpcap_events::{Mode, Verdict};
use agentpcap_reassemble::{Frame, Reassembler};
use serde_json::json;

fn frame(peer: &str, pid: u32, ppid: u32, payload: serde_json::Value, evidence: Vec<String>) -> Frame {
    Frame {
        transport: "stdio-pipe".into(),
        peer: peer.into(),
        pid,
        ppid,
        comm: "client".into(),
        payload,
        tap_evidence: evidence,
    }
}

#[test]
fn r121_the_reply_side_headers_face_the_record() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());

    // the tools/call request rides the socket class with its endpoint
    // faces and NO header faces
    let req = json!({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "read", "arguments": {}}
    });
    let req_ev = vec![
        "local-end:127.0.0.1:40000".to_string(),
        "remote-end:127.0.0.1:8443".to_string(),
        "probe-face:send".to_string(),
    ];
    assert!(r.feed(frame("net-1.tcp:127.0.0.1:40000=tcp:127.0.0.1:8443", 3001, 100, req, req_ev)).is_empty());

    // the reply carries the header faces ONLY: the session id and the
    // version the reply observed face the merged record
    let resp = json!({
        "jsonrpc": "2.0", "id": 9,
        "result": {"content": [{"type": "text", "text": "r121"}]}
    });
    let resp_ev = vec![
        "local-end:127.0.0.1:40000".to_string(),
        "remote-end:127.0.0.1:8443".to_string(),
        "probe-face:receive".to_string(),
        "http-session:sess-r121".to_string(),
        "http-version:2025-06-18".to_string(),
    ];
    let bound = r.feed(frame(
        "net-1.tcp:127.0.0.1:40000=tcp:127.0.0.1:8443",
        100,
        3001,
        resp,
        resp_ev,
    ));
    assert_eq!(bound.len(), 1, "the reply binds its request");
    let ev = &bound[0];
    assert_eq!(ev.verdict, Verdict::Mcp);
    eprintln!(
        "r121 receipt: session={:?} evidence={:?}",
        ev.session_id, ev.evidence
    );
    // the merged record's session id rides the REPLY-observed header
    assert!(
        ev.session_id
            .as_deref()
            .map(|s| s.contains("http-session:sess-r121"))
            .unwrap_or(false),
        "the reply's session id faces the record"
    );
    // the version face the reply observed rides the evidence
    assert!(
        ev.evidence
            .as_ref()
            .map(|e| e.iter().any(|x| x == "http-version:2025-06-18"))
            .unwrap_or(false),
        "the reply's version face rides the evidence"
    );
}
