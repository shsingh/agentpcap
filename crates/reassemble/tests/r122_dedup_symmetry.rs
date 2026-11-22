// R122 — the reply's ENDPOINT-COPY symmetry: one reply observed at BOTH
// endpoints (the requester's receive face and the replying server's
// send face) binds once — the duplicate check and the completed face
// both compare the PROBE-FACE-SELECTED requester, so the second copy
// drops and no extra orphan-response rides.
// Spec: docs/spec.md#6-classification (ADR-0005 direction faces).

use agentpcap_events::Mode;
use agentpcap_reassemble::{Frame, Reassembler};
use serde_json::json;

fn frame(peer: &str, pid: u32, ppid: u32, payload: serde_json::Value, evidence: Vec<String>) -> Frame {
    Frame {
        transport: "tcp".into(),
        peer: peer.into(),
        pid,
        ppid,
        comm: "client".into(),
        payload,
        tap_evidence: evidence,
    }
}

fn req_payload() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "read", "arguments": {}}
    })
}

fn reply_payload() -> serde_json::Value {
    json!({"jsonrpc": "2.0", "id": 3, "result": {"content": "r122-done"}})
}

#[test]
fn r122_the_reply_copy_drops_once_symmetrically() {
    let mut r = Reassembler::new("host".into(), Mode::Attributed, "test".into());
    let peer = "net-1.tcp:127.0.0.1:40001=tcp:127.0.0.1:8443";

    // the request parks through the SEND face (the requester's local
    // face rides sock_local)
    let req_ev = vec![
        "local-end:127.0.0.1:40001".to_string(),
        "remote-end:127.0.0.1:8443".to_string(),
        "probe-face:send".to_string(),
    ];
    assert!(r
        .feed(frame(peer, 3001, 100, req_payload(), req_ev))
        .is_empty());

    // the request's OTHER endpoint copy (the replying server's read
    // face of the same request): probe faces differ, bodies match —
    // the observation-merge face drops it, one park per call
    let req_copy_ev = vec![
        "local-end:127.0.0.1:8443".to_string(),
        "remote-end:127.0.0.1:40001".to_string(),
        "probe-face:receive".to_string(),
    ];
    assert!(r
        .feed(frame(peer, 100, 3001, req_payload(), req_copy_ev))
        .is_empty());

    // the reply's send copy (the replying server's face) binds
    let resp_send = vec![
        "local-end:127.0.0.1:8443".to_string(),
        "remote-end:127.0.0.1:40001".to_string(),
        "probe-face:send".to_string(),
    ];
    let bound = r.feed(frame(peer, 100, 3001, reply_payload(), resp_send));
    let merged: Vec<_> = bound.into_iter().filter(|e| e.event == "tools-call").collect();
    assert_eq!(merged.len(), 1, "the reply binds its request once");

    // the reply's RECEIVE copy (the requesting client's face
    // observation of the SAME reply body) drops at the completed face:
    // the completed entry stores the send-face requester, and the
    // receive copy's PROBE-FACE-SELECTED requester names the SAME face
    let resp_recv = vec![
        "local-end:127.0.0.1:40001".to_string(),
        "remote-end:127.0.0.1:8443".to_string(),
        "probe-face:receive".to_string(),
    ];
    let copy: Vec<_> = r
        .feed(frame(peer, 3001, 100, reply_payload(), resp_recv))
        .into_iter()
        .filter(|e| e.event == "orphan-response")
        .collect();
    eprintln!("r122 receipt: orphan rows for the reply's endpoint copy={}", copy.len());
    assert!(
        copy.is_empty(),
        "the same reply's endpoint copy never rides an orphan"
    );
}
