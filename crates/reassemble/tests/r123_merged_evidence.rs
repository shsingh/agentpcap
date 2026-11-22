// R123 — the merged record carries the RESPONSE half's boundary
// evidence: a reply that rides the tls-boundary with its own capture
// faces (chunked-join, sse-data-line) leaves those faces ON the merged
// session record — the merge never folds the reply's capture proof
// away. The request half's evidence stays; the dedup keeps one line.
// Spec: docs/spec.md#6-classification, ADR-0006.

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

#[test]
fn r123_the_merged_record_carries_the_reply_boundary_faces() {
    let mut r = Reassembler::new("host".into(), Mode::Attributed, "test".into());
    let peer = "net-1.tcp:127.0.0.1:40003=tcp:127.0.0.1:8443";

    let req_ev = vec![
        "tls-boundary".to_string(),
        "probe-face:send".to_string(),
    ];
    assert!(r
        .feed(frame(peer, 3001, 100, json!({
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "read", "arguments": {}}
        }), req_ev))
        .is_empty());

    // the reply rides its OWN capture faces: a chunked-join boundary
    // decode plus the tls-boundary face the request already carries
    let reply_ev = vec![
        "tls-boundary".to_string(),
        "chunked-join".to_string(),
        "probe-face:receive".to_string(),
    ];
    let evs = r.feed(frame(peer, 100, 3001, json!({
        "jsonrpc": "2.0", "id": 9, "result": {"content": "r123-done"}
    }), reply_ev));
    assert_eq!(evs.len(), 1, "the bind merges one record");
    let evidence = evs[0]
        .evidence
        .as_ref()
        .expect("the merged record carries evidence");
    assert!(
        evidence.iter().any(|e| e == "chunked-join"),
        "the reply half's chunked-join face rides the merged record: {evidence:?}"
    );
    // the shared boundary face dedups to one line
    assert_eq!(
        evidence.iter().filter(|e| e.as_str() == "tls-boundary").count(),
        1,
        "the shared tls-boundary face never duplicates: {evidence:?}"
    );
    // the request half's faces stay
    assert!(
        evidence.iter().any(|e| e == "probe-face:send"),
        "the request half's direction face stays: {evidence:?}"
    );
}
