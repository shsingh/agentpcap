// R120 — sequential id reuse: two DISTINCT tools/call exchanges that
// reuse the id (1 after 1, the exchange completed between them) never
// share a dedupe key — a consumer of `dedup` mistakes separate calls
// for copies of each other. The keys carry the observation moment
// (ADR-0008), so the second exchange keys its own event.
// Spec: docs/spec.md#6-classification (ADR-0008 dedupe-key faces).

use agentpcap_events::Mode;
use agentpcap_reassemble::{Frame, Reassembler};
use serde_json::json;

fn frame(payload: serde_json::Value) -> Frame {
    Frame {
        transport: "stdio-pipe".into(),
        peer: "pipe:1".into(),
        pid: 3001,
        ppid: 100,
        comm: "client".into(),
        payload,
        tap_evidence: vec![],
    }
}

#[test]
fn r120_the_reused_id_keys_two_exchanges() {
    let mut r = Reassembler::new("h".into(), Mode::Attributed, "test".into());

    // the first tools/call, id 1, with args A
    let req1 = frame(json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "read", "args": "A"}
    }));
    // the merged tools-call rides the RESPONSE feed (r103's face)
    assert!(r.feed(req1).is_empty(), "the request parks, nothing rides yet");
    let resp1 = Frame {
        transport: "stdio-pipe".into(),
        peer: "pipe:1".into(),
        pid: 100,
        ppid: 3001,
        comm: "server".into(),
        payload: json!({"jsonrpc": "2.0", "id": 1, "result": {"content": "A done"}}),
        tap_evidence: vec![],
    };
    let first: Vec<_> = r
        .feed(resp1)
        .into_iter()
        .filter(|e| e.event == "tools-call")
        .collect();
    assert_eq!(first.len(), 1, "the first exchange answers once");
    let d1 = first[0].dedup.clone();

    // the id REUSES: a second tools/call, id 1 again, with args B —
    // a distinct exchange, never a copy; its reply never arrives, so
    // the flush face carries its no-response merge and the key face
    let req2 = frame(json!({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "write", "args": "B"}
    }));
    assert!(r.feed(req2).is_empty(), "the reused id parks again");
    let flushed = r.flush();
    let second: Vec<_> = flushed
        .into_iter()
        .filter(|e| e.event == "tools-call")
        .collect();
    assert_eq!(second.len(), 1, "the reused id keys its own face");
    let d2 = second[0].dedup.clone();
    eprintln!("r120 receipt: first={d1} second={d2}");
    // the keys carry the observation moment: the two exchanges never
    // share one key, and consumers of `dedup` count two calls
    assert_ne!(d1, d2, "sequential id reuse keys distinct events");
    // the key rides the (transport, session, event, id, observed ts)
    // face with the observation moment after the @ separator
    assert!(d2.contains('@'), "the observation moment rides the key");
}
