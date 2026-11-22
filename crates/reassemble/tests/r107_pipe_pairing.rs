// R107 — the pipe-pair keying rule: the pairing parent answers which
// server and the payload id answers which request; a second server
// binds its own pair and never steals the other's ids; a request no
// response ever binds still lands at flush, keyed by its own channel
// with the no-response evidence (capture loss degrades the ledger, it
// never drops it silently).

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
fn r107_two_servers_pair_per_response_and_a_lost_response_lands_at_flush() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // one client parks two requests
    let req1 = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}});
    let req2 = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": "read", "arguments": {}}});
    assert!(r.feed(frame("pipe:100", 3001, 100, req1)).is_empty());
    assert!(r.feed(frame("pipe:100", 3001, 100, req2)).is_empty());
    // server S2 answers id 1: its own pair binds id 1 only
    let s2_resp = json!({
        "jsonrpc": "2.0", "id": 1,
        "result": {"tools": [{"name": "read", "description": "read a file"}]}
    });
    let out = r.feed(frame("pipe:102", 5002, 3001, s2_resp));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].peer, "pipe-pair:3001:5002", "the pair names the answering server");
    assert_eq!(out[0].event, "tools-list");
    // a response from server S1 binds its own pair
    let s1_resp = json!({
        "jsonrpc": "2.0", "id": 2, "result": {"content": [{"text": "done"}]}
    });
    let out = r.feed(frame("pipe:103", 4001, 3001, s1_resp));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].peer, "pipe-pair:3001:4001");
    assert_eq!(out[0].event, "tools-call");
    assert_eq!(out[0].tool_name.as_deref(), Some("read"));
    // one more request nobody answers lands at flush on its channel
    let req3 = json!({"jsonrpc": "2.0", "id": 3, "method": "initialize", "params": {}});
    assert!(r.feed(frame("pipe:104", 3001, 100, req3)).is_empty());
    let flushed = r.flush();
    assert_eq!(flushed.len(), 1, "only the lost request flushes");
    let ev = &flushed[0];
    assert_eq!(ev.event, "init");
    assert_eq!(ev.peer, "pipe:104", "the flush key stays the request's channel");
    let evidence = ev.evidence.as_ref().unwrap().clone();
    assert!(evidence.contains(&"no-response".to_string()), "evidence: {evidence:?}");
    assert!(
        ev.cap_fingerprint.is_none(),
        "a lost initialize carries no fingerprint"
    );
}
