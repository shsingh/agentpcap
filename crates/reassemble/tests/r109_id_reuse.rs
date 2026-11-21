// R109 — the id-reuse face: one client parks the same id on two
// channels (two child servers). Both requests stay preserved; a
// response that names the id ambiguously orphans honestly; the flush
// recovers both captures. Spec: docs/spec.md#6-classification.

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
fn r109_the_reused_id_preserves_both_requests_and_orphans_the_ambiguous_response() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    let req = json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}});
    // the same client parks id 7 on two channels, to two servers
    assert!(r.feed(frame("pipe:100", 700, 100, req.clone())).is_empty());
    assert!(r.feed(frame("pipe:101", 700, 100, req)).is_empty());
    // a dying response names id 7: one id, two pendings: ambiguous
    let resp = json!({"jsonrpc": "2.0", "id": 7, "result": {"tools": []}});
    let out = r.feed(dying(frame("pipe:500", 4002, 0, resp)));
    assert_eq!(out.len(), 1, "the response lands, unmerged");
    assert_eq!(out[0].event, "unidentified");
    let evidence = out[0].evidence.as_ref().unwrap().clone();
    assert!(
        evidence.contains(&"pair-unresolved:ambiguous-id".to_string()),
        "evidence: {evidence:?}"
    );
    // the flush recovers both parked requests, never one overwritten
    let flushed = r.flush();
    assert_eq!(flushed.len(), 2, "both parked requests land at flush");
    for ev in &flushed {
        assert_eq!(ev.event, "tools-list");
        let evidence = ev.evidence.as_ref().unwrap().clone();
        assert!(evidence.contains(&"no-response".to_string()));
    }
    assert_eq!(flushed[0].peer, "pipe:100", "each flush rides its own channel");
    assert_eq!(flushed[1].peer, "pipe:101");
}

#[test]
fn r109_the_live_unownable_response_orphans_without_a_foreign_bind() {
    let mut r = Reassembler::new("lab-host".into(), Mode::Attributed, "tap".into());
    // client 700 owns id 11; an unrelated live writer answers id 11
    let req = json!({"jsonrpc": "2.0", "id": 11, "method": "tools/list", "params": {}});
    assert!(r.feed(frame("pipe:100", 700, 100, req)).is_empty());
    let resp = json!({"jsonrpc": "2.0", "id": 11, "result": {"tools": []}});
    // the writer is alive (ppid resolves, the fd resolved) but no
    // pairing owns it: the by-id fallback never fires for it
    let out = r.feed(frame("pipe:500", 4002, 3900, resp));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].event, "unidentified");
    assert_eq!(out[0].peer, "pipe:500", "the orphan keys its own channel");
    // the parked request survives to flush
    let flushed = r.flush();
    assert_eq!(flushed.len(), 1, "the parked request land at flush");
}
