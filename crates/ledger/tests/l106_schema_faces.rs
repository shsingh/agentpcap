// L106 — the schema faces rule (ADR-0007): the writer chains both
// known faces (1.0 frame, 2.0 session-event) into one ledger and
// refuses a foreign version; the chain verifies after every append.
// Spec: docs/spec.md#4-event-record-schema,
// docs/spec.md#11-coexistence-and-flow-deduplication.

use agentpcap_ledger::LedgerWriter;
use serde_json::json;

fn event(id: u64, dedup: &str, schema_version: &str) -> serde_json::Value {
    json!({
        "schema_version": schema_version,
        "ts": "2026-01-01T00:00:0{id}Z",
        "host": "lab",
        "process": "client",
        "pid": id,
        "transport": "stdio-pipe",
        "mode": "attributed",
        "verdict": "mcp",
        "event": "tools-call",
        "peer": "pipe:1",
        "dedup": dedup,
        "evidence": [],
        "source": "tap"
    })
}

#[test]
fn l106_both_schema_faces_chain_and_a_foreign_version_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let mut w = LedgerWriter::create(&ledger).unwrap();
    // the frame face 1.0 rides
    assert!(
        w.append(&event(1, "tap:pipe:1:call:1", "1.0")).is_ok(),
        "the frame face chains"
    );
    // the session-event face 2.0 rides the same ledger
    assert!(
        w.append(&event(2, "tap:pipe:1:call:2", "2.0")).is_ok(),
        "the session face chains beside the frame face"
    );
    // a foreign version refuses
    assert!(
        w.append(&event(3, "tap:pipe:1:call:3", "9.9")).is_err(),
        "the foreign version refuses"
    );
    drop(w);
    let n = agentpcap_ledger::verify_chain(&ledger).expect("the chain verifies");
    assert_eq!(n, 2, "the refused record never rides");
}
