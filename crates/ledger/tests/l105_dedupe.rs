// L105 — the coexistence dedupe at the writer: a record whose `dedup`
// key already rides the ledger refuses the append; the chain stays
// intact and the count does not move. Spec: docs/spec.md#11-coexistence-and-flow-deduplication.

use agentpcap_ledger::LedgerWriter;
use serde_json::json;

fn event(id: u64, dedup: &str) -> serde_json::Value {
    json!({
        "schema_version": "1.0",
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
fn l105_the_duplicate_dedup_key_refuses_and_the_chain_stays_intact() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let mut w = LedgerWriter::create(&ledger).unwrap();
    assert!(w.append(&event(1, "tap:pipe:1:call:4")).is_ok(), "the first lands");
    // the same event re-ingested from the coexistence export
    assert!(
        w.append(&event(2, "tap:pipe:1:call:4")).is_err(),
        "the doubled event refuses"
    );
    // a distinct event rides
    assert!(w.append(&event(3, "tap:pipe:1:call:5")).is_ok());
    drop(w);
    // the chain verifies: two records, the refused one absent, the
    // count did not move for the refusal
    let n = agentpcap_ledger::verify_chain(&ledger).expect("the chain verifies");
    assert_eq!(n, 2, "the doubled event never rides the ledger");
    let text = std::fs::read_to_string(&ledger).unwrap();
    assert!(text.lines().count() == 2, "no doubled record");
}
