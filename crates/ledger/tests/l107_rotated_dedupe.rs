// L107 — the dedupe promise survives rotation and reopening: a key an
// earlier (rotated) segment holds refuses again after `rotate()` and a
// fresh `create()`, while a distinct key lands in the new segment.
// Spec: docs/spec.md#11-coexistence-and-flow-deduplication.

use agentpcap_ledger::{LedgerError, LedgerWriter};
use serde_json::json;

fn record(dedup: &str) -> serde_json::Value {
    json!({
        "ts": "2026-01-01T00:00:00Z",
        "host": "lab-host",
        "process": "proc",
        "pid": 42,
        "transport": "stdio-pipe",
        "mode": "attributed",
        "verdict": "mcp",
        "event": "init",
        "session_id": "pipe-pair:1:2",
        "peer": "pipe-pair:1:2",
        "dedup": dedup,
        "source": "tap",
        "schema_version": "1.0"
    })
}

#[test]
fn l107_reopening_keeps_the_rotated_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("l107.jsonl");

    {
        let mut w = LedgerWriter::create(&path).unwrap();
        w.append(&record("l107:first")).unwrap();
        // the segment closes to <name>.1; the fresh one continues the chain
        w.rotate().unwrap();
        w.append(&record("l107:second")).unwrap();
    }

    // a fresh writer over the same path loads the keys from BOTH faces
    let mut w2 = LedgerWriter::create(&path).unwrap();
    match w2.append(&record("l107:first")) {
        Err(LedgerError::Duplicate(_)) => (),       // the rotated key remembered
        other => panic!("the rotated-segment key refused again, got: {other:?}"),
    }
    // a distinct key lands in the reopened segment
    w2.append(&record("l107:third")).unwrap();
    // the C129 read boundary: verify_chain reads the file, so the
    // pending records land first (the writer still lives)
    w2.flush_pending().unwrap();
    // the family holds three records across the two segments: the
    // rotated face and the live face each verify
    let rotated = path.with_file_name("l107.jsonl.1");
    assert_eq!(agentpcap_ledger::verify_chain(&rotated).unwrap(), 1);
    assert_eq!(agentpcap_ledger::verify_chain(&path).unwrap(), 2);
}
