// L109 — the reload order: the closed segments load in numeric order
// first, the active file LAST, so the window trim keeps the keys the
// live capture wrote most recently. The replay face protects recent
// events, never stale ones.
// Spec: docs/spec.md#11-coexistence-and-flow-deduplication (ADR-0008).

use agentpcap_ledger::{LedgerError, LedgerWriter};
use serde_json::json;

fn record(n: usize) -> serde_json::Value {
    json!({
        "ts": "2026-01-01T00:00:00Z",
        "host": "lab-host",
        "process": "proc",
        "pid": 9,
        "transport": "stdio-pipe",
        "mode": "attributed",
        "verdict": "mcp",
        "event": "init",
        "session_id": "pipe-pair:1:2",
        "peer": "pipe-pair:1:2",
        "dedup": format!("l109:key-{n}"),
        "source": "tap",
        "schema_version": "2.1"
    })
}

#[test]
fn l109_the_reload_keeps_the_newest_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("l109.jsonl");
    let budget = 2usize;

    let mut w = LedgerWriter::create_with_budget(&path, budget).unwrap();
    w.append(&record(1)).unwrap();
    w.append(&record(2)).unwrap();
    w.rotate().unwrap();
    // the active segment's keys are the newest events
    w.append(&record(3)).unwrap();
    w.append(&record(4)).unwrap();

    // the C129 read boundary: the reload reads the active file, so the
    // pending records land first (the writer still lives)
    w.flush_pending().unwrap();
    // the reload reads the closed segment first, the active file last:
    // the trim keeps 3 and 4, and the replays of 3 and 4 still refuse
    let mut w2 = LedgerWriter::create_with_budget(&path, budget).unwrap();
    match w2.append(&record(3)) {
        Err(LedgerError::Duplicate(_)) => (),
        other => panic!("the recent key (active segment) refuses, got: {other:?}"),
    }
    match w2.append(&record(4)) {
        Err(LedgerError::Duplicate(_)) => (),
        other => panic!("the recent key (active segment) refuses, got: {other:?}"),
    }
    // the older face sits outside the window: the bound is honest
    match w2.append(&record(1)) {
        Ok(_) => (),
        other => panic!("the stale key rides the window, got: {other:?}"),
    }
}
