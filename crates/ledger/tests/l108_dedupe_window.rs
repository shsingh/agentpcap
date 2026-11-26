// L108 — the dedupe window is bounded: the writer keeps at most
// `budget` keys (the newest), so a service that runs for weeks never
// grows memory with its history. A key evicted from the window
// appends again; a key inside it still refuses.
// Spec: docs/spec.md#11-coexistence-and-flow-deduplication (ADR-0007 2.1).

use agentpcap_ledger::{LedgerError, LedgerWriter};
use serde_json::json;

fn record(n: usize) -> serde_json::Value {
    json!({
        "ts": "2026-01-01T00:00:00Z",
        "host": "lab-host",
        "process": "proc",
        "pid": 7,
        "transport": "stdio-pipe",
        "mode": "attributed",
        "verdict": "mcp",
        "event": "init",
        "session_id": "pipe-pair:1:2",
        "peer": "pipe-pair:1:2",
        "dedup": format!("l108:key-{n}"),
        "source": "tap",
        "schema_version": "2.1"
    })
}

#[test]
fn l108_the_window_bounds_the_keys_it_keeps() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("l108.jsonl");
    let budget = 3usize;

    let mut w = LedgerWriter::create_with_budget(&path, budget).unwrap();
    for n in 1..=4 {
        w.append(&record(n)).unwrap();
    }
    // the newest key (4) still rides; key 1 left the window
    match w.append(&record(4)) {
        Err(LedgerError::Duplicate(_)) => (),
        other => panic!("the newest key refuses, got: {other:?}"),
    }
    match w.append(&record(1)) {
        Ok(_) => (), // evicted: the window bound is honest
        other => panic!("the evicted key appends again, got: {other:?}"),
    }
    // the C129 read boundary: the reload loads the file's keys, so the
    // pending records land first (the writer still lives)
    w.flush_pending().unwrap();
    // a fresh writer loads the file's keys and trims to the budget:
    // the file order is 1,2,3,4,1 — the newest three (3,4,1) stay,
    // key 2 falls outside and appends again
    let mut w2 = LedgerWriter::create_with_budget(&path, budget).unwrap();
    match w2.append(&record(3)) {
        Err(LedgerError::Duplicate(_)) => (),
        other => panic!("the key inside the window refuses, got: {other:?}"),
    }
    match w2.append(&record(2)) {
        Ok(_) => (), // outside the window: the bound is honest on reload too
        other => panic!("the reloaded window trims, got: {other:?}"),
    }
}
