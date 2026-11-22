// L110 — the privacy face: the ledger file carries captured arguments
// and results and rides owner-only (mode 0600), create or append alike.
// Spec: docs/spec.md#4-event-record-schema (the ledger is the
// operator's read surface, never a shared one).

use agentpcap_ledger::LedgerWriter;
use serde_json::json;
use std::os::unix::fs::PermissionsExt;

fn record() -> serde_json::Value {
    json!({
        "ts": "2026-01-01T00:00:00Z",
        "host": "lab-host",
        "process": "proc",
        "pid": 11,
        "transport": "stdio-pipe",
        "mode": "attributed",
        "verdict": "mcp",
        "event": "init",
        "session_id": "pipe-pair:1:2",
        "peer": "pipe-pair:1:2",
        "dedup": "l110:1",
        "source": "tap",
        "schema_version": "2.1"
    })
}

#[test]
fn l110_the_ledger_is_owner_only_create_and_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("l110.jsonl");

    // create: the fresh file rides owner-only
    {
        let mut w = LedgerWriter::create(&path).unwrap();
        w.append(&record()).unwrap();
    }
    let mode = std::fs::metadata(&path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "a fresh ledger rides owner-only: {mode:o}");

    // append: an existing ledger stays owner-only across the reopen
    let mut w = LedgerWriter::create(&path).unwrap();
    let mut rec = record();
    rec["dedup"] = json!("l110:2");
    w.append(&rec).unwrap();
    let mode = std::fs::metadata(&path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "a reopened ledger stays owner-only: {mode:o}");
}
