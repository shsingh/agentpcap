// L001 — the prev-hash chain recomputes: each line's `prev` equals the
// truncated SHA-256 (16 hex chars) of the previous line; the first line
// carries an empty `prev`. Spec: docs/spec.md#7-the-flow-ledger.

use agentpcap_ledger::{verify_chain, LedgerWriter};
use serde_json::json;
use sha2::{Digest, Sha256};

fn trunc(line: &str) -> String {
    let d = Sha256::digest(line.as_bytes());
    hex::encode(d)[..16].to_string()
}

#[test]
fn l001_chain_recomputes_after_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let mut w = LedgerWriter::create(&path).unwrap();
    w.append(&json!({"event": "tools-call", "tool_name": "read"}))
        .unwrap();
    w.append(&json!({"event": "tools-list"})).unwrap();
    w.append(&json!({"event": "init"})).unwrap();
    drop(w);

    let lines = std::fs::read_to_string(&path).unwrap();
    let rows: Vec<String> = lines.lines().map(str::to_string).collect();
    assert_eq!(rows.len(), 3);

    let prevs: Vec<String> = rows
        .iter()
        .map(|l| {
            let o: serde_json::Value = serde_json::from_str(l).unwrap();
            o["prev"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(prevs[0], "");
    assert_eq!(prevs[1], trunc(&rows[0]));
    assert_eq!(prevs[2], trunc(&rows[1]));

    // the chain verifier agrees
    assert_eq!(verify_chain(&path).unwrap(), 3);
}
