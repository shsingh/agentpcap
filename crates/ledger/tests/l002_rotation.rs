// L002 — rotation preserves the prefix: a closed segment moves to
// `<name>.<n>` and the fresh segment continues the chain with its `prev`
// set from the last record of the closed segment. Spec §7.

use agentpcap_ledger::{verify_chain, LedgerWriter};
use serde_json::json;
use sha2::{Digest, Sha256};

fn trunc(line: &str) -> String {
    let d = Sha256::digest(line.as_bytes());
    hex::encode(d)[..16].to_string()
}

#[test]
fn l002_rotation_carries_the_chain_forward() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let mut w = LedgerWriter::create(&path).unwrap();
    w.append(&json!({"event": "init"})).unwrap();
    w.append(&json!({"event": "tools-list"})).unwrap();
    w.rotate().unwrap();
    w.append(&json!({"event": "tools-call"})).unwrap();
    drop(w);

    // the closed segment moved to <name>.<1> and is untouched
    let seg = dir.path().join("ledger.jsonl.1");
    let closed = std::fs::read_to_string(&seg).unwrap();
    let closed_lines: Vec<&str> = closed.lines().collect();
    assert_eq!(closed_lines.len(), 2);

    // the fresh segment exists and its chain continues from the closed one
    let fresh = std::fs::read_to_string(&path).unwrap();
    let fresh_lines: Vec<&str> = fresh.lines().collect();
    assert_eq!(fresh_lines.len(), 1);
    let o: serde_json::Value = serde_json::from_str(fresh_lines[0]).unwrap();
    assert_eq!(
        o["prev"].as_str().unwrap(),
        trunc(closed_lines[closed_lines.len() - 1])
    );

    assert!(std::fs::read_to_string(&seg).unwrap() == closed);

    // the whole ladder verifies
    assert_eq!(verify_chain(&path).unwrap(), 1);
}
