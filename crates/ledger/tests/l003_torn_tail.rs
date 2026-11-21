// L003 — a torn tail is detectable: a truncated final line fails chain
// verification and the writer refuses to chain from corrupt data.
// Spec §7: plain-text, order-checked ledger; append-only.

use agentpcap_ledger::{verify_chain, LedgerWriter};
use serde_json::json;

#[test]
fn l003_torn_tail_fails_verification_and_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let mut w = LedgerWriter::create(&path).unwrap();
    w.append(&json!({"event": "init"})).unwrap();
    drop(w);

    // simulate a crash mid-append: a partial second line, no newline
    let existing = std::fs::read_to_string(&path).unwrap();
    let torn = existing + "{\"event\": \"t";
    std::fs::write(&path, torn).unwrap();

    // verification must fail loudly, not silently skip
    assert!(verify_chain(&path).is_err());

    // and the writer must refuse to chain from the corrupt tail
    assert!(LedgerWriter::create(&path).is_err());
}
