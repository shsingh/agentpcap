// L005 — the schema contract: every record carries `schema_version`,
// and the ledger format pins it. Spec §4: the event record is the
// interface contract; the field `schema_version` MUST be present.

use agentpcap_ledger::LedgerWriter;
use serde_json::json;

#[test]
fn l005_schema_version_pinned_on_every_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let mut w = LedgerWriter::create(&path).unwrap();
    w.append(&json!({"event": "init"})).unwrap();
    w.append(&json!({"event": "tools-list"})).unwrap();
    drop(w);

    let lines = std::fs::read_to_string(&path).unwrap();
    for l in lines.lines() {
        let o: serde_json::Value = serde_json::from_str(l).unwrap();
        assert_eq!(
            o["schema_version"].as_str().unwrap(),
            "1.0",
            "schema_version must be present and pinned"
        );
    }
}
