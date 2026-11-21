// L004 — ledger access is logged: an adjacent append-only access log
// records actor, time and scope per read. Spec §7.

use agentpcap_ledger::{LedgerReader, LedgerWriter};
use serde_json::json;

#[test]
fn l004_access_log_records_the_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let mut w = LedgerWriter::create(&path).unwrap();
    w.append(&json!({"event": "init"})).unwrap();
    let actor = "agentpcap-report/test";
    let read = LedgerReader::open(&path, actor).unwrap();
    assert_eq!(read.len(), 1);

    let log = std::fs::read_to_string(dir.path().join("ledger.jsonl.access.log")).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 1);
    let o: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(o["actor"].as_str().unwrap(), actor);
    assert!(o["ts"].as_str().unwrap().len() >= 20, "timestamp present");
    assert_eq!(
        o["scope"].as_str().unwrap(),
        path.to_str().unwrap()
    );
}
