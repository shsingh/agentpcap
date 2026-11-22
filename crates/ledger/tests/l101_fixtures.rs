// L101-L104 — the conformance fixtures: every fixture under
// `tests/fixtures/ledger` gets its expectation verdict back:
// chain-ok, chain-broken, torn-tail, schema-mismatch.
// Spec: docs/spec.md#7-the-flow-ledger. Cell ledger: tests/matrix/LEDGER.md.

use agentpcap_ledger::conformance;
use std::path::PathBuf;

#[test]
fn l101_fixtures_answer_their_expectations() {
    let dir = std::env::var("AGENTPCAP_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ledger")
        });
    eprintln!("fixture dir: {}", dir.display());
    let results = conformance::run(&dir).expect("fixture walk");
    assert_eq!(
        results.len(),
        6,
        "the fixture set carries six cases plus expectations"
    );
    for r in &results {
        assert_eq!(
            r.actual, r.expected,
            "fixture {} answered {} but expected {}",
            r.name, r.actual, r.expected
        );
    }
}

#[test]
fn l104_writer_refuses_foreign_schema() {
    use agentpcap_ledger::LedgerWriter;
    use serde_json::json;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.jsonl");
    let mut w = LedgerWriter::create(&path).unwrap();

    let foreign = json!({"event": "init", "schema_version": "9.9"});
    assert!(w.append(&foreign).is_err(), "a foreign schema_version is refused");

    let ok = json!({"event": "init"});
    assert!(w.append(&ok).is_ok(), "a versionless record continues");
}
