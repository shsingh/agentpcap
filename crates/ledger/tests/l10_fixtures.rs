// L101-L104 — the conformance fixtures: every fixture under
// `tests/fixtures/ledger` gets its expectation verdict back:
// chain-ok, chain-broken, torn-tail, schema-mismatch.
// Spec: docs/spec.md#7-the-flow-ledger. Cell ledger: tests/matrix/LEDGER.md.

use std::path::Path;

#[test]
fn l10_fixtures_answer_their_expectations() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ledger");
    let results = agentpcap_ledger::conformance::run(&dir).expect("fixture walk");
    assert_eq!(
        results.len(),
        5,
        "the fixture set carries five cases plus expectations"
    );
    for r in &results {
        assert_eq!(
            r.actual, r.expected,
            "fixture {} answered {} but expected {}",
            r.name, r.actual, r.expected
        );
    }
}
