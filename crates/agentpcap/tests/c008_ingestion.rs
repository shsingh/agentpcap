// C008 — the coexistence export ingestion: a foreign export stream
// rides the ledger through `record`, carries the stamped capture path
// (`source = export` where the feed names none), and a doubled event
// skips with the dedupe key - no doubled records for covered flows.
// Spec: docs/spec.md#11-coexistence-and-flow-deduplication,
// docs/spec.md#9-operator-cli.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

fn foreign_export(id: u64, dedup: &str) -> String {
    format!(
        r#"{{"schema_version":"1.0","ts":"2026-01-01T00:00:0{id}Z","host":"lab","process":"client","pid":{id},"transport":"stdio-pipe","mode":"opaque","verdict":"mcp","event":"tools-call","peer":"tcp:10.0.0.1:5200","session_id":"tcp:10.0.0.1:5200","dedup":"{dedup}","payload":{{"id":{id}}},"evidence":[],"source":"gateway"}}"#
    )
}

#[test]
fn c008_the_export_stream_ingests_with_the_dedupe() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    // the coexistence feed: two events, then the first's flow re-reported
    let feed = [
        foreign_export(1, "tcp:10.0.0.1:5200:call:1"),
        foreign_export(2, "tcp:10.0.0.1:5200:call:2"),
        foreign_export(3, "tcp:10.0.0.1:5200:call:1"),
    ];
    let mut out = bin()
        .args(["record", "--ledger"])
        .arg(&ledger)
        .arg("--source")
        .arg("export")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("agentpcap binary");
    {
        let mut w = out.stdin.take().unwrap();
        for l in &feed {
            writeln!(w, "{l}").expect("the feed writes");
        }
    }
    let st = out.wait_with_output().expect("record exits");
    assert!(st.status.success(), "the doubled event skips, the face continues");
    let errs = String::from_utf8_lossy(&st.stderr).to_string();
    eprintln!("c008 ingestion receipt: {errs}");
    assert!(errs.contains("dedupe skipped"), "the skip states itself: {errs}");

    let text = std::fs::read_to_string(&ledger).unwrap();
    let recs: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("the ledger carries JSON objects"))
        .collect();
    eprintln!("c008 ledger receipt: records={}", recs.len());
    assert_eq!(recs.len(), 2, "no doubled record for the covered flow");
    for r in &recs {
        assert_eq!(
            r["source"].as_str(),
            Some("export"),
            "the ingested records name their capture path"
        );
    }
    // the chain verifies past the skip
    agentpcap_ledger::verify_chain(&ledger).expect("the chain stays intact");
}
