// C004 — the export: the gate stream streams the ledger's events to
// stdout as JSON Lines in lossless order, for a ledger segment; the
// read lands in the access log as actor = agentpcap.export.
// Spec: docs/spec.md#9-operator-cli, docs/spec.md#12-gate-handoff.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

fn record_json(id: u64, method: &str) -> String {
    format!(
        r#"{{"schema_version":"1.0","ts":"2026-01-01T00:00:0{id}Z","host":"lab","process":"t","pid":{id},"transport":"stdio-pipe","mode":"attributed","verdict":"mcp","event":"tools-call","method":"{method}","peer":"pipe:{id}","dedup":"pipe:{id}","payload":{{"id":{id}}},"evidence":[],"source":"tap"}}"#
    )
}

#[test]
fn c004_export_streams_the_ledger_segment_lossless() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let records = [record_json(1, "initialize"), record_json(2, "tools/call")];
    let mut stream = bin()
        .args(["record", "--ledger"])
        .arg(&ledger)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("agentpcap binary");
    {
        let mut w = stream.stdin.take().unwrap();
        for r in &records {
            writeln!(w, "{r}").unwrap();
        }
    }
    let st = stream.wait_with_output().expect("record exits");
    assert!(st.status.success(), "record exits cleanly");

    let out = bin()
        .args(["export", "--ledger"])
        .arg(&ledger)
        .output()
        .expect("agentpcap binary");
    assert!(out.status.success(), "export must succeed");
    let text = String::from_utf8_lossy(&out.stdout);
    let streamed: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("export lines are JSON objects"))
        .collect();
    let fed: Vec<serde_json::Value> = records
        .iter()
        .map(|r| serde_json::from_str(r).expect("the fixture records parse"))
        .collect();
    // the ledger writes its own record face (the chained prev hash and
    // its key order); the stream matches the EVENTS in lossless order
    for (s, f) in streamed.iter().zip(fed.iter()) {
        let mut s = s.clone();
        let mut f = f.clone();
        s["prev"] = f["prev"].take();
        assert_eq!(s, f, "the stream matches the event in lossless order");
    }
    assert_eq!(streamed.len(), fed.len());

    // the read logs as agentpcap.export
    let access = dir.path().join("ledger.jsonl.access.log");
    let log = std::fs::read_to_string(&access).expect("the adjacent access log");
    let entry: serde_json::Value = serde_json::from_str(log.lines().last().expect("the read logs"))
        .expect("the access log entries are JSON objects");
    assert_eq!(
        entry["actor"].as_str(),
        Some("agentpcap.export"),
        "the export read logs: {log}"
    );
}
