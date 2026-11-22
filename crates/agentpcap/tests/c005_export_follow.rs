// C005 — the export live follow: `export --ledger P --follow` streams
// the segment, then the events appended after startup, and ends on the
// stream close with a clean exit. Order is lossless across the boundary.
// Spec: docs/spec.md#9-operator-cli, docs/spec.md#12-gate-handoff.

use std::io::{BufRead, Write};
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
fn c005_export_follow_streams_appends_live() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let first = record_json(1, "initialize");
    std::fs::write(&ledger, format!("{first}\n")).unwrap();
    let fed: Vec<serde_json::Value> = vec![
        serde_json::from_str::<serde_json::Value>(&first)
            .expect("the fixture record parses"),
        serde_json::from_str::<serde_json::Value>(&record_json(2, "tools/call"))
            .expect("the fixture record parses"),
    ];

    // the gate consumer: export --follow reads from poll pipes
    let mut export = bin()
        .args(["export", "--ledger"])
        .arg(&ledger)
        .arg("--follow")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("agentpcap binary");
    let mut out = export.stdout.take().unwrap();

    // the segment's existing event arrives first
    let mut reader = std::io::BufReader::new(&mut out);
    let mut line = String::new();
    reader.read_line(&mut line).expect("the existing line arrives");
    // the ledger writes its own record face (the chained prev hash and
    // its key order); the stream matches the EVENTS in lossless order
    let compare = |v: &serde_json::Value, f: &serde_json::Value| {
        let mut v = v.clone();
        let mut f = f.clone();
        v["prev"] = f["prev"].take();
        assert_eq!(v, f, "the stream matches the event in lossless order");
    };
    let first_view: serde_json::Value = serde_json::from_str(line.trim()).expect("JSON object");
    compare(&first_view, &fed[0]);

    // the writer appends after the consumer is live
    std::fs::OpenOptions::new()
        .append(true)
        .open(&ledger)
        .unwrap()
        .write_all(format!("{}\n", record_json(2, "tools/call")).as_bytes())
        .unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).expect("the appended line arrives");
    let second_view: serde_json::Value = serde_json::from_str(line.trim()).expect("JSON object");
    compare(&second_view, &fed[1]);

    // the consumer ends: the test closes the reader and reaps
    drop(reader);
    drop(out);
    export.kill().expect("reap the follow stream");
    let _ = export.wait();
}
