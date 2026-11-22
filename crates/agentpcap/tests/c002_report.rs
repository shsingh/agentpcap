// C002 — the report CLI cell (`docs/spec.md#9-operator-cli`).
// report renders the sessions view from the ledger: one line per
// session, per peer; the read logs as actor = agentpcap.report.
// Cell ledger: tests/matrix/LEDGER.md.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

fn session_event(id: u64, pair: &str, event: &str) -> String {
    format!(
        r#"{{"schema_version":"1.0","ts":"2026-01-01T00:00:0{id}Z","host":"lab","process":"client","pid":{id},"transport":"stdio-pipe","mode":"attributed","verdict":"mcp","event":"{event}","peer":"{pair}","session_id":"{pair}","dedup":"{pair}:{event}:{id}","payload":{{}},"evidence":[],"source":"tap"}}"#
    )
}

#[test]
fn c002_report_renders_the_sessions_view_and_logs_the_read() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let records = [
        session_event(1, "pipe-pair:1:2", "init"),
        session_event(2, "pipe-pair:3:4", "tools-list"),
    ];
    let mut child = bin()
        .args(["record", "--ledger"])
        .arg(&ledger)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("agentpcap binary");
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(records.join("\n").as_bytes())
        .expect("record append");
    let st = child.wait().unwrap();
    assert!(st.success(), "record exits cleanly");

    let out = bin()
        .args(["report", "--ledger"])
        .arg(&ledger)
        .output()
        .expect("agentpcap binary");
    assert!(out.status.success(), "report must succeed");
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("report lines are JSON objects"))
        .collect();
    eprintln!("c002 sessions receipt: {lines:?}");
    assert_eq!(lines.len(), 2, "one session view line per session");
    assert_eq!(lines[0]["session_id"], "pipe-pair:1:2");
    assert_eq!(lines[1]["session_id"], "pipe-pair:3:4");

    let access = std::fs::read_to_string(dir.path().join("ledger.jsonl.access.log")).unwrap();
    let entry = access.lines().last().expect("access log entry");
    let v: serde_json::Value = serde_json::from_str(entry).unwrap();
    assert_eq!(v["actor"].as_str().unwrap(), "agentpcap.report");
}
