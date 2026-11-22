// C006 — the report sessions view: `report` renders the sessions view
// from the ledger per peer and per server: the tools discovered, the
// capability fingerprints, the invocation counts, transport, mode; the
// read lands in the access log as actor = agentpcap.report.
// Spec: docs/spec.md#9-operator-cli.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

fn session_event(id: u64, method: &str) -> String {
    format!(
        r#"{{"schema_version":"1.0","ts":"2026-01-01T00:00:0{id}Z","host":"lab","process":"client","pid":1,"transport":"stdio-pipe","mode":"attributed","verdict":"mcp","event":"{event}","method":"{method}","tool_name":{tool},"cap_fingerprint":{fp},"protocol_version":"2025-06-18","session_id":"pipe-pair:1:2","peer":"pipe-pair:1:2","dedup":"pipe-pair:1:2:{event}:{id}","payload":{payload},"evidence":["tool:read"],"source":"tap"}}"#,
        event = match method {
            "initialize" => "init",
            "tools/list" => "tools-list",
            _ => "tools-call",
        },
        tool = if method == "tools/call" { r#""read""# } else { "null" },
        fp = r#""ba8e230d1afc3aa1""#,
        payload = if method == "initialize" {
            r#"{"request":{"method":"initialize"},"result":{"serverInfo":{"name":"alpha1-server"},"capabilities":{"tools":{}}}}"#
        } else if method == "tools/list" {
            r#"{"request":{"method":"tools/list"},"result":{"tools":[{"name":"read","description":"read a file"}]}}"#
        } else {
            r#"{"request":{"method":"tools/call","params":{"name":"read"}},"result":{"content":[]}}"#
        },
    )
}

#[test]
fn c006_report_renders_the_sessions_view() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    let records = [
        session_event(1, "initialize"),
        session_event(2, "tools/list"),
        session_event(3, "tools/call"),
    ];
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
    assert!(st.status.success());

    let out = bin()
        .args(["report", "--ledger"])
        .arg(&ledger)
        .output()
        .expect("agentpcap binary");
    assert!(out.status.success(), "report must succeed");
    let text = String::from_utf8_lossy(&out.stdout);
    let views: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("report lines are JSON objects"))
        .collect();
    eprintln!("c006 sessions receipt: {views:?}");
    assert_eq!(views.len(), 1, "one session view line per session");
    let v = &views[0];
    assert_eq!(v["peer"], "pipe-pair:1:2");
    assert_eq!(v["transport"], "stdio-pipe");
    assert_eq!(v["mode"], "attributed");
    assert_eq!(v["server"], "alpha1-server");
    assert_eq!(v["cap_fingerprint"], "ba8e230d1afc3aa1");
    assert_eq!(v["protocol_version"], "2025-06-18");
    assert_eq!(v["invocations"], 1, "one tools-call invocation");
    assert_eq!(v["tools"][0]["name"], "read");
    assert_eq!(v["tools"][0]["description"], "read a file");

    let access = dir.path().join("ledger.jsonl.access.log");
    let log = std::fs::read_to_string(&access).expect("the adjacent access log");
    let entry: serde_json::Value = serde_json::from_str(log.lines().last().expect("the read logs"))
        .expect("the access log entries are JSON objects");
    assert_eq!(
        entry["actor"].as_str(),
        Some("agentpcap.report"),
        "the report read logs: {log}"
    );
}
