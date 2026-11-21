// C002 — the report CLI cell (`docs/spec.md#9-operator-cli`).
// report: the records to stdout, with the read logged.
// Cell ledger: tests/matrix/LEDGER.md.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

fn feed(ledger: &std::path::Path, events: &[&str]) -> Result<(), String> {
    let mut child = bin()
        .args(["record", "--ledger"])
        .arg(ledger)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("agentpcap binary: {e}"))?;
    child
        .stdin
        .take()
        .expect("stdin piped")
        .write_all(events.join("\n").as_bytes())
        .and_then(|_| {
            child
                .stdin
                .take()
                .map(|mut s| s.write_all(b"\n"))
                .unwrap_or(Ok(()))
        })
        .map_err(|e| e.to_string())?;
    let st = child.wait().unwrap();
    if st.success() {
        Ok(())
    } else {
        Err(format!("record exited {st}"))
    }
}

#[test]
fn c002_report_prints_records_and_logs_the_read() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    feed(&ledger, &["{\"event\": \"init\"}", "{\"event\": \"tools-list\"}"]).expect("record");

    let out = bin()
        .args(["report", "--ledger"])
        .arg(&ledger)
        .output()
        .expect("agentpcap binary");
    assert!(out.status.success(), "report must succeed");
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.trim_end_matches('\n').lines().collect();
    assert_eq!(lines.len(), 2, "report prints the records");

    let access = std::fs::read_to_string(dir.path().join("ledger.jsonl.access.log")).unwrap();
    let entry = access.lines().last().expect("access log entry");
    let v: serde_json::Value = serde_json::from_str(entry).unwrap();
    assert_eq!(v["actor"].as_str().unwrap(), "agentpcap.report");
}
