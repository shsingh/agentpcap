// C001-C003 — the record and report CLI faces (`docs/spec.md#9-operator-cli`).
// record: JSON Lines on stdin append to the ledger, chain intact.
// report: the records to stdout, with the read logged.
// report refuses a torn or broken ledger loudly. Cell ledger: tests/matrix/LEDGER.md.

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
fn c001_record_appends_chained_events_from_stdin() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    feed(
        &ledger,
        &[
            "{\"event\": \"init\"}",
            "{\"event\": \"tools-call\", \"payload\": {\"method\": \"tools/call\"}}",
        ],
    )
    .expect("record must succeed");
    assert_eq!(
        agentpcap_ledger::verify_chain(&ledger).unwrap(),
        2,
        "the ledger carries two chained records"
    );
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

#[test]
fn c003_report_refuses_a_torn_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");
    feed(&ledger, &["{\"event\": \"init\"}"]).expect("record");

    // simulate a crash mid-append
    let existing = std::fs::read_to_string(&ledger).unwrap();
    std::fs::write(&ledger, format!("{}{{\"event\": \"t", existing)).unwrap();

    let out = bin()
        .args(["report", "--ledger"])
        .arg(&ledger)
        .output()
        .expect("agentpcap binary");
    assert!(!out.status.success(), "report must fail loudly");
    assert!(
        out.stdout.is_empty(),
        "a torn ledger produces no records on stdout"
    );
    assert!(!out.stderr.is_empty(), "the failure states itself on stderr");
}
