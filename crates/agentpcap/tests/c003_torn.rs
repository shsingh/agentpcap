// C003 — the report CLI cell (`docs/spec.md#9-operator-cli`).
// report refuses a torn or broken ledger loudly.
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
