// C001 — the record CLI cell (`docs/spec.md#9-operator-cli`).
// record: JSON Lines on stdin append to the ledger, chain intact.
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
