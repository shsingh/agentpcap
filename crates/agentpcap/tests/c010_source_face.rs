// C010 — the value face: a trailing `--source` is misuse, exit 2
// before the ledger opens. The mistyped ingest never records the
// wrong capture path.
// Spec: docs/spec.md#9-operator-cli.

use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin() -> PathBuf {
    env!("CARGO_BIN_EXE_agentpcap").into()
}

#[test]
fn c010_a_trailing_source_is_misuse_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("c010.jsonl");
    let out = Command::new(bin())
        .args(["record", "--ledger", ledger.to_str().unwrap(), "--source"])
        .stdin(Stdio::null())
        .output()
        .expect("the record face answers");
    assert_eq!(
        out.status.code(),
        Some(2),
        "the misuse face is exit 2"
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("--source needs a value"),
        "the failure states itself: {err}"
    );
    assert!(
        !ledger.exists(),
        "the ledger never opens for a misuse face"
    );
}

#[test]
fn c010_the_valued_source_ingests() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("c010-ok.jsonl");
    let mut child = Command::new(bin())
        .args([
            "record",
            "--ledger",
            ledger.to_str().unwrap(),
            "--source",
            "export",
        ])
        .stdin(Stdio::piped())
        .spawn()
        .expect("the record face answers");
    let stdin = child.stdin.as_mut().unwrap();
    stdin
        .write_all(
            br#"{"ts":"2026-01-01T00:00:00Z","host":"h","process":"p","pid":1,"transport":"stdio-pipe","mode":"attributed","verdict":"mcp","event":"init","session_id":"s","peer":"pipe:1","dedup":"c010:1","source":"x","schema_version":"1.0"}"#,
        )
        .unwrap();
    drop(child.stdin.take());
    let st = child.wait().unwrap();
    assert!(st.success(), "valued --source ingests");
    let text = std::fs::read_to_string(&ledger).unwrap();
    assert!(text.contains("\"source\":\"export\""), "the stamp rides");
}

use std::io::Write;
