// C009 — the tap's duration faces:
// (a) `--duration 1` ends by itself around the one-second window;
// (b) `--duration 0` is the service face: the capture outlives the
//     alpha1 default's 60 seconds (a deployed unit never stops
//     capturing at the CLI default). The cell runs its wait once.
// Spec: docs/spec.md#9-operator-cli.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> PathBuf {
    env!("CARGO_BIN_EXE_agentpcap").into()
}

fn spawn_tap(ledger: &PathBuf, duration: &str) -> std::process::Child {
    Command::new(bin())
        .args(["tap", "--ledger", ledger.to_str().unwrap(), "--duration", duration])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the tap spawns")
}

#[test]
fn c009_the_bounded_window_ends_by_itself() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("c009-bounded.jsonl");
    let mut child = spawn_tap(&ledger, "1");
    // one second plus the drain: the bounded tap exits on its own
    std::thread::sleep(Duration::from_millis(1500));
    let exited = child.try_wait().expect("the tap answers").is_some();
    assert!(
        exited,
        "a --duration 1 tap ends inside about one second"
    );
    let _ = child.wait();
}

#[test]
fn c009_the_service_face_outlives_the_default() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("c009-unbounded.jsonl");
    let mut child = spawn_tap(&ledger, "0");
    // 62 seconds: the alpha1 default (60s) would have retired the tap
    // by now; the service face keeps capturing
    std::thread::sleep(Duration::from_secs(62));
    let alive = child.try_wait().expect("the tap answers").is_none();
    assert!(
        alive,
        "--duration 0 keeps the capture running past the 60s default"
    );
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        ledger.exists(),
        "the calibrated tap owns its ledger file"
    );
}
