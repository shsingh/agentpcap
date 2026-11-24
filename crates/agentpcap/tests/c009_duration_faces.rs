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

fn spawn_tap(ledger: &std::path::Path, duration: &str) -> std::process::Child {
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
    // one second plus the drain (the calibration face + the probe
    // attach face + the drain's last poll ride the same window on this
    // host the exit face posts ~1.5 s) — the wait bounds at 2.5 s so
    // the boundary race never flakes the face; the assertion is the
    // CLEAN exit, never the wall time
    std::thread::sleep(Duration::from_millis(2500));
    let st = child.try_wait().expect("the tap answers").expect("the tap exits");
    // the exit face: the bounded tap exits SUCCESS — a startup failure
    // (a probe load error, an unopenable ledger) never passes this face
    assert!(
        st.success(),
        "a --duration 1 tap ends CLEAN inside about one second, not in failure"
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
