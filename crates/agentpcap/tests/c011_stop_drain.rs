// C011 — the stop face: the unit's SIGTERM marks the stop, the tap
// breaks its loop and the drain flushes the still-pending requests
// with the no-response face — a stop loses nothing. The cell proves
// the unbounded tap answers SIGTERM promptly with exit success.
// Spec: docs/spec.md#10-deployment.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> PathBuf {
    env!("CARGO_BIN_EXE_agentpcap").into()
}

#[test]
fn c011_the_stop_drains_and_answers_success() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("c011.jsonl");
    let mut child = Command::new(bin())
        .args(["tap", "--ledger", ledger.to_str().unwrap(), "--duration", "0"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the tap spawns");
    // let the calibration finish, then stop the unit
    std::thread::sleep(Duration::from_millis(1200));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    // the drain face: the tap answers promptly (within ~2s) and
    // reports success — the flush ran, the ledger closes cleanly
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let code = loop {
        match child.try_wait().expect("the tap answers") {
            Some(st) => break st.code(),
            None => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the stop face answers within seconds, never hangs"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    assert_eq!(code, Some(0), "the drained stop reports success");
    assert!(ledger.exists(), "the drained tap owns its ledger");
}
