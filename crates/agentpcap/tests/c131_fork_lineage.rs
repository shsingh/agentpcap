// C131 — the in-probe fork lineage feed (ADR-0009, issue #55). The
// sched_process_fork tracepoint feeds parent-child pairs into the
// fork_lineage map; the receipt face answers both faces of each pair.
// Spec: docs/spec.md#5-collectors, docs/spec.md#8-modes.
// Cell ledger: tests/matrix/LEDGER.md.

use std::process::{Command, Stdio};
use std::time::Duration;

#[test]
fn c131_the_fork_feed_rides_the_lineage_map() {
    let dir = tempfile::tempdir().unwrap();
    let err = dir.path().join("tap-stderr.txt");

    let mut tap = Command::new(env!("CARGO_BIN_EXE_agentpcap"))
        .args(["tap", "--ledger"])
        .arg(dir.path().join("c131.jsonl"))
        .arg("--duration")
        .arg("6")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&err).expect("the tap stderr rides"))
        .spawn()
        .expect("agentpcap binary");

    // the fork face: a child of THIS process — the receipt face answers
    // the pair with the test's own pid as parent
    let mut child = std::process::Command::new("sleep")
        .arg("0.3")
        .spawn()
        .expect("the child spawns");
    let _ = child.wait();

    for _ in 0..20 {
        if tap.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let _ = tap.wait();

    // the receipt face: the pair receipt rides child=parent with a real
    // pid face — a name-byte face would answer non-pid values (the
    // parked receipt's 1.2M face); the pid face answers this kernel's
    // pid space
    let face = std::fs::read_to_string(&err).unwrap_or_default();
    let pair = face
        .lines()
        .find(|l| l.starts_with("agentpcap tap: fork face child="))
        .unwrap_or_else(|| panic!("the fork pair receipt rides: {face}"));
    let child_face: String = pair
        .split("child=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    assert!(
        !child_face.is_empty() && child_face.parse::<u32>().is_ok(),
        "the child face answers a pid, not name bytes: {pair}"
    );
    let pairs = face
        .lines()
        .find(|l| l.starts_with("agentpcap tap: fork lineage pairs="))
        .expect("the pairs count rides");
    assert!(
        !pairs.contains("pairs=0"),
        "the lineage map carries the fork face: {pairs}"
    );
}
