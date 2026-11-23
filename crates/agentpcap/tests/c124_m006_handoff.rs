// C124 — the M006 gate handoff face (spec section 13, issue #30): the
// criteria-scoring budget is 2 seconds (ADR-0002, the rc1 gate). ONE
// real tap, ONE real counting server over stdio, and the harness plays
// the client over representative bursts: 4 frames inside a burst at a
// 0.1 s cadence, 0.9 s between bursts. The harness stamps the exact
// write time per frame and the exact landing time per verdict row it
// tails out of the ledger file, then posts the latency distribution
// (min, median, p95, max) against the budget explicitly. Harness
// overhead stays out of the tap measurement path: the polling rides
// the gate-side reader.
// Cell ledger: tests/matrix/LEDGER.md.

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentpcap")
}

#[test]
fn c124_the_gate_eats_its_input_inside_the_two_second_budget() {
    let dir = tempfile::tempdir().unwrap();
    let eval_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval")
        .canonicalize()
        .expect("the eval package resolves");
    let out = std::process::Command::new("python3")
        .args(["-m", "agentpcap_eval.m006"])
        .arg("--binary")
        .arg(bin())
        .arg("--workdir")
        .arg(dir.path().to_str().expect("the workdir stays utf8"))
        .env(
            "PYTHONPATH",
            format!(
                "{}:{}",
                eval_dir.to_str().expect("the eval path stays utf8"),
                std::env::var("PYTHONPATH").unwrap_or_default()
            ),
        )
        .output()
        .expect("python3 runs");
    eprintln!("c124 harness stdout: {}", String::from_utf8_lossy(&out.stdout));
    eprintln!("c124 harness stderr: {}", String::from_utf8_lossy(&out.stderr));
    let receipt: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("the harness receipt is one JSON object");
    assert_eq!(
        receipt["item"].as_str(),
        Some("M006"),
        "the receipt names the M-item"
    );
    assert_eq!(
        receipt["result"].as_str(),
        Some("pass"),
        "the handoff face rides: {}",
        receipt["reasons"]
    );
    // the bounded fresh-capture face: the receipt names the attempts
    let attempts = receipt["attempts"].as_u64().expect("the attempts ride");
    assert!(
        (1..=3).contains(&attempts),
        "the face reports its attempt count in the bounded range: {attempts}"
    );
    // every burst frame's verdict row landed
    assert_eq!(
        receipt["frames_written"].as_u64(),
        Some(17),
        "the initialize rides plus 4 frames x 4 bursts"
    );
    assert_eq!(
        receipt["landed"].as_u64(),
        Some(17),
        "every frame's verdict row lands"
    );
    // the distribution posts and the budget comparison rides explicit
    assert!(
        receipt["distribution"]["max_s"].is_number(),
        "the max latency rides the distribution"
    );
    assert_eq!(
        receipt["within_budget"].as_bool(),
        Some(true),
        "every verdict row lands inside the 2-second criteria budget"
    );
    let max_s = receipt["distribution"]["max_s"].as_f64().expect("the max rides");
    let budget = receipt["budget_s"].as_f64().expect("the budget rides");
    assert!(max_s < budget, "max {max_s} stays inside the {budget}s budget");
}
