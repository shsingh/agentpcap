// C120 — the M004 between-sessions face (spec section 13, issue #28):
// TWO served sessions carry the SEEDS injected between them — the served
// tool set changes (one description changed, one tool added, one
// removed) and the capability face changes. The CLI diff must surface
// the drift from ledger data alone — never decryption — and the drift
// events must match the injected change set EXACTLY: kind-for-kind,
// name-for-name, fingerprint-for-fingerprint. The rows read their
// records through the export surface. Harness overhead stays out of the
// tap measurement path.
// Cell ledger: tests/matrix/LEDGER.md.

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentpcap")
}

#[test]
fn c120_the_between_sessions_drift_matches_the_injected_change_exactly() {
    let dir = tempfile::tempdir().unwrap();
    let eval_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval")
        .canonicalize()
        .expect("the eval package resolves");
    let out = std::process::Command::new("python3")
        .args(["-m", "agentpcap_eval.m004", "--mode", "between-sessions"])
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
    eprintln!("c120 harness stdout: {}", String::from_utf8_lossy(&out.stdout));
    eprintln!("c120 harness stderr: {}", String::from_utf8_lossy(&out.stderr));
    let receipt: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("the harness receipt is one JSON object");
    assert_eq!(
        receipt["item"].as_str(),
        Some("M004"),
        "the receipt names the M-item"
    );
    assert_eq!(
        receipt["mode"].as_str(),
        Some("between-sessions"),
        "the receipt names the between-sessions mode"
    );
    assert_eq!(
        receipt["result"].as_str(),
        Some("pass"),
        "the drift events match the injected change set exactly"
    );
    assert!(
        receipt["exact"].as_bool() == Some(true),
        "the exact face rides the receipt"
    );
    // the bounded fresh-capture face: the receipt names the attempts
    let attempts = receipt["attempts"].as_u64().expect("the attempts ride");
    assert!(
        (1..=3).contains(&attempts),
        "the face reports its attempt count in the bounded range: {attempts}"
    );
    // injected == emitted, face by face: the kinds, the description
    // texts, the tool names, and the capability fingerprints
    assert_eq!(
        receipt["injected"]["kinds"], receipt["emitted"]["kinds"],
        "the kinds match exactly"
    );
    assert_eq!(
        receipt["injected"]["descriptions"]["read"],
        receipt["emitted"]["descriptions"]["read"],
        "the description texts match exactly (no decryption face)"
    );
    assert_eq!(
        receipt["injected"]["added"], receipt["emitted"]["added"],
        "the added names match exactly"
    );
    assert_eq!(
        receipt["injected"]["removed"], receipt["emitted"]["removed"],
        "the removed names match exactly"
    );
    let rescope = receipt["emitted"]["rescoped"]
        .as_object()
        .expect("the rescoped face rides");
    assert_ne!(
        rescope["before"], rescope["after"],
        "the capability fingerprints differ across the sessions"
    );
}
