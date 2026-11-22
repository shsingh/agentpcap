// C117 — the evaluation harness scaffold (spec section 13): the Python
// harness under `eval/` reproduces ONE full M-item end to end — M004's
// ledger fidelity on capability drift — consuming only the CLI surfaces.
// The harness spawns the real tap per scenario, plays the stdio exchange,
// runs `agentpcap diff` on the two ledgers, and compares the drift events
// kind-for-kind against the seeded expectation. Harness overhead stays out
// of the tap's measurement path: the harness times nothing inside the tap.
// Cell ledger: tests/matrix/LEDGER.md.

use std::path::PathBuf;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentpcap")
}

#[test]
fn c117_the_harness_runs_the_m004_fidelity_item_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let eval_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval")
        .canonicalize()
        .expect("the eval package resolves");
    let out = std::process::Command::new("python3")
        .args([
            "-m",
            "agentpcap_eval.m004",
            "--binary",
            bin(),
            "--workdir",
            dir.path().to_str().expect("the workdir stays utf8"),
        ])
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
    eprintln!(
        "c117 harness stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    eprintln!(
        "c117 harness stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "the harness M004 item answers exit 0 end to end"
    );

    // the receipt: JSON, named, with the drift kinds and the seeded texts
    let receipt: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("the harness receipt is one JSON object");
    assert_eq!(
        receipt["item"].as_str(),
        Some("M004"),
        "the receipt names the M-item"
    );
    assert_eq!(
        receipt["result"].as_str(),
        Some("pass"),
        "the drift fidelity passes against the seeds"
    );
    let kinds = receipt["diff"]["kinds"]
        .as_array()
        .expect("the receipt carries the drift kinds");
    let names: Vec<&str> = kinds.iter().filter_map(|k| k.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "server-rescoped",
            "tool-description-changed",
            "tools-added",
            "tools-removed"
        ],
        "the drift kind set matches the seeds (sorted face)"
    );
    let read_before = receipt["diff"]["descriptions"]["read"]["before"]
        .as_str()
        .expect("the receipt carries the before description");
    let read_after = receipt["diff"]["descriptions"]["read"]["after"]
        .as_str()
        .expect("the receipt carries the after description");
    assert_eq!(read_before, "read a file", "the seeded before text rides");
    assert_eq!(read_after, "read a file v2", "the seeded after text rides");
    // the overhead face: no timing rides inside the tap path, the receipt
    // carries none
    assert!(
        receipt.get("tap_ms").is_none(),
        "harness overhead stays out of the tap measurement path"
    );
    let _ = PathBuf::new();
}
