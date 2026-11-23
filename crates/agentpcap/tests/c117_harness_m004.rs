// C117 — the evaluation harness scaffold (spec section 13): the Python
// harness under `eval/` reproduces ONE full M-item end to end — M004's
// ledger fidelity on capability drift — consuming only the CLI and
// export surfaces. The harness spawns the real tap per scenario, plays
// the stdio exchange whose server re-scopes mid-flight, reads the
// capture through `export`, selects its own session by the run-unique
// server name, slices the capture at the change point (owner-only
// files), and the CLI `diff` answers the drift events kind-for-kind
// against the seeds — the kinds, the description texts, the added and
// removed names, and the capability fingerprints. The negative face:
// with the capability member stripped from the seeds the fidelity
// fails by design — losing capability data never passes silently.
// Harness overhead stays out of the tap's measurement path: the
// receipt carries no tap timing.
// Cell ledger: tests/matrix/LEDGER.md.

use std::path::PathBuf;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentpcap")
}

fn harness(dir: &std::path::Path, extra: &[&str]) -> (bool, serde_json::Value) {
    let eval_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval")
        .canonicalize()
        .expect("the eval package resolves");
    let out = std::process::Command::new("python3")
        .args(["-m", "agentpcap_eval.m004"])
        .arg("--binary")
        .arg(bin())
        .arg("--workdir")
        .arg(dir.to_str().expect("the workdir stays utf8"))
        .args(extra)
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
    eprintln!("c117 harness stdout: {}", String::from_utf8_lossy(&out.stdout));
    eprintln!("c117 harness stderr: {}", String::from_utf8_lossy(&out.stderr));
    let receipt = serde_json::from_slice(&out.stdout)
        .expect("the harness receipt is one JSON object");
    (out.status.success(), receipt)
}

#[test]
fn c117_the_harness_runs_the_m004_fidelity_item_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let (ok, receipt) = harness(dir.path(), &[]);
    assert!(ok, "the harness M004 item answers exit 0 end to end");
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
    // the seed names: the added and removed faces compare against the
    // seeds, not only the kinds
    let added = receipt["diff"]["added"]
        .as_array()
        .expect("the receipt carries the added names")
        .iter()
        .filter_map(|n| n.as_str())
        .collect::<Vec<_>>();
    assert_eq!(added, vec!["write"], "the seeded added tool rides");
    let removed = receipt["diff"]["removed"]
        .as_array()
        .expect("the receipt carries the removed names")
        .iter()
        .filter_map(|n| n.as_str())
        .collect::<Vec<_>>();
    assert_eq!(removed, vec!["gone"], "the seeded removed tool rides");
    // the capability fingerprints: present, differing — the rescoped
    // event never passes on a null-fingerprint fallback
    assert_eq!(
        receipt["diff"]["fingerprint_face"].as_str(),
        Some("capability"),
        "the fingerprint face names the capability surface"
    );
    let r_before = receipt["diff"]["rescoped"]["before"]
        .as_str()
        .filter(|s| !s.is_empty())
        .expect("the rescoped before fingerprint rides and is non-null");
    let r_after = receipt["diff"]["rescoped"]["after"]
        .as_str()
        .filter(|s| !s.is_empty())
        .expect("the rescoped after fingerprint rides and is non-null");
    assert_ne!(r_before, r_after, "the fingerprints differ across the change");
    // the overhead face: no timing rides inside the tap path, the receipt
    // carries none
    assert!(
        receipt.get("tap_ms").is_none(),
        "harness overhead stays out of the tap measurement path"
    );
}

#[test]
fn c117_the_negative_face_fails_without_capability_data() {
    let dir = tempfile::tempdir().unwrap();
    // the seeds strip the capability member entirely: the fingerprints
    // cannot ride — the fidelity face fails by design
    let (ok, receipt) = harness(dir.path(), &["--strip-caps"]);
    assert_eq!(
        receipt["item"].as_str(),
        Some("M004"),
        "the negative receipt names the M-item"
    );
    assert_eq!(
        receipt["diff"]["fingerprint_face"].as_str(),
        Some("absent"),
        "the negative face names the absent capability surface"
    );
    assert_eq!(
        receipt["result"].as_str(),
        Some("fail"),
        "losing capability data never passes the fidelity face"
    );
    assert!(!ok, "the negative run answers exit 1");
}
