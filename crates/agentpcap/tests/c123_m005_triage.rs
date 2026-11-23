// C123 — the M005 triage face (spec section 13, issue #29): the
// agent-shaped, unattributed label scores against the metadata
// baseline and the prober baseline. Four real writers ride one tap
// window: mcp-probe (attributed mcp), agent-probe (JSON-RPC framing
// without MCP semantics — ground truth agent-unidentified), logwriter
// and agent-log (plain traffic; agent-log is the DECOY with an
// agent-like comm). The classifier scores from protocol semantics and
// never a catalog (spec section 6): the tap labels the shaped stream
// and stays silent on the plain streams while the catalog labels the
// decoy. The receipt posts precision and the false-positive rates.
// Cell ledger: tests/matrix/LEDGER.md.

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentpcap")
}

#[test]
fn c123_the_triage_label_beats_the_catalog_without_one() {
    let dir = tempfile::tempdir().unwrap();
    let eval_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval")
        .canonicalize()
        .expect("the eval package resolves");
    let out = std::process::Command::new("python3")
        .args(["-m", "agentpcap_eval.m005"])
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
    eprintln!("c123 harness stdout: {}", String::from_utf8_lossy(&out.stdout));
    eprintln!("c123 harness stderr: {}", String::from_utf8_lossy(&out.stderr));
    let receipt: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("the harness receipt is one JSON object");
    assert_eq!(
        receipt["item"].as_str(),
        Some("M005"),
        "the receipt names the M-item"
    );
    assert_eq!(
        receipt["result"].as_str(),
        Some("pass"),
        "the triage face rides: {}",
        receipt["reasons"]
    );
    // the bounded fresh-capture face: the receipt names the attempts
    let attempts = receipt["attempts"].as_u64().expect("the attempts ride");
    assert!(
        (1..=3).contains(&attempts),
        "the face reports its attempt count in the bounded range: {attempts}"
    );
    // the tap scores from protocol semantics: the shaped stream rides
    // agent-unidentified and the plain streams never do
    let tp = receipt["tap"]["true_positives"].as_u64()
        .expect("the true-positive count rides the receipt");
    assert!(tp >= 1, "the shaped stream carries the label: {tp}");
    assert_eq!(
        receipt["tap"]["false_positives"].as_u64(),
        Some(0),
        "the plain streams stay unlabeled: the decoy and its sibling"
    );
    assert_eq!(
        receipt["tap"]["false_positive_rate"].as_f64(),
        Some(0.0),
        "the tap's false-positive rate rides 0 on the seeded mix"
    );
    assert_eq!(
        receipt["tap"]["precision"].as_f64(),
        Some(1.0),
        "every agent-unidentified label is true on the seeded mix"
    );
    // the catalog face: the decoy's agent-like comm catches the
    // metadata baseline — the tap never reads comm names
    let meta_fp = receipt["metadata_baseline"]["false_positive_rate"]
        .as_f64()
        .expect("the metadata false-positive rate rides the receipt");
    assert!(
        meta_fp > 0.0,
        "the decoy catches the name catalog: {meta_fp}"
    );
    assert_eq!(
        receipt["prober_baseline"]["precision"].as_f64(),
        Some(1.0),
        "the prober baseline posts the generator's precision"
    );
    assert_eq!(
        receipt["prober_baseline"]["false_positive_rate"].as_f64(),
        Some(0.0),
        "the prober baseline posts the generator's ground truth"
    );
    // the attributed face: the mcp stream rides verdict mcp
    let mcp_rows = receipt["streams"]["mcp-probe"]["mcp"]
        .as_u64()
        .expect("the mcp stream's verdict counts ride the receipt");
    assert!(mcp_rows >= 1, "the mcp stream labels mcp: {mcp_rows}");
}
