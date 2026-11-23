// C119 — the M003 transport-coverage matrix on the harness scaffold
// (spec section 13, issue #27): each transport of the coverage claim —
// stdio, Streamable HTTP over TLS, legacy HTTP+SSE, A2A detection —
// runs through the harness and answers a coverage verdict per row; a
// face the capture cannot support names its gap with its issue link.
// Gaps are enumerated, never implicit. The receipt carries no
// tap-internal timing.
// Cell ledger: tests/matrix/LEDGER.md.

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentpcap")
}

#[test]
fn c119_the_m003_matrix_reports_every_transport_row() {
    let dir = tempfile::tempdir().unwrap();
    let eval_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval")
        .canonicalize()
        .expect("the eval package resolves");
    let out = std::process::Command::new("python3")
        .args(["-m", "agentpcap_eval.m003"])
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
    eprintln!("c119 harness stdout: {}", String::from_utf8_lossy(&out.stdout));
    eprintln!("c119 harness stderr: {}", String::from_utf8_lossy(&out.stderr));
    let receipt: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("the harness receipt is one JSON object");
    assert_eq!(
        receipt["item"].as_str(),
        Some("M003"),
        "the receipt names the M-item"
    );
    // the exit contract: 0 when every row carries a verdict and every
    // gap names its evidence; 1 otherwise
    let expected_code = if receipt["gaps"].is_null() {
        panic!("the receipt carries the gaps list")
    } else if receipt["matrix"].as_array().expect("the matrix rides").len() == 4 {
        0
    } else {
        1
    };
    assert!(out.status.success() || expected_code == 1 || out.status.code() == Some(0),
        "the rig exit stays coherent with the receipt");
    // the four transport rows, each with a verdict and evidence
    let matrix = receipt["matrix"].as_array().expect("the matrix rides");
    assert_eq!(matrix.len(), 4, "the matrix carries the four transports");
    let transports: Vec<&str> = matrix
        .iter()
        .filter_map(|r| r["transport"].as_str())
        .collect();
    assert_eq!(
        transports,
        vec!["stdio", "streamable-http-tls", "legacy-http-sse", "a2a"],
        "the matrix carries the coverage claim's transports in order"
    );
    // the stdio and a2a rows pass their capture faces today
    let stdio = matrix
        .iter()
        .find(|r| r["transport"] == "stdio")
        .expect("the stdio row rides");
    assert_eq!(stdio["verdict"], "covered", "the stdio row is covered");
    let a2a = matrix
        .iter()
        .find(|r| r["transport"] == "a2a")
        .expect("the a2a row rides");
    assert_eq!(a2a["verdict"], "covered", "the a2a detection row is covered");
    // the tls row: covered on the boundary face
    let tls = matrix
        .iter()
        .find(|r| r["transport"] == "streamable-http-tls")
        .expect("the tls row rides");
    assert_eq!(
        tls["verdict"], "covered",
        "the streamable-http-tls row rides the boundary face"
    );
    // the sse row: the GAP named with its evidence — never implicit
    let sse = matrix
        .iter()
        .find(|r| r["transport"] == "legacy-http-sse")
        .expect("the sse row rides");
    assert_eq!(
        sse["verdict"], "gap",
        "the legacy-http-sse row names its gap honestly"
    );
    let sse_evidence = sse["evidence"].as_str().expect("the gap evidence rides");
    assert!(
        sse_evidence.contains("/issues/83"),
        "the sse gap names its issue link: {sse_evidence}"
    );
}

#[test]
fn c119_the_a2a_row_classifies_from_protocol_semantics() {
    let dir = tempfile::tempdir().unwrap();
    let eval_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval")
        .canonicalize()
        .expect("the eval package resolves");
    // the a2a row's face in isolation: message/send classifies a2a
    let out = std::process::Command::new("python3")
        .args(["-m", "agentpcap_eval.m003"])
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
    let receipt: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("the receipt is one JSON object");
    let a2a = receipt["matrix"]
        .as_array()
        .and_then(|m| m.iter().find(|r| r["transport"] == "a2a"))
        .expect("the a2a row rides");
    // the classification rides protocol semantics, never a method
    // catalog alone: the evidence names the a2a-verdict record count
    let ev = a2a["evidence"].as_str().unwrap_or_default();
    assert!(
        ev.contains("a2a-verdict records="),
        "the a2a row names its classification receipt: {ev}"
    );
}
