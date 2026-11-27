// C119 — the M003 transport-coverage matrix on the harness scaffold
// (spec section 13, issue #27): each transport of the coverage claim —
// stdio, Streamable HTTP over TLS, legacy HTTP+SSE, A2A detection —
// runs through the harness and answers a coverage verdict per row. The
// coverage ties to the run's own faces: a run-unique server name and
// marker ride every row, so unrelated host traffic never satisfies a
// row. The rows read their records through the export surface. A face
// the capture cannot support names its gap with its issue link —
// gaps are enumerated, never implicit. The receipt carries no
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
    // the stdio row merges its own session AND carries the run marker
    // (the seeded result text) — the flush fallback never passes
    let stdio = matrix
        .iter()
        .find(|r| r["transport"] == "stdio")
        .expect("the stdio row rides");
    assert_eq!(stdio["verdict"], "covered", "the stdio row is covered");
    let stdio_ev = stdio["evidence"].as_str().unwrap_or_default();
    assert!(
        stdio_ev.contains("merged=true") && stdio_ev.contains("seeded=true"),
        "the stdio row names the merged + seeded faces: {stdio_ev}"
    );
    // the tls row: covered on the run's own boundary face
    let tls = matrix
        .iter()
        .find(|r| r["transport"] == "streamable-http-tls")
        .expect("the tls row rides");
    assert_eq!(
        tls["verdict"], "covered",
        "the streamable-http-tls row rides the boundary face"
    );
    let tls_ev = tls["evidence"].as_str().unwrap_or_default();
    assert!(
        tls_ev.contains("owned boundary records="),
        "the tls row names its marker tie: {tls_ev}"
    );
    // the sse row: COVERED on the run's own served exchange (the
    // per-flavor park face closed the stale-content defect; the C115
    // face re-lands)
    let sse = matrix
        .iter()
        .find(|r| r["transport"] == "legacy-http-sse")
        .expect("the sse row rides");
    assert_eq!(
        sse["verdict"], "covered",
        "the legacy-http-sse row rides the served exchange"
    );
    let sse_evidence = sse["evidence"].as_str().expect("the coverage face rides");
    assert!(
        sse_evidence.contains("owned boundary records=")
            && sse_evidence.contains("sse-merged=true"),
        "the sse row names its marker tie and the merged face: {sse_evidence}"
    );
    // the a2a row: covered with the owned-classification receipt
    let a2a = matrix
        .iter()
        .find(|r| r["transport"] == "a2a")
        .expect("the a2a row rides");
    assert_eq!(a2a["verdict"], "covered", "the a2a detection row is covered");
    let a2a_ev = a2a["evidence"].as_str().unwrap_or_default();
    assert!(
        a2a_ev.contains("owned a2a records="),
        "the a2a row names its owned-classification receipt: {a2a_ev}"
    );
    // the per-flavor park face closed the legacy-SSE gap (issue #83):
    // the receipt answers an empty gap list — nothing implicit
    let gapped = receipt["gaps"].as_array().expect("the gaps ride");
    assert!(
        gapped.is_empty(),
        "the gap list stays empty: {gapped:?}"
    );
}

#[test]
fn c119_the_a2a_row_names_zero_records_when_the_face_is_absent() {
    // the focused face replacing the duplicate full matrix run: the a2a
    // row's receipt prefix carries the record count, so a zero-record
    // face reads differently from a covered one — the row's covered
    // verdict requires owned > 0, and this face checks the prefix is a
    // count face, never a bare truthiness (the classification test
    // face distinguished counts from booleans)
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
    let _ = out.status;
    let receipt: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("the receipt is one JSON object");
    let a2a = receipt["matrix"]
        .as_array()
        .and_then(|m| m.iter().find(|r| r["transport"] == "a2a"))
        .expect("the a2a row rides");
    let ev = a2a["evidence"].as_str().unwrap_or_default();
    let prefix = "owned a2a records=";
    let i = ev.find(prefix).expect("the a2a row names its count face");
    let count_text: String = ev[i + prefix.len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let count: usize = count_text.parse().expect("the count face parses");
    // the covered verdict REQUIRES this count to be non-zero: the row
    // never reports covered on zero records
    if a2a["verdict"] == "covered" {
        assert!(count > 0, "a covered a2a row never rides zero records");
    } else {
        assert!(ev.contains("marker="), "a gap row still names its marker tie");
    }
}
