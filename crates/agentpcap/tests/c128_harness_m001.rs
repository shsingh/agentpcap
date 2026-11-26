// C128 — the M001 item on the harness scaffold (issue #26): the seeded
// fleet runs the harness — 3 known MCP sessions plus 2 shadow
// deployments over one tap window; the verdict reads BOTH recall rows
// (the known face and the shadow face answer the discovered/planted
// ratio); the baselines (the header-heuristic class and the active
// probe) ride the receipt's own table. The cell asserts the
// receipt-shape and the verdict-formula faces — never a bent number.
// Spec: docs/spec.md#13-evaluation-hooks.
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentpcap")
}

#[test]
fn c128_the_m001_item_answers_the_fleet_recall() {
    let dir = tempfile::tempdir().unwrap();
    let workdir = dir.path().join("m001-work");
    let marker = format!("m001-run-{}", std::process::id());
    let out = Command::new("python3")
        .arg("-m")
        .arg("agentpcap_eval.m001")
        .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../eval"))
        .arg("--binary")
        .arg(bin())
        .arg("--workdir")
        .arg(workdir.canonicalize().unwrap_or(workdir))
        .arg("--window")
        .arg("8")
        .arg("--marker")
        .arg(&marker)
        .env("PYTHONPATH", format!(
            "{}/../../eval",
            env!("CARGO_MANIFEST_DIR")
        ))
        .output()
        .expect("the harness runs");
    eprintln!(
        "c128 harness status: {} stderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    eprintln!("c128 harness stdout: {}", &text[..text.len().min(1200)]);
    let receipt: serde_json::Value =
        serde_json::from_str(text.trim()).expect("the harness receipt is one JSON object");

    assert_eq!(receipt["item"], "M001", "the receipt names its item");
    assert_eq!(
        receipt["fleet"]["known"].as_u64(),
        Some(3),
        "the seeded known face rides the receipt"
    );
    assert_eq!(
        receipt["fleet"]["shadow"].as_u64(),
        Some(2),
        "the shadow face rides the receipt"
    );
    let rows = receipt["recall_rows"].as_array().expect("the recall rows ride");
    assert_eq!(
        rows.len(),
        2,
        "the known and the shadow classes answer"
    );
    for r in rows {
        let planted = r["planted"].as_u64().expect("the planted face rides");
        let agentpcap = r["agentpcap"].as_u64().expect("the agentpcap face rides");
        // the verdict formula face: recall = discovered / planted
        let recall = r["recall_agentpcap"].as_f64().expect("the recall rides");
        let recomputed = agentpcap as f64 / planted as f64;
        assert!(
            (recall - recomputed).abs() < 0.001,
            "the recall derives from the discovered and the planted faces"
        );
    }
    // the baseline table rides the receipt
    let table = receipt["baseline_table"].as_array().expect("the baseline table rides");
    for r in table {
        assert!(
            r.get("header_heuristic").is_some(),
            "the header-heuristic class rides the table"
        );
        assert!(
            r.get("active_probe").is_some(),
            "the active-probe class rides the table"
        );
    }
    // the verdict must carry PASS: recall 1.0 on both planted classes —
    // a fail faces the item's issue as a defect, never a bent assert
    assert_eq!(
        receipt["result"], "pass",
        "the M001 verdict answers pass on the seeded fleet"
    );
}
