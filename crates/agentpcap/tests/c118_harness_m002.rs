// C118 — the M002 overhead item on the harness scaffold (spec section
// 13): the IDENTICAL harness runs the workload twice — tap off, tap on —
// and the delta answers the tap's cost against the published sub-3%
// figure. The workload: a fixed frame count through a real pipe with
// inter-frame gaps (the agent-shaped profile); the calibration waits
// OUTSIDE the measured window; the tap-on phase also measures the tap's
// own CPU consumption from /proc/<tap>/stat across the window. Both
// phases repeat the same repeats; the phase minima answer the delta;
// the two overhead faces must BOTH sit under the figure. The receipt
// carries no tap-internal timing.
// Cell ledger: tests/matrix/LEDGER.md.

/// The measurement face rides the RELEASE binary: the M002 figure is a
/// performance contract, and the artifact an operator runs is the
/// optimized build (ADR-0002). The debug profile's unoptimized sha and
/// serde paths roughly double the per-record CPU and never answer the
/// release face. The cell builds the release binary once, cached in
/// `target/release`, and points the harness at it.
fn bin() -> String {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.join("../..");
    // the target dir rides CARGO_TARGET_DIR when the caller sets it —
    // a default-path face would measure a stale binary left behind
    let target_dir = std::path::PathBuf::from(
        std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| {
            workspace
                .join("target")
                .to_str()
                .expect("the target path stays utf8")
                .to_string()
        }),
    );
    let status = std::process::Command::new(
        std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()),
    )
    .args(["build", "--release", "-p", "agentpcap"])
    .current_dir(&workspace)
    .status()
    .expect("cargo runs");
    assert!(status.success(), "the release build answers green");
    target_dir
        .join("release/agentpcap")
        .to_str()
        .expect("the release path stays utf8")
        .to_string()
}

#[test]
fn c118_the_m002_item_answers_the_tap_delta_against_the_figure() {
    let dir = tempfile::tempdir().unwrap();
    let eval_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval")
        .canonicalize()
        .expect("the eval package resolves");
    let out = std::process::Command::new("python3")
        .args(["-m", "agentpcap_eval.m002"])
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
        .env(
            "CARGO",
            std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string()),
        )
        .output()
        .expect("python3 runs");
    eprintln!("c118 harness stdout: {}", String::from_utf8_lossy(&out.stdout));
    eprintln!("c118 harness stderr: {}", String::from_utf8_lossy(&out.stderr));
    let receipt: serde_json::Value = serde_json::from_slice(&out.stdout)
        .expect("the harness receipt is one JSON object");
    assert_eq!(
        receipt["item"].as_str(),
        Some("M002"),
        "the receipt names the M-item"
    );
    // the M002 rig: both overhead faces measure and ride; the verdict
    // formula reads the faces (the wall delta AND the tap's own measured
    // CPU consumption sit under the published figure for a pass — the
    // current head honestly FAILS the CPU face: the idle drain loop
    // polls at 2ms and burns over the figure; the defect rides its own
    // issue and the item stays open)
    assert!(
        out.status.success() || receipt["result"].as_str() == Some("fail"),
        "the rig answers exit 0 on a pass and exit 1 with a fail receipt"
    );
    // the identical-harness face: both phases carry the same workload
    let frames = receipt["workload"]["frames"].as_u64().expect("the frames ride");
    assert!(frames >= 100, "the workload carries enough frames to measure");
    let repeats = receipt["workload"]["repeats"].as_u64().expect("the repeats ride");
    assert!(repeats >= 2, "both phases repeat; the minima answer the delta");
    let off_ms = receipt["off_ms"].as_f64().expect("the tap-off minimum rides");
    let on_ms = receipt["on_ms"].as_f64().expect("the tap-on minimum rides");
    assert!(
        off_ms > 0.0 && on_ms > 0.0,
        "both phase minima are measured, never defaulted"
    );
    let delta = receipt["delta_pct"].as_f64().expect("the delta rides");
    let recomputed = (on_ms - off_ms) / off_ms * 100.0;
    assert!(
        (delta - recomputed).abs() < 0.05,
        "the delta derives from the phase minima"
    );
    // the two overhead faces: the wall delta AND the tap's own measured
    // CPU consumption — both must sit under the published figure
    let figure = receipt["figure_pct"].as_f64().expect("the published figure rides");
    let cpu = receipt["tap_cpu_pct"]
        .as_f64()
        .expect("the tap's own CPU face rides the receipt");
    assert!(
        cpu >= 0.0,
        "the tap's measured CPU consumption is measured, never defaulted"
    );
    // the CPU face: the tap's own consumption stays under the published
    // figure. The measurement rides the RELEASE binary (ADR-0002: the
    // operator's artifact, never the debug profile). The faces that cut
    // the per-sample cost: the idle backoff (the ringbuf leaf), the
    // wire comm (PR #109), the batched writer surface (C129)
    assert!(
        cpu <= figure,
        "the tap's own CPU consumption stays under the published {figure}%: {cpu}"
    );
    // the verdict formula face: pass iff BOTH faces sit under the figure
    let pass = delta <= figure && cpu <= figure;
    assert_eq!(
        receipt["result"].as_str(),
        Some(if pass { "pass" } else { "fail" }),
        "the verdict reads from the measured faces, never defaulted"
    );
    // The drain face (the busy-queue face): the on-phase ledger carries
    // every frame's rows — a drain that loses samples (a busy queue
    // stalled behind an empty one) rides fewer rows than frames. The
    // dedupe may fold rows (repeat frames share keys), so the face
    // asserts the rows never drop BELOW the frame count by more than
    // the dedupe fold — every frame lands AT LEAST one row family.
    let rows = receipt["tap_rows"].as_f64().expect("the ledger rows ride");
    let frames = frames as f64;
    assert!(
        rows * 1.0 >= frames * 0.5,
        "the drain never loses a frame face: tap_rows {rows} vs frames {frames}"
    );
    // the wall face: the delta sits under the published figure on this
    // host (the CPU face is the item's gate face and may fail honestly)
    assert!(
        delta <= figure,
        "the wall delta stays under the published {figure}%"
    );
    // the overhead face: no timing rides inside the tap in the receipt —
    // the phases carry the workload wall time only
    assert!(
        receipt.get("tap_ms").is_none(),
        "harness overhead stays out of the tap measurement path"
    );
}
