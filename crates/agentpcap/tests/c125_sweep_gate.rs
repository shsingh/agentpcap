// C125 — the sweep-gate face (issue #88): the tap's pending sweep rides
// a 50 ms gate in the drain loop (the per-turn sweep face burned the
// hot loop). The behaviour's check: through the BINARY, a parked
// request with no response still delivers its no-response row — the
// gate never swallows a due sweep or the flush. The reassembler's own
// expiry units ride r118 (the ttl face, the once-only face, the idle
// session face).
// Spec: docs/spec.md#11-coexistence-and-flow-deduplication.

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentpcap")
}

#[test]
fn c125_the_sweep_gate_never_swallows_the_no_response_face() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("c125.jsonl");
    let ledger_s = ledger.to_str().expect("the ledger path stays utf8");

    let mut tap = std::process::Command::new(bin())
        .args(["tap", "--ledger", ledger_s, "--duration", "4"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the tap spawns");

    // a tools/call frame with NO response: the request parks and lands
    // the no-response face at the pending expiry
    let frame = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read","arguments":{"path":"/tmp/x"}}}"#;
    let mut sink = std::process::Command::new("sh")
        .arg("-c")
        .arg("cat >/dev/null")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the sink spawns");
    use std::io::Write;
    // the calibration rides outside the capture face (the same face the
    // m002 harness rides): the write lands after the probe attaches
    std::thread::sleep(std::time::Duration::from_millis(1300));
    let stdin = sink.stdin.as_mut().expect("the sink stdin opens");
    stdin.write_all(frame.as_bytes()).unwrap();
    stdin.write_all(b"\n").unwrap();
    drop(sink.stdin.take());
    sink.wait().unwrap();

    let status = tap.wait().expect("the tap runs to completion");
    assert!(status.success(), "the tap face rides exit 0");

    let text = std::fs::read_to_string(ledger_s).expect("the ledger rides");
    let rows: Vec<serde_json::Value> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("the ledger rows parse"))
        .collect();
    assert!(
        !rows.is_empty(),
        "the capture carries at least the request's rows"
    );
    let methods: Vec<&str> = rows
        .iter()
        .filter_map(|r| r.get("method").and_then(|m| m.as_str()))
        .collect();
    assert!(
        methods.contains(&"tools/call"),
        "the request lands: the ledger carries the tools/call face"
    );
    let no_response = rows.iter().any(|r| {
        r.get("evidence")
            .and_then(|e| e.as_array())
            .map(|e| e.iter().any(|v| v.as_str() == Some("no-response")))
            .unwrap_or(false)
    });
    assert!(
        no_response,
        "the gate never swallows the no-response face: the parked request delivers"
    );
}
