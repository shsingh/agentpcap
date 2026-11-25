// C126 — the dead-sink echo face (issue #88's cost face; the
// doubled-sample face rides the C116b row): a frame written into a
// sink that /dev/nulls it and DIES inside the pop window rides TWO
// candidate writes — the writer's pipe write, and the sink's echo
// write to its /dev/null fd after the fd resolve failed. The
// unresolved loss rows key the CONTENT hash inside a one-second
// observation bucket, so the echo copy keys the face the writer's
// first copy keyed and the ledger's Duplicate face absorbs it: one
// record per logical frame, never a real-call disappearance past it.
// Spec: docs/spec.md#11-coexistence-and-flow-deduplication.

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentpcap")
}

#[test]
fn c126_the_dead_sink_echo_never_lands_a_second_row() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("c126.jsonl");
    let ledger_s = ledger.to_str().expect("the ledger path stays utf8");

    let mut tap = std::process::Command::new(bin())
        .args(["tap", "--ledger", ledger_s, "--duration", "4"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the tap spawns");

    // a tools/call frame with NO response: the write-side copy parks
    // with the writer's own pid; the sink's echo copy (its /dev/null
    // fd, dead at the pop) keys the face the writer's first copy
    // keyed and the ledger absorbs it. The frame carries THIS RUN's
    // marker: the count face never satisfies on unrelated traffic.
    let marker = format!("c126-marker-{}", std::process::id());
    let frame = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read","arguments":{{"path":"{marker}"}}}}}}"#
    );
    let mut sink = std::process::Command::new("sh")
        .arg("-c")
        .arg("cat >/dev/null")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("the sink spawns");
    use std::io::Write;
    // the calibration rides outside the capture face (the same face
    // the m002 harness rides): the write lands after the probe attaches
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
    // the marker face selects THIS run's frame only; both copies of a
    // marked frame stay in the selection (the dedupe check rides)
    let marked: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| {
            serde_json::to_string(r)
                .map(|s| s.contains(&marker))
                .unwrap_or(false)
        })
        .collect();
    let marked_len = marked.len();
    let calls: Vec<&serde_json::Value> = marked
        .into_iter()
        .filter(|r| r.get("method").and_then(|m| m.as_str()) == Some("tools/call"))
        .collect();
    eprintln!(
        "c126 ledger receipt: records={} marked={} call_rows={} evidence={:?}",
        rows.len(),
        marked_len,
        calls.len(),
        calls.iter().map(|r| r["evidence"].clone()).collect::<Vec<_>>()
    );
    assert_eq!(
        calls.len(),
        1,
        "one logical frame leaves one record: the echo copy absorbs, never a direction pair"
    );
    assert!(
        calls[0]["evidence"]
            .as_array()
            .map(|e| e.iter().any(|v| v.as_str() == Some("probe-face:send")))
            .unwrap_or(false),
        "the pipe class stamps its write face"
    );
    assert!(
        calls[0]["evidence"]
            .as_array()
            .map(|e| e.iter().any(|v| v.as_str() == Some("no-response")))
            .unwrap_or(false),
        "the parked request keeps its no-response face (capture loss degrades, never drops)"
    );
}
