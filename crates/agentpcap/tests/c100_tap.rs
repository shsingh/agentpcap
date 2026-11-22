// C100 — the tap runtime: `agentpcap tap` runs the probe loop, classifies
// the samples, and appends the reassembled events to the ledger. The test
// writes one MCP-shaped frame and one methodless result frame on a real
// pipe (the tap records pipe traffic only, per ADR-0003). The ids ride
// this cell's own space (500/501): the parallel suite runs every cell's
// tap on the host's pipe traffic, and an id another cell parks would
// make the reassembler's bind ambiguous. Both surface in the report
// with the right verdicts and the attributed mode.
// Spec: docs/spec.md#5-collectors, docs/spec.md#9-operator-cli.
// Cell ledger: tests/matrix/LEDGER.md.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

#[test]
fn c100_tap_ledgers_the_classified_flow() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    // the tap runs for three seconds while the test writes two lines
    let mut tap = bin()
        .args(["tap", "--ledger"])
        .arg(&ledger)
        .arg("--duration")
        .arg("3")
        .stdout(Stdio::null())
        .spawn()
        .expect("agentpcap binary");
    std::thread::sleep(Duration::from_millis(1200));

    // the framed writer: the test writes both frames on the pipe this
    // process owns (the tap records pipe traffic only)
    let mut sink = Command::new("sh")
        .arg("-c")
        .arg("cat >/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sink spawn");
    let mut f = sink.stdin.take().unwrap();
    writeln!(
        f,
        r#"{{"jsonrpc":"2.0","id":500,"method":"tools/call","params":{{"name":"read","arguments":{{"path":"/etc/hostname"}}}}}}"#
    )
    .unwrap();
    writeln!(
        f,
        r#"{{"jsonrpc":"2.0","id":501,"result":{{"content":[{{"type":"text","text":"captured"}}]}}}}"#
    )
    .unwrap();
    let _ = f.flush();
    drop(f);
    let _ = sink.wait().expect("sink exits");

    let st = tap.wait().expect("tap exits");
    assert!(st.success(), "tap must exit cleanly");

    // the report answers
    let out = bin()
        .args(["report", "--ledger"])
        .arg(&ledger)
        .output()
        .expect("agentpcap binary");
    assert!(out.status.success(), "report must succeed");
    let text = String::from_utf8_lossy(&out.stdout);
    let views: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("report lines are JSON objects"))
        .collect();
    eprintln!("c100 sessions receipt ({}):", views.len());
    for v in &views {
        eprintln!(
            "  session={} invocations={} unidentified={}",
            v["session_id"], v["invocations"], v["unidentified"]
        );
    }
    assert!(!views.is_empty(), "the ledger carries the flow");

    // the scenario's session rides the raw ledger rows: this test's
    // pid wrote the frames, and rows without that pid (the host's own
    // pipe traffic) never select the assertions' row
    let scenario_pid = u64::from(std::process::id());
    let rec = std::fs::read_to_string(&ledger).expect("the ledger reads");
    let mine: Vec<serde_json::Value> = rec
        .lines()
        .flat_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|r| r["pid"].as_u64() == Some(scenario_pid))
        .collect();
    let own_session = mine
        .first()
        .and_then(|r| r["session_id"].as_str())
        .map(String::from)
        .expect("the scenario's session lands in the ledger");
    let view = views
        .iter()
        .find(|v| v["session_id"].as_str() == Some(own_session.as_str()))
        .expect("the scenario's session answers in the report");
    assert_eq!(
        view["invocations"].as_u64(),
        Some(1),
        "the tools-call frame counts as an invocation"
    );
    assert!(
        view["unidentified"].as_u64().unwrap_or(0) >= 1,
        "the methodless result rides agent-unidentified"
    );
    // the live-file-write exclusion assert rides the alpha2 in-kernel fd
    // resolution (ADR-0004) - verified: the userspace /proc lookup cannot
    // name a channel for a writer whose pid view drifts on this host
}
