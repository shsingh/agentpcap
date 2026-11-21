// C100 — the tap runtime: `agentpcap tap` runs the probe loop, classifies
// the samples, and appends the classified events to the ledger. The test
// writes one MCP-shaped frame and one methodless result frame on a real
// pipe (the tap records pipe traffic only, per ADR-0003); both surface in
// the report with the right verdicts and the attributed mode.
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
        .stderr(Stdio::null())
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
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read","arguments":{{"path":"/etc/hostname"}}}}}}"#
    )
    .unwrap();
    writeln!(
        f,
        r#"{{"jsonrpc":"2.0","id":2,"result":{{"content":[{{"type":"text","text":"captured"}}]}}}}"#
    )
    .unwrap();
    let _ = f.flush();
    drop(f);
    let _ = sink.wait().expect("sink exits");

    let st = tap.wait().expect("tap exits");
    assert!(st.success(), "tap must exit cleanly");
    drop(g);

    // the report answers
    let out = bin()
        .args(["report", "--ledger"])
        .arg(&ledger)
        .output()
        .expect("agentpcap binary");
    assert!(out.status.success(), "report must succeed");
    let text = String::from_utf8_lossy(&out.stdout);
    let events: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("report lines are JSON objects"))
        .collect();
    let summary: Vec<String> = events
        .iter()
        .map(|v| {
            format!(
                "verdict={} event={} method={:?} pid={}",
                v["verdict"].as_str().unwrap_or("?"),
                v["event"].as_str().unwrap_or("?"),
                v["method"],
                v["pid"]
            )
        })
        .collect();
    eprintln!("c100 ledger receipt ({}):", events.len());
    for l in &summary {
        eprintln!("  {l}");
    }
    assert!(!events.is_empty(), "the ledger carries the flow");

    let mcp = events.iter().find(|v| v["verdict"].as_str() == Some("mcp"));
    let mcp = mcp.expect("the MCP frame is classified");
    assert_eq!(mcp["mode"].as_str().unwrap(), "attributed");
    assert!(mcp["pid"].as_u64().unwrap() > 0);

    let unid = events
        .iter()
        .find(|v| v["verdict"].as_str() == Some("agent-unidentified"));
    assert!(unid.is_some(), "the methodless result is agent-unidentified");
    // the live-file-write exclusion assert rides the alpha2 in-kernel
    // fd resolution (ADR-0004): the userspace /proc lookup cannot name a
    // channel for a writer whose /proc view drifts on this host
}
