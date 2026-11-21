// C111 — the wire-class TLS scenario (ADR-0002): a remote MCP server
// over Streamable HTTP's TLS class. The python fixture completes one
// TLS exchange (initialize, tools/call) through the host libssl, the
// tap runs throughout in attributed mode, and the ledger carries the
// merged session events captured at the TLS boundary: the method, the
// arguments and the result.
// Spec: docs/spec.md#5-collectors, docs/spec.md#8-modes.
// Cell ledger: tests/matrix/LEDGER.md.

use std::io::BufRead;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

#[test]
fn c111_the_tls_scenario_answers_the_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    // the tap: three-second window, attributed mode (the default)
    let mut tap = bin()
        .args(["tap", "--ledger"])
        .arg(&ledger)
        .arg("--duration")
        .arg("9")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("agentpcap binary");

    // the cert chain + the fixture ride the repo
    if !std::path::Path::new("/tmp/agentpcap-tls-cert.pem").is_file() {
        let gen = Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-keyout",
                "/tmp/agentpcap-tls-key.pem", "-out", "/tmp/agentpcap-tls-cert.pem",
                "-days", "2", "-nodes", "-subj", "/CN=lab",
            ])
            .stderr(Stdio::null())
            .status()
            .expect("openssl runs");
        assert!(gen.success());
    }
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval/fixtures/mcp-tls.py");
    std::fs::copy(fixture.canonicalize().expect("the fixture ships"), "/tmp/agentpcap-c111-tls.py")
        .expect("the fixture copies");

    std::thread::sleep(Duration::from_millis(1200));

    let mut server = Command::new("python3")
        .args(["-u", "/tmp/agentpcap-c111-tls.py", "server", "0", "c111"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the python server spawns");
    let port: String = std::io::BufReader::new(server.stdout.take().unwrap())
        .lines()
        .next()
        .and_then(|l| l.ok())
        .unwrap_or_default();
    eprintln!("c111 receipt: server port={port}");
    let client = Command::new("python3")
        .args(["-u", "/tmp/agentpcap-c111-tls.py", "client", &port, "c111"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the python client spawns");
    assert!(client.success(), "the TLS exchange completes");
    let _ = server.wait();

    // the window runs out: the flush lands what capture loss parked
    let _ts = tap.wait().expect("tap exits at its deadline");

    let text = std::fs::read_to_string(&ledger).unwrap();
    let recs: Vec<serde_json::Value> = text
        .lines()
        .flat_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect();
    eprintln!(
        "c111 ledger receipt: records={} events={:?} transports={:?}",
        recs.len(),
        recs.iter().map(|r| r["event"].as_str()).collect::<Vec<_>>(),
        recs.iter().map(|r| r["transport"].as_str()).collect::<Vec<_>>()
    );
    // the TLS-boundary records ride the tcp transport with the
    // tls-boundary evidence
    let tls: Vec<&serde_json::Value> = recs
        .iter()
        .filter(|r| {
            r["transport"] == "tcp"
                && r["evidence"]
                    .as_array()
                    .map(|e| e.iter().any(|x| x == "tls-boundary"))
                    .unwrap_or(false)
        })
        .collect();
    eprintln!("c111 tls receipt: tls-records={}", tls.len());
    assert!(!tls.is_empty(), "the tls-boundary capture rode the ledger");
    let init = tls.iter().find(|r| r["event"] == "init");
    let init = init.expect("the initialize pair merges from the TLS plaintext");
    assert_eq!(init["mode"], "attributed");
    assert_eq!(init["protocol_version"], "2025-06-18");
    assert_eq!(
        init["payload"]["result"]["serverInfo"]["name"],
        "tls-server",
        "the merged payload carries the result's content - attributed capture"
    );
    let call = tls.iter().find(|r| r["event"] == "tools-call");
    let call = call.expect("the tools-call pair merges from the TLS plaintext");
    assert_eq!(call["tool_name"].as_str(), Some("fetch"));
    assert_eq!(
        call["payload"]["result"]["content"][0]["text"],
        "tls-hello",
        "the tool result rides the TLS session"
    );
}
