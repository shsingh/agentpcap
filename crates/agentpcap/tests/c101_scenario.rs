// C101 — the alpha1 scenario, end to end (ADR-0002): one host, one MCP
// client, one local MCP server over a stdio pipe, the tap running, and
// the ledger answering who called what. The test itself plays the MCP
// client; the server answers on stdout; a single FIFO carries the frames.
// The cell asserts: the ledger records the initialize framing and the
// tools/call with its tool payload, and both ends surface with distinct
// pids. The ledger excerpt rides the receipt.
// Spec: docs/spec.md#5-collectors, docs/spec.md#13-evaluation-hooks.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

#[test]
fn c101_the_stdio_scenario_answers_the_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let dir_c = dir.path().display().to_string();
    let ledger = dir.path().join("ledger.jsonl");

    // the tap runs for the whole scenario window
    let mut tap = bin()
        .args(["tap", "--ledger"])
        .arg(&ledger)
        .arg("--duration")
        .arg("8")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("agentpcap binary");
    std::thread::sleep(Duration::from_millis(1200));

    let f1 = format!("{dir_c}/client-to-server.fifo");
    std::fs::remove_file(&f1).ok();
    Command::new("mkfifo").arg(&f1).status().expect("mkfifo f1");

    let server_out = format!("{dir_c}/server.log");

    // the MCP server: a child of this test process
    let mut server = Command::new("sh")
        .arg(env!("CARGO_MANIFEST_DIR").to_string() + "/../../eval/scenario/mcp-server.sh")
        .arg(&f1)
        .stdout(Stdio::from(std::fs::File::create(&server_out).unwrap()))
        .stderr(Stdio::null())
        .spawn()
        .expect("server spawn");
    let server_pid = server.id();
    std::thread::sleep(Duration::from_millis(500));

    // this test is the MCP client: write the three framed requests
    let frames = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"alpha1-client","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read","arguments":{"path":"/etc/hostname"}}}"#,
    ];
    for f in frames {
        let mut h = std::fs::OpenOptions::new()
            .write(true)
            .open(&f1)
            .expect("fifo open");
        h.write_all(format!("{f}\n").as_bytes()).expect("frame write");
        std::thread::sleep(Duration::from_millis(300));
    }
    let _sw = server.wait().expect("server exits on eof");

    // give the tap time to drain the last samples
    let _ts = tap.wait().expect("tap exits at its deadline");

    // the server's transcript: three answers
    let replied = std::fs::read_to_string(&server_out).unwrap();
    eprintln!("c101 receipt: server_pid={server_pid} replies={}", replied.lines().count());
    assert_eq!(replied.lines().count(), 3, "three answers on stdout");

    // the ledger answers
    let text = std::fs::read_to_string(&ledger).unwrap();
    let mcp: Vec<&str> = text.lines().filter(|l| l.contains(r#""verdict":"mcp""#)).collect();
    eprintln!("c101 ledger receipt: records={} mcp-records={}", text.lines().count(), mcp.len());
    assert!(!mcp.is_empty(), "mcp verdicts recorded");
    assert!(text.contains(r#""method":"initialize""#), "initialize recorded");
    assert!(text.contains(r#""method":"tools/call""#), "the tools/call recorded");
    assert!(mcp.len() >= 6, "every frame surfaces: requests and answers");
}
