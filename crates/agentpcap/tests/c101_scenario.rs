// C101 — the alpha1 scenario, end to end (ADR-0002): one host, one MCP
// client, one local MCP server over a stdio pipe, the tap running, and
// the ledger answering who called what. The test itself plays the MCP
// client: it pipes the three framed requests into the server's stdin,
// and the server answers on stdout (captured). The tap sees every write
// on both ends. The cell asserts: the ledger records the initialize
// framing and the tools/call, and the excerpt rides the receipt.
// Spec: docs/spec.md#5-collectors, docs/spec.md#13-evaluation-hooks.

use std::io::{BufRead, Write};
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

#[test]
fn c101_the_stdio_scenario_answers_the_ledger() {
    let dir = tempfile::tempdir().unwrap();
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
    eprintln!("c101 own pid = {}", std::process::id());
    std::thread::sleep(Duration::from_millis(1200));

    // the MCP server: a child of this test process, frames on its
    // piped stdin, replies on its piped stdout — one real pipe per
    // channel; the shell itself is the writer for both (no redirection
    // forks), so the tap resolves its live fds to the channel inodes
    let mut server = Command::new("sh")
        .arg(env!("CARGO_MANIFEST_DIR").to_string() + "/../../eval/scenario/mcp-server.sh")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("server spawn");
    let server_pid = server.id();
    let mut server_out = server.stdout.take().unwrap();
    let mut server_in = server.stdin.take().unwrap();
    // drain the reply pipe concurrently: the responses = the server's
    // stdout writes on a real pipe the tap records by inode
    let reader = std::thread::spawn(move || {
        let mut text = String::new();
        for l in std::io::BufReader::new(&mut server_out).lines() {
            match l {
                Ok(line) => {
                    text.push_str(&line);
                    text.push('\n');
                }
                Err(_) => break,
            }
        }
        text
    });
    // wait out the tap's calibration: the ledger writer only exists after it
    std::thread::sleep(Duration::from_millis(1200));

    // this test is the MCP client: write the three framed requests
    let frames = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"alpha1-client","version":"0"}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read","arguments":{"path":"/etc/hostname"}}}"#,
    ];
    for f in frames {
        server_in
            .write_all(format!("{f}\n").as_bytes())
            .expect("frame write");
        server_in.flush().expect("frame flush");
        std::thread::sleep(Duration::from_millis(300));
    }
    drop(server_in);
    let _sw = server.wait().expect("server exits on eof");
    let replied = reader.join().expect("the reply reader joins");

    // give the tap time to drain the last samples
    let _ts = tap.wait().expect("tap exits at its deadline");

    // the server's transcript: three answers
    eprintln!("c101 receipt: server_pid={server_pid} replies={}", replied.lines().count());
    assert_eq!(replied.lines().count(), 3, "three answers on the reply pipe");

    let text = std::fs::read_to_string(&ledger).unwrap();
    let recs: Vec<serde_json::Value> = text
        .lines()
        .flat_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect();
    let own = std::process::id() as u64;
    // the reassembled session shape: the initialize, tools/list, and
    // tools/call pairs merge into three session events; the replies
    // bind their requests and leave no orphans (the tap window outlasts
    // the scenario). The suite runs tests in parallel: every tap hears
    // the other tests' pipes, so the records filter to this
    // scenario's own client pid.
    eprintln!(
        "c101 ledger receipt: records={} events={:?} peers={:?}",
        recs.len(),
        recs.iter().map(|r| r["event"].as_str()).collect::<Vec<_>>(),
        recs.iter().map(|r| format!("{}", r["peer"])).collect::<Vec<_>>()
    );
    let mine: Vec<&serde_json::Value> = recs
        .iter()
        .filter(|r| r["pid"].as_u64() == Some(own))
        .collect();
    assert_eq!(mine.len(), 3, "three session events land in the ledger");
    for ev in &mine {
        assert_eq!(ev["verdict"], "mcp");
    }
    assert_eq!(mine[0]["event"], "init");
    let init = mine[0];
    let fp = init["cap_fingerprint"].as_str().unwrap_or("");
    assert_eq!(fp.len(), 16, "the fingerprint carries 16 hex digits");
    assert!(
        fp.chars().all(|c| c.is_ascii_hexdigit()),
        "the fingerprint is hex"
    );
    assert_eq!(
        init["protocol_version"].as_str(),
        Some("2025-06-18"),
        "the initialize result's protocolVersion rides as evidence"
    );
    assert_eq!(
        init["payload"]["result"]["serverInfo"]["name"],
        "alpha1-server",
        "the merged init record carries the server's name"
    );
    assert_eq!(mine[1]["event"], "tools-list");
    let list = mine[1];
    assert_eq!(
        list["payload"]["result"]["tools"][0]["name"],
        "read",
        "the merged tools-list record carries the server's tools"
    );
    assert!(
        list["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e == "tool:read"),
        "the discovered tool name rides the evidence"
    );
    assert_eq!(mine[2]["event"], "tools-call");
    let call = mine[2];
    assert_eq!(call["tool_name"].as_str(), Some("read"));
    assert_eq!(
        call["payload"]["result"]["content"][0]["text"],
        "hello-from-read",
        "the tool result text rides the merged record"
    );
    let session = mine[0]["session_id"].as_str().unwrap().to_string();
    assert_eq!(
        mine[1]["session_id"].as_str(),
        Some(session.as_str()),
        "all three events key one session"
    );

    // the operator answers: the sessions view over the scenario ledger;
    // the read logs (the access log's own cell rides C002)
    let out = bin()
        .args(["report", "--ledger"])
        .arg(&ledger)
        .output()
        .expect("agentpcap binary");
    assert!(out.status.success(), "report exits cleanly");
    let answer = String::from_utf8_lossy(&out.stdout);
    let answered: Vec<serde_json::Value> = answer
        .lines()
        .flat_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect();
    // the report rows filter to this scenario's session: the tap also
    // records the host's other pipe traffic, and those rows never ride
    // the assertions (the raw ledger rows filter by the scenario pid
    // the same way the checks above do)
    let answered: Vec<serde_json::Value> = answered
        .into_iter()
        .filter(|v| v["session_id"].as_str() == Some(session.as_str()))
        .collect();
    eprintln!("c101 report receipt: sessions={}", answered.len());
    assert_eq!(answered.len(), 1, "the report folds one session view line");
    let view = &answered[0];
    assert_eq!(
        view["session_id"], session,
        "the session view keys the scenario's session"
    );
    assert_eq!(view["server"], "alpha1-server");
    assert_eq!(view["cap_fingerprint"], fp);
    assert_eq!(
        view["tools"][0]["name"], "read",
        "the discovered tool rides the session view"
    );
    assert_eq!(view["invocations"], 1, "the tool call counts");
}
