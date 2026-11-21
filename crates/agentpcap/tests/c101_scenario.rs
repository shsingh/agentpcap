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
    let reply_fd = server.stdout.as_ref().unwrap().as_raw_fd();
    // the reply channel's peer key: the inode of this test's read end
    let reply_peer = std::fs::read_link(format!(
        "/proc/{}/fd/{}",
        std::process::id(),
        reply_fd
    ))
    .map(|l| {
        format!(
            "pipe:{}",
            l.to_string_lossy()
                .trim_start_matches("pipe:[")
                .trim_end_matches(']')
        )
    })
    .expect("the reply pipe's read end resolves to its inode");
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
    let client: Vec<&serde_json::Value> = recs
        .iter()
        .filter(|r| r["pid"].as_u64() == Some(own))
        .collect();
    // the reply records: tied to the scenario's reply channel — the peer
    // names the inode of the pipe this test reads, so ambient jsonrpc
    // from unrelated processes cannot enter the set
    let server: Vec<&serde_json::Value> = recs
        .iter()
        .filter(|r| r["peer"].as_str() == Some(reply_peer.as_str()))
        .collect();
    eprintln!(
        "c101 ledger receipt: records={} client-records={} server-records={} pids={:?} methods={:?}",
        recs.len(),
        client.len(),
        server.len(),
        recs.iter().map(|r| r["pid"].as_u64()).collect::<Vec<_>>(),
        client.iter().map(|r| r["method"].as_str()).collect::<Vec<_>>()
    );
    for (meth, id) in [
        ("initialize", 1),
        ("tools/list", 2),
        ("tools/call", 3),
    ] {
        assert!(
            client.iter().any(|r| {
                r["verdict"] == "mcp"
                    && r["method"] == meth
                    && r["payload"]["id"] == id
            }),
            "the client's {meth} request with id {id} classified mcp"
        );
    }
    assert_eq!(server.len(), 3, "the server's three replies recorded");
    for (id, frag) in [
        (1, "alpha1-server"),
        (2, "\"tools\""),
        (3, "hello-from-read"),
    ] {
        assert!(
            server
                .iter()
                .any(|r| r["payload"]["id"] == id
                    && r.to_string().contains(frag)),
            "the reply with id {id} carries its result"
        );
    }

    // the operator answers: `report` prints the records over the
    // scenario ledger and logs the read (the alpha1 evidence output)
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
    eprintln!("c101 report receipt: lines={}", answered.len());
    assert_eq!(answered.len(), 6, "the report answers with all six records");
    assert!(answer.contains(r#""method":"tools/call""#), "the report lists the tool call");
    assert!(answer.contains("hello-from-read"), "the report lists the tool result");
}
