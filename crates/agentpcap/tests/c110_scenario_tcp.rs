// C110 — the wire-class scenario (ADR-0002): a local JSON-RPC exchange
// over Streamable HTTP's TCP class — the test plays the MCP client over
// a loopback TCP socket, an in-process server answers on its own
// socket, and the tap runs throughout. The ledger carries the merged
// session events with the tcp transport, the canonical five-tuple face
// and the reassembled init fingerprint.
// Spec: docs/spec.md#5-collectors, docs/spec.md#6-classification.
// Cell ledger: tests/matrix/LEDGER.md.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

#[test]
fn c110_the_tcp_scenario_answers_the_ledger() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    let mut tap = bin()
        .args(["tap", "--ledger"])
        .arg(&ledger)
        .arg("--duration")
        .arg("8")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("agentpcap binary");

    // the TCP JSON-RPC server: one connection, one initialize answer,
    // one tools/call answer (Streamable HTTP's transport face, minus
    // the HTTP envelope: the socket class sees the payload line)
    let listener = TcpListener::bind("127.0.0.1:0").expect("the listener binds");
    let addr = listener.local_addr().expect("the local addr");
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("the accept");
        let mut reader = BufReader::new(sock.try_clone().expect("the clone"));
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap_or(0) > 0 {
            let resp = if line.contains("initialize") {
                "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"tcp-server\",\"version\":\"0\"}}}\n"
            } else if line.contains("tools/call") {
                "{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"content\":[{\"text\":\"tcp-hello\"}]}}\n"
            } else {
                continue;
            };
            sock.write_all(resp.as_bytes()).expect("the reply writes");
            sock.flush().expect("the reply flushes");
            line.clear();
        }
    });

    // wait out the tap's calibration; the ledger writer only exists after
    std::thread::sleep(Duration::from_millis(1200));

    // the test is the MCP client: two framed requests over TCP
    let mut client = TcpStream::connect(addr).expect("the client connects");
    let frames = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://lab"}}}"#,
    ];
    for f in frames {
        client.write_all(format!("{f}\n").as_bytes()).expect("the frame writes");
        client.flush().expect("the frame flushes");
        std::thread::sleep(Duration::from_millis(400));
    }
    drop(client);
    server.join().expect("the server joins");

    let _ts = tap.wait().expect("tap exits at its deadline");

    let text = std::fs::read_to_string(&ledger).unwrap();
    let recs: Vec<serde_json::Value> = text
        .lines()
        .flat_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect();
    let own = std::process::id() as u64;
    // the socket class rides the tcp transport with the canonical
    // five-tuple face. The server's BufReader reads deliver more than
    // one frame per kernel read: the sample cuts at the 256-byte cap
    // and the cut rides the ledger honestly as `unidentified`
    // (a first-class record with the truncation face), while the
    // client's own writes bind their pairs.
    let mine: Vec<&serde_json::Value> = recs
        .iter()
        .filter(|r| r["pid"].as_u64() == Some(own) && r["transport"] == "tcp")
        .collect();
    eprintln!(
        "c110 ledger receipt: records={} tcp={} events={:?} peers={:?}",
        recs.len(),
        mine.len(),
        mine.iter().map(|r| r["event"].as_str()).collect::<Vec<_>>(),
        mine.iter().map(|r| format!("{}", r["peer"])).collect::<Vec<_>>()
    );
    assert!(mine.len() >= 2, "the client's session events ride the ledger");
    let mine = mine
        .iter()
        .filter(|r| r["session_id"].is_string())
        .collect::<Vec<_>>();
    assert!(mine.len() >= 2, "the session-carrying socket events ride");
    let session = mine[0]["session_id"].as_str().unwrap().to_string();
    for ev in &mine {
        let evidence = ev["evidence"].as_array().unwrap();
        assert!(
            evidence.iter().any(|e| e.as_str() == Some("socket")),
            "the socket class evidence rides"
        );
        assert!(
            evidence
                .iter()
                .any(|e| e.as_str().map(|x| x.starts_with("peer-face:tcp:")) == Some(true)),
            "the canonical five-tuple face rides"
        );
        assert_eq!(
            ev["session_id"].as_str(),
            Some(session.as_str()),
            "the socket session keys by the canonical pair"
        );
    }
    let init = mine.iter().find(|r| r["event"] == "init");
    let init = init.expect("the initialize pair merges over the socket class");
    assert_eq!(init["verdict"], "mcp");
    assert_eq!(init["protocol_version"], "2025-06-18");
    assert_eq!(
        init["payload"]["result"]["serverInfo"]["name"],
        "tcp-server",
        "the socket class carries the result's content"
    );
    let call = mine.iter().find(|r| r["event"] == "tools-call");
    let call = call.expect("the tools-call pair merges");
    assert_eq!(call["tool_name"].as_str(), Some("fetch"));
    assert_eq!(
        call["payload"]["result"]["content"][0]["text"],
        "tcp-hello",
        "the tool result rides the socket session"
    );
}
