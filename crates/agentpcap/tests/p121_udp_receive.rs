// P121 — the receive face and the UDP transport: the client's
// `recvfrom` answer rides the EXIT probe (the buffer coordinates park
// at entry, the capture bounds by the kernel's byte count), and the
// resolver's table face names the transport — a UDP connection is
// udp, never tcp. The request/result pair merges on the five-tuple.
// Spec: docs/spec.md#5-collectors. Cell ledger: tests/matrix/LEDGER.md.

use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

#[test]
fn p121_the_udp_receive_face_rides_the_ledger() {
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

    // wait out the tap's calibration
    std::thread::sleep(Duration::from_millis(1200));

    // the UDP pair: the client writes the tools/call request, the
    // server answers, the client recvfrom's the result
    let client = UdpSocket::bind("127.0.0.1:0").expect("the client binds");
    let client_addr = client.local_addr().expect("the client's face");
    let server = UdpSocket::bind("127.0.0.1:0").expect("the server binds");
    let server_addr = server.local_addr().expect("the server's face");
    client.connect(server_addr).expect("the client connects");
    let client_face = format!("local-end:{}", client.local_addr().expect("the client face"));

    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        server
            .send_to(
                br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"text":"udp-hello"}]}}"#,
                client_addr,
            )
            .expect("the reply sends");
    });

    let request =
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://lab"}}}"#;
    client.send(request).expect("the request rides");
    let mut buf = [0u8; 512];
    let n = client.recv(&mut buf).expect("the client recvfrom answers");
    assert!(n > 0, "the receive carried bytes");
    writer.join().expect("the reply joins");
    drop(client);

    let _ = tap.wait().expect("tap exits at its deadline");

    let text = std::fs::read_to_string(&ledger).unwrap();
    let recs: Vec<serde_json::Value> = text
        .lines()
        .flat_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect();
    eprintln!(
        "p121 ledger receipt: records={} udp={}",
        recs.len(),
        recs.iter()
            .filter(|r| r["transport"] == "udp")
            .count()
    );
    // the transport face: the UDP observations ride udp, never tcp
    let udp: Vec<&serde_json::Value> =
        recs.iter().filter(|r| r["transport"] == "udp").collect();
    assert!(
        udp.len() >= 1,
        "a UDP observation rides the udp transport: {recs:?}"
    );
    // the merged pair: the request parked under the five-tuple, the
    // receive bound its result — the tools-call event carries the
    // merged face on the same connection
    // the receive face: the event must carry the CLIENT's own
    // endpoint - a bound receive, not the server's send face nor the
    // flush's null-result face
    let merged = udp
        .iter()
        .filter(|r| {
            r["event"] == "tools-call"
                && r["verdict"] == "mcp"
                && r["evidence"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .any(|e| e.as_str() == Some(client_face.as_str()))
                    })
                    .unwrap_or(false)
        })
        .find(|r| {
            r["payload"]["result"]["content"]
                .as_array()
                .is_some_and(|c| {
                    c.iter()
                        .any(|x| x["text"] == "udp-hello")
                })
        })
        .copied();
    assert!(
        merged.is_some(),
        "the request and its receive merge on the five-tuple with the          captured reply text: {recs:?}"
    );
    let session = merged.unwrap()["session_id"].as_str().unwrap();
    assert!(
        session.contains(".udp:"),
        "the session keys the canonical five-tuple: {session}"
    );
}
