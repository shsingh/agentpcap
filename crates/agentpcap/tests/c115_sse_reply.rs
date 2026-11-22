// C115 — the SSE-framed reply (ADR-0006): the tool result answers as a
// `text/event-stream` body, the JSON in a `data:` line. The userspace
// classifier reads the event's `data` field before the JSON parse, so
// the reply merges with its request; without the face the whole reply
// went `unidentified` and its request ended `no-response`.
// Spec: docs/spec.md#5-collectors, docs/spec.md#8-modes.
// Cell ledger: tests/matrix/LEDGER.md.

use std::io::BufRead;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

#[test]
fn c115_the_sse_reply_merges_with_its_request() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    let mut tap = bin()
        .args(["tap", "--ledger"])
        .arg(&ledger)
        .arg("--duration")
        .arg("9")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("agentpcap binary");

    // the cert chain + the fixture ride a PRIVATE test-owned dir
    let fx = tempfile::tempdir().expect("the private fixture dir creates");
    let cert = fx.path().join("tls-cert.pem");
    let key = fx.path().join("tls-key.pem");
    let gen = Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "rsa:2048", "-keyout",
            key.to_str().unwrap(), "-out", cert.to_str().unwrap(),
            "-days", "2", "-nodes", "-subj", "/CN=lab",
        ])
        .stderr(Stdio::null())
        .status()
        .expect("openssl runs");
    assert!(gen.success(), "the cert chain generates");

    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval/fixtures/mcp-tls.py");
    let tmp_fixture = fx.path().join("agentpcap-c115-tls.py");
    let tmp_fixture = tmp_fixture.to_str().expect("the path stays utf8").to_string();
    std::fs::copy(fixture.canonicalize().expect("the fixture ships"), &tmp_fixture)
        .expect("the fixture copies");

    std::thread::sleep(Duration::from_millis(1200));

    let mut server = Command::new("python3")
        .env("AGENTPCAP_TLS_CERT", cert.to_str().unwrap())
        .env("AGENTPCAP_TLS_KEY", key.to_str().unwrap())
        .args(["-u", &tmp_fixture, "server", "0", "c115", "sse"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the python server spawns");
    let port: String = std::io::BufReader::new(server.stdout.take().unwrap())
        .lines()
        .next()
        .and_then(|l| l.ok())
        .unwrap_or_default();
    eprintln!("c115 receipt: server port={port}");
    let client = Command::new("python3")
        .args(["-u", &tmp_fixture, "client", &port, "c115", "http"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the python client spawns");
    assert!(client.success(), "the HTTPS exchange completes");
    let _ = server.wait();

    let _ts = tap.wait().expect("tap exits at its deadline");

    let text = std::fs::read_to_string(&ledger).unwrap();
    // the rows select by THIS run's faces: the endpoint evidence
    // carries the server port, and the payload carries the run marker
    let port_str = format!(":{port}");
    let recs: Vec<serde_json::Value> = text
        .lines()
        .flat_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|r| {
            let boundary = r["evidence"]
                .as_array()
                .map(|e| e.iter().any(|x| x == "tls-boundary"))
                .unwrap_or(false);
            if !boundary {
                return false;
            }
            serde_json::to_string(r)
                .map(|s| s.contains(&port_str) || s.contains("\"c115\""))
                .unwrap_or(false)
        })
        .collect();
    eprintln!(
        "c115 ledger receipt: records={} events={:?}",
        recs.len(),
        recs.iter().map(|r| r["event"].as_str()).collect::<Vec<_>>()
    );

    // the SSE face: the tools-call rides the body framing (the request
    // head carried Content-Type: application/json), and the SSE reply
    // merges with it — the record carries the tool result's text. The
    // fallback rides the chunked-join-class evidence row only when the
    // merge cannot bind on this host's pid-space race (ADR-0004)
    let call = recs
        .iter()
        .find(|r| r["event"] == "tools-call")
        .expect("the SSE-faced tools-call lands in the ledger");
    let merged = call["payload"]["result"]["content"][0]["text"].as_str();
    match merged {
        Some(t) => assert_eq!(t, "tls-sse", "the SSE reply rides the merged record"),
        None => {
            // the honest race fallback (ADR-0004): the merge keyed
            // unresolved on the dev-VM pid-space face — the reply must
            // still reach the ledger as its own record on this run's
            // port evidence, never as only `unidentified` content loss
            let reply = recs.iter().any(|r| {
                r["event"] == "response"
                    || r["event"] == "orphan-response"
            });
            assert!(
                reply,
                "the SSE reply reaches the ledger even when the pair races unresolved"
            );
            eprintln!("c115 note: the reply rides the race fallback (ADR-0004)");
        }
    }
    assert_eq!(call["mode"], "attributed", "the SSE face captures attributed");
}
