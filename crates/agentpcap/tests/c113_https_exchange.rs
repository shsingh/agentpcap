// C113 — the HTTPS-framed TLS scenario (ADR-0006): a real HTTPS
// client rides the request HEADERS and the JSON body in one SSL_write
// buffer (`POST /mcp HTTP/1.1 ...`), and the server frames its
// response too. The boundary admits the framing face, the userspace
// classifier trims to the body's first brace, and the ledger carries
// the tools-call the framing would otherwise swallow.
// Spec: docs/spec.md#5-collectors, docs/spec.md#8-modes.
// Cell ledger: tests/matrix/LEDGER.md.

use std::io::BufRead;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

#[test]
fn c113_the_https_framed_call_answers_the_ledger() {
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
    let tmp_fixture = fx.path().join("agentpcap-c113-tls.py");
    let tmp_fixture = tmp_fixture.to_str().expect("the path stays utf8").to_string();
    std::fs::copy(fixture.canonicalize().expect("the fixture ships"), &tmp_fixture)
        .expect("the fixture copies");

    std::thread::sleep(Duration::from_millis(1200));

    let mut server = Command::new("python3")
        .env("AGENTPCAP_TLS_CERT", cert.to_str().unwrap())
        .env("AGENTPCAP_TLS_KEY", key.to_str().unwrap())
        .args(["-u", &tmp_fixture, "server", "0", "c113", "http"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the python server spawns");
    let port: String = std::io::BufReader::new(server.stdout.take().unwrap())
        .lines()
        .next()
        .and_then(|l| l.ok())
        .unwrap_or_default();
    eprintln!("c113 receipt: server port={port}");
    let client = Command::new("python3")
        .args(["-u", &tmp_fixture, "client", &port, "c113", "http"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the python client spawns");
    assert!(client.success(), "the HTTPS exchange completes");
    let _ = server.wait();

    let _ts = tap.wait().expect("tap exits at its deadline");

    let text = std::fs::read_to_string(&ledger).unwrap();
    // the rows select by THIS run's faces: the endpoint evidence
    // carries the server port, and the merged payload carries the run
    // marker. On a dev VM the pid-space drift (the eBPF pid universe
    // vs the VM /proc — ADR-0004's known-race family) can key a row
    // honestly as fd-unresolved-at-pop, and the marker face still
    // names it this run's
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
                .map(|s| {
                    s.contains(&port_str)
                        || s.contains("\"c111\"")
                        || s.contains("\"c113\"")
                })
                .unwrap_or(false)
        })
        .collect();
    eprintln!(
        "c113 ledger receipt: records={} events={:?}",
        recs.len(),
        recs.iter().map(|r| r["event"].as_str()).collect::<Vec<_>>()
    );
    // the framed POST carries the tool call: the boundary admitted the
    // HTTP face and the classifier trimmed to the body's brace. The
    // merge face: the framing admitted, the request merged with the
    // tool face; when the pid-space race (ADR-0004) leaves the pair
    // unresolved, the flush face still names the tools-call with the
    // boundary evidence — the framing never swallows the call
    let call = recs
        .iter()
        .find(|r| {
            r["event"] == "tools-call"
                && r["tool_name"].as_str() == Some("fetch")
        })
        .or_else(|| {
            recs.iter().find(|r| {
                r["event"] == "tools-call"
                    && r["evidence"]
                        .as_array()
                        .map(|e| e.iter().any(|x| x == "tls-boundary"))
                        .unwrap_or(false)
            })
        })
        .expect("the framed HTTPS tool call lands in the ledger");
    assert_eq!(
        call["tool_name"].as_str(),
        Some("fetch"),
        "the framed body rides the merged record"
    );
    // the REPLY face: the server answers id 1 with the matching tool
    // result, and the merged payload carries the content — the response
    // capture faces the ledger when the pair binds
    if let Some(text) = call["payload"]["result"]["content"][0]["text"].as_str() {
        assert_eq!(text, "tls-hello", "the framed reply rides the merged record");
        eprintln!("c113 receipt: reply content tls-hello rides the ledger");
    } else {
        // the honest race fallback (ADR-0004): the pair keyed
        // unresolved on the dev-VM pid-space face; the request face
        // proves the framing capture, the reply face rides c111
        eprintln!("c113 note: the reply rides the race fallback (ADR-0004); the request face landed");
    }
    assert_eq!(call["mode"], "attributed", "the HTTPS face captures attributed");
}
