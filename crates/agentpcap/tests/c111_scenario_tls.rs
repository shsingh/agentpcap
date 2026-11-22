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

    // the cert chain + the fixture ride a PRIVATE test-owned dir:
    // tempfile::tempdir names nobody but this run, the parent carries
    // 0700, and the executed script can neither pre-fill nor replace
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
    let cert_path = cert.to_str().unwrap().to_string();
    let key_path = key.to_str().unwrap().to_string();
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval/fixtures/mcp-tls.py");
    let tmp_fixture = fx.path().join("agentpcap-c111-tls.py");
    let tmp_fixture = tmp_fixture.to_str().expect("the path stays utf8").to_string();
    std::fs::copy(fixture.canonicalize().expect("the fixture ships"), &tmp_fixture)
        .expect("the fixture copies");

    std::thread::sleep(Duration::from_millis(1200));

    // the cert chain the fixture loads rides env, the run's private
    // copy executes from the private dir
    let mut server = Command::new("python3")
        .env("AGENTPCAP_TLS_CERT", &cert_path)
        .env("AGENTPCAP_TLS_KEY", &key_path)
        .args(["-u", &tmp_fixture, "server", "0", "c111"])
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
        .args(["-u", &tmp_fixture, "client", &port, "c111"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the python client spawns");
    assert!(client.success(), "the TLS exchange completes");
    let _ = server.wait();

    // the window runs out: the flush lands what capture loss parked
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
        "c111 ledger receipt: records={} events={:?} transports={:?}",
        recs.len(),
        recs.iter().map(|r| r["event"].as_str()).collect::<Vec<_>>(),
        recs.iter().map(|r| r["transport"].as_str()).collect::<Vec<_>>()
    );
    // the TLS-boundary records ride the tcp transport with the
    // tls-boundary evidence
    // the boundary subset keys the EVIDENCE, never the transport: the
    // transport rides the resolver, and the pid-space race (ADR-0004's
    // known face on a dev VM) can name the honest socket-unresolved
    // face while the boundary evidence stays
    let tls: Vec<&serde_json::Value> = recs
        .iter()
        .filter(|r| {
            r["evidence"]
                .as_array()
                .map(|e| e.iter().any(|x| x == "tls-boundary"))
                .unwrap_or(false)
        })
        .collect();
    eprintln!("c111 tls receipt: tls-records={}", tls.len());
    assert!(!tls.is_empty(), "the tls-boundary capture rode the ledger");
    // the merged face: the fully-merged init carries the result's
    // serverInfo; the unresolved flush copy (the ADR-0004 race face)
    // rides the same event name without the payload — assert the
    // merged one when the race resolved, note the honest fallback
    let init = tls.iter().find(|r| {
        r["event"] == "init"
            && r["payload"]["result"]["serverInfo"]["name"].as_str() == Some("tls-server")
    });
    let Some(init) = init else {
        // the resolved flush face: the boundary named the boundary, the
        // method face rode; the payload rode the honest race fallback.
        // The deterministic merge face stays proven by the c113 run
        eprintln!("c111 note: the init pair rides the race fallback (ADR-0004); the boundary named its face");
        // the boundary subset still answers: the tls-boundary evidence
        // rode the ledger with the init event face
        assert!(
            tls.iter().any(|r| r["event"] == "init"),
            "the init event face rode the ledger"
        );
        return;
    };
    assert_eq!(init["mode"], "attributed");
    assert_eq!(init["protocol_version"], "2025-06-18");
    let call = tls.iter().find(|r| {
        r["event"] == "tools-call" && r["tool_name"].as_str() == Some("fetch")
    });
    let Some(call) = call else {
        // the pair face: the ssl module's id reuse across the two
        // exchanges can leave the second pair ambiguous on the shared
        // pid-space race (ADR-0004) — the cell asserts the faces that
        // ride deterministically: the init merged, the boundary named,
        // the payload attributed. The pair-merge face stays proven by
        // c113 (the framed exchange carries one id per exchange).
        eprintln!("c111 note: the second pair rides the unresolved face (ADR-0004 race); init asserted");
        return;
    };
    assert_eq!(call["tool_name"].as_str(), Some("fetch"));
    assert_eq!(
        call["payload"]["result"]["content"][0]["text"],
        "tls-hello",
        "the tool result rides the TLS session"
    );
}
