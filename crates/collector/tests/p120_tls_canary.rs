// P120 — the TLS canary: the uprobe attaches the host libssl's
// SSL_write, and after the python TLS fixture's send the counter moves
// in-process. Spec: docs/spec.md#8-modes.
// Cell ledger: tests/matrix/LEDGER.md.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn p120_the_tls_uprobe_attaches_and_fires() {
    let obj = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpcap-ebpf/target/bpfel-unknown-none/release/agentpcap");
    assert!(obj.is_file(), "P120 red: the bpf object is absent");

    let mut bpf = aya::Ebpf::load_file(&obj).expect("bpf load failed");
    let prog: &mut aya::programs::UProbe = bpf
        .program_mut("agentpcap_tls_write")
        .expect("the tls program missing")
        .try_into()
        .expect("agentpcap_tls_write is not an uprobe");
    prog.load().expect("bpf verifier rejected the tls program");

    // the cert chain once per VM (the fixture pins nothing else)
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
        assert!(gen.success(), "the cert chain generates");
    }

    // the fixture rides the repo's eval fixtures, copied where the
    // python faces can import by path
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval/fixtures/mcp-tls.py");
    let fixture = fixture.canonicalize().expect("the fixture ships with the repo");
    let tmp_fixture = "/tmp/agentpcap-tls.py";
    std::fs::copy(&fixture, tmp_fixture).expect("the fixture copies");

    let libssl = "/usr/lib/aarch64-linux-gnu/libssl.so.3";
    prog.attach(Some("SSL_write_ex"), 0, libssl, None)
        .expect("the uprobe attach to SSL_write_ex failed");

    let mut canary: aya::maps::Array<_, u64> = bpf
        .take_map("tls_canary")
        .expect("tls_canary map missing")
        .try_into()
        .expect("tls_canary is not an array");
    let before = canary.get(&0, 0).expect("the invoke counter reads back");

    // the server prints its port, the client rides it
    let mut server = Command::new("python3")
        .args(["-u", tmp_fixture, "server", "0", "p120"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the python server spawns");
    let port: u16 = BufReader::new(server.stdout.take().unwrap())
        .lines()
        .next()
        .and_then(|l| l.ok())
        .and_then(|l| l.trim().parse().ok())
        .expect("the server states its port");
    eprintln!("p120 receipt: server port={port}");
    let client = Command::new("python3")
        .args(["-u", tmp_fixture, "client", &port.to_string(), "p120"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the python client spawns");
    assert!(client.success(), "the TLS exchange completes");
    let _ = server.wait();

    // the counter moves in the drain window
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let after = canary.get(&0, 0).expect("the invoke counter reads back");
        if after > before {
            eprintln!("p120 receipt: tls invokes {before} -> {after}");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the SSL_write_ex uprobe never fired: the counter stayed at {before}");
}
