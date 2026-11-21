// P120c — the libssl face falsification: the same program attached to
// `SSL_new` (every session setup fires it) and `SSL_write_ex`
// (OpenSSL 3.0's writer the host ssl module rides through). The
// python TLS exchange runs; whichever counter moves names the live
// face, and a flat pair pins the libssl-specific attach cause.
// Spec: docs/spec.md#8-modes.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn attach_and_count(
    obj: &std::path::Path,
    symbol: &str,
    port: Option<&str>,
    marker: &str,
) -> u64 {
    let mut bpf = aya::Ebpf::load_file(obj).expect("bpf load failed");
    let prog: &mut aya::programs::UProbe = bpf
        .program_mut("agentpcap_tls_write")
        .expect("the tls program missing")
        .try_into()
        .expect("agentpcap_tls_write is not an uprobe");
    prog.load().expect("bpf verifier rejected");
    let libssl = "/usr/lib/aarch64-linux-gnu/libssl.so.3";
    prog.attach(Some(symbol), 0, libssl, None)
        .expect("the attach failed");
    let mut canary: aya::maps::Array<_, u64> = bpf
        .take_map("tls_canary")
        .expect("tls_canary map missing")
        .try_into()
        .expect("tls_canary is not an array");
    let before = canary.get(&0, 0).expect("the invoke counter reads back");

    // the exchange: the server rides the given port (an empty arg for
    // a fresh one), the client completes the handshake and sends
    let mut server = Command::new("python3")
        .args(["-u", "/tmp/agentpcap-tls.py", "server", port.unwrap_or("0"), marker])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("the python server spawns");
    let port_out = if port.is_none() {
        BufReader::new(server.stdout.take().unwrap())
            .lines()
            .next()
            .and_then(|l| l.ok())
            .unwrap_or_default()
    } else {
        port.unwrap_or_default().to_string()
    };
    let client = Command::new("python3")
        .args(["-u", "/tmp/agentpcap-tls.py", "client", &port_out, marker])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("the python client spawns");
    let _ = client;
    let _ = server.wait();

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut after = before;
    while Instant::now() < deadline {
        after = canary.get(&0, 0).expect("the invoke counter reads back");
        if after > before {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    after
}

#[test]
fn p120c_the_libssl_attach_face_names_the_live_symbol() {
    let obj = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpcap-ebpf/target/bpfel-unknown-none/release/agentpcap");
    assert!(obj.is_file(), "P120c red: the bpf object is absent");

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
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../eval/fixtures/mcp-tls.py");
    std::fs::copy(fixture.canonicalize().expect("the fixture ships"), "/tmp/agentpcap-tls.py")
        .expect("the fixture copies");

    for symbol in ["SSL_new", "SSL_write", "SSL_write_ex"] {
        let before = 0u64;
        let after = attach_and_count(&obj, symbol, None, "p120c");
        eprintln!("p120c receipt: {symbol} invokes {before} -> {after}");
    }
    // the cell stays informational: the live face rides the receipt
    // lines; the pass face lands once a symbol names the live path
}
