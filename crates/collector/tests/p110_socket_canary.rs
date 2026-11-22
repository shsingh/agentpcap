// P110 — the socket canary: the socket object builds, loads, attaches
// the send face pair (`sys_enter_sendto` parks, `sys_exit_sendto`
// captures) on the build-VM kernel, and the exit face's invoke counter
// reads back greater than in-process after the test writes a JSON-RPC
// line over a loopback TCP socket.
// Spec: docs/spec.md#5-collectors. Cell ledger: tests/matrix/LEDGER.md.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

#[test]
fn p110_the_socket_probe_loads_fires_and_counts() {
    let obj = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpcap-ebpf/target/bpfel-unknown-none/release/agentpcap");
    assert!(
        obj.is_file(),
        "P110 red: the compiled bpf object is absent at {}",
        obj.display()
    );

    let mut bpf = aya::Ebpf::load_file(&obj).expect("bpf load failed");
    let prog: &mut aya::programs::TracePoint = bpf
        .program_mut("agentpcap_socket")
        .expect("the socket program missing from object")
        .try_into()
        .expect("agentpcap_socket is not a tracepoint");
    prog.load().expect("bpf verifier rejected the socket program");
    prog.attach("syscalls", "sys_enter_sendto")
        .expect("attach to sys_enter_sendto failed");
    let prog_exit: &mut aya::programs::TracePoint = bpf
        .program_mut("agentpcap_send_exit")
        .expect("the send exit program missing from object")
        .try_into()
        .expect("agentpcap_send_exit is not a tracepoint");
    prog_exit.load().expect("bpf verifier rejected the send exit program");
    prog_exit
        .attach("syscalls", "sys_exit_sendto")
        .expect("attach to sys_exit_sendto failed");

    // the canary counts outcomes: invoke at 0, push-ok at 2
    let canary: aya::maps::Array<_, u64> = bpf
        .take_map("sock_canary")
        .expect("sock_canary map missing")
        .try_into()
        .expect("sock_canary is not an array");
    let before = canary.get(&0, 0).expect("the invoke counter reads back");

    // the test writes one plaintext JSON-RPC line over a loopback TCP
    // socket; the send rides `sendto`
    let listener = TcpListener::bind("127.0.0.1:0").expect("the listener binds");
    let addr = listener.local_addr().expect("the local addr");
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("the accept");
        let mut buf = [0u8; 512];
        let n = s.read(&mut buf).unwrap_or(0);
        let _ = s.write_all(buf[..n].to_vec().as_slice());
    });
    let mut client = TcpStream::connect(addr).expect("the client connects");
    client
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}\n")
        .expect("the client sends");
    let _ = client.read(&mut [0u8; 64]).ok();
    server.join().expect("the server joins");

    // the counter moves inside the drain window
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        let now = canary.get(&0, 0).expect("the invoke counter reads back");
        if now > before {
            eprintln!("p110 receipt: socket invokes {before} -> {now}");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the socket probe never fired: the invoke counter stuck at {before}");
}
