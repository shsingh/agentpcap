// P111 — the socket emit path: a plaintext JSON-RPC write over a
// loopback TCP socket rides the `sock_events` queue with its payload
// intact; the userspace reads its own sample back. ADR-0005: the class
// comes from the map, the wire keeps the 272-byte face.
// Spec: docs/spec.md#5-collectors. Cell ledger: tests/matrix/LEDGER.md.

use agentpcap_collector::PipeSample;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

#[test]
fn p111_the_socket_sample_rides_the_queue_with_its_payload() {
    let obj = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpcap-ebpf/target/bpfel-unknown-none/release/agentpcap");
    assert!(obj.is_file(), "P111 red: the bpf object is absent");

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
    let mut queue: aya::maps::Queue<_, PipeSample> = bpf
        .take_map("sock_events")
        .expect("sock_events map missing")
        .try_into()
        .expect("sock_events map is not a queue");

    let marker = "p111-marker";
    let line = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{marker}\",\"params\":{{}}}}\n"
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("the listener binds");
    let addr = listener.local_addr().expect("the local addr");
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("the accept");
        let mut buf = [0u8; 512];
        let n = s.read(&mut buf).unwrap_or(0);
        let _ = n;
    });
    let mut client = TcpStream::connect(addr).expect("the client connects");
    client.write_all(line.into_bytes().as_slice()).expect("the client sends");
    std::thread::sleep(Duration::from_millis(300));
    drop(client);
    server.join().expect("the server joins");

    // the drain searches its own sample by the marker token
    let now = Instant::now();
    let deadline = now + Duration::from_secs(8);
    while Instant::now() < deadline {
        match queue.pop(0) {
            Ok(s) => {
                let text = String::from_utf8_lossy(
                    &s.first_bytes[..(s.len as usize).min(256)],
                )
                .to_string();
                if text.contains(marker) {
                    eprintln!("p111 receipt: sample pid={} len={} payload={text}", s.pid, s.len);
                    return;
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    panic!("the socket sample never surfaced in the drain window");
}
