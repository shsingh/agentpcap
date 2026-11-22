// P113 — the cgroup filter (ADR-0005): the probe self-reports the
// running task's cgroup id through `cgroup_seen` (the container
// boundary hides the kernel's view from /proc on delegated
// hierarchies), the cell marks the allow set from that calibrated
// face, a sample from the allowed cgroup rides, and with the marker
// removed the same write drops while the invoke counter stays
// current. Spec: docs/spec.md#5-collectors.

use agentpcap_collector::PipeSample;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

fn jsonrpc_marked(marker: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{marker}\",\"params\":{{}}}}\n"
    )
}

/// One marker send over a loopback TCP connection this process owns.
fn send_once(port: u16, marker: &str) {
    let mut c = TcpStream::connect(("127.0.0.1", port)).expect("the connect");
    c.write_all(jsonrpc_marked(marker).as_bytes())
        .expect("the send");
    let mut buf = [0u8; 32];
    let _ = c.read(&mut buf);
}

#[test]
fn p113_the_cgroup_allow_filter_gates_the_socket_queue() {
    let obj = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpcap-ebpf/target/bpfel-unknown-none/release/agentpcap");
    assert!(obj.is_file(), "P113 red: the bpf object is absent");

    let mut bpf = aya::Ebpf::load_file(&obj).expect("bpf load failed");
    let prog: &mut aya::programs::TracePoint = bpf
        .program_mut("agentpcap_socket")
        .expect("the socket program missing")
        .try_into()
        .expect("the socket program is not a tracepoint");
    prog.load().expect("bpf verifier rejected");
    prog.attach("syscalls", "sys_enter_sendto")
        .expect("the attach failed");
    let prog_exit: &mut aya::programs::TracePoint = bpf
        .program_mut("agentpcap_send_exit")
        .expect("the send exit program missing from object")
        .try_into()
        .expect("agentpcap_send_exit is not a tracepoint");
    prog_exit.load().expect("bpf verifier rejected the send exit program");
    prog_exit
        .attach("syscalls", "sys_exit_sendto")
        .expect("attach to sys_exit_sendto failed");
    let mut allow: aya::maps::HashMap<_, u64, u32> = bpf
        .take_map("cgroup_allow")
        .expect("cgroup_allow map missing")
        .try_into()
        .expect("cgroup_allow is not a hashmap");
    let mut seen: aya::maps::Array<_, u64> = bpf
        .take_map("cgroup_seen")
        .expect("cgroup_seen map missing")
        .try_into()
        .expect("cgroup_seen is not an array");
    let mut queue: aya::maps::Queue<_, PipeSample> = bpf
        .take_map("sock_events")
        .expect("sock_events missing")
        .try_into()
        .expect("sock_events is not a queue");

    // phase 1: an unmarked send calibrates the cgroup id from the
    // kernel's own view; the probe stays silent (no marker ride)
    let listener = TcpListener::bind("127.0.0.1:0").expect("the listener binds");
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("the accept");
        let mut buf = [0u8; 64];
        s.read(&mut buf).unwrap_or(0);
    });
    send_once(port, "p113-calibrate");
    server.join().expect("the server joins");
    let deadline = Instant::now() + Duration::from_secs(8);
    let cgroup_id = loop {
        if Instant::now() > deadline {
            panic!("the probe never self-reported the cgroup id");
        }
        if let Ok(id) = seen.get(&0, 0) {
            if id != 0 {
                break id;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    eprintln!("p113 calibrated receipt: cgroup id={cgroup_id:#x}");

    // phase 2: the calibrated allow admits the task's own writes
    allow
        .insert(u64::MAX, 1, 0)
        .expect("the marker inserts");
    allow
        .insert(cgroup_id, 1, 0)
        .expect("the allow inserts");
    let listener = TcpListener::bind("127.0.0.1:0").expect("the listener binds");
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().expect("the accept");
        let mut buf = [0u8; 64];
        s.read(&mut buf).unwrap_or(0);
    });
    send_once(port, "p113-writer-in");
    server.join().expect("the server joins");
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut rode = false;
    while Instant::now() < deadline {
        if let Ok(s) = queue.pop(0) {
            let text = String::from_utf8_lossy(
                &s.first_bytes[..(s.len as usize).min(256)],
            )
            .to_string();
            if text.contains("p113-writer-in") {
                rode = true;
                eprintln!("p113 allowed receipt: {text}");
            }
        } else {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    assert!(rode, "the allowed cgroup's sample never surfaced");

    // phase 3: the marker leaves, the same write drops, the canary
    // stays current (the probe invoked)
    {
        let mut canary: aya::maps::Array<_, u64> = bpf
            .take_map("sock_canary")
            .expect("sock_canary map missing")
            .try_into()
            .expect("sock_canary is not an array");
        let invokes_before =
            canary.get(&0, 0).expect("the invoke counter reads back");
        // the drop face: the marker STAYS (an absent marker re-opens
        // capture-all) and the allow list loses the task's own id
        allow.remove(&cgroup_id).expect("the allow removes");
        let listener = TcpListener::bind("127.0.0.1:0").expect("the listener binds");
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("the accept");
            let mut buf = [0u8; 64];
            s.read(&mut buf).unwrap_or(0);
        });
        send_once(port, "p113-writer-unallowed");
        server.join().expect("the server joins");
        std::thread::sleep(Duration::from_millis(400));
        while let Ok(s) = queue.pop(0) {
            let text = String::from_utf8_lossy(
                &s.first_bytes[..(s.len as usize).min(256)],
            )
            .to_string();
            assert!(
                !text.contains("p113-writer-unallowed"),
                "the unallowed cgroup's sample must never ride: {text}"
            );
        }
        let invokes_after =
            canary.get(&0, 0).expect("the invoke counter reads back");
        eprintln!(
            "p113 dropped receipt: invokes {invokes_before} -> {invokes_after}, the unallowed send dropped"
        );
        assert!(
            invokes_after > invokes_before,
            "the unallowed send still reached the probe (the invoke counter stayed flat)"
        );
    }
}
