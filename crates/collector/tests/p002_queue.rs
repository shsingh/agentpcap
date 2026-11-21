// P002 — the pipe emit path: the probe pushes one pipe sample per
// system write into the `pipe-events` queue; the userspace pops the
// sample of its own writer. Wire cap: 32 payload bytes.
// Spec: docs/spec.md#5-collectors. Cell ledger: tests/matrix/LEDGER.md.

use agentpcap_collector::PipeSample;
use std::io::Write;
use std::time::{Duration, Instant};

#[test]
fn p002_probe_emits_and_userspace_reads_back() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = dir.path().join("scratch.txt");

    let obj = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpcap-ebpf/target/bpfel-unknown-none/release/agentpcap");
    assert!(
        obj.is_file(),
        "P002 red: the compiled bpf object is absent at {}",
        obj.display()
    );

    let mut bpf = aya::Bpf::load_file(&obj).expect("bpf load failed");
    let prog: &mut aya::programs::TracePoint = bpf
        .program_mut("agentpcap")
        .expect("program missing from object")
        .try_into()
        .expect("program is not a tracepoint");
    prog.load().expect("bpf verifier rejected the program");
    prog.attach("syscalls", "sys_enter_write")
        .expect("attach to sys_enter_write failed");

    let mut queue: aya::maps::Queue<_, PipeSample> = bpf
        .take_map("pipe_events")
        .expect("pipe_events map missing")
        .try_into()
        .expect("pipe_events map is not a queue");

    // Our own writes drive the probe; the queue carries our sample back.
    let me = std::process::id();
    let now = Instant::now();
    let deadline = now + Duration::from_secs(5);
    let mut found = false;
    while Instant::now() < deadline && !found {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&scratch)
            .unwrap();
        writeln!(
            f,
            "p002 {}",
            Instant::now().duration_since(now).as_millis()
        )
        .unwrap();
        let _ = f.flush();
        match queue.pop(0) {
            Ok(s) => {
                if s.pid == me && s.len >= 5 {
                    found = true;
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
    drop(bpf);
    assert!(found, "no pipe sample from this writer within 5 s");
}
