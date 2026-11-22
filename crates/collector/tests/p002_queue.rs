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

    let mut bpf = aya::Ebpf::load_file(&obj).expect("bpf load failed");
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

    // Our own writes drive the probe; the round drains the queue and
    // searches for the marker payload this test writes. Host-wide
    // writes never reach the queue (ADR 0003 filter); the drain keeps
    // the search exhaustive.
    let marker = b"\"method\":\"p002-marker\"";
    let now = Instant::now();
    let deadline = now + Duration::from_secs(8);
    let mut found = false;
    while Instant::now() < deadline && !found {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&scratch)
            .unwrap();
        for _ in 0..8 {
            let _ = writeln!(
                f,
                "{{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"p002-marker\",\"params\":{{\"t\":{}}}}}",
                Instant::now().duration_since(now).as_millis()
            );
        }
        let _ = f.flush();
        for _ in 0..2048 {
            match queue.pop(0) {
                Ok(s) => {
                    let n = (s.len as usize).min(agentpcap_collector::PAYLOAD_BYTES_CAP);
                    if n >= marker.len()
                        && s.first_bytes[..n].windows(marker.len()).any(|w| w == *marker)
                    {
                        found = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if !found {
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // Counter receipts from the probe: invocations and push outcomes.
    let counters: aya::maps::Array<_, u64> = bpf
        .take_map("events")
        .expect("canary counter map missing")
        .try_into()
        .expect("canary map is not an array");
    let counters: Vec<u64> = (0..4)
        .map(|i| counters.get(&i, 0).unwrap_or(0))
        .collect();
    drop(bpf);

    eprintln!(
        "p002 receipts: invokes={} read_fail={} push_ok={} push_fail={}",
        counters[0], counters[1], counters[2], counters[3]
    );
    assert!(found, "no pipe sample with this test's payload within 8 s");
}
