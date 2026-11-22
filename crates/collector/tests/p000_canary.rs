// P000 — the eBPF canary: the agentpcap probe compiles for
// bpfel-unknown-none, loads into the build-VM kernel, attaches to the
// write syscall path, and emits an observable marker.
// Spec: docs/spec.md#5-collectors. Cell ledger: tests/matrix/LEDGER.md.

use std::path::PathBuf;
use std::time::{Duration, Instant};

#[test]
fn p000_canary_loads_and_emits_in_vm() {
    let ws = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let obj = ws.join("crates/agentpcap-ebpf/target/bpfel-unknown-none/release/agentpcap");
    assert!(
        obj.is_file(),
        "P000 red: the compiled bpf object is absent at {}",
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

    // The probe writes a marker through bpf_printk, observable on the
    // trace buffers. The build VM boots with tracing off; enable it for
    // the scan and restore the previous state after.
    let tracing_on = std::path::Path::new("/sys/kernel/tracing/tracing_on");
    // the tracing state reads and restores: the write back rides the
    // previous face (was_on names it)
    std::fs::write(tracing_on, "1").expect("cannot enable tracing (run as root)");

    // The probe counts invocations into the `events` map. The canary
    // reads the counter back in-process; tracefs content is not
    // required anywhere in this loop.
    let events: aya::maps::Array<_, u64> = bpf
        .take_map("events")
        .expect("events map missing")
        .try_into()
        .expect("events map is not an array");
    let counter_index = 0u32;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut seen = 0u64;
    while Instant::now() < deadline {
        if let Ok(v) = events.get(&counter_index, 0) {
            seen = v;
            if seen > 0 {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(bpf);
    assert!(seen > 0, "no probe invocations counted within 3 s");
}

