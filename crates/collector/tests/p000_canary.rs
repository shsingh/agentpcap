// P000 — the eBPF canary: the agentpcap probe compiles for
// bpfel-unknown-none, loads into the build-VM kernel, attaches to the
// write syscall entry, and emits at least one ring-buffer event.
// Spec: docs/spec.md#5-collectors. Cell ledger: tests/matrix/LEDGER.md.

use std::path::PathBuf;
use std::time::{Duration, Instant};

#[test]
fn p000_canary_loads_and_emits_in_vm() {
    let ws = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let obj = ws.join("target/bpfel-unknown-none/release/agentpcap-ebpf");
    assert!(
        obj.is_file(),
        "P000 red: the compiled bpf object is absent at {}",
        obj.display()
    );

    let mut bpf = aya::Bpf::load_file(&obj).expect("bpf load failed");
    let prog: &mut aya::programs::KProbe = bpf
        .program_mut("agentpcap")
        .expect("program missing from object")
        .try_into()
        .expect("program is not a kprobe");
    prog.load().expect("bpf verifier rejected the program");
    prog.attach("sys_enter_write", 0)
        .expect("attach to sys_enter_write failed");

    let mut events: aya::maps::RingBuf = bpf
        .take_map("events")
        .expect("events map missing")
        .try_into()
        .expect("events map is not a ring buffer");
    let mut seen = 0usize;
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Some(buf) = events.poll(Duration::from_millis(200)).expect("poll failed") {
            assert!(!buf.as_ref().is_empty(), "event without a payload");
            seen += 1;
        }
    }
    assert!(seen >= 1, "no probe events within 2 s");
}
