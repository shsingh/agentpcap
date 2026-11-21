// P000 — the eBPF canary: the agentpcap probe compiles for
// bpfel-unknown-none, loads into the build-VM kernel, attaches to the
// write syscall path, and emits an observable marker.
// Spec: docs/spec.md#5-collectors. Cell ledger: tests/matrix/LEDGER.md.

use std::io::Read;
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

    let mut bpf = aya::Bpf::load_file(&obj).expect("bpf load failed");
    let prog: &mut aya::programs::KProbe = bpf
        .program_mut("agentpcap")
        .expect("program missing from object")
        .try_into()
        .expect("program is not a kprobe");
    prog.load().expect("bpf verifier rejected the program");
    prog.attach("ksys_write", 0)
        .expect("attach to ksys_write failed");

    // The probe writes a marker through bpf_printk, observable on the
    // trace buffers. The build VM boots with tracing off; enable it for
    // the scan and restore the previous state after.
    let tracing_on = std::path::Path::new("/sys/kernel/tracing/tracing_on");
    let was_on = std::fs::read_to_string(tracing_on)
        .ok()
        .is_some_and(|s| s.trim() == "1");
    std::fs::write(tracing_on, "1").expect("cannot enable tracing (run as root)");

    let marker = "canary-agentpcap-p000";
    let mut trace = std::fs::File::open("/sys/kernel/tracing/trace_pipe")
        .expect("trace_pipe is not readable; tracing is unavailable");
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut seen = false;
    while Instant::now() < deadline && !seen {
        let mut chunk = vec![0u8; 131_072];
        let n = trace.read(&mut chunk).unwrap_or(0);
        if n > 0 {
            let text = String::from_utf8_lossy(&chunk[..n]);
            if text.contains(marker) {
                seen = true;
            }
        }
    }
    drop(bpf);
    let _ = std::fs::write(tracing_on, if was_on { "1" } else { "0" });
    assert!(seen, "no canary marker on trace_pipe within 3 s");
}
