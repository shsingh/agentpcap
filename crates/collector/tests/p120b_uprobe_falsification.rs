// P120b — the uprobe falsification face: the identical program shape
// attached to libc's `write` (fd, buf, len - the same arm64 register
// file as SSL_write). The test's own writeln drives libc's write
// in-process; the canary must move. A flat canary here means the
// kernel's uprobe path never fires, distinct from any TLS-specific
// cause. Spec: docs/spec.md#8-modes.

use std::io::Write;
use std::time::{Duration, Instant};

#[test]
fn p120b_the_uprobe_path_fires_on_libc_write() {
    let obj = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpcap-ebpf/target/bpfel-unknown-none/release/agentpcap");
    assert!(obj.is_file(), "P120b red: the bpf object is absent");

    let mut bpf = aya::Ebpf::load_file(&obj).expect("bpf load failed");
    let prog: &mut aya::programs::UProbe = bpf
        .program_mut("agentpcap_tls_write")
        .expect("the tls program missing")
        .try_into()
        .expect("agentpcap_tls_write is not an uprobe");
    prog.load().expect("bpf verifier rejected the tls program");
    prog.attach(Some("write"), 0, "/lib/aarch64-linux-gnu/libc.so.6", None)
        .expect("the uprobe attach to libc write failed");

    let mut canary: aya::maps::Array<_, u64> = bpf
        .take_map("tls_canary")
        .expect("tls_canary map missing")
        .try_into()
        .expect("tls_canary is not an array");
    let before = canary.get(&0, 0).expect("the invoke counter reads back");

    // the test's own writes ride libc's write: the file writes go to
    // /dev/null's real fd (the cargo capture buffers the eprintln face
    // until after the window)
    let mut devnull =
        std::fs::OpenOptions::new().write(true).open("/dev/null").expect("devnull opens");
    for i in 0..64 {
        devnull
            .write_all(
                format!(
                    "{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"p120b\",\"params\":{{}}}}\n"
                )
                .as_bytes(),
            )
            .expect("the write lands");
    }
    drop(devnull);
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let after = canary.get(&0, 0).expect("the invoke counter reads back");
        if after > before {
            eprintln!("p120b receipt: uprobe invokes {before} -> {after}");
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "the libc write uprobe never fired: the kernel's uprobe path is dead (kprobe class)"
    );
}
