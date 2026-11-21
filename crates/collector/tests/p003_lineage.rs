// P003 — the lineage ask: the probe resolves the writer's parent pid
// and the sample carries it. A child process writes; the userspace pops
// the child's sample with `ppid` equal to this test process.
// Spec: docs/spec.md#5-collectors. Cell ledger: tests/matrix/LEDGER.md.

use agentpcap_collector::PipeSample;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn p003_child_write_carries_the_parent_pid() {
    let dir = tempfile::tempdir().unwrap();
    let scratch = dir.path().join("scratch.txt");
    let scratch_c = scratch.display().to_string();

    let obj = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agentpcap-ebpf/target/bpfel-unknown-none/release/agentpcap");
    assert!(
        obj.is_file(),
        "P003 red: the compiled bpf object is absent at {}",
        obj.display()
    );

    let mut bpf = aya::Bpf::load_file(&obj).expect("bpf load failed");
    let write_prog: &mut aya::programs::TracePoint = bpf
        .program_mut("agentpcap")
        .expect("write program missing from object")
        .try_into()
        .expect("agentpcap is not a tracepoint");
    write_prog.load().expect("bpf verifier rejected the write program");
    write_prog
        .attach("syscalls", "sys_enter_write")
        .expect("attach to sys_enter_write failed");

    let fork_prog: &mut aya::programs::TracePoint = bpf
        .program_mut("agentpcap_fork")
        .expect("fork program missing from object")
        .try_into()
        .expect("agentpcap_fork is not a tracepoint");
    fork_prog.load().expect("bpf verifier rejected the fork program");
    fork_prog
        .attach("sched", "sched_process_fork")
        .expect("attach to sched_process_fork failed");

    let mut queue: aya::maps::Queue<_, PipeSample> = bpf
        .take_map("pipe_events")
        .expect("pipe_events map missing")
        .try_into()
        .expect("pipe_events map is not a queue");

    // the child writes; its parent is this test process
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!("echo agentpcap-p003-marker >> '{scratch_c}'"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("child spawn");
    let child_pid = child.id();
    let _wait = child.wait().expect("child exits");

    let me = std::process::id() as u32;
    let now = Instant::now();
    let deadline = now + Duration::from_secs(8);
    let mut found = false;
    while Instant::now() < deadline && !found {
        for _ in 0..2048 {
            match queue.pop(0) {
                Ok(s) => {
                    if s.pid == child_pid
                        && s.ppid == me
                        && s.first_bytes[..(s.len as usize).min(32)]
                            .starts_with(b"agentpcap-p003")
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
    drop(bpf);
    assert!(
        found,
        "no lineage-resolved sample for child {child_pid} of {me} within 8 s"
    );
}
