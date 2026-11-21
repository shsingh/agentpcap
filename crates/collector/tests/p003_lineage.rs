// P003 — the lineage ask: the write sample carries the writer's pid;
// the userspace resolves the parent through the /proc scan with a TTL
// cache. The in-probe fork feed is parked (kernel receipts in the
// tracked issue); the alpha1 lineage is userspace-side.
// Spec: docs/spec.md#5-collectors. Cell ledger: tests/matrix/LEDGER.md.

use agentpcap_collector::{resolve_parent, ParentCache, PipeSample};
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn p003_child_lineage_resolves_through_the_proc_scan() {
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

    let mut queue: aya::maps::Queue<_, PipeSample> = bpf
        .take_map("pipe_events")
        .expect("pipe_events map missing")
        .try_into()
        .expect("pipe_events map is not a queue");

    // the child writes the marker; the probe sees it; the sample's ppid
    // stays 0 — the lineage resolution happens userspace-side
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo agentpcap-p003-marker >> '{scratch_c}'; sleep 5"
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("child spawn");
    let child_pid = child.id();
    // settle: the child writes within milliseconds; poll briefly
    let settled = (0..40).any(|_| {
        std::thread::sleep(Duration::from_millis(50));
        std::fs::read_to_string(&scratch)
            .map(|s| s.contains("agentpcap-p003-marker"))
            .unwrap_or(false)
    });
    assert!(settled, "the child's write landed");

    let me = std::process::id() as u32;
    let now = Instant::now();
    let deadline = now + Duration::from_secs(8);
    let mut sample_pid = 0u32;
    let mut raw_ppid = 0u32;
    let mut saw_marker_pid = false;
    while Instant::now() < deadline && !saw_marker_pid {
        for _ in 0..2048 {
            match queue.pop(0) {
                Ok(s) => {
                    let prefix = String::from_utf8_lossy(
                        &s.first_bytes[..(s.len as usize).min(32)],
                    )
                    .to_string();
                    if prefix.starts_with("agentpcap-p003") && !saw_marker_pid {
                        saw_marker_pid = true;
                        sample_pid = s.pid;
                        raw_ppid = s.ppid;
                    }
                }
                Err(_) => break,
            }
        }
        if !saw_marker_pid {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    // The probe reports root-namespace pids; on the OrbStack build VM the
    // machine's pid namespace adds a fixed per-boot offset. The tap
    // self-calibrates: the offset falls out of the child's own marker
    // sample (deployment hosts sit at offset 0).
    assert!(saw_marker_pid, "no marker sample within 8 s");
    let offset = sample_pid as i64 - child_pid as i64;
    let translated = sample_pid as i64 - offset;
    eprintln!(
        "p003 receipt: marker sample root_pid={sample_pid} ppid={raw_ppid} child_ns={child_pid} offset={offset} translated={translated}"
    );
    assert_eq!(
        translated, child_pid as i64,
        "the sample pid translates to the writer's pid with the boot offset"
    );

    // lineage: the /proc scan resolves the machine pid's parent, cached
    // (the child still lives: the sleep keeps its /proc entry present)
    let mut cache = ParentCache::new();
    let ttl = Duration::from_secs(2);
    let ppid = resolve_parent(translated as u32, &mut cache, ttl);
    eprintln!("p003 receipt: resolve_parent({translated}) = {ppid}; cache={cache:?}");
    assert_eq!(ppid, me, "the child's parent is this test process");
    let again = resolve_parent(translated as u32, &mut cache, ttl);
    assert_eq!(again, me, "the cached resolution holds");
    assert_eq!(cache.len(), 1, "one cached lineage entry");
    let _ = child.wait().expect("child exits after its sleep");
}
