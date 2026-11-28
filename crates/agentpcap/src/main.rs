// The agentpcap operator CLI. Normative source: `docs/spec.md#9-operator-cli`.
// `record` appends JSON Lines events from stdin to the ledger; `report`
// renders the sessions view and logs the read; `export` streams the gate
// stream; `diff` names the capability drift from two report sets; `tap`
// runs the eBPF probe loop and appends the reassembled session events.
// All faces fail closed: exit 0 on success, 2 on misuse, 1 on a capture
// error.

use agentpcap_collector::{classify_pipe_sample, resolve_parent, Decision, ParentCache};
use agentpcap_events::{Event, Mode, Verdict};
use agentpcap_ledger::{now_rfc3339, LedgerReader, LedgerWriter};
use agentpcap_reassemble::{Frame, Reassembler};
use aya::maps::RingBuf;
use std::os::fd::AsRawFd;
use aya::programs::TracePoint;
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

mod diff;
mod report;

// The probe object is a build artifact of the standalone eBPF crate;
// the workspace build order produces it before this crate compiles.
static BPF_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../agentpcap-ebpf/target/bpfel-unknown-none/release/agentpcap"
));

const USAGE: &str = "usage: agentpcap record --ledger <path> [--source <face>]\n       agentpcap report --ledger <path>\n       agentpcap tap --ledger <path> [--duration <seconds>] [--cgroup <id>] [--mode opaque]\n       (--duration 0 runs the capture unbounded; --mode opaque strips the payload content at the feed face)";

/// The flag walker: `--flag <value>` pairs and standalone `--flag`
/// switches. Misuse is the caller's exit-2 face.
fn flag(args: &[String], name: &str, takes_value: bool) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            if takes_value {
                return it.next().cloned();
            }
            return Some(String::new());
        }
    }
    None
}

/// The stop face: the signal handler marks the stop; the tap loop
/// breaks and the drain flushes the still-pending requests.
static STOP_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

extern "C" fn on_stop(_sig: i32) {
    STOP_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
}

/// One resolved peer face per class: the pipe channel and the socket
/// five-tuple carry different members; both name the session.
#[derive(Clone)]
enum ResolvedPeer {
    Pipe { channel: String },
    Socket(agentpcap_collector::SocketPeer),
}

impl ResolvedPeer {
    fn peer(&self) -> String {
        match self {
            ResolvedPeer::Pipe { channel } => channel.clone(),
            ResolvedPeer::Socket(fp) => fp.peer.clone(),
        }
    }
    fn local(&self) -> Option<String> {
        match self {
            ResolvedPeer::Pipe { .. } => None,
            ResolvedPeer::Socket(fp) => Some(fp.local.clone()),
        }
    }
    fn remote(&self) -> Option<String> {
        match self {
            ResolvedPeer::Pipe { .. } => None,
            ResolvedPeer::Socket(fp) => Some(fp.remote.clone()),
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // a trailing `--source` is misuse, not an omitted flag: the value
    // face distinguishes an absent switch from a missing value (exit
    // 2, before the ledger opens)
    if args.contains(&"--source".to_string())
        && args.get(args.iter().position(|a| a == "--source").unwrap() + 1)
            .is_none()
    {
        eprintln!("agentpcap: --source needs a value");
        return ExitCode::from(2);
    }
    match (args.first().map(String::as_str), args.get(2)) {
        (Some("record"), Some(path)) => record(
            PathBuf::from(path),
            flag(&args[1..], "--source", true),
        ),
        (Some("report"), Some(path)) => report(PathBuf::from(path)),
        (Some("tap"), Some(path)) => {
            // the misuse face: `--cgroup` present without a valid
            // cgroup id never silently widens capture — the value
            // face rejects the run before the probe loads
            let cgroup_value = args
                .iter()
                .position(|a| a == "--cgroup")
                .and_then(|i| args.get(i + 1))
                .cloned();
            let cgroup = match cgroup_value {
                Some(v) => match v.parse::<u64>() {
                    Ok(id) => Some(id),
                    Err(_) => {
                        eprintln!("agentpcap: --cgroup needs a cgroup id (a number)");
                        return ExitCode::from(2);
                    }
                },
                None => {
                    if args.contains(&"--cgroup".to_string()) {
                        eprintln!("agentpcap: --cgroup needs a value");
                        return ExitCode::from(2);
                    }
                    None
                }
            };
            tap(
                PathBuf::from(path),
                args.iter()
                    .position(|a| a == "--duration")
                    .and_then(|i| args.get(i + 1))
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(60),
                cgroup,
                // the mode face: attributed is the default (spec
                // section 8); `--mode opaque` strips the payload
                // content at the feed face. A supplied but invalid
                // value takes the misuse face: silent broadening of
                // the capture scope never survives an argument
                match args.iter().position(|a| a == "--mode") {
                    Some(i) => match args.get(i + 1).map(String::as_str) {
                        Some("opaque") => Mode::Opaque,
                        Some("attributed") => Mode::Attributed,
                        Some(_) => {
                            eprintln!("agentpcap: --mode needs attributed or opaque");
                            return ExitCode::from(2);
                        }
                        None => {
                            eprintln!("agentpcap: --mode needs a value");
                            return ExitCode::from(2);
                        }
                    },
                    None => Mode::Attributed,
                },
            )
        }
        (Some("export"), Some(path)) => export(
            PathBuf::from(path),
            flag(&args[1..], "--follow", false).is_some(),
        ),
        (Some("diff"), Some(_)) => {
            let before = flag(&args[1..], "--before", true);
            let after = flag(&args[1..], "--after", true);
            match (before, after) {
                (Some(b), Some(a)) => diff(PathBuf::from(b), PathBuf::from(a)),
                _ => {
                    eprintln!("{USAGE}");
                    ExitCode::from(2)
                }
            }
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// The FNV-1a hash over bytes: the tap's dedupe keys ride the sample
/// content, not the per-run counter — a restarted capture re-mints
/// nothing from an earlier run.
fn fnv64(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn record(path: PathBuf, source: Option<String>) -> ExitCode {
    let mut writer = match LedgerWriter::create(&path) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("agentpcap record: {e}");
            return ExitCode::FAILURE;
        }
    };
    let stdin = std::io::stdin();
    let mut count = 0usize;
    for (n, line) in stdin.lock().lines().enumerate() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("agentpcap record: stdin read failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let mut event =
            match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("agentpcap record: event {n} is not valid JSON: {e}");
                return ExitCode::FAILURE;
            }
        };
        // the coexistence stamp: the ingest face names the capture path
        // the record entered through (spec section 11)
        if let Some(s) = &source {
            if let Some(obj) = event.as_object_mut() {
                obj.insert("source".into(), Value::String(s.clone()));
            }
        }
        match writer.append(&event) {
            Ok(_) => {
                // C129: the import face lands every record — stdin can
                // stay open for a live stream, and the export --follow
                // face reads the tail; the import volume is low, the
                // per-record landing is the semantics face here
                if let Err(e) = writer.flush_pending() {
                    eprintln!("agentpcap record: {e}");
                    return ExitCode::FAILURE;
                }
                count += 1;
            }
            Err(agentpcap_ledger::LedgerError::Duplicate(_)) => {
                // the coexistence dedupe: the covered flow exists, the
                // face continues and states the skip
                eprintln!("agentpcap record: the dedupe skipped event {n}: the event's dedup key already rides the ledger");
                continue;
            }
            Err(e) => {
                eprintln!("agentpcap record: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    eprintln!("agentpcap record: {count} record(s) -> {}", path.display());
    if let Err(e) = writer.close() {
        eprintln!("agentpcap record: {e}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

fn report(path: PathBuf) -> ExitCode {
    let view = match report::sessions(&path, "agentpcap.report") {
        Ok(v) => v,
        Err(e) => {
            // a broken ledger's read fails: report states the failure
            // on stderr and answers nothing on stdout
            eprintln!("agentpcap report: {e}");
            return ExitCode::FAILURE;
        }
    };
    if print_sessions(view).is_err() {
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// The tap: load the probe, drain the queue, classify, reassemble,
/// ledger. The classified frames feed the reassembler; the reassembled
/// session events land in the ledger one per session event.
fn tap(ledger_path: PathBuf, duration_secs: u64, cgroup: Option<u64>, mode: Mode) -> ExitCode {
    // `--duration 0` is the service face: the capture runs unbounded
    // until the unit stops it. The default face stays the 60-second
    // window the alpha1 CLI promised.
    let unbounded = duration_secs == 0;
    // the stop face: the unit's SIGTERM (and Ctrl-C) marks the stop.
    // The loop breaks and the drain flushes every still-pending
    // request with the no-response face — a stop loses nothing.
    STOP_REQUESTED.store(false, std::sync::atomic::Ordering::SeqCst);
    unsafe {
        libc::signal(libc::SIGTERM, on_stop as *const () as usize);
        libc::signal(libc::SIGINT, on_stop as *const () as usize);
    }
    let mut bpf = match aya::Ebpf::load(BPF_OBJ) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("agentpcap tap: probe load failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let prog: &mut TracePoint = match bpf.program_mut("agentpcap").unwrap().try_into() {
        Ok(p) => p,
        Err(_) => {
            eprintln!("agentpcap tap: agentpcap is not a tracepoint");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = prog
        .load()
        .and_then(|_| prog.attach("syscalls", "sys_enter_write"))
    {
        eprintln!("agentpcap tap: probe attach failed: {e}");
        return ExitCode::FAILURE;
    }

    let mut queue: RingBuf<_> =
        match bpf.take_map("pipe_events").expect("queue map").try_into() {
            Ok(q) => q,
            Err(e) => {
                eprintln!("agentpcap tap: {e}");
                return ExitCode::FAILURE;
            }
        };

    // The pid-namespace face (issue #106): the probe keys each sample
    // with the pid the writer's own namespace /proc reports. The tap
    // publishes its pid-ns identity (new_encode_dev(dev), ino) so the
    // same-namespace writers translate wire-true and the userspace
    // faces (readlink, pidfd_open) read under one pid space. The
    // helper's ns_match compares against the writer's own pid
    // namespace (kernel/bpf/helpers.c): the dev/ino must name the pid
    // ns, never another ns-class face. Writers outside this pid ns
    // ride the raw tgid — the faces unchanged.
    let mut ns_armed = false;
    {
        let pidns_path = "/proc/self/ns/pid";
        let st = match std::fs::metadata(pidns_path) {
            Ok(m) => std::os::unix::fs::MetadataExt::dev(&m),
            Err(_) => 0,
        };
        let ino = match std::fs::metadata(pidns_path) {
            Ok(m) => std::os::unix::fs::MetadataExt::ino(&m),
            Err(_) => 0,
        };
        // new_encode_dev: the kernel's dev_t packing (major<<8 | minor)
        let major = ((st >> 8) & 0xfffu64) | ((st >> 32) & !0xfffu64);
        let minor = (st & 0xffu64) | ((st >> 12) & !0xffu64);
        let encoded = ((major & 0xfff) << 8)
            | (minor & 0xff)
            | ((major & !0xfff) << 32)
            | ((minor & !0xff) << 12);
        if let Some(nsmap) = bpf.map_mut("ns_config") {
            let mut cfg: aya::maps::Array<_, u64> = match nsmap.try_into() {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("agentpcap tap: the ns_config map failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(e) = cfg.set(0, encoded, 0) {
                eprintln!("agentpcap tap: the ns_config dev write failed: {e}");
                return ExitCode::FAILURE;
            }
            if let Err(e) = cfg.set(1, ino, 0) {
                eprintln!("agentpcap tap: the ns_config ino write failed: {e}");
                return ExitCode::FAILURE;
            }
            ns_armed = true;
        }
    }

    // The cgroup filter face (ADR-0005): the marker key turns the
    // probe's allow filter on; the lab default captures all. The face
    // installs BEFORE the socket probes attach — a gap would let
    // unscoped traffic into the queue and land it in the ledger.
    if let Some(cg) = cgroup {
        // the map BORROWS through bpf: its fd stays alive until every
        // program that references it loads (a taken-and-dropped fd
        // would fail the socket probe's load on a filtered run)
        let raw = match bpf.map_mut("cgroup_allow") {
            Some(m) => m,
            None => {
                eprintln!("agentpcap tap: the cgroup_allow map is missing");
                return ExitCode::FAILURE;
            }
        };
        let mut allow: aya::maps::HashMap<_, u64, u32> = match raw.try_into() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("agentpcap tap: {e}");
                return ExitCode::FAILURE;
            }
        };
        let marker = allow
            .insert(u64::MAX, 1, 0)
            .map_err(|e| eprintln!("agentpcap tap: the filter marker failed: {e}"))
            .is_ok();
        let entry = allow
            .insert(cg, 1, 0)
            .map_err(|e| eprintln!("agentpcap tap: the cgroup filter failed: {e}"))
            .is_ok();
        if !(marker && entry) {
            // the filter face never starts half-armed: a failed insert
            // stops the run before any probe can capture
            return ExitCode::FAILURE;
        }
    }

    // The socket class rides the same object (ADR-0005): two more
    // tracepoints attach beside the pipe one and share the calibration
    // and the pid offset.
    let prog_sock: &mut TracePoint =
        match bpf.program_mut("agentpcap_socket").expect("socket program").try_into() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("agentpcap tap: agentpcap_socket is not a tracepoint");
                return ExitCode::FAILURE;
            }
        };
    if let Err(e) = prog_sock
        .load()
        .and_then(|_| prog_sock.attach("syscalls", "sys_enter_sendto"))
    {
        eprintln!("agentpcap tap: the socket probe attach failed: {e}");
        return ExitCode::FAILURE;
    }
    let prog_send_exit: &mut TracePoint =
        match bpf
            .program_mut("agentpcap_send_exit")
            .expect("send exit program")
            .try_into()
        {
            Ok(p) => p,
            Err(_) => {
                eprintln!("agentpcap tap: agentpcap_send_exit is not a tracepoint");
                return ExitCode::FAILURE;
            }
        };
    if let Err(e) = prog_send_exit
        .load()
        .and_then(|_| prog_send_exit.attach("syscalls", "sys_exit_sendto"))
    {
        eprintln!("agentpcap tap: the send exit probe attach failed: {e}");
        return ExitCode::FAILURE;
    }
    let prog_recv_entry: &mut TracePoint =
        match bpf
            .program_mut("agentpcap_recv_enter")
            .expect("recv entry program")
            .try_into()
        {
            Ok(p) => p,
            Err(_) => {
                eprintln!("agentpcap tap: agentpcap_recv_entry is not a tracepoint");
                return ExitCode::FAILURE;
            }
        };
    if let Err(e) = prog_recv_entry
        .load()
        .and_then(|_| prog_recv_entry.attach("syscalls", "sys_enter_recvfrom"))
    {
        eprintln!("agentpcap tap: the recv entry probe attach failed: {e}");
        return ExitCode::FAILURE;
    }
    let prog_recv: &mut TracePoint =
        match bpf.program_mut("agentpcap_recv_exit").expect("recv exit program").try_into() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("agentpcap tap: agentpcap_recv_exit is not a tracepoint");
                return ExitCode::FAILURE;
            }
        };
    if let Err(e) = prog_recv
        .load()
        .and_then(|_| prog_recv.attach("syscalls", "sys_exit_recvfrom"))
    {
        eprintln!("agentpcap tap: the recv probe attach failed: {e}");
        return ExitCode::FAILURE;
    }
    // The fork lineage feed (issue #55, ADR-0009): the
    // sched_process_fork tracepoint feeds parent-child pairs; the
    // face rides beside the pipe calibration so forks during the
    // window land the lineage map.
    let prog_fork: &mut TracePoint = match bpf
        .program_mut("agentpcap_fork")
        .expect("fork program")
        .try_into()
    {
        Ok(p) => p,
        Err(_) => {
            eprintln!("agentpcap tap: agentpcap_fork is not a tracepoint");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = prog_fork
        .load()
        .and_then(|_| prog_fork.attach("sched", "sched_process_fork"))
    {
        eprintln!("agentpcap tap: the fork feed attach failed: {e}");
        return ExitCode::FAILURE;
    }
    let mut sock_queue: RingBuf<_> =
        match bpf.take_map("sock_events").expect("sock queue map").try_into() {
            Ok(q) => q,
            Err(e) => {
                eprintln!("agentpcap tap: {e}");
                return ExitCode::FAILURE;
            }
        };
    // The TLS-boundary collector (ADR-0006): the uprobes ride the host
    // libssl's SSL_write_ex/SSL_read_ex (the face the host ssl module
    // calls directly), sharing the calibration and the cgroup map. The
    // ENTRY probes park the buffer coordinates; the RETURN probes
    // (uretprobes on the same symbols) collect only the bytes the call
    // reports as accepted.
    let libssl = "/usr/lib/aarch64-linux-gnu/libssl.so.3";
    let libssl_read = std::env::var("AGENTPCAP_TLS_LIBSSL_READ").unwrap_or_else(|_| libssl.to_string());
    let tls_faces = ["agentpcap_tls_write", "agentpcap_tls_write_ret", "agentpcap_tls_read", "agentpcap_tls_read_ret"];
    let tls_attach = mode != Mode::Opaque;
    if mode == Mode::Opaque {
        // the scope face: the spec (Section 3) limits the TLS-boundary
        // collector to attributed capture — opaque never loads or
        // attaches the boundary probes, the plaintext never enters the
        // queue, and the face states why
        eprintln!("agentpcap tap: the tls faces stay unavailable (opaque mode keeps the boundary unattributed)");
    }
    let mut attached_link_ids: Vec<aya::programs::uprobe::UProbeLinkId> = Vec::new();
    let mut progs_tls: Vec<&'static str> = Vec::new();
    for name in tls_faces {
        if !tls_attach {
            break;
        }
        progs_tls.push(name);
        let prog: &mut aya::programs::UProbe = match bpf.program_mut(name).expect("tls program object exists").try_into() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("agentpcap tap: {name} is not an uprobe");
                return ExitCode::FAILURE;
            }
        };
        let sym = if name.contains("write") {
            "SSL_write_ex"
        } else {
            "SSL_read_ex"
        };
        // the dual-libssl face: the read pair's attach target may ride
        // its own path (a host's read-side libssl differs from the
        // write side; the rollback test faces it too)
        let attach_path = if name.contains("write") {
            libssl
        } else {
            libssl_read.as_str()
        };
        // The load/attach failure is an ENVIRONMENT face: perf_event_open
        // carries the privileges a foreign-user tap never carries (the
        // c112 cross-user face runs unprivileged by design). The tap
        // states the tls faces unavailable and keeps the pipe and socket
        // faces it can still capture — the boundary slice degrades, the
        // honest answer never widens. A missing program object stays
        // fatal: that is a build-face bug, not an environment.
        match prog.load().and_then(|_| prog.attach(Some(sym), 0, attach_path, None)) {
            Ok(link_id) => attached_link_ids.push(link_id),
            Err(e) => {
                // the partial-attach face: the earlier links undo before
                // the degrade — a half-attached boundary would record
                // outgoing requests without their incoming replies, and
                // parked reads would strand in the map. The detach rides
                // each link id through its own program's handle
                for (i, link_id) in attached_link_ids.drain(0..).enumerate() {
                    let prog_name = progs_tls[i];
                    if let Some(p) = bpf.program_mut(prog_name) {
                        if let Ok(pr) = <&mut aya::programs::UProbe>::try_from(p) {
                            let _ = pr.detach(link_id);
                        }
                    }
                }
                eprintln!(
                    "agentpcap tap: the tls faces stay unavailable ({name} did not attach: {e})"
                );
                break;
            }
        }
    }
    let mut tls_queue: RingBuf<_> =
        match bpf.take_map("tls_events").expect("tls queue map").try_into() {
            Ok(q) => q,
            Err(e) => {
                eprintln!("agentpcap tap: {e}");
                return ExitCode::FAILURE;
            }
        };
    // the pending map's sweeping face (the bounded-cleanup face): a
    // thread killed inside its SSL call parks keys nobody answers —
    // the tap deletes an entry when its pid no longer exists, so the
    // map never exhausts and the canary stays truthful
    // the falsification face (issue #83 scratch): the TLS canary's
    // pair/stale faces ride the tap's stderr at exit
    let tls_canary: aya::maps::Array<aya::maps::MapData, u64> =
        match bpf.take_map("tls_canary").expect("tls canary map").try_into() {
            Ok(m) => m,
            Err(_) => panic!("the tls canary map takes"),
        };
    let mut tls_pending: aya::maps::HashMap<aya::maps::MapData, u64, SavedTlsWire> =
        match bpf.take_map("tls_pending").expect("tls pending map").try_into() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("agentpcap tap: {e}");
                return ExitCode::FAILURE;
            }
        };

    // Calibrate the pid-namespace offset: the tap writes one sentinel
    // through the same path every tapped writer uses; the probe's
    // root-namespace pid for that write minus the tap's own pid is the
    // deployment's offset (zero on a direct host). The sentinel carries
    // a fresh unpredictable token (read from the host entropy pool) and
    // the file is created exclusively in a private scratch directory, so
    // a competing writer can neither pre-fill nor guess the accepted
    // sample.
    let calib_dir = tempfile::tempdir().map_err(|e| {
        eprintln!("agentpcap tap: the calibration dir failed: {e}");
        std::io::Error::other("calibration dir")
    });
    let calib_dir = match calib_dir {
        Ok(d) => d,
        Err(_) => return ExitCode::FAILURE,
    };
                        // The calibration token: fresh bytes from the
                        // host entropy pool; the read failure is fatal.
                        // /dev/urandom never ends, so the request is a
                        // bounded exact read.
                        let token = match random_token() {
                            Ok(t) => t,
                            Err(e) => {
                                eprintln!("agentpcap tap: the entropy read failed: {e}");
                                return ExitCode::FAILURE;
                            }
                        };
    let mut expected = b"agentpcap-calib-".to_vec();
    expected.extend_from_slice(token.as_bytes());
    expected.push(b'\n');
    let calib_path = calib_dir.path().join("calib");
    if std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&calib_path)
        .and_then(|mut f| f.write_all(&expected))
        .is_err()
    {
        eprintln!("agentpcap tap: the calibration write failed");
        return ExitCode::FAILURE;
    }
    let own = std::process::id();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut offset: Option<i64> = None;
    while Instant::now() < deadline && offset.is_none() {
        // the ring drain: the consumer rides mmap'd (zero bpf syscalls
        // per item); an empty ring sleeps the gap and re-polls
        while let Some(item) = queue.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < std::mem::size_of::<agentpcap_collector::PipeSample>() {
                continue;
            }
            let s: &agentpcap_collector::PipeSample =
                unsafe { &*(bytes.as_ptr() as *const _) };
            let n = (s.len as usize).min(agentpcap_collector::PAYLOAD_BYTES_CAP);
            if n == expected.len() && s.first_bytes[..n] == expected {
                offset = Some(s.pid as i64 - own as i64);
            }
        }
        if offset.is_none() {
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    drop(calib_dir);
    let Some(offset) = offset else {
        eprintln!("agentpcap tap: the calibration sample never arrived");
        return ExitCode::FAILURE;
    };
    // The ns face armed (issue #106): the probe emits the /proc-true
    // pid already, so the machine-path translation rides zero offset;
    // the calibration face keeps its sentinel window only. The
    // per-process offset face never held across writers — the ns face
    // replaces it.
    let offset = if ns_armed { 0 } else { offset };


    let mut writer = match LedgerWriter::create(&ledger_path) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("agentpcap tap: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut cache = ParentCache::new();
    let host = std::fs::read_to_string("/etc/hostname")
        .map(|h| h.trim().to_string())
        .unwrap_or_default();
    let mut reassembler = Reassembler::new(host.clone(), mode.clone(), "tap".into());
    let mut seq: u64 = 0;
    let mut idle_turns: u32 = 0;
    let mut comm_cache: agentpcap_collector::CommCache =
        std::collections::HashMap::new();
    let mut chan_cache: agentpcap_collector::ChannelRetryCache =
        std::collections::HashMap::new();
    let start = Instant::now();
    let expired = || !unbounded && Instant::now() >= start + Duration::from_secs(duration_secs);

    // the wake face descriptors: the three ring fds poll in ONE
    // syscall per drain cycle; the item reads ride the mmap'd consumer
    // (zero bpf syscalls per item) — issue #88
    let mut poll_set = [
        libc::pollfd { fd: queue.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: sock_queue.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: tls_queue.as_raw_fd(), events: libc::POLLIN, revents: 0 },
    ];
    let sweep_every = Duration::from_secs(2);
    let mut last_sweep = Instant::now();
    // the pending-sweep gate: the reassembler's sweep face iterates the
    // pending parks, and at the 2 ms turn face that face rides per-turn
    // work into the tap's hot loop. A 50 ms cadence keeps the expiry
    // latency faces (the no-response and the idle-session faces) far
    // inside the M006 2 s budget while dropping the per-turn cost.
    let pending_sweep_every = Duration::from_millis(50);
    let mut last_pending_sweep = Instant::now();
    while !expired() && !STOP_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) {
        // the pending sweep: a thread killed inside its TLS call parks
        // an entry nobody collects — the face deletes an entry once its
        // pid no longer reads through /proc, and the map never exhausts
        if last_sweep.elapsed() >= sweep_every {
            last_sweep = Instant::now();
            agentpcap_collector::shrink_if_over(
                &mut comm_cache, agentpcap_collector::CACHE_CAP,
                Duration::from_secs(2),
                |v: &(Option<String>, std::time::Instant)| v.1,
            );
            agentpcap_collector::shrink_if_over(
                &mut chan_cache, agentpcap_collector::CACHE_CAP,
                Duration::from_secs(2),
                |v: &(agentpcap_collector::ChanKind, std::time::Instant)| v.1,
            );
            if let Ok(keys) = tls_pending
                .keys()
                .collect::<Result<Vec<u64>, aya::maps::MapError>>()
            {
                for k in keys {
                    // the pid comes from the parked value itself: the
                    // park face stores the writer's namespace-visible
                    // pid (the ns face, issue #106) — /proc answers
                    // the tap's view directly, no translation rides
                    // the kernel-space key
                    //
                    // the removal needs a STABLE value: two agreeing
                    // reads. A torn read (the sweep racing the park's
                    // write) rides a half-written slot — a mismatch
                    // or a zero pid skips the removal and the next
                    // tick re-reads the settled value. A live parked
                    // entry keeps a live pid, so the /proc check
                    // passes and the call survives the sweep.
                    let v1 = match tls_pending.get(&k, 0) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    let v2 = match tls_pending.get(&k, 0) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if v1.ns_pid != v2.ns_pid
                        || v1.ubuf != v2.ubuf
                        || v1.wptr != v2.wptr
                        || v1.ns_pid == 0
                    {
                        continue;
                    }
                    if !std::path::Path::new(&format!("/proc/{}", v1.ns_pid)).exists()
                    {
                        let _ = tls_pending.remove(&k);
                    }
                }
            }
        }
        // the idle face: the sweep expires stale parked requests (they
        // ride the no-response face once) and idle sessions — the
        // deployed service never grows its in-memory faces without
        // limit
        if last_pending_sweep.elapsed() >= pending_sweep_every {
            last_pending_sweep = Instant::now();
            for ev in reassembler.sweep() {
                if let Err(e) = writer.append(&serde_json::to_value(&ev).unwrap()) {
                    if matches!(e, agentpcap_ledger::LedgerError::Duplicate(_)) {
                        eprintln!("agentpcap tap: the dedupe skipped the sweep event: its session event already rides the ledger");
                    } else {
                        eprintln!("agentpcap tap: {e}");
                        return ExitCode::FAILURE;
                    }
                }
            }
        }
        // THE WAKE FACE (issue #88, the ringbuf leaf): the drain polls
        // all three ring fds in ONE syscall per cycle and drains the
        // readiness on wake; the item reads ride the mmap'd consumer
        // (zero bpf syscalls per item). The poll's timeout carries the
        // idle backoff's step: an idle face sleeps in-kernel and burns
        // no CPU, a sampled write wakes the drain at once.
        //
        // C129: the batch-boundary landing face sits at the cycle head
        // so EVERY turn reaches it, idle turns included — the records
        // land whole at most one cycle after the capture, never in
        // memory past the boundary, and the ADR-0002 sync window fires
        // here too (at least every five seconds, even on an idle tap).
        if let Err(e) = writer.flush_pending() {
            eprintln!("agentpcap tap: {e}");
            return ExitCode::FAILURE;
        }
        if let Err(e) = writer.sync_if_due() {
            eprintln!("agentpcap tap: {e}");
            return ExitCode::FAILURE;
        }
        let step_ms = if idle_turns >= 24 {
            16
        } else if idle_turns >= 16 {
            8
        } else if idle_turns >= 8 {
            4
        } else {
            2
        };
        for p in poll_set.iter_mut() {
            p.revents = 0;
        }
        let woke = unsafe { libc::poll(poll_set.as_mut_ptr(), 3, step_ms) };
        if woke <= 0 {
            // the idle face: no ring carries data; the backoff ladder
            // rides the same 2->16 ms faces the drained loop used
            idle_turns = (idle_turns + 1).min(32);
            continue;
        }
        idle_turns = 0;
        // the drain: a ready ring empties in batch; the class rides the
        // ring's identity — every ready ring drains each cycle (the
        // ADR-0005 alternation face rides the poll's fairness)
        for (face_i, ring, class) in [
            (0usize, &mut queue, "pipe"),
            (1usize, &mut sock_queue, "socket"),
            (2usize, &mut tls_queue, "tls"),
        ] {
            if poll_set[face_i].revents & libc::POLLIN == 0 && face_i > 0 {
                continue;
            }
            let mut batch = 0u32;
            loop {
                // the batch bound (peer review, ringbuf leaf): a hot
                // producer never holds the drain hostage — at most 64
                // items per ring per cycle, then the cycle re-polls and
                // the other shares ride. The bound rides BEFORE the
                // next() face: a fetched item the drain never processes
                // would drop on the guard (a request vanishing or a
                // captured reply riding a false no-response). The stop
                // and the duration faces recheck the same way.
                if batch >= 64 { break; }
                if expired() || STOP_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) { break; }
                let Some(item) = ring.next() else { break; };
                batch += 1;
                let bytes: &[u8] = &item;
                if bytes.len() < std::mem::size_of::<agentpcap_collector::PipeSample>() {
                    continue;
                }
                let s: &agentpcap_collector::PipeSample =
                    unsafe { &*(bytes.as_ptr() as *const _) };
                seq += 1;
        let machine_pid = s.pid as i64 - offset;
            if machine_pid <= 0 {
                continue;
            }
            let machine_pid = machine_pid as u32;
            let payload_bytes =
                &s.first_bytes[..(s.len as usize).min(agentpcap_collector::PAYLOAD_BYTES_CAP)];
            // The pipe fd face rides BEFORE the parse face (issue #88 +
            // the C116 family): a sink that re-writes the same agent
            // bytes to /dev/null or a file rides as a whole second
            // sample per frame otherwise — the skip face costs one
            // cached readlink, never the classify face. Only the pipe
            // class hoists: the socket and TLS faces resolve through
            // /proc/net and uprobes with the same cost shape as the
            // parse.
            let mut pipe_channel: Option<String> = None;
            if class == "pipe" {
                match agentpcap_collector::resolved_pipe_channel(
                    machine_pid, s.fd, &mut chan_cache,
                    Duration::from_secs(2),
                ) {
                    agentpcap_collector::ChanResolve::Skipped => {
                        // a resolvable fd naming no pipe: live traffic
                        // to a file or terminal — the no-record face
                        // (the C116 family), never a row
                        continue;
                    }
                    agentpcap_collector::ChanResolve::Failed => {
                        // the writer's /proc entry is gone; the record
                        // lands keyed honestly unresolved (ADR-0004)
                    }
                    agentpcap_collector::ChanResolve::Pipe(channel) => {
                        pipe_channel = Some(channel);
                    }
                }
            }
            if classify_pipe_sample(s.pid, s.ppid, "", payload_bytes) == Decision::Other {
                continue;
            }
            // The channel face, per class. The pipe class: the write's
            // fd must name a pipe; the pipe inode is the channel's pair
            // key, so both ends of one channel share the peer and
            // unrelated channels never collide. Three outcomes: a
            // resolvable fd that names pipe[:] records the channel; a
            // resolvable fd that names anything else is live process
            // traffic to a file or socket and never records; a failed
            // lookup means the writer's /proc entry is gone (it died
            // inside the pop window) and the record lands keyed
            // honestly as unresolved, with the fd-unresolved-at-pop
            // evidence. The socket class: the fd names socket[:<inode>]
            // and the five-tuple resolves through /proc/net (ADR-0005).
            // the transport face rides the resolver: a UDP connection
            // is udp, a TCP one tcp — the tap never guesses the class
            let (transport, resolved): (&'static str, Option<ResolvedPeer>) =
                if class == "pipe" {
                    // the hoisted face: the channel resolved before the
                    // parse; the failed face rides unresolved
                    (
                        agentpcap_collector::TRANSPORT_PIPE,
                        pipe_channel
                            .map(|channel| ResolvedPeer::Pipe { channel }),
                    )
                } else if class == "tls" {
                    // the TLS face (ADR-0006): the fd carries no socket
                    // face (the uprobe hands the buffer, not the fd) —
                    // the peer resolves through the writer's connected
                    // socket as the FULL five-tuple face. The endpoint
                    // evidence and the probe direction then name the
                    // same faces the socket class rides: a same-id
                    // reply binds ITS request through the remote-end
                    // face, never the first parked one
                    match agentpcap_collector::scan_connected_socket(machine_pid) {
                        Some(fp) => (fp.transport, Some(ResolvedPeer::Socket(fp))),
                        None => ("socket-unresolved", None),
                    }
                } else {
                    match agentpcap_collector::resolve_socket_peer(machine_pid, s.fd) {
                        Some(fp) => (fp.transport, Some(ResolvedPeer::Socket(fp))),
                        None => ("socket-unresolved", None),
                    }
                };
            let died_unresolved = resolved.is_none();
            let resolved_face = resolved.clone();
            let resolved = resolved
                .map(|rf| rf.peer())
                .unwrap_or_else(|| "unresolved".to_string());
            let ppid = if class == "pipe" {
                resolve_parent(machine_pid, &mut cache, Duration::from_secs(2))
            } else {
                // the socket samples carry no lineage: the session keys
                // by the canonical five-tuple either way (ADR-0005)
                0
            };
            let process = {
                // the wire comm rides the syscall face (ADR-0009, issue
                // #95): the /proc read at the pop never races the
                // writer's own task comm. The /proc face stays the
                // fallback for an empty wire face (a truncated or
                // failed comm fill).
                let wire = agentpcap_collector::wire_comm(&s.comm);
                if wire.is_empty() {
                    agentpcap_collector::cached_comm(
                        machine_pid,
                        &mut comm_cache,
                        Duration::from_secs(2),
                    )
                    .unwrap_or_else(|| "unknown".to_string())
                } else {
                    wire
                }
            };
            let lossy = String::from_utf8_lossy(payload_bytes).to_string();
            let mut evidence = vec![class.to_string()];
            if class == "tls" {
                // the Streamable HTTP framing face (spec Section 5):
                // the transport's headers carry Mc-Session-Id and
                // MCP-Protocol-Version — the session id leads the
                // session face where present, the version rides the
                // evidence. The extraction is case-insensitive on the
                // header names and never guesses outside the buffer
                let lower = lossy.to_ascii_lowercase();
                if let Some(v) = header_value(&lossy, &lower, "mcp-session-id") {
                    evidence.push(format!("http-session:{v}"));
                }
                if let Some(v) = header_value(&lossy, &lower, "mcp-protocol-version") {
                    evidence.push(format!("http-version:{v}"));
                }
                // the session face: a streamable HTTP session id leads
                // the frame's peer, never the endpoints alone (spec
                // Section 5's MUST: the reassembler reconstructs the
                // session from Mc-Session-Id)
            }
            if class == "pipe" {
                evidence[0] = "stdio-pipe".into();
                // the direction face: the pipe ring carries the write
                // faces only (the write tracepoint rides ppid 0; the
                // receive faces push the socket ring), so the pipe
                // class stamps send.
                evidence.push("probe-face:send".into());
            };
            if class == "tls" {
                evidence[0] = "tls-boundary".into();
            };
            if let Some(rf) = &resolved_face {
                if matches!(rf, ResolvedPeer::Socket(_)) {
                    // the canonical five-tuple face rides the evidence
                    evidence.push(format!("peer-face:{resolved}"));
                    // the direction face: the process's own endpoint
                    // and its peer side — the response matching needs it
                    if let Some(local) = rf.local() {
                        evidence.push(format!("local-end:{local}"));
                        evidence.push(format!(
                            "remote-end:{}",
                            rf.remote().unwrap_or_default()
                        ));
                    }
                    // the direction face: which probe observed the frame
                    if s.ppid == 1 {
                        evidence.push("probe-face:receive".into());
                    } else {
                        evidence.push("probe-face:send".into());
                    }
                }
            }
            if ppid != 0 {
                evidence.push(format!("lineage:parent-{ppid}"));
            }
            if died_unresolved {
                evidence.push("fd-unresolved-at-pop".into());
            }
                // The parsed frame feeds the reassembler; a sample with
                // no parseable JSON object (a truncation at the sample
                // cap) records agent-shaped and unresolved, the alpha1
                // face, never a guess.
                // the HTTP-framed face: the body starts AFTER the header
                // block - a header's own braces (a cookie value's JSON
                // shape) never lead the parse, the tool call after the
                // headers still fits the sample limit
                let body_bytes: Vec<u8> = if payload_bytes.starts_with(b"HTTP/1.")
                    || ["POST ", "GET ", "PUT ", "PATCH", "HEAD ", "DELETE"]
                        .iter()
                        .any(|m| payload_bytes.starts_with(m.as_bytes()))
                {
                    let head_end = payload_bytes
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .or_else(|| {
                            payload_bytes.windows(2).position(|w| w == b"\n\n")
                        })
                        .map(|i| {
                            if payload_bytes
                                .get(i..i + 4)
                                .map(|w| w == b"\r\n\r\n")
                                .unwrap_or(false)
                            {
                                i + 4
                            } else {
                                i + 2
                            }
                        })
                        .unwrap_or(payload_bytes.len());
                    let headers =
                        String::from_utf8_lossy(&payload_bytes[..head_end]);
                    // the chunked face: a Transfer-Encoding: chunked body
                    // carries per-chunk size lines — the byte decode
                    // concatenates the chunk payloads so a reply whose
                    // chunks fit the sample window parses whole; the one
                    // lossy decode rides the JOIN, never a slice cut.
                    // the chunked-join evidence lands WHETHER or not the
                    // replayed pair resolves: the evidence row proves the
                    // chunked reply reached the ledger
                    if headers.to_ascii_lowercase().contains("transfer-encoding: chunked") {
                        evidence.push("chunked-join".to_string());
                        dechunk(&payload_bytes[head_end..])
                    } else {
                        payload_bytes[head_end..].to_vec()
                    }
                } else {
                    payload_bytes.to_vec()
                };
                let candidate = String::from_utf8_lossy(&body_bytes);
                // the sse face: a text/event-stream reply carries its
                // JSON in `data:` lines — each line parses on its own
                // (an SSE event never holds split JSON), and the first
                // structurally complete line answers the request. The
                // content-type faces the RAW sample's header block (a
                // reply face: `HTTP/1.` start); a request face carries
                // application/json and never rides this face
                let sse_headers = if payload_bytes.starts_with(b"HTTP/1.") {
                    payload_bytes
                        .windows(4)
                        .position(|w| w == b"\r\n\r\n")
                        .map(|i| {
                            String::from_utf8_lossy(&payload_bytes[..i])
                                .to_ascii_lowercase()
                                .contains("content-type: text/event-stream")
                        })
                        .unwrap_or(false)
                } else {
                    false
                };
                let mut parsed = if sse_headers {
                    let mut found = None;
                    for line in candidate.lines() {
                        if let Some(rest) = line.strip_prefix("data:") {
                            let rest = rest.strip_prefix(' ').unwrap_or(rest);
                            if let Ok(v) = serde_json::from_str::<Value>(rest) {
                                if v.is_object() {
                                    found = Some(v);
                                    break;
                                }
                            }
                        }
                    }
                    found
                } else {
                    serde_json::from_str::<Value>(candidate.as_ref()).ok().filter(|v| v.is_object())
                };
                // the raw fingerprint rides BEFORE any mode rebuild: a
                // notification's dedupe face keeps the raw message's
                // digest (a hash, not content), so two different
                // notifications never strip to one body and drop — the
                // burst face counts them both
                if mode == Mode::Opaque {
                    evidence.push(format!(
                        "nhash:{:016x}",
                        fnv64(candidate.as_bytes())
                    ));
                }
                // the opaque mode rebuilds the object to its identity
                // face: jsonrpc + method + id survive, every other
                // member (params, result, error, any extension the
                // writer injected) strips — an opaque-mode ledger
                // carries no content face ever (ADR-0006). The
                // response side keeps a content-free `result: null`
                // marker so the reassembler still binds the pair, and
                // an error keeps only its stripped shape
                if mode == Mode::Opaque {
                    if let Some(obj) = parsed.as_mut().and_then(|v| v.as_object_mut()) {
                        let id_face = obj.get("id").cloned();
                        let method = obj.get("method").cloned();
                        let jsonrpc = obj.get("jsonrpc").cloned();
                        let mut face = serde_json::Map::new();
                        if let Some(j) = jsonrpc {
                            face.insert("jsonrpc".to_string(), j);
                        }
                        if let Some(m) = method {
                            face.insert("method".to_string(), m);
                        }
                        // the id face carries ONLY when the original
                        // carried it: a JSON-RPC notification omits that
                        // field, and inserting id:null would ride it as
                        // a parked request (the no-response face would
                        // swallow the notify)
                        if let Some(v) = id_face {
                            face.insert("id".to_string(), v);
                        }
                        if obj.contains_key("result") {
                            face.insert("result".to_string(), Value::Null);
                        }
                        if obj.contains_key("error") {
                            let mut stripped = serde_json::Map::new();
                            stripped.insert("stripped".to_string(), Value::Bool(true));
                            if let Some(c) = obj["error"]["code"].as_i64() {
                                stripped.insert("code".to_string(), json!(c));
                            }
                            face.insert("error".to_string(), Value::Object(stripped));
                        }
                        *obj = face;
                    }
                }
                match parsed {
                    Some(payload) => {
                        let frame = Frame {
                            transport: transport.to_string(),
                            peer: resolved,
                            pid: machine_pid,
                            ppid,
                            comm: process,
                            payload,
                            tap_evidence: evidence,
                        };
                        for ev in reassembler.feed(frame) {
                            if let Err(e) =
                                writer.append(&serde_json::to_value(&ev).unwrap())
                            {
                                if matches!(
                                    e,
                                    agentpcap_ledger::LedgerError::Duplicate(_)
                                ) {
                                    eprintln!("agentpcap tap: the dedupe skipped the event: its session event already rides the ledger");
                                    continue;
                                }
                                eprintln!("agentpcap tap: {e}");
                                return ExitCode::FAILURE;
                            }
                        }
                    }
                    None => {
                        // The fd-unresolved face dedups on the CONTENT
                        // hash alone: a sink that re-writes the same
                        // agent bytes (its own pop-window death already
                        // keyed the first copy unresolved) never lands a
                        // second row for the same capture.
                        let dedup_face = if died_unresolved && class == "pipe" {
                            format!("t:{:016x}", fnv64(payload_bytes))
                        } else {
                            format!("{resolved}:t:{:016x}", fnv64(payload_bytes))
                        };
                        let ev = Event {
                            ts: now_rfc3339(),
                            host: host.clone(),
                            process,
                            pid: machine_pid,
                            transport: transport.to_string(),
                            mode: mode.clone(),
                            verdict: Verdict::AgentUnidentified,
                            event: "unidentified".into(),
                            method: None,
                            tool_name: None,
                            cap_fingerprint: None,
                            protocol_version: None,
                            session_id: None,
                            peer: resolved.clone(),
                            dedup: dedup_face,
                            payload: None,
                            evidence: Some(evidence),
                            source: "tap".into(),
                            schema_version: "1.0".into(),
                        };
                        if let Err(e) = writer.append(&serde_json::to_value(&ev).unwrap()) {
                            if matches!(
                                e,
                                agentpcap_ledger::LedgerError::Duplicate(_)
                            ) {
                                eprintln!("agentpcap tap: the dedupe skipped the event: its session event already rides the ledger");
                            } else {
                                eprintln!("agentpcap tap: {e}");
                                return ExitCode::FAILURE;
                            }
                        }
                     }
                }
            }
        }
        }
    // the window ends: every still-pending request lands with the
    // no-response evidence — capture loss degrades the ledger, it never
    // silently drops it
    for ev in reassembler.flush() {
        if let Err(e) = writer.append(&serde_json::to_value(&ev).unwrap()) {
            if matches!(e, agentpcap_ledger::LedgerError::Duplicate(_)) {
                eprintln!("agentpcap tap: the dedupe skipped the flush event: its session event already rides the ledger");
            } else {
                eprintln!("agentpcap tap: {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    // the falsification receipt (issue #83 scratch): the pair stats
    for (idx, name) in [(8u32, "pair_mismatch"), (9, "stale_at_entry"), (11, "collects")] {
        if let Ok(v) = tls_canary.get(&idx, 0) {
            eprintln!("agentpcap tap: c115diag {name}={}", v);
        }
    }
    eprintln!("agentpcap tap: {seq} sample(s) sequenced");

    // The fork lineage face (issue #55): pair receipt at the exit face —
    // the spawned-child pids ride the lineage map, the fork feed = live.
    if let Ok(fork_map) = bpf.take_map("fork_lineage").expect("fork map").try_into() {
        let fork_map: aya::maps::HashMap<_, u32, u32> = fork_map;
        let keys: Vec<u32> = fork_map.keys().flatten().collect();
        for k in keys.iter().take(5) {
            // the pair receipt: both faces ride — the child key and the
            // parent value read back from the same entry
            if let Ok(parent) = fork_map.get(k, 0) {
                eprintln!("agentpcap tap: fork face child={k} parent={parent}");
            }
        }
        eprintln!("agentpcap tap: fork lineage pairs={}", keys.len());
    }

    // C129/the ADR-0002 exit face: the final writes carry the no-response
    // flush face's tail — close() flushes and syncs; a failed final write
    // (the disk full or gone) must not exit success and lose the tail.
    if let Err(e) = writer.close() {
        eprintln!("agentpcap tap: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}


/// A fresh hex token for the calibration sentinel (host entropy pool).
/// /dev/urandom never ends, so the request is a bounded exact read.
/// The calibration token: fresh bytes from the host entropy pool; the
/// read failure is fatal (a zero token makes the sentinel guessable).
/// /dev/urandom never ends, so the request is a bounded exact read.
/// The HTTP header value face: the framed sample's headers ride the
/// buffer with the body; the value reads case-insensitively by name
/// and stops at the first CR or LF. The search bounds by the header
/// block (the blank line), never the body.
/// The wire face of the eBPF's parked TLS call coordinates (the same
/// layout both sides assert): the map's sweeping face needs the value
/// type only for key iteration, the bytes never ride the ledger.
#[derive(Clone, Copy)]
#[repr(C, align(8))]
struct SavedTlsWire {
    ubuf: u64,
    wptr: u64,
    // The park face stores the writer's namespace-visible pid (the ns
    // face, issue #106): the bounded-cleanup sweep checks /proc by it
    // directly — the key's pid half never translates in userspace.
    ns_pid: u32,
    // The park's call flavor + the *written slot's pre-call value ride
    // the wire for the issue #83 falsification face (the probe's
    // SavedTls layout keeps the two sides identical — the field lists
    // match, the sizes assert together).
    flavor: u32,
    stale_at_entry: u64,
}

const _: () = assert!(core::mem::size_of::<SavedTlsWire>() == 32);
// zeroable + any-bit-pattern: the sweep face reads its values' ns pid
unsafe impl aya::Pod for SavedTlsWire {}

/// The chunked decode face rides BYTES: `SIZE\r\n chunk \r\n
/// 0\r\n\r\n` — the chunk payloads concatenate as raw bytes and the
/// UTF-8 decode runs ONCE over the join (a str slice would cut a lossy
/// replacement character mid-sequence and panic). The sizes and
/// separators never ride the body. A malformed size ends the body
/// honestly.
fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut rest = body;
    let mut guard = 0usize;
    while guard < 64 {
        guard += 1;
        let Some(line_end) = rest.iter().position(|b| *b == b'\n') else {
            break;
        };
        let size_line = String::from_utf8_lossy(&rest[..line_end])
            .trim_end()
            .to_string();
        let size_str = size_line.split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(size_str, 16) {
            Ok(s) => s,
            Err(_) => break,
        };
        rest = &rest[line_end + 1..];
        if size == 0 {
            break;
        }
        if size > rest.len() {
            out.extend_from_slice(rest);
            break;
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size..];
        // the chunk's trailing newline pair
        if rest.starts_with(b"\r\n") {
            rest = &rest[2..];
        } else if rest.starts_with(b"\n") {
            rest = &rest[1..];
        }
    }
    out
}

fn header_value(orig: &str, lower: &str, name: &str) -> Option<String> {
    // the search bounds to the HEADER block: the first blank line
    // separates it from the body, and body text never searches
    let head_end = lower
        .find("\r\n\r\n")
        .or_else(|| lower.find("\n\n"))
        .unwrap_or(lower.len());
    // whole header-name match: the name rides its own line start
    let needle = format!("{name}:");
    let mut at = 0usize;
    while let Some(line_end) = lower[at..head_end].find('\n') {
        let line = &lower[at..at + line_end];
        if line.starts_with(&needle) {
            let v = orig[at + needle.len()..at + line_end].trim();
            let v = v.trim_end_matches('\r');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
        at += line_end + 1;
        if at >= head_end {
            break;
        }
    }
    // the tail: the LAST header line holds no own newline inside the
    // head slice — it rides as the final segment
    if at < head_end {
        let line = &lower[at..head_end];
        if line.starts_with(&needle) {
            let v = orig[at + needle.len()..head_end].trim();
            let v = v.trim_end_matches('\r');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

fn random_token() -> Result<String, std::io::Error> {
    use std::io::Read;
    let mut b = [0u8; 8];
    // three bounded attempts: an /dev/urandom hiccup is transient, an
    // unexplained failure stays fatal (fail-closed)
    let mut last = None;
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(5));
        }
        match std::fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut b)) {
            Ok(()) => {
                return Ok(b.iter().map(|x| format!("{x:02x}")).collect());
            }
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap())
}

fn print_sessions(view: Vec<Value>) -> std::io::Result<()> {
    report::print_sessions(view)
}

/// The gate stream: the ledger's events to stdout as JSON Lines, in
/// lossless order; `--follow` keeps streaming the appends after the
/// existing segment. The read logs as agentpcap.export. The stream
/// carries the ledger's ORIGINAL line bytes: a consumer re-verifying
/// the chain hashes the same bytes the recorder shipped — a
/// re-serialization would change a line's bytes and break the next
/// record's `prev` hash against it.
fn export(path: PathBuf, follow: bool) -> ExitCode {
    // the chain verification and the access log ride the reader open
    if let Err(e) = LedgerReader::open(&path, "agentpcap.export") {
        eprintln!("agentpcap export: {e}");
        return ExitCode::FAILURE;
    }
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    // The initial position rides ONE read from byte zero: the complete
    // lines stream now and `pos` answers from the same bytes — an
    // append that lands while the dump drains never slips between a
    // records() call and a later metadata read.
    let mut f = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("agentpcap export: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut buf = Vec::new();
    use std::io::Read as _;
    if f.read_to_end(&mut buf).is_err() {
        return ExitCode::FAILURE;
    }
    drop(f);
    let mut pos = match stream_complete(&mut out, &buf, true) {
        Ok(n) => n,
        Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
            eprintln!("agentpcap export: a ledger line is not valid JSON");
            return ExitCode::FAILURE;
        }
        Err(_) => return ExitCode::FAILURE,
    };
    if out.flush().is_err() {
        return ExitCode::FAILURE;
    }
    if !follow {
        return ExitCode::SUCCESS;
    }
    // the follow: a position face — the file reads from the last
    // offset, only complete lines stream, and an unfinished tail waits
    // for its newline. The access log logs once, at the open above;
    // the idle polls parse nothing. File identity rides the inode: a
    // ledger rotation renames the closed segment and opens a fresh
    // file, and the gate stream drains the closed segment's tail from
    // the old position before the fresh segment streams from zero.
    let mut ino = std::fs::metadata(&path)
        .map(|m| std::os::unix::fs::MetadataExt::ino(&m))
        .unwrap_or(0);
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let Ok(meta) = std::fs::metadata(&path) else {
            return ExitCode::FAILURE;
        };
        let cur_ino = std::os::unix::fs::MetadataExt::ino(&meta);
        let len = meta.len();
        if cur_ino != ino {
            // the ledger rotated: the closed segment's tail drains
            // from the segment file, then the fresh one starts at zero
            let closed = PathBuf::from(format!("{}.1", path.display()));
            match std::fs::read(&closed) {
                Ok(tail) => {
                    if (tail.len() as u64) > pos {
                        if let Err(e) = stream_complete(&mut out, &tail[pos as usize..], false) {
                            match e.kind() {
                                // the consumer closed the stream mid-drain:
                                // a clean end on either shutdown face
                                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::WriteZero => {
                                    return ExitCode::SUCCESS
                                }
                                _ => return ExitCode::FAILURE,
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("agentpcap export: the closed segment read failed: {e}");
                    return ExitCode::FAILURE;
                }
            }
            let _ = out.flush();
            pos = 0;
            ino = cur_ino;
            continue;
        }
        if len <= pos {
            continue;
        }
        let Ok(mut f) = std::fs::File::open(&path) else {
            return ExitCode::FAILURE;
        };
        use std::io::Seek;
        if f.seek(std::io::SeekFrom::Start(pos)).is_err() {
            return ExitCode::FAILURE;
        }
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_err() {
            return ExitCode::FAILURE;
        }
        match stream_complete(&mut out, &buf, true) {
            Ok(n) => {
                pos += n;
                let _ = out.flush();
            }
            Err(e) => match e.kind() {
                // the consumer closed the stream: a clean end. SIGPIPE
                // on a closed gate lands as BrokenPipe on write_all; a
                // permanently clogged pipe lands as WriteZero. Both
                // are ordinary shutdown faces, never a failed export
                std::io::ErrorKind::BrokenPipe => return ExitCode::SUCCESS,
                std::io::ErrorKind::WriteZero => return ExitCode::SUCCESS,
                std::io::ErrorKind::InvalidData => {
                    // a complete malformed line never streams: fail-closed
                    eprintln!("agentpcap export: an appended line is not valid JSON");
                    return ExitCode::FAILURE;
                }
                _ => return ExitCode::FAILURE,
            },
        }
    }
}

/// Stream `buf`'s complete lines verbatim (each byte rides); the
/// return value is the consumed byte count — the trailing partial tail
/// waits for its newline. A complete malformed line never streams.
/// With `lenient_tail` unset, any trailing garbage is fatal.
fn stream_complete(
    out: &mut std::io::StdoutLock,
    buf: &[u8],
    lenient_tail: bool,
) -> std::io::Result<u64> {
    let mut consumed = 0u64;
    let mut start = 0usize;
    let mut complete_end = buf.len();
    if !buf.ends_with(b"\n") {
        match buf.iter().rposition(|b| *b == b'\n') {
            Some(i) => complete_end = i + 1,
            // nothing complete arrived; the tail waits (or is fatal
            // for a closed read)
            None => {
                if lenient_tail && !buf.is_empty() {
                    eprintln!("agentpcap export: the tail waits for its newline");
                    return Ok(0);
                }
                if !std::str::from_utf8(buf).map(|s| s.trim().is_empty()).unwrap_or(false) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "the tail has no newline",
                    ));
                }
                return Ok(0);
            }
        }
    }
    for i in 0..complete_end {
        if buf[i] == b'\n' {
            let line = &buf[start..i];
            if serde_json::from_slice::<Value>(line).is_err() {
                eprintln!(
                    "agentpcap export: the line is not valid JSON: {}",
                    String::from_utf8_lossy(line)
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "the line is not valid JSON",
                ));
            }
            out.write_all(line)?;
            out.write_all(b"\n")?;
            consumed = (i + 1) as u64;
            start = i + 1;
        }
    }
    Ok(consumed)
}

fn diff(before: PathBuf, after: PathBuf) -> ExitCode {
    let events = match diff::drift(&before, &after) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("agentpcap diff: {e}");
            return ExitCode::FAILURE;
        }
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for e in &events {
        if serde_json::to_writer(&mut out, e).is_err() || writeln!(out).is_err() {
            return ExitCode::FAILURE;
        }
    }
    let _ = out.flush();
    ExitCode::SUCCESS
}
