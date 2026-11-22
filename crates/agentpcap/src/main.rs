// The agentpcap operator CLI. Normative source: `docs/spec.md#9-operator-cli`.
// `record` appends JSON Lines events from stdin to the ledger; `report`
// prints the records and logs the read; `tap` runs the eBPF probe loop
// and appends the reassembled session events. All faces fail closed.

use agentpcap_collector::{classify_pipe_sample, resolve_parent, Decision, ParentCache};
use agentpcap_events::{Event, Mode, Verdict};
use agentpcap_ledger::{now_rfc3339, LedgerReader, LedgerWriter};
use agentpcap_reassemble::{Frame, Reassembler};
use aya::maps::Queue;
use aya::programs::TracePoint;
use serde_json::Value;
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant};

// The probe object is a build artifact of the standalone eBPF crate;
// the workspace build order produces it before this crate compiles.
static BPF_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../agentpcap-ebpf/target/bpfel-unknown-none/release/agentpcap"
));

const USAGE: &str = "usage: agentpcap record --ledger <path> [--source <face>]\n       agentpcap report --ledger <path>\n       agentpcap tap --ledger <path> [--duration <seconds>] [--cgroup <id>]\n       (--duration 0 runs the capture unbounded)";

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
            )
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
            Ok(_) => count += 1,
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
    ExitCode::SUCCESS
}

fn report(path: PathBuf) -> ExitCode {
    let reader = match LedgerReader::open(&path, "agentpcap.report") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("agentpcap report: {e}");
            return ExitCode::FAILURE;
        }
    };
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for rec in reader.records() {
        let line = serde_json::to_string(rec).unwrap_or_default();
        if writeln!(out, "{line}").is_err() {
            return ExitCode::FAILURE;
        }
    }
    if out.flush().is_err() {
        return ExitCode::FAILURE;
    }
    eprintln!("agentpcap report: {} record(s)", reader.len());
    ExitCode::SUCCESS
}

/// The tap: load the probe, drain the queue, classify, reassemble,
/// ledger. The classified frames feed the reassembler; the reassembled
/// session events land in the ledger one per session event.
fn tap(ledger_path: PathBuf, duration_secs: u64, cgroup: Option<u64>) -> ExitCode {
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
    let mut bpf = match aya::Bpf::load(BPF_OBJ) {
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

    let mut queue: Queue<_, agentpcap_collector::PipeSample> =
        match bpf.take_map("pipe_events").expect("queue map").try_into() {
            Ok(q) => q,
            Err(e) => {
                eprintln!("agentpcap tap: {e}");
                return ExitCode::FAILURE;
            }
        };

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
    let mut sock_queue: Queue<_, agentpcap_collector::PipeSample> =
        match bpf.take_map("sock_events").expect("sock queue map").try_into() {
            Ok(q) => q,
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
        match queue.pop(0) {
            Ok(s) => {
                let n = (s.len as usize).min(agentpcap_collector::PAYLOAD_BYTES_CAP);
                if n == expected.len() && s.first_bytes[..n] == expected {
                    offset = Some(s.pid as i64 - own as i64);
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    drop(calib_dir);
    let Some(offset) = offset else {
        eprintln!("agentpcap tap: the calibration sample never arrived");
        return ExitCode::FAILURE;
    };

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
    let mut reassembler = Reassembler::new(host.clone(), Mode::Attributed, "tap".into());
    let mut seq: u64 = 0;
    let start = Instant::now();
    let expired = || !unbounded && Instant::now() >= start + Duration::from_secs(duration_secs);

    // the drain alternates the two class queues (ADR-0005): each cycle
    // gives one queue the first share and falls back to the other, so
    // sustained pipe traffic never starves the socket face
    let mut turn = true;
    while !expired() && !STOP_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) {
        // the idle face: the sweep expires stale parked requests (they
        // ride the no-response face once) and idle sessions — the
        // deployed service never grows its in-memory faces without
        // limit
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
        let sample_class = if turn {
            queue
                .pop(0)
                .ok()
                .map(|s| ("pipe", s))
                .or_else(|| sock_queue.pop(0).ok().map(|s| ("socket", s)))
        } else {
            sock_queue
                .pop(0)
                .ok()
                .map(|s| ("socket", s))
                .or_else(|| queue.pop(0).ok().map(|s| ("pipe", s)))
        };
        turn = !turn;
        let Some((class, s)) = sample_class else {
            std::thread::sleep(Duration::from_millis(2));
            continue;
        };
        {
            seq += 1;
            let machine_pid = s.pid as i64 - offset;
            if machine_pid <= 0 {
                continue;
            }
            let machine_pid = machine_pid as u32;
            let payload_bytes =
                &s.first_bytes[..(s.len as usize).min(agentpcap_collector::PAYLOAD_BYTES_CAP)];
            match classify_pipe_sample(s.pid, s.ppid, "", payload_bytes) {
                Decision::Other => continue,
                _ => (),
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
                    let fd_path = format!("/proc/{machine_pid}/fd/{}", s.fd);
                    (
                        agentpcap_collector::TRANSPORT_PIPE,
                        pipe_fd_channel(&fd_path, machine_pid, s.fd)
                            .map(|channel| ResolvedPeer::Pipe { channel }),
                    )
                } else {
                    match agentpcap_collector::resolve_socket_peer(machine_pid, s.fd) {
                        Some(fp) => (fp.transport, Some(ResolvedPeer::Socket(fp))),
                        None => ("socket-unresolved", None),
                    }
                };
            let died_unresolved = resolved.is_none();
            let resolved_face = resolved.clone();
            let resolved = resolved.map(|rf| rf.peer()).unwrap_or_else(|| "unresolved".to_string());
            let ppid = if class == "pipe" {
                resolve_parent(machine_pid, &mut cache, Duration::from_secs(2))
            } else {
                // the socket samples carry no lineage: the session keys
                // by the canonical five-tuple either way (ADR-0005)
                0
            };
            let process =
                std::fs::read_to_string(format!("/proc/{machine_pid}/comm"))
                    .map(|c| c.trim().to_string())
                    .unwrap_or_else(|_| "unknown".to_string());
            let lossy = String::from_utf8_lossy(payload_bytes).to_string();
            let mut evidence = vec![class.to_string()];
            if class == "pipe" {
                evidence[0] = "stdio-pipe".into();
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
                let candidate = lossy.trim_start_matches(|c| c != '{');
                let parsed = serde_json::from_str::<Value>(candidate)
                    .ok()
                    .filter(|v| v.is_object());
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
                                if matches!(e, agentpcap_ledger::LedgerError::Duplicate(_)) {
                                    eprintln!("agentpcap tap: the dedupe skipped the event: its session event already rides the ledger");
                                    continue;
                                }
                                eprintln!("agentpcap tap: {e}");
                                return ExitCode::FAILURE;
                            }
                        }
                    }
                    None => {
                        let ev = Event {
                            ts: now_rfc3339(),
                            host: host.clone(),
                            process,
                            pid: machine_pid,
                            transport: transport.to_string(),
                            mode: Mode::Attributed,
                            verdict: Verdict::AgentUnidentified,
                            event: "unidentified".into(),
                            method: None,
                            tool_name: None,
                            cap_fingerprint: None,
                            protocol_version: None,
                            session_id: None,
                            peer: resolved.clone(),
                            dedup: format!(
                                "{resolved}:t:{:016x}",
                                fnv64(payload_bytes)
                            ),
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
    eprintln!("agentpcap tap: {seq} sample(s) sequenced");
    ExitCode::SUCCESS
}

/// The pipe channel face (ADR-0004): a resolvable fd naming
/// `pipe:[<inode>]` names the channel; a resolvable fd naming anything
/// else is live non-pipe traffic and never records; a failed lookup
/// (the writer died inside the pop window) keys the record honestly
/// unresolved with its evidence.
fn pipe_fd_channel(fd_path: &str, machine_pid: u32, fd: u32) -> Option<String> {
    (0..5)
        .find_map(|attempt| {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(2));
            }
            std::fs::read_link(fd_path).ok()
        })
        .map(|l| {
            let text = l.to_string_lossy().to_string();
            match text
                .strip_suffix(']')
                .and_then(|rest| rest.strip_prefix("pipe:["))
            {
                Some(inode) => format!("pipe:{inode}"),
                _ => {
                    eprintln!("agentpcap tap: skip: pid={machine_pid} fd={fd} link={text}");
                    String::from("skipped")
                }
            }
        })
        .and_then(|p| if p == "skipped" { None } else { Some(p) })
}

/// A fresh hex token for the calibration sentinel (host entropy pool).
/// /dev/urandom never ends, so the request is a bounded exact read.
/// The calibration token: fresh bytes from the host entropy pool; the
/// read failure is fatal (a zero token makes the sentinel guessable).
/// /dev/urandom never ends, so the request is a bounded exact read.
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
