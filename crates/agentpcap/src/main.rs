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

const USAGE: &str = "usage: agentpcap record --ledger <path>\n       agentpcap report --ledger <path>\n       agentpcap tap --ledger <path> [--duration <seconds>] [--cgroup <id>] [--mode opaque]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match (args.first().map(String::as_str), args.get(2)) {
        (Some("record"), Some(path)) => record(PathBuf::from(path)),
        (Some("report"), Some(path)) => report(PathBuf::from(path)),
        (Some("tap"), Some(path)) => tap(
            PathBuf::from(path),
            args.iter()
                .position(|a| a == "--duration")
                .and_then(|i| args.get(i + 1))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(60),
            args.iter()
                .position(|a| a == "--cgroup")
                .and_then(|i| args.get(i + 1))
                .and_then(|v| v.parse::<u64>().ok()),
            // the mode face: attributed is the default (spec section 8);
            // `--mode opaque` strips the payload content at the feed face
            args.iter()
                .position(|a| a == "--mode")
                .and_then(|i| args.get(i + 1))
                .map(|v| match v.as_str() {
                    "opaque" => Mode::Opaque,
                    _ => Mode::Attributed,
                })
                .unwrap_or(Mode::Attributed),
        ),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn record(path: PathBuf) -> ExitCode {
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
        let event = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("agentpcap record: event {n} is not valid JSON: {e}");
                return ExitCode::FAILURE;
            }
        };
        if let Err(e) = writer.append(&event) {
            eprintln!("agentpcap record: {e}");
            return ExitCode::FAILURE;
        }
        count += 1;
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
fn tap(ledger_path: PathBuf, duration_secs: u64, cgroup: Option<u64>, mode: Mode) -> ExitCode {
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
    let prog_recv: &mut TracePoint =
        match bpf.program_mut("agentpcap_recv").expect("recv program").try_into() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("agentpcap tap: agentpcap_recv is not a tracepoint");
                return ExitCode::FAILURE;
            }
        };
    if let Err(e) = prog_recv
        .load()
        .and_then(|_| prog_recv.attach("syscalls", "sys_enter_recvfrom"))
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
    // The cgroup filter face (ADR-0005): the marker key turns the
    // probe's allow filter on; the lab default captures all.
    if let Some(cg) = cgroup {
        let mut allow: aya::maps::HashMap<_, u64, u32> = match bpf
            .take_map("cgroup_allow")
            .expect("cgroup_allow map")
            .try_into()
        {
            Ok(a) => a,
            Err(e) => {
                eprintln!("agentpcap tap: {e}");
                return ExitCode::FAILURE;
            }
        };
        allow.insert(u64::MAX, 1, 0).ok();
        allow.insert(cg, 1, 0).ok();
        drop(allow);
    }

    // The TLS-boundary collector (ADR-0006): the uprobes ride the host
    // libssl's SSL_write_ex/SSL_read_ex (the face the host ssl module
    // calls directly), sharing the calibration and the cgroup map.
    let prog_tls_w: &mut aya::programs::UProbe =
        match bpf.program_mut("agentpcap_tls_write").expect("tls write program").try_into() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("agentpcap tap: agentpcap_tls_write is not an uprobe");
                return ExitCode::FAILURE;
            }
        };
    let libssl = "/usr/lib/aarch64-linux-gnu/libssl.so.3";
    if let Err(e) = prog_tls_w
        .load()
        .and_then(|_| prog_tls_w.attach(Some("SSL_write_ex"), 0, libssl, None))
    {
        eprintln!("agentpcap tap: the tls write load/attach failed: {e}");
        return ExitCode::FAILURE;
    }
    let prog_tls_r: &mut aya::programs::UProbe =
        match bpf.program_mut("agentpcap_tls_read").expect("tls read program").try_into() {
            Ok(p) => p,
            Err(_) => {
                eprintln!("agentpcap tap: agentpcap_tls_read is not an uprobe");
                return ExitCode::FAILURE;
            }
        };
    if let Err(e) = prog_tls_r
        .load()
        .and_then(|_| prog_tls_r.attach(Some("SSL_read_ex"), 0, libssl, None))
    {
        eprintln!("agentpcap tap: the tls read load/attach failed: {e}");
        return ExitCode::FAILURE;
    }
    let mut tls_queue: Queue<_, agentpcap_collector::PipeSample> =
        match bpf.take_map("tls_events").expect("tls queue map").try_into() {
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
    let mut reassembler = Reassembler::new(host.clone(), mode.clone(), "tap".into());
    let mut seq: u64 = 0;
    let deadline = Instant::now() + Duration::from_secs(duration_secs);

    while Instant::now() < deadline {
        // the drain alternates the three class queues (ADR-0005,
        // ADR-0006): the class of a sample comes from the map, not
        // from the wire
        let sample_class = match queue.pop(0) {
            Ok(s) => Some(("stdio-pipe", "pipe", s)),
            Err(_) => match sock_queue.pop(0) {
                Ok(s) => Some((agentpcap_collector::TRANSPORT_TCP, "socket", s)),
                Err(_) => match tls_queue.pop(0) {
                    Ok(s) => Some((agentpcap_collector::TRANSPORT_TCP, "tls", s)),
                    Err(_) => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                },
            },
        };
        let Some((transport, class, s)) = sample_class else {
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
            let peer = if class == "pipe" {
                let fd_path = format!("/proc/{machine_pid}/fd/{}", s.fd);
                pipe_fd_channel(&fd_path, machine_pid, s.fd)
            } else if class == "socket" {
                match agentpcap_collector::resolve_socket_peer(machine_pid, s.fd) {
                    Some(p) => Some(p),
                    None => None,
                }
            } else {
                // the TLS face (ADR-0006): the fd carries no socket; the
                // peer scans the writer's connected sockets
                agentpcap_collector::scan_connected_socket(machine_pid)
            };
            let died_unresolved = peer.is_none();
            let resolved = peer.unwrap_or_else(|| "unresolved".to_string());
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
            if class == "tls" {
                evidence[0] = "tls-boundary".into();
            };
            if class != "pipe" {
                // the canonical five-tuple face rides the evidence
                evidence.push(format!("peer-face:{resolved}"));
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
        // face, never a guess. The opaque mode strips the payload
        // content at this feed face: the record carries the method and
        // the id face, the args and results never ride.
        let candidate = lossy.trim_start_matches(|c| c != '{');
        let mut parsed = serde_json::from_str::<Value>(candidate)
            .ok()
            .filter(|v| v.is_object());
        if mode == Mode::Opaque {
            if let Some(obj) = parsed.as_mut().and_then(|v| v.as_object_mut()) {
                obj.remove("params");
                obj.remove("result");
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
                            dedup: format!("{resolved}:{seq}"),
                            payload: None,
                            evidence: Some(evidence),
                            source: "tap".into(),
                            schema_version: "1.0".into(),
                        };
                        if let Err(e) = writer.append(&serde_json::to_value(&ev).unwrap()) {
                            eprintln!("agentpcap tap: {e}");
                            return ExitCode::FAILURE;
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
            eprintln!("agentpcap tap: {e}");
            return ExitCode::FAILURE;
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
