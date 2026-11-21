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
use aya::maps::Queue;
use aya::programs::TracePoint;
use serde_json::Value;
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

const USAGE: &str = "usage: agentpcap record --ledger <path>\n       agentpcap report --ledger <path>\n       agentpcap export --ledger <path> [--follow]\n       agentpcap diff --before <ledger> --after <ledger>\n       agentpcap tap --ledger <path> [--duration <seconds>]";

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

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verb = args.first().map(String::as_str);
    match verb {
        Some("record") => match flag(&args[1..], "--ledger", true) {
            Some(path) => record(PathBuf::from(path)),
            None => misuse(USAGE),
        },
        Some("report") => match flag(&args[1..], "--ledger", true) {
            Some(path) => report(PathBuf::from(path)),
            None => misuse(USAGE),
        },
        Some("export") => match flag(&args[1..], "--ledger", true) {
            Some(path) => export(
                PathBuf::from(path),
                flag(&args[1..], "--follow", false).is_some(),
            ),
            None => misuse(USAGE),
        },
        Some("diff") => {
            let before = flag(&args[1..], "--before", true);
            let after = flag(&args[1..], "--after", true);
            match (before, after) {
                (Some(b), Some(a)) => diff(PathBuf::from(b), PathBuf::from(a)),
                _ => misuse(USAGE),
            }
        }
        Some("tap") => match flag(&args[1..], "--ledger", true) {
            Some(path) => tap(
                PathBuf::from(path),
                flag(&args[1..], "--duration", true)
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(60),
            ),
            None => misuse(USAGE),
        },
        _ => misuse(USAGE),
    }
}

fn misuse(_msg: &str) -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
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

fn print_sessions(view: Vec<Value>) -> std::io::Result<()> {
    report::print_sessions(view)
}

/// The gate stream: the ledger's events to stdout as JSON Lines, in
/// lossless order; `--follow` keeps streaming the appends after the
/// existing segment. The read logs as agentpcap.export.
fn export(path: PathBuf, follow: bool) -> ExitCode {
    let stdout = std::io::stdout();
    let dump = |out: &mut std::io::StdoutLock, reader: &mut LedgerReader| -> std::io::Result<()> {
        for rec in reader.records() {
            let line = serde_json::to_string(rec).unwrap_or_default();
            writeln!(out, "{line}")?;
        }
        out.flush()
    };
    let mut reader = match LedgerReader::open(&path, "agentpcap.export") {
        Ok(r) => r,
        Err(e) => {
            eprintln!("agentpcap export: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut out = stdout.lock();
    if dump(&mut out, &mut reader).is_err() {
        return ExitCode::FAILURE;
    }
    let before = reader.len();
    drop(reader);
    if !follow {
        return ExitCode::SUCCESS;
    }
    // the follow: poll the file's growth, stream the new records in
    // order, stay until the consumer closes the stream
    let mut streamed = before;
    loop {
        std::thread::sleep(Duration::from_millis(200));
        let Ok(mut reader) = LedgerReader::open(&path, "agentpcap.export") else {
            return ExitCode::FAILURE;
        };
        let len = reader.len();
        if len == streamed {
            drop(reader);
            continue;
        }
        let records = reader.records();
        for rec in records.iter().skip(streamed) {
            let line = serde_json::to_string(rec).unwrap_or_default();
            if writeln!(out, "{line}").is_err() {
                // the consumer closed the stream: a clean end
                return ExitCode::SUCCESS;
            }
        }
        let _ = out.flush();
        streamed = len;
        drop(reader);
    }
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

/// The tap: load the probe, drain the queue, classify, reassemble,
/// ledger. The classified frames feed the reassembler; the reassembled
/// session events land in the ledger one per session event.
fn tap(ledger_path: PathBuf, duration_secs: u64) -> ExitCode {
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
    let deadline = Instant::now() + Duration::from_secs(duration_secs);

    while Instant::now() < deadline {
        match queue.pop(0) {
            Ok(s) => {
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
                // Pipe identity: the write's fd must name a pipe; the
                // pipe inode is the channel's pair key, so both ends of
                // one channel share the peer and unrelated channels
                // never collide. Three outcomes: a resolvable fd that
                // names pipe[:] records the channel; a resolvable fd
                // that names anything else is live process traffic to a
                // file or socket and never records; a failed lookup
                // means the writer's /proc entry is gone (it died
                // inside the pop window) and the record lands keyed
                // honestly as unresolved, with the fd-unresolved-at-pop
                // evidence.
                let fd_path = format!("/proc/{machine_pid}/fd/{}", s.fd);
                let peer = (0..5)
                    .find_map(|attempt| {
                        if attempt > 0 {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        match std::fs::read_link(&fd_path) {
                            // the entry is gone: retry
                            Err(_) => None,
                            Ok(p) => Some(p),
                        }
                    })
                    .map(|l| {
                        // the fd resolved at least once: final answer
                        let text = l.to_string_lossy().to_string();
                        match text
                            .strip_suffix(']')
                            .and_then(|rest| rest.strip_prefix("pipe:["))
                        {
                            Some(inode) => format!("pipe:{inode}"),
                            // a live non-pipe fd: not stdio traffic
                            _ => {
                                eprintln!(
                                    "agentpcap tap: skip: pid={machine_pid} fd={} link={text}",
                                    s.fd
                                );
                                String::from("skipped")
                            }
                        }
                    })
                    .and_then(|p| {
                        if p == "skipped" {
                            None
                        } else {
                            Some(p)
                        }
                    });
                let died_unresolved = peer.is_none();
                let resolved = peer.unwrap_or_else(|| "unresolved".to_string());
                let ppid = resolve_parent(machine_pid, &mut cache, Duration::from_secs(2));
                let process =
                    std::fs::read_to_string(format!("/proc/{machine_pid}/comm"))
                        .map(|c| c.trim().to_string())
                        .unwrap_or_else(|_| "unknown".to_string());
                let lossy = String::from_utf8_lossy(payload_bytes).to_string();
                let mut evidence = vec!["stdio-pipe".to_string()];
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
                            transport: "stdio-pipe".into(),
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
                            transport: "stdio-pipe".into(),
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
            Err(_) => std::thread::sleep(Duration::from_millis(2)),
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
