// The agentpcap operator CLI. Normative source: `docs/spec.md#9-operator-cli`.
// `record` appends JSON Lines events from stdin to the ledger; `report`
// prints the records and logs the read; `tap` runs the eBPF probe loop
// and appends the classified flows. All faces fail closed.

use agentpcap_collector::{classify_pipe_sample, resolve_parent, Decision, ParentCache};
use agentpcap_events::{Event, Mode, Verdict};
use agentpcap_ledger::{now_rfc3339, LedgerReader, LedgerWriter};
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

const USAGE: &str = "usage: agentpcap record --ledger <path>\n       agentpcap report --ledger <path>\n       agentpcap tap --ledger <path> [--duration <seconds>]";

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

/// The tap: load the probe, drain the queue, classify, ledger.
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
    let token = random_token();
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
                    decision => {
                        let verdict = match decision {
                            Decision::Mcp => Verdict::Mcp,
                            Decision::AgentUnidentified => Verdict::AgentUnidentified,
                            Decision::Other => continue,
                        };
                        let lossy = String::from_utf8_lossy(payload_bytes).to_string();
                        let method = extract_method(payload_bytes);
                        let event_name = event_name_for(method.as_deref());
                        let payload: Option<Value> =
                            serde_json::from_str::<Value>(lossy.trim_start_matches(|c| c != '{'))
                                .ok();
                        let process =
                            std::fs::read_to_string(format!("/proc/{machine_pid}/comm"))
                                .map(|c| c.trim().to_string())
                                .unwrap_or_else(|_| "unknown".to_string());
                        // pipe identity: the write's fd must name a pipe;
                        // the pipe inode is the channel's pair key, so
                        // both ends of one channel share the peer and
                        // unrelated channels never collide. Non-pipe
                        // writes (regular files, sockets) are not stdio
                        // traffic and are not recorded.
                        let link = std::fs::read_link(format!(
                            "/proc/{machine_pid}/fd/{}",
                            s.fd
                        ))
                        .map(|l| l.to_string_lossy().to_string())
                        .unwrap_or_default();
                        let Some(inode) = link
                            .strip_prefix("pipe:[")
                            .and_then(|r| r.strip_suffix(']'))
                        else {
                            eprintln!(
                                "agentpcap tap: skipped: pid={machine_pid} fd={} link not a pipe ({link})",
                                s.fd
                            );
                            continue;
                        };
                        let peer = format!("pipe:{inode}");
                        let ppid =
                            resolve_parent(machine_pid, &mut cache, Duration::from_secs(2));
                        let mut evidence = vec!["stdio-pipe".to_string()];
                        if ppid != 0 {
                            evidence.push(format!("lineage:parent-{ppid}"));
                        }
                        let event = Event {
                            ts: now_rfc3339(),
                            host: host.clone(),
                            process,
                            pid: machine_pid,
                            transport: "stdio-pipe".into(),
                            mode: Mode::Attributed,
                            verdict,
                            event: event_name.into(),
                            method: method.clone(),
                            tool_name: None,
                            cap_fingerprint: None,
                            protocol_version: None,
                            session_id: None,
                            peer: peer.clone(),
                            dedup: format!("{peer}:{seq}"),
                            payload,
                            evidence: Some(evidence),
                            source: "tap".into(),
                            schema_version: "1.0".into(),
                        };
                        if let Err(e) = writer.append(&serde_json::to_value(&event).unwrap()) {
                            eprintln!("agentpcap tap: {e}");
                            return ExitCode::FAILURE;
                        }
                    }
                }
            }
            Err(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    eprintln!("agentpcap tap: {seq} sample(s) sequenced");
    // the push outcomes ride a receipt file beside the ledger: the
    // test's tap stderr is discarded, the counters' answer is not
    if let Some(m) = bpf.take_map("events") {
        if let Ok(counters) = aya::maps::Array::<_, u64>::try_from(m) {
            let ok = counters.get(&2u32, 0).unwrap_or(0);
            let fail = counters.get(&3u32, 0).unwrap_or(0);
            let _ = std::fs::write(
                format!("{}.push-receipt", ledger_path.display()),
                format!("push_ok={ok} push_fail={fail}\n"),
            );
        }
    }
    ExitCode::SUCCESS
}

fn extract_method(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes);
    let candidate = text.trim_start_matches(|c| c != '{');
    let v: Value = serde_json::from_str(candidate).ok()?;
    v["method"].as_str().map(|m| m.to_string())
}

fn event_name_for(method: Option<&str>) -> &'static str {
    match method {
        Some("initialize") => "init",
        Some("tools/list") => "tools-list",
        Some("tools/call") => "tools-call",
        Some(m) if m.starts_with("notifications/") => "notify",
        _ => "unidentified",
    }
}

/// A fresh hex token for the calibration sentinel (host entropy pool).
/// /dev/urandom never ends, so the request is a bounded exact read.
fn random_token() -> String {
    use std::io::Read;
    let mut b = [0u8; 8];
    std::fs::OpenOptions::new()
        .read(true)
        .open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .ok();
    b.iter().map(|x| format!("{x:02x}")).collect()
}
