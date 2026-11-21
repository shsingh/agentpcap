// The agentpcap operator CLI. Normative source: `docs/spec.md#9-operator-cli`.
// `record` appends JSON Lines events from stdin to the ledger; `report`
// prints the records and logs the read. Both fail closed.

use agentpcap_ledger::{LedgerReader, LedgerWriter};
use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "usage: agentpcap record --ledger <path>\n       agentpcap report --ledger <path>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match (args.first().map(String::as_str), args.get(2)) {
        (Some("record"), Some(path)) => record(PathBuf::from(path)),
        (Some("report"), Some(path)) => report(PathBuf::from(path)),
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
