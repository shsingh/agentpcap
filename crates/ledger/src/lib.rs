//! The agentpcap ledger: JSON Lines, append-only, `prev`-hash chained.
//!
//! Normative source: `docs/spec.md#7-the-flow-ledger`.
//!
//! Hash rule: `prev` is the first 16 hex digits of the SHA-256 of the
//! previous record body, without the trailing newline. The first record
//! in a segment carries an empty `prev`; a rotated segment continues
//! the chain with the last record of the closed segment.

use serde_json::json;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SCHEMA_VERSION: &str = "1.0";

/// Failure classes for the ordered-check semantics of the ledger.
#[derive(Debug)]
pub enum LedgerError {
    /// The file does not end with a newline: a crash mid-append.
    TornTail,
    /// Record at index does not chain from its predecessor.
    ChainBreak(usize),
    /// Record at index is not a valid JSON object.
    Format(usize),
    Io(std::io::Error),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::TornTail => write!(f, "torn tail: file does not end with a newline"),
            LedgerError::ChainBreak(i) => write!(f, "chain break at record {i}"),
            LedgerError::Format(i) => write!(f, "record {i} is not a valid JSON object"),
            LedgerError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<std::io::Error> for LedgerError {
    fn from(e: std::io::Error) -> Self {
        LedgerError::Io(e)
    }
}

fn trunc(body: &str) -> String {
    let d = Sha256::digest(body.as_bytes());
    hex::encode(d)[..16].to_string()
}

/// Verify a single ledger file. Returns the record count and the hash
/// of the last record body.
fn check(path: &Path) -> Result<(usize, String), LedgerError> {
    let data = fs::read(path)?;
    if data.is_empty() {
        return Ok((0, String::new()));
    }
    if data.last() != Some(&b'\n') {
        return Err(LedgerError::TornTail);
    }
    let text = String::from_utf8_lossy(&data);
    let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
    // Line 0 is genesis (empty `prev`) or a carried hash from a closed
    // segment after rotation. In-file chaining is enforced from line 1.
    let mut expected = String::new();
    for (i, line) in lines.iter().enumerate() {
        let v: Value = serde_json::from_str(line).map_err(|_| LedgerError::Format(i))?;
        let got = v["prev"].as_str().unwrap_or_default().to_string();
        if i == 0 {
            let valid_carry = got.len() == 16 && got.chars().all(|c| c.is_ascii_hexdigit());
            if !got.is_empty() && !valid_carry {
                return Err(LedgerError::ChainBreak(0));
            }
            expected = got;
        } else if got != expected {
            return Err(LedgerError::ChainBreak(i));
        }
        expected = trunc(line);
    }
    Ok((lines.len(), expected))
}

/// Verify a ledger file. Returns its record count.
pub fn verify_chain(path: &Path) -> Result<usize, LedgerError> {
    check(path).map(|(n, _)| n)
}

/// Append-only JSONL writer with the `prev`-hash chain.
pub struct LedgerWriter {
    path: PathBuf,
    file: File,
    prev: String,
    count: usize,
}

impl LedgerWriter {
    /// Open for append. An existing file re-verifies first; a torn or
    /// broken chain refuses the write.
    pub fn create(path: &Path) -> Result<LedgerWriter, LedgerError> {
        let (_, prev) = if path.exists() {
            check(path)?
        } else {
            (0, String::new())
        };
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?;
        Ok(LedgerWriter {
            path: path.to_path_buf(),
            file,
            prev,
            count: 0,
        })
    }

    /// Append one record. Injects the chain field `prev`; injects
    /// `schema_version` when the record does not carry it.
    pub fn append(&mut self, record: &Value) -> Result<usize, LedgerError> {
        let mut line = record.clone();
        let obj = line
            .as_object_mut()
            .ok_or(LedgerError::Format(self.count))?;
        obj.insert("prev".into(), Value::String(self.prev.clone()));
        obj.entry("schema_version")
            .or_insert_with(|| Value::String(SCHEMA_VERSION.into()));
        let body = serde_json::to_string(&line).map_err(|_| LedgerError::Format(self.count))?;
        self.file.write_all(body.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.prev = trunc(&body);
        self.count += 1;
        Ok(self.count)
    }

    fn segment_path(&self, n: usize) -> PathBuf {
        let mut s = self.path.to_path_buf().into_os_string();
        s.push(format!(".{n}"));
        PathBuf::from(s)
    }

    /// Close the current segment to `<name>.<n>` and open a fresh
    /// segment. The fresh segment continues the chain: its first record
    /// carries the hash of the last record of the closed segment.
    pub fn rotate(&mut self) -> Result<(), LedgerError> {
        self.file.flush()?;
        let mut n = 1;
        let mut seg = self.segment_path(n);
        while seg.exists() {
            n += 1;
            seg = self.segment_path(n);
        }
        fs::rename(&self.path, &seg)?;
        self.file = File::create(&self.path)?;
        Ok(())
    }
}

/// Point-in-time reader with an adjacent, append-only access log.
pub struct LedgerReader {
    records: Vec<Value>,
}

impl LedgerReader {
    /// Read the ledger; log actor, time and scope to `<path>.access.log`.
    pub fn open(path: &Path, actor: &str) -> Result<LedgerReader, LedgerError> {
        let data = fs::read(path)?;
        if data.last().is_some_and(|b| *b != b'\n') {
            return Err(LedgerError::TornTail);
        }
        let mut records = Vec::new();
        let text = String::from_utf8_lossy(&data);
        for (i, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(line).map_err(|_| LedgerError::Format(i))?;
            records.push(v);
        }
        let mut log = path.to_path_buf().into_os_string();
        log.push(".access.log");
        let entry = json!({
            "actor": actor,
            "ts": rfc3339_now(),
            "scope": path.display().to_string(),
        });
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(PathBuf::from(log))?;
        f.write_all(
            serde_json::to_string(&entry)
                .unwrap()
                .as_bytes(),
        )?;
        f.write_all(b"\n")?;
        Ok(LedgerReader { records })
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn records(&self) -> &[Value] {
        &self.records
    }
}

/// Current UTC time as an RFC 3339 string, std-only.
fn rfc3339_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Days-since-epoch to civil date. Howard Hinnant's algorithm.
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
