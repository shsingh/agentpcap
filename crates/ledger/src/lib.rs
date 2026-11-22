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

pub mod conformance;

pub const SCHEMA_VERSION: &str = "1.0";

/// The known record faces (ADR-0007): the frame face 1.0 and the
/// session-event face 2.0 chain into one ledger; anything else
/// refuses.
pub const SCHEMA_VERSIONS: [&str; 3] = ["1.0", "2.0", "2.1"];

/// The dedupe window bound: the writer keeps at most this many dedupe
/// keys in memory (the newest). `AGENTPCAP_DEDUP_BUDGET` overrides it.
/// The bound is the memory face of the coexistence dedupe: a service
/// that runs for weeks never grows without limit. Keys outside the
/// window no longer refuse: the retained window is the stated
/// trade-off (ADR-0007, schema 2.1).
pub const DEFAULT_DEDUP_BUDGET: usize = 65_536;

pub fn dedup_budget() -> usize {
    std::env::var("AGENTPCAP_DEDUP_BUDGET")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&b| b > 0)
        .unwrap_or(DEFAULT_DEDUP_BUDGET)
}

/// Failure classes for the ordered-check semantics of the ledger.
#[derive(Debug)]
pub enum LedgerError {
    /// The file does not end with a newline: a crash mid-append.
    TornTail,
    /// Record at index does not chain from its predecessor.
    ChainBreak(usize),
    /// Record at index is not a valid JSON object.
    Format(usize),
    /// The record carries a foreign `schema_version`.
    SchemaMismatch(usize),
    /// The record's `dedup` key already rides the ledger: the event
    /// exists, the append refuses (spec section 11: no doubled events
    /// for covered flows).
    Duplicate(usize),
    Io(std::io::Error),
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::TornTail => write!(f, "torn tail: file does not end with a newline"),
            LedgerError::ChainBreak(i) => write!(f, "chain break at record {i}"),
            LedgerError::Format(i) => write!(f, "record {i} is not a valid JSON object"),
            LedgerError::SchemaMismatch(i) => write!(f, "record {i} carries a foreign schema_version"),
            LedgerError::Duplicate(i) => write!(f, "record {i} carries a dedup key that already rides the ledger"),
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

pub(crate) fn trunc(body: &str) -> String {
    let d = Sha256::digest(body.as_bytes());
    hex::encode(d)[..16].to_string()
}

/// Verify one in-memory record sequence against the chain rule.
/// Shared by `check` and the conformance runner.
pub(crate) fn chain_of(lines: &[&str]) -> Result<(), LedgerError> {
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
        } else if got != expected {
            return Err(LedgerError::ChainBreak(i));
        }
        expected = trunc(line);
    }
    Ok(())
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
    chain_of(&lines)?;
    let last = lines[lines.len() - 1];
    Ok((lines.len(), trunc(last)))
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
    /// The dedupe keys the ledger already carries: the existing
    /// segments at open time, then every appended record (spec
    /// section 11: no doubled events for covered flows).
    seen_dedup: DedupWindow,
}

/// The bounded dedupe window: insertion-ordered keys with a hard cap.
/// The order rides a `VecDeque`: the eviction pops the front in O(1),
/// never a full shift of 65k entries per append.
struct DedupWindow {
    keys: std::collections::VecDeque<String>,
    set: std::collections::HashSet<String>,
    budget: usize,
}

impl DedupWindow {
    fn new(budget: usize) -> Self {
        DedupWindow {
            keys: std::collections::VecDeque::new(),
            set: std::collections::HashSet::new(),
            budget: budget.max(1),
        }
    }

    fn contains(&self, k: &str) -> bool {
        self.set.contains(k)
    }

    fn insert(&mut self, k: String) {
        if self.set.insert(k.clone()) {
            self.keys.push_back(k);
            while self.keys.len() > self.budget {
                if let Some(evicted) = self.keys.pop_front() {
                    self.set.remove(&evicted);
                }
            }
        }
    }

    fn retain_last(&mut self, keys: Vec<String>) {
        let start = keys.len().saturating_sub(self.budget);
        for k in keys[start..].iter().cloned() {
            self.insert(k);
        }
    }
}

fn dedup_keys(path: &Path) -> Vec<String> {
    /// Collect the dedupe keys one segment carries.
    fn keys_of(text: &str, out: &mut Vec<String>) {
        for line in text.lines() {
            if let Ok(v) = serde_json::from_str::<Value>(line) {
                if let Some(k) = v["dedup"].as_str() {
                    out.push(k.to_string());
                }
            }
        }
    }
    let mut keys = Vec::new();
    // the rotated segments ride the same dedupe promise: a reopening
    // writer refuses a replay of any event an earlier segment holds
    // (`<name>.1`, `<name>.2`, ...). The closed segments load in
    // NUMERIC order first, the active file LAST: the newest keys land
    // at the window's tail, so the trim keeps what the live capture
    // wrote most recently.
    if let (Some(parent), Some(name)) = (path.parent(), path.file_name()) {
        let prefix = format!("{}.", name.to_string_lossy());
        let mut numbers: Vec<u32> = Vec::new();
        if let Ok(rd) = fs::read_dir(parent) {
            for entry in rd.flatten() {
                let rest = entry
                    .file_name()
                    .to_string_lossy()
                    .strip_prefix(&prefix)
                    .map(str::to_string)
                    .unwrap_or_default();
                if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
                    numbers.push(rest.parse::<u32>().unwrap_or(0));
                }
            }
        }
        numbers.sort();
        for n in numbers {
            let seg = path.with_file_name(format!("{}{}", prefix, n));
            if let Ok(data) = fs::read(&seg) {
                keys_of(&String::from_utf8_lossy(&data), &mut keys);
            }
        }
    }
    if let Ok(data) = fs::read(path) {
        keys_of(&String::from_utf8_lossy(&data), &mut keys);
    }
    keys
}

impl LedgerWriter {
    /// Open for append. An existing file re-verifies first; a torn or
    /// broken chain refuses the write. The dedupe set loads from the
    /// existing segments.
    pub fn create(path: &Path) -> Result<LedgerWriter, LedgerError> {
        let budget = dedup_budget();
        Self::create_with_budget(path, budget)
    }

    /// The budget face: the same open with an explicit dedupe window.
    pub fn create_with_budget(path: &Path, budget: usize) -> Result<LedgerWriter, LedgerError> {
        let (count, prev) = if path.exists() {
            check(path)?
        } else {
            (0, String::new())
        };
        let seen_dedup_keys = dedup_keys(path);
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?;
        // the privacy face: the ledger carries captured arguments and
        // results - the file rides owner-only, create or append alike
        // (spec section 4: the ledger is the operator's read surface,
        // never a shared one)
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let mut seen_dedup = DedupWindow::new(budget);
        seen_dedup.retain_last(seen_dedup_keys);
        Ok(LedgerWriter {
            path: path.to_path_buf(),
            file,
            prev,
            count,
            seen_dedup,
        })
    }

    /// Append one record. Injects the chain field `prev`; injects
    /// `schema_version` when the record does not carry it. A record
    /// whose `dedup` key already rides the ledger refuses: the
    /// coexistence dedupe (spec section 11), and the ledger's own
    /// count does not move.
    pub fn append(&mut self, record: &Value) -> Result<usize, LedgerError> {
        let mut line = record.clone();
        let obj = line
            .as_object_mut()
            .ok_or(LedgerError::Format(self.count))?;
        if let Some(v) = obj.get("schema_version") {
            let known = v
                .as_str()
                .map(|s| SCHEMA_VERSIONS.contains(&s))
                .unwrap_or(false);
            if !known {
                return Err(LedgerError::SchemaMismatch(self.count));
            }
        }
        if let Some(k) = obj.get("dedup").and_then(|v| v.as_str()).map(str::to_string) {
            if self.seen_dedup.contains(&k) {
                return Err(LedgerError::Duplicate(self.count));
            }
        }
        // the key ride for the seen-set insert at the append's tail
        let dedup_key = obj.get("dedup").and_then(|v| v.as_str()).map(str::to_string);
        obj.insert("prev".into(), Value::String(self.prev.clone()));
        obj.entry("schema_version")
            .or_insert_with(|| Value::String(SCHEMA_VERSION.into()));
        let body = serde_json::to_string(&line).map_err(|_| LedgerError::Format(self.count))?;
        self.file.write_all(body.as_bytes())?;
        self.file.write_all(b"\n")?;
        self.file.flush()?;
        self.prev = trunc(&body);
        self.count += 1;
        if let Some(k) = dedup_key {
            self.seen_dedup.insert(k);
        }
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
            "ts": now_rfc3339(),
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
pub fn now_rfc3339() -> String {
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
