//! The conformance runner. Golden fixtures answer their `.expect`
//! verdicts: chain-ok, chain-broken, torn-tail, schema-mismatch.

use crate::{chain_of, SCHEMA_VERSION};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq)]
pub struct FixtureResult {
    pub name: String,
    pub expected: String,
    pub actual: String,
}

/// The verdict for one ledger file, by content. Same hash rule as the
/// writer: `prev` is the first 16 hex digits of the SHA-256 of the
/// previous record body.
pub fn verdict(data: &str) -> &'static str {
    if !data.ends_with('\n') {
        return "torn-tail";
    }
    let text = data.trim_end_matches('\n');
    if text.is_empty() {
        return "chain-ok";
    }
    let lines: Vec<&str> = text.split('\n').collect();
    for line in &lines {
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return "chain-broken",
        };
        if v["schema_version"].as_str() != Some(SCHEMA_VERSION) {
            return "schema-mismatch";
        }
    }
    match chain_of(&lines) {
        Ok(()) => "chain-ok",
        Err(_) => "chain-broken",
    }
}

/// Run every `*.jsonl` fixture in `dir` against its `.expect` verdict.
pub fn run(dir: &Path) -> Result<Vec<FixtureResult>, std::io::Error> {
    let mut names: Vec<String> = match std::fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .filter_map(|e| e.file_name().into_string().ok())
            .filter(|n| n.ends_with(".jsonl"))
            .collect(),
        Err(e) => {
            eprintln!("conformance: read_dir({}) failed: {e}", dir.display());
            return Err(e);
        }
    };
    names.sort();
    let mut out = Vec::new();
    for f in names {
        let stem = f.trim_end_matches(".jsonl").to_string();
        let expected_path = dir.join(format!("{stem}.expect"));
        let expected = match std::fs::read_to_string(&expected_path) {
            Ok(e) => e.trim().to_string(),
            Err(e) => {
                eprintln!("conformance: read({}) failed: {e}", expected_path.display());
                return Err(e);
            }
        };
        let data_path = dir.join(&f);
        let data = std::fs::read_to_string(&data_path).map_err(|e| {
            eprintln!("conformance: read({}) failed: {e}", data_path.display());
            e
        })?;
        let actual = verdict(&data).to_string();
        out.push(FixtureResult {
            name: stem,
            expected,
            actual,
        });
    }
    Ok(out)
}
