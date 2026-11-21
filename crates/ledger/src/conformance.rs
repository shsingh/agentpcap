//! The conformance runner. Golden fixtures answer their `.expect`
//! verdicts: chain-ok, chain-broken, torn-tail, schema-mismatch.
//! A rotated pair is one case: `<base>.jsonl` plus continuation
//! segments `<base>.<n>.jsonl`, each carrying the previous segment's
//! tail hash on its first line.

use crate::trunc;
use crate::SCHEMA_VERSION;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, PartialEq)]
pub struct FixtureResult {
    pub name: String,
    pub expected: String,
    pub actual: String,
}

/// The verdict for one case: the base segment plus its continuations,
/// in numeric segment order. The cross-file carry is verified exactly.
pub fn verdict_case(paths: &[String]) -> &'static str {
    let mut read: Vec<String> = Vec::new();
    for f in paths {
        let data = match std::fs::read_to_string(PathBuf::from(f)) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("conformance: read({f}) failed: {e}");
                return "unreadable";
            }
        };
        if !data.ends_with('\n') {
            return "torn-tail";
        }
        read.push(data);
    }

    let mut parsed: Vec<Vec<Value>> = Vec::new();
    for data in &read {
        let mut seg = Vec::new();
        for line in data.trim_end_matches('\n').split('\n') {
            match serde_json::from_str::<Value>(line) {
                Ok(v) => seg.push(v),
                Err(_) => return "chain-broken",
            }
        }
        parsed.push(seg);
    }

    // schema contract first: any foreign version answers schema-mismatch
    for seg in &parsed {
        for rec in seg {
            if rec["schema_version"].as_str() != Some(SCHEMA_VERSION) {
                return "schema-mismatch";
            }
        }
    }

    // in-file chaining and the cross-file carry
    let mut prev_tail: Option<String> = None;
    for (si, seg) in parsed.iter().enumerate() {
        let raw = read[si].trim_end_matches('\n');
        let raw_lines: Vec<&str> = raw.split('\n').collect();
        let mut expected = String::new();
        for (li, line) in raw_lines.iter().enumerate() {
            let got = seg[li]["prev"].as_str().unwrap_or_default().to_string();
            if li == 0 {
                match (&prev_tail, got.as_str()) {
                    // first segment: genesis empty or an opaque carry
                    (None, "") => {}
                    (None, g) if g.len() == 16 && g.chars().all(|c| c.is_ascii_hexdigit()) => {}
                    // continuation: the carry must be the previous tail hash, exactly
                    (Some(tail), g) => {
                        if g != trunc(tail) {
                            return "chain-broken";
                        }
                    }
                    _ => return "chain-broken",
                }
                expected = got;
            } else if got != expected {
                return "chain-broken";
            }
            expected = trunc(line);
        }
        prev_tail = Some(raw_lines[raw_lines.len() - 1].to_string());
    }
    "chain-ok"
}

/// Run every fixture case in `dir` against its `.expect` verdict.
pub fn run(dir: &std::path::Path) -> Result<Vec<FixtureResult>, std::io::Error> {
    let mut names: Vec<String> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".jsonl"))
        .collect();
    names.sort();

    // group: base case name -> [(segment order, file name)]
    let mut cases: BTreeMap<String, Vec<(u32, String)>> = BTreeMap::new();
    for f in names {
        let stem = f.trim_end_matches(".jsonl").to_string();
        let (base, seg) = match stem.rfind('.') {
            Some(i) if stem[i + 1..].chars().all(|c| c.is_ascii_digit()) => {
                (stem[..i].to_string(), stem[i + 1..].parse::<u32>().unwrap())
            }
            _ => (stem.clone(), 0),
        };
        if !dir.join(format!("{base}.expect")).exists() {
            eprintln!("conformance: no .expect for case {base}; skipped {f}");
            continue;
        }
        cases.entry(base).or_default().push((seg, f));
    }

    let mut out = Vec::new();
    for (base, mut segs) in cases {
        segs.sort_by_key(|(n, _)| *n);
        let paths: Vec<String> = segs
            .into_iter()
            .map(|(_, f)| dir.join(&f).display().to_string())
            .collect();
        let actual = verdict_case(&paths).to_string();
        let expected = std::fs::read_to_string(dir.join(format!("{base}.expect")))?
            .trim()
            .to_string();
        out.push(FixtureResult {
            name: base,
            expected,
            actual,
        });
    }
    Ok(out)
}
