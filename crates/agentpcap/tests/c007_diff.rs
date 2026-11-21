// C007 — the diff: two report sets in, capability drift events out.
// New tools, changed tool descriptions, removed tools and re-scoped
// servers surface from ledger data. The read logs as actor = agentpcap.diff.
// Spec: docs/spec.md#9-operator-cli.

use std::io::Write;
use std::process::{Command, Stdio};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

fn tools_list(id: u64, fingerprint: &str, tools: &str) -> String {
    format!(
        r#"{{"schema_version":"1.0","ts":"2026-01-01T00:00:0{id}Z","host":"lab","process":"client","pid":1,"transport":"stdio-pipe","mode":"attributed","verdict":"mcp","event":"tools-list","method":"tools/list","cap_fingerprint":"{fingerprint}","protocol_version":"2025-06-18","session_id":"pipe-pair:1:2","peer":"pipe-pair:1:2","dedup":"pipe-pair:1:2:tools-list:{id}","payload":{{"request":{{"method":"tools/list"}},"result":{{"tools":{tools}}}}},"evidence":[],"source":"tap","schema_version":"1.0"}}"#
    )
}

fn ledger(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("{content}\n")).unwrap();
    path
}

#[test]
fn c007_diff_names_the_capability_drift() {
    let dir = tempfile::tempdir().unwrap();
    // the before set: one tool, description A
    let before = ledger(
        dir.path(),
        "before.jsonl",
        &tools_list(
            1,
            "aaaa1111aaaa1111",
            r#"[{"name":"read","description":"read a file"},{"name":"gone","description":"was here"}]"#,
        ),
    );
    // the after set: the same tool's description changed, one added, one removed
    let after = ledger(
        dir.path(),
        "after.jsonl",
        &tools_list(
            2,
            "bbbb2222bbbb2222",
            r#"[{"name":"read","description":"read a file v2"},{"name":"write","description":"write a file"}]"#,
        ),
    );
    let out = bin()
        .args(["diff", "--before"])
        .arg(&before)
        .arg("--after")
        .arg(&after)
        .output()
        .expect("agentpcap binary");
    assert!(out.status.success(), "diff must succeed");
    let text = String::from_utf8_lossy(&out.stdout);
    let events: Vec<serde_json::Value> = text
        .lines()
        .map(|l| serde_json::from_str(l).expect("diff lines are JSON objects"))
        .collect();
    eprintln!("c007 drift receipt: {events:?}");
    let kinds: Vec<&str> = events
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"tools-added"), "{kinds:?}");
    assert!(kinds.contains(&"tools-removed"), "{kinds:?}");
    assert!(kinds.contains(&"tool-description-changed"), "{kinds:?}");
    assert!(kinds.contains(&"server-rescoped"), "{kinds:?}");
    let changed = events
        .iter()
        .find(|e| e["kind"] == "tool-description-changed")
        .expect("the changed tool rides an event");
    assert_eq!(changed["tool"], "read");
    assert_eq!(changed["before"], "read a file");
    assert_eq!(changed["after"], "read a file v2");
    let added = events
        .iter()
        .find(|e| e["kind"] == "tools-added")
        .expect("the added tool rides an event");
    assert_eq!(added["tools"][0], "write");
    let removed = events
        .iter()
        .find(|e| e["kind"] == "tools-removed")
        .expect("the removed tool rides an event");
    assert_eq!(removed["tools"][0], "gone");
    let rescoped = events
        .iter()
        .find(|e| e["kind"] == "server-rescoped")
        .expect("the fingerprint change rides an event");
    assert_eq!(rescoped["before"], "aaaa1111aaaa1111");
    assert_eq!(rescoped["after"], "bbbb2222bbbb2222");

    // the reads log as agentpcap.diff
    let before_log =
        std::fs::read_to_string(dir.path().join("before.jsonl.access.log")).unwrap();
    let entry: serde_json::Value = serde_json::from_str(
        before_log.lines().last().expect("the diff reads log"),
    )
    .expect("the access log entries are JSON objects");
    assert_eq!(
        entry["actor"].as_str(),
        Some("agentpcap.diff"),
        "the diff reads log: {before_log}"
    );
}
