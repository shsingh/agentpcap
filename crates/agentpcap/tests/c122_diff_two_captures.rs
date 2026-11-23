use std::process::Command;

// C122 — the diff pairs a server seen ONCE in EACH set by the server
// face. Two fresh captures of the same server name (separate taps, new
// pipe faces per capture) are the operator's between-captures shape:
// the pairing may not fall back to the session-id keys just because
// the name appears in both sets — the fallback keys never pair across
// captures, and the diff would report everything added/removed while
// losing the changed descriptions and the capability fingerprints.
// Peer review finding 4662904887. Spec: docs/spec.md#9-operator-cli.

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

fn init(id: u64, host: &str, session: &str, server: &str) -> String {
    let sid = format!("pipe-pair:{session}");
    let dedup = format!("{host}:{sid}:init:{id}");
    format!(
        r#"{{"schema_version":"1.0","ts":"2026-01-01T00:00:0{id}Z","host":"{host}","process":"client","pid":1,"transport":"stdio-pipe","mode":"attributed","verdict":"mcp","event":"initialize","method":"initialize","protocol_version":"2025-06-18","session_id":"{sid}","peer":"{sid}","dedup":"{dedup}","payload":{{"request":{{"method":"initialize"}},"result":{{"serverInfo":{{"name":"{server}"}}}}}},"evidence":[],"source":"tap","schema_version":"1.0"}}"#
    )
}

fn tools_list(id: u64, host: &str, session: &str, fingerprint: &str, tools: &str) -> String {
    let sid = format!("pipe-pair:{session}");
    let dedup = format!("{host}:{sid}:tools-list:{id}");
    format!(
        r#"{{"schema_version":"1.0","ts":"2026-01-01T00:00:0{id}Z","host":"{host}","process":"client","pid":1,"transport":"stdio-pipe","mode":"attributed","verdict":"mcp","event":"tools-list","method":"tools/list","cap_fingerprint":"{fingerprint}","protocol_version":"2025-06-18","session_id":"{sid}","peer":"{sid}","dedup":"{dedup}","payload":{{"request":{{"method":"tools/list"}},"result":{{"tools":{tools}}}}},"evidence":[],"source":"tap","schema_version":"1.0"}}"#
    )
}

fn ledger(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("{content}\n")).unwrap();
    path
}

const FP_BEFORE: &str = "aaa1aaa1aaa1aaa1";
const FP_AFTER: &str = "bbb2bbb2bbb2bbb2";

#[test]
fn c122_diff_pairs_one_server_seen_once_per_set() {
    let dir = tempfile::tempdir().unwrap();
    // capture one: capture-time session "1:2", tools v1
    let before = ledger(
        dir.path(),
        "before.jsonl",
        &format!(
            "{}\n{}\n",
            init(1, "lab", "1:2", "fedsrv"),
            tools_list(
                2,
                "lab",
                "1:2",
                FP_BEFORE,
                r#"[{"name":"read","description":"read a file"},{"name":"gone","description":"was here"}]"#,
            )
        ),
    );
    // capture two: a FRESH tap, new capture-time session "5:6", tools v2 —
    // the same server between the captures
    let after = ledger(
        dir.path(),
        "after.jsonl",
        &format!(
            "{}\n{}\n",
            init(3, "lab", "5:6", "fedsrv"),
            tools_list(
                4,
                "lab",
                "5:6",
                FP_AFTER,
                r#"[{"name":"read","description":"read a file v2"},{"name":"write","description":"write a file"}]"#,
            )
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
    eprintln!("c122 drift receipt: {events:?}");
    // the between-captures pair rides the matched branch: the changed
    // description and the capability fingerprints ride
    let changed = events
        .iter()
        .find(|e| e["kind"] == "tool-description-changed")
        .unwrap_or_else(|| {
            panic!(
                "the between-captures pair keeps the changed description: {events:?}"
            )
        });
    assert_eq!(changed["tool"], "read");
    assert_eq!(changed["before"], "read a file");
    assert_eq!(changed["after"], "read a file v2");
    let rescoped = events
        .iter()
        .find(|e| e["kind"] == "server-rescoped")
        .unwrap_or_else(|| {
            panic!(
                "the between-captures pair keeps the capability fingerprints: {events:?}"
            )
        });
    assert_eq!(rescoped["before"], FP_BEFORE);
    assert_eq!(rescoped["after"], FP_AFTER);
    let kinds: Vec<&str> = events
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"tools-added"), "{kinds:?}");
    assert!(kinds.contains(&"tools-removed"), "{kinds:?}");
}
