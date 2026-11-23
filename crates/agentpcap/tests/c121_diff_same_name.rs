use std::process::Command;

// C121 — the diff keeps distinct peers when sessions advertise the SAME
// server name. The per-server key folds same-named instances into one
// map slot (only the last session in order survives), so an unchanged
// session would hide another session's changed tools. When one set
// holds a same-named instance pair, the faces ride their session-id
// keys — every distinct peer keeps its own slot. Peer review 4662429079.
// Spec: docs/spec.md#9-operator-cli.

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

fn init(id: u64, host: &str, session: &str, server: &str) -> String {
    let sid = format!("pipe-pair:{session}");
    let dedup_host = format!("{host}:{sid}:init:{id}");
    format!(
        r#"{{"schema_version":"1.0","ts":"2026-01-01T00:00:0{id}Z","host":"{host}","process":"client","pid":1,"transport":"stdio-pipe","mode":"attributed","verdict":"mcp","event":"initialize","method":"initialize","protocol_version":"2025-06-18","session_id":"{sid}","peer":"{sid}","dedup":"{dedup_host}","payload":{{"request":{{"method":"initialize"}},"result":{{"serverInfo":{{"name":"{server}"}}}}}},"evidence":[],"source":"tap","schema_version":"1.0"}}"#
    )
}

fn tools_list(id: u64, host: &str, session: &str, fingerprint: &str, tools: &str) -> String {
    let sid = format!("pipe-pair:{session}");
    let dedup = format!("{host}:pipe-pair:{session}:tools-list:{id}");
    format!(
        r#"{{"schema_version":"1.0","ts":"2026-01-01T00:00:0{id}Z","host":"{host}","process":"client","pid":1,"transport":"stdio-pipe","mode":"attributed","verdict":"mcp","event":"tools-list","method":"tools/list","cap_fingerprint":"{fingerprint}","protocol_version":"2025-06-18","session_id":"{sid}","peer":"{sid}","dedup":"{dedup}","payload":{{"request":{{"method":"tools/list"}},"result":{{"tools":{tools}}}}},"evidence":[],"source":"tap","schema_version":"1.0"}}"#
    )
}

fn ledger(dir: &std::path::Path, name: &str, content: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("{content}\n")).unwrap();
    path
}

const FP: &str = "cccc3333cccc3333";

// session one: the tool description changes between the sets
fn changed_session(side: &str) -> String {
    let tools = if side == "after" {
        r#"[{"name":"read","description":"read a file v2"}]"#
    } else {
        r#"[{"name":"read","description":"read a file"}]"#
    };
    format!(
        "{}\n{}\n",
        init(3, "lab", "1:2", "samename"),
        tools_list(4, "lab", "1:2", FP, tools)
    )
}

// session two: an UNCHANGED instance of the SAME server name — under a
// fold-into-one-key face this session's order position must not hide
// session one's changed tools
fn unchanged_session() -> String {
    format!(
        "{}\n{}\n",
        init(5, "lab", "3:4", "samename"),
        tools_list(6, "lab", "3:4", FP, r#"[{"name":"read","description":"read a file"}]"#)
    )
}

#[test]
fn c121_diff_keeps_same_named_peers_distinct() {
    let dir = tempfile::tempdir().unwrap();
    // the before set: two sessions advertise the same server name
    let before = ledger(
        dir.path(),
        "before.jsonl",
        &format!("{}\n{}", changed_session("before"), unchanged_session()),
    );
    // the after set: the UNCHANGED session rides last in order — the
    // fold face would let it win the shared slot
    let after = ledger(
        dir.path(),
        "after.jsonl",
        &format!("{}\n{}", changed_session("after"), unchanged_session()),
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
    eprintln!("c121 drift receipt: {events:?}");
    // the changed session's drift survives the same-named sibling
    let changed = events
        .iter()
        .find(|e| e["kind"] == "tool-description-changed")
        .unwrap_or_else(|| {
            panic!(
                "the changed tool rides an event despite the same-named sibling: {events:?}"
            )
        });
    assert_eq!(changed["tool"], "read");
    assert_eq!(changed["before"], "read a file");
    assert_eq!(changed["after"], "read a file v2");
    // the changed event attributes its own session — not the sibling's
    assert_eq!(changed["session_id"], "pipe-pair:1:2");
    // the unchanged sibling emits no spurious faces
    let spurious: Vec<&str> = events
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .filter(|k| *k == "tools-added" || *k == "tools-removed")
        .collect();
    assert!(
        spurious.is_empty(),
        "the unchanged sibling emits no drift: {spurious:?}"
    );
}

// The cross-host face: two hosts advertise the SAME server name with
// disjoint pid spaces (the federated capture shape — two collector
// nodes hold the same pid space, spec section 7). Every key face
// carries the host, so a host's diff never folds into a peer host's
// slot: host lab1's changed tools emit and attribute to lab1, and an
// unchanged lab2 emits no drift that could hide it.
#[test]
fn c121_diff_keeps_cross_host_serves_distinct() {
    let dir = tempfile::tempdir().unwrap();
    let lab1 = |side: &str| -> String {
        let tools = if side == "after" {
            r#"[{"name":"read","description":"read a file v2"}]"#
        } else {
            r#"[{"name":"read","description":"read a file"}]"#
        };
        format!(
            "{}\n{}\n",
            init(7, "lab1", "1:2", "fedsrv"),
            tools_list(8, "lab1", "1:2", FP, tools)
        )
    };
    let lab2 = format!(
        "{}\n{}\n",
        init(9, "lab2", "1:2", "fedsrv"),
        tools_list(10, "lab2", "1:2", FP, r#"[{"name":"read","description":"read a file"}]"#)
    );
    let before = ledger(
        dir.path(),
        "before.jsonl",
        &format!("{}\n{}", lab1("before"), lab2),
    );
    let after = ledger(
        dir.path(),
        "after.jsonl",
        &format!("{}\n{}", lab1("after"), lab2),
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
    eprintln!("c121 cross-host drift receipt: {events:?}");
    // lab1's changed tool emits — a fold of one host into another would
    // let the unchanged lab2 view win the shared slot and hide it
    let changed = events
        .iter()
        .find(|e| e["kind"] == "tool-description-changed")
        .unwrap_or_else(|| {
            panic!("lab1's changed tool rides an event across the same-named serve on lab2: {events:?}")
        });
    assert_eq!(changed["host"], "lab1");
    assert_eq!(changed["session_id"], "pipe-pair:1:2");
    assert_eq!(changed["before"], "read a file");
    assert_eq!(changed["after"], "read a file v2");
    // the unchanged lab2 emits no spurious faces
    let spurious: Vec<&str> = events
        .iter()
        .filter_map(|e| e["kind"].as_str())
        .filter(|k| *k == "tools-added" || *k == "tools-removed")
        .collect();
    assert!(
        spurious.is_empty(),
        "the unchanged host emits no drift: {spurious:?}"
    );
}
