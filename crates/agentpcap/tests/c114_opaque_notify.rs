// C114 — the opaque mode's notification face: a JSON-RPC notification
// (no id member) rides --mode opaque without becoming a parked request
// (it never waits for a reply, never joins the no-response face), and
// the notification carries NO content: the rebuild keeps the identity
// faces only. The attributed-mode pair beside it proves the same wire
// still merges normally.
// Spec: docs/spec.md#8-modes, docs/spec.md#6-classification.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

#[test]
fn c114_the_opaque_notification_never_waits_for_a_reply() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    // the tap in OPAQUE mode
    let mut tap = bin()
        .args(["tap", "--ledger"])
        .arg(&ledger)
        .arg("--mode")
        .arg("opaque")
        .arg("--duration")
        .arg("3")
        .stdout(Stdio::null())
        .spawn()
        .expect("agentpcap binary");
    std::thread::sleep(Duration::from_millis(1200));

    // the framed writer: one id-LESS notification plus one id'd pair on
    // the pipe this process owns
    let mut sink = Command::new("sh")
        .arg("-c")
        .arg("cat >/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("sink spawn");
    let mut f = sink.stdin.take().unwrap();
    writeln!(
        f,
        r#"{{"jsonrpc":"2.0","method":"notifications/message","params":{{"secret":"private-note","step":1}}}}"#
    )
    .unwrap();
    writeln!(
        f,
        r#"{{"jsonrpc":"2.0","method":"notifications/message","params":{{"secret":"private-note","step":2}}}}"#
    )
    .unwrap();
    writeln!(
        f,
        r#"{{"jsonrpc":"2.0","id":600,"method":"tools/call","params":{{"name":"read","path":"/etc/hostname"}}}}"#
    )
    .unwrap();
    writeln!(
        f,
        r#"{{"jsonrpc":"2.0","id":600,"result":{{"content":[]}}}}"#
    )
    .unwrap();
    let _ = f.flush();
    drop(f);
    let st = tap.wait().expect("tap exits at its deadline");
    assert!(st.success(), "c114: the tap exits cleanly");

    let text = std::fs::read_to_string(&ledger).unwrap();
    let recs: Vec<serde_json::Value> = text
        .lines()
        .flat_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|r| serde_json::to_string(r).unwrap_or_default().contains("notifications/message"))
        .collect();
    let notify = recs
        .iter()
        .find(|r| {
            r["method"].as_str() == Some("notifications/message")
                || r["payload"]["method"].as_str() == Some("notifications/message")
        })
        .unwrap_or_else(|| {
            panic!(
                "c114 ledger receipt: events={:?}",
                text.lines()
                    .map(|l| {
                        serde_json::from_str::<serde_json::Value>(l)
                            .ok()
                            .map(|r| r["event"].clone().to_string())
                    })
                    .collect::<Vec<_>>()
            )
        });
    eprintln!("c114 receipt: the notification rides the {}", notify["event"]);
    // the notification NEVER waits: no no-response face, no parked
    // request face — the notify face answers the ledger
    assert_ne!(
        notify["event"], "unidentified",
        "the notification never becomes an unanswered request"
    );
    // TWO different notifications ride: the dedupe face hashes the RAW
    // message (the digest never narrows to one stripped body), so the
    // burst face counts both
    let distinct = recs.iter().filter(|r| r["event"] == "notify").count();
    eprintln!("c114 receipt: notify rows={}", distinct);
    assert_eq!(
        distinct, 2,
        "two different stripped notifications both land"
    );
    // the params content rides NOWHERE: the opaque rebuild keeps the
    // identity faces only
    let full = serde_json::to_string(notify).unwrap_or_default();
    assert!(
        !full.contains("private-note"),
        "opaque strips the notification content"
    );
    assert!(!full.contains("secret"), "opaque strips the secret face");
}
