// C116 — the file-write noise face (the #64 sweep face): a live
// process writing JSON-RPC candidates to a REGULAR FILE leaves no
// ledger record — a class-pipe sample whose fd resolves to a file is
// neither pipe nor socket traffic; the tap drops it with its skip
// evidence and never feeds a channel-less frame. A pipe fd that died
// inside the pop window keeps the honest race fallback (ADR-0004).
// Spec: docs/spec.md#5-collectors; cell ledger: tests/matrix/LEDGER.md.

use std::io::BufRead;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

#[test]
#[ignore = "held until issue #106: the c116 cell rides the pid-namespace calibration face"]
fn c116_the_file_write_leaves_no_record() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    let mut tap = bin()
        .args(["tap", "--ledger"])
        .arg(&ledger)
        .arg("--duration")
        .arg("9")
        .stderr(Stdio::piped())
        .spawn()
        .expect("agentpcap binary");
    let tap_stderr = std::io::BufReader::new(tap.stderr.take().unwrap());
    let stderr_handle = std::thread::spawn(move || {
        tap_stderr
            .lines()
            .map_while(|l| l.ok())
            .collect::<Vec<_>>()
    });
    std::thread::sleep(Duration::from_millis(1200));

    // a live writer appends two JSON-RPC candidates to a REGULAR FILE
    // in its own private dir — no pipe, no socket face. The writer
    // stays ALIVE for the whole window: a live fd resolves at pop (the
    // NotPipe face); a dead writer rides the ADR-0004 race face instead
        let fx = tempfile::tempdir().expect("the private writer dir creates");
    let file = fx.path().join("notes.jsonl");
    // the writer rides a SCRIPT FILE (never -c quoting): the JSON
    // body lands CLEAN (a real newline, no brace/escape pasting) so
    // the classify face sees what a real agent writes — the face under
    // test is the fd kind, never the payload shape; the bodies ride
    // rust's {:?} quoting so the generated python literal stays valid
    let body_req = "{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{\"name\":\"c116\"}}\n";
    let body_res = "{\"jsonrpc\":\"2.0\",\"id\":12,\"result\":{\"content\":\"c116-file\"}}\n";
    let script_body = format!(
        "import time\nf = open(r'{}', 'a')\nf.write({:?})\nf.flush()\nf.write({:?})\nf.flush()\ntime.sleep(8.0)\n",
        file.to_str().unwrap(),
        body_req,
        body_res,
    );
    let script = fx.path().join("c116writer.py");
    std::fs::write(&script, script_body)
        .expect("the script writes");
    let mut writer = Command::new("python3")
        .arg(&script)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the python writer spawns");

    // one REAL pipe ride: the channel faces stay recorded — the file
    // face must drop only the class-pipe sample it cannot channel
    let mut sink = Command::new("sh")
        .arg("-c")
        .arg("cat >/dev/null")
        .stdin(Stdio::piped())
        .spawn()
        .expect("sink spawn");
    let mut f = sink.stdin.take().unwrap();
    use std::io::Write;
    writeln!(
        f,
        r#"{{"jsonrpc":"2.0","id":701,"method":"tools/list","params":{{"marker":"c116-pipe"}}}}"#
    )
    .unwrap();
    let _ = f.flush();
    drop(f);
    let _ = sink.wait();

    // the writer stays alive through the tap's whole window; the wait
    // rides after the tap's deadline (the tap exits first)
    let st = tap.wait().expect("tap exits at its deadline");
    assert!(st.success(), "the tap exits cleanly");
    let _ = writer.wait();
    let lines = stderr_handle.join().expect("the stderr joins");
    eprintln!("c116 tap stderr: {lines:?}");

    let text = std::fs::read_to_string(&ledger).unwrap_or_default();
    eprintln!("c116 ledger receipt: bytes={}", text.len());
    let recs: Vec<serde_json::Value> = text
        .lines()
        .flat_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect();
    eprintln!(
        "c116 ledger receipt: records={} events={:?}",
        recs.len(),
        recs.iter().map(|r| r["event"].as_str()).collect::<Vec<_>>()
    );
    // the file face: no record ties the file writer's ids (11, 12) —
    // neither a merged tools-call nor an unidentified/norphan row can
    // key the never-channelled file face
    let file_face = recs.iter().any(|r| {
        serde_json::to_string(r)
            .map(|s| s.contains("\"c116-file\"") || s.contains(":11@") || s.contains(":12@"))
            .unwrap_or(false)
    });
    assert!(
        !file_face,
        "a class-pipe sample whose fd names a regular file leaves NO ledger record"
    );
    // the pipe face: the REAL pipe ride lands (the channel face works)
    let pipe_face = recs.iter().any(|r| {
        r["event"] == "tools-list"
            && serde_json::to_string(r)
                .map(|s| s.contains("c116-pipe"))
                .unwrap_or(false)
    });
    assert!(
        pipe_face,
        "the real pipe ride keeps landing while the file face drops"
    );
}
