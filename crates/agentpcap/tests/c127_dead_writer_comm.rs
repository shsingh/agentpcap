// C127 — the wire comm face (issue #95; ADR-0009): a writer that
// exits before the pop keys its own comm, never `unknown`. The
// sample's comm fills at the syscall — the /proc read at the pop
// never races the writer's own task face. The harness reaps the
// writer immediately after its write, so the /proc face is
// deterministically gone at the pop and the wire face answers. The
// harness frame rides argv (no shell quoting face); the marker rides
// its own argv (the run-unique face).
// Spec: docs/spec.md#6-classification (the metadata faces never lead
// a verdict; the comm face rides evidence).

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_agentpcap")
}


fn fmt_frame(marker: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{{\"name\":\"read\",\"arguments\":{{\"path\":\"{}\"}}}}}}",
        marker
    )
}

#[test]
fn c127_the_dead_writer_rides_its_own_comm() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("c127.jsonl");
    let ledger_s = ledger.to_str().expect("the ledger path stays utf8");

    let mut tap = std::process::Command::new(bin())
        .args(["tap", "--ledger", ledger_s, "--duration", "6"])
        .stdout(std::process::Stdio::null())
        .stderr(std::fs::File::create(dir.path().join("tap.err")).expect("the tap err file opens"))
        .spawn()
        .expect("the tap spawns");

    // the actor harness = the python face: the c126 shape's sink (a
    // /dev/null `cat`), a short-lived writer whose stdout = the sink's
    // stdin pipe, and the reap before the pop. The frame rides argv:
    // `python3 -c <code> <frame>` names it argv[1]; the marker rides
    // its own argv slot.
    let marker = format!("c127-{}", std::process::id());
    let harness = [
        "import subprocess, sys",
        "sink = subprocess.Popen(['sh', '-c', 'cat >/dev/null'], stdin=subprocess.PIPE,",
        "    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
        "frame = sys.argv[2]",
        "writer = subprocess.Popen(['python3', '-c',",
        "    'import sys, time; sys.stdout.write(sys.argv[1]); sys.stdout.flush(); time.sleep(0.4)',",
        "    frame], stdout=sink.stdin, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
        "writer.wait()",
        "sys.stdout.write('WRITER-PID ' + str(writer.pid) + chr(10))",
        "sink.stdin.close()",
        "sink.wait()",
    ].join("\n");
    std::fs::write(dir.path().join("harness.py"), harness).expect("the harness writes");

    // the calibration rides outside the capture face (the same face
    // the m002 harness rides): the harness lands after the probe attaches
    std::thread::sleep(std::time::Duration::from_millis(1500));
    let actor = std::process::Command::new("python3")
        .arg(dir.path().join("harness.py"))
        .arg(&marker)
        .arg(fmt_frame(&marker))
        .output()
        .expect("the harness runs");
    eprintln!(
        "c127 actor receipt: harness status={} stdout={:?}",
        actor.status, actor.stdout
    );
    let writer_pid: u64 = String::from_utf8_lossy(&actor.stdout)
        .lines()
        .find(|l| l.starts_with("WRITER-PID "))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .expect("the harness reports the writer's pid");

    let status = tap.wait().expect("the tap runs to completion");
    eprintln!(
        "c127 tap receipt: rc={} stderr={:?}",
        status.code().unwrap_or(-1),
        std::fs::read_to_string(dir.path().join("tap.err"))
            .map(|s| s.chars().take(220).collect::<String>())
    );

    let text = std::fs::read_to_string(ledger_s).expect("the ledger rides");
    let rows: Vec<serde_json::Value> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("the ledger rows parse"))
        .collect();
    let marked: Vec<&serde_json::Value> = rows
        .iter()
        .filter(|r| {
            serde_json::to_string(r)
                .map(|s| s.contains(&marker))
                .unwrap_or(false)
        })
        .collect();
    eprintln!(
        "c127 ledger receipt: records={} marked={} faces={:?}",
        rows.len(),
        marked.len(),
        marked.iter().map(|r| r["process"].clone()).collect::<Vec<_>>()
    );
    for r in &rows {
        eprintln!(
            "c127 row receipt: process={} event={} method={:?} payload={}",
            r.get("process").and_then(|p| p.as_str()).unwrap_or("?"),
            r.get("event").and_then(|e| e.as_str()).unwrap_or("?"),
            r.get("method").and_then(|m| m.as_str()),
            serde_json::to_string(&r["payload"]).unwrap_or_default()
        );
    }
    assert!(
        !marked.is_empty(),
        "the marked frame rides the capture"
    );
    for r in &marked {
        // the writer reapped before the pop: the /proc face is gone, so
        // the wire face alone answers — the pid and the exact comm name
        // tie to the reapped writer, never a sibling's comm
        assert_eq!(
            r.get("pid").and_then(|p| p.as_u64()),
            Some(writer_pid),
            "the row keys the reapped writer's pid"
        );
        assert_eq!(
            r.get("process").and_then(|p| p.as_str()),
            Some("python3"),
            "the writer's own comm rides the wire, never an unknown face and never a sibling's comm"
        );
    }
}
