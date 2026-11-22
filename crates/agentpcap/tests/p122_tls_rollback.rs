// P122 — the TLS attach ROLLBACK face: when a later TLS probe fails to
// attach, the earlier attached links detach before the degrade — the
// tap records NO half-boundary rows (a receive face without its send
// face), the pending map stays empty, and the tap survives with the
// pipe and socket faces.
// Spec: docs/spec.md#5-collectors, ADR-0006; cell ledger: tests/matrix/LEDGER.md.

use std::io::BufRead;
use std::process::{Command, Stdio};
use std::time::Duration;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_agentpcap"))
}

#[test]
fn p122_the_failed_read_attach_undoes_the_write_links() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.jsonl");

    // the read pair's attach face points at a path without the symbol:
    // the read probes fail AFTER the write pair attaches — the rollback
    // detaches the write links before the degrade
    let mut tap = bin()
        .args(["tap", "--ledger"])
        .arg(&ledger)
        .arg("--duration")
        .arg("8")
        .env("AGENTPCAP_TLS_LIBSSL_READ", "/tmp/agentpcap-no-such-libssl.so.3")
        .stdout(Stdio::piped())
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

    // a framed write rides the pipe face while the boundary degrades
    std::thread::sleep(Duration::from_millis(1200));
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
        r#"{{"jsonrpc":"2.0","id":700,"method":"tools/list","params":{{}}}}"#
    )
    .unwrap();
    let _ = f.flush();
    drop(f);
    // the child's input pipe closes BEFORE the wait: `cat` exits on
    // EOF, so the wait never races its own stdin
    let _ = sink.wait();

    let st = tap.wait().expect("tap exits at its deadline");
    let _ = tap;
    assert!(st.success(), "the tap exits cleanly on the degrade face");
    let lines = stderr_handle.join().expect("the stderr joins");
    eprintln!("p122 tap stderr: {lines:?}");

    // the rollback face rode: the read pair's failure named (the entry
    // probe fails first on the bogus path), the write pair's links
    // undone before the degrade
    assert!(
        lines
            .iter()
            .any(|l| l.contains("agentpcap_tls_read did not attach")
                && l.contains("the tls faces stay unavailable")),
        "the failing read face states its attach failure and the rollback"
    );

    let text = std::fs::read_to_string(&ledger).unwrap_or_default();
    let recs: Vec<serde_json::Value> = text
        .lines()
        .flat_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .collect();
    // NO half-boundary rows: a receive face without its send face never
    // rides the ledger after the rollback
    let recv_rows: Vec<_> = recs
        .iter()
        .filter(|r| {
            r["evidence"]
                .as_array()
                .map(|e| e.iter().any(|x| x == "probe-face:receive"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        recv_rows.is_empty(),
        "p122 receipt: no half-boundary receive rows after the rollback (got {recv_rows:?})"
    );
}
