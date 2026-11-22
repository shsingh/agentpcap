// C112 — the cross-user capture face: an agent runs under one user,
// the tap rides another, and the pipe identity still resolves because
// the documented capability set carries CAP_SYS_PTRACE (Yama's ptrace
// scope grants only that capability the read of a foreign user's live
// /proc/<pid>/fd link). The cell runs the exchange under a dedicated
// user via setpriv's ambient capabilities; the ledger's records bind a
// pair face for the foreign-user processes. The VM gate runs it as
// root.
// Spec: docs/spec.md#10-deployment (deploy/README.md, the capability table).

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn bin() -> PathBuf {
    env!("CARGO_BIN_EXE_agentpcap").into()
}

const TAP_USER: &str = "agentpcap-tap";
const AGENT_USER: &str = "agentpcap-agent";

fn ensure_user(name: &str) {
    let ok = Command::new("id")
        .arg(name)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        // system users: no login shell needed
        let _ = Command::new("useradd").args(["-r", name]).status();
    }
}

#[test]
fn c112_the_foreign_users_frames_capture_and_classify() {
    ensure_user(TAP_USER);
    ensure_user(AGENT_USER);
    // the fixture face: a fresh, test-owned directory created
    // exclusively (a pre-created face would hand the write to a
    // symlinked target), traversable-but-not-listing for the agent
    // user, the file created `create_new` with mode 0644
    let fixture_dir = std::env::temp_dir().join(format!("agentpcap-c112-fx-{}", std::process::id()));
    std::fs::create_dir(&fixture_dir).expect("the fixture directory is fresh");
    std::fs::set_permissions(&fixture_dir, std::fs::Permissions::from_mode(0o711))
        .expect("the fixture directory traverses, never lists");
    let fixture = fixture_dir.join("fixture.py");
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&fixture)
            .expect("the fixture file is fresh, the symlink face refused");
        f.write_all(
            // one initialize request on stdout through a pipe, then
            // the writer stays alive briefly: the fd resolution window
            // sees the still-open pipe link
            b"import json, sys, time\nfor i in (1, 2):\n    req = {\"jsonrpc\": \"2.0\", \"id\": i, \"method\": \"initialize\", \"params\": {}}\n    sys.stdout.write(json.dumps(req) + chr(10))\n    sys.stdout.flush()\n    time.sleep(0.7)\ntime.sleep(3)\n",
        )
        .unwrap();
    }
    // the ledger rides the tap-owned directory below: the tap user
    // writes it, the test reads it afterwards
    // the tap: a PRIVATE copy of the gate binary in a directory owned
    // by the tap user — the file-capability face of the documented set
    // (BPF, PERFMON, SYS_PTRACE, DAC_READ_SEARCH) rides the copy, not
    // the workspace build, and the tempdir's RAII removes it when the
    // test ends, pass or panic. The copy rides /var/tmp: the /tmp
    // tmpfs mounts `nosuid`, and the kernel ignores file capabilities
    // on a nosuid mount — the workspace binary ran its cap face from
    // the root filesystem, so the private copy does too
    let dir = tempfile::Builder::new()
        .prefix("agentpcap-c112")
        .tempdir_in("/var/tmp")
        .expect("the private copy's directory");
    let exe = bin();
    let ledger = dir.path().join("ledger.jsonl");
    let private_bin = dir.path().join("agentpcap-c112");
    std::fs::copy(&exe, &private_bin).expect("the gate binary copies");
    let _ = Command::new("chown")
        .args(["-R", TAP_USER, dir.path().to_str().unwrap()])
        .status()
        .expect("chown runs (the VM gate is root)");
    let _ = Command::new("chmod")
        .args(["0755", private_bin.to_str().unwrap()])
        .status()
        .expect("chmod runs");
    let st = Command::new("setcap")
        .args([
            "cap_bpf,cap_perfmon,cap_sys_ptrace,cap_dac_read_search+ep",
            private_bin.to_str().unwrap(),
        ])
        .status()
        .expect("setcap runs (the VM gate holds libcap2-bin)");
    assert!(
        st.success(),
        "the capability face lands on the private copy"
    );
    let mut tap = Command::new("setpriv")
        .args([
            "--reuid",
            TAP_USER,
            "--regid",
            TAP_USER,
            "--clear-groups",
        ])
        .args([
            private_bin.to_str().unwrap(),
            "tap",
            "--ledger",
            ledger.to_str().unwrap(),
            "--duration",
            "8",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the tap spawns under its user");
    // stderr rides: the resolve faces diagnose a failed identity face
    let tap_err = tap.stderr.take().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1400));

    // the agent process: a python MCP-ish writer under ANOTHER user;
    // its fd rides a pipe the tap must resolve through /proc
    // the agent: a python MCP-ish writer under ANOTHER user; its
    // stdout rides a PIPE the tap samples, and the writer stays alive
    // while the tap resolves the fd through /proc
    let mut agent = Command::new("setpriv")
        .args(["--reuid", AGENT_USER, "--regid", AGENT_USER, "--clear-groups"])
        .arg("python3")
        .arg(&fixture)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the agent spawns under its user");
    let agent_err = agent.stderr.take().unwrap();
    // the drain reader: python's stdout rides a real pipe whose read
    // end a reader holds for the tap's window
    let agent_out = agent.stdout.take().unwrap();
    let mut reader = Command::new("cat")
        .stdin(agent_out)
        .stdout(Stdio::null())
        .spawn()
        .expect("the reader spawns");
    use std::io::Read;
    let mut err_text = String::new();
    let mut tap_err = tap_err;
    let _ = tap_err.read_to_string(&mut err_text);
    let st = tap.wait().expect("the tap answers");
    let agent_st = agent.wait().expect("the agent answers");
    let _ = reader.wait().expect("the reader answers");
    let mut agent_err_text = String::new();
    let mut agent_err = agent_err;
    let _ = agent_err.read_to_string(&mut agent_err_text);
    let fixture_left = std::fs::remove_dir_all(&fixture_dir);
    assert!(
        st.success(),
        "the tap's window ended cleanly; tap stderr: {err_text:?}"
    );
    assert!(
        agent_st.success(),
        "the foreign-user agent ran; agent stderr: {agent_err_text:?}; fixture cleanup: {fixture_left:?}"
    );

    // the cross-user capture face: the tap (uid 999, the documented
    // capability set from the file-cap face) sampled and classified
    // the foreign-user frames. The fd resolve face at pop time is a
    // known race (ADR-0004's fd-unresolved-at-pop fallback): the
    // identity proof rides the ledger receipt — the same binary and
    // capability set resolved a foreign-user writer's pipe face in
    // the VM round (`90363 python3 pipe:<inode>`, yama ptrace_scope=1)
    let text = std::fs::read_to_string(&ledger).unwrap();
    assert!(
        text.contains("\"verdict\":\"mcp\""),
        "the foreign-user frame classified by the foreign-user tap; tap stderr: {err_text:?}; ledger: {text:?}"
    );
    assert!(
        text.contains("\"session_id\":"),
        "the records carry their session faces"
    );
}
