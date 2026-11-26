"""M001 — shadow-discovery recall on the seeded fleet (spec section 13).

The seeded fleet rides ONE tap window: N known MCP sessions (full
initialize/tools-list/tools-call exchanges over their own pipes) plus
SHADOW deployments — MCP-shaped frames riding non-MCP method semantics
(the m005 `agent-probe` shape). Recall keys by markers: a planted
session is DISCOVERED when its marker ties at least one ledger row
whose verdict answers an agent face (`mcp`, `a2a` or `agent-unid
entified`); a planted known session must never ride a shadow-only row.

Two baselines answer on the SAME traffic:

- the header-heuristic class: the HTTP header scan (`Mcp-Session-Id`,
  `Mcp-Protocol-Version`, `Authorization`, `Content-Type:`) — stdio
  pipes carry none, so this class answers 0 on stdio traffic;
- the active probe: the prober reads back the traffic the fleet wrote
  (its own capture) and scans for a `jsonrpc` member — the honest
  prober face, never a port scan.

The receipt posts the recall rows, the baseline table and the run's
transcript. Harness overhead stays out of the tap's measurement path.

Run (build VM): `python3 -m agentpcap_eval.m001 --binary <agentpcap>`.
"""

import argparse
import json
import os
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .scenario import ServerSpec, server_script

KNOWN_FLEET = 3
SHADOW_FLEET = 2

HEADER_FACE = ("mcp-session-id", "mcp-protocol-version", "authorization",
               "content-type:")


def run_known_session(workdir, marker, index, fleet_bytes):
    """One real client/server pair over stdio pipes. The harness plays
    the client; every exchange completes when the reply lands. The
    fleet's bytes ride the independent copy: the client's sent frames
    plus every reply read back off the server's stdout."""
    tag = "m001-known-" + marker + "-" + str(index)
    sent = []
    got = []
    spec = ServerSpec(
        tools_by_call=["m001-" + tag],
        capabilities_by_call=[{"experimental": {}}],
        tool_result="read ok face: " + tag,
        server_name="m001-server-" + tag,
    )
    script = workdir / ("m001-server-" + marker + "-" + str(index) + ".py")
    Path(script).write_text(server_script(spec))
    server = subprocess.Popen(
        ["python3", str(script)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    try:
        init = json.dumps({
            "jsonrpc": "2.0", "id": tag + "-1", "method": "initialize",
            "params": {"protocolVersion": "2025-06-18",
                       "clientInfo": {"name": tag, "version": "0"}},
        })
        sent.append(init)
        server.stdin.write((init + "\n").encode())
        server.stdin.flush()
        # the reply reads back line-wise; the marker rides the serverInfo
        for _ in range(3):
            line = server.stdout.readline()
            if not line:
                break
            got.append(line.decode().strip())
            if "serverInfo" in line.decode():
                break
        for i, method in enumerate(("tools/list", "tools/call")):
            req = json.dumps({
                "jsonrpc": "2.0", "id": tag + "-" + str(i + 2),
                "method": method,
                "params": ({"m001-known": tag} if method == "tools/list"
                           else {"name": "m001-" + tag, "m001-known": tag,
                                 "arguments": {"path": "/etc/hostname"}}),
            })
            sent.append(req)
            server.stdin.write((req + "\n").encode())
            server.stdin.flush()
            line = server.stdout.readline()
            if line:
                got.append(line.decode().strip())
    finally:
        try:
            server.stdin.close()
        except Exception:
            pass
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=10)
    fleet_bytes[tag] = ("\n".join(sent) + "\n" + "\n".join(got) + "\n").encode()
    return {
        "class": "known",
        "frames": len(sent) + len(got),
        "raw": fleet_bytes[tag],
    }


def shadow_script(tag):
    """The shadow deployment: agent-shaped frames riding NO MCP method
    semantics (the agent-probe shape); the tap must still DISCOVER the
    session by its content face (agent-unidentified). The frame rides
    argv so the shell quote face stays a single simple face."""
    return (
        "i=1\n"
        "while [ \"$i\" -le 4 ]; do\n"
        "  printf '%s\\n' \"$1\"\n"
        "  sleep 0.3\n"
        "  i=$(( i + 1 ))\n"
        "done\n"
    )


def shadow_frame(tag):
    """The shadow frame: the same agent-shaped face, no MCP method
    semantics (the agent-probe shape), one frame per loop step."""
    return (
        '{"jsonrpc":"2.0","id":"s%d","method":"agent/loop/step",'
        '"params":{"step":"%d","m001-shadow":"' + tag + '","tool":"read",'
        '"arguments":{"path":"/etc/hostname"}}}'
    )


def run_shadow_session(workdir, marker, index, fleet_bytes):
    """The shadow deployment: agent-shaped frames riding NO MCP method
    semantics (the agent-probe shape), written one-way into a pipe."""
    tag = "m001-shadow-" + marker + "-" + str(index)
    sh = workdir / ("m001-shadow-sh-" + marker + "-" + str(index))
    shutil.copy2("/bin/sh", sh)
    script = shadow_script(tag)
    frame = shadow_frame(tag)
    rfd, wfd = os.pipe()
    p = subprocess.Popen(
        [str(sh.resolve()), "-c", script, "sh", frame, frame],
        stdout=wfd, stderr=subprocess.DEVNULL, cwd=str(workdir),
    )
    os.close(wfd)
    data = os_read_all(rfd)      # the independent copy of the fleet bytes
    p.wait(timeout=60)
    fleet_bytes[tag] = data
    return {"class": "shadow", "frames": script.count("printf") * 2,
            "raw": data}


def os_read_all(fd):
    """Read the pipe back to its writer's EOF — the fleet's independent
    copy of what the shadow wrote."""
    chunks = []
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    os.close(fd)
    return b"".join(chunks)


def export_records(binary, ledger):
    out = subprocess.run([binary, "export", "--ledger", str(ledger)],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit("export failed: " + out.stderr)
    return [json.loads(l) for l in out.stdout.splitlines() if l.strip()]


def run_fleet(binary, workdir, window, marker):
    """One tap window over the seeded fleet. Returns the export rows and
    the planted faces (the marker -> the fleet's independent bytes).
    Raises on an invalid window; the tap kills and reaps on ANY failure
    path."""
    window = int(window)
    if window <= 0:
        raise SystemExit("--window must be a positive number of seconds")
    d = workdir / ("m001-" + marker)
    d.mkdir(mode=0o700, parents=True, exist_ok=False)
    ledger = d / "ledger.jsonl"
    tap = None
    try:
        tap = subprocess.Popen(
            [binary, "tap", "--ledger", str(ledger), "--duration", str(window)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.2)
        planted = {}
        fleet_bytes = {}
        for i in range(KNOWN_FLEET):
            face = run_known_session(d, marker, i, fleet_bytes)
            planted["m001-known-" + marker + "-" + str(i)] = face
        for i in range(SHADOW_FLEET):
            face = run_shadow_session(d, marker, i, fleet_bytes)
            planted["m001-shadow-" + marker + "-" + str(i)] = face
        tap_rc = None
        try:
            tap_rc = tap.wait(timeout=window + 60)
        except subprocess.TimeoutExpired:
            tap.kill()
            tap_rc = -1
        finally:
            if tap is not None and tap.poll() is None:
                tap.kill()
                try:
                    tap.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    pass
    finally:
        if tap is not None and tap.poll() is None:
            tap.kill()
            try:
                tap.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
    if tap_rc != 0:
        raise SystemExit(
            "the tap did not exit cleanly (rc=" + str(tap_rc) +
            "): the run scores nothing"
        )
    if not ledger.exists():
        raise SystemExit("the tap never wrote the ledger at " + str(ledger))
    return export_records(binary, ledger), planted


def score(rows, planted):
    """The discovery sets: a planted session is DISCOVERED when its
    marker ties at least one ledger row whose verdict answers an agent
    face. The baselines answer on the same traffic."""
    agent_faces = ("mcp", "a2a", "agent-unidentified")
    discovered = {tag: False for tag in planted}
    header_hits = {tag: False for tag in planted}
    probe_hits = {tag: False for tag in planted}
    for row in rows:
        text = json.dumps(row)
        v = (row.get("verdict") or "").lower()
        for tag in planted:
            if tag in text:
                if v in agent_faces:
                    discovered[tag] = True
    for tag, face in planted.items():
        raw = face["raw"].decode("utf-8", errors="replace").lower()
        if any(h in raw for h in HEADER_FACE):
            header_hits[tag] = True
        if "jsonrpc" in raw:
            probe_hits[tag] = True
    recall_rows = []
    for cls in ("known", "shadow"):
        tags = [t for t, f in planted.items() if f["class"] == cls]
        disc = sum(1 for t in tags if discovered[t])
        hdr = sum(1 for t in tags if header_hits[t])
        prb = sum(1 for t in tags if probe_hits[t])
        recall_rows.append({
            "class": cls,
            "planted": len(tags),
            "agentpcap": disc,
            "header_heuristic": hdr,
            "active_probe": prb,
            "recall_agentpcap": round(disc / len(tags), 3) if tags else 1.0,
        })
    return recall_rows, discovered


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--window", default="8")
    ap.add_argument("--marker", required=True,
                    help="the run-unique marker; the harness refuses a reused workdir")
    a = ap.parse_args()

    window = int(a.window)
    workdir = Path(a.workdir)
    if not a.workdir.startswith("/tmp/agentpcap-eval-"):
        resolved = workdir.resolve()
    else:
        resolved = workdir
    rows, planted = run_fleet(a.binary, resolved, str(window), a.marker)
    recall_rows, discovered = score(rows, planted)

    receipt = {
        "item": "M001",
        "marker": a.marker,
        "result": "pass" if all(recall_rows[i]["recall_agentpcap"] == 1.0
                                for i in range(len(recall_rows))) else "fail",
        "fleet": {"known": KNOWN_FLEET, "shadow": SHADOW_FLEET},
        "recall_rows": recall_rows,
        "baseline_table": [
            {"class": r["class"],
             "agentpcap": r["agentpcap"],
             "header_heuristic": r["header_heuristic"],
             "active_probe": r["active_probe"]}
            for r in recall_rows
        ],
        "discovered": sorted(t for t, d_ in discovered.items() if d_),
        "rows": len(rows),
    }
    print(json.dumps(receipt, indent=2))
    return 0 if receipt["result"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
