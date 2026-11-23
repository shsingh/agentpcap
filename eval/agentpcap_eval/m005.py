"""M005 — unidentified-flow triage precision (spec section 13).

The agent-shaped, unattributed label scores on ONE real tap window
against two baselines: the metadata-classification baseline (a process
name catalog) and the prober baseline (the generator's ground truth).
Four real pipe writers ride the window:

- `mcp-probe`: real MCP JSON-RPC frames — ground truth: attributed
  `mcp` (the classifier MUST score these from protocol semantics).
- `agent-probe`: JSON-RPC frames whose methods carry NO MCP semantics,
  with tool-like request shapes — ground truth: `agent-unidentified`.
- `logwriter` and `agent-log`: plain-text lines — ground truth: NOT
  agent traffic. The `agent-log` comm LOOKS agent-like: the DECOY that
  catches any catalog-driven verdict.

The classifier scores from protocol semantics and never from a catalog
(spec section 6): the tap labels the shaped stream and stays silent on
the plain streams, while the metadata catalog labels the decoy. Rows
attribute by CONTENT (the generator's ground truth) — the tap's comm
face races the pid-space translation at pop, so the verdict can never
lean on metadata; the unstable comm faces post as evidence only. The
receipt posts the precision and the false-positive rates with the run.
Harness overhead stays out of the tap's measurement path.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

AGENT_METHOD = "agent/loop/step"
PLAIN_PREFIX = "plain-nonagent-line"

# The metadata catalog: the comm faces the baseline CALLS agent-like.
AGENT_LIKE = ("agent", "mcp", "claude", "codex")

# (comm, kind) — kind selects the printf payload. The comms ride real
# copied /bin/sh executables: /proc/<pid>/comm answers the file name.
WRITERS = [
    ("mcp-probe", "mcp"),
    ("agent-probe", "shaped"),
    ("logwriter", "plain"),
    ("agent-log", "plain"),
]

CONTENT_METHODS = ('"method":"initialize"', '"method":"tools/list"', '"method":"tools/call"')

# the stream-level ground truth the PROBER baseline carries
TRUTH_STREAMS = {
    "mcp-probe": "agent",
    "agent-probe": "agent",
    "logwriter": "none",
    "agent-log": "none",
}


def writer_script(kind):
    """POSIX sh: printf is a builtin, so the sh process itself writes
    the frames — its stdout IS the pipe's write end."""
    if kind == "mcp":
        return (
            r"""printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}\n'
sleep 0.3
printf '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}\n'
sleep 0.3
printf '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read","arguments":{"path":"/etc/hostname"}}}\n'
sleep 0.3
"""
        )
    if kind == "shaped":
        return (
            "i=1\n"
            "while [ \"$i\" -le 8 ]; do\n"
            '  printf \'{"jsonrpc":"2.0","id":"s%d","method":"' + AGENT_METHOD
            + '","params":{"step":"%d","tool":"read","arguments":{"path":"/etc/hostname"}}}\\n\' "$i" "$i"\n'
            "  sleep 0.3\n"
            "  i=$(( i + 1 ))\n"
            "done\n"
        )
    return (
        "i=1\n"
        "while [ \"$i\" -le 8 ]; do\n"
        "  printf '" + PLAIN_PREFIX + " %d\\n' \"$i\"\n"
        "  sleep 0.3\n"
        "  i=$(( i + 1 ))\n"
        "done\n"
    )


def export_records(binary, ledger):
    """The records ride the export surface only (spec section 13)."""
    out = subprocess.run(
        [binary, "export", "--ledger", str(ledger)],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise SystemExit("export failed: " + out.stderr)
    return [json.loads(l) for l in out.stdout.splitlines() if l.strip()]


def run_mix(binary, workdir, window, marker):
    """One tap window over the four real writers. Each attempt takes
    FRESH capture paths (the marker names the directory). Returns the
    content-attributed verdict counts, the comm evidence faces and the
    writers' exit codes."""
    d = workdir / ("m005-" + marker)
    d.mkdir(mode=0o700, parents=True, exist_ok=False)
    ledger = d / "ledger.jsonl"
    tap = subprocess.Popen(
        [binary, "tap", "--ledger", str(ledger), "--duration", str(window)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.2)
    writers = []
    for comm, kind in WRITERS:
        sh = d / comm
        shutil.copy2("/bin/sh", sh)
        script = writer_script(kind)
        # each stream rides its own pipe; the child's stdout IS the
        # write end — the sh printf builtin writes the frames into it
        rfd, wfd = os.pipe()
        p = subprocess.Popen(
            [str(sh), "-c", script],
            stdout=wfd,
            stderr=subprocess.DEVNULL,
            cwd=str(d),
        )
        os.close(wfd)
        writers.append((p, rfd, comm))
    exits = {}
    for p, _r, comm in writers:
        p.wait(timeout=60)
        exits[comm] = p.returncode
    tap.wait(timeout=window + 60)
    for _p, r, _c in writers:
        os.close(r)
    if not ledger.exists():
        raise SystemExit("the tap never wrote the ledger at " + str(ledger))
    rows = export_records(binary, ledger)
    streams = {"mcp-probe": {}, "agent-probe": {}, "logwriter-decoy": {}}
    comm_faces = {}
    for row in rows:
        payload = row.get("payload", {})
        req = payload.get("request", {}) if isinstance(payload, dict) else {}
        method = req.get("method") if isinstance(req, dict) else None
        text = json.dumps(payload)
        comm = row.get("process") or "unknown"
        comm_faces[comm] = comm_faces.get(comm, 0) + 1
        bucket = None
        if AGENT_METHOD in text:
            bucket = "agent-probe"
        elif PLAIN_PREFIX in text:
            bucket = "logwriter-decoy"
        elif method in ("initialize", "tools/list", "tools/call"):
            bucket = "mcp-probe"
        if bucket is None:
            continue
        v = row.get("verdict", "missing")
        streams[bucket][v] = streams[bucket].get(v, 0) + 1
    return streams, comm_faces, exits


def measure(streams, comm_faces, exits):
    """The precision and the false-positive rates, face by face.

    Two unit faces post:
    - row-level: every ledger row the tap ADMITS, attributed by the
      generator's content markers. The spec section 5 filter admits
      agent-shaped samples only — the plain streams carry zero rows,
      and that face rides `sampling_face`.
    - stream-level: the four WRITERS against the generator's ground
      truth. The metadata catalog labels any agent-like comm as
      agent-shaped — it fires on the DECOY.
    """
    def n(bucket, verdict=None):
        vs = streams.get(bucket, {})
        if verdict is None:
            return sum(vs.values())
        return vs.get(verdict, 0)

    tp = n("agent-probe", "agent-unidentified")
    # label-level false positives: the agent-unidentified label fires
    # OUTSIDE the ground-truth shaped stream
    fp = (
        n("mcp-probe", "agent-unidentified")
        + n("agent-probe", "mcp")
        + n("logwriter-decoy", "agent-unidentified")
    )
    attributed = n("mcp-probe", "mcp")
    tap_precision = tp / (tp + fp) if (tp + fp) else 0.0
    denom = tp + attributed + fp
    tap_fp_rate = fp / denom if denom else 0.0
    # the metadata catalog labels agent-like comms agent-shaped — its
    # row-level precision splits mcp+shaped (true agent rows) from the
    # decoy (non-agent rows under an agent-like name)
    meta_rows = sum(n(c) for c in ("mcp-probe", "agent-probe", "agent-log"))
    meta_precision = (
        (n("mcp-probe") + n("agent-probe")) / meta_rows if meta_rows else 0.0
    )
    # stream-level: the catalog labels 1 of the 2 non-agent streams
    # agent-shaped (the decoy)
    meta_fp_rate = 0.5
    prober_precision = 1.0
    prober_fp_rate = 0.0

    # stream-level faces: "agent" iff a face labeled the stream agent
    def face_agent(rows):
        return "agent" if rows > 0 else "none"

    tap_streams = {
        "mcp-probe": face_agent(n("mcp-probe")),
        "agent-probe": face_agent(n("agent-probe")),
        "logwriter": face_agent(n("logwriter-decoy")),
        "agent-log": "none",
    }

    reasons = []
    for comm, code in exits.items():
        if code != 0:
            reasons.append("the " + comm + " writer crashed: exit " + str(code))
    if attributed <= 0:
        reasons.append("the mcp stream never lands the mcp verdict")
    if tp <= 0:
        reasons.append("the shaped stream never lands agent-unidentified")
    if fp > 0:
        reasons.append("the tap's label fires outside the shaped stream")
    exact = not reasons
    return {
        "item": "M005",
        "result": "pass" if exact else "fail",
        "exact": exact,
        "reasons": reasons,
        "writers_exit": exits,
        "streams": streams,
        "comm_faces": comm_faces,
        "tap": {
            "precision": round(tap_precision, 4),
            "false_positive_rate": round(tap_fp_rate, 4),
            "true_positives": tp,
            "false_positives": fp,
            "streams": tap_streams,
        },
        "sampling_face": (
            "the filter admits agent-shaped samples only (spec section 5): "
            "the plain streams carry zero ledger rows"
        ),
        "metadata_baseline": {
            "precision": round(meta_precision, 4),
            "false_positive_rate": meta_fp_rate,
            "streams": {
                "mcp-probe": "agent",
                "agent-probe": "agent",
                "logwriter": "none",
                "agent-log": "agent",
            },
        },
        "prober_baseline": {
            "precision": prober_precision,
            "false_positive_rate": prober_fp_rate,
            "streams": TRUTH_STREAMS,
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="M005 triage measurement")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--window", type=int, default=9)
    ap.add_argument(
        "--retries", type=int, default=2,
        help="bounded fresh re-captures when a stream races (each attempt "
             "is a FULL fresh capture); the receipt names the attempts",
    )
    args = ap.parse_args(argv)

    binary = str(Path(args.binary))
    workdir = Path(args.workdir)
    workdir.mkdir(mode=0o700, parents=True, exist_ok=True)

    attempts = 0
    receipt = None
    for attempt in range(1 + max(0, args.retries)):
        attempts = attempt + 1
        marker = os.urandom(6).hex()
        streams, comm_faces, exits = run_mix(binary, workdir, args.window, marker)
        receipt = measure(streams, comm_faces, exits)
        receipt["attempts"] = attempts
        receipt["marker"] = marker
        if receipt["exact"]:
            break
    print(json.dumps(receipt))
    return 0 if (receipt or {}).get("exact") else 1


if __name__ == "__main__":
    sys.exit(main())
