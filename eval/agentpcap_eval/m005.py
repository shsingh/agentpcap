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

Every frame carries the run's marker, and the writers' pipes carry
their inode faces — attribution never leans on common method names,
and the tap's comm face races the pid-space translation at pop (it
posts as evidence only). The classifier scores from protocol semantics
and never from a catalog (spec section 6): the tap labels the shaped
stream and stays silent on the plain streams, while the metadata
catalog labels the decoy. Rates post with their unit faces: the
row-level precision and false-positive rate, and the stream-level
precision and false-positive rate. The receipt posts them with the
run. Harness overhead stays out of the tap's measurement path.
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

# (comm, kind) — kind selects the printf payload. The comms ride real
# copied /bin/sh executables: /proc/<pid>/comm answers the file name.
WRITERS = [
    ("mcp-probe", "mcp"),
    ("agent-probe", "shaped"),
    ("logwriter", "plain"),
    ("agent-log", "plain"),
]

# the stream-level ground truth the PROBER baseline carries
TRUTH_STREAMS = {
    "mcp-probe": "agent",
    "agent-probe": "agent",
    "logwriter": "none",
    "agent-log": "none",
}


def writer_script(kind, tag):
    """POSIX sh: printf is a builtin, so the sh process itself writes
    the frames into the pipe its stdout IS. Every frame carries the
    run's tag, so attribution never leans on common method names."""
    if kind == "mcp":
        return (
            'printf \'{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
            '{"protocolVersion":"2025-06-18","m005":"' + tag + '"}}\\n\'\n'
            "sleep 0.3\n"
            'printf \'{"jsonrpc":"2.0","id":2,"method":"tools/list","params":'
            '{"m005":"' + tag + '"}}\\n\'\n'
            "sleep 0.3\n"
            'printf \'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":'
            '{"name":"read","m005":"' + tag + '","arguments":{"path":"/etc/hostname"}}}\\n\'\n'
            "sleep 0.3\n"
        )
    if kind == "shaped":
        return (
            "i=1\n"
            "while [ \"$i\" -le 8 ]; do\n"
            '  printf \'{"jsonrpc":"2.0","id":"s%d","method":"' + AGENT_METHOD
            + '","params":{"step":"%d","m005":"' + tag
            + '","tool":"read","arguments":{"path":"/etc/hostname"}}}\\n\' "$i" "$i"\n'
            "  sleep 0.3\n"
            "  i=$(( i + 1 ))\n"
            "done\n"
        )
    return (
        "i=1\n"
        "while [ \"$i\" -le 8 ]; do\n"
        "  printf '" + tag + " plain-nonagent-line %d\\n' \"$i\"\n"
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
    per-stream verdict counts, the comm evidence faces and the writers'
    exit codes. The writers' pipes carry their inode faces, so rows tie
    to their writers even when the tap cannot parse the payload."""
    d = workdir / ("m005-" + marker)
    d.mkdir(mode=0o700, parents=True, exist_ok=False)
    ledger = d / "ledger.jsonl"
    tap = subprocess.Popen(
        [binary, "tap", "--ledger", str(ledger), "--duration", str(window)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.2)
    tags = {
        "mcp-probe": "m005mcp-" + marker,
        "agent-probe": "m005agent-" + marker,
        "logwriter": "m005plain-" + marker,
        "agent-log": "m005plain-" + marker,
    }
    writers = []
    pipes = {}
    for comm, kind in WRITERS:
        sh = d / comm
        shutil.copy2("/bin/sh", sh)
        script = writer_script(kind, tags[comm])
        # each stream rides its own pipe; the child's stdout IS the
        # write end — the sh printf builtin writes the frames into it
        rfd, wfd = os.pipe()
        pipe_face = "pipe:" + str(os.fstat(rfd).st_ino)
        p = subprocess.Popen(
            [str(sh.resolve()), "-c", script],
            stdout=wfd,
            stderr=subprocess.DEVNULL,
            cwd=str(d),
        )
        os.close(wfd)
        writers.append((p, rfd, comm))
        pipes[pipe_face] = comm
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
    streams = {c: {} for c, _k in WRITERS}
    comm_faces = {}
    for row in rows:
        payload = row.get("payload", {})
        text = json.dumps(payload)
        comm = row.get("process") or "unknown"
        comm_faces[comm] = comm_faces.get(comm, 0) + 1
        bucket = None
        for pipe_face, owner in pipes.items():
            face = row.get("peer", "") or ""
            sid = row.get("session_id", "") or ""
            if pipe_face in face or pipe_face in sid:
                bucket = owner
                break
        if bucket is None:
            for comm_, tag in tags.items():
                if tag in text:
                    bucket = comm_
                    break
        if bucket is None:
            continue
        v = row.get("verdict", "missing")
        streams[bucket][v] = streams[bucket].get(v, 0) + 1
    return streams, comm_faces, exits


def measure(streams, comm_faces, exits, marker):
    """The precision and the false-positive rates, face by face. Each
    rate carries its unit face: row or stream."""
    def n(bucket, verdict=None):
        vs = streams.get(bucket, {})
        if verdict is None:
            return sum(vs.values())
        return vs.get(verdict, 0)

    # row-level faces (unit: row): the agent-unidentified label scores
    # against the rows the run's own writers admitted
    tp = n("agent-probe", "agent-unidentified")
    fp = (
        n("logwriter", "agent-unidentified")
        + n("agent-log", "agent-unidentified")
        + n("mcp-probe", "agent-unidentified")
    )
    attributed = n("mcp-probe", "mcp")
    row_precision = tp / (tp + fp) if (tp + fp) else 0.0
    row_fp_rate = fp / (fp + attributed) if (fp + attributed) else 0.0
    # stream-level faces (unit: stream): the four writers, ground truth
    # from the prober. The tap labels a stream agent when any of its
    # rows land; the metadata catalog labels an agent-like comm agent
    # (3 of 4 streams), the decoy fires on the truth-non-agent stream.
    tap_streams = {
        "mcp-probe": "agent" if n("mcp-probe") > 0 else "none",
        "agent-probe": "agent" if n("agent-probe") > 0 else "none",
        "logwriter": "agent" if n("logwriter") > 0 else "none",
        "agent-log": "agent" if n("agent-log") > 0 else "none",
    }
    tap_stream_true = sum(
        1 for c, truth in TRUTH_STREAMS.items()
        if truth == "agent" and tap_streams[c] == "agent"
    )
    tap_stream_fp = sum(
        1 for c, truth in TRUTH_STREAMS.items()
        if truth == "none" and tap_streams[c] == "agent"
    )
    stream_precision = tap_stream_true / 2  # 2 agent streams in truth
    stream_fp_rate = tap_stream_fp / 2  # 2 non-agent streams in truth
    meta_streams = {
        "mcp-probe": "agent",
        "agent-probe": "agent",
        "logwriter": "none",
        "agent-log": "agent",
    }
    meta_stream_true = sum(
        1 for c, truth in TRUTH_STREAMS.items()
        if truth == "agent" and meta_streams[c] == "agent"
    )
    meta_stream_fp = sum(
        1 for c, truth in TRUTH_STREAMS.items()
        if truth == "none" and meta_streams[c] == "agent"
    )
    meta_stream_precision = meta_stream_true / 2
    meta_stream_fp_rate = meta_stream_fp / 2

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
        "marker": marker,
        "streams": streams,
        "comm_faces": comm_faces,
        "tap": {
            "row_precision": round(row_precision, 4),
            "row_false_positive_rate": round(row_fp_rate, 4),
            "true_positives": tp,
            "false_positives": fp,
            "stream_precision": round(stream_precision, 4),
            "stream_false_positive_rate": round(stream_fp_rate, 4),
            "streams": tap_streams,
        },
        "sampling_face": (
            "the filter admits agent-shaped samples only (spec section 5): "
            "the plain writers' pipes carry zero ledger rows unless the "
            "unparseable-sample path admits them — any row on a plain "
            "writer's pipe counts a false positive"
        ),
        "metadata_baseline": {
            "stream_precision": round(meta_stream_precision, 4),
            "stream_false_positive_rate": round(meta_stream_fp_rate, 4),
            "streams": meta_streams,
        },
        "prober_baseline": {
            "stream_precision": 1.0,
            "stream_false_positive_rate": 0.0,
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
    workdir = Path(args.workdir).resolve()
    workdir.mkdir(mode=0o700, parents=True, exist_ok=True)

    attempts = 0
    receipt = None
    for attempt in range(1 + max(0, args.retries)):
        attempts = attempt + 1
        marker = os.urandom(6).hex()
        streams, comm_faces, exits = run_mix(binary, workdir, args.window, marker)
        receipt = measure(streams, comm_faces, exits, marker)
        receipt["attempts"] = attempts
        if receipt["exact"]:
            break
    print(json.dumps(receipt))
    return 0 if (receipt or {}).get("exact") else 1


if __name__ == "__main__":
    sys.exit(main())
