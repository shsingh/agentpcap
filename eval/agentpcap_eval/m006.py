"""M006 — gate handoff latency (spec section 13, issue #30).

The criteria-scoring budget is 2 seconds ([ADR-0002], the rc1 gate):
the gate's verdict rows must land in the ledger in time for the gate
to eat its input. This harness measures the ledger-to-verdict latency
on representative event bursts: ONE real tap, ONE real counting server
over stdio, and the harness playing the client — burst groups of
tools/call frames ride the window with the run's marker in the frame
ids, and a poller thread tails the ledger at a 20 ms cadence through
the WHOLE window, stamping the exact landing time per verdict row.
The latency distribution (per-event latencies, plus min, median, p95
and max by nearest rank) posts against the budget, and the comparison
rides the receipt explicitly. Harness overhead stays out of the tap's
measurement path: the polling rides the gate-side reader, never the
tap.
"""

import argparse
import json
import math
import os
import statistics
import subprocess
import sys
import threading
import time
from pathlib import Path

from .scenario import ServerSpec, server_script

TOOLS = [{"name": "read", "description": "read a file"}]
CALL_RESULT = "c124-hello"
CAPS = {"tools": {}}
BUDGET_S = 2.0

# representative bursts: 4 frames inside a burst at a 0.1 s cadence
# (the burst shape), 0.9 s between bursts
BURSTS = 4
FRAMES_PER_BURST = 4
INTRA_BURST_S = 0.1
INTER_BURST_S = 0.9


class LedgerPoller(threading.Thread):
    """The gate-side reader: tails the ledger file bytes for the whole
    window and stamps the landing wall-clock per parsed request id.
    Polling stays in the harness (the gate's reader) at a 20 ms cadence
    — granular against the 2 s budget without a reader storm."""

    def __init__(self, ledger):
        super().__init__(daemon=True)
        self.ledger = str(ledger)
        self.landed = {}  # request-id string -> landing wall-clock
        self._pos = 0
        self._pending = b""
        self._stop = threading.Event()

    def run(self):
        while not self._stop.is_set():
            self.poll()
            time.sleep(0.02)

    def stop(self):
        self._stop.set()
        self.poll()

    def poll(self):
        try:
            with open(self.ledger, "rb") as f:
                f.seek(self._pos)
                chunk = f.read()
            if not chunk:
                return
        except FileNotFoundError:
            return
        self._pos += len(chunk)
        self._pending += chunk
        while b"\n" in self._pending:
            line, self._pending = self._pending.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            rid = (rec.get("payload", {}) or {}).get("request", {}).get("id")
            if rid is not None and str(rid) not in self.landed:
                self.landed[str(rid)] = time.time()


def main(argv=None):
    ap = argparse.ArgumentParser(description="M006 gate handoff measurement")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--window", type=int, default=12)
    ap.add_argument(
        "--retries", type=int, default=2,
        help="bounded fresh re-captures when a burst races (each attempt "
             "is a FULL fresh capture); the receipt names the attempts",
    )
    ap.add_argument("--budget-s", type=float, default=BUDGET_S,
                    help="the ADR-0002 criteria budget, in seconds")
    args = ap.parse_args(argv)

    binary = str(Path(args.binary))
    workdir = Path(args.workdir).resolve()
    workdir.mkdir(mode=0o700, parents=True, exist_ok=True)

    attempts = 0
    receipt = None
    for attempt in range(1 + max(0, args.retries)):
        attempts = attempt + 1
        marker = os.urandom(6).hex()
        receipt = run_window(binary, workdir, args.window, marker, args.budget_s)
        receipt["attempts"] = attempts
        if receipt["exact"]:
            break
    print(json.dumps(receipt))
    return 0 if (receipt or {}).get("exact") else 1


def run_window(binary, workdir, window, marker, budget_s):
    """One tap window over the burst schedule; the poller thread tails
    the ledger for the whole window; the harness plays the client.
    Every frame's id carries the run's marker: one run never counts
    another run's rows."""
    d = workdir / ("m006-" + marker)
    d.mkdir(mode=0o700, parents=True, exist_ok=False)
    ledger = d / "ledger.jsonl"
    server_name = "m006-server-" + marker

    tap = subprocess.Popen(
        [binary, "tap", "--ledger", str(ledger), "--duration", str(window)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(1.2)

    poller = LedgerPoller(ledger)
    poller.start()

    spec = ServerSpec(
        tools_by_call=[TOOLS],
        capabilities_by_call=[CAPS],
        tool_result=CALL_RESULT,
        server_name=server_name,
    )
    script = d / "server.py"
    Path(script).write_text(server_script(spec))
    server = subprocess.Popen(
        ["python3", str(script)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )

    write_times = {}
    reasons = []
    init_id = marker + "-init"
    init = json.dumps({
        "jsonrpc": "2.0", "id": init_id, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "m006-" + marker, "version": "0"},
        },
    })
    write_times[init_id] = time.time()
    server.stdin.write((init + "\n").encode())
    server.stdin.flush()
    init_landed = poller.landed.get(init_id)
    deadline = time.time() + 5.0
    while init_landed is None and time.time() < deadline:
        time.sleep(0.02)
        init_landed = poller.landed.get(init_id)
    if init_landed is None:
        reasons.append("the initialize never merged inside the window")
    else:
        # the merge face settles: the m004 schedule rides 0.3 s between
        # the initialize and the next frame
        time.sleep(0.3)
        burst_ids = []
        for burst in range(BURSTS):
            if burst:
                time.sleep(INTER_BURST_S)
            for i in range(FRAMES_PER_BURST):
                frame_id = f"{marker}-c{burst}{i}"
                burst_ids.append(frame_id)
                call = json.dumps({
                    "jsonrpc": "2.0", "id": frame_id,
                    "method": "tools/call",
                    "params": {"name": "read", "arguments": {"path": "/x"}},
                })
                write_times[frame_id] = time.time()
                server.stdin.write((call + "\n").encode())
                server.stdin.flush()
                if i < FRAMES_PER_BURST - 1:
                    time.sleep(INTRA_BURST_S)
    # the writer stays alive past the pop window per ADR-0004
    time.sleep(1.5)
    try:
        server.stdin.close()
    except Exception:
        pass
    tap.wait(timeout=max(1, window + 60))
    try:
        server.wait(timeout=30)
    except Exception:
        server.kill()
    poller.stop()

    return score(binary, ledger, poller, write_times, server_name,
                 budget_s, marker, reasons)


def score(binary, ledger, poller, write_times, server_name, budget_s,
          marker, reasons):
    """The latency distribution against the budget. The export must
    answer every measured frame: a torn tail or a failed export never
    rides a pass."""
    out = subprocess.run(
        [binary, "export", "--ledger", str(poller.ledger)],
        capture_output=True, text=True,
    )
    export_rows = []
    if out.returncode == 0:
        export_rows = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
    else:
        reasons.append("the export face failed: " + (out.stderr or "").strip()[:120])
    export_ids = set()
    for r in export_rows:
        rid = (r.get("payload", {}) or {}).get("request", {}).get("id")
        if rid is not None:
            export_ids.add(str(rid))
    latencies = []
    missing = []
    for fid, t_write in write_times.items():
        if fid not in poller.landed:
            missing.append(fid)
            continue
        latencies.append({"id": fid, "latency_s": round(poller.landed[fid] - t_write, 6)})
    values = sorted(x["latency_s"] for x in latencies)
    distribution = {
        "min_s": round(values[0], 4) if values else None,
        "median_s": round(statistics.median(values), 4) if values else None,
        "p95_s": (round(values[math.ceil(0.95 * len(values)) - 1], 4)
                  if values else None),
        "max_s": round(values[-1], 4) if values else None,
    }
    not_exported = [fid for fid in write_times if fid not in export_ids]
    if not_exported:
        reasons.append("the export face never answers: " + ",".join(not_exported))
    over = [x["id"] for x in latencies if x["latency_s"] >= budget_s]
    if over:
        reasons.append("rows outside the budget: " + ",".join(over))
    exact = not reasons
    verdicts = {}
    for r in export_rows:
        rid = (r.get("payload", {}) or {}).get("request", {}).get("id")
        if rid is not None:
            verdicts[str(rid)] = r.get("verdict", "missing")
    return {
        "item": "M006",
        "result": "pass" if exact else "fail",
        "exact": exact,
        "reasons": reasons,
        "marker": marker,
        "server_name": server_name,
        "frames_written": len(write_times),
        "landed": len(values),
        "verdicts": verdicts,
        "latencies": latencies,
        "distribution": distribution,
        "budget_s": budget_s,
        "within_budget": bool(values) and all(
            x["latency_s"] < budget_s for x in latencies
        ),
    }


if __name__ == "__main__":
    sys.exit(main())
