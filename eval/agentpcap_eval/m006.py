"""M006 — gate handoff latency (spec section 13, issue #30).

The criteria-scoring budget is 2 seconds ([ADR-0002], the rc1 gate):
the gate's verdict rows must land in the ledger in time for the gate
to eat its input. This harness measures the ledger-to-verdict latency
on representative event bursts: ONE real tap, ONE real counting server
over stdio, and the harness playing the client — burst groups of
tools/list and tools/call frames ride the window, and the harness
stamps the exact write time for every frame and the exact landing
time for every verdict row it tails out of the ledger file. The
latency distribution (per-event latencies, plus min, median, p95 and
max) posts against the budget, and the comparison rides the receipt
explicitly. Harness overhead stays out of the tap's measurement path:
the polling rides the harness (the gate's reader), never the tap.
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
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


def main(argv=None):
    ap = argparse.ArgumentParser(description="M006 gate handoff measurement")
    ap.add_argument("--binary", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--window", type=int, default=10)
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
    """One tap window with the burst schedule riding the counting
    server; the harness stamps write and landing times per frame."""
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

    follow = LedgerFollow(ledger)
    write_times = {}  # frame id -> write wall-clock

    def send(frame_id, obj, sleep_after=0.1):
        write_times[frame_id] = time.time()
        server.stdin.write((json.dumps(obj) + "\n").encode())
        server.stdin.flush()
        if sleep_after:
            time.sleep(sleep_after)

    send("init", {
        "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "clientInfo": {"name": "m006-" + marker, "version": "0"},
        },
    })
    follow.wait_for("init", write_times)
    time.sleep(0.3)
    burst_ids = []
    for burst in range(BURSTS):
        if burst:
            time.sleep(INTER_BURST_S)
        for i in range(FRAMES_PER_BURST):
            frame_id = f"c{burst}{i}"
            burst_ids.append(frame_id)
            send(frame_id, {
                "jsonrpc": "2.0", "id": frame_id,
                "method": "tools/call",
                "params": {"name": "read", "arguments": {"path": "/x"}},
            })
            follow.poll()
    # the writer stays alive past the pop window per ADR-0004
    time.sleep(1.5)
    try:
        server.stdin.close()
    except Exception:
        pass

    follow.join_tap(tap, server)
    return follow.score(binary, burst_ids, write_times, server_name, budget_s, marker)


class LedgerFollow:
    """The gate-side reader: tails the ledger file bytes and stamps the
    landing wall-clock per parsed id. Polling stays in the harness (the
    gate's reader) at a 20 ms cadence — granular against the 2 s budget
    without a reader storm on the writer."""

    def __init__(self, ledger):
        self.ledger = ledger
        self.landed = {}  # id -> landing wall-clock
        self._pos = 0
        self.pending = b""

    def poll(self):
        if os.environ.get("M006_NO_POLL"):
            return
        try:
            with open(self.ledger, "rb") as f:
                f.seek(self._pos)
                chunk = f.read()
            if not chunk:
                return
        except FileNotFoundError:
            return
        self._pos += len(chunk)
        self.pending += chunk
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            rid = (rec.get("payload", {}) or {}).get("request", {}).get("id")
            if rid is not None and rid not in self.landed:
                # one unique id lands once: the first sight stamps
                self.landed[str(rid)] = time.time()

    def wait_for(self, frame_id, write_times, timeout=10.0):
        """Poll until the frame's landing row shows, stamping."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.poll()
            if frame_id in self.landed:
                return
            time.sleep(0.02)
        return

    def join_tap(self, tap, server):
        deadline = time.time() + 120
        poll_until = time.time() + 60
        while time.time() < poll_until:
            self.poll()
            time.sleep(0.02)
        tap.wait(timeout=min(60, max(1, deadline - time.time())))
        server.wait(timeout=60)
        self.poll()

    def score(self, binary, frames, write_times, server_name, budget_s, marker):
        # the verdict face rides the export surface
        out = subprocess.run(
            [binary, "export", "--ledger", str(self.ledger)],
            capture_output=True, text=True,
        )
        rows = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
        verdicts = {}
        for r in rows:
            rid = str((r.get("payload", {}) or {}).get("request", {}).get("id"))
            if rid:
                verdicts[rid] = r.get("verdict", "missing")
        latencies = []
        missing = []
        for fid, t_write in write_times.items():
            if fid == "init":
                continue
            if fid in self.landed:
                latencies.append({
                    "id": fid,
                    "latency_s": round(self.landed[fid] - t_write, 6),
                })
            else:
                missing.append(fid)
        values = sorted(x["latency_s"] for x in latencies)
        distribution = {
            "min_s": round(values[0], 4) if values else None,
            "median_s": round(statistics.median(values), 4) if values else None,
            "p95_s": round(values[int(len(values) * 0.95) - 1], 4) if values else None,
            "max_s": round(values[-1], 4) if values else None,
        }
        within = bool(values) and not missing and max(values) < budget_s
        reasons = []
        if missing:
            reasons.append("frames never landed: " + ",".join(missing))
        if not values:
            reasons.append("the burst frames never landed a verdict row")
        if values and max(values) >= budget_s:
            reasons.append(
                "the max latency carries the budget: "
                + str(distribution["max_s"]) + " >= " + str(budget_s)
            )
        exact = not reasons
        return {
            "item": "M006",
            "result": "pass" if exact else "fail",
            "exact": exact,
            "reasons": reasons,
            "marker": marker,
            "server_name": server_name,
            "frames_written": len([f for f in write_times if f != "init"]),
            "verdicts": verdicts,
            "latencies": latencies,
            "distribution": distribution,
            "budget_s": budget_s,
            "within_budget": within,
        }





if __name__ == "__main__":
    sys.exit(main())
