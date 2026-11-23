"""M002 — tap overhead, the identical-harness delta (spec section 13).

The IDENTICAL harness runs one workload twice: tap off, tap on. The
workload: a fixed frame count through a real pipe in one write loop
with inter-frame gaps — the agent-shaped profile (the model wait sits
at the gaps), so the tap's per-write cost rides a realistic face, not a
pure-syscall microbench. The tap-on phase also measures the tap's own
CPU consumption from `/proc/<tap>/stat` across the measured window
(the OS face, never a tap internal) — the overhead face the published
AgentSight figure (the sub-3% ceiling) binds. Both phases repeat the
same repeats; the phase minima answer the wall delta; the receipt
names the noise face so a noise-bound delta never reads as precision.
The receipt carries no tap-internal timing.
"""

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .scenario import CALL

FRAMES = 250
REPEATS = 3
GAP_S = 0.004
FRAME_GAP_S = 0.005


def workload(binary, workdir, frames, gap):
    """One run of the frame-write workload through a real pipe: a
    cat-style sink child, one writer loop with inter-frame gaps (the
    agent-shaped profile). Returns the wall milliseconds of the loop.
    The pipe pair and the sink stay identical in both phases."""
    del binary, workdir
    sink = subprocess.Popen(
        ["sh", "-c", "cat >/dev/null"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    f = sink.stdin
    start = time.perf_counter()
    for _ in range(frames):
        f.write((CALL + "\n").encode())
        f.flush()
        time.sleep(gap)
    f.close()
    sink.wait(timeout=30)
    return (time.perf_counter() - start) * 1000.0


def tap_cpu_seconds(pid):
    stat = Path(f"/proc/{pid}/stat").read_text()
    fields = stat.rsplit(")", 1)[1].split()
    utime, stime = int(fields[11]), int(fields[12])
    return (utime + stime) / 100.0


def phase(binary, workdir, tap_on, frames, repeats, gap):
    """One phase. With the tap on, the tap starts BEFORE the measured
    window (the calibration face sits outside it) and its window
    outlasts the repeats; the tap's own CPU consumption rides
    `/proc/<tap>/stat` across the window. Returns (min_ms, tap_cpu_s)."""
    tap = None
    if tap_on:
        ledger = workdir / "m002.jsonl"
        tap = subprocess.Popen(
            [binary, "tap", "--ledger", str(ledger), "--duration", "12"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # the calibration: outside the measured window
        time.sleep(1.2)
        cpu_start = tap_cpu_seconds(tap.pid)
    try:
        minima = None
        for _ in range(repeats):
            ms = workload(binary, workdir, frames, gap)
            if minima is None or ms < minima:
                minima = ms
        cpu_s = 0.0
        if tap is not None:
            cpu_s = tap_cpu_seconds(tap.pid) - cpu_start
        return minima, cpu_s
    finally:
        if tap is not None:
            tap.wait(timeout=20)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--frames", type=int, default=FRAMES)
    ap.add_argument("--repeats", type=int, default=REPEATS)
    ap.add_argument("--figure-pct", type=float, default=3.0)
    args = ap.parse_args(argv)

    binary = str(Path(args.binary))
    workdir = Path(args.workdir)
    workdir.mkdir(mode=0o700, parents=True, exist_ok=True)
    # the phases run in DIFFERENT tempdirs: no ledger writes mix into
    # the tap-off phase
    off_dir = tempfile.TemporaryDirectory(dir=workdir)
    on_dir = tempfile.TemporaryDirectory(dir=workdir)

    off_ms = phase(binary, Path(off_dir.name), False, args.frames, args.repeats, FRAME_GAP_S)[0]
    on_ms, tap_cpu_s = phase(binary, Path(on_dir.name), True, args.frames, args.repeats, FRAME_GAP_S)

    delta_pct = (on_ms - off_ms) / off_ms * 100.0
    wall_secs = on_ms / 1000.0
    cpu_pct = tap_cpu_s / wall_secs * 100.0 if wall_secs > 0 else 0.0
    ok = delta_pct <= args.figure_pct and cpu_pct <= args.figure_pct
    receipt = {
        "item": "M002",
        "result": "pass" if ok else "fail",
        "off_ms": round(off_ms, 1),
        "on_ms": round(on_ms, 1),
        "delta_pct": round(delta_pct, 2),
        "tap_cpu_pct": round(cpu_pct, 3),
        "figure_pct": args.figure_pct,
        "workload": {"frames": args.frames, "repeats": args.repeats},
    }
    print(json.dumps(receipt))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
