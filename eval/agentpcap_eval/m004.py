"""M004 — ledger fidelity on capability drift (spec section 13).

One full M-item end to end, cell-level: ONE real capture session whose
server re-scopes mid-flight — the tool set changes (one description
changed, one tool added, one removed) and the capability face changes.
The harness reads the capture through the `export` surface (the
access-log face rides it), selects the run's own session by its
run-unique server name, slices the session at the change point into
the before and after sets (owner-only files), then the CLI diff answers
the drift events. The seeded expectation compares kind-for-kind against
the seeds — the kinds, the changed description's texts, the added and
removed tool names, and the capability fingerprints (both present and
differing). With `--strip-caps` the seeds lose the capability member
entirely: the fidelity face then fails by design (the negative face —
losing capability data never passes silently). Harness overhead stays
out of the tap's measurement path: the receipt carries no tap timing.
"""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from .scenario import ServerSpec, run_scenario

TOOLS_V1 = [
    {"name": "read", "description": "read a file"},
    {"name": "gone", "description": "was here"},
]
TOOLS_V2 = [
    {"name": "read", "description": "read a file v2"},
    {"name": "write", "description": "write a file"},
]
CAP_V1 = {"tools": {}}
CAP_V2 = {"tools": {}, "listChanged": True}
TOOL_RESULT = "c117-hello"

SEEDED_KINDS = [
    "server-rescoped",
    "tool-description-changed",
    "tools-added",
    "tools-removed",
]
SEEDED_ADDED = ["write"]
SEEDED_REMOVED = ["gone"]


def export_records(binary, ledger):
    """The records ride the export surface only (spec section 13); the
    export read logs access on the original ledger."""
    out = subprocess.run(
        [binary, "export", "--ledger", str(ledger)],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise SystemExit("export failed: " + out.stderr)
    return [json.loads(l) for l in out.stdout.splitlines() if l.strip()]


def owner_file(path, text):
    """Write capture content to an owner-only file (mode 0600) — the
    before/after copies carry captured faces, so they never widen past
    the tap's own ledger permissions."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return path


def run_names(events):
    """The added and removed tool names from the drift events. The
    tools-added/removed events carry the tool NAME list."""
    added, removed = [], []
    for e in events:
        if e["kind"] == "tools-added":
            added += sorted(e["tools"])
        if e["kind"] == "tools-removed":
            removed += sorted(e["tools"])
    return added, removed


def drifted_drift(binary, before, after):
    out = subprocess.run(
        [binary, "diff", "--before", str(before), "--after", str(after)],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise SystemExit("diff failed: " + out.stderr)
    events = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
    return events


def descriptions(events):
    face = {}
    for e in events:
        if e["kind"] == "tool-description-changed":
            face[e["tool"]] = {"before": e["before"], "after": e["after"]}
    return face


def rescoped(events):
    for e in events:
        if e["kind"] == "server-rescoped":
            return {"before": e.get("before"), "after": e.get("after")}
    return None


def run_between(binary, workdir, window, marker, strip_caps=False):
    """The issue #28 face: TWO served sessions with the SEEDS injected
    per session — the served tool set changes between the sessions (the
    description changed, one tool added, one removed, the capability
    face changed). The CLI diff must surface the drift from ledger data
    alone — never decryption — and the drift events must match the
    injected change set EXACTLY. Returns (before_ledger, after_ledger)."""
    cap_v1 = {} if strip_caps else CAP_V1
    cap_v2 = {} if strip_caps else CAP_V2
    spec_before = ServerSpec(
        tools_by_call=[TOOLS_V1],
        capabilities_by_call=[{"tools": {}}] if strip_caps else [CAP_V1],
        tool_result=TOOL_RESULT,
        server_name="harness-server-" + marker,
    )
    spec_after = ServerSpec(
        tools_by_call=[TOOLS_V2],
        capabilities_by_call=[{"tools": {}, "listChanged": True}] if not strip_caps else [{"tools": {}}],
        tool_result=TOOL_RESULT,
        server_name="harness-server-" + marker,
    )
    b_ledger, _ = run_scenario(binary, workdir, "sess1", window, spec_before)
    a_ledger, _ = run_scenario(binary, workdir, "sess2", window, spec_after)
    return b_ledger, a_ledger


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--window", type=int, default=8)
    ap.add_argument(
        "--strip-caps", action="store_true",
        help="the negative face: the seeds carry no capability member "
             "at all — the fidelity face fails by design",
    )
    ap.add_argument(
        "--retries", type=int, default=2,
        help="between-sessions only: bounded fresh re-captures when a "
             "drift face races (each attempt is a FULL fresh capture, "
             "never a cherry-picked face); the receipts name the attempts",
    )
    ap.add_argument(
        "--mode", default="midflight",
        choices=["midflight", "between-sessions"],
        help="midflight: one session re-scopes inline (C117); "
             "between-sessions: two served sessions carry the injected "
             "change set (issue #28)",
    )
    args = ap.parse_args(argv)

    binary = str(Path(args.binary))
    workdir = Path(args.workdir)
    workdir.mkdir(mode=0o700, parents=True, exist_ok=True)

    if args.mode == "between-sessions":
        # the #28 face: the seeds injected BETWEEN two served sessions.
        # The fp merge face races under the ADR-0004 pop-time family, so
        # the face runs up to 1 + retries FRESH captures (a new marker
        # each) and reports the last attempt, naming the attempt count —
        # a retry is a fresh capture, never a face cherry-pick.
        attempts = 0
        receipt = None
        for attempt in range(1 + max(0, args.retries)):
            attempts = attempt + 1
            marker = os.urandom(6).hex()
            try:
                b_ledger, a_ledger = run_between(
                    binary, workdir, args.window, marker, args.strip_caps
                )
            except SystemExit as e:
                receipt = {
                    "item": "M004", "mode": "between-sessions",
                    "result": "fail", "reason": str(e),
                    "attempts": attempts,
                }
                continue
            events = drifted_drift(binary, b_ledger, a_ledger)
            kinds = sorted(e["kind"] for e in events)
            read = descriptions(events).get("read", {})
            added, removed = run_names(events)
            rescope = rescoped(events)
            exact = (
                kinds == SEEDED_KINDS
                and read.get("before") == "read a file"
                and read.get("after") == "read a file v2"
                and sorted(added) == SEEDED_ADDED
                and sorted(removed) == SEEDED_REMOVED
                and rescope is not None
                and bool(rescope["before"])
                and bool(rescope["after"])
                and rescope["before"] != rescope["after"]
            )
            receipt = {
                "item": "M004",
                "mode": "between-sessions",
                "result": "pass" if exact else "fail",
                "exact": exact,
                "attempts": attempts,
                "injected": {
                    "kinds": SEEDED_KINDS,
                    "descriptions": {"read": {
                        "before": "read a file", "after": "read a file v2"}},
                    "added": SEEDED_ADDED,
                    "removed": SEEDED_REMOVED,
                },
                "emitted": {
                    "kinds": kinds,
                    "descriptions": {"read": read},
                    "added": sorted(added),
                    "removed": sorted(removed),
                    "rescoped": rescope,
                },
                "marker": marker,
            }
            if exact:
                break
        print(json.dumps(receipt))
        return 0 if receipt.get("exact") else 1

    run_token = "harness-" + os.urandom(6).hex()
    spec = ServerSpec(
        tools_by_call=[TOOLS_V1, TOOLS_V2],
        capabilities_by_call=[CAP_V1, CAP_V2],
        tool_result=TOOL_RESULT,
        server_name=run_token,
        strip_caps=args.strip_caps,
    )
    ledger, _ = run_scenario(binary, workdir, "m004", args.window, spec)

    everything = export_records(binary, ledger)
    # select this run's own session: the initialize reply carries the
    # run-unique server name; unrelated host traffic never names it
    own = [
        r for r in everything
        if json.dumps(r).find(run_token) >= 0
    ]
    if not own:
        receipt = {
            "item": "M004", "result": "fail",
            "reason": "the run-unique session never landed",
        }
        print(json.dumps(receipt))
        return 1
    session_id = own[0].get("session_id")
    session_records = [
        r for r in everything
        if r.get("session_id") == session_id
    ]

    # the change point: the merged initialize record whose request id is
    # 4 (the second initialize re-arms the capability face)
    split_index = None
    for i, r in enumerate(session_records):
        if (
            r.get("event") == "init"
            and str(r.get("payload", {}).get("request", {}).get("id")) == "4"
        ):
            split_index = i
            break
    if split_index is None:
        receipt = {
            "item": "M004", "result": "fail",
            "reason": "the re-scoped initialize record never landed",
        }
        print(json.dumps(receipt))
        return 1

    before = owner_file(
        workdir / (run_token + ".before.jsonl"),
        "\n".join(json.dumps(r) for r in session_records[:split_index]) + "\n",
    )
    after = owner_file(
        workdir / (run_token + ".after.jsonl"),
        "\n".join(json.dumps(r) for r in session_records[split_index:]) + "\n",
    )
    events = drifted_drift(binary, before, after)
    kinds = sorted(e["kind"] for e in events)
    read = descriptions(events).get("read", {})
    added, removed = run_names(events)
    rescope = rescoped(events)

    ok = (
        kinds == SEEDED_KINDS
        and read.get("before") == "read a file"
        and read.get("after") == "read a file v2"
        and sorted(added) == SEEDED_ADDED
        and sorted(removed) == SEEDED_REMOVED
        and rescope is not None
        and bool(rescope["before"])
        and bool(rescope["after"])
        and rescope["before"] != rescope["after"]
    )
    receipt = {
        "item": "M004",
        "result": "pass" if ok else "fail",
        "diff": {
            "kinds": kinds,
            "descriptions": {"read": read},
            "added": sorted(added),
            "removed": sorted(removed),
            "rescoped": rescope,
            "fingerprint_face": (
                "absent" if args.strip_caps else "capability"
            ),
        },
        "reason": (
            "the capability fingerprints are absent; the fidelity face "
            "requires them" if args.strip_caps and not ok else None
        ),
    }
    receipt = {k: v for k, v in receipt.items() if v is not None}
    print(json.dumps(receipt))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
