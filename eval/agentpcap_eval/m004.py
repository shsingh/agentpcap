"""M004 — ledger fidelity on capability drift (spec section 13).

One full M-item end to end, cell-level: ONE real capture session whose
server re-scopes mid-flight — the tool set changes (one description
changed, one tool added, one removed) and the capability face changes.
The harness slices the capture at the change point into the before and
after sets (the export-surface face), then the CLI diff answers the
drift events. The seeded expectation compares kind-for-kind:
`tool-description-changed`, `tools-added`, `tools-removed`,
`server-rescoped`, with the seeded description texts. Harness overhead
stays out of the tap's measurement path: the receipt carries no tap
timing.
"""

import argparse
import json
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
    "tool-description-changed",
    "tools-added",
    "tools-removed",
    "server-rescoped",
]


def split_ledger(records, split_index, ledger):
    """Slice the capture at the change point: the before set rides every
    record through the last pre-change face; the after set rides the
    changed faces onward. Each side stays a valid JSONL ledger."""
    lines = ledger.read_text().splitlines()
    before = Path(str(ledger) + ".before")
    after = Path(str(ledger) + ".after")
    after.write_text("\n".join(lines[split_index:]) + "\n")
    before.write_text("\n".join(lines[:split_index]) + "\n")
    del records
    return before, after


def drift_diff(binary, before, after):
    """The CLI face: diff on the two sliced ledger sets, one JSON event
    per line."""
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


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--window", type=int, default=8)
    args = ap.parse_args(argv)

    binary = str(Path(args.binary))
    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)

    spec = ServerSpec(
        tools_by_call=[TOOLS_V1, TOOLS_V2],
        capabilities_by_call=[CAP_V1, CAP_V2],
        tool_result=TOOL_RESULT,
    )
    ledger, records = run_scenario(binary, workdir, "m004", args.window, spec)

    # the change point: the merged initialize record whose request id is
    # 4 (the second initialize re-arms the capability face) — the before
    # slice carries the pre-change faces, the after slice carries init_2
    # and the changed tool set
    split_index = None
    for i, r in enumerate(records):
        if (
            r.get("event") == "init"
            and str(r.get("payload", {}).get("request", {}).get("id")) == "4"
        ):
            split_index = i
            break
    if split_index is None:
        receipt = {
            "item": "M004",
            "result": "fail",
            "reason": "the re-scoped initialize record never landed",
        }
        print(json.dumps(receipt))
        return 1

    before, after = split_ledger(records, split_index, ledger)
    events = drift_diff(binary, before, after)
    kinds = sorted(e["kind"] for e in events)
    read = descriptions(events).get("read", {})

    ok = (
        kinds == sorted(SEEDED_KINDS)
        and read.get("before") == "read a file"
        and read.get("after") == "read a file v2"
    )
    receipt = {
        "item": "M004",
        "result": "pass" if ok else "fail",
        "diff": {"kinds": kinds, "descriptions": {"read": read}},
    }
    print(json.dumps(receipt))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
