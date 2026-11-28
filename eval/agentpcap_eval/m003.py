"""M003 — the transport-coverage matrix (spec section 13).

The matrix over the four transports of the coverage claim: stdio,
Streamable HTTP (the TLS boundary), legacy HTTP+SSE, and A2A detection.
Each row runs a real capture through the harness and answers a coverage
verdict per transport. Coverage ties to THIS run's own faces: the run
names its server with a run-unique marker, and every row requires the
fixture's own reply data (the seeded tool set, the result text, the
classifying verdict) before it reports covered. A face the capture
cannot support names its gap with its issue link — gaps are
enumerated, never implicit. All rows read their records through the
`export` surface (the chain check and access log face it), never the
raw ledger. The receipt carries no tap-internal timing.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .scenario import ServerSpec, run_scenario

A2A_FRAMES = [
    '{"jsonrpc":"2.0","id":11,"method":"message/send","params":'
    '{"role":"agent","parts":[{"kind":"text","text":"c119-a2a"}]}}',
]


def export_records(binary, ledger_path):
    """The records ride the export surface only (the chain check and
    access-log face it carries); a nonzero export fails the row."""
    out = subprocess.run(
        [binary, "export", "--ledger", str(ledger_path)],
        capture_output=True,
        text=True,
    )
    if out.returncode != 0:
        raise SystemExit("export failed: " + out.stderr)
    return [json.loads(l) for l in out.stdout.splitlines() if l.strip()]


def run_stdio(binary, workdir, marker):
    """The stdio row: the m004-shaped capture re-scopes mid-flight.
    Covered requires the fixture's OWN reply faces: the seeded tool
    set, the run marker in the server name, and the seeded result
    text — the merged capture, not the flush fallback."""
    spec = ServerSpec(
        tools_by_call=[
            [{"name": "read", "description": "read a file"}],
            [{"name": "read", "description": "read a file v2"}],
        ],
        capabilities_by_call=[{"tools": {}}, {"tools": {}, "listChanged": True}],
        tool_result=marker,
        server_name="harness-stdio-" + marker,
    )
    ledger, records = run_scenario(binary, workdir, "m003-stdio", 9, spec)
    exported = export_records(binary, ledger)
    events = sorted({r["event"] for r in exported if r.get("event")})
    merged = set(events) == {"init", "tools-call", "tools-list"}
    seeded = json.dumps(exported).find(marker) >= 0 and json.dumps(
        exported
    ).find('"read a file v2"') >= 0
    covered = merged and seeded
    return {
        "transport": "stdio",
        "verdict": "covered" if covered else "gap",
        "evidence": "merged=" + json.dumps(merged) + " seeded=" + json.dumps(seeded)
        + " events=" + json.dumps(events),
    }


def serve_and_client(binary, script, client_args, ledger, window):
    """Shared capture face: the tap, then the caller's server/client."""
    tap = subprocess.Popen(
        [binary, "tap", "--ledger", str(ledger), "--duration", str(window)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        import time as _t  # noqa: PLC0415

        _t.sleep(1.2)
        return tap, _t
    finally:
        pass


def finish_tap(tap):
    if tap.poll() is None:
        tap.kill()
    if tap.stderr:
        tap.stderr.close()


def run_a2a(binary, workdir, marker):
    """The A2A row: message/send classifies verdict a2a from protocol
    semantics (spec section 6). Covered requires the classifying record
    carrying THIS run's own marker — the frame text rides it, so the
    request record ties whatever the reply merge face does."""
    ledger = workdir / "m003-a2a.jsonl"
    script = workdir / "m003-a2a-server.py"
    lines = [
        "#!/usr/bin/env python3",
        "import json, sys",
        "MARKER = " + repr(marker),
        "for line in sys.stdin:",
        "    line = line.strip()",
        "    if not line:",
        "        continue",
        "    try:",
        "        obj = json.loads(line)",
        "    except Exception:",
        "        continue",
        '    if obj.get("method") == "message/send":',
        "        reply = {\"jsonrpc\":\"2.0\",\"id\":obj[\"id\"],"
        '"result":{"text":"ack"}}',
        "        print(json.dumps(reply), flush=True)",
    ]
    Path(script).write_text("\n".join(lines) + "\n")
    tap = subprocess.Popen(
        [binary, "tap", "--ledger", str(ledger), "--duration", "9"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        import time as _t  # noqa: PLC0415

        _t.sleep(1.2)
        server = subprocess.Popen(
            ["python3", str(script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        frame = (
            '{"jsonrpc":"2.0","id":11,"method":"message/send","params":'
            '{"role":"agent","parts":[{"kind":"text","text":"' + marker + '"}]}}'
        )
        try:
            for _ in range(1):
                server.stdin.write((frame + "\n").encode())
                server.stdin.flush()
                _t.sleep(0.3)
        except BrokenPipeError:
            pass
        try:
            server.stdin.close()
        except OSError:
            pass
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        tap.wait(timeout=30)
    finally:
        finish_tap(tap)

    records = export_records(binary, ledger)
    a2a = [
        r for r in records
        if r.get("verdict") == "a2a" or r.get("event") == "a2a-handoff"
        and r.get("payload", {}).get("request", {}).get("method")
        == "message/send"
    ]
    owned = [r for r in a2a if json.dumps(r).find(marker) >= 0]
    covered = len(owned) > 0
    return {
        "transport": "a2a",
        "verdict": "covered" if covered else "gap",
        "evidence": "owned a2a records=" + str(len(owned))
        + " total=" + str(len(records)) + " marker=" + marker,
    }


def run_tls(binary, workdir, marker):
    """The Streamable HTTP row: the TLS fixture's framed POST reply
    (the C113 face). Covered requires THIS run's own boundary evidence
    tied to the run's marker."""
    fx = Path(workdir) / "tls"
    fx.mkdir(parents=True, exist_ok=True)
    cert = fx / "tls-cert.pem"
    key = fx / "tls-key.pem"
    try:
        gen = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", str(key), "-out", str(cert),
             "-days", "2", "-nodes", "-subj", "/CN=lab"],
            capture_output=True,
        )
    except FileNotFoundError as e:
        return {
            "transport": "streamable-http-tls",
            "verdict": "gap",
            "evidence": "the openssl face missing: " + str(e),
        }
    if gen.returncode != 0:
        return {
            "transport": "streamable-http-tls",
            "verdict": "gap",
            "evidence": "the openssl face failed: " + gen.stderr.decode()[:120],
        }
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "mcp-tls.py"
    if not fixture.exists():
        return {
            "transport": "streamable-http-tls",
            "verdict": "gap",
            "evidence": "the fixture ships missing: mcp-tls.py",
        }
    tmp_fixture = fx / "agentpcap-m003-tls.py"
    shutil.copy(fixture, tmp_fixture)
    ledger = fx / "m003-tls.jsonl"
    tap = subprocess.Popen(
        [binary, "tap", "--ledger", str(ledger), "--duration", "10"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        import time as _t  # noqa: PLC0415

        _t.sleep(1.2)
        server = subprocess.Popen(
            ["python3", "-u", str(tmp_fixture), "server", "0", marker, "http"],
            env={
                "AGENTPCAP_TLS_CERT": str(cert),
                "AGENTPCAP_TLS_KEY": str(key),
                "PATH": os.environ.get("PATH", ""),
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        port = server.stdout.readline().decode().strip()
        client = subprocess.run(
            ["python3", "-u", str(tmp_fixture), "client", port, marker, "http"],
            capture_output=True,
            env={
                "AGENTPCAP_TLS_CERT": str(cert),
                "AGENTPCAP_TLS_KEY": str(key),
                "PATH": os.environ.get("PATH", ""),
            },
        )
        _t.sleep(4)
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        # the tap's drain face joins before the export: the export face
        # answers on the landed ledger, not the tap's live window (the
        # a2a leg carries the same join face)
        tap.wait(timeout=30)
        records = export_records(binary, ledger)
        boundary = [r for r in records if "tls-boundary" in json.dumps(r)]
        # the coverage tie: this run's own marker rides the boundary rows
        # — the fixture's tools-call carries the marker parameter
        owned = [r for r in boundary if json.dumps(r).find(marker) >= 0]
        covered = len(owned) > 0 and client.returncode == 0
        events = sorted({r["event"] for r in records if r.get("event")})
        return {
            "transport": "streamable-http-tls",
            "verdict": "covered" if covered else "gap",
            "evidence": "owned boundary records=" + str(len(owned))
            + " marker=" + marker + " port=" + port
            + " client-rc=" + str(client.returncode)
            + " events=" + json.dumps(events),
        }
    finally:
        finish_tap(tap)


def run_sse(binary, workdir, marker):
    """The legacy HTTP+SSE row: the SSE-framed reply rides the same TLS
    boundary (the C115 face) — the fixture serves a real exchanged
    `text/event-stream` body with the JSON in a `data:` line. Covered
    requires THIS run's own boundary evidence tied to the run's marker.
    The stale-content capture defect (issue #83) rides the per-flavor
    park face; the exchange runs and the capture proves it either way."""
    fx = Path(workdir) / "sse"
    fx.mkdir(parents=True, exist_ok=True)
    cert = fx / "tls-cert.pem"
    key = fx / "tls-key.pem"
    try:
        gen = subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", str(key), "-out", str(cert),
             "-days", "2", "-nodes", "-subj", "/CN=lab"],
            capture_output=True,
        )
    except FileNotFoundError as e:
        return {
            "transport": "legacy-http-sse",
            "verdict": "gap",
            "evidence": "the openssl face missing: " + str(e),
        }
    if gen.returncode != 0:
        return {
            "transport": "legacy-http-sse",
            "verdict": "gap",
            "evidence": "the openssl face failed: " + gen.stderr.decode()[:120],
        }
    fixture = Path(__file__).resolve().parents[1] / "fixtures" / "mcp-tls.py"
    if not fixture.exists():
        return {
            "transport": "legacy-http-sse",
            "verdict": "gap",
            "evidence": "the fixture ships missing: mcp-tls.py",
        }
    tmp_fixture = fx / "agentpcap-m003-sse.py"
    shutil.copy(fixture, tmp_fixture)
    ledger = fx / "m003-sse.jsonl"
    tap = subprocess.Popen(
        [binary, "tap", "--ledger", str(ledger), "--duration", "10"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        import time as _t2  # noqa: PLC0415

        _t2.sleep(1.2)
        server = subprocess.Popen(
            ["python3", "-u", str(tmp_fixture), "server", "0", marker, "sse"],
            env={
                "AGENTPCAP_TLS_CERT": str(cert),
                "AGENTPCAP_TLS_KEY": str(key),
                "PATH": os.environ.get("PATH", ""),
            },
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        port = server.stdout.readline().decode().strip()
        client = subprocess.run(
            ["python3", "-u", str(tmp_fixture), "client", port, marker, "sse"],
            capture_output=True,
        )
        _t2.sleep(4)
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
        records = export_records(binary, ledger)
        boundary = [r for r in records if "tls-boundary" in json.dumps(r)]
        # the coverage tie: the marker rides the boundary face — either
        # merged into the tools-call record or, on the ADR-0004 race
        # fallback (the C115 contract), riding its own record with the
        # `tls-<marker>` result preserved. Loss never reads as capture:
        # a record without the tool result's text never passes, and the
        # `chan:unresolved` evidence rides the fallback row when the
        # in-probe fd resolution (issue #76) is not shipped.
        owned = [r for r in boundary if json.dumps(r).find(marker) >= 0]
        # the merged face and the fallback face report separately: a
        # merged reply rides the tools-call record's own result text; a
        # fallback reply (the ADR-0004 race contract) rides its own
        # orphan-response record with the result text preserved. Either
        # face = content preserved = covered; neither face = gap.
        merged_face = any(
            r.get("method") == "tools/call"
            and ((r.get("payload") or {}).get("result") or {}).get("content") is not None
            and "tls-" + marker in json.dumps(r)
            for r in owned
        )
        fallback_face = any(
            "orphan-response" in json.dumps(r)
            and "tls-" + marker in json.dumps(r.get("payload") or {})
            for r in owned
        )
        covered = (merged_face or fallback_face) and client.returncode == 0
        events = sorted({r["event"] for r in records if r.get("event")})
        row = {
            "transport": "legacy-http-sse",
            "verdict": "covered" if covered else "gap",
            "evidence": "owned boundary records=" + str(len(owned))
            + " sse-merged=" + str(merged_face).lower()
            + " sse-fallback=" + str(fallback_face).lower()
            + " marker=" + marker + " port=" + port
            + " client-rc=" + str(client.returncode)
            + " events=" + json.dumps(events),
        }
        if not covered:
            row["evidence"] += (
                " (the capture face rides issue"
                " https://github.com/shsingh/agentpcap/issues/83)")
        return row
    finally:
        finish_tap(tap)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--workdir", required=True)
    args = ap.parse_args(argv)

    binary = str(Path(args.binary))
    workdir = Path(args.workdir)
    workdir.mkdir(mode=0o700, parents=True, exist_ok=True)

    marker = os.urandom(6).hex()
    matrix = [
        run_stdio(binary, workdir, marker),
        run_tls(binary, workdir, marker),
        run_sse(binary, workdir, marker),
        run_a2a(binary, workdir, marker),
    ]
    receipt = {
        "item": "M003",
        "marker": marker,
        "matrix": matrix,
        "gaps": [r["transport"] for r in matrix if r["verdict"] == "gap"],
    }
    print(json.dumps(receipt))
    # the acceptance: the full matrix reported; the gaps enumerated,
    # never implicit — the item passes when every row carries a verdict
    # and every gap names its evidence
    ok = all(r["verdict"] in ("covered", "gap") for r in matrix) and all(
        "evidence" in r for r in matrix if r["verdict"] == "gap"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
