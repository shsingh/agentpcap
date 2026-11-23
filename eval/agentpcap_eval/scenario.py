"""The scenario runner (spec section 13).

One scenario = one real tap + one stdio MCP server (a pipe-paired
child) whose replies carry the seeded faces. The harness plays the
client: the frames sequence the seeded tool sets and capability faces.
The ledger and the parsed records return. The harness consumes only
the CLI surfaces.
"""

import json
import time


class ServerSpec:
    """The seeded server faces: per-call-count tool sets and capability
    faces, and a run-unique server name. The server answers from its
    counters — the re-scope faces mid-capture, exactly the operator
    shape M004 measures. `strip_caps` rides the negative face: the
    initialize replies carry no capability member at all."""

    def __init__(self, tools_by_call, capabilities_by_call, tool_result,
                 server_name, strip_caps=False):
        self.tools_by_call = tools_by_call
        self.capabilities_by_call = capabilities_by_call
        self.tool_result = tool_result
        self.server_name = server_name
        self.strip_caps = strip_caps


def server_script(spec):
    """Build the counting stdio server. Plain concatenation for the
    reply templates — a template over JSON braces eats literal braces."""
    lines = [
        "#!/usr/bin/env python3",
        "import json, sys",
        "TOOLS_BY_CALL = " + repr(spec.tools_by_call),
        "CAPS_BY_CALL = " + repr(spec.capabilities_by_call),
        "TOOL_RESULT = " + repr(spec.tool_result),
        "SERVER_NAME = " + repr(spec.server_name),
        "STRIP_CAPS = " + repr(spec.strip_caps),
        "lists = 0",
        "inits = 0",
        "for line in sys.stdin:",
        "    line = line.strip()",
        "    if not line:",
        "        continue",
        "    try:",
        "        obj = json.loads(line)",
        "    except Exception:",
        "        continue",
        '    m = obj.get("method")',
        '    if m == "initialize":',
        "        caps = CAPS_BY_CALL[min(inits, len(CAPS_BY_CALL) - 1)]",
        "        inits += 1",
        '        result = {"protocolVersion":"2025-06-18"}',
        "        if not STRIP_CAPS:",
        '            result["capabilities"] = caps',
        '        result["serverInfo"] = {"name":SERVER_NAME,"version":"0"}',
        "        reply = {\"jsonrpc\":\"2.0\",\"id\":obj[\"id\"],\"result\":result}",
        "        print(json.dumps(reply), flush=True)",
        '    elif m == "tools/list":',
        "        tools = TOOLS_BY_CALL[min(lists, len(TOOLS_BY_CALL) - 1)]",
        "        lists += 1",
        "        reply = {\"jsonrpc\":\"2.0\",\"id\":obj[\"id\"],\"result\":"
        '{"tools":tools}}',
        "        print(json.dumps(reply), flush=True)",
        '    elif m == "tools/call":',
        "        reply = {\"jsonrpc\":\"2.0\",\"id\":obj[\"id\"],\"result\":"
        '{"content":[{"type":"text","text":TOOL_RESULT}]}}',
        "        print(json.dumps(reply), flush=True)",
    ]
    return "\n".join(lines) + "\n"


INIT_1 = (
    '{"jsonrpc":"2.0","id":1,"method":"initialize","params":'
    '{"protocolVersion":"2025-06-18","capabilities":{},'
    '"clientInfo":{"name":"harness-client","version":"0"}}}'
)
LIST_1 = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
CALL = (
    '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":'
    '{"name":"read","arguments":{"path":"/etc/hostname"}}}'
)
INIT_2 = (
    '{"jsonrpc":"2.0","id":4,"method":"initialize","params":'
    '{"protocolVersion":"2025-06-18","capabilities":{},'
    '"clientInfo":{"name":"harness-client","version":"0"}}}'
)
LIST_2 = '{"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}}'


def run_scenario(binary, workdir, name, window, spec):
    """One M004 scenario: the tap over a real stdio exchange whose
    server re-scopes mid-flight. Returns (ledger_path, records)."""

    import subprocess  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    ledger = workdir / (name + ".jsonl")
    if ledger.exists():
        raise SystemExit(
            "the harness refuses a reused workdir: the capture at "
            + str(ledger) + " belongs to another run"
        )
    script = workdir / (name + "-server.py")
    Path(script).write_text(server_script(spec))

    tap = subprocess.Popen(
        [binary, "tap", "--ledger", str(ledger), "--duration", str(window)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    tap_err = tap.stderr
    try:
        # wait out the tap's calibration: the ledger writer exists after it
        time.sleep(1.2)

        server = subprocess.Popen(
            ["python3", str(script)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )

        # the frame order: init1, list1, call, [pause], init2, list2 —
        # the second initialize re-arms the session's capability face,
        # the second list rides the changed tool set (the operator shape)
        frames = [INIT_1, LIST_1, CALL]
        try:
            for f in frames:
                server.stdin.write((f + "\n").encode())
                server.stdin.flush()
                time.sleep(0.3)
            time.sleep(0.8)
            for f in [INIT_2, LIST_2]:
                server.stdin.write((f + "\n").encode())
                server.stdin.flush()
                time.sleep(0.3)
            # the writer stays alive past the pop window: the ADR-0004
            # fd resolve face at pop needs the writer's fds, and a writer
            # that dies inside the window keys the ADR-0004 race face —
            # the fidelity item needs the resolved faces, not the race
            time.sleep(1.5)
        except BrokenPipeError:
            pass
        try:
            server.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()

        # the tap's window runs out; the drain lands the parked samples
        tap.wait(timeout=window + 30)

        # spec section 13: the records ride the EXPORT surface; the read
        # also logs access on the original ledger (the access-log face)
        out = subprocess.run(
            [binary, "export", "--ledger", str(ledger)],
            capture_output=True, text=True,
        )
        if out.returncode != 0:
            raise SystemExit("export failed: " + out.stderr)
        records = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
        return ledger, records
    finally:
        if tap.poll() is None:
            tap.kill()
        if tap_err:
            tap_err.close()
