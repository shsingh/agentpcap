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
    faces. The server answers from its counters — the re-scope faces
    mid-capture, exactly the operator shape M004 measures."""

    def __init__(self, tools_by_call, capabilities_by_call, tool_result):
        self.tools_by_call = tools_by_call
        self.capabilities_by_call = capabilities_by_call
        self.tool_result = tool_result


def server_script(spec):
    """Build the counting stdio server. Plain concatenation for the
    reply templates — a template over JSON braces eats literal braces."""
    lines = [
        "#!/usr/bin/env python3",
        "import json, sys",
        "TOOLS_BY_CALL = " + repr(spec.tools_by_call),
        "CAPS_BY_CALL = " + repr(spec.capabilities_by_call),
        "TOOL_RESULT = " + repr(spec.tool_result),
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
        "        reply = {\"jsonrpc\":\"2.0\",\"id\":obj[\"id\"],\"result\":"
        '{"protocolVersion":"2025-06-18","capabilities":caps,'
        '"serverInfo":{"name":"harness-server","version":"0"}}}',
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

        text = Path(ledger).read_text()
        records = [json.loads(l) for l in text.splitlines() if l.strip()]
        return ledger, records
    finally:
        if tap.poll() is None:
            tap.kill()
        if tap_err:
            tap_err.close()
