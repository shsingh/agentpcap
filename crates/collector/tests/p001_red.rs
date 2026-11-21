// P001 — the pipe collector's userspace match contract. Spec §5 (C003) and
// §6 (classification from protocol semantics). RED draft: the tests fail on
// the `unimplemented!()` `classify_pipe_sample` body only. The alpha1 slice
// implements the match function and turns this cell green.

use agentpcap_collector::{classify_pipe_sample, Decision};

const SERVER_PID: u32 = 4242; // the spawned MCP server process
const CLIENT_PID: u32 = 1000; // the client that launched it

// P001.1 — initialize request framing classifies Mcp. The line carries the
// JSON-RPC envelope and the `initialize` method name.
fn initialize_request_sample() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"0"}}}"#
        .to_vec()
}

// P001.2 — tools/list request framing classifies Mcp.
fn tools_list_sample() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#.to_vec()
}

// P001.3 — tools/call request framing classifies Mcp.
fn tools_call_sample() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_file","arguments":{}}}"#
        .to_vec()
}

// P001.4 — an MCP JSON-RPC notification (no id) still carries the framing
// and classifies Mcp. The contract names the notifications/* shapes.
fn notification_sample() -> Vec<u8> {
    br#"{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}"#.to_vec()
}

#[test]
fn p001_initialize_request_is_mcp() {
    let d = classify_pipe_sample(SERVER_PID, CLIENT_PID, "mcp-server", &initialize_request_sample());
    assert_eq!(d, Decision::Mcp);
}

#[test]
fn p001_tools_list_request_is_mcp() {
    let d = classify_pipe_sample(SERVER_PID, CLIENT_PID, "mcp-server", &tools_list_sample());
    assert_eq!(d, Decision::Mcp);
}

#[test]
fn p001_tools_call_request_is_mcp() {
    let d = classify_pipe_sample(SERVER_PID, CLIENT_PID, "mcp-server", &tools_call_sample());
    assert_eq!(d, Decision::Mcp);
}

#[test]
fn p001_jsonrpc_notification_is_mcp() {
    let d = classify_pipe_sample(SERVER_PID, CLIENT_PID, "mcp-server", &notification_sample());
    assert_eq!(d, Decision::Mcp);
}

// P001.5 — non-JSON binary bytes (a sample with no JSON start byte and no
// framing evidence) classify Other.
#[test]
fn p001_binary_payload_is_other() {
    let d = classify_pipe_sample(SERVER_PID, CLIENT_PID, "mcp-server", &[0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]);
    assert_eq!(d, Decision::Other);
}

// P001.6 — JSON that carries a "jsonrpc" key but none of the named MCP
// method shapes is agent-shaped without MCP framing: the verdict is
// agent-unidentified (spec §6: the classifier binds evidence, not a catalog).
#[test]
fn p001_json_without_mcp_method_is_agent_unidentified() {
    let d = classify_pipe_sample(
        SERVER_PID,
        CLIENT_PID,
        "mcp-server",
        br#"{"jsonrpc":"2.0","id":7,"method":"other/domain","params":{}}"#,
    );
    assert_eq!(d, Decision::AgentUnidentified);
}

// P001.7 — plain text with no JSON framing classifies agent-unidentified.
#[test]
fn p001_plain_text_without_framing_is_agent_unidentified() {
    let d = classify_pipe_sample(SERVER_PID, CLIENT_PID, "mcp-server", b"ready\n");
    assert_eq!(d, Decision::AgentUnidentified);
}

// P001.8 — a sample cut inside the line (sample-first-N-bytes policy) has no
// complete framing line: the verdict is agent-unidentified, the safe form.
#[test]
fn p001_partial_line_without_framing_is_agent_unidentified() {
    let d = classify_pipe_sample(SERVER_PID, CLIENT_PID, "mcp-server", &tools_list_sample()[..12]);
    assert_eq!(d, Decision::AgentUnidentified);
}
