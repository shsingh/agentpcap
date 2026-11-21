//! Collector crate: the C003 pipe collector's userspace match contract.
//!
//! The eBPF probe (aya, `syscalls:sys_enter_write` plus `sys_enter_writev`)
//! feeds one pipe sample per event. This crate holds the userspace half of
//! spec docs/spec.md section 5: the verdict decision for one sample.
//!
//! RED state: `classify_pipe_sample` is `unimplemented!()` on purpose. The
//! RED test draft `tests/p001_red.rs` fails on the missing match function
//! only. The alpha1 collector slice implements the function body and turns
//! the draft green.

/// The record verdict for one captured pipe sample, per spec section 6.
///
/// The build carries the three first-verdict forms only. The `a2a` verdict
/// waits for the A2A collector slice and does not appear here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Decision {
    /// The sample carries MCP JSON-RPC framing: verdict `mcp`.
    Mcp,
    /// The sample looks agent-shaped but carries no MCP framing:
    /// verdict `agent-unidentified` (spec section 6).
    AgentUnidentified,
    /// The sample carries no agent shape: verdict `other`.
    Other,
}

const SAMPLE_BYTES_CAP: usize = 256;

/// Classify one captured pipe write sample.
///
/// Inputs are one probe event: the writer pid, the writer's parent pid (the
/// lineage ask: the client holds the spawned MCP server as a child), the
/// writer's `comm`, and the first bytes of the write buffer. The sample
/// carries at most `SAMPLE_BYTES_CAP` bytes (sample-first-N-bytes policy).
///
/// Contract (RED until the alpha1 slice implements it):
/// a complete line with `"jsonrpc": "2.0"` plus an MCP method name
/// (`initialize`, `tools/list`, `tools/call`, or one of the
/// `notifications/*` shapes) classifies [`Decision::Mcp`]; non-JSON binary
/// bytes classify [`Decision::Other`]; everything else, including a sample
/// with no complete line, classifies [`Decision::AgentUnidentified`].
///
/// # Panics
///
/// Panics until the alpha1 collector slice implements the match function.
pub fn classify_pipe_sample(pid: u32, ppid: u32, comm: &str, first_bytes: &[u8]) -> Decision {
    // P001/P002 cell. The lineage inputs (pid, ppid, comm) and the framing
    // scan over `first_bytes` set the Decision. Body lands with alpha1.
    let _ = (pid, ppid, comm, SAMPLE_BYTES_CAP, first_bytes);
    unimplemented!(
        "P001 RED: classify_pipe_sample is the alpha1 match function; tests/p001_red.rs fails here"
    )
}
