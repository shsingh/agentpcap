//! Collector crate: the C003 pipe collector's userspace half.
//!
//! The eBPF probe (`syscalls:sys_enter_write` plus `sys_enter_writev`)
//! pushes one [`PipeSample`] per system write into the `pipe-events`
//! queue. This crate holds the userspace half of spec docs/spec.md
//! section 5: the wire format and the verdict decision for one sample,
//! and section 6: the classification.

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

/// The wire format of one queued pipe write sample.
///
/// Layout-locked at compile time on both sides: the probe push side and
/// this crate. A change here is a wire-format change and lands with
/// cells, never silently.
#[derive(Debug, Clone, Copy)]
#[repr(C, align(8))]
pub struct PipeSample {
    /// The writing thread's process id.
    pub pid: u32,
    /// Reserved for the lineage ask (P003): the writer's parent pid.
    pub ppid: u32,
    /// Payload bytes carried in `first_bytes`.
    pub len: u32,
    /// The writer's file descriptor (the write syscall's first argument).
    pub fd: u32,
    /// The first payload bytes of the write buffer.
    pub first_bytes: [u8; 256],
}

// SAFETY: the struct is POD (fixed size, no padding-sensitive fields in
// use) and the wire layout is const-locked; aya reads it by value.
unsafe impl aya::Pod for PipeSample {}

pub const PAYLOAD_BYTES_CAP: usize = 256;

/// The parent-pid cache: a pid resolved recently, cached with the time
/// of the resolution. The caller drops stale entries.
pub type ParentCache = std::collections::HashMap<u32, (u32, std::time::Instant)>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentCacheEntry {
    pub pid: u32,
    pub ppid: u32,
    pub resolved_at: std::time::Instant,
}

impl ParentCacheEntry {
    pub fn fresh(&self, ttl: Duration) -> bool {
        self.resolved_at.elapsed() <= ttl
    }
}

use std::time::Duration;

/// Resolve the parent pid of `pid` through `/proc/<pid>/status` (the
/// `PPid` line) and cache the answer for `ttl`. A process that has
/// exited resolves to `0`; the cache entry drops. The cache answers
/// without consulting `/proc` until the entry expires, so an exited
/// child's parent persists until then — exit-sensitive callers ask
/// after the expiry, not before.
pub fn resolve_parent(pid: u32, cache: &mut ParentCache, ttl: Duration) -> u32 {
    if let Some(cached) = cache.get(&pid) {
        if cached.1.elapsed() <= ttl {
            return cached.0;
        }
    }
    let ppid = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|l| l.strip_prefix("PPid:").map(|v| v.trim().to_string()))
                .and_then(|v| v.parse::<u32>().ok())
        })
        .unwrap_or(0);
    if ppid == 0 {
        cache.remove(&pid);
    } else {
        cache.insert(pid, (ppid, std::time::Instant::now()));
    }
    ppid
}

const _: () = assert!(core::mem::size_of::<PipeSample>() == 272);

const SAMPLE_BYTES_CAP: usize = 256;

/// Classify one captured pipe write sample.
///
/// Inputs are one probe event: the writer pid, the writer's parent pid (the
/// lineage ask: the client holds the spawned MCP server as a child), the
/// writer's `comm`, and the first bytes of the write buffer. The sample
/// carries at most `SAMPLE_BYTES_CAP` bytes (sample-first-N-bytes policy).
///
/// Contract: a complete line with `"jsonrpc": "2.0"` plus an MCP method name
/// (`initialize`, `tools/list`, `tools/call`, or one of the
/// `notifications/*` shapes) classifies [`Decision::Mcp`]; non-ASCII binary
/// bytes with no JSON object classify [`Decision::Other`]; everything else,
/// including a sample with no complete line, classifies
/// [`Decision::AgentUnidentified`] (the safe form).
pub fn classify_pipe_sample(pid: u32, ppid: u32, comm: &str, first_bytes: &[u8]) -> Decision {
    let _ = (pid, ppid, comm, SAMPLE_BYTES_CAP);

    let sample = String::from_utf8_lossy(first_bytes);

    // The first JSON object in the sample; a parse failure at one start
    // position is not a verdict, the sample may hold the object later.
    let start = match sample.find('{') {
        Some(i) => i,
        None => {
            // No JSON shape at all. Non-ASCII bytes are binary traffic.
            return if sample.bytes().any(|b| !b.is_ascii()) {
                Decision::Other
            } else {
                Decision::AgentUnidentified
            };
        }
    };
    let candidate = &sample[start..];
    let object = match serde_json::from_str::<serde_json::Value>(candidate) {
        Ok(v) => v,
        // A truncated sample (sample-first-N-bytes) must not guess.
        Err(_) => {
            return if sample.starts_with('{') {
                Decision::AgentUnidentified
            } else {
                Decision::AgentUnidentified
            };
        }
    };
    let Some(obj) = object.as_object() else {
        return Decision::AgentUnidentified;
    };
    if obj.get("jsonrpc").and_then(|j| j.as_str()) != Some("2.0") {
        return Decision::AgentUnidentified;
    }
    match obj.get("method").and_then(|m| m.as_str()) {
        Some("initialize") | Some("tools/list") | Some("tools/call") => Decision::Mcp,
        Some(m) if m.starts_with("notifications/") => Decision::Mcp,
        _ => Decision::AgentUnidentified,
    }
}
