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

/// Resolve a socket fd's canonical five-tuple face (ADR-0005): the
/// writer's `/proc/<pid>/fd/<fd>` names `socket:[<inode>]`; the inode
/// looks its endpoints up in `/proc/net/tcp` (and `tcp6`, `udp`),
/// where one connection lists once per process, each with its own
/// socket inode; the peer is the canonical sorted endpoint pair,
/// identical for both directions of one connection.
/// One resolved connection face: the canonical five-tuple and the
/// transport the observation rides (the resolver names the table, not
/// the tap's guess — a UDP connection is never tcp).
#[derive(Clone)]
pub struct SocketPeer {
    pub transport: &'static str,
    /// The connection key: the network namespace rides it — two
    /// containers with identical loopback faces never share a key.
    pub peer: String,
    /// The process's own endpoint (the row's local face) — the
    /// direction face the response matching needs.
    pub local: String,
    /// The row's remote face (the peer side of the process).
    pub remote: String,
}

/// The observed process's connection face: the fd's `socket:[<inode>]`
/// reads through the OBSERVED process's `/proc/<pid>/net/{table}` — a
/// containerised writer's tables live in its own network namespace,
/// and the tap's own tables never list its sockets. Tables the kernel
/// does not provide skip (an ip4-only box carries no `tcp6` truth),
/// never stop the scan.
pub fn resolve_socket_peer(pid: u32, fd: u32) -> Option<SocketPeer> {
    let link = std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok()?;
    let text = link.to_string_lossy().to_string();
    let inode = text
        .strip_suffix(']')
        .and_then(|rest| rest.strip_prefix("socket:["))?;
    let inode: u64 = inode.parse().ok()?;
    five_tuple_by_inode(pid, inode)
}

/// The `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` face: one line per
/// socket, the columns `sl local rem st ... uid timeout inode`. The
/// addresses ride hex: `AABBCCDD:port` little-endian ip; parse to
/// dotted form.
fn five_tuple_by_inode(pid: u32, inode: u64) -> Option<SocketPeer> {
    let tables = ["tcp", "tcp6", "udp", "udp6"];
    for table in tables {
        let data = match std::fs::read_to_string(format!("/proc/{pid}/net/{table}")) {
            Ok(data) => data,
            Err(_) => continue,
        };
        for line in data.lines().skip(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            // the netstat face: sl local rem st tx-rx tr tm retr uid
            // timeout inode ... - the inode rides column 9, the pointer
            // columns continue past it
            if cols.len() < 10 {
                continue;
            }
            let found = cols[9].parse::<u64>().ok();
            if found != Some(inode) {
                continue;
            }
            let local = endpoint(cols[1])?;
            let remote = endpoint(cols[2])?;
            // a wildcard remote names no connection face: every remote
            // client of one unconnected UDP socket would share the row
            // — the direction face rides the syscall capture instead
            // (the post-gate lane)
            if remote == "0.0.0.0:0" || remote == "[::]:0" {
                continue;
            }
            let mut pair = [local.clone(), remote.clone()];
            pair.sort();
            let transport: &'static str = if table.starts_with("tcp") {
                TRANSPORT_TCP
            } else {
                TRANSPORT_UDP
            };
            // the namespace face: the peer carries it, so two
            // namespaces' identical faces never merge
            let ns = net_namespace(pid)?;
            // the dual-stack face: the key names the TRANSPORT (tcp/udp)
            // not the table, and the endpoint normalizes the v4-mapped
            // v6 rows — an ip4 client on a v6 listener shares its peer
            // face with both ends
            return Some(SocketPeer {
                transport,
                peer: format!("{ns}{transport}:{}={transport}:{}", pair[0], pair[1]),
                local,
                remote,
            });
        }
    }
    None
}

/// The process's network-namespace identity: `/proc/<pid>/ns/net`
/// links `net:[<inode>]` — the inode carries the connection key. The
/// key rider is `net-<inode>.` (the format composes it directly).
fn net_namespace(pid: u32) -> Option<String> {
    let link = std::fs::read_link(format!("/proc/{pid}/ns/net")).ok()?;
    let text = link.to_string_lossy().to_string();
    text.strip_suffix(']')
        .and_then(|rest| rest.strip_prefix("net:["))
        .map(|ns| format!("net-{ns}."))
}

/// One `/proc/net/` endpoint: `AABBCCDD:PORT` hex (little-endian ip4,
/// net byte order ip6) to a stable dotted face. The address decodes
/// from the address half only — the port never appears twice.
fn endpoint(hex: &str) -> Option<String> {
    let (addr, port) = hex.rsplit_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let bytes: Vec<u8> = (0..addr.len() / 2)
        .map(|i| u8::from_str_radix(&addr[i * 2..i * 2 + 2], 16).ok())
        .collect::<Option<Vec<_>>>()?;
    let ip = match bytes.len() {
        4 => {
            let mut b = bytes.clone();
            b.reverse();
            b.iter().map(|x| format!("{x}")).collect::<Vec<_>>().join(".")
        }
        16 => {
            // the v4-mapped face (::ffff:A.B.C.D): the last four bytes
            // decode the dotted endpoint, so an ip4 client on a v6
            // listener names the same endpoint both ways
            if bytes[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
                bytes[12..]
                    .iter()
                    .map(|x| format!("{x}"))
                    .collect::<Vec<_>>()
                    .join(".")
            } else {
                addr.to_lowercase()
            }
        }
        _ => addr.to_lowercase(),
    };
    Some(format!("{ip}:{port}"))
}

/// The sample class face (ADR-0005): the transport comes from the map
/// the tap drains and the table the resolver reads.
pub const TRANSPORT_PIPE: &str = "stdio-pipe";
pub const TRANSPORT_TCP: &str = "tcp";
pub const TRANSPORT_UDP: &str = "udp";

/// The TLS face (ADR-0006): an fd-less sample's peer resolves through
/// the writer's /proc fd scan - the first connected socket the writer
/// holds, never the ssl struct. A writer with several connected
/// sockets is ambiguous and keys honestly with its evidence; the
/// ambiguity face rides the caller.
pub fn scan_connected_socket(pid: u32) -> Option<String> {
    let dir = format!("/proc/{pid}/fd");
    let entries = std::fs::read_dir(&dir).ok()?;
    let mut inode = None;
    for e in entries.flatten() {
        if let Ok(link) = std::fs::read_link(e.path()) {
            let text = link.to_string_lossy().to_string();
            if !text.starts_with("socket:[") || !text.ends_with(']') {
                continue;
            }
            if let Ok(in_) = text[8..text.len() - 1].parse::<u64>() {
                if let Some(face) = five_tuple_by_inode(pid, in_) {
                    // a listener's remote face rides 0.0.0.0:0; the
                    // connected socket carries a real remote
                    if !face.peer.ends_with(".tcp:0.0.0.0:0") {
                        inode = Some(face.peer);
                        break;
                    }
                }
            }
        }
    }
    inode
}

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
        Err(_) => return Decision::AgentUnidentified,
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
