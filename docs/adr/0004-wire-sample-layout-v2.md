# 0004 — Wire sample layout v2: the fd field, the pipe-keyed peer, and the filter boundary

Status: accepted (supersedes [0003](0003-wire-sample-layout.md) in part;
0003's size contract stays in force). The socket-class decision extends
this record: see [0005](0005-wire-sample-layout-v3-socket-class.md).

## Context

Three review findings forced this record:

1. The tap recorded every classified write as `transport=stdio-pipe`
   without consulting the write's file descriptor: a JSON-RPC line
   written to a regular file or a socket also landed with pipe evidence,
   widening the capture scope.
2. `peer` named the writer's pid, not the channel: a client and its
   server on one pipe received different peers, while separate pipes
   written by one process collapsed into one.
3. The peer could not outlive its writer: redirected shell builtins fork
   a child that writes and exits inside the tap's pop window, so the
   writer's `/proc` entry is already gone when the sample is processed.

ADR-0003's accepted layout text was also edited in place during the same
pass, which its record forbids; this record is the proper superseding
decision, and 0003 carries the pointer instead.

## Decision

1. **The sample carries the write's file descriptor.** The former 12-byte
   padding field carries `fd` (the `write` syscall's first argument, read
   at tracepoint offset 16). The total size stays 272 bytes and both
   sides keep their size asserts; the layout history (48 → 144 → 272
   bytes) is ADR-0003's contract with this field reinterpretation.
2. **The tap resolves the fd through `/proc/<pid>/fd/<fd>` at pop time
   and keeps the two outcomes apart:**
   - a resolvable fd naming `pipe:[<inode>]` records with
     `peer = pipe:<inode>`; both ends of the channel share the inode, so
     the peer is the channel key;
   - a resolvable fd naming anything else (a regular file, a socket) is
     not stdio traffic and is never recorded;
   - an unresolvable fd (the writer died inside the pop window) records
     with `peer = unresolved` and the evidence
     `fd-unresolved-at-pop`. The alpha2 in-kernel fd resolution
     replaces this fallback.
3. **The capture filter's sniff window** stays as ADR-0003 specified
   (leading whitespace skipped, `{` plus the `jsonrpc` member within 40
   bytes, or the calibration sentinel prefix). Frames whose `jsonrpc`
   member starts later than byte 40 are outside this filter; opening the
   window cites an update to this record.
4. The calibration sentinel carries a fresh token read from the host
   entropy pool per run; a failed entropy read is fatal to the tap. The
   sentinel file is created exclusively inside a private temporary
   directory. The tap leaves no persistent diagnostic artifacts beside
   the ledger.

## Consequences

- The probe crate, the collector crate, the tap runtime and the scenario
  rebuild together; the size asserts fail loudly when one side drifts.
- The tap's per-record work scales with pipe traffic, not with host
  traffic: regular-file writes of matched candidate shape are skipped
  after one `/proc` lookup.
- The scenario cell ties its assertions to the reply channel's inode,
  so ambient jsonrpc traffic from unrelated processes cannot enter the
  asserted set.
