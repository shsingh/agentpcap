# 0005 — Wire sample layout v3: the socket class rides the pipe-class wire, the sample class rides the map

Status: accepted (extends [0004](0004-wire-sample-layout-v2.md); 0004's
272-byte contract stays in force)

## Context

The alpha2 wire class adds the socket collector (spec section 5): eBPF
observe of the socket boundary, filtered by cgroup and process lineage,
five-tuple flow records keyed to one session face. The pipe-class
sample already carries `pid`, `ppid`, `len`, `fd` and the first payload
bytes in a const-locked 272-byte wire. Two designs were on the table:

1. widen the wire with a sample-kind discriminant and one shared queue;
2. keep the wire and give the socket class its own queue.

## Decision

2. **The socket class rides the same 272-byte wire; the class of a
   sample comes from the queue map, not from the wire.** The probe
   pushes `sendto` and `recvfrom` samples into a second queue,
   `sock_events`, of the same type and size assert. The userspace
   reader knows the class from the map it drains: the pipe queue
   records `transport = stdio-pipe`, the socket queue records
   `transport = tcp` (or `udp` by the socket's `/proc` face). No wire
   change lands; the size asserts on both sides stay untouched.

- **The cgroup filter lives in the probe, keyed by a marker map.** The
  probe holds a `cgroup_allow` map: the tap marks filtering active
  with a sentinel key (`u64::MAX -> 1`) and lists the allowed cgroup
  ids beside it. A sample passes when the marker is absent (the lab
  default: capture all) or when the sample's cgroup id is in the allow
  set. The probe reads its cgroup id with
  `bpf_get_current_cgroup_id`.
- **The capture filter sniff stays ADR-0003's rule** (leading
  whitespace skipped, `{` plus the `jsonrpc` member within 40 bytes, or
  the calibration sentinel) applied to the socket buffer: plaintext
  JSON-RPC over TCP is line-delimited the same way.
- **The five-tuple resolves userspace** through the writer's `/proc`
  fd: a resolvable fd naming `socket:[<inode>]` looks its local and
  remote endpoints up in `/proc/net/tcp` (or `udp`), and the peer is
  the canonical sorted endpoint pair, identical for both directions of
  one connection - the session then keys one connection, not one
  direction. A failing lookup keys the record `unresolved` with the
  same honesty face ADR-0004 set. The dying-writer class and its
  in-probe resolution ride the tracked issue #76.
- The socket queue carries the same outcome counter set (invoke,
  read-fail, push-ok, push-fail) in its own canary array, so probe
  health stays observable per class.

## Consequences

- Wire-layout changes keep landing once with cells on both sides; the
  class face never needs one.
- The tap drains two queues and appends the reassembled events from
  both; `tap.wait()` semantics stay unchanged.
- The `recvfrom` samples key the direction by the reader's fd face; the
  canonical pair face keeps both directions of one connection in one
  session either way.
