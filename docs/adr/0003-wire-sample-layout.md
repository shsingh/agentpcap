# 0003 — Wire sample layout and capture filter

Status: accepted

## Context

The probe hands every captured write to the tap over one wire structure.
Two events forced this record into existence:

1. The first wire layout carried a 32-byte payload. MCP request frames
   are longer than 32 bytes, so the classifier never saw the `method`
   member. One widening pass followed, and the alpha1 scenario exposed a
   second bound: a 150-byte `initialize` frame truncated at 128 bytes
   loses its framing newline and classifies `agent-unidentified` — by
   contract, but wrongly for a complete frame.
2. A busy host writes tens of thousands of non-agent lines per second.
   The first capture pass queued every write; the tap drained what it
   could, the 1024-slot queue stayed permanently full, and target
   samples were dropped in a race. Widening the queue alone did not
   hold: the drain rate, not the queue depth, was the bottleneck.

## Decision

The wire sample layout is fixed at 272 bytes:

```text
offset  size  field
0       4     pid    — the writer's kernel pid (root namespace)
4       4     ppid   — the parent pid stamped by the fork probe
8       4     len    — the captured byte count (<= payload cap)
12      4     pad    — alignment
16      256   first_bytes — the first payload bytes of the write
```

- `PAYLOAD_BYTES_CAP` is 256 on both sides and both sides carry a
  compile-time size assert (`core::mem::size_of::<PipeSample>() == 272`
  in the eBPF crate and in the collector crate).
- Any future change to this layout lands in one commit on both sides,
  with the size asserts updated together, and cites this record.
- The capture filter lives in the probe: a write only becomes a sample
  when its leading bytes pass the sniff — after skipping up to 15
  whitespace bytes, the payload starts with `{` and contains the
  `jsonrpc` member within the first 40 bytes, or the payload starts with
  `agentpcap-c` (the calibration sentinel). The sniff window admits
  member reordering such as `{"id":3,"jsonrpc":"2.0",...}`. Frames whose
  `jsonrpc` member starts later than byte 40 are outside this filter and
  are not captured; a future widening of the window cites an update to
  this record.
- The probe counts every invocation in the canary map before the sniff,
  so health checks stay independent of the filter.

## Consequences

- Both the probe crate and the collector crate must rebuild together;
  the const asserts fail loudly when one side drifts.
- The tap's per-record work scales with agent traffic, not host
  traffic: the filtered queue is near-empty on a busy host, target
  samples land, and drop-races disappear.
- The scenario cell asserts all six messages (three framed requests
  classified `mcp`, three replies recorded) by selecting records on the
  client pid and the server pid, so wire regressions surface in C101.
