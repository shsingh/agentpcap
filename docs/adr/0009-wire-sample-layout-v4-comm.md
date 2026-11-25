# 0009 — Wire sample layout v4: the writer's comm rides the wire

Status: accepted (extends [0005](0005-wire-sample-layout-v3-socket-class.md);
0003/0004's payload-face contract and 0005's class-from-queue face stay
in force; the 272-byte sample face grows to 288)

## Context

The ledger row's `process` face rode `/proc/{pid}/comm` read at the pop:
a writer whose /proc row vanished inside the pop window keyed
`unknown`, and the reassembler's lineage face sometimes keyed a sibling
child's comm instead of the writer's (issue #95; the m005 comm receipts
rode `unknown: 7` on one attempt). A wire face read at the syscall
never races the pop: the kernel answers the writer's own task comm.

## Decision

1. **The 272-byte sample grows to 288 bytes with a `comm: [u8; 16]`
   field (`TASK_COMM_LEN`).** The four producers (the pipe write
   tracepoint, the socket send/recv-exit pair, the TLS collect) fill it
   with `bpf_get_current_comm` at the syscall; a failed fill rides
   zeros. Both sides carry the size assert.
2. **The drain prefers the wire comm** (trim at the first NUL, lossy on
   the tail); the `/proc` comm read stays the fallback for an empty
   wire face. The rows' `process` field faces the writer's own comm, so
   the lineage machinery never picks the comm — the `ppid`/lineage face
   keeps its own job.
3. **The event schema does not move**: `process` rides the record as
   before; the dedupe keys and the version faces stay untouched.

## Consequences

- The `unknown` comm faces never ride a row whose writer filled the
  wire — the pop-window race loses its comm face (issue #95's
  acceptance).
- The per-sample `/proc` comm read leaves the hot path (the fallback
  fires only on an empty wire face); the M002 CPU residual rides one
  face narrower (issue #88).
- Readers treat `process` as opaque to the wire; no ledger migration
  rides (the record face never carried the sample source).
- The comm truncation face stays kernel-bound: a task comm longer than
  15 bytes truncates at the NUL — the honest face, never widened.
