# TDD Ledger — alpha1

Every behavioural change lands as a RED cell first. RED means the test
fails on the missing behaviour, not on the test itself. Receipts name
the commit and the gate that ran in the `agentpcap-build-dev` VM
(ubuntu noble arm64, kernel 7.2.12).

## Ledger crate — `agentpcap-ledger`

| Cell | Spec anchor | Assertion | Red receipt | Green receipt |
|------|-------------|-----------|-------------|---------------|
| L001 | `docs/spec.md#7-the-flow-ledger` | `prev` recomputes: 16-hex SHA-256 of the previous record body; first record empty | `9c2f46a` compile red | `025f904` 1/1 pass |
| L002 | `docs/spec.md#7-the-flow-ledger` | rotation closes to `<name>.1` untouched; fresh segment carries the last-record hash in its first `prev` | `9c2f46a` compile red | `025f904` 1/1 pass (first attempt failed; verifier carried-hash fixup `df5d52f`) |
| L003 | `docs/spec.md#7-the-flow-ledger` | torn tail: verification fails and the writer refuses to chain from corrupt data | `9c2f46a` (syntax fixup to red-for-the-right-reason: `2f84e8e`) | `025f904` 1/1 pass |
| L004 | `docs/spec.md#7-the-flow-ledger` | read appends actor, RFC 3339 time, path scope to the adjacent `.access.log` | `9c2f46a` compile red | `025f904` 1/1 pass |
| L005 | `docs/spec.md#4-event-record-schema` | every record carries `schema_version` pinned `1.0` | `9c2f46a` compile red | `025f904` 1/1 pass |

## Events crate — `agentpcap-events`

| Cell | Spec anchor | Assertion | Red receipt | Green receipt |
|------|-------------|-----------|-------------|---------------|
| L006 | `docs/spec.md#4-event-record-schema` | required fields serialise; `Mode`/`Verdict` take the spec forms; enumerations round-trip | `921eff4` compile red | `2d64528` + fixup `914ac91`, 2/2 pass |

## Collector crate — `agentpcap-collector` (spike)

| Cell | Spec anchor | Assertion | Status |
|------|-------------|-----------|--------|
| P000 | `docs/spec.md#5-collectors` | the eBPF canary: object builds for `bpfel-unknown-none`, loads into the build-VM kernel, attaches `syscalls:sys_enter_write`, and the bpf array counter is read back greater than zero in-process | RED (object absent), GREEN on `feat/2026.01-alpha1` |
| P001 | `docs/spec.md#5-collectors` | userspace match: JSON-RPC framing over a pipe sample -> `mcp`; non-JSON -> `other`; unknown agent framing -> `agent-unidentified` | RED draft on main (8 of 8 failing on the unimplemented match), implementation pending |

### P000 design receipts

- A kprobe on `ksys_write` attaches but never fires on the OrbStack
  kernel (7.2.12): tracefs records nothing for it, and the map counter
  stayed at zero. The tracepoint equivalent fires instantly.
- `tracefs` content is unusable on this kernel even with tracepoints
  enabled and `tracing_on` set; the BPF-map readback is the only valid
  emit path. The alpha1 canary therefore reads a counter in-process and
  never touches tracefs.
- A bpf-side `HashMap` lookup for a never-written key returns no
  pointer: the counter rides a pre-allocated `Array` slot.
- `bpf_printk` is unusable as the receipt path on this kernel for the
  same reason as the trace-buffer emptiness.

## Planned (alpha1 remainder)

- L101–L104 conformance fixtures: chained rotation across segments,
  tamper detection on a mid-chain edit, access-log append-only growth,
  schema mismatch refusal. Issue #14.

## Ledger fixtures — conformance set (issue #14)

| Cell | Spec anchor | Assertion | Status |
|------|-------------|-----------|--------|
| L101 | `docs/spec.md#7-the-flow-ledger` | golden fixtures answer `chain-ok`: genesis and the rotated pair (carry verified) | RED: `conformance::run` missing |
| L102 | `docs/spec.md#7-the-flow-ledger` | tampered fixture answers `chain-broken` | RED: `conformance::run` missing |
| L103 | `docs/spec.md#7-the-flow-ledger` | torn fixture answers `torn-tail` | RED: `conformance::run` missing |
| L104 | `docs/spec.md#4-event-record-schema` | schema-mismatch fixture answers `schema-mismatch`; a writer record carrying a foreign `schema_version` is refused | RED: refusal and runner missing |

## Green gate rule

A cell moves to green only on a fresh run in the build VM. The run
receipt (`test result: ok. N passed`) is evidence, not the commit
message. A green without a named run receipt does not count.
