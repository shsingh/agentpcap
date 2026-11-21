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
| P001 | `docs/spec.md#5-collectors` | userspace match: JSON-RPC framing over a pipe sample -> `mcp`; non-JSON -> `other`; unknown agent framing -> `agent-unidentified` | RED draft on `feat/probe-spike` (spike note with verified probe receipts), implementation pending |

## Planned (alpha1 remainder)

- L101–L104 conformance fixtures: chained rotation across segments,
  tamper detection on a mid-chain edit, access-log append-only growth,
  schema mismatch refusal. Issue #14.
- The eBPF canary cell: compile and attach a minimal aya probe in the
  `agentpcap-build-dev` VM. Issue #10.

## Green gate rule

A cell moves to green only on a fresh run in the build VM. The run
receipt (`test result: ok. N passed`) is evidence, not the commit
message. A green without a named run receipt does not count.
