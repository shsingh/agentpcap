# TDD Ledger

Every behavioural change lands as a RED cell first. RED means the test
fails on the missing behaviour, not on the test itself. Receipts name
the commit and the gate that ran in the `agentpcap-build-dev` VM
(ubuntu noble arm64, kernel 7.2.12). The alpha1 cells keep their
receipts; the alpha2 cells ride below.

## Ledger crate — `agentpcap-ledger`

| Cell | Spec anchor | Assertion | Red receipt | Green receipt |
|------|-------------|-----------|-------------|---------------|
| L001 | [§7 The flow ledger](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#7-the-flow-ledger) | `prev` recomputes: 16-hex SHA-256 of the previous record body; first record empty | `9c2f46a` compile red | `025f904` 1/1 pass |
| L002 | [§7 The flow ledger](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#7-the-flow-ledger) | rotation closes to `<name>.1` untouched; fresh segment carries the last-record hash in its first `prev` | `9c2f46a` compile red | `025f904` 1/1 pass (first attempt failed; verifier carried-hash fixup `df5d52f`) |
| L003 | [§7 The flow ledger](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#7-the-flow-ledger) | torn tail: verification fails and the writer refuses to chain from corrupt data | `9c2f46a` (syntax fixup to red-for-the-right-reason: `2f84e8e`) | `025f904` 1/1 pass |
| L004 | [§7 The flow ledger](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#7-the-flow-ledger) | read appends actor, RFC 3339 time, path scope to the adjacent `.access.log` | `9c2f46a` compile red | `025f904` 1/1 pass |
| L005 | [§4 Event record schema](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#4-event-record-schema) | every record carries `schema_version` pinned `1.0` | `9c2f46a` compile red | `025f904` 1/1 pass |

## Events crate — `agentpcap-events`

| Cell | Spec anchor | Assertion | Red receipt | Green receipt |
|------|-------------|-----------|-------------|---------------|
| L006 | [§4 Event record schema](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#4-event-record-schema) | required fields serialise; `Mode`/`Verdict` take the spec forms; enumerations round-trip | `921eff4` compile red | `2d64528` + fixup `914ac91`, 2/2 pass |

## Collector crate — `agentpcap-collector` (spike)

| Cell | Spec anchor | Assertion | Status |
|------|-------------|-----------|--------|
| P000 | [§5 Collectors and transport coverage](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#5-collectors) | the eBPF canary: object builds for `bpfel-unknown-none`, loads into the build-VM kernel, attaches `syscalls:sys_enter_write`, and the bpf array counter is read back greater than zero in-process | RED (object absent), GREEN on `feat/2026.01-alpha1` |
| P002 | [§5 Collectors and transport coverage](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#5-collectors) | the emit path: the probe pushes one sample per filtered write into the `pipe_events` queue (pid, ppid, len, first payload bytes) and the userspace reads its own payload back through the typed queue; the marker rides a jsonrpc frame (ADR 0003 filter) | RED (queue map absent), GREEN on `feat/2026.01-alpha1`; re-verified GREEN on `fix/greptile-audit` with the capture filter, the 256-byte wire and the fd-carrying sample |
| P001 | [§5 Collectors and transport coverage](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#5-collectors) | userspace match: JSON-RPC framing over a pipe sample -> `mcp`; non-JSON -> `other`; unknown agent framing -> `agent-unidentified` | GREEN (8 of 8), landed via PR #48 |
| P003 | [§5 Collectors and transport coverage](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#5-collectors) | lineage: the marker sample's root pid translates to the writer's pid with the per-boot offset (calibrated from its own sample); `resolve_parent` reads `PPid` from `/proc` with a TTL cache and the cache serves the second ask; the marker rides a jsonrpc frame (ADR 0003 filter) | GREEN on `feat/2026.01-alpha1`; re-verified GREEN on `fix/greptile-audit` — the cell now ALSO proves the calibration generalizes to a second writer the sentinel never saw; the in-probe fork feed parked in issue #55 with kernel receipts |
kprobe on `ksys_write` attaches but never fires on the OrbStack
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
| L101 | [§7 The flow ledger](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#7-the-flow-ledger) | golden fixtures answer `chain-ok`: genesis and the rotated pair; the cross-file carry is verified exactly against the closed segment's tail hash | GREEN on `feat/2026.01-alpha1` |
| L102 | [§7 The flow ledger](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#7-the-flow-ledger) | tampered fixture answers `chain-broken` | GREEN on `feat/2026.01-alpha1` |
| L103 | [§7 The flow ledger](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#7-the-flow-ledger) | torn fixture answers `torn-tail` | GREEN on `feat/2026.01-alpha1` |
| L104 | [§4 Event record schema](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#4-event-record-schema) | schema-mismatch fixture answers `schema-mismatch`; a writer record carrying a foreign `schema_version` is refused and the chain continues for a versionless record | GREEN on `feat/2026.01-alpha1` |

Fixture cases (`crates/ledger/tests/fixtures/ledger/`): `01-genesis`,
`02-rotated` (`+ .1` continuation), `03-tampered`, `04-torn`,
`05-schema-mismatch`. A continuation segment carries no own `.expect`;
it belongs to its base case.

## CLI crate — `agentpcap` (issue #13)

| Cell | Spec anchor | Assertion | Status |
|------|-------------|-----------|--------|
| C001 | [§9 Operator CLI](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#9-operator-cli) | `record --ledger P` appends JSON Lines from stdin; exit 0; two chained records verified | GREEN on `feat/2026.01-alpha1` |
| C002 | [§9 Operator CLI](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#9-operator-cli) | `report --ledger P` prints the records; the read lands in the access log as `actor = agentpcap.report` | GREEN on `feat/2026.01-alpha1` |
| C003 | [§9 Operator CLI](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#9-operator-cli) | `report` on a torn ledger: nonzero exit, no records on stdout, the failure states itself on stderr | GREEN on `feat/2026.01-alpha1` |
| C101 | [§13 Evaluation hooks](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#13-evaluation-hooks) | the stdio scenario (ADR-0002): the test plays an MCP client, the frames ride the server's stdin pipe, the server answers on a piped stdout, the tap runs throughout — the initialize, tools/list and tools/call pairs merge into three session events: `init` with the 16-hex capability fingerprint and the `2025-06-18` protocolVersion evidence, `tools-list` with the discovered tool name on the evidence, `tools-call` with `tool_name=read` and the result text, all in one session | GREEN on `feat/reassembler` `1115302`; receipt: records=3 events=[init, tools-list, tools-call] one session, report lines=3 own=47047. The alpha1 shape (six frame records) preceded the reassembler; its receipts live on `fix/greptile-audit` and in the alpha1 gate report |
| C100 | [§5 Collectors and transport coverage](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#5-collectors) | the tap: probe loop, pid-space calibration, pipe-fd identity, classifier, reassembler and ledger in one run — a real MCP frame lands `verdict=mcp`, a methodless result lands `agent-unidentified` as the orphan, both on one pipe. The ids ride this cell's own space (500/501): an id another cell parks in the parallel suite makes the bind ambiguous | GREEN on `feat/reassembler` `1115302`; receipt: `test result: ok. 1 passed` (3.08s), the mcp frame's parked request flushes `mcp` and the methodless result orphans `agent-unidentified` |

## Green gate rule

A cell moves to green only on a fresh run in the build VM. The run
receipt (`test result: ok. N passed`) is evidence, not the commit
message. A green without a named run receipt does not count.

## Reassembler crate — `agentpcap-reassemble` (issues #17, #18)

The session-event state machine. Cell prefix `R` in this section. The
tap feeds one frame per classified sample; the reassembler emits one
event record per session event (`docs/spec.md#4-event-record-schema`).
Pairing: the pipe class keys a session by the pipe pair — the client
pid that writes requests and the child server whose responses resolve
`ppid`; a response whose writer dies inside the pop window binds by the
exact id when it names one pending request across every bucket, and
orphan-honestly (`orphan-response`) otherwise. The in-probe fd
resolution that removes the dying-writer class at the root is parked in
issue #76 with its kernel receipts (the BTF walk).

| Cell | Spec anchor | Assertion | Red receipts | Green receipt |
|------|-------------|-----------|--------------|---------------|
| R101 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the initialize pair merges into one `init` record: the capability fingerprint recomputes 16-hex from the result's capabilities by the ledger hash rule, `protocolVersion` rides evidence, the merged payload carries both halves, the pair is `pipe-pair:C:S`, `dedup` = transport:pair:event:id | compile red `642d531` E0599/E0382; fingerprint red `d5dfc21`: left None, right `ba8e230d1afc3aa1` (the merge read the envelope, not the result member) | GREEN `1115302`, 1 passed |
| R102 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the tools/list pair merges with the discovered tool names and the count on the evidence (16 tools cap); no single `tool_name` | compile red `642d531` | GREEN `1115302`, 1 passed |
| R103 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the tools/call pair merges with `tool_name` from `params.name` and the result text in the payload | compile red `642d531` | GREEN `1115302`, 1 passed |
| R104 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | a server-initiated notification emits on arrival keyed by the pipe pair; two notifications keep distinct dedupe keys (the per-session notify sequence) | compile red `642d531` | GREEN `1115302`, 1 passed |
| R105 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | unidentified flow as a first-class record: an orphan response, the unframed shape, and the burst cadence (`cadence:burst-N-in-1s` on repeated frames inside one second on one session); the absence of `MCP-Protocol-Version` alone never decides the verdict | compile red `642d531` | GREEN `1115302`, 1 passed |
| R106 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | `message/send` classifies verdict `a2a` with the `a2a-handoff` event from protocol semantics, never a catalog | compile red `642d531` | GREEN `1115302`, 1 passed |
| R107 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the pairing rule: the pairing parent answers which server and the payload id answers which request; two servers of one client bind their own pairs, never across ids; a request no response binds still lands at flush on its own channel with the `no-response` evidence and no fingerprint | compile red `642d531` | GREEN `1115302`, 1 passed |

The full workspace suite at `1115302` ran green in one VM round
(32 test binaries, rc=0): the reassembler cells, the collector cells
P000-P003 (8 passed), the ledger cells L001-L005 and the L10x
fixtures, and the CLI cells C001-C003, C100, C101.
