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
| C002 | [§9 Operator CLI](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#9-operator-cli) | `report` renders the sessions view: one line per session, per peer; the read lands in the access log as `actor = agentpcap.report` | GREEN on `feat/export-diff` `be47b22`; receipt: two sessions, two view lines |
| C003 | [§9 Operator CLI](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#9-operator-cli) | `report` on a torn ledger: nonzero exit, no records on stdout, the failure states itself on stderr | GREEN on `feat/2026.01-alpha1` |
| C004 | [§9 Operator CLI](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#9-operator-cli) | `export --ledger P` streams the ledger's events as JSON Lines in lossless order for a segment; the stream matches the event schema; the read logs as `actor = agentpcap.export` | GREEN on `feat/export-diff` `be47b22`, 1 passed |
| C005 | [§9 Operator CLI](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#9-operator-cli) | `export --follow` streams the segment first and the appends live after startup, in lossless order across the boundary | GREEN on `feat/export-diff` `be47b22`, 1 passed (0.20s) |
| C006 | [§9 Operator CLI](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#9-operator-cli) | the sessions view carries per session: the server name from the initialize result, the capability fingerprint, `protocolVersion`, the tools with their descriptions, the invocation count, transport and mode | GREEN on `feat/export-diff` `be47b22`; receipt: server=alpha1-server, tools=[read: "read a file"], invocations=1 |
| C007 | [§9 Operator CLI](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#9-operator-cli) | `diff --before B --after A` emits the capability drift events from two report sets: `tools-added`, `tools-removed`, `tool-description-changed` with the before/after descriptions, `server-rescoped` with the fingerprint change; the reads log as `actor = agentpcap.diff` | GREEN on `feat/export-diff` `be47b22`; receipt: kinds=[tools-added, tools-removed, tool-description-changed, server-rescoped], tool=read before "read a file" after "read a file v2" |
| C101 | [§13 Evaluation hooks](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#13-evaluation-hooks) | the stdio scenario (ADR-0002): the test plays an MCP client, the frames ride the server's stdin pipe, the server answers on a piped stdout, the tap runs throughout — the initialize, tools/list and tools/call pairs merge into three session events: `init` with the 16-hex capability fingerprint and the `2025-06-18` protocolVersion evidence, `tools-list` with the discovered tool name on the evidence, `tools-call` with `tool_name=read` and the result text, all in one session; `report` folds one sessions view line | GREEN on `feat/reassembler` `1115302`; receipt: records=3 events=[init, tools-list, tools-call] one session, report one session view. The alpha1 shape (six frame records) preceded the reassembler; its receipts live on `fix/greptile-audit` and in the alpha1 gate report |
| C100 | [§5 Collectors and transport coverage](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#5-collectors) | the tap: probe loop, pid-space calibration, pipe-fd identity, classifier, reassembler and ledger in one run — a real MCP frame lands `verdict=mcp`, a methodless result lands `agent-unidentified` as the orphan, both on one pipe. The ids ride this cell's own space (500/501): an id another cell parks in the parallel suite makes the bind ambiguous | GREEN on `feat/reassembler` `1115302`; receipt: `test result: ok. 1 passed` (3.08s), the mcp frame's parked request flushes `mcp` and the methodless result orphans `agent-unidentified` |
| C008 | [§11 Coexistence and flow deduplication](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#11-coexistence-and-flow-deduplication) | the export stream ingests through `record` with the `--source export` stamp; a doubled event skips with the dedupe key and the face continues; the ingested records name their capture path; the chain stays intact red at `dd4a0d8` (the pre-dedupe parent): `c008_the_export_stream_ingests_with_the_dedupe ... panicked at crates/agentpcap/tests/c008_ingestion.rs:51:5: the skip states itself: agentpcap record: 3 record(s) -> ledger` — all three events appended, the skip face did not exist yet | GREEN at `389a959`; receipt: records=2 of the 3 fed, the dedupe skip states itself on stderr, `verify_chain` rc=0 (`test result: ok. 1 passed`) |
| L105 | [§11 Coexistence and flow deduplication](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#11-coexistence-and-flow-deduplication) | the writer refuses a record whose `dedup` key already rides the ledger; the chain verifies after the refusal and the count does not move for it red at `dd4a0d8` (the pre-dedupe parent): `l105_the_duplicate_dedup_key_refuses_and_the_chain_stays_intact` panicked at `crates/ledger/tests/l105_dedupe.rs:33:5` — the append returned Ok, the writer did not refuse the replayed key yet | GREEN at `389a959`, 1 passed (`test result: ok. 1 passed`) |
| C009 | [§9 Operator CLI](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#9-operator-cli) | the duration faces: `--duration 1` ends inside about one second, and `--duration 0` is the service face — the tap outlives the alpha1 default's 60-second window and keeps capturing until the unit stops it | red at `dd4a0d8` (the pre-fix parent): a `--duration 0` tap did not exist (only the 60s default) | GREEN at `389a959`, 2 passed (`test result: ok. 2 passed ... 62.01s` — the unbounded face outlived the default) |
| C010 | [§9 Operator CLI](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#9-operator-cli) | the value face: a trailing `--source` is misuse — exit 2, the failure states itself, and the ledger never opens; a valued `--source export` ingests and stamps | red at `dd4a0d8` (the pre-fix parent): the trailing flag read as an omit and succeeded | GREEN at `389a959`, 2 passed (`test result: ok. 2 passed`) |
| L107 | [§11 Coexistence and flow deduplication](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#11-coexistence-and-flow-deduplication) | the dedupe promise survives rotation and reopening: a key a rotated segment (`<name>.1`) holds refuses again after `rotate()` and a fresh `create()`, while a distinct key lands; both faces of the family verify | red at `dd4a0d8` (the pre-fix parent): a reopening writer carried no keys at all | GREEN at `389a959`, 1 passed (`test result: ok. 1 passed`) |

## The deployment faces (issue #21, #22)

The receipt faces above carry their named run heads. The full workspace
suite re-ran green at `25e937c` (the signal-face cast fix rides it):
`cargo test --workspace -- --test-threads=2`, rc=0.

`deploy/systemd/agentpcap.service`, `deploy/launchd/dev.agentpcap.plist`,
`deploy/k8s/daemonset.yaml` and `deploy/k8s/Containerfile` join the
build. The capability set is exactly `CAP_BPF`, `CAP_PERFMON`,
`CAP_DAC_READ_SEARCH` on the systemd face and `BPF`, `PERFMON`,
`DAC_READ_SEARCH` on the DaemonSet face after an explicit
`drop: [ALL]`, documented in
[deploy/README.md](https://github.com/shsingh/agentpcap/blob/main/deploy/README.md);
the ledger write access rides the state directory (the systemd
`StateDirectory`, owner-only at 0700 with `UMask=0077`) and the
DaemonSet hostPath; the DaemonSet mounts the host's tracefs at
`/sys/kernel/tracing` - the path the probe's attach expects. The DaemonSet carries a
writable `emptyDir` at `/tmp` (calibration writes its pid-space file
there) and both faces run `tap --duration 0`: the capture runs
unbounded until the unit or the pod stops. The image builds
`FROM gcr.io/distroless/cc-debian12:nonroot`, which ships the glibc
loader and libgcc the release binary links dynamically — the static
(musl) release build is the post-gate lane. The launchd face serves
the review subcommands and runs no capture.

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
| R108 | [§4 Event record schema](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#4-event-record-schema) | a matched error response keeps its error object in the merged payload (`code`, `message`) and carries the `error-response` evidence; capture scope never narrows silently | review red (Greptile #77: the error face dropped) | GREEN `6e964ca`, 1 passed |
| R109 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the by-id fallback fires only for a writer that died inside the pop window; a live unownable response orphans on its own channel and never reads another client's id; an id parked on two channels stays preserved, its ambiguous response orphans `pair-unresolved:ambiguous-id`, and the flush recovers both captures | review red (Greptile #77: cross-client binds, id reuse overwrites) | GREEN `6e964ca`, 2 passed |
| R110 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the merged verdict comes from the method's protocol semantics: unknown plain methods stay `agent-unidentified` with the `unidentified` event face; `tasks/*` prefixes ride verdict `a2a` | review red (Greptile #77: unknown traffic became mcp) | GREEN `6e964ca`, 2 passed |
| R111 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the client-side notification session rule: before any pair binds, the notification keys the client's own face (`client:{pid}`) with the `notification:client-side` evidence; after the pair binds, the notification's channel resolves it into the BOUND session (`pipe-pair:P:S`) with the session's capability face - the client and the server notifications share one session, never two | review red (Greptile #77 twice + the 3/5 pass: client notifications split sessions, then picked an arbitrary session on the shared channel) | GREEN `9554035`, 1 passed (both phases); the 3/5 pass added the ambiguity face `r117` |
| R112 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the completed id leaves the pending map: a bound id's empty vec never blocks a later client's ride of the same id through the by-id fallback; the flush carries nothing stale | review red (Greptile #77 re-review: empty vecs block later answers) | GREEN `3e9d1d0`, 1 passed (`test result: ok. 1 passed`, r112) |
| R113 | [§4 Event record schema](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#4-event-record-schema) | the session-event schema face: the reassembled records carry `schema_version: 2.0` (ADR-0007), and the flush face stamps the request's observation time, never the capture window's end - the strict gate: a capture-end face stamps the gate's own second and fails `ev.ts < gate` | review red (Greptile #77 re-review 2/5: the record shape outgrew its version, unanswered calls got wrong times; the 4/5 pass rejected the test as accepting wrong times) | GREEN `0f17e96`, 1 passed (strict face)
| R114 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the placeholder rule: the tap's `unresolved` face never registers as a session channel and never matches one - a dying writer's notification keys its own face and never hijacks another conversation's capability fingerprint | review red (Greptile #77 4/5: unrelated notifications shared a session through the placeholder) | GREEN `af27376`, 1 passed; the session-fix receipts carry `9554035` |
| R115 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the framing face: the verdict requires the valid JSON-RPC member - a broken `jsonrpc` face never receives mcp or a2a from its method string, in the merged record, on the flush face, or on notifications | review red (Greptile #77 4/5: unframed traffic became mcp) | GREEN `6f67636`, 3 passed r115 (`test result: ok. 3 passed`) in the same VM round (l101 two cases ok) |
| R116 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the flush-session resolve: after a pair binds on a channel, a later unanswered request keys the BOUND session (the pipe-pair face with its fingerprint); more than one pair on a channel is honest ambiguity and the raw channel face answers | review red (Greptile #77 4/5: unanswered calls lost their session) | GREEN `6f67636`, 2 passed r116 (`test result: ok. 2 passed`) |
| R117 | [§6 Classification](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#6-classification) | the resolution rule: a notification on a channel two pairs share keys the client face (never an arbitrary pair), and the dying writer's by-id fallback after a bind carries the BOUND session's face - the fingerprint and protocolVersion ride; both faces hold cells r117 | review red (Greptile #77 3/5 pass: arbitrary session pick + the fallback losing its session) | GREEN `3f55227`, 2 passed r117 |
| L106 | [§4 Event record schema](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#4-event-record-schema) | the writer chains both known schema faces (1.0 frame, 2.0 session-event) into one ledger and refuses a foreign version; the conformance checker accepts the same two faces and the `06-schema-v2` fixture joins the golden set (six cases); the chain verifies after every append; the 2.1 face rides ADR-0007's migration note (the dedup keys ride the observation time and content hashes; importers treat `dedup` as opaque, the window bound replaces the full-history reload; the record lives in ADR-0008) | GREEN `6f67636`, l101 `test result: ok. 2 passed` (6+1 cases), r106 face rides the same round |

The full workspace suite at `6e964ca` re-ran green in one VM round
(rc=0), covering the R101-R111 cells, C100, C101 and every alpha1
cell. The Greptile review threads on PR #77 each carry their reply.

The full workspace suite at `1115302` ran green in one VM round
(32 test binaries, rc=0): the reassembler cells, the collector cells
P000-P003 (8 passed), the ledger cells L001-L005 and the L10x
fixtures, and the CLI cells C001-C003, C100, C101.
| C011 | [§10 Deployment](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#10-deployment) | the stop face: the unit's SIGTERM marks the stop, the tap breaks its loop, and the drain flushes every still-pending request with the no-response face — a stop loses nothing; the drained tap answers exit 0 inside seconds | red at `dd4a0d8` (the pre-fix parent): a SIGTERM killed the unbounded tap mid-loop, the pending requests died with it | GREEN at `b8bce16`, c011 `test result: ok. 1 passed`; suite receipt at the same head: full workspace rc=0 |
| L110 | [§4 Event record schema](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#4-event-record-schema) | the privacy face: the ledger carries captured arguments and results and rides owner-only (mode 0600) at create and at every reopen; the systemd face carries \`StateDirectoryMode=0700\` and \`UMask=0077\`, and the DaemonSet ledger rides the init-container owner hand-off | review red (Greptile #79 5/5 pass: the writer left the ledger at the umask default, world-readable) | GREEN at \`e10af9a\`, l110 \`test result: ok. 1 passed\`; suite receipt at the same head: full workspace rc=0 (c101 rides both the suite and an isolated pass) |
| L109 | [§11 Coexistence and flow deduplication](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#11-coexistence-and-flow-deduplication) | the reload order: the closed segments load in numeric order first, the active file LAST, so the window trim keeps the keys the live capture wrote most recently — recent replays refuse, stale ones land honestly outside the bound red at `1e7aa05` (the pre-window parent): `error[E0599]: no associated function or constant named 'create_with_budget' found for struct 'LedgerWriter' in the current scope` — the bounded-window API does not exist yet | GREEN at `ee59f15`, l109 `test result: ok. 1 passed`; suite receipt at the same head: full workspace rc=0 |
| R119 | [§11 Coexistence and flow deduplication](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#11-coexistence-and-flow-deduplication) | separate observations never share a key: two identical notifications inside one second ride distinct observation numbers (run-unique `obs_seq` + the observation moment), so both land in the ledger while true replays still refuse | red at `25e937c` (the content-hash face): \`panicked at crates/reassemble/tests/r119_distinct_observations.rs:46\` — same-second twins shared the hash key | GREEN at \`0076c8e\`, r119 \`test result: ok. 1 passed\`; suite receipt at the same head: full workspace rc=0 |
| R118 | [§10 Deployment](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#10-deployment) | the idle face: a request parked longer than the ttl rides the no-response face once at the sweep and leaves the pending map; the idle session follows; the deployed tap never grows its in-memory faces without limit (ADR-0008) red at `1e7aa05` (the pre-window parent): `error[E0599]: no associated function or constant named 'new_with_ttl' found for struct 'Reassembler' in the current scope` — the sweep API does not exist yet | GREEN at `ee59f15`, r118 `test result: ok. 2 passed`; suite receipt at the same head: full workspace rc=0 (the sweep fires at most once per ttl quarter — the loop's idle ticks stay O(1)) |
| C112 | [§10 Deployment](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#10-deployment) | the cross-user capture face: the tap (uid 999 with the documented capability set, the file-cap face of `deploy/README.md`) samples and classifies a foreign-user agent's frames; the fd resolve face at pop time is a known race (ADR-0004's `fd-unresolved-at-pop` fallback) — the tap binary rides a PRIVATE chowned copy under /var/tmp (the /tmp tmpfs mounts `nosuid` and the kernel ignores file capabilities there) removed by the test's RAII; the fixture rides a fresh test-owned directory created exclusively (`create_new` refuses a pre-planted symlink face) and the ledger lives in the tap-owned directory; the identity proof rides the VM receipt: the same binary and capability set resolved a foreign-user writer's pipe face `90363 python3 pipe:13980623` under yama `ptrace_scope=1` | red at `dd4a0d8` (the pre-fix parent): no `CAP_SYS_PTRACE` face existed, and a foreign-user tap could not resolve any writer identity | GREEN at `b8bce16`, c112 `test result: ok. 1 passed`; suite receipt at the same head: full workspace rc=0. c101's parallel-suite flake (one red at full parallelism, the same class as P003's) stays noted: it passes isolated |
| L108 | [§11 Coexistence and flow deduplication](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#11-coexistence-and-flow-deduplication) | the dedupe window is bounded: the writer keeps at most `budget` keys (the newest; default 65,536, `AGENTPCAP_DEDUP_BUDGET` overrides), an evicted key appends again, a key inside it still refuses, and the reload trims to the budget the same way — a service that runs for weeks never grows memory with its history (ADR-0008) | red at `dd4a0d8` (the pre-fix parent): no window face existed, the set grew with the ledger's lifetime | GREEN at `b8bce16`, l108 `test result: ok. 1 passed`; suite receipt at the same head: full workspace rc=0 |
