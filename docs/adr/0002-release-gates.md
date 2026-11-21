# 0002 — Release gates and evaluation scenarios

Status: accepted

## Context

The project releases in slices. Each merge must land with evidence, and
each named release carries one gate the evaluation fleet measures.
Without a written gate, a release is a date; with one, it is a set of
scenarios with numbers. The companion research note defines six
measurements (M001 to M006); this record binds them to release gates.

## Decision

Three gates, each with its scenario set and its measurement. Each gate
releases under the project's release convention: a calendar version
(`YYYY.01`) with `alpha` and `rc` qualifiers, then general availability —
the same sequence the maintainer's other projects shipped (rc suffixes
while the gate scenarios run, GA once they pass). The MVP gate
releases as `2026.12-alpha1`, the wire-class gate as `2026.12-alpha2`,
the evaluation gate as `2026.12-rc1`; the general-availability tag is
`2026.12`.

### 2026.12-alpha1 — MVP: the stdio class, end to end

Scenario: one lab host, one MCP client, one local MCP server launched
over stdio. The pipe collector captures the JSON-RPC frames; the ledger
appends; `report` answers "who called what with which capabilities".

- Coverage: the pipe class, attributed capture with tool messages
  recorded (method, arguments, results), one event schema, four CLI
  subcommands' `record` and `report` paths.
- Measures: the ledger chains and verifies after rotation (M004
  partial); no path writes (the read-only invariant test); tool
  messages present in the ledger.
- Evidence: the ledger excerpt, the report output, the conformance
  fixtures, posted in the release.

### 2026.12-alpha2 — the wire class and both modes

Scenario: the same fleet plus remote MCP servers over Streamable HTTP
with TLS, attributed mode active by default on every host.

- Coverage: socket collector, TLS-boundary collector, session
  reassembly, unidentified-flow events, `diff` and `export`, the
  systemd unit and the DaemonSet manifest.
- Measures: transport-coverage matrix over stdio, Streamable HTTP,
  legacy SSE and A2A (M003 run); capability-drift detection before and
  after a tool-set change (M004 full).
- Evidence: the coverage matrix, the drift diff, the deployment
  manifests, in the release.

### 2026.12-rc1 — the evaluation gate

Scenario: the full lab fleet with seeded shadow deployments, measured
against the published baselines of the survey.

- Coverage: everything above, plus the unidentified-flow pass and the
  criteria-gate handoff.
- Measures: all six — M001 shadow-discovery recall against the
  header-heuristic class and active probing; M002 tap overhead, tap-on
  versus tap-off delta with the identical harness, against the sub-3%
  published figure; M003 the coverage matrix at full pass; M004 ledger
  fidelity on capability drift; M005 unidentified-triage precision; M006
  gate-handoff latency against the 2-second criteria budget.
- Gate rule: M001 passing with M003's full matrix, at M002's cost, is the
  result that decides the project's public claims.

## Consequences

- No release before its gate: a slice may ship behind a pre-release
  tag without a gate, but no gate carries a version claim until its
  scenarios pass and their evidence posts.
- The evaluation harness owns the measurement surfaces; the binary
  exposes counters (spec, Section 13) and nothing else.
- The gates map to the project milestones `2026.12-alpha1`,
`2026.12-alpha2` and `2026.12-rc1`; the
  roadmap page carries the live issue mapping.
