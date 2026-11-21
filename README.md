# agentpcap

[![License: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](https://github.com/shsingh/agentpcap/blob/main/LICENSE) [![agentpcap site](https://img.shields.io/website?down_message=offline&up_message=live&url=https%3A%2F%2Fagentpcap.kalatopi.sh%2F&label=site)](https://agentpcap.kalatopi.sh/) [![GitHub commit activity](https://img.shields.io/github/commit-activity/m/shsingh/agentpcap.svg)](https://github.com/shsingh/agentpcap/graphs/commit-activity) [![GitHub Release](https://img.shields.io/github/v/release/shsingh/agentpcap?include_prereleases)](https://github.com/shsingh/agentpcap/releases)

[![agentpcap pre-commit.ci status](https://results.pre-commit.ci/badge/github/shsingh/agentpcap/main.svg)](https://results.pre-commit.ci/latest/github/shsingh/agentpcap/main) [![Dependency Review](https://github.com/shsingh/agentpcap/actions/workflows/dependency-review.yml/badge.svg)](https://github.com/shsingh/agentpcap/actions/workflows/dependency-review.yml) [![OpenSSF Scorecard](https://img.shields.io/ossf-scorecard/github.com/shsingh/agentpcap?label=OpenSSF%20Scorecard&style=flat)](https://scorecard.dev/viewer/?uri=github.com/shsingh/agentpcap) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16971/badge.svg)](https://www.bestpractices.dev/projects/16971) [![SLSA Build Level 2](https://img.shields.io/badge/SLSA-Build%20Level%202-3D577A)](https://github.com/shsingh/agentpcap/attestations)

A read-only, protocol-aware tap for agent tool calls. It observes the
socket and pipe boundaries of the Model Context Protocol (MCP) and
agent-to-agent (A2A) traffic on a host, reassembles sessions, and
appends every flow to a lossless, per-host ledger. One static Rust
binary. No agent-side library, no routing change, no gateway in the
path.

## Status

Early development, specification-first. The specification
([`docs/spec.md`](docs/spec.md)) is in force and renders in CI. The
reference implementation builds to it in Rust (eBPF via
[aya](https://github.com/aya-rs/aya)).

## Contents

- [Why agentpcap exists](#why-agentpcap-exists)
- [How it differs](#how-it-differs)
- [What it does](#what-it-does)
- [Quick examples](#quick-examples)
- [Specification](#specification)
- [Companion artifacts](#companion-artifacts)
- [Deployment](#deployment)
- [Evaluation and roadmap](#evaluation-and-roadmap)
- [Contributing](#contributing)
- [Licence](#licence)

## Why agentpcap exists

Agent fleets reach their tools through MCP, and each tool call is a
network event: a JSON-RPC message carrying a tool name and arguments to
an endpoint the change process did not ticket. The enterprise has
decades of instrumentation for the wire — taps, flow collectors, IDS —
and none of it names this traffic class. Three structural blind spots
stay open in every survey lane:

1. **The path problem.** In-path gateways govern what routes through
   them. The fleet that most needs governing is the one that bypasses
   them — local tools, off-network traffic, unsupported clients.
2. **The decryption problem.** Network detection wants the encrypted
   payload; without TLS termination on the inspection path, a tool call
   is unattributable metadata.
3. **The stdio problem.** The largest MCP transport never touches a
   network: the client launches the server as a subprocess and speaks
   JSON-RPC over pipes. No network-side product can see it, ever.

agentpcap closes all three with one out-of-path instrument and a per-host
append-only ledger built for capability-drift review.

## How it differs

The project sits beside established tooling; it does not replace any of
it. Each row names a real system, what it covers today, its structural
limit, and the answer agentpcap gives for that limit.

| Solution | What it covers | Structural limit | agentpcap's answer |
|---|---|---|---|
| [agentgateway](https://agentgateway.dev) (Linux Foundation) — Rust proxy for MCP and A2A | protocol-aware routing and policy for routed traffic; `tools/list` and `tools/call` tracing | in-path by configuration: traffic that does not traverse it is invisible | the tap sees the bypass flows; agentgateway's exports feed the same ledger (spec §11) |
| In-path enterprise gateways (Netskope Agentic Broker, Palo Alto AI Gateway class) | MCP visibility, catalogs, enforcement at the Zero Trust exchange | same in-path boundary; coverage ends where routing ends | out-of-path capture on the host; the bypass class is the named target |
| [Microsoft Global Secure Access MCP logging](https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-view-model-context-protocol-logging) | deep-packet-inspection MCP identification with session records | requires TLS inspection on the network path; local stdio servers invisible (no network footprint) | plaintext captured at the host TLS boundary (attributed by default); the pipe collector observes stdio directly |
| [Cloudflare Gateway MCP detection](https://blog.cloudflare.com/mcp-security-updates) (`is_mcp` selector) | header-heuristic classification (`MCP-Protocol-Version` positive signal); requires decryption on the path | absence of the header proves nothing; legacy and early-session traffic escape; decryption required | classification from protocol semantics in the reassembler; the header is recorded evidence, never the gate |
| [AgentSight](https://github.com/eunomia-bpf/agentsight) — eBPF observability at the system boundary | uprobes on TLS libraries, process lineage, under-3% overhead | scoped to known agent processes and the single host; no MCP/A2A session semantics; no ledger | cgroup-filtered capture plus full session reassembly; the ledger is the product, not a dashboard |
| [Pixie](https://docs.px.dev/about-pixie/pixie-ebpf) / [Cilium Hubble](https://github.com/cilium/hubble) | generic eBPF L7 visibility: HTTP, DNS, databases, Kafka | fixed protocol table with no MCP row; a tool call is another HTTP transaction | protocol semantics as a first-class layer over the same proven capture mechanics |
| [AgentSniff](https://docs.agentsniff.org/detectors) — active prober | active MCP probing by protocol version; TLS fingerprint hints | point-in-time probing, not continuous observation | the passive ledger carries the unidentified stream; probing joins as triage follow-up |
| [MCP Scanner](https://mcpscanner.cloud) / [Microsoft MCP Scan CLI](https://microsoft.github.io/agent-governance-toolkit/tutorials/27-mcp-scan-cli) | scan-time checks: tool poisoning, rug-pull fingerprints, schema abuse | answers "what did we know at scan time", never "what crossed the wire at 14:02" | capability fingerprints in the ledger give the drift question at drift time |
| Metadata-research tooling (classification from packet timing and graph shape) | workflow inference from encrypted traffic | academic prototypes; no operator instrument | the unidentified-flow pass is a CLI surface and a policy stream, not a paper |

The one-line difference: every system above answers the question it was
built for. agentpcap is the instrument for the flows all of them leave
open, and it produces the one artefact none of them produce — the
append-only, per-host record of who called what, with which
capabilities, when.

## What it does

- **tap points** — three collectors, one event model, all read-only: an
  eBPF socket collector filtered by cgroup and process lineage, a
  TLS-boundary collector (uprobes; attributed mode only), and a pipe
  collector for the stdio transport.
- **protocol reassembly** — MCP initialization, tool discovery, tool
  invocation and server-initiated messages as session events; A2A task
  handoffs; anything agent-shaped but unattributed becomes a
  first-class unidentified-flow event with probing leads.
- **the flow ledger** — JSON Lines, append-only, hash-chained (`prev`
  field), access-logged. Tool messages ride the record: method,
  arguments and result. Retention and redaction are operator settings;
  rotation preserves the prefix; no index is built.
- **gate handoff** — the event stream feeds a criteria gate; policy is
  the operator's own declared criteria, verified on the stream.

## Quick examples

The commands below are the specified interface; the binary builds to
them (spec, Sections 4 to 10).

```bash
# the default service face: collectors running, ledger appending
agentpcap record --ledger /var/lib/agentpcap/ledger.jsonl

# who called what, with which capabilities, when
agentpcap report --ledger /var/lib/agentpcap/ledger.jsonl | jq 'select(.verdict=="mcp")'

# capability drift between two review points: new, changed, removed tools
agentpcap diff --before monday.jsonl --after friday.jsonl

# the event stream to the policy gate or the estate collector
agentpcap export --follow
```

## Specification

The canonical specification is [`docs/spec.md`](docs/spec.md). Every
issue links the sections it implements through the heading anchors. It
renders to text, HTML and PDF artifacts in CI.

| Section | Anchor |
|---|---|
| Architecture | [`docs/spec.md#3-architecture`](docs/spec.md#3-architecture) |
| Event record schema | [`docs/spec.md#4-event-record-schema`](docs/spec.md#4-event-record-schema) |
| Collectors and transport coverage | [`docs/spec.md#5-collectors-and-transport-coverage`](docs/spec.md#5-collectors-and-transport-coverage) |
| Classification | [`docs/spec.md#6-classification`](docs/spec.md#6-classification) |
| The flow ledger | [`docs/spec.md#7-the-flow-ledger`](docs/spec.md#7-the-flow-ledger) |
| Modes | [`docs/spec.md#8-modes`](docs/spec.md#8-modes) |
| Operator CLI | [`docs/spec.md#9-operator-cli`](docs/spec.md#9-operator-cli) |
| Deployment | [`docs/spec.md#10-deployment`](docs/spec.md#10-deployment) |
| Coexistence and deduplication | [`docs/spec.md#11-coexistence-and-flow-deduplication`](docs/spec.md#11-coexistence-and-flow-deduplication) |

## Companion artifacts

| Artifact | Source |
|---|---|
| Research note (the survey behind the design) | [`docs/agentpcap-paper.md`](docs/agentpcap-paper.md) — rendered PDF on [the site](https://agentpcap.kalatopi.sh/) |
| Source ledger (every citation, grouped) | [`docs/references.md`](docs/references.md) |
| Foundational decisions | [`docs/adr/0001-foundational-decisions.md`](docs/adr/0001-foundational-decisions.md) — index at [`docs/adr/0000-architecture-decision-records.md`](docs/adr/0000-architecture-decision-records.md) |
| Release gates | [`docs/adr/0002-release-gates.md`](docs/adr/0002-release-gates.md) |
| Build board | [agentpcap — Roadmap & Build Board](https://github.com/users/shsingh/projects/7) — 23 cards, one per build item, grouped by gate |
| Roadmap (the gates as issues) | [`/roadmap.html`](https://agentpcap.kalatopi.sh/roadmap.html) on the site |

## Deployment

Two placement modes, one binary, one event schema; capture is
Linux-only, review runs anywhere.

- **Host-native:** the binary as a service under systemd or launchd,
  BPF and performance-monitoring capabilities plus ledger write access,
  documented per build. Non-root with ambient capabilities where the
  platform allows.
- **Cluster-native:** the same binary per node as a Kubernetes
  DaemonSet; node-scoped visibility of the node's agent pods; node
  ledger in the same format; cluster review aggregates node ledgers.

The instrument never intercepts, terminates or modifies traffic:
capture loss degrades the ledger, the path is never affected.

## Evaluation and roadmap

The evaluation plan defines six measurements that gate the build:
shadow-discovery recall, tap overhead (against the sub-3% published
figure), transport-coverage matrix, ledger fidelity on capability
drift, unidentified-flow triage precision, and gate-handoff latency.
The harness runs in Python under `eval/` and consumes only the CLI and
export surfaces. Current phase: evaluation fleet build.

## Contributing

- [`CONTRIBUTING.md`](CONTRIBUTING.md) — the working agreement
  (Conventional Commits, signed commits, one logical change per PR).
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting
  ([private advisory](https://github.com/shsingh/agentpcap/security/advisories/new)).
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
- Architecture decisions live in [`docs/adr/`](docs/adr/0000-architecture-decision-records.md);
  ADR-0001 records the read-only invariant, the attributed default, the
  Rust choice and the licence posture.

**Engineering standard — harness before capability:** every behavioural
change goes in as a RED→GREEN pair. The failing test exists and runs
first. The PR records the RED output verbatim. See
[CONTRIBUTING.md](CONTRIBUTING.md).

Tap only estates you own or are authorised to observe.

## Licence

[MIT](LICENSE). Third-party sources keep their own terms and are
inventoried in [NOTICE.md](NOTICE.md).
