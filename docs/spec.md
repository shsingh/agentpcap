%%%
title = "agentpcap — A Read-Only, Protocol-Aware Tap for Agent Tool Calls on Hosts and in Clusters"
abbrev = "agentpcap"
ipr = "none"
docName = "agentpcap-spec-00"
category = "info"
area = "Security"
workgroup = "Independent Submission"
keyword = ["MCP", "agent security", "eBPF", "flow ledger", "network visibility", "Rust"]
date = 2026-11-21
submissionType = "independent"
language = "en"

[seriesInfo]
name = "Internet-Draft"
value = "agentpcap-spec-00"
stream = "independent"
status = "informational"

[[author]]
initials = "S."
surname = "Singh"
fullname = "Shaineel Singh"
organization = "agentpcap project"
  [author.address]
  email = "shain.singh@owasp.org"
%%%

{mainmatter}

# agentpcap — Product Specification

*Revision 00 · November 2026 · github.com/shsingh/agentpcap*

## Spec card

| | |
|---|---|
| **Name** | `agentpcap` |
| **One-liner** | A read-only tap observes agent tool calls at socket and pipe boundaries, reassembles MCP and A2A sessions, and appends every flow to a lossless, per-host ledger. One static binary; review subcommands included. |
| **Modelled on** | Capture placement of AgentSight and Pixie; append-only ledger practice from long-horizon agent memory work; gate handoff to natural-language criteria verification. |
| **Runtime shape** | One static Rust binary (linux amd64 + arm64, musl); host-native daemon mode and per-node Kubernetes DaemonSet mode; eBPF collectors on Linux; review subcommands run anywhere the binary runs. |
| **Status** | Draft 00. This document is the canonical specification of the agentpcap repository. |

## Terminology and requirements language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals, as shown here.

Definitions used throughout:

- **Tap**: a read-only observer. A tap MUST NOT modify, delay, inject into, or terminate any traffic path, and MUST NOT require a change to agent, SDK, or routing configuration.

- **Flow record**: one observed transaction at a boundary, keyed by host, process lineage, transport, and peer; the unit the collectors emit.

- **Session event**: one classified event after reassembly; initialization, tool discovery, tool invocation, server-initiated message, task handoff, or unidentified-flow event.

- **Ledger**: the append-only log of session events per host or per node, in the format of Section 7.

- **Capability fingerprint**: a stable hash over the server's advertised capabilities from the initialize response; the value whose change between sessions is capability drift.

- **Attributed mode** / **opaque mode**: capture states per Section 8; attributed is the default, opaque is the opt-out.

- **Unidentified flow**: traffic the classifier cannot bind to a named protocol but that carries agent-shaped transport features; a first-class ledger event.

- **Socket class / pipe class**: the TCP-UDP-QUIC boundary and the client-launched-server stdio pipe boundary respectively.

## 1. Scope

agentpcap covers the flows the four surveyed tooling classes do not: out-of-path coverage (G001), capture without TLS termination (G002), the stdio transport (G003), MCP and A2A session semantics (G004), the append-only operator flow ledger (G005), and triaged unidentified agent flows (G006). This document defines the event record, the ledger format, the collectors, the classification behavior, the CLI, and the two deployment topologies.

## 2. Non-goals

agentpcap is not a gateway and does not sit in any path. It is not a configuration or tool-description scanner. It is not an internet-wide census tool. It is not an LLM observability SDK; it requires no agent-side library, no prompt change, and no routing change. It does not decrypt traffic it cannot observe at an owned boundary.

## 3. Architecture

The instrument is one binary with six components:

- **C001 — socket collector**: eBPF programs observe send and receive at the socket boundary, filtered by cgroup and process lineage; emits flow records.

- **C002 — TLS-boundary collector**: uprobes on the host's TLS libraries capture plaintext before encryption; active only in attributed mode.

- **C003 — pipe collector**: observes reads and writes on the client-server stdio pipes; emits frame records of the same shape.

- **Reassembler**: a userspace state machine turns frame streams into session events (Section 6).

- **Ledger writer**: appends session events to the per-host (or per-node) ledger (Section 7).

- **Operator CLI**: `record`, `report`, `diff`, `export` subcommands (Section 9).

The data path:

```
socket collector (eBPF) ─┐
TLS-boundary collector ──┼─→ ring buffer → reassembler → classifier → ledger ──→ gate stream
pipe collector (stdio) ──┘                                        └──→ report · diff · export
```

Every component is a re-use candidate first: aya for the eBPF probe and userspace split (Rust, Apache-2.0), and the released probe programs of AgentSight as re-use or reference implementations where licensing permits. The build MUST record its dependency set and license report in the repository.

## 4. Event record schema

The event record is the project's interface contract; both deployment topologies MUST emit it identically. The schema is versioned; the field `schema_version` MUST be present and MUST change on any incompatible change.

| Field | Type | Requirement | Note |
|---|---|---|---|
| schema_version | string | MUST | SemVer pair; incompatible changes bump major. |
| ts | RFC3339 UTC | MUST | Host clock at observation. |
| host | string | MUST | Stable host or node identity. |
| process | string | MUST | Executable name plus lineage hash. |
| pid | integer | MUST | Observed process id. |
| transport | string | MUST | `stdio-pipe`, `tcp`, `udp`, `quic`, `socket-unresolved`. The `socket-unresolved` face names a socket observation whose connection face closed before the resolver ran; it carries the `fd-unresolved-at-pop` evidence. |
| mode | string | MUST | `opaque` or `attributed`; per Section 8. |
| verdict | string | MUST | `mcp`, `a2a`, `agent-unidentified`, `other` (Section 6). |
| event | string | MUST | `init`, `tools-list`, `tools-call`, `notify`, `a2a-handoff`, `unidentified`, `other`. |
| method | string | SHOULD | JSON-RPC method where parsed. |
| tool_name | string | SHOULD | From `tools/call` or `tools/list` payload. |
| cap_fingerprint | string | SHOULD | Capability fingerprint; absent in opaque mode without plaintext. |
| protocol_version | string | SHOULD | `MCP-Protocol-Version` header value where observed. |
| session_id | string | SHOULD | `Mcp-Session-Id` header or pipe channel key. |
| peer | string | MUST | Remote five-tuple or pipe pair id. |
| dedup | string | MUST | Coexistence deduplication key (Section 11). |
| evidence | array | SHOULD | Header, SNI, DNS, or timing features that drove classification. |

The event record carries the tool call's method, arguments, and result. Payload content rides the record: capture runs in attributed mode by default (Section 8), and retention or redaction are operator settings. A build MAY add redacted diagnostic fields; the schema MUST then note the redaction rule.

## 5. Collectors and transport coverage

- **stdio pipe class (MUST).** The pipe collector MUST capture newline-delimited JSON-RPC in both directions on pipes between a client and a client-launched server process, identified through process lineage. Channel identity is the pipe pair; no network involvement exists.

- **Streamable HTTP (MUST).** The reassembler MUST reconstruct sessions using `Mcp-Session-Id` where present, and MUST record `MCP-Protocol-Version` header values as evidence.

- **Legacy HTTP plus SSE (SHOULD).** Best effort; the verdict and evidence fields carry the weaker result.

- **A2A (MUST detect, SHOULD full session semantics).** Task handoff shapes are classified `a2a` with peer identity; full state tracking MAY trail the MCP path without schema change.

- **QUIC and HTTP/3 (SHOULD).** Opaque-mode flow records with transport features only.

- **Non-carried platforms.** The eBPF collectors are Linux-only. The review subcommands run on any platform the binary builds for.

## 6. Classification

The classifier assigns the `verdict` from protocol semantics, not from catalogs: session keying, method names, and initialize response shape. The `MCP-Protocol-Version` header is positive evidence; its absence MUST NOT produce a negative verdict on its own. Sessions the classifier cannot bind but that carry agent-shaped features (burst-and-loop cadence, tool-like request shapes, model-traffic pairing) MUST surface as `agent-unidentified`, carrying evidence features for later probing. The classifier MUST NOT require any catalog lookup for its first two verdicts.

## 7. The flow ledger

The ledger is a per-host (and per-node) append-only file of event records in JSON Lines order.

- Appends MUST carry a `prev` field: the truncated SHA-256 of the previous line, making the chain verifiable after any tamper.

- The ledger MUST NOT be rewritten, re-indexed, or compacted by the instrument. Rotation MUST preserve the prefix: a closed segment moves to `<name>.<n>` and a fresh segment continues the chain with its `prev` set.

- The writer SHOULD sync at least every five seconds, and MUST sync at process exit.

- Reads sidecar off the file (regex and `report` tooling); no index is built.

- Ledger access MUST itself be logged, append-only, in an adjacent access log; the access log stores actor, time, and scope.

- Default retention SHOULD be unlimited with explicit rotation; any retention cap MUST be an explicit operator setting.

## 8. Modes

Attributed mode is the default. The TLS-boundary collector (C002) captures plaintext at the host's own TLS libraries through uprobes, in the demonstrated manner of Pixie and AgentSight, so the record carries the method, the arguments, and the result without extra operator work. Attributed capture MUST NOT require TLS termination of any session or a change to any path. Opaque mode (metadata-only: transport features, headers visible before encryption, DNS and SNI evidence) remains available and MAY be selected per host. The mode that produced each event MUST be recorded in the event's `mode` field. A build MUST document its own capability requirements.

## 9. Operator CLI

Four subcommands; exit code 0 on success, 2 on misuse, 1 on capture error.

| Subcommand | Contract |
|---|---|
| `agentpcap record` | Default service face: collectors running, ledger appending, event stream exportable. |
| `agentpcap report` | Renders the sessions view from the ledger: per peer and per server; tools discovered, capability fingerprints, invocation counts, transport, mode. Output JSON Lines by default, table with `--table`. |
| `agentpcap diff` | Compares two report sets and emits capability drift events: new tools, changed tool descriptions, removed tools, re-scoped servers. |
| `agentpcap export` | Streams ledger events to stdout as JSON Lines for the policy gate or estate collection; supports a ledger segment or live follow. |

The CLI MUST NOT write to the ledger except through the `record` writer.

## 10. Deployment

Two topologies, one binary and one schema:

- **Host-native.** The binary runs as a service under the host's init; a shipped systemd unit named `agentpcap.service` and a launchd template for workstation review builds. The service needs the BPF and performance-monitoring capabilities plus write access to the ledger path; it SHOULD run non-root with ambient capabilities where the platform allows, and MUST document its capability set in the build. The ledger sits at a versioned path with optional onward export to the estate's collection.

- **Cluster-native.** The identical binary ships in a container image placed per node as a DaemonSet, matching per-node eBPF placement practice. The manifest: node-scoped visibility of the node's agent pods, a hostPath for the node ledger, and the image's capability set documented in the build. Cluster review aggregates node ledgers; a consumer MUST be able to tell records apart only by their fields, not by topology.

The instrument MUST NOT intercept, terminate, or modify traffic in either topology. Capture loss degrades the ledger; the path is never affected.

## 11. Coexistence and flow deduplication

agentpcap does not require any other product, and none becomes a prerequisite. Where an in-path gateway or a host observer already runs, agentpcap SHOULD consume its published export formats as corroborating evidence into the same ledger. Where the same flow is already covered by an in-path system, the `dedup` key (five-tuple plus session identity) MUST prevent double-event records; the record MUST name its own capture path (`source` field: `tap`, `export`, or `build-reuse`). Build-time reuse of libraries is a dependency decision, never a co-install: aya and agentgateway under Apache-2.0 are re-use candidates, and the released AgentSight probe programs are a re-use candidate where licensing permits.

## 12. Gate handoff

The ledger's event stream is the input surface for a criteria gate. A policy pass over events ("no tool calls to unregistered servers", "no system-control invocation from unregistered servers") SHOULD re-use natural-language criteria verification machinery instead of inventing a rule language. The gate consumes the `export` stream; the instrument imposes no policy language of its own.

## 13. Evaluation hooks

The evaluation plan defines six measurements: shadow-discovery recall, overhead, transport coverage, ledger fidelity, unidentified-flow triage, and gate handoff latency. The binary SHOULD expose counters that let the Python evaluation harness measure M001 through M006 without instrumenting the tap internals; the harness lives in the repository's `eval/` directory and consumes only the CLI and export surfaces. Harness overhead MUST be kept out of the tap's measurement path; M002 measures tap-on versus tap-off deltas with the identical harness.

## 14. Privacy and capture data handling

Attributed capture with payload content is the default: the ledger records the operator's tool traffic with the method, arguments, and result per event. Retention, redaction, and purge are operator settings; any build default MUST be documented. Ledger access MUST be logged. The instrument runs inside one boundary — the estate the operator owns — and MUST NOT ship any telemetry of its own beyond what the operator's own paths carry.

## 15. Security considerations

The tap is a host-resident, kernel-leg observer; the eBPF program surface is attack surface and MUST stay minimal, pinned, and reviewed with each build. Probe programs taken from upstream are re-vendored with license records and verified hashes; the build MUST NOT load unpinned probe bytecode. The ledger contains operational metadata about agent activity and is itself sensitive: its access log, rotation, and tamper chain exist for that reason. Read-only enforcement is the product's own safety property: a tap that becomes writable memory on the host defeats its threat model. Classification of agent workflows from metadata is dual-use; the metadata literature places that boundary precisely, and this spec fixes the defaults above (attributed by default with tool messages recorded, scope-locked deployment, and logged access).

## 16. IANA considerations

This document has no IANA actions.

## 17. Implementation status

The repository implements this specification in Rust: the eBPF probe and userspace split through aya, the ledger writer, and the operator CLI, with the Python evaluation harness under `eval/`. CI renders this document to text, HTML, and PDF per push of the source; the rendered files are build outputs and are never committed. The project carries the MIT licence for its original code; vendored sources keep their upstream licences and are inventoried in the repository's [NOTICE.md](../NOTICE.md). This document is the canonical specification; surfaces that cite it link it by heading anchor.

### 17.1 Release signing and provenance

Release operations bind every named release to an operator-verifiable chain. The chain covers the tag, the merge history, and the build provenance of each asset.

1. The release tag MUST be signed. Each named release tag (`YYYY.NN` with an optional `-alphaN` or `-rcN` qualifier) is an annotated tag created with `git tag -s`. The tag points at the merge commit of the release-gate pull request. An unsigned tag MUST NOT move the release state, and the release MUST NOT republish from a re-pointed tag.
2. Every release asset MUST carry build provenance. The release workflow attests each asset with a SLSA v1.0 build provenance record, generated with a SHA-pinned, GitHub-verified action under a short-lived Sigstore identity. The attestation is the checksum of record and carries the asset digest.
3. Consumers MUST verify in order: the tag signature, the required signatures on the merge history, then the provenance of each downloaded asset. Provenance verification uses the repository's attestation store with the provenance predicate type.
4. This build configuration is SLSA v1.0 Build Level 2: the build runs on ephemeral, source-declared, hosted runners. Build Level 3 arrives when the build moves behind an isolated, shared reusable workflow. Release notes MUST state the level and MUST NOT claim a higher one.
5. The release workflow runs only on pushed release tags. It MUST refuse a tag that carries no committed gate report under `releases/`, MUST build and attest each asset, and MUST publish the release with that gate report as the release notes. The gate report is authored by the release-gate pull request.
6. Source archives rendered from the signed tag carry the tag hash; they carry no separate attestation record.

## References

- Model Context Protocol specification, revision 2025-11-25, transports: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- AgentSight: System-Level Observability for AI Agents Using eBPF: https://arxiv.org/abs/2508.02736
- How Pixie uses eBPF: https://docs.px.dev/about-pixie/pixie-ebpf
- aya, an eBPF library for Rust: https://github.com/aya-rs/aya
- agentgateway introduction (Linux Foundation / AAIF): https://docs.solo.io/agentgateway/standalone/latest/documentation/about/introduction
- OWASP MCP Top 10, MCP09:2025 Shadow MCP Servers: https://owasp.github.io/www-project-mcp-top-10/2025/MCP09-2025%E2%80%93Shadow-MCP-Servers
- Censys, MCP servers on the internet: https://censys.com/blog/mcp-servers-on-the-internet
- Forget Freely, Grep Later: Lossless, Index-Free Memory for Long-Horizon LLM Agents: https://arxiv.org/abs/2611.25123
- Runtime Verification of Multiple Natural Language Criteria for Agent Governance: https://arxiv.org/abs/2611.23074
- RFC 2119 and RFC 8174 (BCP 14): https://www.rfc-editor.org/info/bcp14
