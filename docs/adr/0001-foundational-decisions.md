# 0001 — Foundational decisions: read-only tap, opaque default, Rust, MIT

Status: accepted

## Context

agentpcap observes agent tool calls on hosts and in clusters. Four
early choices shape everything that follows them, and each choice was
made once for the whole project rather than per component:

- What the instrument may and may not do to the traffic it observes.
- What the default capture posture reveals and stores.
- The implementation language for an eBPF-based, per-host sensor.
- The licence under which the project releases.

The context each choice answers:

1. A tap that touches the traffic path would need enforcement policy,
   routing cooperation and a blast radius the project does not want;
   the surveyed gateway class carries that shape already [agentgateway,
   docs](https://docs.solo.io/agentgateway/standalone/latest/documentation/about/introduction).
2. A capture posture that stores arguments or prompts makes the
   instrument a content-retention system; the operator-facing value is
   tool and capability metadata, which survives without payloads.
3. The instrument is an always-on host sensor with kernel-side
   programs; the write path must be predictable, the binaries static,
   and the eBPF leg in one language with the userspace
   ([aya](https://github.com/aya-rs/aya)).
4. Upstream sources the project re-uses carry MIT and Apache-2.0 terms;
   the ecosystem's permissive norm keeps reuse and contribution two-way.

## Decision

1. **Read-only invariant.** The tap MUST NOT modify, delay, inject
   into, or terminate any traffic path; capture loss degrades the
   ledger and never the path. The invariant is a property of every
   release, tested per build.
2. **Opaque by default, nothing stored by default.** Attributed mode
   (TLS-boundary uprobes) is opt-in per host. Tool names and capability
   fingerprints are stored; arguments, prompts and payloads are not.
3. **Rust with aya.** The eBPF probe and the userspace share one
   language and one toolchain; binaries are static; the ledger writer
   runs without garbage-collection pauses.
4. **MIT for the project's original code.** Vendored sources keep
   their upstream licences with notices preserved
   ([NOTICE.md](../../NOTICE.md)); the specification, the evaluation
   harness and the site live in the same public repository. The project
   is free and open-source software.

These choices are recorded normatively in `docs/spec.md` (Sections 1,
8, 10 and 17); this record carries the reasoning.

## Consequences

- The read-only invariant bounds what the tap can offer: it complements
  gateways and consumers rather than replacing enforcement.
- The minimization defaults bound the evidence the ledger carries; the
  unidentified-flow pass and the capability fingerprints are the design
  answers to that bound.
- The Rust choice fixes the build chain: `cargo`, aya with its pinned
  kernel-legend conventions, and cross-compiled static targets.
- The MIT posture keeps the project usable everywhere; any vendored
  Apache-2.0 source carries its own licence file and change statement,
  and the inventory in `NOTICE.md` must name it before it lands.
