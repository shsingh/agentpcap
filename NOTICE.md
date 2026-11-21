# Third-party notices and licence posture

agentpcap's original code carries the MIT licence ([LICENSE](LICENSE)).
This file inventories the third-party sources the project links,
re-uses or references, and states what terms each carries.

## How licences are inherited

- **Linked dependencies** (Rust crates): upstream terms flow through
  the dependency graph. This project does not relicense upstream code.
- **Vendored source files** (a future step, if taken): every vendored
  file keeps its upstream licence in the file header, and the licence
  text lands under `licenses/third-party/` with a change statement.
- **Technique re-use**: no copyright attaches to a technique. The
  specification names the provenance of each re-used capture mechanism
  (`docs/spec.md`, Section 3).

MIT and Apache-2.0 are both permissive licences. Code under Apache-2.0
may be redistributed inside an MIT-licensed project when its notice,
licence text and change statements travel with the code. The MIT licence
then covers this project's original code only. That is this
repository's posture.

## Inventory

| Source | Licence | Use in agentpcap | Inheritance |
|---|---|---|---|
| [aya](https://github.com/aya-rs/aya) | MIT OR Apache-2.0 | Rust eBPF library; the probe and userspace split | linked crate; not vendored |
| [AgentSight](https://github.com/eunomia-bpf/agentsight) | MIT | eBPF probe programs; reference and re-vendor candidate | MIT headers preserved on any vendored file |
| [agentgateway](https://github.com/agentgateway/agentgateway) | Apache-2.0 | MCP / A2A session semantics; reference for the reassembly layer | no code at draft 00; any vendored file carries its Apache-2.0 notice and change statement |
| [Pixie](https://github.com/pixie-io/pixie) | Apache-2.0 | the uprobe-on-TLS-library technique (C2) | technique credit only; no code |
| [Hubble](https://github.com/cilium/hubble) | Apache-2.0 | flow-layer reference; per-node placement precedent | technique credit only; no code |
| [Model Context Protocol](https://modelcontextprotocol.io/) | specification | the named protocol surface | no code |

Upstream projects carry no endorsement of agentpcap, and agentpcap
carries no endorsement from them.
