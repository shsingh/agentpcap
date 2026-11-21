# References

The project's source ledger. The research note
([`docs/agentpcap-paper.md`](agentpcap-paper.md)) cites these as
`[n]`; this file groups them for browsing. Specifications and
foundations first, then the four survey classes, then the measurement
and method layer.

## Protocols and standards

- `[1]` Model Context Protocol specification, revision 2025-11-25, transports — https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- `[30]` aya: an eBPF library for Rust — https://github.com/aya-rs/aya
- `[29]` Runtime Verification of Multiple Natural Language Criteria for Agent Governance — https://arxiv.org/abs/2611.23074
- `[28]` Forget Freely, Grep Later: Lossless, Index-Free Memory for Long-Horizon LLM Agents — https://arxiv.org/abs/2611.25123

## Guidance and posture

- `[2]` The state of MCP security in 2026 (Microsoft Security Blog) — https://techcommunity.microsoft.com/blog/microsoft-security-blog/the-state-of-mcp-security-in-2026/4531327
- `[3]` OWASP MCP Top 10, MCP09:2025 Shadow MCP Servers — https://owasp.github.io/www-project-mcp-top-10/2025/MCP09-2025%E2%80%93Shadow-MCP-Servers

## In-path gateways and secure web gateways

- `[11]` agentgateway introduction (Linux Foundation / AAIF) — https://docs.solo.io/agentgateway/standalone/latest/documentation/about/introduction
- `[4]` MCP traffic logs in Global Secure Access (Microsoft) — https://learn.microsoft.com/en-us/entra/global-secure-access/how-to-view-model-context-protocol-logging
- `[5]` How Cloudflare detects MCP traffic — https://blog.cloudflare.com/mcp-security-updates
- `[6]` MCP protocol detection and AI Security dashboard (Cloudflare changelog) — https://developers.cloudflare.com/changelog/post/2026-08-12-mcp-detection-and-dashboard
- `[7]` Netskope Agentic Broker documentation — https://docs.netskope.com/en/agentic-broker
- `[8]` Prisma AIRS AI Gateway (Palo Alto Networks) — https://www.paloaltonetworks.com/ai-security/ai-gateway
- `[9]` Market survey: Palo Alto Prisma alternatives (witness.ai) — https://witness.ai/blog/palo-alto-prisma-alternatives
- `[10]` Market survey: AI agent DLP solutions (arcade.dev) — https://www.arcade.dev/blog/dlp-solutions-ai-agents
- `[25]` State of MCP Security 2026 (PipeLab) — https://pipelab.org/blog/state-of-mcp-security-2026

## Endpoint and eBPF capture

- `[12]` AgentSight: System-Level Observability for AI Agents Using eBPF — https://arxiv.org/abs/2508.02736
- `[13]` How Pixie uses eBPF — https://docs.px.dev/about-pixie/pixie-ebpf
- `[14]` Hubble: observability for cloud-native workloads — https://github.com/cilium/hubble
- `[15]` AgentSniff: detectors — https://docs.agentsniff.org/detectors
- `[16]` I captured what an AI agent looks like on the wire (Blaze Security) — https://blazesecurity.substack.com/p/i-captured-what-an-ai-agent-looks
- `[17]` Hunting for MCP in the wild — https://disinfectedmind.substack.com/p/tech-deep-dive-hunting-for-mcp-in

## Inventory, census, and academic work

- `[18]` MCP servers on the internet (Censys) — https://censys.com/blog/mcp-servers-on-the-internet
- `[19]` A First Measurement Study on Authentication Security in Real-World Remote MCP Servers — https://arxiv.org/abs/2605.22333
- `[20]` Dynamic assessment of internet-facing MCP servers — https://arxiv.org/abs/2608.00150
- `[21]` From Privacy to Workflow Integrity: Communication-Graph Metadata in Autonomous Agent Interoperability — https://arxiv.org/abs/2606.07150
- `[22]` MCP-DPT: A Defense-Placement Taxonomy and Coverage Analysis for MCP Security — https://arxiv.org/abs/2604.07551
- `[23]` MCPThreatHive: Automated Threat Intelligence for MCP Ecosystems — https://arxiv.org/abs/2604.13849
- `[24]` Security Threat Modeling for Emerging AI-Agent Protocols: MCP, A2A, Agora, and ANP — https://arxiv.org/abs/2602.11327
- `[26]` MCP Scanner: security scanner for MCP servers — https://mcpscanner.cloud
- `[27]` MCP Scan CLI (Microsoft Agent Governance Toolkit) — https://microsoft.github.io/agent-governance-toolkit/tutorials/27-mcp-scan-cli
