# agentpcap: guide for contributors and coding agents

This file is the single source of truth for humans and coding agents
(GitHub Copilot, Claude, Cursor, Hermes, etc.) working on agentpcap.
Tool-specific files (`CLAUDE.md`) only point here. When this file and a
tool-specific file disagree, this file wins.

The product specification is
[`docs/spec.md`](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md)
in this repository — the normative prose for the collectors, the event
schema, the ledger, the CLI faces and the release ladder. Every issue that
drives work links the specification sections it implements using GitHub
heading anchors (never bare section numbers, never `.pdf` references, never
`/pulls/N` links for issues).

## Project overview

agentpcap is a read-only, host-native observability surface for agent
tool calls: the eBPF probe and the pipe collector capture what agents
say to their tools (MCP over stdio pipes; the wire class lands on the
2026.01-alpha2 lane), append it to a hash-chained JSONL ledger, and the
operator answers "who called what with which capabilities" with one
command. The tool is an instrument, not a gatekeeper: it changes no path
writes and takes no decisions.

The delivery unit is a leaf-sized slice: one milestone acceptance row or
issue task, tests in the same change, merge via pull request.

## Repository structure

| Path | Purpose |
| --- | --- |
| `crates/agentpcap/` | operator CLI (`record`, `report`); subcommands grow on the ladder |
| `crates/ledger/` | the append-only, prev-hash-chained JSONL writer, verifier and conformance runner |
| `crates/events/` | the versioned event record — the interface contract |
| `crates/collector/` | the pipe collector's userspace half: wire format, match, tap |
| `crates/agentpcap-ebpf/` | the eBPF objects (standalone workspace, `bpfel-unknown-none`) |
| `docs/spec.md` | product specification (canonical) |
| `docs/paper/` | the research note and its figures |
| `docs/adr/` | architecture decision records |
| `tests/matrix/LEDGER.md` | the TDD cell matrix: every cell with its red and green receipts |
| `tests/fixtures/` | golden conformance fixtures with `.expect` verdicts |
| `site/` | the website (Quarto): [agentpcap.kalatopi.sh](https://agentpcap.kalatopi.sh/) |

## The TDD protocol (how work moves)

**Test before feature.** Work moves in red-green pairs, and the receipts
are the deliverable:

1. The failing cell lands first, committed with its receipt in
   [`tests/matrix/LEDGER.md`](https://github.com/shsingh/agentpcap/blob/main/tests/matrix/LEDGER.md);
   a red cell has a named reason (missing API, absent behaviour) — a red
   for the wrong reason is fixed before it counts.
2. The minimal implementation turns it green only on a fresh run in the
   build VM (`agentpcap-build-dev`, kernel receipts included for
   anything kernel-adjacent). A green without a run receipt does not
   count — see the gate rule at the bottom of the matrix.
3. The eBPF probe builds with
   `cargo +nightly build --target bpfel-unknown-none -Zbuild-std=core
   --release` inside `crates/agentpcap-ebpf/` (a standalone workspace);
   the probe object must be regenerated on any probe change before the
   cell runs.

**No invented transcripts.** Any README, PR or issue claim about
behaviour cites a real run verbatim (or links the CI run); a claim
without a traceable run is marked PENDING with its owning issue — never
approximated.

## Running agentpcap (operator and agent runbook)

- **Build** the userspace binary (stable Rust; the VM carries the pinned
  toolchain):

```bash
cargo build --release -p agentpcap && ./target/release/agentpcap --help
```

- **Record** (append JSON Lines events from stdin to a ledger):

```bash
./agentpcap record --ledger ./out/ledger.jsonl <<'EOF'
{"event": "init", "payload": {"client": "demo"}}
{"event": "tools-call", "payload": {"method": "tools/call", "name": "read"}}
EOF
```

- **Report** (print the records; the read lands in the access log):

```bash
./agentpcap report --ledger ./out/ledger.jsonl
```

- **Verify the ledger** (chain, rotation carry, torn tail):

```bash
cargo test -p agentpcap-ledger
python3 -c "pass"  # the conformance fixtures live in code: L101-L104
```

- **Conformance** (the golden fixtures answer their verdicts):

```bash
cargo test -p agentpcap-ledger --test l101_fixtures
```

- **The eBPF object** (probe objects are build artifacts, never
  committed):

```bash
cd crates/agentpcap-ebpf
cargo +nightly build --target bpfel-unknown-none -Zbuild-std=core --release
```

- **Verify a release binary before running it**: every release asset
  carries SLSA v1.0 provenance
  ([spec §17.1](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#171-release-signing-and-provenance)) —
  `gh attestation verify <asset> -R shsingh/agentpcap` (unsigned or
  unprovable → do not run).

## Signing

**Everything is GPG-signed, always** — commits and tags (releases are
signed tags). The `protect-default` ruleset enforces `required_signatures`;
an unsigned or badly-attributed commit blocks the pull request. The
signing key and the commit email must agree with a GitHub-verified
identity or verification fails and the PR cannot merge.

This repository signs with the OWASP identity: OpenPGP key fingerprint
`9CB1781DC2BB28D37A0155DCAAF8226F3F4C1712`, email `shain.singh@owasp.org`.
Default branch: **`main`**.

## Architecture Decision Records

Structural changes carry an ADR in the same PR. Most slices are
leaf-sized — the issue plus the linked spec sections are the design
record, no ADR needed — write one only when the change **introduces a new
persistent artifact** (the event schema shape, the wire layout, a
workflow, a fixture layout) **or removes/changes one**. Records live in
`docs/adr/`, numbered sequentially, one decision per file; accepted
records are immutable and are superseded, never rewritten.

Current records: [0000 — the ADR process](https://github.com/shsingh/agentpcap/blob/main/docs/adr/0000-architecture-decision-records.md)
· [0001 — foundational decisions](https://github.com/shsingh/agentpcap/blob/main/docs/adr/0001-foundational-decisions.md)
· [0002 — release gates and evaluation scenarios](https://github.com/shsingh/agentpcap/blob/main/docs/adr/0002-release-gates.md).

Release signing and provenance are **normative in the specification**
([§17.1](https://github.com/shsingh/agentpcap/blob/main/docs/spec.md#171-release-signing-and-provenance)), not an ADR: the tag is signed, every release asset carries SLSA v1.0
provenance, and the workflow refuses a tag without its committed gate
report.

## Pull requests

Follow [`CONTRIBUTING.md`](CONTRIBUTING.md) and treat the PR checklist as
a contract, not decoration.

### Before opening

- Work happens on a leaf branch cut from current `origin/main` — branch
  names follow `<type>/<short-description>` kebab-case (e.g.
  `feat/schema`, `site/governance-agents`).
- **One logical change per PR.** No drive-by refactors, formatting or
  dependency bumps.
- All commits GPG-signed with a GitHub-verified identity (see
  [Signing](#signing)).
- Run what CI runs locally before opening: the relevant `cargo test`,
  `pre-commit run --all-files`.

### Title and description

- Title follows Conventional Commits (`type(scope): summary`); a CI
  title gate checks the form. Issue titles follow the same convention.
- Body: **what** changed, **why** (issue link), **how verified** (test
  output, run receipts). Spec sections the change implements are
  hyperlinked (`docs/spec.md#<heading-anchor>`); reviewers should not
  have to read the diff to know something changed. Issue/PR bodies carry
  scope and evidence only — no session narration.
- The maintainer personally reviews and merges every PR. Do not enable
  auto-merge on the maintainer's behalf.

### Commits

- Small, self-contained, conventional-commit subjects; no stray scratch
  files; probe files and rendered spec outputs are deleted before
  commit, never gitignored.

## Labels

| Label | Meaning |
| --- | --- |
| `tap`, `ledger`, `events`, `classify`, `cli`, `deploy`, `eval`, `docs`, `ci` | component areas — every issue carries the right area(s) |
| `test`, `bug`, `documentation` | maintenance — `bug` = a genuine operator-facing defect |
| `mvp` | alpha-lane gating |
| `release-gate` | gate issues (`2026.01-alpha1`, `-alpha2`, `-rc1`) |

Board status is a project-field, not a label: labels never encode
progress. Never invent new labels — growing the catalog is a deliberate
change, not agent improvisation.

## Security

### Vulnerabilities

**Never open a public issue or PR describing an exploitable bug.** Report
through the GitHub security advisory link
([new advisory](https://github.com/shsingh/agentpcap/security/advisories/new));
see [`SECURITY.md`](SECURITY.md).

### Policy-relevant invariants

- **Read-only invariant.** The tap changes no path bytes and takes no
  enforcement decisions; a change that weakens the read-only posture is
  review-blocking and needs its own ADR.
- **Capture scope is contractual.** Attributed capture (method,
  arguments, results) is the default; the ledger records the mode that
  produced every event. Silently narrowing or widening capture is
  review-blocking (spec §8 Modes).
- **No personal-infrastructure references.** This is a public repository:
  issues, PR bodies, commit messages and code carry no local paths,
  private tooling, or environment specifics — abstract wording only.
- Secrets never enter the tree; secret scanning and push protection stay
  enabled in repository settings.
- The event record is the versioned interface contract: changes to
  existing fields are breaking and require a schema bump plus a
  migration note.
