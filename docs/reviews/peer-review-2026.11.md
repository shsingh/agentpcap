# Peer review audit — Greptile comments, every merged PR (2026-11-21)

The repository's peer review (Greptile) comments across every merged
pull request, with where each one landed: fixed, superseded by a later
merged change, or accepted and documented. The open gaps carry fixes in
the PR that adds this document.

## PR #61 — the tap runtime

| Comment | Finding | Disposition |
|---------|---------|-------------|
| main.rs:235 | the tap captures its own ledger writes: a feedback loop | Fixed structurally by the ADR-0003 filter: the ledger's JSONL lines start `{"dedup"` — no `jsonrpc` member within the sniff window, so the tap's own appends never ride the queue. Verified in the C101 runs: the ledger holds exactly the scenario's records, none self-fed. |
| main.rs:22 | `include_bytes_aligned!` needs an object a fresh checkout lacks; the release build fails | Fixed in this PR: release.yml installs the eBPF toolchain and builds the probe before the userspace binary; the step asserts the object exists. |
| main.rs:191 | the pid-namespace offset is unsafe across namespaces | Accepted and documented for this release: the alpha1 gate is one lab host, one PID namespace (ADR-0002). Multi-namespace translation is an alpha2 concern. |
| main.rs:145 | the calibration file has a predictable name, opened non-exclusively | Fixed in this PR: the sentinel file is created exclusively (`create_new`) inside a private tempdir owned by this tap. |
| main.rs:157 | the calibration payload prefix is public and spoofable | Fixed in this PR: every calibration writes a fresh token from the host entropy pool; the tap accepts only its own exact bytes. |
| main.rs:219 | `transport=stdio-pipe` on every write, fd unchecked | Fixed in this PR: the sample now carries the write's fd; the tap resolves it through `/proc` and records only pipe-writes. |
| main.rs:228 | `peer` names the writer, not the channel | Fixed in this PR: `peer` is the pipe's inode (`pipe:<inode>`), shared by both ends of one channel, distinct per channel. |
| main.rs:217 | the resolved lineage is discarded | Fixed in this PR: the resolved parent rides the record's `evidence` (`lineage:parent-<ppid>`). |
| main.rs:262 | `event=session` is not in the schema's allowed values | Fixed in this PR: unidentified records emit `unidentified` (spec §4: init, tools-list, tools-call, notify, a2a-handoff, unidentified, other). |
| collector/lib.rs:40 | the 48→144 wire change carries no ADR | Superseded: ADR-0003 (added later) covers the whole widening history 48→144→272 and governs future changes. |
| LEDGER.md:71 | C100 green without a named run receipt | Fixed in this PR: C100 re-run on this branch with the receipt recorded in the matrix. |

## PR #56 — P003 lineage

| Comment | Finding | Disposition |
|---------|---------|-------------|
| p003_lineage.rs:103 | the translation assert is tautological | Fixed in this PR: the calibration generalizes — a second writer's sample is translated with the first writer's offset and asserted against its own pid. |
| collector/lib.rs:74 | `resolve_parent` documents exit-then-cache behavior in two conflicting sentences | Fixed in this PR: one doc sentence — the cache answers without consulting `/proc` until the entry expires. |
| p003_lineage.rs:49 | P003 writes its marker once against a flooding 1024-slot queue | Superseded by the ADR-0003 filter: the queue sees only jsonrbrc candidates, so the single marker cannot be crowded out. Re-verified green on this branch. |

## PR #62 — the alpha1 scenario (all addressed pre-merge)

The capture-scope filter (whitespace + member order), the P002/P003
marker fixtures, the record-level C101 assertions, and ADR-0003 itself —
fixed and replied on the review threads before merge.

## PR #63 — the gate report

| Comment | Finding | Disposition |
|---------|---------|-------------|
| release page | the required `report` output missing | Fixed: C101 runs `agentpcap report` over the scenario ledger and asserts all six records; the real output rides the release page. |
| release page | the roadmap still describes alpha1 as unshipped | Fixed: the roadmap's current-phase and alpha1 sections updated; the render receipt noted in the PR. |
| c101_scenario.rs:96 | the reply filter accepts any non-client process's replies | Fixed in this PR: the reply records are selected by the reply pipe's inode — the test holds the read end of that pipe, so ambient traffic cannot enter the set. |

## The release-workflow note

The toolchain step (LLVM 19 + bpf-linker on GitHub runners) is proven at
tag time: the first release build exercises it. The build VM proved the
same chain on LLVM 23 with the local shim; the workflow pins the 19-dev
packages.
