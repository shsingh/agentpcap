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
| c101_scenario.rs:96 | the ambient-reply fix remains incomplete | Fixed in this PR, with the honest scope: the replies tie to the scenario through the payload set — the exact ids, the scenario's server name, the exact tool list and the exact result text — so an ambient exchange cannot pass. The fd-based channel key works for pipe-resident writers (the client's own writes resolve); forked-builtin reply writers die inside the pop window and key `peer=unresolved` with `fd-unresolved-at-pop` evidence. The in-kernel fd resolution in alpha2 makes every peer channel-keyed. |

## The release-workflow note

The toolchain step (LLVM 19 + bpf-linker on GitHub runners) is proven at
tag time: the first release build exercises it. The build VM proved the
same chain on LLVM 23 with the local shim; the workflow pins the 19-dev
packages.

## The alpha2 wire-class sweep (PRs #62–#81, 2026-11-22)

Every merged pull request of the alpha2 wire-class lane, audited after
the last PR (#81) merged. Thread counts ride each PR's review threads;
every resolved thread's fix carries its ledger receipt on that PR. The
five still-open threads disposition here.

| PR | Lane | Threads | Resolved | Open |
|----|------|---------|----------|------|
| #62 | the alpha1 scenario | 4 | 4 | 0 |
| #63 | the gate report | 3 | 2 | 1 |
| #64 | the audit fixes | 8 | 6 | 2 |
| #67 | the release toolchain | 1 | 1 | 0 |
| #68 | the eBPF toolchain | 1 | 1 | 0 |
| #71 | the badge rows | 1 | 1 | 0 |
| #76 | the spec anchors | 0 | 0 | 0 (no thread) |
| #77 | the reassembler | 18 | 18 | 0 |
| #78 | the export and drift slice | 19 | 19 | 0 |
| #79 | the deploy and coexistence slice | 31 | 30 | 1 |
| #80 | the socket collector | 41 | 41 | 0 |
| #81 | the TLS boundary collector | 57 | 56 | 1 |

### The open dispositions

- **PR #63 — `c101_scenario.rs`, "Other traffic fails the scenario":**
  superseded on main. The rows filter to the run's own client pid
  (`tests/agentpcap/tests/c101_scenario.rs`, the `mine` selection), so
  another server's replies never satisfy the asserts; the payload-set
  tie (the exact ids, the server name, the tool list, the result text)
  rides every C1xx cell.
- **PR #64 — `main.rs`, "Non-pipe writes are still recorded":**
  the remaining gap stands, described honestly: a class-pipe sample
  whose fd names a live file keys `stdio-pipe` with
  `fd-unresolved-at-pop` evidence through the alpha1 fallback — the
  pipe path does not yet distinguish a file fd from a dead writer.
  The fix (a three-face `PipeFdFace` resolve: Pipe / NotPipe / Dead,
  the NotPipe face drops the sample) rides
  [#85](https://github.com/shsingh/agentpcap/issues/85) with its cell;
  the collect face is offset-robust before it rides the serial suite
  (the p003 known face: the calibration offset drifts between runs).
- **PR #64 — `main.rs`, "Messages name the wrong pipe" (fd reuse):**
  accepted and documented inside ADR-0004's pop-time race family. The
  fd may close and its number may ride a different file inside the pop
  window; the reassembler keys sessions by the session-event faces, and
  the C1xx cells tie their rows to run-unique markers, so a reused fd
  never crosses a test's records.
- **PR #79 — `c009_duration_faces.rs`, "Startup errors pass duration
  test":** fixed in this PR. The bounded-window face asserts the exit
  status (`st.success()`); a probe-load or ledger-open failure can no
  longer pass it. Receipt at this PR's head: full workspace rc=0.
- **PR #81 — `main.rs`, "Streamed replies lose results" (SSE):** the
  `data:`-line parse face landed in #81; the integration cell holds on
  the stale-content capture defect (#83), whose red receipt rides that
  issue. The cell re-lands with the collect-provenance fix.

### The verdict

No open review bot thread blocks the `2026.01-alpha2` gate: two ride
documented races the specs declare (ADR-0004, issue #83), one carries a
follow-up slice with its red receipt and cell (#85), one is superseded
on main (#63), and one is fixed in this audit PR (C009).

(The tally corrected per the open review finding on the sweep PR
itself: the #85 follow-up and the file-write drop face are one and the
same fix. The follow-up has since LANDED — [PR
#105](https://github.com/shsingh/agentpcap/pull/105) closed #85 with
the pidfd `fstat` resolve and the `ChanResolve` skip face;
`resolved_pipe_channel` in `crates/collector/src/lib.rs` carries the
three faces on main.)

## The rc1 evaluation-lane sweep (PRs #86–#111, 2026-11-26)

Every merged pull request of the rc1 evaluation lane, audited after the
last PR (#111) merged. Thread counts ride each PR's review threads; a
resolved thread's fix carries its ledger receipt on that PR. The
census: one `reviewThreads(first: 100)` GraphQL query per PR.

| PR | Lane | Threads | Resolved | Open |
|----|------|---------|----------|------|
| #86 | the alpha2 gate report | 2 | 2 | 0 |
| #87 | the M004 harness scaffold | 5 | 5 | 0 |
| #89 | the M002 overhead faces | 6 | 6 | 0 |
| #90 | the M003 transport matrix | 5 | 5 | 0 |
| #91 | the M004 between-sessions face | 6 | 6 | 0 |
| #94 | the M005 triage measurement | 5 | 5 | 0 |
| #97 | the M006 gate-handoff harness | 6 | 6 | 0 |
| #98 | the idle-drain backoff | 0 | 0 | 0 (no thread) |
| #99 | the per-sample comm and fd caches | 5 | 5 | 0 |
| #101 | the one-share drain and the sweep gate | 3 | 3 | 0 |
| #102 | the eBPF ring buffers | 3 | 3 | 0 |
| #105 | the pidfd fstat fd resolve | 5 | 5 | 0 |
| #107 | the pidns identity face | 1 | 1 | 0 |
| #108 | the pipe direction-stamp merge | 4 | 4 | 0 |
| #109 | the wire comm face | 2 | 2 | 0 |
| #110 | the M001 fleet recall | 6 | 6 | 0 |
| #111 | the buffered ledger landing | 7 | 7 | 0 |
| #84 | the alpha2 sweep itself | 2 | 1 | 0* |

*The #84 tally finding dispositioned with the verdict correction above;
the thread resolves on the audit PR that carries this section.

### The rc1 disposition set

Every thread across #86–#111 resolved pre-merge with its fix cited on
the thread. One open thread dispositioned in this sweep:

- **PR #84 — `the verdict counts #85 twice`:** fixed here. The
  corrected tally reads the #85 follow-up as ONE fix, the #63 thread as
  superseded, and names the #85 slice LANDED at PR #105 (the fact-check
  rides the live `resolved_pipe_channel` in `crates/collector/src/lib.rs`).

### The verdict

No open review bot thread blocks the `2026.01-rc1` gate. The two
parked research faces (#76's btf_type walk, #55's fork lineage) carry
their issue receipts and stay open untouched; the stale TLS-buffer
defect (#83) rides its documented race face into the rc1 gate report's
remaining-gaps row.
