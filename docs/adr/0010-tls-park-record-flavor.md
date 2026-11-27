# ADR-0010: the TLS park record rides the call's flavor and a per-flavor slot

Status: Accepted
Date: 2026-11-26
Supersedes: nothing
Context issue: [#83](https://github.com/shsingh/agentpcap/issues/83)

## Context

The TLS-boundary collector parks each `SSL_*_ex` call at its entry face
and collects at its return face. The park record keyed ONE
`tls_pending` map slot by the full `pid_tgid`, and the collect face
consumed whatever that slot held — the CPython ssl wrapper interleaves
`SSL_read_ex` and `SSL_write_ex` heavily from one thread, so a wrong
flavor's return face consumed a park and read the OTHER call's buffer
state: a dead const-pool buffer rode the ledger as an `orphan-response`
row (the #83 receipts: one clean exchange produced an
initialize-result payload that never rode that wire). The falsification
receipts (the C115 scratch harness, one exchange):
`pair_mismatch=14805`, `stale_at_entry=0`, `collects=4` —
the mispair rode every face the wrapper interleaved.

A wire-layout change needs this record: the park record is the
probe's contract with the userspace sweep (AGENTS.md's ADR rule).

## Decision

1. **The park record carries the call flavor.** `SavedTls` and its
   userspace mirror `SavedTlsWire` grow 24 → 32 bytes: the two new
   fields are `flavor: u32` (0 = write, 1 = read) and
   `stale_at_entry: u64` (the *written slot's pre-call value — the
   fingerprint face that lets the falsification prove a slot-reuse
   hypothesis dead). The field ORDER rides both structs identically;
   the 32-byte asserts pin both sides together.
2. **The park/collect keys pair the tgid with the flavor.**
   `tls_pending`'s key is `(pid_tgid << 1) | flavor`. A park is only
   ever consumed by its own flavor's return face; a cross-flavor
   consume is impossible by construction.
3. **The regression tripwires ride the TLS canary.** `TLS_CANARY`
   widens to twelve slots: `SLOT_PAIR_MISMATCH` (8), `SLOT_TLS_STALE_COUNT` (9),
   `SLOT_TLS_MISPAIR_WRITE_READ` (10), `SLOT_TLS_COLLECTS` (11).
   `SLOT_CGID` keeps slot 4 — the falsification caught its own
   instrumentation clobbering it (the relocated-slot receipt in the
   C130 ledger row).

## Compatibility

- The probe and userspace builds MUST ship the same record layout: the
  32-byte asserts fail a build that moves one side.
- The userspace sweep reads only `ns_pid`, `ubuf` and `wptr` — the new
  fields ride transparently; no sweeper change.
- The map's key face changes from `pid_tgid` to
  `(pid_tgid << 1) | flavor`: the sweep iterates the map's keys and
  never decodes them, so no key consumer breaks.
- The `tls_canary` array's length is a probe-side counter surface only;
  the userspace reads it for the falsification receipts.

## Consequences

- The M003 legacy-SSE row runs the real two-connection legacy exchange
  (the POST endpoint and the separate `/sse` GET stream) and answers
  covered with zero gaps.
- The C115 cell rides the suite (its held face closes with #83).
- A wrong-flavor consume leaves a canary receipt and no ledger row.
