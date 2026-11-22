# 0008 — Schema version 2.1: the restart-safe dedupe keys

Status: accepted (extends the dedupe and schema faces, spec sections 4 and 11)

## Context

Review of the deploy and coexistence slice found the `dedup` key faces
restart-unsafe: the per-run counters minted the same key across a
`tap` restart, the writer's refusal then treated a NEW call as a
replay and the restarted capture lost it. The fix changes the `dedup`
field's shape and bounds the writer's in-memory key set. Review of the
ADR record found the 2.1 decision drafted inside the accepted 0007
record; accepted records stay unchanged and get superseded, so the
decision moves to its own record.

## Decision

1. **The session-event keys append `@{observed_ts}`.** A restarted
   capture that re-observes the same id on the same session is a NEW
   call; the observation time in the key makes the restart face never
   re-mint an earlier run's key.
2. **The notification and orphan faces ride content hashes** (16-hex
   FNV-1a of the record's payload), dropping the per-run counters.
3. **The writer accepts `1.0`, `2.0` and `2.1`** and still refuses a
   foreign version; the chain never verifies differently per face.
4. **The dedupe window is bounded.** The writer keeps at most
   `budget` dedupe keys in memory (the newest; default 65,536,
   `AGENTPCAP_DEDUP_BUDGET` overrides). The reload reads the closed
   segments in numeric order, the active segment last, and trims to
   the newest budget keys. Keys outside the window no longer refuse:
   the retained window is the stated trade-off, so a service that
   runs for weeks never grows memory with its history.

## Consequences

- The `dedup` face changes; no other event field moves and the
  `schema_version` bump is the migration signal.
- Readers and importers treat `dedup` as an opaque face: never parse
  or compose it. A 2.0-faced ledger reloads its full key set at open
  (the rotated segments ride the same load); a 2.1 writer bounds the
  set in memory per the window face above.
- The conformance fixtures stay 1.0-faced; the `schema-mismatch`
  refusal rule is unchanged.
- The next wire or payload-face change carries its own version bump in
  the ADR pattern, as its own record.
