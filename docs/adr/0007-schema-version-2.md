# 0007 — Schema version 2.0: the session-event record face

Status: accepted (extends the event record schema, spec section 4)

## Context

The reassembler's merged session record changed the `payload` face: the
request and the result ride as named members (`request`, `result`) of
the new shape, while the alpha1 frame records carried the raw JSON-RPC
object with `id`/`method`/`params` at the top. Review found the two
faces sharing one ledger with no version that distinguishes them, and
readers addressing `payload.method` on a session record find nothing.
Spec section 4's rule applies directly: `schema_version` MUST be
present and MUST change on any incompatible change.

## Decision

1. **The session-event face carries `schema_version: "2.0"`.** Every
   record the reassembler emits - the merged `init`/`tools-list`/
   `tools-call`/`a2a-handoff` records, the notifications, and the
   orphan `unidentified` records - carries the 2.0 face.
2. **The frame face keeps `1.0`.** The tap's truncated-face records
   (the alpha1 face: no parseable JSON object) carry 1.0. Old segments
   on disk carry 1.0. A ledger may carry both faces; the version
   answers which shape the payload holds.
3. **The writer accepts both known faces** (`1.0`, `2.0`) and refuses
   everything else: the coexistence ingestion and the alpha1 archives
   chain into the same ledger, and a foreign version still refuses.
4. **The flush face rides the observation time.** A `no-response`
   record's `ts` carries the request's observation time (stamped when
   the parked frame arrived), not the capture window's end; the merged
   records keep the bind time - the response half completes the
   record.

## Consequences

- Readers switch on `schema_version`: 1.0 reads `payload` as the raw
  frame; 2.0 reads `payload.request` and `payload.result`.
- The conformance fixtures stay 1.0-faced; the `schema-mismatch`
  refusal rule is unchanged.
- The next wire or payload-face change carries its own version bump in
  the same ADR pattern.
