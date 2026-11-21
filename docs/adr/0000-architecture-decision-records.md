# 0000 — Architecture decision records

Status: accepted

This directory carries the project's architecture decision records. An
ADR records one decision with its context and its consequences. The
records are numbered serially; the `0000` record is this index. A new
decision takes the next number, the `docs` commit type and conventional
subject, and lands on a branch like any other change.

Records carry three states:

- **accepted** — the project follows the decision now.
- **proposed** — the decision is open for review.
- **superseded** — a later record replaces it; the record names its
  successor.

The specification ([`docs/spec.md`](../spec.md)) carries the normative
behaviour. ADRs carry the reasoning behind the choices the
specification fixes — why the read-only invariant, why the language,
why the licence posture — so the next reader gets the argument and not
only the rule.
