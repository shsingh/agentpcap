# 0003 — Signed tags and SLSA provenance for release assets

Status: accepted

## Context

Named releases carry the project's verdicts over captured agent traffic.
A release whose tag or assets can be replaced silently does not support
those verdicts. The maintainer's other projects already ship signed
release tags and attested release assets; this project inherits the same
posture. GitHub artifact attestations bind a build artifact to an
SLSA v1.0 provenance record, signed with a short-lived Sigstore
identity; the public repo uses the public-good Sigstore instance.

## Decision

1. The tag is signed. Every named release tag
   (`YYYY.NN` plus an optional `-alphaN` or `-rcN` qualifier) is an
   annotated tag created with `git tag -s`. The tag points at the merge
   commit of the release-gate pull request. No unsigned tag moves the
   branch's release state, and a re-pointed tag fails the release.
2. Every release asset carries provenance. The release workflow builds
   each asset and runs `actions/attest-build-provenance` (pinned by
   commit SHA, GitHub-verified) on it. The attestation is the checksum
   of record: it carries the asset digest. The asset set verifies with
   `gh attestation verify --predicate-type https://slsa.dev/provenance/v1
   --repository shsingh/agentpcap`.
3. This artifact set is SLSA v1.0 Build Level 2. The build runs on
   GitHub-hosted, ephemeral, source-declared runners. Build Level 3
   arrives when the build moves behind a shared reusable workflow with
   stricter isolation. The release notes of each gate state the level
   and its evidence; no claim rises above it.
4. The workflow runs only on pushed tags matching `2026.*`. It builds
   the userspace binary for each supported runner architecture
   (`amd64`, `arm64`), attests each binary, uploads the binaries to the
   draft release, and publishes the release with the gate report
   document (`releases/<tag>.md`) as the release notes. The gate report
   is written by the release-gate pull request; a tag without a gate
   report document does not publish.
5. Verification, in order: the tag signature (GitHub renders it as
   verified), the required signatures on the merge history, then the
   provenance of each downloaded asset. A consumer verifies all three.

## Consequences

- Release assets carry an operator-verifiable chain: tag, merge commit,
  build provenance. The chain needs no maintained key material on the
  consumer side beyond the GitHub trust root.
- The eBPF object joins the attested asset set when its build lands in
  CI; until then the release carries the userspace binary only.
- Source archives rendered by GitHub from the signed tag carry the tag
  hash and carry no separate attestation.
