# Contributing

The project welcomes contributions. This document gives the working
agreement. It covers: how the project proposes, reviews and merges
changes, and what the continuous-integration gates enforce.

## Ground rules

1. **Never commit to `main`.** All work happens on a branch, one change
   per branch, merged via pull request. Branch names follow
   `<type>/<short-description>` kebab-case — e.g. `feat/pipe-collector`,
   `fix/ledger-prefix-chain`, `docs/spec-dedupe-keys`.
2. **Conventional Commits.** Every commit subject follows the
   [specification](https://www.conventionalcommits.org/en/v1.0.0):
   `type(scope): subject`.
   - Types: `feat`, `fix`, `docs`, `refactor`, `test`, `build`, `ci`,
     `chore`, `perf`, `revert`, `site`.
   - `scope` is a component: `tap` (the eBPF collectors, the pipe
     collector), `reassemble` (MCP and A2A state machines),
     `classify` (verdicts, evidence), `ledger` (format, rotation,
     chain, access log), `cli` (record, report, diff, export),
     `deploy` (service unit, DaemonSet, manifests), `spec`,
     `eval` (evaluation harness), `docs`, `ci`, `release`.
   - Subject: imperative, lowercase, no trailing period. Body
     (optional): what changed and why; wrap at 72 columns.
   - PR titles follow the same form. Squash merges use the PR title as
     the commit subject, so the PR title is the commit record. A CI
     gate checks the form on every PR; bot/dependency PRs (renovate,
     pre-commit.ci autoupdate) keep their canonical titles.
3. **Sign everything.** Commits carry a GPG or SSH signature
   (`git config commit.gpgsign true`); releases carry signed tags. An
   unsigned commit or tag blocks the merge and the publish. This
   repository signs with the OWASP identity: OpenPGP key
   `9CB1781DC2BB28D37A0155DCAAF8226F3F4C1712`, email
   `shain.singh@owasp.org`. The `protect-default` ruleset enforces
   `required_signatures`. Verify with `git log --show-signature` /
   `git tag -v`.
4. **One logical change per PR.** Small, reviewable diffs merge faster.
5. **Pre-commit runs locally.** Install the hooks once per clone:
   `pre-commit install && pre-commit install --hook-type pre-push`.
   Then every `git commit` and `git push` runs the same hook set CI
   runs. Bypass with `--no-verify` for the rare legitimate exception.

## Security-sensitive changes

Extra care applies to the capture-scope boundaries and the ledger
contract ([SECURITY.md](SECURITY.md) carries the full posture):

- **Vulnerabilities do not go into public issues.** Follow
  [SECURITY.md](SECURITY.md); never open a public issue for an
  unreported vulnerability.
- **Read-only invariant:** a change that lets the tap write to a traffic
  path, inject, or terminate a connection is a security defect, and a
  change that only loosens the invariant in a test is rejected in
  review.
- **Event schema and ledger format:** field removals or semantic
  changes break the contract. The change needs a `schema_version` bump
  and a migration note.
- **Capture scope:** the tap observing beyond its configured scope —
  hosts, transports, or content classes beyond the documented tool
  message — is a defect, not a preference.
- **Capability set:** the documented eBPF capability set is the
  published posture; a change that silently adds privileges needs its
  own stated justification.

## The acceptance suite

```
cargo fmt --check && cargo clippy -- -D warnings   # formatting + lint
cargo test                                          # unit suite
pre-commit run --all-files                          # the hook set CI runs
```

The Rust suite arrives with the first implementation slice; until then
the hook set runs on every PR. The repo is dependency-first-principles:
new dependencies need the justification in the PR body.

## CI on every pull request

| Check | What it does |
|---|---|
| PR title — Conventional Commits | PR title checked against the Conventional Commits form |
| Dependency Review | flags vulnerable or licence-incompatible dependency changes |
| site-check | the Quarto site renders with no broken references |
| `required_signatures` | ruleset-enforced: unsigned commits block the PR |

Required status checks grow as CI surfaces arrive.

## Commits and pull requests

- Push the branch and open a PR against `main`; describe the what and
  the why.
- The PR body links the `docs/spec.md` sections it exercises (GitHub
  heading anchors).
- The maintainer reviews and merges every PR; do not enable auto-merge
  on the maintainer's behalf.
- Releases carry signed tags.

## Reporting bugs

Open a [GitHub issue](https://github.com/shsingh/agentpcap/issues/new).
The report carries: the version or commit, the subcommand and collector
hit, the host OS and kernel where eBPF is concerned, and the relevant
ledger or output excerpt (arguments redacted; see the minimization
defaults). Security issues never go here — [SECURITY.md](SECURITY.md)
instead.

The **harness-before-capability** standard applies to every change: the
check that gates a behaviour goes in the same PR as the behaviour. The
failing test exists first; the PR records the RED output verbatim.

## Licence

The project carries the **MIT** licence — see [LICENSE](LICENSE).
Third-party sources keep their own terms; see [NOTICE.md](NOTICE.md).
Contributions come in under the project's MIT terms.
