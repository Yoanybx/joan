# JOAN Operations

## Product metrics

JOAN does not transmit runtime telemetry. The `product-metrics` GitHub workflow runs weekly or on demand and records only repository-level aggregates already exposed by GitHub: stars, forks, release downloads, issue counts, workflow outcomes and, when repository permissions allow it, the rolling 14-day traffic window.

Each run writes a job summary and retains an immutable JSON artifact for 90 days. The report explicitly distinguishes adoption proxies from active installations. Exact user count and command frequency are unknown unless a user voluntarily submits the structured `Adoption report` issue form.

Local inspection:

```bash
GITHUB_TOKEN=... node tools/github-metrics.mjs OWNER/REPOSITORY
```

The token is read from the environment and is never printed or persisted. Without a token, public metadata can still be collected but traffic may be unavailable.

## Reproducible local evidence

Install the pinned `cargo-audit`, `cargo-deny` and `cargo-cyclonedx` versions used by CI, then run:

```bash
./scripts/verify-all.sh
```

Maintainers may refresh `.joan/evidence/latest.json` only after every local gate passes:

```bash
./scripts/refresh-evidence.sh
```

The evidence index binds the source tree, inventory, JCE1 suite and exact specification, the 10,000-case simulation test, digest benchmark, payment-cost vector and supply-chain outcomes. Every accepted refresh requires three complete execution receipts. Each receipt records command arguments, executable hashes, timestamps, exit status and output hashes. `verify-all.sh` rejects source, tool or recorded-result drift. Three passes on one Mac are not a release, external audit or independent reproduction.

The SBOM gate generates CycloneDX 1.5 twice in an external temporary directory,
rejects path leaks or graph drift and requires byte-identical output. To inspect
the complete runtime/workspace artifact without packaging a release:

```bash
./scripts/generate-sbom.sh all /absolute/external/output/directory
```

Release archives contain the generated `SBOM/` directory. An SBOM inventories
declared components; it does not establish vulnerability absence, ownership or
permission to use JOAN.

The dependency policy denies every unreviewed duplicate version. Two exact
older transitive versions required by pinned Cranelift dependencies are
documented in `deny.toml`; stale exceptions and any new duplicate fail:

```bash
./scripts/verify-dependency-policy.sh
```

## Bug intake

Use the structured GitHub `Bug report` form for reproducible, non-sensitive defects. Never publish credentials, private source or undisclosed exploit details. Security reports follow `SECURITY.md` and remain separate from public issue metrics.

## Updating JOAN

Dependency updates are proposed by Dependabot and must pass the guardian workflow, JCE1 cross-implementation conformance and review before merge. No dependency update, release or agent output bypasses those gates.

JOAN does not yet have an official GitHub remote or a stable release channel. Until both exist, there is no trusted automatic binary update path. The intended release process is:

1. LED ACTION LLC designates the official repository and protected release environment.
2. A reviewed commit passes all required checks on the protected default branch.
3. The release workflow builds from an immutable tag, publishes checksums and GitHub provenance attestations, and records the exact source commit.
4. Clients download only from the configured official repository, verify provenance and checksums, install `joan` and its sibling `joan-executor` side by side, run both self-checks, then switch atomically.
5. The prior verified binary remains available for rollback.

The current machine-readable publication state is blocked and can be inspected
without authorizing an effect:

```bash
./scripts/verify-publication-readiness.sh source
```

Tag workflows first enter the protected `release` environment. They require the
exact approval identity, commit and tag described in `RELEASE-CUSTODY.md`, plus
all readiness flags. Missing metadata fails before build. The gate is a
technical control, not proof of legal sufficiency or independent review.

Unattended self-update remains prohibited until release-key recovery, downgrade prevention and compromise response are implemented and independently tested. Once `.joan/update-policy.json` is deliberately enabled with the exact official repository, an operator can install one explicit tag with:

```bash
./scripts/install-release.sh OWNER/REPOSITORY vX.Y.Z
```

The installer rejects forks, implicit latest versions, missing checksums, missing GitHub attestations, unsupported platforms and failed self-checks. The previous binary is retained as `joan.previous`.
